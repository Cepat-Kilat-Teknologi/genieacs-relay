# genieacs-relay - TR-069 CPE Adapter

## Overview

REST API adapter between isp-agent Temporal workflows and **GenieACS** (TR-069
ACS server). Translates HTTP calls into GenieACS NBI tasks with async worker
pool for slow WLAN provisioning. Powers all 7 CPE workflows in isp-agent.

- **Module:** `github.com/Cepat-Kilat-Teknologi/genieacs-relay`
- **Go:** 1.26.6
- **Router:** chi v5 (deliberate framework mix, NOT Fiber)
- **Logger:** zap (structured JSON)
- **Layout:** flat: all source in `package main`, no `internal/` or `cmd/`
- **Entry:** `main.go` → `runServer(":8080")`
- **Version:** v2.2.1 (latest tagged release)

## Architecture

```
isp-agent (Temporal worker) → HTTP /api/v1/genieacs/* → genieacs-relay → GenieACS NBI → TR-069 devices
```

Tier 4 core adapter. 40+ endpoints covering WLAN CRUD, device capability,
optical health, DHCP, reboot, and factory reset operations. Real-device
verified on ZTE F670L.

## Module Map

| File(s) | Purpose |
|---------|---------|
| `models.go`, `response.go`, `error_codes.go` | Request/response envelope, error codes |
| `handlers_wlan.go` | 5 WLAN endpoints (create, available, update, delete, optimize) |
| `handlers_ssid.go` | 3 SSID endpoints (by IP, force refresh, refresh) |
| `handlers_device.go` | 2 device endpoints (DHCP clients, capability) |
| `client.go` | HTTP client to GenieACS NBI |
| `wlan.go`, `dhcp.go`, `capability.go` | Domain logic |
| `validation.go` | Input validation (IP, WLAN ID, SSID, password) |
| `cache.go` | In-process TTL cache for GenieACS responses |
| `worker.go` | Async worker pool for long-running tasks |
| `middleware.go` | API key auth, rate limiter, CORS, security headers |
| `idempotency.go` | `MemoryStore` TTL cache, `X-Idempotency-Key` on writes |
| `server.go` | Config loading, router wiring |
| `logger.go`, `reqctx.go`, `loggermw.go`, `audit.go` | Structured logging + audit |
| `health.go`, `metrics.go`, `apiversion.go` | Health probes, Prometheus, version headers |

## Build / Test / Lint

```bash
go test -race -coverprofile=coverage.out $(go list ./... | grep -v /docs)
go tool cover -func=coverage.out | tail -5
golangci-lint run --timeout=5m
govulncheck ./...

# Hot reload
air -c .air.toml

# Swagger regenerate
swag init -g main.go -o docs/
```

Coverage: 100% statement coverage. Tests use httptest + testify (`require`,
`assert`). Table-driven with `t.Run()` subtests.

## Middleware Chain (order matters)

```
RequestID → requestIDMiddleware → RealIP → apiVersionHeaders →
structuredLogger → metrics → audit → Recoverer
  └─ per-route /api/v1/genieacs: apiKeyAuth → idempotency
```

Key invariants:
- `requestIDMiddleware` MUST run before anything that logs
- `metricsMiddleware` reads `chi.RouteContext`: must run after route resolution
- Idempotency caches only status < 500 (retries re-execute on server errors)

## Key Patterns

- **Error responses** always via `sendError(w, r, code, errCode, data)`: never
  write to `w` directly (loses `request_id` injection)
- **Request-scoped logger**: `WithRequestIDLogger(r.Context())` for correlation
- **Context propagation**: all GenieACS calls use `r.Context()` via
  `http.NewRequestWithContext` for timeouts/cancellation
- **Worker pool**: if `taskWorkerPool.Submit()` returns false → 503, never drop

## API Routes

### Public (unauthenticated)

`/health`, `/healthz`, `/readyz`, `/version`, `/metrics`, `/swagger/*`

### Authenticated (`/api/v1/genieacs/*`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/ssid/{ip}` | WLAN configs for device |
| GET | `/force/ssid/{ip}` | WLAN with force refresh + retry |
| POST | `/ssid/{ip}/refresh` | Async WLAN refresh |
| GET | `/dhcp-client/{ip}` | DHCP client list |
| GET | `/capability/{ip}` | Band capability (single/dual) |
| GET | `/wlan/available/{ip}` | Available WLAN slots |
| POST | `/wlan/create/{wlan}/{ip}` | Create WLAN |
| PUT | `/wlan/update/{wlan}/{ip}` | Update WLAN |
| DELETE | `/wlan/delete/{wlan}/{ip}` | Disable WLAN (soft delete) |
| PUT | `/wlan/optimize/{wlan}/{ip}` | Optimize radio settings |
| PUT | `/wlan/enable/{wlan}/{ip}` | Re-enable disabled WLAN |
| POST | `/reboot/{ip}` | TR-069 Reboot RPC |
| POST | `/dhcp/{ip}/refresh` | DHCP cache refresh |
| GET | `/optical/{ip}` | Optical TX/RX/temp/voltage (5-vendor auto-detect) |
| POST | `/cache/clear` | Clear device cache |

## Environment

**Required:** `GENIEACS_BASE_URL` (default `http://localhost:7557`)

**Auth:** `MIDDLEWARE_AUTH=true` + `AUTH_KEY`: API key on `/api/v1/genieacs/*`.
`NBI_AUTH=true` + `NBI_AUTH_KEY`: forward key to GenieACS NBI.

**Optional:** `SERVER_ADDR` (`:8080`), `CORS_ALLOWED_ORIGINS` (`*`),
`RATE_LIMIT_REQUESTS` (`100`), `RATE_LIMIT_WINDOW` (`60s`),
`STALE_THRESHOLD_MINUTES` (`30`).

**Optical thresholds (dBm):** `OPTICAL_RX_NO_SIGNAL_DBM` (`-30.0`),
`OPTICAL_RX_CRITICAL_DBM` (`-27.0`), `OPTICAL_RX_WARNING_DBM` (`-24.0`),
`OPTICAL_RX_OVERLOAD_DBM` (`-8.0`).

**Observability (Sprint 18-19):**
- `SENTRY_DSN`: Sentry error tracking; empty = disabled
- `SENTRY_ENVIRONMENT`: Sentry environment (e.g. `prod-jkt`); falls back to
  `APP_ENV`, then the legacy `ENVIRONMENT`
- `SENTRY_RELEASE`: overrides the Sentry release; default
  `genieacs-relay@<version>` from `main.version` (tag, short SHA, or `dev`)
- `OTEL_ENABLED` (`false`): OpenTelemetry tracing
- `OTEL_EXPORTER_OTLP_ENDPOINT` (`localhost:4317`): OTel collector
- `OTEL_SERVICE_NAME` (`genieacs-relay`): OTel service name

**Security middleware (Sprint 19):** security headers
(`securityHeadersMiddleware` in `middleware.go`): no env vars, always active.

## Config Loading

Uses raw `os.Getenv` with defaults: does NOT auto-load `.env`. When running
via overmind, env comes from `.overmind.env`. For standalone, export vars or
use a wrapper script.

## Ldflags

```bash
go build -ldflags "-X main.version=<semver> -X main.commit=<sha> -X main.buildTs=<iso8601>"
```

Variable names MUST be **lowercase** (`main.version`, not `main.Version`).
Go silently ignores `-X` for non-existent symbols, uppercase produces a
binary reporting `"dev"/"none"` with no error.

## Gotchas

- **Factory-reset upstream blocker**: GenieACS `PeriodicInformTime` write
  conflict blocks post-reset device wake. Not a relay bug, needs
  genieacs-stack fix.
- **HTTP 202**: GenieACS NBI returns 202 for `?connection_request` tasks,
  not 200. Handlers accept `status < 400` as success.
- **CORS**: defaults to `localhost:3000` in production. Set
  `CORS_ALLOWED_ORIGINS` for other origins.

## Cross-cutting (Sprint 18-19)

| Feature | Status | Details |
|---------|:------:|---------|
| OTel tracing | Yes | `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` |
| Sentry | Yes | `SENTRY_DSN` (empty = disabled), `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE` |
| Rate limiting | Yes | Per-IP token bucket: `RATE_LIMIT_REQUESTS` / `RATE_LIMIT_WINDOW` |
| Security headers | Yes | `securityHeadersMiddleware` in `middleware.go` (always active, no env vars) |
| Body size limit | Yes | 1 MB (JSON-only CPE commands) |
