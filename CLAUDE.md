# CLAUDE.md — genieacs-relay

> **READ FIRST (AI agents):** `~/Projects/knowledge-base/BOOTSTRAP.md` is
> the canonical cold-start doc for this platform. This repo is 1 of 5
> HTTP adapters subordinate to [[isp-agent]]. Current platform state:
> `~/Projects/knowledge-base/STATUS.md`.

## Wiki Update Discipline (HARD RULE)

**"Release done" ≠ "tag pushed". Release done = tag + wiki + platform status
all updated together.**

When releasing a new version or making substantive changes:

1. `CHANGELOG.md` — move Unreleased to `[vX.Y.Z] — DATE`
2. Git tag + push: `git tag -a vX.Y.Z && git push origin vX.Y.Z`
3. Verify release workflow success (multi-arch Docker + GitHub Release)
4. **Wiki entity page**: `~/Projects/knowledge-base/wiki/genieacs-relay.md`
5. **Platform status**: `~/Projects/knowledge-base/STATUS.md`
6. **Platform changelog**: `~/Projects/knowledge-base/PLATFORM_CHANGELOG.md`
7. **Dependency manifest**: `~/Projects/knowledge-base/platform-deps.yaml`
8. If breaking change: notify isp-agent dev lead — genieacs-relay powers
   **all 7 CPE workflows** in isp-agent v0.1.0, breaking changes have
   high blast radius

**v2.1.0 status (2026-04-14):** All 3 v2.1 endpoints implemented and
merged on main, awaiting tag + Docker push:
- `POST /api/v1/genieacs/reboot/{ip}` — TR-069 Reboot RPC
- `POST /api/v1/genieacs/dhcp/{ip}/refresh` — dedicated DHCP host refresh
- `GET /api/v1/genieacs/optical/{ip}` — read TX/RX power + temp +
  voltage + bias current with vendor auto-detection (ZTE CT-COM EPON/GPON,
  Huawei HW_DEBUG, Realtek EPON, standard TR-181) and configurable
  health classification thresholds

These unblock isp-agent v0.2+ `RestartOnu`, `RefreshDhcpStatus`, and a
new `GetOpticalHealth` workflow. See `CHANGELOG.md` `[Unreleased]`
section for full detail and `TODO.md` for the v2.1.0 checklist.

## Versioning Policy

This project follows **Semantic Versioning 2.0.0** strictly. Binary version (reported
via `/version`, `X-App-Version` response header, and Docker image tag) is the single
source of truth for "what did this change cost clients?":

- **MAJOR (X.y.z)** — breaking changes. Any client-visible change that would force
  `billing-agent` or other consumers to update integration code. Current: **v2.0.0**.
- **MINOR (x.Y.z)** — backwards-compatible additions (new endpoint, new optional
  field, new header, new metric, new env var with default).
- **PATCH (x.y.Z)** — bug fixes only, no API change.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) §Versioning Policy for the full rules table,
version history, and rules of thumb for edge cases.

## Project Overview

REST API adapter that sits between [billing-agent](https://github.com/Cepat-Kilat-Teknologi/billing-agent)
and **GenieACS** (TR-069 ACS server). Translates internal HTTP calls into GenieACS REST API
tasks, with an async worker pool for slow WLAN provisioning operations. Fourth compliant
adapter in the ISP billing architecture (after freeradius-api v1.2.0, go-snmp-olt-zte-c320 v3.0.0,
and write-olt-zte-c320-svc v3.0.0). Current release: **v2.0.0** (local semver track — see CONTRIBUTING.md).

- **Module path:** `github.com/Cepat-Kilat-Teknologi/genieacs-relay`
- **Go version:** 1.26.2
- **Web framework:** `go-chi/chi v5.2.5` (NOT Fiber — deliberate framework mix across the adapter fleet)
- **Logger:** `go.uber.org/zap` (structured JSON per `isp-logging-standard`)
- **Layout:** flat — all source files at repo root under `package main`. No `internal/` or `cmd/` subfolders.
- **Entrypoint:** `main.go` → `runServer(":8080")`

## Architecture

```
billing-agent (future v2)
       │
       │ HTTP /api/v1/genieacs/*
       ▼
genieacs-relay  ← THIS adapter
       │
       │ HTTP NBI (+ X-Request-ID forwarding)
       ▼
GenieACS server → TR-069 devices (ONUs)
```

NOT in billing-agent v1 scope — the `activate_customer` workflow uses freeradius-api + write-olt-svc
only because the OLT auto-pushes OMCI to ONUs during registration. genieacs-relay becomes relevant
for v2 workflows: `change_wlan_ssid`, `change_wlan_password`, force-provisioning, device firmware
polling. The standardization work done for v2.0.0 is proactive readiness.

## Module Map (flat package main layout)

### Core request/response envelope
- `models.go` — `Response` struct (code/status/error_code/data/request_id), WLAN domain types
- `response.go` — `sendResponse(w, code, data)` + `sendError(w, r, code, errCode, data)`
- `error_codes.go` — machine-readable error code constants
- `constants.go` — env var names, paths, auth modes, status strings, error messages

### Build metadata + version endpoint
- `buildinfo.go` — `buildVersion`/`buildCommit`/`buildDate` vars + `setBuildInfo()` setter + accessors
- `main.go` lowercase ldflags vars (`version`, `commit`, `buildTs`) propagated via `setBuildInfo` at startup

### Logging
- `logger.go` — `initProductionLogger()` attaches `service`/`version` base fields + `WithRequestIDLogger(ctx)` / `WithModule(base, name)` helpers
- `reqctx.go` — typed context key + `WithRequestID`/`RequestIDFromContext` + `requestIDMiddleware` bridging chi's RequestID into our typed key
- `loggermw.go` — `structuredLoggerMiddleware` emits per-request zap lines with correlation and skips health paths
- `audit.go` — `auditMiddleware` emits one audit log line per POST/PUT/PATCH/DELETE via `logger.Named("audit")`

### Health + observability
- `health.go` — `healthChecker` with cached (5s TTL) GenieACS ping + `healthzHandler` + `readyzHandler`
- `metrics.go` — Prometheus collectors + idempotent `registerMetrics()` + `metricsMiddleware` with chi path templates
- `apiversion.go` — `apiVersionHeadersMiddleware` attaches `X-API-Version`/`X-App-Version`/`X-Build-Commit` to every response
- `routes.go` — `healthCheckHandler`, `versionHandler`, `clearCacheHandler`

### Request-level idempotency
- `idempotency.go` — `MemoryStore` TTL cache (7 day default) + `idempotencyMiddleware` for write ops on `/api/v1/genieacs/*`

### HTTP handlers
- `handlers_wlan.go` — 5 WLAN endpoints (create, available, update, delete, optimize)
- `handlers_ssid.go` — 3 SSID endpoints (by IP, force refresh, refresh)
- `handlers_device.go` — 2 device endpoints (DHCP clients, capability)

### Domain logic
- `client.go` — HTTP client to GenieACS NBI (device lookup, setParameterValues)
- `wlan.go` — WLAN config parsing, validation, slot allocation
- `dhcp.go` — DHCP client data extraction
- `capability.go` — device capability detection (single-band vs dual-band)
- `utils.go` — request helpers (ExtractDeviceIDByIP, ParseJSONRequest, SubmitWLANUpdate, etc.)
- `validation.go` — input validation (IP, WLAN ID, SSID, password, encryption, auth mode)
- `cache.go` — `deviceCache` in-process TTL cache for GenieACS responses
- `worker.go` — async worker pool for long-running tasks (setParameterValues, applyChanges, refreshWLAN)

### Middleware + security
- `middleware.go` — API key auth with brute-force lockout, rate limiter, CORS, security headers, audit tracker
- `server.go` — `runServer`, config loading, router wiring (chi middleware chain order matters)

## HTTP Middleware Chain (server.go)

Chi middleware is composed in a specific order; each layer sees the request with the
previous layers already applied. Order is:

```
RequestID               // chi generates a correlation ID
requestIDMiddleware     // bridge chi's ID into our typed ctx + echo X-Request-ID header
RealIP                  // resolve client IP from X-Forwarded-For / X-Real-IP
apiVersionHeadersMiddleware  // attach X-API-Version/X-App-Version/X-Build-Commit
structuredLoggerMiddleware   // zap per-request log; skips /health*, /readyz, /metrics, /version
metricsMiddleware       // Prometheus counters/histograms with chi RoutePattern labels
auditMiddleware         // audit sub-logger line for POST/PUT/PATCH/DELETE
Recoverer               // chi panic → 500

(per-route /api/v1/genieacs)
apiKeyAuthMiddleware    // optional — only when MIDDLEWARE_AUTH=true
idempotencyMiddleware   // X-Idempotency-Key cache replay on POST/PUT/PATCH/DELETE
```

**Important invariants** when adding middleware:
1. `requestIDMiddleware` MUST run before anything that logs — it populates the ctx key
   that `WithRequestIDLogger(ctx)` reads from.
2. `structuredLoggerMiddleware` skips health/probe paths via `skipRequestLogPaths` — if
   you add a new endpoint that should not be logged per request, add it to the set.
3. `metricsMiddleware` reads `chi.RouteContext(r.Context()).RoutePattern()` which is only
   populated AFTER chi resolves the route — that's why it runs late in the chain.
4. `idempotencyMiddleware` caches responses only when status < 500, so saga retries
   against transient server errors re-execute (which is the desired behavior).

## Key Patterns

- **Error responses** ALWAYS go through `sendError(w, r, code, errCode, data)`. Do NOT write
  to `w` directly — you'll lose `request_id` injection and break the standardized envelope.
- **Request-scoped logger**: handlers call `WithRequestIDLogger(r.Context())` to get a
  zap logger pre-decorated with `request_id`. Don't use the bare package-level `logger` var
  in request paths — it works but loses correlation.
- **Context propagation**: every GenieACS HTTP call goes through `r.Context()` via
  `http.NewRequestWithContext`, so timeouts, deadlines, and cancellations all flow through.
  (TODO for v2.1: also forward the `X-Request-ID` header to GenieACS for end-to-end tracing.)
- **Worker pool submit-fail**: if `taskWorkerPool.Submit()` returns false, respond with
  `ErrCodeServiceUnavailable` (503) — never silently drop the request.
- **Idempotency scope**: middleware is wired only on `/api/v1/genieacs/*` route group. Health,
  version, metrics endpoints are idempotent by definition and do not participate.
- **State-aware idempotency is NOT implemented** — the request-level `MemoryStore` cache is
  the only layer. GenieACS itself dedupes tasks per-device on its side, and WLAN ops are
  not strictly destructive the way SSH DeleteOnu is. v2.1 may revisit this if field data
  shows retries with divergent state.

## Ldflags Injection Safety

The binary version, commit, and build timestamp are injected at compile time:

```
-ldflags "-X main.version=<semver> -X main.commit=<sha> -X main.buildTs=<iso8601>"
```

Variable names MUST be lowercase. Go silently ignores `-X` for non-existent symbols, so
a Dockerfile that injects `main.Version` (uppercase) against `main.version` (lowercase)
produces a binary with the default `"dev"`/`"none"`/`"unknown"` values — silent failure.

**Always verify after a real Docker build**:

```bash
docker run --rm -p 8080:8080 cepatkilatteknologi/genieacs-relay:dev &
curl -s localhost:8080/version
# Expected: {"version":"2.0.0","commit":"ed729fd",...}
# If you see "dev"/"none" → Dockerfile ARG casing is wrong. Check the Dockerfile ARG
# declarations and the go build -ldflags line.
```

## Testing

- **Table-driven** + `t.Run()` subtests (existing convention)
- **sqlmock**: not applicable (no SQL — adapter talks to GenieACS over HTTP)
- **httptest** for handler/middleware integration tests (`v3_test.go`, `handlers_*_test.go`)
- **zaptest/observer** can be used to capture audit log lines in new tests
- **testify** (`require`, `assert`)

### Coverage

- Total: **100.0%** statement coverage (baseline match)
- All new v2 code paths covered in `v3_test.go` (buildinfo, reqctx, logger, response
  envelope, idempotency, audit middleware, metrics middleware, apiversion headers,
  health checker with GenieACS ping stub)
- `doRegisterMetrics` and `initProductionLogger` were deliberately simplified to use
  `zap.Must(cfg.Build())` and lenient `prometheus.Register` error handling so no
  unreachable dead branches remain

### v2.0.0 Integration Test (real device, 2026-04-12)

Verified end-to-end against a live ZTE F670L (IP `10.90.4.173`) connected to a
local `genieacs-stack`. All 18 endpoints tested with 96/96 assertions passing.
Full CRUD lifecycle (CREATE → UPDATE → OPTIMIZE → DELETE) confirmed on the actual
device by polling for the device's next periodic inform after each mutation and
verifying parameter values in the GenieACS NBI database.

**One runtime bug was discovered and fixed during integration testing:**
`refreshDHCP` and `refreshWLANConfig` checked `resp.StatusCode != http.StatusOK`
(200), but GenieACS NBI returns **HTTP 202 Accepted** when using `?connection_request`
for any refresh task. This caused `/dhcp-client?refresh=true` to always return 500
despite the task being successfully queued. Fixed to accept `status < 400` as success.

This bug existed in v2.x as well — it was latent because mocked unit tests used
200 responses and the real `?connection_request` path was never exercised in CI.
Lesson: **mock-only tests cannot substitute for at least one real-device smoke test
before release** for adapters whose purpose is forwarding requests to upstream systems.

## Development Commands

```bash
# Run locally (hot reload via air)
air -c .air.toml

# Run tests
go test -race -coverprofile=coverage.out $(go list ./... | grep -v /docs)
go tool cover -func=coverage.out | tail -5

# Lint
golangci-lint run --timeout=5m

# Vulncheck
govulncheck ./...

# Swagger regenerate (after response/model changes)
swag init -g main.go -o docs/

# Smoke test the v2 envelope end-to-end
go build -ldflags "-X main.version=2.0.0 -X main.commit=$(git rev-parse --short HEAD) -X main.buildTs=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o /tmp/relay . && /tmp/relay &
curl -s localhost:8080/version
curl -sI localhost:8080/health | grep -i x-
curl -s localhost:8080/metrics | head -3
curl -s localhost:8080/readyz
kill %1
```

## API Routes

### Unauthenticated (outside `/api/v1/genieacs`)

| Method | Path        | Purpose                                   |
|--------|-------------|-------------------------------------------|
| GET    | /health     | Liveness alias (backwards compat)         |
| GET    | /healthz    | k8s liveness probe                        |
| GET    | /ready      | Readiness alias (Fiber convention)        |
| GET    | /readyz     | k8s readiness probe w/ GenieACS ping      |
| GET    | /version    | Build metadata (ldflags-injected)         |
| GET    | /metrics    | Prometheus exposition                     |
| GET    | /swagger/*  | Swagger UI                                |

### Authenticated (`/api/v1/genieacs/*`) — all honor `X-Idempotency-Key` for writes

| Method | Path                       | Purpose                                  |
|--------|----------------------------|------------------------------------------|
| GET    | /ssid/{ip}                 | Get WLAN configs for device              |
| GET    | /force/ssid/{ip}           | Get WLAN with force refresh + retry loop |
| POST   | /ssid/{ip}/refresh         | Trigger async WLAN refresh               |
| GET    | /dhcp-client/{ip}          | List DHCP clients                        |
| POST   | /cache/clear               | Clear device cache (all or specific)     |
| GET    | /capability/{ip}           | Device band capability (single/dual)     |
| GET    | /wlan/available/{ip}       | Available WLAN slots                     |
| POST   | /wlan/create/{wlan}/{ip}   | Create new WLAN on slot                  |
| PUT    | /wlan/update/{wlan}/{ip}   | Update existing WLAN                     |
| DELETE | /wlan/delete/{wlan}/{ip}   | Disable WLAN (soft delete)               |
| PUT    | /wlan/optimize/{wlan}/{ip} | Optimize radio settings                  |

## Environment Configuration

**Required:**
- `GENIEACS_BASE_URL` — GenieACS NBI base URL (default: `http://localhost:7557`)

**Authentication:**
- `MIDDLEWARE_AUTH=true` + `AUTH_KEY=<key>` — enable API key auth on `/api/v1/genieacs/*`
- `NBI_AUTH=true` + `NBI_AUTH_KEY=<key>` — forward API key to GenieACS NBI

**Optional:**
- `SERVER_ADDR` (default `:8080`)
- `CORS_ALLOWED_ORIGINS` (default `*`, comma-separated list or `*`)
- `CORS_MAX_AGE` (default `86400`)
- `RATE_LIMIT_REQUESTS` (default `100`)
- `RATE_LIMIT_WINDOW` (default `60` seconds)
- `STALE_THRESHOLD_MINUTES` (default `30`)

## Related Documentation

- `CHANGELOG.md` — v2.0.0 breaking changes, added endpoints, fixed ldflags bug
- `API_REFERENCE.md` — full endpoint reference with examples
- `test.http` — REST Client (VS Code) smoke test suite
- `k6-load-test.js` — k6 load test scenarios (health + contract only, no real GenieACS)
- `docs/swagger.json` — OpenAPI spec (regenerate via `swag init`)
- Wiki entity page: `isp:genieacs-relay` (in the knowledge-base repo)
