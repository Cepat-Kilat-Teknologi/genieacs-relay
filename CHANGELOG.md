# Changelog

All notable changes to genieacs-relay are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v2.1.0 (CPE lifecycle operations + optical health)

### Added

- **`POST /api/v1/genieacs/reboot/{ip}`** — TR-069 Reboot RPC. Triggers
  GenieACS task `{"name": "reboot"}` against the device matched by IP,
  with `?connection_request` so the call blocks until the task is
  applied (200 OK) or queued (202 Accepted). Actual CPE reboot takes
  30-90 seconds before the device reconnects to the ACS — callers
  (typically the future `RestartOnu` workflow in isp-agent) should NOT
  block waiting for the device to come back. Idempotency middleware
  applies via the `/api/v1/genieacs` route group, so double-clicks
  within the dedup TTL window replay the same response. Implementation:
  `reboot.go` + handler in `handlers_device.go` + route in `server.go`.
  Tests: `reboot_test.go` covering 200/202 success, 404 device-not-found,
  500 NBI error, payload literal verification.

- **`POST /api/v1/genieacs/dhcp/{ip}/refresh`** — dedicated DHCP host
  cache refresh endpoint. Reuses the existing internal `refreshDHCP()`
  function but exposes it as a clean POST-for-side-effect primitive
  distinct from the read endpoint `GET /dhcp-client/{ip}?refresh=true`
  which mixes read and side-effect semantics. Use case: future
  `RefreshDhcpStatus` workflow that triggers a refresh now and reads
  the fresh data on a follow-up call. Idempotency-cached. The cached
  device data is cleared on success so the next read fetches fresh.

- **`GET /api/v1/genieacs/optical/{ip}`** — read CPE optical interface
  health metrics (TX power, RX power, temperature, voltage, bias
  current). Detects the vendor parameter tree automatically:

  | Source label | TR-069 path |
  |---|---|
  | `zte_ct_com_epon` | `InternetGatewayDevice.X_CT-COM_EponInterfaceConfig.Stats.*` |
  | `zte_ct_com_gpon` | `InternetGatewayDevice.X_CT-COM_GponInterfaceConfig.Stats.*` |
  | `huawei_hw_debug` | `InternetGatewayDevice.X_HW_DEBUG.AdminTR069.{Tx,Rx}Power` |
  | `realtek_epon` | `InternetGatewayDevice.X_Realtek_EponInterfaceConfig.Stats.*` |
  | `standard_tr181` | `Device.Optical.Interface.1.Stats.*` |

  Detection order matches typical Indonesian ISP deployment frequency
  (most ZTE F670L/F660 ONTs in residential PON deployments). Returns
  HTTP 404 with `error_code: OPTICAL_NOT_SUPPORTED` for CPEs that
  don't expose any known tree.

  **Health classification.** Raw RxPower (dBm) is bucketed into
  categorical labels by `classifyOpticalHealth`:

  | RxPower (dBm) | Health |
  |---|---|
  | `rx <= -30` | `no_signal` (fiber broken/disconnected) |
  | `-30 < rx <= -27` | `critical` (marginal, intermittent drops likely) |
  | `-27 < rx <= -24` | `warning` (attenuated, watch closely) |
  | `-24 < rx < -8` | `good` (normal PON ONT operating range) |
  | `rx >= -8` | `warning` (overload — receiver too hot, link too short) |

  Thresholds are configurable per-deployment via env vars (read at
  startup): `OPTICAL_RX_NO_SIGNAL_DBM`, `OPTICAL_RX_CRITICAL_DBM`,
  `OPTICAL_RX_WARNING_DBM`, `OPTICAL_RX_OVERLOAD_DBM`. Defaults match
  typical PON ONT operating ranges; tune if your deployment has
  unusual splitter ratios or distance profiles.

  **Freshness.** By default the endpoint reads from the cached device
  tree (fast but possibly stale up to the GenieACS device cache TTL).
  Pass `?refresh=true` to force a `refreshObject` task on every known
  vendor optical subtree before reading — slower (round-trips to the
  CPE) but guaranteed fresh.

  **Response schema** (`OpticalStats`):

  ```json
  {
    "device_id":      "001141-F670L-ZTEGCFLN794B3A1",
    "tx_power_dbm":   2.5,
    "rx_power_dbm":   -21.3,
    "bias_current_ma": 12.5,
    "temperature_c":  45.0,
    "voltage_v":      3.3,
    "health":         "good",
    "source":         "zte_ct_com_epon",
    "fetched_at":     "2026-04-14T13:00:00Z"
  }
  ```

  Implementation: `optical.go` (vendor extractors + classifier +
  `refreshOpticalStats` + helpers `navigateNested`/`readFloat`).
  Tests: `optical_test.go` with fixture-based device tree samples for
  all 5 vendor paths + health classification table + helper unit
  tests + `refreshOpticalStats` partial-success path. **Manual
  validation against a real CPE is pending the first ISP pilot
  deployment** — fixtures are based on documented production samples
  but not yet hit a live device through this code path.

- New env vars (all optional, with sensible defaults):
  - `OPTICAL_RX_NO_SIGNAL_DBM` (default `-30`)
  - `OPTICAL_RX_CRITICAL_DBM` (default `-27`)
  - `OPTICAL_RX_WARNING_DBM` (default `-24`)
  - `OPTICAL_RX_OVERLOAD_DBM` (default `-8`)

- New error code: `OPTICAL_NOT_SUPPORTED` (HTTP 404) — distinguishes
  "device exists but no optical params exposed" from "device not found".

### Notes for deployers

- **No genieacs-stack changes required.** Reboot + DHCP refresh use
  standard GenieACS NBI tasks (`reboot`, `refreshObject`) that work
  out-of-the-box. Optical reading uses `getDeviceData` against the
  CPE's existing parameter tree — if the CPE exposes the parameters,
  GenieACS already has them after the next inform.
- **Optional GenieACS provisioning preset.** For deployments where
  ops want optical data auto-refreshed periodically (rather than
  on-demand via `?refresh=true`), configure a GenieACS provisioning
  preset via the GenieACS UI to fetch the relevant subtree on every
  inform — vendor-specific, not bundled with the stack. Example
  preset for ZTE CT-COM EPON:

  ```javascript
  declare("InternetGatewayDevice.X_CT-COM_EponInterfaceConfig.Stats.RxPower",
          {value: 1}, {value: now});
  ```

### Downstream unblock

With these endpoints live, isp-agent v0.2+ can add:
- `RestartOnu` workflow → `POST /reboot/{ip}`
- `RefreshDhcpStatus` workflow → `POST /dhcp/{ip}/refresh`
- New `GetOpticalHealth` workflow → `GET /optical/{ip}` (read-only,
  same shape as existing `GetDeviceCapability`)

See `~/Projects/isp-agent/TODO.md` Phase 6 backlog.

## [2.0.0] — 2026-04-12

**First standardized release**, aligned with [`isp-adapter-standard`][adapter-std] and
[`isp-logging-standard`][logging-std]. **Fourth compliant adapter** overall (after
[freeradius-api] v1.2.0, [go-snmp-olt-zte-c320] v3.0.0, and [write-olt-zte-c320-svc] v3.0.0).
Serves as the **chi + request-level idempotency reference** for bridge adapters.

> **Versioning note:** this is a MAJOR version bump from v1.0.1 because the JSON
> response envelope shape changed in a way that forces clients to update. Sister
> adapters (`freeradius-api`, `go-snmp-olt-zte-c320`, `write-olt-zte-c320-svc`)
> carry their own independent semver tracks — their v3.0.0 does NOT imply v3.0.0
> here. Going forward, all releases must follow
> [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) strictly —
> see [`CONTRIBUTING.md`](CONTRIBUTING.md#versioning-policy) for the full rules.

### BREAKING

Response envelope shape changed. Clients parsing the old `{"status":"OK","error":"..."}` shape
MUST update to the new `{"status":"success"|"Bad Request","error_code":"...","data":...,"request_id":"..."}`
format.

| Before (v1.x)                                    | After (v2.0.0)                                                       |
|--------------------------------------------------|----------------------------------------------------------------------|
| `{"status":"OK", ...}`                           | `{"status":"success", ...}`                                          |
| `{"error":"message"}`                            | `{"error_code":"VALIDATION_ERROR","data":"message","request_id":"..."}` |
| `sendError(w, code, status, errorMsg)`           | `sendError(w, r, code, errorCode, data)` — takes `*http.Request`     |
| `sendResponse(w, code, status, data)`            | `sendResponse(w, code, data)` — status auto-set to `"success"`       |
| `Response.Error string`                          | `Response.ErrorCode string` + `Response.Data any` + `Response.RequestID string` |

Error code constants are defined in `error_codes.go`: `VALIDATION_ERROR`, `UNAUTHORIZED`,
`FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `TIMEOUT`, `RATE_LIMITED`, `INTERNAL_ERROR`,
`SERVICE_UNAVAILABLE`, `GENIEACS_ERROR`.

### Added

- **`/healthz`** — Kubernetes liveness probe (minimal `{"status":"healthy"}`).
- **`/readyz`** and **`/ready`** — readiness probes with cached (5s TTL) GenieACS reachability check.
  Returns 503 + per-dependency state when GenieACS is unreachable.
- **`/version`** — build metadata endpoint (`version`, `commit`, `build_time`, `api_version`, `uptime`).
- **`/metrics`** — Prometheus exposition format with `http_requests_total`,
  `http_request_duration_seconds`, `http_requests_in_flight`, and default Go runtime collectors.
- **`X-API-Version`**, **`X-App-Version`**, **`X-Build-Commit`** response headers on every response.
- **`X-Request-ID`** correlation header — extracted from chi's `middleware.RequestID`, injected
  into every zap log line via `WithRequestIDLogger(ctx)`, echoed in error response bodies,
  and available to all handlers via `RequestIDFromContext(ctx)`.
- **`X-Idempotency-Key`** support on all `POST/PUT/PATCH/DELETE` endpoints under `/api/v1/genieacs/*`.
  First request with a given key is executed and its response cached; retries with the
  same key within a 7-day TTL replay the cached response. In-memory store (`MemoryStore`);
  migrate to Redis in v2.1 if multi-replica dedup is needed.
- **Audit log sub-logger** via `logger.Named("audit")` emits one JSON line per write request
  (POST/PUT/PATCH/DELETE) with `method`, `path`, `status`, `client_ip`, `user_agent`,
  `duration_ms`, and `body_size`.
- **Centralized zap logger** with standardized base fields (`service`, `version`, `module`).
  ISO8601 UTC timestamps with millisecond precision.
- **`VersionResponse`**, **`ReadinessResponse`**, and **`DependencyState`** model types for
  health endpoints.
- **`buildinfo.go`** package with `setBuildInfo()` setter and ldflags-injected version accessors.
- **`reqctx.go`** leaf-package style context key for the request ID, used by both the logger
  and the error envelope.
- **`.golangci.yml` v2** configuration with 20+ linters enabled, mirroring the v3.0.0 reference
  adapters. Baseline was 0 after fixing 20 pre-existing issues.
- **`CLAUDE.md`**, **`test.http`**, **`k6-load-test.js`** — AI assistant context, REST Client
  smoke test suite, and k6 load test scenarios.
- **Multi-arch Docker**: `linux/amd64`, `linux/arm64`, `linux/arm/v7` (was amd64+arm64 in 2.x).
- **Trivy image scan** in CI (best-effort; fails build on CRITICAL/HIGH, SARIF upload
  `continue-on-error: true` to tolerate repos without GitHub Advanced Security).
- **`APP_VERSION` + `APP_COMMIT` + `APP_BUILD_TIME`** Docker build args propagated from CI
  into ldflags. Verify with `curl /version` after a real Docker build.

### Fixed

- **Alpine base image security upgrade (CVE-2026-28390)** — Trivy image scan on
  the post-merge edge build flagged 2 HIGH vulnerabilities in the alpine 3.21 base
  (`libcrypto3`/`libssl3` 3.3.6-r0 — openssl NULL pointer dereference in CMS,
  fixed in 3.3.7-r0). Added `apk update && apk upgrade --no-cache` as the first
  step of the production stage so every rebuild picks up the latest patched
  packages from the live alpine 3.21 repo without needing to chase minor base
  image bumps. Local Trivy rescan after fix: **0 CRITICAL / 0 HIGH**. This fix
  is included in the `v2.0.0` git tag (commit `317f15c`) so all published
  `v2.0.0` Docker images already ship with the patched packages.
- **`refreshDHCP` / `refreshWLANConfig` rejected HTTP 202 Accepted** — both functions
  checked `resp.StatusCode != http.StatusOK` which caused `/dhcp-client?refresh=true`
  and `/force/ssid` refresh path to always return 500 whenever GenieACS returned a
  202 (which it does for every `?connection_request` task even when the task is
  successfully queued). Fixed to accept any `status < 400` as success. Discovered
  during real-device integration testing on ZTE F670L with live genieacs-stack;
  prior CI tests mocked the HTTP response and never hit the real 202 case.
- **ldflags injection silently broken** — Dockerfile previously used
  `-X main.version=${VERSION:-dev}` where `VERSION` was never declared as an `ARG`,
  so shell expansion always emitted `dev`. Fixed via explicit `ARG APP_VERSION`,
  `ARG APP_COMMIT`, `ARG APP_BUILD_TIME` and target vars `version`/`commit`/`buildTs`
  in `main.go` (lowercase to match `go build -X`).
- **Request ID never reached zap logs** — chi's `middleware.RequestID` was in the
  middleware chain but its generated ID was not extracted into our logger context.
  New `requestIDMiddleware` bridges the chi value into `reqctx` so every log line
  and error body now carries `request_id`.
- **20 pre-existing lint issues** (errorlint, gocritic httpNoBody, prealloc, whitespace,
  gofmt, nestingReduce, goconst, gosec false positives) resolved as part of the v2
  baseline. Required because the stricter `.golangci.yml` v2 config would otherwise
  block CI from day one.

### Changed

- **Go 1.26.1 → 1.26.2**.
- **chi v5.2.3 → v5.2.5**.
- **go-openapi/jsonpointer 0.22.4 → 0.22.5**, **spec 0.22.3 → 0.22.4**.
- `healthCheckHandler` now emits the standard `Response` envelope (was ad-hoc).
- `middleware.Logger` replaced with `structuredLoggerMiddleware` which emits zap JSON
  with `request_id`, `duration_ms`, and `size_bytes`, and skips `/health`, `/healthz`,
  `/ready`, `/readyz`, `/version`, `/metrics` from request logs.

### Known gaps

- **`MemoryStore` does not survive restart** and is not shared across replicas.
  Acceptable for single-instance site deployments; v2.1 should add a Redis-backed
  store when the genieacs-relay container runs in a multi-replica k8s Deployment.
- **State-aware idempotency is deliberately NOT implemented** for WLAN ops. Request-level
  caching is sufficient because GenieACS itself dedupes tasks per-device and WLAN
  ops are not strictly destructive the way SSH DeleteOnu is.
- **Not yet validated against billing-agent end-to-end** — billing-agent is still in
  design phase, so the full saga workflow (NATS COMMAND → agent → genieacs-relay →
  task queued → device inform → response back) has not been exercised. The adapter
  surface itself was validated against a real ZTE F670L with the full genieacs-stack
  running locally (see Integration Test Results below).

### Integration Test Results (2026-04-12)

Full end-to-end test against real hardware:
- **Target device**: ZTE F670L (ID `C6B2D2-F670L-ZTEEQFLN6212992`) at `10.90.4.173`
- **Upstream**: `genieacs-stack` running locally (GenieACS 1.2.16 + MongoDB 8.0)
- **Relay binary**: v2.0.0-integration, ldflags-injected

**96/96 assertions passed** across 18 HTTP endpoints, 0 failures:

| Phase | Tests | Highlights |
|---|---|---|
| Phase 1 — unauth + reads + errors + idempotency | 55 | All 7 public endpoints, 5 authenticated reads, 5 error contract probes, 2 idempotency replay tests |
| Phase 2 — CREATE on fresh slot + verify | 14 | WLAN.3 `Enable:false→true`, `SSID:SSID3→FullTestCreate3`, 8 setParameterValues params all queued correctly |
| Phase 3a — UPDATE + OPTIMIZE + verify | 10 | `SSID:FullTestCreate3→FullTestUpdate3`, `TransmitPower:→60`, all post-inform state changes verified |
| Phase 3b — DELETE + verify | 8 | `Enable:true→false` confirmed via direct GenieACS NBI query + relay `/wlan/available` re-query |
| Post-bug-fix regression | 5 | `/dhcp-client?refresh=true` + `/force/ssid` 5x consecutive success (was 0/5 before fix) |
| Corrections | 4 | |

**Full CRUD lifecycle verified on real device**: each mutation was confirmed by
1) reading the task queue in GenieACS NBI directly, 2) waiting for the device's
next periodic inform, 3) re-querying device state in GenieACS to confirm the
parameter actually changed on the device, and 4) re-querying via the relay's
own read endpoints to confirm the change is visible end-to-end.

### Compliance Status

- [x] JSON response format (success + error + paginated)
- [x] Error responses include `error_code`, `request_id`
- [x] Success uses `status:"success"`
- [x] `/health`, `/healthz`, `/ready`, `/readyz`, `/version`, `/metrics` endpoints
- [x] `/readyz` with cached dependency probes (5s TTL)
- [x] `X-Request-ID` middleware (extract/generate/echo in body)
- [x] `X-API-Version`, `X-App-Version`, `X-Build-Commit` response headers
- [x] Input validation via `go-playground/validator`
- [x] Rate limiting middleware (in-memory; Redis-backed in v2.1 when multi-instance)
- [x] CORS middleware
- [x] Audit log for write ops via `logger.Named("audit")`
- [x] Prometheus `/metrics` with normalized path labels
- [x] ldflags injection verified via `curl /version` against local build
- [x] `X-Idempotency-Key` middleware (request-level, in-memory)
- [x] Multi-arch Docker (amd64/arm64/arm/v7)
- [x] zap logging with `service`, `version`, `module`, `request_id` base fields
- [x] **Test coverage: 100.0%** (baseline match)
- [x] `golangci-lint` v2 clean, `govulncheck` clean, `go test -race` clean
- [x] Trivy image scan clean: 0 CRITICAL, 0 HIGH (after post-merge apk upgrade fix)

### Release Timeline

| Date (UTC) | Commit | Event |
|---|---|---|
| 2026-04-12 13:11 | `7d0b303` | PR #2 (v2.0.0 feat) squashed → `main` |
| 2026-04-12 13:48 | `317f15c` | PR #3 (Dockerfile apk upgrade, CVE-2026-28390) squashed → `main` |
| 2026-04-12 13:56 | `317f15c` | **Tag `v2.0.0` created and pushed** |
| 2026-04-12 14:00 | — | GitHub Release `v2.0.0` published |
| 2026-04-12 14:09 | `8704e46` | PR #4 (examples/ version pins to 2.0.0) squashed → `main` (post-release docs) |

### Docker Images Published

**Docker Hub:** `cepatkilatteknologi/genieacs-relay`
**GHCR:** `ghcr.io/cepat-kilat-teknologi/genieacs-relay`

Published tags (both registries):
- `2.0.0`
- `2.0`
- `2`
- `latest`
- `edge` (built from `main`)

Multi-arch: `linux/amd64`, `linux/arm64`, `linux/arm/v7`.

```bash
# Production pin
docker pull cepatkilatteknologi/genieacs-relay:2.0.0

# Verify
docker run --rm -p 8080:8080 cepatkilatteknologi/genieacs-relay:2.0.0 &
curl -s localhost:8080/version
# {"version":"2.0.0","commit":"317f15c",...}
```

### Helm Chart

Chart `genieacs-relay v0.2.0` (appVersion `2.0.0`) auto-released by the `Helm Chart Release` workflow when `examples/helm/genieacs-relay/Chart.yaml` was updated in PR #4.

[adapter-std]: https://github.com/Cepat-Kilat-Teknologi/knowledge-base/blob/main/wiki/isp-adapter-standard.md
[logging-std]: https://github.com/Cepat-Kilat-Teknologi/knowledge-base/blob/main/wiki/isp-logging-standard.md
[freeradius-api]: https://github.com/Cepat-Kilat-Teknologi/freeradius-api
[go-snmp-olt-zte-c320]: https://github.com/Cepat-Kilat-Teknologi/go-snmp-olt-zte-c320
[write-olt-zte-c320-svc]: https://github.com/Cepat-Kilat-Teknologi/write-olt-zte-c320

## [2.x] and earlier

See git history for pre-standardization releases.
