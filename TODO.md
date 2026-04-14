# TODO — genieacs-relay roadmap

## v2.1.0 — CPE lifecycle operations + optical health (DONE on main, awaiting tag)

**Status (2026-04-14):** all 3 endpoints implemented + tested + lint
clean + vulncheck clean. Merged on main via PR (TBD). Awaiting explicit
`git tag v2.1.0` + Docker push to ship.

- [x] **2.1.1** `POST /api/v1/genieacs/reboot/{ip}` — CPE reboot via
      TR-069 Reboot RPC. `reboot.go` + handler + route + tests.
- [x] **2.1.2** `POST /api/v1/genieacs/dhcp/{ip}/refresh` — dedicated
      DHCP host cache refresh endpoint. Reuses existing `refreshDHCP()`,
      new handler + route, idempotency-cached.
- [x] **2.1.3** `GET /api/v1/genieacs/optical/{ip}` — read CPE optical
      interface health metrics (TX/RX power, temperature, voltage,
      bias current). Auto-detects vendor parameter tree (ZTE CT-COM
      EPON/GPON, Huawei HW_DEBUG, Realtek EPON, standard TR-181).
      `?refresh=true` for guaranteed-fresh reads. Configurable health
      thresholds via env vars. Manual validation against real CPE
      pending first ISP pilot deployment.
- [x] **2.1.4** Updated `CHANGELOG.md` `[Unreleased]` section + this
      `TODO.md` + `CLAUDE.md` outstanding-work note + `.env.example`
      with new optical threshold env vars.
- [x] **2.1.5** Tests pass, lint clean (0 issues), vulncheck clean
      (0 vulnerabilities).
- [ ] **2.1.6** Tag `v2.1.0` + push Docker image to
      `cepatkilatteknologi/genieacs-relay:2.1.0` + create GitHub
      release notes. Awaits explicit instruction.

**Original v2.1.0 spec preserved below for historical reference / merge
review context.**

---

## v2.1.0 — CPE lifecycle operations (PLANNED, original spec)

Triggered by **isp-agent v0.1.0** Phase 2 completion — the Temporal worker
needs these endpoints to orchestrate full CPE management workflows.
None of these exist in v2.0.0 yet.

**Requested by:** `isp-agent` maintainer, 2026-04-13.
**Related:** `~/Projects/isp-agent/TODO.md` §v1 completion (TerminateCustomer,
ChangeOnu, RefreshDhcp, RestartOnu workflows).

### 2.1.1 Add `POST /api/v1/genieacs/reboot/{ip}` endpoint — CPE reboot

**Use case:** remote reboot customer modem via TR-069 `Reboot` RPC.
Support operator uses this when CPE is stuck but physically reachable.

**Current state:** TR-069 protocol supports `Reboot` RPC and GenieACS NBI
exposes it via `POST /devices/{id}/tasks` with `{"name": "reboot"}`.
genieacs-relay has NO handler or internal function for this yet.

**Scope:**
- [ ] New internal function `rebootDevice(ctx, deviceID) error` in
      `device.go` or new `reboot.go`. Sends `POST /devices/{id}/tasks?connection_request`
      with JSON body `{"name": "reboot"}` to the GenieACS NBI.
- [ ] Handle 202 Accepted (queued async) and 200 OK (applied synchronously)
      the same way as existing `refreshDHCP` function — both are success,
      only 4xx/5xx are errors.
- [ ] New handler `rebootDeviceHandler(w, r)` that parses `{ip}` from URL
      path, resolves device ID via `resolveDeviceID(ctx, ip)` (reuse existing
      helper), calls `rebootDevice`, returns the standard JSON envelope.
- [ ] Register route inside `server.go` `/api/v1/genieacs` group:
      ```go
      r.Post("/reboot/{ip}", rebootDeviceHandler)
      ```
- [ ] Apply `idempotencyMiddleware` (reuse existing). TTL 5 min — reboots
      should be deduplicated if operator double-clicks.
- [ ] Audit log entry with `operation: "reboot_cpe"`.
- [ ] Structured log fields: `device_id`, `ip`, `operation: "reboot_cpe"`,
      `duration_ms`, `request_id`.

**Tests:**
- [ ] `handlers_device_test.go` (or new `handlers_reboot_test.go`):
      - happy path → 200 with success envelope
      - device not found → 404 NOT_FOUND
      - GenieACS NBI 5xx → 500 with upstream message
      - idempotency key replay → same response from cache
- [ ] `client_test.go`: unit test `rebootDevice` with httptest
      server stubbing GenieACS NBI (happy + error paths)
- [ ] Coverage ≥95% maintained

**Notes:**
- TR-069 reboot is async. HTTP call to genieacs-relay returns as soon as
  GenieACS queues the task (fast, <1s). Actual CPE reboot takes 30-90
  seconds before the modem reconnects. The workflow on the isp-agent
  side treats this as fire-and-forget — a follow-up `RefreshDhcp`
  workflow can poll status if verification is needed.
- Authentication: apply existing `apiKeyAuthMiddleware` + idempotency
  middleware same as other `/api/v1/genieacs/*` endpoints.

**Effort estimate:** ~1-2 hours (endpoint + test + docs).

### 2.1.2 Explicit `POST /api/v1/genieacs/dhcp/{ip}/refresh` endpoint

**Use case:** isp-agent `RefreshDhcp` workflow needs a dedicated trigger
endpoint. Currently `refreshDHCP()` is only called indirectly from
`GET /dhcp-client/{ip}` when the cache is stale, which is a side effect
of a read operation — not a clean "force refresh" primitive.

**Scope:**
- [ ] New handler `refreshDHCPHandler(w, r)` that parses `{ip}`,
      resolves device ID, calls existing `refreshDHCP(ctx, deviceID)`,
      returns success envelope. No return body beyond `{"refreshed": true}`.
- [ ] Register route: `r.Post("/dhcp/{ip}/refresh", refreshDHCPHandler)`
- [ ] Apply idempotency middleware, TTL 5 min.
- [ ] Reuse existing `refreshDHCP()` internal function — no changes to
      `dhcp.go` needed.
- [ ] Tests: happy path, not found, upstream error, idempotency replay.
- [ ] Audit log with `operation: "refresh_dhcp"`.

**Why a dedicated endpoint** (instead of reusing `GET /dhcp-client/{ip}`):
- Semantics clarity — workflow is intentionally triggering a refresh,
  not fetching data.
- Idempotency key scoping — write operations (POST) get dedup cache
  treatment via existing middleware.
- API cleanliness — follows POST-for-side-effects convention.
- Audit log gets the right operation name.

**Effort estimate:** ~30 minutes (endpoint + test + docs).

### 2.1.3 (optional) `POST /api/v1/genieacs/factory-reset/{ip}` — CPE factory reset

**Use case:** last-resort action when CPE is stuck in a bad config state
and even `reboot` doesn't fix it. Forces TR-069 `FactoryReset` RPC which
clears all CPE configuration including WLAN credentials.

**Scope:** similar to reboot endpoint. TR-069 supports `FactoryReset` RPC
via GenieACS NBI task `{"name": "factoryReset"}`.

**Caveats:**
- **DESTRUCTIVE** — wipes customer WLAN configuration. Follow-up workflow
  must re-provision the CPE (re-set SSID, password, VLAN).
- Should require admin-level auth in production. For v2.1.0 just same
  API key as other endpoints — v2.2.0 can add role-based auth.
- Audit log with `operation: "factory_reset_cpe"`, flag as sensitive.

**Effort estimate:** ~1 hour (endpoint + test + docs + safety notes).

**Deferred to v2.2.0** unless isp-agent explicitly needs it in v0.1.0
(currently out of scope per `isp-agent/TODO.md`).

### 2.1.4 Update API_REFERENCE.md + Swagger + CHANGELOG

- [ ] Document new endpoints with request/response examples.
- [ ] Regenerate Swagger spec (`make swagger`).
- [ ] Add CHANGELOG v2.1.0 section listing the new endpoints and
      migration notes (none — additive changes only).

### 2.1.5 Release v2.1.0

- [ ] Tag `v2.1.0`
- [ ] Push Docker image to Docker Hub (`cepatkilatteknologi/genieacs-relay:2.1.0`)
- [ ] GitHub release notes
- [ ] Update isp-agent docker-compose to pin `2.1.0` image tag
      (currently builds from sibling source — when moved to image pulls
      in Phase 5 of isp-agent roadmap, pin this version)

### Exit criteria

```
[ ] POST /api/v1/genieacs/reboot/{ip} endpoint live and tested
[ ] POST /api/v1/genieacs/dhcp/{ip}/refresh endpoint live and tested
[ ] Both endpoints authenticated + idempotent
[ ] Audit log entries for reboot + refresh_dhcp operations
[ ] Structured logs include device_id, ip, operation, duration_ms, request_id
[ ] govulncheck: 0 vulnerabilities
[ ] golangci-lint: 0 issues
[ ] Tests: ≥95% coverage maintained
[ ] Swagger regenerated
[ ] CHANGELOG v2.1.0 section added
[ ] Docker image pushed to cepatkilatteknologi/genieacs-relay:2.1.0
[ ] GitHub release created
```

### Downstream unblock

Once v2.1.0 ships, `isp-agent` can add:
- `RestartOnu` workflow (calls `POST /reboot/{ip}`)
- `RefreshDhcp` workflow (calls `POST /dhcp/{ip}/refresh`)

Both workflows are already scoped in `~/Projects/isp-agent/TODO.md` but
blocked on this v2.1.0 release.

---

# Historical — v2.0.0 Agent Integration Readiness

> **STATUS: COMPLETED in v2.0.0 (2026-04-12).**
> All items below were resolved on the `feature/v3-standardization` branch.
> See `CHANGELOG.md` v2.0.0 section for the full diff and `CLAUDE.md` for the
> updated architecture notes. This file is retained as a historical record.

Standardization tasks agar genieacs-relay siap diintegrasikan dengan billing-agent.
Reference format: freeradius-api v1.2.0.

## Priority 1: Response Format Standardization

### 1.1 Add `error_code` field to error responses
- **File:** `response.go`, `models.go`
- **Current:** `{"code":400, "status":"Bad Request", "error":"message"}`
- **Target:** `{"code":400, "status":"Bad Request", "error_code":"VALIDATION_ERROR", "data":"message"}`
- **Tasks:**
  - [ ] Add `ErrorCode` field to Response struct (`models.go`)
  - [ ] Add `Data` field (rename `error` → `data` for consistency with freeradius-api)
  - [ ] Define error code constants: `VALIDATION_ERROR`, `NOT_FOUND`, `CONFLICT`, `INTERNAL_ERROR`, `SERVICE_UNAVAILABLE`
  - [ ] Update `sendError()` in `response.go` to accept error code
  - [ ] Update all handler calls to `sendError()` with appropriate error code
  - [ ] Update swagger annotations for new response format
  - [ ] Update tests

### 1.2 Standardize success response field
- **Current:** `{"code":200, "status":"OK", "data":{...}}`
- **Target:** `{"code":200, "status":"success", "data":{...}}`
- **Tasks:**
  - [ ] Change status string from HTTP reason ("OK") to "success" for 2xx responses
  - [ ] Update `sendResponse()` in `response.go`
  - [ ] Update tests

## Priority 2: Logging Standardization

Reference: `~/Projects/architecture-isp-app/docs/LOGGING.md`

### 2.0 Standardize log schema per LOGGING.md
- **Files:** `main.go`, `config.go`, all handler/service files
- **Current:** zap.NewProduction() — sudah JSON, tapi belum lengkap
- **Tasks:**
  - [ ] Centralize logger init di `logger.go` (saat ini inline di `config.go`)
  - [ ] Add required base fields: `service`, `version`, `module`
  - [ ] Add `WithRequestID(ctx)` helper function
  - [ ] Ensure ISO8601 UTC timestamps dengan ms precision
  - [ ] Rename keys to snake_case (audit existing camelCase if any)
  - [ ] Add `_ms` suffix untuk semua duration fields
  - [ ] Use `_bytes` suffix untuk semua size fields
  - [ ] Use standard field names: `username`, `groupname`, `ip`, `device_id`, `operation`
  - [ ] Error logs must include `error`, `error_code`, `operation`
  - [ ] Skip logging for `/health`, `/healthz`, `/readyz`, `/metrics` endpoints
  - [ ] Audit log middleware untuk POST/PUT/DELETE operations
  - [ ] Mask sensitive fields (`api_key`, `password`, `token`)

## Priority 3: Request ID / Correlation Tracing

### 3.1 Propagate X-Request-ID to structured logs
- **File:** `middleware.go`, all handlers
- **Current:** chi middleware.RequestID generates ID but not used in zap logs
- **Tasks:**
  - [ ] Extract request ID from chi context in logging middleware
  - [ ] Add `zap.String("request_id", ...)` to all structured log entries
  - [ ] Include `request_id` field in error responses
  - [ ] Include `request_id` in audit log entries (`AuditLog`, `AuditLogWithFields`)

### 3.2 Forward X-Request-ID to GenieACS calls
- **File:** `client.go`
- **Current:** HTTP calls to GenieACS do not include request ID
- **Tasks:**
  - [ ] Accept `context.Context` with request ID in client methods
  - [ ] Set `X-Request-ID` header on outbound GenieACS HTTP requests
  - [ ] Log request ID in GenieACS call debug logs

## Priority 4: Health Endpoints

### 4.1 Add `/healthz` endpoint (liveness)
- **Current:** `/health` exists, returns `{"status":"healthy"}`
- **Tasks:**
  - [ ] Rename or alias `/health` → `/healthz` (keep `/health` as alias)
  - [ ] Ensure minimal response: `{"status":"healthy"}`

### 4.2 Add `/readyz` endpoint (readiness)
- **Current:** Does not exist
- **Tasks:**
  - [ ] Add `GET /readyz` endpoint (unauthenticated, outside `/api/v1/`)
  - [ ] Check GenieACS connectivity (HTTP ping to `GENIEACS_BASE_URL`)
  - [ ] Response: `{"status":"ready", "genieacs":"connected"}` or 503 if unreachable
  - [ ] Update Dockerfile healthcheck to use `/healthz`

## Priority 5: Idempotency

### 5.1 Add idempotency for async WLAN operations
- **File:** `worker.go`, `handlers_wlan.go`
- **Current:** WLAN create/update/delete submitted to worker pool without dedup
- **Tasks:**
  - [ ] Accept `X-Idempotency-Key` header on POST/PUT/DELETE endpoints
  - [ ] Check idempotency store (in-memory map with TTL, atau Redis jika tersedia)
  - [ ] Return cached response if operation already completed
  - [ ] Store result after successful operation
  - [ ] TTL: 1 hour (WLAN operations are infrequent)

## Priority 6: Dependencies & Security

### 6.1 Update dependencies
- **Tasks:**
  - [ ] `go get -u github.com/go-chi/chi/v5` (v5.2.3 → v5.2.5)
  - [ ] `go get -u github.com/go-openapi/jsonpointer` (v0.22.4 → v0.22.5)
  - [ ] `go get -u github.com/go-openapi/spec` (v0.22.3 → v0.22.4)
  - [ ] `go mod tidy`
  - [ ] Run `govulncheck ./...`

### 6.2 golangci-lint v2 config
- **Tasks:**
  - [ ] Update `.golangci.yml` to v2 format (add `version: "2"`)
  - [ ] Verify `make lint` passes with 0 issues

## Priority 7: Documentation

### 7.1 Update API_REFERENCE.md
- [ ] Document new response format with `error_code`
- [ ] Document `X-Request-ID` header behavior
- [ ] Document `/healthz` and `/readyz` endpoints
- [ ] Document idempotency key usage

### 7.2 Regenerate Swagger
- [ ] `make swagger` after response format changes
- [ ] Verify swagger UI reflects new format

### 7.3 Update CHANGELOG.md
- [ ] Add standardization changes under new version

---

## Acceptance Criteria

All items must pass before billing-agent can integrate:

```
[ ] Error responses include error_code field
[ ] Success responses use status:"success"
[ ] X-Request-ID propagated to logs and GenieACS calls
[ ] /healthz and /readyz endpoints functional
[ ] WLAN async operations are idempotent
[ ] govulncheck: 0 vulnerabilities
[ ] golangci-lint: 0 issues
[ ] Tests: 100% coverage maintained
[ ] Swagger: regenerated and up to date
```

## Reference

- freeradius-api v1.2.0 response format: `pkg/httputil/response.go`, `pkg/httputil/error_codes.go`
- Billing agent design spec: `~/Projects/billing-agent/docs/specs/2026-04-12-billing-agent-design.md`
- Wiki: [[module-planning]] — full prerequisites checklist
