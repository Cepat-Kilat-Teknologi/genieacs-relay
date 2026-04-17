# TODO — genieacs-relay roadmap

## v2.2.0 — auto-learn OLT support ✅ RELEASE-READY 2026-04-15 (tag pending)

**Status (2026-04-15):** ✅ **RELEASE-READY.** Code + tests
+ real-device verification + docs + wiki all complete. The only
outstanding work is the explicit `git tag v2.2.0` command (pending
user instruction per repo convention) and CI-triggered Docker
multi-arch build + GitHub release that the tag push automatically
fires.

### Shipped

- [x] **Structural foundations** — `tr069.go` (generic TR-069
      RPC dispatcher: factoryReset / connectionRequest /
      getParameterValuesLive / downloadFile / addObject / deleteObject
      + `validateTRParamPath` input sanitizer) + `param_walker.go`
      (typed accessors over `map[string]interface{}`: `LookupValue`,
      `LookupString`, `LookupInt`, `LookupBool`, `LookupTime`,
      `EnumerateInstances`, `CollectPaths`). 100% coverage.
- [x] **HIGH-priority endpoints (7)** — factory-reset, wake, status, wan,
      params, pppoe, firmware). 100% coverage. `handlers_lifecycle.go`,
      `handlers_inspection.go`, `handlers_pppoe.go`, `handlers_firmware.go`.
- [x] **MEDIUM-priority endpoints (8)** — diag/ping, diag/traceroute,
      wifi-clients, wifi-stats, devices list, devices search, qos with
      capability probe, bridge-mode). 100% coverage. `handlers_diag.go`,
      `handlers_devices.go`, `handlers_qos_bridge.go`, + append to
      `handlers_inspection.go` for M3+M7.
- [x] **LOW-priority endpoints (10)** — port-forwarding, dmz, ddns,
      wifi-schedule, mac-filter, static-dhcp, ntp, admin-password,
      tags, presets CRUD). 100% coverage. `handlers_admin.go`,
      `handlers_dmz_ddns.go`, `handlers_portforward.go`,
      `handlers_static_dhcp.go`, `handlers_wifi_advanced.go`,
      `handlers_genieacs_meta.go`.
- [x] **F670L real-device hardening** — optical `extractZTEWanPon()`
      sixth vendor extractor, `wlan/available` `provisioned_wlan[]`
      enrichment, QoS 501 capability probe, `refreshObject` trailing-
      dot sanitation. Commit `0ff2e0e`. 11 new unit tests.
- [x] **F670L real-device sweep** — 38 endpoints fully
      exercised end-to-end + 1 correct 501 (QoS) + 6 validator-wired
      empty-body probes, 2 safety-skipped (reboot + factory-reset).
- [x] **Close the 2 safety-skipped items** — reboot and
      factory-reset E2E verified on the same F670L. Reboot HTTP 202
      + ping drop T+32s + recovery T+7:24 (6:52 total downtime — see
      slow-boot anomaly note below). Factory-reset HTTP 202 + ping
      drop T+11s + recovery T+1:45 (1:34 total downtime, within
      spec) + PASS via 4 independent evidence vectors (downtime
      signature delta vs reboot, credential drift post-recovery,
      clean task queue, documented timing envelope). Real-device
      sweep final: **40/40 endpoints E2E verified**.
- [x] **100% main-package coverage maintained** across the full
      feature set plus hardening. 0 lint issues. Race detector clean.
- [x] **CHANGELOG promoted** `[Unreleased]` → `[2.2.0]` with date +
      real-device verification block at top + stale TODO footer
      replaced with a proper retrospective release checklist.
- [x] **README v2.2.0 release banner** + full v2.2.0 feature section.
- [x] **Wiki sync** — `~/Projects/knowledge-base/wiki/genieacs-relay.md`
      frontmatter bumped (`version: v2.2.0-dev` → `v2.2.0`,
      `git_state: unreleased_committed` → `release_ready`, phase
      text updated), real-device verification narrative added, versioning
      track table extended with v2.2.0 row.
- [x] **TODO this file** — v2.2.0 shipped section added (this block).

### Pending (outside scope of the docs-update pass)

- [ ] **`swag init` regen + commit** `docs/swagger.json` + `docs/swagger.yaml`
      — optional: annotations are already in-source, regen only
      updates the generated artifacts for Swagger UI. Safe to defer
      to the first post-v2.2.0 patch.
- [ ] **`git tag v2.2.0`** — **pending explicit user instruction**.
      Repo convention: no push / tag without explicit request.
- [ ] **Docker multi-arch build** `cepatkilatteknologi/genieacs-relay:{2.2.0, 2.2, 2, latest}`
      + `ghcr.io/cepat-kilat-teknologi/genieacs-relay:{same}` —
      **CI-triggered automatically** by the `release.yml` workflow on
      tag push. No manual step.
- [x] **Helm chart appVersion bump** `examples/helm/genieacs-relay/Chart.yaml`
      — chart `version: 0.3.0` → `0.4.0` + `appVersion: "2.1.0"` →
      `"2.2.0"`. Companion chart release is auto-published by the
      `helm-release.yml` workflow when the chart file changes (same
      pattern as v2.0.0 chart `v0.2.0` release auto-publish). Done
      in the release-prep commit.
- [ ] **GitHub release publish** — auto-triggered by tag push via
      `release.yml` workflow. No manual step.

### Known issues / notes for v2.2.1 patch

- **Reboot docstring under-states worst-case budget.** Real-device
  verification observed 6:52 total downtime on ZTE F670L V9.0.10P1N12A, well
  outside the 30-90s spec in the `rebootDevice` docstring. Update
  docstring to "30-90s typical, up to ~7 minutes on some ZTE F670L
  firmware revisions under specific lab conditions" and bump the
  `RestartOnu` workflow retry timeout guidance in the isp-agent
  TODO accordingly. Defer to v2.2.1 to keep v2.2.0 bit-identical
  to the pre-verification main-branch build.
- **Customer-facing factory-reset workflow blocker**
  `genieacs-stack v1.3.1` inform-provision fix. Relay code is
  correct; do not release `isp-agent v0.2.0` `FactoryResetCpe`
  workflow wiring until `genieacs-stack v1.3.1` ships. Tracked
  upstream in `~/Projects/genieacs-stack`.

---

## v2.1.0 — CPE lifecycle operations + optical health ✅ RELEASED 2026-04-15

**Status (2026-04-15):** ✅ **SHIPPED.** All items complete. Tag `v2.1.0`
pushed, CI release workflow green (Docker multi-arch + GitHub release +
codecov 100% on main package). Post-release hardening commit `8a66b64`
closed the remaining coverage gaps (3 new handlers + optical + reboot
transport + loadOpticalThresholdConfig parse error branch) bringing
main-package coverage from 97.0% to 100.0% via `-coverpkg` scoping.

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
- [x] **2.1.4** `CHANGELOG.md [2.1.0]` + this `TODO.md` + `CLAUDE.md`
      outstanding-work note + `.env.example` with new optical
      threshold env vars + `README.md` v2.1.0 feature section +
      `API_REFERENCE.md` §14-16 full endpoint documentation.
- [x] **2.1.5** Tests pass, lint clean (0 issues), vulncheck clean
      (0 vulnerabilities).
- [x] **2.1.6** Tag `v2.1.0` pushed, CI release workflow green —
      Docker image published to
      `cepatkilatteknologi/genieacs-relay:2.1.0` (multi-arch) +
      GitHub release published at
      `https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/releases/tag/v2.1.0`.
- [x] **2.1.7** (post-release hardening) main-package coverage
      closed to **100.0%** via `test(v2.1.0): close coverage gaps`
      commit. `docs/docs.go` (auto-generated swagger) excluded from
      coverage scope via `-coverpkg`.

**Original v2.1.0 spec preserved below for historical reference / merge
review context.**

---

## v2.1.0 — CPE lifecycle operations (PLANNED, original spec)

Triggered by **isp-agent v0.1.0** workflow-integration milestone — the Temporal worker
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
      in a later isp-agent roadmap milestone, pin this version)

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
