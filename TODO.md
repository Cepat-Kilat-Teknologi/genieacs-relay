# TODO — Agent Integration Readiness

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
