![GenieACS Relay Logo](assets/LOGO.png)

# GenieACS Relay

[![CI](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Cepat-Kilat-Teknologi/genieacs-relay/graph/badge.svg?token=Q0XLKG2ZPE)](https://codecov.io/gh/Cepat-Kilat-Teknologi/genieacs-relay)
[![Go Reference](https://pkg.go.dev/badge/github.com/Cepat-Kilat-Teknologi/genieacs-relay.svg)](https://pkg.go.dev/github.com/Cepat-Kilat-Teknologi/genieacs-relay)
[![Go Report Card](https://goreportcard.com/badge/github.com/Cepat-Kilat-Teknologi/genieacs-relay)](https://goreportcard.com/report/github.com/Cepat-Kilat-Teknologi/genieacs-relay)

A lightweight **Relay** for managing devices via **GenieACS**, built with **Go**.
This service provides HTTP endpoints for CPE lifecycle operations
(reboot, DHCP refresh, optical health read), SSID/WLAN management, device
capability detection, and DHCP client retrieval — all via the GenieACS NBI.

> **v2.1.0 released 2026-04-15** — CPE lifecycle operations (reboot,
> dedicated DHCP refresh) + optical interface health (TX/RX power,
> temperature, voltage, bias current) across 5 vendor parameter paths
> (ZTE CT-COM EPON/GPON, Huawei HW_DEBUG, Realtek EPON, standard TR-181).
> 100% unit-test coverage on the main package. See
> [`CHANGELOG.md`](CHANGELOG.md) `[2.1.0]` section for full details.
>
> **v2.0.0 released 2026-04-12** — adapter aligned with
> `isp-adapter-standard` + `isp-logging-standard`, ready for integration
> with `isp-agent`. Fourth compliant adapter after `freeradius-api` v1.2.0,
> `go-snmp-olt-zte-c320` v3.0.0, and `write-olt-zte-c320-svc` v3.0.0.
> **Breaking change** in v2.0.0: response envelope shape changed
> (`status:"OK"` → `status:"success"`, error responses now include
> `error_code` + `request_id`). See
> [`CHANGELOG.md`](CHANGELOG.md) v2.0.0 section for the migration table.

---

## Documentation

- [Installation & Configuration](INSTALLATION.md) - Setup, environment variables, and deployment
- [API Reference](API_REFERENCE.md) - Complete API endpoint examples and v2 envelope contract
- [CHANGELOG](CHANGELOG.md) - v2.0.0 breaking changes and migration table
- [CLAUDE.md](CLAUDE.md) - AI assistant context + architecture notes + module map
- [Security](SECURITY.md) - Authentication, rate limiting, and security features
- [ONU Models](ONU.md) - Supported ONU/ONT device models
- [Contributing](CONTRIBUTING.md) - How to contribute, commit style, and **semantic versioning policy**

### Testing Documentation

- [test.http](test.http) - REST Client test suite (v2 envelope, real device examples)
- [k6-load-test.js](k6-load-test.js) - k6 load test scenarios (health + contract, no destructive)
- [Single-Band Test Results](TEST_RESULT_SINGLEBAND.md) - Test results for 2.4GHz only devices
- [Dual-Band Test Results](TEST_RESULT_DUALBAND.md) - Test results for 2.4GHz + 5GHz devices
- [test_singleband.http](test_singleband.http) - HTTP test file for single-band devices
- [test_dualband.http](test_dualband.http) - HTTP test file for dual-band devices

---

## Features

- Built in **Go 1.26.2** with flat package layout (no `internal/`), chi v5 router
- Dockerized with **multi-stage builds**, multi-arch (`linux/amd64`, `linux/arm64`, `linux/arm/v7`)
- **Swagger/OpenAPI** documentation with interactive UI
- **Caching** for device data with configurable TTL
- **Worker pool** for asynchronous task processing
- **ONU/ONT Band Detection** - Automatic detection of single-band and dual-band devices
- **API Key Authentication** - Protect sensitive endpoints with API keys
- **Cross-band Validation** - Prevent cross-band SSID/password updates

### v2.1.0 Features (2026-04-15)

- **`POST /reboot/{ip}`** — TR-069 Reboot RPC with `?connection_request`
  semantics. Returns `202 Accepted` when the task is submitted to the
  GenieACS NBI. Actual CPE reboot takes 30–90 seconds — callers should
  not block waiting for reconnect.
- **`POST /dhcp/{ip}/refresh`** — dedicated DHCP host cache refresh.
  Reuses the internal refresh routine but exposes it as a clean
  POST-for-side-effect primitive distinct from the read-with-refresh
  pattern of `GET /dhcp-client/{ip}?refresh=true`.
- **`GET /optical/{ip}`** — reads CPE optical interface health
  (TX/RX power dBm, temperature °C, voltage V, bias current mA) with
  automatic vendor detection across 5 parameter paths: ZTE CT-COM EPON,
  ZTE CT-COM GPON, Huawei HW_DEBUG, Realtek EPON, standard TR-181.
  Vendor-aware health classification (`no_signal` / `critical` /
  `warning` / `good` / `overload`) with env-tunable thresholds
  (`OPTICAL_RX_NO_SIGNAL_DBM`, `_CRITICAL_DBM`, `_WARNING_DBM`,
  `_OVERLOAD_DBM`). Returns `404 OPTICAL_NOT_SUPPORTED` on CPE models
  that don't expose any known optical parameter tree.
- **100% unit-test coverage** on the main package, including fixture-
  driven tests for every vendor extractor.

### v2.0.0 Standardization Features

- **Standard JSON envelope** per `isp-adapter-standard` with machine-readable `error_code`
- **`X-Request-ID` correlation** — every log line + error body carries the ID for Loki/Grafana end-to-end tracing
- **`X-Idempotency-Key`** support on write endpoints with 7-day TTL in-memory cache (safe for saga retries)
- **`X-API-Version` / `X-App-Version` / `X-Build-Commit`** response headers on every response
- **Kubernetes-ready health probes**: `/healthz` (liveness) + `/readyz` (readiness with cached GenieACS ping)
- **Prometheus metrics** at `/metrics` with chi RoutePattern labels (no cardinality explosion)
- **`/version` endpoint** with ldflags-injected build metadata
- **`zap` structured logging** with `service`, `version`, `module`, `request_id` base fields
- **Audit log sub-logger** (`logger.Named("audit")`) for all write operations
- **100% unit test coverage** + verified end-to-end against real ZTE F670L on full GenieACS stack

### Security Features

- **Brute Force Protection** - Automatic IP lockout after failed attempts
- **Rate Limiting** - Configurable per-IP rate limiting
- **Audit Logging** - Security event logging
- **Security Headers** - HSTS, CSP, X-Frame-Options
- **Input Validation** - Strict validation for all inputs

See [SECURITY.md](SECURITY.md) for details.

### API Endpoints

**Public endpoints (no authentication):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Backwards-compat liveness alias |
| GET | `/healthz` | Kubernetes liveness probe |
| GET | `/ready` / `/readyz` | Kubernetes readiness (checks GenieACS reachability) |
| GET | `/version` | Build metadata (ldflags-injected) |
| GET | `/metrics` | Prometheus exposition format |
| GET | `/swagger/*` | Interactive Swagger UI |

**Authenticated endpoints (`/api/v1/genieacs/*`):**

| Method | Endpoint | Description | Idempotent |
|--------|----------|-------------|:-:|
| GET | `/ssid/{ip}` | Get SSID configurations for device | — |
| GET | `/force/ssid/{ip}` | Get SSID with force refresh + retry loop | — |
| POST | `/ssid/{ip}/refresh` | Trigger async SSID refresh task | ✅ |
| GET | `/dhcp-client/{ip}` | Get DHCP clients (optional `?refresh=true`) | — |
| GET | `/capability/{ip}` | Get device band capability (single / dualband) | — |
| GET | `/wlan/available/{ip}` | Get available WLAN slots with configuration options | — |
| POST | `/wlan/create/{wlan}/{ip}` | Create new WLAN on slot 1-8 | ✅ |
| PUT | `/wlan/update/{wlan}/{ip}` | Update WLAN (SSID / password / auth / encryption / hidden / max_clients) | ✅ |
| DELETE | `/wlan/delete/{wlan}/{ip}` | Disable WLAN slot (soft-delete, preserves configuration) | ✅ |
| PUT | `/wlan/optimize/{wlan}/{ip}` | Optimize radio settings (channel, bandwidth, mode, transmit_power) | ✅ |
| POST | `/cache/clear` | Clear device cache (specific or all) | — |

Write endpoints honor `X-Idempotency-Key` header; repeated calls within a
7-day TTL replay the cached response without re-executing.

---

## Quick Start

### Using Docker (Recommended)

**Docker Hub:**
```bash
docker pull cepatkilatteknologi/genieacs-relay:latest
```

**GitHub Container Registry (GHCR):**
```bash
docker pull ghcr.io/cepat-kilat-teknologi/genieacs-relay:latest
```

**Run the container:**
```bash
docker run -d \
  -p 8080:8080 \
  -e GENIEACS_BASE_URL=http://your-genieacs:7557 \
  cepatkilatteknologi/genieacs-relay:latest
```

### Using Helm (Kubernetes)

```bash
# Add Helm repository
helm repo add genieacs-relay https://cepat-kilat-teknologi.github.io/genieacs-relay
helm repo update

# Install
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  --set config.genieacsBaseUrl="http://genieacs-nbi:7557"
```

### From Source

```bash
# Clone and setup
git clone https://github.com/Cepat-Kilat-Teknologi/genieacs-relay.git
cd genieacs-relay
make setup

# Configure
nano .env

# Run
make run
```

See [INSTALLATION.md](INSTALLATION.md) for detailed setup instructions.

---

## Project Structure

```text
.
├── main.go                 # Application entry point
├── config.go               # Configuration management
├── server.go               # HTTP server setup
├── routes.go               # Route definitions
├── middleware.go           # Auth, rate limiting, CORS, security headers
├── handlers_ssid.go        # SSID endpoint handlers
├── handlers_device.go      # Device/capability handlers
├── handlers_wlan.go        # WLAN CRUD & optimize handlers
├── client.go               # GenieACS NBI API client
├── models.go               # Data structures
├── validation.go           # Input validation
├── cache.go                # Device data caching with TTL
├── worker.go               # Async worker pool
├── capability.go           # Device band detection
├── wlan.go                 # WLAN helper functions
├── dhcp.go                 # DHCP client helpers
├── constants.go            # Application constants
├── response.go             # HTTP response helpers
├── utils.go                # Utility functions
├── onu_models.go           # ONU/ONT model definitions
├── *_test.go               # Unit tests
│
├── docs/                   # Swagger/OpenAPI documentation
├── assets/                 # Static assets (logo, images)
│
├── test_singleband.http    # HTTP test file for single-band devices
├── test_dualband.http      # HTTP test file for dual-band devices
├── TEST_RESULT_SINGLEBAND.md  # Single-band test results
├── TEST_RESULT_DUALBAND.md    # Dual-band test results
├── API_REFERENCE.md        # API reference documentation
│
├── examples/
│   ├── docker/             # Docker Compose deployment
│   ├── kubernetes/         # Kubernetes manifests
│   ├── helm/               # Helm chart
│   ├── systemd/            # Systemd service files
│   └── argocd/             # ArgoCD GitOps manifests
│
├── .github/workflows/      # CI/CD pipelines
├── Dockerfile              # Multi-stage Docker build
├── docker-compose.yml      # Local development
├── Makefile                # Build & dev commands
└── .env.example            # Environment template
```

---

## API Usage

> **Note:** `X-API-Key` header is only required when `MIDDLEWARE_AUTH=true`.

### Standard Response Envelope

**Success (2xx)** — always `status:"success"` with `data` as the resource payload:
```json
{ "code": 200, "status": "success", "data": { ... } }
```

**Error (4xx/5xx)** — includes `error_code` for machine handling and `request_id` for end-to-end tracing:
```json
{
  "code": 404,
  "status": "Not Found",
  "error_code": "NOT_FOUND",
  "data": "Device not found",
  "request_id": "req-abc-123"
}
```

Error codes: `VALIDATION_ERROR`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`,
`CONFLICT`, `TIMEOUT`, `RATE_LIMITED`, `INTERNAL_ERROR`, `SERVICE_UNAVAILABLE`.
See [`API_REFERENCE.md`](API_REFERENCE.md#v300-response-envelope--standard-contract) for the full contract.

### Health Check

```bash
curl http://localhost:8080/healthz
# {"code":200,"status":"success","data":{"status":"healthy"}}
```

### Readiness Check (with dependency probe)

```bash
curl http://localhost:8080/readyz
# ready:     {"status":"ready","dependencies":{"genieacs":{"state":"up"}}}
# not_ready: 503 + {"status":"not_ready","dependencies":{"genieacs":{"state":"down","error":"..."}}}
```

### Version Info

```bash
curl http://localhost:8080/version
# {"version":"2.0.0","commit":"a2a62e0","build_time":"2026-04-12T12:00:00Z","api_version":"v1","uptime":"2h15m30s"}
```

### Legacy Health Alias

```bash
curl http://localhost:8080/health
```

### Get SSID

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41"
```

**Response:**
```json
{
  "code": 200,
  "status": "success",
  "data": [
    {
      "wlan": "1",
      "ssid": "MyWiFi",
      "password": "********",
      "band": "2.4GHz",
      "hidden": false,
      "max_clients": 32,
      "auth_mode": "WPA2",
      "encryption": "AES"
    },
    {
      "wlan": "5",
      "ssid": "MyWiFi-5G",
      "password": "********",
      "band": "5GHz",
      "hidden": false,
      "max_clients": 32,
      "auth_mode": "WPA2",
      "encryption": "AES"
    }
  ]
}
```

### Get Device Capability

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/capability/10.90.14.41"
```

**Response:**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "model": "F670L",
    "band_type": "dualband",
    "is_dual_band": true
  }
}
```

### Create WLAN

```bash
curl -H "X-API-Key: YourSecretKey" \
  -H "X-Request-ID: saga-activate-01-step-2" \
  -H "X-Idempotency-Key: saga-activate-01-step-2" \
  -X POST "http://localhost:8080/api/v1/genieacs/wlan/create/2/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{
    "ssid": "GuestNetwork",
    "password": "GuestPass123",
    "hidden": false,
    "max_clients": 10,
    "auth_mode": "WPA2",
    "encryption": "AES"
  }'
```

> **Idempotency**: if the same `X-Idempotency-Key` is sent again within 7 days,
> the cached response is replayed without re-submitting the task to GenieACS.
> This makes billing-agent saga retries safe.

### Update WLAN

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"ssid": "NewNetworkName", "password": "NewPassword123"}'
```

### Delete WLAN

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X DELETE "http://localhost:8080/api/v1/genieacs/wlan/delete/2/10.90.14.41"
```

### Optimize WLAN Radio

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"channel": "6", "mode": "b/g/n", "bandwidth": "40MHz", "transmit_power": 100}'
```

### Get DHCP Clients

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.14.41"
```

### Clear Cache

```bash
# Clear all cache
curl -X POST -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/cache/clear"

# Clear specific device
curl -X POST -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/cache/clear?device_id=DEVICE-ID"
```

---

## Swagger UI

Access interactive API documentation at:
```
http://localhost:8080/swagger/index.html
```

Generate docs:
```bash
make swagger
```

---

## Common Error Responses

All error responses follow the v2 envelope with an `error_code` field for
machine-readable branching and `request_id` for end-to-end correlation:

```json
{
  "code": 404,
  "status": "Not Found",
  "error_code": "NOT_FOUND",
  "data": "Device not found",
  "request_id": "req-abc-123"
}
```

| HTTP | `error_code` | Description |
|------|---|---|
| 400 | `VALIDATION_ERROR` | Invalid input parameters |
| 401 | `UNAUTHORIZED` | Missing or invalid API key |
| 404 | `NOT_FOUND` | Device or WLAN not found |
| 408 | `TIMEOUT` | Operation timed out |
| 409 | `CONFLICT` | WLAN already exists |
| 429 | `RATE_LIMITED` | Rate limit or brute force protection |
| 500 | `INTERNAL_ERROR` | Server-side error |
| 503 | `SERVICE_UNAVAILABLE` | Worker pool saturated or upstream down |

---

## Container Registries

Images are available on both **Docker Hub** and **GitHub Container Registry (GHCR)**:

| Registry | Image |
|----------|-------|
| Docker Hub | `cepatkilatteknologi/genieacs-relay` |
| GHCR | `ghcr.io/cepat-kilat-teknologi/genieacs-relay` |

### Available Tags

We follow **semantic versioning** with multiple tag formats:

| Tag | Description | Update Behavior |
|-----|-------------|-----------------|
| `1.0.0` | Exact version (pinned) | Never changes |
| `1.0` | Minor version | Auto-updates to `1.0.x` patches |
| `1` | Major version | Auto-updates to `1.x.x` releases |
| `latest` | Latest stable | Always latest stable release |
| `edge` | Latest from main branch | Bleeding edge (may be unstable) |

**Recommended usage:**
```bash
# Production (pinned version - recommended)
docker pull cepatkilatteknologi/genieacs-relay:1.0.0

# Auto-update patches only
docker pull cepatkilatteknologi/genieacs-relay:1.0

# Auto-update minor versions
docker pull cepatkilatteknologi/genieacs-relay:1

# Using GHCR
docker pull ghcr.io/cepat-kilat-teknologi/genieacs-relay:1.0.0
```

---

## Deployment Options

| Method | Description | Guide |
|--------|-------------|-------|
| **Docker Compose** | Quick local/production setup | [examples/docker](examples/docker/) |
| **Kubernetes** | K8s manifests with Kustomize | [examples/kubernetes](examples/kubernetes/) |
| **Helm** | Helm chart for K8s | [examples/helm](examples/helm/genieacs-relay/) |
| **ArgoCD** | GitOps with auto-sync | [examples/argocd](examples/argocd/) |
| **Systemd** | Bare metal Linux service | [examples/systemd](examples/systemd/) |

See [INSTALLATION.md](INSTALLATION.md) for detailed deployment instructions.

---

## Testing

### Running Unit Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run tests with race detection
go test -race ./...
```

### API Testing with HTTP Files

This project includes HTTP test files for testing the API endpoints using VS Code REST Client or IntelliJ HTTP Client.

| Device Type | Test File | Description |
|-------------|-----------|-------------|
| Single-Band | [test_singleband.http](test_singleband.http) | Tests for 2.4GHz only devices (WLAN 1-4) |
| Dual-Band | [test_dualband.http](test_dualband.http) | Tests for 2.4GHz + 5GHz devices (WLAN 1-8) |

**Usage:**
1. Open the `.http` file in VS Code with REST Client extension
2. Update the `@deviceIP` variable with your device's IP address
3. Update the `@apiKey` variable if authentication is enabled
4. Click "Send Request" to execute each test

### Test Results Summary

| Device Type | Model | Band Type | Total Tests | Status |
|-------------|-------|-----------|-------------|--------|
| Single-Band | CDATA FD512XW-R460 | 2.4GHz | 30 | All PASS |
| Dual-Band | ZTE F670L | 2.4GHz + 5GHz | 30 | All PASS |

**Detailed Test Results:**
- [TEST_RESULT_SINGLEBAND.md](TEST_RESULT_SINGLEBAND.md) - Single-band device test results
- [TEST_RESULT_DUALBAND.md](TEST_RESULT_DUALBAND.md) - Dual-band device test results

### Test Coverage

| Category | Tests |
|----------|-------|
| Endpoint Tests | Health, SSID, DHCP, Capability, WLAN CRUD, Optimize, Cache |
| Error Handling | Validation, Invalid inputs, Cross-band validation |
| Authentication | API Key validation (when MIDDLEWARE_AUTH=true) |

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
