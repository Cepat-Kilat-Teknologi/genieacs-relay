![GenieACS Relay Logo](assets/LOGO.png)

# GenieACS Relay

[![CI](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Cepat-Kilat-Teknologi/genieacs-relay/graph/badge.svg?token=Q0XLKG2ZPE)](https://codecov.io/gh/Cepat-Kilat-Teknologi/genieacs-relay)
[![Go Reference](https://pkg.go.dev/badge/github.com/Cepat-Kilat-Teknologi/genieacs-relay.svg)](https://pkg.go.dev/github.com/Cepat-Kilat-Teknologi/genieacs-relay)
[![Go Report Card](https://goreportcard.com/badge/github.com/Cepat-Kilat-Teknologi/genieacs-relay)](https://goreportcard.com/report/github.com/Cepat-Kilat-Teknologi/genieacs-relay)

A lightweight **Relay** for managing devices via **GenieACS**, built with **Go**.
This service provides endpoints for retrieving and updating device SSID, WiFi passwords, and DHCP clients.

---

## Documentation

- [Installation & Configuration](INSTALLATION.md) - Setup, environment variables, and deployment
- [Security](SECURITY.md) - Authentication, rate limiting, and security features
- [ONU Models](ONU.md) - Supported ONU/ONT device models
- [Contributing](CONTRIBUTING.md) - How to contribute to this project
- [API Reference](API_TEST.md) - Complete API endpoint examples and documentation

### Testing Documentation

- [Single-Band Test Results](TEST_RESULT_SINGLEBAND.md) - Test results for 2.4GHz only devices
- [Dual-Band Test Results](TEST_RESULT_DUALBAND.md) - Test results for 2.4GHz + 5GHz devices
- [test_singleband.http](test_singleband.http) - HTTP test file for single-band devices
- [test_dualband.http](test_dualband.http) - HTTP test file for dual-band devices

---

## Features

- Built in **Go (Golang)** with clean architecture
- Dockerized with **multi-stage builds** (development, builder, production)
- **Swagger/OpenAPI** documentation with interactive UI
- **Caching** for device data with configurable TTL
- **Worker pool** for asynchronous task processing
- **ONU/ONT Band Detection** - Automatic detection of single-band and dual-band devices
- **API Key Authentication** - Protect sensitive endpoints with API keys
- **Cross-band Validation** - Prevent cross-band SSID/password updates

### Security Features

- **Brute Force Protection** - Automatic IP lockout after failed attempts
- **Rate Limiting** - Configurable per-IP rate limiting
- **Audit Logging** - Security event logging
- **Security Headers** - HSTS, CSP, X-Frame-Options
- **Input Validation** - Strict validation for all inputs

See [SECURITY.md](SECURITY.md) for details.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/genieacs/ssid/{ip}` | Get SSID by device IP |
| GET | `/api/v1/genieacs/force/ssid/{ip}` | Get SSID with force refresh |
| POST | `/api/v1/genieacs/ssid/{ip}/refresh` | Trigger SSID refresh |
| GET | `/api/v1/genieacs/dhcp-client/{ip}` | Get DHCP clients |
| GET | `/api/v1/genieacs/capability/{ip}` | Get device capability |
| GET | `/api/v1/genieacs/wlan/available/{ip}` | Get available WLAN slots |
| POST | `/api/v1/genieacs/wlan/create/{wlan}/{ip}` | Create new WLAN |
| PUT | `/api/v1/genieacs/wlan/update/{wlan}/{ip}` | Update WLAN |
| DELETE | `/api/v1/genieacs/wlan/delete/{wlan}/{ip}` | Delete/disable WLAN |
| PUT | `/api/v1/genieacs/wlan/optimize/{wlan}/{ip}` | Optimize WLAN radio |
| POST | `/api/v1/genieacs/cache/clear` | Clear cache |

---

## Quick Start

### Using Docker (Recommended)

```bash
docker pull cepatkilatteknologi/genieacs-relay:latest

docker run -d \
  -p 8080:8080 \
  -e GENIEACS_BASE_URL=http://your-genieacs:7557 \
  cepatkilatteknologi/genieacs-relay:latest
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
├── API_TEST.md             # API reference documentation
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

### Health Check

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
  "status": "OK",
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
  "status": "OK",
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

| Code | Status | Description |
|------|--------|-------------|
| 400 | Bad Request | Invalid input parameters |
| 401 | Unauthorized | Missing or invalid API key |
| 404 | Not Found | Device or WLAN not found |
| 408 | Timeout | Operation timed out |
| 409 | Conflict | WLAN already exists |
| 429 | Too Many Requests | Rate limit or brute force protection |
| 500 | Internal Server Error | Server-side error |

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
