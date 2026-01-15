# ACS API Gateway

[![ci](https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Cepat-Kilat-Teknologi/acs-api-gateway/graph/badge.svg?token=Q0XLKG2ZPE)](https://codecov.io/gh/Cepat-Kilat-Teknologi/acs-api-gateway)

A lightweight **API Gateway** for managing devices via **GenieACS**, built with **Go**.
This service provides endpoints for retrieving and updating device SSID, WiFi passwords, and DHCP clients.

---

## Features

- Built in **Go (Golang)** with clean architecture
- **100% test coverage** with race condition detection
- Dockerized with **multi-stage builds** (development, builder, production)
- Supports **Docker Compose** for both development and production
- **Caching** for device data with configurable TTL
- **Worker pool** for asynchronous task processing
- API Endpoints:
    - Get / Update SSID
    - Get SSID with Force Refresh (retry mechanism)
    - Post / Refresh SSID Data
    - Update WiFi Password
    - Get DHCP Clients
    - Clear Cache

---

## Project Structure

```bash
.
├── main.go              # Application entry point and core logic
├── constants.go         # All constants (paths, timeouts, messages)
├── models.go            # Data structures and navigation helpers
├── handlers.go          # HTTP handler helper functions
├── main_test.go         # Unit tests for main
├── constants_test.go    # Unit tests for constants
├── models_test.go       # Unit tests for models
├── handlers_test.go     # Unit tests for handlers
├── Dockerfile           # Multi-stage build (dev, builder, production)
├── Makefile             # Development, testing, Docker, and CI helper
├── docker-compose.yml   # Local development environment
├── docker-compose.prod.yml # Production deployment
├── go.mod               # Go module dependencies
├── go.sum
├── .env.example         # Environment variables template
├── .gitignore           # Git ignore rules
└── README.md            # Documentation
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GENIEACS_BASE_URL` | No | `http://localhost:7557` | GenieACS server URL |
| `NBI_AUTH_KEY` | **Yes** | *(empty)* | Authentication key for GenieACS NBI |
| `SERVER_ADDR` | No | `:8080` | Server listen address |
| `MIDDLEWARE_AUTH` | No | `false` | Enable API key authentication for incoming requests |
| `AUTH_KEY` | Conditional | *(empty)* | API key for authenticating incoming requests (required if `MIDDLEWARE_AUTH=true`) |
| `STALE_THRESHOLD_MINUTES` | No | `30` | Time in minutes after which a device is considered stale |

> **Security Warning**: Never commit `.env` files with real credentials. Use `.env.example` as a template.

### Stale Device Validation

When querying devices by IP address, the API validates whether the device has recently reported to GenieACS using the `_lastInform` timestamp. This helps prevent returning data for devices that may have been disconnected and their IP reassigned to another device.

**How it works:**
1. When a device is queried by IP, the API checks the `_lastInform` timestamp from GenieACS
2. If the device hasn't reported within the threshold (default: 30 minutes), it's considered "stale"
3. Stale devices return an error with details about when the device was last seen

**Configuration:**
- Set `STALE_THRESHOLD_MINUTES` to adjust the threshold (in minutes)
- Set to `0` to disable stale device validation

**Example error response for stale device:**
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "device with IP 10.90.14.41 is stale (last seen: 45 minutes ago). The IP may have been reassigned to another device"
}
```

### API Authentication

By default, the API Gateway does **not** require authentication for incoming requests. To enable API key authentication:

1. Set `MIDDLEWARE_AUTH=true` in your `.env` file
2. Set `AUTH_KEY` to your desired API key value
3. Include the `X-API-Key` header in all requests to `/api/v1/genieacs/*` endpoints

**Note:** The `/health` endpoint does **not** require authentication, even when `MIDDLEWARE_AUTH=true`.

---

## Development

### Prerequisites
- [Go 1.21+](https://go.dev/)
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

### 1. Clone Repository
```bash
git clone https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway.git
cd acs-api-gateway
```

### 2. Setup Environment
```bash
make setup
```

This will:
- Copy `.env.example` to `.env`
- Create required directories (`bin/`, `test-results/`, `tmp/`)

### 3. Configure Environment
Edit `.env` file with your configuration:
```bash
GENIEACS_BASE_URL=http://your-genieacs-server:7557
NBI_AUTH_KEY=your-secret-key-here
```

### 4. Run Locally
```bash
make run
```

Or with Docker Compose:
```bash
make up
```

### 5. Run Tests
```bash
make test            # Run all tests
make test-coverage   # Run with coverage analysis
make test-html       # Generate HTML coverage report
```

---

## Makefile Commands

```bash
ACS API Gateway Management Makefile

Usage:
  make [target]

First, setup environment:
  make setup           Copy .env.example to .env and setup environment
  make env-copy        Copy .env file only

Local Development:
  make build           Build binary for local execution
  make run             Build and run application locally
  make dev             Run with hot-reload (Air)
  make tidy            Tidy go.mod dependencies

Testing:
  make test            Run all tests
  make test-race       Run tests with race detector
  make test-coverage   Run tests with coverage analysis
  make test-html       Generate HTML coverage report
  make test-bench      Run benchmark tests
  make test-vet        Run go vet for static analysis

Docker Development:
  make up              Start development environment with Docker Compose
  make up-d            Start development environment in detached mode
  make down            Stop development environment
  make logs            View development logs
  make restart         Restart development containers

Docker Production:
  make prod-up         Start production environment
  make prod-down       Stop production environment
  make logs-prod       View production logs
  make prod-restart    Restart production containers

Docker Image Management:
  make docker-build    Build production Docker image (single arch)
  make docker-push     Build and push single arch image to registry
  make docker-buildx   Build multi-architecture Docker image
  make docker-pushx    Build and push multi-arch image to registry
  make docker-clean    Clean up Docker resources

Code Quality:
  make lint            Run golangci-lint
  make format          Format Go code
  make check-deps      Check for outdated dependencies
  make check-deps-install Install dependency checking tools

Utilities:
  make healthcheck     Check if application is healthy
  make clean           Remove build artifacts
  make clean-all       Clean everything including Docker
  make help            Show this help message
```

---

## API Usage

> **Note:** The `X-API-Key` header in the examples below is **only required** when `MIDDLEWARE_AUTH=true`. If authentication is disabled (default), you can omit the header.

### Health Check

```bash
curl http://localhost:8080/health | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "status": "healthy"
  }
}
```

---

### GET SSID

```bash
# With authentication enabled (MIDDLEWARE_AUTH=true)
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/ssid/10.90.8.164" | jq

# Without authentication (MIDDLEWARE_AUTH=false, default)
curl "http://localhost:8080/api/v1/genieacs/ssid/10.90.8.164" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": [
    {
      "wlan": "1",
      "ssid": "MyHomeWiFi_2.4G",
      "password": "SuperSecretPassword",
      "band": "2.4GHz"
    },
    {
      "wlan": "5",
      "ssid": "MyHomeWiFi_5G",
      "password": "AnotherPassword",
      "band": "5GHz"
    }
  ]
}
```

**Password Display Behavior:**
| Condition | Display Value |
|-----------|---------------|
| Password available | Actual password (e.g., `SuperSecretPassword`) |
| Password encrypted (field exists but empty) | `******` |
| Password field not found | `N/A` |

---

### GET SSID with Force Refresh

This endpoint automatically triggers a refresh if WLAN data is not available and retries until data is found or timeout.

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/force/ssid/10.90.8.164" | jq
```

**Optional Query Parameters:**
- `max_retries` - Maximum number of retry attempts (default: 12)
- `retry_delay_ms` - Delay between retries in milliseconds (default: 5000)

**Example with custom parameters:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/force/ssid/10.90.8.164?max_retries=5&retry_delay_ms=2000" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "attempts": 2,
    "wlan_data": [
      {
        "wlan": "1",
        "ssid": "MyHomeWiFi_2.4G",
        "password": "SuperSecretPassword",
        "band": "2.4GHz"
      }
    ]
  }
}
```

---

### Trigger SSID Refresh

```bash
curl -X POST -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/ssid/10.90.8.164/refresh" | jq
```

**Response:**
```json
{
  "code": 202,
  "status": "Accepted",
  "data": {
    "message": "Refresh task submitted. Please query the GET endpoint again after a few moments."
  }
}
```

---

### Update SSID

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/ssid/update/1/10.90.8.164" \
  -H "Content-Type: application/json" \
  -d '{"ssid": "New_SSID_Name"}' | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "SERIAL-NUMBER-XYZ",
    "ip": "10.90.8.164",
    "message": "SSID update submitted successfully",
    "ssid": "New_SSID_Name",
    "wlan": "1"
  }
}
```

---

### Update Password

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/password/update/1/10.90.8.164" \
  -H "Content-Type: application/json" \
  -d '{"password": "NewSecurePassword123"}' | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "SERIAL-NUMBER-XYZ",
    "ip": "10.90.8.164",
    "message": "Password update submitted successfully",
    "wlan": "1"
  }
}
```

---

### GET DHCP Clients

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.8.164" | jq
```

**With refresh:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.8.164?refresh=true" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": [
    {
      "mac": "AA:BB:CC:11:22:33",
      "hostname": "Johns-iPhone",
      "ip": "192.168.1.100"
    },
    {
      "mac": "DD:EE:FF:44:55:66",
      "hostname": "Living-Room-TV",
      "ip": "192.168.1.102"
    }
  ]
}
```

---

### Clear Cache

Clear cache for specific device:
```bash
curl -X POST -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/cache/clear?device_id=DEVICE-ID-HERE" | jq
```

Clear all cache:
```bash
curl -X POST -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/cache/clear" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "message": "Cache cleared"
  }
}
```

---

## Common Error Responses

### 401 Unauthorized (when MIDDLEWARE_AUTH=true)
```json
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Missing X-API-Key header"
}
```

```json
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Invalid API key"
}
```

### 400 Bad Request
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password value required"
}
```

### 404 Not Found
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "device not found with IP: 10.90.200.100"
}
```

### 408 Request Timeout
```json
{
  "code": 408,
  "status": "Timeout",
  "error": "Operation timed out while retrieving WLAN data"
}
```

### 500 Internal Server Error
```json
{
  "code": 500,
  "status": "Internal Server Error",
  "error": "Could not verify WLAN status."
}
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway/blob/main/LICENSE) file for details.