# GenieACS Relay

[![ci](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Cepat-Kilat-Teknologi/genieacs-relay/graph/badge.svg?token=Q0XLKG2ZPE)](https://codecov.io/gh/Cepat-Kilat-Teknologi/genieacs-relay)

A lightweight **Relay** for managing devices via **GenieACS**, built with **Go**.
This service provides endpoints for retrieving and updating device SSID, WiFi passwords, and DHCP clients.

---

## Features

- Built in **Go (Golang)** with clean architecture
- **100% test coverage** with race condition detection
- Dockerized with **multi-stage builds** (development, builder, production)
- Supports **Docker Compose** for both development and production
- **Caching** for device data with configurable TTL
- **Worker pool** for asynchronous task processing
- **ONU/ONT Band Detection** - Automatic detection of single-band (2.4GHz) and dual-band (2.4GHz + 5GHz) devices
- **WLAN Slot Management** - Track available and used WLAN slots per device
- API Endpoints:
    - Get / Update SSID
    - Get SSID with Force Refresh (retry mechanism)
    - Post / Refresh SSID Data
    - Update WiFi Password
    - Get DHCP Clients
    - Clear Cache
    - **Get Device Capability** (single-band/dual-band detection)
    - **Get Available WLAN Slots** (with configuration options)
    - **Create New WLAN** (with advanced options: hidden SSID, max clients, auth mode, encryption)
    - **Update Existing WLAN** (partial update support for SSID, password, visibility, etc.)
    - **Delete/Disable WLAN** (disable existing WLAN configuration)
    - **Optimize WLAN Radio** (channel, mode, bandwidth, transmit power settings)

---

## Project Structure

```bash
.
├── main.go              # Application entry point and core logic
├── constants.go         # All constants (paths, timeouts, messages)
├── models.go            # Data structures and navigation helpers
├── handlers.go          # HTTP handler helper functions
├── onu_models.go        # ONU/ONT model database (single-band/dual-band)
├── main_test.go         # Unit tests for main
├── constants_test.go    # Unit tests for constants
├── models_test.go       # Unit tests for models
├── handlers_test.go     # Unit tests for handlers
├── onu_models_test.go   # Unit tests for ONU models
├── test.http            # HTTP test file for API testing (VS Code REST Client)
├── ONU.md               # ONU/ONT model reference documentation
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
git clone https://github.com/Cepat-Kilat-Teknologi/genieacs-relay.git
cd genieacs-relay
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
GenieACS Relay Management Makefile

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
  "http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41" | jq

# Without authentication (MIDDLEWARE_AUTH=false, default)
curl "http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "attempts": 1,
    "wlan_data": [
      {
        "wlan": "1",
        "ssid": "5abib7",
        "password": "******",
        "band": "2.4GHz"
      },
      {
        "wlan": "5",
        "ssid": "5abib7-5G",
        "password": "******",
        "band": "5GHz"
      }
    ]
  }
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
  "http://localhost:8080/api/v1/genieacs/force/ssid/10.90.14.41" | jq
```

**Optional Query Parameters:**
- `max_retries` - Maximum number of retry attempts (default: 12)
- `retry_delay_ms` - Delay between retries in milliseconds (default: 5000)

**Example with custom parameters:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/force/ssid/10.90.14.41?max_retries=5&retry_delay_ms=2000" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "attempts": 1,
    "wlan_data": [
      {
        "wlan": "1",
        "ssid": "5abib7",
        "password": "******",
        "band": "2.4GHz"
      },
      {
        "wlan": "5",
        "ssid": "5abib7-5G",
        "password": "******",
        "band": "5GHz"
      }
    ]
  }
}
```

---

### Trigger SSID Refresh

```bash
curl -X POST -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41/refresh" | jq
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
  -X PUT "http://localhost:8080/api/v1/genieacs/ssid/update/1/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"ssid": "New_SSID_Name"}' | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
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
  -X PUT "http://localhost:8080/api/v1/genieacs/password/update/1/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"password": "NewSecurePassword123"}' | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "Password update submitted successfully",
    "wlan": "1"
  }
}
```

---

### GET DHCP Clients

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.14.41" | jq
```

**With refresh:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.14.41?refresh=true" | jq
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

### GET Device Capability

Get the wireless capability of a device (single-band or dual-band detection based on ONU model).

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/capability/10.90.14.41" | jq
```

**Response (Dual-band device):**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "model": "F670L",
    "band_type": "dualband",
    "is_dual_band": true,
    "supported_wlan": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": [5, 6, 7, 8]
    },
    "description": "Device supports both 2.4GHz (WLAN 1-4) and 5GHz (WLAN 5-8) bands"
  }
}
```

**Response (Single-band device):**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "001141-F663N-ZTEGCFAB123456",
    "model": "F663N",
    "band_type": "singleband",
    "is_dual_band": false,
    "supported_wlan": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": []
    },
    "description": "Device supports only 2.4GHz band (WLAN 1-4)"
  }
}
```

---

### GET Available WLAN Slots

Get available WLAN slots for creating new WiFi networks. Returns which slots are in use and which are available based on device capability.

```bash
curl -H "X-API-Key: YourSecretKey" \
  "http://localhost:8080/api/v1/genieacs/wlan/available/10.90.14.41" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "model": "F670L",
    "band_type": "dualband",
    "total_slots": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": [5, 6, 7, 8]
    },
    "used_wlan": [
      {
        "wlan_id": 1,
        "ssid": "MyWiFi",
        "band": "2.4GHz"
      },
      {
        "wlan_id": 5,
        "ssid": "MyWiFi-5G",
        "band": "5GHz"
      }
    ],
    "available_wlan": {
      "2_4ghz": [2, 3, 4],
      "5ghz": [6, 7, 8]
    },
    "config_options": {
      "auth_modes": ["Open", "WPA", "WPA2", "WPA/WPA2"],
      "encryptions": ["AES", "TKIP", "TKIP+AES"],
      "max_clients": {
        "min": 1,
        "max": 64,
        "default": 32
      }
    }
  }
}
```

**WLAN Slot Assignment:**
| Band | WLAN IDs | Description |
|------|----------|-------------|
| 2.4GHz | 1, 2, 3, 4 | Available for all devices |
| 5GHz | 5, 6, 7, 8 | Only available for dual-band devices |

---

### Create New WLAN

Create a new WLAN on an available slot with advanced configuration options.

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
  }' | jq
```

**Request Body Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ssid` | string | **Yes** | - | Network name (1-32 characters) |
| `password` | string | Conditional | - | WiFi password (8-63 characters). Required for WPA/WPA2 |
| `hidden` | boolean | No | `false` | Hide SSID from broadcast |
| `max_clients` | integer | No | `32` | Maximum connected devices (1-64) |
| `auth_mode` | string | No | `"WPA2"` | Authentication mode |
| `encryption` | string | No | `"AES"` | Encryption method |

**Authentication Modes:**
| Value | Description |
|-------|-------------|
| `Open` | No password required (not recommended) |
| `WPA` | WPA only |
| `WPA2` | WPA2 only (recommended) |
| `WPA/WPA2` | Mixed mode for compatibility |

**Encryption Modes:**
| Value | Description |
|-------|-------------|
| `AES` | AES encryption (recommended) |
| `TKIP` | TKIP encryption (legacy) |
| `TKIP+AES` | Mixed encryption for compatibility |

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "message": "WLAN creation submitted successfully",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "wlan": "2",
    "ssid": "GuestNetwork",
    "band": "2.4GHz",
    "ip": "10.90.14.41",
    "hidden": false,
    "max_clients": 10,
    "auth_mode": "WPA2",
    "encryption": "AES"
  }
}
```

**Error Response (WLAN already exists):**
```json
{
  "code": 409,
  "status": "Conflict",
  "error": "WLAN 2 already exists and is enabled on this device. Use the update endpoint to modify it."
}
```

**Error Response (5GHz on single-band device):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID 5 (5GHz band) is not supported on this single-band device. Use WLAN 1-4 for 2.4GHz band"
}
```

---

### Update Existing WLAN

Update an existing WLAN configuration. Supports partial updates - only include fields you want to change.

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{
    "ssid": "UpdatedNetwork",
    "password": "NewPassword123",
    "hidden": true,
    "max_clients": 20
  }' | jq
```

**Request Body Parameters (all optional):**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ssid` | string | New network name (1-32 characters) |
| `password` | string | New WiFi password (8-63 characters) |
| `hidden` | boolean | Hide/show SSID from broadcast |
| `max_clients` | integer | Maximum connected devices (1-64) |
| `auth_mode` | string | Authentication mode (Open, WPA, WPA2, WPA/WPA2) |
| `encryption` | string | Encryption method (AES, TKIP, TKIP+AES) |

**Example - Update SSID only:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"ssid": "NewNetworkName"}' | jq
```

**Example - Update password only:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"password": "NewSecurePassword"}' | jq
```

**Example - Make network hidden:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"hidden": true}' | jq
```

**Example - Change authentication mode:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_mode": "WPA/WPA2",
    "encryption": "TKIP+AES"
  }' | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "message": "WLAN update submitted successfully",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "wlan": "2",
    "band": "2.4GHz",
    "ip": "10.90.14.41",
    "updated_fields": {
      "ssid": "UpdatedNetwork",
      "password": "********",
      "hidden": true,
      "max_clients": 20
    }
  }
}
```

**Error Response (WLAN not found):**
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "WLAN 2 does not exist or is not enabled on this device"
}
```

**Error Response (No fields to update):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "no fields to update"
}
```

---

### Delete/Disable WLAN

Disable an existing WLAN configuration. This effectively "deletes" the WLAN by disabling it.

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X DELETE "http://localhost:8080/api/v1/genieacs/wlan/delete/2/10.90.14.41" | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "message": "WLAN disabled successfully",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "wlan": "2",
    "band": "2.4GHz",
    "ip": "10.90.14.41"
  }
}
```

**Error Response (WLAN not found):**
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "WLAN 2 does not exist or is already disabled on this device"
}
```

**Error Response (5GHz on single-band device):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID 5 (5GHz band) is not supported on this single-band device. Use WLAN 1-4 for 2.4GHz band"
}
```

---

### Optimize WLAN Radio

Optimize WLAN radio settings including channel, mode, bandwidth, and transmit power. Supports partial updates - only include fields you want to change.

```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{
    "channel": "6",
    "mode": "b/g/n",
    "bandwidth": "40MHz",
    "transmit_power": 100
  }' | jq
```

**Request Body Parameters (all optional):**

| Parameter | Type | Description |
|-----------|------|-------------|
| `channel` | string | WiFi channel (see valid values below) |
| `mode` | string | WiFi standard mode (see valid values below) |
| `bandwidth` | string | Channel bandwidth (see valid values below) |
| `transmit_power` | integer | Transmit power percentage: 0, 20, 40, 60, 80, 100 |

**Valid Values for 2.4GHz Band (WLAN 1-4):**

| Parameter | Valid Values |
|-----------|--------------|
| Channel | `Auto`, `1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, `9`, `10`, `11`, `12`, `13` |
| Mode | `b`, `g`, `n`, `b/g`, `g/n`, `b/g/n` |
| Bandwidth | `20MHz`, `40MHz`, `Auto` |

**Valid Values for 5GHz Band (WLAN 5-8):**

| Parameter | Valid Values |
|-----------|--------------|
| Channel | `Auto`, `36`, `40`, `44`, `48`, `52`, `56`, `60`, `64`, `149`, `153`, `157`, `161` |
| Mode | `a`, `n`, `ac`, `a/n`, `a/n/ac` |
| Bandwidth | `20MHz`, `40MHz`, `80MHz`, `Auto` |

**Example - Set channel only (2.4GHz):**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"channel": "6"}' | jq
```

**Example - Set auto channel:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"channel": "Auto"}' | jq
```

**Example - Set mode and bandwidth (5GHz):**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/optimize/5/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "a/n/ac",
    "bandwidth": "80MHz"
  }' | jq
```

**Example - Reduce transmit power:**
```bash
curl -H "X-API-Key: YourSecretKey" \
  -X PUT "http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41" \
  -H "Content-Type: application/json" \
  -d '{"transmit_power": 60}' | jq
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "message": "WLAN optimization submitted successfully",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "wlan": "1",
    "band": "2.4GHz",
    "ip": "10.90.14.41",
    "updated_settings": {
      "channel": "6",
      "mode": "b/g/n",
      "bandwidth": "40MHz",
      "transmit_power": 100
    }
  }
}
```

**Error Response (Invalid channel):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid channel '99' for 2.4GHz band. Valid channels: Auto, 1-13"
}
```

**Error Response (Invalid mode):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid mode 'xyz' for 2.4GHz band. Valid modes: b, g, n, b/g, g/n, b/g/n"
}
```

**Error Response (No fields provided):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "at least one optimization field must be provided (channel, mode, bandwidth, or transmit_power)"
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

This project is licensed under the MIT License. See the [LICENSE](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/blob/main/LICENSE) file for details.