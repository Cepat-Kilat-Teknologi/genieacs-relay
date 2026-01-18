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

---

## Features

- Built in **Go (Golang)** with clean architecture
- Dockerized with **multi-stage builds** (development, builder, production)
- **Swagger/OpenAPI** documentation with interactive UI
- **Caching** for device data with configurable TTL
- **Worker pool** for asynchronous task processing
- **ONU/ONT Band Detection** - Automatic detection of single-band and dual-band devices

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

```
.
├── main.go                 # Application entry point
├── server.go               # HTTP server setup
├── routes.go               # Route definitions
├── handlers_*.go           # HTTP handlers
├── middleware.go           # Auth, rate limiting, CORS
├── validation.go           # Input validation
├── cache.go                # Device data caching
├── client.go               # GenieACS API client
├── worker.go               # Worker pool
├── capability.go           # Device capability detection
├── docs/                   # Swagger documentation
├── assets/                 # Static assets
├── example/
│   └── docker/             # Docker deployment example
│       ├── docker-compose.yml
│       ├── .env.example
│       └── README.md
├── Dockerfile              # Multi-stage build
└── docker-compose.yml      # Development environment
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
    {"wlan": "1", "ssid": "MyWiFi", "password": "******", "band": "2.4GHz"},
    {"wlan": "5", "ssid": "MyWiFi-5G", "password": "******", "band": "5GHz"}
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
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "model": "F670L",
    "band_type": "dualband",
    "is_dual_band": true,
    "supported_wlan": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": [5, 6, 7, 8]
    }
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

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
