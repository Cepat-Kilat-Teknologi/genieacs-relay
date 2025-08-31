# ACS API Gateway

[![ci](https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Cepat-Kilat-Teknologi/acs-api-gateway/graph/badge.svg?token=Q0XLKG2ZPE)](https://codecov.io/gh/Cepat-Kilat-Teknologi/acs-api-gateway)

A lightweight **API Gateway** for managing devices via **GenieACS**, built with **Love**.  
This service provides endpoints for retrieving and updating device SSID, WiFi passwords, and DHCP clients.

---

## 🚀 Features
- Built in **Go (Golang)**
- Dockerized with **multi-stage builds** (development, builder, production)
- Supports **Docker Compose** for both development and production
- API Endpoints:
    - Get / Update SSID
    - Post / Refresh SSID Data
    - Update WiFi Password
    - Get DHCP Clients

---

## 📂 Project Structure

```bash
.
├── Dockerfile # Multi-stage build (dev, builder, production)
├── Makefile # Development, testing, Docker, and CI helper
├── docker-compose.yml # Local development environment
├── docker-compose.prod.yml # Production deployment
├── go.mod # Go module dependencies
├── go.sum
├── main.go # Application entry point
├── main_test.go # Unit tests
└── README.md # Documentation
```
---
## 🛠️ Development

### Prerequisites
- [Go](https://go.dev/)
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)


### 1. Clone Repository
```bash
git clone https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway.git
cd acs-api-gateway
```

### 2. Setup
```bash
make setup
```

#### This will:
- Copy .env.template to .env
- Create required directories (bin/, test-results/, tmp/)

### 3. Run Locally
```bash
make run
```
or with Docker Compose:
```bash
make up
```

### 4. Run tests
```bash
make test
make test-coverage
make test-html
```

### For Information on Makefile commands
```bash
ACS API Gateway Management Makefile

Usage:
  make [target]

First, setup environment:
  make setup           Copy .env.template to .env and setup environment
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
## 📡 API Usage

## GET SSID

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
"http://localhost:8080/api/v1/genieacs/ssid/10.90.8.164" | jq
```
### Response (when not yet available)

```bash
{
  "code": 200,
  "status": "OK",
  "data": null
}
```
### Trigger SSID Refresh

```bash
curl -X POST -H "X-API-Key: YourSecretGatewayAPI_Key" \
"http://localhost:8080/api/v1/genieacs/ssid/10.90.8.164/refresh" | jq
```

### Refresh Response
```bash
{
  "code": 202,
  "status": "Accepted",
  "data": {
    "message": "Refresh task submitted. Please query the GET endpoint again after a few moments."
  }
}
```

### Re-query GET SSID

```bash
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

### Update SSID

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
-X PUT "http://localhost:8080/api/v1/genieacs/ssid/update/1/10.90.8.164" \
-H "Content-Type: application/json" \
-d '{"ssid": "New_SSID_Name"}' | jq
```

### Response SSID Update

```bash
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

### Update Password

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
-X PUT "http://localhost:8080/api/v1/genieacs/password/update/1/10.90.8.164" \
-H "Content-Type: application/json" \
-d '{"password": "NewSecurePassword123"}' | jq
```

### Response Password Update

```bash
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

## GET DHCP Clients

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
"http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.8.164" | jq
```

### Successful Response Get DHCP Clients

```bash
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

## ❌ Common Error Responses

### 400 Bad Request

```bash
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password value required"
}
```
### 401 Unauthorized

```bash
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Invalid API Key"
}
```
### 404 Not Found

```bash
{
  "code": 404,
  "status": "Not Found",
  "error": "device not found with IP: 10.90.200.100"
}
```

## 📜 License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/Cepat-Kilat-Teknologi/acs-api-gateway/blob/main/LICENSE) file for details.
