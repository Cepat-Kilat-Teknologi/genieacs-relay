# Installation & Configuration

This document covers installation, configuration, and development setup for GenieACS Relay.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)
- [Running the Application](#running-the-application)
- [Makefile Commands](#makefile-commands)
- [Swagger Documentation](#swagger-documentation)

---

## Prerequisites

- [Go 1.24+](https://go.dev/)
- [Docker](https://www.docker.com/) (optional)
- [Docker Compose](https://docs.docker.com/compose/) (optional)

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/Cepat-Kilat-Teknologi/genieacs-relay.git
cd genieacs-relay

# Setup environment
make setup

# Configure (edit .env file)
nano .env

# Run locally
make run

# Or run with Docker
make up
```

---

## Environment Variables

### Server Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SERVER_ADDR` | No | `:8080` | Server listen address |
| `GENIEACS_BASE_URL` | No | `http://localhost:7557` | GenieACS server URL |
| `NBI_AUTH_KEY` | **Yes** | *(empty)* | Authentication key for GenieACS NBI |

### Authentication

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MIDDLEWARE_AUTH` | No | `false` | Enable API key authentication |
| `AUTH_KEY` | Conditional | *(empty)* | API key for incoming requests (required if `MIDDLEWARE_AUTH=true`) |

### CORS Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | No | `*` | Allowed origins (`*` for all, or comma-separated list) |
| `CORS_MAX_AGE` | No | `86400` | Preflight cache duration in seconds (24 hours) |

### Rate Limiting

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RATE_LIMIT_REQUESTS` | No | `100` | Maximum requests per window |
| `RATE_LIMIT_WINDOW` | No | `60` | Rate limit window in seconds |

### Device Validation

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STALE_THRESHOLD_MINUTES` | No | `30` | Time in minutes after which a device is considered stale |

> **Security Warning**: Never commit `.env` files with real credentials. Use `.env.example` as a template.

---

## Configuration Examples

### Development (Permissive)

```bash
# .env
GENIEACS_BASE_URL=http://localhost:7557
NBI_AUTH_KEY=your-genieacs-key
CORS_ALLOWED_ORIGINS=*
MIDDLEWARE_AUTH=false
```

### Production (Restrictive)

```bash
# .env
GENIEACS_BASE_URL=http://genieacs:7557
NBI_AUTH_KEY=your-secure-genieacs-key
CORS_ALLOWED_ORIGINS=https://myapp.com,https://admin.myapp.com
MIDDLEWARE_AUTH=true
AUTH_KEY=your-secure-api-key
RATE_LIMIT_REQUESTS=50
RATE_LIMIT_WINDOW=30
STALE_THRESHOLD_MINUTES=15
```

---

## Running the Application

### Local Development

```bash
# Build and run
make run

# Run with hot-reload (requires Air)
make dev
```

### Docker Compose (Development)

```bash
# Start with logs
make up

# Start in background
make up-d

# View logs
make logs

# Stop
make down
```

### Docker Compose (Production)

See [example/docker/README.md](example/docker/README.md) for detailed Docker deployment guide.

```bash
# Quick start with example config
cd example/docker
cp .env.example .env
nano .env  # Configure your settings
docker compose up -d
```

Or using Makefile from project root:

```bash
# Start production
make prod-up

# View logs
make logs-prod

# Stop
make prod-down
```

### Testing

```bash
# Run all tests
make test

# Run with race detector
make test-race

# Run with coverage analysis
make test-coverage

# Generate HTML coverage report
make test-html
```

---

## Makefile Commands

```
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

Swagger Documentation:
  make swagger         Generate Swagger documentation
  make swagger-install Install swag CLI tool
  make swagger-fmt     Format Swagger annotations
  make swagger-clean   Remove generated Swagger docs
  make swagger-serve   Generate docs and start server

Utilities:
  make healthcheck     Check if application is healthy
  make clean           Remove build artifacts
  make clean-all       Clean everything including Docker
  make help            Show this help message
```

---

## Swagger Documentation

This project includes interactive API documentation using **Swagger/OpenAPI**.

### Accessing Swagger UI

Once the server is running, access the Swagger UI at:
```
http://localhost:8080/swagger/index.html
```

### Generating Swagger Docs

```bash
# Install swag CLI (first time only)
make swagger-install

# Generate Swagger documentation
make swagger

# Format Swagger annotations
make swagger-fmt

# Generate docs and start server
make swagger-serve
```

### Swagger Features

- **Interactive API Testing** - Test endpoints directly from the browser
- **Request/Response Examples** - See expected request formats and responses
- **Authentication Support** - Test authenticated endpoints with API key
- **Schema Documentation** - View all data models and their structures
