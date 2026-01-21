# Installation & Configuration

This document covers installation, configuration, and deployment options for GenieACS Relay.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Container Registries](#container-registries)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)
- [Deployment Options](#deployment-options)
  - [Local Development](#local-development)
  - [Docker Compose](#docker-compose)
  - [Kubernetes](#kubernetes)
  - [Helm Chart](#helm-chart)
  - [ArgoCD (GitOps)](#argocd-gitops)
  - [Systemd (Bare Metal)](#systemd-bare-metal)
- [Makefile Commands](#makefile-commands)
- [Swagger Documentation](#swagger-documentation)

---

## Prerequisites

- [Go 1.24+](https://go.dev/) (for local development)
- [Docker](https://www.docker.com/) (for containerized deployment)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (for Kubernetes deployment)
- [Helm 3.0+](https://helm.sh/) (for Helm deployment)

---

## Container Registries

Images are published to both **Docker Hub** and **GitHub Container Registry (GHCR)**:

| Registry | Image | Pull Command |
|----------|-------|--------------|
| Docker Hub | `cepatkilatteknologi/genieacs-relay` | `docker pull cepatkilatteknologi/genieacs-relay:1.0.0` |
| GHCR | `ghcr.io/cepat-kilat-teknologi/genieacs-relay` | `docker pull ghcr.io/cepat-kilat-teknologi/genieacs-relay:1.0.0` |

### Image Tags (Semantic Versioning)

We publish multiple tags for each release following semantic versioning:

| Tag | Example | Description | Use Case |
|-----|---------|-------------|----------|
| `X.Y.Z` | `1.0.0` | Exact version (immutable) | Production - pinned deployments |
| `X.Y` | `1.0` | Minor version | Auto-receive patch updates (1.0.1, 1.0.2) |
| `X` | `1` | Major version | Auto-receive minor updates (1.1.0, 1.2.0) |
| `latest` | - | Latest stable release | Development/testing |
| `edge` | - | Latest from main branch | Bleeding edge (unstable) |

**Recommended for Production:**
```bash
# Use exact version for reproducible deployments
docker pull cepatkilatteknologi/genieacs-relay:1.0.0

# Or use GHCR
docker pull ghcr.io/cepat-kilat-teknologi/genieacs-relay:1.0.0
```

**For Development/Staging:**
```bash
# Auto-update to latest patch
docker pull cepatkilatteknologi/genieacs-relay:1.0

# Or latest stable
docker pull cepatkilatteknologi/genieacs-relay:latest
```

---

## Quick Start

### Option 1: Using Docker (Fastest)

```bash
# Pull from Docker Hub
docker pull cepatkilatteknologi/genieacs-relay:latest

# Or pull from GHCR
docker pull ghcr.io/cepat-kilat-teknologi/genieacs-relay:latest

# Run
docker run -d \
  -p 8080:8080 \
  -e GENIEACS_BASE_URL=http://your-genieacs:7557 \
  cepatkilatteknologi/genieacs-relay:latest

# Verify
curl http://localhost:8080/health
```

### Option 2: Using Helm (Kubernetes)

```bash
# Add Helm repository
helm repo add genieacs-relay https://cepat-kilat-teknologi.github.io/genieacs-relay
helm repo update

# Install
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  --set config.genieacsBaseUrl="http://genieacs-nbi:7557"

# Verify
kubectl get pods -n genieacs
```

### Option 3: From Source

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

# Or run with Docker Compose
make up
```

---

## Environment Variables

### Server Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SERVER_ADDR` | No | `:8080` | Server listen address |
| `GENIEACS_BASE_URL` | No | `http://localhost:7557` | GenieACS server URL |

### NBI Authentication (GenieACS API)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NBI_AUTH` | No | `false` | Enable NBI authentication for GenieACS API calls |
| `NBI_AUTH_KEY` | Conditional | *(empty)* | Authentication key for GenieACS NBI (required if `NBI_AUTH=true`) |

### API Authentication (Incoming Requests)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MIDDLEWARE_AUTH` | No | `false` | Enable API key authentication for incoming requests |
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
NBI_AUTH=false
CORS_ALLOWED_ORIGINS=*
MIDDLEWARE_AUTH=false
```

### Production (Restrictive)

```bash
# .env
GENIEACS_BASE_URL=http://genieacs:7557
NBI_AUTH=true
NBI_AUTH_KEY=your-secure-genieacs-key
CORS_ALLOWED_ORIGINS=https://myapp.com,https://admin.myapp.com
MIDDLEWARE_AUTH=true
AUTH_KEY=your-secure-api-key
RATE_LIMIT_REQUESTS=50
RATE_LIMIT_WINDOW=30
STALE_THRESHOLD_MINUTES=15
```

---

## Deployment Options

### Local Development

```bash
# Build and run
make run

# Run with hot-reload (requires Air)
make dev

# Run tests
make test
```

### Docker Compose

See [examples/docker/README.md](examples/docker/README.md) for detailed guide.

```bash
# Quick start
cd examples/docker
cp .env.example .env
nano .env  # Configure your settings
docker compose up -d

# Or using Makefile from project root
make up        # Development
make prod-up   # Production
```

**Docker Commands:**

```bash
make up          # Start development environment
make up-d        # Start in background
make down        # Stop environment
make logs        # View logs
make prod-up     # Start production
make prod-down   # Stop production
```

### Kubernetes

See [examples/kubernetes/README.md](examples/kubernetes/README.md) for detailed guide.

```bash
cd examples/kubernetes

# Edit secret with your keys
nano secret.yaml

# Deploy with Kustomize
kubectl apply -k .

# Or deploy manually
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

**Verify deployment:**

```bash
kubectl get pods -n genieacs
kubectl get svc -n genieacs
kubectl port-forward -n genieacs svc/genieacs-relay 8080:80
curl http://localhost:8080/health
```

**Available manifests:**

| File | Description |
|------|-------------|
| `namespace.yaml` | Namespace definition |
| `configmap.yaml` | Environment configuration |
| `secret.yaml` | API keys (basic) |
| `sealed-secret.yaml` | Encrypted secrets (GitOps) |
| `external-secret.yaml` | External secret manager integration |
| `deployment.yaml` | Application deployment |
| `service.yaml` | ClusterIP service |
| `ingress.yaml` | Ingress resource |
| `hpa.yaml` | Horizontal Pod Autoscaler |
| `pdb.yaml` | Pod Disruption Budget |
| `networkpolicy.yaml` | Network policies |

### Helm Chart

See [examples/helm/genieacs-relay/README.md](examples/helm/genieacs-relay/README.md) for detailed guide.

#### Install from Helm Repository (Recommended)

```bash
# Add the GenieACS Relay Helm repository
helm repo add genieacs-relay https://cepat-kilat-teknologi.github.io/genieacs-relay
helm repo update

# Search available versions
helm search repo genieacs-relay --versions

# Install latest version
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  --set config.genieacsBaseUrl="http://genieacs-nbi:7557"

# Install specific version
helm install my-relay genieacs-relay/genieacs-relay \
  --version 1.0.0 \
  -n genieacs --create-namespace

# Install with custom values file
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  -f my-values.yaml
```

#### Install from Local Source

```bash
cd examples/helm

# Validate chart
helm lint genieacs-relay

# Preview manifests
helm template my-release genieacs-relay

# Install from local
helm install genieacs-relay ./genieacs-relay \
  -n genieacs --create-namespace \
  --set config.nbiAuth.key="your-nbi-key"
```

#### Using GHCR Image with Helm

To use the GHCR image instead of Docker Hub:

```bash
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  --set image.repository="ghcr.io/cepat-kilat-teknologi/genieacs-relay" \
  --set image.tag="1.0.0"
```

**Example values.yaml:**

```yaml
replicaCount: 3

# Use GHCR instead of Docker Hub (optional)
image:
  repository: ghcr.io/cepat-kilat-teknologi/genieacs-relay
  tag: "1.0.0"  # Use specific version for production

config:
  genieacsBaseUrl: "http://genieacs-nbi:7557"
  nbiAuth:
    enabled: true
    key: "your-32-byte-hex-key"

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: genieacs-relay.example.com
      paths:
        - path: /
          pathType: Prefix
```

**Helm Commands:**

```bash
# From repository
helm install my-relay genieacs-relay/genieacs-relay -n genieacs --create-namespace
helm upgrade my-relay genieacs-relay/genieacs-relay -n genieacs
helm uninstall my-relay -n genieacs

# Update repository and upgrade
helm repo update
helm upgrade my-relay genieacs-relay/genieacs-relay -n genieacs

# Rollback
helm rollback my-relay 1 -n genieacs

# View history
helm history my-relay -n genieacs
```

### ArgoCD (GitOps)

See [examples/argocd/README.md](examples/argocd/README.md) for detailed guide.

```bash
cd examples/argocd

# Option 1: Single environment (auto-sync)
kubectl apply -f application.yaml

# Option 2: With automatic image updates (auto-sync)
kubectl apply -f application-image-updater.yaml

# Option 3: Multi-environment (recommended)
kubectl apply -f applicationset.yaml          # Dev & Staging (auto-sync)
kubectl apply -f application-production.yaml  # Production (manual sync)
```

**Available manifests:**

| File | Description | Sync Policy |
|------|-------------|-------------|
| `application.yaml` | Basic ArgoCD Application | Auto-sync |
| `application-image-updater.yaml` | With automatic image updates | Auto-sync |
| `applicationset.yaml` | Dev & Staging environments | Auto-sync |
| `application-production.yaml` | Production environment | **Manual** |
| `project.yaml` | ArgoCD AppProject for access control | - |

**Install ArgoCD Image Updater (optional):**

```bash
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj-labs/argocd-image-updater/stable/manifests/install.yaml
```

**Production Deployment (Manual Sync):**

```bash
# Review changes
argocd app diff genieacs-relay-prod

# Sync after approval
argocd app sync genieacs-relay-prod
```

### Systemd (Bare Metal)

See [examples/systemd/README.md](examples/systemd/README.md) for detailed guide.

**Quick Install:**

```bash
# Build binary
go build -ldflags="-w -s" -o genieacs-relay .

# Copy to server
scp genieacs-relay user@server:/tmp/
scp examples/systemd/* user@server:/tmp/

# On server, run installer
ssh user@server
cd /tmp
sudo chmod +x install.sh
sudo ./install.sh

# Configure
sudo nano /etc/genieacs-relay/env

# Start service
sudo systemctl start genieacs-relay
```

**Manual Installation:**

```bash
# 1. Build for target platform
GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o genieacs-relay .

# 2. Create user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin genieacs

# 3. Install binary
sudo cp genieacs-relay /usr/local/bin/
sudo chmod +x /usr/local/bin/genieacs-relay

# 4. Create directories
sudo mkdir -p /etc/genieacs-relay /var/lib/genieacs-relay
sudo chown genieacs:genieacs /var/lib/genieacs-relay

# 5. Configure environment
sudo cp examples/systemd/env.example /etc/genieacs-relay/env
sudo chmod 600 /etc/genieacs-relay/env
sudo nano /etc/genieacs-relay/env

# 6. Install service
sudo cp examples/systemd/genieacs-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now genieacs-relay
```

**Systemd Commands:**

```bash
sudo systemctl start genieacs-relay     # Start
sudo systemctl stop genieacs-relay      # Stop
sudo systemctl restart genieacs-relay   # Restart
sudo systemctl status genieacs-relay    # Status
sudo journalctl -u genieacs-relay -f    # View logs
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
