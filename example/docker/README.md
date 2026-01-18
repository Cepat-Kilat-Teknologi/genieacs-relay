# Docker Deployment Guide

This guide explains how to deploy GenieACS Relay using Docker.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 20.10+
- [Docker Compose](https://docs.docker.com/compose/install/) v2.0+
- Access to GenieACS NBI API

## Quick Start

```bash
# 1. Copy example files
cp .env.example .env

# 2. Configure environment
nano .env

# 3. Start the service
docker compose up -d

# 4. Check status
docker compose ps
docker compose logs -f
```

## Configuration

### Environment Variables

Edit `.env` file with your configuration:

```bash
# GenieACS NBI URL
GENIEACS_BASE_URL=http://genieacs:7557

# NBI Authentication (if your GenieACS requires authentication)
NBI_AUTH=false
# NBI_AUTH_KEY=your-genieacs-nbi-key  # Required if NBI_AUTH=true

# Enable API authentication (recommended for production)
MIDDLEWARE_AUTH=true
AUTH_KEY=your-secure-api-key

# CORS (restrict in production)
CORS_ALLOWED_ORIGINS=https://your-app.com

# Rate limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

### Docker Compose Options

The `docker-compose.yml` includes:

| Option | Value | Description |
|--------|-------|-------------|
| `image` | `cepatkilatteknologi/genieacs-relay:2.0` | Docker image |
| `ports` | `8080:8080` | Port mapping |
| `restart` | `unless-stopped` | Restart policy |
| `memory` | `256M` (limit), `128M` (reserved) | Memory limits |
| `cpus` | `0.5` (limit), `0.25` (reserved) | CPU limits |

## Commands

```bash
# Start service
docker compose up -d

# Stop service
docker compose down

# View logs
docker compose logs -f

# Restart service
docker compose restart

# Check health
curl http://localhost:8080/health
```

## Health Check

The container includes a built-in health check:

```bash
# Check container health status
docker inspect --format='{{.State.Health.Status}}' genieacs-relay
```

## Network Configuration

### Connect to GenieACS on same host

If GenieACS runs on the same Docker host:

```yaml
services:
  api:
    # ... other config
    extra_hosts:
      - "genieacs:host-gateway"
    environment:
      - GENIEACS_BASE_URL=http://genieacs:7557
```

### Connect to external GenieACS

```bash
# In .env file
GENIEACS_BASE_URL=http://192.168.1.100:7557
```

### Docker network with GenieACS

If GenieACS runs in Docker, connect to the same network:

```yaml
services:
  api:
    # ... other config
    networks:
      - genieacs_network

networks:
  genieacs_network:
    external: true
```

## Production Recommendations

### 1. Use specific image tag

```yaml
image: cepatkilatteknologi/genieacs-relay:2.0  # Don't use :latest
```

### 2. Enable authentication

```bash
MIDDLEWARE_AUTH=true
AUTH_KEY=<strong-random-key>
```

### 3. Restrict CORS

```bash
CORS_ALLOWED_ORIGINS=https://your-app.com
```

### 4. Use reverse proxy (nginx/traefik)

```yaml
services:
  api:
    # Remove public port mapping
    expose:
      - "8080"
    # Add labels for Traefik (example)
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.genieacs-relay.rule=Host(`api.example.com`)"
```

### 5. Add logging

```yaml
services:
  api:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker compose logs

# Common issues:
# - Invalid GENIEACS_BASE_URL
# - NBI_AUTH=true but NBI_AUTH_KEY not set
# - MIDDLEWARE_AUTH=true but AUTH_KEY not set
# - Port 8080 already in use
```

### Cannot connect to GenieACS

```bash
# Test connectivity from container
docker compose exec api curl -v http://genieacs:7557

# Check DNS resolution
docker compose exec api nslookup genieacs
```

### Health check failing

```bash
# Check health endpoint manually
curl http://localhost:8080/health

# Check container logs
docker compose logs --tail=50
```

## Updating

```bash
# Pull latest image
docker compose pull

# Restart with new image
docker compose up -d
```

## Backup & Restore

This service is stateless - no backup needed. Configuration is in `.env` file.
