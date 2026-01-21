# GenieACS Relay Helm Chart

Helm chart for deploying GenieACS Relay to Kubernetes.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.0+

## Container Registries

The chart supports both Docker Hub and GHCR images:

| Registry | Image |
|----------|-------|
| Docker Hub (default) | `cepatkilatteknologi/genieacs-relay` |
| GHCR | `ghcr.io/cepat-kilat-teknologi/genieacs-relay` |

### Available Image Tags

| Tag | Description | Recommended For |
|-----|-------------|-----------------|
| `1.0.0` | Exact version (immutable) | Production |
| `1.0` | Minor version (auto-updates patches) | Staging |
| `1` | Major version (auto-updates minor) | Development |
| `latest` | Latest stable release | Testing |

## Installation

### Install from Helm Repository (Recommended)

```bash
# Add the GenieACS Relay Helm repository
helm repo add genieacs-relay https://cepat-kilat-teknologi.github.io/genieacs-relay
helm repo update

# Search available versions
helm search repo genieacs-relay --versions

# Install the chart (uses Docker Hub by default)
helm install my-relay genieacs-relay/genieacs-relay -n genieacs --create-namespace

# Install with custom values
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  --set config.genieacsBaseUrl="http://genieacs-nbi:7557" \
  --set config.nbiAuth.key="your-nbi-key-here"

# Install specific chart version
helm install my-relay genieacs-relay/genieacs-relay --version 1.0.0 -n genieacs --create-namespace

# Install using GHCR image instead of Docker Hub
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  --set image.repository="ghcr.io/cepat-kilat-teknologi/genieacs-relay" \
  --set image.tag="1.0.0"
```

### Install from Local Source

```bash
# Clone the repository
git clone https://github.com/Cepat-Kilat-Teknologi/genieacs-relay.git
cd genieacs-relay/examples/helm

# Install from local
helm install genieacs-relay ./genieacs-relay -n genieacs --create-namespace
```

### Install with Custom Values

```bash
# Install with NBI auth key
helm install genieacs-relay ./genieacs-relay \
  -n genieacs --create-namespace \
  --set config.nbiAuth.key="your-nbi-key-here" \
  --set config.genieacsBaseUrl="http://genieacs-nbi.genieacs:7557"

# Install with custom values file
helm install genieacs-relay ./genieacs-relay \
  -n genieacs --create-namespace \
  -f my-values.yaml
```

## Configuration

### Minimal Production Values (my-values.yaml)

```yaml
replicaCount: 3

# Use pinned version for production
image:
  tag: "1.0.0"

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
    - host: genieacs-relay.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: genieacs-relay-tls
      hosts:
        - genieacs-relay.yourdomain.com
```

### Using GHCR Image (my-values.yaml)

```yaml
replicaCount: 3

# Use GHCR instead of Docker Hub
image:
  repository: ghcr.io/cepat-kilat-teknologi/genieacs-relay
  tag: "1.0.0"

config:
  genieacsBaseUrl: "http://genieacs-nbi:7557"
  nbiAuth:
    enabled: true
    key: "your-32-byte-hex-key"
```

### Using Existing Secrets

```yaml
config:
  nbiAuth:
    enabled: true
    existingSecret: "my-existing-secret"
    existingSecretKey: "NBI_AUTH_KEY"
```

## Parameters

### Common Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Image repository | `cepatkilatteknologi/genieacs-relay` |
| `image.tag` | Image tag | `""` (uses appVersion) |

### Config Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.genieacsBaseUrl` | GenieACS NBI URL | `http://genieacs-nbi:7557` |
| `config.nbiAuth.enabled` | Enable NBI authentication | `true` |
| `config.nbiAuth.key` | NBI auth key | `""` |
| `config.middlewareAuth.enabled` | Enable API authentication | `false` |
| `config.corsAllowedOrigins` | CORS origins | `*` |

### Service Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `80` |

### Ingress Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class | `nginx` |
| `ingress.hosts` | Ingress hosts | `[]` |

## Commands

```bash
# Install from repository
helm install my-relay genieacs-relay/genieacs-relay -n genieacs --create-namespace

# Install from local
helm install genieacs-relay ./genieacs-relay -n genieacs --create-namespace

# Upgrade from repository
helm upgrade my-relay genieacs-relay/genieacs-relay -n genieacs

# Upgrade from local
helm upgrade genieacs-relay ./genieacs-relay -n genieacs

# Uninstall
helm uninstall my-relay -n genieacs

# Template (preview manifests)
helm template my-relay genieacs-relay/genieacs-relay

# Lint (validate chart)
helm lint ./genieacs-relay
```

## Upgrading

```bash
# Update repository
helm repo update

# Upgrade with new values
helm upgrade my-relay genieacs-relay/genieacs-relay \
  -n genieacs \
  --set replicaCount=5

# Rollback to previous version
helm rollback my-relay 1 -n genieacs

# View release history
helm history my-relay -n genieacs
```
