# GenieACS Relay Helm Chart

Helm chart for deploying GenieACS Relay to Kubernetes.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.0+

## Installation

### Install from Helm Repository (Recommended)

```bash
# Add the GenieACS Relay Helm repository
helm repo add genieacs-relay https://cepat-kilat-teknologi.github.io/genieacs-relay
helm repo update

# Search available versions
helm search repo genieacs-relay

# Install the chart
helm install my-relay genieacs-relay/genieacs-relay -n genieacs --create-namespace

# Install with custom values
helm install my-relay genieacs-relay/genieacs-relay \
  -n genieacs --create-namespace \
  --set config.genieacsBaseUrl="http://genieacs-nbi:7557" \
  --set config.nbiAuth.key="your-nbi-key-here"

# Install specific version
helm install my-relay genieacs-relay/genieacs-relay --version 0.1.0 -n genieacs --create-namespace
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
