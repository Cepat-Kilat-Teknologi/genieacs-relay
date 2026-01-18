# GenieACS Relay Helm Chart

Helm chart for deploying GenieACS Relay to Kubernetes.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.0+

## Installation

### Quick Install

```bash
# Add repo (if published)
# helm repo add genieacs https://cepat-kilat-teknologi.github.io/charts
# helm repo update

# Install from local
cd examples/helm
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
# Install
helm install genieacs-relay ./genieacs-relay -n genieacs --create-namespace

# Upgrade
helm upgrade genieacs-relay ./genieacs-relay -n genieacs

# Uninstall
helm uninstall genieacs-relay -n genieacs

# Template (preview manifests)
helm template genieacs-relay ./genieacs-relay

# Lint (validate chart)
helm lint ./genieacs-relay
```

## Upgrading

```bash
# Upgrade with new values
helm upgrade genieacs-relay ./genieacs-relay \
  -n genieacs \
  --set replicaCount=5

# Rollback to previous version
helm rollback genieacs-relay 1 -n genieacs
```
