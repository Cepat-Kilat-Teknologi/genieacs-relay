# Kubernetes Deployment Examples

This directory contains Kubernetes manifests for deploying GenieACS Relay.

## Files

| File | Description |
|------|-------------|
| `namespace.yaml` | Creates the `genieacs` namespace |
| `configmap.yaml` | Non-sensitive configuration (URLs, feature flags) |
| `secret.yaml` | Basic secret (for development only) |
| `sealed-secret.yaml` | SealedSecret for GitOps (production) |
| `external-secret.yaml` | ExternalSecret for AWS/Vault/GCP (production) |
| `deployment.yaml` | Application deployment with 2 replicas |
| `service.yaml` | ClusterIP service exposing port 80 |
| `ingress.yaml` | Ingress resource for external access (optional) |
| `hpa.yaml` | Horizontal Pod Autoscaler (optional) |
| `pdb.yaml` | Pod Disruption Budget (optional) |
| `networkpolicy.yaml` | Network policies for security (optional) |
| `kustomization.yaml` | Kustomize configuration for easy deployment |

## Quick Start

### Option 1: Using Kustomize (Recommended)

```bash
# Edit the secret with your actual keys
vim examples/kubernetes/secret.yaml

# Preview the manifests
kubectl kustomize examples/kubernetes/

# Apply all resources
kubectl apply -k examples/kubernetes/
```

### Option 2: Manual Deployment

```bash
# Create namespace
kubectl apply -f examples/kubernetes/namespace.yaml

# Create config and secrets (edit secret.yaml first!)
kubectl apply -f examples/kubernetes/configmap.yaml
kubectl apply -f examples/kubernetes/secret.yaml

# Deploy the application
kubectl apply -f examples/kubernetes/deployment.yaml
kubectl apply -f examples/kubernetes/service.yaml

# Optional: Add ingress for external access
kubectl apply -f examples/kubernetes/ingress.yaml
```

## Configuration

### Secret Management Options

#### Option A: Basic Secret (Development Only)

```bash
# Generate and apply secret directly
kubectl create secret generic genieacs-relay-secret \
  --namespace=genieacs \
  --from-literal=NBI_AUTH_KEY=$(openssl rand -hex 32) \
  --from-literal=AUTH_KEY=$(openssl rand -hex 32)
```

#### Option B: SealedSecrets (Production - GitOps)

Safe to commit encrypted secrets to Git:

```bash
# Install SealedSecrets controller
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets sealed-secrets/sealed-secrets -n kube-system

# Create and seal secret
kubectl create secret generic genieacs-relay-secret \
  --namespace=genieacs \
  --from-literal=NBI_AUTH_KEY=$(openssl rand -hex 32) \
  --from-literal=AUTH_KEY=$(openssl rand -hex 32) \
  --dry-run=client -o yaml | kubeseal --format=yaml > sealed-secret.yaml

# Apply sealed secret
kubectl apply -f sealed-secret.yaml
```

#### Option C: ExternalSecrets (Production - Cloud)

Sync secrets from AWS Secrets Manager, Vault, GCP, Azure:

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace

# Create secret in AWS Secrets Manager
aws secretsmanager create-secret \
  --name genieacs/relay \
  --secret-string '{"nbi_auth_key":"your-key","auth_key":"your-api-key"}'

# Apply ExternalSecret
kubectl apply -f external-secret.yaml
```

### ConfigMap Options

| Variable | Default | Description |
|----------|---------|-------------|
| `GENIEACS_BASE_URL` | `http://genieacs-nbi:7557` | GenieACS NBI URL |
| `NBI_AUTH` | `true` | Enable NBI authentication |
| `CORS_ALLOWED_ORIGINS` | `*` | CORS allowed origins |
| `MIDDLEWARE_AUTH` | `false` | Enable API authentication |
| `RATE_LIMIT_REQUESTS` | `50` | Max requests per window |
| `RATE_LIMIT_WINDOW` | `30` | Rate limit window (seconds) |
| `STALE_THRESHOLD_MINUTES` | `15` | Device stale threshold |

## Verify Deployment

```bash
# Check pods
kubectl get pods -n genieacs

# Check service
kubectl get svc -n genieacs

# Test health endpoint
kubectl port-forward -n genieacs svc/genieacs-relay 8080:80
curl http://localhost:8080/health

# View logs
kubectl logs -n genieacs -l app.kubernetes.io/name=genieacs-relay -f
```

## Production Recommendations

1. **Enable HPA** for auto-scaling:
   ```bash
   kubectl apply -f examples/kubernetes/hpa.yaml
   ```

2. **Enable PDB** for high availability:
   ```bash
   kubectl apply -f examples/kubernetes/pdb.yaml
   ```

3. **Enable NetworkPolicy** for security:
   ```bash
   kubectl apply -f examples/kubernetes/networkpolicy.yaml
   ```

4. **Configure Ingress** with TLS:
   - Update `ingress.yaml` with your domain
   - Uncomment TLS section
   - Use cert-manager for automatic certificates

5. **Use external secrets** manager (e.g., Vault, AWS Secrets Manager) instead of Kubernetes secrets for production.

## Scaling

```bash
# Manual scaling
kubectl scale deployment genieacs-relay -n genieacs --replicas=5

# Or use HPA for automatic scaling
kubectl apply -f examples/kubernetes/hpa.yaml
```

## Cleanup

```bash
# Delete all resources
kubectl delete -k examples/kubernetes/

# Or delete namespace (removes everything)
kubectl delete namespace genieacs
```
