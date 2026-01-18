# ArgoCD Deployment

Deploy GenieACS Relay using ArgoCD with GitOps methodology.

## Prerequisites

- Kubernetes 1.23+
- ArgoCD installed in cluster
- ArgoCD Image Updater (optional, for auto image updates)

## Quick Start

```bash
# Apply the application
kubectl apply -f application.yaml

# Or with image updater
kubectl apply -f application-image-updater.yaml

# Or multi-environment with ApplicationSet
kubectl apply -f applicationset.yaml
```

## Available Manifests

| File | Description | Sync Policy |
|------|-------------|-------------|
| `application.yaml` | Basic ArgoCD Application | Auto-sync |
| `application-image-updater.yaml` | With automatic image updates | Auto-sync |
| `applicationset.yaml` | Dev & Staging environments | Auto-sync |
| `application-production.yaml` | Production environment | **Manual sync** |
| `project.yaml` | ArgoCD AppProject for access control | - |

## Configuration Options

### 1. Basic Auto-Sync (Git Changes Only)

Use `application.yaml` when you want ArgoCD to sync only when Git repository changes.

```bash
kubectl apply -f application.yaml
```

**Workflow:**
```
Git Push → ArgoCD detects change → Auto Sync → Cluster Updated
```

### 2. Image Updater (Auto Image Updates)

Use `application-image-updater.yaml` when you want automatic updates when new Docker images are pushed.

```bash
# Install ArgoCD Image Updater first
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj-labs/argocd-image-updater/stable/manifests/install.yaml

# Apply application
kubectl apply -f application-image-updater.yaml
```

**Workflow:**
```
Docker Push (v1.1.0) → Image Updater detects → Updates Git → ArgoCD Sync
```

### 3. Multi-Environment Setup

**Recommended approach:** Use ApplicationSet for dev/staging (auto-sync) and separate Application for production (manual sync).

```bash
# Dev & Staging - auto-sync enabled
kubectl apply -f applicationset.yaml

# Production - manual sync (requires approval)
kubectl apply -f application-production.yaml
```

**Creates:**
- `genieacs-relay-dev` → development namespace (auto-sync)
- `genieacs-relay-staging` → staging namespace (auto-sync)
- `genieacs-relay-prod` → production namespace (manual sync)

### 4. Production Deployment Workflow

Production uses manual sync for safety. Here's the workflow:

```bash
# 1. Check what will change (diff)
argocd app diff genieacs-relay-prod

# 2. Preview sync (dry-run)
argocd app sync genieacs-relay-prod --dry-run

# 3. Sync production (after approval)
argocd app sync genieacs-relay-prod

# 4. Verify deployment
argocd app get genieacs-relay-prod
kubectl get pods -n genieacs-prod
```

**Via ArgoCD UI:**
1. Go to Applications → genieacs-relay-prod
2. Review "OutOfSync" changes
3. Click "Sync" button
4. Confirm sync options
5. Monitor sync progress

## Update Strategies

| Strategy | Use Case | Example |
|----------|----------|---------|
| `semver` | Production - stable versions only | `1.0.0` → `1.1.0` → `2.0.0` |
| `latest` | Development - always latest | Always pulls `latest` tag |
| `digest` | Immutable - track by SHA | Updates when digest changes |

## Customization

### Using Different Values File

```yaml
spec:
  source:
    helm:
      valueFiles:
        - values.yaml
        - values-production.yaml  # Override with production values
```

### Setting Helm Parameters

```yaml
spec:
  source:
    helm:
      parameters:
        - name: replicaCount
          value: "5"
        - name: config.nbiAuth.enabled
          value: "true"
```

### Using External Values File

```yaml
spec:
  source:
    helm:
      valueFiles:
        - $values/environments/production/values.yaml
  sources:
    - repoURL: https://github.com/your-org/your-config-repo.git
      targetRevision: main
      ref: values
```

## Notifications (Optional)

Add Slack/Teams notifications for sync events:

```yaml
metadata:
  annotations:
    notifications.argoproj.io/subscribe.on-sync-succeeded.slack: deployments
    notifications.argoproj.io/subscribe.on-sync-failed.slack: deployments
```

## Troubleshooting

```bash
# Check application status
argocd app get genieacs-relay

# Check sync status
argocd app sync genieacs-relay

# View application logs
argocd app logs genieacs-relay

# Force refresh
argocd app get genieacs-relay --refresh

# Check image updater logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-image-updater
```

## Security Notes

- Use `project.yaml` to restrict which repositories and clusters the application can access
- Store sensitive values in SealedSecrets or ExternalSecrets, not in Git
- Use RBAC to control who can sync applications
