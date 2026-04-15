# Contributing to GenieACS Relay

Thank you for your interest in contributing to GenieACS Relay! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

---

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/genieacs-relay.git
   cd genieacs-relay
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Cepat-Kilat-Teknologi/genieacs-relay.git
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## Development Setup

### Prerequisites

- Go 1.24 or higher
- Docker (optional, for containerized development)
- Make

### Setup

```bash
# Install dependencies
go mod download

# Copy environment file
make setup

# Edit configuration
nano .env

# Run locally
make run

# Or run with hot-reload
make dev
```

### Useful Commands

```bash
make build          # Build binary
make test           # Run tests
make test-coverage  # Run tests with coverage
make lint           # Run linter
make format         # Format code
make swagger        # Generate Swagger docs
```

---

## Making Changes

### Branching Strategy

- `main` - Production-ready code
- `develop` - Development branch
- `feature/*` - New features
- `fix/*` - Bug fixes
- `docs/*` - Documentation changes

### Workflow

1. Sync with upstream:
   ```bash
   git fetch upstream
   git rebase upstream/develop
   ```

2. Make your changes in small, focused commits

3. Ensure tests pass:
   ```bash
   make test
   ```

4. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

5. Create a Pull Request to the `develop` branch

---

## Code Style

### Go Code Standards

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use `gofmt` for formatting (run `make format`)
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions small and focused

### Linting

We use `golangci-lint` for code quality:

```bash
make lint
```

Fix all linting issues before submitting a PR.

### File Structure

```text
.
├── main.go              # Application entry point
├── config.go            # Configuration handling
├── server.go            # HTTP server setup
├── routes.go            # Route definitions
├── middleware.go        # HTTP middleware
├── handlers_*.go        # HTTP handlers by domain
├── models.go            # Data structures
├── client.go            # GenieACS client
├── validation.go        # Input validation
├── *_test.go            # Test files
└── examples/            # Deployment examples
```

---

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run with race detector
make test-race

# Run with coverage
make test-coverage

# Generate HTML coverage report
make test-html
```

### Writing Tests

- Place tests in `*_test.go` files
- Use table-driven tests where appropriate
- Aim for high coverage on new code
- Test both success and error cases

Example:

```go
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid input",
            input:    "test",
            expected: "result",
            wantErr:  false,
        },
        {
            name:    "invalid input",
            input:   "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := FunctionName(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Coverage Requirements

- Maintain minimum 80% code coverage
- New features should have corresponding tests
- Bug fixes should include regression tests

---

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Format

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Code style (formatting, etc.) |
| `refactor` | Code refactoring |
| `test` | Adding/updating tests |
| `chore` | Maintenance tasks |
| `perf` | Performance improvement |
| `ci` | CI/CD changes |

### Examples

```bash
feat(wlan): add support for WPA3 authentication

fix(ssid): handle special characters in SSID names

docs(readme): update installation instructions

test(handlers): add tests for error cases

chore(deps): update Go dependencies
```

### Good Practices

- Use imperative mood ("add" not "added")
- Keep first line under 72 characters
- Reference issues when applicable: `Fixes #123`

---

## Versioning Policy

This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
Version numbers are `MAJOR.MINOR.PATCH`:

| Bump | When to use | Examples |
|---|---|---|
| **MAJOR** (X.y.z) | **Breaking changes** — any change that would require clients (especially `billing-agent`) to update their integration code | JSON envelope shape change, removal of an endpoint, rename of a field, change in HTTP status code semantics, change in auth scheme |
| **MINOR** (x.Y.z) | **Additive features** — new endpoints, new optional fields, new middleware, new observability — anything that is backwards-compatible with existing clients | New endpoint, new optional request field, new response header, new Prometheus metric, new env var with default, new error code |
| **PATCH** (x.y.Z) | **Bug fixes** only — no API change, no new feature, no config change | Status code fix, panic fix, race condition fix, dependency bump, lint fix |

### Version History

| Version | Released | Type | Summary |
|---|---|---|---|
| **v2.2.0** | 2026-04-15 (release-ready, tag pending) | MINOR | Auto-learn OLT support — 25 new operational endpoints across 4 phases (7 HIGH CPE lifecycle + 8 MEDIUM NOC tools + 10 LOW customer self-service + metadata) plus structural `tr069.go` / `param_walker.go` foundations + session 5i F670L real-device hardening (sixth optical extractor `X_ZTE-COM_WANPONInterfaceConfig`, `wlan/available` `provisioned_wlan[]` enrichment, QoS 501 capability probe, trailing-dot `refreshObject` sanitation) + session 5j reboot/factory-reset E2E close-out (40/40 endpoints verified on real ZTE F670L V9.0.10P1N12A). 100% main-package coverage maintained. |
| **v2.1.0** | 2026-04-15 | MINOR | CPE lifecycle operations + optical health — added `POST /reboot/{ip}`, `POST /dhcp/{ip}/refresh`, `GET /optical/{ip}` with 5-vendor auto-detection (ZTE CT-COM EPON/GPON, Huawei HW_DEBUG, Realtek EPON, standard TR-181) and env-tunable health classification thresholds. Post-release hardening closed coverage to 100.0%. |
| **v2.0.0** | 2026-04-12 | MAJOR | v1 standardization — breaking response envelope change, new health/readiness/version/metrics endpoints, request-ID correlation, idempotency middleware, multi-arch Docker, bug fix for HTTP 202 status handling, alpine CVE-2026-28390 patched |
| v1.0.1 | (prior) | PATCH | legacy release |
| v1.0.0 | (prior) | MAJOR | initial release |

### Rules of thumb

1. **Never silently break the response envelope** — if the JSON shape changes in any
   way that could surprise a client that parses the old shape, it is a MAJOR bump.
2. **Adding a new error code is MINOR** (clients should have a fallback to the HTTP
   status code anyway per isp-adapter-standard). Removing or renaming an error
   code is MAJOR.
3. **Changing the default value of an env var** is MINOR if the old value remains
   valid, MAJOR if the old value is no longer accepted.
4. **Ldflags injection bugs** (e.g. wrong `-X` target name) are PATCH even though
   they affect the `/version` endpoint, because the API contract is unchanged —
   only the reported value was wrong.
5. **The Docker image tag must match the semver tag**. A git tag of `v2.1.0` must
   publish `:2.1.0`, `:2.1`, `:2`, and `:latest` via the CI release workflow.
6. **Update `CHANGELOG.md` in the same commit** that bumps the version — never
   tag a release whose changelog section is missing or incomplete.

---

## Pull Request Process

### Before Submitting

- [ ] Code follows project style guidelines
- [ ] All tests pass locally (`make test`)
- [ ] Linter passes (`make lint`)
- [ ] New code has test coverage
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventions

### PR Template

When creating a PR, include:

```text
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
How were changes tested?

## Related Issues
Fixes #123
```

### Review Process

1. Create PR to `develop` branch
2. Wait for CI checks to pass
3. Address reviewer feedback
4. Squash commits if requested
5. Maintainer will merge when approved

### After Merge

- Delete your feature branch
- Sync your fork with upstream

---

## Reporting Issues

### Before Creating an Issue

- Search existing issues to avoid duplicates
- Check if it's already fixed in `develop` branch

### Bug Reports

Include:

1. **Environment**: Go version, OS, Docker version
2. **Steps to reproduce**: Minimal steps to trigger the bug
3. **Expected behavior**: What should happen
4. **Actual behavior**: What actually happens
5. **Logs**: Relevant error messages or logs

### Feature Requests

Include:

1. **Problem**: What problem does this solve?
2. **Solution**: How would you like it to work?
3. **Alternatives**: Other solutions you've considered
4. **Context**: Additional context or screenshots

---

## Questions?

- Open a [GitHub Issue](https://github.com/Cepat-Kilat-Teknologi/genieacs-relay/issues)
- Check existing documentation in `INSTALLATION.md`

---

Thank you for contributing!
