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

```
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

```
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

```markdown
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
