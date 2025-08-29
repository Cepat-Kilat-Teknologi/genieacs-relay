# Makefile for ACS API Gateway

# Variables
REGISTRY_USER   := cepatkilatteknologi
IMAGE_NAME      := acs-api-gateway
TAG             := 1.0
DOCKER_COMPOSE  := docker compose
DOCKER_COMPOSE_PROD := docker compose -f docker-compose.prod.yml
BUILDX_PLATFORMS := linux/amd64,linux/arm64,linux/arm/v7
GO_TEST_FLAGS   := -v -race -timeout=30s
GO_COVER_FLAGS  := -coverprofile=coverage.out -covermode=atomic
BIN_DIR         := bin
TEST_DIR        := test-results

.PHONY: all setup env-copy build run dev test test-race test-coverage test-html clean \
        up down logs \
        prod-up prod-down logs-prod \
        docker-build docker-push \
        docker-buildx docker-pushx \
        healthcheck lint format check-deps \
        check-deps-intall help

.DEFAULT_GOAL := help

# Setup
## setup: Setup environment (copy .env.template to .env and create directories)
setup: env-copy dirs
	@echo ">> Setup completed. Please edit .env file with your configuration."

## env-copy: Copy .env.template to .env
env-copy:
	@if [ ! -f .env ]; then \
		echo ">> Copying .env.template to .env..."; \
		cp .env.template .env; \
		echo ">> Please edit .env file with your configuration."; \
	else \
		echo ">> .env file already exists. Skipping copy."; \
	fi

## dirs: Create necessary directories
dirs:
	@mkdir -p $(BIN_DIR) $(TEST_DIR) tmp

# Local Development
## build: Build the binary for local execution
build:
	@echo ">> Building binary..."
	go build -o $(BIN_DIR)/api main.go

## run: Build and run the application locally
run: build
	@echo ">> Running application locally..."
	./$(BIN_DIR)/api

## dev: Run the application with hot-reload (Air)
dev:
	@echo ">> Starting development server with Air hot-reload..."
	air -c .air.toml

# Testing
## test: Run all tests
test:
	@echo ">> Running tests..."
	go test $(GO_TEST_FLAGS) ./...

## test-race: Run tests with race detector
test-race:
	@echo ">> Running tests with race detector..."
	go test -race -v ./...

## test-coverage: Run tests with coverage analysis
test-coverage:
	@echo ">> Running tests with coverage..."
	go test $(GO_TEST_FLAGS) $(GO_COVER_FLAGS) ./...
	@echo ">> Coverage summary:"
	go tool cover -func=coverage.out

## test-html: Generate HTML coverage report
test-html: test-coverage
	@echo ">> Generating HTML coverage report..."
	go tool cover -html=coverage.out -o $(TEST_DIR)/coverage.html
	@echo ">> HTML coverage report generated: $(TEST_DIR)/coverage.html"

## test-bench: Run benchmark tests
test-bench:
	@echo ">> Running benchmark tests..."
	go test -bench=. -benchmem -run=^$$ ./...

## test-vet: Run go vet for static analysis
test-vet:
	@echo ">> Running go vet..."
	go vet ./...

# Docker Compose (Development)
## up: Start development environment with Docker Compose
up:
	@echo ">> Starting development environment..."
	$(DOCKER_COMPOSE) up --build

## up-d: Start development environment in detached mode
up-d:
	@echo ">> Starting development environment in detached mode..."
	$(DOCKER_COMPOSE) up --build -d

## down: Stop and remove development containers
down:
	@echo ">> Stopping development environment..."
	$(DOCKER_COMPOSE) down -v

## logs: Follow logs from the development container
logs:
	$(DOCKER_COMPOSE) logs -f

## restart: Restart development containers
restart: down up-d

# Docker Compose (Production)
## prod-up: Start production environment in detached mode
prod-up:
	@echo ">> Starting production environment..."
	$(DOCKER_COMPOSE_PROD) up --build -d

## prod-down: Stop and remove production containers
prod-down:
	$(DOCKER_COMPOSE_PROD) down -v

## logs-prod: Follow logs from the production container
logs-prod:
	$(DOCKER_COMPOSE_PROD) logs -f

## prod-restart: Restart production containers
prod-restart: prod-down prod-up

# Docker Image Management
## docker-build: Build a production Docker image
docker-build:
	@echo ">> Building Docker image: $(REGISTRY_USER)/$(IMAGE_NAME):$(TAG)"
	docker build -t $(REGISTRY_USER)/$(IMAGE_NAME):$(TAG) .

## docker-push: Build and push image to the registry
docker-push: docker-build
	@echo ">> Pushing image: $(REGISTRY_USER)/$(IMAGE_NAME):$(TAG)"
	docker push $(REGISTRY_USER)/$(IMAGE_NAME):$(TAG)

## docker-buildx: Build multi-architecture Docker image using Buildx
docker-buildx:
	@echo ">> Building multi-architecture Docker image for platforms: $(BUILDX_PLATFORMS)"
	@if ! docker buildx ls | grep -q multiarch-builder; then \
		echo ">> Creating multi-architecture builder..."; \
		docker buildx create --name multiarch-builder --use --bootstrap; \
	fi
	docker buildx build --platform $(BUILDX_PLATFORMS) \
		-t $(REGISTRY_USER)/$(IMAGE_NAME):$(TAG) \
		--push .

## docker-pushx: Build and push multi-architecture image to registry
docker-pushx: docker-buildx
	@echo ">> Multi-architecture image built and pushed successfully"

## docker-clean: Clean up Docker images and containers
docker-clean:
	@echo ">> Cleaning up Docker resources..."
	docker system prune -f
	docker image prune -f

# Code Quality
## lint: Run golangci-lint
lint:
	@echo ">> Running golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Installing..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.59.0; \
		golangci-lint run ./...; \
	fi

## format: Format Go code
format:
	@echo ">> Formatting Go code..."
	go fmt ./...

## tidy: Tidy go.mod
tidy:
	@echo ">> Tidying go.mod..."
	go mod tidy

## check-deps: Check for outdated and vulnerable dependencies
check-deps:
	@echo ">> Checking for outdated dependencies..."
	@echo ">> Outdated dependencies:"
	@if go list -m -u all | grep -E "\[.*\]"; then \
		echo ""; \
		echo ">> Some dependencies have updates available."; \
	else \
		echo ">> All dependencies are up to date!"; \
	fi

	@echo ""
	@echo ">> Checking for vulnerabilities..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		echo ">> Running govulncheck..."; \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. To install:"; \
		echo "  go install golang.org/x/vuln/cmd/govulncheck@latest"; \
		echo ""; \
		echo ">> To see detailed dependency information:"; \
		echo "  go mod why <module>    # Why a dependency is needed"; \
		echo "  go mod graph           # Dependency graph"; \
	fi

## check-deps-install: Install dependency checking tools
check-deps-install:
	@echo ">> Installing govulncheck for vulnerability scanning..."
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo ">> Install complete! Now run: make check-deps"

# Utilities
## healthcheck: Check if the local running application is healthy
healthcheck:
	@echo ">> Performing healthcheck..."
	@if command -v curl >/dev/null 2>&1; then \
		curl --fail http://localhost:8080/health || (echo "Healthcheck failed!" && exit 1); \
		echo "Healthcheck successful!"; \
	else \
		echo "curl not available, skipping healthcheck"; \
	fi

## clean: Remove build artifacts and temporary files
clean:
	@echo ">> Cleaning up..."
	rm -rf $(BIN_DIR)/ $(TEST_DIR)/ tmp/ coverage.out coverage.html

## clean-all: Clean everything including Docker resources
clean-all: clean docker-clean

## help: Show this help message
help:
	@echo "ACS API Gateway Management Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "First, setup environment:"
	@echo "  make setup           Copy .env.template to .env and setup environment"
	@echo "  make env-copy        Copy .env file only"
	@echo ""
	@echo "Local Development:"
	@echo "  make build           Build binary for local execution"
	@echo "  make run             Build and run application locally"
	@echo "  make dev             Run with hot-reload (Air)"
	@echo "  make tidy            Tidy go.mod dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  make test            Run all tests"
	@echo "  make test-race       Run tests with race detector"
	@echo "  make test-coverage   Run tests with coverage analysis"
	@echo "  make test-html       Generate HTML coverage report"
	@echo "  make test-bench      Run benchmark tests"
	@echo "  make test-vet        Run go vet for static analysis"
	@echo ""
	@echo "Docker Development:"
	@echo "  make up              Start development environment with Docker Compose"
	@echo "  make up-d            Start development environment in detached mode"
	@echo "  make down            Stop development environment"
	@echo "  make logs            View development logs"
	@echo "  make restart         Restart development containers"
	@echo ""
	@echo "Docker Production:"
	@echo "  make prod-up         Start production environment"
	@echo "  make prod-down       Stop production environment"
	@echo "  make logs-prod       View production logs"
	@echo "  make prod-restart    Restart production containers"
	@echo ""
	@echo "Docker Image Management:"
	@echo "  make docker-build    Build production Docker image (single arch)"
	@echo "  make docker-push     Build and push single arch image to registry"
	@echo "  make docker-buildx   Build multi-architecture Docker image"
	@echo "  make docker-pushx    Build and push multi-arch image to registry"
	@echo "  make docker-clean    Clean up Docker resources"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint            Run golangci-lint"
	@echo "  make format          Format Go code"
	@echo "  make check-deps      Check for outdated dependencies"
	@echo "  make check-deps-install Install dependency checking tools"
	@echo ""
	@echo "Utilities:"
	@echo "  make healthcheck     Check if application is healthy"
	@echo "  make clean           Remove build artifacts"
	@echo "  make clean-all       Clean everything including Docker"
	@echo "  make help            Show this help message"

# Default target
all: test build