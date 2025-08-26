.PHONY: build run dev test clean docker-build docker-run docker-dev docker-prod docker-down docker-logs docker-push docker-buildx help

# Build the binary
build:
	go build -o bin/api main.go

# Run the application
run: build
	./bin/api

# Development with air
dev:
	air -c .air.toml

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -rf bin/ tmp/

# Build Docker image (single platform)
docker-build:
	docker build -t acs-api-gateway:latest .

# Run Docker container
docker-run: docker-build
	docker run -p 8080:8080 --name acs-api-gateway acs-api-gateway:latest

# Development with Docker Compose
docker-dev:
	docker-compose up --build

# Production with Docker Compose
docker-prod:
	docker-compose -f docker-compose.prod.yml up --build -d

# Stop and remove containers
docker-down:
	docker-compose down
	docker-compose -f docker-compose.prod.yml down

# View logs development
docker-logs:
	docker-compose logs -f

# View logs production
docker-logs-prod:
	docker-compose -f docker-compose.prod.yml logs -f

# Build and push to registry (single platform)
docker-push:
	docker build -t cepatkilatteknologi/acs-api-gateway:1.0 .
	docker push cepatkilatteknologi/acs-api-gateway:1.0

# Buildx multi-platform build
docker-buildx:
	@echo "Building multi-platform image..."
	docker buildx create --use --name multi-platform-builder || true
	docker buildx build \
		--platform linux/amd64,linux/arm64,linux/arm/v7 \
		-t cepatkilatteknologi/acs-api-gateway:1.0 \
		-t cepatkilatteknologi/acs-api-gateway:latest \
		--push .

# Buildx multi-platform build without push (for testing)
docker-buildx-test:
	@echo "Building multi-platform image (no push)..."
	docker buildx create --use --name multi-platform-builder || true
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t cepatkilatteknologi/acs-api-gateway:1.0 \
		-t cepatkilatteknologi/acs-api-gateway:latest .

# Buildx multi-platform build and load to local docker
docker-buildx-load:
	@echo "Building multi-platform image and loading to local docker..."
	docker buildx create --use --name multi-platform-builder || true
	docker buildx build \
		--platform linux/amd64 \
		-t acs-api-gateway:multi \
		--load .

# Inspect multi-platform images
docker-buildx-inspect:
	docker buildx imagetools inspect cepatkilatteknologi/acs-api-gateway:latest

# Create builder instance (run once)
docker-buildx-setup:
	docker buildx create --name multi-platform-builder --use
	docker buildx inspect --bootstrap

# List available builders
docker-buildx-ls:
	docker buildx ls

# Health check
healthcheck:
	curl -f http://localhost:8080/api/v1/genieacs/ssid/health || exit 1

# Help
help:
	@echo "Available commands:"
	@echo "  build                 - Build the binary"
	@echo "  run                   - Run the application"
	@echo "  dev                   - Run with air (hot reload)"
	@echo "  test                  - Run tests"
	@echo "  clean                 - Clean build artifacts"
	@echo "  docker-build          - Build Docker image (single platform)"
	@echo "  docker-run            - Run Docker container"
	@echo "  docker-dev            - Run development container with compose"
	@echo "  docker-prod           - Run production container with compose"
	@echo "  docker-down           - Stop and remove all containers"
	@echo "  docker-logs           - View development container logs"
	@echo "  docker-logs-prod      - View production container logs"
	@echo "  docker-push           - Build and push to registry (single platform)"
	@echo "  docker-buildx         - Multi-platform build and push to registry"
	@echo "  docker-buildx-test    - Multi-platform build without push"
	@echo "  docker-buildx-load    - Multi-platform build and load to local docker"
	@echo "  docker-buildx-inspect - Inspect multi-platform images"
	@echo "  docker-buildx-setup   - Setup multi-platform builder (run once)"
	@echo "  docker-buildx-ls      - List available builders"
	@echo "  healthcheck           - Check if API is healthy"