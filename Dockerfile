# Stage 1: Development
FROM golang:1.25-alpine AS development
RUN apk add --no-cache git build-base
RUN go install github.com/air-verse/air@latest
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
CMD ["air", "-c", ".air.toml"]

# Stage 2: Builder untuk multi-platform
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETARCH
ARG TARGETOS
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
RUN go mod tidy
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev}" \
    -o /app/main main.go

# Stage 3: Final image
FROM alpine:3.19 AS production
LABEL org.opencontainers.image.source="https://github.com/cepatkilatteknologi/acs-api-gateway"
RUN apk add --no-cache tzdata ca-certificates curl \
    && cp /usr/share/zoneinfo/Asia/Jakarta /etc/localtime \
    && echo "Asia/Jakarta" > /etc/timezone \
    && apk del tzdata \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser
WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /app/main /app/main

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/main"]