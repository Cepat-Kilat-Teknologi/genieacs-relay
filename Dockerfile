# syntax=docker/dockerfile:1

# Stage 1: Development
FROM golang:1.26-alpine AS development
RUN apk add --no-cache git build-base
RUN go install github.com/air-verse/air@latest
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
CMD ["air", "-c", ".air.toml"]

# Stage 2: Builder untuk multi-platform
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETARCH
ARG TARGETOS
# Build metadata injected into the binary via ldflags. CI should pass APP_VERSION,
# APP_COMMIT, and APP_BUILD_TIME so /version and the X-App-Version header return
# real values instead of the "dev"/"none"/"unknown" defaults. See cmd/api/main.go
# for the lowercase var targets — a casing mismatch makes -X silently no-op.
ARG APP_VERSION=dev
ARG APP_COMMIT=none
ARG APP_BUILD_TIME=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-w -s -X main.version=${APP_VERSION} -X main.commit=${APP_COMMIT} -X main.buildTs=${APP_BUILD_TIME}" \
    -o /app/main .

# Stage 3: Final image
FROM alpine:3.21 AS production
LABEL org.opencontainers.image.source="https://github.com/Cepat-Kilat-Teknologi/genieacs-relay"
# Force package upgrade to pick up the latest patched security packages. The alpine:3.21
# base image ships a snapshot at tag time, so CVEs fixed AFTER the tag's mint date (e.g.
# CVE-2026-28390 in libcrypto3/libssl3, fixed in 3.3.7-r0 while base still has 3.3.6-r0)
# require an explicit `apk upgrade` against the live 3.21 repo. This keeps us on the
# alpine 3.21 track without chasing minor base bumps every time a new CVE lands.
RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Jakarta /etc/localtime \
    && echo "Asia/Jakarta" > /etc/timezone \
    && apk del tzdata \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser
WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /app/main /app/main

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/main"]