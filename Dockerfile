# syntax=docker/dockerfile:1

# Stage 1: Development
FROM golang:1.26.6-alpine AS development
RUN apk add --no-cache git build-base
RUN go install github.com/air-verse/air@latest
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
CMD ["air", "-c", ".air.toml"]

# Stage 2: Builder untuk multi-platform
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS builder
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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-s -w" -o /bin/healthcheck ./cmd/healthcheck/main.go

# Stage 3: Final image
FROM gcr.io/distroless/static-debian12:nonroot AS production
LABEL org.opencontainers.image.source="https://github.com/Cepat-Kilat-Teknologi/genieacs-relay"

COPY --from=builder /app/main /app/main
COPY --from=builder /bin/healthcheck /healthcheck

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/healthcheck"]

ENTRYPOINT ["/app/main"]
