# Stage 1: Development (Sudah bagus, tidak perlu diubah)
FROM golang:1.25-alpine AS development
RUN apk add --no-cache git build-base
RUN go install github.com/air-verse/air@latest
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
CMD ["air", "-c", ".air.toml"]


# Stage 2: Production Build (Dengan optimisasi cache)
FROM golang:1.25-alpine AS build
WORKDIR /src
# 1. Salin file modul terlebih dahulu
COPY go.mod go.sum ./
# 2. Unduh dependensi. Layer ini akan di-cache jika go.mod/sum tidak berubah
RUN go mod download
RUN go mod tidy
# 3. Baru salin sisa source code
COPY . .
# 4. Build aplikasi
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /app/main main.go


# Stage 3: Final image
FROM alpine:3.19 AS production
RUN apk add --no-cache tzdata ca-certificates curl \
    && cp /usr/share/zoneinfo/Asia/Jakarta /etc/localtime \
    && echo "Asia/Jakarta" > /etc/timezone \
    && apk del tzdata \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser
COPY --from=build --chown=appuser:appgroup /app/main /app/main

EXPOSE 8080
ENTRYPOINT ["/app/main"]
