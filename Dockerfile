# Stage 1: Development
FROM golang:1.24-alpine AS development

RUN apk add --no-cache git build-base
RUN go install github.com/air-verse/air@latest

WORKDIR /app

# copy only go.mod/sum dulu biar cache go mod ke-save
COPY go.mod go.sum ./
RUN go mod download

# copy semua source
COPY . .

# gunakan air (tidak build binary manual)
CMD ["air", "-c", ".air.toml"]

# Stage 2: Production
FROM golang:1.24-alpine AS build

WORKDIR /src
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /app main.go

# Stage 3: Final image
FROM alpine:3.19 AS production
RUN apk add --no-cache tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Jakarta /etc/localtime \
    && echo "Asia/Jakarta" > /etc/timezone \
    && apk del tzdata \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser
COPY --from=build --chown=appuser:appgroup /app /app

EXPOSE 8080
ENTRYPOINT ["/app"]