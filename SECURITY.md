# Security

This document describes the security features and configurations for GenieACS Relay.

## Table of Contents

- [API Authentication](#api-authentication)
- [Brute Force Protection](#brute-force-protection)
- [Rate Limiting](#rate-limiting)
- [Audit Logging](#audit-logging)
- [Security Headers](#security-headers)
- [Input Validation](#input-validation)
- [Stale Device Validation](#stale-device-validation)

---

## API Authentication

By default, the API Gateway does **not** require authentication for incoming requests. To enable API key authentication:

1. Set `MIDDLEWARE_AUTH=true` in your `.env` file
2. Set `AUTH_KEY` to your desired API key value
3. Include the `X-API-Key` header in all requests to `/api/v1/genieacs/*` endpoints

**Note:** The `/health` and `/swagger/*` endpoints do **not** require authentication, even when `MIDDLEWARE_AUTH=true`.

### Authentication Errors

**Missing API Key:**
```json
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Missing X-API-Key header"
}
```

**Invalid API Key:**
```json
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Invalid API key"
}
```

---

## Brute Force Protection

The API includes automatic brute force protection for authentication:

- **Max Failed Attempts**: 5 attempts within 5 minutes
- **Lockout Duration**: 15 minutes after max failed attempts
- **Automatic Cleanup**: Expired lockouts are automatically cleaned up

When an IP is locked out, the API returns:
```json
{
  "code": 429,
  "status": "Too Many Requests",
  "error": "Too many failed authentication attempts. Please try again later."
}
```

The response includes a `Retry-After` header indicating when the lockout expires.

---

## Rate Limiting

Configurable per-IP rate limiting to prevent abuse:

- Default: 100 requests per 60-second window
- Memory protection: Maximum 10,000 tracked IPs to prevent memory exhaustion
- Automatic cleanup of stale entries

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_REQUESTS` | `100` | Maximum requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |

### Rate Limit Error

```json
{
  "code": 429,
  "status": "Too Many Requests",
  "error": "Rate limit exceeded. Please try again later."
}
```

---

## Audit Logging

Security-relevant events are logged for audit purposes:

| Event | Description |
|-------|-------------|
| `AUTH_SUCCESS` | Successful authentication |
| `AUTH_FAILURE` | Failed authentication attempt |
| `AUTH_BLOCKED` | Request blocked due to brute force protection |
| `WLAN_CREATE` | New WLAN created |
| `WLAN_UPDATE` | WLAN configuration updated |
| `WLAN_DELETE` | WLAN deleted/disabled |
| `WLAN_OPTIMIZE` | WLAN radio settings optimized |
| `CACHE_CLEAR` | Device cache cleared |

### Example Audit Log Entry

```json
{
  "level": "info",
  "msg": "AUDIT",
  "event": "WLAN_CREATE",
  "client_ip": "192.168.1.10",
  "device_id": "001141-F670L-ZTEGCFLN794B3A1",
  "wlan": "2",
  "ssid": "GuestNetwork",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## Security Headers

All responses include security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforce HTTPS |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | XSS filter (legacy) |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Restrict resources |
| `Referrer-Policy` | `no-referrer` | Prevent referrer leakage |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Disable browser features |
| `Cache-Control` | `no-store, no-cache, must-revalidate, private` | Prevent caching |

---

## Input Validation

Strict input validation for security:

| Input | Validation |
|-------|------------|
| **IP Addresses** | Rejects loopback (`127.0.0.1`, `::1`), multicast, and unspecified addresses |
| **SSID** | 1-32 characters, printable ASCII only, no leading/trailing spaces |
| **Password** | 8-63 characters |
| **WLAN ID** | 1-99, numeric only |
| **Request Body** | Limited to 1KB to prevent DoS |

---

## Stale Device Validation

When querying devices by IP address, the API validates whether the device has recently reported to GenieACS using the `_lastInform` timestamp. This helps prevent returning data for devices that may have been disconnected and their IP reassigned to another device.

### How it works

1. When a device is queried by IP, the API checks the `_lastInform` timestamp from GenieACS
2. If the device hasn't reported within the threshold (default: 30 minutes), it's considered "stale"
3. Stale devices return an error with details about when the device was last seen

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `STALE_THRESHOLD_MINUTES` | `30` | Time in minutes after which a device is considered stale |

Set to `0` to disable stale device validation.

### Example Error Response

```json
{
  "code": 404,
  "status": "Not Found",
  "error": "device with IP 10.90.14.41 is stale (last seen: 45 minutes ago). The IP may have been reassigned to another device"
}
```

---

## Security Best Practices

1. **Always use HTTPS** in production
2. **Enable authentication** (`MIDDLEWARE_AUTH=true`) in production
3. **Use strong API keys** - at least 32 characters with mixed case, numbers, and symbols
4. **Restrict CORS origins** - don't use `*` in production
5. **Never commit `.env` files** with real credentials
6. **Monitor audit logs** for suspicious activity
7. **Keep dependencies updated** - run `make check-deps` regularly
