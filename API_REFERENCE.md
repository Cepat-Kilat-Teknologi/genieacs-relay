# GenieACS Relay API Reference

**Version:** 2.0.0 — aligned with `isp-adapter-standard` and `isp-logging-standard`
**Last Updated:** 2026-04-12

This document provides complete API reference with request/response examples for all GenieACS Relay endpoints.

> **Note:** For device-specific test results, see:
> - [TEST_RESULT_SINGLEBAND.md](TEST_RESULT_SINGLEBAND.md) - Single-band device tests (CDATA FD512XW-R460)
> - [TEST_RESULT_DUALBAND.md](TEST_RESULT_DUALBAND.md) - Dual-band device tests (ZTE F670L)

---

## v2.0.0 Response Envelope — Standard Contract

All endpoints follow a uniform JSON envelope per `isp-adapter-standard`.
This is a **breaking change** from v2.x, which used `"status":"OK"` and a flat `error` string.

### Success envelope (2xx)
```json
{
  "code": 200,
  "status": "success",
  "data": <resource payload>
}
```

### Error envelope (4xx/5xx)
```json
{
  "code": 400,
  "status": "Bad Request",
  "error_code": "VALIDATION_ERROR",
  "data": "<human-readable message>",
  "request_id": "<correlation id echoed from X-Request-ID>"
}
```

### Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 400, 413, 415 | Input failed validation |
| `UNAUTHORIZED` | 401 | Missing or invalid API key |
| `FORBIDDEN` | 403 | Access denied |
| `NOT_FOUND` | 404 | Resource / device not found |
| `CONFLICT` | 409 | Resource already exists (e.g. WLAN slot in use) |
| `TIMEOUT` | 408 | Upstream request timed out |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `INTERNAL_ERROR` | 500 | Unhandled server error |
| `SERVICE_UNAVAILABLE` | 503 | Worker pool saturated or upstream down |

### Standard response headers

Every response carries:

| Header | Value | Purpose |
|---|---|---|
| `X-API-Version` | `v1` | Public API major version |
| `X-App-Version` | semver | Binary version from ldflags (`curl /version` to verify) |
| `X-Build-Commit` | git short SHA | Binary build commit |
| `X-Request-ID` | correlation ID | Echoed from request or auto-generated |

### Idempotency (`X-Idempotency-Key`)

POST/PUT/PATCH/DELETE requests under `/api/v1/genieacs/*` accept an optional
`X-Idempotency-Key` header. The first request with a given key is executed
and its response cached; subsequent requests with the same key within a
7-day TTL replay the cached response without re-executing. Saga-style
retries from billing-agent are safe by design.

Server errors (5xx) are NOT cached — they remain retryable.

---

## Table of Contents

1. [Health / Liveness Probes](#1-health--liveness-probes)
2. [Readiness Probes](#2-readiness-probes)
3. [Version Endpoint](#3-version-endpoint)
4. [Metrics Endpoint](#4-metrics-endpoint)
5. [SSID Endpoints](#5-ssid-endpoints)
6. [DHCP Client Endpoints](#6-dhcp-client-endpoints)
7. [Device Capability Endpoints](#7-device-capability-endpoints)
8. [WLAN Available Endpoints](#8-wlan-available-endpoints)
9. [WLAN Create Endpoints](#9-wlan-create-endpoints)
10. [WLAN Update Endpoints](#10-wlan-update-endpoints)
11. [WLAN Delete Endpoints](#11-wlan-delete-endpoints)
12. [WLAN Optimize Endpoints](#12-wlan-optimize-endpoints)
13. [Cache Endpoints](#13-cache-endpoints)
14. [CPE Reboot Endpoint (v2.1.0)](#14-cpe-reboot-endpoint-v210)
15. [DHCP Refresh Endpoint (v2.1.0)](#15-dhcp-refresh-endpoint-v210)
16. [Optical Health Endpoint (v2.1.0)](#16-optical-health-endpoint-v210)
17. [Error Cases](#17-error-cases)
18. [Authentication Error Cases](#18-authentication-error-cases-middleware_authtrue)

---

## 1. Health / Liveness Probes

### GET /health

Backwards-compatible liveness alias. Public, no authentication required.

**Request:**
```http
GET http://localhost:8080/health
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "status": "healthy"
  }
}
```

### GET /healthz

Kubernetes liveness probe. Identical payload; returns 200 as long as the HTTP server is accepting connections.

```http
GET http://localhost:8080/healthz
```

---

## 2. Readiness Probes

### GET /readyz

Kubernetes readiness probe. Checks upstream GenieACS NBI reachability with a cached 5-second TTL probe (prevents probe storms on k8s). Returns 200 when ready, 503 when GenieACS is unreachable.

**Request:**
```http
GET http://localhost:8080/readyz
```

**Response (200 ready):**
```json
{
  "status": "ready",
  "dependencies": {
    "genieacs": {
      "state": "up"
    }
  }
}
```

**Response (503 not_ready):**
```json
{
  "status": "not_ready",
  "dependencies": {
    "genieacs": {
      "state": "down",
      "error": "request failed: Get \"http://localhost:7557/\": dial tcp: connect: connection refused"
    }
  }
}
```

### GET /ready

Alias of `/readyz` (Fiber convention). Same response shape.

---

## 3. Version Endpoint

### GET /version

Build metadata injected at compile time via `-ldflags`. Returns real values only when built through the CI Docker pipeline or manual `-ldflags`; local dev builds show `"dev"` / `"none"` / `"unknown"` defaults.

**Request:**
```http
GET http://localhost:8080/version
```

**Response (200 OK):**
```json
{
  "version": "2.0.0",
  "commit": "a2a62e0",
  "build_time": "2026-04-12T12:00:00Z",
  "api_version": "v1",
  "uptime": "2h15m30s"
}
```

> **Tip:** after any Docker build, `curl /version` is the fastest way to verify ldflags injection actually worked — a silently-broken Dockerfile will return `"dev"` here.

---

## 4. Metrics Endpoint

### GET /metrics

Prometheus exposition format. Public (no authentication). Used by Prometheus scrape jobs every 15s.

**Standard collectors:**
- `http_requests_total{method, path, status}` — uses chi RoutePattern labels (e.g. `/api/v1/genieacs/wlan/create/{wlan}/{ip}`) to prevent cardinality explosion from IPs-in-path
- `http_request_duration_seconds_bucket{method, path, le}` — latency histogram
- `http_requests_in_flight` — current active requests gauge
- `go_*` / `process_*` — default Go runtime collectors

---

## 5. SSID Endpoints

### GET /api/v1/genieacs/ssid/{ip}

Get SSID information for a device by IP address.

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": [
    {
      "wlan": "1",
      "ssid": "MyNetwork-2G",
      "password": "********",
      "band": "2.4GHz",
      "hidden": false,
      "max_clients": 32,
      "auth_mode": "WPA2",
      "encryption": "AES"
    },
    {
      "wlan": "2",
      "ssid": "GuestNetwork",
      "password": "********",
      "band": "2.4GHz",
      "hidden": true,
      "max_clients": 10,
      "auth_mode": "WPA2",
      "encryption": "AES"
    },
    {
      "wlan": "5",
      "ssid": "MyNetwork-5G",
      "password": "********",
      "band": "5GHz",
      "hidden": false,
      "max_clients": 32,
      "auth_mode": "WPA2",
      "encryption": "AES"
    }
  ]
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| wlan | string | WLAN ID (1-4 for 2.4GHz, 5-8 for 5GHz) |
| ssid | string | Network name |
| password | string | Password (masked as `********` or actual value) |
| band | string | Frequency band (`2.4GHz` or `5GHz`) |
| hidden | boolean | Whether SSID is hidden (not broadcast) |
| max_clients | integer | Maximum connected clients (1-64) |
| auth_mode | string | Authentication mode (`Open`, `WPA`, `WPA2`, `WPA/WPA2`) |
| encryption | string | Encryption type (`AES`, `TKIP`, `TKIP+AES`) |

### GET /api/v1/genieacs/force/ssid/{ip}

Force refresh SSID information from the device.

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/force/ssid/10.90.14.41
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "attempts": 1,
    "wlan_data": [
      {
        "wlan": "1",
        "ssid": "MyNetwork-2G",
        "password": "********",
        "band": "2.4GHz",
        "hidden": false,
        "max_clients": 32,
        "auth_mode": "WPA2",
        "encryption": "AES"
      },
      {
        "wlan": "5",
        "ssid": "MyNetwork-5G",
        "password": "********",
        "band": "5GHz",
        "hidden": false,
        "max_clients": 32,
        "auth_mode": "WPA2",
        "encryption": "AES"
      }
    ]
  }
}
```

### GET /api/v1/genieacs/force/ssid/{ip}?max_retries=5&retry_delay_ms=2000

Force refresh with custom retry parameters.

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/force/ssid/10.90.14.41?max_retries=5&retry_delay_ms=2000
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "attempts": 2,
    "wlan_data": [
      {
        "wlan": "1",
        "ssid": "MyNetwork-2G",
        "password": "MyPassword123",
        "band": "2.4GHz",
        "hidden": false,
        "max_clients": 32,
        "auth_mode": "WPA2",
        "encryption": "AES"
      },
      {
        "wlan": "5",
        "ssid": "MyNetwork-5G",
        "password": "MyPassword456",
        "band": "5GHz",
        "hidden": false,
        "max_clients": 32,
        "auth_mode": "WPA2",
        "encryption": "AES"
      }
    ]
  }
}
```

### POST /api/v1/genieacs/ssid/{ip}/refresh

Trigger SSID refresh task (asynchronous).

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41/refresh
```

**Response (202 Accepted):**
```json
{
  "code": 202,
  "status": "Accepted",
  "data": {
    "message": "Refresh task submitted. Please query the GET endpoint again after a few moments."
  }
}
```

---

## 6. DHCP Client Endpoints

### GET /api/v1/genieacs/dhcp-client/{ip}

Get DHCP client list from a device.

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.14.41
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": [
    {
      "mac": "6c:3b:6b:7a:52:b0",
      "hostname": "",
      "ip": "192.168.213.121"
    }
  ]
}
```

### GET /api/v1/genieacs/dhcp-client/{ip}?refresh=true

Get DHCP client list with force refresh.

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.14.41?refresh=true
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": [
    {
      "mac": "6c:3b:6b:7a:52:b0",
      "hostname": "",
      "ip": "192.168.213.121"
    }
  ]
}
```

---

## 7. Device Capability Endpoints

### GET /api/v1/genieacs/capability/{ip}

Get device capability (single-band/dual-band detection).

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/capability/10.90.14.41
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "model": "F670L",
    "band_type": "dualband",
    "is_dual_band": true
  }
}
```

---

## 8. WLAN Available Endpoints

### GET /api/v1/genieacs/wlan/available/{ip}

Get available WLAN slots for creating new networks.

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/wlan/available/10.90.14.41
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "model": "F670L",
    "band_type": "dualband",
    "total_slots": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": [5, 6, 7, 8]
    },
    "used_wlan": [
      {
        "wlan_id": 1,
        "ssid": "MyNewSSID",
        "band": "2.4GHz"
      },
      {
        "wlan_id": 2,
        "ssid": "HIDE_2G",
        "band": "2.4GHz"
      },
      {
        "wlan_id": 3,
        "ssid": "SecureNetwork",
        "band": "2.4GHz"
      },
      {
        "wlan_id": 5,
        "ssid": "5abib7-5G",
        "band": "5GHz"
      }
    ],
    "available_wlan": {
      "2_4ghz": [4],
      "5ghz": [6, 7, 8]
    },
    "config_options": {
      "auth_modes": ["Open", "WPA", "WPA2", "WPA/WPA2"],
      "encryptions": ["AES", "TKIP", "TKIP+AES"],
      "max_clients": {
        "min": 1,
        "max": 64,
        "default": 32
      }
    }
  }
}
```

---

## 9. WLAN Create Endpoints

### POST /api/v1/genieacs/wlan/create/{wlan}/{ip}

Create a new WLAN network.

#### 2.4GHz WLAN Creation

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/4/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork",
    "password": "TestPass123456",
    "auth_mode": "WPA2",
    "encryption": "AES"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "auth_mode": "WPA2",
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "encryption": "AES",
    "hidden": false,
    "ip": "10.90.14.41",
    "max_clients": 32,
    "message": "WLAN creation submitted successfully",
    "ssid": "TestNetwork",
    "wlan": "4"
  }
}
```

#### 5GHz WLAN Creation

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/6/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork-5G",
    "password": "Test5GPass123",
    "auth_mode": "WPA2",
    "encryption": "AES"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "auth_mode": "WPA2",
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "encryption": "AES",
    "hidden": false,
    "ip": "10.90.14.41",
    "max_clients": 32,
    "message": "WLAN creation submitted successfully",
    "ssid": "TestNetwork-5G",
    "wlan": "6"
  }
}
```

#### Hidden Network Creation

Create a hidden WLAN that won't broadcast its SSID.

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/4/10.90.14.41
Content-Type: application/json

{
    "ssid": "HiddenNetwork",
    "password": "HiddenPass123",
    "hidden": true,
    "auth_mode": "WPA2",
    "encryption": "AES"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "auth_mode": "WPA2",
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "encryption": "AES",
    "hidden": true,
    "ip": "10.90.14.41",
    "max_clients": 32,
    "message": "WLAN creation submitted successfully",
    "ssid": "HiddenNetwork",
    "wlan": "4"
  }
}
```

#### Open Network Creation (No Password)

Create an open network without password (not recommended for production).

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/7/10.90.14.41
Content-Type: application/json

{
    "ssid": "OpenGuestNetwork",
    "auth_mode": "Open"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "auth_mode": "Open",
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "encryption": "AES",
    "hidden": false,
    "ip": "10.90.14.41",
    "max_clients": 32,
    "message": "WLAN creation submitted successfully",
    "ssid": "OpenGuestNetwork",
    "wlan": "7"
  }
}
```

#### WPA/WPA2 Mixed Mode Creation

Create a WLAN with mixed WPA/WPA2 for legacy device compatibility.

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/8/10.90.14.41
Content-Type: application/json

{
    "ssid": "LegacyNetwork-5G",
    "password": "LegacyPass123",
    "auth_mode": "WPA/WPA2",
    "encryption": "TKIP+AES",
    "max_clients": 20
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "auth_mode": "WPA/WPA2",
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "encryption": "TKIP+AES",
    "hidden": false,
    "ip": "10.90.14.41",
    "max_clients": 20,
    "message": "WLAN creation submitted successfully",
    "ssid": "LegacyNetwork-5G",
    "wlan": "8"
  }
}
```

---

## 10. WLAN Update Endpoints

### PUT /api/v1/genieacs/wlan/update/{wlan}/{ip}

Update an existing WLAN network.

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/4/10.90.14.41
Content-Type: application/json

{
    "ssid": "UpdatedNetwork",
    "max_clients": 20
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "max_clients": 20,
      "ssid": "UpdatedNetwork"
    },
    "wlan": "4"
  }
}
```

#### Update Hidden Status Only

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41
Content-Type: application/json

{
    "hidden": true
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "hidden": true
    },
    "wlan": "2"
  }
}
```

#### Update Authentication Mode Only

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/3/10.90.14.41
Content-Type: application/json

{
    "auth_mode": "WPA/WPA2",
    "encryption": "TKIP+AES"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "auth_mode": "WPA/WPA2",
      "encryption": "TKIP+AES"
    },
    "wlan": "3"
  }
}
```

---

## 11. WLAN Delete Endpoints

### DELETE /api/v1/genieacs/wlan/delete/{wlan}/{ip}

Delete/disable a WLAN network.

**Request:**
```http
DELETE http://localhost:8080/api/v1/genieacs/wlan/delete/4/10.90.14.41
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "WLAN deletion submitted successfully",
    "wlan": "4"
  }
}
```

---

## 12. WLAN Optimize Endpoints

### PUT /api/v1/genieacs/wlan/optimize/{wlan}/{ip}

Optimize WLAN settings (channel, mode, bandwidth, transmit power).

#### 2.4GHz Optimization

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41
Content-Type: application/json

{
    "channel": "6",
    "mode": "b/g/n",
    "bandwidth": "40MHz"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "bandwidth": "40MHz",
      "channel": "6",
      "mode": "b/g/n"
    },
    "wlan": "1"
  }
}
```

#### 5GHz Optimization

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/5/10.90.14.41
Content-Type: application/json

{
    "channel": "149",
    "mode": "a/n/ac",
    "bandwidth": "80MHz"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "bandwidth": "80MHz",
      "channel": "149",
      "mode": "a/n/ac"
    },
    "wlan": "5"
  }
}
```

#### Auto Channel Optimization

Set channel to Auto for automatic channel selection.

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41
Content-Type: application/json

{
    "channel": "Auto"
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.14.41",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "channel": "Auto"
    },
    "wlan": "1"
  }
}
```

---

## 13. Cache Endpoints

### POST /api/v1/genieacs/cache/clear

Clear all cached data.

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/cache/clear
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "message": "Cache cleared"
  }
}
```

### POST /api/v1/genieacs/cache/clear?device_id={device_id}

Clear cache for a specific device.

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/cache/clear?device_id=001141-F670L-ZTEGCFLN794B3A1
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "message": "Cache cleared"
  }
}
```

---

## 14. CPE Reboot Endpoint (v2.1.0)

### POST /api/v1/genieacs/reboot/{ip}

Triggers a **TR-069 Reboot RPC** against the CPE identified by IP.
The call is dispatched through the GenieACS NBI as a `{"name":"reboot"}`
task with `?connection_request` so the call blocks until either the
task is applied synchronously (200 OK) or queued asynchronously when
the connection request fails (202 Accepted). Both status codes indicate
successful task submission per the NBI contract.

Actual CPE reboot takes 30-90 seconds before the device reconnects to
the ACS. Callers (typically the future `RestartOnu` workflow in
`isp-agent` v2+) should **NOT** block waiting for the device to come
back — the workflow's retry policy or a follow-up health check is the
right tool for that.

Idempotency middleware applies via the `/api/v1/genieacs` route group,
so double-clicks within the dedup TTL window replay the same response.

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/reboot/192.168.1.100
X-API-Key: your-api-key
X-Idempotency-Key: cmd_abc123
```

**Success Response (202 Accepted):**
```json
{
  "code": 202,
  "status": "success",
  "data": {
    "message": "Reboot task submitted. CPE will reconnect to the ACS in approximately 30-90 seconds."
  },
  "request_id": "..."
}
```

**Error Responses:**
| Code | error_code | Cause |
|---|---|---|
| 400 | `INVALID_IP` | malformed IP in path |
| 404 | `DEVICE_NOT_FOUND` | no device indexed with that IP in GenieACS |
| 500 | `REBOOT_FAILED` | NBI returned 4xx/5xx, task rejected |

---

## 15. DHCP Refresh Endpoint (v2.1.0)

### POST /api/v1/genieacs/dhcp/{ip}/refresh

Forces GenieACS to refresh the `LANDevice.1` (DHCP host) subtree on the
CPE. This is the dedicated endpoint for the side-effect "force refresh"
— distinct from the read endpoint `GET /dhcp-client/{ip}?refresh=true`
which mixes read and side-effect semantics.

Use case: future `RefreshDhcpStatus` workflow in `isp-agent` that
triggers a refresh now and reads the fresh DHCP client list on a
follow-up call. The device cache is cleared so the next
`GET /dhcp-client/{ip}` fetches the fresh post-refresh tree from
GenieACS.

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/dhcp/192.168.1.100/refresh
X-API-Key: your-api-key
X-Idempotency-Key: cmd_abc124
```

**Success Response (202 Accepted):**
```json
{
  "code": 202,
  "status": "success",
  "data": {
    "message": "DHCP refresh task submitted. Read /dhcp-client/{ip} after ~5s for updated data."
  },
  "request_id": "..."
}
```

**Error Responses:**
| Code | error_code | Cause |
|---|---|---|
| 400 | `INVALID_IP` | malformed IP in path |
| 404 | `DEVICE_NOT_FOUND` | no device indexed with that IP |
| 500 | `REFRESH_FAILED` | NBI task submission failed |

---

## 16. Optical Health Endpoint (v2.1.0)

### GET /api/v1/genieacs/optical/{ip}

Reads **optical interface health metrics** from the CPE — TX power,
RX power, temperature, voltage, and bias current. Vendor detection
picks the correct TR-069 parameter path automatically across **5
vendor variants**:

| Vendor | Parameter path |
|---|---|
| ZTE CT-COM EPON | `InternetGatewayDevice.X_CT-COM_EponInterfaceConfig.Stats` |
| ZTE CT-COM GPON | `InternetGatewayDevice.X_CT-COM_GponInterfaceConfig.Stats` |
| Huawei HW_DEBUG | `InternetGatewayDevice.X_HW_DEBUG.AdminTR069.OpticalDiagnostic` |
| Realtek EPON | `InternetGatewayDevice.X_Realtek_EponInterfaceConfig.Stats` |
| Standard TR-181 | `Device.Optical.Interface.1.Stats` |

Detection order matches typical Indonesian ISP deployment frequency
(most ZTE F670L/F660 ONTs in residential PON). First vendor extractor
that returns a populated struct wins.

**Vendor-aware health classification** derives a categorical `health`
field from the raw RX power reading:

| Health | RX power range (dBm) | Interpretation |
|---|---|---|
| `no_signal` | ≤ `OPTICAL_RX_NO_SIGNAL_DBM` (default -30) | fiber disconnected / laser dead |
| `critical` | `(-30, -27]` | immediate attention needed |
| `warning` | `(-27, -24]` | degrading |
| `good` | `(-24, -8]` | normal operation |
| `overload` | `> OPTICAL_RX_OVERLOAD_DBM` (default -8) | too close / saturation |

Thresholds are env-tunable via `OPTICAL_RX_NO_SIGNAL_DBM`,
`OPTICAL_RX_CRITICAL_DBM`, `OPTICAL_RX_WARNING_DBM`,
`OPTICAL_RX_OVERLOAD_DBM`. Invalid values fall back to the defaults
and log a warning.

**Request (read cached):**
```http
GET http://localhost:8080/api/v1/genieacs/optical/192.168.1.100
X-API-Key: your-api-key
```

**Request (force refresh before reading — slower but guaranteed fresh):**
```http
GET http://localhost:8080/api/v1/genieacs/optical/192.168.1.100?refresh=true
X-API-Key: your-api-key
```

With `?refresh=true`, the relay first triggers GenieACS `refreshObject`
tasks against every known optical subtree, clears the local cache, and
then reads the fresh device tree. As long as at least one subtree
accepts the refresh task the call proceeds.

**Success Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "source": "zte-ct-com-epon",
    "rx_power_dbm": -21.3,
    "tx_power_dbm": 2.5,
    "health": "good",
    "temperature_c": 45.0,
    "voltage_v": 3.3,
    "bias_current_ma": 12.0,
    "fetched_at": "2026-04-15T13:00:00Z"
  },
  "request_id": "..."
}
```

**Error Responses:**
| Code | error_code | Cause |
|---|---|---|
| 400 | `INVALID_IP` | malformed IP in path |
| 404 | `DEVICE_NOT_FOUND` | no device indexed with that IP |
| 404 | `OPTICAL_NOT_SUPPORTED` | device found but no known optical parameter tree |
| 500 | `OPTICAL_READ_FAILED` | GenieACS device fetch or refresh failed |

---

## 17. Error Cases

### Invalid IP Address Format

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/ssid/invalid-ip
```

**Response (404 Not Found):**
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "Invalid IP address format"
}
```

### Missing SSID in WLAN Creation

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/2/10.90.14.41
Content-Type: application/json

{
    "password": "TestPass123"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "SSID value required"
}
```

### Password Too Short

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/2/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork",
    "password": "short"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password must be at least 8 characters"
}
```

### Invalid WLAN ID

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/0/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork",
    "password": "TestPass123"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID must be a number between 1 and 99"
}
```

### SSID Too Long (max 32 characters)

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/2/10.90.14.41
Content-Type: application/json

{
    "ssid": "ThisSSIDIsWayTooLongAndExceeds32Characters",
    "password": "TestPass123"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "SSID must be at most 32 characters"
}
```

### Update WLAN with Empty Body

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41
Content-Type: application/json

{}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "At least one field must be provided for update"
}
```

### Optimize WLAN with Empty Body

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41
Content-Type: application/json

{}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "at least one optimization field must be provided (channel, mode, bandwidth, or transmit_power)"
}
```

### Invalid Channel for 2.4GHz Band

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41
Content-Type: application/json

{
    "channel": "99"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid channel for 2.4GHz band. Valid channels: Auto, 1-13"
}
```

### WLAN Not Found

**Request:**
```http
DELETE http://localhost:8080/api/v1/genieacs/wlan/delete/6/10.90.14.41
```

**Response (404 Not Found):**
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "WLAN 6 does not exist or is already disabled on this device."
}
```

### Missing Password for WPA2

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/4/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork",
    "auth_mode": "WPA2"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password is required for WPA, WPA2, or WPA/WPA2 authentication"
}
```

### Invalid Authentication Mode

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/4/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork",
    "password": "TestPass123",
    "auth_mode": "InvalidMode"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid authentication mode. Valid values: Open, WPA, WPA2, WPA/WPA2"
}
```

### Invalid Encryption Mode

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/4/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork",
    "password": "TestPass123",
    "encryption": "InvalidEncryption"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid encryption mode. Valid values: AES, TKIP, TKIP+AES"
}
```

### Max Clients Out of Range

**Request:**
```http
POST http://localhost:8080/api/v1/genieacs/wlan/create/4/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork",
    "password": "TestPass123",
    "max_clients": 100
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Max clients must be between 1 and 64"
}
```

### Update - Invalid SSID (too long)

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41
Content-Type: application/json

{
    "ssid": "ThisSSIDIsWayTooLongAndExceeds32Characters"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "SSID must be at most 32 characters"
}
```

### Update - Invalid Password (too short)

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41
Content-Type: application/json

{
    "password": "short"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password must be at least 8 characters"
}
```

### Update - Invalid Max Clients

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41
Content-Type: application/json

{
    "max_clients": 100
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Max clients must be between 1 and 64"
}
```

### Update - Invalid Authentication Mode

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41
Content-Type: application/json

{
    "auth_mode": "InvalidMode"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid authentication mode. Valid values: Open, WPA, WPA2, WPA/WPA2"
}
```

### Update - Invalid Encryption Mode

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/2/10.90.14.41
Content-Type: application/json

{
    "encryption": "InvalidEncryption"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid encryption mode. Valid values: AES, TKIP, TKIP+AES"
}
```

### Update - WLAN Not Found

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/update/8/10.90.14.41
Content-Type: application/json

{
    "ssid": "TestNetwork"
}
```

**Response (404 Not Found):**
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "WLAN 8 does not exist or is not enabled on this device. Use the create endpoint to create it first."
}
```

### Delete - Invalid WLAN ID (0)

**Request:**
```http
DELETE http://localhost:8080/api/v1/genieacs/wlan/delete/0/10.90.14.41
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID must be a number between 1 and 99"
}
```

### Delete - Invalid WLAN ID (9)

**Request:**
```http
DELETE http://localhost:8080/api/v1/genieacs/wlan/delete/9/10.90.14.41
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID must be between 1 and 8"
}
```

### Optimize - Invalid Channel for 5GHz Band

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/5/10.90.14.41
Content-Type: application/json

{
    "channel": "100"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid channel for 5GHz band. Valid channels: Auto, 36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161"
}
```

### Optimize - Invalid Mode for 2.4GHz Band

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41
Content-Type: application/json

{
    "mode": "invalid"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid mode for 2.4GHz band. Valid modes: b, g, n, b/g, g/n, b/g/n"
}
```

### Optimize - Invalid Mode for 5GHz Band (using 2.4GHz mode)

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/5/10.90.14.41
Content-Type: application/json

{
    "mode": "b/g/n"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid mode for 5GHz band. Valid modes: a, n, ac, a/n, a/n/ac"
}
```

### Optimize - Invalid Bandwidth for 2.4GHz Band

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41
Content-Type: application/json

{
    "bandwidth": "160MHz"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid bandwidth for 2.4GHz band. Valid values: 20MHz, 40MHz, Auto"
}
```

### Optimize - Invalid Transmit Power

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/1/10.90.14.41
Content-Type: application/json

{
    "transmit_power": 50
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid transmit power. Valid values: 0, 20, 40, 60, 80, 100 (percentage)"
}
```

### Optimize - Invalid Bandwidth for 5GHz Band

**Request:**
```http
PUT http://localhost:8080/api/v1/genieacs/wlan/optimize/5/10.90.14.41
Content-Type: application/json

{
    "bandwidth": "160MHz"
}
```

**Response (400 Bad Request):**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid bandwidth for 5GHz band. Valid values: 20MHz, 40MHz, 80MHz, Auto"
}
```

---

## 18. Authentication Error Cases (MIDDLEWARE_AUTH=true)

When `MIDDLEWARE_AUTH=true` is enabled, API key authentication is required for all `/api/v1/genieacs/*` endpoints.

### Missing API Key

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41
Content-Type: application/json
```

**Response (401 Unauthorized):**
```json
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Missing X-API-Key header"
}
```

### Invalid API Key

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41
Content-Type: application/json
X-API-Key: WrongApiKey
```

**Response (401 Unauthorized):**
```json
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Invalid API key"
}
```

### Successful Authentication

**Request:**
```http
GET http://localhost:8080/api/v1/genieacs/ssid/10.90.14.41
Content-Type: application/json
X-API-Key: YourSecretKey
```

**Response (200 OK):**
```json
{
  "code": 200,
  "status": "success",
  "data": [
    {
      "wlan": "1",
      "ssid": "MyNetwork-2G",
      "password": "********",
      "band": "2.4GHz",
      "hidden": false,
      "max_clients": 32,
      "auth_mode": "WPA2",
      "encryption": "AES"
    }
  ]
}
```

---

## Test Summary

### Endpoint Tests

| Category | Endpoint | Status |
|----------|----------|--------|
| Health | GET /health | PASS |
| SSID | GET /ssid/{ip} | PASS |
| SSID | GET /force/ssid/{ip} | PASS |
| SSID | GET /force/ssid/{ip}?max_retries&retry_delay_ms | PASS |
| SSID | POST /ssid/{ip}/refresh | PASS |
| DHCP | GET /dhcp-client/{ip} | PASS |
| DHCP | GET /dhcp-client/{ip}?refresh=true | PASS |
| Capability | GET /capability/{ip} | PASS |
| WLAN | GET /wlan/available/{ip} | PASS |
| WLAN | POST /wlan/create/{wlan}/{ip} (2.4GHz) | PASS |
| WLAN | POST /wlan/create/{wlan}/{ip} (5GHz) | PASS |
| WLAN | POST /wlan/create (hidden network) | PASS |
| WLAN | POST /wlan/create (open network) | PASS |
| WLAN | POST /wlan/create (WPA/WPA2 mixed) | PASS |
| WLAN | PUT /wlan/update/{wlan}/{ip} | PASS |
| WLAN | PUT /wlan/update (hidden only) | PASS |
| WLAN | PUT /wlan/update (auth_mode only) | PASS |
| WLAN | DELETE /wlan/delete/{wlan}/{ip} | PASS |
| WLAN | PUT /wlan/optimize/{wlan}/{ip} (2.4GHz) | PASS |
| WLAN | PUT /wlan/optimize/{wlan}/{ip} (5GHz) | PASS |
| WLAN | PUT /wlan/optimize (Auto channel) | PASS |
| Cache | POST /cache/clear | PASS |
| Cache | POST /cache/clear?device_id={id} | PASS |

### Error Handling Tests

| Category | Test Case | Status |
|----------|-----------|--------|
| Validation | Invalid IP address | PASS |
| Validation | Missing SSID | PASS |
| Validation | Password too short | PASS |
| Validation | Invalid WLAN ID (0) | PASS |
| Validation | SSID too long (>32 chars) | PASS |
| Validation | Empty update body | PASS |
| Validation | Empty optimize body | PASS |
| Validation | Invalid channel (2.4GHz) | PASS |
| Validation | Invalid channel (5GHz) | PASS |
| Validation | Missing password for WPA2 | PASS |
| Validation | Invalid auth mode | PASS |
| Validation | Invalid encryption mode | PASS |
| Validation | Max clients out of range | PASS |
| Update | Invalid SSID (too long) | PASS |
| Update | Invalid password (too short) | PASS |
| Update | Invalid max clients | PASS |
| Update | Invalid auth mode | PASS |
| Update | Invalid encryption mode | PASS |
| Update | WLAN not found | PASS |
| Delete | Invalid WLAN ID (0) | PASS |
| Delete | Invalid WLAN ID (9) | PASS |
| Delete | WLAN not found | PASS |
| Optimize | Invalid mode (2.4GHz) | PASS |
| Optimize | Invalid mode (5GHz) | PASS |
| Optimize | Invalid bandwidth (2.4GHz) | PASS |
| Optimize | Invalid bandwidth (5GHz) | PASS |
| Optimize | Invalid transmit power | PASS |

### Authentication Tests (MIDDLEWARE_AUTH=true)

| Category | Test Case | Status |
|----------|-----------|--------|
| Auth | Missing API Key | PASS |
| Auth | Invalid API Key | PASS |
| Auth | Valid API Key | PASS |

---

**Total: 53 test cases documented**

---

## Related Documentation

- [TEST_RESULT_SINGLEBAND.md](TEST_RESULT_SINGLEBAND.md) - Single-band device test results (CDATA FD512XW-R460)
- [TEST_RESULT_DUALBAND.md](TEST_RESULT_DUALBAND.md) - Dual-band device test results (ZTE F670L)
- [test_singleband.http](test_singleband.http) - HTTP test file for single-band devices
- [test_dualband.http](test_dualband.http) - HTTP test file for dual-band devices