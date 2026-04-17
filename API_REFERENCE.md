# GenieACS Relay API Reference

**Version:** 2.2.0-dev (25 new endpoints complete, release pending)
**Last Updated:** 2026-04-14

This document provides complete API reference with request/response examples for all GenieACS Relay endpoints. **v2.2.0** adds 25 new endpoints (Section 17) to support auto-learning OLT deployments where the OLT doesn't push customer profile config — see `V2.2.0-DESIGN.md` in the repo root for the design doc.

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
17. [v2.2.0 Endpoints — Auto-Learn OLT Support (25 new)](#17-v220-endpoints--auto-learn-olt-support-25-new)
18. [Error Cases](#18-error-cases)
19. [Authentication Error Cases](#19-authentication-error-cases-middleware_authtrue)

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

## 14. CPE Reboot Endpoint (v2.1.0, E2E verified in v2.2.0)

### POST /api/v1/genieacs/reboot/{ip}

Triggers a **TR-069 Reboot RPC** against the CPE identified by IP.
The call is dispatched through the GenieACS NBI as a `{"name":"reboot"}`
task with `?connection_request` so the call blocks until either the
task is applied synchronously (200 OK) or queued asynchronously when
the connection request fails (202 Accepted). Both status codes indicate
successful task submission per the NBI contract.

Actual CPE reboot takes 30-90 seconds typical before the device
reconnects to the ACS. Callers (typically the future `RestartOnu`
workflow in `isp-agent` v2+) should **NOT** block waiting for the
device to come back — the workflow's retry policy or a follow-up
health check is the right tool for that.

> **Slow-boot anomaly observed during real-device verification** — on
> a real ZTE F670L running V9.0.10P1N12A, the observed total downtime
> was **6 min 52 seconds**, well outside the 30-90s docstring spec.
> Root cause unconfirmed but likely specific to this ZTE firmware
> revision's config-parsing path or lab-VPN WAN re-establishment.
> Callers deploying on ZTE fleets with this firmware should budget
> **up to ~7 minutes** before treating a reboot as failed. A
> docstring patch is scheduled for v2.2.1. See CHANGELOG.md `[2.2.0]`
> real-device verification block for the full test timeline.

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

## 17. v2.2.0 Endpoints — Auto-Learn OLT Support (25 new)

This section documents the 25 new endpoints added in v2.2.0 to
support **auto-learning OLT deployments** (Hioso, HSGQ, Jolink, CDATA
auto mode, etc.). In those topologies the OLT does **not** push
customer profile config — it only bridges traffic — so **all**
customer-facing configuration must flow through TR-069 from the
GenieACS plane. v2.1.0's CRUD slice was too narrow for that workflow;
v2.2.0 expands the surface to cover lifecycle, inspection,
provisioning, diagnostics, and customer self-service features.

Endpoints are grouped by priority tier:

- **HIGH priority (7)** — operational essentials for auto-learn ISP
  scenarios
- **MEDIUM priority (8)** — NOC support tools
- **LOW priority (10)** — customer-facing self-service + metadata

All 25 endpoints share the same response envelope, idempotency
middleware, audit logging, and API-key authentication as the v1.x /
v2.1.0 endpoints. See `V2.2.0-DESIGN.md` in the repo root for the
full design doc with endpoint contracts and vendor caveats.

### 17.1 HIGH priority endpoints

#### POST /api/v1/genieacs/factory-reset/{ip}  (H6)

**TR-069 FactoryReset RPC. DESTRUCTIVE.**

Triggers a TR-069 FactoryReset against the CPE. The device loses all
locally-stored config (PPPoE credentials, WLAN, port-forward rules,
static DHCP leases, etc.), reboots, and rejoins the ACS in a fresh
provisioning state. Unreachable for 60-180 seconds during the reset
cycle. Used by RMA flows and customer-requested "reset my modem"
support tickets. Fire-and-forget — does NOT block waiting for the
device to come back.

```bash
curl -X POST http://localhost:8080/api/v1/genieacs/factory-reset/192.168.1.1 \
  -H "X-API-Key: your-api-key"
```

**Response (202 Accepted):**
```json
{
  "code": 202,
  "status": "success",
  "data": {
    "message": "FactoryReset task submitted. Device will be unreachable for 60-180 seconds, will lose its current PPPoE credentials and WLAN config, and will rejoin the ACS in a fresh provisioning state."
  }
}
```

**⚠️ Real-lab constraint:** DO NOT run against production CPE
without a recovery plan — the device's admin-set config is lost
permanently once the reset is applied.

> **Real-device verification (2026-04-15)** — end-to-end verified on
> a real ZTE F670L V9.0.10P1N12A via VPN lab. Observed: HTTP 202,
> ping drop at T+11s (faster than reboot's T+32s because FactoryReset
> is a more direct RPC), full ping recovery at T+1:45 for **1:34
> total downtime** — within the documented 60-180s window. PASS
> verdict supported by four independent evidence vectors (downtime
> signature distinct from reboot on the same unit, post-recovery
> credential drift proving device-side creds were wiped, clean task
> queue transition, timing match). See CHANGELOG.md `[2.2.0]`
> real-device verification block for the full reasoning chain.

> **⚠️ Production-deployment blocker (genieacs-stack v1.3.1 pending)**
> — after factory-reset, genieacs cannot wake the device via
> `POST /wake/{ip}` until the device informs on its own periodic cycle
> (30 min default). Root cause is a stock `/init` provision in
> upstream genieacs-stack: it writes a numeric `PeriodicInformTime`
> that ZTE rejects with fault 9007, and TR-069 atomic rollback wipes
> the sibling `ConnectionRequestUsername`/`Password` writes in the
> same `setParameterValues` call, so genieacs ends up with cached
> ACS-side credentials that no longer match what the freshly-reset
> device expects. The earlier mongo-side mitigation does **not**
> survive a factory-reset cycle. Permanent fix ships in
> `genieacs-stack v1.3.1`. NOT a relay bug; relay code is correct.
> Do not wire `isp-agent v0.2+` `FactoryResetCpe` customer workflow
> until `genieacs-stack v1.3.1` has landed.

#### POST /api/v1/genieacs/wake/{ip}  (H2)

**Fires a TR-069 ConnectionRequest without queuing real work.**

Wakes a freshly-installed CPE so the first config push lands
synchronously (instead of queuing until the next periodic inform),
or wakes an idle device for diagnostics, or probes responsiveness.
Implemented as a no-op `getParameterValues` task for
`DeviceInfo.UpTime` (cheapest always-present parameter) submitted
with `?connection_request` enabled. Fire-and-forget; wake takes
1-30 seconds depending on CPE CWMP timer config.

```bash
curl -X POST http://localhost:8080/api/v1/genieacs/wake/192.168.1.1 \
  -H "X-API-Key: your-api-key"
```

**Response (202):**
```json
{
  "code": 202,
  "status": "success",
  "data": {
    "message": "ConnectionRequest dispatched to device. Wake-up takes 1-30 seconds depending on CPE responsiveness."
  }
}
```

#### GET /api/v1/genieacs/status/{ip}  (H1)

**Returns device status snapshot from the cached tree.**

Returns `last_inform` timestamp, computed `online` flag, `uptime_seconds`,
and identification fields (manufacturer, model, software/hardware
version). Walks both TR-098 (`InternetGatewayDevice.DeviceInfo.*`) and
TR-181 (`Device.DeviceInfo.*`) paths so the same handler works across
the Indonesian ONT fleet. `_lastInform` is read directly from the
top-level field (bare RFC3339 string, not wrapped in `_value`). Online
flag = `time.Since(last_inform) < 3*stale_threshold` with a 30-min
fallback when the stale-check env var is disabled.

```bash
curl http://localhost:8080/api/v1/genieacs/status/192.168.1.1 \
  -H "X-API-Key: your-api-key"
```

**Response (200):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "192.168.1.1",
    "last_inform": "2026-04-14T11:35:21Z",
    "last_inform_age_seconds": 42,
    "online": true,
    "uptime_seconds": 1234567,
    "manufacturer": "ZTE",
    "model": "F670L",
    "software_version": "V9.0.10P5N12",
    "hardware_version": "V1.0"
  }
}
```

#### GET /api/v1/genieacs/wan/{ip}  (H4)

**Returns WAN connection state(s) — type, status, external IP, uptime.**

Walks every `WANDevice.{n}.WANConnectionDevice.{m}.WANPPPConnection.{k}`
and `WANIPConnection.{k}` instance in the cached tree and surfaces
each as a separate `WANConnectionInfo` entry. Handles multi-WAN and
dual-stack devices (PPPoE on WAN1 + DHCP on WAN2, for example).
Per-connection fields: instance, type (`pppoe`/`dhcp`/`static`/`ipcp`),
connection status, external IP, uptime seconds, PPPoE username
(PPPoE only), last connection error.

```bash
curl http://localhost:8080/api/v1/genieacs/wan/192.168.1.1 \
  -H "X-API-Key: your-api-key"
```

**Response (200):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "192.168.1.1",
    "wan_connections": [
      {
        "instance": 1,
        "type": "pppoe",
        "connection_status": "Connected",
        "external_ip": "203.0.113.45",
        "uptime_seconds": 12345,
        "username": "pppoe-customer-001",
        "last_connection_error": ""
      }
    ]
  }
}
```

#### POST /api/v1/genieacs/params/{ip}  (H7)

**Generic GetParameterValues passthrough.**

NOC L2/L3 debugging tool — inspect arbitrary TR-069 parameter values
without the relay needing a dedicated endpoint per parameter. Up to
50 paths per request, each validated against
`^[a-zA-Z][a-zA-Z0-9_.]*$` (no shell metacharacters or query
injection). Two modes:

- `live=false` (default) — walks the cached device tree immediately
  (sub-100ms)
- `live=true` — dispatches a fresh GetParameterValues task with
  `?connection_request`, clears the cache, then reads the refreshed
  tree

```bash
curl -X POST http://localhost:8080/api/v1/genieacs/params/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "paths": [
      "InternetGatewayDevice.DeviceInfo.UpTime",
      "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username"
    ],
    "live": false
  }'
```

**Response (200):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "192.168.1.1",
    "params": {
      "InternetGatewayDevice.DeviceInfo.UpTime": "1234567",
      "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username": "pppoe-customer-001"
    },
    "missing_paths": [],
    "live": false
  }
}
```

#### PUT /api/v1/genieacs/pppoe/{ip}  (H3)

**Set PPPoE credentials on the CPE. Critical for auto-learn activate flow.**

Without this endpoint, the customer activate flow in auto-learning
OLT topologies has no way to provision the customer's PPPoE username
and password onto the CPE. Submitted via the existing worker pool so
the handler returns 202 immediately; the actual NBI dispatch happens
asynchronously. v2.2.0 hardcodes the TR-098 path
`WANDevice.{n}.WANConnectionDevice.1.WANPPPConnection.1.{Username,Password}`;
v2.3.0 will add TR-181 detection.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/pppoe/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "pppoe-customer-001",
    "password": "secret-pass"
  }'
```

**Validation rules:**
- `username` non-empty, ≤ 64 chars, no whitespace
- `password` non-empty, ≤ 64 chars
- `wan_instance` 1-8 if specified, defaults to 1

**Response (202):**
```json
{
  "code": 202,
  "status": "success",
  "data": {
    "message": "PPPoE credentials updated. Device will reconnect within 30s.",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "192.168.1.1",
    "wan_instance": 1
  }
}
```

#### POST /api/v1/genieacs/firmware/{ip}  (H5)

**TR-069 Download RPC for firmware upgrade. LONG-RUNNING.**

Dispatches a TR-069 Download task against the CPE. Returns 202 +
GenieACS task ID immediately; does NOT block waiting for the download
to complete (typical 60-300s depending on file size and link speed).
Includes HTTPS-only validation + SSRF guard rejecting private IPs /
loopback / link-local / metadata service hostnames.

**⚠️ REAL-LAB CONSTRAINT:** DO NOT test against production CPE
without an offline-verified firmware blob matching the exact ONU
model. A wrong firmware image **bricks the device**.

```bash
curl -X POST http://localhost:8080/api/v1/genieacs/firmware/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "file_url": "https://firmware.example.com/zte-f670l-v9.0.11.bin",
    "file_type": "1 Firmware Upgrade Image",
    "file_size": 12345678,
    "command_key": "fleet-rollout-2026-04-14"
  }'
```

**Response (202):**
```json
{
  "code": 202,
  "status": "success",
  "data": {
    "task_id": "67abc1234567890abcdef123",
    "message": "Firmware download dispatched. Use the returned task_id to poll status.",
    "estimated_duration_seconds": 180
  }
}
```

**SSRF guard rejects:**
- Non-HTTPS schemes (plain HTTP, FTP, file://)
- Private IPs (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`)
- Loopback (`127.x.x.x`, `::1`)
- Link-local (`169.254.x.x`, `fe80::/10`)
- Metadata service hostnames (`localhost`, `metadata`,
  `metadata.google.internal`)
- Unspecified (`0.0.0.0`)

---

### 17.2 MEDIUM priority endpoints

#### POST /api/v1/genieacs/diag/ping/{ip}  (M1)

**TR-069 IPPingDiagnostics dispatch. Long-running; poll result separately.**

Sets the IPPingDiagnostics parameters (Host, NumberOfRepetitions,
Timeout, DataBlockSize, DSCP) + `DiagnosticsState=Requested` to
trigger the run. The trigger entry MUST be last per TR-069 §A.4.1 so
the CPE applies all inputs before starting the diagnostic. Returns
202 + the list of result parameter paths the caller should poll via
`POST /params/{ip}` after 5-15 seconds. Polling is delegated to the
caller to keep the relay request-handler thread decoupled from CPE
inform latency.

```bash
curl -X POST http://localhost:8080/api/v1/genieacs/diag/ping/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "8.8.8.8",
    "count": 4,
    "timeout_ms": 5000
  }'
```

**Response (202):**
```json
{
  "code": 202,
  "status": "success",
  "data": {
    "message": "Diagnostic task dispatched. Poll /params/{ip} for the diagnostic result paths after 5-15 seconds.",
    "device_id": "...",
    "ip": "192.168.1.1",
    "diagnostic": "ping",
    "result_paths": [
      "InternetGatewayDevice.IPPingDiagnostics.DiagnosticsState",
      "InternetGatewayDevice.IPPingDiagnostics.SuccessCount",
      "InternetGatewayDevice.IPPingDiagnostics.FailureCount",
      "InternetGatewayDevice.IPPingDiagnostics.AverageResponseTime",
      "InternetGatewayDevice.IPPingDiagnostics.MinimumResponseTime",
      "InternetGatewayDevice.IPPingDiagnostics.MaximumResponseTime"
    ]
  }
}
```

**Validation rules:** count 1-64, timeout 100-60000ms.

#### POST /api/v1/genieacs/diag/traceroute/{ip}  (M2)

**TR-069 TraceRouteDiagnostics dispatch.** Same pattern as M1, with
`max_hops` instead of `count`.

```bash
curl -X POST http://localhost:8080/api/v1/genieacs/diag/traceroute/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"host":"8.8.8.8","max_hops":30,"timeout_ms":5000}'
```

#### GET /api/v1/genieacs/wifi-clients/{ip}  (M3)

**Returns associated WiFi clients across all WLAN radios.**

Walks `LANDevice.1.WLANConfiguration.{n}.AssociatedDevice.{m}`
(TR-098). Distinct from `/dhcp-client/{ip}` — this reads the WLAN
association table directly, which includes clients on static IPs or
clients that haven't asked for DHCP. Per-client fields: MAC, WLAN
instance, SSID, band, signal strength dBm, authentication state.
Reads both `X_SignalStrength` vendor extension and standard
`SignalStrength` paths.

```bash
curl http://localhost:8080/api/v1/genieacs/wifi-clients/192.168.1.1 \
  -H "X-API-Key: your-api-key"
```

**Response (200):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "device_id": "...",
    "ip": "192.168.1.1",
    "clients": [
      {
        "mac": "AA:BB:CC:DD:EE:FF",
        "wlan": 1,
        "ssid": "MyWiFi-2.4GHz",
        "band": "2.4GHz",
        "signal_strength_dbm": -55,
        "authenticated": true
      }
    ]
  }
}
```

#### GET /api/v1/genieacs/wifi-stats/{ip}  (M7)

**Returns per-radio WiFi statistics.**

Channel, transmit power (standard `TransmitPower` + vendor `X_TXPower`),
bytes/packets sent and received, error counters. Used by WiFi
optimization recommendations and "my wifi is slow" tickets.

```bash
curl http://localhost:8080/api/v1/genieacs/wifi-stats/192.168.1.1 \
  -H "X-API-Key: your-api-key"
```

#### GET /api/v1/genieacs/devices  (M4)

**Paginated device listing — FIRST endpoint without an `{ip}` URL param.**

Wraps the GenieACS NBI `/devices?query=...` call directly. Optional
filters: `model` (substring), `online` (last inform within 3x stale
threshold), `pppoe_username` (substring). Pagination via
`?page=N&page_size=N` (1-indexed, max 200). Returns lightweight
`DeviceSummary` rows — not the full device tree. Used by admin UI
device discovery flow.

```bash
curl "http://localhost:8080/api/v1/genieacs/devices?page=1&page_size=50&model=F670L" \
  -H "X-API-Key: your-api-key"
```

**Response (200):**
```json
{
  "code": 200,
  "status": "success",
  "data": {
    "page": 1,
    "page_size": 50,
    "count": 2,
    "has_more": false,
    "devices": [
      {
        "device_id": "001141-F670L-ZTEGCFLN794B3A1",
        "ip": "203.0.113.45",
        "last_inform": "2026-04-14T11:35:21Z",
        "manufacturer": "ZTE",
        "model": "F670L",
        "serial": "ZTEGCFLN794B3A1",
        "mac": "AA:BB:CC:DD:EE:FF"
      }
    ]
  }
}
```

#### GET /api/v1/genieacs/devices/search  (M5)

**Single-device lookup by alternative key.**

Exactly one of `?mac=...`, `?serial=...`, or `?pppoe_username=...`
must be provided. Precedence: mac → serial → pppoe_username. Returns
404 if no device matches. Used in the customer onboarding flow when
the IP is not yet known.

```bash
curl "http://localhost:8080/api/v1/genieacs/devices/search?mac=AA:BB:CC:DD:EE:FF" \
  -H "X-API-Key: your-api-key"
```

#### PUT /api/v1/genieacs/qos/{ip}  (M6)

**Per-WAN bandwidth rate limit via TR-069 SetParameterValues.**

Sets `X_DownStreamMaxBitRate` / `X_UpStreamMaxBitRate` on the
standard WANPPPConnection path. At least one rate must be provided;
rates of 0 clear the cap. Vendor-specific QoS extensions
(`X_HW_BandwidthLimit`, `X_TPLINK_QoSManagement`, etc.) are deferred
to v2.3.0.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/qos/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"download_kbps":102400,"upload_kbps":51200}'
```

#### PUT /api/v1/genieacs/bridge-mode/{ip}  (M8)

**Toggle CPE bridge / router mode. COARSE APPROXIMATION.**

Sets `WANPPPConnection.Enable` — `enabled=true` puts CPE in bridge
mode (PPPoE off, customer router handles termination); `enabled=false`
reverts to router mode. Real bridge-mode toggling varies by vendor
and may require multiple parameter writes (disable PPPoE + enable
IP passthrough + switch L2 forwarding); v2.3.0 will add vendor
detection.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/bridge-mode/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}'
```

---

### 17.3 LOW priority endpoints

#### PUT /api/v1/genieacs/ntp/{ip}  (L7)

**Set NTP servers and/or timezone.**

Max 5 NTP server entries (TR-098 schema limit). Either field alone
is valid — "timezone-only" or "servers-only" updates are allowed.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/ntp/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ntp_servers":["pool.ntp.org","time.google.com"],"timezone":"Asia/Jakarta"}'
```

#### PUT /api/v1/genieacs/admin-password/{ip}  (L8)

**Set CPE local web admin password.**

Distinct from PPPoE credentials (`/pppoe/{ip}`) and TR-069 ACS auth.
Password is **NOT echoed** in the response or audit logs for
security.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/admin-password/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"password":"new-admin-password"}'
```

#### PUT /api/v1/genieacs/dmz/{ip}  (L2)

**Set DMZ host on the CPE WAN connection.**

`enabled=true` requires `host_ip`; `enabled=false` clears the DMZ.
Uses vendor extension paths (`X_DMZEnable`, `X_DMZHost`).

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/dmz/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"host_ip":"192.168.1.100"}'
```

#### PUT /api/v1/genieacs/ddns/{ip}  (L3)

**Set DDNS provider, hostname, credentials.**

Uses TR-098 `Services.X_DynDNS.1.*` paths. Username and password are
**NOT echoed** in the response. When `enabled=false`, provider /
hostname / credentials are not required.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/ddns/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "provider": "dyndns.com",
    "hostname": "mycpe.dyndns.com",
    "username": "user",
    "password": "pass"
  }'
```

#### PUT /api/v1/genieacs/port-forwarding/{ip}  (L1)

**Set port forwarding rules at caller-specified slot indexes.**

v2.2.0 uses **set-at-index** semantics — caller specifies which
PortMapping slot to write. Does NOT auto-create new instances
(v2.3.0 enhancement). Use `enabled=false` to disable a slot without
removing it. Max 32 rules per request.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/port-forwarding/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [
      {
        "index": 1,
        "name": "ssh",
        "protocol": "tcp",
        "external_port": 2222,
        "internal_ip": "192.168.1.100",
        "internal_port": 22,
        "enabled": true
      }
    ]
  }'
```

**Protocol values:** `tcp`, `udp`, `both` (→ TR-069 `TCP AND UDP`).

#### PUT /api/v1/genieacs/static-dhcp/{ip}  (L6)

**Set static DHCP lease entries at caller-specified slot indexes.**

Same set-at-index semantics as port forwarding. Max 32 leases.
MAC format validated with `([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/static-dhcp/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "leases": [
      {
        "index": 1,
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.168.1.100",
        "hostname": "my-laptop"
      }
    ]
  }'
```

#### PUT /api/v1/genieacs/wifi-schedule/{ip}  (L4)

**Set parental-control WiFi schedule entries.**

`day` is 0-6 (Sun=0, Sat=6). `start_time` / `end_time` are HH:MM
format (`00:00`-`23:59`). Max 14 entries (2 per day for 7 days).
Uses vendor extension path `X_TimerSchedule` common across ZTE,
Huawei, and FiberHome ONUs. v2.3.0 will add per-vendor detection.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/wifi-schedule/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "schedules": [
      {"day": 1, "start_time": "22:00", "end_time": "06:00", "enabled": true},
      {"day": 2, "start_time": "22:00", "end_time": "06:00", "enabled": true}
    ]
  }'
```

#### PUT /api/v1/genieacs/mac-filter/{ip}  (L5)

**Set WLAN MAC filter list.**

`mode` is `allow` (whitelist) or `deny` (blacklist); canonicalized to
TR-069 `Allow`/`Deny` on the wire. Max 32 MAC entries. Each entry
validated against the standard MAC address regex.

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/mac-filter/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "allow",
    "macs": ["AA:BB:CC:DD:EE:FF","11:22:33:44:55:66"]
  }'
```

#### PUT /api/v1/genieacs/tags/{ip}  (L9)

**Add and remove GenieACS device tags via the NBI.**

Tags are metadata only — they don't trigger TR-069 RPCs. Used by ops
to group devices for bulk operations, alerting, or fleet rollouts.
Wraps NBI `POST /devices/{id}/tags/{tag}` and `DELETE /devices/{id}/tags/{tag}`.
Tag names must match `[a-zA-Z0-9_-]{1,64}`. First failure aborts
the batch (no transactional rollback).

```bash
curl -X PUT http://localhost:8080/api/v1/genieacs/tags/192.168.1.1 \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "add": ["prod", "region-jkt"],
    "remove": ["staging"]
  }'
```

#### GET|PUT|DELETE /api/v1/genieacs/presets/{name}  (L10)

**GenieACS provisioning preset management via NBI passthrough.**

Three methods on the same path. Preset name must match
`[a-zA-Z0-9_-]{1,64}`.

```bash
# Read
curl http://localhost:8080/api/v1/genieacs/presets/prod-default \
  -H "X-API-Key: your-api-key"

# Create / update (body forwarded as-is)
curl -X PUT http://localhost:8080/api/v1/genieacs/presets/prod-default \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"weight": 10, "configurations": []}'

# Delete
curl -X DELETE http://localhost:8080/api/v1/genieacs/presets/prod-default \
  -H "X-API-Key: your-api-key"
```

---

## 18. Error Cases

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

## 19. Authentication Error Cases (MIDDLEWARE_AUTH=true)

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