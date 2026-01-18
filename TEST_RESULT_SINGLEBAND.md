# Test Results - Single-Band Device

**Test Date:** 2026-01-18
**Device:** CDATA FD512XW-R460 (Single-Band)
**Device IP:** 10.21.0.32
**Band Type:** 2.4GHz only (WLAN 1-4)

---

## Device Information

| Property | Value |
|----------|-------|
| Model | FD512XW-R460 |
| Band Type | singleband |
| Is Dual Band | false |
| Device ID | D05FAF-FD512XW%2DR460-CDTCAF8583D6 |
| Total Slots (2.4GHz) | 1, 2, 3, 4 |
| Total Slots (5GHz) | None |

---

## Test Results Summary

| # | Endpoint | Method | Status | Result |
|---|----------|--------|--------|--------|
| 1 | /health | GET | 200 OK | PASS |
| 2 | /api/v1/genieacs/capability/{ip} | GET | 200 OK | PASS |
| 3 | /api/v1/genieacs/wlan/available/{ip} | GET | 200 OK | PASS |
| 4 | /api/v1/genieacs/ssid/{ip} | GET | 200 OK | PASS |
| 5 | /api/v1/genieacs/force/ssid/{ip} | GET | 200 OK | PASS |
| 6 | /api/v1/genieacs/ssid/{ip}/refresh | POST | 202 Accepted | PASS |
| 7 | /api/v1/genieacs/dhcp-client/{ip} | GET | 200 OK | PASS |
| 8 | /api/v1/genieacs/wlan/create/{wlan}/{ip} | POST | 200 OK | PASS |
| 9 | /api/v1/genieacs/wlan/update/{wlan}/{ip} | PUT | 200 OK | PASS |
| 10 | /api/v1/genieacs/wlan/optimize/{wlan}/{ip} | PUT | 200 OK | PASS |
| 11 | /api/v1/genieacs/wlan/delete/{wlan}/{ip} | DELETE | 200 OK | PASS |
| 12 | /api/v1/genieacs/cache/clear | POST | 200 OK | PASS |

---

## Detailed Test Results

### 1. Health Check

**Request:**
```http
GET /health
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "status": "healthy"
  }
}
```

---

### 2. Get Device Capability

**Request:**
```http
GET /api/v1/genieacs/capability/10.90.5.92
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "model": "FD512XW-R460",
    "band_type": "singleband",
    "is_dual_band": false
  }
}
```

---

### 3. Get Available WLAN Slots

**Request:**
```http
GET /api/v1/genieacs/wlan/available/10.90.5.92
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF8583D6",
    "model": "FD512XW-R460",
    "band_type": "singleband",
    "total_slots": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": []
    },
    "used_wlan": [
      {"wlan_id": 1, "ssid": "MyNewSSID", "band": "2.4GHz"},
      {"wlan_id": 3, "ssid": "HiddenNetwork", "band": "2.4GHz"}
    ],
    "available_wlan": {
      "2_4ghz": [2, 4],
      "5ghz": []
    },
    "config_options": {
      "auth_modes": ["Open", "WPA", "WPA2", "WPA/WPA2"],
      "encryptions": ["AES", "TKIP", "TKIP+AES"],
      "max_clients": {"min": 1, "max": 64, "default": 32}
    }
  }
}
```

---

### 4. Get SSID

**Request:**
```http
GET /api/v1/genieacs/ssid/10.90.5.92
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": [
    {
      "wlan": "1",
      "ssid": "MyNewSSID",
      "password": "NewPassword123",
      "band": "2.4GHz",
      "hidden": false,
      "auth_mode": "WPA/WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "3",
      "ssid": "HiddenNetwork",
      "password": "HiddenPass123",
      "band": "2.4GHz",
      "hidden": true,
      "auth_mode": "WPA2",
      "encryption": "TKIP+AES"
    }
  ]
}
```

---

### 5. Get SSID (Force Refresh)

**Request:**
```http
GET /api/v1/genieacs/force/ssid/10.90.5.92
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "attempts": 1,
    "wlan_data": [
      {
        "wlan": "1",
        "ssid": "MyNewSSID",
        "password": "NewPassword123",
        "band": "2.4GHz",
        "hidden": false,
        "auth_mode": "WPA/WPA2",
        "encryption": "TKIP+AES"
      },
      {
        "wlan": "3",
        "ssid": "HiddenNetwork",
        "password": "HiddenPass123",
        "band": "2.4GHz",
        "hidden": true,
        "auth_mode": "WPA2",
        "encryption": "TKIP+AES"
      }
    ]
  }
}
```

---

### 6. Trigger SSID Refresh

**Request:**
```http
POST /api/v1/genieacs/ssid/10.90.5.92/refresh
X-API-Key: YourSecretKey
```

**Response:**
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

### 7. Get DHCP Clients

**Request:**
```http
GET /api/v1/genieacs/dhcp-client/10.90.5.92
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": null
}
```

> Note: Returns `null` when no DHCP clients are connected.

---

### 8. Create WLAN

**Request:**
```http
POST /api/v1/genieacs/wlan/create/2/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "TestSingleBand",
  "password": "TestPass123",
  "hidden": false,
  "max_clients": 15,
  "auth_mode": "WPA2",
  "encryption": "AES"
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "auth_mode": "WPA2",
    "band": "2.4GHz",
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF8583D6",
    "encryption": "AES",
    "hidden": false,
    "ip": "10.90.5.92",
    "max_clients": 15,
    "message": "WLAN creation submitted successfully",
    "ssid": "TestSingleBand",
    "wlan": "2"
  }
}
```

---

### 9. Update WLAN

#### 9.1 Full Update

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "UpdatedSingleBand",
  "password": "NewPass456",
  "hidden": true,
  "max_clients": 20
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "2.4GHz",
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF8583D6",
    "ip": "10.90.5.92",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "hidden": true,
      "max_clients": 20,
      "password": "********",
      "ssid": "UpdatedSingleBand"
    },
    "wlan": "2"
  }
}
```

#### 9.2 SSID Only Update

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "SSIDOnlyUpdate"
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "2.4GHz",
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF8583D6",
    "ip": "10.90.5.92",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "ssid": "SSIDOnlyUpdate"
    },
    "wlan": "2"
  }
}
```

---

### 10. Optimize WLAN

#### 10.1 Full Optimization

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "6",
  "mode": "b/g/n",
  "bandwidth": "20MHz",
  "transmit_power": 100
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "2.4GHz",
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF8583D6",
    "ip": "10.90.5.92",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "bandwidth": "20MHz",
      "channel": "6",
      "mode": "b/g/n",
      "transmit_power": 100
    },
    "wlan": "1"
  }
}
```

#### 10.2 Auto Channel

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "Auto"
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "2.4GHz",
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF8583D6",
    "ip": "10.90.5.92",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "channel": "Auto"
    },
    "wlan": "1"
  }
}
```

---

### 11. Delete WLAN

**Request:**
```http
DELETE /api/v1/genieacs/wlan/delete/2/10.90.5.92
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "2.4GHz",
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF8583D6",
    "ip": "10.90.5.92",
    "message": "WLAN deletion submitted successfully",
    "wlan": "2"
  }
}
```

---

### 12. Clear Cache

**Request:**
```http
POST /api/v1/genieacs/cache/clear
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "message": "Cache cleared"
  }
}
```

---

## Error Handling Tests

### Invalid IP Address

**Request:**
```http
GET /api/v1/genieacs/ssid/invalid-ip
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 404,
  "status": "Not Found",
  "error": "Invalid IP address format"
}
```

---

### Missing SSID

**Request:**
```http
POST /api/v1/genieacs/wlan/create/2/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "password": "TestPass123"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "SSID value required"
}
```

---

### Password Too Short

**Request:**
```http
POST /api/v1/genieacs/wlan/create/2/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "Test",
  "password": "short"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password must be at least 8 characters"
}
```

---

### 5GHz WLAN on Single-Band Device

**Request:**
```http
POST /api/v1/genieacs/wlan/create/5/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "Test5GHz",
  "password": "TestPass123"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "this device does not support 5GHz WLAN (IDs 5-8), available WLAN IDs: 1-4"
}
```

---

### Invalid Channel for 2.4GHz

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "99"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid channel for 2.4GHz band, valid channels: Auto, 1-13"
}
```

---

### Invalid Mode for 2.4GHz (5GHz Mode)

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "mode": "a/n/ac"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid mode for 2.4GHz band, valid modes: b, g, n, b/g, g/n, b/g/n"
}
```

---

### Invalid Bandwidth for 2.4GHz (80MHz)

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.5.92
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "bandwidth": "80MHz"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid bandwidth for 2.4GHz band, valid values: 20MHz, 40MHz, Auto"
}
```

---

## Configuration Options (2.4GHz Single-Band)

### Valid Channels
- Auto, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13

### Valid Modes
- b, g, n, b/g, g/n, b/g/n

### Valid Bandwidth
- 20MHz, 40MHz, Auto

### Valid Transmit Power
- 0, 20, 40, 60, 80, 100 (percentage)

### Valid Auth Modes
- Open, WPA, WPA2, WPA/WPA2

### Valid Encryptions
- AES, TKIP, TKIP+AES

### Max Clients Range
- Min: 1
- Max: 64
- Default: 32

---

## Conclusion

All endpoints tested successfully on single-band device CDATA FD512XW-R460. The API correctly:

1. Detects single-band device capability
2. Returns only 2.4GHz WLAN slots (1-4)
3. Rejects 5GHz WLAN creation (IDs 5-8)
4. Validates 2.4GHz-specific parameters (channels, modes, bandwidth)
5. Returns enhanced SSID response with hidden, auth_mode, and encryption fields
6. Handles all CRUD operations for WLAN configuration
7. Provides proper error messages for invalid inputs
