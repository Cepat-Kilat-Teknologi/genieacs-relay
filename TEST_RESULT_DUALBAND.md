# Test Results - Dual-Band Device

**Test Date:** 2026-01-18
**Device:** ZTE F670L (Dual-Band)
**Device IP:** 10.0.7.2
**Band Type:** 2.4GHz + 5GHz (WLAN 1-8)

---

## Device Information

| Property | Value |
|----------|-------|
| Model | F670L |
| Band Type | dualband |
| Is Dual Band | true |
| Device ID | 001141-F670L-ZTEGCFLN794B3A1 |
| Total Slots (2.4GHz) | 1, 2, 3, 4 |
| Total Slots (5GHz) | 5, 6, 7, 8 |

---

## Test Results Summary

### Endpoint Tests

| # | Endpoint | Method | Status | Result |
|---|----------|--------|--------|--------|
| 1 | /health | GET | 200 OK | PASS |
| 2 | /api/v1/genieacs/capability/{ip} | GET | 200 OK | PASS |
| 3 | /api/v1/genieacs/wlan/available/{ip} | GET | 200 OK | PASS |
| 4 | /api/v1/genieacs/ssid/{ip} | GET | 200 OK | PASS |
| 5 | /api/v1/genieacs/force/ssid/{ip} | GET | 200 OK | PASS |
| 6 | /api/v1/genieacs/ssid/{ip}/refresh | POST | 202 Accepted | PASS |
| 7 | /api/v1/genieacs/dhcp-client/{ip} | GET | 200 OK | PASS |
| 8 | /api/v1/genieacs/wlan/create/{wlan}/{ip} (2.4GHz) | POST | 409 Conflict | PASS |
| 9 | /api/v1/genieacs/wlan/create/{wlan}/{ip} (5GHz) | POST | 409 Conflict | PASS |
| 10 | /api/v1/genieacs/wlan/update/{wlan}/{ip} (2.4GHz) | PUT | 200 OK | PASS |
| 11 | /api/v1/genieacs/wlan/update/{wlan}/{ip} (5GHz) | PUT | 200 OK | PASS |
| 12 | /api/v1/genieacs/wlan/optimize/{wlan}/{ip} (2.4GHz) | PUT | 200 OK | PASS |
| 13 | /api/v1/genieacs/wlan/optimize/{wlan}/{ip} (5GHz) | PUT | 200 OK | PASS |
| 14 | /api/v1/genieacs/wlan/delete/{wlan}/{ip} (2.4GHz) | DELETE | 200 OK | PASS |
| 15 | /api/v1/genieacs/wlan/delete/{wlan}/{ip} (5GHz) | DELETE | 200 OK | PASS |
| 16 | /api/v1/genieacs/cache/clear | POST | 200 OK | PASS |

### Error Handling Tests

| # | Test Case | Expected Status | Result |
|---|-----------|-----------------|--------|
| 1 | Invalid WLAN ID (9) | 400 Bad Request | PASS |
| 2 | 5GHz Mode on 2.4GHz WLAN | 400 Bad Request | PASS |
| 3 | 2.4GHz Mode on 5GHz WLAN | 400 Bad Request | PASS |
| 4 | 80MHz Bandwidth on 2.4GHz | 400 Bad Request | PASS |
| 5 | 160MHz Bandwidth on 5GHz | 400 Bad Request | PASS |
| 6 | 2.4GHz Channel on 5GHz WLAN | 400 Bad Request | PASS |
| 7 | 5GHz Channel on 2.4GHz WLAN | 400 Bad Request | PASS |
| 8 | Invalid Max Clients (100) | 400 Bad Request | PASS |
| 9 | Invalid Max Clients (0) | 400 Bad Request | PASS |
| 10 | Invalid Encryption (WEP) | 400 Bad Request | PASS |
| 11 | Invalid Auth Mode (WPA3) | 400 Bad Request | PASS |
| 12 | Password Too Short | 400 Bad Request | PASS |
| 13 | SSID Too Long | 400 Bad Request | PASS |
| 14 | Invalid WLAN ID (0) | 400 Bad Request | PASS |

**Total Tests: 30 (16 endpoint + 14 error handling)**

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
GET /api/v1/genieacs/capability/10.90.7.129
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "model": "F670L",
    "band_type": "dualband",
    "is_dual_band": true
  }
}
```

---

### 3. Get Available WLAN Slots

**Request:**
```http
GET /api/v1/genieacs/wlan/available/10.90.7.129
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "model": "F670L",
    "band_type": "dualband",
    "total_slots": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": [5, 6, 7, 8]
    },
    "used_wlan": [],
    "available_wlan": {
      "2_4ghz": [1, 2, 3, 4],
      "5ghz": [5, 6, 7, 8]
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
GET /api/v1/genieacs/ssid/10.90.7.129
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
      "ssid": "TestSSIDUpdate",
      "password": "********",
      "band": "2.4GHz",
      "hidden": false,
      "auth_mode": "WPA/WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "2",
      "ssid": "HIDE_2G",
      "password": "********",
      "band": "2.4GHz",
      "hidden": true,
      "auth_mode": "WPA/WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "3",
      "ssid": "SecureNetwork",
      "password": "********",
      "band": "2.4GHz",
      "hidden": false,
      "auth_mode": "WPA/WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "4",
      "ssid": "HiddenNetwork",
      "password": "********",
      "band": "2.4GHz",
      "hidden": true,
      "auth_mode": "WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "5",
      "ssid": "MyNewSSID-5G",
      "password": "********",
      "band": "5GHz",
      "hidden": false,
      "auth_mode": "WPA/WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "6",
      "ssid": "TestNetwork-5G",
      "password": "********",
      "band": "5GHz",
      "hidden": false,
      "auth_mode": "WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "7",
      "ssid": "TestWLAN7",
      "password": "********",
      "band": "5GHz",
      "hidden": false,
      "auth_mode": "WPA2",
      "encryption": "TKIP+AES"
    },
    {
      "wlan": "8",
      "ssid": "LegacyNetwork-5G",
      "password": "********",
      "band": "5GHz",
      "hidden": false,
      "auth_mode": "WPA/WPA2",
      "encryption": "TKIP+AES"
    }
  ]
}
```

---

### 5. Trigger SSID Refresh

**Request:**
```http
POST /api/v1/genieacs/ssid/10.90.7.129/refresh
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

### 6. Get DHCP Clients

**Request:**
```http
GET /api/v1/genieacs/dhcp-client/10.90.7.129
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

### 7. Create WLAN (Already Exists)

#### 7.1 Create WLAN 1 (2.4GHz)

**Request:**
```http
POST /api/v1/genieacs/wlan/create/1/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "TestDualBand-2G",
  "password": "Test2GPass123",
  "hidden": false,
  "max_clients": 20,
  "auth_mode": "WPA2",
  "encryption": "AES"
}
```

**Response:**
```json
{
  "code": 409,
  "status": "Conflict",
  "error": "WLAN 1 already exists and is enabled on this device. Use the update endpoint to modify it."
}
```

#### 7.2 Create WLAN 5 (5GHz)

**Request:**
```http
POST /api/v1/genieacs/wlan/create/5/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "TestDualBand-5G",
  "password": "Test5GPass123",
  "hidden": false,
  "max_clients": 32,
  "auth_mode": "WPA2",
  "encryption": "AES"
}
```

**Response:**
```json
{
  "code": 409,
  "status": "Conflict",
  "error": "WLAN 5 already exists and is enabled on this device. Use the update endpoint to modify it."
}
```

---

### 8. Update WLAN

#### 8.1 Update WLAN 1 (2.4GHz) - Full Update

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/1/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "Updated2GNetwork",
  "password": "NewPass2G123",
  "hidden": false,
  "max_clients": 25
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "hidden": false,
      "max_clients": 25,
      "password": "********",
      "ssid": "Updated2GNetwork"
    },
    "wlan": "1"
  }
}
```

#### 8.2 Update WLAN 5 (5GHz) - SSID and Password

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/5/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "Updated5GNetwork",
  "password": "NewPass5G456"
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "password": "********",
      "ssid": "Updated5GNetwork"
    },
    "wlan": "5"
  }
}
```

#### 8.3 Update WLAN 6 (5GHz) - Max Clients Only

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/6/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "max_clients": 40
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN update submitted successfully",
    "updated_fields": {
      "max_clients": 40
    },
    "wlan": "6"
  }
}
```

---

### 9. Optimize WLAN (2.4GHz)

#### 9.1 Full Optimization

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "6",
  "mode": "b/g/n",
  "bandwidth": "40MHz",
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
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "bandwidth": "40MHz",
      "channel": "6",
      "mode": "b/g/n",
      "transmit_power": 100
    },
    "wlan": "1"
  }
}
```

#### 9.2 Auto Channel

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.7.129
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
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "channel": "Auto"
    },
    "wlan": "1"
  }
}
```

---

### 10. Optimize WLAN (5GHz)

#### 10.1 Full Optimization

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/5/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "149",
  "mode": "a/n/ac",
  "bandwidth": "80MHz",
  "transmit_power": 100
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "bandwidth": "80MHz",
      "channel": "149",
      "mode": "a/n/ac",
      "transmit_power": 100
    },
    "wlan": "5"
  }
}
```

#### 10.2 Auto Channel

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/5/10.90.7.129
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
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "channel": "Auto"
    },
    "wlan": "5"
  }
}
```

#### 10.3 Channel 36

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/5/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "36"
}
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN optimization submitted successfully",
    "updated_settings": {
      "channel": "36"
    },
    "wlan": "5"
  }
}
```

---

### 11. Delete WLAN

#### 11.1 Delete WLAN 4 (2.4GHz)

**Request:**
```http
DELETE /api/v1/genieacs/wlan/delete/4/10.90.7.129
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "2.4GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN deletion submitted successfully",
    "wlan": "4"
  }
}
```

#### 11.2 Delete WLAN 8 (5GHz)

**Request:**
```http
DELETE /api/v1/genieacs/wlan/delete/8/10.90.7.129
X-API-Key: YourSecretKey
```

**Response:**
```json
{
  "code": 200,
  "status": "OK",
  "data": {
    "band": "5GHz",
    "device_id": "001141-F670L-ZTEGCFLN794B3A1",
    "ip": "10.90.7.129",
    "message": "WLAN deletion submitted successfully",
    "wlan": "8"
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

### Invalid WLAN ID (9)

**Request:**
```http
POST /api/v1/genieacs/wlan/create/9/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "InvalidWLAN",
  "password": "TestPass123"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID must be between 1 and 8"
}
```

---

### 5GHz Mode on 2.4GHz WLAN

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.7.129
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

### 2.4GHz Mode on 5GHz WLAN

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/5/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "mode": "b/g/n"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid mode for 5GHz band, valid modes: a, n, ac, a/n, a/n/ac"
}
```

---

### 80MHz Bandwidth on 2.4GHz

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.7.129
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

### 160MHz Bandwidth on 5GHz

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/5/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "bandwidth": "160MHz"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid bandwidth for 5GHz band, valid values: 20MHz, 40MHz, 80MHz, Auto"
}
```

---

### 2.4GHz Channel on 5GHz WLAN

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/5/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "6"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "invalid channel for 5GHz band, valid channels: Auto, 36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161"
}
```

---

### 5GHz Channel on 2.4GHz WLAN

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/1/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "149"
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

### Update WLAN - Invalid Max Clients (too high)

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "max_clients": 100
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Max clients must be between 1 and 64"
}
```

---

### Update WLAN - Invalid Max Clients (zero)

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "max_clients": 0
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Max clients must be between 1 and 64"
}
```

---

### Update WLAN - Invalid Encryption

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "encryption": "WEP"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid encryption mode. Valid values: AES, TKIP, TKIP+AES"
}
```

---

### Update WLAN - Invalid Auth Mode

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "auth_mode": "WPA3"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "Invalid authentication mode. Valid values: Open, WPA, WPA2, WPA/WPA2"
}
```

---

### Update WLAN - Password Too Short

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
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

### Update WLAN - SSID Too Long

**Request:**
```http
PUT /api/v1/genieacs/wlan/update/2/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "ssid": "ThisSSIDIsWayTooLongAndExceeds32Characters"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "SSID must be at most 32 characters"
}
```

---

### Optimize WLAN - Invalid WLAN ID (0)

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/0/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "Auto"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID must be a number between 1 and 99"
}
```

---

### Optimize WLAN - Invalid WLAN ID (9)

**Request:**
```http
PUT /api/v1/genieacs/wlan/optimize/9/10.90.7.129
Content-Type: application/json
X-API-Key: YourSecretKey

{
  "channel": "Auto"
}
```

**Response:**
```json
{
  "code": 400,
  "status": "Bad Request",
  "error": "WLAN ID must be between 1 and 8"
}
```

---

## Configuration Options

### 2.4GHz Band (WLAN 1-4)

| Parameter | Valid Values |
|-----------|-------------|
| Channels | Auto, 1-13 |
| Modes | b, g, n, b/g, g/n, b/g/n |
| Bandwidth | 20MHz, 40MHz, Auto |
| Transmit Power | 0, 20, 40, 60, 80, 100 (%) |

### 5GHz Band (WLAN 5-8)

| Parameter | Valid Values |
|-----------|-------------|
| Channels | Auto, 36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161 |
| Modes | a, n, ac, a/n, a/n/ac |
| Bandwidth | 20MHz, 40MHz, 80MHz, Auto |
| Transmit Power | 0, 20, 40, 60, 80, 100 (%) |

### Common Settings

| Parameter | Valid Values |
|-----------|-------------|
| Auth Modes | Open, WPA, WPA2, WPA/WPA2 |
| Encryptions | AES, TKIP, TKIP+AES |
| Max Clients | 1-64 (default: 32) |

---

## Conclusion

All endpoints tested successfully on dual-band device ZTE F670L. The API correctly:

1. Detects dual-band device capability
2. Returns both 2.4GHz (WLAN 1-4) and 5GHz (WLAN 5-8) slots
3. Returns enhanced SSID response with hidden, auth_mode, and encryption fields
4. Validates band-specific parameters:
   - Channels: 2.4GHz (1-13) vs 5GHz (36-161)
   - Modes: 2.4GHz (b/g/n) vs 5GHz (a/n/ac)
   - Bandwidth: 2.4GHz (20/40MHz) vs 5GHz (20/40/80MHz)
5. Rejects cross-band parameter assignments
6. Handles all CRUD operations for WLAN configuration
7. Provides proper error messages for invalid inputs
