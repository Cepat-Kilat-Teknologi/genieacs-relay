# GenieACS Relay API Reference

**Last Updated:** January 18, 2026

This document provides complete API reference with request/response examples for all GenieACS Relay endpoints.

> **Note:** For device-specific test results, see:
> - [TEST_RESULT_SINGLEBAND.md](TEST_RESULT_SINGLEBAND.md) - Single-band device tests (CDATA FD512XW-R460)
> - [TEST_RESULT_DUALBAND.md](TEST_RESULT_DUALBAND.md) - Dual-band device tests (ZTE F670L)

---

## Table of Contents

1. [Health Check](#1-health-check)
2. [SSID Endpoints](#2-ssid-endpoints)
3. [DHCP Client Endpoints](#3-dhcp-client-endpoints)
4. [Device Capability Endpoints](#4-device-capability-endpoints)
5. [WLAN Available Endpoints](#5-wlan-available-endpoints)
6. [WLAN Create Endpoints](#6-wlan-create-endpoints)
7. [WLAN Update Endpoints](#7-wlan-update-endpoints)
8. [WLAN Delete Endpoints](#8-wlan-delete-endpoints)
9. [WLAN Optimize Endpoints](#9-wlan-optimize-endpoints)
10. [Cache Endpoints](#10-cache-endpoints)
11. [Error Cases](#11-error-cases)
12. [Authentication Error Cases](#12-authentication-error-cases-middleware_authtrue)

---

## 1. Health Check

### GET /health

**Request:**
```http
GET http://localhost:8080/health
```

**Response (200 OK):**
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

## 2. SSID Endpoints

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
  "status": "OK",
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
  "status": "OK",
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
  "status": "OK",
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

## 3. DHCP Client Endpoints

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
  "status": "OK",
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
  "status": "OK",
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

## 4. Device Capability Endpoints

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
  "status": "OK",
  "data": {
    "model": "F670L",
    "band_type": "dualband",
    "is_dual_band": true
  }
}
```

---

## 5. WLAN Available Endpoints

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
  "status": "OK",
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

## 6. WLAN Create Endpoints

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
  "status": "OK",
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
  "status": "OK",
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
  "status": "OK",
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
  "status": "OK",
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
  "status": "OK",
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

## 7. WLAN Update Endpoints

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
  "status": "OK",
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
  "status": "OK",
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
  "status": "OK",
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

## 8. WLAN Delete Endpoints

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
  "status": "OK",
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

## 9. WLAN Optimize Endpoints

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
  "status": "OK",
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
  "status": "OK",
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
  "status": "OK",
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

## 10. Cache Endpoints

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
  "status": "OK",
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
  "status": "OK",
  "data": {
    "message": "Cache cleared"
  }
}
```

---

## 11. Error Cases

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

## 12. Authentication Error Cases (MIDDLEWARE_AUTH=true)

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
  "status": "OK",
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