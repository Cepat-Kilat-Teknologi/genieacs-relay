## GET SSID

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
"http://localhost:8080/api/v1/genieacs/ssid/10.90.8.164" | jq
```
### If Results are not yet available:

```bash
{
  "code": 200,
  "status": "OK",
  "data": null
}
```
### Trigger a refresh:

```bash
curl -X POST -H "X-API-Key: YourSecretGatewayAPI_Key" \
"http://localhost:8080/api/v1/genieacs/ssid/10.90.8.164/refresh" | jq
```

### Response refresh
```bash
{
  "code": 202,
  "status": "Accepted",
  "data": {
    "message": "Refresh task submitted. Please query the GET endpoint again after a few moments."
  }
}
```

### Re-query GET SSID after a few moments:

```bash
{
  "code": 200,
  "status": "OK",
  "data": [
    {
      "wlan": "1",
      "ssid": "MyHomeWiFi_2.4G",
      "password": "SuperSecretPassword",
      "band": "2.4GHz"
    },
    {
      "wlan": "5",
      "ssid": "MyHomeWiFi_5G",
      "password": "AnotherPassword",
      "band": "5GHz"
    }
  ]
}
```

### Update SSID

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
-X PUT "http://localhost:8080/api/v1/genieacs/ssid/update/1/10.90.8.164" \
-H "Content-Type: application/json" \
-d '{"ssid": "New_SSID_Name"}' | jq
```

### Response SSID Update

```bash
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "SERIAL-NUMBER-XYZ",
    "ip": "10.90.8.164",
    "message": "SSID update submitted successfully",
    "ssid": "New_SSID_Name",
    "wlan": "1"
  }
}
```

### Update Password

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
-X PUT "http://localhost:8080/api/v1/genieacs/password/update/1/10.90.8.164" \
-H "Content-Type: application/json" \
-d '{"password": "NewSecurePassword123"}' | jq
```

### Response Password Update

```bash
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "SERIAL-NUMBER-XYZ",
    "ip": "10.90.8.164",
    "message": "Password update submitted successfully",
    "wlan": "1"
  }
}
```

## GET DHCP Clients

```bash
curl -H "X-API-Key: YourSecretGatewayAPI_Key" \
"http://localhost:8080/api/v1/genieacs/dhcp-client/10.90.8.164" | jq
```

### Successful Response Get DHCP Clients

```bash
{
  "code": 200,
  "status": "OK",
  "data": [
    {
      "mac": "AA:BB:CC:11:22:33",
      "hostname": "Johns-iPhone",
      "ip": "192.168.1.100"
    },
    {
      "mac": "DD:EE:FF:44:55:66",
      "hostname": "Living-Room-TV",
      "ip": "192.168.1.102"
    }
  ]
}
```

## Common Error Responses
- Bad Request (400): The request body is missing a required field or is malformed.

```bash
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password value required"
}
```
- Unauthorized (401): The X-API-Key header is missing or incorrect.

```bash
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Invalid API Key"
}
```

- Not Found (404): The device with the specified IP address could not be found in GenieACS.

```bash
{
  "code": 404,
  "status": "Not Found",
  "error": "device not found with IP: 10.90.200.100"
}
```