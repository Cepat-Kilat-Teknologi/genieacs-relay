```bash
curl -sS -H "X-API-Key: alhamdulillah" \
"http://192.168.216.10:8088/api/v1/genieacs/ssid/10.90.8.164" | jq
```

```bash
{
  "code": 200,
  "status": "OK",
  "data": [
    {
      "wlan": "1",
      "ssid": "SSID_1",
      "password": "Password_SSID_1",
      "band": "2.4GHz"
    },
    {
      "wlan": "2",
      "ssid": "SSID_2",
      "password": "Password_SSID_2",
      "band": "2.4GHz"
    }
  ]
}
```

```bash
curl -sS -H "X-API-Key: alhamdulillah" \
-X PUT "http://192.168.216.10:8088/api/v1/genieacs/ssid/update/1/10.90.8.164" \
-H "Content-Type: application/json" \
-d '{"ssid": "Update_New_SSID_1"}' | jq
```

```bash
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF52FE56",
    "ip": "10.90.8.164",
    "message": "SSID updated and applied successfully",
    "ssid": "Update_New_SSID_1",
    "wlan": "1"
  }
}
```

```bash
curl -sS -H "X-API-Key: alhamdulillah" \
-X PUT "http://192.168.216.10:8088/api/v1/genieacs/password/update/1/10.90.8.164" \
-H "Content-Type: application/json" \
-d '{"password": "Update_Password"}' | jq
```

```bash
{
  "code": 200,
  "status": "OK",
  "data": {
    "device_id": "D05FAF-FD512XW%2DR460-CDTCAF52FE56",
    "ip": "10.90.8.164",
    "message": "Password updated and applied successfully",
    "wlan": "1"
  }
}
```

### Error
```bash
{
  "code": 400,
  "status": "Bad Request",
  "error": "Password value required"
}
```

```bash
{
  "code": 401,
  "status": "Unauthorized",
  "error": "Invalid API Key"
}
```

```bash
{
  "code": 404,
  "status": "Not Found",
  "error": "device not found with IP: 10.90.200.100"
}
```