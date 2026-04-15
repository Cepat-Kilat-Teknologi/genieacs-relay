package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handlers_inspection_test.go covers the v2.2.0 read-side device
// inspection handlers: getDeviceStatusHandler (H1), getWanStatusHandler
// (H4), and getGenericParamsHandler (H7).

// --- shared fixtures ---

// mockDeviceTreeWithStatusAndWAN returns a mock GenieACS device
// document with the fields needed to exercise H1 (status) and H4 (wan)
// at the same time. Uses a recent _lastInform so the device is
// classified as online.
func mockDeviceTreeWithStatusAndWAN() string {
	lastInform := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{
        "_id": "%s",
        "_lastInform": "%s",
        "InternetGatewayDevice": {
            "DeviceInfo": {
                "UpTime":          {"_value": 1234567},
                "Manufacturer":    {"_value": "ZTE"},
                "ModelName":       {"_value": "F670L"},
                "SoftwareVersion": {"_value": "V9.0.10P5N12"},
                "HardwareVersion": {"_value": "V1.0"}
            },
            "WANDevice": {
                "1": {
                    "WANConnectionDevice": {
                        "1": {
                            "WANPPPConnection": {
                                "1": {
                                    "ConnectionStatus":     {"_value": "Connected"},
                                    "ExternalIPAddress":    {"_value": "203.0.113.45"},
                                    "Username":             {"_value": "pppoe-customer-001"},
                                    "Uptime":               {"_value": 98765},
                                    "LastConnectionError": {"_value": ""}
                                }
                            },
                            "WANIPConnection": {
                                "1": {
                                    "ConnectionStatus":   {"_value": "Connected"},
                                    "ExternalIPAddress":  {"_value": "203.0.113.46"},
                                    "Uptime":             {"_value": 12345},
                                    "AddressingType":     {"_value": "DHCP"},
                                    "LastConnectionError": {"_value": ""}
                                },
                                "2": {
                                    "ConnectionStatus": {"_value": "Disconnected"},
                                    "AddressingType":   {"_value": "Static"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }`, mockDeviceID, lastInform)
}

// inspectionMockHandler builds a GenieACS NBI mock that handles the
// device-id projection lookup and full device tree fetch needed by
// the inspection handlers.
func inspectionMockHandler(deviceJSON string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + deviceJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

// decodeStatusResponse pulls the data field out of the standard
// envelope and decodes it as DeviceStatusResponse.
func decodeStatusResponse(t *testing.T, body []byte) DeviceStatusResponse {
	t.Helper()
	var env Response
	require.NoError(t, json.Unmarshal(body, &env))
	dataBytes, err := json.Marshal(env.Data)
	require.NoError(t, err)
	var status DeviceStatusResponse
	require.NoError(t, json.Unmarshal(dataBytes, &status))
	return status
}

func decodeWanResponse(t *testing.T, body []byte) WANConnectionsResponse {
	t.Helper()
	var env Response
	require.NoError(t, json.Unmarshal(body, &env))
	dataBytes, err := json.Marshal(env.Data)
	require.NoError(t, err)
	var wan WANConnectionsResponse
	require.NoError(t, json.Unmarshal(dataBytes, &wan))
	return wan
}

func decodeParamsResponse(t *testing.T, body []byte) GenericParamsResponse {
	t.Helper()
	var env Response
	require.NoError(t, json.Unmarshal(body, &env))
	dataBytes, err := json.Marshal(env.Data)
	require.NoError(t, err)
	var params GenericParamsResponse
	require.NoError(t, json.Unmarshal(dataBytes, &params))
	return params
}

// --- H1: GET /status/{ip} ---

func TestGetDeviceStatusHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/status/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	status := decodeStatusResponse(t, rr.Body.Bytes())
	assert.Equal(t, mockDeviceID, status.DeviceID)
	assert.Equal(t, mockDeviceIP, status.IP)
	assert.True(t, status.Online)
	assert.Equal(t, 1234567, status.UptimeSeconds)
	assert.Equal(t, "ZTE", status.Manufacturer)
	assert.Equal(t, "F670L", status.Model)
	assert.Equal(t, "V9.0.10P5N12", status.SoftwareVersion)
	assert.Equal(t, "V1.0", status.HardwareVersion)
}

func TestGetDeviceStatusHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/status/192.0.2.99", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetDeviceStatusHandler_TreeReadFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First call (id projection) succeeds, second call (full tree) fails.
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/status/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to read device status")
}

// --- buildDeviceStatusResponse direct unit tests ---

func TestBuildDeviceStatusResponse_TR181Fallback(t *testing.T) {
	// Tree only exposes the TR-181 Device.* paths, not the TR-098
	// InternetGatewayDevice.* paths. The function should fall back to
	// TR-181 for every identification field.
	tree := map[string]interface{}{
		// _lastInform is a top-level bare RFC3339 string in real
		// GenieACS device documents (mirrors the Device struct in
		// client.go). Tests must use the same shape, NOT a _value
		// wrapper, otherwise the status reader can't read it.
		"_lastInform": time.Now().UTC().Format(time.RFC3339),
		"Device": map[string]interface{}{
			"DeviceInfo": map[string]interface{}{
				"UpTime":          map[string]interface{}{"_value": float64(99999)},
				"Manufacturer":    map[string]interface{}{"_value": "Huawei"},
				"ModelName":       map[string]interface{}{"_value": "EG8145V5"},
				"SoftwareVersion": map[string]interface{}{"_value": "V5R020"},
				"HardwareVersion": map[string]interface{}{"_value": "V2.0"},
			},
		},
	}
	resp := buildDeviceStatusResponse(tree, "huawei-device", "10.0.0.1")
	assert.Equal(t, "huawei-device", resp.DeviceID)
	assert.Equal(t, "10.0.0.1", resp.IP)
	assert.Equal(t, 99999, resp.UptimeSeconds)
	assert.Equal(t, "Huawei", resp.Manufacturer)
	assert.Equal(t, "EG8145V5", resp.Model)
	assert.Equal(t, "V5R020", resp.SoftwareVersion)
	assert.Equal(t, "V2.0", resp.HardwareVersion)
	assert.True(t, resp.Online)
}

func TestBuildDeviceStatusResponse_NoLastInform(t *testing.T) {
	tree := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"DeviceInfo": map[string]interface{}{
				"UpTime": map[string]interface{}{"_value": float64(123)},
			},
		},
	}
	resp := buildDeviceStatusResponse(tree, "no-inform-device", "10.0.0.2")
	assert.Equal(t, "", resp.LastInform)
	assert.Equal(t, int64(0), resp.LastInformAgeSecond)
	assert.False(t, resp.Online)
	assert.Equal(t, 123, resp.UptimeSeconds)
}

func TestBuildDeviceStatusResponse_FutureLastInform(t *testing.T) {
	// Defensive: a clock-skewed _lastInform that's in the future
	// should report age=0, not a negative number.
	future := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	tree := map[string]interface{}{
		"_lastInform": future,
	}
	resp := buildDeviceStatusResponse(tree, "future-device", "10.0.0.3")
	assert.Equal(t, int64(0), resp.LastInformAgeSecond)
	// Future timestamps trivially count as online (age < threshold).
	assert.True(t, resp.Online)
}

func TestBuildDeviceStatusResponse_StaleThresholdDisabled(t *testing.T) {
	// Force the package-level staleThreshold to 0 (disabled) and
	// verify the function falls back to the 30-minute window for
	// the online classification.
	originalThreshold := staleThreshold
	staleThreshold = 0
	t.Cleanup(func() { staleThreshold = originalThreshold })

	// Recent inform should still be online with the fallback window.
	recent := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	tree := map[string]interface{}{
		"_lastInform": recent,
	}
	resp := buildDeviceStatusResponse(tree, "fallback-device", "10.0.0.4")
	assert.True(t, resp.Online)

	// Very old inform (2 hours ago) should be offline because
	// 3*30min = 90min < 2h.
	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	tree2 := map[string]interface{}{
		"_lastInform": old,
	}
	resp2 := buildDeviceStatusResponse(tree2, "old-device", "10.0.0.5")
	assert.False(t, resp2.Online)
}

func TestBuildDeviceStatusResponse_LastInformBadType(t *testing.T) {
	// _lastInform present but not a string (e.g. accidentally numeric)
	tree := map[string]interface{}{
		"_lastInform": float64(12345),
	}
	resp := buildDeviceStatusResponse(tree, "bad-type-device", "10.0.0.10")
	assert.Equal(t, "", resp.LastInform)
	assert.False(t, resp.Online)
}

func TestBuildDeviceStatusResponse_LastInformBadFormat(t *testing.T) {
	// _lastInform is a string but not RFC3339 parseable
	tree := map[string]interface{}{
		"_lastInform": "not-a-timestamp",
	}
	resp := buildDeviceStatusResponse(tree, "bad-format-device", "10.0.0.11")
	assert.Equal(t, "", resp.LastInform)
	assert.False(t, resp.Online)
}

func TestBuildDeviceStatusResponse_EmptyTree(t *testing.T) {
	resp := buildDeviceStatusResponse(map[string]interface{}{}, "empty-device", "10.0.0.6")
	assert.Equal(t, "empty-device", resp.DeviceID)
	assert.Equal(t, "10.0.0.6", resp.IP)
	assert.Equal(t, "", resp.LastInform)
	assert.False(t, resp.Online)
	assert.Equal(t, 0, resp.UptimeSeconds)
	assert.Equal(t, "", resp.Manufacturer)
}

// --- H4: GET /wan/{ip} ---

func TestGetWanStatusHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wan/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	wan := decodeWanResponse(t, rr.Body.Bytes())
	assert.Equal(t, mockDeviceID, wan.DeviceID)
	assert.Equal(t, mockDeviceIP, wan.IP)
	require.Len(t, wan.WANConnections, 3)

	// PPP connection
	pppFound := false
	dhcpFound := false
	staticFound := false
	for _, c := range wan.WANConnections {
		switch c.Type {
		case "pppoe":
			pppFound = true
			assert.Equal(t, "Connected", c.ConnectionStatus)
			assert.Equal(t, "203.0.113.45", c.ExternalIP)
			assert.Equal(t, "pppoe-customer-001", c.Username)
			assert.Equal(t, 98765, c.UptimeSeconds)
		case "dhcp":
			dhcpFound = true
			assert.Equal(t, "203.0.113.46", c.ExternalIP)
			assert.Equal(t, 12345, c.UptimeSeconds)
		case "static":
			staticFound = true
			assert.Equal(t, "Disconnected", c.ConnectionStatus)
		}
	}
	assert.True(t, pppFound, "PPPoE connection should be present")
	assert.True(t, dhcpFound, "DHCP connection should be present")
	assert.True(t, staticFound, "Static connection should be present")
}

func TestGetWanStatusHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wan/192.0.2.99", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetWanStatusHandler_TreeReadFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wan/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to read WAN")
}

// --- buildWanConnectionsResponse direct unit tests ---

func TestBuildWanConnectionsResponse_NoConnections(t *testing.T) {
	tree := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"DeviceInfo": map[string]interface{}{},
		},
	}
	resp := buildWanConnectionsResponse(tree, "empty-device", "10.0.0.7")
	assert.Equal(t, "empty-device", resp.DeviceID)
	assert.Equal(t, "10.0.0.7", resp.IP)
	assert.Empty(t, resp.WANConnections)
}

func TestBuildWanConnectionsResponse_IPCPType(t *testing.T) {
	// Test the IPCP addressing type branch
	tree := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"WANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WANConnectionDevice": map[string]interface{}{
						"1": map[string]interface{}{
							"WANIPConnection": map[string]interface{}{
								"1": map[string]interface{}{
									"AddressingType":   map[string]interface{}{"_value": "IPCP"},
									"ConnectionStatus": map[string]interface{}{"_value": "Connected"},
								},
							},
						},
					},
				},
			},
		},
	}
	resp := buildWanConnectionsResponse(tree, "ipcp-device", "10.0.0.8")
	require.Len(t, resp.WANConnections, 1)
	assert.Equal(t, "ipcp", resp.WANConnections[0].Type)
}

func TestBuildWanConnectionsResponse_UnknownAddressingType(t *testing.T) {
	// Addressing type is something the switch doesn't recognize → defaults to "dhcp"
	tree := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"WANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WANConnectionDevice": map[string]interface{}{
						"1": map[string]interface{}{
							"WANIPConnection": map[string]interface{}{
								"1": map[string]interface{}{
									"AddressingType":   map[string]interface{}{"_value": "Unknown"},
									"ConnectionStatus": map[string]interface{}{"_value": "Connected"},
									"ExternalIPAddress": map[string]interface{}{"_value": "192.0.2.99"},
									"Uptime":           map[string]interface{}{"_value": float64(42)},
									"LastConnectionError": map[string]interface{}{"_value": "ICMP_TIMEOUT"},
								},
							},
						},
					},
				},
			},
		},
	}
	resp := buildWanConnectionsResponse(tree, "unknown-type-device", "10.0.0.9")
	require.Len(t, resp.WANConnections, 1)
	assert.Equal(t, "dhcp", resp.WANConnections[0].Type)
	assert.Equal(t, "ICMP_TIMEOUT", resp.WANConnections[0].LastError)
}

// --- H7: POST /params/{ip} ---

func TestGetGenericParamsHandler_Success_Cached(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	body := `{
        "paths": [
            "InternetGatewayDevice.DeviceInfo.UpTime",
            "InternetGatewayDevice.DeviceInfo.Manufacturer",
            "InternetGatewayDevice.DoesNotExist"
        ],
        "live": false
    }`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	resp := decodeParamsResponse(t, rr.Body.Bytes())
	assert.Equal(t, mockDeviceID, resp.DeviceID)
	assert.False(t, resp.Live)
	assert.Equal(t, "1234567", resp.Params["InternetGatewayDevice.DeviceInfo.UpTime"])
	assert.Equal(t, "ZTE", resp.Params["InternetGatewayDevice.DeviceInfo.Manufacturer"])
	require.Len(t, resp.MissingPaths, 1)
	assert.Equal(t, "InternetGatewayDevice.DoesNotExist", resp.MissingPaths[0])
}

func TestGetGenericParamsHandler_Success_AllFound(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	body := `{"paths": ["InternetGatewayDevice.DeviceInfo.Manufacturer"]}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	resp := decodeParamsResponse(t, rr.Body.Bytes())
	assert.Equal(t, []string{}, resp.MissingPaths)
}

func TestGetGenericParamsHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)

	body := `{"paths":["X.Y"]}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/192.0.2.99", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetGenericParamsHandler_BadJSON(t *testing.T) {
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestGetGenericParamsHandler_EmptyPaths(t *testing.T) {
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(`{"paths":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "At least one parameter path")
}

func TestGetGenericParamsHandler_TooManyPaths(t *testing.T) {
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	// Build a request with 51 paths
	paths := make([]string, MaxGenericParamPathsPerRequest+1)
	for i := range paths {
		paths[i] = fmt.Sprintf("Path.Segment%d", i)
	}
	bodyBytes, _ := json.Marshal(map[string]interface{}{"paths": paths})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "max 50")
}

func TestGetGenericParamsHandler_InvalidPath(t *testing.T) {
	mock := inspectionMockHandler(mockDeviceTreeWithStatusAndWAN())
	_, router := setupTestServer(t, mock)

	// One valid path + one with shell metachar
	body := `{"paths":["InternetGatewayDevice.DeviceInfo.UpTime","Bad;Injection"]}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid parameter path")
}

func TestGetGenericParamsHandler_Live_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	// Mock that handles: device id projection + getParameterValues task + full tree fetch
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Live mode dispatches a task to /devices/{id}/tasks
		if strings.HasSuffix(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Then the full tree fetch
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[" + mockDeviceTreeWithStatusAndWAN() + "]"))
	})
	_, router := setupTestServer(t, mock)

	body := `{"paths":["InternetGatewayDevice.DeviceInfo.Manufacturer"],"live":true}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	resp := decodeParamsResponse(t, rr.Body.Bytes())
	assert.True(t, resp.Live)
	assert.Equal(t, "ZTE", resp.Params["InternetGatewayDevice.DeviceInfo.Manufacturer"])
}

func TestGetGenericParamsHandler_Live_DispatchFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Live mode task fails
		if strings.HasSuffix(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, router := setupTestServer(t, mock)

	body := `{"paths":["InternetGatewayDevice.DeviceInfo.Manufacturer"],"live":true}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "live GetParameterValues")
}

func TestGetGenericParamsHandler_TreeReadFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, router := setupTestServer(t, mock)

	body := `{"paths":["X.Y"]}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/params/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to read parameters")
}

// --- formatInvalidParamPath direct unit test ---

func TestFormatInvalidParamPath_Short(t *testing.T) {
	got := formatInvalidParamPath("Bad;Injection")
	assert.Equal(t, "Invalid parameter path: Bad;Injection", got)
}

func TestFormatInvalidParamPath_TruncatesLongPath(t *testing.T) {
	long := strings.Repeat("X", 100)
	got := formatInvalidParamPath(long)
	assert.Contains(t, got, "...")
	// Truncated to 77 chars + "..." = 80
	assert.Equal(t, "Invalid parameter path: "+strings.Repeat("X", 77)+"...", got)
}

// --- M3: wifi-clients ---

// mockDeviceTreeWithWifiClients returns a device tree containing 2
// WLAN radios (1 = 2.4GHz, 5 = 5GHz) each with associated clients.
func mockDeviceTreeWithWifiClients() string {
	return fmt.Sprintf(`{
        "_id": "%s",
        "_lastInform": "%s",
        "InternetGatewayDevice": {
            "LANDevice": {
                "1": {
                    "WLANConfiguration": {
                        "1": {
                            "SSID":     {"_value": "MyWiFi-2.4"},
                            "Standard": {"_value": "b,g,n"},
                            "AssociatedDevice": {
                                "1": {
                                    "AssociatedDeviceMACAddress":         {"_value": "AA:BB:CC:00:00:01"},
                                    "X_SignalStrength":                   {"_value": -55},
                                    "AssociatedDeviceAuthenticationState": {"_value": true}
                                },
                                "2": {
                                    "AssociatedDeviceMACAddress":         {"_value": "AA:BB:CC:00:00:02"},
                                    "SignalStrength":                     {"_value": -65}
                                }
                            }
                        },
                        "5": {
                            "SSID":     {"_value": "MyWiFi-5"},
                            "Standard": {"_value": "a,n,ac"},
                            "AssociatedDevice": {
                                "1": {
                                    "AssociatedDeviceMACAddress": {"_value": "AA:BB:CC:00:00:03"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }`, mockDeviceID, time.Now().UTC().Format(time.RFC3339))
}

func TestGetWifiClientsHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := inspectionMockHandler(mockDeviceTreeWithWifiClients())
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wifi-clients/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Decode response and inspect
	var env Response
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &env))
	dataBytes, _ := json.Marshal(env.Data)
	var resp WiFiClientsResponse
	require.NoError(t, json.Unmarshal(dataBytes, &resp))
	require.Len(t, resp.Clients, 3)

	mac1Found := false
	mac3Found := false
	for _, c := range resp.Clients {
		if c.MAC == "AA:BB:CC:00:00:01" {
			mac1Found = true
			assert.Equal(t, -55, c.SignalStrengthDBm)
			assert.True(t, c.Authenticated)
			assert.Equal(t, "2.4GHz", c.Band)
		}
		if c.MAC == "AA:BB:CC:00:00:03" {
			mac3Found = true
			assert.Equal(t, "5GHz", c.Band)
		}
	}
	assert.True(t, mac1Found)
	assert.True(t, mac3Found)
}

func TestGetWifiClientsHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wifi-clients/192.0.2.99", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetWifiClientsHandler_TreeReadFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wifi-clients/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestBuildWifiClientsResponse_Empty(t *testing.T) {
	tree := map[string]interface{}{}
	resp := buildWifiClientsResponse(tree, "x", "10.0.0.1")
	assert.Equal(t, "x", resp.DeviceID)
	assert.Empty(t, resp.Clients)
}

func TestExtractWifiClient_StandardSignalStrength(t *testing.T) {
	// Synthetic tree with the standard SignalStrength field (no X_ prefix)
	tree := map[string]interface{}{
		"AssocDev": map[string]interface{}{
			"AssociatedDeviceMACAddress": map[string]interface{}{"_value": "FF:FF:FF:FF:FF:FF"},
			"SignalStrength":             map[string]interface{}{"_value": -77},
		},
	}
	c := extractWifiClient(tree, "AssocDev", 1, "TestSSID", "2.4GHz")
	assert.Equal(t, -77, c.SignalStrengthDBm)
	assert.Equal(t, "FF:FF:FF:FF:FF:FF", c.MAC)
}

func TestClassifyWLANBand_Missing(t *testing.T) {
	tree := map[string]interface{}{
		"WLAN": map[string]interface{}{},
	}
	band := classifyWLANBand(tree, "WLAN")
	assert.Equal(t, "", band)
}

func TestClassifyWLANBand_24GHz(t *testing.T) {
	tree := map[string]interface{}{
		"WLAN": map[string]interface{}{
			"Standard": map[string]interface{}{"_value": "b,g,n"},
		},
	}
	assert.Equal(t, "2.4GHz", classifyWLANBand(tree, "WLAN"))
}

func TestClassifyWLANBand_5GHz_AC(t *testing.T) {
	tree := map[string]interface{}{
		"WLAN": map[string]interface{}{
			"Standard": map[string]interface{}{"_value": "a,n,ac"},
		},
	}
	assert.Equal(t, "5GHz", classifyWLANBand(tree, "WLAN"))
}

// --- M7: wifi-stats ---

// mockDeviceTreeWithWifiStats returns a device tree with WLAN stats fields populated.
func mockDeviceTreeWithWifiStats() string {
	return fmt.Sprintf(`{
        "_id": "%s",
        "_lastInform": "%s",
        "InternetGatewayDevice": {
            "LANDevice": {
                "1": {
                    "WLANConfiguration": {
                        "1": {
                            "SSID":          {"_value": "MyWiFi-2.4"},
                            "Standard":      {"_value": "b,g,n"},
                            "Channel":       {"_value": 6},
                            "TransmitPower": {"_value": 100},
                            "Stats": {
                                "TotalBytesSent":     {"_value": 12345678},
                                "TotalBytesReceived": {"_value": 87654321},
                                "TotalPacketsSent":   {"_value": 100},
                                "TotalPacketsReceived": {"_value": 200},
                                "ErrorsSent":         {"_value": 1},
                                "ErrorsReceived":     {"_value": 2}
                            }
                        },
                        "5": {
                            "SSID":     {"_value": "MyWiFi-5"},
                            "Standard": {"_value": "a,n,ac"},
                            "Channel":  {"_value": 36},
                            "X_TXPower": {"_value": 80}
                        }
                    }
                }
            }
        }
    }`, mockDeviceID, time.Now().UTC().Format(time.RFC3339))
}

func TestGetWifiStatsHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := inspectionMockHandler(mockDeviceTreeWithWifiStats())
	_, router := setupTestServer(t, mock)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wifi-stats/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var env Response
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &env))
	dataBytes, _ := json.Marshal(env.Data)
	var resp WiFiStatsResponse
	require.NoError(t, json.Unmarshal(dataBytes, &resp))
	require.Len(t, resp.Radios, 2)

	for _, r := range resp.Radios {
		switch r.WLAN {
		case 1:
			assert.Equal(t, 6, r.Channel)
			assert.Equal(t, 100, r.TxPowerLevel)
			assert.Equal(t, 12345678, r.BytesSent)
			assert.Equal(t, 1, r.ErrorsSent)
		case 5:
			assert.Equal(t, 36, r.Channel)
			assert.Equal(t, 80, r.TxPowerLevel)
		}
	}
}

func TestGetWifiStatsHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wifi-stats/192.0.2.99", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetWifiStatsHandler_TreeReadFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/wifi-stats/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestBuildWifiStatsResponse_Empty(t *testing.T) {
	resp := buildWifiStatsResponse(map[string]interface{}{}, "x", "10.0.0.1")
	assert.Empty(t, resp.Radios)
}
