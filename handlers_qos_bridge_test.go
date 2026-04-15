package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handlers_qos_bridge_test.go covers M6 (setQoSHandler) and
// M8 (setBridgeModeHandler) plus their pure helper functions.

// --- validateQoSRequest ---

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

func TestValidateQoSRequest_HappyPath(t *testing.T) {
	req := SetQoSRequest{DownloadKbps: intPtr(102400), UploadKbps: intPtr(51200)}
	assert.Equal(t, "", validateQoSRequest(&req))
	assert.Equal(t, 1, req.WANInstance)
}

func TestValidateQoSRequest_OnlyDownload(t *testing.T) {
	req := SetQoSRequest{DownloadKbps: intPtr(20480)}
	assert.Equal(t, "", validateQoSRequest(&req))
}

func TestValidateQoSRequest_OnlyUpload(t *testing.T) {
	req := SetQoSRequest{UploadKbps: intPtr(10240)}
	assert.Equal(t, "", validateQoSRequest(&req))
}

func TestValidateQoSRequest_NoFields(t *testing.T) {
	req := SetQoSRequest{}
	assert.Equal(t, ErrQosNoFieldsProvided, validateQoSRequest(&req))
}

func TestValidateQoSRequest_NegativeDownload(t *testing.T) {
	req := SetQoSRequest{DownloadKbps: intPtr(-1)}
	assert.Equal(t, ErrQosNegativeRate, validateQoSRequest(&req))
}

func TestValidateQoSRequest_NegativeUpload(t *testing.T) {
	req := SetQoSRequest{UploadKbps: intPtr(-1)}
	assert.Equal(t, ErrQosNegativeRate, validateQoSRequest(&req))
}

func TestValidateQoSRequest_InvalidWANInstance(t *testing.T) {
	req := SetQoSRequest{DownloadKbps: intPtr(1024), WANInstance: 99}
	assert.Equal(t, ErrPPPoEInvalidWanInstance, validateQoSRequest(&req))
}

// --- buildQoSParameterValues ---

func TestBuildQoSParameterValues_Both(t *testing.T) {
	values := buildQoSParameterValues(intPtr(102400), intPtr(51200), 1)
	require.Len(t, values, 2)
	assert.Contains(t, values[0][0], "X_DownStreamMaxBitRate")
	assert.Equal(t, 102400, values[0][1])
	assert.Contains(t, values[1][0], "X_UpStreamMaxBitRate")
	assert.Equal(t, 51200, values[1][1])
}

func TestBuildQoSParameterValues_DownloadOnly(t *testing.T) {
	values := buildQoSParameterValues(intPtr(20480), nil, 2)
	require.Len(t, values, 1)
	assert.Contains(t, values[0][0], "WANDevice.2.")
	assert.Contains(t, values[0][0], "X_DownStreamMaxBitRate")
}

func TestBuildQoSParameterValues_UploadOnly(t *testing.T) {
	values := buildQoSParameterValues(nil, intPtr(10240), 1)
	require.Len(t, values, 1)
	assert.Contains(t, values[0][0], "X_UpStreamMaxBitRate")
}

// --- setQoSHandler ---

// qosMockHandler serves both the IP→device-id projection lookup AND a
// minimal device tree containing the X_DownStreamMaxBitRate /
// X_UpStreamMaxBitRate fields so cpeSupportsXStreamBitRate returns true
// for the QoS happy-path test. The PPPoE handler's simpler mock returns
// an empty tree which would now trip the capability probe.
func qosMockHandler(withQoSField bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			if withQoSField {
				_, _ = w.Write([]byte(qosDeviceTreeWithField()))
			} else {
				_, _ = w.Write([]byte(qosDeviceTreeWithoutField()))
			}
			return
		}
		// Worker pool task submission — return success.
		w.WriteHeader(http.StatusOK)
	}
}

// qosDeviceTreeWithField returns a device tree whose WANPPPConnection.1
// subtree includes the X_DownStreamMaxBitRate field — the capability
// probe should treat such a device as QoS-capable.
func qosDeviceTreeWithField() string {
	return `[{
		"_id": "` + mockDeviceID + `",
		"InternetGatewayDevice": {
			"WANDevice": {
				"1": {
					"WANConnectionDevice": {
						"1": {
							"WANPPPConnection": {
								"1": {
									"X_DownStreamMaxBitRate": {"_value": 0, "_type": "xsd:unsignedInt"},
									"X_UpStreamMaxBitRate":   {"_value": 0, "_type": "xsd:unsignedInt"}
								}
							}
						}
					}
				}
			}
		}
	}]`
}

// qosDeviceTreeWithoutField returns a device tree whose
// WANPPPConnection.1 subtree lacks the X_*StreamMaxBitRate vendor
// extension — emulates a real ZTE F670L where the capability probe
// should return false and cause the handler to answer 501.
func qosDeviceTreeWithoutField() string {
	return `[{
		"_id": "` + mockDeviceID + `",
		"InternetGatewayDevice": {
			"WANDevice": {
				"1": {
					"WANConnectionDevice": {
						"1": {
							"WANPPPConnection": {
								"1": {
									"Uptime": {"_value": 12345, "_type": "xsd:unsignedInt"},
									"ConnectionStatus": {"_value": "Connected", "_type": "xsd:string"}
								}
							}
						}
					}
				}
			}
		}
	}]`
}

func TestSetQoSHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, qosMockHandler(true))

	body := `{"download_kbps":102400,"upload_kbps":51200}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/qos/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "QoS rate-limit update dispatched")
}

// TestSetQoSHandler_UnsupportedDevice covers the v2.2.1 capability
// probe: a device tree that lacks the X_*StreamMaxBitRate vendor
// extension (e.g. ZTE F670L) should receive HTTP 501 Not Implemented
// with error_code QOS_UNSUPPORTED_BY_DEVICE and a clear message
// pointing the caller at OLT-side rate limiting via RADIUS CoA.
func TestSetQoSHandler_UnsupportedDevice(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, qosMockHandler(false))

	body := `{"download_kbps":102400,"upload_kbps":51200}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/qos/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotImplemented, rr.Code)
	assert.Contains(t, rr.Body.String(), "QOS_UNSUPPORTED_BY_DEVICE")
	assert.Contains(t, rr.Body.String(), "RADIUS CoA")
}

// TestSetQoSHandler_CapabilityProbeError covers the branch where the
// capability probe itself fails to read device data (e.g. NBI 500).
// The handler should surface 500 with ErrQosCapabilityProbeFailed
// instead of falling through to a silent dispatch.
func TestSetQoSHandler_CapabilityProbeError(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	_, router := setupTestServer(t, mock)

	body := `{"download_kbps":102400}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/qos/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "probe CPE QoS capability")
}

// TestCpeSupportsXStreamBitRate_OnlyUpload proves the probe accepts a
// tree where only the upstream field is present — it uses a logical
// OR between the two vendor fields so partial exposure still qualifies.
func TestCpeSupportsXStreamBitRate_OnlyUpload(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{
				"_id": "` + mockDeviceID + `",
				"InternetGatewayDevice": {
					"WANDevice": {"1": {"WANConnectionDevice": {"1": {"WANPPPConnection": {"1": {
						"X_UpStreamMaxBitRate": {"_value": 0}
					}}}}}}
				}
			}]`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)
	geniesBaseURL = srv.URL

	ok, err := cpeSupportsXStreamBitRate(t.Context(), mockDeviceID, 1)
	require.NoError(t, err)
	assert.True(t, ok, "upstream-only vendor field still counts as supported")
}

// TestCpeSupportsXStreamBitRate_MissingWANInstance proves the probe
// returns false (not error) when the requested WAN instance key is
// absent from the tree — some dual-stack CPEs only populate WANDevice.1
// and return empty for WANDevice.2.
func TestCpeSupportsXStreamBitRate_MissingWANInstance(t *testing.T) {
	deviceCacheInstance.clearAll()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{
				"_id": "` + mockDeviceID + `",
				"InternetGatewayDevice": {"WANDevice": {"1": {}}}
			}]`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)
	geniesBaseURL = srv.URL

	ok, err := cpeSupportsXStreamBitRate(t.Context(), mockDeviceID, 2)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSetQoSHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	body := `{"download_kbps":1024}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/qos/192.0.2.99", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetQoSHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/qos/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetQoSHandler_ValidationError(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/qos/"+mockDeviceIP, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "download_kbps or upload_kbps")
}

func TestSetQoSHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })

	// Use the QoS-aware mock so the capability probe passes and the
	// request falls through to the worker pool submission path.
	_, router := setupTestServer(t, qosMockHandler(true))
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{
		workers: 0,
		queue:   make(chan task, 0),
		wg:      sync.WaitGroup{},
	}

	body := `{"download_kbps":1024}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/qos/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// --- validateBridgeModeRequest ---

func TestValidateBridgeModeRequest_HappyPath(t *testing.T) {
	req := SetBridgeModeRequest{Enabled: boolPtr(true)}
	assert.Equal(t, "", validateBridgeModeRequest(&req))
	assert.Equal(t, 1, req.WANInstance)
}

func TestValidateBridgeModeRequest_EnabledMissing(t *testing.T) {
	req := SetBridgeModeRequest{}
	got := validateBridgeModeRequest(&req)
	assert.Contains(t, got, "enabled is required")
}

func TestValidateBridgeModeRequest_InvalidWANInstance(t *testing.T) {
	req := SetBridgeModeRequest{Enabled: boolPtr(false), WANInstance: 99}
	assert.Equal(t, ErrPPPoEInvalidWanInstance, validateBridgeModeRequest(&req))
}

// --- buildBridgeModeParameterValues ---

func TestBuildBridgeModeParameterValues_BridgeOn(t *testing.T) {
	values := buildBridgeModeParameterValues(true, 1)
	require.Len(t, values, 1)
	// bridgeEnabled=true → pppEnable=false (disable PPPoE)
	assert.Equal(t, false, values[0][1])
}

func TestBuildBridgeModeParameterValues_BridgeOff(t *testing.T) {
	values := buildBridgeModeParameterValues(false, 2)
	require.Len(t, values, 1)
	assert.Equal(t, true, values[0][1])
	assert.Contains(t, values[0][0], "WANDevice.2.")
}

// --- setBridgeModeHandler ---

func TestSetBridgeModeHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())

	body := `{"enabled":true}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/bridge-mode/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "Bridge mode toggle dispatched")
}

func TestSetBridgeModeHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	body := `{"enabled":true}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/bridge-mode/192.0.2.99", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetBridgeModeHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/bridge-mode/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetBridgeModeHandler_MissingEnabled(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/bridge-mode/"+mockDeviceIP, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "enabled is required")
}

func TestSetBridgeModeHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })

	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{
		workers: 0,
		queue:   make(chan task, 0),
		wg:      sync.WaitGroup{},
	}

	body := `{"enabled":false}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/bridge-mode/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
