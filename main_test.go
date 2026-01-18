package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Note: Mock data and shared helpers are in test_helpers_test.go
//
// Tests have been organized into separate files:
// - routes_test.go: HTTP handler tests (TestHealthCheckHandler, TestGetSSIDByIPHandler, etc.)
// - client_test.go: GenieACS client function tests (TestRefreshDHCP, TestGetDeviceData, etc.)
// - cache_test.go: Cache tests (TestDeviceCache, TestCacheEviction, etc.)
// - config_test.go: Configuration tests (TestGetEnv)
// - worker_test.go: Worker pool tests (TestWorker_TaskFailure)
// - capability_test.go: Device capability tests
// - handlers_test.go: Handler helper function tests
// - middleware_test.go: Middleware tests
// - validation_test.go: Validation tests
// - server_test.go: Server lifecycle tests

// --- Test Cases ---

func TestSafeClose_Error(t *testing.T) {
	var buffer bytes.Buffer
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buffer), zap.InfoLevel)
	testLogger := zap.New(core)
	originalLogger := logger
	logger = testLogger
	defer func() { logger = originalLogger }()
	safeClose(&errorCloser{})
	assert.Contains(t, buffer.String(), "Failed to close resource")
}

func TestParsingErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("getBand Fallback", func(t *testing.T) {
		wlanData := map[string]interface{}{
			"Standard": map[string]interface{}{"_value": "802.11g"},
		}
		band := getBand(wlanData, "2")
		assert.Equal(t, "2.4GHz", band)

		wlanData = map[string]interface{}{
			"Standard": map[string]interface{}{"_value": "802.11ac"},
		}
		band = getBand(wlanData, "3")
		assert.Equal(t, "5GHz", band)

		wlanData = map[string]interface{}{
			"Standard": map[string]interface{}{"_value": "unknown-std"},
		}
		band = getBand(wlanData, "4")
		assert.Equal(t, "Unknown", band)
	})

	t.Run("getDHCPClients with malformed data", func(t *testing.T) {

		var err error

		deviceData := map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{}}
		deviceCacheInstance.set("test-no-landevice", deviceData)
		_, err = getDHCPClients(ctx, "test-no-landevice")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice data not found")

		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{}}}
		deviceCacheInstance.set("test-no-landevice1", deviceData)
		_, err = getDHCPClients(ctx, "test-no-landevice1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice.1 data not found")

		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{"1": map[string]interface{}{}}}}
		deviceCacheInstance.set("test-no-hosts", deviceData)
		clients, err := getDHCPClients(ctx, "test-no-hosts")
		assert.NoError(t, err)
		assert.Empty(t, clients)

		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{"1": map[string]interface{}{"Hosts": map[string]interface{}{}}}}}
		deviceCacheInstance.set("test-no-host", deviceData)
		clients, err = getDHCPClients(ctx, "test-no-host")
		assert.NoError(t, err)
		assert.Empty(t, clients)
	})

	t.Run("isWLANValid with malformed data", func(t *testing.T) {
		var err error

		deviceData := map[string]interface{}{}
		deviceCacheInstance.set("test-no-igd", deviceData)
		_, err = isWLANValid(ctx, "test-no-igd", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "InternetGatewayDevice data not found")

		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{}}
		deviceCacheInstance.set("test-no-landevice", deviceData)
		_, err = isWLANValid(ctx, "test-no-landevice", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice data not found")

		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{}}}
		deviceCacheInstance.set("test-no-landevice1", deviceData)
		_, err = isWLANValid(ctx, "test-no-landevice1", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice.1 data not found")

		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{"1": map[string]interface{}{}}}}
		deviceCacheInstance.set("test-no-wlanconfig", deviceData)
		valid, err := isWLANValid(ctx, "test-no-wlanconfig", "1")
		assert.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestFullCoverageScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("getPassword various cases", func(t *testing.T) {
		wlanData1 := map[string]interface{}{
			"PreSharedKey": map[string]interface{}{
				"1": map[string]interface{}{
					"KeyPassphrase": map[string]interface{}{"_value": "keypass123"},
				},
			},
		}
		assert.Equal(t, "keypass123", getPassword(wlanData1))

		wlanData2 := map[string]interface{}{
			"PreSharedKey": map[string]interface{}{
				"1": map[string]interface{}{
					"PreSharedKey": map[string]interface{}{"_value": "preshared456"},
				},
			},
		}
		assert.Equal(t, "preshared456", getPassword(wlanData2))

		// No password field at all - returns N/A
		wlanData3 := map[string]interface{}{}
		assert.Equal(t, "N/A", getPassword(wlanData3))

		// Password field exists but empty (encrypted) - returns ********
		wlanData4 := map[string]interface{}{
			"PreSharedKey": map[string]interface{}{
				"1": map[string]interface{}{
					"KeyPassphrase": map[string]interface{}{"_value": ""},
				},
			},
		}
		assert.Equal(t, "********", getPassword(wlanData4))
	})

	t.Run("Communication function errors", func(t *testing.T) {
		t.Run("httpClient.Do fails", func(t *testing.T) {
			deviceCacheInstance.clear(mockDeviceID) // Clear cache to force API call
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			geniesBaseURL = mockServer.URL
			mockServer.Close()
			_, err := getDeviceData(ctx, mockDeviceID)
			assert.Error(t, err)
		})

		t.Run("io.ReadAll fails", func(t *testing.T) {
			deviceCacheInstance.clear(mockDeviceID) // Clear cache to force API call
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "5")
			}))
			defer mockServer.Close()
			geniesBaseURL = mockServer.URL
			_, err := getDeviceData(ctx, mockDeviceID)
			assert.Error(t, err)
		})

		t.Run("json.Unmarshal fails", func(t *testing.T) {
			deviceCacheInstance.clear(mockDeviceID) // Clear cache to force API call
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "123"`))
			}))
			defer mockServer.Close()
			geniesBaseURL = mockServer.URL
			_, err := getDeviceData(ctx, mockDeviceID)
			assert.Error(t, err)
		})

		t.Run("device not found in array", func(t *testing.T) {
			deviceCacheInstance.clear(mockDeviceID) // Clear cache to force API call
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[]`))
			}))
			defer mockServer.Close()
			geniesBaseURL = mockServer.URL
			_, err := getDeviceData(ctx, mockDeviceID)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "no device found with ID")
		})

		t.Run("postJSONRequest unmarshallable", func(t *testing.T) {
			_, err := postJSONRequest(ctx, "http://dummyurl", make(chan int))
			assert.Error(t, err)
		})

		t.Run("setParameterValues fails", func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			geniesBaseURL = mockServer.URL
			mockServer.Close()
			err := setParameterValues(ctx, mockDeviceID, nil)
			assert.Error(t, err)
		})
	})

	t.Run("sendResponse encoding fails", func(t *testing.T) {
		var buffer bytes.Buffer
		testLogger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buffer), zap.InfoLevel))
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		rr := httptest.NewRecorder()
		sendResponse(rr, http.StatusOK, "OK", make(chan int))
		assert.Contains(t, buffer.String(), "Failed to encode JSON response")
	})

	t.Run("sendError encoding fails", func(t *testing.T) {
		var buffer bytes.Buffer
		testLogger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&buffer), zap.InfoLevel))
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		errorWriter := &errorResponseWriter{}
		sendError(errorWriter, http.StatusInternalServerError, "Error", "msg")
		assert.Contains(t, buffer.String(), "Failed to encode JSON error response")
	})
}

// Note: TestGetDeviceIDByIPHTTPClientError, TestSetParameterValuesBodyReadError,
// TestGetDeviceIDByIPJSONMarshalError moved to client_test.go
