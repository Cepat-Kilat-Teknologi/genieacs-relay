package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// --- SSID Handler Tests ---

func TestGetSSIDByIPHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			query := r.URL.Query().Get("query")
			if strings.Contains(query, mockDeviceIP) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			// Use valid IP format for "not found" scenario
			if strings.Contains(query, "192.168.255.255") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[]`))
				return
			}
		}

		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/"+mockDeviceIP, nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		wlanConfigs := resp.Data.([]interface{})
		assert.Len(t, wlanConfigs, 2)
	})

	t.Run("Device Not Found", func(t *testing.T) {
		// Use valid IP format for "not found" scenario
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/192.168.255.255", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestGetSSIDByIPForceHandler(t *testing.T) {
	// Save original httpClient to ensure test isolation
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	// Setup test server with routes, including the force handler
	setupTestServerWithForce := func(t *testing.T, mockHandler http.Handler) (*httptest.Server, *chi.Mux) {
		mockGenieServer := httptest.NewServer(mockHandler)
		t.Cleanup(mockGenieServer.Close)

		// Set mock server URL and auth key
		geniesBaseURL = mockGenieServer.URL
		nbiAuthKey = "mock-nbi-key"

		// Initialize worker pool
		taskWorkerPool = &workerPool{
			workers: 1,
			queue:   make(chan task, 10),
			wg:      sync.WaitGroup{},
		}
		taskWorkerPool.Start()
		t.Cleanup(taskWorkerPool.Stop)

		// Initialize device cache
		deviceCacheInstance = &deviceCache{
			data:    make(map[string]cachedDeviceData),
			timeout: 30 * time.Second,
		}

		// Reset httpClient to default for consistency
		httpClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     30 * time.Second,
			},
		}

		// Setup router with the force handler
		r := chi.NewRouter()
		r.Route("/api/v1/genieacs", func(r chi.Router) {
			r.Get("/force/ssid/{ip}", getSSIDByIPForceHandler)
		})

		return mockGenieServer, r
	}

	// Subtest: Success on first attempt
	t.Run("Success on first attempt", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				query := r.URL.Query().Get("query")
				if strings.Contains(query, mockDeviceIP) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[]`)) // No devices found
				return
			}

			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP, nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

		// Check for error response
		if rr.Code != http.StatusOK {
			t.Fatalf("Unexpected response status %d: %s", rr.Code, resp.Error)
		}

		require.NotNil(t, resp.Data, "Response data should not be nil")

		data, ok := resp.Data.(map[string]interface{})
		require.True(t, ok, "Response data should be a map")

		assert.Equal(t, float64(1), data["attempts"]) // JSON numbers are float64
		assert.Contains(t, data, "wlan_data")
		assert.Len(t, data["wlan_data"].([]interface{}), 2) // Expect 2 WLAN configs
	})

	// Subtest: Success after refresh
	t.Run("Success after refresh", func(t *testing.T) {
		attemptCount := 0
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}

			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				attemptCount++
				if attemptCount == 1 {
					// First attempt: return empty WLAN data
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `", "InternetGatewayDevice": {"LANDevice": {"1": {}}}}]`))
					return
				}
				// Second attempt: return valid WLAN data
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
				return
			}

			if strings.Contains(r.URL.Path, "/tasks") && r.Method == "POST" {
				w.WriteHeader(http.StatusOK)
				return
			}

			w.WriteHeader(http.StatusNotFound)
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP, nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

		if rr.Code != http.StatusOK {
			t.Fatalf("Unexpected response status %d: %s", rr.Code, resp.Error)
		}

		data, ok := resp.Data.(map[string]interface{})
		require.True(t, ok, "Response data should be a map")

		assert.Equal(t, float64(2), data["attempts"]) // Should take 2 attempts
		assert.Contains(t, data, "wlan_data")
		assert.Len(t, data["wlan_data"].([]interface{}), 2) // Expect 2 WLAN configs
	})

	// Subtest: Device not found
	t.Run("Device not found", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`)) // No devices found
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		// Use a valid IP address format that won't be found
		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/192.168.255.255", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusNotFound, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "Device not found", resp.Error)
	})

	// Subtest: Timeout (covers errors.Is(err, context.DeadlineExceeded))
	t.Run("Timeout", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			// Simulate slow response to trigger timeout in getWLANData
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		// Create request with short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP, nil)
		req = req.WithContext(ctx)
		req.Header.Set("X-API-Key", mockAPIKey)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusRequestTimeout, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "Operation timed out while retrieving WLAN data", resp.Error)
	})

	// Subtest: Custom retry parameters
	t.Run("Custom retry parameters", func(t *testing.T) {
		attemptCount := 0
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}

			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				attemptCount++
				if attemptCount < 4 { // Return empty data for first 3 attempts
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `", "InternetGatewayDevice": {"LANDevice": {"1": {}}}}]`))
					return
				}
				// 4th attempt: return valid data
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
				return
			}

			if strings.Contains(r.URL.Path, "/tasks") && r.Method == "POST" {
				w.WriteHeader(http.StatusOK)
				return
			}

			w.WriteHeader(http.StatusNotFound)
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?max_retries=5&retry_delay_ms=5", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

		data, ok := resp.Data.(map[string]interface{})
		require.True(t, ok, "Response data should be a map")

		assert.Equal(t, float64(4), data["attempts"]) // Should take 4 attempts
		assert.Contains(t, data, "wlan_data")
		assert.Len(t, data["wlan_data"].([]interface{}), 2) // Expect 2 WLAN configs
	})

	// Subtest: Max retries exceeded
	t.Run("Max retries exceeded", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}

			// Always return empty WLAN data
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `", "InternetGatewayDevice": {"LANDevice": {"1": {}}}}]`))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?max_retries=2&retry_delay_ms=10", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusNotFound, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Contains(t, resp.Error, "No WLAN data found after 2 attempts")
	})

	// Subtest: Error getting WLAN data
	t.Run("Error getting WLAN data", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			// Return error for WLAN data
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP, nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusInternalServerError, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.Error)
	})

	// Subtest: Refresh error but eventually succeeds
	t.Run("Refresh error but eventually succeeds", func(t *testing.T) {
		attemptCount := 0
		refreshErrorCount := 0
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}

			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				attemptCount++
				if attemptCount <= 2 {
					// First 2 attempts: return empty data
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `", "InternetGatewayDevice": {"LANDevice": {"1": {}}}}]`))
					return
				}
				// 3rd attempt: return valid data
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
				return
			}

			if strings.Contains(r.URL.Path, "/tasks") && r.Method == "POST" {
				refreshErrorCount++
				if refreshErrorCount == 1 {
					// First refresh fails
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				// Second refresh succeeds
				w.WriteHeader(http.StatusOK)
				return
			}

			w.WriteHeader(http.StatusNotFound)
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP, nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

		data, ok := resp.Data.(map[string]interface{})
		require.True(t, ok, "Response data should be a map")

		assert.Equal(t, float64(3), data["attempts"]) // Should take 3 attempts
		assert.Contains(t, data, "wlan_data")
		assert.Len(t, data["wlan_data"].([]interface{}), 2) // Expect 2 WLAN configs
	})

	// Subtest: Invalid max_retries
	t.Run("Invalid max_retries", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.InfoLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?max_retries=invalid", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		data, ok := resp.Data.(map[string]interface{})
		require.True(t, ok, "Response data should be a map")
		assert.Equal(t, float64(1), data["attempts"]) // Should succeed on first attempt
		assert.Contains(t, data, "wlan_data")
		assert.Len(t, data["wlan_data"].([]interface{}), 2)
	})

	// Subtest: Invalid retry_delay_ms
	t.Run("Invalid retry_delay_ms", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.InfoLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?retry_delay_ms=invalid", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		data, ok := resp.Data.(map[string]interface{})
		require.True(t, ok, "Response data should be a map")
		assert.Equal(t, float64(1), data["attempts"]) // Should succeed on first attempt
		assert.Contains(t, data, "wlan_data")
		assert.Len(t, data["wlan_data"].([]interface{}), 2)
	})

	// Subtest: JSON encoding failure
	t.Run("JSON encoding failure", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.ErrorLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		// Create a custom ResponseRecorder that fails on Write
		rr := &errorResponseRecorder{*httptest.NewRecorder()}

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP, nil)
		req = req.WithContext(context.Background())
		req.Header.Set("X-API-Key", mockAPIKey)
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusOK, rr.Code) // Status set before encoding
		assert.Contains(t, logBuffer.String(), "Failed to encode JSON response")
	})

	// Subtest: Context timeout in retry loop
	t.Run("Context timeout in retry loop", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.InfoLevel)
		testLogger := zap.New(core)
		originalLogger := logger

		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			// Respond instantly with empty WLAN data to enter retry loop
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `", "InternetGatewayDevice": {"LANDevice": {"1": {}}}}]`))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		// Create request with short timeout to trigger ctx.Done() in retry loop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP, nil)
		req = req.WithContext(ctx)
		req.Header.Set("X-API-Key", mockAPIKey)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		assert.Equal(t, http.StatusRequestTimeout, rr.Code)
		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "Operation timed out while retrieving WLAN data", resp.Error)
	})

	// Subtest: max_retries out of bounds (negative)
	t.Run("max_retries out of bounds negative", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.WarnLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?max_retries=-1", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		// Should still succeed using default max_retries
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, logBuffer.String(), "max_retries out of bounds")
	})

	// Subtest: max_retries out of bounds (too large)
	t.Run("max_retries out of bounds too large", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.WarnLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?max_retries=100", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		// Should still succeed using default max_retries
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, logBuffer.String(), "max_retries out of bounds")
	})

	// Subtest: retry_delay_ms out of bounds (negative)
	t.Run("retry_delay_ms out of bounds negative", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.WarnLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?retry_delay_ms=-1", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		// Should still succeed using default retry_delay_ms
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, logBuffer.String(), "retry_delay_ms out of bounds")
	})

	// Subtest: retry_delay_ms out of bounds (too large)
	t.Run("retry_delay_ms out of bounds too large", func(t *testing.T) {
		var logBuffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.WarnLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServerWithForce(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/force/ssid/"+mockDeviceIP+"?retry_delay_ms=60000", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		t.Logf("Status: %d", rr.Code)
		t.Logf("Body: %s", rr.Body.String())

		// Should still succeed using default retry_delay_ms
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, logBuffer.String(), "retry_delay_ms out of bounds")
	})
}

func TestRefreshSSIDHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			if r.Method == "POST" {
				w.WriteHeader(http.StatusOK)
				return
			}
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/ssid/"+mockDeviceIP+"/refresh", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusAccepted, rr.Code)
	})

	t.Run("Device Not Found", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})
		_, router := setupTestServer(t, mockHandler)
		// Use valid IP format for "not found" scenario
		req := httptest.NewRequest("POST", "/api/v1/genieacs/ssid/192.168.255.255/refresh", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestGetSSIDByIPHandler_ErrorCases(t *testing.T) {
	t.Run("Error Getting WLAN Data", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusInternalServerError) // Error saat get device data
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/"+mockDeviceIP, nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}
