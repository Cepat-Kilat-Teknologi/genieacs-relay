// simpan sebagai main_test.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

// --- Mock Data ---

const (
	mockDeviceID = "002568-BCM963268-684752"
	mockDeviceIP = "192.168.1.100"
	mockAPIKey   = "test-secret-key"
)

var mockDeviceDataJSON = `
{
    "_id": "002568-BCM963268-684752",
    "InternetGatewayDevice": {
        "LANDevice": {
            "1": {
                "Hosts": {
                    "Host": {
                        "1": {
                            "IPAddress": { "_value": "192.168.1.2" },
                            "MACAddress": { "_value": "AA:BB:CC:DD:EE:FF" },
                            "HostName": { "_value": "My-Phone" }
                        }
                    }
                },
                "WLANConfiguration": {
                    "1": {
                        "Enable": { "_value": true },
                        "SSID": { "_value": "MyWiFi-2.4GHz" },
                        "Standard": { "_value": "b,g,n" },
                        "PreSharedKey": {
                            "1": {
                                "PreSharedKey": { "_value": "password123" }
                            }
                        }
                    },
                    "5": {
                        "Enable": { "_value": true },
                        "SSID": { "_value": "MyWiFi-5GHz" },
                        "Standard": { "_value": "a,n,ac" },
                        "X_CMS_KeyPassphrase": { "_value": "password5G" }
                    },
                    "2": {
                        "Enable": { "_value": false },
                        "SSID": { "_value": "Disabled-WiFi" }
                    }
                }
            }
        }
    }
}
`

// --- Test Setup ---

func setupTestServer(t *testing.T, mockHandler http.Handler) (*httptest.Server, *chi.Mux) {
	mockGenieServer := httptest.NewServer(mockHandler)
	t.Cleanup(mockGenieServer.Close)

	geniesBaseURL = mockGenieServer.URL
	apiKey = mockAPIKey
	nbiAuthKey = "mock-nbi-key"

	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
		wg:      sync.WaitGroup{},
	}
	taskWorkerPool.Start()
	t.Cleanup(taskWorkerPool.Stop)

	deviceCacheInstance.clearAll()

	r := chi.NewRouter()
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		r.Use(authMiddleware)
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Post("/ssid/{ip}/refresh", refreshSSIDHandler)
		r.Put("/ssid/update/{wlan}/{ip}", updateSSIDByIPHandler)
		r.Put("/password/update/{wlan}/{ip}", updatePasswordByIPHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/cache/clear", clearCacheHandler)
	})
	r.Get("/health", healthCheckHandler)

	return mockGenieServer, r
}

// --- Test Cases ---

func TestHealthCheckHandler(t *testing.T) {
	_, router := setupTestServer(t, nil)
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"status":"healthy"`)
}

func TestAuthMiddleware(t *testing.T) {
	_, router := setupTestServer(t, nil)

	t.Run("Valid API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/some-ip", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.NotEqual(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Invalid API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/some-ip", nil)
		req.Header.Set("X-API-Key", "invalid-key")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Missing API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/some-ip", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestGetSSIDByIPHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("projection") == "_id" {
			query := r.URL.Query().Get("query")
			if strings.Contains(query, mockDeviceIP) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
				return
			}
			if strings.Contains(query, "not-found-ip") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[]`))
				return
			}
		}

		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[" + mockDeviceDataJSON + "]"))
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
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/not-found-ip", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestUpdateSSIDByIPHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Query().Get("projection") == "_id" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
			return
		}

		if r.Method == "GET" && strings.Contains(r.URL.Query().Get("query"), `{"_id":"`+mockDeviceID+`"}`) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}

		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Success", func(t *testing.T) {
		payload := `{"ssid": "New-SSID-Test"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestGetDHCPClientByIPHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("projection") == "_id" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mockHandler)
	req := httptest.NewRequest("GET", "/api/v1/genieacs/dhcp-client/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestDeviceCache(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 50 * time.Millisecond,
	}
	testData := map[string]interface{}{"key": "value"}
	deviceID := "test-device"
	cache.set(deviceID, testData)
	_, found := cache.get(deviceID)
	assert.True(t, found)
}

func TestGetEnv(t *testing.T) {
	key := "TEST_ENV_VAR"
	expectedValue := "hello_world"
	os.Setenv(key, expectedValue)
	defer os.Unsetenv(key)
	val := getEnv(key, "default")
	assert.Equal(t, expectedValue, val)
}

func TestRefreshSSIDHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
			w.Write([]byte(`[]`))
		})
		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/ssid/not-found-ip/refresh", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestWorker_TaskFailure(t *testing.T) {
	var buffer bytes.Buffer
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buffer), zap.InfoLevel)
	testLogger := zap.New(core)
	originalLogger := logger
	logger = testLogger
	defer func() { logger = originalLogger }()

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	mockServer := httptest.NewServer(mockHandler)
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	nbiAuthKey = "mock-nbi-key"

	wp := &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
		wg:      sync.WaitGroup{},
	}
	wp.Start()
	wp.Submit(mockDeviceID, taskTypeSetParams, [][]interface{}{{"some.param", "value", "xsd:string"}})
	wp.Stop()
	assert.Contains(t, buffer.String(), "Worker task failed")
}

type errorCloser struct{}

func (ec *errorCloser) Read(p []byte) (n int, err error) { return 0, io.EOF }
func (ec *errorCloser) Close() error                     { return errors.New("mock close error") }

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

func TestClearCacheHandler(t *testing.T) {
	_, router := setupTestServer(t, nil)
	deviceCacheInstance.set("device1", map[string]interface{}{"key": "value1"})
	t.Run("Clear Specific Device", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/genieacs/cache/clear?device_id=device1", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("Clear All Devices", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/genieacs/cache/clear", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestUpdatePasswordByIPHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if r.Method == "GET" && r.URL.Query().Get("projection") == "_id" {
				w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
			} else if r.Method == "GET" {
				w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			}
		})
		_, router := setupTestServer(t, mockHandler)
		payload := `{"password": "new-secret-password"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Bad Request - Invalid JSON", func(t *testing.T) {
		_, router := setupTestServer(t, nil)
		payload := `{"password": "bad-json`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Not Found - Device IP", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
		})
		_, router := setupTestServer(t, mockHandler)
		payload := `{"password": "any-password"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/not-found-ip", strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("Internal Error - WLAN Validation", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("projection") == "_id" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		})
		_, router := setupTestServer(t, mockHandler)
		payload := `{"password": "any-password"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestRefreshDHCP(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		err := refreshDHCP(ctx, mockDeviceID)
		assert.NoError(t, err)
	})
	t.Run("Non-OK Status", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		err := refreshDHCP(ctx, mockDeviceID)
		assert.Error(t, err)
	})
}

// --- Tes baru untuk mencakup error parsing dan kasus-kasus spesifik ---

func TestParsingErrors(t *testing.T) {
	ctx := context.Background()

	// Tes untuk getBand
	t.Run("getBand Fallback", func(t *testing.T) {
		// Data wlan tanpa key "1" atau "5"
		wlanData := map[string]interface{}{
			"Standard": map[string]interface{}{"_value": "802.11g"},
		}
		band := getBand(wlanData, "2") // Gunakan key non-standar
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

	// Tes untuk kasus-kasus data JSON yang "rusak"
	t.Run("getDHCPClients with malformed data", func(t *testing.T) {
		// 1. Tidak ada InternetGatewayDevice
		_, err := getDHCPClients(ctx, "test")
		// (ini akan gagal di getDeviceData, jadi tidak perlu tes spesifik)

		// 2. Tidak ada LANDevice
		deviceData := map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{}}
		deviceCacheInstance.set("test-no-landevice", deviceData)
		_, err = getDHCPClients(ctx, "test-no-landevice")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice data not found")

		// 3. Tidak ada LANDevice.1
		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{}}}
		deviceCacheInstance.set("test-no-landevice1", deviceData)
		_, err = getDHCPClients(ctx, "test-no-landevice1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice.1 data not found")

		// 4. Tidak ada Hosts
		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{"1": map[string]interface{}{}}}}
		deviceCacheInstance.set("test-no-hosts", deviceData)
		clients, err := getDHCPClients(ctx, "test-no-hosts")
		assert.NoError(t, err)
		assert.Empty(t, clients) // Harusnya mengembalikan slice kosong

		// 5. Tidak ada Host di dalam Hosts
		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{"1": map[string]interface{}{"Hosts": map[string]interface{}{}}}}}
		deviceCacheInstance.set("test-no-host", deviceData)
		clients, err = getDHCPClients(ctx, "test-no-host")
		assert.NoError(t, err)
		assert.Empty(t, clients)
	})

	t.Run("isWLANValid with malformed data", func(t *testing.T) {
		// 1. Tidak ada InternetGatewayDevice
		deviceData := map[string]interface{}{}
		deviceCacheInstance.set("test-no-igd", deviceData)
		_, err := isWLANValid(ctx, "test-no-igd", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "InternetGatewayDevice data not found")

		// 2. Tidak ada LANDevice
		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{}}
		deviceCacheInstance.set("test-no-landevice", deviceData)
		_, err = isWLANValid(ctx, "test-no-landevice", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice data not found")

		// 3. Tidak ada LANDevice.1
		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{}}}
		deviceCacheInstance.set("test-no-landevice1", deviceData)
		_, err = isWLANValid(ctx, "test-no-landevice1", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LANDevice.1 data not found")

		// 4. Tidak ada WLANConfiguration
		deviceData = map[string]interface{}{"InternetGatewayDevice": map[string]interface{}{"LANDevice": map[string]interface{}{"1": map[string]interface{}{}}}}
		deviceCacheInstance.set("test-no-wlanconfig", deviceData)
		valid, err := isWLANValid(ctx, "test-no-wlanconfig", "1")
		assert.NoError(t, err)
		assert.False(t, valid)
	})
}
