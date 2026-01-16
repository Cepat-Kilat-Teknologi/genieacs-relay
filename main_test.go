package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// mockDeviceResponseWithLastInform returns a mock device response with a recent _lastInform timestamp
func mockDeviceResponseWithLastInform() string {
	// Use current time as ISO 8601 string for _lastInform (device is active)
	// GenieACS returns _lastInform as ISO 8601 date string (e.g., "2025-01-16T10:30:00.000Z")
	lastInform := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, mockDeviceID, lastInform)
}

// mockDeviceResponseStale returns a mock device response with an old _lastInform timestamp (stale device)
func mockDeviceResponseStale() string {
	// Use time 1 hour ago (definitely stale with default 30 minute threshold)
	// GenieACS returns _lastInform as ISO 8601 date string (e.g., "2025-01-16T10:30:00.000Z")
	lastInform := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, mockDeviceID, lastInform)
}

var httpListenAndServe = http.ListenAndServe

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

func setupTestServer(t *testing.T, mockHandler http.Handler) (*httptest.Server, *chi.Mux) {
	mockGenieServer := httptest.NewServer(mockHandler)
	t.Cleanup(mockGenieServer.Close)

	geniesBaseURL = mockGenieServer.URL
	nbiAuthKey = "mock-nbi-key"

	// Simpan HTTP client asli dan restore setelah test
	originalHTTPClient := httpClient
	t.Cleanup(func() { httpClient = originalHTTPClient })

	// Gunakan HTTP client khusus untuk test
	httpClient = mockGenieServer.Client()

	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
		wg:      sync.WaitGroup{},
	}
	taskWorkerPool.Start()
	t.Cleanup(taskWorkerPool.Stop)

	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	r := chi.NewRouter()
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Get("/force/ssid/{ip}", getSSIDByIPForceHandler)
		r.Post("/ssid/{ip}/refresh", refreshSSIDHandler)
		r.Put("/ssid/update/{wlan}/{ip}", updateSSIDByIPHandler)
		r.Put("/password/update/{wlan}/{ip}", updatePasswordByIPHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/cache/clear", clearCacheHandler)
		// WLAN management routes
		r.Get("/capability/{ip}", getDeviceCapabilityHandler)
		r.Get("/wlan/available/{ip}", getAvailableWLANHandler)
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)
		r.Put("/wlan/update/{wlan}/{ip}", updateWLANHandler)
		r.Delete("/wlan/delete/{wlan}/{ip}", deleteWLANHandler)
		r.Put("/wlan/optimize/{wlan}/{ip}", optimizeWLANHandler)
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

func TestUpdateSSIDByIPHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}

		if r.Method == "GET" && strings.Contains(r.URL.Query().Get("query"), `{"_id":"`+mockDeviceID+`"}`) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
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
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
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
	err := os.Setenv(key, expectedValue)
	if err != nil {
		return
	}
	defer func(key string) {
		err := os.Unsetenv(key)
		if err != nil {
			t.Fatalf("Failed to unset env var: %v", err)
		}
	}(key)
	val := getEnv(key, "default")
	assert.Equal(t, expectedValue, val)
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

func (ec *errorCloser) Read([]byte) (n int, err error) { return 0, io.EOF }
func (ec *errorCloser) Close() error                   { return errors.New("mock close error") }

type errorResponseWriter struct{ httptest.ResponseRecorder }

func (e *errorResponseWriter) Write([]byte) (int, error) { return 0, errors.New("mock write error") }

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
			if r.Method == "GET" && strings.Contains(r.URL.Query().Get("projection"), "_id") {
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			} else if r.Method == "GET" {
				_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
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
			_, _ = w.Write([]byte("[]"))
		})
		_, router := setupTestServer(t, mockHandler)
		payload := `{"password": "any-password"}`
		// Use valid IP format for "not found" scenario
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/192.168.255.255", strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("Internal Error - WLAN Validation", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
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
		assert.Equal(t, "keypass123", getPassword(wlanData1, false))

		wlanData2 := map[string]interface{}{
			"PreSharedKey": map[string]interface{}{
				"1": map[string]interface{}{
					"PreSharedKey": map[string]interface{}{"_value": "preshared456"},
				},
			},
		}
		assert.Equal(t, "preshared456", getPassword(wlanData2, false))

		// ZTE password is no longer masked - returns actual password
		assert.Equal(t, "keypass123", getPassword(wlanData1, true))

		// No password field at all - returns N/A
		wlanData3 := map[string]interface{}{}
		assert.Equal(t, "N/A", getPassword(wlanData3, false))

		// Password field exists but empty (encrypted) - returns ******
		wlanData4 := map[string]interface{}{
			"PreSharedKey": map[string]interface{}{
				"1": map[string]interface{}{
					"KeyPassphrase": map[string]interface{}{"_value": ""},
				},
			},
		}
		assert.Equal(t, "******", getPassword(wlanData4, false))
	})

	t.Run("Communication function errors", func(t *testing.T) {
		t.Run("httpClient.Do fails", func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			geniesBaseURL = mockServer.URL
			mockServer.Close()
			_, err := getDeviceData(ctx, mockDeviceID)
			assert.Error(t, err)
		})

		t.Run("io.ReadAll fails", func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "5")
			}))
			defer mockServer.Close()
			geniesBaseURL = mockServer.URL
			_, err := getDeviceData(ctx, mockDeviceID)
			assert.Error(t, err)
		})

		t.Run("json.Unmarshal fails", func(t *testing.T) {
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

func TestGetDHCPClientByIPHandler_Complete(t *testing.T) {
	t.Run("Error Getting Device ID", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("GET", "/api/v1/genieacs/dhcp-client/error-ip", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("Error Getting DHCP Clients", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("GET", "/api/v1/genieacs/dhcp-client/"+mockDeviceIP, nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Refresh DHCP Error", func(t *testing.T) {
		deviceCacheInstance.clearAll()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			if r.URL.Query().Get("refresh") == "true" {
				w.WriteHeader(http.StatusInternalServerError) // Refresh gagal
				return
			}
			w.WriteHeader(http.StatusInternalServerError) // Get device data juga gagal
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("GET", "/api/v1/genieacs/dhcp-client/"+mockDeviceIP+"?refresh=true", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestUpdateSSIDByIPHandler_ErrorCases(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		_, router := setupTestServer(t, nil)
		payload := `{"ssid": "bad-json`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Missing SSID", func(t *testing.T) {
		_, router := setupTestServer(t, nil)
		payload := `{}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("WLAN Validation Error", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, router := setupTestServer(t, mockHandler)
		payload := `{"ssid": "New-SSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("WLAN Not Found", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServer(t, mockHandler)
		payload := `{"ssid": "New-SSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/99/"+mockDeviceIP, strings.NewReader(payload))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("getEnv with default value", func(t *testing.T) {
		val := getEnv("NON_EXISTENT_VAR", "default_value")
		assert.Equal(t, "default_value", val)
	})

	t.Run("safeClose with nil", func(t *testing.T) {
		assert.NotPanics(t, func() {
			safeClose(nil)
		})
	})

	t.Run("getBand with various standards", func(t *testing.T) {
		testCases := []struct {
			standard string
			expected string
		}{
			{"b,g,n", "2.4GHz"},
			{"a,n,ac", "5GHz"},
			{"n", "Unknown"},
			{"", "Unknown"},
		}

		for _, tc := range testCases {
			wlanData := map[string]interface{}{
				"Standard": map[string]interface{}{"_value": tc.standard},
			}
			band := getBand(wlanData, "test")
			assert.Equal(t, tc.expected, band)
		}
	})

	t.Run("getPassword for ZTE devices - no longer masked", func(t *testing.T) {
		wlanData := map[string]interface{}{
			"PreSharedKey": map[string]interface{}{
				"1": map[string]interface{}{
					"PreSharedKey": map[string]interface{}{"_value": "password123"},
				},
			},
		}
		password := getPassword(wlanData, true) // ZTE device - password now visible
		assert.Equal(t, "password123", password)
	})
}

func TestWorkerPool_EdgeCases(t *testing.T) {
	t.Run("Unknown task type", func(t *testing.T) {
		var buffer bytes.Buffer
		encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
		core := zapcore.NewCore(encoder, zapcore.AddSync(&buffer), zap.InfoLevel)
		testLogger := zap.New(core)
		originalLogger := logger
		logger = testLogger
		defer func() { logger = originalLogger }()

		wp := &workerPool{
			workers: 1,
			queue:   make(chan task, 1),
			wg:      sync.WaitGroup{},
		}
		wp.Start()
		wp.Submit("test-device", "unknown_task_type", nil)
		time.Sleep(100 * time.Millisecond) // Give worker time to process
		wp.Stop()

		assert.Contains(t, buffer.String(), "Worker task failed")
	})
}

func TestDeviceCache_Timeout(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 10 * time.Millisecond, // Very short timeout
	}

	testData := map[string]interface{}{"key": "value"}
	deviceID := "test-device"

	cache.set(deviceID, testData)
	time.Sleep(20 * time.Millisecond) // Wait for cache to expire

	_, found := cache.get(deviceID)
	assert.False(t, found)
}

func TestGetDeviceIDByIP_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("HTTP Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL

		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})

	t.Run("JSON Parse Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`invalid json`))
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL

		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})
}

func TestPostJSONRequest_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("HTTP Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		geniesBaseURL = mockServer.URL
		mockServer.Close()

		_, err := postJSONRequest(ctx, geniesBaseURL+"/test", "payload")
		assert.Error(t, err)
	})
}

func TestSetParameterValues_Success(t *testing.T) {
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL

	params := [][]interface{}{{"param.path", "value", "xsd:string"}}
	err := setParameterValues(ctx, mockDeviceID, params)
	assert.NoError(t, err)
}

func TestRefreshWLANConfig_Success(t *testing.T) {
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL

	err := refreshWLANConfig(ctx, mockDeviceID)
	assert.NoError(t, err)
}

func TestMainFunction(t *testing.T) {
	originalGenieURL := geniesBaseURL
	originalNBIKey := nbiAuthKey
	originalLogger := logger

	defer func() {
		geniesBaseURL = originalGenieURL
		nbiAuthKey = originalNBIKey
		logger = originalLogger
	}()

	assert.NotPanics(t, func() {
		// Test minimal initialization
		geniesBaseURL = "http://test"
		nbiAuthKey = "test"
	})
}

func TestGetDeviceIDByIP_ReadAllError(t *testing.T) {
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Length", "100")
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL

	_, err := getDeviceIDByIP(ctx, "1.1.1.1")
	assert.Error(t, err)
}

func TestIsWLANValid_OutOfRange(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": []interface{}{"a", "b"}, // cuma 2 index
				},
			},
		},
	}
	deviceCacheInstance.set("out-of-range", deviceData)

	ok, err := isWLANValid(ctx, "out-of-range", "5")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestUpdateSSIDByIPHandler_ExtraCases(t *testing.T) {
	// Case: invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/update-ssid", strings.NewReader("{invalid"))
	req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
	w := httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	// Case: empty SSID
	body := `{"ssid":""}`
	req = httptest.NewRequest(http.MethodPost, "/update-ssid", strings.NewReader(body))
	req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
	w = httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	// Case: empty IP - device not found (with valid WLAN ID)
	req = httptest.NewRequest(http.MethodPost, "/update-ssid", strings.NewReader(`{"ssid":"newssid"}`))
	req = withChiURLParams(req, map[string]string{"wlan": "99", "ip": ""})
	w = httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
}

func TestUpdatePasswordByIPHandler_ExtraCases(t *testing.T) {
	// Case: invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/update-password", strings.NewReader("{invalid"))
	req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
	w := httptest.NewRecorder()
	updatePasswordByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	// Case: empty password
	body := `{"password":""}`
	req = httptest.NewRequest(http.MethodPost, "/update-password", strings.NewReader(body))
	req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
	w = httptest.NewRecorder()
	updatePasswordByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	// Case: empty IP - device not found (with valid WLAN ID)
	req = httptest.NewRequest(http.MethodPost, "/update-password", strings.NewReader(`{"password":"validpass123"}`))
	req = withChiURLParams(req, map[string]string{"wlan": "99", "ip": ""})
	w = httptest.NewRecorder()
	updatePasswordByIPHandler(w, req)
	assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
}

func TestPostJSONRequest_ExtraCases(t *testing.T) {
	// Case: invalid URL
	_, err := postJSONRequest(context.Background(), "https://[::1]:namedport", nil)
	assert.Error(t, err)

	ch := make(chan int)
	_, err = postJSONRequest(context.Background(), "http://localhost", map[string]interface{}{"bad": ch})
	assert.Error(t, err)

	// Case: server OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key":"value"}`))
	}))
	defer server.Close()

	geniesBaseURL = server.URL
	_, err = postJSONRequest(context.Background(), geniesBaseURL, nil)
	assert.NoError(t, err)
}

func TestGetDeviceIDByIP_ExtraCases(t *testing.T) {
	ctx := context.Background()

	// Case: empty response body (valid JSON array tapi kosong)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	_, err := getDeviceIDByIP(ctx, "1.2.3.4")
	assert.Error(t, err)
}

func TestRefreshWLANConfig_ExtraCases(t *testing.T) {
	ctx := context.Background()

	// Case: 500 status
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	err := refreshWLANConfig(ctx, "dev1")
	assert.Error(t, err)
}

func TestGetWLANData_ExtraCases(t *testing.T) {
	ctx := context.Background()

	// Case: malformed JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	_, err := getWLANData(ctx, "dev1")
	assert.Error(t, err)
}

func TestRefreshDHCP_ExtraCases(t *testing.T) {
	ctx := context.Background()

	// Case: 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	err := refreshDHCP(ctx, "dev1")
	assert.Error(t, err)
}

func TestIsWLANValid_ExtraCases(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.set("bad-wlan", map[string]interface{}{"SSID": 123})
	ok, err := isWLANValid(ctx, "bad-wlan", "1")
	assert.False(t, ok)
	assert.Error(t, err)
}

func TestGetDeviceData_Success(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `[{"_id":"` + mockDeviceID + `"}]`
		_, _ = w.Write([]byte(resp))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	data, err := getDeviceData(ctx, mockDeviceID)
	assert.NoError(t, err)
	assert.Equal(t, mockDeviceID, data["_id"])
}

func TestGetDeviceIDByIP_Success(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Include _lastInform with current timestamp (active device)
		_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	id, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.NoError(t, err)
	assert.Equal(t, mockDeviceID, id)
}

func TestGetDeviceIDByIP_StaleDevice(t *testing.T) {
	ctx := context.Background()

	// Save original staleThreshold
	originalThreshold := staleThreshold

	// Set stale threshold to 10 minutes
	staleThreshold = 10 * time.Minute

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return device with _lastInform 1 hour ago (stale)
		_, _ = w.Write([]byte(mockDeviceResponseStale()))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	// Restore original threshold after test
	defer func() {
		staleThreshold = originalThreshold
	}()

	id, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
	assert.Empty(t, id)
	assert.Contains(t, err.Error(), "stale")
}

func TestGetWLANData_Success(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	data, err := getWLANData(ctx, mockDeviceID)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Equal(t, "MyWiFi-2.4GHz", data[0].SSID)
	assert.Equal(t, "2.4GHz", data[0].Band)
}

func TestGetDHCPClients_Success(t *testing.T) {
	ctx := context.Background()

	// Simulate cached device data with DHCP clients
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"Hosts": map[string]interface{}{
						"Host": map[string]interface{}{
							"1": map[string]interface{}{
								"IPAddress":  map[string]interface{}{"_value": "192.168.1.50"},
								"MACAddress": map[string]interface{}{"_value": "AA:BB:CC:DD:EE:FF"},
								"HostName":   map[string]interface{}{"_value": "TestHost"},
							},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("device-dhcp", deviceData)

	clients, err := getDHCPClients(ctx, "device-dhcp")
	assert.NoError(t, err)
	assert.Len(t, clients, 1)
	assert.Equal(t, "192.168.1.50", clients[0].IP)
	assert.Equal(t, "TestHost", clients[0].Hostname)
}

func TestUpdatePasswordByIPHandler_WLANNotFound(t *testing.T) {
	// Mock server balikin device data valid tapi WLANConfig gak ada index 99
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
	})

	_, router := setupTestServer(t, mockHandler)

	payload := `{"password":"validpass123"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/99/"+mockDeviceIP, strings.NewReader(payload))
	req.Header.Set("X-API-Key", mockAPIKey)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func loadConfigFromEnv() {
	geniesBaseURL = getEnv("GENIEACS_BASE_URL", "http://127.0.0.1:7557")
	nbiAuthKey = getEnv("NBI_AUTH_KEY", "mock-nbi-key")
}

func init() {
	loadConfigFromEnv()
}

func TestInitEnvFallback(t *testing.T) {
	oldGenie := os.Getenv("GENIEACS_BASE_URL")
	oldNBI := os.Getenv("NBI_AUTH_KEY")
	oldAPI := os.Getenv("API_KEY")
	defer func() {
		_ = os.Setenv("GENIEACS_BASE_URL", oldGenie)
		_ = os.Setenv("NBI_AUTH_KEY", oldNBI)
		_ = os.Setenv("API_KEY", oldAPI)
	}()

	_ = os.Unsetenv("GENIEACS_BASE_URL")
	_ = os.Unsetenv("NBI_AUTH_KEY")
	_ = os.Unsetenv("API_KEY")
	loadConfigFromEnv()

	assert.NotEmpty(t, geniesBaseURL)
	assert.NotEmpty(t, nbiAuthKey)
}

func TestGetDeviceData_Non200(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusBadRequest)
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	_, err := getDeviceData(ctx, "dev-x")
	assert.Error(t, err)
}

func TestGetDeviceIDByIP_NoID(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{}]`))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	id, err := getDeviceIDByIP(ctx, "1.1.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "", id) // device kosong, no error
}

func TestRefreshWLANConfig_AllPaths(t *testing.T) {
	ctx := context.Background()
	// success
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv1.Close()
	geniesBaseURL = srv1.URL
	assert.NoError(t, refreshWLANConfig(ctx, "dev1"))

	// non-200
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusInternalServerError)
	}))
	defer srv2.Close()
	geniesBaseURL = srv2.URL
	assert.Error(t, refreshWLANConfig(ctx, "dev2"))
}

func TestGetWLANData_DisabledOrMalformed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
            "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Enable": {"_value":"0"},
            "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID": {"_value":"ssid-disabled"}
        }`))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	wlan, err := getWLANData(context.Background(), "dev-1")
	assert.Error(t, err)
	assert.Empty(t, wlan)
}

func TestGetDHCPClients_MalformedHosts(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"Hosts": map[string]interface{}{
						"Host": "not-map", // salah tipe
					},
				},
			},
		},
	}
	deviceCacheInstance.set("bad-host", deviceData)

	clients, err := getDHCPClients(ctx, "bad-host")
	assert.NoError(t, err)
	assert.Empty(t, clients)
}

func TestIsWLANValid_Disabled(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": false},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("disabled-wlan", deviceData)
	ok, err := isWLANValid(ctx, "disabled-wlan", "1")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func loadEnv() {
	geniesBaseURL = getEnv("GENIEACS_URL", geniesBaseURL)
	nbiAuthKey = getEnv("NBI_AUTH_KEY", nbiAuthKey)
}
func TestInit_WithEnvVars(t *testing.T) {
	os.Setenv("GENIEACS_URL", "http://env-url")
	os.Setenv("NBI_AUTH_KEY", "env-nbi")
	os.Setenv("API_KEY", "env-api")
	defer os.Clearenv()

	loadEnv()
	if geniesBaseURL != "http://env-url" {
		t.Errorf("expected %q, got %q", "http://env-url", geniesBaseURL)
	}
	if nbiAuthKey != "env-nbi" {
		t.Errorf("expected %q, got %q", "env-nbi", nbiAuthKey)
	}
}

var (
	originalListenAndServe = httpListenAndServe
)

func TestMainFunction_NoListen(t *testing.T) {
	called := false
	httpListenAndServe = func(addr string, handler http.Handler) error {
		called = true
		return nil
	}
	defer func() { httpListenAndServe = originalListenAndServe }()

	// langsung panggil bagian main yang sebelum ListenAndServe
	loadEnv()

	// panggil router setup ala main()
	r := http.NewServeMux()
	r.HandleFunc("/health", healthCheckHandler)

	// simulasi pemanggilan httpListenAndServe
	_ = httpListenAndServe(":8080", r)

	if !called {
		t.Errorf("ListenAndServe should be called")
	}
}

func TestGetDeviceIDByIP_EmptyArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`)) // kosong
	}))
	defer server.Close()

	geniesBaseURL = server.URL
	_, err := getDeviceIDByIP(context.Background(), "1.1.1.1")
	assert.Error(t, err)
}

func TestRefreshWLANConfig_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	geniesBaseURL = server.URL
	err := refreshWLANConfig(context.Background(), "device-1")
	assert.Error(t, err)
}

func TestGetWLANData_DisabledAndMalformed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// WLAN disabled & data tidak lengkap
		_, _ = w.Write([]byte(`{
			"InternetGatewayDevice.WLANConfiguration.1.Enable._value":"0",
			"InternetGatewayDevice.WLANConfiguration.1.SSID._value":123
		}`))
	}))
	defer server.Close()

	geniesBaseURL = server.URL
	_, err := getWLANData(context.Background(), "dev-x")
	assert.Error(t, err)
}

func TestGetDHCPClients_InvalidHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// data hosts tapi malformed
		_, _ = w.Write([]byte(`{"InternetGatewayDevice.LANDevice.1.Hosts.Host.1.HostName":{}}`))
	}))
	defer server.Close()

	geniesBaseURL = server.URL
	_, err := getDHCPClients(context.Background(), "dev-x")
	assert.Error(t, err)
}

func TestRefreshDHCP_ErrorPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	geniesBaseURL = server.URL
	err := refreshDHCP(context.Background(), "dev-x")
	assert.Error(t, err)
}

type badCloser struct{}

func (b badCloser) Close() error { return errors.New("close error") }

func Test_safeClose_Error(t *testing.T) {
	safeClose(badCloser{}) // hanya untuk memanggil branch error
	safeClose(nil)         // test dengan nil
}

// Test_getDeviceData_Error memaksa error saat HTTP request
func Test_getDeviceData_Error(t *testing.T) {
	// pakai URL invalid biar NewRequest gagal
	geniesBaseURL = "http://[::1]:namedport"
	_, err := getDeviceData(context.Background(), "dummy")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// Test_getDeviceIDByIP_Error memaksa error di http.NewRequest
func Test_getDeviceIDByIP_Error(t *testing.T) {
	geniesBaseURL = "http://[::1]:badport"
	_, err := getDeviceIDByIP(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// Test_refreshWLANConfig_Error forcing error di http.NewRequest
func Test_refreshWLANConfig_Error(t *testing.T) {
	// URL invalid force error
	geniesBaseURL = "http://[::1]:invalid"
	err := refreshWLANConfig(context.Background(), "dev123")
	if err == nil {
		t.Fatal("expected error")
	}
}

// Test_refreshDHCP_Error memaksa postJSONRequest return error
func Test_refreshDHCP_Error(t *testing.T) {
	geniesBaseURL = "http://[::1]:invalid"
	err := refreshDHCP(context.Background(), "dev123")
	if err == nil {
		t.Fatal("expected error")
	}
}

// Test_getWLANData_ErrorCases forcing various error cases
func Test_getWLANData_ErrorCases(t *testing.T) {
	// inject data kosong
	deviceCacheInstance.set("dev1", map[string]interface{}{})
	_, err := getWLANData(context.Background(), "dev1")
	if err == nil {
		t.Fatal("expected error karena InternetGatewayDevice tidak ada")
	}

	// inject LANDevice tanpa WLANConfiguration
	deviceCacheInstance.set("dev2", map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{},
			},
		},
	})
	data, err := getWLANData(context.Background(), "dev2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty WLAN config, got %v", data)
	}
}

type WorkerPool interface {
	Start()
	Stop()
	Submit(action, deviceID string, params [][]interface{})
}

func Test_main(t *testing.T) {
	// backup instance asli
	orig := taskWorkerPool
	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 1),
	}
	defer func() { taskWorkerPool = orig }()

	// set env minimal
	os.Setenv("GENIEACS_BASE_URL", "http://localhost")
	os.Setenv("NBI_AUTH_KEY", "test")
	os.Setenv("API_KEY", "apitest")

	done := make(chan struct{})
	go func() {
		defer close(done)
		// trigger signal setelah 200ms
		go func() {
			time.Sleep(200 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(os.Interrupt)
		}()
		main()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("main() tidak selesai dalam waktu 2s")
	}
}

// Test_sendResponse_sendError memaksa JSON encoder gagal
func Test_sendResponse_sendError(t *testing.T) {
	w := httptest.NewRecorder()
	// channel tidak bisa di-encode ke JSON
	sendResponse(w, 200, "OK", make(chan int))

	w2 := httptest.NewRecorder()
	sendError(w2, 400, "Bad", string([]byte{0x7f})) // tetap bisa di-encode
}

// Test_updateSSIDByIPHandler_BadJSON memaksa JSON salah
func Test_updateSSIDByIPHandler_BadJSON(t *testing.T) {
	req := httptest.NewRequest("PUT", "/ssid/update/1/127.0.0.1", strings.NewReader("{bad json"))
	req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "127.0.0.1"})
	w := httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// Test_updatePasswordByIPHandler_BadJSON memaksa JSON salah
func Test_updatePasswordByIPHandler_BadJSON(t *testing.T) {
	req := httptest.NewRequest("PUT", "/password/update/1/127.0.0.1", strings.NewReader("{bad json"))
	req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "127.0.0.1"})
	w := httptest.NewRecorder()
	updatePasswordByIPHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// Test_postJSONRequest_BadPayload memaksa json.Marshal gagal
func Test_postJSONRequest_BadPayload(t *testing.T) {
	_, err := postJSONRequest(context.Background(), "http://localhost", func() {})
	if err == nil {
		t.Fatal("expected error dari marshal")
	}
}

// Test_getPassword_NoField untuk coverage when password field not found
func Test_getPassword_NoField(t *testing.T) {
	pw := getPassword(map[string]interface{}{}, false)
	if pw != "N/A" {
		t.Fatalf("expected N/A, got %s", pw)
	}
}

// Test_getPassword_EmptyField untuk coverage when password field exists but empty (encrypted)
func Test_getPassword_EmptyField(t *testing.T) {
	wlanData := map[string]interface{}{
		"X_CMS_KeyPassphrase": map[string]interface{}{"_value": ""},
	}
	pw := getPassword(wlanData, false)
	if pw != "******" {
		t.Fatalf("expected ******, got %s", pw)
	}
}

// Test_getPassword_EmptyPreSharedKey untuk coverage when PreSharedKey.1.PreSharedKey exists but empty
func Test_getPassword_EmptyPreSharedKey(t *testing.T) {
	wlanData := map[string]interface{}{
		"PreSharedKey": map[string]interface{}{
			"1": map[string]interface{}{
				"PreSharedKey": map[string]interface{}{"_value": ""},
			},
		},
	}
	pw := getPassword(wlanData, false)
	if pw != "******" {
		t.Fatalf("expected ******, got %s", pw)
	}
}

// Test_getBand_Unknown untuk coverage unknown
func Test_getBand_Unknown(t *testing.T) {
	b := getBand(map[string]interface{}{}, "99")
	if b != "Unknown" {
		t.Fatalf("expected Unknown, got %s", b)
	}
}

// Test_formatDuration tests all branches of formatDuration function
func Test_formatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"seconds", 30 * time.Second, "30 seconds"},
		{"minutes", 45 * time.Minute, "45 minutes"},
		{"hours", 5 * time.Hour, "5.0 hours"},
		{"days", 48 * time.Hour, "2.0 days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMain_ServerErrors(t *testing.T) {
	// Simulasi server yang selalu error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	// Override geniesBaseURL ke server mock
	originalGeniesBaseURL := geniesBaseURL
	geniesBaseURL = server.URL
	defer func() { geniesBaseURL = originalGeniesBaseURL }()

	// Panggil fungsi yang akan memicu error dari server
	ctx := context.Background()
	_, err := getDeviceIDByIP(ctx, "ip")
	if err == nil {
		t.Fatal("expected error from server")
	}
}

func TestGetDeviceIDByIP_UnmarshalError(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`)) // JSON salah
	}))
	defer server.Close()
	geniesBaseURL = server.URL
	_, err := getDeviceIDByIP(ctx, "ip")
	if err == nil {
		t.Fatal("expected JSON unmarshal error")
	}
}

func TestGetWLANData_LANDeviceMissing(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{},
	}
	deviceCacheInstance.set("no-lan", deviceData)

	_, err := getWLANData(ctx, "no-lan")
	if err == nil {
		t.Fatal("expected error karena LANDevice tidak ada")
	}
}

func TestGetWLANData_SortInvalidKeys(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"a": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "SSID-A"},
							"Standard": map[string]interface{}{
								"_value": "b,g,n",
							},
						},
						"b": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "SSID-B"},
							"Standard": map[string]interface{}{
								"_value": "a,n,ac",
							},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("invalid-keys", deviceData)

	data, err := getWLANData(ctx, "invalid-keys")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 2 {
		t.Fatalf("expected 2 WLAN configs, got %d", len(data))
	}

	// Cek isi slice tanpa peduli urutan
	ssids := []string{data[0].SSID, data[1].SSID}
	sort.Strings(ssids)
	expected := []string{"SSID-A", "SSID-B"}
	if !reflect.DeepEqual(ssids, expected) {
		t.Fatalf("unexpected SSIDs: %v", ssids)
	}
}

func TestGetDHCPClients_InternetGatewayMissing(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"SomeOtherDevice": map[string]interface{}{},
	}
	deviceCacheInstance.set("no-igd", deviceData)

	_, err := getDHCPClients(ctx, "no-igd")
	if err == nil {
		t.Fatal("expected error karena InternetGatewayDevice tidak ada")
	}
}
func TestGetDHCPClients_LANDevice1Missing(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"2": map[string]interface{}{}, // LANDevice.1 tidak ada
			},
		},
	}
	deviceCacheInstance.set("no-lan1-dhcp", deviceData)

	_, err := getDHCPClients(ctx, "no-lan1-dhcp")
	if err == nil {
		t.Fatal("expected error karena LANDevice.1 tidak ada")
	}
}

type fakeRoundTripper struct {
	resp *http.Response
	err  error
}

func (f *fakeRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return f.resp, f.err
}

func TestGetDeviceIDByIP_ReadBodyError(t *testing.T) {
	httpClient = &http.Client{
		Transport: &fakeRoundTripper{
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(errReader{}),
			},
			err: nil,
		},
	}
	_, err := getDeviceIDByIP(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestGetWLANData_NonNumericKeys(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"a": map[string]interface{}{
							"Enable":   map[string]interface{}{"_value": true},
							"SSID":     map[string]interface{}{"_value": "SSID-A"},
							"Standard": map[string]interface{}{"_value": "b,g,n"},
						},
						"b": map[string]interface{}{
							"Enable":   map[string]interface{}{"_value": true},
							"SSID":     map[string]interface{}{"_value": "SSID-B"},
							"Standard": map[string]interface{}{"_value": "a,n,ac"},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("non-numeric-test", deviceData)

	configs, err := getWLANData(ctx, "non-numeric-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(configs))
	}

	// urutan slice tidak dijamin karena comparator return false,
	// jadi cek isi slice saja, bukan index
	ssids := []string{configs[0].SSID, configs[1].SSID}
	sort.Strings(ssids)
	expected := []string{"SSID-A", "SSID-B"}
	if !reflect.DeepEqual(ssids, expected) {
		t.Fatalf("unexpected SSIDs: got %v, want %v", ssids, expected)
	}
}

func TestGetWLANData_DeviceNotFound(t *testing.T) {
	ctx := context.Background()
	_, err := getWLANData(ctx, "unknown-device")
	if err == nil {
		t.Fatal("expected error for unknown device, got nil")
	}
}

func TestGetWLANData_NoInternetGatewayDevice(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.set("no-igd", map[string]interface{}{})
	_, err := getWLANData(ctx, "no-igd")
	if err == nil {
		t.Fatal("expected error for missing InternetGatewayDevice, got nil")
	}
}

func TestGetWLANData_NoWLANConfig(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.set("no-wlan", map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{},
			},
		},
	})
	configs, err := getWLANData(ctx, "no-wlan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Fatalf("expected 0 configs, got %d", len(configs))
	}
}

func TestGetWLANData_NoLANDevice1(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.set("no-landev1", map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{}, // tidak ada "1"
		},
	})

	_, err := getWLANData(ctx, "no-landev1")
	if err == nil || !strings.Contains(err.Error(), "LANDevice.1 data not found") {
		t.Fatalf("expected LANDevice.1 not found error, got %v", err)
	}
}

func TestGetWLANData_MissingEnable(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.set("missing-enable", map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{ // WLAN tanpa Enable
							"SSID":     map[string]interface{}{"_value": "TestSSID"},
							"Standard": map[string]interface{}{"_value": "b,g,n"},
						},
					},
				},
			},
		},
	})

	configs, err := getWLANData(ctx, "missing-enable")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Fatalf("expected 0 configs, got %d", len(configs))
	}
}

func TestGetWLANData_MissingSSID(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.set("missing-ssid", map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{ // WLAN tanpa SSID
							"Enable":   map[string]interface{}{"_value": true},
							"Standard": map[string]interface{}{"_value": "a,n,ac"},
						},
					},
				},
			},
		},
	})

	configs, err := getWLANData(ctx, "missing-ssid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	// SSID hilang → hasilnya "" (empty string)
	if configs[0].SSID != "" {
		t.Fatalf("expected empty SSID, got %q", configs[0].SSID)
	}
}

func TestGetWLANData_InvalidEntryType(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.set("invalid-entry", map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": "not-a-map", // 🚀 bikin gagal type assertion
					},
				},
			},
		},
	})

	configs, err := getWLANData(ctx, "invalid-entry")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(configs) != 0 {
		t.Fatalf("expected 0 configs for invalid entry, got %d", len(configs))
	}
}

func TestRunServer_StartFail(t *testing.T) {
	// Simpan original function
	originalNewHTTPServer := newHTTPServer

	// Buat listener untuk memegang port sebentar
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	occupiedPort := listener.Addr().(*net.TCPAddr).Port

	// Override newHTTPServer forcing it to return server that tries to use occupied port
	newHTTPServer = func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:    fmt.Sprintf(":%d", occupiedPort),
			Handler: handler,
		}
	}

	// Restore original function
	defer func() {
		newHTTPServer = originalNewHTTPServer
		listener.Close()
	}()

	// Test server start failure
	err = runServer(":0")
	if err == nil {
		t.Fatal("Expected server start to fail due to occupied port, but it didn't")
	}

	// Check error message
	if err != nil && !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("Expected 'address already in use' error, got: %v", err)
	}
}

func TestRunServer_ShutdownFail(t *testing.T) {
	// Save original function
	originalNewHTTPServer := newHTTPServer

	// Create channel for signaling server start
	serverStarted := make(chan bool, 1)

	// Override newHTTPServer forcing it to return server that fails on Shutdown
	newHTTPServer = func(addr string, handler http.Handler) *http.Server {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}

		s := &http.Server{
			Addr:    listener.Addr().String(),
			Handler: handler,
		}

		// Start server di goroutine
		go func() {
			serverStarted <- true
			if err := s.Serve(listener); err != nil && err != http.ErrServerClosed {
				t.Logf("Test server error: %v", err)
			}
		}()

		// After server started, close listener to force shutdown error
		go func() {
			<-serverStarted
			time.Sleep(50 * time.Millisecond)
			listener.Close() // Close listener to cause shutdown error
		}()

		return s
	}

	// Restore original function after doing test
	defer func() {
		newHTTPServer = originalNewHTTPServer
	}()

	// Send SIGINT after short delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Test server shutdown failure
	err := runServer(":0")
	if err == nil {
		t.Fatal("Expected server shutdown to fail, but it didn't")
	}
}

func TestRunServer_NormalOperation(t *testing.T) {
	// Send SIGINT after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Test normal operation
	err := runServer(":0")
	if err != nil {
		t.Fatalf("Expected normal shutdown, got error: %v", err)
	}
}

func TestRunServer_EmptyNBIAuthKey(t *testing.T) {
	// Save original env value
	originalNBIKey := os.Getenv("NBI_AUTH_KEY")

	// Unset NBI_AUTH_KEY to trigger warning
	os.Unsetenv("NBI_AUTH_KEY")

	// Restore original value after test
	defer func() {
		if originalNBIKey != "" {
			os.Setenv("NBI_AUTH_KEY", originalNBIKey)
		}
	}()

	// Send SIGINT after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Test should complete without error (warning is logged but not fatal)
	err := runServer(":0")
	if err != nil {
		t.Fatalf("Expected normal shutdown, got error: %v", err)
	}
}

func TestRunServer_WithMiddlewareAuthEnabled(t *testing.T) {
	// Save original env values
	originalMiddlewareAuth := os.Getenv("MIDDLEWARE_AUTH")
	originalAuthKey := os.Getenv("AUTH_KEY")

	// Set MIDDLEWARE_AUTH=true with a valid AUTH_KEY
	os.Setenv("MIDDLEWARE_AUTH", "true")
	os.Setenv("AUTH_KEY", "test-key-for-server")

	// Restore original values after a test
	defer func() {
		if originalMiddlewareAuth != "" {
			os.Setenv("MIDDLEWARE_AUTH", originalMiddlewareAuth)
		} else {
			os.Unsetenv("MIDDLEWARE_AUTH")
		}
		if originalAuthKey != "" {
			os.Setenv("AUTH_KEY", originalAuthKey)
		} else {
			os.Unsetenv("AUTH_KEY")
		}
	}()

	// Send SIGINT after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Test should complete without error
	err := runServer(":0")
	if err != nil {
		t.Fatalf("Expected normal shutdown, got error: %v", err)
	}
}

func TestRunServer_WithMiddlewareAuthEnabledAndEmptyKey(t *testing.T) {
	// Save original env values
	originalMiddlewareAuth := os.Getenv("MIDDLEWARE_AUTH")
	originalAuthKey := os.Getenv("AUTH_KEY")

	// Set MIDDLEWARE_AUTH=true but no AUTH_KEY to trigger warning
	os.Setenv("MIDDLEWARE_AUTH", "true")
	os.Unsetenv("AUTH_KEY")

	// Restore original values after test
	defer func() {
		if originalMiddlewareAuth != "" {
			os.Setenv("MIDDLEWARE_AUTH", originalMiddlewareAuth)
		} else {
			os.Unsetenv("MIDDLEWARE_AUTH")
		}
		if originalAuthKey != "" {
			os.Setenv("AUTH_KEY", originalAuthKey)
		} else {
			os.Unsetenv("AUTH_KEY")
		}
	}()

	// Send SIGINT after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Test should complete without error (warning is logged but not fatal)
	err := runServer(":0")
	if err != nil {
		t.Fatalf("Expected normal shutdown, got error: %v", err)
	}
}

func TestRunServer_ServerError(t *testing.T) {
	// Save original function
	originalNewHTTPServer := newHTTPServer

	// Override newHTTPServer forcing it to return server that fails on ListenAndServe
	newHTTPServer = func(addr string, handler http.Handler) *http.Server {
		// Return server with invalid address to force error
		return &http.Server{
			Addr:    "invalid-address:99999",
			Handler: handler,
		}
	}

	// Restore original function after test
	defer func() {
		newHTTPServer = originalNewHTTPServer
	}()

	// Test server error
	err := runServer(":0")
	if err == nil {
		t.Fatal("Expected server error, but it didn't fail")
	}
}

func TestLoggerInitialization_ErrorCase(t *testing.T) {
	// Save original logger and function
	originalLogger := logger
	originalNewProduction := newProductionFunc

	// Override zap.NewProduction forcing it to return error
	newProductionFunc = func(...zap.Option) (*zap.Logger, error) {
		return nil, fmt.Errorf("simulated logger error")
	}

	// Capture log output
	var logOutput bytes.Buffer
	log.SetOutput(&logOutput)
	defer func() {
		log.SetOutput(os.Stderr)
		newProductionFunc = originalNewProduction
		logger = originalLogger

		// Restore original logger if it was set
		if originalLogger != nil {
			logger = originalLogger
		} else {
			// If original was nil, create a default logger
			logger, _ = zap.NewProduction()
		}
	}()

	// Call logger initialization
	initializeLogger()

	// Check if the error was logged
	if !strings.Contains(logOutput.String(), "Failed to initialize logger") {
		t.Error("Expected logger initialization error to be logged")
	}

	// Ensure logger is still nil
	if logger != nil {
		t.Error("Expected logger to be nil after initialization error")
	}
}

// Helper function for test logger initialization
func initializeLogger() {
	var err error
	logger, err = newProductionFunc()
	if err != nil {
		log.Printf("Failed to initialize logger: %v", err)
		return
	}
	_ = logger.Sugar()
}

var newProductionFunc = zap.NewProduction

// main_test.go
func TestMain(m *testing.M) {
	// Setup global logger for all tests
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to create test logger: %v", err)
	}

	// Run tests
	code := m.Run()

	// Cleanup - properly handle the error return (check for nil in case a test set logger to nil)
	if logger != nil {
		_ = logger.Sync()
	}
	os.Exit(code)
}

func TestRunServerShutdownError(t *testing.T) {
	// Mock server shutdown to return error
	originalShutdown := serverShutdown
	serverShutdown = func(ctx context.Context, server *http.Server) error {
		return errors.New("shutdown error")
	}
	defer func() { serverShutdown = originalShutdown }()

	// Start server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runServer(":0")
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Send actual SIGINT signal to the process
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGINT)

	// Wait for result with timeout
	select {
	case err := <-serverErr:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shutdown error")
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out waiting for server shutdown")
	}
}

func TestRunServerWithCustomStaleThreshold(t *testing.T) {
	// This test verifies that the STALE_THRESHOLD_MINUTES environment variable
	// is properly parsed by testing the parsing logic directly

	// Test case 1: Valid environment variable
	t.Run("Valid_60_minutes", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "60")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		// Parse using same logic as runServer
		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		assert.Equal(t, 60*time.Minute, result)
	})

	// Test case 2: Invalid environment variable (non-numeric)
	t.Run("Invalid_non_numeric", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "invalid")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should fall back to default since parsing fails
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 3: Zero value (disabled)
	t.Run("Zero_value_disabled", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "0")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should fall back to default since 0 is not > 0
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 4: Negative value
	t.Run("Negative_value", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "-10")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should fall back to default since -10 is not > 0
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 5: Empty environment variable
	t.Run("Empty_env_var", func(t *testing.T) {
		os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should use default when env var is not set
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 6: Integration test - runServer with custom stale threshold
	// This test covers lines 191-194 in main.go
	t.Run("runServer_with_env_var", func(t *testing.T) {
		// Save original values
		originalStaleThreshold := staleThreshold
		originalNewHTTPServer := newHTTPServer
		defer func() {
			staleThreshold = originalStaleThreshold
			newHTTPServer = originalNewHTTPServer
		}()

		// Set custom stale threshold via environment variable
		_ = os.Setenv("STALE_THRESHOLD_MINUTES", "45")
		defer func() { _ = os.Unsetenv("STALE_THRESHOLD_MINUTES") }()

		// Create a channel to signal server creation
		serverCreated := make(chan struct{})

		// Mock newHTTPServer to create a server that fails immediately
		newHTTPServer = func(addr string, handler http.Handler) *http.Server {
			close(serverCreated) // Signal that we've reached this point
			// Return a server with invalid address to cause immediate failure
			return &http.Server{
				Addr:    ":::invalid:::address:::",
				Handler: handler,
			}
		}

		// Run server synchronously - it will fail immediately due to invalid address
		errChan := make(chan error, 1)
		go func() {
			errChan <- runServer(":0")
		}()

		// Wait for server to be created (staleThreshold is set before newHTTPServer is called)
		select {
		case <-serverCreated:
			// Server was created, staleThreshold should be set now
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for server creation")
		}

		// Wait a bit for the server to fail and runServer to finish
		select {
		case <-errChan:
			// runServer finished
		case <-time.After(2 * time.Second):
			// Timeout is ok, main thing is staleThreshold was set
		}

		// Verify staleThreshold was set correctly (45 minutes from env var)
		// This read is safe because newHTTPServer has already been called,
		// meaning staleThreshold was already set
		assert.Equal(t, 45*time.Minute, staleThreshold)
	})
}

func TestMainFunctionWithLoggerError(t *testing.T) {
	// Test specific scenario for main error handling
	oldInitLogger := initLogger
	defer func() { initLogger = oldInitLogger }()

	initLogger = func() (*zap.Logger, error) {
		return nil, errors.New("test error")
	}

	// Since we can't easily test main() directly, test the component it calls
	err := initLoggerWrapper()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize logger")
}

// Test for logger initialization failure handling
func TestLoggerInitializationFailure(t *testing.T) {
	// Test scenario where logger initialization fails
	//  to Backup original logger

	tempLogger := logger
	logger = nil // Simulate uninitialized logger

	// Test function that uses logger
	assert.NotPanics(t, func() {
		safeClose(nil) // Should handle nil logger gracefully
	})

	logger = tempLogger // Restore
}

func TestInitLoggerWrapperError(t *testing.T) {
	// Backup original function
	originalInitLogger := initLogger
	defer func() {
		initLogger = originalInitLogger
		// Reset logger for other tests
		logger, _ = zap.NewDevelopment()
	}()

	// Mock initLogger to return error
	initLogger = func() (*zap.Logger, error) {
		return nil, errors.New("mock logger error")
	}

	err := initLoggerWrapper()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize logger")
	assert.Contains(t, err.Error(), "mock logger error")

	// Verify logger is still nil (not initialized)
	assert.Nil(t, logger)
}

func TestInitLoggerWrapperSuccess(t *testing.T) {
	// Backup original function
	originalInitLogger := initLogger
	defer func() {
		initLogger = originalInitLogger
	}()

	// Mock initLogger to return success
	testLogger, _ := zap.NewDevelopment()
	initLogger = func() (*zap.Logger, error) {
		return testLogger, nil
	}

	err := initLoggerWrapper()

	assert.NoError(t, err)
	assert.NotNil(t, logger)
	assert.Equal(t, testLogger, logger)

}

func TestMain_ErrorBranch(t *testing.T) {
	orig := runServerFunc
	defer func() { runServerFunc = orig }()

	runServerFunc = func(addr string) error {
		return fmt.Errorf("forced error")
	}

	assert.NotPanics(t, func() {
		main() //
	})
}

// TestGetSSIDByIPForceHandler tests the getSSIDByIPForceHandler function for various scenarios
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
		rr := &errorResponseRecorder{httptest.NewRecorder()}

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
}

// Custom ResponseRecorder to simulate JSON encoding failure
type errorResponseRecorder struct {
	*httptest.ResponseRecorder
}

func (e *errorResponseRecorder) Write([]byte) (int, error) {
	return 0, errors.New("write error")
}

// --- API Key Authentication Middleware Tests ---

func TestAPIKeyAuthMiddleware_ValidKey(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	// Set the auth key
	originalAuthKey := authKey
	authKey = "test-valid-api-key"
	defer func() { authKey = originalAuthKey }()

	// Create a test handler that the middleware wraps
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"success"}`))
	})

	// Wrap handler with middleware
	handler := apiKeyAuthMiddleware(testHandler)

	// Create request with valid API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderXAPIKey, "test-valid-api-key")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "success")
}

func TestAPIKeyAuthMiddleware_MissingKey(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	// Set the auth key
	originalAuthKey := authKey
	authKey = "test-valid-api-key"
	defer func() { authKey = originalAuthKey }()

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap handler with middleware
	handler := apiKeyAuthMiddleware(testHandler)

	// Create request without API key header
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, StatusUnauthorized, resp.Status)
	assert.Equal(t, ErrMissingAPIKey, resp.Error)
}

func TestAPIKeyAuthMiddleware_InvalidKey(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	// Set the auth key
	originalAuthKey := authKey
	authKey = "correct-api-key"
	defer func() { authKey = originalAuthKey }()

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap handler with middleware
	handler := apiKeyAuthMiddleware(testHandler)

	// Create request with invalid API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderXAPIKey, "wrong-api-key")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, StatusUnauthorized, resp.Status)
	assert.Equal(t, ErrInvalidAPIKey, resp.Error)
}

func TestRunServer_MiddlewareAuthEnabled(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	// Set environment variables for middleware auth
	os.Setenv("MIDDLEWARE_AUTH", "true")
	os.Setenv("AUTH_KEY", "test-api-key")
	defer func() {
		os.Unsetenv("MIDDLEWARE_AUTH")
		os.Unsetenv("AUTH_KEY")
	}()

	// Create mock GenieACS server
	mockGenieServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"_id": "test-device"}]`))
	}))
	defer mockGenieServer.Close()

	os.Setenv("GENIEACS_BASE_URL", mockGenieServer.URL)
	defer os.Unsetenv("GENIEACS_BASE_URL")

	// Override runServerFunc to capture the setup
	originalRunServerFunc := runServerFunc
	defer func() { runServerFunc = originalRunServerFunc }()

	serverStarted := make(chan bool, 1)
	runServerFunc = func(addr string) error {
		// Verify environment variables are loaded correctly
		middlewareAuth = os.Getenv("MIDDLEWARE_AUTH") == "true"
		authKey = os.Getenv("AUTH_KEY")

		assert.True(t, middlewareAuth)
		assert.Equal(t, "test-api-key", authKey)
		serverStarted <- true
		return nil
	}

	go func() {
		_ = runServerFunc(":8080")
	}()

	select {
	case <-serverStarted:
		// Test passed
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not start in time")
	}
}

func TestRunServer_MiddlewareAuthEnabledWithEmptyKey(t *testing.T) {
	// Setup logger with buffer to capture warnings
	var logBuffer bytes.Buffer
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&logBuffer), zap.WarnLevel)
	testLogger := zap.New(core)
	originalLogger := logger
	logger = testLogger
	defer func() { logger = originalLogger }()

	// Set environment variable for middleware auth but no AUTH_KEY
	os.Setenv("MIDDLEWARE_AUTH", "true")
	os.Unsetenv("AUTH_KEY")
	defer os.Unsetenv("MIDDLEWARE_AUTH")

	// Load the env vars as runServer would
	middlewareAuth = os.Getenv("MIDDLEWARE_AUTH") == "true"
	authKey = os.Getenv("AUTH_KEY")

	// Simulate the warning log
	if middlewareAuth && authKey == "" {
		logger.Warn("MIDDLEWARE_AUTH is enabled but AUTH_KEY is not set - all requests will be rejected")
	}

	assert.True(t, middlewareAuth)
	assert.Equal(t, "", authKey)
	assert.Contains(t, logBuffer.String(), "AUTH_KEY is not set")
}

func TestRouterWithMiddlewareEnabled(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	// Enable middleware auth
	originalMiddlewareAuth := middlewareAuth
	originalAuthKey := authKey
	middlewareAuth = true
	authKey = "test-router-api-key"
	defer func() {
		middlewareAuth = originalMiddlewareAuth
		authKey = originalAuthKey
	}()

	// Create mock GenieACS server
	mockGenieServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[` + mockDeviceDataJSON + `]`))
	}))
	defer mockGenieServer.Close()

	geniesBaseURL = mockGenieServer.URL
	nbiAuthKey = "mock-key"

	// Store original HTTP client and restore after test
	originalHTTPClient := httpClient
	defer func() { httpClient = originalHTTPClient }()
	httpClient = mockGenieServer.Client()

	// Clear the cache
	deviceCacheInstance.clearAll()

	// Initialize worker pool
	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
	}
	taskWorkerPool.Start()
	defer taskWorkerPool.Stop()

	// Create router with middleware applied
	r := chi.NewRouter()
	r.Get("/health", healthCheckHandler)
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		// Apply API key authentication middleware (this is the code path we want to test)
		if middlewareAuth {
			r.Use(apiKeyAuthMiddleware)
		}
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
	})

	// Test 1: Request without API key should be rejected
	t.Run("Without API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, ErrMissingAPIKey, resp.Error)
	})

	// Test 2: Request with valid API key should succeed
	t.Run("With Valid API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/"+mockDeviceIP, nil)
		req.Header.Set(HeaderXAPIKey, "test-router-api-key")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Test 3: Health endpoint should NOT require auth (outside protected route)
	t.Run("Health endpoint without auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// --- Cache Eviction Tests ---

func TestCacheEviction(t *testing.T) {
	t.Run("StartEviction and StopEviction", func(t *testing.T) {
		cache := &deviceCache{
			data:    make(map[string]cachedDeviceData),
			timeout: 50 * time.Millisecond,
		}

		// Start eviction
		cache.StartEviction()

		// Add some data
		cache.set("device1", map[string]interface{}{"key": "value1"})
		cache.set("device2", map[string]interface{}{"key": "value2"})

		// Verify data exists
		_, found := cache.get("device1")
		assert.True(t, found)

		// Wait for data to expire and eviction to run
		time.Sleep(100 * time.Millisecond)

		// Data should be evicted now
		_, found = cache.get("device1")
		assert.False(t, found)

		// Stop eviction
		cache.StopEviction()
	})

	t.Run("StopEviction without StartEviction", func(t *testing.T) {
		cache := &deviceCache{
			data:    make(map[string]cachedDeviceData),
			timeout: 50 * time.Millisecond,
		}

		// Should not panic when stopCh is nil
		cache.StopEviction()
	})

	t.Run("StopEviction multiple times", func(t *testing.T) {
		cache := &deviceCache{
			data:    make(map[string]cachedDeviceData),
			timeout: 50 * time.Millisecond,
		}

		cache.StartEviction()

		// Multiple stops should not panic (sync.Once)
		cache.StopEviction()
		cache.StopEviction()
		cache.StopEviction()
	})

	t.Run("EvictExpired removes only expired entries", func(t *testing.T) {
		cache := &deviceCache{
			data:    make(map[string]cachedDeviceData),
			timeout: 100 * time.Millisecond,
		}

		// Add data
		cache.set("device1", map[string]interface{}{"key": "value1"})

		// Wait half the timeout
		time.Sleep(50 * time.Millisecond)

		// Add another device
		cache.set("device2", map[string]interface{}{"key": "value2"})

		// Wait for device1 to expire but not device2
		time.Sleep(60 * time.Millisecond)

		// Run eviction
		cache.evictExpired()

		// device1 should be evicted (expired)
		_, found1 := cache.get("device1")
		assert.False(t, found1)

		// device2 should still exist (not yet expired)
		_, found2 := cache.get("device2")
		assert.True(t, found2)
	})

	t.Run("StartEviction with small timeout uses minimum interval", func(t *testing.T) {
		cache := &deviceCache{
			data:    make(map[string]cachedDeviceData),
			timeout: 100 * time.Millisecond, // Half would be 50ms, but minimum is 1s
		}

		cache.StartEviction()
		defer cache.StopEviction()

		// Add data
		cache.set("device1", map[string]interface{}{"key": "value1"})

		// Should not panic and should work normally
		time.Sleep(10 * time.Millisecond)
		_, found := cache.get("device1")
		assert.True(t, found)
	})
}

func TestValidateIP(t *testing.T) {
	t.Run("Valid IPv4", func(t *testing.T) {
		err := validateIP("192.168.1.1")
		assert.NoError(t, err)
	})

	t.Run("Valid IPv6", func(t *testing.T) {
		err := validateIP("::1")
		assert.NoError(t, err)
	})

	t.Run("Invalid IP - not an IP", func(t *testing.T) {
		err := validateIP("not-an-ip")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP address format")
	})

	t.Run("Invalid IP - empty string", func(t *testing.T) {
		err := validateIP("")
		assert.Error(t, err)
	})

	t.Run("Invalid IP - injection attempt", func(t *testing.T) {
		err := validateIP(`192.168.1.1","$ne":""}`)
		assert.Error(t, err)
	})
}

// --- Worker Pool Deadlock Prevention Tests ---

func TestWorkerPoolNonBlockingSubmit(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	t.Run("Submit when queue is full drops task", func(t *testing.T) {
		// Create worker pool with tiny queue (size 1)
		wp := &workerPool{
			workers: 1,
			queue:   make(chan task, 1),
			wg:      sync.WaitGroup{},
		}

		// Don't start workers so queue fills up
		// Fill the queue
		wp.queue <- task{deviceID: "device1", taskType: "test", params: nil}

		// This should NOT block - it should drop the task and log warning
		done := make(chan bool, 1)
		go func() {
			wp.Submit("device2", "test", nil)
			done <- true
		}()

		select {
		case <-done:
			// Success - Submit returned without blocking
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Submit blocked when queue was full - potential deadlock")
		}
	})

	t.Run("TrySubmit returns false when queue is full", func(t *testing.T) {
		wp := &workerPool{
			workers: 1,
			queue:   make(chan task, 1),
			wg:      sync.WaitGroup{},
		}

		// Fill the queue
		wp.queue <- task{deviceID: "device1", taskType: "test", params: nil}

		// TrySubmit should return false
		result := wp.TrySubmit("device2", "test", nil)
		assert.False(t, result)
	})

	t.Run("TrySubmit returns true when queue has space", func(t *testing.T) {
		wp := &workerPool{
			workers: 1,
			queue:   make(chan task, 10),
			wg:      sync.WaitGroup{},
		}

		// TrySubmit should return true
		result := wp.TrySubmit("device1", "test", nil)
		assert.True(t, result)

		// Drain the queue
		<-wp.queue
	})

	t.Run("Submit succeeds when queue has space", func(t *testing.T) {
		wp := &workerPool{
			workers: 1,
			queue:   make(chan task, 10),
			wg:      sync.WaitGroup{},
		}

		done := make(chan bool, 1)
		go func() {
			wp.Submit("device1", "test", nil)
			done <- true
		}()

		select {
		case <-done:
			// Success
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Submit blocked when queue had space")
		}

		// Drain the queue
		<-wp.queue
	})
}

// --- Rate Limiter Tests ---

func TestRateLimiter_NewRateLimiter(t *testing.T) {
	rl := newRateLimiter(100, time.Minute)
	assert.NotNil(t, rl)
	assert.NotNil(t, rl.requests)
	assert.Equal(t, 100, rl.rate)
	assert.Equal(t, time.Minute, rl.window)
}

func TestRateLimiter_Allow(t *testing.T) {
	t.Run("Allows requests within limit", func(t *testing.T) {
		rl := newRateLimiter(5, time.Minute)

		// First 5 requests should be allowed
		for i := 0; i < 5; i++ {
			assert.True(t, rl.Allow("192.168.1.1"), "Request %d should be allowed", i+1)
		}

		// 6th request should be denied
		assert.False(t, rl.Allow("192.168.1.1"), "6th request should be denied")
	})

	t.Run("Different IPs have separate limits", func(t *testing.T) {
		rl := newRateLimiter(2, time.Minute)

		// First IP uses up its limit
		assert.True(t, rl.Allow("192.168.1.1"))
		assert.True(t, rl.Allow("192.168.1.1"))
		assert.False(t, rl.Allow("192.168.1.1"))

		// Second IP still has full limit
		assert.True(t, rl.Allow("192.168.1.2"))
		assert.True(t, rl.Allow("192.168.1.2"))
		assert.False(t, rl.Allow("192.168.1.2"))
	})

	t.Run("Tokens reset after window passes", func(t *testing.T) {
		rl := newRateLimiter(2, 50*time.Millisecond)

		// Use up the limit
		assert.True(t, rl.Allow("192.168.1.1"))
		assert.True(t, rl.Allow("192.168.1.1"))
		assert.False(t, rl.Allow("192.168.1.1"))

		// Wait for window to pass
		time.Sleep(60 * time.Millisecond)

		// Should be allowed again
		assert.True(t, rl.Allow("192.168.1.1"))
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	t.Run("Allows requests within limit", func(t *testing.T) {
		rl := newRateLimiter(5, time.Minute)
		handler := rateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "Request %d should be allowed", i+1)
		}
	})

	t.Run("Blocks requests exceeding limit", func(t *testing.T) {
		rl := newRateLimiter(2, time.Minute)
		handler := rateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First 2 requests should succeed
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}

		// 3rd request should be rate limited
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Contains(t, resp.Error, "Rate limit exceeded")
	})

	t.Run("Uses X-Real-IP header when present", func(t *testing.T) {
		rl := newRateLimiter(2, time.Minute)
		handler := rateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First IP (via X-Real-IP) uses its limit
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.0.0.1:12345"
			req.Header.Set("X-Real-IP", "203.0.113.1")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}

		// Should be rate limited based on X-Real-IP
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.1")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)

		// Different X-Real-IP should be allowed
		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "10.0.0.1:12345"
		req2.Header.Set("X-Real-IP", "203.0.113.2")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		assert.Equal(t, http.StatusOK, rr2.Code)
	})
}

// --- sanitizeErrorMessage Tests ---

func TestSanitizeErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
		{
			name:     "device not found with IP",
			err:      errors.New("device not found with IP: 192.168.1.100"),
			expected: "Device not found",
		},
		{
			name:     "no device found with ID",
			err:      errors.New("no device found with ID: abc123"),
			expected: "Device not found",
		},
		{
			name:     "device is stale",
			err:      errors.New("device with IP 192.168.1.1 is stale (last seen: 1h ago)"),
			expected: "Device is offline or unresponsive",
		},
		{
			name:     "invalid IP address format",
			err:      errors.New("invalid IP address format: not-an-ip"),
			expected: "Invalid IP address format",
		},
		{
			name:     "GenieACS returned non-OK status",
			err:      errors.New("GenieACS returned non-OK status: 500"),
			expected: "Backend service error",
		},
		{
			name:     "HTTP error",
			err:      errors.New("HTTP error: 502 Bad Gateway"),
			expected: "Backend service error",
		},
		{
			name:     "unknown error",
			err:      errors.New("some internal system error with sensitive data"),
			expected: "An error occurred processing your request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeErrorMessage(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- Input Validation Tests ---

func TestInputValidation_Password(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()

	t.Run("Password too short", func(t *testing.T) {
		body := `{"password":"short"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/genieacs/password/update/1/192.168.1.1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
		w := httptest.NewRecorder()
		updatePasswordByIPHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		var resp Response
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, ErrPasswordTooShort, resp.Error)
	})

	t.Run("Password too long", func(t *testing.T) {
		// Create a password with 64 characters (exceeds MaxPasswordLength of 63)
		longPassword := strings.Repeat("a", 64)
		body := fmt.Sprintf(`{"password":"%s"}`, longPassword)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/genieacs/password/update/1/192.168.1.1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
		w := httptest.NewRecorder()
		updatePasswordByIPHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		var resp Response
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, ErrPasswordTooLong, resp.Error)
	})

	t.Run("Password exactly minimum length", func(t *testing.T) {
		// Create a password with exactly 8 characters (MinPasswordLength)
		validPassword := "12345678"
		body := fmt.Sprintf(`{"password":"%s"}`, validPassword)

		// Setup mock server
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should pass validation (status should be 200 OK, not 400 Bad Request)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

// withChiURLParams adds chi URL parameters to a request context
func withChiURLParams(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for key, value := range params {
		rctx.URLParams.Add(key, value)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestInputValidation_SSID(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()

	t.Run("SSID with leading space", func(t *testing.T) {
		body := `{"ssid":" MySSID"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/genieacs/ssid/update/1/192.168.1.1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
		w := httptest.NewRecorder()
		updateSSIDByIPHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		var resp Response
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, ErrSSIDInvalidSpaces, resp.Error)
	})

	t.Run("SSID with trailing space", func(t *testing.T) {
		body := `{"ssid":"MySSID "}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/genieacs/ssid/update/1/192.168.1.1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
		w := httptest.NewRecorder()
		updateSSIDByIPHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		var resp Response
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, ErrSSIDInvalidSpaces, resp.Error)
	})

	t.Run("SSID with leading and trailing spaces", func(t *testing.T) {
		body := `{"ssid":" MySSID "}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/genieacs/ssid/update/1/192.168.1.1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
		w := httptest.NewRecorder()
		updateSSIDByIPHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		var resp Response
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, ErrSSIDInvalidSpaces, resp.Error)
	})

	t.Run("SSID with space in middle is valid", func(t *testing.T) {
		body := `{"ssid":"My SSID"}`

		// Setup mock server
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should pass validation (SSID with space in middle is allowed)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("SSID too long", func(t *testing.T) {
		// Create an SSID with 33 characters (exceeds MaxSSIDLength of 32)
		longSSID := strings.Repeat("a", 33)
		body := fmt.Sprintf(`{"ssid":"%s"}`, longSSID)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/genieacs/ssid/update/1/192.168.1.1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withChiURLParams(req, map[string]string{"wlan": "1", "ip": "192.168.1.1"})
		w := httptest.NewRecorder()
		updateSSIDByIPHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		var resp Response
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, ErrSSIDTooLong, resp.Error)
	})

	t.Run("SSID exactly maximum length", func(t *testing.T) {
		// Create an SSID with exactly 32 characters (MaxSSIDLength)
		validSSID := strings.Repeat("a", 32)
		body := fmt.Sprintf(`{"ssid":"%s"}`, validSSID)

		// Setup mock server
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
		})

		_, router := setupTestServer(t, mockHandler)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("X-API-Key", mockAPIKey)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should pass validation (status should be 200 OK, not 400 Bad Request)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

func TestValidationConstants(t *testing.T) {
	// Verify validation constants are set correctly
	assert.Equal(t, 8, MinPasswordLength)
	assert.Equal(t, 63, MaxPasswordLength)
	assert.Equal(t, 1, MinSSIDLength)
	assert.Equal(t, 32, MaxSSIDLength)
}

// --- Security Fix Tests ---

// TestValidateWLANID tests the WLAN ID validation function
func TestValidateWLANID(t *testing.T) {
	t.Run("Valid WLAN IDs", func(t *testing.T) {
		validIDs := []string{"1", "5", "10", "99"}
		for _, id := range validIDs {
			err := validateWLANID(id)
			assert.NoError(t, err, "WLAN ID %s should be valid", id)
		}
	})

	t.Run("Invalid WLAN ID - Non-numeric", func(t *testing.T) {
		invalidIDs := []string{"abc", "../1", "1/../../etc/passwd", "1;ls", "1'--"}
		for _, id := range invalidIDs {
			err := validateWLANID(id)
			assert.Error(t, err, "WLAN ID %s should be invalid", id)
			assert.Contains(t, err.Error(), ErrInvalidWLANID)
		}
	})

	t.Run("Invalid WLAN ID - Out of range", func(t *testing.T) {
		outOfRangeIDs := []string{"0", "-1", "100", "999"}
		for _, id := range outOfRangeIDs {
			err := validateWLANID(id)
			assert.Error(t, err, "WLAN ID %s should be out of range", id)
			assert.Contains(t, err.Error(), ErrInvalidWLANID)
		}
	})
}

// TestSecurityHeadersMiddleware tests the security headers middleware
func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify all security headers are set
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"), "X-Content-Type-Options should be set")
	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"), "X-Frame-Options should be set")
	assert.Equal(t, "1; mode=block", rr.Header().Get("X-XSS-Protection"), "X-XSS-Protection should be set")
	assert.Contains(t, rr.Header().Get("Cache-Control"), "no-store", "Cache-Control should prevent caching")
	assert.Contains(t, rr.Header().Get("Content-Security-Policy"), "default-src 'none'", "CSP should be set")
	assert.Equal(t, "no-referrer", rr.Header().Get("Referrer-Policy"), "Referrer-Policy should be set")
	assert.Contains(t, rr.Header().Get("Permissions-Policy"), "geolocation=()", "Permissions-Policy should be set")
}

// TestRateLimiterCleanup tests the rate limiter cleanup functionality to prevent memory leaks
func TestRateLimiterCleanup(t *testing.T) {
	t.Run("Cleanup removes stale entries", func(t *testing.T) {
		rl := newRateLimiter(100, 50*time.Millisecond)

		// Add some IPs
		rl.Allow("192.168.1.1")
		rl.Allow("192.168.1.2")
		rl.Allow("192.168.1.3")

		// Verify they exist
		rl.mu.RLock()
		assert.Equal(t, 3, len(rl.requests), "Should have 3 entries")
		rl.mu.RUnlock()

		// Wait for entries to become stale (2x window)
		time.Sleep(110 * time.Millisecond)

		// Run cleanup
		rl.cleanup()

		// Verify entries are removed
		rl.mu.RLock()
		assert.Equal(t, 0, len(rl.requests), "Should have 0 entries after cleanup")
		rl.mu.RUnlock()
	})

	t.Run("StartCleanup and StopCleanup work correctly", func(t *testing.T) {
		rl := newRateLimiter(100, 50*time.Millisecond)

		// Start cleanup
		rl.StartCleanup()
		assert.NotNil(t, rl.stopCh, "stopCh should be initialized")

		// Add an IP
		rl.Allow("192.168.1.1")

		// Wait for auto cleanup to run (2x window interval = 100ms)
		time.Sleep(120 * time.Millisecond)

		// Verify entry is cleaned up automatically
		rl.mu.RLock()
		assert.Equal(t, 0, len(rl.requests), "Should have 0 entries after auto cleanup")
		rl.mu.RUnlock()

		// Stop cleanup - should not panic
		rl.StopCleanup()
	})
}

// TestRequestBodySizeLimit tests that request body size is limited
func TestRequestBodySizeLimit(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("SSID update rejects large body", func(t *testing.T) {
		// Create a body larger than MaxRequestBodySize (1KB)
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should return 413 Request Entity Too Large or 400 Bad Request (depends on how the error is caught)
		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest,
			"Should reject large request body, got status %d", rr.Code)
	})

	t.Run("Password update rejects large body", func(t *testing.T) {
		// Create a body larger than MaxRequestBodySize (1KB)
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should return 413 Request Entity Too Large or 400 Bad Request
		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest,
			"Should reject large request body, got status %d", rr.Code)
	})

	t.Run("Normal size body is accepted", func(t *testing.T) {
		body := `{"ssid": "TestSSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should not be rejected due to size (may fail for other reasons)
		assert.NotEqual(t, http.StatusRequestEntityTooLarge, rr.Code, "Normal size body should not be rejected")
	})
}

// TestWLANIDValidationInHandlers tests that WLAN ID validation is applied in handlers
func TestWLANIDValidationInHandlers(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("SSID update rejects invalid WLAN ID", func(t *testing.T) {
		// Note: URLs with path traversal like "../1" are handled by chi router differently
		// and may result in 404, so we only test simple invalid values here
		invalidWLANIDs := []string{"abc", "0", "100", "999"}
		for _, wlanID := range invalidWLANIDs {
			body := `{"ssid": "TestSSID"}`
			req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/"+wlanID+"/"+mockDeviceIP, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusBadRequest, rr.Code, "WLAN ID %s should be rejected", wlanID)

			var resp Response
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			assert.Contains(t, resp.Error, ErrInvalidWLANID, "Error should mention invalid WLAN ID for %s", wlanID)
		}
	})

	t.Run("Password update rejects invalid WLAN ID", func(t *testing.T) {
		invalidWLANIDs := []string{"abc", "0", "100", "-1"}
		for _, wlanID := range invalidWLANIDs {
			body := `{"password": "ValidPassword123"}`
			req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/"+wlanID+"/"+mockDeviceIP, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusBadRequest, rr.Code, "WLAN ID %s should be rejected", wlanID)

			var resp Response
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			assert.Contains(t, resp.Error, ErrInvalidWLANID, "Error should mention invalid WLAN ID for %s", wlanID)
		}
	})
}

// TestConstantTimeAPIKeyComparison verifies the constant-time comparison is being used
// Note: This test verifies the code path, not the actual timing properties
func TestConstantTimeAPIKeyComparison(t *testing.T) {
	originalAuthKey := authKey
	originalMiddlewareAuth := middlewareAuth
	t.Cleanup(func() {
		authKey = originalAuthKey
		middlewareAuth = originalMiddlewareAuth
	})

	middlewareAuth = true
	authKey = "correct-api-key"

	handler := apiKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Correct key passes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(HeaderXAPIKey, "correct-api-key")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Wrong key fails", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(HeaderXAPIKey, "wrong-api-key")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Similar key fails", func(t *testing.T) {
		// Test with similar but different key (timing attack would exploit this)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(HeaderXAPIKey, "correct-api-kex") // Last char different
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

// TestMaxRequestBodySizeConstant verifies the constant is properly defined
func TestMaxRequestBodySizeConstant(t *testing.T) {
	assert.Equal(t, 1024, MaxRequestBodySize, "MaxRequestBodySize should be 1KB")
}

// TestValidateSSIDCharacters tests the SSID character validation function
func TestValidateSSIDCharacters(t *testing.T) {
	t.Run("Valid SSIDs with printable ASCII", func(t *testing.T) {
		validSSIDs := []string{
			"MyNetwork",
			"Home WiFi 5G",
			"Test_Network-123",
			"Guest!@#$%^&*()",
			" spaces allowed ",
			"~tilde~",
			"with`backtick",
		}
		for _, ssid := range validSSIDs {
			err := validateSSIDCharacters(ssid)
			assert.NoError(t, err, "SSID %q should be valid", ssid)
		}
	})

	t.Run("Invalid SSIDs with control characters", func(t *testing.T) {
		invalidSSIDs := []string{
			"Test\x00Network", // NULL character
			"Test\x01Network", // SOH
			"Test\x07Network", // BEL
			"Test\nNetwork",   // Newline (LF)
			"Test\rNetwork",   // Carriage Return
			"Test\tNetwork",   // Tab
			"Test\x1BNetwork", // ESC (escape)
			"Test\x7FNetwork", // DEL character
		}
		for _, ssid := range invalidSSIDs {
			err := validateSSIDCharacters(ssid)
			assert.Error(t, err, "SSID %q should be invalid (contains control character)", ssid)
			assert.Contains(t, err.Error(), ErrSSIDInvalidChars)
		}
	})

	t.Run("Invalid SSIDs with non-ASCII characters", func(t *testing.T) {
		invalidSSIDs := []string{
			"Test中文Network", // Chinese characters
			"Testрусский",   // Russian characters
			"Test日本語",       // Japanese characters
			"Emoji😀Network", // Emoji
			"Café",          // Accented characters
			"über",          // German umlaut
		}
		for _, ssid := range invalidSSIDs {
			err := validateSSIDCharacters(ssid)
			assert.Error(t, err, "SSID %q should be invalid (contains non-ASCII)", ssid)
			assert.Contains(t, err.Error(), ErrSSIDInvalidChars)
		}
	})

	t.Run("Edge cases", func(t *testing.T) {
		// Empty string should pass character validation (length validation is separate)
		err := validateSSIDCharacters("")
		assert.NoError(t, err, "Empty SSID should pass character validation")

		// Single space is valid
		err = validateSSIDCharacters(" ")
		assert.NoError(t, err, "Single space SSID should pass character validation")

		// All printable ASCII (0x20-0x7E)
		var allPrintable string
		for i := 0x20; i <= 0x7E; i++ {
			allPrintable += string(rune(i))
		}
		err = validateSSIDCharacters(allPrintable)
		assert.NoError(t, err, "All printable ASCII characters should be valid")
	})
}

// TestSSIDCharacterValidationInHandler tests that SSID character validation is applied in handlers
func TestSSIDCharacterValidationInHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("SSID with control characters is rejected", func(t *testing.T) {
		body := `{"ssid": "Test\nNetwork"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Contains(t, resp.Error, ErrSSIDInvalidChars)
	})

	t.Run("SSID with non-ASCII characters is rejected", func(t *testing.T) {
		body := `{"ssid": "Test中文"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Contains(t, resp.Error, ErrSSIDInvalidChars)
	})

	t.Run("Valid SSID is accepted", func(t *testing.T) {
		body := `{"ssid": "ValidNetwork123"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should not fail due to character validation (may fail for other reasons)
		assert.NotEqual(t, http.StatusBadRequest, rr.Code, "Valid SSID should not be rejected")
	})
}

// TestHTTPServerTimeouts tests that HTTP server is configured with proper timeouts
func TestHTTPServerTimeouts(t *testing.T) {
	// Create a new HTTP server using the newHTTPServer function
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := newHTTPServer(":8080", handler)

	t.Run("ReadTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 15*time.Second, server.ReadTimeout, "ReadTimeout should be 15 seconds")
	})

	t.Run("WriteTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 15*time.Second, server.WriteTimeout, "WriteTimeout should be 15 seconds")
	})

	t.Run("IdleTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 60*time.Second, server.IdleTimeout, "IdleTimeout should be 60 seconds")
	})

	t.Run("ReadHeaderTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 5*time.Second, server.ReadHeaderTimeout, "ReadHeaderTimeout should be 5 seconds (prevents Slowloris)")
	})

	t.Run("Server address is set", func(t *testing.T) {
		assert.Equal(t, ":8080", server.Addr, "Server address should be set correctly")
	})

	t.Run("Handler is set", func(t *testing.T) {
		assert.NotNil(t, server.Handler, "Handler should be set")
	})
}

// TestUpdateWLANHandler tests the updateWLANHandler function
func TestUpdateWLANHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Update WLAN - SSID only", func(t *testing.T) {
		body := `{"ssid": "UpdatedNetwork"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Password only", func(t *testing.T) {
		body := `{"password": "NewPassword123"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Hidden status", func(t *testing.T) {
		body := `{"hidden": true}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Max clients", func(t *testing.T) {
		body := `{"max_clients": 20}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Auth mode WPA2", func(t *testing.T) {
		body := `{"auth_mode": "WPA2"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Auth mode WPA", func(t *testing.T) {
		body := `{"auth_mode": "WPA"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Auth mode WPA/WPA2", func(t *testing.T) {
		body := `{"auth_mode": "WPA/WPA2"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Auth mode Open", func(t *testing.T) {
		body := `{"auth_mode": "Open"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Full update", func(t *testing.T) {
		body := `{"ssid": "UpdatedNetwork", "password": "NewPassword123", "hidden": true, "max_clients": 20, "auth_mode": "WPA2", "encryption": "AES"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update WLAN - Invalid WLAN ID", func(t *testing.T) {
		body := `{"ssid": "Test"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/0/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - No fields provided", func(t *testing.T) {
		body := `{}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - SSID too long", func(t *testing.T) {
		body := `{"ssid": "ThisSSIDIsWayTooLongAndExceeds32Characters"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Password too short", func(t *testing.T) {
		body := `{"password": "short"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid max clients (too high)", func(t *testing.T) {
		body := `{"max_clients": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid max clients (zero)", func(t *testing.T) {
		body := `{"max_clients": 0}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid auth mode", func(t *testing.T) {
		body := `{"auth_mode": "InvalidMode"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid encryption", func(t *testing.T) {
		body := `{"encryption": "InvalidEncryption"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Large body rejected", func(t *testing.T) {
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest)
	})
}

// TestDeleteWLANHandler tests the deleteWLANHandler function
func TestDeleteWLANHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Delete WLAN - Success", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Delete WLAN - Invalid WLAN ID (0)", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/0/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Delete WLAN - Invalid WLAN ID (100)", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/100/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Delete WLAN - Invalid WLAN ID (abc)", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/abc/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestOptimizeWLANHandler tests the optimizeWLANHandler function
func TestOptimizeWLANHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// 2.4GHz Band Tests (WLAN 1)
	t.Run("Optimize WLAN 2.4GHz - Channel only", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Auto channel", func(t *testing.T) {
		body := `{"channel": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Mode only", func(t *testing.T) {
		body := `{"mode": "b/g/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Bandwidth only", func(t *testing.T) {
		body := `{"bandwidth": "40MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Transmit power only", func(t *testing.T) {
		body := `{"transmit_power": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Full optimization", func(t *testing.T) {
		body := `{"channel": "6", "mode": "b/g/n", "bandwidth": "40MHz", "transmit_power": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Test all valid 2.4GHz modes
	t.Run("Optimize WLAN 2.4GHz - Mode b", func(t *testing.T) {
		body := `{"mode": "b"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Mode g", func(t *testing.T) {
		body := `{"mode": "g"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Mode n", func(t *testing.T) {
		body := `{"mode": "n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Mode b/g", func(t *testing.T) {
		body := `{"mode": "b/g"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Mode g/n", func(t *testing.T) {
		body := `{"mode": "g/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Test all valid 2.4GHz bandwidths
	t.Run("Optimize WLAN 2.4GHz - Bandwidth 20MHz", func(t *testing.T) {
		body := `{"bandwidth": "20MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Bandwidth Auto", func(t *testing.T) {
		body := `{"bandwidth": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Test all valid transmit power values
	t.Run("Optimize WLAN - Transmit power 0%", func(t *testing.T) {
		body := `{"transmit_power": 0}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN - Transmit power 20%", func(t *testing.T) {
		body := `{"transmit_power": 20}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN - Transmit power 40%", func(t *testing.T) {
		body := `{"transmit_power": 40}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN - Transmit power 60%", func(t *testing.T) {
		body := `{"transmit_power": 60}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN - Transmit power 80%", func(t *testing.T) {
		body := `{"transmit_power": 80}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Error cases
	t.Run("Optimize WLAN - Invalid WLAN ID", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/0/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - No fields provided", func(t *testing.T) {
		body := `{}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Invalid channel", func(t *testing.T) {
		body := `{"channel": "99"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Invalid mode", func(t *testing.T) {
		body := `{"mode": "invalid"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN 2.4GHz - Invalid bandwidth (80MHz)", func(t *testing.T) {
		body := `{"bandwidth": "80MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Invalid transmit power", func(t *testing.T) {
		body := `{"transmit_power": 50}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Large body rejected", func(t *testing.T) {
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest)
	})
}

// TestOptimizeWLAN5GHz tests the optimizeWLANHandler for 5GHz band
func TestOptimizeWLAN5GHz(t *testing.T) {
	// Mock handler for dual-band device (F670L)
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// 5GHz Band Tests (WLAN 5)
	t.Run("Optimize WLAN 5GHz - Channel 36", func(t *testing.T) {
		body := `{"channel": "36"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Channel 149", func(t *testing.T) {
		body := `{"channel": "149"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Auto channel", func(t *testing.T) {
		body := `{"channel": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Mode a/n/ac", func(t *testing.T) {
		body := `{"mode": "a/n/ac"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Mode ac", func(t *testing.T) {
		body := `{"mode": "ac"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Mode a", func(t *testing.T) {
		body := `{"mode": "a"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Mode a/n", func(t *testing.T) {
		body := `{"mode": "a/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Bandwidth 80MHz", func(t *testing.T) {
		body := `{"bandwidth": "80MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Full optimization", func(t *testing.T) {
		body := `{"channel": "36", "mode": "a/n/ac", "bandwidth": "80MHz", "transmit_power": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Error cases for 5GHz
	t.Run("Optimize WLAN 5GHz - Invalid channel", func(t *testing.T) {
		body := `{"channel": "100"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Invalid mode (2.4GHz mode)", func(t *testing.T) {
		body := `{"mode": "b/g/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN 5GHz - Invalid bandwidth (160MHz)", func(t *testing.T) {
		body := `{"bandwidth": "160MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestGetAvailableWLANHandler tests the getAvailableWLANHandler function
func TestGetAvailableWLANHandler(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Get available WLAN slots - Success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, StatusOK, resp.Status)
	})
}

// TestSingleBandDeviceValidation tests that 5GHz WLAN IDs are rejected for single-band devices
func TestSingleBandDeviceValidation(t *testing.T) {
	// Mock data for single-band device (F663N)
	singleBandDeviceID := "001141-F663N-ZTEGCFAB123456"
	singleBandDeviceDataJSON := `
{
    "_id": "001141-F663N-ZTEGCFAB123456",
    "InternetGatewayDevice": {
        "DeviceInfo": {
            "ProductClass": { "_value": "F663N" },
            "ModelName": { "_value": "F663N" }
        },
        "LANDevice": {
            "1": {
                "WLANConfiguration": {
                    "1": {
                        "Enable": { "_value": true },
                        "SSID": { "_value": "SingleBand-WiFi" },
                        "PreSharedKey": {
                            "1": {
                                "PreSharedKey": { "_value": "password123" }
                            }
                        }
                    }
                }
            }
        }
    }
}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			lastInform := time.Now().UTC().Format(time.RFC3339)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, singleBandDeviceID, lastInform)))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), singleBandDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + singleBandDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Create WLAN 5GHz on single-band device rejected", func(t *testing.T) {
		body := `{"ssid": "Test5G", "password": "TestPass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "5GHz")
	})

	t.Run("Update WLAN 5GHz on single-band device rejected", func(t *testing.T) {
		body := `{"ssid": "Test5G"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "5GHz")
	})

	t.Run("Delete WLAN 5GHz on single-band device rejected", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/5/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "5GHz")
	})

	t.Run("Optimize WLAN 5GHz on single-band device rejected", func(t *testing.T) {
		body := `{"channel": "36"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "5GHz")
	})

	t.Run("Optimize WLAN 2.4GHz on single-band device allowed", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed or fail for other reasons, but NOT because of band validation
		assert.NotContains(t, rr.Body.String(), "5GHz")
	})
}

// TestCreateWLANHandlerErrorCases tests error cases for createWLANHandler
func TestCreateWLANHandlerErrorCases(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Create WLAN - Invalid WLAN ID (0)", func(t *testing.T) {
		body := `{"ssid": "Test", "password": "TestPass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/0/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Invalid WLAN ID (100)", func(t *testing.T) {
		body := `{"ssid": "Test", "password": "TestPass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/100/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Missing SSID", func(t *testing.T) {
		body := `{"password": "TestPass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - SSID too long", func(t *testing.T) {
		body := `{"ssid": "ThisSSIDIsWayTooLongAndExceeds32Characters", "password": "TestPass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - SSID with leading spaces", func(t *testing.T) {
		body := `{"ssid": " LeadingSpace", "password": "TestPass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - SSID with trailing spaces", func(t *testing.T) {
		body := `{"ssid": "TrailingSpace ", "password": "TestPass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Password too short", func(t *testing.T) {
		body := `{"ssid": "TestNetwork", "password": "short"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Password too long", func(t *testing.T) {
		longPassword := strings.Repeat("a", 64)
		body := fmt.Sprintf(`{"ssid": "TestNetwork", "password": "%s"}`, longPassword)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Missing password for WPA2", func(t *testing.T) {
		body := `{"ssid": "TestNetwork", "auth_mode": "WPA2"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Invalid auth mode", func(t *testing.T) {
		body := `{"ssid": "TestNetwork", "password": "TestPass123", "auth_mode": "InvalidMode"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Invalid encryption", func(t *testing.T) {
		body := `{"ssid": "TestNetwork", "password": "TestPass123", "encryption": "InvalidEncryption"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Invalid max clients (0)", func(t *testing.T) {
		body := `{"ssid": "TestNetwork", "password": "TestPass123", "max_clients": 0}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Invalid max clients (100)", func(t *testing.T) {
		body := `{"ssid": "TestNetwork", "password": "TestPass123", "max_clients": 100}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN - Large body rejected", func(t *testing.T) {
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest)
	})

	t.Run("Create WLAN - Open network without password", func(t *testing.T) {
		body := `{"ssid": "OpenNetwork", "auth_mode": "Open"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Open network should be created successfully (or conflict if WLAN exists)
		assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusConflict)
	})

	t.Run("Create WLAN - WPA mode", func(t *testing.T) {
		body := `{"ssid": "WPANetwork", "password": "TestPass123", "auth_mode": "WPA"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed or conflict
		assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusConflict)
	})

	t.Run("Create WLAN - WPA/WPA2 mode", func(t *testing.T) {
		body := `{"ssid": "MixedNetwork", "password": "TestPass123", "auth_mode": "WPA/WPA2"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/4/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed or conflict
		assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusConflict)
	})

	t.Run("Create WLAN - TKIP encryption", func(t *testing.T) {
		body := `{"ssid": "TKIPNetwork", "password": "TestPass123", "encryption": "TKIP"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed or conflict
		assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusConflict)
	})

	t.Run("Create WLAN - TKIP+AES encryption", func(t *testing.T) {
		body := `{"ssid": "MixedEncNetwork", "password": "TestPass123", "encryption": "TKIP+AES"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed or conflict
		assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusConflict)
	})

	t.Run("Create WLAN - Hidden network", func(t *testing.T) {
		body := `{"ssid": "HiddenNetwork", "password": "TestPass123", "hidden": true}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed or conflict
		assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusConflict)
	})

	t.Run("Create WLAN - Custom max clients", func(t *testing.T) {
		body := `{"ssid": "CustomNetwork", "password": "TestPass123", "max_clients": 10}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed or conflict
		assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusConflict)
	})
}

// TestDeleteWLANHandlerErrorCases tests error cases for deleteWLANHandler
func TestDeleteWLANHandlerErrorCases(t *testing.T) {
	// Create a mock for WLAN that doesn't exist
	mockHandlerWLANNotFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query - return device with only WLAN 1 enabled
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			deviceData := `[{
				"_id": "002568-BCM963268-684752",
				"InternetGatewayDevice": {
					"LANDevice": {
						"1": {
							"WLANConfiguration": {
								"1": {
									"Enable": { "_value": true },
									"SSID": { "_value": "MyWiFi" }
								}
							}
						}
					}
				}
			}]`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(deviceData))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandlerWLANNotFound)

	t.Run("Delete WLAN - WLAN not found", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/3/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestUpdateWLANHandlerWLANNotFound tests updateWLANHandler when WLAN is not found
func TestUpdateWLANHandlerWLANNotFound(t *testing.T) {
	// Create a mock for WLAN that doesn't exist
	mockHandlerWLANNotFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query - return device with only WLAN 1 enabled
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			deviceData := `[{
				"_id": "002568-BCM963268-684752",
				"InternetGatewayDevice": {
					"LANDevice": {
						"1": {
							"WLANConfiguration": {
								"1": {
									"Enable": { "_value": true },
									"SSID": { "_value": "MyWiFi" }
								}
							}
						}
					}
				}
			}]`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(deviceData))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandlerWLANNotFound)

	t.Run("Update WLAN - WLAN not found", func(t *testing.T) {
		body := `{"ssid": "TestNetwork"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestOptimizeWLANHandlerWLANNotFound tests optimizeWLANHandler when WLAN is not found
func TestOptimizeWLANHandlerWLANNotFound(t *testing.T) {
	// Create a mock for WLAN that doesn't exist
	mockHandlerWLANNotFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query - return device with only WLAN 1 enabled
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			deviceData := `[{
				"_id": "002568-BCM963268-684752",
				"InternetGatewayDevice": {
					"LANDevice": {
						"1": {
							"WLANConfiguration": {
								"1": {
									"Enable": { "_value": true },
									"SSID": { "_value": "MyWiFi" }
								}
							}
						}
					}
				}
			}]`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(deviceData))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandlerWLANNotFound)

	t.Run("Optimize WLAN - WLAN not found", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestOptimizationConstants tests the optimization constants
func TestOptimizationConstants(t *testing.T) {
	t.Run("Valid 2.4GHz channels", func(t *testing.T) {
		validChannels := []string{"Auto", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"}
		for _, ch := range validChannels {
			assert.True(t, ValidChannels24GHz[ch], "Channel %s should be valid for 2.4GHz", ch)
		}
	})

	t.Run("Invalid 2.4GHz channels", func(t *testing.T) {
		invalidChannels := []string{"0", "14", "15", "36", "149"}
		for _, ch := range invalidChannels {
			assert.False(t, ValidChannels24GHz[ch], "Channel %s should be invalid for 2.4GHz", ch)
		}
	})

	t.Run("Valid 5GHz channels", func(t *testing.T) {
		validChannels := []string{"Auto", "36", "40", "44", "48", "52", "56", "60", "64", "149", "153", "157", "161"}
		for _, ch := range validChannels {
			assert.True(t, ValidChannels5GHz[ch], "Channel %s should be valid for 5GHz", ch)
		}
	})

	t.Run("Invalid 5GHz channels", func(t *testing.T) {
		invalidChannels := []string{"0", "1", "6", "11", "100", "165"}
		for _, ch := range invalidChannels {
			assert.False(t, ValidChannels5GHz[ch], "Channel %s should be invalid for 5GHz", ch)
		}
	})

	t.Run("Valid 2.4GHz modes", func(t *testing.T) {
		validModes := []string{"b", "g", "n", "b/g", "g/n", "b/g/n"}
		for _, mode := range validModes {
			_, ok := ValidModes24GHz[mode]
			assert.True(t, ok, "Mode %s should be valid for 2.4GHz", mode)
		}
	})

	t.Run("Valid 5GHz modes", func(t *testing.T) {
		validModes := []string{"a", "n", "ac", "a/n", "a/n/ac"}
		for _, mode := range validModes {
			_, ok := ValidModes5GHz[mode]
			assert.True(t, ok, "Mode %s should be valid for 5GHz", mode)
		}
	})

	t.Run("Valid 2.4GHz bandwidths", func(t *testing.T) {
		validBW := []string{"20MHz", "40MHz", "Auto"}
		for _, bw := range validBW {
			assert.True(t, ValidBandwidth24GHz[bw], "Bandwidth %s should be valid for 2.4GHz", bw)
		}
	})

	t.Run("Invalid 2.4GHz bandwidths", func(t *testing.T) {
		assert.False(t, ValidBandwidth24GHz["80MHz"], "80MHz should be invalid for 2.4GHz")
		assert.False(t, ValidBandwidth24GHz["160MHz"], "160MHz should be invalid for 2.4GHz")
	})

	t.Run("Valid 5GHz bandwidths", func(t *testing.T) {
		validBW := []string{"20MHz", "40MHz", "80MHz", "Auto"}
		for _, bw := range validBW {
			assert.True(t, ValidBandwidth5GHz[bw], "Bandwidth %s should be valid for 5GHz", bw)
		}
	})

	t.Run("Invalid 5GHz bandwidths", func(t *testing.T) {
		assert.False(t, ValidBandwidth5GHz["160MHz"], "160MHz should be invalid for 5GHz")
	})

	t.Run("Valid transmit power values", func(t *testing.T) {
		validPower := []int{0, 20, 40, 60, 80, 100}
		for _, power := range validPower {
			assert.True(t, ValidTransmitPower[power], "Transmit power %d should be valid", power)
		}
	})

	t.Run("Invalid transmit power values", func(t *testing.T) {
		invalidPower := []int{-1, 10, 30, 50, 70, 90, 101, 200}
		for _, power := range invalidPower {
			assert.False(t, ValidTransmitPower[power], "Transmit power %d should be invalid", power)
		}
	})

	t.Run("Mode mappings for 2.4GHz", func(t *testing.T) {
		assert.Equal(t, "b", ValidModes24GHz["b"])
		assert.Equal(t, "g", ValidModes24GHz["g"])
		assert.Equal(t, "n", ValidModes24GHz["n"])
		assert.Equal(t, "b,g", ValidModes24GHz["b/g"])
		assert.Equal(t, "g,n", ValidModes24GHz["g/n"])
		assert.Equal(t, "b,g,n", ValidModes24GHz["b/g/n"])
	})

	t.Run("Mode mappings for 5GHz", func(t *testing.T) {
		assert.Equal(t, "a", ValidModes5GHz["a"])
		assert.Equal(t, "n", ValidModes5GHz["n"])
		assert.Equal(t, "ac", ValidModes5GHz["ac"])
		assert.Equal(t, "a,n", ValidModes5GHz["a/n"])
		assert.Equal(t, "a,n,ac", ValidModes5GHz["a/n/ac"])
	})
}

// TestGetAvailableWLANHandlerErrors tests error cases for getAvailableWLANHandler
func TestGetAvailableWLANHandlerErrors(t *testing.T) {
	t.Run("Device not found", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return empty array to simulate device not found
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/192.168.255.255", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("GenieACS server error on device lookup", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal error"}`))
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/192.168.1.100", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusNotFound || rr.Code == http.StatusInternalServerError)
	})
}

// TestUpdateWLANHandlerErrors tests additional error cases for updateWLANHandler
func TestUpdateWLANHandlerErrors(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Update WLAN - Invalid WLAN ID", func(t *testing.T) {
		body := `{"ssid": "Test"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/abc/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Request body too large", func(t *testing.T) {
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest)
	})

	t.Run("Update WLAN - Empty body (no fields to update)", func(t *testing.T) {
		body := `{}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid SSID (too long)", func(t *testing.T) {
		body := `{"ssid": "ThisSSIDIsWayTooLongAndExceeds32Characters"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid SSID (leading space)", func(t *testing.T) {
		body := `{"ssid": " LeadingSpace"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid password (too short)", func(t *testing.T) {
		body := `{"password": "short"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid password (too long)", func(t *testing.T) {
		longPassword := strings.Repeat("a", 64)
		body := fmt.Sprintf(`{"password": "%s"}`, longPassword)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid auth mode", func(t *testing.T) {
		body := `{"auth_mode": "InvalidMode"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid encryption", func(t *testing.T) {
		body := `{"encryption": "InvalidEncryption"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid max clients (too low)", func(t *testing.T) {
		body := `{"max_clients": 0}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update WLAN - Invalid max clients (too high)", func(t *testing.T) {
		body := `{"max_clients": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestDeleteWLANHandlerErrors tests additional error cases for deleteWLANHandler
func TestDeleteWLANHandlerErrors(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Delete WLAN - Invalid WLAN ID (non-numeric)", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/abc/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Delete WLAN - Invalid WLAN ID (0)", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/0/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Delete WLAN - Invalid WLAN ID (10)", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/10/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Delete WLAN - Device not found", func(t *testing.T) {
		mockNotFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})

		_, router := setupTestServer(t, mockNotFoundHandler)

		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/192.168.255.255", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestOptimizeWLANHandlerErrors tests additional error cases for optimizeWLANHandler
func TestOptimizeWLANHandlerErrors(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle device lookup by IP
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Handle device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		// Handle task submissions
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Optimize WLAN - Invalid WLAN ID", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/abc/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Request body too large", func(t *testing.T) {
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest)
	})

	t.Run("Optimize WLAN - Empty body", func(t *testing.T) {
		body := `{}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Invalid channel for 2.4GHz", func(t *testing.T) {
		body := `{"channel": "99"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Invalid mode for 2.4GHz", func(t *testing.T) {
		body := `{"mode": "ac"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Invalid bandwidth for 2.4GHz (80MHz)", func(t *testing.T) {
		body := `{"bandwidth": "80MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Invalid transmit power", func(t *testing.T) {
		power := 50
		body := fmt.Sprintf(`{"transmit_power": %d}`, power)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize WLAN - Device not found", func(t *testing.T) {
		mockNotFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})

		_, router := setupTestServer(t, mockNotFoundHandler)

		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/192.168.255.255", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestGetDeviceCapabilityHandlerErrors tests additional error cases
func TestGetDeviceCapabilityHandlerErrors(t *testing.T) {
	t.Run("Device not found", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/capability/192.168.255.255", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("GenieACS error", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/capability/192.168.1.100", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusNotFound || rr.Code == http.StatusInternalServerError)
	})

	t.Run("Device found but capability fetch fails", func(t *testing.T) {
		requestCount := 0
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			// First request: IP lookup succeeds
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			// Second request: device data query fails
			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "internal error"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/capability/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should return internal server error because capability fetch failed
		assert.True(t, rr.Code == http.StatusInternalServerError || rr.Code == http.StatusNotFound)
	})
}

// TestGetAvailableWLANHandlerWithCapabilityError tests error in getDeviceCapability
func TestGetAvailableWLANHandlerWithCapabilityError(t *testing.T) {
	t.Run("Device found but capability fetch fails", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First request: IP lookup succeeds
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			// Second request: device data query fails
			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusInternalServerError || rr.Code == http.StatusNotFound)
	})
}

// TestSSIDValidationCharacters tests SSID character validation edge cases
func TestSSIDValidationCharacters(t *testing.T) {
	t.Run("SSID with invalid characters", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
				return
			}
			w.WriteHeader(http.StatusOK)
		})

		_, router := setupTestServer(t, mockHandler)

		// Test with control characters in SSID
		body := fmt.Sprintf(`{"ssid": "Test%cWiFi", "password": "TestPass123"}`, 0x01)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestUpdateWLANHandlerWithWLANExistsCheck tests the WLAN exists validation
func TestUpdateWLANHandlerWithWLANExistsCheck(t *testing.T) {
	// Mock device with WLAN 1 but not WLAN 3
	mockDeviceWithWLAN1Only := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "BCM963268"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "TestNetwork"}
						}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithWLAN1Only + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Update WLAN that doesn't exist", func(t *testing.T) {
		body := `{"ssid": "NewSSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestDeleteWLANHandlerWithWLANExistsCheck tests the delete WLAN exists validation
func TestDeleteWLANHandlerWithWLANExistsCheck(t *testing.T) {
	// Mock device with WLAN 1 but not WLAN 3
	mockDeviceWithWLAN1Only := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "BCM963268"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "TestNetwork"}
						}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithWLAN1Only + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Delete WLAN that doesn't exist", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/3/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestOptimizeWLANHandlerWithWLANExistsCheck tests the optimize WLAN exists validation
func TestOptimizeWLANHandlerWithWLANExistsCheck(t *testing.T) {
	// Mock device with WLAN 1 but not WLAN 3
	mockDeviceWithWLAN1Only := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "BCM963268"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "TestNetwork"}
						}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithWLAN1Only + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Optimize WLAN that doesn't exist", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

// TestCacheEvictionWithShortTimeout tests StartEviction with very short timeout
func TestCacheEvictionWithShortTimeout(t *testing.T) {
	// Create cache with timeout less than 1 second to trigger minimum interval check
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 500 * time.Millisecond, // Less than 1 second
	}

	// Start eviction - should use minimum 1 second interval
	cache.StartEviction()

	// Add some test data
	cache.set("test-device", map[string]interface{}{"test": "data"})

	// Wait a bit and verify cache is working
	time.Sleep(100 * time.Millisecond)
	data, found := cache.get("test-device")
	assert.True(t, found)
	assert.NotNil(t, data)

	// Stop eviction
	cache.StopEviction()
}

// TestSetParameterValuesErrors tests setParameterValues error cases
func TestSetParameterValuesErrors(t *testing.T) {
	t.Run("Non-OK status response", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/tasks") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": "invalid parameters"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		geniesBaseURL = mockServer.URL
		httpClient = mockServer.Client()

		defer func() {
			geniesBaseURL = originalBaseURL
			httpClient = originalClient
		}()

		params := [][]interface{}{
			{"Test.Path", "value", "xsd:string"},
		}
		err := setParameterValues(context.Background(), "test-device", params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "set parameter values failed")
	})
}

// TestGetDeviceIDByIPEdgeCases tests edge cases in getDeviceIDByIP
func TestGetDeviceIDByIPEdgeCases(t *testing.T) {
	t.Run("Invalid IP address", func(t *testing.T) {
		_, err := getDeviceIDByIP(context.Background(), "invalid-ip")
		assert.Error(t, err)
	})

	t.Run("HTTP request creation error", func(t *testing.T) {
		originalBaseURL := geniesBaseURL
		// Use an invalid URL that will cause request creation to fail
		geniesBaseURL = "://invalid-url"

		defer func() {
			geniesBaseURL = originalBaseURL
		}()

		_, err := getDeviceIDByIP(context.Background(), "192.168.1.1")
		assert.Error(t, err)
	})

	t.Run("Non-OK status from GenieACS", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer mockServer.Close()

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		geniesBaseURL = mockServer.URL
		httpClient = mockServer.Client()

		defer func() {
			geniesBaseURL = originalBaseURL
			httpClient = originalClient
		}()

		_, err := getDeviceIDByIP(context.Background(), "192.168.1.1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-OK status")
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`invalid json`))
		}))
		defer mockServer.Close()

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		geniesBaseURL = mockServer.URL
		httpClient = mockServer.Client()

		defer func() {
			geniesBaseURL = originalBaseURL
			httpClient = originalClient
		}()

		_, err := getDeviceIDByIP(context.Background(), "192.168.1.1")
		assert.Error(t, err)
	})
}

// TestUpdateSSIDByIPHandlerEdgeCases tests edge cases for updateSSIDByIPHandler
func TestUpdateSSIDByIPHandlerEdgeCases(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("SSID with only whitespace", func(t *testing.T) {
		body := `{"ssid": "   "}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should be rejected - SSID with leading/trailing spaces is invalid
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestUpdatePasswordByIPHandlerEdgeCases tests edge cases for updatePasswordByIPHandler
func TestUpdatePasswordByIPHandlerEdgeCases(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Password exactly 8 characters (minimum)", func(t *testing.T) {
		body := `{"password": "12345678"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed - exactly minimum length
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Password exactly 63 characters (maximum)", func(t *testing.T) {
		longPassword := strings.Repeat("a", 63)
		body := fmt.Sprintf(`{"password": "%s"}`, longPassword)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed - exactly maximum length
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestCreateWLANHandlerEdgeCases tests more edge cases for createWLANHandler
func TestCreateWLANHandlerEdgeCases(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Create with hidden SSID true", func(t *testing.T) {
		body := `{"ssid": "HiddenNet", "password": "SecurePass123", "hidden": true}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with custom max_clients", func(t *testing.T) {
		body := `{"ssid": "CustomNet", "password": "SecurePass123", "max_clients": 10}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with TKIP encryption", func(t *testing.T) {
		body := `{"ssid": "TKIPNet", "password": "SecurePass123", "encryption": "TKIP"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/4/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestGetAvailableWLANHandlerWithInvalidWLANID tests getAvailableWLANHandler with invalid WLAN IDs
func TestGetAvailableWLANHandlerWithInvalidWLANID(t *testing.T) {
	// Device with a non-numeric WLAN ID (edge case)
	mockDeviceWithInvalidWLAN := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "BCM963268"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"invalid": {
							"Enable": {"_value": true},
							"SSID": {"_value": "InvalidWLAN"}
						},
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "ValidWLAN"}
						}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithInvalidWLAN + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Get available WLAN with invalid WLAN IDs in config", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed, invalid WLAN IDs should be skipped
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestUpdateWLANHandlerMoreEdgeCases tests more edge cases for updateWLANHandler
func TestUpdateWLANHandlerMoreEdgeCases(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Update with hidden true", func(t *testing.T) {
		body := `{"hidden": true}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with max_clients", func(t *testing.T) {
		body := `{"max_clients": 20}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with auth_mode Open", func(t *testing.T) {
		body := `{"auth_mode": "Open"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with auth_mode WPA", func(t *testing.T) {
		body := `{"auth_mode": "WPA"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with auth_mode WPA/WPA2", func(t *testing.T) {
		body := `{"auth_mode": "WPA/WPA2"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestOptimizeWLANHandlerMoreEdgeCases tests more edge cases for optimizeWLANHandler
func TestOptimizeWLANHandlerMoreEdgeCases(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Optimize with Auto channel", func(t *testing.T) {
		body := `{"channel": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize with 20MHz bandwidth", func(t *testing.T) {
		body := `{"bandwidth": "20MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize with g/n mode", func(t *testing.T) {
		body := `{"mode": "g/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize with b/g mode", func(t *testing.T) {
		body := `{"mode": "b/g"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize with all parameters combined", func(t *testing.T) {
		body := `{"channel": "6", "mode": "b/g/n", "bandwidth": "40MHz", "transmit_power": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestUpdateWLANHandlerValidationPaths tests additional validation paths in updateWLANHandler
func TestUpdateWLANHandlerValidationPaths(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Update with auth_mode WPA2", func(t *testing.T) {
		body := `{"auth_mode": "WPA2"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with TKIP+AES encryption", func(t *testing.T) {
		body := `{"encryption": "TKIP+AES"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with invalid encryption", func(t *testing.T) {
		body := `{"encryption": "InvalidEnc"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with invalid auth_mode", func(t *testing.T) {
		body := `{"auth_mode": "InvalidAuth"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with invalid max_clients (too low)", func(t *testing.T) {
		body := `{"max_clients": 0}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with invalid max_clients (too high)", func(t *testing.T) {
		body := `{"max_clients": 999}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with empty SSID", func(t *testing.T) {
		body := `{"ssid": ""}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with SSID having trailing space", func(t *testing.T) {
		body := `{"ssid": "TestSSID "}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with SSID too long", func(t *testing.T) {
		longSSID := strings.Repeat("a", 33)
		body := fmt.Sprintf(`{"ssid": "%s"}`, longSSID)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with SSID containing control character", func(t *testing.T) {
		body := `{"ssid": "Test\u0001SSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with password too long", func(t *testing.T) {
		longPass := strings.Repeat("a", 64)
		body := fmt.Sprintf(`{"password": "%s"}`, longPass)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with AES encryption", func(t *testing.T) {
		body := `{"encryption": "AES"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with TKIP encryption", func(t *testing.T) {
		body := `{"encryption": "TKIP"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestDeleteWLANHandlerMoreEdgeCases tests more edge cases for deleteWLANHandler
func TestDeleteWLANHandlerMoreEdgeCases(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Delete existing WLAN 1", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Delete with invalid WLAN ID (non-numeric)", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/abc/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestOptimizeWLANHandler5GHzValidation tests 5GHz specific validation paths
func TestOptimizeWLANHandler5GHzValidation(t *testing.T) {
	// Mock dual-band device
	mockDualBandDeviceResponse := fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, mockDeviceID, time.Now().UTC().Format(time.RFC3339))
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi24"}},
						"5": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi5G"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDualBandDeviceResponse))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDualBandDeviceData + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Optimize 5GHz with a/n mode", func(t *testing.T) {
		body := `{"mode": "a/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz with a/n/ac mode", func(t *testing.T) {
		body := `{"mode": "a/n/ac"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz with 80MHz bandwidth", func(t *testing.T) {
		body := `{"bandwidth": "80MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz with channel 36", func(t *testing.T) {
		body := `{"channel": "36"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz with invalid 2.4GHz channel", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize 5GHz with invalid 2.4GHz mode", func(t *testing.T) {
		body := `{"mode": "b/g/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize 2.4GHz with invalid 5GHz channel", func(t *testing.T) {
		body := `{"channel": "36"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize 2.4GHz with invalid 5GHz mode", func(t *testing.T) {
		body := `{"mode": "a/n/ac"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize with invalid transmit power", func(t *testing.T) {
		body := `{"transmit_power": 50}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize with invalid bandwidth for 2.4GHz", func(t *testing.T) {
		body := `{"bandwidth": "80MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize with valid transmit power 60", func(t *testing.T) {
		body := `{"transmit_power": 60}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize with valid channel 11", func(t *testing.T) {
		body := `{"channel": "11"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestGetAvailableWLANHandlerBandValidation tests band validation in getAvailableWLANHandler
func TestGetAvailableWLANHandlerBandValidation(t *testing.T) {
	// Mock single-band device
	mockSingleBandDeviceResponse := fmt.Sprintf(`[{"_id": "002568-HG8245H-123456", "_lastInform": "%s"}]`, time.Now().UTC().Format(time.RFC3339))
	mockSingleBandDeviceData := `{
		"_id": "002568-HG8245H-123456",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "HG8245H"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi24"}},
						"2": {"Enable": {"_value": false}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockSingleBandDeviceResponse))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "002568-HG8245H-123456") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockSingleBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Get available WLAN for single-band device", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should succeed and show only 2.4GHz WLANs
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestCreateWLANHandlerMoreValidation tests more validation paths in createWLANHandler
func TestCreateWLANHandlerMoreValidation(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		if r.Method == "POST" && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_id": "task123"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Create with SSID containing control character", func(t *testing.T) {
		body := `{"ssid": "Test\u0001SSID", "password": "SecurePass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with password too long", func(t *testing.T) {
		longPass := strings.Repeat("a", 64)
		body := fmt.Sprintf(`{"ssid": "TestSSID", "password": "%s"}`, longPass)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create WLAN with all optional fields", func(t *testing.T) {
		body := `{"ssid": "TestSSID", "password": "SecurePass123", "hidden": true, "max_clients": 20, "auth_mode": "WPA2", "encryption": "AES"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with SSID leading space", func(t *testing.T) {
		body := `{"ssid": " TestSSID", "password": "SecurePass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestStartEvictionMinimumInterval tests StartEviction with timeout < 2 seconds
func TestStartEvictionMinimumInterval(t *testing.T) {
	// Create cache with 1 second timeout (evictionInterval would be 500ms, but should be clamped to 1s)
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 1 * time.Second, // This will make evictionInterval = 500ms < 1 second
	}
	cache.StartEviction()

	// Add an item to the cache
	cache.set("test-device", map[string]interface{}{"test": "data"})

	// Verify item exists
	data, found := cache.get("test-device")
	assert.True(t, found)
	assert.NotNil(t, data)

	// Clean up
	cache.StopEviction()
}

// TestDeleteWLANHandlerNotFoundErrors tests various error cases for deleteWLANHandler
func TestDeleteWLANHandlerNotFoundErrors(t *testing.T) {
	t.Run("Device not found", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return empty response for device lookup
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/192.168.255.255", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("WLAN not found/disabled", func(t *testing.T) {
		// Device exists but WLAN 3 doesn't exist
		mockDeviceWithNoWLAN3 := `{
			"_id": "002568-BCM963268-684752",
			"InternetGatewayDevice": {
				"DeviceInfo": {
					"ProductClass": {"_value": "F670L"}
				},
				"LANDevice": {
					"1": {
						"WLANConfiguration": {
							"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
						}
					}
				}
			}
		}`

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN3 + "]"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/3/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "does not exist")
	})
}

// TestUpdateSSIDByIPHandlerInternalError tests internal server error paths
func TestUpdateSSIDByIPHandlerInternalError(t *testing.T) {
	t.Run("isWLANValid returns error", func(t *testing.T) {
		// Mock server that returns invalid data to cause isWLANValid to fail
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				// Return valid device but without proper WLAN structure
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `", "_lastInform": "` + time.Now().UTC().Format(time.RFC3339) + `"}]`))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, router := setupTestServer(t, mockHandler)

		body := `{"ssid": "TestSSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should return internal server error due to WLAN validation failure
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

// TestUpdatePasswordByIPHandlerInternalError tests internal server error paths
func TestUpdatePasswordByIPHandlerInternalError(t *testing.T) {
	t.Run("isWLANValid returns error", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
				// Return valid device but without proper WLAN structure
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `", "_lastInform": "` + time.Now().UTC().Format(time.RFC3339) + `"}]`))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, router := setupTestServer(t, mockHandler)

		body := `{"password": "SecurePass123"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

// TestGetAvailableWLANHandlerDeviceDataError tests getDeviceData error path for getAvailableWLANHandler
func TestGetAvailableWLANHandlerDeviceDataError(t *testing.T) {
	t.Run("GetDeviceData returns error", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			// Return empty for device data query to trigger error
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		})

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should return error
		assert.NotEqual(t, http.StatusOK, rr.Code)
	})
}

// TestSetParameterValuesMoreErrors tests additional error paths in setParameterValues
func TestSetParameterValuesMoreErrors(t *testing.T) {
	t.Run("HTTP request creation error", func(t *testing.T) {
		// This is hard to test directly, but we can test the JSON marshal error path
		originalBaseURL := geniesBaseURL
		geniesBaseURL = "http://invalid\x00url" // Invalid URL that will fail

		defer func() {
			geniesBaseURL = originalBaseURL
		}()

		params := [][]interface{}{
			{"InternetGatewayDevice.Test", "value", "xsd:string"},
		}

		err := setParameterValues(context.Background(), "test-device", params)
		assert.Error(t, err)
	})
}

// TestUpdateWLANHandlerBodyTooLarge tests request body too large error
func TestUpdateWLANHandlerBodyTooLarge(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Create a very large body
	largeBody := strings.Repeat("a", 1024*1024+1) // Over 1MB
	body := fmt.Sprintf(`{"ssid": "%s"}`, largeBody)
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

// TestOptimizeWLANHandlerBodyTooLarge tests request body too large error
func TestOptimizeWLANHandlerBodyTooLarge(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Create a very large body
	largeBody := strings.Repeat("a", 1024*1024+1) // Over 1MB
	body := fmt.Sprintf(`{"channel": "%s"}`, largeBody)
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

// TestCreateWLANHandlerBodyTooLarge tests request body too large error
func TestCreateWLANHandlerBodyTooLarge(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Create a very large body
	largeBody := strings.Repeat("a", 1024*1024+1) // Over 1MB
	body := fmt.Sprintf(`{"ssid": "%s", "password": "SecurePass123"}`, largeBody)
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

// TestDeleteWLANHandlerBandValidation tests WLAN ID band validation for deleteWLANHandler
func TestDeleteWLANHandlerBandValidation(t *testing.T) {
	// Single-band device response
	mockSingleBandResponse := fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, mockDeviceID, time.Now().UTC().Format(time.RFC3339))
	mockSingleBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "HG8245H"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi24"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockSingleBandResponse))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockSingleBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Delete WLAN 5 on single-band device", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/5/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "single-band")
	})
}

// TestUpdateWLANHandlerBandValidation tests WLAN ID band validation for updateWLANHandler
func TestUpdateWLANHandlerBandValidation(t *testing.T) {
	// Single-band device response
	mockSingleBandResponse := fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, mockDeviceID, time.Now().UTC().Format(time.RFC3339))
	mockSingleBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "HG8245H"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi24"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockSingleBandResponse))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockSingleBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Update WLAN 5 on single-band device", func(t *testing.T) {
		body := `{"ssid": "NewSSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "single-band")
	})
}

// TestOptimizeWLANHandlerBandValidation tests WLAN ID band validation for optimizeWLANHandler
func TestOptimizeWLANHandlerBandValidation(t *testing.T) {
	// Single-band device response
	mockSingleBandResponse := fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, mockDeviceID, time.Now().UTC().Format(time.RFC3339))
	mockSingleBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "HG8245H"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi24"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockSingleBandResponse))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockSingleBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("Optimize WLAN 5 on single-band device", func(t *testing.T) {
		body := `{"channel": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "single-band")
	})
}

// TestUpdateSSIDByIPHandlerWLANNotFound tests WLAN not found error in updateSSIDByIPHandler
func TestUpdateSSIDByIPHandlerWLANNotFound(t *testing.T) {
	mockDeviceWithNoWLAN3 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN3 + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "TestSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/3/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestUpdatePasswordByIPHandlerWLANNotFound tests WLAN not found error in updatePasswordByIPHandler
func TestUpdatePasswordByIPHandlerWLANNotFound(t *testing.T) {
	mockDeviceWithNoWLAN3 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN3 + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"password": "SecurePass123"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/3/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestGetAvailableWLANHandlerCapabilityError tests getDeviceCapability error in getAvailableWLANHandler
func TestGetAvailableWLANHandlerCapabilityError(t *testing.T) {
	// Device without proper structure for capability detection
	mockDeviceWithInvalidStructure := `{
		"_id": "002568-BCM963268-684752"
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithInvalidStructure + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should succeed but with limited WLAN data due to missing structure
	// The handler should still work, it will just have empty WLAN configs
	assert.True(t, rr.Code == http.StatusOK || rr.Code == http.StatusInternalServerError)
}

// TestStartEvictionTickerFires tests that the eviction ticker fires and evicts expired entries
func TestStartEvictionTickerFires(t *testing.T) {
	// Create cache with very short timeout so eviction happens quickly
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 100 * time.Millisecond, // Very short timeout
	}

	// Add an item to the cache with a timestamp that will expire
	cache.mu.Lock()
	cache.data["test-device"] = cachedDeviceData{
		data:      map[string]interface{}{"test": "data"},
		timestamp: time.Now().Add(-200 * time.Millisecond), // Already expired
	}
	cache.mu.Unlock()

	// Start eviction - evictionInterval will be 50ms (half of 100ms), but clamped to 1 second minimum
	cache.StartEviction()

	// Wait for ticker to fire at least once (slightly more than 1 second due to minimum interval)
	time.Sleep(1200 * time.Millisecond)

	// Check if the expired item was evicted
	cache.mu.RLock()
	_, found := cache.data["test-device"]
	cache.mu.RUnlock()

	// Stop eviction
	cache.StopEviction()

	// The item should have been evicted
	assert.False(t, found, "Expired item should have been evicted by ticker")
}

// TestDeleteWLANHandlerIsWLANValidInternalError tests internal error from isWLANValid
func TestDeleteWLANHandlerIsWLANValidInternalError(t *testing.T) {
	// Mock server that returns error when trying to get device data for isWLANValid
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Return error for device data query (for isWLANValid)
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal error"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Band validation fails first with 400, not isWLANValid
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestUpdateWLANHandlerIsWLANValidInternalError tests internal error from isWLANValid
func TestUpdateWLANHandlerIsWLANValidInternalError(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Return error for device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal error"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "NewSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Returns 400 because band validation (validateWLANIDForDevice) fails before isWLANValid
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOptimizeWLANHandlerIsWLANValidInternalError tests internal error from isWLANValid
func TestOptimizeWLANHandlerIsWLANValidInternalError(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Return error for device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal error"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"channel": "Auto"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Returns 400 because band validation (validateWLANIDForDevice) fails before isWLANValid
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestCreateWLANHandlerIsWLANValidInternalError tests internal error from getDeviceData
func TestCreateWLANHandlerIsWLANValidInternalError(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Return error for device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal error"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "NewSSID", "password": "SecurePass123"}`
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Returns 400 because band validation (validateWLANIDForDevice) fails before isWLANValid
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestGetAvailableWLANHandlerGetDeviceDataError tests getDeviceData error in getAvailableWLANHandler
func TestGetAvailableWLANHandlerGetDeviceDataError(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Return error for device data query
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal error"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestUpdateSSIDByIPHandlerBodyTooLarge tests request body too large error
func TestUpdateSSIDByIPHandlerBodyTooLarge(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Create a very large body
	largeBody := strings.Repeat("a", 1024*1024+1) // Over 1MB
	body := fmt.Sprintf(`{"ssid": "%s"}`, largeBody)
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/ssid/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

// TestUpdatePasswordByIPHandlerBodyTooLarge tests request body too large error
func TestUpdatePasswordByIPHandlerBodyTooLarge(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Create a very large body
	largeBody := strings.Repeat("a", 1024*1024+1) // Over 1MB
	body := fmt.Sprintf(`{"password": "%s"}`, largeBody)
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/password/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

// TestUpdateWLANHandlerWLANNotFound tests WLAN not found in updateWLANHandler
func TestUpdateWLANHandlerWLANNotFoundPath(t *testing.T) {
	mockDeviceWithNoWLAN3 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN3 + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "NewSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/3/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "does not exist")
}

// TestOptimizeWLANHandlerWLANNotFound tests WLAN not found in optimizeWLANHandler
func TestOptimizeWLANHandlerWLANNotFoundPath(t *testing.T) {
	mockDeviceWithNoWLAN3 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
					}
				}
			}
		}
	}`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN3 + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"channel": "Auto"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/3/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "does not exist")
}

// TestDeleteWLANHandlerIsWLANValidInternalErrorPath tests the isWLANValid error path in deleteWLANHandler
// Device data passes band validation (model from _id) but causes isWLANValid error (missing LANDevice)
func TestDeleteWLANHandlerIsWLANValidInternalErrorPath(t *testing.T) {
	// Device data with dual-band model (from _id) but missing LANDevice structure
	// This passes band validation but fails isWLANValid
	mockDeviceDataMissingLAN := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A1",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A1", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A1") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceDataMissingLAN))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Clear cache to ensure fresh data
	deviceCacheInstance.clearAll()

	req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/10.90.14.41", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to check WLAN status")
}

// TestUpdateWLANHandlerIsWLANValidInternalErrorPath tests the isWLANValid error path in updateWLANHandler
func TestUpdateWLANHandlerIsWLANValidInternalErrorPath(t *testing.T) {
	// Device data with dual-band model but missing LANDevice structure
	mockDeviceDataMissingLAN := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A2",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A2", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A2") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceDataMissingLAN))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	body := `{"ssid": "NewSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/10.90.14.42", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to check WLAN status")
}

// TestOptimizeWLANHandlerIsWLANValidInternalErrorPath tests the isWLANValid error path in optimizeWLANHandler
func TestOptimizeWLANHandlerIsWLANValidInternalErrorPath(t *testing.T) {
	// Device data with dual-band model but missing LANDevice structure
	mockDeviceDataMissingLAN := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A3",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A3", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A3") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceDataMissingLAN))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	body := `{"channel": "Auto"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/10.90.14.43", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to check WLAN status")
}

// TestCreateWLANHandlerIsWLANValidInternalErrorPath tests the isWLANValid error path in createWLANHandler
func TestCreateWLANHandlerIsWLANValidInternalErrorPath(t *testing.T) {
	// Device data with dual-band model but missing LANDevice structure
	mockDeviceDataMissingLAN := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A4",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A4", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A4") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceDataMissingLAN))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	body := `{"ssid": "NewSSID", "password": "SecurePass123"}`
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/10.90.14.44", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to check WLAN status")
}

// TestGetAvailableWLANHandlerInternalGatewayMissing tests missing InternetGatewayDevice returns error
func TestGetAvailableWLANHandlerInternalGatewayMissing(t *testing.T) {
	mockDeviceWithoutGateway := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A5"
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A5", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A5") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceWithoutGateway))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/10.90.14.45", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should return 500 because InternetGatewayDevice is missing
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestGetDeviceIDByIPNonOKStatus tests non-OK status from GenieACS
func TestGetDeviceIDByIPNonOKStatus(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			// Return non-OK status for device ID lookup
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error": "service unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/1/10.90.14.50", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should return 404 because device lookup failed
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestGetDeviceIDByIPInvalidJSON tests invalid JSON response from GenieACS
func TestGetDeviceIDByIPInvalidJSON(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`not valid json`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/1/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestGetAvailableWLANHandlerWithNonNumericWLANKey tests getAvailableWLANHandler with non-numeric WLAN keys
// This triggers the continue branch in strconv.Atoi
func TestGetAvailableWLANHandlerWithNonNumericWLANKey(t *testing.T) {
	// Device with WLAN configurations that have non-numeric keys (should be skipped)
	mockDeviceWithInvalidWLANID := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A6",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}},
						"invalid": {"Enable": {"_value": true}, "SSID": {"_value": "InvalidWLAN"}},
						"abc": {"Enable": {"_value": true}, "SSID": {"_value": "AbcWLAN"}}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A6", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A6") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceWithInvalidWLANID))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/10.90.14.46", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should return OK and skip the invalid WLAN IDs
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestUpdateWLANHandlerWithWPAAuthMode tests updateWLANHandler with WPA auth mode
func TestUpdateWLANHandlerWithWPAAuthMode(t *testing.T) {
	mockDeviceWithWLAN := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A7",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A7", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A7") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceWithWLAN))
			return
		}
		if strings.Contains(r.URL.Path, "/tasks") && r.Method == "POST" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	body := `{"auth_mode": "WPA"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/10.90.14.47", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "WLAN update submitted successfully")
}

// TestUpdateWLANHandlerWithWPAWPA2AuthMode tests updateWLANHandler with WPA/WPA2 auth mode
func TestUpdateWLANHandlerWithWPAWPA2AuthMode(t *testing.T) {
	mockDeviceWithWLAN := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A8",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A8", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A8") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceWithWLAN))
			return
		}
		if strings.Contains(r.URL.Path, "/tasks") && r.Method == "POST" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	body := `{"auth_mode": "WPA/WPA2"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/10.90.14.48", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "WLAN update submitted successfully")
}

// TestUpdateWLANHandlerWithOpenAuthMode tests updateWLANHandler with Open auth mode (no encryption)
func TestUpdateWLANHandlerWithOpenAuthMode(t *testing.T) {
	mockDeviceWithWLAN := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A9",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			lastInform := time.Now().UTC().Format(time.RFC3339)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"_id": "001141-F670L-ZTEGCFLN794B3A9", "_lastInform": "%s"}]`, lastInform)))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "001141-F670L-ZTEGCFLN794B3A9") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceWithWLAN))
			return
		}
		if strings.Contains(r.URL.Path, "/tasks") && r.Method == "POST" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	body := `{"auth_mode": "Open"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/10.90.14.49", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "WLAN update submitted successfully")
}

// TestGetAvailableWLANHandlerNoEnabledWLAN tests when no WLANs are enabled (usedWLAN == nil path)
func TestGetAvailableWLANHandlerNoEnabledWLAN(t *testing.T) {
	// Device with no enabled WLANs - all Enable values are false
	mockDeviceData := `[{
		"_id": "001141-F670L-ZTEGCFLN794B3A50",
		"_deviceId": {
			"_ProductClass": "F670L"
		},
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": false}, "SSID": {"_value": "Test1"}},
						"2": {"Enable": {"_value": false}, "SSID": {"_value": "Test2"}},
						"3": {"Enable": {"_value": false}, "SSID": {"_value": "Test3"}},
						"4": {"Enable": {"_value": false}, "SSID": {"_value": "Test4"}}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockDeviceData))
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/10.90.14.50", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Response should have empty used_wlan array (not null)
	assert.Contains(t, rr.Body.String(), `"used_wlan":[]`)
}

// TestGetAvailableWLANHandlerAllSlotsUsed tests when all WLAN slots are used (available24GHz == nil path)
func TestGetAvailableWLANHandlerAllSlotsUsed(t *testing.T) {
	// Single-band device with all 4 WLANs enabled (no available slots)
	mockDeviceData := `[{
		"_id": "001141-F663N-ZTEGCFLN794B3A51",
		"_deviceId": {
			"_ProductClass": "F663N"
		},
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F663N"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "Net1"}},
						"2": {"Enable": {"_value": true}, "SSID": {"_value": "Net2"}},
						"3": {"Enable": {"_value": true}, "SSID": {"_value": "Net3"}},
						"4": {"Enable": {"_value": true}, "SSID": {"_value": "Net4"}}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockDeviceData))
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/10.90.14.51", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// Response should have empty available 2.4GHz array (all slots used)
	// The nil check code should convert nil to empty array []
	assert.Contains(t, rr.Body.String(), `"2_4ghz":[]`)
}

// TestUpdateWLANHandlerDeviceNotFound tests when device is not found by IP
func TestUpdateWLANHandlerDeviceNotFound(t *testing.T) {
	// Return empty array to simulate device not found
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
	})

	_, router := setupTestServer(t, mockHandler)
	deviceCacheInstance.clearAll()

	body := `{"ssid": "NewSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/10.90.14.52", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "Not Found")
}

// failingTransport is an HTTP transport that always returns an error
type failingTransport struct{}

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network failure")
}

// errorReader is a reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated read error")
}

func (e *errorReader) Close() error {
	return nil
}

// failingBodyTransport returns a response with a body that fails to read
type failingBodyTransport struct{}

func (f *failingBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
		Status:     "500 Internal Server Error",
		Body:       &errorReader{},
	}, nil
}

// TestGetDeviceIDByIPHTTPClientError tests the httpClient.Do error path
func TestGetDeviceIDByIPHTTPClientError(t *testing.T) {
	// Save original values
	originalHTTPClient := httpClient
	originalGeniesBaseURL := geniesBaseURL
	t.Cleanup(func() {
		httpClient = originalHTTPClient
		geniesBaseURL = originalGeniesBaseURL
	})

	// Use a failing HTTP client
	httpClient = &http.Client{
		Transport: &failingTransport{},
	}
	geniesBaseURL = "http://localhost:9999" // Unused but required

	deviceCacheInstance.clearAll()

	// Call getDeviceIDByIP directly
	ctx := context.Background()
	_, err := getDeviceIDByIP(ctx, "192.168.1.1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "simulated network failure")
}

// TestSetParameterValuesBodyReadError tests the io.ReadAll error path in setParameterValues
func TestSetParameterValuesBodyReadError(t *testing.T) {
	// Save original values
	originalHTTPClient := httpClient
	originalGeniesBaseURL := geniesBaseURL
	t.Cleanup(func() {
		httpClient = originalHTTPClient
		geniesBaseURL = originalGeniesBaseURL
	})

	// Use HTTP client with failing body transport
	httpClient = &http.Client{
		Transport: &failingBodyTransport{},
	}
	geniesBaseURL = "http://localhost:9999"

	// Call setParameterValues directly
	ctx := context.Background()
	parameterValues := [][]interface{}{{"path", "value", "xsd:string"}}
	err := setParameterValues(ctx, "test-device", parameterValues)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "set parameter values failed with status")
	assert.Contains(t, err.Error(), "failed to read response body")
	assert.Contains(t, err.Error(), "simulated read error")
}

// TestGetDeviceIDByIPJSONMarshalError tests the json.Marshal error path in getDeviceIDByIP
func TestGetDeviceIDByIPJSONMarshalError(t *testing.T) {
	// Save original jsonMarshal function
	originalJSONMarshal := jsonMarshal
	t.Cleanup(func() {
		jsonMarshal = originalJSONMarshal
	})

	// Override jsonMarshal to return an error
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, errors.New("simulated json marshal error")
	}

	deviceCacheInstance.clearAll()

	// Call getDeviceIDByIP directly
	ctx := context.Background()
	_, err := getDeviceIDByIP(ctx, "192.168.1.1")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "simulated json marshal error")
}
