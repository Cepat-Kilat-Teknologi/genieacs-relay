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

	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

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
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
				return
			}
			if strings.Contains(query, "not-found-ip") {
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
			_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
		if r.URL.Query().Get("projection") == "_id" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
			if r.Method == "GET" && r.URL.Query().Get("projection") == "_id" {
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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

		assert.Equal(t, "********", getPassword(wlanData1, true))

		wlanData3 := map[string]interface{}{}
		assert.Equal(t, "N/A", getPassword(wlanData3, false))
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
			if r.URL.Query().Get("projection") == "_id" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
			if r.URL.Query().Get("projection") == "_id" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
			if r.URL.Query().Get("projection") == "_id" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
			if r.URL.Query().Get("projection") == "_id" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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
			if r.URL.Query().Get("projection") == "_id" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
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

	t.Run("getPassword for ZTE devices", func(t *testing.T) {
		wlanData := map[string]interface{}{
			"PreSharedKey": map[string]interface{}{
				"1": map[string]interface{}{
					"PreSharedKey": map[string]interface{}{"_value": "password123"},
				},
			},
		}
		password := getPassword(wlanData, true) // ZTE device
		assert.Equal(t, "********", password)
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
	originalAPIKey := apiKey
	originalLogger := logger

	defer func() {
		geniesBaseURL = originalGenieURL
		nbiAuthKey = originalNBIKey
		apiKey = originalAPIKey
		logger = originalLogger
	}()

	assert.NotPanics(t, func() {
		// Test minimal initialization
		geniesBaseURL = "http://test"
		nbiAuthKey = "test"
		apiKey = "test"
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
	w := httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	// Case: empty SSID
	body := `{"SSID":""}`
	req = httptest.NewRequest(http.MethodPost, "/update-ssid", strings.NewReader(body))
	w = httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	req = httptest.NewRequest(http.MethodPost, "/update-ssid?ip=", strings.NewReader(`{"SSID":"newssid","WLAN":"99"}`))
	w = httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	assert.Equal(t, http.StatusNotFound, w.Result().StatusCode)
}

func TestUpdatePasswordByIPHandler_ExtraCases(t *testing.T) {
	// Case: invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/update-password", strings.NewReader("{invalid"))
	w := httptest.NewRecorder()
	updatePasswordByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	// Case: empty password
	body := `{"Password":""}`
	req = httptest.NewRequest(http.MethodPost, "/update-password", strings.NewReader(body))
	w = httptest.NewRecorder()
	updatePasswordByIPHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	// Case: WLAN not valid → ip kosong, expected 404
	req = httptest.NewRequest(http.MethodPost, "/update-password?ip=", strings.NewReader(`{"Password":"abc","WLAN":"99"}`))
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
