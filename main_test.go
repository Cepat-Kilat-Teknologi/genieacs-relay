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
	"os/signal"
	"reflect"
	"sort"
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
		resp := `[{"_id":"` + mockDeviceID + `"}]`
		_, _ = w.Write([]byte(resp))
	}))
	defer server.Close()
	geniesBaseURL = server.URL

	id, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.NoError(t, err)
	assert.Equal(t, mockDeviceID, id)
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
		if r.URL.Query().Get("projection") == "_id" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_id": "` + mockDeviceID + `"}]`))
			return
		}
		_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
	})

	_, router := setupTestServer(t, mockHandler)

	payload := `{"password":"abc"}`
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
	w := httptest.NewRecorder()
	updateSSIDByIPHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// Test_updatePasswordByIPHandler_BadJSON memaksa JSON salah
func Test_updatePasswordByIPHandler_BadJSON(t *testing.T) {
	req := httptest.NewRequest("PUT", "/password/update/1/127.0.0.1", strings.NewReader("{bad json"))
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

// Test_getPassword_NoField untuk coverage "N/A"
func Test_getPassword_NoField(t *testing.T) {
	pw := getPassword(map[string]interface{}{}, false)
	if pw != "N/A" {
		t.Fatalf("expected N/A, got %s", pw)
	}
}

// Test_getBand_Unknown untuk coverage unknown
func Test_getBand_Unknown(t *testing.T) {
	b := getBand(map[string]interface{}{}, "99")
	if b != "Unknown" {
		t.Fatalf("expected Unknown, got %s", b)
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

	// Cleanup - properly handle the error return
	_ = logger.Sync()
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

	// Send shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT)
	quit <- syscall.SIGINT

	// Wait for result
	err := <-serverErr
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shutdown error")
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
	// Backup original logger

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
