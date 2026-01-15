package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestGetLANDeviceFromDeviceData(t *testing.T) {
	t.Run("Valid LANDevice", func(t *testing.T) {
		deviceData := map[string]interface{}{
			PathInternetGatewayDevice: map[string]interface{}{
				PathLANDevice: map[string]interface{}{
					"1": map[string]interface{}{
						"test": "value",
					},
				},
			},
		}
		lanDevice, err := GetLANDeviceFromDeviceData(deviceData)
		assert.NoError(t, err)
		assert.NotNil(t, lanDevice)
		assert.Equal(t, "value", lanDevice["test"])
	})

	t.Run("Missing InternetGatewayDevice", func(t *testing.T) {
		deviceData := map[string]interface{}{}
		lanDevice, err := GetLANDeviceFromDeviceData(deviceData)
		assert.Error(t, err)
		assert.Nil(t, lanDevice)
		assert.Contains(t, err.Error(), "InternetGatewayDevice")
	})

	t.Run("Invalid InternetGatewayDevice type", func(t *testing.T) {
		deviceData := map[string]interface{}{
			PathInternetGatewayDevice: "invalid",
		}
		lanDevice, err := GetLANDeviceFromDeviceData(deviceData)
		assert.Error(t, err)
		assert.Nil(t, lanDevice)
	})

	t.Run("Missing LANDevice", func(t *testing.T) {
		deviceData := map[string]interface{}{
			PathInternetGatewayDevice: map[string]interface{}{},
		}
		lanDevice, err := GetLANDeviceFromDeviceData(deviceData)
		assert.Error(t, err)
		assert.Nil(t, lanDevice)
		assert.Contains(t, err.Error(), "LANDevice")
	})

	t.Run("Missing LANDevice.1", func(t *testing.T) {
		deviceData := map[string]interface{}{
			PathInternetGatewayDevice: map[string]interface{}{
				PathLANDevice: map[string]interface{}{},
			},
		}
		lanDevice, err := GetLANDeviceFromDeviceData(deviceData)
		assert.Error(t, err)
		assert.Nil(t, lanDevice)
		assert.Contains(t, err.Error(), "LANDevice.1")
	})
}

func TestGetWLANConfigurationFromLANDevice(t *testing.T) {
	t.Run("Valid WLANConfiguration", func(t *testing.T) {
		lanDevice := map[string]interface{}{
			PathWLANConfiguration: map[string]interface{}{
				"1": map[string]interface{}{"SSID": "test"},
			},
		}
		wlanConfig, ok := GetWLANConfigurationFromLANDevice(lanDevice)
		assert.True(t, ok)
		assert.NotNil(t, wlanConfig)
	})

	t.Run("Missing WLANConfiguration", func(t *testing.T) {
		lanDevice := map[string]interface{}{}
		wlanConfig, ok := GetWLANConfigurationFromLANDevice(lanDevice)
		assert.False(t, ok)
		assert.Nil(t, wlanConfig)
	})
}

func TestExtractDeviceIDByIP_Integration(t *testing.T) {
	// Setup mock server
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("projection") == "_id" {
			query := r.URL.Query().Get("query")
			if strings.Contains(query, "192.168.1.100") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"_id": "test-device-id"}]`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	mockServer := httptest.NewServer(mockHandler)
	defer mockServer.Close()

	// Store original values
	originalBaseURL := geniesBaseURL
	originalClient := httpClient
	originalLogger := logger

	// Setup test environment
	geniesBaseURL = mockServer.URL
	httpClient = mockServer.Client()
	logger, _ = zap.NewDevelopment()

	defer func() {
		geniesBaseURL = originalBaseURL
		httpClient = originalClient
		logger = originalLogger
	}()

	t.Run("Success", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/test/{ip}", func(w http.ResponseWriter, r *http.Request) {
			deviceID, ok := ExtractDeviceIDByIP(w, r)
			if ok {
				sendResponse(w, http.StatusOK, StatusOK, map[string]string{"device_id": deviceID})
			}
		})

		req := httptest.NewRequest("GET", "/test/192.168.1.100", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "test-device-id")
	})

	t.Run("Device Not Found", func(t *testing.T) {
		r := chi.NewRouter()
		r.Get("/test/{ip}", func(w http.ResponseWriter, r *http.Request) {
			_, ok := ExtractDeviceIDByIP(w, r)
			assert.False(t, ok)
		})

		req := httptest.NewRequest("GET", "/test/not-found-ip", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestValidateWLANAndRespond_Integration(t *testing.T) {
	mockDeviceData := `[{
		"_id": "test-device",
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "TestWiFi"}
						},
						"2": {
							"Enable": {"_value": false},
							"SSID": {"_value": "DisabledWiFi"}
						}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockDeviceData))
	})

	mockServer := httptest.NewServer(mockHandler)
	defer mockServer.Close()

	// Store original values
	originalBaseURL := geniesBaseURL
	originalClient := httpClient
	originalLogger := logger
	originalCache := deviceCacheInstance

	// Setup test environment
	geniesBaseURL = mockServer.URL
	httpClient = mockServer.Client()
	logger, _ = zap.NewDevelopment()
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	defer func() {
		geniesBaseURL = originalBaseURL
		httpClient = originalClient
		logger = originalLogger
		deviceCacheInstance = originalCache
	}()

	t.Run("Valid WLAN", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		valid := ValidateWLANAndRespond(rr, req, "test-device", "1")
		assert.True(t, valid)
	})

	t.Run("Disabled WLAN", func(t *testing.T) {
		deviceCacheInstance.clearAll()
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		valid := ValidateWLANAndRespond(rr, req, "test-device", "2")
		assert.False(t, valid)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("Non-existent WLAN", func(t *testing.T) {
		deviceCacheInstance.clearAll()
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		valid := ValidateWLANAndRespond(rr, req, "test-device", "99")
		assert.False(t, valid)
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("Error validating WLAN", func(t *testing.T) {
		// Setup mock server that returns error for device data
		errorMockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		errorMockServer := httptest.NewServer(errorMockHandler)
		defer errorMockServer.Close()

		// Temporarily change base URL to error server
		geniesBaseURL = errorMockServer.URL
		httpClient = errorMockServer.Client()
		deviceCacheInstance.clearAll()

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		valid := ValidateWLANAndRespond(rr, req, "non-existent-device", "1")
		assert.False(t, valid)
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), ErrWLANValidationFailed)
	})
}

func TestUpdateWLANParameter_Success(t *testing.T) {
	mockDeviceData := `[{
		"_id": "test-device",
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "TestWiFi"}
						}
					}
				}
			}
		}
	}]`

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("projection") == "_id" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_id": "test-device"}]`))
			return
		}
		if strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockDeviceData))
	})

	mockServer := httptest.NewServer(mockHandler)
	defer mockServer.Close()

	// Store original values
	originalBaseURL := geniesBaseURL
	originalClient := httpClient
	originalLogger := logger
	originalCache := deviceCacheInstance
	originalWorkerPool := taskWorkerPool

	// Setup test environment
	geniesBaseURL = mockServer.URL
	httpClient = mockServer.Client()
	logger, _ = zap.NewDevelopment()
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}
	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
		wg:      sync.WaitGroup{},
	}
	taskWorkerPool.Start()

	defer func() {
		taskWorkerPool.Stop()
		geniesBaseURL = originalBaseURL
		httpClient = originalClient
		logger = originalLogger
		deviceCacheInstance = originalCache
		taskWorkerPool = originalWorkerPool
	}()

	r := chi.NewRouter()
	r.Put("/test/{wlan}/{ip}", func(w http.ResponseWriter, r *http.Request) {
		UpdateWLANParameter(
			w, r,
			PathWLANSSIDFormat,
			"NewSSID",
			MsgSSIDUpdateSubmitted,
			map[string]string{"ssid": "NewSSID"},
		)
	})

	req := httptest.NewRequest("PUT", "/test/1/192.168.1.100", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), MsgSSIDUpdateSubmitted)
}

func TestUpdateWLANParameter_DeviceNotFound(t *testing.T) {
	// Setup mock server that returns empty device list
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("projection") == "_id" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	notFoundServer := httptest.NewServer(notFoundHandler)
	defer notFoundServer.Close()

	// Store original values
	originalBaseURL := geniesBaseURL
	originalClient := httpClient
	originalLogger := logger
	originalCache := deviceCacheInstance
	originalWorkerPool := taskWorkerPool

	// Setup test environment
	geniesBaseURL = notFoundServer.URL
	httpClient = notFoundServer.Client()
	logger, _ = zap.NewDevelopment()
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}
	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
		wg:      sync.WaitGroup{},
	}
	taskWorkerPool.Start()

	defer func() {
		taskWorkerPool.Stop()
		geniesBaseURL = originalBaseURL
		httpClient = originalClient
		logger = originalLogger
		deviceCacheInstance = originalCache
		taskWorkerPool = originalWorkerPool
	}()

	r := chi.NewRouter()
	r.Put("/test/{wlan}/{ip}", func(w http.ResponseWriter, r *http.Request) {
		UpdateWLANParameter(
			w, r,
			PathWLANSSIDFormat,
			"NewSSID",
			MsgSSIDUpdateSubmitted,
			nil,
		)
	})

	req := httptest.NewRequest("PUT", "/test/1/not-found-ip", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestUpdateWLANParameter_WLANValidationFailure(t *testing.T) {
	// Setup mock server that returns device with disabled WLAN
	disabledWLANData := `[{
		"_id": "test-device-disabled",
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": false},
							"SSID": {"_value": "DisabledWiFi"}
						}
					}
				}
			}
		}
	}]`

	disabledHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("projection") == "_id" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_id": "test-device-disabled"}]`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(disabledWLANData))
	})

	disabledServer := httptest.NewServer(disabledHandler)
	defer disabledServer.Close()

	// Store original values
	originalBaseURL := geniesBaseURL
	originalClient := httpClient
	originalLogger := logger
	originalCache := deviceCacheInstance
	originalWorkerPool := taskWorkerPool

	// Setup test environment
	geniesBaseURL = disabledServer.URL
	httpClient = disabledServer.Client()
	logger, _ = zap.NewDevelopment()
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}
	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
		wg:      sync.WaitGroup{},
	}
	taskWorkerPool.Start()

	defer func() {
		taskWorkerPool.Stop()
		geniesBaseURL = originalBaseURL
		httpClient = originalClient
		logger = originalLogger
		deviceCacheInstance = originalCache
		taskWorkerPool = originalWorkerPool
	}()

	r := chi.NewRouter()
	r.Put("/test/{wlan}/{ip}", func(w http.ResponseWriter, r *http.Request) {
		UpdateWLANParameter(
			w, r,
			PathWLANSSIDFormat,
			"NewSSID",
			MsgSSIDUpdateSubmitted,
			nil,
		)
	})

	req := httptest.NewRequest("PUT", "/test/1/192.168.1.200", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandlerContext(t *testing.T) {
	ctx := HandlerContext{
		IP:       "192.168.1.100",
		WLAN:     "1",
		DeviceID: "test-device-123",
	}

	assert.Equal(t, "192.168.1.100", ctx.IP)
	assert.Equal(t, "1", ctx.WLAN)
	assert.Equal(t, "test-device-123", ctx.DeviceID)
}
