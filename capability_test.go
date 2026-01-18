package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestNormalizeModelName(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"HG8245H5", "HG8245H5"},
		{"hg8245h5", "HG8245H5"},
		{"HG-8245-H5", "HG8245H5"},
		{"HG 8245 H5", "HG8245H5"},
		{"HG_8245_H5", "HG8245H5"},
		{"F609 V3", "F609V3"},
		{"F609-V3", "F609V3"},
		{"V2804AX30(T)-H", "V2804AX30(T)H"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeModelName(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsDualBandModel(t *testing.T) {
	dualBandTestCases := []struct {
		model    string
		expected bool
	}{
		// Huawei Wi-Fi 6
		{"EG8145X6", true},
		{"HG8145X6", true},
		{"K662c", true},
		{"K662C", true},
		// Huawei Wi-Fi 5
		{"HG8245Q2", true},
		{"HG8145V5", true},
		{"EG8145V5", true},
		// ZTE Wi-Fi 6
		{"F6600P", true},
		{"F670L", true},
		{"F680", true},
		// ZTE Wi-Fi 5
		{"F609V3", true},
		{"F609 V3", true},
		{"F660V7", true},
		// VSOL Dual-Band
		{"V2804AX15-R", true},
		{"HG325AX", true},
		// Nokia/Alcatel
		{"G-2426G-A", true},
		{"G240WF", true},
		// Single-band models should return false
		{"HG8245H", false},
		{"F663N", false},
		{"F609", false},
		{"UnknownModel", false},
	}

	for _, tc := range dualBandTestCases {
		t.Run(tc.model, func(t *testing.T) {
			result := isDualBandModel(tc.model)
			assert.Equal(t, tc.expected, result, "model: %s", tc.model)
		})
	}
}

func TestIsSingleBandModel(t *testing.T) {
	singleBandTestCases := []struct {
		model    string
		expected bool
	}{
		// Huawei Wi-Fi 4 (single-band)
		{"HG8245H", true},
		{"HG8245H5", true},
		{"HG8546M", true},
		{"HS8545M", true},
		// ZTE Single-Band
		{"F663N", true},
		{"F663NV3a", true},
		{"F609", true},
		{"F609V1", true},
		{"F660", true},
		{"F660V5", true},
		// Fiberhome Single-Band
		{"AN5506-04-FG", true},
		{"HG6243C", true},
		// VSOL Single-Band
		{"V2802GWT", true},
		{"HG325N", true},
		// Nokia/Alcatel Single-Band
		{"G-140W-F", true},
		{"I-240W-A", true},
		// Dual-band models should return false
		{"EG8145X6", false},
		{"F670L", false},
		{"UnknownModel", false},
	}

	for _, tc := range singleBandTestCases {
		t.Run(tc.model, func(t *testing.T) {
			result := isSingleBandModel(tc.model)
			assert.Equal(t, tc.expected, result, "model: %s", tc.model)
		})
	}
}

func TestGetDeviceBandType(t *testing.T) {
	testCases := []struct {
		model    string
		expected BandType
	}{
		// Dual-band (including Wi-Fi 7)
		{"F8748Q", BandTypeDualBand},
		{"EG8145X6", BandTypeDualBand},
		{"F670L", BandTypeDualBand},
		{"HG8145V5", BandTypeDualBand},
		// Single-band
		{"HG8245H", BandTypeSingleBand},
		{"F663N", BandTypeSingleBand},
		{"F609", BandTypeSingleBand},
		// Unknown
		{"UnknownModel123", BandTypeUnknown},
	}

	for _, tc := range testCases {
		t.Run(tc.model, func(t *testing.T) {
			result := getDeviceBandType(tc.model)
			assert.Equal(t, tc.expected, result, "model: %s", tc.model)
		})
	}
}

func TestExtractModelFromDeviceID(t *testing.T) {
	testCases := []struct {
		deviceID string
		expected string
	}{
		{"202BC1-HG8245H5-48575443xxxxxxxx", "HG8245H5"},
		{"ZTEGC0-F663N-ZTEGC0xxxxxxxx", "F663N"},
		{"Nokia-G-2426G-A-123456", "G"},
		{"SinglePart", "SinglePart"},
		{"", ""},
		{"OUI-Model", "Model"},
	}

	for _, tc := range testCases {
		t.Run(tc.deviceID, func(t *testing.T) {
			result := extractModelFromDeviceID(tc.deviceID)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractModelFromDeviceData(t *testing.T) {
	t.Run("From _deviceId._ProductClass", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"_deviceId": map[string]interface{}{
				"_ProductClass": "HG8245H5",
			},
		}
		result := extractModelFromDeviceData(deviceData)
		assert.Equal(t, "HG8245H5", result)
	})

	t.Run("From _id field", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"_id": "202BC1-F663N-48575443xxxxxxxx",
		}
		result := extractModelFromDeviceData(deviceData)
		assert.Equal(t, "F663N", result)
	})

	t.Run("From InternetGatewayDevice.DeviceInfo.ProductClass", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"DeviceInfo": map[string]interface{}{
					"ProductClass": map[string]interface{}{
						"_value": "EG8145X6",
					},
				},
			},
		}
		result := extractModelFromDeviceData(deviceData)
		assert.Equal(t, "EG8145X6", result)
	})

	t.Run("From InternetGatewayDevice.DeviceInfo.ModelName", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"DeviceInfo": map[string]interface{}{
					"ModelName": map[string]interface{}{
						"_value": "F670L",
					},
				},
			},
		}
		result := extractModelFromDeviceData(deviceData)
		assert.Equal(t, "F670L", result)
	})

	t.Run("Empty data returns empty string", func(t *testing.T) {
		deviceData := map[string]interface{}{}
		result := extractModelFromDeviceData(deviceData)
		assert.Equal(t, "", result)
	})
}

func TestDetectBandTypeFromWLANConfig(t *testing.T) {
	t.Run("Dual-band detected from WLAN 5", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"LANDevice": map[string]interface{}{
					"1": map[string]interface{}{
						"WLANConfiguration": map[string]interface{}{
							"1": map[string]interface{}{},
							"2": map[string]interface{}{},
							"5": map[string]interface{}{},
						},
					},
				},
			},
		}
		result := detectBandTypeFromWLANConfig(deviceData)
		assert.Equal(t, BandTypeDualBand, result)
	})

	t.Run("Single-band detected (no WLAN 5+)", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"LANDevice": map[string]interface{}{
					"1": map[string]interface{}{
						"WLANConfiguration": map[string]interface{}{
							"1": map[string]interface{}{},
							"2": map[string]interface{}{},
							"3": map[string]interface{}{},
							"4": map[string]interface{}{},
						},
					},
				},
			},
		}
		result := detectBandTypeFromWLANConfig(deviceData)
		assert.Equal(t, BandTypeSingleBand, result)
	})

	t.Run("Missing WLANConfiguration returns single-band", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"LANDevice": map[string]interface{}{
					"1": map[string]interface{}{},
				},
			},
		}
		result := detectBandTypeFromWLANConfig(deviceData)
		assert.Equal(t, BandTypeSingleBand, result)
	})

	t.Run("Missing LANDevice returns unknown", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{},
		}
		result := detectBandTypeFromWLANConfig(deviceData)
		assert.Equal(t, BandTypeUnknown, result)
	})

	t.Run("Missing InternetGatewayDevice returns unknown", func(t *testing.T) {
		deviceData := map[string]interface{}{}
		result := detectBandTypeFromWLANConfig(deviceData)
		assert.Equal(t, BandTypeUnknown, result)
	})
}

func TestGetWLANBandByID(t *testing.T) {
	testCases := []struct {
		wlanID   int
		expected string
	}{
		{1, Band2_4GHz},
		{2, Band2_4GHz},
		{3, Band2_4GHz},
		{4, Band2_4GHz},
		{5, Band5GHz},
		{6, Band5GHz},
		{7, Band5GHz},
		{8, Band5GHz},
		{9, BandUnknown}, // WLAN 9 is now out of range (max is 8)
		{0, BandUnknown},
		{10, BandUnknown},
		{-1, BandUnknown},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("WLAN_%d", tc.wlanID), func(t *testing.T) {
			result := getWLANBandByID(tc.wlanID)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetDeviceCapabilityHandler(t *testing.T) {
	// Mock device data for a dual-band device
	mockDualBandDeviceID := "202BC1-EG8145X6-48575443xxxxxxxx"
	mockDualBandDevice := `{
		"_id": "202BC1-EG8145X6-48575443xxxxxxxx",
		"_deviceId": {
			"_ProductClass": "EG8145X6"
		},
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}},
						"5": {"Enable": {"_value": true}}
					}
				}
			}
		}
	}`

	// Mock device data for a single-band device
	mockSingleBandDeviceID := "202BC1-HG8245H5-48575443xxxxxxxx"
	mockSingleBandDevice := `{
		"_id": "202BC1-HG8245H5-48575443xxxxxxxx",
		"_deviceId": {
			"_ProductClass": "HG8245H5"
		},
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}},
						"2": {"Enable": {"_value": true}}
					}
				}
			}
		}
	}`

	setupMockServer := func(deviceID, deviceResponse string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query().Get("query")
			lastInform := time.Now().UTC().Format(time.RFC3339)

			// Handle IP-based lookup (for ExtractDeviceIDByIP)
			if strings.Contains(query, "192.168.1.100") {
				w.WriteHeader(http.StatusOK)
				// Return minimal device info with _id for IP lookup
				response := fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, deviceID, lastInform)
				_, _ = w.Write([]byte(response))
				return
			}

			// Handle device ID-based lookup (for getDeviceData)
			if strings.Contains(query, deviceID) {
				w.WriteHeader(http.StatusOK)
				// Return full device data with _lastInform
				response := fmt.Sprintf(`[%s]`, strings.Replace(deviceResponse, `"_id"`, fmt.Sprintf(`"_lastInform": "%s", "_id"`, lastInform), 1))
				_, _ = w.Write([]byte(response))
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))
	}

	t.Run("Dual-band device capability", func(t *testing.T) {
		mockServer := setupMockServer(mockDualBandDeviceID, mockDualBandDevice)
		defer mockServer.Close()

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		originalLogger := logger
		originalCache := deviceCacheInstance

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

		r := chi.NewRouter()
		r.Get("/capability/{ip}", getDeviceCapabilityHandler)

		req := httptest.NewRequest("GET", "/capability/192.168.1.100", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)

		data := response["data"].(map[string]interface{})
		assert.Equal(t, "EG8145X6", data["model"])
		assert.Equal(t, "dualband", data["band_type"])
		assert.Equal(t, true, data["is_dual_band"])
	})

	t.Run("Single-band device capability", func(t *testing.T) {
		mockServer := setupMockServer(mockSingleBandDeviceID, mockSingleBandDevice)
		defer mockServer.Close()

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		originalLogger := logger
		originalCache := deviceCacheInstance

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

		r := chi.NewRouter()
		r.Get("/capability/{ip}", getDeviceCapabilityHandler)

		req := httptest.NewRequest("GET", "/capability/192.168.1.100", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)

		data := response["data"].(map[string]interface{})
		assert.Equal(t, "HG8245H5", data["model"])
		assert.Equal(t, "singleband", data["band_type"])
		assert.Equal(t, false, data["is_dual_band"])
	})

	t.Run("Device not found", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))
		defer mockServer.Close()

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		originalLogger := logger

		geniesBaseURL = mockServer.URL
		httpClient = mockServer.Client()
		logger, _ = zap.NewDevelopment()

		defer func() {
			geniesBaseURL = originalBaseURL
			httpClient = originalClient
			logger = originalLogger
		}()

		r := chi.NewRouter()
		r.Get("/capability/{ip}", getDeviceCapabilityHandler)

		req := httptest.NewRequest("GET", "/capability/192.168.255.255", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestCreateWLANHandler(t *testing.T) {
	// Mock dual-band device with existing WLAN 1
	mockDualBandDeviceID := "202BC1-EG8145X6-48575443xxxxxxxx"
	mockDualBandDevice := `{
		"_id": "202BC1-EG8145X6-48575443xxxxxxxx",
		"_deviceId": {
			"_ProductClass": "EG8145X6"
		},
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "ExistingSSID"}
						}
					}
				}
			}
		}
	}`

	// Mock single-band device
	mockSingleBandDeviceID := "202BC1-HG8245H5-48575443xxxxxxxx"
	mockSingleBandDevice := `{
		"_id": "202BC1-HG8245H5-48575443xxxxxxxx",
		"_deviceId": {
			"_ProductClass": "HG8245H5"
		},
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "ExistingSSID"}
						}
					}
				}
			}
		}
	}`

	setupTestEnv := func(deviceID, deviceResponse string) (*httptest.Server, func()) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/tasks") {
				w.WriteHeader(http.StatusOK)
				return
			}
			query := r.URL.Query().Get("query")
			lastInform := time.Now().UTC().Format(time.RFC3339)

			// Handle IP-based lookup (for ExtractDeviceIDByIP)
			if strings.Contains(query, "192.168.1.100") {
				w.WriteHeader(http.StatusOK)
				response := fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, deviceID, lastInform)
				_, _ = w.Write([]byte(response))
				return
			}

			// Handle device ID-based lookup (for getDeviceData)
			if strings.Contains(query, deviceID) {
				w.WriteHeader(http.StatusOK)
				response := fmt.Sprintf(`[%s]`, strings.Replace(deviceResponse, `"_id"`, fmt.Sprintf(`"_lastInform": "%s", "_id"`, lastInform), 1))
				_, _ = w.Write([]byte(response))
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		originalLogger := logger
		originalCache := deviceCacheInstance
		originalWorkerPool := taskWorkerPool

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

		cleanup := func() {
			taskWorkerPool.Stop()
			mockServer.Close()
			geniesBaseURL = originalBaseURL
			httpClient = originalClient
			logger = originalLogger
			deviceCacheInstance = originalCache
			taskWorkerPool = originalWorkerPool
		}

		return mockServer, cleanup
	}

	t.Run("Success - Create WLAN 2 on dual-band", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "NewWiFi", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/2/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "NewWiFi")
	})

	t.Run("Success - Create WLAN 5 on dual-band (5GHz)", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "WiFi5GHz", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/5/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, rr.Body.String(), "WiFi5GHz")
		assert.Contains(t, rr.Body.String(), "5GHz")
	})

	t.Run("Fail - Create WLAN 5 on single-band device", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockSingleBandDeviceID, mockSingleBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "WiFi5GHz", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/5/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		// Error message is sanitized to not expose device details
		assert.Contains(t, rr.Body.String(), "does not support 5GHz WLAN")
	})

	t.Run("Fail - WLAN ID out of range (0)", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "Test", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/0/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail - WLAN ID out of range (10)", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "Test", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/10/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail - Invalid WLAN ID (non-numeric)", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "Test", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/abc/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Fail - Missing SSID", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/2/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "SSID")
	})

	t.Run("Fail - Missing password", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "TestWiFi"}`
		req := httptest.NewRequest("POST", "/wlan/create/2/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Password")
	})

	t.Run("Fail - Password too short", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "TestWiFi", "password": "short"}`
		req := httptest.NewRequest("POST", "/wlan/create/2/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "8 characters")
	})

	t.Run("Fail - SSID too long", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		longSSID := strings.Repeat("a", 33)
		body := fmt.Sprintf(`{"ssid": "%s", "password": "SecurePassword123"}`, longSSID)
		req := httptest.NewRequest("POST", "/wlan/create/2/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "32 characters")
	})

	t.Run("Fail - Existing WLAN conflict", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "TestWiFi", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/1/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusConflict, rr.Code)
		assert.Contains(t, rr.Body.String(), "already exists")
	})

	t.Run("Fail - Invalid JSON", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{invalid json}`
		req := httptest.NewRequest("POST", "/wlan/create/2/192.168.1.100", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid JSON")
	})

	t.Run("Fail - Device not found", func(t *testing.T) {
		_, cleanup := setupTestEnv(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		r := chi.NewRouter()
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)

		body := `{"ssid": "TestWiFi", "password": "SecurePassword123"}`
		req := httptest.NewRequest("POST", "/wlan/create/2/192.168.255.255", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestModelNormalizationWithVersionSuffix(t *testing.T) {
	// Test that models with version suffixes are correctly identified
	testCases := []struct {
		model    string
		expected bool
	}{
		// Test partial matching for versions
		{"F609V3", true},
		{"F609 V3", true},
		{"F609V4", true},
		{"F609 V4", true},
		{"F660V7", true},
		{"F660 V7", true},
	}

	for _, tc := range testCases {
		t.Run(tc.model, func(t *testing.T) {
			result := isDualBandModel(tc.model)
			assert.Equal(t, tc.expected, result, "model: %s should be dual-band", tc.model)
		})
	}
}

func TestBandTypeConstants(t *testing.T) {
	// Verify band type constants are correct
	assert.Equal(t, BandType("singleband"), BandTypeSingleBand)
	assert.Equal(t, BandType("dualband"), BandTypeDualBand)
	assert.Equal(t, BandType("unknown"), BandTypeUnknown)
}

func TestWLANIDRangeConstants(t *testing.T) {
	// Verify WLAN ID range constants are correct
	assert.Equal(t, 1, WLAN24GHzMin)
	assert.Equal(t, 4, WLAN24GHzMax)
	assert.Equal(t, 5, WLAN5GHzMin)
	assert.Equal(t, 8, WLAN5GHzMax)
}

// TestIsDualBandModelPartialMatch tests partial matching logic for dual-band models
func TestIsDualBandModelPartialMatch(t *testing.T) {
	testCases := []struct {
		model    string
		expected bool
		desc     string
	}{
		// Model with extra version suffix (partial match should work)
		{"F670LExtraVersion", true, "F670L with extra suffix"},
		{"HG8145V5Pro", true, "HG8145V5 with Pro suffix"},
		{"EG8145X6Custom", true, "EG8145X6 with Custom suffix"},
		// Exact matches still work
		{"F670L", true, "Exact match F670L"},
		{"HG8145V5", true, "Exact match HG8145V5"},
		// Normalized lookup tests (lowercase input matching uppercase key)
		{"f670l", true, "Lowercase model matching via normalization"},
		{"hg8145v5", true, "Lowercase HG8145V5 via normalization"},
		{"eg8145x6", true, "Lowercase EG8145X6 via normalization"},
		// Model with spaces/hyphens that normalize to known model
		{"F-670-L", true, "Model with hyphens normalizing to F670L"},
		{"HG 8145V5", true, "Model with space normalizing to HG8145V5"},
		// Models that shouldn't match (unknown)
		{"SomeUnknownModel", false, "Unknown model"},
		{"RandomDevice", false, "Random device"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := isDualBandModel(tc.model)
			assert.Equal(t, tc.expected, result, "model: %s", tc.model)
		})
	}
}

// TestIsSingleBandModelPartialMatch tests partial matching logic for single-band models
func TestIsSingleBandModelPartialMatch(t *testing.T) {
	testCases := []struct {
		model    string
		expected bool
		desc     string
	}{
		// Model with extra version suffix (partial match should work)
		{"F663NExtra", true, "F663N with extra suffix"},
		{"HG8245H5Pro", true, "HG8245H5 with Pro suffix"},
		{"F609Custom", true, "F609 with custom suffix"},
		// Exact matches still work
		{"F663N", true, "Exact match F663N"},
		{"HG8245H", true, "Exact match HG8245H"},
		// Normalized lookup tests (lowercase input matching uppercase key)
		{"f663n", true, "Lowercase model matching via normalization"},
		{"hg8245h", true, "Lowercase HG8245H via normalization"},
		{"f609", true, "Lowercase F609 via normalization"},
		// Model with spaces/hyphens that normalize to known model
		{"F-663-N", true, "Model with hyphens normalizing to F663N"},
		{"HG 8245H", true, "Model with space normalizing to HG8245H"},
		// Models that shouldn't match (unknown)
		{"SomeUnknownModel", false, "Unknown model"},
		{"RandomDevice", false, "Random device"},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := isSingleBandModel(tc.model)
			assert.Equal(t, tc.expected, result, "model: %s", tc.model)
		})
	}
}

// TestDetectBandTypeFromWLANConfigEdgeCases tests edge cases for detectBandTypeFromWLANConfig
func TestDetectBandTypeFromWLANConfigEdgeCases(t *testing.T) {
	t.Run("WLAN config with non-numeric keys only", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"LANDevice": map[string]interface{}{
					"1": map[string]interface{}{
						"WLANConfiguration": map[string]interface{}{
							"wlan_a": map[string]interface{}{},
							"wlan_b": map[string]interface{}{},
							"abc":    map[string]interface{}{},
						},
					},
				},
			},
		}
		result := detectBandTypeFromWLANConfig(deviceData)
		// Should return single-band since no numeric key >= 5 found
		assert.Equal(t, BandTypeSingleBand, result)
	})

	t.Run("Missing LANDevice.1 returns unknown", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"LANDevice": map[string]interface{}{
					"2": map[string]interface{}{
						"WLANConfiguration": map[string]interface{}{
							"5": map[string]interface{}{},
						},
					},
				},
			},
		}
		result := detectBandTypeFromWLANConfig(deviceData)
		assert.Equal(t, BandTypeUnknown, result)
	})

	t.Run("WLAN config with mixed keys (numeric and non-numeric)", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"InternetGatewayDevice": map[string]interface{}{
				"LANDevice": map[string]interface{}{
					"1": map[string]interface{}{
						"WLANConfiguration": map[string]interface{}{
							"1":      map[string]interface{}{},
							"notnum": map[string]interface{}{},
							"6":      map[string]interface{}{}, // This should trigger dual-band
						},
					},
				},
			},
		}
		result := detectBandTypeFromWLANConfig(deviceData)
		assert.Equal(t, BandTypeDualBand, result)
	})
}

// TestValidateWLANIDForDeviceEdgeCases tests edge cases for validateWLANIDForDevice
func TestValidateWLANIDForDeviceEdgeCases(t *testing.T) {
	// Setup mock server for dual-band device
	mockDualBandDeviceID := "202BC1-EG8145X6-48575443xxxxxxxx"
	mockDualBandDevice := `{
		"_id": "202BC1-EG8145X6-48575443xxxxxxxx",
		"_deviceId": {
			"_ProductClass": "EG8145X6"
		},
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}},
						"5": {"Enable": {"_value": true}}
					}
				}
			}
		}
	}`

	setupMockServer := func(deviceID, deviceResponse string) (*httptest.Server, func()) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query().Get("query")
			lastInform := time.Now().UTC().Format(time.RFC3339)

			if strings.Contains(query, deviceID) {
				w.WriteHeader(http.StatusOK)
				response := fmt.Sprintf(`[%s]`, strings.Replace(deviceResponse, `"_id"`, fmt.Sprintf(`"_lastInform": "%s", "_id"`, lastInform), 1))
				_, _ = w.Write([]byte(response))
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))

		originalBaseURL := geniesBaseURL
		originalClient := httpClient
		originalLogger := logger
		originalCache := deviceCacheInstance

		geniesBaseURL = mockServer.URL
		httpClient = mockServer.Client()
		logger, _ = zap.NewDevelopment()
		deviceCacheInstance = &deviceCache{
			data:    make(map[string]cachedDeviceData),
			timeout: 30 * time.Second,
		}

		cleanup := func() {
			mockServer.Close()
			geniesBaseURL = originalBaseURL
			httpClient = originalClient
			logger = originalLogger
			deviceCacheInstance = originalCache
		}

		return mockServer, cleanup
	}

	t.Run("WLAN ID below valid range (0)", func(t *testing.T) {
		_, cleanup := setupMockServer(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		err := validateWLANIDForDevice(context.Background(), mockDualBandDeviceID, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be between")
	})

	t.Run("WLAN ID above valid range (9)", func(t *testing.T) {
		_, cleanup := setupMockServer(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		err := validateWLANIDForDevice(context.Background(), mockDualBandDeviceID, 9)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be between")
	})

	t.Run("WLAN ID negative", func(t *testing.T) {
		_, cleanup := setupMockServer(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		err := validateWLANIDForDevice(context.Background(), mockDualBandDeviceID, -1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be between")
	})

	t.Run("Valid WLAN ID for dual-band device (5GHz range)", func(t *testing.T) {
		_, cleanup := setupMockServer(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		err := validateWLANIDForDevice(context.Background(), mockDualBandDeviceID, 5)
		assert.NoError(t, err)
	})

	t.Run("Device not found", func(t *testing.T) {
		_, cleanup := setupMockServer(mockDualBandDeviceID, mockDualBandDevice)
		defer cleanup()

		err := validateWLANIDForDevice(context.Background(), "NonExistentDevice", 1)
		assert.Error(t, err)
		// Error message is sanitized to not expose internal details
		assert.Contains(t, err.Error(), "unable to verify device capability")
	})
}

// TestGetDeviceCapabilityWithUnknownBandType tests device capability retrieval with unknown model
func TestGetDeviceCapabilityWithUnknownBandType(t *testing.T) {
	// Test with a device that has unknown model but WLAN config indicating dual-band
	mockUnknownDeviceID := "202BC1-UnknownModelXYZ-48575443xxxxxxxx"
	mockUnknownDevice := `{
		"_id": "202BC1-UnknownModelXYZ-48575443xxxxxxxx",
		"_deviceId": {
			"_ProductClass": "UnknownModelXYZ"
		},
		"InternetGatewayDevice": {
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}},
						"2": {"Enable": {"_value": true}},
						"5": {"Enable": {"_value": true}},
						"6": {"Enable": {"_value": true}}
					}
				}
			}
		}
	}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		lastInform := time.Now().UTC().Format(time.RFC3339)

		if strings.Contains(query, mockUnknownDeviceID) {
			w.WriteHeader(http.StatusOK)
			response := fmt.Sprintf(`[%s]`, strings.Replace(mockUnknownDevice, `"_id"`, fmt.Sprintf(`"_lastInform": "%s", "_id"`, lastInform), 1))
			_, _ = w.Write([]byte(response))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer mockServer.Close()

	originalBaseURL := geniesBaseURL
	originalClient := httpClient
	originalLogger := logger
	originalCache := deviceCacheInstance

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

	t.Run("Unknown model detected as dual-band from WLAN config", func(t *testing.T) {
		capability, err := getDeviceCapability(context.Background(), mockUnknownDeviceID)
		assert.NoError(t, err)
		assert.NotNil(t, capability)
		assert.Equal(t, "UnknownModelXYZ", capability.Model)
		assert.Equal(t, BandTypeDualBand, capability.BandType)
		assert.True(t, capability.IsDualBand)
	})
}
