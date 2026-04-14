package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- Device Handler Tests (DHCP, Password, Capability) ---

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

func TestGetDeviceIDByIPEdgeCases_Placeholder(t *testing.T) {
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

// TestGetDeviceIDByIPNonOKStatusHandler tests non-OK status from GenieACS via handler
func TestGetDeviceIDByIPNonOKStatusHandler(t *testing.T) {
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

// TestGetDeviceIDByIPInvalidJSONHandler tests invalid JSON response from GenieACS via handler
func TestGetDeviceIDByIPInvalidJSONHandler(t *testing.T) {
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

// --- v2.1.0 handler tests (reboot, refreshDHCP, opticalStats) ---

func mockDeviceLookupHandler(t *testing.T, statusForTasks int) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/devices") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(statusForTasks)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
}

func TestRebootDeviceHandler_Success(t *testing.T) {
	_, router := setupTestServer(t, mockDeviceLookupHandler(t, http.StatusOK))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/genieacs/reboot/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "Reboot")
}

func TestRebootDeviceHandler_NBIFailure(t *testing.T) {
	_, router := setupTestServer(t, mockDeviceLookupHandler(t, http.StatusInternalServerError))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/genieacs/reboot/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRebootDeviceHandler_InvalidIP(t *testing.T) {
	_, router := setupTestServer(t, mockDeviceLookupHandler(t, http.StatusOK))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/genieacs/reboot/not-an-ip", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.NotEqual(t, http.StatusAccepted, rr.Code)
}

func TestRefreshDHCPHandler_Success(t *testing.T) {
	_, router := setupTestServer(t, mockDeviceLookupHandler(t, http.StatusOK))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/genieacs/dhcp/"+mockDeviceIP+"/refresh", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "DHCP")
}

func TestRefreshDHCPHandler_NBIFailure(t *testing.T) {
	_, router := setupTestServer(t, mockDeviceLookupHandler(t, http.StatusInternalServerError))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/genieacs/dhcp/"+mockDeviceIP+"/refresh", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRefreshDHCPHandler_InvalidIP(t *testing.T) {
	_, router := setupTestServer(t, mockDeviceLookupHandler(t, http.StatusOK))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/genieacs/dhcp/bad.ip/refresh", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.NotEqual(t, http.StatusAccepted, rr.Code)
}

// opticalDeviceHandlerZTE responds to the device-data lookup with a ZTE
// CT-COM EPON optical tree so getOpticalStats returns successfully.
func opticalDeviceHandlerZTE(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/devices") {
			body := `[{
				"_id": "` + mockDeviceID + `",
				"_lastInform": "2026-04-15T13:00:00.000Z",
				"InternetGatewayDevice": {
					"X_CT-COM_EponInterfaceConfig": {
						"Stats": {
							"TxPower":     {"_value": 2.5,  "_type": "xsd:float"},
							"RxPower":     {"_value": -21.3,"_type": "xsd:float"},
							"Temperature": {"_value": 45.0, "_type": "xsd:float"},
							"Voltage":     {"_value": 3.3,  "_type": "xsd:float"},
							"BiasCurrent": {"_value": 12.0, "_type": "xsd:float"}
						}
					}
				}
			}]`
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			_, _ = w.Write([]byte(body))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
}

func TestGetOpticalStatsHandler_Success(t *testing.T) {
	_, router := setupTestServer(t, opticalDeviceHandlerZTE(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/optical/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "rx_power_dbm")
}

func TestGetOpticalStatsHandler_WithRefresh(t *testing.T) {
	_, router := setupTestServer(t, opticalDeviceHandlerZTE(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/optical/"+mockDeviceIP+"?refresh=true", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestGetOpticalStatsHandler_RefreshFailure(t *testing.T) {
	_, router := setupTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/devices") {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/optical/"+mockDeviceIP+"?refresh=true", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestGetOpticalStatsHandler_NotSupported(t *testing.T) {
	_, router := setupTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/devices") {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			_, _ = w.Write([]byte(`[{"_id":"` + mockDeviceID + `","InternetGatewayDevice":{}}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/optical/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "OPTICAL_NOT_SUPPORTED")
}

func TestGetOpticalStatsHandler_GenericError(t *testing.T) {
	_, router := setupTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/devices") {
			if strings.Contains(r.URL.Query().Get("projection"), "_id") {
				_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/optical/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestGetOpticalStatsHandler_InvalidIP(t *testing.T) {
	_, router := setupTestServer(t, opticalDeviceHandlerZTE(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/optical/not-an-ip", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.NotEqual(t, http.StatusOK, rr.Code)
}
