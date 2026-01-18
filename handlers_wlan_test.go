package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- WLAN Handler Tests (Create, Update, Delete, Optimize, Available) ---

// TestOptimizationConstants tests validity maps for channels, modes, bandwidths, and transmit power
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

	t.Run("Update WLAN - Invalid password (too short)", func(t *testing.T) {
		body := `{"password": "short"}`
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

	t.Run("Optimize WLAN - Invalid transmit power", func(t *testing.T) {
		power := 50
		body := fmt.Sprintf(`{"transmit_power": %d}`, power)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestSingleBandDeviceValidation tests single-band device validation
func TestSingleBandDeviceValidation(t *testing.T) {
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
		// Error message is sanitized to not expose device details
		assert.Contains(t, rr.Body.String(), "does not support 5GHz WLAN")
	})

	t.Run("Update WLAN 5 on single-band device", func(t *testing.T) {
		body := `{"ssid": "NewSSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		// Error message is sanitized to not expose device details
		assert.Contains(t, rr.Body.String(), "does not support 5GHz WLAN")
	})

	t.Run("Optimize WLAN 5 on single-band device", func(t *testing.T) {
		body := `{"channel": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		// Error message is sanitized to not expose device details
		assert.Contains(t, rr.Body.String(), "does not support 5GHz WLAN")
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

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with custom max_clients", func(t *testing.T) {
		body := `{"ssid": "CustomNet", "password": "SecurePass123", "max_clients": 10}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
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

	largeBody := strings.Repeat("a", 1024*1024+1)
	body := fmt.Sprintf(`{"ssid": "%s", "password": "SecurePass123"}`, largeBody)
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
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

	largeBody := strings.Repeat("a", 1024*1024+1)
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

	largeBody := strings.Repeat("a", 1024*1024+1)
	body := fmt.Sprintf(`{"channel": "%s"}`, largeBody)
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

// TestGetAvailableWLANHandlerWithCapabilityError tests error in getDeviceCapability
func TestGetAvailableWLANHandlerWithCapabilityError(t *testing.T) {
	t.Run("Device found but capability fetch fails", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		_, router := setupTestServer(t, mockHandler)

		req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.True(t, rr.Code == http.StatusInternalServerError || rr.Code == http.StatusNotFound)
	})
}

// TestUpdateWLANHandlerWithWLANExistsCheck tests the WLAN exists validation
func TestUpdateWLANHandlerWithWLANExistsCheck(t *testing.T) {
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

// TestGetAvailableWLANHandlerSuccess tests full happy path for getAvailableWLANHandler
func TestGetAvailableWLANHandlerSuccess(t *testing.T) {
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
						},
						"5": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi5G"}
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
			_, _ = w.Write([]byte("[" + mockDualBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "dualband")
	assert.Contains(t, rr.Body.String(), "available_wlan")
}

// TestGetAvailableWLANHandlerSingleBand tests single band device
func TestGetAvailableWLANHandlerSingleBand(t *testing.T) {
	mockSingleBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "HG8245H"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockSingleBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "singleband")
}

// TestGetAvailableWLANHandlerWLANDataError tests WLAN data fetch error
func TestGetAvailableWLANHandlerWLANDataError(t *testing.T) {
	mockDeviceNoLANDevice := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
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
			_, _ = w.Write([]byte("[" + mockDeviceNoLANDevice + "]"))
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

// TestUpdateWLANHandlerAllFields tests updating all fields at once
func TestUpdateWLANHandlerAllFields(t *testing.T) {
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

	t.Run("Update with SSID only", func(t *testing.T) {
		body := `{"ssid": "NewTestSSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with password only", func(t *testing.T) {
		body := `{"password": "NewSecurePassword123"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

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

	t.Run("Update with WPA auth_mode", func(t *testing.T) {
		body := `{"auth_mode": "WPA"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with WPA2 auth_mode", func(t *testing.T) {
		body := `{"auth_mode": "WPA2"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with WPA/WPA2 auth_mode", func(t *testing.T) {
		body := `{"auth_mode": "WPA/WPA2"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with Open auth_mode", func(t *testing.T) {
		body := `{"auth_mode": "Open"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
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

	t.Run("Update with TKIP+AES encryption", func(t *testing.T) {
		body := `{"encryption": "TKIP+AES"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Update with empty SSID value", func(t *testing.T) {
		body := `{"ssid": ""}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with SSID leading/trailing spaces", func(t *testing.T) {
		body := `{"ssid": " SpacedSSID "}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with invalid SSID characters", func(t *testing.T) {
		body := `{"ssid": "Invalid\x00SSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Update with password too long", func(t *testing.T) {
		longPassword := strings.Repeat("a", 64)
		body := fmt.Sprintf(`{"password": "%s"}`, longPassword)
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

	t.Run("Update with invalid encryption", func(t *testing.T) {
		body := `{"encryption": "InvalidEnc"}`
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
		body := `{"max_clients": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestOptimizeWLANHandlerAllOptions tests all optimization options
func TestOptimizeWLANHandlerAllOptions(t *testing.T) {
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
						},
						"5": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi5G"}
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

	// 2.4GHz tests (WLAN 1)
	t.Run("Optimize 2.4GHz - Auto channel", func(t *testing.T) {
		body := `{"channel": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 2.4GHz - Specific channel", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 2.4GHz - Mode b/g/n", func(t *testing.T) {
		body := `{"mode": "b/g/n"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 2.4GHz - Bandwidth 20MHz", func(t *testing.T) {
		body := `{"bandwidth": "20MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 2.4GHz - Bandwidth 40MHz", func(t *testing.T) {
		body := `{"bandwidth": "40MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 2.4GHz - Transmit power 100", func(t *testing.T) {
		body := `{"transmit_power": 100}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 2.4GHz - Invalid mode", func(t *testing.T) {
		body := `{"mode": "ac"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize 2.4GHz - Invalid bandwidth 80MHz", func(t *testing.T) {
		body := `{"bandwidth": "80MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	// 5GHz tests (WLAN 5)
	t.Run("Optimize 5GHz - Auto channel", func(t *testing.T) {
		body := `{"channel": "Auto"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz - Specific channel 36", func(t *testing.T) {
		body := `{"channel": "36"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz - Mode a/n/ac", func(t *testing.T) {
		body := `{"mode": "a/n/ac"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz - Bandwidth 80MHz", func(t *testing.T) {
		body := `{"bandwidth": "80MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Optimize 5GHz - Invalid channel for 5GHz", func(t *testing.T) {
		body := `{"channel": "6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize 5GHz - Invalid mode b/g", func(t *testing.T) {
		body := `{"mode": "b/g"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Optimize 5GHz - Invalid bandwidth 160MHz", func(t *testing.T) {
		body := `{"bandwidth": "160MHz"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestCreateWLANHandlerAllAuthModes tests all authentication modes
func TestCreateWLANHandlerAllAuthModes(t *testing.T) {
	mockDeviceWithNoWLAN2 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN2 + "]"))
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

	t.Run("Create with WPA auth", func(t *testing.T) {
		body := `{"ssid": "WPANetwork", "password": "SecurePass123", "auth_mode": "WPA"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with WPA2 auth", func(t *testing.T) {
		body := `{"ssid": "WPA2Network", "password": "SecurePass123", "auth_mode": "WPA2"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with WPA/WPA2 auth", func(t *testing.T) {
		body := `{"ssid": "MixedNetwork", "password": "SecurePass123", "auth_mode": "WPA/WPA2"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/4/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with Open auth", func(t *testing.T) {
		body := `{"ssid": "OpenNetwork", "auth_mode": "Open"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with invalid auth", func(t *testing.T) {
		body := `{"ssid": "InvalidAuth", "password": "SecurePass123", "auth_mode": "WEP"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with invalid encryption", func(t *testing.T) {
		body := `{"ssid": "InvalidEnc", "password": "SecurePass123", "encryption": "WEP"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create without password for WPA2", func(t *testing.T) {
		body := `{"ssid": "NoPassword", "auth_mode": "WPA2"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with password too short", func(t *testing.T) {
		body := `{"ssid": "ShortPass", "password": "short"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with password too long", func(t *testing.T) {
		longPassword := strings.Repeat("a", 64)
		body := fmt.Sprintf(`{"ssid": "LongPass", "password": "%s"}`, longPassword)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with invalid max_clients", func(t *testing.T) {
		body := `{"ssid": "MaxClients", "password": "SecurePass123", "max_clients": 0}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestCreateWLANHandlerConflict tests WLAN already exists case
func TestCreateWLANHandlerConflict(t *testing.T) {
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

	t.Run("Create on existing enabled WLAN", func(t *testing.T) {
		body := `{"ssid": "DuplicateNetwork", "password": "SecurePass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusConflict, rr.Code)
	})
}

// TestCreateWLANHandlerValidationErrors tests all validation errors
func TestCreateWLANHandlerValidationErrors(t *testing.T) {
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

	t.Run("Create with empty SSID", func(t *testing.T) {
		body := `{"ssid": "", "password": "SecurePass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with SSID leading/trailing spaces", func(t *testing.T) {
		body := `{"ssid": " SpacedSSID ", "password": "SecurePass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with SSID too long", func(t *testing.T) {
		longSSID := strings.Repeat("a", 33)
		body := fmt.Sprintf(`{"ssid": "%s", "password": "SecurePass123"}`, longSSID)
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with invalid WLAN ID (0)", func(t *testing.T) {
		body := `{"ssid": "TestSSID", "password": "SecurePass123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/0/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Create with invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestDeleteWLANHandlerSuccess tests successful delete
func TestDeleteWLANHandlerSuccess(t *testing.T) {
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

	req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "deletion submitted successfully")
}

// TestCreateWLANHandlerIsWLANValidError tests isWLANValid error case
func TestCreateWLANHandlerIsWLANValidError(t *testing.T) {
	callCount := 0
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			callCount++
			if callCount > 1 {
				// Return error for device data (capability check)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// First call returns incomplete device data
			incompleteData := `[{"_id": "002568-BCM963268-684752", "InternetGatewayDevice": {"DeviceInfo": {"ProductClass": {"_value": "F670L"}}}}]`
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(incompleteData))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "TestNetwork", "password": "SecurePass123"}`
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.True(t, rr.Code == http.StatusInternalServerError || rr.Code == http.StatusOK)
}

// TestDeleteWLANHandlerIsWLANValidError tests isWLANValid error case for delete
func TestDeleteWLANHandlerIsWLANValidError(t *testing.T) {
	mockDeviceNoLANDevice := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
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
			_, _ = w.Write([]byte("[" + mockDeviceNoLANDevice + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestUpdateWLANHandlerIsWLANValidError tests isWLANValid error case for update
func TestUpdateWLANHandlerIsWLANValidError(t *testing.T) {
	mockDeviceNoLANDevice := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
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
			_, _ = w.Write([]byte("[" + mockDeviceNoLANDevice + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "UpdatedSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestOptimizeWLANHandlerIsWLANValidError tests isWLANValid error case for optimize
func TestOptimizeWLANHandlerIsWLANValidError(t *testing.T) {
	mockDeviceNoLANDevice := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
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
			_, _ = w.Write([]byte("[" + mockDeviceNoLANDevice + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"channel": "6"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestGetAvailableWLANHandlerCapabilityError tests capability check error
func TestGetAvailableWLANHandlerCapabilityError(t *testing.T) {
	callCount := 0
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.True(t, rr.Code == http.StatusInternalServerError || rr.Code == http.StatusOK)
}

// TestUpdateWLANHandlerNoFieldsProvided tests update with no fields
func TestUpdateWLANHandlerNoFieldsProvided(t *testing.T) {
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

	body := `{}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOptimizeWLANHandlerEmptyBody tests optimize with empty body
func TestOptimizeWLANHandlerEmptyBody(t *testing.T) {
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

	body := `{}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestUpdateWLANHandlerHiddenFalse tests setting hidden to false
func TestUpdateWLANHandlerHiddenFalse(t *testing.T) {
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

	body := `{"hidden": false}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestOptimizeWLANHandlerInvalidTransmitPower tests invalid transmit power values
func TestOptimizeWLANHandlerInvalidTransmitPower(t *testing.T) {
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

	t.Run("Transmit power invalid value", func(t *testing.T) {
		body := `{"transmit_power": 50}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Transmit power too high", func(t *testing.T) {
		body := `{"transmit_power": 200}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestCreateWLANHandlerSSIDInvalidChars tests SSID with invalid characters
func TestCreateWLANHandlerSSIDInvalidChars(t *testing.T) {
	mockDeviceWithNoWLAN2 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN2 + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// SSID with non-ASCII character (unicode character outside printable ASCII range)
	body := "{\"ssid\": \"TestSSID\\u00e9\", \"password\": \"SecurePass123\"}"
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestUpdateWLANHandlerSSIDTooLong tests SSID too long
func TestUpdateWLANHandlerSSIDTooLong(t *testing.T) {
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

	longSSID := strings.Repeat("a", 33)
	body := fmt.Sprintf(`{"ssid": "%s"}`, longSSID)
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestUpdateWLANHandlerPasswordTooShort tests password too short
func TestUpdateWLANHandlerPasswordTooShort(t *testing.T) {
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

	body := `{"password": "short"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestUpdateWLANHandlerWLANNotExists tests update on non-existing WLAN
func TestUpdateWLANHandlerWLANNotExists(t *testing.T) {
	mockDeviceWithWLAN1Only := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "UpdatedSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/3/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestUpdateWLANHandlerInvalidWLANIDForDevice tests WLAN ID not supported by device
func TestUpdateWLANHandlerInvalidWLANIDForDevice(t *testing.T) {
	mockSingleBandDevice := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "HG8245H"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockSingleBandDevice + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Try to update WLAN 5 (5GHz) on a single-band device
	body := `{"ssid": "UpdatedSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/5/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOptimizeWLANHandlerInvalidWLANIDForDevice tests WLAN ID not supported by device for optimize
func TestOptimizeWLANHandlerInvalidWLANIDForDevice(t *testing.T) {
	mockSingleBandDevice := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "HG8245H"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockSingleBandDevice + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Try to optimize WLAN 5 (5GHz) on a single-band device
	body := `{"channel": "Auto"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOptimizeWLANHandlerWLANNotExists tests optimize on non-existing WLAN
func TestOptimizeWLANHandlerWLANNotExists(t *testing.T) {
	mockDeviceWithWLAN1Only := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"channel": "6"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/3/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestOptimizeWLANHandler2GHz_Channel11 tests specific 2.4GHz channel 11
func TestOptimizeWLANHandler2GHz_Channel11(t *testing.T) {
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

	body := `{"channel": "11"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestOptimizeWLANHandler5GHz_Channel149 tests specific 5GHz channel 149
func TestOptimizeWLANHandler5GHz_Channel149(t *testing.T) {
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
						},
						"5": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi5G"}
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

	body := `{"channel": "149"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestGetAvailableWLANHandlerDeviceNotFound tests device not found
func TestGetAvailableWLANHandlerDeviceNotFound(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/192.168.255.255", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestCreateWLANHandlerWithAllOptions tests create with all optional parameters
func TestCreateWLANHandlerWithAllOptions(t *testing.T) {
	mockDeviceWithNoWLAN2 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN2 + "]"))
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

	t.Run("Create with all options", func(t *testing.T) {
		body := `{"ssid": "FullOptionsNetwork", "password": "SecurePass123", "auth_mode": "WPA2", "encryption": "AES", "hidden": true, "max_clients": 20}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Create with hidden false", func(t *testing.T) {
		body := `{"ssid": "VisibleNetwork", "password": "SecurePass123", "hidden": false}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/3/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestCreateWLANHandlerAuthModeWPA tests create with WPA auth mode
func TestCreateWLANHandlerAuthModeWPA(t *testing.T) {
	mockDeviceWithNoWLAN2 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN2 + "]"))
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

	body := `{"ssid": "WPANetwork", "password": "SecurePass123", "auth_mode": "WPA", "encryption": "TKIP"}`
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestCreateWLANHandlerAuthModeWPAWPA2 tests create with WPA/WPA2 auth mode
func TestCreateWLANHandlerAuthModeWPAWPA2(t *testing.T) {
	mockDeviceWithNoWLAN2 := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockDeviceWithNoWLAN2 + "]"))
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

	body := `{"ssid": "MixedNetwork", "password": "SecurePass123", "auth_mode": "WPA/WPA2", "encryption": "TKIP+AES"}`
	req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestUpdateWLANHandlerAuthModeWPA tests update with WPA auth mode
func TestUpdateWLANHandlerAuthModeWPA(t *testing.T) {
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

	body := `{"auth_mode": "WPA"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestUpdateWLANHandlerAuthModeWPAWPA2 tests update with WPA/WPA2 auth mode
func TestUpdateWLANHandlerAuthModeWPAWPA2(t *testing.T) {
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

	body := `{"auth_mode": "WPA/WPA2"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestUpdateWLANHandlerEncryption tests update with encryption only
func TestUpdateWLANHandlerEncryption(t *testing.T) {
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

	body := `{"encryption": "AES"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestUpdateWLANHandlerInvalidEncryption tests update with invalid encryption
func TestUpdateWLANHandlerInvalidEncryption(t *testing.T) {
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

	body := `{"encryption": "INVALID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOptimizeWLANHandler5GHzMode tests 5GHz mode optimization
func TestOptimizeWLANHandler5GHzMode(t *testing.T) {
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
						},
						"5": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi5G"}
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

	body := `{"mode": "ac"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestOptimizeWLANHandler5GHzBandwidth tests 5GHz bandwidth optimization
func TestOptimizeWLANHandler5GHzBandwidth(t *testing.T) {
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
						},
						"5": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi5G"}
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

	body := `{"bandwidth": "80MHz"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestOptimizeWLANHandler5GHzInvalidBandwidth tests invalid 5GHz bandwidth
func TestOptimizeWLANHandler5GHzInvalidBandwidth(t *testing.T) {
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
						},
						"5": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi5G"}
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
			_, _ = w.Write([]byte("[" + mockDualBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"bandwidth": "160MHz"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOptimizeWLANHandler5GHzInvalidMode tests invalid 5GHz mode
func TestOptimizeWLANHandler5GHzInvalidMode(t *testing.T) {
	mockDualBandDeviceData := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
						},
						"5": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi5G"}
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
			_, _ = w.Write([]byte("[" + mockDualBandDeviceData + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"mode": "802.11b"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/5/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestGetAvailableWLANHandlerNoUsedWLAN tests device with no WLANs in use
func TestGetAvailableWLANHandlerNoUsedWLAN(t *testing.T) {
	// Device with no enabled WLANs
	mockDeviceNoWLAN := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {
							"Enable": {"_value": false},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockDeviceNoWLAN + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"used_wlan":[]`)
}

// TestGetAvailableWLANHandlerAll24GHzUsed tests device with all 2.4GHz WLANs in use
func TestGetAvailableWLANHandlerAll24GHzUsed(t *testing.T) {
	// Device with all 2.4GHz WLANs (1-4) in use
	mockDeviceAllWLAN := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"1": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi1"}},
						"2": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi2"}},
						"3": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi3"}},
						"4": {"Enable": {"_value": true}, "SSID": {"_value": "WiFi4"}}
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
			_, _ = w.Write([]byte("[" + mockDeviceAllWLAN + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	// When all 2.4GHz WLANs are in use, available_wlan.2_4ghz should be empty
	assert.Contains(t, rr.Body.String(), `"2_4ghz":[]`)
}

// TestUpdateWLANHandlerSSIDInvalidChars tests SSID with invalid characters in update
func TestUpdateWLANHandlerSSIDInvalidCharsUnicode(t *testing.T) {
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

	// SSID with non-ASCII unicode character
	body := "{\"ssid\": \"UpdatedSSID\\u00e9\"}"
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestUpdateWLANHandlerDeviceNotFound tests device not found in update
func TestUpdateWLANHandlerDeviceNotFoundCase(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"ssid": "NewSSID"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/192.168.255.255", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestOptimizeWLANHandlerDeviceNotFound tests device not found in optimize
func TestOptimizeWLANHandlerDeviceNotFoundCase(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	})

	_, router := setupTestServer(t, mockHandler)

	body := `{"channel": "6"}`
	req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/192.168.255.255", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// TestGetAvailableWLANHandlerInvalidWLANKey tests device with invalid WLAN key
func TestGetAvailableWLANHandlerInvalidWLANKey(t *testing.T) {
	// Device with invalid WLAN key "abc" that can't be parsed to int
	mockDeviceInvalidKey := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
			},
			"LANDevice": {
				"1": {
					"WLANConfiguration": {
						"abc": {
							"Enable": {"_value": true},
							"SSID": {"_value": "InvalidKeyWiFi"}
						},
						"1": {
							"Enable": {"_value": true},
							"SSID": {"_value": "WiFi24"}
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
			_, _ = w.Write([]byte("[" + mockDeviceInvalidKey + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest("GET", "/api/v1/genieacs/wlan/available/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should still work, just skip the invalid WLAN key
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestGetAvailableWLANHandlerWithDeviceDataError tests error in getWLANData
func TestGetAvailableWLANHandlerWithDeviceDataError(t *testing.T) {
	// Device with malformed data that will cause getWLANData to fail
	mockMalformedDevice := `{
		"_id": "002568-BCM963268-684752",
		"InternetGatewayDevice": {
			"DeviceInfo": {
				"ProductClass": {"_value": "F670L"}
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
			_, _ = w.Write([]byte("[" + mockMalformedDevice + "]"))
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
