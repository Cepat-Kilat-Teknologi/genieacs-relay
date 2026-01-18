package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- IP Validation Tests ---

func TestValidateIP(t *testing.T) {
	t.Run("Valid IPv4", func(t *testing.T) {
		err := validateIP("192.168.1.1")
		assert.NoError(t, err)
	})

	t.Run("Valid IPv6", func(t *testing.T) {
		// Use a valid non-loopback IPv6 address
		err := validateIP("2001:db8::1")
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

	t.Run("Invalid IP - IPv4 loopback", func(t *testing.T) {
		err := validateIP("127.0.0.1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "loopback addresses are not allowed")
	})

	t.Run("Invalid IP - IPv6 loopback", func(t *testing.T) {
		err := validateIP("::1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "loopback addresses are not allowed")
	})

	t.Run("Invalid IP - multicast", func(t *testing.T) {
		err := validateIP("224.0.0.1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "multicast addresses are not allowed")
	})

	t.Run("Invalid IP - unspecified", func(t *testing.T) {
		err := validateIP("0.0.0.0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unspecified addresses are not allowed")
	})
}

// --- WLAN ID Validation Tests ---

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

// --- Validation Constants Tests ---

func TestValidationConstants(t *testing.T) {
	// Verify validation constants are set correctly
	assert.Equal(t, 8, MinPasswordLength)
	assert.Equal(t, 63, MaxPasswordLength)
	assert.Equal(t, 1, MinSSIDLength)
	assert.Equal(t, 32, MaxSSIDLength)
}

// --- Error Sanitization Tests ---

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

// TestMaxRequestBodySizeConstant verifies the constant is properly defined
func TestMaxRequestBodySizeConstant(t *testing.T) {
	assert.Equal(t, 1024, MaxRequestBodySize, "MaxRequestBodySize should be 1KB")
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

	t.Run("WLAN update rejects large body", func(t *testing.T) {
		// Create a body larger than MaxRequestBodySize (1KB)
		largeBody := strings.Repeat("a", MaxRequestBodySize+100)
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should return 413 Request Entity Too Large or 400 Bad Request
		assert.True(t, rr.Code == http.StatusRequestEntityTooLarge || rr.Code == http.StatusBadRequest,
			"Large body should be rejected with 413 or 400, got %d", rr.Code)
	})

	t.Run("Normal size body is accepted", func(t *testing.T) {
		body := `{"ssid": "NormalSSID"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should not be rejected due to body size (may fail for other reasons)
		assert.NotEqual(t, http.StatusRequestEntityTooLarge, rr.Code)
	})
}

func TestWLANIDValidationInHandlers(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
	})

	_, router := setupTestServer(t, mockHandler)

	t.Run("WLAN update rejects invalid WLAN ID", func(t *testing.T) {
		// Note: URLs with path traversal like "../1" are handled by chi router differently
		// and may result in 404, so we only test simple invalid values here
		invalidWLANIDs := []string{"abc", "0", "100", "999"}
		for _, wlanID := range invalidWLANIDs {
			body := `{"ssid": "TestSSID"}`
			req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/"+wlanID+"/"+mockDeviceIP, strings.NewReader(body))
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
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
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
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
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
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should not fail due to character validation (may fail for other reasons)
		assert.NotEqual(t, http.StatusBadRequest, rr.Code, "Valid SSID should not be rejected")
	})
}

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
