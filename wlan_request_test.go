package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

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

		// Temporarily change base URL to the error server
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

func TestValidatePassword(t *testing.T) {
	t.Run("Empty password", func(t *testing.T) {
		err := ValidatePassword("")
		assert.Equal(t, ErrPasswordRequired, err)
	})

	t.Run("All whitespace password", func(t *testing.T) {
		err := ValidatePassword("     ")
		assert.Equal(t, ErrPasswordRequired, err)
	})

	t.Run("Password too short", func(t *testing.T) {
		err := ValidatePassword("1234567") // 7 chars, assuming min is 8
		assert.Equal(t, ErrPasswordTooShort, err)
	})

	t.Run("Password too long", func(t *testing.T) {
		longPassword := strings.Repeat("a", MaxPasswordLength+1)
		err := ValidatePassword(longPassword)
		assert.Equal(t, ErrPasswordTooLong, err)
	})

	t.Run("Valid password", func(t *testing.T) {
		err := ValidatePassword("ValidPassword123")
		assert.Empty(t, err)
	})

	t.Run("Minimum length password", func(t *testing.T) {
		minPassword := strings.Repeat("a", MinPasswordLength)
		err := ValidatePassword(minPassword)
		assert.Empty(t, err)
	})

	t.Run("Maximum length password", func(t *testing.T) {
		maxPassword := strings.Repeat("a", MaxPasswordLength)
		err := ValidatePassword(maxPassword)
		assert.Empty(t, err)
	})
}
