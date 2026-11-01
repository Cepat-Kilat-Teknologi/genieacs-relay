package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mockDeviceResponseHandlers returns a mock device response with a recent _lastInform timestamp for handler tests
func mockDeviceResponseHandlers(deviceID string) string {
	// GenieACS returns _lastInform as ISO 8601 date string (e.g., "2025-01-16T10:30:00.000Z")
	lastInform := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, deviceID, lastInform)
}

func TestExtractDeviceIDByIP_Integration(t *testing.T) {
	// Setup mock server
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			query := r.URL.Query().Get("query")
			if strings.Contains(query, "192.168.1.100") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(mockDeviceResponseHandlers("test-device-id")))
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
				sendResponse(w, http.StatusOK, map[string]string{"device_id": deviceID})
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

		// Use valid IP format for the "not found" scenario
		req := httptest.NewRequest("GET", "/test/192.168.255.255", nil)
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

// TestFormatDuration tests all duration formatting cases
func TestFormatDuration(t *testing.T) {
	t.Run("Seconds", func(t *testing.T) {
		d := 30 * time.Second
		result := formatDuration(d)
		assert.Equal(t, "30 seconds", result)
	})

	t.Run("Minutes", func(t *testing.T) {
		d := 5 * time.Minute
		result := formatDuration(d)
		assert.Equal(t, "5 minutes", result)
	})

	t.Run("Hours", func(t *testing.T) {
		d := 3 * time.Hour
		result := formatDuration(d)
		assert.Contains(t, result, "hours")
	})

	t.Run("Days", func(t *testing.T) {
		d := 48 * time.Hour
		result := formatDuration(d)
		assert.Contains(t, result, "days")
	})

	t.Run("Zero seconds", func(t *testing.T) {
		d := 0 * time.Second
		result := formatDuration(d)
		assert.Equal(t, "0 seconds", result)
	})

	t.Run("59 seconds", func(t *testing.T) {
		d := 59 * time.Second
		result := formatDuration(d)
		assert.Equal(t, "59 seconds", result)
	})

	t.Run("59 minutes", func(t *testing.T) {
		d := 59 * time.Minute
		result := formatDuration(d)
		assert.Equal(t, "59 minutes", result)
	})

	t.Run("23 hours", func(t *testing.T) {
		d := 23 * time.Hour
		result := formatDuration(d)
		assert.Contains(t, result, "hours")
	})
}

// TestExtractDeviceIDByIP_ErrorSanitization verifies that error messages are sanitized
func TestExtractDeviceIDByIP_ErrorSanitization(t *testing.T) {
	// Setup mock server that returns empty array (device not found)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer mockServer.Close()

	// Save and restore original values
	originalURL := geniesBaseURL
	geniesBaseURL = mockServer.URL
	defer func() { geniesBaseURL = originalURL }()

	// Initialize logger if needed
	if logger == nil {
		logger, _ = zap.NewDevelopment()
	}

	r := chi.NewRouter()
	r.Get("/test/{ip}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = ExtractDeviceIDByIP(w, r)
	})

	// Test with valid IP but device not found
	req := httptest.NewRequest("GET", "/test/192.168.1.100", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	// Verify that error message is sanitized and doesn't contain internal details
	responseBody := rr.Body.String()
	assert.NotContains(t, responseBody, "device not found with IP: 192.168.1.100")
	assert.Contains(t, responseBody, "Device not found")
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name    string
		trusted string
		realIP  string
		want    string
	}{
		{"peer without headers drops the port", "", "", "192.168.1.100"},
		{"x-real-ip from untrusted peer ignored", "", "10.0.0.1", "192.168.1.100"},
		{"x-real-ip from trusted peer used", "192.168.1.0/24", "10.0.0.1", "10.0.0.1"},
		{"invalid x-real-ip from trusted peer ignored", "192.168.1.0/24", "not-a-valid-ip", "192.168.1.100"},
		{"ipv6 x-real-ip from trusted peer", "192.168.1.0/24", "::1", "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTrustedProxies(t, tt.trusted)
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.100:12345"
			if tt.realIP != "" {
				req.Header.Set("X-Real-IP", tt.realIP)
			}
			assert.Equal(t, tt.want, GetClientIP(req))
		})
	}
}

func TestParseJSONRequest(t *testing.T) {
	t.Run("Valid JSON request", func(t *testing.T) {
		body := strings.NewReader(`{"name": "test"}`)
		req := httptest.NewRequest("POST", "/test", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		var result map[string]string
		ok := ParseJSONRequest(rr, req, &result)
		assert.True(t, ok)
		assert.Equal(t, "test", result["name"])
	})

	t.Run("Invalid Content-Type", func(t *testing.T) {
		body := strings.NewReader(`{"name": "test"}`)
		req := httptest.NewRequest("POST", "/test", body)
		req.Header.Set("Content-Type", "text/plain")
		rr := httptest.NewRecorder()

		var result map[string]string
		ok := ParseJSONRequest(rr, req, &result)
		assert.False(t, ok)
		assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code)
	})

	t.Run("Invalid JSON format", func(t *testing.T) {
		body := strings.NewReader(`{invalid json}`)
		req := httptest.NewRequest("POST", "/test", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		var result map[string]string
		ok := ParseJSONRequest(rr, req, &result)
		assert.False(t, ok)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Empty Content-Type is allowed", func(t *testing.T) {
		body := strings.NewReader(`{"name": "test"}`)
		req := httptest.NewRequest("POST", "/test", body)
		// No Content-Type header set
		rr := httptest.NewRecorder()

		var result map[string]string
		ok := ParseJSONRequest(rr, req, &result)
		assert.True(t, ok)
		assert.Equal(t, "test", result["name"])
	})

	t.Run("Application/json with charset is allowed", func(t *testing.T) {
		body := strings.NewReader(`{"name": "test"}`)
		req := httptest.NewRequest("POST", "/test", body)
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		rr := httptest.NewRecorder()

		var result map[string]string
		ok := ParseJSONRequest(rr, req, &result)
		assert.True(t, ok)
		assert.Equal(t, "test", result["name"])
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

func TestExtractDeviceIDByIP_LookupTimeout(t *testing.T) {
	ctx := newExpiringCtx()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx.expire()
		<-r.Context().Done()
	}))
	defer mockServer.Close()

	originalURL := geniesBaseURL
	geniesBaseURL = mockServer.URL
	defer func() { geniesBaseURL = originalURL }()

	if logger == nil {
		logger, _ = zap.NewDevelopment()
	}

	r := chi.NewRouter()
	r.Get("/test/{ip}", func(w http.ResponseWriter, r *http.Request) {
		_, ok := ExtractDeviceIDByIP(w, r)
		assert.False(t, ok)
	})

	req := httptest.NewRequest("GET", "/test/192.168.1.100", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestTimeout, rr.Code)
	assert.Contains(t, rr.Body.String(), `"error_code":"TIMEOUT"`)
	assert.Contains(t, rr.Body.String(), ErrDeviceLookupTimeout)
}

func TestExtractDeviceIDByIP_LookupErrorMapping(t *testing.T) {
	if logger == nil {
		logger, _ = zap.NewDevelopment()
	}

	tests := []struct {
		name       string
		ip         string // defaults to 192.168.1.100
		lookup     int    // status the NBI returns for the device lookup
		breaker    bool
		prime      bool // send one request first to trip the breaker
		wantStatus int
		wantCode   string
		wantMsg    string
		wantNoNBI  bool // the request must be rejected before any NBI call
	}{
		{name: "NBI 500", lookup: http.StatusInternalServerError, wantStatus: http.StatusBadGateway, wantCode: ErrCodeGenieACS, wantMsg: ErrDeviceLookupUpstream},
		{name: "NBI 503", lookup: http.StatusServiceUnavailable, wantStatus: http.StatusBadGateway, wantCode: ErrCodeGenieACS, wantMsg: ErrDeviceLookupUpstream},
		{name: "circuit open", lookup: http.StatusInternalServerError, breaker: true, prime: true, wantStatus: http.StatusServiceUnavailable, wantCode: ErrCodeServiceUnavailable, wantMsg: ErrDeviceLookupUnavailable},
		{name: "device not found", lookup: http.StatusOK, wantStatus: http.StatusNotFound, wantCode: ErrCodeNotFound, wantMsg: "Device not found"},
		{name: "NBI 401", lookup: http.StatusUnauthorized, wantStatus: http.StatusBadGateway, wantCode: ErrCodeGenieACS, wantMsg: ErrDeviceLookupUpstream},
		{name: "NBI 403", lookup: http.StatusForbidden, wantStatus: http.StatusBadGateway, wantCode: ErrCodeGenieACS, wantMsg: ErrDeviceLookupUpstream},
		{name: "malformed ip", ip: "not-an-ip", wantStatus: http.StatusBadRequest, wantCode: ErrCodeValidation, wantMsg: "Invalid IP address format", wantNoNBI: true},
		{name: "loopback ip", ip: "127.0.0.1", wantStatus: http.StatusBadRequest, wantCode: ErrCodeValidation, wantMsg: "loopback addresses are not allowed", wantNoNBI: true},
		{name: "ipv6", ip: "2001:db8::1", wantStatus: http.StatusBadRequest, wantCode: ErrCodeValidation, wantMsg: "IPv6 addresses are not supported", wantNoNBI: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var nbiCalls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nbiCalls.Add(1)
				w.WriteHeader(tc.lookup)
				if tc.lookup == http.StatusOK {
					_, _ = w.Write([]byte(`[]`))
					return
				}
				// Upstream body text must never reach the client.
				_, _ = w.Write([]byte(`{"error":"upstream-secret-detail"}`))
			}))
			defer srv.Close()

			originalURL := geniesBaseURL
			geniesBaseURL = srv.URL
			defer func() { geniesBaseURL = originalURL }()

			if tc.breaker {
				initBreaker(testBreakerConfig(1), zap.NewNop())
				defer func() { nbiBreaker = nil }()
			}

			r := chi.NewRouter()
			r.Get("/test/{ip}", func(w http.ResponseWriter, r *http.Request) {
				_, _ = ExtractDeviceIDByIP(w, r)
			})
			ip := tc.ip
			if ip == "" {
				ip = "192.168.1.100"
			}
			serve := func() *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				r.ServeHTTP(rr, httptest.NewRequest("GET", "/test/"+url.PathEscape(ip), nil))
				return rr
			}

			if tc.prime {
				require.Equal(t, http.StatusBadGateway, serve().Code)
			}
			rr := serve()

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), `"error_code":"`+tc.wantCode+`"`)
			assert.Contains(t, rr.Body.String(), tc.wantMsg)
			assert.NotContains(t, rr.Body.String(), "upstream-secret-detail")
			if tc.wantNoNBI {
				assert.Zero(t, nbiCalls.Load(), "invalid ip must not reach the NBI")
			}
		})
	}
}
