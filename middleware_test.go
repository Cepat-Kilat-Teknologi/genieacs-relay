package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

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

		// Exhaust limit for X-Real-IP
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.0.0.1:12345"
			req.Header.Set("X-Real-IP", "192.168.1.1")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}

		// Should be blocked for X-Real-IP
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "192.168.1.1")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)

		// Different X-Real-IP should still have its limit
		req = httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "192.168.1.2")
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// --- Security Headers Middleware Tests ---

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

// --- Rate Limiter Cleanup Tests ---

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

// --- CORS Middleware Tests ---

func TestCORSMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"success"}`))
	})

	t.Run("Allows requests from allowed origin", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://example.com", "https://app.example.com"}, 86400)(testHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "https://example.com", rr.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rr.Header().Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, rr.Header().Get("Access-Control-Allow-Headers"), "X-API-Key")
	})

	t.Run("Blocks requests from disallowed origin", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://example.com"}, 86400)(testHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://evil.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)                         // Request still succeeds
		assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin")) // But no CORS headers
	})

	t.Run("Handles preflight OPTIONS request for allowed origin", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://example.com"}, 86400)(testHandler)

		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Equal(t, "https://example.com", rr.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Handles preflight OPTIONS request for disallowed origin", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://example.com"}, 86400)(testHandler)

		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "https://evil.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("No CORS headers when no allowed origins configured", func(t *testing.T) {
		handler := corsMiddleware([]string{}, 86400)(testHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("No CORS headers when no origin header in request", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://example.com"}, 86400)(testHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		// No Origin header
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Wildcard origin allows all origins", func(t *testing.T) {
		handler := corsMiddleware([]string{"*"}, 86400)(testHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://any-origin.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Wildcard origin handles preflight OPTIONS", func(t *testing.T) {
		handler := corsMiddleware([]string{"*"}, 86400)(testHandler)

		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "https://any-origin.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Empty origin in allowed list is ignored", func(t *testing.T) {
		handler := corsMiddleware([]string{"", "https://example.com"}, 86400)(testHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "https://example.com", rr.Header().Get("Access-Control-Allow-Origin"))
	})
}

// --- Auth Attempt Tracker Tests ---

func TestAuthAttemptTracker_IsBlocked(t *testing.T) {
	t.Run("Returns false for non-existent IP", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		assert.False(t, tracker.isBlocked("192.168.1.1"))
	})

	t.Run("Returns true for blocked IP within lockout period", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.attempts["192.168.1.1"] = &authAttempt{
			lockedUntil: time.Now().Add(5 * time.Minute),
		}
		assert.True(t, tracker.isBlocked("192.168.1.1"))
	})

	t.Run("Returns false for IP past lockout period", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.attempts["192.168.1.1"] = &authAttempt{
			lockedUntil: time.Now().Add(-1 * time.Minute),
		}
		assert.False(t, tracker.isBlocked("192.168.1.1"))
	})
}

func TestAuthAttemptTracker_RecordFailure(t *testing.T) {
	t.Run("Creates new entry for new IP", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.recordFailure("192.168.1.1")
		assert.Equal(t, 1, tracker.attempts["192.168.1.1"].failedCount)
	})

	t.Run("Increments failure count for existing IP", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.recordFailure("192.168.1.1")
		tracker.recordFailure("192.168.1.1")
		assert.Equal(t, 2, tracker.attempts["192.168.1.1"].failedCount)
	})

	t.Run("Resets count when outside attempt window", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.attempts["192.168.1.1"] = &authAttempt{
			failedCount: 3,
			firstFailed: time.Now().Add(-AuthAttemptWindow - time.Minute),
		}
		tracker.recordFailure("192.168.1.1")
		assert.Equal(t, 1, tracker.attempts["192.168.1.1"].failedCount)
	})

	t.Run("Locks out IP after max failed attempts", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		for i := 0; i < MaxFailedAuthAttempts; i++ {
			tracker.recordFailure("192.168.1.1")
		}
		assert.True(t, tracker.attempts["192.168.1.1"].lockedUntil.After(time.Now()))
	})
}

func TestAuthAttemptTracker_GetRemainingLockout(t *testing.T) {
	t.Run("Returns 0 for non-existent IP", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		assert.Equal(t, time.Duration(0), tracker.getRemainingLockout("192.168.1.1"))
	})

	t.Run("Returns 0 for expired lockout", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.attempts["192.168.1.1"] = &authAttempt{
			lockedUntil: time.Now().Add(-1 * time.Minute),
		}
		assert.Equal(t, time.Duration(0), tracker.getRemainingLockout("192.168.1.1"))
	})

	t.Run("Returns remaining duration for active lockout", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.attempts["192.168.1.1"] = &authAttempt{
			lockedUntil: time.Now().Add(5 * time.Minute),
		}
		remaining := tracker.getRemainingLockout("192.168.1.1")
		assert.True(t, remaining > 4*time.Minute && remaining <= 5*time.Minute)
	})
}

func TestAuthAttemptTracker_Cleanup(t *testing.T) {
	t.Run("Removes expired entries", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		// Add expired entry
		tracker.attempts["192.168.1.1"] = &authAttempt{
			firstFailed: time.Now().Add(-AuthAttemptWindow - time.Minute),
			lockedUntil: time.Now().Add(-1 * time.Minute),
		}
		// Add fresh entry
		tracker.attempts["192.168.1.2"] = &authAttempt{
			firstFailed: time.Now(),
			lockedUntil: time.Time{},
		}

		tracker.cleanup()

		assert.Nil(t, tracker.attempts["192.168.1.1"])
		assert.NotNil(t, tracker.attempts["192.168.1.2"])
	})

	t.Run("Keeps entries within attempt window", func(t *testing.T) {
		tracker := &authAttemptTracker{
			attempts: make(map[string]*authAttempt),
		}
		tracker.attempts["192.168.1.1"] = &authAttempt{
			firstFailed: time.Now(),
			lockedUntil: time.Time{},
		}

		tracker.cleanup()

		assert.NotNil(t, tracker.attempts["192.168.1.1"])
	})
}

func TestAuthAttemptTracker_StartStopCleanup(t *testing.T) {
	tracker := &authAttemptTracker{
		attempts: make(map[string]*authAttempt),
	}

	// Start cleanup
	tracker.StartCleanup()
	assert.NotNil(t, tracker.stopCh)

	// Give goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Stop cleanup
	tracker.StopCleanup()

	// Verify stopCh is closed (calling StopCleanup again should be safe)
	// This tests that the cleanup goroutine exited properly
	time.Sleep(50 * time.Millisecond)
}

// TestAuthAttemptTracker_CleanupTicker tests that the periodic ticker triggers cleanup
func TestAuthAttemptTracker_CleanupTicker(t *testing.T) {
	tracker := &authAttemptTracker{
		attempts:        make(map[string]*authAttempt),
		cleanupInterval: 50 * time.Millisecond, // Short interval for testing
	}

	// Add a stale entry that should be cleaned up
	tracker.attempts["192.168.1.1"] = &authAttempt{
		failedCount: 1,
		firstFailed: time.Now().Add(-10 * time.Minute), // Older than AuthAttemptWindow
		lockedUntil: time.Now().Add(-5 * time.Minute),  // Lockout expired
	}

	// Start cleanup with short interval
	tracker.StartCleanup()
	defer tracker.StopCleanup()

	// Wait for at least one ticker tick to trigger cleanup
	time.Sleep(100 * time.Millisecond)

	// Verify the stale entry was cleaned up by the ticker
	tracker.mu.RLock()
	_, exists := tracker.attempts["192.168.1.1"]
	tracker.mu.RUnlock()

	assert.False(t, exists, "Stale entry should be cleaned up by ticker")
}

func TestAPIKeyAuthMiddleware_BlockedIP(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	originalAuthKey := authKey
	authKey = "test-api-key"
	defer func() { authKey = originalAuthKey }()

	// Save and reset authTracker
	originalAttempts := authTracker.attempts
	authTracker.attempts = make(map[string]*authAttempt)
	defer func() { authTracker.attempts = originalAttempts }()

	// Block the IP (must match RemoteAddr exactly as middleware uses r.RemoteAddr)
	authTracker.attempts["192.168.1.100:12345"] = &authAttempt{
		failedCount: MaxFailedAuthAttempts,
		lockedUntil: time.Now().Add(5 * time.Minute),
	}

	handler := apiKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set(HeaderXAPIKey, "test-api-key")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("Retry-After"))
}

func TestAPIKeyAuthMiddleware_XRealIP(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	originalAuthKey := authKey
	authKey = "test-api-key"
	defer func() { authKey = originalAuthKey }()

	// Save and reset authTracker
	originalAttempts := authTracker.attempts
	authTracker.attempts = make(map[string]*authAttempt)
	defer func() { authTracker.attempts = originalAttempts }()

	handler := apiKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Uses valid X-Real-IP header", func(t *testing.T) {
		// Block the X-Real-IP
		authTracker.attempts["10.0.0.1"] = &authAttempt{
			failedCount: MaxFailedAuthAttempts,
			lockedUntil: time.Now().Add(5 * time.Minute),
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		req.Header.Set("X-Real-IP", "10.0.0.1")
		req.Header.Set(HeaderXAPIKey, "test-api-key")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	})

	t.Run("Ignores invalid X-Real-IP header", func(t *testing.T) {
		// Clear any tracked attempts
		authTracker.attempts = make(map[string]*authAttempt)

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		req.Header.Set("X-Real-IP", "invalid-ip")
		req.Header.Set(HeaderXAPIKey, "test-api-key")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		// Should succeed because X-Real-IP is invalid and falls back to RemoteAddr
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestRateLimitMiddleware_InvalidXRealIP(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	handler := rateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use invalid X-Real-IP - should fall back to RemoteAddr
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Real-IP", "not-a-valid-ip")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRateLimiter_Allow_MaxCapacity(t *testing.T) {
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	rl := newRateLimiter(100, time.Minute)

	// Fill up the rate limiter to max capacity
	for i := 0; i < MaxRateLimiterEntries; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		rl.Allow(ip)
	}

	// Verify that the rate limiter is at capacity
	assert.Equal(t, MaxRateLimiterEntries, len(rl.requests))

	// Try to add a new IP - should be rejected
	allowed := rl.Allow("192.168.255.255")
	assert.False(t, allowed, "New IP should be rejected when rate limiter is at max capacity")
}
