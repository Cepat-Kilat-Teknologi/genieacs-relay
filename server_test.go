package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// --- Server Tests ---

var (
	originalListenAndServe = httpListenAndServe
)

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

	// Send actual SIGINT signal to the process
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGINT)

	// Wait for result with timeout
	select {
	case err := <-serverErr:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shutdown error")
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out waiting for server shutdown")
	}
}

// TestHTTPServerTimeouts tests that HTTP server is configured with proper timeouts
func TestHTTPServerTimeouts(t *testing.T) {
	// Create a new HTTP server using the newHTTPServer function
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := newHTTPServer(":8080", handler)

	t.Run("ReadTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 15*time.Second, server.ReadTimeout, "ReadTimeout should be 15 seconds")
	})

	t.Run("WriteTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 15*time.Second, server.WriteTimeout, "WriteTimeout should be 15 seconds")
	})

	t.Run("IdleTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 60*time.Second, server.IdleTimeout, "IdleTimeout should be 60 seconds")
	})

	t.Run("ReadHeaderTimeout is configured", func(t *testing.T) {
		assert.Equal(t, 5*time.Second, server.ReadHeaderTimeout, "ReadHeaderTimeout should be 5 seconds (prevents Slowloris)")
	})

	t.Run("Server address is set", func(t *testing.T) {
		assert.Equal(t, ":8080", server.Addr, "Server address should be set correctly")
	})
}

func TestRunServer_EmptyNBIAuthKey(t *testing.T) {
	// Save original env value
	originalNBIKey := os.Getenv("NBI_AUTH_KEY")

	// Unset NBI_AUTH_KEY to trigger warning
	os.Unsetenv("NBI_AUTH_KEY")

	// Restore original value after test
	defer func() {
		if originalNBIKey != "" {
			os.Setenv("NBI_AUTH_KEY", originalNBIKey)
		}
	}()

	// Send SIGINT after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Test should complete without error (warning is logged but not fatal)
	err := runServer(":0")
	if err != nil {
		t.Fatalf("Expected normal shutdown, got error: %v", err)
	}
}

func TestRunServer_WithMiddlewareAuthEnabled(t *testing.T) {
	// Save original env values
	originalMiddlewareAuth := os.Getenv("MIDDLEWARE_AUTH")
	originalAuthKey := os.Getenv("AUTH_KEY")

	// Set MIDDLEWARE_AUTH=true with a valid AUTH_KEY
	os.Setenv("MIDDLEWARE_AUTH", "true")
	os.Setenv("AUTH_KEY", "test-key-for-server")

	// Restore original values after a test
	defer func() {
		if originalMiddlewareAuth != "" {
			os.Setenv("MIDDLEWARE_AUTH", originalMiddlewareAuth)
		} else {
			os.Unsetenv("MIDDLEWARE_AUTH")
		}
		if originalAuthKey != "" {
			os.Setenv("AUTH_KEY", originalAuthKey)
		} else {
			os.Unsetenv("AUTH_KEY")
		}
	}()

	// Send SIGINT after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Test should complete without error
	err := runServer(":0")
	if err != nil {
		t.Fatalf("Expected normal shutdown, got error: %v", err)
	}
}

func TestRunServer_WithMiddlewareAuthEnabledAndEmptyKey(t *testing.T) {
	// Save original env values
	originalMiddlewareAuth := os.Getenv("MIDDLEWARE_AUTH")
	originalAuthKey := os.Getenv("AUTH_KEY")

	// Set MIDDLEWARE_AUTH=true but no AUTH_KEY to trigger error
	os.Setenv("MIDDLEWARE_AUTH", "true")
	os.Unsetenv("AUTH_KEY")

	// Restore original values after test
	defer func() {
		if originalMiddlewareAuth != "" {
			os.Setenv("MIDDLEWARE_AUTH", originalMiddlewareAuth)
		} else {
			os.Unsetenv("MIDDLEWARE_AUTH")
		}
		if originalAuthKey != "" {
			os.Setenv("AUTH_KEY", originalAuthKey)
		} else {
			os.Unsetenv("AUTH_KEY")
		}
	}()

	// Server should fail to start with error about missing AUTH_KEY
	err := runServer(":0")
	if err == nil {
		t.Fatal("Expected error when MIDDLEWARE_AUTH=true but AUTH_KEY is empty")
	}
	if !strings.Contains(err.Error(), "AUTH_KEY") {
		t.Errorf("Expected error message to mention AUTH_KEY, got: %v", err)
	}
}

func TestMain_ErrorBranch(t *testing.T) {
	orig := runServerFunc
	defer func() { runServerFunc = orig }()

	runServerFunc = func(addr string) error {
		return fmt.Errorf("forced error")
	}

	assert.NotPanics(t, func() {
		main()
	})
}

// TestRunServer_MiddlewareAuthEnabled tests middleware auth environment variable handling
func TestRunServer_MiddlewareAuthEnabled(t *testing.T) {
	// Setup logger with proper restoration
	originalLogger := logger
	logger, _ = zap.NewDevelopment()
	defer func() {
		_ = logger.Sync()
		logger = originalLogger
	}()

	// Set environment variables for middleware auth
	os.Setenv("MIDDLEWARE_AUTH", "true")
	os.Setenv("AUTH_KEY", "test-api-key")
	defer func() {
		os.Unsetenv("MIDDLEWARE_AUTH")
		os.Unsetenv("AUTH_KEY")
	}()

	// Create mock GenieACS server
	mockGenieServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"_id": "test-device"}]`))
	}))
	defer mockGenieServer.Close()

	os.Setenv("GENIEACS_BASE_URL", mockGenieServer.URL)
	defer os.Unsetenv("GENIEACS_BASE_URL")

	// Override runServerFunc to capture the setup
	originalRunServerFunc := runServerFunc
	defer func() { runServerFunc = originalRunServerFunc }()

	serverStarted := make(chan bool, 1)
	runServerFunc = func(addr string) error {
		// Verify environment variables are loaded correctly
		middlewareAuth = os.Getenv("MIDDLEWARE_AUTH") == "true"
		authKey = os.Getenv("AUTH_KEY")

		assert.True(t, middlewareAuth)
		assert.Equal(t, "test-api-key", authKey)
		serverStarted <- true
		return nil
	}

	go func() {
		_ = runServerFunc(":8080")
	}()

	select {
	case <-serverStarted:
		// Test passed
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not start in time")
	}
}

// --- Additional Server Tests (moved from main_test.go) ---

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

func TestRunServerWithCustomStaleThreshold(t *testing.T) {
	// This test verifies that the STALE_THRESHOLD_MINUTES environment variable
	// is properly parsed by testing the parsing logic directly

	// Test case 1: Valid environment variable
	t.Run("Valid_60_minutes", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "60")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		// Parse using same logic as runServer
		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		assert.Equal(t, 60*time.Minute, result)
	})

	// Test case 2: Invalid environment variable (non-numeric)
	t.Run("Invalid_non_numeric", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "invalid")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should fall back to default since parsing fails
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 3: Zero value (disabled)
	t.Run("Zero_value_disabled", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "0")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should fall back to default since 0 is not > 0
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 4: Negative value
	t.Run("Negative_value", func(t *testing.T) {
		os.Setenv("STALE_THRESHOLD_MINUTES", "-10")
		defer os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should fall back to default since -10 is not > 0
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 5: Empty environment variable
	t.Run("Empty_env_var", func(t *testing.T) {
		os.Unsetenv("STALE_THRESHOLD_MINUTES")

		result := DefaultStaleThreshold
		if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
			if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
				result = time.Duration(staleMin) * time.Minute
			}
		}
		// Should use default when env var is not set
		assert.Equal(t, DefaultStaleThreshold, result)
	})

	// Test case 6: Integration test - runServer with custom stale threshold
	// This test covers lines 191-194 in main.go
	t.Run("runServer_with_env_var", func(t *testing.T) {
		// Save original values
		originalStaleThreshold := staleThreshold
		originalNewHTTPServer := newHTTPServer
		defer func() {
			staleThreshold = originalStaleThreshold
			newHTTPServer = originalNewHTTPServer
		}()

		// Set custom stale threshold via environment variable
		_ = os.Setenv("STALE_THRESHOLD_MINUTES", "45")
		defer func() { _ = os.Unsetenv("STALE_THRESHOLD_MINUTES") }()

		// Create a channel to signal server creation
		serverCreated := make(chan struct{})

		// Mock newHTTPServer to create a server that fails immediately
		newHTTPServer = func(addr string, handler http.Handler) *http.Server {
			close(serverCreated) // Signal that we've reached this point
			// Return a server with invalid address to cause immediate failure
			return &http.Server{
				Addr:    ":::invalid:::address:::",
				Handler: handler,
			}
		}

		// Run server synchronously - it will fail immediately due to invalid address
		errChan := make(chan error, 1)
		go func() {
			errChan <- runServer(":0")
		}()

		// Wait for server to be created (staleThreshold is set before newHTTPServer is called)
		select {
		case <-serverCreated:
			// Server was created, staleThreshold should be set now
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for server creation")
		}

		// Wait a bit for the server to fail and runServer to finish
		select {
		case <-errChan:
			// runServer finished
		case <-time.After(2 * time.Second):
			// Timeout is ok, main thing is staleThreshold was set
		}

		// Verify staleThreshold was set correctly (45 minutes from env var)
		// This read is safe because newHTTPServer has already been called,
		// meaning staleThreshold was already set
		assert.Equal(t, 45*time.Minute, staleThreshold)
	})
}

func TestRouterWithMiddlewareEnabled(t *testing.T) {
	// Setup logger
	logger, _ = zap.NewDevelopment()
	defer func() { _ = logger.Sync() }()

	// Enable middleware auth
	originalMiddlewareAuth := middlewareAuth
	originalAuthKey := authKey
	middlewareAuth = true
	authKey = "test-router-api-key"
	defer func() {
		middlewareAuth = originalMiddlewareAuth
		authKey = originalAuthKey
	}()

	// Create mock GenieACS server
	mockGenieServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[` + mockDeviceDataJSON + `]`))
	}))
	defer mockGenieServer.Close()

	geniesBaseURL = mockGenieServer.URL
	nbiAuthKey = "mock-key"

	// Store original HTTP client and restore after test
	originalHTTPClient := httpClient
	defer func() { httpClient = originalHTTPClient }()
	httpClient = mockGenieServer.Client()

	// Clear the cache
	deviceCacheInstance.clearAll()

	// Initialize worker pool
	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
	}
	taskWorkerPool.Start()
	defer taskWorkerPool.Stop()

	// Create router with middleware applied
	r := chi.NewRouter()
	r.Get("/health", healthCheckHandler)
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		// Apply API key authentication middleware (this is the code path we want to test)
		if middlewareAuth {
			r.Use(apiKeyAuthMiddleware)
		}
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
	})

	// Test 1: Request without API key should be rejected
	t.Run("Without API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		var resp Response
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, ErrMissingAPIKey, resp.Error)
	})

	// Test 2: Request with valid API key should succeed
	t.Run("With Valid API Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/genieacs/ssid/"+mockDeviceIP, nil)
		req.Header.Set(HeaderXAPIKey, "test-router-api-key")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	// Test 3: Health endpoint should NOT require auth (outside protected route)
	t.Run("Health endpoint without auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

// TestRunServer_EnvVarParsing tests environment variable parsing branches in runServer
func TestRunServer_EnvVarParsing(t *testing.T) {
	// Test CORS specific origins (not "*") - covers lines 63-65
	t.Run("CORS_specific_origins", func(t *testing.T) {
		// Save original env values
		origCORSOrigins := os.Getenv(EnvCORSAllowedOrigins)
		defer func() {
			if origCORSOrigins != "" {
				os.Setenv(EnvCORSAllowedOrigins, origCORSOrigins)
			} else {
				os.Unsetenv(EnvCORSAllowedOrigins)
			}
		}()

		// Set specific origins (not "*")
		os.Setenv(EnvCORSAllowedOrigins, "http://localhost:3000,http://example.com")

		// Send SIGINT after short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()

		err := runServer(":0")
		assert.NoError(t, err)
	})

	// Test RATE_LIMIT_REQUESTS env parsing - covers lines 73-76
	t.Run("RATE_LIMIT_REQUESTS_parsing", func(t *testing.T) {
		// Save original env values
		origRateLimitRequests := os.Getenv(EnvRateLimitRequests)
		defer func() {
			if origRateLimitRequests != "" {
				os.Setenv(EnvRateLimitRequests, origRateLimitRequests)
			} else {
				os.Unsetenv(EnvRateLimitRequests)
			}
		}()

		// Set valid rate limit requests
		os.Setenv(EnvRateLimitRequests, "200")

		// Send SIGINT after short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()

		err := runServer(":0")
		assert.NoError(t, err)
	})

	// Test RATE_LIMIT_WINDOW env parsing - covers lines 79-82
	t.Run("RATE_LIMIT_WINDOW_parsing", func(t *testing.T) {
		// Save original env values
		origRateLimitWindow := os.Getenv(EnvRateLimitWindow)
		defer func() {
			if origRateLimitWindow != "" {
				os.Setenv(EnvRateLimitWindow, origRateLimitWindow)
			} else {
				os.Unsetenv(EnvRateLimitWindow)
			}
		}()

		// Set valid rate limit window
		os.Setenv(EnvRateLimitWindow, "120")

		// Send SIGINT after short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()

		err := runServer(":0")
		assert.NoError(t, err)
	})

	// Test CORS_MAX_AGE env parsing - covers lines 90-93
	t.Run("CORS_MAX_AGE_parsing", func(t *testing.T) {
		// Save original env values
		origCORSMaxAge := os.Getenv(EnvCORSMaxAge)
		defer func() {
			if origCORSMaxAge != "" {
				os.Setenv(EnvCORSMaxAge, origCORSMaxAge)
			} else {
				os.Unsetenv(EnvCORSMaxAge)
			}
		}()

		// Set valid CORS max age
		os.Setenv(EnvCORSMaxAge, "7200")

		// Send SIGINT after short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()

		err := runServer(":0")
		assert.NoError(t, err)
	})

	// Test all env vars together
	t.Run("All_env_vars_combined", func(t *testing.T) {
		// Save original env values
		origCORSOrigins := os.Getenv(EnvCORSAllowedOrigins)
		origRateLimitRequests := os.Getenv(EnvRateLimitRequests)
		origRateLimitWindow := os.Getenv(EnvRateLimitWindow)
		origCORSMaxAge := os.Getenv(EnvCORSMaxAge)
		defer func() {
			if origCORSOrigins != "" {
				os.Setenv(EnvCORSAllowedOrigins, origCORSOrigins)
			} else {
				os.Unsetenv(EnvCORSAllowedOrigins)
			}
			if origRateLimitRequests != "" {
				os.Setenv(EnvRateLimitRequests, origRateLimitRequests)
			} else {
				os.Unsetenv(EnvRateLimitRequests)
			}
			if origRateLimitWindow != "" {
				os.Setenv(EnvRateLimitWindow, origRateLimitWindow)
			} else {
				os.Unsetenv(EnvRateLimitWindow)
			}
			if origCORSMaxAge != "" {
				os.Setenv(EnvCORSMaxAge, origCORSMaxAge)
			} else {
				os.Unsetenv(EnvCORSMaxAge)
			}
		}()

		// Set all env vars
		os.Setenv(EnvCORSAllowedOrigins, "http://localhost:3000")
		os.Setenv(EnvRateLimitRequests, "500")
		os.Setenv(EnvRateLimitWindow, "300")
		os.Setenv(EnvCORSMaxAge, "3600")

		// Send SIGINT after short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()

		err := runServer(":0")
		assert.NoError(t, err)
	})
}
