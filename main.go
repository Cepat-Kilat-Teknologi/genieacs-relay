package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

// Legacy task type constants for backward compatibility with existing code
const (
	taskTypeSetParams    = TaskTypeSetParams
	taskTypeApplyChanges = TaskTypeApplyChanges
	taskTypeRefreshWLAN  = TaskTypeRefreshWLAN
)

// Global variables for application configuration and shared resources
var (
	serverAddr     string
	geniesBaseURL  string        // Base URL for GenieACS server API endpoints
	nbiAuthKey     string        // Authentication key for GenieACS Northbound Interface (NBI)
	logger         *zap.Logger   // Structured logger for application logging
	middlewareAuth bool          // Whether API key authentication middleware is enabled
	authKey        string        // API key for authenticating incoming requests
	staleThreshold time.Duration // Threshold for considering device as stale (default: 10 minutes)
)

// Pre-initialized variables and instances for modularity
var (
	// jsonMarshal is a package-level variable for JSON marshaling (allows test mocking)
	jsonMarshal = json.Marshal

	// Function to initialize logger
	initLogger = func() (*zap.Logger, error) {
		return zap.NewProduction() // Use production configuration for logger
	}

	// Function to create new HTTP server instance
	serverShutdown = func(ctx context.Context, server *http.Server) error {
		return server.Shutdown(ctx) // Gracefully shutdown server with context
	}

	// HTTP client with timeout and connection pooling settings for efficient API calls to GenieACS server
	httpClient = &http.Client{
		Timeout: 15 * time.Second, // Set request timeout
		Transport: &http.Transport{ // Configure transport for connection pooling
			MaxIdleConns:        100,              // Maximum idle connections across all hosts
			MaxIdleConnsPerHost: 20,               // Maximum idle connections per host
			IdleConnTimeout:     30 * time.Second, // Timeout for idle connections
		},
	}

	// Device cache instance for caching device data with expiration
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData), // Initialize empty cache map
		timeout: 30 * time.Second,                  // Set cache expiration duration
	}

	// Worker pool instance for handling asynchronous tasks
	taskWorkerPool = &workerPool{
		workers: 10,                   // Number of worker goroutines
		queue:   make(chan task, 100), // Buffered channel for task queue
	}

	// Function to create new HTTP server instance
	// Configured with timeouts to prevent Slowloris and SlowPOST DoS attacks
	newHTTPServer = func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,             // Server address to listen on
			Handler:           handler,          // HTTP handler for incoming requests
			ReadTimeout:       15 * time.Second, // Max time to read entire request including body
			WriteTimeout:      15 * time.Second, // Max time to write response
			IdleTimeout:       60 * time.Second, // Max time for keep-alive connections
			ReadHeaderTimeout: 5 * time.Second,  // Max time to read request headers (prevents Slowloris)
		}
	}

	runServerFunc = runServer // Function to start the HTTP server (for easier testing/mock

)

// --- Struct Definitions ---
// deviceCache provides thread-safe caching mechanism for device data with expiration
type deviceCache struct {
	mu       sync.RWMutex                // Read-write mutex for concurrent access
	data     map[string]cachedDeviceData // Cache storage mapping device IDs to cached data
	timeout  time.Duration               // Duration after which cached data is considered stale
	stopCh   chan struct{}               // Channel to signal eviction goroutine to stop
	stopOnce sync.Once                   // Ensure StopEviction is only called once
}

// cachedDeviceData holds the actual cached data and timestamp for expiration tracking
type cachedDeviceData struct {
	data      map[string]interface{} // The cached device data as key-value pairs
	timestamp time.Time              // Time when this data was cached for expiration calculation
}

// --- Worker Pool Implementation ---

// workerPool manages a pool of worker goroutines for asynchronous task processing
type workerPool struct {
	workers int            // Number of active workers
	queue   chan task      // Channel for receiving tasks
	wg      sync.WaitGroup // WaitGroup for graceful shutdown synchronization
	once    sync.Once      // Ensure Start is only called once
}

// rateLimiter implements a simple token bucket rate limiter per IP
type rateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*tokenBucket
	rate     int           // requests per window
	window   time.Duration // time window
	stopCh   chan struct{} // channel to signal cleanup goroutine to stop
}

// tokenBucket tracks request counts for rate limiting
type tokenBucket struct {
	tokens    int
	lastReset time.Time
}

// -- Task Definition ---

// task represents a unit of work to be processed by the worker pool
type task struct {
	deviceID string          // Target device identifier for the task
	taskType string          // Type of task to execute (see taskType constants)
	params   [][]interface{} // Parameters for parameter-setting tasks
}

// Device represents a network device with its unique identifier
type Device struct {
	ID         string     `json:"_id"`         // Device unique identifier from GenieACS
	LastInform *time.Time `json:"_lastInform"` // Timestamp of last inform from device
}

// WLANConfig represents wireless LAN configuration for a device
type WLANConfig struct {
	WLAN     string `json:"wlan"`     // WLAN interface identifier (e.g., "1", "5")
	SSID     string `json:"ssid"`     // Network name broadcast by the WLAN
	Password string `json:"password"` // Security key/password for the WLAN
	Band     string `json:"band"`     // Frequency band (2.4GHz, 5GHz, etc.)
}

// DHCPClient represents a client device that obtained IP address via DHCP
type DHCPClient struct {
	MAC      string `json:"mac"`      // MAC address of the client device
	Hostname string `json:"hostname"` // Hostname reported by the client
	IP       string `json:"ip"`       // IP address assigned to the client
}

// UpdateSSIDRequest represents JSON payload for SSID update operations
type UpdateSSIDRequest struct {
	SSID string `json:"ssid"` // New SSID value to be set
}

// UpdatePasswordRequest represents JSON payload for password update operations
type UpdatePasswordRequest struct {
	Password string `json:"password"` // New password value to be set
}

// Response represents standardized API response format for all endpoints
type Response struct {
	Code   int         `json:"code"`            // HTTP status code
	Status string      `json:"status"`          // Status message (e.g., "OK", "Error")
	Data   interface{} `json:"data,omitempty"`  // Response payload data when successful
	Error  string      `json:"error,omitempty"` // Error description when operation fails
}

// --- HTTP Response Helper Functions ---

func runServer(addr string) error {
	// load config
	serverAddr = getEnv("SERVER_ADDR", addr)
	geniesBaseURL = getEnv("GENIEACS_BASE_URL", DefaultGenieACSURL)
	nbiAuthKey = getEnv("NBI_AUTH_KEY", DefaultNBIAuthKey)

	// Warn if NBI_AUTH_KEY is not set (security best practice)
	if nbiAuthKey == "" {
		logger.Warn("NBI_AUTH_KEY environment variable is not set - API authentication may fail")
	}

	// Load middleware authentication config
	middlewareAuth = getEnv(EnvMiddlewareAuth, "false") == "true"
	authKey = getEnv(EnvAuthKey, DefaultAuthKey)

	// Warn if middleware auth is enabled but AUTH_KEY is not set
	if middlewareAuth && authKey == "" {
		logger.Warn("MIDDLEWARE_AUTH is enabled but AUTH_KEY is not set - all requests will be rejected")
	}

	// Log middleware auth status
	logger.Info("Middleware authentication", zap.Bool("enabled", middlewareAuth))

	// Load stale threshold config (default: 10 minutes)
	staleThreshold = DefaultStaleThreshold
	if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
		if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
			staleThreshold = time.Duration(staleMin) * time.Minute
		}
	}
	logger.Info("Stale device threshold", zap.Duration("threshold", staleThreshold))

	// start worker pool
	taskWorkerPool.Start()
	defer taskWorkerPool.Stop()

	logger.Info("Starting server", zap.String("genieacs_url", geniesBaseURL))

	// router
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	// Apply rate limiting middleware (100 requests per minute per IP)
	rl := newRateLimiter(100, time.Minute)
	rl.StartCleanup() // Start background cleanup to prevent memory leaks
	defer rl.StopCleanup()
	r.Use(rateLimitMiddleware(rl))
	r.Use(securityHeadersMiddleware)
	r.Get("/health", healthCheckHandler)
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		// Apply API key authentication middleware if enabled
		if middlewareAuth {
			r.Use(apiKeyAuthMiddleware)
		}
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Get("/force"+"/ssid/{ip}", getSSIDByIPForceHandler)
		r.Post("/ssid/{ip}/refresh", refreshSSIDHandler)
		r.Put("/ssid/update/{wlan}/{ip}", updateSSIDByIPHandler)
		r.Put("/password/update/{wlan}/{ip}", updatePasswordByIPHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/cache/clear", clearCacheHandler)
		// Device capability and WLAN management endpoints
		r.Get("/capability/{ip}", getDeviceCapabilityHandler)
		r.Get("/wlan/available/{ip}", getAvailableWLANHandler)
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)
		r.Put("/wlan/update/{wlan}/{ip}", updateWLANHandler)
		r.Delete("/wlan/delete/{wlan}/{ip}", deleteWLANHandler)
		r.Put("/wlan/optimize/{wlan}/{ip}", optimizeWLANHandler)
	})

	// server
	server := newHTTPServer(serverAddr, r)

	// start server
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server listening", zap.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return err
	case <-quit:
		logger.Info("Shutdown signal received, starting graceful shutdown...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := serverShutdown(ctx, server); err != nil {
			return err
		}

		logger.Info("Server exited properly")
		return nil
	}

}

// --- Main Application Entry Point ---
func main() {
	_ = initLoggerWrapper()

	defer func() {
		if err := logger.Sync(); err != nil {
			log.Printf("Failed to sync logger: %v", err)
		}
	}()

	if err := runServerFunc(":8080"); err != nil {
		logger.Info("Server failed", zap.Error(err))
	}
}

// initLoggerWrapper handles logger initialization and returns error
func initLoggerWrapper() error {
	var err error
	logger, err = initLogger()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	_ = logger.Sugar()
	return nil
}

// Start initializes the worker pool by launching all worker goroutines
func (wp *workerPool) Start() {
	// Create a specified number of worker goroutines
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)   // Increment WaitGroup counter
		go wp.worker() // Start a worker goroutine
	}
}

// Stop gracefully shuts down the worker pool by closing queue and waiting for completion
func (wp *workerPool) Stop() {
	wp.once.Do(func() { // Ensure Stop is only executed once
		close(wp.queue) // Close the task queue to signal workers to stop
		wp.wg.Wait()    // Wait for all workers to finish processing
	})
}

// worker is the goroutine that processes tasks from the queue
func (wp *workerPool) worker() {
	defer wp.wg.Done()          // Signal completion when goroutine exits
	ctx := context.Background() // Create background context for task execution

	// Process tasks from queue until channel is closed
	for t := range wp.queue {
		var err error
		// Execute appropriate function based on task type
		switch t.taskType {
		case taskTypeSetParams:
			err = setParameterValues(ctx, t.deviceID, t.params)
		case taskTypeApplyChanges:
			err = refreshWLANConfig(ctx, t.deviceID)
		case taskTypeRefreshWLAN:
			err = refreshWLANConfig(ctx, t.deviceID)
		default:
			err = fmt.Errorf("unknown task type: %s", t.taskType)
		}

		// Log any errors encountered during task execution
		if err != nil {
			logger.Error("Worker task failed",
				zap.String("deviceID", t.deviceID),
				zap.String("taskType", t.taskType),
				zap.Error(err),
			)
		}
	}
}

// Submit adds a new task to the worker pool queue for asynchronous processing
// This version uses non-blocking send to prevent deadlocks when queue is full
func (wp *workerPool) Submit(deviceID, taskType string, params [][]interface{}) {
	select {
	case wp.queue <- task{deviceID, taskType, params}:
		// Task successfully queued
	default:
		// Queue is full, log warning
		logger.Warn("Worker pool queue full, task dropped",
			zap.String("deviceID", deviceID),
			zap.String("taskType", taskType),
		)
	}
}

// TrySubmit attempts to add a task to the worker pool queue
// Returns true if task was queued, false if queue is full
func (wp *workerPool) TrySubmit(deviceID, taskType string, params [][]interface{}) bool {
	select {
	case wp.queue <- task{deviceID, taskType, params}:
		return true
	default:
		return false
	}
}

// --- Cache Methods ---

// get retrieves cached data for a device if it exists and hasn't expired
func (c *deviceCache) get(deviceID string) (map[string]interface{}, bool) {
	c.mu.RLock()         // Acquire read lock for thread safety
	defer c.mu.RUnlock() // Ensure lock is released when function exits
	// Check if device exists in cache and data is still fresh
	if cached, exists := c.data[deviceID]; exists && time.Since(cached.timestamp) < c.timeout {
		return cached.data, true // Return cached data and success status
	}
	return nil, false // Return empty result if not found or expired
}

// set stores device data in cache with current timestamp
func (c *deviceCache) set(deviceID string, data map[string]interface{}) {
	c.mu.Lock()         // Acquire write lock for thread safety
	defer c.mu.Unlock() // Ensure lock release
	// Store data with current timestamp for expiration tracking
	c.data[deviceID] = cachedDeviceData{data, time.Now()}
}

// clear removes cached data for a specific device
func (c *deviceCache) clear(deviceID string) {
	c.mu.Lock() // Acquire write lock
	defer c.mu.Unlock()
	delete(c.data, deviceID) // Remove device entry from cache
}

// clearAll removes all cached data (complete cache flush)
func (c *deviceCache) clearAll() {
	c.mu.Lock() // Acquire write lock
	defer c.mu.Unlock()
	c.data = make(map[string]cachedDeviceData) // Reinitialize empty cache map
}

// StartEviction starts a background goroutine that periodically removes expired cache entries
// The eviction interval is set to half the cache timeout to ensure timely cleanup
func (c *deviceCache) StartEviction() {
	c.stopCh = make(chan struct{})
	evictionInterval := c.timeout / 2 // Run eviction at half the timeout interval
	if evictionInterval < time.Second {
		evictionInterval = time.Second // Minimum 1 second interval
	}

	go func() {
		ticker := time.NewTicker(evictionInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.evictExpired()
			case <-c.stopCh:
				return
			}
		}
	}()
}

// StopEviction stops the background eviction goroutine
func (c *deviceCache) StopEviction() {
	c.stopOnce.Do(func() {
		if c.stopCh != nil {
			close(c.stopCh)
		}
	})
}

// evictExpired removes all expired entries from the cache
func (c *deviceCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for deviceID, cached := range c.data {
		if now.Sub(cached.timestamp) >= c.timeout {
			delete(c.data, deviceID)
		}
	}
}

// --- Helper Functions ---

// safeClose safely closes an io.Closer resource and logs any errors
func safeClose(closer io.Closer) {
	if closer != nil {
		if err := closer.Close(); err != nil {
			logger.Warn("Failed to close resource", zap.Error(err))
		}
	}
}

// getEnv retrieves environment variable value with fallback to default if not set
func getEnv(key, defaultValue string) string {
	// Check if environment variable exists
	if value, exists := os.LookupEnv(key); exists {
		return value // Return environment variable value
	}
	return defaultValue // Return default value if environment variable not set
}

// sendResponse sends a standardized success response with JSON formatting
func sendResponse(w http.ResponseWriter, code int, status string, data interface{}) {
	w.Header().Set("Content-Type", "application/json") // Set response content type
	w.WriteHeader(code)                                // Set HTTP status code
	// Encode and send JSON response
	if err := json.NewEncoder(w).Encode(Response{Code: code, Status: status, Data: data}); err != nil {
		logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// sendError sends a standardized error response with JSON formatting
func sendError(w http.ResponseWriter, code int, status string, errorMsg string) {
	w.Header().Set("Content-Type", "application/json") // Set response content type
	w.WriteHeader(code)                                // Set HTTP status code
	// Encode and send JSON error response
	if err := json.NewEncoder(w).Encode(Response{Code: code, Status: status, Error: errorMsg}); err != nil {
		logger.Error("Failed to encode JSON error response", zap.Error(err))
	}
}

// postJSONRequest sends a POST request with JSON payload to specified URL
func postJSONRequest(ctx context.Context, urlQ string, payload interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	// Handle different payload types (string or struct)
	switch v := payload.(type) {
	case string:
		// Use string directly as request body
		bodyReader = strings.NewReader(v)
	default:
		// Marshal struct to JSON for request body
		jsonPayload, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonPayload)
	}
	// Create HTTP POST request with context
	req, err := http.NewRequestWithContext(ctx, "POST", urlQ, bodyReader)
	if err != nil {
		return nil, err
	}
	// Set content type to JSON
	req.Header.Set("Content-Type", "application/json")
	// Add authentication header
	req.Header.Set("X-API-Key", nbiAuthKey)
	// Execute HTTP request and return response
	return httpClient.Do(req)
}

// --- Middleware Functions ---

// apiKeyAuthMiddleware validates X-API-Key header for incoming requests
// Uses constant-time comparison to prevent timing attacks
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get API key from header
		apiKey := r.Header.Get(HeaderXAPIKey)

		// Check if API key is provided
		if apiKey == "" {
			sendError(w, http.StatusUnauthorized, StatusUnauthorized, ErrMissingAPIKey)
			return
		}

		// Validate API key using constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(authKey)) != 1 {
			sendError(w, http.StatusUnauthorized, StatusUnauthorized, ErrInvalidAPIKey)
			return
		}

		// API key is valid, proceed to next handler
		next.ServeHTTP(w, r)
	})
}

// newRateLimiter creates a new rate limiter with specified rate and window
func newRateLimiter(rate int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string]*tokenBucket),
		rate:     rate,
		window:   window,
	}
}

// Allow checks if a request from the given IP is allowed
func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.requests[ip]

	if !exists {
		// Create new bucket for this IP
		rl.requests[ip] = &tokenBucket{
			tokens:    rl.rate - 1, // Use one token
			lastReset: now,
		}
		return true
	}

	// Check if window has passed, reset tokens
	if now.Sub(bucket.lastReset) >= rl.window {
		bucket.tokens = rl.rate - 1
		bucket.lastReset = now
		return true
	}

	// Check if tokens available
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

// StartCleanup starts a background goroutine that periodically removes stale IP entries
// to prevent memory leaks from accumulating IP addresses that no longer make requests
func (rl *rateLimiter) StartCleanup() {
	rl.stopCh = make(chan struct{})
	cleanupInterval := rl.window * 2 // Run cleanup at 2x the window interval

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rl.cleanup()
			case <-rl.stopCh:
				return
			}
		}
	}()
}

// StopCleanup stops the background cleanup goroutine
func (rl *rateLimiter) StopCleanup() {
	if rl.stopCh != nil {
		close(rl.stopCh)
	}
}

// cleanup removes stale entries from the rate limiter map
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, bucket := range rl.requests {
		// Remove entries that haven't been accessed in 2x the window period
		if now.Sub(bucket.lastReset) >= rl.window*2 {
			delete(rl.requests, ip)
		}
	}
}

// rateLimitMiddleware creates a middleware that limits requests per IP
func rateLimitMiddleware(rl *rateLimiter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			ip := r.RemoteAddr
			if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
				ip = realIP
			}

			// Check rate limit
			if !rl.Allow(ip) {
				sendError(w, http.StatusTooManyRequests, "Too Many Requests", "Rate limit exceeded. Please try again later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// securityHeadersMiddleware adds security headers to all responses
// to protect against common web vulnerabilities like XSS, clickjacking, etc.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking by denying iframe embedding
		w.Header().Set("X-Frame-Options", "DENY")
		// Enable XSS filter in browsers (legacy browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Prevent caching of sensitive API responses
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		// Content Security Policy - restrict resource loading
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Referrer Policy - don't leak referrer information
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Permissions Policy - disable unnecessary browser features
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

// sanitizeErrorMessage removes potentially sensitive information from error messages
func sanitizeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	errMsg := err.Error()

	// List of patterns that might contain sensitive info
	// Remove device IDs from error messages
	if strings.Contains(errMsg, "device not found with IP") {
		return "Device not found"
	}
	if strings.Contains(errMsg, "no device found with ID") {
		return "Device not found"
	}
	if strings.Contains(errMsg, "device with IP") && strings.Contains(errMsg, "is stale") {
		return "Device is offline or unresponsive"
	}
	if strings.Contains(errMsg, "invalid IP address format") {
		return "Invalid IP address format"
	}
	if strings.Contains(errMsg, "GenieACS returned non-OK status") {
		return "Backend service error"
	}
	if strings.Contains(errMsg, "HTTP error") {
		return "Backend service error"
	}

	// Return generic message for unknown errors to prevent info leakage
	return "An error occurred processing your request"
}

// --- GenieACS Communication Functions ---

// getDeviceData retrieves device data either from cache or from GenieACS API

func getDeviceData(ctx context.Context, deviceID string) (map[string]interface{}, error) {
	// First try to get data from cache to avoid API call
	if cachedData, found := deviceCacheInstance.get(deviceID); found {
		return cachedData, nil // Return cached data if available and fresh
	}

	// Build query to fetch device by ID from GenieACS
	query := fmt.Sprintf(`{"_id":"%s"}`, deviceID)
	urlQ := fmt.Sprintf("%s/devices/?query=%s", geniesBaseURL, url.QueryEscape(query))
	// Create HTTP request with context for cancellation
	req, err := http.NewRequestWithContext(ctx, "GET", urlQ, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication header for GenieACS API
	req.Header.Set("X-API-Key", nbiAuthKey)
	resp, err := httpClient.Do(req) // Execute HTTP request
	if err != nil {
		return nil, err
	}
	defer safeClose(resp.Body) // Ensure response body is closed

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse JSON response into map structure
	var result []map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	// Check if device was found
	if len(result) == 0 {
		return nil, fmt.Errorf("no device found with ID: %s", deviceID)
	}
	deviceData := result[0]                       // Get first (and should be only) device
	deviceCacheInstance.set(deviceID, deviceData) // Cache the retrieved data
	return deviceData, nil
}

// validateIP validates that the provided string is a valid IP address
func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf(ErrInvalidIPAddress, ip)
	}
	return nil
}

// validateWLANID validates that the WLAN ID is a numeric value between 1 and 99
// This prevents path injection and ensures the WLAN ID is in a valid range
func validateWLANID(wlanID string) error {
	// Check if it's a valid number
	num, err := strconv.Atoi(wlanID)
	if err != nil {
		return fmt.Errorf(ErrInvalidWLANID)
	}
	// Check if it's in valid range (1-99)
	if num < 1 || num > 99 {
		return fmt.Errorf(ErrInvalidWLANID)
	}
	return nil
}

// validateSSIDCharacters validates that the SSID contains only allowed characters
// SSIDs should only contain printable ASCII characters (0x20-0x7E) to prevent
// control character injection and display issues on various devices
func validateSSIDCharacters(ssid string) error {
	for _, r := range ssid {
		// Allow only printable ASCII characters (space to tilde)
		// This excludes control characters (0x00-0x1F) and DEL (0x7F)
		// as well as non-ASCII characters that may cause compatibility issues
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf(ErrSSIDInvalidChars)
		}
	}
	return nil
}

// ipQuery represents the MongoDB query structure for IP-based device lookup
type ipQuery struct {
	Or []map[string]string `json:"$or"`
}

// getDeviceIDByIP finds device ID by searching for devices with matching IP address
// It also validates that the device is not stale (last inform within threshold)
func getDeviceIDByIP(ctx context.Context, ip string) (string, error) {
	// Validate IP address format to prevent query injection
	if err := validateIP(ip); err != nil {
		return "", err
	}

	// Construct query using proper JSON marshaling to prevent injection
	queryStruct := ipQuery{
		Or: []map[string]string{
			{FieldSummaryIP: ip},
			{FieldWANPPPConn1: ip},
			{FieldWANPPPConn2: ip},
		},
	}

	queryBytes, err := jsonMarshal(queryStruct)
	if err != nil {
		return "", err
	}
	query := string(queryBytes)
	// Build URL with query parameter - include _lastInform for stale device validation
	urlQ := fmt.Sprintf("%s/devices/?query=%s&projection=_id,_lastInform", geniesBaseURL, url.QueryEscape(query))
	// Create HTTP GET request
	req, err := http.NewRequestWithContext(ctx, "GET", urlQ, nil)
	if err != nil {
		return "", err
	}
	// Add authentication header
	req.Header.Set("X-API-Key", nbiAuthKey)
	// Execute HTTP request
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	// Ensure response body is closed
	defer safeClose(resp.Body)
	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GenieACS returned non-OK status: %s", resp.Status)
	}
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// Parse JSON response into Device slice
	var devices []Device
	if err := json.Unmarshal(body, &devices); err != nil {
		return "", err
	}
	// Check if any devices were found
	if len(devices) == 0 {
		return "", fmt.Errorf("device not found with IP: %s", ip)
	}

	device := devices[0]

	// Validate device is not stale (if staleThreshold is configured and _lastInform is available)
	if staleThreshold > 0 && device.LastInform != nil {
		// GenieACS stores _lastInform as ISO 8601 date string (e.g., "2025-01-16T10:30:00.000Z")
		lastInformTime := *device.LastInform
		timeSinceLastInform := time.Since(lastInformTime)

		// Check if device is stale
		if timeSinceLastInform > staleThreshold {
			return "", fmt.Errorf(ErrDeviceStale, ip, formatDuration(timeSinceLastInform))
		}
	}

	// Return ID of matching device
	return device.ID, nil
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}

// refreshWLANConfig triggers refresh of WLAN configuration data from device
func refreshWLANConfig(ctx context.Context, deviceID string) error {
	// Build URL for refresh task endpoint
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))
	// Prepare refresh task payload
	payload := `{"name": "refreshObject", "objectName": "InternetGatewayDevice.LANDevice.1.WLANConfiguration"}`
	// Send POST request to trigger refresh
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	// Ensure response body is closed
	defer safeClose(resp.Body)
	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}
	return nil
}

// getWLANData extracts WLAN configuration information from device data
func getWLANData(ctx context.Context, deviceID string) ([]WLANConfig, error) {
	// Retrieve device data from cache or GenieACS
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// Check if device is from ZTE (special handling for password masking)
	isZTE := strings.Contains(deviceID, "ZTE") || strings.Contains(deviceID, "ZT")

	// Safely extract InternetGatewayDevice section with type checking
	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("InternetGatewayDevice data not found or invalid format")
	}

	// Safely extract LANDevice section with type checking
	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice data not found or invalid format")
	}

	// Safely extract LANDevice.1 section with type checking
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice.1 data not found")
	}

	// Extract WLANConfiguration section (optional - may not exist)
	wlanConfigsMap, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		// Return empty slice if no WLAN configurations found
		return []WLANConfig{}, nil
	}

	// Process each WLAN configuration
	var configs []WLANConfig
	for key, value := range wlanConfigsMap {
		// Type assert to map for WLAN configuration
		wlan, ok := value.(map[string]interface{})
		if !ok {
			continue // Skip invalid entries
		}

		// Check if WLAN is enabled
		enableMap, ok := wlan["Enable"].(map[string]interface{})
		if !ok {
			continue // Skip if Enable field missing
		}
		// Only process enabled WLAN configurations
		if enable, ok := enableMap["_value"].(bool); !ok || !enable {
			continue // Skip disabled WLANs
		}

		// Extract SSID value
		var ssid string
		if ssidMap, ok := wlan["SSID"].(map[string]interface{}); ok {
			if ssidVal, ok := ssidMap["_value"].(string); ok {
				ssid = ssidVal
			}
		}

		// Create WLANConfig struct and add to results
		configs = append(configs, WLANConfig{
			WLAN:     key,                      // WLAN interface identifier
			SSID:     ssid,                     // Network name
			Password: getPassword(wlan, isZTE), // Security password (masked for ZTE)
			Band:     getBand(wlan, key),       // Frequency band
		})
	}

	// Sort WLAN configurations by interface number (if numeric)
	sort.Slice(configs, func(i, j int) bool {
		numI, errI := strconv.Atoi(configs[i].WLAN)
		numJ, errJ := strconv.Atoi(configs[j].WLAN)

		if errI == nil && errJ == nil {
			return numI < numJ // sort numerically if both are numbers
		}
		return configs[i].WLAN < configs[j].WLAN // fallback to string comparison
	})

	return configs, nil
}

// getPassword extracts password from WLAN configuration
func getPassword(wlan map[string]interface{}, _ bool) string {
	// Try to get password from X_CMS_KeyPassphrase field
	if passMap, ok := wlan["X_CMS_KeyPassphrase"].(map[string]interface{}); ok {
		if pass, ok := passMap["_value"].(string); ok {
			if pass != "" {
				return pass
			}
			// Field exists but empty (encrypted)
			return "******"
		}
	}
	// Try to get password from PreSharedKey structure
	if psk, ok := wlan["PreSharedKey"].(map[string]interface{}); ok {
		if psk1, ok := psk["1"].(map[string]interface{}); ok {
			// Try KeyPassphrase field first
			if keyPassMap, ok := psk1["KeyPassphrase"].(map[string]interface{}); ok {
				if keyPass, ok := keyPassMap["_value"].(string); ok {
					if keyPass != "" {
						return keyPass
					}
					// Field exists but empty (encrypted)
					return "******"
				}
			}
			// Fall back to PreSharedKey field
			if preSharedMap, ok := psk1["PreSharedKey"].(map[string]interface{}); ok {
				if preShared, ok := preSharedMap["_value"].(string); ok {
					if preShared != "" {
						return preShared
					}
					// Field exists but empty (encrypted)
					return "******"
				}
			}
		}
	}
	// No password field found at all
	return "N/A"
}

// getBand determines the frequency band based on WLAN key and Standard field
func getBand(wlan map[string]interface{}, wlanKey string) string {
	// Determine band based on WLAN interface key (common convention)
	if wlanKey == "1" {
		return "2.4GHz" // Typically WLAN1 is 2.4GHz
	} else if wlanKey == "5" {
		return "5GHz" // Typically WLAN5 is 5GHz
	}
	// Fall back to Standard field if key-based detection fails
	if stdMap, ok := wlan["Standard"].(map[string]interface{}); ok {
		if std, ok := stdMap["_value"].(string); ok {
			std = strings.ToLower(std) // Normalize to lowercase
			// Check for 2.4GHz standards
			if strings.ContainsAny(std, "bg") {
				return "2.4GHz"
			}
			// Check for 5GHz standards
			if strings.ContainsAny(std, "ac") {
				return "5GHz"
			}
		}
	}
	// Return unknown if band cannot be determined
	return "Unknown"
}

// getDHCPClients retrieves DHCP client information from device data
func getDHCPClients(ctx context.Context, deviceID string) ([]DHCPClient, error) {
	// Retrieve device data from cache or GenieACS API
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// Safely extract InternetGatewayDevice section with type assertion
	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		// Return error if InternetGatewayDevice section is missing or invalid format
		return nil, fmt.Errorf("InternetGatewayDevice data not found")
	}

	// Safely extract LANDevice section with type assertion
	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		// Return error if LANDevice section is missing or invalid format
		return nil, fmt.Errorf("LANDevice data not found")
	}

	// Safely extract LANDevice.1 section (first LAN device) with type assertion
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		// Return error if LANDevice.1 section is missing
		return nil, fmt.Errorf("LANDevice.1 data not found")
	}

	// Extract Hosts section (optional - may not exist if no DHCP clients)
	hostsMap, ok := lanDevice["Hosts"].(map[string]interface{})
	if !ok {
		// Return empty slice if no Hosts section found (no DHCP clients)
		return []DHCPClient{}, nil
	}

	// Extract Host subsection containing individual client information
	hosts, ok := hostsMap["Host"].(map[string]interface{})
	if !ok {
		// Return empty slice if no Host entries found
		return []DHCPClient{}, nil
	}

	// Process each DHCP client entry
	var clients []DHCPClient
	for _, host := range hosts {
		// Type assert to map for individual host data
		if hostData, ok := host.(map[string]interface{}); ok {
			var client DHCPClient

			// Extract MAC address from host data
			if valMap, ok := hostData["MACAddress"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.MAC = val
				}
			}

			// Extract hostname from host data
			if valMap, ok := hostData["HostName"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.Hostname = val
				}
			}

			// Extract IP address from host data
			if valMap, ok := hostData["IPAddress"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.IP = val
				}
			}

			// Add client to results slice
			clients = append(clients, client)
		}
	}
	return clients, nil
}

// refreshDHCP triggers a refresh of DHCP client information from the device
func refreshDHCP(ctx context.Context, deviceID string) error {
	// Build URL for refresh task endpoint targeting LANDevice.1
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))
	// Prepare refresh task payload for LANDevice section
	payload := `{"name": "refreshObject", "objectName": "InternetGatewayDevice.LANDevice.1"}`
	// Send POST request to trigger DHCP data refresh
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	// Ensure response body is properly closed
	defer safeClose(resp.Body)
	// Check for successful HTTP response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}
	return nil
}

// setParameterValues sends parameter value changes to device via GenieACS
func setParameterValues(ctx context.Context, deviceID string, parameterValues [][]interface{}) error {
	// Build URL for task creation endpoint
	urlQ := fmt.Sprintf("%s/devices/%s/tasks", geniesBaseURL, url.PathEscape(deviceID))
	// Prepare payload for setParameterValues task
	payload := map[string]interface{}{"name": "setParameterValues", "parameterValues": parameterValues}
	// Send POST request to set parameter values
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	// Ensure response body is properly closed
	defer safeClose(resp.Body)
	// Check for successful or accepted HTTP response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		// Read response body for detailed error information
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("set parameter values failed with status: %s (failed to read response body: %v)", resp.Status, readErr)
		}
		return fmt.Errorf("set parameter values failed with status: %s, response: %s", resp.Status, string(body))
	}
	return nil
}

// isWLANValid checks if a specific WLAN interface exists and is enabled on a device
func isWLANValid(ctx context.Context, deviceID, wlanID string) (bool, error) {
	// Retrieve device data from cache or GenieACS API
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		// Return error with wrapping context if device data retrieval fails
		return false, fmt.Errorf("could not get device data for validation: %w", err)
	}

	// Safely extract InternetGatewayDevice section with type assertion
	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		// Return false if InternetGatewayDevice section is missing
		return false, fmt.Errorf("InternetGatewayDevice data not found")
	}

	// Safely extract LANDevice section with type assertion
	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		// Return false if LANDevice section is missing
		return false, fmt.Errorf("LANDevice data not found")
	}

	// Safely extract LANDevice.1 section with type assertion
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		// Return false if LANDevice.1 section is missing
		return false, fmt.Errorf("LANDevice.1 data not found")
	}

	// Extract WLANConfiguration section (optional - device might not have WLAN)
	wlanConfigsMap, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		// Return false if no WLAN configurations exist
		return false, nil
	}

	// Check if the specific WLAN ID exists in the configurations
	wlanConfigData, wlanExists := wlanConfigsMap[wlanID]
	if !wlanExists {
		// Return false if WLAN ID doesn't exist
		return false, nil
	}

	// Type assert to map for WLAN configuration details
	if wlan, ok := wlanConfigData.(map[string]interface{}); ok {
		// Extract Enable field to check if WLAN is enabled
		if enableMap, ok := wlan["Enable"].(map[string]interface{}); ok {
			// Check the actual boolean value of the Enable field
			if enable, ok := enableMap["_value"].(bool); ok && enable {
				// Return true only if WLAN exists AND is enabled
				return true, nil
			}
		}
	}
	// Return false if WLAN exists but is disabled or has invalid configuration
	return false, nil
}

// --- HTTP Request Handlers ---

// healthCheckHandler handles health check requests to verify service status
func healthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	// Return simple health status response indicating service is operational
	sendResponse(w, http.StatusOK, "OK", map[string]string{"status": "healthy"})
}

// clearCacheHandler handles requests to clear device cache (specific device or all)
func clearCacheHandler(w http.ResponseWriter, r *http.Request) {
	// Get device_id query parameter to determine if clearing specific device or all
	deviceID := r.URL.Query().Get("device_id")
	if deviceID != "" {
		// Clear cache for specific device only
		deviceCacheInstance.clear(deviceID)
	} else {
		// Clear entire cache if no specific device specified
		deviceCacheInstance.clearAll()
	}
	// Return success response indicating cache was cleared
	sendResponse(w, http.StatusOK, "OK", map[string]string{"message": "Cache cleared"})
}

// getSSIDByIPHandler retrieves WLAN/SSID information for a device by its IP address
func getSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	// Extract IP address from URL path parameter
	ip := chi.URLParam(r, "ip")
	// Find device ID using the provided IP address
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		// Log error and return 404 if device not found
		logger.Error("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}
	// Retrieve WLAN configuration data for the device
	wlanData, err := getWLANData(r.Context(), deviceID)
	if err != nil {
		// Log error and return 500 if WLAN data retrieval fails
		logger.Error("Failed to get WLAN data", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, sanitizeErrorMessage(err))
		return
	}
	// Return successful response with WLAN data
	sendResponse(w, http.StatusOK, StatusOK, wlanData)
}

// getSSIDByIPForceHandler retrieves WLAN/SSID information, triggering refresh if needed
func getSSIDByIPForceHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip") // Extract IP address from URL path parameter

	// --- Step 1: get device ID ---
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}

	// --- Step 2: setup context & retry config ---
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second) // overall timeout of 60s
	defer cancel()

	// Default retry config
	maxRetries := 12              // default to 12 attempts
	retryDelay := 5 * time.Second // default to 5 seconds between attempts

	// Override with query parameters if provided
	if mrStr := r.URL.Query().Get("max_retries"); mrStr != "" {
		if mr, err := strconv.Atoi(mrStr); err == nil && mr > 0 {
			maxRetries = mr
		}
	}

	// Override retry delay if provided in milliseconds
	if rdStr := r.URL.Query().Get("retry_delay_ms"); rdStr != "" {
		if rd, err := strconv.Atoi(rdStr); err == nil && rd > 0 {
			retryDelay = time.Duration(rd) * time.Millisecond
		}
	}

	var wlanData []WLANConfig // to hold retrieved WLAN data
	refreshDone := false      // flag to ensure refresh is triggered only once

	// --- Step 3: retry loop ---
	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			sendError(w, http.StatusRequestTimeout, "Timeout",
				"Operation timed out while retrieving WLAN data")
			return
		default:
		}

		// clear cache before each attempt
		deviceCacheInstance.clear(deviceID)

		// attempt to get WLAN data
		wlanData, err = getWLANData(ctx, deviceID)

		// handle errors
		if err != nil {
			// Check for context timeout explicitly
			if errors.Is(err, context.DeadlineExceeded) {
				sendError(w, http.StatusRequestTimeout, "Timeout",
					"Operation timed out while retrieving WLAN data")
				return
			}
			// Other errors
			logger.Error("Failed to get WLAN data (error)",
				zap.String("deviceID", deviceID),
				zap.Int("attempt", attempt+1),
				zap.Error(err))
			sendError(w, http.StatusInternalServerError, "Internal Server Error", sanitizeErrorMessage(err))
			return
		}

		// if data found, return immediately
		if len(wlanData) > 0 {
			sendResponse(w, http.StatusOK, "OK", map[string]interface{}{
				"wlan_data": wlanData,
				"attempts":  attempt + 1,
			})
			return
		}

		// Trigger refresh only once if no data found
		if !refreshDone {
			logger.Info("No WLAN data found, triggering refresh",
				zap.String("deviceID", deviceID),
				zap.Int("attempt", attempt+1))
			if err := refreshWLANConfig(ctx, deviceID); err != nil {
				logger.Warn("Failed to refresh WLAN config",
					zap.String("deviceID", deviceID),
					zap.Error(err))
			}
			refreshDone = true
		}

		// wait before next attempt
		time.Sleep(retryDelay)
	}

	// --- Step 4: fail after max retries ---
	sendError(w, http.StatusNotFound, "Not Found",
		fmt.Sprintf("No WLAN data found after %d attempts", maxRetries))
}

// refreshSSIDHandler triggers a refresh of WLAN configuration data for a device
func refreshSSIDHandler(w http.ResponseWriter, r *http.Request) {
	// Extract IP address from URL path parameter
	ip := chi.URLParam(r, "ip")
	// Find device ID using the provided IP address
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		// Log error and return 404 if device not found
		logger.Info("Failed to get device ID by IP for refresh", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", sanitizeErrorMessage(err))
		return
	}
	// Submit refresh task to worker pool for asynchronous processing
	taskWorkerPool.Submit(deviceID, taskTypeRefreshWLAN, nil)
	// Clear cached data for this device to force fresh data on next request
	deviceCacheInstance.clear(deviceID)
	// Return accepted response indicating task was queued
	sendResponse(w, http.StatusAccepted, "Accepted", map[string]string{
		"message": "Refresh task submitted. Please query the GET endpoint again after a few moments.",
	})
}

// getDHCPClientByIPHandler retrieves DHCP client information for a device
func getDHCPClientByIPHandler(w http.ResponseWriter, r *http.Request) {
	// Extract IP address from URL path parameter
	ip := chi.URLParam(r, "ip")
	// Find device ID using the provided IP address
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		// Log error and return 404 if device not found
		logger.Info("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", sanitizeErrorMessage(err))
		return
	}
	// Check if refresh parameter is set to true to force data refresh
	if r.URL.Query().Get("refresh") == "true" {
		// Refresh DHCP data from device
		if err := refreshDHCP(r.Context(), deviceID); err != nil {
			// Log error and return 500 if refresh fails
			logger.Info("DHCP refresh task failed", zap.String("deviceID", deviceID), zap.Error(err))
			sendError(w, http.StatusInternalServerError, "Internal Server Error", "Refresh failed")
			return
		}
	}
	// Retrieve DHCP client information from device
	dhcpClients, err := getDHCPClients(r.Context(), deviceID)
	if err != nil {
		// Log error and return 500 if DHCP data retrieval fails
		logger.Info("Failed to get DHCP clients", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", sanitizeErrorMessage(err))
		return
	}
	// Return successful response with DHCP client data
	sendResponse(w, http.StatusOK, "OK", dhcpClients)
}

// updateSSIDByIPHandler updates the SSID for a specific WLAN interface on a device
func updateSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	// Extract WLAN interface ID and IP address from URL path parameters
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")

	// Validate WLAN ID is a valid numeric value (prevents path injection)
	if err := validateWLANID(wlan); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidWLANID)
		return
	}

	// Limit request body size to prevent DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	// Parse JSON request body containing new SSID value
	var updateReq UpdateSSIDRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		// Check if the error is due to body size limit
		if err.Error() == "http: request body too large" {
			sendError(w, http.StatusRequestEntityTooLarge, "Request Entity Too Large", ErrRequestBodyTooLarge)
			return
		}
		// Return 400 if JSON is malformed
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}
	// Validate that SSID value is provided and not empty
	if updateReq.SSID == "" {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDRequired)
		return
	}
	// Validate SSID has no leading or trailing spaces
	if strings.TrimSpace(updateReq.SSID) != updateReq.SSID {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDInvalidSpaces)
		return
	}
	// Validate SSID length (max 32 characters per IEEE 802.11)
	if len(updateReq.SSID) > MaxSSIDLength {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDTooLong)
		return
	}
	// Validate SSID contains only printable ASCII characters (prevents control char injection)
	if err := validateSSIDCharacters(updateReq.SSID); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDInvalidChars)
		return
	}
	// Find device ID using the provided IP address
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		// Log error and return 404 if device not found
		logger.Error("Failed to get device ID for SSID update", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", sanitizeErrorMessage(err))
		return
	}
	// Validate that the specified WLAN interface exists and is enabled
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		// Log error and return 500 if WLAN validation fails
		logger.Info("Failed to validate WLAN", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", "Could not verify WLAN status.")
		return
	}
	if !valid {
		// Return 404 if WLAN doesn't exist or is disabled
		sendError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("WLAN ID %s does not exist or is not enabled on this device.", wlan))
		return
	}
	// Construct parameter path for SSID configuration
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSID", wlan)
	// Prepare parameter values for setting operation
	parameterValues := [][]interface{}{{parameterPath, updateReq.SSID, "xsd:string"}}
	// Submit set parameter task to worker pool
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	// Submit apply changes task to make configuration active
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	// Clear cached data for this device to reflect changes
	deviceCacheInstance.clear(deviceID)
	// Return success response with update details
	sendResponse(w, http.StatusOK, "OK", map[string]string{
		"message": "SSID update submitted successfully", "device_id": deviceID, "wlan": wlan, "ssid": updateReq.SSID, "ip": ip,
	})
}

// updatePasswordByIPHandler updates the password for a specific WLAN interface on a device
func updatePasswordByIPHandler(w http.ResponseWriter, r *http.Request) {
	// Extract WLAN interface ID and IP address from URL path parameters
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")

	// Validate WLAN ID is a valid numeric value (prevents path injection)
	if err := validateWLANID(wlan); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidWLANID)
		return
	}

	// Limit request body size to prevent DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	// Parse JSON request body containing new password value
	var updateReq UpdatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		// Check if the error is due to body size limit
		if err.Error() == "http: request body too large" {
			sendError(w, http.StatusRequestEntityTooLarge, "Request Entity Too Large", ErrRequestBodyTooLarge)
			return
		}
		// Return 400 if JSON is malformed
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}
	// Validate that password value is provided and not empty
	if updateReq.Password == "" {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordRequired)
		return
	}
	// Validate password length (min 8, max 63 characters per WPA2 standard)
	if len(updateReq.Password) < MinPasswordLength {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooShort)
		return
	}
	if len(updateReq.Password) > MaxPasswordLength {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooLong)
		return
	}
	// Find device ID using the provided IP address
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		// Log error and return 404 if device not found
		logger.Info("Failed to get device ID for password update", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", sanitizeErrorMessage(err))
		return
	}
	// Validate that the specified WLAN interface exists and is enabled
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		// Log error and return 500 if WLAN validation fails
		logger.Info("Failed to validate WLAN for password update", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", "Could not verify WLAN status.")
		return
	}
	if !valid {
		// Return 404 if WLAN doesn't exist or is disabled
		sendError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("WLAN ID %s does not exist or is not enabled on this device.", wlan))
		return
	}
	// Construct parameter path for PreSharedKey configuration
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.PreSharedKey.1.PreSharedKey", wlan)
	// Prepare parameter values for setting operation
	parameterValues := [][]interface{}{{parameterPath, updateReq.Password, "xsd:string"}}
	// Submit set parameter task to worker pool
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	// Submit apply changes task to make configuration active
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	// Clear cached data for this device to reflect changes
	deviceCacheInstance.clear(deviceID)
	// Return success response with update details
	sendResponse(w, http.StatusOK, "OK", map[string]string{
		"message": "Password update submitted successfully", "device_id": deviceID, "wlan": wlan, "ip": ip,
	})
}

// getDeviceCapabilityHandler retrieves the wireless capability of a device (single-band or dual-band)
func getDeviceCapabilityHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	// Get device ID from IP
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for capability check", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}

	// Get device capability
	capability, err := getDeviceCapability(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get device capability", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, "Failed to determine device capability")
		return
	}

	sendResponse(w, http.StatusOK, StatusOK, capability)
}

// CreateWLANRequest represents JSON payload for creating a new WLAN
type CreateWLANRequest struct {
	SSID       string `json:"ssid"`                  // SSID for the new WLAN
	Password   string `json:"password,omitempty"`    // Password for the new WLAN (required for WPA/WPA2)
	Hidden     *bool  `json:"hidden,omitempty"`      // Hide SSID (SSIDAdvertisementEnabled = false)
	MaxClients *int   `json:"max_clients,omitempty"` // Maximum number of associated devices (1-64)
	AuthMode   string `json:"auth_mode,omitempty"`   // Authentication mode: Open, WPA, WPA2, WPA/WPA2
	Encryption string `json:"encryption,omitempty"`  // Encryption mode: AES, TKIP, TKIP+AES
}

// createWLANHandler creates a new WLAN on a device with band capability validation
func createWLANHandler(w http.ResponseWriter, r *http.Request) {
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")

	// Validate WLAN ID format (1-9)
	if err := validateWLANID(wlan); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidWLANID)
		return
	}

	// Parse WLAN ID as integer for band validation
	wlanID, _ := strconv.Atoi(wlan) // Already validated above

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	// Parse request body
	var createReq CreateWLANRequest
	if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
		if err.Error() == "http: request body too large" {
			sendError(w, http.StatusRequestEntityTooLarge, "Request Entity Too Large", ErrRequestBodyTooLarge)
			return
		}
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidJSON)
		return
	}

	// Validate SSID
	if createReq.SSID == "" {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDRequired)
		return
	}
	if strings.TrimSpace(createReq.SSID) != createReq.SSID {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDInvalidSpaces)
		return
	}
	if len(createReq.SSID) > MaxSSIDLength {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDTooLong)
		return
	}
	if err := validateSSIDCharacters(createReq.SSID); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDInvalidChars)
		return
	}

	// Apply defaults for optional fields
	authMode := createReq.AuthMode
	if authMode == "" {
		authMode = "WPA2" // Default to WPA2
	}

	encryption := createReq.Encryption
	if encryption == "" {
		encryption = "AES" // Default to AES
	}

	hidden := DefaultHiddenSSID
	if createReq.Hidden != nil {
		hidden = *createReq.Hidden
	}

	maxClients := DefaultMaxClients
	if createReq.MaxClients != nil {
		maxClients = *createReq.MaxClients
	}

	// Validate authentication mode
	validAuthModes := map[string]string{
		"Open":     AuthModeOpen,
		"WPA":      AuthModeWPA,
		"WPA2":     AuthModeWPA2,
		"WPA/WPA2": AuthModeWPAWPA2,
	}
	beaconType, validAuth := validAuthModes[authMode]
	if !validAuth {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidAuthMode)
		return
	}

	// Validate encryption mode
	validEncryptions := map[string]string{
		"AES":      EncryptionAES,
		"TKIP":     EncryptionTKIP,
		"TKIP+AES": EncryptionTKIPAES,
	}
	encryptionValue, validEnc := validEncryptions[encryption]
	if !validEnc {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidEncryption)
		return
	}

	// Validate max clients
	if maxClients < MinMaxClients || maxClients > MaxMaxClients {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidMaxClients)
		return
	}

	// Validate password - required for non-Open authentication
	if authMode != "Open" {
		if createReq.Password == "" {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordRequiredAuth)
			return
		}
		if len(createReq.Password) < MinPasswordLength {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooShort)
			return
		}
		if len(createReq.Password) > MaxPasswordLength {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooLong)
			return
		}
	}

	// Get device ID from IP
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for WLAN creation", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, err.Error())
		return
	}

	// Check if WLAN already exists and is enabled
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to check WLAN status", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, "Failed to check WLAN status")
		return
	}
	if valid {
		// WLAN already exists and is enabled
		sendError(w, http.StatusConflict, "Conflict",
			fmt.Sprintf("WLAN %s already exists and is enabled on this device. Use the update endpoint to modify it.", wlan))
		return
	}

	// Build parameter values for creating WLAN
	enablePath := fmt.Sprintf(PathWLANEnableFormat, wlan)
	ssidPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSID", wlan)
	ssidAdvertisementPath := fmt.Sprintf(PathWLANSSIDAdvertisementFormat, wlan)
	maxAssocDevicesPath := fmt.Sprintf(PathWLANMaxAssocDevicesFormat, wlan)
	beaconTypePath := fmt.Sprintf(PathWLANBeaconTypeFormat, wlan)

	parameterValues := [][]interface{}{
		{enablePath, true, XSDBoolean},
		{ssidPath, createReq.SSID, XSDString},
		{ssidAdvertisementPath, !hidden, XSDBoolean}, // SSIDAdvertisementEnabled = true means visible (not hidden)
		{maxAssocDevicesPath, maxClients, XSDUnsignedInt},
		{beaconTypePath, beaconType, XSDString},
	}

	// Add password and encryption settings for non-Open authentication
	if authMode != "Open" {
		passwordPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.PreSharedKey.1.PreSharedKey", wlan)
		parameterValues = append(parameterValues, []interface{}{passwordPath, createReq.Password, XSDString})

		// Set encryption based on authentication mode
		if authMode == "WPA" {
			// WPA only - set WPAEncryptionModes
			wpaEncryptionPath := fmt.Sprintf(PathWLANWPAEncryptionModesFormat, wlan)
			wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
			parameterValues = append(parameterValues,
				[]interface{}{wpaEncryptionPath, encryptionValue, XSDString},
				[]interface{}{wpaAuthModePath, "PSKAuthentication", XSDString},
			)
		} else if authMode == "WPA2" {
			// WPA2 only (11i) - set IEEE11iEncryptionModes
			ieee11iEncryptionPath := fmt.Sprintf(PathWLAN11iEncryptionModesFormat, wlan)
			ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
			parameterValues = append(parameterValues,
				[]interface{}{ieee11iEncryptionPath, encryptionValue, XSDString},
				[]interface{}{ieee11iAuthModePath, "PSKAuthentication", XSDString},
			)
		} else if authMode == "WPA/WPA2" {
			// WPA and WPA2 - set both encryption modes
			wpaEncryptionPath := fmt.Sprintf(PathWLANWPAEncryptionModesFormat, wlan)
			wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
			ieee11iEncryptionPath := fmt.Sprintf(PathWLAN11iEncryptionModesFormat, wlan)
			ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
			parameterValues = append(parameterValues,
				[]interface{}{wpaEncryptionPath, encryptionValue, XSDString},
				[]interface{}{wpaAuthModePath, "PSKAuthentication", XSDString},
				[]interface{}{ieee11iEncryptionPath, encryptionValue, XSDString},
				[]interface{}{ieee11iAuthModePath, "PSKAuthentication", XSDString},
			)
		}
	}

	// Submit set parameter task
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	// Submit apply changes task
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	// Clear cache
	deviceCacheInstance.clear(deviceID)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	// Build response with applied settings
	responseData := map[string]interface{}{
		"message":     "WLAN creation submitted successfully",
		"device_id":   deviceID,
		"wlan":        wlan,
		"ssid":        createReq.SSID,
		"band":        band,
		"ip":          ip,
		"hidden":      hidden,
		"max_clients": maxClients,
		"auth_mode":   authMode,
		"encryption":  encryption,
	}

	sendResponse(w, http.StatusOK, StatusOK, responseData)
}

// UsedWLANInfo contains information about a WLAN slot that is in use
type UsedWLANInfo struct {
	WLANID int    `json:"wlan_id"`
	SSID   string `json:"ssid"`
	Band   string `json:"band"`
}

// AvailableWLANResponse contains the response for available WLAN slots endpoint
type AvailableWLANResponse struct {
	DeviceID   string `json:"device_id"`
	Model      string `json:"model"`
	BandType   string `json:"band_type"`
	TotalSlots struct {
		Band24GHz []int `json:"2_4ghz"`
		Band5GHz  []int `json:"5ghz"`
	} `json:"total_slots"`
	UsedWLAN      []UsedWLANInfo `json:"used_wlan"`
	AvailableWLAN struct {
		Band24GHz []int `json:"2_4ghz"`
		Band5GHz  []int `json:"5ghz"`
	} `json:"available_wlan"`
	ConfigOptions struct {
		AuthModes   []string `json:"auth_modes"`
		Encryptions []string `json:"encryptions"`
		MaxClients  struct {
			Min     int `json:"min"`
			Max     int `json:"max"`
			Default int `json:"default"`
		} `json:"max_clients"`
	} `json:"config_options"`
}

// getAvailableWLANHandler returns available WLAN slots for a device
func getAvailableWLANHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	// Get device ID from IP
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for available WLAN check", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}

	// Get device capability
	capability, err := getDeviceCapability(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get device capability", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, "Failed to get device capability")
		return
	}

	// Get current WLAN configurations (enabled ones)
	wlanConfigs, err := getWLANData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get WLAN data", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, "Failed to get WLAN data")
		return
	}

	// Build used WLAN info and track used IDs
	usedWLANIDs := make(map[int]bool)
	var usedWLAN []UsedWLANInfo
	for _, wlan := range wlanConfigs {
		wlanID, err := strconv.Atoi(wlan.WLAN)
		if err != nil {
			continue // Skip invalid WLAN IDs
		}
		usedWLANIDs[wlanID] = true
		usedWLAN = append(usedWLAN, UsedWLANInfo{
			WLANID: wlanID,
			SSID:   wlan.SSID,
			Band:   wlan.Band,
		})
	}

	// Calculate total slots based on band type
	var total24GHz, total5GHz []int
	for i := WLAN24GHzMin; i <= WLAN24GHzMax; i++ {
		total24GHz = append(total24GHz, i)
	}
	if capability.IsDualBand {
		for i := WLAN5GHzMin; i <= WLAN5GHzMax; i++ {
			total5GHz = append(total5GHz, i)
		}
	}

	// Calculate available slots
	var available24GHz, available5GHz []int
	for i := WLAN24GHzMin; i <= WLAN24GHzMax; i++ {
		if !usedWLANIDs[i] {
			available24GHz = append(available24GHz, i)
		}
	}
	if capability.IsDualBand {
		for i := WLAN5GHzMin; i <= WLAN5GHzMax; i++ {
			if !usedWLANIDs[i] {
				available5GHz = append(available5GHz, i)
			}
		}
	}

	// Build response
	response := AvailableWLANResponse{
		DeviceID: deviceID,
		Model:    capability.Model,
		BandType: string(capability.BandType),
	}
	response.TotalSlots.Band24GHz = total24GHz
	response.TotalSlots.Band5GHz = total5GHz
	if response.TotalSlots.Band5GHz == nil {
		response.TotalSlots.Band5GHz = []int{}
	}

	response.UsedWLAN = usedWLAN
	if response.UsedWLAN == nil {
		response.UsedWLAN = []UsedWLANInfo{}
	}

	response.AvailableWLAN.Band24GHz = available24GHz
	if response.AvailableWLAN.Band24GHz == nil {
		response.AvailableWLAN.Band24GHz = []int{}
	}
	response.AvailableWLAN.Band5GHz = available5GHz
	if response.AvailableWLAN.Band5GHz == nil {
		response.AvailableWLAN.Band5GHz = []int{}
	}

	// Add configuration options for frontend
	response.ConfigOptions.AuthModes = []string{"Open", "WPA", "WPA2", "WPA/WPA2"}
	response.ConfigOptions.Encryptions = []string{"AES", "TKIP", "TKIP+AES"}
	response.ConfigOptions.MaxClients.Min = MinMaxClients
	response.ConfigOptions.MaxClients.Max = MaxMaxClients
	response.ConfigOptions.MaxClients.Default = DefaultMaxClients

	sendResponse(w, http.StatusOK, StatusOK, response)
}

// UpdateWLANRequest contains the request body for updating a WLAN
type UpdateWLANRequest struct {
	SSID       *string `json:"ssid,omitempty"`        // New SSID (optional)
	Password   *string `json:"password,omitempty"`    // New password (optional)
	Hidden     *bool   `json:"hidden,omitempty"`      // Hide SSID (optional)
	MaxClients *int    `json:"max_clients,omitempty"` // Maximum clients (optional)
	AuthMode   *string `json:"auth_mode,omitempty"`   // Authentication mode (optional)
	Encryption *string `json:"encryption,omitempty"`  // Encryption mode (optional)
}

// OptimizeWLANRequest contains the request body for optimizing WLAN radio settings
type OptimizeWLANRequest struct {
	Channel       *string `json:"channel,omitempty"`        // Channel: Auto, or channel number
	Mode          *string `json:"mode,omitempty"`           // WiFi standard mode (b, g, n, b/g, g/n, b/g/n for 2.4GHz; a, n, ac, a/n, a/n/ac for 5GHz)
	Bandwidth     *string `json:"bandwidth,omitempty"`      // Bandwidth: 20MHz, 40MHz, 80MHz (5GHz only), Auto
	TransmitPower *int    `json:"transmit_power,omitempty"` // Transmit power percentage: 0, 20, 40, 60, 80, 100
}

// updateWLANHandler updates an existing WLAN configuration
func updateWLANHandler(w http.ResponseWriter, r *http.Request) {
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")

	// Validate WLAN ID format (1-9)
	if err := validateWLANID(wlan); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidWLANID)
		return
	}

	// Parse WLAN ID as integer for band validation
	wlanID, _ := strconv.Atoi(wlan)

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	// Parse request body
	var updateReq UpdateWLANRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		if err.Error() == "http: request body too large" {
			sendError(w, http.StatusRequestEntityTooLarge, "Request Entity Too Large", ErrRequestBodyTooLarge)
			return
		}
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidJSON)
		return
	}

	// Check if at least one field is provided
	if updateReq.SSID == nil && updateReq.Password == nil && updateReq.Hidden == nil &&
		updateReq.MaxClients == nil && updateReq.AuthMode == nil && updateReq.Encryption == nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, "At least one field must be provided for update")
		return
	}

	// Get device ID from IP
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for WLAN update", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, err.Error())
		return
	}

	// Check if WLAN exists and is enabled
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to check WLAN status", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, "Failed to check WLAN status")
		return
	}
	if !valid {
		sendError(w, http.StatusNotFound, StatusNotFound,
			fmt.Sprintf("WLAN %s does not exist or is not enabled on this device. Use the create endpoint to create it first.", wlan))
		return
	}

	// Build parameter values for updating WLAN
	var parameterValues [][]interface{}
	updatedFields := make(map[string]interface{})

	// Validate and add SSID if provided
	if updateReq.SSID != nil {
		ssid := *updateReq.SSID
		if ssid == "" {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDRequired)
			return
		}
		if strings.TrimSpace(ssid) != ssid {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDInvalidSpaces)
			return
		}
		if len(ssid) > MaxSSIDLength {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDTooLong)
			return
		}
		if err := validateSSIDCharacters(ssid); err != nil {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrSSIDInvalidChars)
			return
		}
		ssidPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSID", wlan)
		parameterValues = append(parameterValues, []interface{}{ssidPath, ssid, XSDString})
		updatedFields["ssid"] = ssid
	}

	// Validate and add password if provided
	if updateReq.Password != nil {
		password := *updateReq.Password
		if len(password) < MinPasswordLength {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooShort)
			return
		}
		if len(password) > MaxPasswordLength {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooLong)
			return
		}
		passwordPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.PreSharedKey.1.PreSharedKey", wlan)
		parameterValues = append(parameterValues, []interface{}{passwordPath, password, XSDString})
		updatedFields["password"] = "********" // Mask password in response
	}

	// Add hidden SSID setting if provided
	if updateReq.Hidden != nil {
		hidden := *updateReq.Hidden
		ssidAdvertisementPath := fmt.Sprintf(PathWLANSSIDAdvertisementFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{ssidAdvertisementPath, !hidden, XSDBoolean})
		updatedFields["hidden"] = hidden
	}

	// Validate and add max clients if provided
	if updateReq.MaxClients != nil {
		maxClients := *updateReq.MaxClients
		if maxClients < MinMaxClients || maxClients > MaxMaxClients {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidMaxClients)
			return
		}
		maxAssocDevicesPath := fmt.Sprintf(PathWLANMaxAssocDevicesFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{maxAssocDevicesPath, maxClients, XSDUnsignedInt})
		updatedFields["max_clients"] = maxClients
	}

	// Validate and add auth mode if provided
	if updateReq.AuthMode != nil {
		authMode := *updateReq.AuthMode
		validAuthModes := map[string]string{
			"Open":     AuthModeOpen,
			"WPA":      AuthModeWPA,
			"WPA2":     AuthModeWPA2,
			"WPA/WPA2": AuthModeWPAWPA2,
		}
		beaconType, validAuth := validAuthModes[authMode]
		if !validAuth {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidAuthMode)
			return
		}
		beaconTypePath := fmt.Sprintf(PathWLANBeaconTypeFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{beaconTypePath, beaconType, XSDString})
		updatedFields["auth_mode"] = authMode

		// Set authentication mode parameters based on type
		if authMode == "WPA" {
			wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
			parameterValues = append(parameterValues, []interface{}{wpaAuthModePath, "PSKAuthentication", XSDString})
		} else if authMode == "WPA2" {
			ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
			parameterValues = append(parameterValues, []interface{}{ieee11iAuthModePath, "PSKAuthentication", XSDString})
		} else if authMode == "WPA/WPA2" {
			wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
			ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
			parameterValues = append(parameterValues,
				[]interface{}{wpaAuthModePath, "PSKAuthentication", XSDString},
				[]interface{}{ieee11iAuthModePath, "PSKAuthentication", XSDString},
			)
		}
	}

	// Validate and add encryption if provided
	if updateReq.Encryption != nil {
		encryption := *updateReq.Encryption
		validEncryptions := map[string]string{
			"AES":      EncryptionAES,
			"TKIP":     EncryptionTKIP,
			"TKIP+AES": EncryptionTKIPAES,
		}
		encryptionValue, validEnc := validEncryptions[encryption]
		if !validEnc {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidEncryption)
			return
		}

		// Set encryption for both WPA and WPA2 paths to cover all cases
		wpaEncryptionPath := fmt.Sprintf(PathWLANWPAEncryptionModesFormat, wlan)
		ieee11iEncryptionPath := fmt.Sprintf(PathWLAN11iEncryptionModesFormat, wlan)
		parameterValues = append(parameterValues,
			[]interface{}{wpaEncryptionPath, encryptionValue, XSDString},
			[]interface{}{ieee11iEncryptionPath, encryptionValue, XSDString},
		)
		updatedFields["encryption"] = encryption
	}

	// Submit set parameter task
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	// Submit apply changes task
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	// Clear cache
	deviceCacheInstance.clear(deviceID)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	// Build response
	responseData := map[string]interface{}{
		"message":        "WLAN update submitted successfully",
		"device_id":      deviceID,
		"wlan":           wlan,
		"band":           band,
		"ip":             ip,
		"updated_fields": updatedFields,
	}

	sendResponse(w, http.StatusOK, StatusOK, responseData)
}

// deleteWLANHandler disables/deletes a WLAN configuration
func deleteWLANHandler(w http.ResponseWriter, r *http.Request) {
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")

	// Validate WLAN ID format (1-9)
	if err := validateWLANID(wlan); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidWLANID)
		return
	}

	// Parse WLAN ID as integer for band validation
	wlanID, _ := strconv.Atoi(wlan)

	// Get device ID from IP
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for WLAN deletion", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, err.Error())
		return
	}

	// Check if WLAN exists and is enabled
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to check WLAN status", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, "Failed to check WLAN status")
		return
	}
	if !valid {
		sendError(w, http.StatusNotFound, StatusNotFound,
			fmt.Sprintf("WLAN %s does not exist or is already disabled on this device.", wlan))
		return
	}

	// Build parameter values for disabling WLAN
	enablePath := fmt.Sprintf(PathWLANEnableFormat, wlan)
	parameterValues := [][]interface{}{
		{enablePath, false, XSDBoolean},
	}

	// Submit set parameter task
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	// Submit apply changes task
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	// Clear cache
	deviceCacheInstance.clear(deviceID)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	sendResponse(w, http.StatusOK, StatusOK, map[string]string{
		"message":   "WLAN deletion submitted successfully",
		"device_id": deviceID,
		"wlan":      wlan,
		"band":      band,
		"ip":        ip,
	})
}

// optimizeWLANHandler optimizes WLAN radio settings (channel, mode, bandwidth, transmit power)
func optimizeWLANHandler(w http.ResponseWriter, r *http.Request) {
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")

	// Validate WLAN ID format (1-8)
	if err := validateWLANID(wlan); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidWLANID)
		return
	}

	// Parse WLAN ID as integer for band validation
	wlanID, _ := strconv.Atoi(wlan)

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	// Parse request body
	var optimizeReq OptimizeWLANRequest
	if err := json.NewDecoder(r.Body).Decode(&optimizeReq); err != nil {
		if err.Error() == "http: request body too large" {
			sendError(w, http.StatusRequestEntityTooLarge, "Request Entity Too Large", ErrRequestBodyTooLarge)
			return
		}
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidJSON)
		return
	}

	// Check if at least one field is provided
	if optimizeReq.Channel == nil && optimizeReq.Mode == nil &&
		optimizeReq.Bandwidth == nil && optimizeReq.TransmitPower == nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrNoOptimizeFields)
		return
	}

	// Get device ID from IP
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for WLAN optimization", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, err.Error())
		return
	}

	// Check if WLAN exists and is enabled
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to check WLAN status", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, "Failed to check WLAN status")
		return
	}
	if !valid {
		sendError(w, http.StatusNotFound, StatusNotFound,
			fmt.Sprintf("WLAN %s does not exist or is not enabled on this device.", wlan))
		return
	}

	// Determine band based on WLAN ID
	is5GHz := wlanID >= WLAN5GHzMin && wlanID <= WLAN5GHzMax
	band := Band2_4GHz
	if is5GHz {
		band = Band5GHz
	}

	// Build parameter values for optimization
	var parameterValues [][]interface{}
	updatedSettings := make(map[string]interface{})

	// Validate and add channel if provided
	if optimizeReq.Channel != nil {
		channel := *optimizeReq.Channel
		if is5GHz {
			if !ValidChannels5GHz[channel] {
				sendError(w, http.StatusBadRequest, StatusBadRequest, fmt.Sprintf(ErrInvalidChannel5GHz, channel))
				return
			}
		} else {
			if !ValidChannels24GHz[channel] {
				sendError(w, http.StatusBadRequest, StatusBadRequest, fmt.Sprintf(ErrInvalidChannel24GHz, channel))
				return
			}
		}

		// Handle Auto channel setting
		autoChannelPath := fmt.Sprintf(PathWLANAutoChannelEnableFormat, wlan)
		if channel == ChannelAuto {
			parameterValues = append(parameterValues, []interface{}{autoChannelPath, true, XSDBoolean})
		} else {
			// Set specific channel and disable auto channel
			channelPath := fmt.Sprintf(PathWLANChannelFormat, wlan)
			channelNum, _ := strconv.Atoi(channel)
			parameterValues = append(parameterValues,
				[]interface{}{autoChannelPath, false, XSDBoolean},
				[]interface{}{channelPath, channelNum, XSDUnsignedInt},
			)
		}
		updatedSettings["channel"] = channel
	}

	// Validate and add mode if provided
	if optimizeReq.Mode != nil {
		mode := *optimizeReq.Mode
		var tr069Mode string
		var validMode bool

		if is5GHz {
			tr069Mode, validMode = ValidModes5GHz[mode]
			if !validMode {
				sendError(w, http.StatusBadRequest, StatusBadRequest, fmt.Sprintf(ErrInvalidMode5GHz, mode))
				return
			}
		} else {
			tr069Mode, validMode = ValidModes24GHz[mode]
			if !validMode {
				sendError(w, http.StatusBadRequest, StatusBadRequest, fmt.Sprintf(ErrInvalidMode24GHz, mode))
				return
			}
		}

		modePath := fmt.Sprintf(PathWLANOperatingStandardFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{modePath, tr069Mode, XSDString})
		updatedSettings["mode"] = mode
	}

	// Validate and add bandwidth if provided
	if optimizeReq.Bandwidth != nil {
		bandwidth := *optimizeReq.Bandwidth
		if is5GHz {
			if !ValidBandwidth5GHz[bandwidth] {
				sendError(w, http.StatusBadRequest, StatusBadRequest, fmt.Sprintf(ErrInvalidBandwidth5GHz, bandwidth))
				return
			}
		} else {
			if !ValidBandwidth24GHz[bandwidth] {
				sendError(w, http.StatusBadRequest, StatusBadRequest, fmt.Sprintf(ErrInvalidBandwidth24GHz, bandwidth))
				return
			}
		}

		bandwidthPath := fmt.Sprintf(PathWLANChannelBandwidthFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{bandwidthPath, bandwidth, XSDString})
		updatedSettings["bandwidth"] = bandwidth
	}

	// Validate and add transmit power if provided
	if optimizeReq.TransmitPower != nil {
		power := *optimizeReq.TransmitPower
		if !ValidTransmitPower[power] {
			sendError(w, http.StatusBadRequest, StatusBadRequest, fmt.Sprintf(ErrInvalidTransmitPower, power))
			return
		}

		powerPath := fmt.Sprintf(PathWLANTransmitPowerFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{powerPath, power, XSDUnsignedInt})
		updatedSettings["transmit_power"] = power
	}

	// Submit set parameter task
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	// Submit apply changes task
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	// Clear cache
	deviceCacheInstance.clear(deviceID)

	// Build response
	responseData := map[string]interface{}{
		"message":          MsgWLANOptimizeSubmitted,
		"device_id":        deviceID,
		"wlan":             wlan,
		"band":             band,
		"ip":               ip,
		"updated_settings": updatedSettings,
	}

	sendResponse(w, http.StatusOK, StatusOK, responseData)
}
