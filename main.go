package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// Task types for worker pool operations - constants to identify different task types
const (
	taskTypeSetParams    = "setParameterValues" // Task to set parameter values on devices
	taskTypeApplyChanges = "applyChanges"       // Task to apply configuration changes
	taskTypeRefreshWLAN  = "refreshWLAN"        // Task to refresh WLAN configuration data
)

// Global variables for application configuration and shared resources
var (
	serverAddr    string
	geniesBaseURL string      // Base URL for GenieACS server API endpoints
	nbiAuthKey    string      // Authentication key for GenieACS Northbound Interface (NBI)
	logger        *zap.Logger // Structured logger for application logging
)

// Pre-initialized variables and instances for modularity
var (

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
	newHTTPServer = func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:    addr,    // Server address to listen on
			Handler: handler, // HTTP handler for incoming requests
		}
	}

	runServerFunc = runServer // Function to start the HTTP server (for easier testing/mock

)

// --- Struct Definitions ---
// deviceCache provides thread-safe caching mechanism for device data with expiration
type deviceCache struct {
	mu      sync.RWMutex                // Read-write mutex for concurrent access
	data    map[string]cachedDeviceData // Cache storage mapping device IDs to cached data
	timeout time.Duration               // Duration after which cached data is considered stale
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

// -- Task Definition ---

// task represents a unit of work to be processed by the worker pool
type task struct {
	deviceID string          // Target device identifier for the task
	taskType string          // Type of task to execute (see taskType constants)
	params   [][]interface{} // Parameters for parameter-setting tasks
}

// Device represents a network device with its unique identifier
type Device struct {
	ID string `json:"_id"` // Device unique identifier from GenieACS
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
	geniesBaseURL = getEnv("GENIEACS_BASE_URL", "http://localhost:7557")
	nbiAuthKey = getEnv("NBI_AUTH_KEY", "ThisIsNBIAuthKey")

	// start worker pool
	taskWorkerPool.Start()
	defer taskWorkerPool.Stop()

	logger.Info("Starting server", zap.String("genieacs_url", geniesBaseURL))

	// router
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Get("/health", healthCheckHandler)
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Get("/force/ssid/{ip}", getSSIDByIPForceHandler)
		r.Post("/ssid/{i"+
			"p}/refresh", refreshSSIDHandler)
		r.Put("/ssid/update/{wlan}/{ip}", updateSSIDByIPHandler)
		r.Put("/password/update/{wlan}/{ip}", updatePasswordByIPHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/cache/clear", clearCacheHandler)
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
	// Create specified number of worker goroutines
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)   // Increment WaitGroup counter
		go wp.worker() // Start worker goroutine
	}
}

// Stop gracefully shuts down the worker pool by closing queue and waiting for completion
func (wp *workerPool) Stop() {
	wp.once.Do(func() { // Ensure Stop is only executed once
		close(wp.queue) // Close task queue to signal workers to stop
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
func (wp *workerPool) Submit(deviceID, taskType string, params [][]interface{}) {
	wp.queue <- task{deviceID, taskType, params} // Send task to queue channel
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

// getDeviceIDByIP finds device ID by searching for devices with matching IP address
func getDeviceIDByIP(ctx context.Context, ip string) (string, error) {
	// Construct query to find device by IP address in multiple possible fields
	query := fmt.Sprintf(`{"$or":[
{"summary.ip": "%s"},
{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value": "%s"},
{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.2.ExternalIPAddress._value": "%s"}
]}`, ip, ip, ip)
	// Build URL with query parameter
	urlQ := fmt.Sprintf("%s/devices/?query=%s&projection=_id", geniesBaseURL, url.QueryEscape(query))
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
	// Return ID of first matching device
	return devices[0].ID, nil
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

// getPassword extracts password from WLAN configuration with special handling for ZTE devices
func getPassword(wlan map[string]interface{}, isZTE bool) string {
	// Mask password for ZTE devices (security measure)
	if isZTE {
		return "********"
	}
	// Try to get password from X_CMS_KeyPassphrase field
	if passMap, ok := wlan["X_CMS_KeyPassphrase"].(map[string]interface{}); ok {
		if pass, ok := passMap["_value"].(string); ok && pass != "" {
			return pass
		}
	}
	// Try to get password from PreSharedKey structure
	if psk, ok := wlan["PreSharedKey"].(map[string]interface{}); ok {
		if psk1, ok := psk["1"].(map[string]interface{}); ok {
			// Try KeyPassphrase field first
			if keyPassMap, ok := psk1["KeyPassphrase"].(map[string]interface{}); ok {
				if keyPass, ok := keyPassMap["_value"].(string); ok && keyPass != "" {
					return keyPass
				}
			}
			// Fall back to PreSharedKey field
			if preSharedMap, ok := psk1["PreSharedKey"].(map[string]interface{}); ok {
				if preShared, ok := preSharedMap["_value"].(string); ok && preShared != "" {
					return preShared
				}
			}
		}
	}
	// Return "N/A" if no password field found
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
		body, _ := io.ReadAll(resp.Body)
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
		logger.Info("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	// Retrieve WLAN configuration data for the device
	wlanData, err := getWLANData(r.Context(), deviceID)
	if err != nil {
		// Log error and return 500 if WLAN data retrieval fails
		logger.Info("Failed to get WLAN data", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	// Return successful response with WLAN data
	sendResponse(w, http.StatusOK, "OK", wlanData)
}

// getSSIDByIPForceHandler retrieves WLAN/SSID information, triggering refresh if needed
func getSSIDByIPForceHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip") // Extract IP address from URL path parameter

	// --- Step 1: get device ID ---
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Info("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
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
			sendError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
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
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
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
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	// Check if refresh parameter is set to true to force data refresh
	if r.URL.Query().Get("refresh") == "true" {
		// Refresh DHCP data from device
		if err := refreshDHCP(r.Context(), deviceID); err != nil {
			// Log error and return 500 if refresh fails
			logger.Info("DHCP refresh task failed", zap.String("deviceID", deviceID), zap.Error(err))
			sendError(w, http.StatusInternalServerError, "Internal Server Error", "Refresh failed: "+err.Error())
			return
		}
	}
	// Retrieve DHCP client information from device
	dhcpClients, err := getDHCPClients(r.Context(), deviceID)
	if err != nil {
		// Log error and return 500 if DHCP data retrieval fails
		logger.Info("Failed to get DHCP clients", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
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
	// Parse JSON request body containing new SSID value
	var updateReq UpdateSSIDRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		// Return 400 if JSON is malformed
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}
	// Validate that SSID value is provided and not empty
	if updateReq.SSID == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "SSID value required")
		return
	}
	// Find device ID using the provided IP address
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		// Log error and return 404 if device not found
		logger.Error("Failed to get device ID for SSID update", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
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
	// Parse JSON request body containing new password value
	var updateReq UpdatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		// Return 400 if JSON is malformed
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}
	// Validate that password value is provided and not empty
	if updateReq.Password == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "Password value required")
		return
	}
	// Find device ID using the provided IP address
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		// Log error and return 404 if device not found
		logger.Info("Failed to get device ID for password update", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
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
