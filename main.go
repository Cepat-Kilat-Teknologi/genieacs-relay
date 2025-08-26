package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Global variables
var (
	genieacsBaseURL string
	validAPIKey     string
)

// Cache untuk device data dengan TTL
type deviceCache struct {
	sync.RWMutex
	data    map[string]cachedDeviceData
	timeout time.Duration
}

type cachedDeviceData struct {
	data      map[string]interface{}
	timestamp time.Time
}

var (
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
		},
	}

	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second, // Cache 30 detik
	}

	// Worker pool untuk concurrent operations
	taskWorkerPool = &workerPool{
		workers: 10,
		queue:   make(chan task, 100),
	}
)

type Device struct {
	ID string `json:"_id"`
}

type WLANConfig struct {
	WLAN     string `json:"wlan"`
	SSID     string `json:"ssid"`
	Password string `json:"password"`
	Band     string `json:"band"`
}

type DHCPClient struct {
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

type UpdateSSIDRequest struct {
	SSID string `json:"ssid"`
}

type UpdatePasswordRequest struct {
	Password string `json:"password"`
}

type Response struct {
	Code   int         `json:"code"`
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// Worker pool implementation
type task struct {
	deviceID string
	taskType string
	params   [][]interface{}
}

type workerPool struct {
	workers int
	queue   chan task
	wg      sync.WaitGroup
}

func (wp *workerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *workerPool) Stop() {
	close(wp.queue)
	wp.wg.Wait()
}

func (wp *workerPool) worker() {
	defer wp.wg.Done()

	for t := range wp.queue {
		switch t.taskType {
		case "setParameterValues":
			setParameterValues(t.deviceID, t.params)
		case "applyChanges":
			applyChanges(t.deviceID)
		case "refreshWLAN":
			refreshWLANConfig(t.deviceID)
		}
	}
}

func (wp *workerPool) Submit(deviceID, taskType string, params [][]interface{}) {
	wp.queue <- task{
		deviceID: deviceID,
		taskType: taskType,
		params:   params,
	}
}

func (c *deviceCache) get(deviceID string) (map[string]interface{}, bool) {
	c.RLock()
	defer c.RUnlock()

	if cached, exists := c.data[deviceID]; exists {
		if time.Since(cached.timestamp) < c.timeout {
			return cached.data, true
		}
	}
	return nil, false
}

func (c *deviceCache) set(deviceID string, data map[string]interface{}) {
	c.Lock()
	defer c.Unlock()

	c.data[deviceID] = cachedDeviceData{
		data:      data,
		timestamp: time.Now(),
	}
}

func (c *deviceCache) clear(deviceID string) {
	c.Lock()
	defer c.Unlock()
	delete(c.data, deviceID)
}

// Fungsi untuk mendapatkan device data dengan cache
func getDeviceData(deviceID string) (map[string]interface{}, error) {
	// Cek cache dulu
	if cachedData, found := deviceCacheInstance.get(deviceID); found {
		return cachedData, nil
	}

	query := fmt.Sprintf(`{"_id":"%s"}`, deviceID)
	encodedQuery := url.QueryEscape(query)
	url := fmt.Sprintf("%s/devices/?query=%s", genieacsBaseURL, encodedQuery)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", validAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no device found with ID: %s", deviceID)
	}

	deviceData := result[0]
	deviceCacheInstance.set(deviceID, deviceData)

	return deviceData, nil
}

// Helper functions untuk response
func sendResponse(w http.ResponseWriter, code int, status string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Code:   code,
		Status: status,
		Data:   data,
	})
}

func sendError(w http.ResponseWriter, code int, status string, errorMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Code:   code,
		Status: status,
		Error:  errorMsg,
	})
}

// Middleware untuk memeriksa API Key
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != validAPIKey {
			sendError(w, http.StatusUnauthorized, "Unauthorized", "Invalid API Key")
			return
		}
		next(w, r)
	}
}

func main() {
	// Load environment variables
	genieacsBaseURL = getEnv("GENIEACS_BASE_URL", "http://192.168.212.138:6969")
	validAPIKey = getEnv("VALID_API_KEY", "alhamdulillah")

	// Start worker pool
	taskWorkerPool.Start()
	defer taskWorkerPool.Stop()

	log.Printf("Starting server with GenieACS URL: %s", genieacsBaseURL)

	// Existing handlers...
	http.HandleFunc("/api/v1/genieacs/ssid/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getSSIDByIPHandler(w, r)
		} else {
			sendError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Method not allowed")
		}
	}))

	http.HandleFunc("/api/v1/genieacs/ssid/update/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			updateSSIDByIPHandler(w, r)
		} else {
			sendError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Method not allowed")
		}
	}))

	http.HandleFunc("/api/v1/genieacs/password/update/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			updatePasswordByIPHandler(w, r)
		} else {
			sendError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Method not allowed")
		}
	}))

	// New handler for DHCP client by IP
	http.HandleFunc("/api/v1/genieacs/dhcp-client/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getDHCPClientByIPHandler(w, r)
		} else {
			sendError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Method not allowed")
		}
	}))

	// Health check endpoint
	http.HandleFunc("/api/v1/genieacs/ssid/health", func(w http.ResponseWriter, r *http.Request) {
		sendResponse(w, http.StatusOK, "OK", map[string]string{"status": "healthy"})
	})

	http.HandleFunc("/api/v1/genieacs/cache/clear", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			deviceID := r.URL.Query().Get("device_id")
			if deviceID != "" {
				deviceCacheInstance.clear(deviceID)
			} else {
				deviceCacheInstance = &deviceCache{
					data:    make(map[string]cachedDeviceData),
					timeout: 30 * time.Second,
				}
			}
			sendResponse(w, http.StatusOK, "OK", map[string]string{"message": "Cache cleared"})
		} else {
			sendError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Method not allowed")
		}
	}))

	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Helper function to get environment variable with fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Function to get device ID by IP
func getDeviceIDByIP(ip string) (string, error) {
	query := fmt.Sprintf(`{"$or":[{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value":"%s"},{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.2.ExternalIPAddress._value":"%s"}]}`, ip, ip)
	encodedQuery := url.QueryEscape(query)

	url := fmt.Sprintf("%s/devices/?query=%s", genieacsBaseURL, encodedQuery)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-API-Key", validAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var devices []Device
	err = json.Unmarshal(body, &devices)
	if err != nil {
		return "", err
	}

	if len(devices) == 0 {
		return "", fmt.Errorf("device not found with IP: %s", ip)
	}

	return devices[0].ID, nil
}

// Function to get device ID by Serial Number
func getDeviceIDBySN(serialNumber string) (string, error) {
	query := fmt.Sprintf(`{"InternetGatewayDevice.DeviceInfo.SerialNumber._value":"%s"}`, serialNumber)
	encodedQuery := url.QueryEscape(query)

	url := fmt.Sprintf("%s/devices/?query=%s", genieacsBaseURL, encodedQuery)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-API-Key", validAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var devices []Device
	err = json.Unmarshal(body, &devices)
	if err != nil {
		return "", err
	}

	if len(devices) == 0 {
		return "", fmt.Errorf("device not found with SN: %s", serialNumber)
	}

	return devices[0].ID, nil
}

func refreshWLANConfig(deviceID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/devices/%s/tasks?connection_request", genieacsBaseURL, url.PathEscape(deviceID))

	payload := strings.NewReader(`{
		"name": "refreshObject",
		"objectName": "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
	}`)

	req, err := http.NewRequestWithContext(ctx, "POST", url, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", validAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}

	return nil
}

func getWLANData(deviceID string) ([]WLANConfig, error) {
	deviceData, err := getDeviceData(deviceID)
	if err != nil {
		return nil, err
	}

	// Determine device type based on ID pattern
	isZTE := strings.Contains(deviceID, "ZTE") || strings.Contains(deviceID, "ZT")

	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("InternetGatewayDevice data not found")
	}

	lanDevice, ok := internetGateway["LANDevice"].(map[string]interface{})["1"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice data not found")
	}

	wlanConfigs, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("WLANConfiguration data not found")
	}

	var configs []WLANConfig

	for key, value := range wlanConfigs {
		if wlan, ok := value.(map[string]interface{}); ok {
			enable, ok := wlan["Enable"].(map[string]interface{})["_value"].(bool)
			if !ok || !enable {
				continue
			}

			ssid := "Unknown"
			if ssidVal, ok := wlan["SSID"].(map[string]interface{})["_value"].(string); ok {
				ssid = ssidVal
			}

			password := getPassword(wlan, isZTE)
			band := getBand(wlan, key)

			configs = append(configs, WLANConfig{
				WLAN:     key,
				SSID:     ssid,
				Password: password,
				Band:     band,
			})
		}
	}

	sort.Slice(configs, func(i, j int) bool {
		numI, errI := strconv.Atoi(configs[i].WLAN)
		numJ, errJ := strconv.Atoi(configs[j].WLAN)

		if errI != nil || errJ != nil {
			return configs[i].WLAN < configs[j].WLAN
		}

		return numI < numJ
	})

	return configs, nil
}

func getPassword(wlan map[string]interface{}, isZTE bool) string {
	// For ZTE devices, always return "********"
	if isZTE {
		return "********"
	}

	// For CData devices, use the existing logic
	if xcms, ok := wlan["X_CMS_KeyPassphrase"].(map[string]interface{})["_value"].(string); ok && xcms != "" {
		return xcms
	}

	if psk, ok := wlan["PreSharedKey"].(map[string]interface{}); ok {
		if psk1, ok := psk["1"].(map[string]interface{}); ok {
			if keyPass, ok := psk1["KeyPassphrase"].(map[string]interface{})["_value"].(string); ok && keyPass != "" {
				return keyPass
			}
			if preShared, ok := psk1["PreSharedKey"].(map[string]interface{})["_value"].(string); ok && preShared != "" {
				return preShared
			}
		}
	}

	if wep, ok := wlan["WEPKey"].(map[string]interface{}); ok {
		if wep1, ok := wep["1"].(map[string]interface{}); ok {
			if wepKey, ok := wep1["WEPKey"].(map[string]interface{})["_value"].(string); ok && wepKey != "" {
				return wepKey
			}
		}
	}

	return "No password"
}

func getBand(wlan map[string]interface{}, wlanKey string) string {
	// First try to determine band by WLAN key
	if wlanKey == "1" {
		return "2.4GHz"
	} else if wlanKey == "5" {
		return "5GHz"
	}

	// Then try by standard
	std, ok := wlan["Standard"].(map[string]interface{})["_value"].(string)
	if ok {
		switch std {
		case "g", "b", "n", "b,g", "g,n", "b,g,n", "b/g", "g/n", "b/g/n":
			return "2.4GHz"
		case "a", "ac", "a,n", "n,ac", "a,n,ac", "a/n", "n/ac", "a/n/ac":
			return "5GHz"
		default:
			return fmt.Sprintf("Unknown (Standard: %s)", std)
		}
	}

	return "Unknown"
}

// New handler for getting SSID by IP
// New handler for getting SSID by IP
func getSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	ip := parts[len(parts)-1]

	if ip == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "IP Address required")
		return
	}

	deviceID, err := getDeviceIDByIP(ip)
	if err != nil {
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}

	// Refresh WLAN configuration secara synchronous terlebih dahulu
	err = refreshWLANConfig(deviceID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Internal Server Error", "Refresh failed: "+err.Error())
		return
	}

	// Tunggu sebentar untuk memastikan data sudah ter-refresh
	// (opsional, bisa disesuaikan dengan kebutuhan)
	time.Sleep(500 * time.Millisecond)

	wlanData, err := getWLANData(deviceID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	// Submit refresh task ke worker pool untuk refresh berikutnya (non-blocking)
	taskWorkerPool.Submit(deviceID, "refreshWLAN", nil)

	sendResponse(w, http.StatusOK, "OK", wlanData)
}

func getDHCPClients(deviceID string) ([]DHCPClient, error) {
	deviceData, err := getDeviceData(deviceID)
	if err != nil {
		return nil, err
	}

	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("InternetGatewayDevice data not found")
	}

	lanDevice, ok := internetGateway["LANDevice"].(map[string]interface{})["1"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice data not found")
	}

	hosts, ok := lanDevice["Hosts"].(map[string]interface{})["Host"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("hosts data not found")
	}

	var clients []DHCPClient

	for _, host := range hosts {
		if hostData, ok := host.(map[string]interface{}); ok {
			mac := "Unknown"
			if macVal, ok := hostData["MACAddress"].(map[string]interface{})["_value"].(string); ok {
				mac = macVal
			}

			hostname := "Unknown"
			if hostVal, ok := hostData["HostName"].(map[string]interface{})["_value"].(string); ok {
				hostname = hostVal
			}

			ip := ""
			if ipVal, ok := hostData["IPAddress"].(map[string]interface{})["_value"].(string); ok {
				ip = ipVal
			}

			clients = append(clients, DHCPClient{
				MAC:      mac,
				Hostname: hostname,
				IP:       ip,
			})
		}
	}

	return clients, nil
}

func refreshDHCP(deviceID string) error {
	url := fmt.Sprintf("%s/devices/%s/tasks?connection_request", genieacsBaseURL, url.PathEscape(deviceID))

	payload := strings.NewReader(`{
		"name": "refreshObject",
		"objectName": "InternetGatewayDevice.LANDevice.1"
	}`)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", validAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}

	return nil
}

func setParameterValues(deviceID string, parameterValues [][]interface{}) error {
	url := fmt.Sprintf("%s/devices/%s/tasks", genieacsBaseURL, url.PathEscape(deviceID))

	payload := map[string]interface{}{
		"name":            "setParameterValues",
		"parameterValues": parameterValues,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonPayload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", validAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("set parameter values failed with status: %s, response: %s", resp.Status, string(body))
	}

	return nil
}

// New function to apply changes to device
func applyChanges(deviceID string) error {
	url := fmt.Sprintf("%s/devices/%s/tasks?connection_request", genieacsBaseURL, url.PathEscape(deviceID))

	payload := strings.NewReader(`{
		"name": "refreshObject",
		"objectName": "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
	}`)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", validAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apply changes failed with status: %s", resp.Status)
	}

	return nil
}

// New handler for getting DHCP clients by IP address
func getDHCPClientByIPHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	ip := parts[len(parts)-1]

	if ip == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "IP Address required")
		return
	}

	deviceID, err := getDeviceIDByIP(ip)
	if err != nil {
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}

	// Optional: hanya refresh kalau query param refresh=true
	refresh := r.URL.Query().Get("refresh")
	if refresh == "true" {
		if err := refreshDHCP(deviceID); err != nil {
			sendError(w, http.StatusInternalServerError, "Internal Server Error", "Refresh failed: "+err.Error())
			return
		}
	}

	dhcpClients, err := getDHCPClients(deviceID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	sendResponse(w, http.StatusOK, "OK", dhcpClients)
}

func updateSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 7 {
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid URL format. Use /api/v1/genieacs/ssid/update/{wlan}/{ip}")
		return
	}

	wlan := parts[6]
	ip := parts[7]

	if wlan == "" || ip == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "WLAN and IP Address required")
		return
	}

	var updateReq UpdateSSIDRequest
	err := json.NewDecoder(r.Body).Decode(&updateReq)
	if err != nil {
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}

	if updateReq.SSID == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "SSID value required")
		return
	}

	// Get device ID by IP
	deviceID, err := getDeviceIDByIP(ip)
	if err != nil {
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}

	// First, get current WLAN configuration to validate the WLAN exists and is enabled
	wlanConfigs, err := getWLANData(deviceID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Internal Server Error", "Failed to get WLAN configuration: "+err.Error())
		return
	}

	// Check if the specified WLAN exists and is enabled
	wlanExists := false
	wlanEnabled := false
	for _, config := range wlanConfigs {
		if config.WLAN == wlan {
			wlanExists = true
			// For ZTE devices, we can't determine if it's enabled from the password field
			// So we'll assume it's enabled if it exists in the configuration
			if strings.Contains(deviceID, "ZTE") || strings.Contains(deviceID, "ZT") {
				wlanEnabled = true
			} else {
				// For non-ZTE devices, check if the WLAN is actually enabled
				enabled, err := isWLANEnabled(deviceID, wlan)
				if err != nil {
					sendError(w, http.StatusInternalServerError, "Internal Server Error", "Failed to check WLAN status: "+err.Error())
					return
				}
				wlanEnabled = enabled
			}
			break
		}
	}

	if !wlanExists {
		sendError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("WLAN %s not found on device", wlan))
		return
	}

	if !wlanEnabled {
		sendError(w, http.StatusBadRequest, "Bad Request", fmt.Sprintf("WLAN %s is not enabled on device", wlan))
		return
	}

	// Set parameter values
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSID", wlan)
	parameterValues := [][]interface{}{
		{parameterPath, updateReq.SSID, "xsd:string"},
	}

	// Submit both tasks to worker pool concurrently
	taskWorkerPool.Submit(deviceID, "setParameterValues", parameterValues)
	taskWorkerPool.Submit(deviceID, "applyChanges", nil)

	// Clear cache untuk device ini
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusOK, "OK", map[string]string{
		"message":   "SSID update submitted successfully",
		"device_id": deviceID,
		"wlan":      wlan,
		"ssid":      updateReq.SSID,
		"ip":        ip,
	})
}

func updatePasswordByIPHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 7 {
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid URL format. Use /api/v1/genieacs/password/update/{wlan}/{ip}")
		return
	}

	wlan := parts[6]
	ip := parts[7]

	if wlan == "" || ip == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "WLAN and IP Address required")
		return
	}

	var updateReq UpdatePasswordRequest
	err := json.NewDecoder(r.Body).Decode(&updateReq)
	if err != nil {
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}

	if updateReq.Password == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "Password value required")
		return
	}

	// Get device ID by IP
	deviceID, err := getDeviceIDByIP(ip)
	if err != nil {
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}

	// First, get current WLAN configuration to validate the WLAN exists and is enabled
	wlanConfigs, err := getWLANData(deviceID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Internal Server Error", "Failed to get WLAN configuration: "+err.Error())
		return
	}

	// Check if the specified WLAN exists and is enabled
	wlanExists := false
	wlanEnabled := false
	for _, config := range wlanConfigs {
		if config.WLAN == wlan {
			wlanExists = true
			// For ZTE devices, we can't determine if it's enabled from the password field
			// So we'll assume it's enabled if it exists in the configuration
			if strings.Contains(deviceID, "ZTE") || strings.Contains(deviceID, "ZT") {
				wlanEnabled = true
			} else {
				// For non-ZTE devices, we need to check if the WLAN is actually enabled
				// We'll do this by getting the raw device data and checking the Enable parameter
				enabled, err := isWLANEnabled(deviceID, wlan)
				if err != nil {
					sendError(w, http.StatusInternalServerError, "Internal Server Error", "Failed to check WLAN status: "+err.Error())
					return
				}
				wlanEnabled = enabled
			}
			break
		}
	}

	if !wlanExists {
		sendError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("WLAN %s not found on device", wlan))
		return
	}

	if !wlanEnabled {
		sendError(w, http.StatusBadRequest, "Bad Request", fmt.Sprintf("WLAN %s is not enabled on device", wlan))
		return
	}

	// Set parameter values
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.PreSharedKey.1.PreSharedKey", wlan)
	parameterValues := [][]interface{}{
		{parameterPath, updateReq.Password, "xsd:string"},
	}

	// Submit both tasks to worker pool concurrently
	taskWorkerPool.Submit(deviceID, "setParameterValues", parameterValues)
	taskWorkerPool.Submit(deviceID, "applyChanges", nil)

	// Clear cache untuk device ini
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusOK, "OK", map[string]string{
		"message":   "Password update submitted successfully",
		"device_id": deviceID,
		"wlan":      wlan,
		"ip":        ip,
	})
}

// New function to check if a specific WLAN is enabled
func isWLANEnabled(deviceID, wlan string) (bool, error) {
	deviceData, err := getDeviceData(deviceID)
	if err != nil {
		return false, err
	}

	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("InternetGatewayDevice data not found")
	}

	lanDevice, ok := internetGateway["LANDevice"].(map[string]interface{})["1"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("LANDevice data not found")
	}

	wlanConfigs, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("WLANConfiguration data not found")
	}

	// Find the specific WLAN
	wlanConfig, ok := wlanConfigs[wlan].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("WLAN %s not found", wlan)
	}

	// Check if the WLAN is enabled
	enable, ok := wlanConfig["Enable"].(map[string]interface{})["_value"].(bool)
	if !ok {
		return false, nil // Default to false if we can't determine
	}

	return enable, nil
}
