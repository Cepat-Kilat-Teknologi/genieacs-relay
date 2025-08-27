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

// Global variables
var (
	geniesBaseURL string
	nbiAuthKey    string
	apiKey        string
	logger        *zap.Logger
)

// Task types for worker pool
const (
	taskTypeSetParams    = "setParameterValues"
	taskTypeApplyChanges = "applyChanges"
	taskTypeRefreshWLAN  = "refreshWLAN"
)

// init initializes the zap logger
func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("Tidak dapat menginisialisasi zap logger: %v", err)
	}
}

// --- Struct Definitions ---
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
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

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

// --- Worker Pool ---
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
	ctx := context.Background()
	for t := range wp.queue {
		var err error
		switch t.taskType {
		case taskTypeSetParams:
			err = setParameterValues(ctx, t.deviceID, t.params)
		case taskTypeApplyChanges:
			err = refreshWLANConfig(ctx, t.deviceID)
		case taskTypeRefreshWLAN:
			err = refreshWLANConfig(ctx, t.deviceID)
		}

		if err != nil {
			logger.Error("Worker task failed",
				zap.String("deviceID", t.deviceID),
				zap.String("taskType", t.taskType),
				zap.Error(err),
			)
		}
	}
}

func (wp *workerPool) Submit(deviceID, taskType string, params [][]interface{}) {
	wp.queue <- task{deviceID, taskType, params}
}

// --- Cache ---
func (c *deviceCache) get(deviceID string) (map[string]interface{}, bool) {
	c.RLock()
	defer c.RUnlock()
	if cached, exists := c.data[deviceID]; exists && time.Since(cached.timestamp) < c.timeout {
		return cached.data, true
	}
	return nil, false
}

func (c *deviceCache) set(deviceID string, data map[string]interface{}) {
	c.Lock()
	defer c.Unlock()
	c.data[deviceID] = cachedDeviceData{data, time.Now()}
}

func (c *deviceCache) clear(deviceID string) {
	c.Lock()
	defer c.Unlock()
	delete(c.data, deviceID)
}

func (c *deviceCache) clearAll() {
	c.Lock()
	defer c.Unlock()
	c.data = make(map[string]cachedDeviceData)
}

// --- Helper Functions ---

func safeClose(closer io.Closer) {
	if err := closer.Close(); err != nil {
		logger.Warn("Failed to close resource", zap.Error(err))
	}
}

// --- GenieACS Communication ---
func getDeviceData(ctx context.Context, deviceID string) (map[string]interface{}, error) {
	if cachedData, found := deviceCacheInstance.get(deviceID); found {
		return cachedData, nil
	}

	query := fmt.Sprintf(`{"_id":"%s"}`, deviceID)
	urlQ := fmt.Sprintf("%s/devices/?query=%s", geniesBaseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, "GET", urlQ, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-Key", nbiAuthKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer safeClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no device found with ID: %s", deviceID)
	}
	deviceData := result[0]
	deviceCacheInstance.set(deviceID, deviceData)
	return deviceData, nil
}

// --- Response Helpers ---
func sendResponse(w http.ResponseWriter, code int, status string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(Response{Code: code, Status: status, Data: data}); err != nil {
		logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func sendError(w http.ResponseWriter, code int, status string, errorMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(Response{Code: code, Status: status, Error: errorMsg}); err != nil {
		logger.Error("Failed to encode JSON error response", zap.Error(err))
	}
}

// --- Middleware ---
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != apiKey {
			sendError(w, http.StatusUnauthorized, "Unauthorized", "Invalid API Key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Main Application ---
func main() {
	defer func() {
		if err := logger.Sync(); err != nil {
			log.Printf("Gagal melakukan sync pada logger: %v", err)
		}
	}()

	geniesBaseURL = getEnv("GENIEACS_BASE_URL", "http://localhost:7557")
	nbiAuthKey = getEnv("NBI_AUTH_KEY", "alhamdulillah")
	apiKey = getEnv("API_KEY", "ThisIsASecretKey")

	taskWorkerPool.Start()

	logger.Info("Starting server", zap.String("genieacs_url", geniesBaseURL))

	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Get("/health", healthCheckHandler)

	r.Route("/api/v1/genieacs", func(r chi.Router) {
		r.Use(authMiddleware)
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Post("/ssid/{ip}/refresh", refreshSSIDHandler)
		r.Put("/ssid/update/{wlan}/{ip}", updateSSIDByIPHandler)
		r.Put("/password/update/{wlan}/{ip}", updatePasswordByIPHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/cache/clear", clearCacheHandler)
	})

	// --- BARU: Implementasi Graceful Shutdown ---
	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	go func() {
		logger.Info("Server listening", zap.String("address", "http://localhost:8080"))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutdown signal received, starting graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger.Info("Stopping worker pool...")
	taskWorkerPool.Stop()
	logger.Info("Worker pool stopped.")

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server graceful shutdown failed", zap.Error(err))
	}

	logger.Info("Server exited properly")
}

// --- Handlers ---
func healthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	sendResponse(w, http.StatusOK, "OK", map[string]string{"status": "healthy"})
}

func clearCacheHandler(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	if deviceID != "" {
		deviceCacheInstance.clear(deviceID)
	} else {
		deviceCacheInstance.clearAll()
	}
	sendResponse(w, http.StatusOK, "OK", map[string]string{"message": "Cache cleared"})
}

func getSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	wlanData, err := getWLANData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get WLAN data", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	sendResponse(w, http.StatusOK, "OK", wlanData)
}

func refreshSSIDHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID by IP for refresh", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	taskWorkerPool.Submit(deviceID, taskTypeRefreshWLAN, nil)
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, "Accepted", map[string]string{
		"message": "Refresh task submitted. Please query the GET endpoint again after a few moments.",
	})
}

func getDHCPClientByIPHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	if r.URL.Query().Get("refresh") == "true" {
		if err := refreshDHCP(r.Context(), deviceID); err != nil {
			logger.Error("DHCP refresh task failed", zap.String("deviceID", deviceID), zap.Error(err))
			sendError(w, http.StatusInternalServerError, "Internal Server Error", "Refresh failed: "+err.Error())
			return
		}
	}
	dhcpClients, err := getDHCPClients(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get DHCP clients", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	sendResponse(w, http.StatusOK, "OK", dhcpClients)
}

func updateSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")
	var updateReq UpdateSSIDRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}
	if updateReq.SSID == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "SSID value required")
		return
	}
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for SSID update", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to validate WLAN", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", "Could not verify WLAN status.")
		return
	}
	if !valid {
		sendError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("WLAN ID %s does not exist or is not enabled on this device.", wlan))
		return
	}
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSID", wlan)
	parameterValues := [][]interface{}{{parameterPath, updateReq.SSID, "xsd:string"}}
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusOK, "OK", map[string]string{
		"message": "SSID update submitted successfully", "device_id": deviceID, "wlan": wlan, "ssid": updateReq.SSID, "ip": ip,
	})
}

func updatePasswordByIPHandler(w http.ResponseWriter, r *http.Request) {
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")
	var updateReq UpdatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		sendError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON format")
		return
	}
	if updateReq.Password == "" {
		sendError(w, http.StatusBadRequest, "Bad Request", "Password value required")
		return
	}
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for password update", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, "Not Found", err.Error())
		return
	}
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to validate WLAN for password update", zap.String("deviceID", deviceID), zap.String("wlan", wlan), zap.Error(err))
		sendError(w, http.StatusInternalServerError, "Internal Server Error", "Could not verify WLAN status.")
		return
	}
	if !valid {
		sendError(w, http.StatusNotFound, "Not Found", fmt.Sprintf("WLAN ID %s does not exist or is not enabled on this device.", wlan))
		return
	}
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.PreSharedKey.1.PreSharedKey", wlan)
	parameterValues := [][]interface{}{{parameterPath, updateReq.Password, "xsd:string"}}
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusOK, "OK", map[string]string{
		"message": "Password update submitted successfully", "device_id": deviceID, "wlan": wlan, "ip": ip,
	})
}

// --- Helper & Logic Functions ---
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func postJSONRequest(ctx context.Context, urlQ string, payload interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	switch v := payload.(type) {
	case string:
		bodyReader = strings.NewReader(v)
	default:
		jsonPayload, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonPayload)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", urlQ, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", nbiAuthKey)
	return httpClient.Do(req)
}

func getDeviceIDByIP(ctx context.Context, ip string) (string, error) {
	query := fmt.Sprintf(`{"$or":[
{"summary.ip": "%s"},
{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value": "%s"},
{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.2.ExternalIPAddress._value": "%s"}
]}`, ip, ip, ip)
	urlQ := fmt.Sprintf("%s/devices/?query=%s&projection=_id", geniesBaseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, "GET", urlQ, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-API-Key", nbiAuthKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer safeClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GenieACS returned non-OK status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var devices []Device
	if err := json.Unmarshal(body, &devices); err != nil {
		return "", err
	}
	if len(devices) == 0 {
		return "", fmt.Errorf("device not found with IP: %s", ip)
	}
	return devices[0].ID, nil
}

func refreshWLANConfig(ctx context.Context, deviceID string) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))
	payload := `{"name": "refreshObject", "objectName": "InternetGatewayDevice.LANDevice.1.WLANConfiguration"}`
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	defer safeClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}
	return nil
}

// DIUBAH: Fungsi ini sekarang jauh lebih aman dari panic
func getWLANData(ctx context.Context, deviceID string) ([]WLANConfig, error) {
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	isZTE := strings.Contains(deviceID, "ZTE") || strings.Contains(deviceID, "ZT")

	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("InternetGatewayDevice data not found or invalid format")
	}

	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice data not found or invalid format")
	}

	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice.1 data not found")
	}

	wlanConfigsMap, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		return []WLANConfig{}, nil
	}

	var configs []WLANConfig
	for key, value := range wlanConfigsMap {
		wlan, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		enableMap, ok := wlan["Enable"].(map[string]interface{})
		if !ok {
			continue
		}
		if enable, ok := enableMap["_value"].(bool); !ok || !enable {
			continue
		}

		var ssid string
		if ssidMap, ok := wlan["SSID"].(map[string]interface{}); ok {
			if ssidVal, ok := ssidMap["_value"].(string); ok {
				ssid = ssidVal
			}
		}

		configs = append(configs, WLANConfig{
			WLAN:     key,
			SSID:     ssid,
			Password: getPassword(wlan, isZTE),
			Band:     getBand(wlan, key),
		})
	}

	sort.Slice(configs, func(i, j int) bool {
		numI, errI := strconv.Atoi(configs[i].WLAN)
		numJ, errJ := strconv.Atoi(configs[j].WLAN)
		if errI != nil || errJ != nil {
			return false // Don't sort if keys are not numeric
		}
		return numI < numJ
	})
	return configs, nil
}

func getPassword(wlan map[string]interface{}, isZTE bool) string {
	if isZTE {
		return "********"
	}
	if passMap, ok := wlan["X_CMS_KeyPassphrase"].(map[string]interface{}); ok {
		if pass, ok := passMap["_value"].(string); ok && pass != "" {
			return pass
		}
	}
	if psk, ok := wlan["PreSharedKey"].(map[string]interface{}); ok {
		if psk1, ok := psk["1"].(map[string]interface{}); ok {
			if keyPassMap, ok := psk1["KeyPassphrase"].(map[string]interface{}); ok {
				if keyPass, ok := keyPassMap["_value"].(string); ok && keyPass != "" {
					return keyPass
				}
			}
			if preSharedMap, ok := psk1["PreSharedKey"].(map[string]interface{}); ok {
				if preShared, ok := preSharedMap["_value"].(string); ok && preShared != "" {
					return preShared
				}
			}
		}
	}
	return "N/A"
}

func getBand(wlan map[string]interface{}, wlanKey string) string {
	if wlanKey == "1" {
		return "2.4GHz"
	} else if wlanKey == "5" {
		return "5GHz"
	}
	if stdMap, ok := wlan["Standard"].(map[string]interface{}); ok {
		if std, ok := stdMap["_value"].(string); ok {
			std = strings.ToLower(std)
			if strings.ContainsAny(std, "bg") {
				return "2.4GHz"
			}
			if strings.ContainsAny(std, "ac") {
				return "5GHz"
			}
		}
	}
	return "Unknown"
}

// DIUBAH: Fungsi ini sekarang jauh lebih aman dari panic
func getDHCPClients(ctx context.Context, deviceID string) ([]DHCPClient, error) {
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("InternetGatewayDevice data not found")
	}

	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice data not found")
	}

	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice.1 data not found")
	}

	hostsMap, ok := lanDevice["Hosts"].(map[string]interface{})
	if !ok {
		return []DHCPClient{}, nil
	}

	hosts, ok := hostsMap["Host"].(map[string]interface{})
	if !ok {
		return []DHCPClient{}, nil
	}

	var clients []DHCPClient
	for _, host := range hosts {
		if hostData, ok := host.(map[string]interface{}); ok {
			var client DHCPClient
			if valMap, ok := hostData["MACAddress"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.MAC = val
				}
			}
			if valMap, ok := hostData["HostName"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.Hostname = val
				}
			}
			if valMap, ok := hostData["IPAddress"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.IP = val
				}
			}
			clients = append(clients, client)
		}
	}
	return clients, nil
}

func refreshDHCP(ctx context.Context, deviceID string) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))
	payload := `{"name": "refreshObject", "objectName": "InternetGatewayDevice.LANDevice.1"}`
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	defer safeClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}
	return nil
}

func setParameterValues(ctx context.Context, deviceID string, parameterValues [][]interface{}) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks", geniesBaseURL, url.PathEscape(deviceID))
	payload := map[string]interface{}{"name": "setParameterValues", "parameterValues": parameterValues}
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	defer safeClose(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set parameter values failed with status: %s, response: %s", resp.Status, string(body))
	}
	return nil
}

// DIHAPUS: Fungsi applyChanges karena duplikat dengan refreshWLANConfig

// DIUBAH: Fungsi ini sekarang jauh lebih aman dari panic
func isWLANValid(ctx context.Context, deviceID, wlanID string) (bool, error) {
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return false, fmt.Errorf("could not get device data for validation: %w", err)
	}

	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("InternetGatewayDevice data not found")
	}

	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("LANDevice data not found")
	}

	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("LANDevice.1 data not found")
	}

	wlanConfigsMap, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	wlanConfigData, wlanExists := wlanConfigsMap[wlanID]
	if !wlanExists {
		return false, nil
	}

	if wlan, ok := wlanConfigData.(map[string]interface{}); ok {
		if enableMap, ok := wlan["Enable"].(map[string]interface{}); ok {
			if enable, ok := enableMap["_value"].(bool); ok && enable {
				return true, nil
			}
		}
	}
	return false, nil
}
