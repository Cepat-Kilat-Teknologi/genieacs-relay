package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	genieacsBaseURL = "http://192.168.212.138:6969"
	validAPIKey     = "alhamdulillah"
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

// Middleware untuk memeriksa API Key
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != validAPIKey {
			http.Error(w, `{"error": "Unauthorized: Invalid API Key"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func main() {
	http.HandleFunc("/api/v1/genieacs/ssid/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getSSIDByIPHandler(w, r)
		} else {
			http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}))

	http.HandleFunc("/api/v1/genieacs/ssid/update/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			updateSSIDByIPHandler(w, r)
		} else {
			http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}))

	http.HandleFunc("/api/v1/genieacs/password/update/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			updatePasswordByIPHandler(w, r)
		} else {
			http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}))

	http.HandleFunc("/api/v1/genieacs/dhcp-client/", authMiddleware(getDHCPClientHandler))

	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Function to get device ID by IP
func getDeviceIDByIP(ip string) (string, error) {
	// Try both PPPoE connection paths (CData and ZTE)
	query := fmt.Sprintf(`{"$or":[{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value":"%s"},{"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.2.ExternalIPAddress._value":"%s"}]}`, ip, ip)
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

func getWLANData(deviceID string) ([]WLANConfig, error) {
	query := fmt.Sprintf(`{"_id":"%s"}`, deviceID)
	encodedQuery := url.QueryEscape(query)
	url := fmt.Sprintf("%s/devices/?query=%s", genieacsBaseURL, encodedQuery)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", validAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
		// Convert WLAN string to integer for proper numeric sorting
		numI, errI := strconv.Atoi(configs[i].WLAN)
		numJ, errJ := strconv.Atoi(configs[j].WLAN)

		// If conversion fails, fall back to string comparison
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
func getSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	ip := parts[len(parts)-1]

	if ip == "" {
		http.Error(w, `{"error": "IP Address required"}`, http.StatusBadRequest)
		return
	}

	deviceID, err := getDeviceIDByIP(ip)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	err = refreshWLANConfig(deviceID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Refresh failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	wlanData, err := getWLANData(deviceID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wlanData)
}

func getDHCPClients(deviceID string) ([]DHCPClient, error) {
	query := fmt.Sprintf(`{"_id":"%s"}`, deviceID)
	encodedQuery := url.QueryEscape(query)
	url := fmt.Sprintf("%s/devices/?query=%s", genieacsBaseURL, encodedQuery)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", validAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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

	client := &http.Client{}
	resp, err := client.Do(req)
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apply changes failed with status: %s", resp.Status)
	}

	return nil
}

func getDHCPClientHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	sn := parts[len(parts)-1]

	if sn == "" {
		http.Error(w, `{"error": "Serial Number required"}`, http.StatusBadRequest)
		return
	}

	deviceID, err := getDeviceIDBySN(sn)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	err = refreshDHCP(deviceID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Refresh failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	dhcpClients, err := getDHCPClients(deviceID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dhcpClients)
}

func updateSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 7 {
		http.Error(w, `{"error": "Invalid URL format. Use /api/v1/genieacs/ssid/update/{wlan}/{ip}"}`, http.StatusBadRequest)
		return
	}

	// The URL pattern is /api/v1/genieacs/ssid/update/{wlan}/{ip}
	// So parts will be: ["", "api", "v1", "genieacs", "ssid", "update", "{wlan}", "{ip}"]
	wlan := parts[6] // Changed from 5 to 6
	ip := parts[7]   // Changed from 6 to 7

	if wlan == "" || ip == "" {
		http.Error(w, `{"error": "WLAN and IP Address required"}`, http.StatusBadRequest)
		return
	}

	var updateReq UpdateSSIDRequest
	err := json.NewDecoder(r.Body).Decode(&updateReq)
	if err != nil {
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if updateReq.SSID == "" {
		http.Error(w, `{"error": "SSID value required"}`, http.StatusBadRequest)
		return
	}

	// Get device ID by IP
	deviceID, err := getDeviceIDByIP(ip)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	// Set parameter values - this works for both ZTE and CData
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSID", wlan)
	parameterValues := [][]interface{}{
		{parameterPath, updateReq.SSID, "xsd:string"},
	}

	err = setParameterValues(deviceID, parameterValues)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to update SSID: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Apply changes to make them take effect immediately
	err = applyChanges(deviceID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "SSID updated but apply failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "SSID updated and applied successfully",
		"device_id": deviceID,
		"wlan":      wlan,
		"ssid":      updateReq.SSID,
		"ip":        ip,
	})
}

func updatePasswordByIPHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 7 {
		http.Error(w, `{"error": "Invalid URL format. Use /api/v1/genieacs/password/update/{wlan}/{ip}"}`, http.StatusBadRequest)
		return
	}

	// The URL pattern is /api/v1/genieacs/password/update/{wlan}/{ip}
	// So parts will be: ["", "api", "v1", "genieacs", "password", "update", "{wlan}", "{ip}"]
	wlan := parts[6] // Changed from 5 to 6
	ip := parts[7]   // Changed from 6 to 7

	if wlan == "" || ip == "" {
		http.Error(w, `{"error": "WLAN and IP Address required"}`, http.StatusBadRequest)
		return
	}

	var updateReq UpdatePasswordRequest
	err := json.NewDecoder(r.Body).Decode(&updateReq)
	if err != nil {
		http.Error(w, `{"error": "Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if updateReq.Password == "" {
		http.Error(w, `{"error": "Password value required"}`, http.StatusBadRequest)
		return
	}

	// Get device ID by IP
	deviceID, err := getDeviceIDByIP(ip)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	// Set parameter values - works for both device types
	parameterPath := fmt.Sprintf("InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.PreSharedKey.1.PreSharedKey", wlan)
	parameterValues := [][]interface{}{
		{parameterPath, updateReq.Password, "xsd:string"},
	}

	err = setParameterValues(deviceID, parameterValues)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to update password: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Apply changes to make them take effect immediately
	err = applyChanges(deviceID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Password updated but apply failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "Password updated and applied successfully",
		"device_id": deviceID,
		"wlan":      wlan,
		"ip":        ip,
	})
}
