package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// HandlerContext provides common context for HTTP handlers
type HandlerContext struct {
	IP       string
	WLAN     string
	DeviceID string
}

// ExtractDeviceIDByIP is a helper that extracts device ID from IP and handles common error responses
// Returns the device ID and true if successful, or sends error response and returns false
func ExtractDeviceIDByIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip := chi.URLParam(r, "ip")
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, err.Error())
		return "", false
	}
	return deviceID, true
}

// ValidateWLANAndRespond validates WLAN and sends appropriate error response if invalid
// Returns true if WLAN is valid, false otherwise (error response already sent)
func ValidateWLANAndRespond(w http.ResponseWriter, r *http.Request, deviceID, wlan string) bool {
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to validate WLAN",
			zap.String("deviceID", deviceID),
			zap.String("wlan", wlan),
			zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, ErrWLANValidationFailed)
		return false
	}
	if !valid {
		sendError(w, http.StatusNotFound, StatusNotFound,
			fmt.Sprintf("WLAN ID %s does not exist or is not enabled on this device.", wlan))
		return false
	}
	return true
}

// UpdateWLANParameter is a generic helper for updating WLAN parameters (SSID or password)
// This reduces code duplication between updateSSIDByIPHandler and updatePasswordByIPHandler
func UpdateWLANParameter(
	w http.ResponseWriter,
	r *http.Request,
	parameterPath string,
	parameterValue string,
	successMessage string,
	additionalResponseFields map[string]string,
) {
	wlan := chi.URLParam(r, "wlan")
	ip := chi.URLParam(r, "ip")

	// Get device ID
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID for parameter update",
			zap.String("ip", ip),
			zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, err.Error())
		return
	}

	// Validate WLAN
	if !ValidateWLANAndRespond(w, r, deviceID, wlan) {
		return
	}

	// Construct full parameter path
	fullPath := fmt.Sprintf(parameterPath, wlan)

	// Prepare parameter values for setting operation
	parameterValues := [][]interface{}{{fullPath, parameterValue, XSDString}}

	// Submit set parameter task to worker pool
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)

	// Submit apply changes task to make configuration active
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)

	// Clear cached data for this device to reflect changes
	deviceCacheInstance.clear(deviceID)

	// Build response map
	response := map[string]string{
		"message":   successMessage,
		"device_id": deviceID,
		"wlan":      wlan,
		"ip":        ip,
	}

	// Add any additional fields
	for k, v := range additionalResponseFields {
		response[k] = v
	}

	// Return success response
	sendResponse(w, http.StatusOK, StatusOK, response)
}

// GetLANDeviceFromDeviceData extracts LANDevice.1 from device data with proper error messages
// This is a common operation used in multiple places
func GetLANDeviceFromDeviceData(deviceData map[string]interface{}) (map[string]interface{}, error) {
	// Safely extract InternetGatewayDevice section
	internetGateway, ok := deviceData[PathInternetGatewayDevice].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("InternetGatewayDevice data not found or invalid format")
	}

	// Safely extract LANDevice section
	lanDeviceMap, ok := internetGateway[PathLANDevice].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice data not found or invalid format")
	}

	// Safely extract LANDevice.1 section
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice.1 data not found")
	}

	return lanDevice, nil
}

// GetWLANConfigurationFromLANDevice extracts WLANConfiguration from LANDevice
func GetWLANConfigurationFromLANDevice(lanDevice map[string]interface{}) (map[string]interface{}, bool) {
	wlanConfigsMap, ok := lanDevice[PathWLANConfiguration].(map[string]interface{})
	return wlanConfigsMap, ok
}
