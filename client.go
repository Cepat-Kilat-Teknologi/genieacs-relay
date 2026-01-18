package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ipQuery represents the MongoDB query structure for IP-based device lookup
type ipQuery struct {
	Or []map[string]string `json:"$or"`
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
	// Add authentication header only if NBI auth is enabled
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set("X-API-Key", nbiAuthKey)
	}
	// Execute HTTP request and return response
	return httpClient.Do(req)
}

// deviceIDQuery represents the MongoDB query structure for device ID lookup
type deviceIDQuery struct {
	ID string `json:"_id"`
}

// getDeviceData retrieves device data either from cache or from GenieACS API
func getDeviceData(ctx context.Context, deviceID string) (map[string]interface{}, error) {
	// First try to get data from cache to avoid API call
	if cachedData, found := deviceCacheInstance.get(deviceID); found {
		return cachedData, nil // Return cached data if available and fresh
	}

	// Build query using proper JSON marshaling to prevent injection
	queryStruct := deviceIDQuery{ID: deviceID}
	queryBytes, err := jsonMarshal(queryStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}
	urlQ := fmt.Sprintf("%s/devices/?query=%s", geniesBaseURL, url.QueryEscape(string(queryBytes)))
	// Create HTTP request with context for cancellation
	req, err := http.NewRequestWithContext(ctx, "GET", urlQ, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication header only if NBI auth is enabled
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set("X-API-Key", nbiAuthKey)
	}
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
	// Add authentication header only if NBI auth is enabled
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set("X-API-Key", nbiAuthKey)
	}
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
