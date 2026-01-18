package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"
)

// getSSIDByIPHandler retrieves WLAN/SSID information for a device by its IP address
func getSSIDByIPHandler(w http.ResponseWriter, r *http.Request) {
	// Extract device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
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
	// --- Step 1: get device ID ---
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// --- Step 2: setup context & retry config ---
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second) // overall timeout of 30s
	defer cancel()

	// Default retry config
	maxRetries := DefaultMaxRetries // default to 12 attempts
	retryDelay := DefaultRetryDelay // default to 5 seconds between attempts

	// Override with query parameters if provided (with security bounds)
	// Log warnings for invalid values to detect potential abuse patterns
	if mrStr := r.URL.Query().Get("max_retries"); mrStr != "" {
		mr, err := strconv.Atoi(mrStr)
		if err != nil {
			logger.Warn("Invalid max_retries parameter (non-numeric), using default",
				zap.String("value", mrStr),
				zap.String("deviceID", deviceID))
		} else if mr <= 0 || mr > MaxRetryAttempts {
			logger.Warn("max_retries out of bounds, using default",
				zap.Int("value", mr),
				zap.Int("max", MaxRetryAttempts),
				zap.String("deviceID", deviceID))
		} else {
			maxRetries = mr
		}
	}

	// Override retry delay if provided in milliseconds (with security bounds)
	if rdStr := r.URL.Query().Get("retry_delay_ms"); rdStr != "" {
		rd, err := strconv.Atoi(rdStr)
		if err != nil {
			logger.Warn("Invalid retry_delay_ms parameter (non-numeric), using default",
				zap.String("value", rdStr),
				zap.String("deviceID", deviceID))
		} else if rd <= 0 || rd > MaxRetryDelayMs {
			logger.Warn("retry_delay_ms out of bounds, using default",
				zap.Int("value", rd),
				zap.Int("max", MaxRetryDelayMs),
				zap.String("deviceID", deviceID))
		} else {
			retryDelay = time.Duration(rd) * time.Millisecond
		}
	}

	var wlanData []WLANConfig // to hold retrieved WLAN data
	var err error             // to hold errors from API calls
	refreshDone := false      // flag to ensure refresh is triggered only once

	// --- Step 3: retry loop ---
	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			sendError(w, http.StatusRequestTimeout, StatusTimeout, ErrOperationTimeout)
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
				sendError(w, http.StatusRequestTimeout, StatusTimeout, ErrOperationTimeout)
				return
			}
			// Other errors
			logger.Error("Failed to get WLAN data (error)",
				zap.String("deviceID", deviceID),
				zap.Int("attempt", attempt+1),
				zap.Error(err))
			sendError(w, http.StatusInternalServerError, StatusInternalError, sanitizeErrorMessage(err))
			return
		}

		// if data found, return immediately
		if len(wlanData) > 0 {
			sendResponse(w, http.StatusOK, StatusOK, map[string]interface{}{
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
	sendError(w, http.StatusNotFound, StatusNotFound,
		fmt.Sprintf(ErrNoWLANDataFound, maxRetries))
}

// refreshSSIDHandler triggers a refresh of WLAN configuration data for a device
func refreshSSIDHandler(w http.ResponseWriter, r *http.Request) {
	// Extract device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	// Submit refresh task to worker pool for asynchronous processing
	taskWorkerPool.Submit(deviceID, taskTypeRefreshWLAN, nil)
	// Clear cached data for this device to force fresh data on next request
	deviceCacheInstance.clear(deviceID)
	// Return accepted response indicating task was queued
	sendResponse(w, http.StatusAccepted, StatusAccepted, map[string]string{
		"message": MsgRefreshSubmitted,
	})
}
