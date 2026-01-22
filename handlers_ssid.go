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
//
//	@Summary		Get SSID by device IP
//	@Description	Retrieves WLAN/SSID configuration for a device identified by its IP address
//	@Tags			SSID
//	@Accept			json
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200	{object}	Response{data=[]WLANConfig}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/ssid/{ip} [get]
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
//
//	@Summary		Get SSID with force refresh
//	@Description	Retrieves WLAN/SSID information, automatically triggering a refresh if data is not available and retrying until data is found or timeout
//	@Tags			SSID
//	@Accept			json
//	@Produce		json
//	@Param			ip				path		string	true	"Device IP address"						example(192.168.1.1)
//	@Param			max_retries		query		int		false	"Maximum retry attempts (default: 12)"	minimum(1)	maximum(30)
//	@Param			retry_delay_ms	query		int		false	"Delay between retries in ms (default: 5000)"	minimum(100)	maximum(30000)
//	@Success		200				{object}	Response{data=SSIDForceResponse}
//	@Failure		400				{object}	Response
//	@Failure		401				{object}	Response
//	@Failure		404				{object}	Response
//	@Failure		408				{object}	Response
//	@Failure		429				{object}	Response
//	@Failure		500				{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/force/ssid/{ip} [get]
func getSSIDByIPForceHandler(w http.ResponseWriter, r *http.Request) {
	// Get device ID
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// Setup context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Parse retry configuration from query parameters
	maxRetries, retryDelay := parseRetryConfig(r, deviceID)

	// Execute retry loop
	wlanData, attempts, err := executeWLANRetryLoop(ctx, deviceID, maxRetries, retryDelay)
	if err != nil {
		handleWLANRetryError(w, err, maxRetries)
		return
	}

	// Return successful response
	sendResponse(w, http.StatusOK, StatusOK, map[string]interface{}{
		"wlan_data": wlanData,
		"attempts":  attempts,
	})
}

// parseRetryConfig parses retry configuration from query parameters
func parseRetryConfig(r *http.Request, deviceID string) (int, time.Duration) {
	maxRetries := DefaultMaxRetries
	retryDelay := DefaultRetryDelay

	if mrStr := r.URL.Query().Get("max_retries"); mrStr != "" {
		if mr, err := strconv.Atoi(mrStr); err != nil {
			logger.Warn("Invalid max_retries parameter", zap.String("value", mrStr), zap.String("deviceID", deviceID))
		} else if mr > 0 && mr <= MaxRetryAttempts {
			maxRetries = mr
		} else {
			logger.Warn("max_retries out of bounds", zap.Int("value", mr), zap.String("deviceID", deviceID))
		}
	}

	if rdStr := r.URL.Query().Get("retry_delay_ms"); rdStr != "" {
		if rd, err := strconv.Atoi(rdStr); err != nil {
			logger.Warn("Invalid retry_delay_ms parameter", zap.String("value", rdStr), zap.String("deviceID", deviceID))
		} else if rd > 0 && rd <= MaxRetryDelayMs {
			retryDelay = time.Duration(rd) * time.Millisecond
		} else {
			logger.Warn("retry_delay_ms out of bounds", zap.Int("value", rd), zap.String("deviceID", deviceID))
		}
	}

	return maxRetries, retryDelay
}

// executeWLANRetryLoop executes the WLAN data fetch with retry logic
func executeWLANRetryLoop(ctx context.Context, deviceID string, maxRetries int, retryDelay time.Duration) ([]WLANConfig, int, error) {
	refreshDone := false

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, 0, context.DeadlineExceeded
		default:
		}

		deviceCacheInstance.clear(deviceID)
		wlanData, err := getWLANData(ctx, deviceID)

		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, 0, context.DeadlineExceeded
			}
			logger.Error("Failed to get WLAN data", zap.String("deviceID", deviceID), zap.Int("attempt", attempt+1), zap.Error(err))
			return nil, 0, err
		}

		if len(wlanData) > 0 {
			return wlanData, attempt + 1, nil
		}

		if !refreshDone {
			logger.Info("No WLAN data found, triggering refresh", zap.String("deviceID", deviceID), zap.Int("attempt", attempt+1))
			if err := refreshWLANConfig(ctx, deviceID); err != nil {
				logger.Warn("Failed to refresh WLAN config", zap.String("deviceID", deviceID), zap.Error(err))
			}
			refreshDone = true
		}

		time.Sleep(retryDelay)
	}

	return nil, maxRetries, fmt.Errorf("max retries exceeded")
}

// handleWLANRetryError handles errors from the WLAN retry loop
func handleWLANRetryError(w http.ResponseWriter, err error, maxRetries int) {
	if errors.Is(err, context.DeadlineExceeded) {
		sendError(w, http.StatusRequestTimeout, StatusTimeout, ErrOperationTimeout)
		return
	}
	if err.Error() == "max retries exceeded" {
		sendError(w, http.StatusNotFound, StatusNotFound, fmt.Sprintf(ErrNoWLANDataFound, maxRetries))
		return
	}
	sendError(w, http.StatusInternalServerError, StatusInternalError, sanitizeErrorMessage(err))
}

// refreshSSIDHandler triggers a refresh of WLAN configuration data for a device
//
//	@Summary		Trigger SSID refresh
//	@Description	Triggers a refresh of WLAN configuration data for a device. The refresh is processed asynchronously.
//	@Tags			SSID
//	@Accept			json
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		202	{object}	Response{data=MessageResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/ssid/{ip}/refresh [post]
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
