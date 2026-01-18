package main

import (
	"net/http"
)

// healthCheckHandler handles health check requests to verify service status
//
//	@Summary		Health check
//	@Description	Returns the health status of the service. Does not require authentication.
//	@Tags			Health
//	@Produce		json
//	@Success		200	{object}	Response{data=HealthResponse}
//	@Router			/health [get]
func healthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	// Return simple health status response indicating service is operational
	sendResponse(w, http.StatusOK, "OK", map[string]string{"status": "healthy"})
}

// clearCacheHandler handles requests to clear device cache (specific device or all)
//
//	@Summary		Clear cache
//	@Description	Clears the device cache. Can clear cache for a specific device or all devices.
//	@Tags			Cache
//	@Produce		json
//	@Param			device_id	query		string	false	"Device ID to clear cache for (omit to clear all)"
//	@Success		200			{object}	Response{data=MessageResponse}
//	@Failure		401			{object}	Response
//	@Failure		429			{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/cache/clear [post]
func clearCacheHandler(w http.ResponseWriter, r *http.Request) {
	// Get client IP for audit logging
	clientIP := GetClientIP(r)

	// Get device_id query parameter to determine if clearing specific device or all
	deviceID := r.URL.Query().Get("device_id")
	if deviceID != "" {
		// Clear cache for specific device only
		deviceCacheInstance.clear(deviceID)
		AuditLog(AuditEventCacheClear, clientIP, deviceID, "Device cache cleared")
	} else {
		// Clear entire cache if no specific device specified
		deviceCacheInstance.clearAll()
		AuditLog(AuditEventCacheClear, clientIP, "", "All device cache cleared")
	}
	// Return success response indicating cache was cleared
	sendResponse(w, http.StatusOK, StatusOK, map[string]string{"message": MsgCacheCleared})
}
