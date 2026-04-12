package main

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
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
	sendResponse(w, http.StatusOK, HealthResponse{Status: "healthy"})
}

// versionHandler returns build metadata injected via ldflags at compile time.
//
//	@Summary		Version info
//	@Description	Returns binary build metadata (version, commit, build_time, api_version, uptime). Does not require authentication.
//	@Tags			Health
//	@Produce		json
//	@Success		200	{object}	VersionResponse
//	@Router			/version [get]
func versionHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(VersionResponse{
		Version:    BuildVersion(),
		Commit:     BuildCommit(),
		BuildTime:  BuildDate(),
		APIVersion: APIVersion,
		Uptime:     Uptime(),
	}); err != nil {
		logger.Error("Failed to encode version response", zap.Error(err))
	}
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
	sendResponse(w, http.StatusOK, map[string]string{"message": MsgCacheCleared})
}
