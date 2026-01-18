package main

import (
	"net/http"
)

// healthCheckHandler handles health check requests to verify service status
func healthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	// Return simple health status response indicating service is operational
	sendResponse(w, http.StatusOK, "OK", map[string]string{"status": "healthy"})
}

// clearCacheHandler handles requests to clear device cache (specific device or all)
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
