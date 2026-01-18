package main

import (
	"net/http"

	"go.uber.org/zap"
)

// getDHCPClientByIPHandler retrieves DHCP client information for a device
//
//	@Summary		Get DHCP clients
//	@Description	Retrieves DHCP client information (connected devices) for a device identified by its IP address
//	@Tags			Device
//	@Produce		json
//	@Param			ip		path		string	true	"Device IP address"	example(192.168.1.1)
//	@Param			refresh	query		bool	false	"Force refresh data from device"
//	@Success		200		{object}	Response{data=[]DHCPClient}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/dhcp-client/{ip} [get]
func getDHCPClientByIPHandler(w http.ResponseWriter, r *http.Request) {
	// Extract device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	// Check if refresh parameter is set to true to force data refresh
	if r.URL.Query().Get("refresh") == "true" {
		// Refresh DHCP data from device
		if err := refreshDHCP(r.Context(), deviceID); err != nil {
			// Log error and return 500 if refresh fails
			logger.Info("DHCP refresh task failed", zap.String("deviceID", deviceID), zap.Error(err))
			sendError(w, http.StatusInternalServerError, StatusInternalError, ErrRefreshFailed)
			return
		}
	}
	// Retrieve DHCP client information from device
	dhcpClients, err := getDHCPClients(r.Context(), deviceID)
	if err != nil {
		// Log error and return 500 if DHCP data retrieval fails
		logger.Info("Failed to get DHCP clients", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, sanitizeErrorMessage(err))
		return
	}
	// Return successful response with DHCP client data
	sendResponse(w, http.StatusOK, StatusOK, dhcpClients)
}

// getDeviceCapabilityHandler retrieves the wireless capability of a device (single-band or dual-band)
//
//	@Summary		Get device capability
//	@Description	Retrieves the wireless capability of a device (single-band or dual-band) based on ONU model detection
//	@Tags			Device
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200	{object}	Response{data=DeviceCapabilityResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/capability/{ip} [get]
func getDeviceCapabilityHandler(w http.ResponseWriter, r *http.Request) {
	// Extract device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// Get device capability
	capability, err := getDeviceCapability(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get device capability", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, ErrDeviceCapability)
		return
	}

	sendResponse(w, http.StatusOK, StatusOK, capability)
}
