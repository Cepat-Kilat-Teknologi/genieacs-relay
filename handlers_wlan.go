package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// createWLANHandler creates a new WLAN on a device with band capability validation
//
//	@Summary		Create new WLAN
//	@Description	Creates a new WLAN on an available slot with advanced configuration options
//	@Tags			WLAN
//	@Accept			json
//	@Produce		json
//	@Param			wlan	path		string				true	"WLAN ID (1-4 for 2.4GHz, 5-8 for 5GHz)"	example(2)
//	@Param			ip		path		string				true	"Device IP address"							example(192.168.1.1)
//	@Param			body	body		CreateWLANRequest	true	"WLAN creation parameters"
//	@Success		200		{object}	Response{data=WLANCreateResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		409		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wlan/create/{wlan}/{ip} [post]
func createWLANHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	// Extract and validate WLAN ID
	wlan, wlanID, ok := ExtractAndValidateWLANID(w, r)
	if !ok {
		return
	}

	// Parse request body
	var createReq CreateWLANRequest
	if !ParseJSONRequest(w, r, &createReq) {
		return
	}

	// Validate SSID
	if errMsg := ValidateSSID(createReq.SSID); errMsg != "" {
		sendError(w, http.StatusBadRequest, StatusBadRequest, errMsg)
		return
	}

	// Apply defaults and validate auth configuration
	cfg := ApplyCreateWLANDefaults(createReq.AuthMode, createReq.Encryption, createReq.Hidden, createReq.MaxClients)
	beaconType, encryptionValue, errMsg := ValidateCreateWLANAuth(cfg, createReq.Password)
	if errMsg != "" {
		sendError(w, http.StatusBadRequest, StatusBadRequest, errMsg)
		return
	}

	// Get device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, sanitizeErrorMessage(err))
		return
	}

	// Check if WLAN already exists and is enabled
	if !CheckWLANNotExistsAndRespond(w, r, deviceID, wlan) {
		return
	}

	// Build and submit parameter values
	parameterValues := buildCreateWLANParams(wlan, createReq.SSID, createReq.Password, cfg, beaconType, encryptionValue)
	SubmitWLANUpdate(deviceID, parameterValues)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	// Audit log for WLAN creation
	AuditLogWithFields(AuditEventWLANCreate, GetClientIP(r), deviceID, map[string]interface{}{
		"wlan":        wlan,
		"ssid":        createReq.SSID,
		"band":        band,
		"auth_mode":   cfg.AuthMode,
		"encryption":  cfg.Encryption,
		"hidden":      cfg.Hidden,
		"max_clients": cfg.MaxClients,
	})

	// Build response with applied settings
	sendResponse(w, http.StatusOK, StatusOK, map[string]interface{}{
		"message":     MsgWLANCreationSubmitted,
		"device_id":   deviceID,
		"wlan":        wlan,
		"ssid":        createReq.SSID,
		"band":        band,
		"ip":          ip,
		"hidden":      cfg.Hidden,
		"max_clients": cfg.MaxClients,
		"auth_mode":   cfg.AuthMode,
		"encryption":  cfg.Encryption,
	})
}

// buildCreateWLANParams builds parameter values for WLAN creation
func buildCreateWLANParams(wlan, ssid, password string, cfg CreateWLANConfig, beaconType, encryptionValue string) [][]interface{} {
	parameterValues := [][]interface{}{
		{fmt.Sprintf(PathWLANEnableFormat, wlan), true, XSDBoolean},
		{fmt.Sprintf(PathWLANSSIDFormat, wlan), ssid, XSDString},
		{fmt.Sprintf(PathWLANSSIDAdvertisementFormat, wlan), !cfg.Hidden, XSDBoolean},
		{fmt.Sprintf(PathWLANMaxAssocDevicesFormat, wlan), cfg.MaxClients, XSDUnsignedInt},
		{fmt.Sprintf(PathWLANBeaconTypeFormat, wlan), beaconType, XSDString},
	}

	if cfg.AuthMode != "Open" {
		passwordPath := fmt.Sprintf(PathWLANPasswordFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{passwordPath, password, XSDString})
		securityParams := BuildWLANSecurityParams(wlan, cfg.AuthMode, encryptionValue)
		parameterValues = append(parameterValues, securityParams...)
	}

	return parameterValues
}

// getAvailableWLANHandler returns available WLAN slots for a device
//
//	@Summary		Get available WLAN slots
//	@Description	Returns available WLAN slots for creating new WiFi networks based on device capability
//	@Tags			WLAN
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200	{object}	Response{data=AvailableWLANResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wlan/available/{ip} [get]
func getAvailableWLANHandler(w http.ResponseWriter, r *http.Request) {
	// Get device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// Get device capability
	capability, err := getDeviceCapability(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get device capability", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, ErrGetDeviceCapability)
		return
	}

	// Get current WLAN configurations (enabled ones)
	wlanConfigs, err := getWLANData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to get WLAN data", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, ErrGetWLANData)
		return
	}

	// Calculate available slots
	slots := CalculateAvailableWLANSlots(capability, wlanConfigs)

	// Build response
	response := buildAvailableWLANResponse(deviceID, capability, slots)
	sendResponse(w, http.StatusOK, StatusOK, response)
}

// buildAvailableWLANResponse builds the response for available WLAN slots
func buildAvailableWLANResponse(deviceID string, capability *DeviceCapability, slots AvailableWLANSlots) AvailableWLANResponse {
	response := AvailableWLANResponse{
		DeviceID: deviceID,
		Model:    capability.Model,
		BandType: string(capability.BandType),
	}

	// Set total slots with nil-safe defaults
	response.TotalSlots.Band24GHz = slots.Total24GHz
	response.TotalSlots.Band5GHz = ensureIntSlice(slots.Total5GHz)

	// Set used WLAN with nil-safe default
	response.UsedWLAN = slots.UsedWLAN
	if response.UsedWLAN == nil {
		response.UsedWLAN = []UsedWLANInfo{}
	}

	// Set available slots with nil-safe defaults
	response.AvailableWLAN.Band24GHz = ensureIntSlice(slots.Available24GHz)
	response.AvailableWLAN.Band5GHz = ensureIntSlice(slots.Available5GHz)

	// Add configuration options for frontend
	response.ConfigOptions.AuthModes = []string{"Open", "WPA", "WPA2", "WPA/WPA2"}
	response.ConfigOptions.Encryptions = []string{"AES", "TKIP", "TKIP+AES"}
	response.ConfigOptions.MaxClients.Min = MinMaxClients
	response.ConfigOptions.MaxClients.Max = MaxMaxClients
	response.ConfigOptions.MaxClients.Default = DefaultMaxClients

	return response
}

// ensureIntSlice returns an empty slice if input is nil
func ensureIntSlice(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

// updateWLANHandler updates an existing WLAN configuration
//
//	@Summary		Update WLAN configuration
//	@Description	Updates an existing WLAN configuration. Supports partial updates - only include fields you want to change.
//	@Tags			WLAN
//	@Accept			json
//	@Produce		json
//	@Param			wlan	path		string				true	"WLAN ID (1-8)"			example(2)
//	@Param			ip		path		string				true	"Device IP address"		example(192.168.1.1)
//	@Param			body	body		UpdateWLANRequest	true	"WLAN update parameters (all fields optional)"
//	@Success		200		{object}	Response{data=WLANUpdateResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wlan/update/{wlan}/{ip} [put]
func updateWLANHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	// Extract and validate WLAN ID
	wlan, wlanID, ok := ExtractAndValidateWLANID(w, r)
	if !ok {
		return
	}

	// Parse request body
	var updateReq UpdateWLANRequest
	if !ParseJSONRequest(w, r, &updateReq) {
		return
	}

	// Check if at least one field is provided
	if !hasUpdateFields(updateReq) {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrUpdateFieldRequired)
		return
	}

	// Get device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, sanitizeErrorMessage(err))
		return
	}

	// Check if WLAN exists and is enabled
	if !CheckWLANExistsAndRespond(w, r, deviceID, wlan, ErrWLANNotFound) {
		return
	}

	// Process update fields
	result := ProcessUpdateWLANFields(wlan, updateReq)
	if result.ErrorMsg != "" {
		sendError(w, http.StatusBadRequest, StatusBadRequest, result.ErrorMsg)
		return
	}

	// Submit update and clear cache
	SubmitWLANUpdate(deviceID, result.Params)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	// Audit log for WLAN update
	AuditLogWithFields(AuditEventWLANUpdate, GetClientIP(r), deviceID, map[string]interface{}{
		"wlan":           wlan,
		"band":           band,
		"updated_fields": result.UpdatedFields,
	})

	// Build response
	sendResponse(w, http.StatusOK, StatusOK, map[string]interface{}{
		"message":        MsgWLANUpdateSubmitted,
		"device_id":      deviceID,
		"wlan":           wlan,
		"band":           band,
		"ip":             ip,
		"updated_fields": result.UpdatedFields,
	})
}

// hasUpdateFields checks if at least one update field is provided
func hasUpdateFields(req UpdateWLANRequest) bool {
	return req.SSID != nil || req.Password != nil || req.Hidden != nil ||
		req.MaxClients != nil || req.AuthMode != nil || req.Encryption != nil
}

// deleteWLANHandler disables/deletes a WLAN configuration
//
//	@Summary		Delete/Disable WLAN
//	@Description	Disables an existing WLAN configuration. This effectively "deletes" the WLAN by disabling it.
//	@Tags			WLAN
//	@Produce		json
//	@Param			wlan	path		string	true	"WLAN ID (1-8)"		example(2)
//	@Param			ip		path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200		{object}	Response{data=WLANDeleteResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wlan/delete/{wlan}/{ip} [delete]
func deleteWLANHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	// Extract and validate WLAN ID
	wlan, wlanID, ok := ExtractAndValidateWLANID(w, r)
	if !ok {
		return
	}

	// Get device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, sanitizeErrorMessage(err))
		return
	}

	// Check if WLAN exists and is enabled
	if !CheckWLANExistsAndRespond(w, r, deviceID, wlan, ErrWLANNotFoundDelete) {
		return
	}

	// Build parameter values for disabling WLAN
	enablePath := fmt.Sprintf(PathWLANEnableFormat, wlan)
	parameterValues := [][]interface{}{
		{enablePath, false, XSDBoolean},
	}

	// Submit update and clear cache
	SubmitWLANUpdate(deviceID, parameterValues)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	// Audit log for WLAN deletion
	AuditLog(AuditEventWLANDelete, GetClientIP(r), deviceID,
		fmt.Sprintf("WLAN %s deleted (band: %s)", wlan, band))

	sendResponse(w, http.StatusOK, StatusOK, map[string]string{
		"message":   MsgWLANDeletionSubmitted,
		"device_id": deviceID,
		"wlan":      wlan,
		"band":      band,
		"ip":        ip,
	})
}

// optimizeWLANHandler optimizes WLAN radio settings (channel, mode, bandwidth, transmit power)
//
//	@Summary		Optimize WLAN radio settings
//	@Description	Optimizes WLAN radio settings including channel, mode, bandwidth, and transmit power. Supports partial updates.
//	@Tags			WLAN
//	@Accept			json
//	@Produce		json
//	@Param			wlan	path		string				true	"WLAN ID (1-8)"			example(1)
//	@Param			ip		path		string				true	"Device IP address"		example(192.168.1.1)
//	@Param			body	body		OptimizeWLANRequest	true	"WLAN optimization parameters (all fields optional)"
//	@Success		200		{object}	Response{data=WLANOptimizeResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wlan/optimize/{wlan}/{ip} [put]
func optimizeWLANHandler(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	// Extract and validate WLAN ID
	wlan, wlanID, ok := ExtractAndValidateWLANID(w, r)
	if !ok {
		return
	}

	// Parse request body
	var optimizeReq OptimizeWLANRequest
	if !ParseJSONRequest(w, r, &optimizeReq) {
		return
	}

	// Check if at least one field is provided
	if !hasOptimizeFields(optimizeReq) {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrNoOptimizeFields)
		return
	}

	// Get device ID from IP
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	// Validate WLAN ID against device capability (band validation)
	if err := validateWLANIDForDevice(r.Context(), deviceID, wlanID); err != nil {
		logger.Info("WLAN ID not supported by device",
			zap.String("deviceID", deviceID),
			zap.Int("wlanID", wlanID),
			zap.Error(err))
		sendError(w, http.StatusBadRequest, StatusBadRequest, sanitizeErrorMessage(err))
		return
	}

	// Check if WLAN exists and is enabled
	if !CheckWLANExistsAndRespond(w, r, deviceID, wlan, ErrWLANNotFound) {
		return
	}

	// Determine band based on WLAN ID
	is5GHz := wlanID >= WLAN5GHzMin && wlanID <= WLAN5GHzMax
	band := Band2_4GHz
	if is5GHz {
		band = Band5GHz
	}

	// Process optimize fields
	result := ProcessOptimizeWLANFields(wlan, optimizeReq, is5GHz)
	if result.ErrorMsg != "" {
		sendError(w, http.StatusBadRequest, StatusBadRequest, result.ErrorMsg)
		return
	}

	// Submit update and clear cache
	SubmitWLANUpdate(deviceID, result.Params)

	// Audit log for WLAN optimization
	AuditLogWithFields(AuditEventWLANOptimize, GetClientIP(r), deviceID, map[string]interface{}{
		"wlan":             wlan,
		"band":             band,
		"updated_settings": result.UpdatedSettings,
	})

	// Build response
	sendResponse(w, http.StatusOK, StatusOK, map[string]interface{}{
		"message":          MsgWLANOptimizeSubmitted,
		"device_id":        deviceID,
		"wlan":             wlan,
		"band":             band,
		"ip":               ip,
		"updated_settings": result.UpdatedSettings,
	})
}

// hasOptimizeFields checks if at least one optimize field is provided
func hasOptimizeFields(req OptimizeWLANRequest) bool {
	return req.Channel != nil || req.Mode != nil || req.Bandwidth != nil || req.TransmitPower != nil
}
