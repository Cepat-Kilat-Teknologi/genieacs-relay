package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// createWLANHandler creates a new WLAN on a device with band capability validation
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

	// Apply defaults for optional fields
	authMode := createReq.AuthMode
	if authMode == "" {
		authMode = "WPA2" // Default to WPA2
	}

	encryption := createReq.Encryption
	if encryption == "" {
		encryption = "AES" // Default to AES
	}

	hidden := DefaultHiddenSSID
	if createReq.Hidden != nil {
		hidden = *createReq.Hidden
	}

	maxClients := DefaultMaxClients
	if createReq.MaxClients != nil {
		maxClients = *createReq.MaxClients
	}

	// Validate authentication mode
	beaconType, validAuth := ValidateAuthMode(authMode)
	if !validAuth {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidAuthMode)
		return
	}

	// Validate encryption mode
	encryptionValue, validEnc := ValidateEncryption(encryption)
	if !validEnc {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidEncryption)
		return
	}

	// Validate max clients
	if maxClients < MinMaxClients || maxClients > MaxMaxClients {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidMaxClients)
		return
	}

	// Validate password - required for non-Open authentication
	if authMode != "Open" {
		if createReq.Password == "" {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordRequiredAuth)
			return
		}
		if len(createReq.Password) < MinPasswordLength {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooShort)
			return
		}
		if len(createReq.Password) > MaxPasswordLength {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrPasswordTooLong)
			return
		}
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

	// Build parameter values for creating WLAN
	enablePath := fmt.Sprintf(PathWLANEnableFormat, wlan)
	ssidPath := fmt.Sprintf(PathWLANSSIDFormat, wlan)
	ssidAdvertisementPath := fmt.Sprintf(PathWLANSSIDAdvertisementFormat, wlan)
	maxAssocDevicesPath := fmt.Sprintf(PathWLANMaxAssocDevicesFormat, wlan)
	beaconTypePath := fmt.Sprintf(PathWLANBeaconTypeFormat, wlan)

	parameterValues := [][]interface{}{
		{enablePath, true, XSDBoolean},
		{ssidPath, createReq.SSID, XSDString},
		{ssidAdvertisementPath, !hidden, XSDBoolean}, // SSIDAdvertisementEnabled = true means visible (not hidden)
		{maxAssocDevicesPath, maxClients, XSDUnsignedInt},
		{beaconTypePath, beaconType, XSDString},
	}

	// Add password and encryption settings for non-Open authentication
	if authMode != "Open" {
		passwordPath := fmt.Sprintf(PathWLANPasswordFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{passwordPath, createReq.Password, XSDString})

		// Set encryption and authentication parameters based on auth mode
		securityParams := BuildWLANSecurityParams(wlan, authMode, encryptionValue)
		parameterValues = append(parameterValues, securityParams...)
	}

	// Submit update and clear cache
	SubmitWLANUpdate(deviceID, parameterValues)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	// Audit log for WLAN creation
	AuditLogWithFields(AuditEventWLANCreate, GetClientIP(r), deviceID, map[string]interface{}{
		"wlan":        wlan,
		"ssid":        createReq.SSID,
		"band":        band,
		"auth_mode":   authMode,
		"encryption":  encryption,
		"hidden":      hidden,
		"max_clients": maxClients,
	})

	// Build response with applied settings
	responseData := map[string]interface{}{
		"message":     MsgWLANCreationSubmitted,
		"device_id":   deviceID,
		"wlan":        wlan,
		"ssid":        createReq.SSID,
		"band":        band,
		"ip":          ip,
		"hidden":      hidden,
		"max_clients": maxClients,
		"auth_mode":   authMode,
		"encryption":  encryption,
	}

	sendResponse(w, http.StatusOK, StatusOK, responseData)
}

// getAvailableWLANHandler returns available WLAN slots for a device
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

	// Build used WLAN info and track used IDs
	usedWLANIDs := make(map[int]bool)
	var usedWLAN []UsedWLANInfo
	for _, wlan := range wlanConfigs {
		wlanID, err := strconv.Atoi(wlan.WLAN)
		if err != nil {
			continue // Skip invalid WLAN IDs
		}
		usedWLANIDs[wlanID] = true
		usedWLAN = append(usedWLAN, UsedWLANInfo{
			WLANID: wlanID,
			SSID:   wlan.SSID,
			Band:   wlan.Band,
		})
	}

	// Calculate total slots based on band type
	var total24GHz, total5GHz []int
	for i := WLAN24GHzMin; i <= WLAN24GHzMax; i++ {
		total24GHz = append(total24GHz, i)
	}
	if capability.IsDualBand {
		for i := WLAN5GHzMin; i <= WLAN5GHzMax; i++ {
			total5GHz = append(total5GHz, i)
		}
	}

	// Calculate available slots
	var available24GHz, available5GHz []int
	for i := WLAN24GHzMin; i <= WLAN24GHzMax; i++ {
		if !usedWLANIDs[i] {
			available24GHz = append(available24GHz, i)
		}
	}
	if capability.IsDualBand {
		for i := WLAN5GHzMin; i <= WLAN5GHzMax; i++ {
			if !usedWLANIDs[i] {
				available5GHz = append(available5GHz, i)
			}
		}
	}

	// Build response
	response := AvailableWLANResponse{
		DeviceID: deviceID,
		Model:    capability.Model,
		BandType: string(capability.BandType),
	}
	response.TotalSlots.Band24GHz = total24GHz
	response.TotalSlots.Band5GHz = total5GHz
	if response.TotalSlots.Band5GHz == nil {
		response.TotalSlots.Band5GHz = []int{}
	}

	response.UsedWLAN = usedWLAN
	if response.UsedWLAN == nil {
		response.UsedWLAN = []UsedWLANInfo{}
	}

	response.AvailableWLAN.Band24GHz = available24GHz
	if response.AvailableWLAN.Band24GHz == nil {
		response.AvailableWLAN.Band24GHz = []int{}
	}
	response.AvailableWLAN.Band5GHz = available5GHz
	if response.AvailableWLAN.Band5GHz == nil {
		response.AvailableWLAN.Band5GHz = []int{}
	}

	// Add configuration options for frontend
	response.ConfigOptions.AuthModes = []string{"Open", "WPA", "WPA2", "WPA/WPA2"}
	response.ConfigOptions.Encryptions = []string{"AES", "TKIP", "TKIP+AES"}
	response.ConfigOptions.MaxClients.Min = MinMaxClients
	response.ConfigOptions.MaxClients.Max = MaxMaxClients
	response.ConfigOptions.MaxClients.Default = DefaultMaxClients

	sendResponse(w, http.StatusOK, StatusOK, response)
}

// updateWLANHandler updates an existing WLAN configuration
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
	if updateReq.SSID == nil && updateReq.Password == nil && updateReq.Hidden == nil &&
		updateReq.MaxClients == nil && updateReq.AuthMode == nil && updateReq.Encryption == nil {
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

	// Build parameter values for updating WLAN
	var parameterValues [][]interface{}
	updatedFields := make(map[string]interface{})

	// Validate and add SSID if provided
	if updateReq.SSID != nil {
		ssid := *updateReq.SSID
		if errMsg := ValidateSSID(ssid); errMsg != "" {
			sendError(w, http.StatusBadRequest, StatusBadRequest, errMsg)
			return
		}
		ssidPath := fmt.Sprintf(PathWLANSSIDFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{ssidPath, ssid, XSDString})
		updatedFields["ssid"] = ssid
	}

	// Validate and add password if provided
	if updateReq.Password != nil {
		password := *updateReq.Password
		if errMsg := ValidatePassword(password); errMsg != "" {
			sendError(w, http.StatusBadRequest, StatusBadRequest, errMsg)
			return
		}
		passwordPath := fmt.Sprintf(PathWLANPasswordFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{passwordPath, password, XSDString})
		updatedFields["password"] = "********" // Mask password in response
	}

	// Add hidden SSID setting if provided
	if updateReq.Hidden != nil {
		hidden := *updateReq.Hidden
		ssidAdvertisementPath := fmt.Sprintf(PathWLANSSIDAdvertisementFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{ssidAdvertisementPath, !hidden, XSDBoolean})
		updatedFields["hidden"] = hidden
	}

	// Validate and add max clients if provided
	if updateReq.MaxClients != nil {
		maxClients := *updateReq.MaxClients
		if maxClients < MinMaxClients || maxClients > MaxMaxClients {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidMaxClients)
			return
		}
		maxAssocDevicesPath := fmt.Sprintf(PathWLANMaxAssocDevicesFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{maxAssocDevicesPath, maxClients, XSDUnsignedInt})
		updatedFields["max_clients"] = maxClients
	}

	// Validate and add auth mode if provided
	if updateReq.AuthMode != nil {
		authMode := *updateReq.AuthMode
		beaconType, validAuth := ValidateAuthMode(authMode)
		if !validAuth {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidAuthMode)
			return
		}
		beaconTypePath := fmt.Sprintf(PathWLANBeaconTypeFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{beaconTypePath, beaconType, XSDString})
		updatedFields["auth_mode"] = authMode

		// Set authentication mode parameters based on type
		authModeParams := BuildAuthModeParams(wlan, authMode)
		parameterValues = append(parameterValues, authModeParams...)
	}

	// Validate and add encryption if provided
	if updateReq.Encryption != nil {
		encryption := *updateReq.Encryption
		encryptionValue, validEnc := ValidateEncryption(encryption)
		if !validEnc {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidEncryption)
			return
		}

		// Set encryption for both WPA and WPA2 paths to cover all cases
		wpaEncryptionPath := fmt.Sprintf(PathWLANWPAEncryptionModesFormat, wlan)
		ieee11iEncryptionPath := fmt.Sprintf(PathWLAN11iEncryptionModesFormat, wlan)
		parameterValues = append(parameterValues,
			[]interface{}{wpaEncryptionPath, encryptionValue, XSDString},
			[]interface{}{ieee11iEncryptionPath, encryptionValue, XSDString},
		)
		updatedFields["encryption"] = encryption
	}

	// Submit update and clear cache
	SubmitWLANUpdate(deviceID, parameterValues)

	// Determine the band for this WLAN
	band := getWLANBandByID(wlanID)

	// Audit log for WLAN update
	AuditLogWithFields(AuditEventWLANUpdate, GetClientIP(r), deviceID, map[string]interface{}{
		"wlan":           wlan,
		"band":           band,
		"updated_fields": updatedFields,
	})

	// Build response
	responseData := map[string]interface{}{
		"message":        MsgWLANUpdateSubmitted,
		"device_id":      deviceID,
		"wlan":           wlan,
		"band":           band,
		"ip":             ip,
		"updated_fields": updatedFields,
	}

	sendResponse(w, http.StatusOK, StatusOK, responseData)
}

// deleteWLANHandler disables/deletes a WLAN configuration
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
	if optimizeReq.Channel == nil && optimizeReq.Mode == nil &&
		optimizeReq.Bandwidth == nil && optimizeReq.TransmitPower == nil {
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

	// Build parameter values for optimization
	var parameterValues [][]interface{}
	updatedSettings := make(map[string]interface{})

	// Validate and add channel if provided
	if optimizeReq.Channel != nil {
		channel := *optimizeReq.Channel
		if err := ValidateWLANChannel(channel, is5GHz); err != nil {
			sendError(w, http.StatusBadRequest, StatusBadRequest, sanitizeErrorMessage(err))
			return
		}

		// Handle Auto channel setting
		autoChannelPath := fmt.Sprintf(PathWLANAutoChannelEnableFormat, wlan)
		if channel == ChannelAuto {
			parameterValues = append(parameterValues, []interface{}{autoChannelPath, true, XSDBoolean})
		} else {
			// Set specific channel and disable auto channel
			channelPath := fmt.Sprintf(PathWLANChannelFormat, wlan)
			channelNum, _ := strconv.Atoi(channel)
			parameterValues = append(parameterValues,
				[]interface{}{autoChannelPath, false, XSDBoolean},
				[]interface{}{channelPath, channelNum, XSDUnsignedInt},
			)
		}
		updatedSettings["channel"] = channel
	}

	// Validate and add mode if provided
	if optimizeReq.Mode != nil {
		mode := *optimizeReq.Mode
		tr069Mode, err := ValidateWLANMode(mode, is5GHz)
		if err != nil {
			sendError(w, http.StatusBadRequest, StatusBadRequest, sanitizeErrorMessage(err))
			return
		}

		modePath := fmt.Sprintf(PathWLANOperatingStandardFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{modePath, tr069Mode, XSDString})
		updatedSettings["mode"] = mode
	}

	// Validate and add bandwidth if provided
	if optimizeReq.Bandwidth != nil {
		bandwidth := *optimizeReq.Bandwidth
		if err := ValidateWLANBandwidth(bandwidth, is5GHz); err != nil {
			sendError(w, http.StatusBadRequest, StatusBadRequest, sanitizeErrorMessage(err))
			return
		}

		bandwidthPath := fmt.Sprintf(PathWLANChannelBandwidthFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{bandwidthPath, bandwidth, XSDString})
		updatedSettings["bandwidth"] = bandwidth
	}

	// Validate and add transmit power if provided
	if optimizeReq.TransmitPower != nil {
		power := *optimizeReq.TransmitPower
		if !ValidTransmitPower[power] {
			sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidTransmitPower)
			return
		}

		powerPath := fmt.Sprintf(PathWLANTransmitPowerFormat, wlan)
		parameterValues = append(parameterValues, []interface{}{powerPath, power, XSDUnsignedInt})
		updatedSettings["transmit_power"] = power
	}

	// Submit update and clear cache
	SubmitWLANUpdate(deviceID, parameterValues)

	// Audit log for WLAN optimization
	AuditLogWithFields(AuditEventWLANOptimize, GetClientIP(r), deviceID, map[string]interface{}{
		"wlan":             wlan,
		"band":             band,
		"updated_settings": updatedSettings,
	})

	// Build response
	responseData := map[string]interface{}{
		"message":          MsgWLANOptimizeSubmitted,
		"device_id":        deviceID,
		"wlan":             wlan,
		"band":             band,
		"ip":               ip,
		"updated_settings": updatedSettings,
	}

	sendResponse(w, http.StatusOK, StatusOK, responseData)
}
