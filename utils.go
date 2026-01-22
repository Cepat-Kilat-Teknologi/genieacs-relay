package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// GetClientIP extracts the client IP address from the request.
// It checks X-Real-IP header first (for proxied requests), then falls back to RemoteAddr.
func GetClientIP(r *http.Request) string {
	clientIP := r.RemoteAddr
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if parsedIP := net.ParseIP(realIP); parsedIP != nil {
			clientIP = realIP
		}
	}
	return clientIP
}

// safeClose safely closes an io.Closer resource and logs any errors
func safeClose(closer io.Closer) {
	if closer != nil {
		if err := closer.Close(); err != nil {
			logger.Warn("Failed to close resource", zap.Error(err))
		}
	}
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}

// --- HTTP Handler Helpers ---

// ExtractDeviceIDByIP is a helper that extracts device ID from IP and handles common error responses
// Returns the device ID and true if successful, or sends an error response and returns false
func ExtractDeviceIDByIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip := chi.URLParam(r, "ip")
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		sendError(w, http.StatusNotFound, StatusNotFound, sanitizeErrorMessage(err))
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

// ExtractAndValidateWLANID extracts WLAN ID from URL, validates format, and parses to integer.
// Returns wlan string, wlanID int, and true if successful.
// Sends error response and returns false if validation fails.
func ExtractAndValidateWLANID(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	wlan := chi.URLParam(r, "wlan")
	if err := validateWLANID(wlan); err != nil {
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidWLANID)
		return "", 0, false
	}
	// Already validated, safe to ignore error
	wlanID, _ := strconv.Atoi(wlan)
	return wlan, wlanID, true
}

// CheckWLANNotExistsAndRespond checks that a WLAN does NOT exist (for create operations).
// Returns true if WLAN does not exist (can proceed with creation).
// Returns false and sends conflict error if WLAN already exists.
func CheckWLANNotExistsAndRespond(w http.ResponseWriter, r *http.Request, deviceID, wlan string) bool {
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to check WLAN status",
			zap.String("deviceID", deviceID),
			zap.String("wlan", wlan),
			zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, ErrWLANCheckFailed)
		return false
	}
	if valid {
		sendError(w, http.StatusConflict, StatusConflict, fmt.Sprintf(ErrWLANAlreadyExists, wlan))
		return false
	}
	return true
}

// CheckWLANExistsAndRespond checks that a WLAN exists (for update/delete/optimize operations).
// Returns true if WLAN exists (can proceed with operation).
// Returns false and sends not found error if WLAN does not exist.
// Use notFoundMsg to customize the error message (e.g., ErrWLANNotFound or ErrWLANNotFoundDelete).
func CheckWLANExistsAndRespond(w http.ResponseWriter, r *http.Request, deviceID, wlan, notFoundMsg string) bool {
	valid, err := isWLANValid(r.Context(), deviceID, wlan)
	if err != nil {
		logger.Error("Failed to check WLAN status",
			zap.String("deviceID", deviceID),
			zap.String("wlan", wlan),
			zap.Error(err))
		sendError(w, http.StatusInternalServerError, StatusInternalError, ErrWLANCheckFailed)
		return false
	}
	if !valid {
		sendError(w, http.StatusNotFound, StatusNotFound, fmt.Sprintf(notFoundMsg, wlan))
		return false
	}
	return true
}

// --- Request Parsing Helpers ---

// ParseJSONRequest parses a JSON request body with size limiting and Content-Type validation.
// Returns true if successful, false if an error response was sent.
func ParseJSONRequest(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	// Validate Content-Type header to prevent non-JSON payloads
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		sendError(w, http.StatusUnsupportedMediaType, "Unsupported Media Type", ErrInvalidContentType)
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if err.Error() == ErrBodyTooLarge {
			sendError(w, http.StatusRequestEntityTooLarge, "Request Entity Too Large", ErrRequestBodyTooLarge)
			return false
		}
		sendError(w, http.StatusBadRequest, StatusBadRequest, ErrInvalidJSON)
		return false
	}
	return true
}

// SubmitWLANUpdate submits parameter updates to a device and clears cache.
// This is a common pattern used across WLAN handlers.
func SubmitWLANUpdate(deviceID string, parameterValues [][]interface{}) {
	taskWorkerPool.Submit(deviceID, taskTypeSetParams, parameterValues)
	taskWorkerPool.Submit(deviceID, taskTypeApplyChanges, nil)
	deviceCacheInstance.clear(deviceID)
}

// --- WLAN Security Parameter Builders ---

// BuildWLANSecurityParams builds encryption and authentication parameters for WLAN creation.
// Returns parameter values for both encryption modes and PSK authentication based on auth mode.
func BuildWLANSecurityParams(wlan, authMode, encryptionValue string) [][]interface{} {
	var params [][]interface{}

	switch authMode {
	case "WPA":
		wpaEncryptionPath := fmt.Sprintf(PathWLANWPAEncryptionModesFormat, wlan)
		wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
		params = append(params,
			[]interface{}{wpaEncryptionPath, encryptionValue, XSDString},
			[]interface{}{wpaAuthModePath, WPAAuthModePSK, XSDString},
		)
	case "WPA2":
		ieee11iEncryptionPath := fmt.Sprintf(PathWLAN11iEncryptionModesFormat, wlan)
		ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
		params = append(params,
			[]interface{}{ieee11iEncryptionPath, encryptionValue, XSDString},
			[]interface{}{ieee11iAuthModePath, WPAAuthModePSK, XSDString},
		)
	case "WPA/WPA2":
		wpaEncryptionPath := fmt.Sprintf(PathWLANWPAEncryptionModesFormat, wlan)
		wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
		ieee11iEncryptionPath := fmt.Sprintf(PathWLAN11iEncryptionModesFormat, wlan)
		ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
		params = append(params,
			[]interface{}{wpaEncryptionPath, encryptionValue, XSDString},
			[]interface{}{wpaAuthModePath, WPAAuthModePSK, XSDString},
			[]interface{}{ieee11iEncryptionPath, encryptionValue, XSDString},
			[]interface{}{ieee11iAuthModePath, WPAAuthModePSK, XSDString},
		)
	}

	return params
}

// BuildAuthModeParams builds PSK authentication parameters for WLAN auth mode updates.
// Returns parameter values for PSKAuthentication based on auth mode.
func BuildAuthModeParams(wlan, authMode string) [][]interface{} {
	var params [][]interface{}

	switch authMode {
	case "WPA":
		wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
		params = append(params, []interface{}{wpaAuthModePath, WPAAuthModePSK, XSDString})
	case "WPA2":
		ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
		params = append(params, []interface{}{ieee11iAuthModePath, WPAAuthModePSK, XSDString})
	case "WPA/WPA2":
		wpaAuthModePath := fmt.Sprintf(PathWLANWPAAuthModeFormat, wlan)
		ieee11iAuthModePath := fmt.Sprintf(PathWLAN11iAuthModeFormat, wlan)
		params = append(params,
			[]interface{}{wpaAuthModePath, WPAAuthModePSK, XSDString},
			[]interface{}{ieee11iAuthModePath, WPAAuthModePSK, XSDString},
		)
	}

	return params
}

// --- Validation Helpers ---

// ValidateSSID validates SSID according to all rules.
// Returns error message if invalid, empty string if valid.
func ValidateSSID(ssid string) string {
	if ssid == "" {
		return ErrSSIDRequired
	}
	if strings.TrimSpace(ssid) != ssid {
		return ErrSSIDInvalidSpaces
	}
	if len(ssid) > MaxSSIDLength {
		return ErrSSIDTooLong
	}
	if err := validateSSIDCharacters(ssid); err != nil {
		return ErrSSIDInvalidChars
	}
	return ""
}

// ValidatePassword validates password according to all rules.
// Returns error message if invalid, empty string if valid.
func ValidatePassword(password string) string {
	if password == "" {
		return ErrPasswordRequired
	}
	// Check for all-whitespace password
	if strings.TrimSpace(password) == "" {
		return ErrPasswordRequired
	}
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return ""
}

// ValidateAuthMode validates authentication mode and returns the TR-069 beacon type.
// Returns empty string if invalid.
func ValidateAuthMode(authMode string) (string, bool) {
	beaconType, valid := ValidAuthModes[authMode]
	return beaconType, valid
}

// ValidateEncryption validates encryption mode and returns the TR-069 encryption value.
// Returns empty string if invalid.
func ValidateEncryption(encryption string) (string, bool) {
	encryptionValue, valid := ValidEncryptions[encryption]
	return encryptionValue, valid
}

// CreateWLANConfig holds configuration for WLAN creation
type CreateWLANConfig struct {
	AuthMode   string
	Encryption string
	Hidden     bool
	MaxClients int
}

// ApplyCreateWLANDefaults applies default values to optional WLAN creation fields
func ApplyCreateWLANDefaults(authMode, encryption string, hidden *bool, maxClients *int) CreateWLANConfig {
	cfg := CreateWLANConfig{
		AuthMode:   authMode,
		Encryption: encryption,
		Hidden:     DefaultHiddenSSID,
		MaxClients: DefaultMaxClients,
	}

	if cfg.AuthMode == "" {
		cfg.AuthMode = "WPA2"
	}
	if cfg.Encryption == "" {
		cfg.Encryption = "AES"
	}
	if hidden != nil {
		cfg.Hidden = *hidden
	}
	if maxClients != nil {
		cfg.MaxClients = *maxClients
	}

	return cfg
}

// ValidateCreateWLANAuth validates auth mode, encryption, and password for WLAN creation.
// Returns beaconType, encryptionValue, and error message (empty if valid).
func ValidateCreateWLANAuth(cfg CreateWLANConfig, password string) (string, string, string) {
	beaconType, validAuth := ValidateAuthMode(cfg.AuthMode)
	if !validAuth {
		return "", "", ErrInvalidAuthMode
	}

	encryptionValue, validEnc := ValidateEncryption(cfg.Encryption)
	if !validEnc {
		return "", "", ErrInvalidEncryption
	}

	if cfg.MaxClients < MinMaxClients || cfg.MaxClients > MaxMaxClients {
		return "", "", ErrInvalidMaxClients
	}

	// Validate password for non-Open authentication
	if cfg.AuthMode != "Open" {
		if password == "" {
			return "", "", ErrPasswordRequiredAuth
		}
		if len(password) < MinPasswordLength {
			return "", "", ErrPasswordTooShort
		}
		if len(password) > MaxPasswordLength {
			return "", "", ErrPasswordTooLong
		}
	}

	return beaconType, encryptionValue, ""
}

// UpdateWLANFieldResult holds the result of processing an update field
type UpdateWLANFieldResult struct {
	Params        [][]interface{}
	UpdatedFields map[string]interface{}
	ErrorMsg      string
}

// ProcessUpdateWLANFields processes optional fields for WLAN update.
// Returns parameter values, updated fields map, and error message (empty if valid).
func ProcessUpdateWLANFields(wlan string, req UpdateWLANRequest) UpdateWLANFieldResult {
	result := UpdateWLANFieldResult{
		Params:        [][]interface{}{},
		UpdatedFields: make(map[string]interface{}),
	}

	if req.SSID != nil {
		if errMsg := ValidateSSID(*req.SSID); errMsg != "" {
			result.ErrorMsg = errMsg
			return result
		}
		ssidPath := fmt.Sprintf(PathWLANSSIDFormat, wlan)
		result.Params = append(result.Params, []interface{}{ssidPath, *req.SSID, XSDString})
		result.UpdatedFields["ssid"] = *req.SSID
	}

	if req.Password != nil {
		if errMsg := ValidatePassword(*req.Password); errMsg != "" {
			result.ErrorMsg = errMsg
			return result
		}
		passwordPath := fmt.Sprintf(PathWLANPasswordFormat, wlan)
		result.Params = append(result.Params, []interface{}{passwordPath, *req.Password, XSDString})
		result.UpdatedFields["password"] = "********"
	}

	if req.Hidden != nil {
		ssidAdvertisementPath := fmt.Sprintf(PathWLANSSIDAdvertisementFormat, wlan)
		result.Params = append(result.Params, []interface{}{ssidAdvertisementPath, !*req.Hidden, XSDBoolean})
		result.UpdatedFields["hidden"] = *req.Hidden
	}

	if req.MaxClients != nil {
		if *req.MaxClients < MinMaxClients || *req.MaxClients > MaxMaxClients {
			result.ErrorMsg = ErrInvalidMaxClients
			return result
		}
		maxAssocDevicesPath := fmt.Sprintf(PathWLANMaxAssocDevicesFormat, wlan)
		result.Params = append(result.Params, []interface{}{maxAssocDevicesPath, *req.MaxClients, XSDUnsignedInt})
		result.UpdatedFields["max_clients"] = *req.MaxClients
	}

	if req.AuthMode != nil {
		beaconType, validAuth := ValidateAuthMode(*req.AuthMode)
		if !validAuth {
			result.ErrorMsg = ErrInvalidAuthMode
			return result
		}
		beaconTypePath := fmt.Sprintf(PathWLANBeaconTypeFormat, wlan)
		result.Params = append(result.Params, []interface{}{beaconTypePath, beaconType, XSDString})
		result.UpdatedFields["auth_mode"] = *req.AuthMode
		authModeParams := BuildAuthModeParams(wlan, *req.AuthMode)
		result.Params = append(result.Params, authModeParams...)
	}

	if req.Encryption != nil {
		encryptionValue, validEnc := ValidateEncryption(*req.Encryption)
		if !validEnc {
			result.ErrorMsg = ErrInvalidEncryption
			return result
		}
		wpaEncryptionPath := fmt.Sprintf(PathWLANWPAEncryptionModesFormat, wlan)
		ieee11iEncryptionPath := fmt.Sprintf(PathWLAN11iEncryptionModesFormat, wlan)
		result.Params = append(result.Params,
			[]interface{}{wpaEncryptionPath, encryptionValue, XSDString},
			[]interface{}{ieee11iEncryptionPath, encryptionValue, XSDString},
		)
		result.UpdatedFields["encryption"] = *req.Encryption
	}

	return result
}

// OptimizeWLANFieldResult holds the result of processing optimization fields
type OptimizeWLANFieldResult struct {
	Params          [][]interface{}
	UpdatedSettings map[string]interface{}
	ErrorMsg        string
}

// ProcessOptimizeWLANFields processes optional fields for WLAN optimization.
func ProcessOptimizeWLANFields(wlan string, req OptimizeWLANRequest, is5GHz bool) OptimizeWLANFieldResult {
	result := OptimizeWLANFieldResult{
		Params:          [][]interface{}{},
		UpdatedSettings: make(map[string]interface{}),
	}

	if req.Channel != nil {
		if err := ValidateWLANChannel(*req.Channel, is5GHz); err != nil {
			result.ErrorMsg = sanitizeErrorMessage(err)
			return result
		}
		result.Params = append(result.Params, buildChannelParams(wlan, *req.Channel)...)
		result.UpdatedSettings["channel"] = *req.Channel
	}

	if req.Mode != nil {
		tr069Mode, err := ValidateWLANMode(*req.Mode, is5GHz)
		if err != nil {
			result.ErrorMsg = sanitizeErrorMessage(err)
			return result
		}
		modePath := fmt.Sprintf(PathWLANOperatingStandardFormat, wlan)
		result.Params = append(result.Params, []interface{}{modePath, tr069Mode, XSDString})
		result.UpdatedSettings["mode"] = *req.Mode
	}

	if req.Bandwidth != nil {
		if err := ValidateWLANBandwidth(*req.Bandwidth, is5GHz); err != nil {
			result.ErrorMsg = sanitizeErrorMessage(err)
			return result
		}
		bandwidthPath := fmt.Sprintf(PathWLANChannelBandwidthFormat, wlan)
		result.Params = append(result.Params, []interface{}{bandwidthPath, *req.Bandwidth, XSDString})
		result.UpdatedSettings["bandwidth"] = *req.Bandwidth
	}

	if req.TransmitPower != nil {
		if !ValidTransmitPower[*req.TransmitPower] {
			result.ErrorMsg = ErrInvalidTransmitPower
			return result
		}
		powerPath := fmt.Sprintf(PathWLANTransmitPowerFormat, wlan)
		result.Params = append(result.Params, []interface{}{powerPath, *req.TransmitPower, XSDUnsignedInt})
		result.UpdatedSettings["transmit_power"] = *req.TransmitPower
	}

	return result
}

// buildChannelParams builds parameter values for channel configuration
func buildChannelParams(wlan, channel string) [][]interface{} {
	autoChannelPath := fmt.Sprintf(PathWLANAutoChannelEnableFormat, wlan)
	if channel == ChannelAuto {
		return [][]interface{}{{autoChannelPath, true, XSDBoolean}}
	}
	channelPath := fmt.Sprintf(PathWLANChannelFormat, wlan)
	channelNum, _ := strconv.Atoi(channel)
	return [][]interface{}{
		{autoChannelPath, false, XSDBoolean},
		{channelPath, channelNum, XSDUnsignedInt},
	}
}

// AvailableWLANSlots holds available and used WLAN slot information
type AvailableWLANSlots struct {
	Total24GHz     []int
	Total5GHz      []int
	Available24GHz []int
	Available5GHz  []int
	UsedWLAN       []UsedWLANInfo
}

// CalculateAvailableWLANSlots calculates available WLAN slots based on capability and current usage
func CalculateAvailableWLANSlots(capability *DeviceCapability, wlanConfigs []WLANConfig) AvailableWLANSlots {
	slots := AvailableWLANSlots{}

	// Build used WLAN IDs map
	usedWLANIDs := make(map[int]bool)
	for _, wlan := range wlanConfigs {
		wlanID, err := strconv.Atoi(wlan.WLAN)
		if err != nil {
			continue
		}
		usedWLANIDs[wlanID] = true
		slots.UsedWLAN = append(slots.UsedWLAN, UsedWLANInfo{
			WLANID: wlanID,
			SSID:   wlan.SSID,
			Band:   wlan.Band,
		})
	}

	// Calculate 2.4GHz slots
	for i := WLAN24GHzMin; i <= WLAN24GHzMax; i++ {
		slots.Total24GHz = append(slots.Total24GHz, i)
		if !usedWLANIDs[i] {
			slots.Available24GHz = append(slots.Available24GHz, i)
		}
	}

	// Calculate 5GHz slots if dual-band
	if capability.IsDualBand {
		for i := WLAN5GHzMin; i <= WLAN5GHzMax; i++ {
			slots.Total5GHz = append(slots.Total5GHz, i)
			if !usedWLANIDs[i] {
				slots.Available5GHz = append(slots.Available5GHz, i)
			}
		}
	}

	return slots
}
