package main

import "time"

// Task types for worker pool operations
const (
	TaskTypeSetParams    = "setParameterValues"
	TaskTypeApplyChanges = "applyChanges"
	TaskTypeRefreshWLAN  = "refreshWLAN"
)

// GenieACS parameter paths
const (
	// Base paths
	PathInternetGatewayDevice = "InternetGatewayDevice"
	PathLANDevice             = "LANDevice"
	PathWLANConfiguration     = "WLANConfiguration"
	PathHosts                 = "Hosts"
	PathHost                  = "Host"

	// WLAN parameter paths
	PathWLANSSIDFormat       = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSID"
	PathWLANPasswordFormat   = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.PreSharedKey.1.PreSharedKey"
	PathWLANConfigRefresh    = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
	PathLANDeviceRefresh     = "InternetGatewayDevice.LANDevice.1"
	PathRefreshObjectPayload = `{"name": "refreshObject", "objectName": "%s"}`

	// Field names in GenieACS data
	FieldID             = "_id"
	FieldValue          = "_value"
	FieldEnable         = "Enable"
	FieldSSID           = "SSID"
	FieldStandard       = "Standard"
	FieldPreSharedKey   = "PreSharedKey"
	FieldKeyPassphrase  = "KeyPassphrase"
	FieldXCMSPassphrase = "X_CMS_KeyPassphrase"
	FieldMACAddress     = "MACAddress"
	FieldHostName       = "HostName"
	FieldIPAddress      = "IPAddress"
	FieldSummaryIP      = "summary.ip"
	FieldWANPPPConn1    = "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value"
	FieldWANPPPConn2    = "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.2.ExternalIPAddress._value"
)

// HTTP and timeout configurations
const (
	DefaultServerAddr  = ":8080"
	DefaultGenieACSURL = "http://localhost:7557"
	// DefaultNBIAuthKey is intentionally empty - MUST be set via NBI_AUTH_KEY environment variable
	DefaultNBIAuthKey       = ""
	DefaultHTTPTimeout      = 15 * time.Second
	DefaultCacheTimeout     = 30 * time.Second
	DefaultShutdownTimeout  = 30 * time.Second
	DefaultRequestTimeout   = 60 * time.Second
	DefaultMaxIdleConns     = 100
	DefaultIdleConnsPerHost = 20
	DefaultIdleConnTimeout  = 30 * time.Second
	DefaultWorkerCount      = 10
	DefaultQueueSize        = 100
)

// Authentication middleware configuration
const (
	// DefaultMiddlewareAuth controls whether API key authentication is enabled (default: false)
	DefaultMiddlewareAuth = false
	// DefaultAuthKey is intentionally empty - MUST be set via AUTH_KEY environment variable when MIDDLEWARE_AUTH=true
	DefaultAuthKey    = ""
	HeaderXAPIKey     = "X-API-Key"
	EnvMiddlewareAuth = "MIDDLEWARE_AUTH"
	EnvAuthKey        = "AUTH_KEY"
)

// Retry configurations for force handler
const (
	DefaultMaxRetries = 12
	DefaultRetryDelay = 5 * time.Second
	QueryMaxRetries   = "max_retries"
	QueryRetryDelayMs = "retry_delay_ms"
	QueryRefresh      = "refresh"
	QueryDeviceID     = "device_id"
)

// Stale device validation configuration
const (
	// DefaultStaleThreshold is the default time after which a device is considered stale (30 minutes)
	// This is approximately 6x the typical TR-069 periodic inform interval (5 minutes)
	DefaultStaleThreshold = 30 * time.Minute
	// EnvStaleThreshold is the environment variable name for stale threshold in minutes
	EnvStaleThreshold = "STALE_THRESHOLD_MINUTES"
	// FieldLastInform is the GenieACS field for last inform timestamp
	FieldLastInform = "_lastInform"
)

// Frequency bands
const (
	Band2_4GHz  = "2.4GHz"
	Band5GHz    = "5GHz"
	BandUnknown = "Unknown"
)

// Password placeholder
const (
	PasswordMasked = "********"
	PasswordNA     = "N/A"
)

// Device vendor identifiers
const (
	VendorZTE = "ZTE"
	VendorZT  = "ZT"
)

// HTTP response messages
const (
	StatusOK            = "OK"
	StatusAccepted      = "Accepted"
	StatusNotFound      = "Not Found"
	StatusBadRequest    = "Bad Request"
	StatusInternalError = "Internal Server Error"
	StatusTimeout       = "Timeout"
)

// Input validation constraints
const (
	// MinPasswordLength is the minimum required password length for WLAN security
	MinPasswordLength = 8
	// MaxPasswordLength is the maximum allowed password length
	MaxPasswordLength = 63
	// MinSSIDLength is the minimum required SSID length
	MinSSIDLength = 1
	// MaxSSIDLength is the maximum allowed SSID length (per IEEE 802.11 standard)
	MaxSSIDLength = 32
	// MaxRequestBodySize is the maximum allowed request body size (1KB - sufficient for SSID/password updates)
	MaxRequestBodySize = 1024
)

// Error messages
const (
	ErrInvalidJSON          = "Invalid JSON format"
	ErrSSIDRequired         = "SSID value required"
	ErrSSIDTooLong          = "SSID must be at most 32 characters"
	ErrSSIDInvalidSpaces    = "The beginning and end cannot be Spaces"
	ErrPasswordRequired     = "Password value required"
	ErrPasswordTooShort     = "Password must be at least 8 characters"
	ErrPasswordTooLong      = "Password must be at most 63 characters"
	ErrWLANValidationFailed = "Could not verify WLAN status."
	ErrOperationTimeout     = "Operation timed out while retrieving WLAN data"
	ErrMissingAPIKey        = "Missing X-API-Key header"
	ErrInvalidAPIKey        = "Invalid API key"
	ErrDeviceStale          = "device with IP %s is stale (last seen: %s ago). The IP may have been reassigned to another device"
	ErrInvalidIPAddress     = "invalid IP address format: %s"
	ErrInvalidWLANID        = "WLAN ID must be a number between 1 and 99"
	ErrRequestBodyTooLarge  = "Request body too large"
	ErrSSIDInvalidChars     = "SSID contains invalid characters"
	ErrInvalidAuthMode      = "Invalid authentication mode. Valid values: Open, WPA, WPA2, WPA/WPA2"
	ErrInvalidEncryption    = "Invalid encryption mode. Valid values: AES, TKIP, TKIP+AES"
	ErrInvalidMaxClients    = "Max clients must be between 1 and 64"
	ErrPasswordRequiredAuth = "Password is required for WPA, WPA2, or WPA/WPA2 authentication"
)

// HTTP status messages for authentication
const (
	StatusUnauthorized = "Unauthorized"
)

// Success messages
const (
	MsgCacheCleared            = "Cache cleared"
	MsgRefreshSubmitted        = "Refresh task submitted. Please query the GET endpoint again after a few moments."
	MsgSSIDUpdateSubmitted     = "SSID update submitted successfully"
	MsgPasswordUpdateSubmitted = "Password update submitted successfully"
)

// XSD types for GenieACS
const (
	XSDString      = "xsd:string"
	XSDBoolean     = "xsd:boolean"
	XSDUnsignedInt = "xsd:unsignedInt"
)

// WLAN configuration parameter paths (TR-069)
const (
	PathWLANEnableFormat             = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.Enable"
	PathWLANSSIDAdvertisementFormat  = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.SSIDAdvertisementEnabled"
	PathWLANMaxAssocDevicesFormat    = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.MaxAssociatedDevices"
	PathWLANBeaconTypeFormat         = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.BeaconType"
	PathWLANWPAEncryptionModesFormat = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.WPAEncryptionModes"
	PathWLAN11iEncryptionModesFormat = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.IEEE11iEncryptionModes"
	PathWLANWPAAuthModeFormat        = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.WPAAuthenticationMode"
	PathWLAN11iAuthModeFormat        = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.IEEE11iAuthenticationMode"
)

// WLAN Authentication modes (BeaconType values in TR-069)
const (
	AuthModeOpen    = "Open"      // No security
	AuthModeWPA     = "WPA"       // WPA only
	AuthModeWPA2    = "11i"       // WPA2 (IEEE 802.11i)
	AuthModeWPAWPA2 = "WPAand11i" // WPA/WPA2 mixed mode
)

// WLAN Encryption modes
const (
	EncryptionAES     = "AESEncryption"        // AES (CCMP) - recommended
	EncryptionTKIP    = "TKIPEncryption"       // TKIP - legacy
	EncryptionTKIPAES = "TKIPandAESEncryption" // TKIP+AES mixed
)

// WLAN Authentication mode for PSK
const (
	WPAAuthModePSK = "PSKAuthentication"
)

// Default WLAN configuration values
const (
	DefaultMaxClients = 32    // Default maximum associated devices
	MinMaxClients     = 1     // Minimum allowed max clients
	MaxMaxClients     = 64    // Maximum allowed max clients
	DefaultHiddenSSID = false // SSID is visible by default
	DefaultAuthMode   = AuthModeWPA2
	DefaultEncryption = EncryptionAES
)

// WLAN Radio optimization parameter paths (TR-069)
const (
	PathWLANChannelFormat           = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.Channel"
	PathWLANAutoChannelEnableFormat = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.AutoChannelEnable"
	PathWLANOperatingStandardFormat = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.Standard"
	PathWLANChannelBandwidthFormat  = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.OperatingChannelBandwidth"
	PathWLANTransmitPowerFormat     = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.%s.TransmitPower"
)

// Channel constants
const (
	ChannelAuto = "Auto"
)

// Valid channels for 2.4GHz band (1-13)
var ValidChannels24GHz = map[string]bool{
	"Auto": true,
	"1":    true, "2": true, "3": true, "4": true, "5": true,
	"6": true, "7": true, "8": true, "9": true, "10": true,
	"11": true, "12": true, "13": true,
}

// Valid channels for 5GHz band
var ValidChannels5GHz = map[string]bool{
	"Auto": true,
	"36":   true, "40": true, "44": true, "48": true,
	"52": true, "56": true, "60": true, "64": true,
	"149": true, "153": true, "157": true, "161": true,
}

// Valid WiFi modes for 2.4GHz band
var ValidModes24GHz = map[string]string{
	"b":     "b",
	"g":     "g",
	"n":     "n",
	"b/g":   "b,g",
	"g/n":   "g,n",
	"b/g/n": "b,g,n",
}

// Valid WiFi modes for 5GHz band
var ValidModes5GHz = map[string]string{
	"a":      "a",
	"n":      "n",
	"ac":     "ac",
	"a/n":    "a,n",
	"a/n/ac": "a,n,ac",
}

// Valid bandwidth options for 2.4GHz band
var ValidBandwidth24GHz = map[string]bool{
	"20MHz": true,
	"40MHz": true,
	"Auto":  true,
}

// Valid bandwidth options for 5GHz band
var ValidBandwidth5GHz = map[string]bool{
	"20MHz": true,
	"40MHz": true,
	"80MHz": true,
	"Auto":  true,
}

// Valid transmit power values (percentage)
var ValidTransmitPower = map[int]bool{
	0: true, 20: true, 40: true, 60: true, 80: true, 100: true,
}

// Error messages for WLAN optimization
const (
	ErrInvalidChannel24GHz   = "invalid channel '%s' for 2.4GHz band. Valid channels: Auto, 1-13"
	ErrInvalidChannel5GHz    = "invalid channel '%s' for 5GHz band. Valid channels: Auto, 36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161"
	ErrInvalidMode24GHz      = "invalid mode '%s' for 2.4GHz band. Valid modes: b, g, n, b/g, g/n, b/g/n"
	ErrInvalidMode5GHz       = "invalid mode '%s' for 5GHz band. Valid modes: a, n, ac, a/n, a/n/ac"
	ErrInvalidBandwidth24GHz = "invalid bandwidth '%s' for 2.4GHz band. Valid values: 20MHz, 40MHz, Auto"
	ErrInvalidBandwidth5GHz  = "invalid bandwidth '%s' for 5GHz band. Valid values: 20MHz, 40MHz, 80MHz, Auto"
	ErrInvalidTransmitPower  = "invalid transmit power '%d'. Valid values: 0, 20, 40, 60, 80, 100 (percentage)"
	ErrNoOptimizeFields      = "at least one optimization field must be provided (channel, mode, bandwidth, or transmit_power)"
)

// Success message for WLAN optimization
const (
	MsgWLANOptimizeSubmitted = "WLAN optimization submitted successfully"
)
