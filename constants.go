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

// Retry configurations for force handler
const (
	DefaultMaxRetries = 12
	DefaultRetryDelay = 5 * time.Second
	QueryMaxRetries   = "max_retries"
	QueryRetryDelayMs = "retry_delay_ms"
	QueryRefresh      = "refresh"
	QueryDeviceID     = "device_id"
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

// Error messages
const (
	ErrInvalidJSON          = "Invalid JSON format"
	ErrSSIDRequired         = "SSID value required"
	ErrPasswordRequired     = "Password value required"
	ErrWLANValidationFailed = "Could not verify WLAN status."
	ErrOperationTimeout     = "Operation timed out while retrieving WLAN data"
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
	XSDString = "xsd:string"
)
