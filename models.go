package main

import "time"

// --- Data Models / Struct Definitions ---

// Device represents a network device with its unique identifier
type Device struct {
	ID         string     `json:"_id"`         // Device unique identifier from GenieACS
	LastInform *time.Time `json:"_lastInform"` // Timestamp of last inform from device
}

// WLANConfig represents wireless LAN configuration for a device
type WLANConfig struct {
	WLAN       string `json:"wlan"`                  // WLAN interface identifier (e.g., "1", "5")
	SSID       string `json:"ssid"`                  // Network name broadcast by the WLAN
	Password   string `json:"password"`              // Security key/password for the WLAN
	Band       string `json:"band"`                  // Frequency band (2.4GHz, 5GHz, etc.)
	Hidden     bool   `json:"hidden"`                // True if SSID is not broadcast
	MaxClients int    `json:"max_clients,omitempty"` // Maximum number of associated devices
	AuthMode   string `json:"auth_mode,omitempty"`   // Authentication mode (Open, WPA, WPA2, WPA/WPA2)
	Encryption string `json:"encryption,omitempty"`  // Encryption mode (AES, TKIP, TKIP+AES)
}

// DHCPClient represents a client device that obtained IP address via DHCP
type DHCPClient struct {
	MAC      string `json:"mac"`      // MAC address of the client device
	Hostname string `json:"hostname"` // Hostname reported by the client
	IP       string `json:"ip"`       // IP address assigned to the client
}

// --- API Request Models ---

// CreateWLANRequest represents JSON payload for creating a new WLAN
type CreateWLANRequest struct {
	SSID       string `json:"ssid"`                  // SSID for the new WLAN
	Password   string `json:"password,omitempty"`    // Password for the new WLAN (required for WPA/WPA2)
	Hidden     *bool  `json:"hidden,omitempty"`      // Hide SSID (SSIDAdvertisementEnabled = false)
	MaxClients *int   `json:"max_clients,omitempty"` // Maximum number of associated devices (1-64)
	AuthMode   string `json:"auth_mode,omitempty"`   // Authentication mode: Open, WPA, WPA2, WPA/WPA2
	Encryption string `json:"encryption,omitempty"`  // Encryption mode: AES, TKIP, TKIP+AES
}

// UpdateWLANRequest contains the request body for updating a WLAN
type UpdateWLANRequest struct {
	SSID       *string `json:"ssid,omitempty"`        // New SSID (optional)
	Password   *string `json:"password,omitempty"`    // New password (optional)
	Hidden     *bool   `json:"hidden,omitempty"`      // Hide SSID (optional)
	MaxClients *int    `json:"max_clients,omitempty"` // Maximum clients (optional)
	AuthMode   *string `json:"auth_mode,omitempty"`   // Authentication mode (optional)
	Encryption *string `json:"encryption,omitempty"`  // Encryption mode (optional)
}

// OptimizeWLANRequest contains the request body for optimizing WLAN radio settings
type OptimizeWLANRequest struct {
	Channel       *string `json:"channel,omitempty"`        // Channel: Auto, or channel number
	Mode          *string `json:"mode,omitempty"`           // WiFi standard mode (b, g, n, b/g, g/n, b/g/n for 2.4GHz; a, n, ac, a/n, a/n/ac for 5GHz)
	Bandwidth     *string `json:"bandwidth,omitempty"`      // Bandwidth: 20MHz, 40MHz, 80MHz (5GHz only), Auto
	TransmitPower *int    `json:"transmit_power,omitempty"` // Transmit power percentage: 0, 20, 40, 60, 80, 100
}

// --- API Response Models ---

// Response represents standardized API response format for all endpoints
type Response struct {
	Code   int         `json:"code"`            // HTTP status code
	Status string      `json:"status"`          // Status message (e.g., "OK", "Error")
	Data   interface{} `json:"data,omitempty"`  // Response payload data when successful
	Error  string      `json:"error,omitempty"` // Error description when operation fails
}

// UsedWLANInfo contains information about a WLAN slot that is in use
type UsedWLANInfo struct {
	WLANID int    `json:"wlan_id"`
	SSID   string `json:"ssid"`
	Band   string `json:"band"`
}

// AvailableWLANResponse contains the response for available WLAN slots endpoint
type AvailableWLANResponse struct {
	DeviceID   string `json:"device_id"`
	Model      string `json:"model"`
	BandType   string `json:"band_type"`
	TotalSlots struct {
		Band24GHz []int `json:"2_4ghz"`
		Band5GHz  []int `json:"5ghz"`
	} `json:"total_slots"`
	UsedWLAN      []UsedWLANInfo `json:"used_wlan"`
	AvailableWLAN struct {
		Band24GHz []int `json:"2_4ghz"`
		Band5GHz  []int `json:"5ghz"`
	} `json:"available_wlan"`
	ConfigOptions struct {
		AuthModes   []string `json:"auth_modes"`
		Encryptions []string `json:"encryptions"`
		MaxClients  struct {
			Min     int `json:"min"`
			Max     int `json:"max"`
			Default int `json:"default"`
		} `json:"max_clients"`
	} `json:"config_options"`
}

// --- Swagger Documentation Response Types ---
// These types are used by swaggo/swag for API documentation generation.
// They appear in Swagger annotations (@Success, @Failure) in handler files.

// Compile-time check to ensure Swagger types are valid (prevents "unused" warnings)
var (
	_ = HealthResponse{}
	_ = MessageResponse{}
	_ = SSIDForceResponse{}
	_ = DeviceCapabilityResponse{}
	_ = WLANCreateResponse{}
	_ = WLANUpdateResponse{}
	_ = WLANDeleteResponse{}
	_ = WLANOptimizeResponse{}
)

// HealthResponse represents health check response
// @Description Health check response data
type HealthResponse struct {
	Status string `json:"status" example:"healthy"`
}

// MessageResponse represents a simple message response
// @Description Simple message response
type MessageResponse struct {
	Message string `json:"message" example:"Operation completed successfully"`
}

// SSIDForceResponse represents the response from force SSID endpoint
// @Description Force SSID response with retry information
type SSIDForceResponse struct {
	WLANData []WLANConfig `json:"wlan_data"`
	Attempts int          `json:"attempts" example:"1"`
}

// DeviceCapabilityResponse represents device capability information
// @Description Device capability response
type DeviceCapabilityResponse struct {
	DeviceID      string `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	Model         string `json:"model" example:"F670L"`
	BandType      string `json:"band_type" example:"dualband"`
	IsDualBand    bool   `json:"is_dual_band" example:"true"`
	SupportedWLAN struct {
		Band24GHz []int `json:"2_4ghz" example:"1,2,3,4"`
		Band5GHz  []int `json:"5ghz" example:"5,6,7,8"`
	} `json:"supported_wlan"`
	Description string `json:"description" example:"Device supports both 2.4GHz and 5GHz bands"`
}

// WLANCreateResponse represents the response from WLAN create endpoint
// @Description WLAN creation response
type WLANCreateResponse struct {
	Message    string `json:"message" example:"WLAN creation submitted successfully"`
	DeviceID   string `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	WLAN       string `json:"wlan" example:"2"`
	SSID       string `json:"ssid" example:"GuestNetwork"`
	Band       string `json:"band" example:"2.4GHz"`
	IP         string `json:"ip" example:"192.168.1.1"`
	Hidden     bool   `json:"hidden" example:"false"`
	MaxClients int    `json:"max_clients" example:"10"`
	AuthMode   string `json:"auth_mode" example:"WPA2"`
	Encryption string `json:"encryption" example:"AES"`
}

// WLANUpdateResponse represents the response from WLAN update endpoint
// @Description WLAN update response
type WLANUpdateResponse struct {
	Message       string                 `json:"message" example:"WLAN update submitted successfully"`
	DeviceID      string                 `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	WLAN          string                 `json:"wlan" example:"2"`
	Band          string                 `json:"band" example:"2.4GHz"`
	IP            string                 `json:"ip" example:"192.168.1.1"`
	UpdatedFields map[string]interface{} `json:"updated_fields"`
}

// WLANDeleteResponse represents the response from WLAN delete endpoint
// @Description WLAN deletion response
type WLANDeleteResponse struct {
	Message  string `json:"message" example:"WLAN disabled successfully"`
	DeviceID string `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	WLAN     string `json:"wlan" example:"2"`
	Band     string `json:"band" example:"2.4GHz"`
	IP       string `json:"ip" example:"192.168.1.1"`
}

// WLANOptimizeResponse represents the response from WLAN optimize endpoint
// @Description WLAN optimization response
type WLANOptimizeResponse struct {
	Message         string                 `json:"message" example:"WLAN optimization submitted successfully"`
	DeviceID        string                 `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	WLAN            string                 `json:"wlan" example:"1"`
	Band            string                 `json:"band" example:"2.4GHz"`
	IP              string                 `json:"ip" example:"192.168.1.1"`
	UpdatedSettings map[string]interface{} `json:"updated_settings"`
}
