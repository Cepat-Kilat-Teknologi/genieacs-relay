package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// refreshWLANConfig triggers refresh of WLAN configuration data from device
func refreshWLANConfig(ctx context.Context, deviceID string) error {
	// Build URL for refresh task endpoint
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))
	// Prepare refresh task payload
	payload := `{"name": "refreshObject", "objectName": "InternetGatewayDevice.LANDevice.1.WLANConfiguration"}`
	// Send POST request to trigger refresh
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	// Ensure response body is closed
	defer safeClose(resp.Body)
	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}
	return nil
}

// getWLANData extracts WLAN configuration information from device data
func getWLANData(ctx context.Context, deviceID string) ([]WLANConfig, error) {
	// Retrieve device data from cache or GenieACS
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// Safely extract InternetGatewayDevice section with type checking
	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("InternetGatewayDevice data not found or invalid format")
	}

	// Safely extract LANDevice section with type checking
	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice data not found or invalid format")
	}

	// Safely extract LANDevice.1 section with type checking
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("LANDevice.1 data not found")
	}

	// Extract WLANConfiguration section (optional - may not exist)
	wlanConfigsMap, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		// Return empty slice if no WLAN configurations found
		return []WLANConfig{}, nil
	}

	// Process each WLAN configuration
	var configs []WLANConfig
	for key, value := range wlanConfigsMap {
		// Type assert to map for WLAN configuration
		wlan, ok := value.(map[string]interface{})
		if !ok {
			continue // Skip invalid entries
		}

		// Check if WLAN is enabled
		enableMap, ok := wlan["Enable"].(map[string]interface{})
		if !ok {
			continue // Skip if Enable field missing
		}
		// Only process enabled WLAN configurations
		if enable, ok := enableMap["_value"].(bool); !ok || !enable {
			continue // Skip disabled WLANs
		}

		// Extract SSID value
		var ssid string
		if ssidMap, ok := wlan["SSID"].(map[string]interface{}); ok {
			if ssidVal, ok := ssidMap["_value"].(string); ok {
				ssid = ssidVal
			}
		}

		// Create WLANConfig struct and add to results
		configs = append(configs, WLANConfig{
			WLAN:       key,                 // WLAN interface identifier
			SSID:       ssid,                // Network name
			Password:   getPassword(wlan),   // Security password
			Band:       getBand(wlan, key),  // Frequency band
			Hidden:     getHidden(wlan),     // SSID broadcast disabled
			MaxClients: getMaxClients(wlan), // Maximum associated devices
			AuthMode:   getAuthMode(wlan),   // Authentication mode
			Encryption: getEncryption(wlan), // Encryption mode
		})
	}

	// Sort WLAN configurations by interface number (if numeric)
	sort.Slice(configs, func(i, j int) bool {
		numI, errI := strconv.Atoi(configs[i].WLAN)
		numJ, errJ := strconv.Atoi(configs[j].WLAN)

		if errI == nil && errJ == nil {
			return numI < numJ // sort numerically if both are numbers
		}
		return configs[i].WLAN < configs[j].WLAN // fallback to string comparison
	})

	return configs, nil
}

// getPassword extracts password from WLAN configuration
func getPassword(wlan map[string]interface{}) string {
	// Try to get password from X_CMS_KeyPassphrase field
	if passMap, ok := wlan["X_CMS_KeyPassphrase"].(map[string]interface{}); ok {
		if pass, ok := passMap["_value"].(string); ok {
			if pass != "" {
				return pass
			}
			// Field exists but empty (encrypted)
			return PasswordMasked
		}
	}
	// Try to get password from PreSharedKey structure
	if psk, ok := wlan["PreSharedKey"].(map[string]interface{}); ok {
		if psk1, ok := psk["1"].(map[string]interface{}); ok {
			// Try KeyPassphrase field first
			if keyPassMap, ok := psk1["KeyPassphrase"].(map[string]interface{}); ok {
				if keyPass, ok := keyPassMap["_value"].(string); ok {
					if keyPass != "" {
						return keyPass
					}
					// Field exists but empty (encrypted)
					return PasswordMasked
				}
			}
			// Fall back to PreSharedKey field
			if preSharedMap, ok := psk1["PreSharedKey"].(map[string]interface{}); ok {
				if preShared, ok := preSharedMap["_value"].(string); ok {
					if preShared != "" {
						return preShared
					}
					// Field exists but empty (encrypted)
					return PasswordMasked
				}
			}
		}
	}
	// No password field found at all
	return PasswordNA
}

// getBand determines the frequency band based on WLAN key and Standard field
func getBand(wlan map[string]interface{}, wlanKey string) string {
	// Determine band based on WLAN interface key (common convention)
	if wlanKey == "1" {
		return "2.4GHz" // Typically WLAN1 is 2.4GHz
	} else if wlanKey == "5" {
		return "5GHz" // Typically WLAN5 is 5GHz
	}
	// Fall back to Standard field if key-based detection fails
	if stdMap, ok := wlan["Standard"].(map[string]interface{}); ok {
		if std, ok := stdMap["_value"].(string); ok {
			std = strings.ToLower(std) // Normalize to lowercase
			// Check for 2.4GHz standards
			if strings.ContainsAny(std, "bg") {
				return "2.4GHz"
			}
			// Check for 5GHz standards
			if strings.ContainsAny(std, "ac") {
				return "5GHz"
			}
		}
	}
	// Return unknown if band cannot be determined
	return "Unknown"
}

// getHidden checks if SSID broadcast is disabled (hidden network)
func getHidden(wlan map[string]interface{}) bool {
	// SSIDAdvertisementEnabled = false means hidden = true
	if advMap, ok := wlan["SSIDAdvertisementEnabled"].(map[string]interface{}); ok {
		if adv, ok := advMap["_value"].(bool); ok {
			return !adv // Invert: advertisement disabled = hidden
		}
	}
	return false // Default to visible
}

// getMaxClients extracts maximum associated devices from WLAN configuration
func getMaxClients(wlan map[string]interface{}) int {
	if maxMap, ok := wlan["MaxAssociatedDevices"].(map[string]interface{}); ok {
		if maxVal, ok := maxMap["_value"].(float64); ok {
			return int(maxVal)
		}
		// Try int type
		if maxVal, ok := maxMap["_value"].(int); ok {
			return maxVal
		}
	}
	return 0 // Return 0 if not found (omitempty will hide it)
}

// getAuthMode extracts authentication mode from BeaconType field
func getAuthMode(wlan map[string]interface{}) string {
	if beaconMap, ok := wlan["BeaconType"].(map[string]interface{}); ok {
		if beacon, ok := beaconMap["_value"].(string); ok {
			// Map BeaconType to user-friendly auth mode
			switch strings.ToLower(beacon) {
			case "none", "basic":
				return "Open"
			case "wpa":
				return "WPA"
			case "11i", "wpa2":
				return "WPA2"
			case "wpaand11i", "wpawpa2":
				return "WPA/WPA2"
			default:
				return beacon // Return as-is if unknown
			}
		}
	}
	return "" // Return empty if not found
}

// getEncryption extracts encryption mode from WLAN configuration
func getEncryption(wlan map[string]interface{}) string {
	// Try WPAEncryptionModes first
	if encMap, ok := wlan["WPAEncryptionModes"].(map[string]interface{}); ok {
		if enc, ok := encMap["_value"].(string); ok {
			return normalizeEncryption(enc)
		}
	}
	// Try IEEE11iEncryptionModes as fallback
	if encMap, ok := wlan["IEEE11iEncryptionModes"].(map[string]interface{}); ok {
		if enc, ok := encMap["_value"].(string); ok {
			return normalizeEncryption(enc)
		}
	}
	return "" // Return empty if not found
}

// normalizeEncryption converts encryption value to user-friendly format
func normalizeEncryption(enc string) string {
	enc = strings.ToUpper(enc)
	switch enc {
	case "AESENCRYPTION", "AES":
		return "AES"
	case "TKIPENCRYPTION", "TKIP":
		return "TKIP"
	case "TKIPANDAESENCRYPTION", "TKIPAES", "TKIP+AES":
		return "TKIP+AES"
	default:
		return enc // Return as-is if unknown
	}
}

// isWLANValid checks if a specific WLAN interface exists and is enabled on a device
func isWLANValid(ctx context.Context, deviceID, wlanID string) (bool, error) {
	// Retrieve device data from cache or GenieACS API
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		// Return error with wrapping context if device data retrieval fails
		return false, fmt.Errorf("could not get device data for validation: %w", err)
	}

	// Safely extract InternetGatewayDevice section with type assertion
	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		// Return false if InternetGatewayDevice section is missing
		return false, fmt.Errorf("InternetGatewayDevice data not found")
	}

	// Safely extract LANDevice section with type assertion
	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		// Return false if LANDevice section is missing
		return false, fmt.Errorf("LANDevice data not found")
	}

	// Safely extract LANDevice.1 section with type assertion
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		// Return false if LANDevice.1 section is missing
		return false, fmt.Errorf("LANDevice.1 data not found")
	}

	// Extract WLANConfiguration section (optional - device might not have WLAN)
	wlanConfigsMap, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		// Return false if no WLAN configurations exist
		return false, nil
	}

	// Check if the specific WLAN ID exists in the configurations
	wlanConfigData, wlanExists := wlanConfigsMap[wlanID]
	if !wlanExists {
		// Return false if WLAN ID doesn't exist
		return false, nil
	}

	// Type assert to map for WLAN configuration details
	if wlan, ok := wlanConfigData.(map[string]interface{}); ok {
		// Extract Enable field to check if WLAN is enabled
		if enableMap, ok := wlan["Enable"].(map[string]interface{}); ok {
			// Check the actual boolean value of the Enable field
			if enable, ok := enableMap["_value"].(bool); ok && enable {
				// Return true only if WLAN exists AND is enabled
				return true, nil
			}
		}
	}
	// Return false if WLAN exists but is disabled or has invalid configuration
	return false, nil
}
