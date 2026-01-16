package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// DeviceCapability represents the wireless capability of a device
type DeviceCapability struct {
	Model         string   `json:"model"`          // Device model name
	BandType      BandType `json:"band_type"`      // singleband, dualband, or unknown
	IsDualBand    bool     `json:"is_dual_band"`   // Convenience field for dual-band check
	AvailableWLAN []int    `json:"available_wlan"` // List of available WLAN IDs
	Max24GHz      int      `json:"max_24ghz"`      // Max WLAN ID for 2.4GHz (always 4)
	Max5GHz       int      `json:"max_5ghz"`       // Max WLAN ID for 5GHz (0 for single-band, 8 for dual-band)
}

// getDeviceBandType determines the band type of a device based on its model
// It uses the model mapping to determine if the device is single-band or dual-band
func getDeviceBandType(model string) BandType {
	// Normalize model name for lookup
	normalizedModel := normalizeModelName(model)

	// Check dual-band first (highest capability)
	if isDualBandModel(normalizedModel) {
		return BandTypeDualBand
	}

	// Check single-band
	if isSingleBandModel(normalizedModel) {
		return BandTypeSingleBand
	}

	// Unknown model - default to checking WLANConfiguration
	return BandTypeUnknown
}

// normalizeModelName normalizes a model name for consistent lookup
// Removes spaces, hyphens, and converts to uppercase
func normalizeModelName(model string) string {
	// Remove common separators and normalize
	normalized := strings.ToUpper(model)
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "_", "")
	return normalized
}

// isDualBandModel checks if a model is known to be dual-band
func isDualBandModel(model string) bool {
	// Direct lookup
	if dualBandModels[model] {
		return true
	}

	// Try normalized version
	normalized := normalizeModelName(model)
	if dualBandModels[normalized] {
		return true
	}

	// Try partial match for models with version suffixes
	// Only match when input model starts with a known model (more specific input)
	// Don't match when known model starts with input (would incorrectly match F609 with F609V3)
	for knownModel := range dualBandModels {
		normalizedKnown := normalizeModelName(knownModel)
		if strings.HasPrefix(normalized, normalizedKnown) && len(normalized) > len(normalizedKnown) {
			return true
		}
	}

	return false
}

// isSingleBandModel checks if a model is known to be single-band
func isSingleBandModel(model string) bool {
	// Direct lookup
	if singleBandModels[model] {
		return true
	}

	// Try normalized version
	normalized := normalizeModelName(model)
	if singleBandModels[normalized] {
		return true
	}

	// Try partial match for models with version suffixes
	// Only match when input model starts with a known model (more specific input)
	for knownModel := range singleBandModels {
		normalizedKnown := normalizeModelName(knownModel)
		if strings.HasPrefix(normalized, normalizedKnown) && len(normalized) > len(normalizedKnown) {
			return true
		}
	}

	return false
}

// extractModelFromDeviceID extracts the model name from GenieACS device ID
// GenieACS device IDs typically follow format: OUI-ProductClass-SerialNumber
// Example: "202BC1-HG8245H5-48575443xxxxxxxx" -> "HG8245H5"
func extractModelFromDeviceID(deviceID string) string {
	parts := strings.Split(deviceID, "-")
	if len(parts) >= 2 {
		// The second part is usually the ProductClass/Model
		return parts[1]
	}
	return deviceID
}

// extractModelFromDeviceData extracts the model from device data
// It tries multiple fields that might contain the model information
func extractModelFromDeviceData(deviceData map[string]interface{}) string {
	// Try to get from _deviceId._ProductClass
	if deviceID, ok := deviceData["_deviceId"].(map[string]interface{}); ok {
		if productClass, ok := deviceID["_ProductClass"].(string); ok && productClass != "" {
			return productClass
		}
	}

	// Try to get from _id field (device ID format: OUI-ProductClass-SerialNumber)
	if id, ok := deviceData["_id"].(string); ok {
		model := extractModelFromDeviceID(id)
		if model != "" {
			return model
		}
	}

	// Try InternetGatewayDevice.DeviceInfo.ProductClass
	if igd, ok := deviceData["InternetGatewayDevice"].(map[string]interface{}); ok {
		if deviceInfo, ok := igd["DeviceInfo"].(map[string]interface{}); ok {
			if productClass, ok := deviceInfo["ProductClass"].(map[string]interface{}); ok {
				if val, ok := productClass["_value"].(string); ok && val != "" {
					return val
				}
			}
			// Also try ModelName
			if modelName, ok := deviceInfo["ModelName"].(map[string]interface{}); ok {
				if val, ok := modelName["_value"].(string); ok && val != "" {
					return val
				}
			}
		}
	}

	return ""
}

// detectBandTypeFromWLANConfig detects band type by checking if WLAN 5+ exists in device config
// This is a fallback method when the model is unknown
func detectBandTypeFromWLANConfig(deviceData map[string]interface{}) BandType {
	// Navigate to WLANConfiguration
	igd, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		return BandTypeUnknown
	}

	lanDeviceMap, ok := igd["LANDevice"].(map[string]interface{})
	if !ok {
		return BandTypeUnknown
	}

	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		return BandTypeUnknown
	}

	wlanConfigs, ok := lanDevice["WLANConfiguration"].(map[string]interface{})
	if !ok {
		return BandTypeSingleBand // No WLAN config means we can't determine
	}

	// Check if any WLAN key >= 5 exists (indicating 5GHz capability)
	for key := range wlanConfigs {
		// Use regex to extract numeric part
		re := regexp.MustCompile(`\d+`)
		matches := re.FindString(key)
		if matches != "" {
			var num int
			if _, err := fmt.Sscanf(matches, "%d", &num); err == nil {
				if num >= 5 {
					return BandTypeDualBand
				}
			}
		}
	}

	return BandTypeSingleBand
}

// getDeviceCapability retrieves the full capability information for a device
func getDeviceCapability(ctx context.Context, deviceID string) (*DeviceCapability, error) {
	// Get device data
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get device data: %w", err)
	}

	// Extract model from device data
	model := extractModelFromDeviceData(deviceData)

	// Determine band type
	bandType := getDeviceBandType(model)

	// If model is unknown, try to detect from WLAN configuration
	if bandType == BandTypeUnknown {
		bandType = detectBandTypeFromWLANConfig(deviceData)
	}

	// Build capability response
	capability := &DeviceCapability{
		Model:    model,
		BandType: bandType,
	}

	// Set available WLAN IDs based on band type
	switch bandType {
	case BandTypeDualBand:
		capability.IsDualBand = true
		capability.AvailableWLAN = []int{1, 2, 3, 4, 5, 6, 7, 8}
		capability.Max24GHz = WLAN24GHzMax
		capability.Max5GHz = WLAN5GHzMax
	default: // SingleBand or Unknown defaults to single-band for safety
		capability.IsDualBand = false
		capability.AvailableWLAN = []int{1, 2, 3, 4}
		capability.Max24GHz = WLAN24GHzMax
		capability.Max5GHz = 0
	}

	return capability, nil
}

// validateWLANIDForDevice validates if a WLAN ID is valid for the device's capability
// Returns nil if valid, error if invalid
func validateWLANIDForDevice(ctx context.Context, deviceID string, wlanID int) error {
	// Get device capability
	capability, err := getDeviceCapability(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get device capability: %w", err)
	}

	// Check if WLAN ID is in valid range
	if wlanID < WLAN24GHzMin || wlanID > WLAN5GHzMax {
		return fmt.Errorf("WLAN ID must be between %d and %d", WLAN24GHzMin, WLAN5GHzMax)
	}

	// Check if device supports this WLAN ID
	if wlanID >= WLAN5GHzMin && !capability.IsDualBand {
		return fmt.Errorf("device %s is single-band and does not support WLAN ID %d (5GHz range). Available WLAN IDs: 1-4",
			capability.Model, wlanID)
	}

	return nil
}

// getWLANBandByID returns the band type for a given WLAN ID
func getWLANBandByID(wlanID int) string {
	if wlanID >= WLAN24GHzMin && wlanID <= WLAN24GHzMax {
		return Band2_4GHz
	}
	if wlanID >= WLAN5GHzMin && wlanID <= WLAN5GHzMax {
		return Band5GHz
	}
	return BandUnknown
}
