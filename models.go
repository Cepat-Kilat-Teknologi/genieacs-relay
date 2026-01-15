package main

// DeviceDataNavigator provides safe navigation through nested GenieACS device data
// This reduces code duplication when extracting nested data structures
type DeviceDataNavigator struct {
	data map[string]interface{}
}

// NewDeviceDataNavigator creates a new navigator for the given device data
func NewDeviceDataNavigator(data map[string]interface{}) *DeviceDataNavigator {
	return &DeviceDataNavigator{data: data}
}

// GetInternetGatewayDevice safely extracts InternetGatewayDevice section
func (n *DeviceDataNavigator) GetInternetGatewayDevice() (map[string]interface{}, bool) {
	igw, ok := n.data[PathInternetGatewayDevice].(map[string]interface{})
	return igw, ok
}

// GetLANDevice safely extracts LANDevice.1 section from InternetGatewayDevice
func (n *DeviceDataNavigator) GetLANDevice(igw map[string]interface{}) (map[string]interface{}, bool) {
	lanDeviceMap, ok := igw[PathLANDevice].(map[string]interface{})
	if !ok {
		return nil, false
	}
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	return lanDevice, ok
}

// GetWLANConfiguration safely extracts WLANConfiguration section
func (n *DeviceDataNavigator) GetWLANConfiguration(lanDevice map[string]interface{}) (map[string]interface{}, bool) {
	wlanConfigs, ok := lanDevice[PathWLANConfiguration].(map[string]interface{})
	return wlanConfigs, ok
}

// GetHosts safely extracts Hosts.Host section
func (n *DeviceDataNavigator) GetHosts(lanDevice map[string]interface{}) (map[string]interface{}, bool) {
	hostsMap, ok := lanDevice[PathHosts].(map[string]interface{})
	if !ok {
		return nil, false
	}
	hosts, ok := hostsMap[PathHost].(map[string]interface{})
	return hosts, ok
}

// ExtractStringValue extracts a string value from a nested map structure
// Used for extracting values like _value from GenieACS data
func ExtractStringValue(data map[string]interface{}, key string) string {
	if valueMap, ok := data[key].(map[string]interface{}); ok {
		if value, ok := valueMap[FieldValue].(string); ok {
			return value
		}
	}
	return ""
}

// ExtractBoolValue extracts a boolean value from a nested map structure
func ExtractBoolValue(data map[string]interface{}, key string) (bool, bool) {
	if valueMap, ok := data[key].(map[string]interface{}); ok {
		if value, ok := valueMap[FieldValue].(bool); ok {
			return value, true
		}
	}
	return false, false
}

// IsZTEDevice checks if the device ID belongs to a ZTE device
func IsZTEDevice(deviceID string) bool {
	return contains(deviceID, VendorZTE) || contains(deviceID, VendorZT)
}

// contains is a helper to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

// containsHelper is a simple contains implementation
func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
