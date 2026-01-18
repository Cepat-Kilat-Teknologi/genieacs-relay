package main

import (
	"testing"
)

// TestGetHidden tests the getHidden function
func TestGetHidden(t *testing.T) {
	tests := []struct {
		name     string
		wlan     map[string]interface{}
		expected bool
	}{
		{
			name: "SSIDAdvertisementEnabled true (visible)",
			wlan: map[string]interface{}{
				"SSIDAdvertisementEnabled": map[string]interface{}{
					"_value": true,
				},
			},
			expected: false,
		},
		{
			name: "SSIDAdvertisementEnabled false (hidden)",
			wlan: map[string]interface{}{
				"SSIDAdvertisementEnabled": map[string]interface{}{
					"_value": false,
				},
			},
			expected: true,
		},
		{
			name:     "SSIDAdvertisementEnabled missing",
			wlan:     map[string]interface{}{},
			expected: false,
		},
		{
			name: "SSIDAdvertisementEnabled wrong type",
			wlan: map[string]interface{}{
				"SSIDAdvertisementEnabled": "invalid",
			},
			expected: false,
		},
		{
			name: "SSIDAdvertisementEnabled value wrong type",
			wlan: map[string]interface{}{
				"SSIDAdvertisementEnabled": map[string]interface{}{
					"_value": "true",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getHidden(tt.wlan)
			if result != tt.expected {
				t.Errorf("getHidden() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestGetMaxClients tests the getMaxClients function
func TestGetMaxClients(t *testing.T) {
	tests := []struct {
		name     string
		wlan     map[string]interface{}
		expected int
	}{
		{
			name: "MaxAssociatedDevices as float64",
			wlan: map[string]interface{}{
				"MaxAssociatedDevices": map[string]interface{}{
					"_value": float64(32),
				},
			},
			expected: 32,
		},
		{
			name: "MaxAssociatedDevices as int",
			wlan: map[string]interface{}{
				"MaxAssociatedDevices": map[string]interface{}{
					"_value": 16,
				},
			},
			expected: 16,
		},
		{
			name:     "MaxAssociatedDevices missing",
			wlan:     map[string]interface{}{},
			expected: 0,
		},
		{
			name: "MaxAssociatedDevices wrong type",
			wlan: map[string]interface{}{
				"MaxAssociatedDevices": "invalid",
			},
			expected: 0,
		},
		{
			name: "MaxAssociatedDevices value wrong type",
			wlan: map[string]interface{}{
				"MaxAssociatedDevices": map[string]interface{}{
					"_value": "32",
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMaxClients(tt.wlan)
			if result != tt.expected {
				t.Errorf("getMaxClients() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestGetAuthMode tests the getAuthMode function
func TestGetAuthMode(t *testing.T) {
	tests := []struct {
		name     string
		wlan     map[string]interface{}
		expected string
	}{
		{
			name: "BeaconType none",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "None",
				},
			},
			expected: "Open",
		},
		{
			name: "BeaconType basic",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "Basic",
				},
			},
			expected: "Open",
		},
		{
			name: "BeaconType WPA",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "WPA",
				},
			},
			expected: "WPA",
		},
		{
			name: "BeaconType 11i (WPA2)",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "11i",
				},
			},
			expected: "WPA2",
		},
		{
			name: "BeaconType wpa2",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "wpa2",
				},
			},
			expected: "WPA2",
		},
		{
			name: "BeaconType WPAand11i",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "WPAand11i",
				},
			},
			expected: "WPA/WPA2",
		},
		{
			name: "BeaconType WPAWPA2",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "WPAWPA2",
				},
			},
			expected: "WPA/WPA2",
		},
		{
			name: "BeaconType unknown",
			wlan: map[string]interface{}{
				"BeaconType": map[string]interface{}{
					"_value": "WPA3",
				},
			},
			expected: "WPA3",
		},
		{
			name:     "BeaconType missing",
			wlan:     map[string]interface{}{},
			expected: "",
		},
		{
			name: "BeaconType wrong type",
			wlan: map[string]interface{}{
				"BeaconType": "invalid",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getAuthMode(tt.wlan)
			if result != tt.expected {
				t.Errorf("getAuthMode() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestGetEncryption tests the getEncryption function
func TestGetEncryption(t *testing.T) {
	tests := []struct {
		name     string
		wlan     map[string]interface{}
		expected string
	}{
		{
			name: "WPAEncryptionModes AES",
			wlan: map[string]interface{}{
				"WPAEncryptionModes": map[string]interface{}{
					"_value": "AESEncryption",
				},
			},
			expected: "AES",
		},
		{
			name: "WPAEncryptionModes TKIP",
			wlan: map[string]interface{}{
				"WPAEncryptionModes": map[string]interface{}{
					"_value": "TKIPEncryption",
				},
			},
			expected: "TKIP",
		},
		{
			name: "IEEE11iEncryptionModes AES",
			wlan: map[string]interface{}{
				"IEEE11iEncryptionModes": map[string]interface{}{
					"_value": "AESEncryption",
				},
			},
			expected: "AES",
		},
		{
			name: "IEEE11iEncryptionModes TKIP+AES",
			wlan: map[string]interface{}{
				"IEEE11iEncryptionModes": map[string]interface{}{
					"_value": "TKIPandAESEncryption",
				},
			},
			expected: "TKIP+AES",
		},
		{
			name: "WPAEncryptionModes takes priority over IEEE11i",
			wlan: map[string]interface{}{
				"WPAEncryptionModes": map[string]interface{}{
					"_value": "AES",
				},
				"IEEE11iEncryptionModes": map[string]interface{}{
					"_value": "TKIP",
				},
			},
			expected: "AES",
		},
		{
			name:     "Encryption modes missing",
			wlan:     map[string]interface{}{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getEncryption(tt.wlan)
			if result != tt.expected {
				t.Errorf("getEncryption() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestNormalizeEncryption tests the normalizeEncryption function
func TestNormalizeEncryption(t *testing.T) {
	tests := []struct {
		name     string
		enc      string
		expected string
	}{
		{name: "AESEncryption", enc: "AESEncryption", expected: "AES"},
		{name: "AES", enc: "AES", expected: "AES"},
		{name: "aes lowercase", enc: "aes", expected: "AES"},
		{name: "TKIPEncryption", enc: "TKIPEncryption", expected: "TKIP"},
		{name: "TKIP", enc: "TKIP", expected: "TKIP"},
		{name: "tkip lowercase", enc: "tkip", expected: "TKIP"},
		{name: "TKIPandAESEncryption", enc: "TKIPandAESEncryption", expected: "TKIP+AES"},
		{name: "TKIPAES", enc: "TKIPAES", expected: "TKIP+AES"},
		{name: "TKIP+AES", enc: "TKIP+AES", expected: "TKIP+AES"},
		{name: "Unknown value", enc: "Unknown", expected: "UNKNOWN"},
		{name: "Empty string", enc: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeEncryption(tt.enc)
			if result != tt.expected {
				t.Errorf("normalizeEncryption(%q) = %v, expected %v", tt.enc, result, tt.expected)
			}
		})
	}
}

// TestGetPassword tests the getPassword function
func TestGetPassword(t *testing.T) {
	tests := []struct {
		name     string
		wlan     map[string]interface{}
		expected string
	}{
		{
			name: "X_CMS_KeyPassphrase with value",
			wlan: map[string]interface{}{
				"X_CMS_KeyPassphrase": map[string]interface{}{
					"_value": "MySecretPassword",
				},
			},
			expected: "MySecretPassword",
		},
		{
			name: "X_CMS_KeyPassphrase empty (masked)",
			wlan: map[string]interface{}{
				"X_CMS_KeyPassphrase": map[string]interface{}{
					"_value": "",
				},
			},
			expected: PasswordMasked,
		},
		{
			name: "PreSharedKey.1.KeyPassphrase with value",
			wlan: map[string]interface{}{
				"PreSharedKey": map[string]interface{}{
					"1": map[string]interface{}{
						"KeyPassphrase": map[string]interface{}{
							"_value": "PSKPassword123",
						},
					},
				},
			},
			expected: "PSKPassword123",
		},
		{
			name: "PreSharedKey.1.KeyPassphrase empty (masked)",
			wlan: map[string]interface{}{
				"PreSharedKey": map[string]interface{}{
					"1": map[string]interface{}{
						"KeyPassphrase": map[string]interface{}{
							"_value": "",
						},
					},
				},
			},
			expected: PasswordMasked,
		},
		{
			name: "PreSharedKey.1.PreSharedKey with value",
			wlan: map[string]interface{}{
				"PreSharedKey": map[string]interface{}{
					"1": map[string]interface{}{
						"PreSharedKey": map[string]interface{}{
							"_value": "PSKValue456",
						},
					},
				},
			},
			expected: "PSKValue456",
		},
		{
			name: "PreSharedKey.1.PreSharedKey empty (masked)",
			wlan: map[string]interface{}{
				"PreSharedKey": map[string]interface{}{
					"1": map[string]interface{}{
						"PreSharedKey": map[string]interface{}{
							"_value": "",
						},
					},
				},
			},
			expected: PasswordMasked,
		},
		{
			name:     "No password field (N/A)",
			wlan:     map[string]interface{}{},
			expected: PasswordNA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPassword(tt.wlan)
			if result != tt.expected {
				t.Errorf("getPassword() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestGetBand tests the getBand function
func TestGetBand(t *testing.T) {
	tests := []struct {
		name     string
		wlan     map[string]interface{}
		wlanKey  string
		expected string
	}{
		{
			name:     "WLAN key 1 (2.4GHz)",
			wlan:     map[string]interface{}{},
			wlanKey:  "1",
			expected: "2.4GHz",
		},
		{
			name:     "WLAN key 5 (5GHz)",
			wlan:     map[string]interface{}{},
			wlanKey:  "5",
			expected: "5GHz",
		},
		{
			name: "Standard with b (2.4GHz)",
			wlan: map[string]interface{}{
				"Standard": map[string]interface{}{
					"_value": "b/g/n",
				},
			},
			wlanKey:  "3",
			expected: "2.4GHz",
		},
		{
			name: "Standard with g (2.4GHz)",
			wlan: map[string]interface{}{
				"Standard": map[string]interface{}{
					"_value": "g",
				},
			},
			wlanKey:  "3",
			expected: "2.4GHz",
		},
		{
			name: "Standard with ac (5GHz)",
			wlan: map[string]interface{}{
				"Standard": map[string]interface{}{
					"_value": "a/n/ac",
				},
			},
			wlanKey:  "6",
			expected: "5GHz",
		},
		{
			name: "Standard with n only (Unknown)",
			wlan: map[string]interface{}{
				"Standard": map[string]interface{}{
					"_value": "n",
				},
			},
			wlanKey:  "3",
			expected: "Unknown",
		},
		{
			name:     "No Standard field (Unknown)",
			wlan:     map[string]interface{}{},
			wlanKey:  "3",
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBand(tt.wlan, tt.wlanKey)
			if result != tt.expected {
				t.Errorf("getBand() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
