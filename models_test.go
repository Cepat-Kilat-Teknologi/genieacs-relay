package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceDataNavigator_GetInternetGatewayDevice(t *testing.T) {
	t.Run("Valid InternetGatewayDevice", func(t *testing.T) {
		data := map[string]interface{}{
			PathInternetGatewayDevice: map[string]interface{}{
				"test": "value",
			},
		}
		nav := NewDeviceDataNavigator(data)
		igw, ok := nav.GetInternetGatewayDevice()
		assert.True(t, ok)
		assert.NotNil(t, igw)
		assert.Equal(t, "value", igw["test"])
	})

	t.Run("Missing InternetGatewayDevice", func(t *testing.T) {
		data := map[string]interface{}{}
		nav := NewDeviceDataNavigator(data)
		igw, ok := nav.GetInternetGatewayDevice()
		assert.False(t, ok)
		assert.Nil(t, igw)
	})

	t.Run("Invalid type InternetGatewayDevice", func(t *testing.T) {
		data := map[string]interface{}{
			PathInternetGatewayDevice: "invalid",
		}
		nav := NewDeviceDataNavigator(data)
		igw, ok := nav.GetInternetGatewayDevice()
		assert.False(t, ok)
		assert.Nil(t, igw)
	})
}

func TestDeviceDataNavigator_GetLANDevice(t *testing.T) {
	t.Run("Valid LANDevice", func(t *testing.T) {
		igw := map[string]interface{}{
			PathLANDevice: map[string]interface{}{
				"1": map[string]interface{}{
					"test": "value",
				},
			},
		}
		nav := NewDeviceDataNavigator(nil)
		lanDevice, ok := nav.GetLANDevice(igw)
		assert.True(t, ok)
		assert.NotNil(t, lanDevice)
		assert.Equal(t, "value", lanDevice["test"])
	})

	t.Run("Missing LANDevice", func(t *testing.T) {
		igw := map[string]interface{}{}
		nav := NewDeviceDataNavigator(nil)
		lanDevice, ok := nav.GetLANDevice(igw)
		assert.False(t, ok)
		assert.Nil(t, lanDevice)
	})

	t.Run("Missing LANDevice.1", func(t *testing.T) {
		igw := map[string]interface{}{
			PathLANDevice: map[string]interface{}{},
		}
		nav := NewDeviceDataNavigator(nil)
		lanDevice, ok := nav.GetLANDevice(igw)
		assert.False(t, ok)
		assert.Nil(t, lanDevice)
	})
}

func TestDeviceDataNavigator_GetWLANConfiguration(t *testing.T) {
	t.Run("Valid WLANConfiguration", func(t *testing.T) {
		lanDevice := map[string]interface{}{
			PathWLANConfiguration: map[string]interface{}{
				"1": map[string]interface{}{
					"SSID": "test",
				},
			},
		}
		nav := NewDeviceDataNavigator(nil)
		wlanConfig, ok := nav.GetWLANConfiguration(lanDevice)
		assert.True(t, ok)
		assert.NotNil(t, wlanConfig)
	})

	t.Run("Missing WLANConfiguration", func(t *testing.T) {
		lanDevice := map[string]interface{}{}
		nav := NewDeviceDataNavigator(nil)
		wlanConfig, ok := nav.GetWLANConfiguration(lanDevice)
		assert.False(t, ok)
		assert.Nil(t, wlanConfig)
	})
}

func TestDeviceDataNavigator_GetHosts(t *testing.T) {
	t.Run("Valid Hosts", func(t *testing.T) {
		lanDevice := map[string]interface{}{
			PathHosts: map[string]interface{}{
				PathHost: map[string]interface{}{
					"1": map[string]interface{}{
						"IPAddress": "192.168.1.1",
					},
				},
			},
		}
		nav := NewDeviceDataNavigator(nil)
		hosts, ok := nav.GetHosts(lanDevice)
		assert.True(t, ok)
		assert.NotNil(t, hosts)
	})

	t.Run("Missing Hosts", func(t *testing.T) {
		lanDevice := map[string]interface{}{}
		nav := NewDeviceDataNavigator(nil)
		hosts, ok := nav.GetHosts(lanDevice)
		assert.False(t, ok)
		assert.Nil(t, hosts)
	})

	t.Run("Missing Host in Hosts", func(t *testing.T) {
		lanDevice := map[string]interface{}{
			PathHosts: map[string]interface{}{},
		}
		nav := NewDeviceDataNavigator(nil)
		hosts, ok := nav.GetHosts(lanDevice)
		assert.False(t, ok)
		assert.Nil(t, hosts)
	})
}

func TestExtractStringValue(t *testing.T) {
	t.Run("Valid string value", func(t *testing.T) {
		data := map[string]interface{}{
			"SSID": map[string]interface{}{
				FieldValue: "MyWiFi",
			},
		}
		result := ExtractStringValue(data, "SSID")
		assert.Equal(t, "MyWiFi", result)
	})

	t.Run("Missing key", func(t *testing.T) {
		data := map[string]interface{}{}
		result := ExtractStringValue(data, "SSID")
		assert.Equal(t, "", result)
	})

	t.Run("Invalid type for key", func(t *testing.T) {
		data := map[string]interface{}{
			"SSID": "invalid",
		}
		result := ExtractStringValue(data, "SSID")
		assert.Equal(t, "", result)
	})

	t.Run("Invalid type for _value", func(t *testing.T) {
		data := map[string]interface{}{
			"SSID": map[string]interface{}{
				FieldValue: 123,
			},
		}
		result := ExtractStringValue(data, "SSID")
		assert.Equal(t, "", result)
	})
}

func TestExtractBoolValue(t *testing.T) {
	t.Run("Valid bool value true", func(t *testing.T) {
		data := map[string]interface{}{
			"Enable": map[string]interface{}{
				FieldValue: true,
			},
		}
		result, ok := ExtractBoolValue(data, "Enable")
		assert.True(t, ok)
		assert.True(t, result)
	})

	t.Run("Valid bool value false", func(t *testing.T) {
		data := map[string]interface{}{
			"Enable": map[string]interface{}{
				FieldValue: false,
			},
		}
		result, ok := ExtractBoolValue(data, "Enable")
		assert.True(t, ok)
		assert.False(t, result)
	})

	t.Run("Missing key", func(t *testing.T) {
		data := map[string]interface{}{}
		result, ok := ExtractBoolValue(data, "Enable")
		assert.False(t, ok)
		assert.False(t, result)
	})

	t.Run("Invalid type for key", func(t *testing.T) {
		data := map[string]interface{}{
			"Enable": "invalid",
		}
		result, ok := ExtractBoolValue(data, "Enable")
		assert.False(t, ok)
		assert.False(t, result)
	})

	t.Run("Invalid type for _value", func(t *testing.T) {
		data := map[string]interface{}{
			"Enable": map[string]interface{}{
				FieldValue: "true",
			},
		}
		result, ok := ExtractBoolValue(data, "Enable")
		assert.False(t, ok)
		assert.False(t, result)
	})
}

func TestIsZTEDevice(t *testing.T) {
	t.Run("ZTE device", func(t *testing.T) {
		assert.True(t, IsZTEDevice("002568-ZTE-123456"))
	})

	t.Run("ZT device", func(t *testing.T) {
		assert.True(t, IsZTEDevice("002568-ZT-123456"))
	})

	t.Run("Non-ZTE device", func(t *testing.T) {
		assert.False(t, IsZTEDevice("002568-BCM963268-684752"))
	})

	t.Run("Empty string", func(t *testing.T) {
		assert.False(t, IsZTEDevice(""))
	})
}

func TestContains(t *testing.T) {
	t.Run("Contains substring", func(t *testing.T) {
		assert.True(t, contains("hello world", "world"))
	})

	t.Run("Does not contain substring", func(t *testing.T) {
		assert.False(t, contains("hello world", "foo"))
	})

	t.Run("Empty substring", func(t *testing.T) {
		assert.True(t, contains("hello", ""))
	})

	t.Run("Substring equals string", func(t *testing.T) {
		assert.True(t, contains("hello", "hello"))
	})

	t.Run("Substring longer than string", func(t *testing.T) {
		assert.False(t, contains("hi", "hello"))
	})
}
