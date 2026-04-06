package main

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkValidateIP benchmarks IP address validation
func BenchmarkValidateIP(b *testing.B) {
	for b.Loop() {
		_ = validateIP("192.168.1.100")
	}
}

// BenchmarkNormalizeModelName benchmarks model name normalization
func BenchmarkNormalizeModelName(b *testing.B) {
	for b.Loop() {
		normalizeModelName("F670L-V2.1")
	}
}

// BenchmarkIsDualBandModel benchmarks dual-band model lookup
func BenchmarkIsDualBandModel(b *testing.B) {
	for b.Loop() {
		isDualBandModel("F670L")
	}
}

// BenchmarkDeviceCacheGetSet benchmarks cache get/set operations
func BenchmarkDeviceCacheGetSet(b *testing.B) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}
	testData := map[string]interface{}{"key": "value"}

	b.Run("Set", func(b *testing.B) {
		for b.Loop() {
			cache.set("device-1", testData)
		}
	})

	b.Run("Get", func(b *testing.B) {
		cache.set("device-1", testData)
		for b.Loop() {
			cache.get("device-1")
		}
	})
}

// BenchmarkGetBand benchmarks WiFi band detection
func BenchmarkGetBand(b *testing.B) {
	wlan := map[string]interface{}{
		"Standard": map[string]interface{}{"_value": "b,g,n"},
	}
	for b.Loop() {
		getBand(wlan, "3")
	}
}

// BenchmarkSanitizeErrorMessage benchmarks error message sanitization
func BenchmarkSanitizeErrorMessage(b *testing.B) {
	err := fmt.Errorf("device not found with IP: 192.168.1.1")
	for b.Loop() {
		sanitizeErrorMessage(err)
	}
}

// BenchmarkValidateWLANID benchmarks WLAN ID validation
func BenchmarkValidateWLANID(b *testing.B) {
	for b.Loop() {
		validateWLANID("5")
	}
}
