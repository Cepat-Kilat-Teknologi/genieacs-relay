package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- Device Cache Tests ---

func TestDeviceCache(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 50 * time.Millisecond,
	}
	testData := map[string]interface{}{"key": "value"}
	deviceID := "test-device"
	cache.set(deviceID, testData)
	_, found := cache.get(deviceID)
	assert.True(t, found)
}

func TestDeviceCache_Timeout(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 10 * time.Millisecond, // Very short timeout
	}

	testData := map[string]interface{}{"key": "value"}
	deviceID := "test-device"

	cache.set(deviceID, testData)
	time.Sleep(20 * time.Millisecond) // Wait for cache to expire

	_, found := cache.get(deviceID)
	assert.False(t, found)
}
