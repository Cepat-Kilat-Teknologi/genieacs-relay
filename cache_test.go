package main

import (
	"fmt"
	"sync"
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
		timeout: 10 * time.Millisecond,
	}

	testData := map[string]interface{}{"key": "value"}
	deviceID := "test-device"

	cache.set(deviceID, testData)
	time.Sleep(20 * time.Millisecond)

	_, found := cache.get(deviceID)
	assert.False(t, found)
}

func TestDeviceCache_Clear(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	cache.set("device-1", map[string]interface{}{"key": "val1"})
	cache.set("device-2", map[string]interface{}{"key": "val2"})

	cache.clear("device-1")

	_, found1 := cache.get("device-1")
	assert.False(t, found1, "device-1 should be cleared")

	_, found2 := cache.get("device-2")
	assert.True(t, found2, "device-2 should still exist")
}

func TestDeviceCache_ClearAll(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	cache.set("device-1", map[string]interface{}{"key": "val1"})
	cache.set("device-2", map[string]interface{}{"key": "val2"})

	cache.clearAll()

	_, found1 := cache.get("device-1")
	_, found2 := cache.get("device-2")
	assert.False(t, found1, "device-1 should be cleared")
	assert.False(t, found2, "device-2 should be cleared")
}

func TestDeviceCache_DeepCopy(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	original := map[string]interface{}{
		"nested": map[string]interface{}{"inner": "original"},
	}
	cache.set("device-1", original)

	// Get a copy and modify it
	copy1, found := cache.get("device-1")
	assert.True(t, found)

	nested := copy1["nested"].(map[string]interface{})
	nested["inner"] = "modified"

	// Original cache should be unaffected
	copy2, found := cache.get("device-1")
	assert.True(t, found)
	nested2 := copy2["nested"].(map[string]interface{})
	assert.Equal(t, "original", nested2["inner"], "cached data should not be mutated by caller")
}

func TestDeepCopyValue_Slice(t *testing.T) {
	original := map[string]interface{}{
		"list": []interface{}{"a", "b", map[string]interface{}{"nested": true}},
	}
	copied := deepCopyMap(original)

	// Modify copied slice
	copiedList := copied["list"].([]interface{})
	copiedList[0] = "modified"

	// Original should be unaffected
	originalList := original["list"].([]interface{})
	assert.Equal(t, "a", originalList[0])
}

func TestDeepCopyValue_Primitives(t *testing.T) {
	original := map[string]interface{}{
		"str":   "hello",
		"num":   float64(42),
		"flag":  true,
		"empty": nil,
	}
	copied := deepCopyMap(original)
	assert.Equal(t, original, copied)
}

func TestDeviceCache_Concurrent(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(id string) {
			defer wg.Done()
			cache.set(id, map[string]interface{}{"key": id})
		}(fmt.Sprintf("device-%d", i))
		go func(id string) {
			defer wg.Done()
			cache.get(id)
		}(fmt.Sprintf("device-%d", i))
	}
	wg.Wait()
}
