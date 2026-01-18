package main

import (
	"sync"
	"time"
)

// deviceCache provides thread-safe caching mechanism for device data with expiration
type deviceCache struct {
	mu      sync.RWMutex                // Read-write mutex for concurrent access
	data    map[string]cachedDeviceData // Cache storage mapping device IDs to cached data
	timeout time.Duration               // Duration after which cached data is considered stale
}

// cachedDeviceData holds the actual cached data and timestamp for expiration tracking
type cachedDeviceData struct {
	data      map[string]interface{} // The cached device data as key-value pairs
	timestamp time.Time              // Time when this data was cached for expiration calculation
}

// get retrieves cached data for a device if it exists and hasn't expired.
// Returns a deep copy of the cached data to prevent race conditions and
// unintended modifications to the cached data by callers.
func (c *deviceCache) get(deviceID string) (map[string]interface{}, bool) {
	c.mu.RLock()         // Acquire read lock for thread safety
	defer c.mu.RUnlock() // Ensure lock is released when function exits
	// Check if device exists in cache and data is still fresh
	cached, exists := c.data[deviceID]
	if !exists || time.Since(cached.timestamp) >= c.timeout {
		return nil, false // Return empty result if not found or expired
	}
	// Return deep copy to prevent external modifications affecting cache
	result := make(map[string]interface{}, len(cached.data))
	for k, v := range cached.data {
		result[k] = v
	}
	return result, true
}

// set stores device data in cache with current timestamp
func (c *deviceCache) set(deviceID string, data map[string]interface{}) {
	c.mu.Lock()         // Acquire write lock for thread safety
	defer c.mu.Unlock() // Ensure lock release
	// Store data with current timestamp for expiration tracking
	c.data[deviceID] = cachedDeviceData{data, time.Now()}
}

// clear removes cached data for a specific device
func (c *deviceCache) clear(deviceID string) {
	c.mu.Lock() // Acquire write lock
	defer c.mu.Unlock()
	delete(c.data, deviceID) // Remove device entry from cache
}

// clearAll removes all cached data (complete cache flush)
func (c *deviceCache) clearAll() {
	c.mu.Lock() // Acquire write lock
	defer c.mu.Unlock()
	c.data = make(map[string]cachedDeviceData) // Reinitialize empty cache map
}
