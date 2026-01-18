package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- System Handler Tests (Health Check and Cache) ---

func TestHealthCheckHandler(t *testing.T) {
	_, router := setupTestServer(t, nil)
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"status":"healthy"`)
}

func TestClearCacheHandler(t *testing.T) {
	_, router := setupTestServer(t, nil)
	deviceCacheInstance.set("device1", map[string]interface{}{"key": "value1"})
	t.Run("Clear Specific Device", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/genieacs/cache/clear?device_id=device1", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("Clear All Devices", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/genieacs/cache/clear", nil)
		req.Header.Set("X-API-Key", mockAPIKey)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
