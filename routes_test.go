package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestVersionHandler(t *testing.T) {
	l, err := initProductionLogger()
	require.NoError(t, err)
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	rr := httptest.NewRecorder()
	versionHandler(rr, httptest.NewRequest(http.MethodGet, "/version", nil))
	assert.Equal(t, 200, rr.Code)
	var vr VersionResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&vr))
	assert.Equal(t, "v1", vr.APIVersion)
}

// versionHandler: exercise the json encode error path by wiring an
// errorResponseWriter that fails on Write. Mirrors the TestSendResponseEncoding
// pattern already in main_test.go.
func TestVersionHandlerEncodeError(t *testing.T) {
	l, _ := initProductionLogger()
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	w := &errorResponseWriter{}
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	// Should not panic even when Write fails — error is logged via zap.
	assert.NotPanics(t, func() {
		versionHandler(w, req)
	})
}
