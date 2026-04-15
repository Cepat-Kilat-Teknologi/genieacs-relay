package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handlers_dmz_ddns_test.go covers L2 (DMZ) and L3 (DDNS).

// --- validateDMZRequest ---

func TestValidateDMZRequest_Enabled_HappyPath(t *testing.T) {
	req := SetDMZRequest{Enabled: boolPtr(true), HostIP: "192.168.1.100"}
	assert.Equal(t, "", validateDMZRequest(&req))
	assert.Equal(t, 1, req.WANInstance)
}

func TestValidateDMZRequest_Disabled(t *testing.T) {
	req := SetDMZRequest{Enabled: boolPtr(false)}
	assert.Equal(t, "", validateDMZRequest(&req))
}

func TestValidateDMZRequest_MissingEnabled(t *testing.T) {
	req := SetDMZRequest{}
	got := validateDMZRequest(&req)
	assert.Contains(t, got, "enabled is required")
}

func TestValidateDMZRequest_EnabledNoHost(t *testing.T) {
	req := SetDMZRequest{Enabled: boolPtr(true)}
	assert.Equal(t, ErrDMZHostInvalid, validateDMZRequest(&req))
}

func TestValidateDMZRequest_InvalidHostIP(t *testing.T) {
	req := SetDMZRequest{Enabled: boolPtr(true), HostIP: "not-an-ip"}
	assert.Equal(t, ErrDMZHostInvalid, validateDMZRequest(&req))
}

func TestValidateDMZRequest_InvalidWANInstance(t *testing.T) {
	req := SetDMZRequest{Enabled: boolPtr(false), WANInstance: 99}
	assert.Equal(t, ErrPPPoEInvalidWanInstance, validateDMZRequest(&req))
}

// --- buildDMZParameterValues ---

func TestBuildDMZParameterValues(t *testing.T) {
	values := buildDMZParameterValues(true, "192.168.1.100", 1)
	require.Len(t, values, 2)
	assert.Equal(t, true, values[0][1])
	assert.Equal(t, "192.168.1.100", values[1][1])
}

// --- setDMZHandler ---

func TestSetDMZHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"enabled":true,"host_ip":"192.168.1.100"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/dmz/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetDMZHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/dmz/192.0.2.99", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetDMZHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/dmz/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetDMZHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/dmz/"+mockDeviceIP, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetDMZHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}

	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/dmz/"+mockDeviceIP, strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// --- validateDDNSRequest ---

func TestValidateDDNSRequest_HappyPath(t *testing.T) {
	req := SetDDNSRequest{
		Enabled:  boolPtr(true),
		Provider: "dyndns.com",
		Hostname: "mycpe.dyndns.com",
		Username: "user",
		Password: "pass",
	}
	assert.Equal(t, "", validateDDNSRequest(&req))
}

func TestValidateDDNSRequest_Disabled(t *testing.T) {
	req := SetDDNSRequest{Enabled: boolPtr(false)}
	assert.Equal(t, "", validateDDNSRequest(&req))
}

func TestValidateDDNSRequest_MissingEnabled(t *testing.T) {
	req := SetDDNSRequest{}
	got := validateDDNSRequest(&req)
	assert.Contains(t, got, "enabled is required")
}

func TestValidateDDNSRequest_NoProvider(t *testing.T) {
	req := SetDDNSRequest{Enabled: boolPtr(true), Hostname: "x"}
	assert.Equal(t, ErrDDNSProviderRequired, validateDDNSRequest(&req))
}

func TestValidateDDNSRequest_NoHostname(t *testing.T) {
	req := SetDDNSRequest{Enabled: boolPtr(true), Provider: "dyn"}
	assert.Equal(t, ErrDDNSHostnameRequired, validateDDNSRequest(&req))
}

// --- buildDDNSParameterValues ---

func TestBuildDDNSParameterValues_Enabled(t *testing.T) {
	req := SetDDNSRequest{
		Enabled:  boolPtr(true),
		Provider: "dyndns.com",
		Hostname: "mycpe.dyndns.com",
		Username: "u",
		Password: "p",
	}
	values := buildDDNSParameterValues(req)
	// Enable + Server + DomainName + Username + Password = 5
	assert.Len(t, values, 5)
}

func TestBuildDDNSParameterValues_Disabled(t *testing.T) {
	req := SetDDNSRequest{Enabled: boolPtr(false)}
	values := buildDDNSParameterValues(req)
	assert.Len(t, values, 1)
	assert.Equal(t, false, values[0][1])
}

// --- setDDNSHandler ---

func TestSetDDNSHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"enabled":true,"provider":"dyndns.com","hostname":"x.dyndns.com","username":"u","password":"p"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ddns/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
	// Username/Password MUST NOT be echoed in response for audit safety
	assert.NotContains(t, rr.Body.String(), `"username"`)
	assert.NotContains(t, rr.Body.String(), `"password"`)
}

func TestSetDDNSHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ddns/192.0.2.99", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetDDNSHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ddns/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetDDNSHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ddns/"+mockDeviceIP, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetDDNSHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}

	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ddns/"+mockDeviceIP, strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
