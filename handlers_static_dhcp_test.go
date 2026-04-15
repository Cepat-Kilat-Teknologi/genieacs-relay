package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// handlers_static_dhcp_test.go covers the L6 static DHCP handler
// (setStaticDHCPHandler) + helpers validateStaticDHCPRequest and
// buildStaticDHCPParameterValues.

func TestValidateStaticDHCPRequest_HappyPath(t *testing.T) {
	req := SetStaticDHCPRequest{Leases: []StaticDHCPLease{
		{Index: 1, MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.1.100", Hostname: "device1"},
	}}
	assert.Equal(t, "", validateStaticDHCPRequest(&req))
}

func TestValidateStaticDHCPRequest_Empty(t *testing.T) {
	req := SetStaticDHCPRequest{}
	assert.Equal(t, ErrStaticDHCPLeasesEmpty, validateStaticDHCPRequest(&req))
}

func TestValidateStaticDHCPRequest_TooMany(t *testing.T) {
	req := SetStaticDHCPRequest{Leases: make([]StaticDHCPLease, MaxStaticDHCPLeases+1)}
	for i := range req.Leases {
		req.Leases[i] = StaticDHCPLease{Index: i + 1, MAC: "AA:BB:CC:DD:EE:FF", IP: "10.0.0.1"}
	}
	assert.Equal(t, ErrStaticDHCPLeasesTooMany, validateStaticDHCPRequest(&req))
}

func TestValidateStaticDHCPRequest_BadIndex(t *testing.T) {
	req := SetStaticDHCPRequest{Leases: []StaticDHCPLease{{Index: 0, MAC: "AA:BB:CC:DD:EE:FF", IP: "10.0.0.1"}}}
	assert.Equal(t, ErrStaticDHCPLeasesTooMany, validateStaticDHCPRequest(&req))
}

func TestValidateStaticDHCPRequest_BadMAC(t *testing.T) {
	req := SetStaticDHCPRequest{Leases: []StaticDHCPLease{{Index: 1, MAC: "not-a-mac", IP: "10.0.0.1"}}}
	assert.Equal(t, ErrStaticDHCPInvalidMAC, validateStaticDHCPRequest(&req))
}

func TestValidateStaticDHCPRequest_BadIP(t *testing.T) {
	req := SetStaticDHCPRequest{Leases: []StaticDHCPLease{{Index: 1, MAC: "AA:BB:CC:DD:EE:FF", IP: "not-an-ip"}}}
	assert.Equal(t, ErrStaticDHCPInvalidIP, validateStaticDHCPRequest(&req))
}

func TestBuildStaticDHCPParameterValues_WithHostname(t *testing.T) {
	leases := []StaticDHCPLease{{Index: 1, MAC: "AA:BB:CC:DD:EE:FF", IP: "10.0.0.1", Hostname: "device1"}}
	values := buildStaticDHCPParameterValues(leases)
	// Enable + Chaddr + Yiaddr + X_Hostname = 4
	assert.Len(t, values, 4)
}

func TestBuildStaticDHCPParameterValues_NoHostname(t *testing.T) {
	leases := []StaticDHCPLease{{Index: 1, MAC: "AA:BB:CC:DD:EE:FF", IP: "10.0.0.1"}}
	values := buildStaticDHCPParameterValues(leases)
	assert.Len(t, values, 3)
}

func TestSetStaticDHCPHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"leases":[{"index":1,"mac":"AA:BB:CC:DD:EE:FF","ip":"192.168.1.100"}]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/static-dhcp/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetStaticDHCPHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/static-dhcp/192.0.2.99", strings.NewReader(`{"leases":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetStaticDHCPHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/static-dhcp/"+mockDeviceIP, strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetStaticDHCPHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/static-dhcp/"+mockDeviceIP, strings.NewReader(`{"leases":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetStaticDHCPHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}
	body := `{"leases":[{"index":1,"mac":"AA:BB:CC:DD:EE:FF","ip":"10.0.0.1"}]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/static-dhcp/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
