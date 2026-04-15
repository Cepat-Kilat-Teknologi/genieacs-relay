package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// handlers_wifi_advanced_test.go covers the L4 WiFi schedule handler
// (setWifiScheduleHandler) and L5 MAC filter handler
// (setMACFilterHandler) + their pure helpers.

// ============================================================
// L4 — wifi schedule
// ============================================================

func TestValidateWifiScheduleRequest_HappyPath(t *testing.T) {
	req := SetWifiScheduleRequest{Schedules: []WifiScheduleEntry{
		{Day: 1, StartTime: "09:00", EndTime: "17:00", Enabled: true},
	}}
	assert.Equal(t, "", validateWifiScheduleRequest(&req))
	assert.Equal(t, 1, req.WLANIndex)
}

func TestValidateWifiScheduleRequest_Empty(t *testing.T) {
	req := SetWifiScheduleRequest{}
	assert.Equal(t, ErrWifiScheduleEmpty, validateWifiScheduleRequest(&req))
}

func TestValidateWifiScheduleRequest_TooMany(t *testing.T) {
	schedules := make([]WifiScheduleEntry, MaxWifiScheduleEntries+1)
	for i := range schedules {
		schedules[i] = WifiScheduleEntry{Day: i % 7, StartTime: "00:00", EndTime: "23:59"}
	}
	req := SetWifiScheduleRequest{Schedules: schedules}
	assert.Equal(t, ErrWifiScheduleTooMany, validateWifiScheduleRequest(&req))
}

func TestValidateWifiScheduleRequest_BadDay(t *testing.T) {
	req := SetWifiScheduleRequest{Schedules: []WifiScheduleEntry{
		{Day: 7, StartTime: "09:00", EndTime: "17:00"},
	}}
	assert.Equal(t, ErrWifiScheduleInvalidDay, validateWifiScheduleRequest(&req))
}

func TestValidateWifiScheduleRequest_BadStartTime(t *testing.T) {
	req := SetWifiScheduleRequest{Schedules: []WifiScheduleEntry{
		{Day: 1, StartTime: "25:00", EndTime: "17:00"},
	}}
	assert.Equal(t, ErrWifiScheduleInvalidTime, validateWifiScheduleRequest(&req))
}

func TestValidateWifiScheduleRequest_BadEndTime(t *testing.T) {
	req := SetWifiScheduleRequest{Schedules: []WifiScheduleEntry{
		{Day: 1, StartTime: "09:00", EndTime: "99:99"},
	}}
	assert.Equal(t, ErrWifiScheduleInvalidTime, validateWifiScheduleRequest(&req))
}

func TestBuildWifiScheduleParameterValues(t *testing.T) {
	schedules := []WifiScheduleEntry{
		{Day: 1, StartTime: "09:00", EndTime: "17:00", Enabled: true},
	}
	values := buildWifiScheduleParameterValues(schedules, 1)
	// Enable + Day + StartTime + EndTime = 4
	assert.Len(t, values, 4)
}

func TestSetWifiScheduleHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"schedules":[{"day":1,"start_time":"09:00","end_time":"17:00","enabled":true}]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/wifi-schedule/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetWifiScheduleHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/wifi-schedule/192.0.2.99", strings.NewReader(`{"schedules":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetWifiScheduleHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/wifi-schedule/"+mockDeviceIP, strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetWifiScheduleHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/wifi-schedule/"+mockDeviceIP, strings.NewReader(`{"schedules":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetWifiScheduleHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}
	body := `{"schedules":[{"day":1,"start_time":"09:00","end_time":"17:00","enabled":true}]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/wifi-schedule/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ============================================================
// L5 — MAC filter
// ============================================================

func TestValidateMACFilterRequest_HappyPath(t *testing.T) {
	req := SetMACFilterRequest{Mode: "allow", MACs: []string{"AA:BB:CC:DD:EE:FF"}}
	assert.Equal(t, "", validateMACFilterRequest(&req))
	assert.Equal(t, 1, req.WLANIndex)
}

func TestValidateMACFilterRequest_DenyMode(t *testing.T) {
	req := SetMACFilterRequest{Mode: "DENY", MACs: []string{"AA:BB:CC:DD:EE:FF"}}
	assert.Equal(t, "", validateMACFilterRequest(&req))
	assert.Equal(t, "deny", req.Mode)
}

func TestValidateMACFilterRequest_BadMode(t *testing.T) {
	req := SetMACFilterRequest{Mode: "block", MACs: []string{"AA:BB:CC:DD:EE:FF"}}
	assert.Equal(t, ErrMacFilterModeInvalid, validateMACFilterRequest(&req))
}

func TestValidateMACFilterRequest_Empty(t *testing.T) {
	req := SetMACFilterRequest{Mode: "allow"}
	assert.Equal(t, ErrMacFilterMacsEmpty, validateMACFilterRequest(&req))
}

func TestValidateMACFilterRequest_TooMany(t *testing.T) {
	macs := make([]string, MaxMacFilterEntries+1)
	for i := range macs {
		macs[i] = "AA:BB:CC:DD:EE:FF"
	}
	req := SetMACFilterRequest{Mode: "allow", MACs: macs}
	assert.Equal(t, ErrMacFilterMacsTooMany, validateMACFilterRequest(&req))
}

func TestValidateMACFilterRequest_BadMAC(t *testing.T) {
	req := SetMACFilterRequest{Mode: "allow", MACs: []string{"not-a-mac"}}
	assert.Equal(t, ErrMacFilterInvalidMAC, validateMACFilterRequest(&req))
}

func TestBuildMACFilterParameterValues_Allow(t *testing.T) {
	req := SetMACFilterRequest{Mode: "allow", MACs: []string{"AA:BB:CC:DD:EE:FF"}, WLANIndex: 1}
	values := buildMACFilterParameterValues(req)
	assert.Len(t, values, 2)
	assert.Equal(t, "Allow", values[0][1])
}

func TestBuildMACFilterParameterValues_Deny(t *testing.T) {
	req := SetMACFilterRequest{Mode: "deny", MACs: []string{"AA:BB:CC:DD:EE:FF"}, WLANIndex: 1}
	values := buildMACFilterParameterValues(req)
	assert.Equal(t, "Deny", values[0][1])
}

func TestSetMACFilterHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"mode":"allow","macs":["AA:BB:CC:DD:EE:FF"]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/mac-filter/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetMACFilterHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/mac-filter/192.0.2.99", strings.NewReader(`{"mode":"allow","macs":["AA:BB:CC:DD:EE:FF"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetMACFilterHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/mac-filter/"+mockDeviceIP, strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetMACFilterHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/mac-filter/"+mockDeviceIP, strings.NewReader(`{"mode":"bad","macs":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetMACFilterHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}
	body := `{"mode":"allow","macs":["AA:BB:CC:DD:EE:FF"]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/mac-filter/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
