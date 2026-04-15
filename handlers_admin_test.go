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

// handlers_admin_test.go covers L7 (setNTPHandler) and L8
// (setAdminPasswordHandler) plus their pure helper functions.

// --- intToStr ---

func TestIntToStr(t *testing.T) {
	assert.Equal(t, "0", intToStr(0))
	assert.Equal(t, "1", intToStr(1))
	assert.Equal(t, "42", intToStr(42))
	assert.Equal(t, "12345", intToStr(12345))
	assert.Equal(t, "-5", intToStr(-5))
}

// --- validateNTPRequest ---

func TestValidateNTPRequest_BothFields(t *testing.T) {
	req := SetNTPRequest{
		NTPServers: []string{"pool.ntp.org", "time.google.com"},
		Timezone:   "Asia/Jakarta",
	}
	assert.Equal(t, "", validateNTPRequest(&req))
}

func TestValidateNTPRequest_OnlyServers(t *testing.T) {
	req := SetNTPRequest{NTPServers: []string{"pool.ntp.org"}}
	assert.Equal(t, "", validateNTPRequest(&req))
}

func TestValidateNTPRequest_OnlyTimezone(t *testing.T) {
	req := SetNTPRequest{Timezone: "UTC"}
	assert.Equal(t, "", validateNTPRequest(&req))
}

func TestValidateNTPRequest_NoFields(t *testing.T) {
	req := SetNTPRequest{}
	assert.Equal(t, ErrNTPNoFields, validateNTPRequest(&req))
}

func TestValidateNTPRequest_TooMany(t *testing.T) {
	req := SetNTPRequest{NTPServers: make([]string, MaxNTPServers+1)}
	for i := range req.NTPServers {
		req.NTPServers[i] = "s"
	}
	assert.Equal(t, ErrNTPServersTooMany, validateNTPRequest(&req))
}

// --- buildNTPParameterValues ---

func TestBuildNTPParameterValues(t *testing.T) {
	values := buildNTPParameterValues([]string{"pool.ntp.org", "time.google.com"}, "Asia/Jakarta")
	require.Len(t, values, 3)
	assert.Contains(t, values[0][0], "NTPServer1")
	assert.Equal(t, "pool.ntp.org", values[0][1])
	assert.Contains(t, values[1][0], "NTPServer2")
	assert.Contains(t, values[2][0], "LocalTimeZoneName")
}

func TestBuildNTPParameterValues_ServersOnly(t *testing.T) {
	values := buildNTPParameterValues([]string{"pool.ntp.org"}, "")
	assert.Len(t, values, 1)
}

// --- setNTPHandler ---

func TestSetNTPHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"ntp_servers":["pool.ntp.org"],"timezone":"UTC"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ntp/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetNTPHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ntp/192.0.2.99", strings.NewReader(`{"timezone":"UTC"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetNTPHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ntp/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetNTPHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ntp/"+mockDeviceIP, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetNTPHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}

	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/ntp/"+mockDeviceIP, strings.NewReader(`{"timezone":"UTC"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// --- validateAdminPasswordRequest ---

func TestValidateAdminPasswordRequest_HappyPath(t *testing.T) {
	req := SetAdminPasswordRequest{Password: "secret"}
	assert.Equal(t, "", validateAdminPasswordRequest(&req))
}

func TestValidateAdminPasswordRequest_Empty(t *testing.T) {
	req := SetAdminPasswordRequest{}
	assert.Equal(t, ErrAdminPasswordRequired, validateAdminPasswordRequest(&req))
}

func TestValidateAdminPasswordRequest_TooLong(t *testing.T) {
	req := SetAdminPasswordRequest{Password: strings.Repeat("x", AdminPasswordMaxLength+1)}
	assert.Equal(t, ErrAdminPasswordTooLong, validateAdminPasswordRequest(&req))
}

// --- setAdminPasswordHandler ---

func TestSetAdminPasswordHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"password":"secret"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/admin-password/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
	// Password MUST NOT appear in the response body for audit safety
	assert.NotContains(t, rr.Body.String(), "secret")
}

func TestSetAdminPasswordHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/admin-password/192.0.2.99", strings.NewReader(`{"password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetAdminPasswordHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/admin-password/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetAdminPasswordHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/admin-password/"+mockDeviceIP, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetAdminPasswordHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}

	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/admin-password/"+mockDeviceIP, strings.NewReader(`{"password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
