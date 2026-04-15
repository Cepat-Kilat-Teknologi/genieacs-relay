package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handlers_diag_test.go covers M1 (dispatchPingHandler) and
// M2 (dispatchTraceRouteHandler) plus their helpers.

// --- validatePingRequest ---

func TestValidatePingRequest_HappyPath(t *testing.T) {
	req := PingDiagRequest{Host: "8.8.8.8"}
	assert.Equal(t, "", validatePingRequest(&req))
	assert.Equal(t, DefaultPingCount, req.Count)
	assert.Equal(t, DefaultPingTimeoutMs, req.TimeoutMs)
}

func TestValidatePingRequest_Explicit(t *testing.T) {
	req := PingDiagRequest{Host: "1.1.1.1", Count: 8, TimeoutMs: 2000}
	assert.Equal(t, "", validatePingRequest(&req))
	assert.Equal(t, 8, req.Count)
	assert.Equal(t, 2000, req.TimeoutMs)
}

func TestValidatePingRequest_HostMissing(t *testing.T) {
	req := PingDiagRequest{}
	assert.Equal(t, ErrDiagInvalidHost, validatePingRequest(&req))
}

func TestValidatePingRequest_CountTooLow(t *testing.T) {
	req := PingDiagRequest{Host: "x", Count: -1}
	assert.Equal(t, ErrDiagInvalidCount, validatePingRequest(&req))
}

func TestValidatePingRequest_CountTooHigh(t *testing.T) {
	req := PingDiagRequest{Host: "x", Count: MaxDiagCount + 1}
	assert.Equal(t, ErrDiagInvalidCount, validatePingRequest(&req))
}

func TestValidatePingRequest_TimeoutTooLow(t *testing.T) {
	req := PingDiagRequest{Host: "x", TimeoutMs: 50}
	assert.Equal(t, ErrDiagInvalidTimeout, validatePingRequest(&req))
}

func TestValidatePingRequest_TimeoutTooHigh(t *testing.T) {
	req := PingDiagRequest{Host: "x", TimeoutMs: 999999}
	assert.Equal(t, ErrDiagInvalidTimeout, validatePingRequest(&req))
}

// --- buildPingParameterValues ---

func TestBuildPingParameterValues_Minimal(t *testing.T) {
	req := PingDiagRequest{Host: "8.8.8.8", Count: 4, TimeoutMs: 5000}
	values := buildPingParameterValues(req)
	require.GreaterOrEqual(t, len(values), 4)
	// Last entry must be DiagnosticsState=Requested (the trigger).
	last := values[len(values)-1]
	assert.Contains(t, last[0].(string), "DiagnosticsState")
	assert.Equal(t, "Requested", last[1])
}

func TestBuildPingParameterValues_WithOptionals(t *testing.T) {
	req := PingDiagRequest{
		Host:          "8.8.8.8",
		Count:         4,
		TimeoutMs:     5000,
		DataBlockSize: 64,
		DSCP:          46,
	}
	values := buildPingParameterValues(req)
	// Should include DataBlockSize + DSCP entries.
	foundDB := false
	foundDSCP := false
	for _, v := range values {
		if strings.Contains(v[0].(string), "DataBlockSize") {
			foundDB = true
		}
		if strings.Contains(v[0].(string), "DSCP") {
			foundDSCP = true
		}
	}
	assert.True(t, foundDB)
	assert.True(t, foundDSCP)
}

// --- validateTraceRouteRequest ---

func TestValidateTraceRouteRequest_HappyPath(t *testing.T) {
	req := TraceRouteDiagRequest{Host: "8.8.8.8"}
	assert.Equal(t, "", validateTraceRouteRequest(&req))
	assert.Equal(t, DefaultTraceMaxHops, req.MaxHops)
}

func TestValidateTraceRouteRequest_HostMissing(t *testing.T) {
	req := TraceRouteDiagRequest{}
	assert.Equal(t, ErrDiagInvalidHost, validateTraceRouteRequest(&req))
}

func TestValidateTraceRouteRequest_MaxHopsBad(t *testing.T) {
	req := TraceRouteDiagRequest{Host: "x", MaxHops: -1}
	assert.Equal(t, ErrDiagInvalidCount, validateTraceRouteRequest(&req))
}

func TestValidateTraceRouteRequest_TimeoutBad(t *testing.T) {
	req := TraceRouteDiagRequest{Host: "x", TimeoutMs: 50}
	assert.Equal(t, ErrDiagInvalidTimeout, validateTraceRouteRequest(&req))
}

// --- buildTraceRouteParameterValues ---

func TestBuildTraceRouteParameterValues_Minimal(t *testing.T) {
	req := TraceRouteDiagRequest{Host: "8.8.8.8", MaxHops: 30, TimeoutMs: 5000}
	values := buildTraceRouteParameterValues(req)
	last := values[len(values)-1]
	assert.Contains(t, last[0].(string), "DiagnosticsState")
	assert.Equal(t, "Requested", last[1])
}

func TestBuildTraceRouteParameterValues_WithOptionals(t *testing.T) {
	req := TraceRouteDiagRequest{
		Host:          "8.8.8.8",
		MaxHops:       30,
		TimeoutMs:     5000,
		DataBlockSize: 64,
		DSCP:          46,
	}
	values := buildTraceRouteParameterValues(req)
	foundDB := false
	foundDSCP := false
	for _, v := range values {
		if strings.Contains(v[0].(string), "DataBlockSize") {
			foundDB = true
		}
		if strings.Contains(v[0].(string), "DSCP") {
			foundDSCP = true
		}
	}
	assert.True(t, foundDB)
	assert.True(t, foundDSCP)
}

// --- dispatchPingHandler ---

// diagMockHandler handles the GenieACS NBI device-id projection +
// SetParameterValues task submission for the diag tests.
func diagMockHandler(taskStatus int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/tasks") {
			w.WriteHeader(taskStatus)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestDispatchPingHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, diagMockHandler(http.StatusOK))

	body := `{"host":"8.8.8.8","count":4,"timeout_ms":5000}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/ping/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "Diagnostic task dispatched")
	assert.Contains(t, rr.Body.String(), "IPPingDiagnostics.SuccessCount")
}

func TestDispatchPingHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	body := `{"host":"8.8.8.8"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/ping/192.0.2.99", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDispatchPingHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, diagMockHandler(http.StatusOK))
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/ping/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestDispatchPingHandler_ValidationError(t *testing.T) {
	_, router := setupTestServer(t, diagMockHandler(http.StatusOK))
	body := `{"host":""}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/ping/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestDispatchPingHandler_DispatchFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, diagMockHandler(http.StatusBadGateway))

	body := `{"host":"8.8.8.8"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/ping/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "diagnostic task")
}

// --- dispatchTraceRouteHandler ---

func TestDispatchTraceRouteHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, diagMockHandler(http.StatusOK))

	body := `{"host":"8.8.8.8","max_hops":30,"timeout_ms":5000}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/traceroute/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "TraceRouteDiagnostics")
}

func TestDispatchTraceRouteHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	body := `{"host":"8.8.8.8"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/traceroute/192.0.2.99", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDispatchTraceRouteHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, diagMockHandler(http.StatusOK))
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/traceroute/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestDispatchTraceRouteHandler_ValidationError(t *testing.T) {
	_, router := setupTestServer(t, diagMockHandler(http.StatusOK))
	body := `{"host":""}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/traceroute/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestDispatchTraceRouteHandler_DispatchFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, diagMockHandler(http.StatusBadGateway))

	body := `{"host":"8.8.8.8"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/diag/traceroute/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
