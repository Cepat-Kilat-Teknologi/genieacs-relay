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

// handlers_portforward_test.go covers the L1 port forwarding handler
// (setPortForwardingHandler) + its pure helpers validatePortForwardingRequest,
// validatePortForwardRule, and buildPortForwardingParameterValues.

// validPortRule returns a happy-path rule used as a baseline for
// validation and parameter-value construction tests.
func validPortRule() PortForwardRule {
	return PortForwardRule{
		Index:        1,
		Name:         "ssh",
		Protocol:     "tcp",
		ExternalPort: 2222,
		InternalIP:   "192.168.1.100",
		InternalPort: 22,
		Enabled:      true,
	}
}

// --- validatePortForwardingRequest / validatePortForwardRule ---

func TestValidatePortForwardingRequest_HappyPath(t *testing.T) {
	req := SetPortForwardingRequest{Rules: []PortForwardRule{validPortRule()}}
	assert.Equal(t, "", validatePortForwardingRequest(&req))
}

func TestValidatePortForwardingRequest_Empty(t *testing.T) {
	req := SetPortForwardingRequest{}
	assert.Equal(t, ErrPortFwdRulesEmpty, validatePortForwardingRequest(&req))
}

func TestValidatePortForwardingRequest_TooMany(t *testing.T) {
	req := SetPortForwardingRequest{Rules: make([]PortForwardRule, MaxPortForwardRules+1)}
	for i := range req.Rules {
		req.Rules[i] = validPortRule()
		req.Rules[i].Index = i + 1
	}
	assert.Equal(t, ErrPortFwdRulesTooMany, validatePortForwardingRequest(&req))
}

func TestValidatePortForwardRule_BadIndex(t *testing.T) {
	rule := validPortRule()
	rule.Index = 0
	req := SetPortForwardingRequest{Rules: []PortForwardRule{rule}}
	assert.Equal(t, ErrPortFwdRulesTooMany, validatePortForwardingRequest(&req))
}

func TestValidatePortForwardRule_BadProtocol(t *testing.T) {
	rule := validPortRule()
	rule.Protocol = "icmp"
	req := SetPortForwardingRequest{Rules: []PortForwardRule{rule}}
	assert.Equal(t, ErrPortFwdInvalidProto, validatePortForwardingRequest(&req))
}

func TestValidatePortForwardRule_BadExtPort(t *testing.T) {
	rule := validPortRule()
	rule.ExternalPort = 0
	req := SetPortForwardingRequest{Rules: []PortForwardRule{rule}}
	assert.Equal(t, ErrPortFwdInvalidPort, validatePortForwardingRequest(&req))
}

func TestValidatePortForwardRule_BadIntPort(t *testing.T) {
	rule := validPortRule()
	rule.InternalPort = 99999
	req := SetPortForwardingRequest{Rules: []PortForwardRule{rule}}
	assert.Equal(t, ErrPortFwdInvalidPort, validatePortForwardingRequest(&req))
}

func TestValidatePortForwardRule_BadIP(t *testing.T) {
	rule := validPortRule()
	rule.InternalIP = "not-an-ip"
	req := SetPortForwardingRequest{Rules: []PortForwardRule{rule}}
	assert.Equal(t, ErrPortFwdInvalidIP, validatePortForwardingRequest(&req))
}

func TestValidatePortForwardRule_BadWANInstance(t *testing.T) {
	rule := validPortRule()
	rule.WANInstance = 99
	req := SetPortForwardingRequest{Rules: []PortForwardRule{rule}}
	assert.Equal(t, ErrPPPoEInvalidWanInstance, validatePortForwardingRequest(&req))
}

// --- buildPortForwardingParameterValues ---

func TestBuildPortForwardingParameterValues_Basic(t *testing.T) {
	values := buildPortForwardingParameterValues([]PortForwardRule{validPortRule()})
	// 5 standard fields + 1 description = 6
	assert.Len(t, values, 6)
}

func TestBuildPortForwardingParameterValues_NoName(t *testing.T) {
	rule := validPortRule()
	rule.Name = ""
	values := buildPortForwardingParameterValues([]PortForwardRule{rule})
	assert.Len(t, values, 5)
}

func TestBuildPortForwardingParameterValues_UDPProtocol(t *testing.T) {
	rule := validPortRule()
	rule.Protocol = "udp"
	rule.Name = ""
	values := buildPortForwardingParameterValues([]PortForwardRule{rule})
	for _, v := range values {
		if strings.Contains(v[0].(string), "PortMappingProtocol") {
			assert.Equal(t, "UDP", v[1])
			return
		}
	}
	t.Fatal("protocol entry not found")
}

func TestBuildPortForwardingParameterValues_BothProtocol(t *testing.T) {
	rule := validPortRule()
	rule.Protocol = "BOTH"
	rule.Name = ""
	values := buildPortForwardingParameterValues([]PortForwardRule{rule})
	for _, v := range values {
		if strings.Contains(v[0].(string), "PortMappingProtocol") {
			assert.Equal(t, "TCP AND UDP", v[1])
			return
		}
	}
	t.Fatal("protocol entry not found")
}

// --- setPortForwardingHandler ---

func TestSetPortForwardingHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())
	body := `{"rules":[{"index":1,"name":"ssh","protocol":"tcp","external_port":2222,"internal_ip":"192.168.1.100","internal_port":22,"enabled":true}]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/port-forwarding/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetPortForwardingHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/port-forwarding/192.0.2.99", strings.NewReader(`{"rules":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetPortForwardingHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/port-forwarding/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetPortForwardingHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/port-forwarding/"+mockDeviceIP, strings.NewReader(`{"rules":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetPortForwardingHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()
	originalPool := taskWorkerPool
	t.Cleanup(func() { taskWorkerPool = originalPool })
	_, router := setupTestServer(t, pppoeMockHandler())
	taskWorkerPool.Stop()
	taskWorkerPool = &workerPool{queue: make(chan task, 0), wg: sync.WaitGroup{}}
	body := `{"rules":[{"index":1,"protocol":"tcp","external_port":22,"internal_ip":"192.168.1.1","internal_port":22,"enabled":true}]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/port-forwarding/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// require import needed for one assertion branch below (keeps import list compile-clean)
var _ = require.NoError
