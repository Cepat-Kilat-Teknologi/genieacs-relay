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

// handlers_pppoe_test.go covers the v2.2.0 PPPoE credential handler
// (H3) and its pure helper functions validatePPPoERequest and
// buildPPPoEParameterValues.

// --- validatePPPoERequest ---

func TestValidatePPPoERequest_HappyPath(t *testing.T) {
	req := SetPPPoERequest{
		Username: "pppoe-customer-001",
		Password: "secret-pass",
	}
	errMsg := validatePPPoERequest(&req)
	assert.Equal(t, "", errMsg)
	assert.Equal(t, 1, req.WANInstance, "wan_instance defaults to 1 when 0")
}

func TestValidatePPPoERequest_HappyPath_ExplicitInstance(t *testing.T) {
	req := SetPPPoERequest{
		Username:    "user",
		Password:    "pass",
		WANInstance: 3,
	}
	errMsg := validatePPPoERequest(&req)
	assert.Equal(t, "", errMsg)
	assert.Equal(t, 3, req.WANInstance)
}

func TestValidatePPPoERequest_UsernameEmpty(t *testing.T) {
	req := SetPPPoERequest{Password: "pass"}
	errMsg := validatePPPoERequest(&req)
	assert.Equal(t, ErrPPPoEUsernameRequired, errMsg)
}

func TestValidatePPPoERequest_PasswordEmpty(t *testing.T) {
	req := SetPPPoERequest{Username: "user"}
	errMsg := validatePPPoERequest(&req)
	assert.Equal(t, ErrPPPoEPasswordRequired, errMsg)
}

func TestValidatePPPoERequest_UsernameTooLong(t *testing.T) {
	req := SetPPPoERequest{
		Username: strings.Repeat("u", PPPoEMaxFieldLength+1),
		Password: "pass",
	}
	errMsg := validatePPPoERequest(&req)
	assert.Equal(t, ErrPPPoEUsernameTooLong, errMsg)
}

func TestValidatePPPoERequest_PasswordTooLong(t *testing.T) {
	req := SetPPPoERequest{
		Username: "user",
		Password: strings.Repeat("p", PPPoEMaxFieldLength+1),
	}
	errMsg := validatePPPoERequest(&req)
	assert.Equal(t, ErrPPPoEPasswordTooLong, errMsg)
}

func TestValidatePPPoERequest_UsernameWhitespace(t *testing.T) {
	cases := []string{
		"user with space",
		"user\twith\ttab",
		"user\nwith\nnewline",
		"user\rwith\rcr",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			req := SetPPPoERequest{Username: u, Password: "pass"}
			errMsg := validatePPPoERequest(&req)
			assert.Equal(t, ErrPPPoEUsernameWhitespace, errMsg)
		})
	}
}

func TestValidatePPPoERequest_InvalidWANInstance(t *testing.T) {
	cases := []int{-1, 9, 100}
	for _, n := range cases {
		req := SetPPPoERequest{
			Username:    "user",
			Password:    "pass",
			WANInstance: n,
		}
		errMsg := validatePPPoERequest(&req)
		assert.Equal(t, ErrPPPoEInvalidWanInstance, errMsg)
	}
}

func TestValidatePPPoERequest_BoundaryWANInstance(t *testing.T) {
	for _, n := range []int{1, PPPoEMaxWANInstance} {
		req := SetPPPoERequest{
			Username:    "user",
			Password:    "pass",
			WANInstance: n,
		}
		errMsg := validatePPPoERequest(&req)
		assert.Equal(t, "", errMsg)
	}
}

// --- buildPPPoEParameterValues ---

func TestBuildPPPoEParameterValues_Default(t *testing.T) {
	values := buildPPPoEParameterValues("user", "pass", 1)
	require.Len(t, values, 2)
	assert.Equal(t,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
		values[0][0])
	assert.Equal(t, "user", values[0][1])
	assert.Equal(t, XSDString, values[0][2])
	assert.Equal(t,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password",
		values[1][0])
	assert.Equal(t, "pass", values[1][1])
	assert.Equal(t, XSDString, values[1][2])
}

func TestBuildPPPoEParameterValues_NonDefaultInstance(t *testing.T) {
	values := buildPPPoEParameterValues("u", "p", 3)
	require.Len(t, values, 2)
	assert.Contains(t, values[0][0], "WANDevice.3.")
	assert.Contains(t, values[1][0], "WANDevice.3.")
}

// --- setPPPoECredentialsHandler ---

// pppoeMockHandler handles the device-id projection lookup but the
// actual setParameterValues task is dispatched via the worker pool
// (asynchronously), so the mock doesn't need to handle it for the
// happy-path test — the handler returns 202 as soon as the task is
// queued, regardless of task completion.
func pppoeMockHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Worker pool task submission — return success.
		w.WriteHeader(http.StatusOK)
	}
}

func TestSetPPPoECredentialsHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, pppoeMockHandler())

	body := `{"username":"pppoe-customer-001","password":"secret-pass"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/pppoe/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "PPPoE credentials updated")
	assert.Contains(t, rr.Body.String(), `"wan_instance":1`)
}

func TestSetPPPoECredentialsHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)

	body := `{"username":"u","password":"p"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/pppoe/192.0.2.99", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetPPPoECredentialsHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())

	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/pppoe/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetPPPoECredentialsHandler_ValidationFailure(t *testing.T) {
	_, router := setupTestServer(t, pppoeMockHandler())

	body := `{"username":"","password":"p"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/pppoe/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "PPPoE username is required")
}

func TestSetPPPoECredentialsHandler_WorkerPoolFull(t *testing.T) {
	deviceCacheInstance.clearAll()

	// Replace the package-level worker pool with one that has zero
	// queue capacity and is NOT started, so any Submit call returns
	// false (queue is "full" because there's no consumer).
	originalPool := taskWorkerPool
	taskWorkerPool = &workerPool{
		workers: 0,
		queue:   make(chan task, 0),
		wg:      sync.WaitGroup{},
	}
	t.Cleanup(func() { taskWorkerPool = originalPool })

	_, router := setupTestServer(t, pppoeMockHandler())
	// setupTestServer overwrites taskWorkerPool back to a fresh pool;
	// re-set ours after to ensure the SubmitWLANUpdate sees the
	// queue-full state.
	taskWorkerPool.Stop() // stop the one setupTestServer started
	taskWorkerPool = &workerPool{
		workers: 0,
		queue:   make(chan task, 0),
		wg:      sync.WaitGroup{},
	}

	body := `{"username":"u","password":"p"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/pppoe/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "PPPoE credential update task")
}
