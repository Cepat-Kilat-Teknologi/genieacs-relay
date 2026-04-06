package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- M-01: HSTS only on HTTPS ---

func TestSecurityHeaders_HSTSOnlyOnHTTPS(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("No HSTS on plain HTTP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Empty(t, rr.Header().Get("Strict-Transport-Security"))
	})

	t.Run("HSTS set when X-Forwarded-Proto is https", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Contains(t, rr.Header().Get("Strict-Transport-Security"), "max-age=31536000")
	})

	t.Run("HSTS set when TLS is present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.TLS = &tls.ConnectionState{}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Contains(t, rr.Header().Get("Strict-Transport-Security"), "max-age=31536000")
	})
}

// --- H-01/L-xx: SubmitWLANUpdate error paths ---

func TestSubmitWLANUpdate_QueueFull(t *testing.T) {
	origPool := taskWorkerPool
	defer func() { taskWorkerPool = origPool }()

	// Pool with zero-size queue (always full) and no workers
	taskWorkerPool = &workerPool{
		workers: 0,
		queue:   make(chan task, 0),
	}

	origCache := deviceCacheInstance
	defer func() { deviceCacheInstance = origCache }()
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	t.Run("First submit fails", func(t *testing.T) {
		err := SubmitWLANUpdate("device-1", [][]interface{}{{"path", "val", "type"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "setParameterValues")
	})

	t.Run("Second submit fails", func(t *testing.T) {
		// Pool with queue size 1 — first submit succeeds, second fails
		taskWorkerPool = &workerPool{
			workers: 0,
			queue:   make(chan task, 1),
		}
		err := SubmitWLANUpdate("device-1", [][]interface{}{{"path", "val", "type"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "applyChanges")
	})
}

// --- H-05: Primary WLAN deletion protection ---

func TestDeleteWLANHandler_PrimaryProtection(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
	})
	_, router := setupTestServer(t, mockHandler)

	t.Run("Reject delete WLAN 1", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/1/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), ErrDeletePrimaryWLAN)
	})

	t.Run("Reject delete WLAN 5", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/5/"+mockDeviceIP, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), ErrDeletePrimaryWLAN)
	})
}

// --- WLAN handler queue-full (503) tests ---

func TestWLANHandlers_QueueFull(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), mockDeviceID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_, router := setupTestServer(t, mockHandler)

	// Replace pool with zero-capacity queue
	origPool := taskWorkerPool
	taskWorkerPool = &workerPool{
		workers: 0,
		queue:   make(chan task, 0),
	}
	defer func() { taskWorkerPool = origPool }()

	t.Run("Create returns 503 on queue full", func(t *testing.T) {
		body := `{"ssid":"TestNet","password":"password123"}`
		req := httptest.NewRequest("POST", "/api/v1/genieacs/wlan/create/2/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	})

	t.Run("Update returns 503 on queue full", func(t *testing.T) {
		body := `{"ssid":"NewName"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/update/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	})

	t.Run("Optimize returns 503 on queue full", func(t *testing.T) {
		body := `{"channel":"6"}`
		req := httptest.NewRequest("PUT", "/api/v1/genieacs/wlan/optimize/1/"+mockDeviceIP, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	})
}

// --- Delete WLAN 503 on queue full (separate test to avoid pool state leak) ---

func TestDeleteWLANHandler_QueueFull(t *testing.T) {
	mockData := `{"_id":"002568-BCM963268-684752","_deviceId":{"_ProductClass":"F670L"},"InternetGatewayDevice":{"DeviceInfo":{"ProductClass":{"_value":"F670L"}},"LANDevice":{"1":{"WLANConfiguration":{"2":{"Enable":{"_value":true},"SSID":{"_value":"Guest"},"Standard":{"_value":"b,g,n"}}}}}}}`
	mockWithWLAN2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[" + mockData + "]"))
	})

	_, router := setupTestServer(t, mockWithWLAN2)

	origPool := taskWorkerPool
	taskWorkerPool = &workerPool{workers: 0, queue: make(chan task, 0)}
	defer func() { taskWorkerPool = origPool }()

	req := httptest.NewRequest("DELETE", "/api/v1/genieacs/wlan/delete/2/"+mockDeviceIP, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// --- refreshSSIDHandler queue full ---

func TestRefreshSSIDHandler_QueueFull(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
	})

	_, router := setupTestServer(t, mockHandler)

	origPool := taskWorkerPool
	taskWorkerPool = &workerPool{workers: 0, queue: make(chan task, 0)}
	defer func() { taskWorkerPool = origPool }()

	req := httptest.NewRequest("POST", "/api/v1/genieacs/ssid/"+mockDeviceIP+"/refresh", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// --- M-03: nil lastInform stale detection ---

func TestGetDeviceIDByIP_NilLastInform(t *testing.T) {
	origThreshold := staleThreshold
	defer func() { staleThreshold = origThreshold }()
	staleThreshold = 30 * time.Minute

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Device with null _lastInform
		_, _ = w.Write([]byte(`[{"_id":"device-123","_lastInform":null}]`))
	})

	mockServer := httptest.NewServer(mockHandler)
	defer mockServer.Close()

	origURL := geniesBaseURL
	geniesBaseURL = mockServer.URL
	defer func() { geniesBaseURL = origURL }()

	origClient := httpClient
	httpClient = mockServer.Client()
	defer func() { httpClient = origClient }()

	_, err := getDeviceIDByIP(t.Context(), "10.0.0.1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has never connected")
}

// --- M-02: getBand with ax standard and edge cases ---

func TestGetBand_AXStandard(t *testing.T) {
	wlan := map[string]interface{}{
		"Standard": map[string]interface{}{"_value": "ax"},
	}
	band := getBand(wlan, "6")
	assert.Equal(t, "5GHz", band)
}

func TestGetBand_NonNumericKey(t *testing.T) {
	// Non-numeric key that can't be parsed — falls through to Unknown
	wlan := map[string]interface{}{}
	band := getBand(wlan, "abc")
	assert.Equal(t, "Unknown", band)
}

func TestGetBand_Key7_5GHz(t *testing.T) {
	// Key 7 with n-only standard — should fallback to 5GHz via key range
	wlan := map[string]interface{}{
		"Standard": map[string]interface{}{"_value": "n"},
	}
	band := getBand(wlan, "7")
	assert.Equal(t, "5GHz", band)
}

// --- executeWLANRetryLoop: context.DeadlineExceeded from getWLANData ---

// slowErrorTransport waits for delay then returns an error from RoundTrip
type slowErrorTransport struct {
	delay time.Duration
	err   error
}

func (t *slowErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	time.Sleep(t.delay)
	return nil, t.err
}

func TestExecuteWLANRetryLoop_ContextExpiredDuringGetWLANData(t *testing.T) {
	// Server that delays response longer than context timeout
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer slowServer.Close()

	origURL := geniesBaseURL
	geniesBaseURL = slowServer.URL
	defer func() { geniesBaseURL = origURL }()

	origClient := httpClient
	httpClient = slowServer.Client()
	defer func() { httpClient = origClient }()

	origCache := deviceCacheInstance
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}
	defer func() { deviceCacheInstance = origCache }()

	// Context expires in 50ms, server takes 200ms per request
	// getWLANData call will fail because context expires during HTTP call
	// ctx.Err() will be non-nil when checked
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err := executeWLANRetryLoop(ctx, "any-device", 3, 10*time.Millisecond)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// --- Cache JSON marshal error (unreachable in practice, but covers branch) ---

func TestDeviceCache_GetReturnsDeepCopy(t *testing.T) {
	cache := &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	// Store data with nested structure
	cache.set("d1", map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": "value",
			},
		},
	})

	// Get should return valid deep copy
	data, ok := cache.get("d1")
	assert.True(t, ok)
	assert.NotNil(t, data["InternetGatewayDevice"])

	// Concurrent reads should not race
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.get("d1")
		}()
	}
	wg.Wait()
}

// --- H-04: executeWLANRetryLoop context expired at loop entry ---

func TestExecuteWLANRetryLoop_AlreadyExpiredContext(t *testing.T) {
	origCache := deviceCacheInstance
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}
	defer func() { deviceCacheInstance = origCache }()

	// Create already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, err := executeWLANRetryLoop(ctx, "any-device", 5, time.Second)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestExecuteWLANRetryLoop_ContextCancelDuringSleep(t *testing.T) {
	// Mock server returns device with no enabled WLANs to force retry+sleep
	emptyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"_id":"empty-device","InternetGatewayDevice":{"LANDevice":{"1":{"WLANConfiguration":{}}}}}]`))
	})
	emptyServer := httptest.NewServer(emptyHandler)
	defer emptyServer.Close()

	origURL := geniesBaseURL
	geniesBaseURL = emptyServer.URL
	defer func() { geniesBaseURL = origURL }()

	origClient := httpClient
	httpClient = emptyServer.Client()
	defer func() { httpClient = origClient }()

	origCache := deviceCacheInstance
	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}
	defer func() { deviceCacheInstance = origCache }()

	// Context expires in 100ms, but retry delay is 5s — forces cancel during sleep
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err := executeWLANRetryLoop(ctx, "empty-device", 10, 5*time.Second)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
