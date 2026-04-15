package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// handlers_lifecycle_test.go covers the v2.2.0 CPE lifecycle handlers:
// factoryResetDeviceHandler (H6) and wakeDeviceHandler (H2).
//
// Both handlers are thin wrappers over the tr069.go RPC dispatchers,
// so the tests mainly exercise the handler glue: device ID lookup,
// error response classification, and success response shape.

// --- factoryResetDeviceHandler (H6) ---

func TestFactoryResetDeviceHandler_Success(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Step 1: device ID lookup (NBI projection query)
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Step 2: factoryReset task submission
		if strings.HasSuffix(r.URL.Path, "/tasks") &&
			strings.Contains(r.URL.RawQuery, "connection_request") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/factory-reset/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "FactoryReset task submitted")
}

func TestFactoryResetDeviceHandler_DeviceNotFound(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/factory-reset/192.0.2.99", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestFactoryResetDeviceHandler_TaskSubmissionFails(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		// Task submission fails with 500
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("nbi error"))
	})
	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/factory-reset/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "FactoryReset task submission failed")
}

// --- wakeDeviceHandler (H2) ---

func TestWakeDeviceHandler_Success(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/tasks") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/wake/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "ConnectionRequest dispatched")
}

func TestWakeDeviceHandler_DeviceNotFound(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/wake/192.0.2.99", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestWakeDeviceHandler_DispatchFails(t *testing.T) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	})
	_, router := setupTestServer(t, mockHandler)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/wake/"+mockDeviceIP, nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "ConnectionRequest dispatch failed")
}
