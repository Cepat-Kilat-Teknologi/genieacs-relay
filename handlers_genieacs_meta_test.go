package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handlers_genieacs_meta_test.go covers the L9 tag handler
// (setTagsHandler) and the L10 preset handlers (getPresetHandler,
// putPresetHandler, deletePresetHandler), plus the NBI helper
// functions applyTagsNBI / tagNBICall / presetNBICall /
// presetQueryNBI and the byteSliceReader helper used by preset PUT.
//
// Unlike the other v2.2.0 handlers, these endpoints do NOT talk
// TR-069 — they call the GenieACS NBI directly for device tag
// metadata and provisioning preset CRUD.

// ============================================================
// L9 — tags (GenieACS NBI passthrough)
// ============================================================

func TestValidateTagsRequest_HappyPath(t *testing.T) {
	req := SetTagsRequest{Add: []string{"prod"}, Remove: []string{"dev"}}
	assert.Equal(t, "", validateTagsRequest(&req))
}

func TestValidateTagsRequest_OnlyAdd(t *testing.T) {
	req := SetTagsRequest{Add: []string{"prod"}}
	assert.Equal(t, "", validateTagsRequest(&req))
}

func TestValidateTagsRequest_OnlyRemove(t *testing.T) {
	req := SetTagsRequest{Remove: []string{"dev"}}
	assert.Equal(t, "", validateTagsRequest(&req))
}

func TestValidateTagsRequest_Empty(t *testing.T) {
	req := SetTagsRequest{}
	assert.Equal(t, ErrTagsAddRemoveEmpty, validateTagsRequest(&req))
}

func TestValidateTagsRequest_BadAddName(t *testing.T) {
	req := SetTagsRequest{Add: []string{"bad tag"}}
	assert.Equal(t, ErrTagsInvalidName, validateTagsRequest(&req))
}

func TestValidateTagsRequest_BadRemoveName(t *testing.T) {
	req := SetTagsRequest{Remove: []string{"bad tag"}}
	assert.Equal(t, ErrTagsInvalidName, validateTagsRequest(&req))
}

// tagsMockHandler handles the NBI device-id projection + tag ops
// (POST /devices/{id}/tags/{tag} or DELETE same).
func tagsMockHandler(tagStatus int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.Contains(r.URL.Path, "/tags/") {
			w.WriteHeader(tagStatus)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestSetTagsHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, tagsMockHandler(http.StatusOK))
	body := `{"add":["prod"],"remove":["dev"]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/tags/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestSetTagsHandler_NBIFailure(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, tagsMockHandler(http.StatusInternalServerError))
	body := `{"add":["prod"]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/tags/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestSetTagsHandler_RemoveNBIFailure(t *testing.T) {
	deviceCacheInstance.clearAll()
	// Succeed on POST (add), fail on DELETE (remove)
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	_, router := setupTestServer(t, mock)
	body := `{"add":["prod"],"remove":["dev"]}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/tags/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestSetTagsHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/tags/192.0.2.99", strings.NewReader(`{"add":["prod"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSetTagsHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, tagsMockHandler(http.StatusOK))
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/tags/"+mockDeviceIP, strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSetTagsHandler_Validation(t *testing.T) {
	_, router := setupTestServer(t, tagsMockHandler(http.StatusOK))
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/tags/"+mockDeviceIP, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestTagNBICall_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })

	err := tagNBICall(t.Context(), http.MethodPost, "d", "tag")
	assert.Error(t, err)
}

func TestTagNBICall_NewRequestFailure(t *testing.T) {
	originalBase := geniesBaseURL
	geniesBaseURL = "http://example.com/\x7f"
	t.Cleanup(func() { geniesBaseURL = originalBase })

	err := tagNBICall(t.Context(), http.MethodPost, "d", "tag")
	assert.Error(t, err)
}

// ============================================================
// L10 — presets (NBI passthrough, GET/PUT/DELETE)
// ============================================================

// presetMockHandler handles the /presets/... NBI operations. The
// GenieACS NBI exposes:
//
//   - GET  /presets/?query={"_id":"<name>"} — list query, returns JSON array
//   - PUT  /presets/{id}                    — create/update direct, JSON body
//   - DELETE /presets/{id}                  — delete direct, empty body
//
// Direct `GET /presets/{id}` is NOT supported (NBI returns 405), so
// getPresetHandler wraps the query form via presetQueryNBI.
func presetMockHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/presets/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}
}

func TestGetPresetHandler_Success(t *testing.T) {
	// GenieACS NBI query returns a JSON ARRAY of matching presets.
	// The handler unwraps the array and returns the first entry.
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, `[{"_id":"prod-default","channel":"A"}]`))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/presets/prod-default", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "prod-default")
	assert.Contains(t, rr.Body.String(), `"channel":"A"`)
}

func TestGetPresetHandler_NotFound(t *testing.T) {
	// Empty JSON array → handler returns 404 with "preset not found".
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, `[]`))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/presets/missing", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "preset not found")
}

func TestGetPresetHandler_InvalidName(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, `[]`))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/presets/bad%20name", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestGetPresetHandler_MalformedBody(t *testing.T) {
	// Malformed body (not a JSON array) — handler treats it as
	// empty and returns 404.
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, `{not-json`))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/presets/prod", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGetPresetHandler_NBIError(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusInternalServerError, ""))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/presets/prod", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestGetPresetHandler_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, ""))
	httpClient = &http.Client{Transport: &failingTransport{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/presets/prod", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestPutPresetHandler_Success(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, `{}`))
	body := `{"channel":"A"}`
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/presets/prod", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestPutPresetHandler_InvalidName(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, `{}`))
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/presets/bad%20name", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestPutPresetHandler_EmptyBody(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, `{}`))
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/presets/prod", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestPutPresetHandler_NBIError(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusInternalServerError, ""))
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/genieacs/presets/prod", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestDeletePresetHandler_Success(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, ""))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/genieacs/presets/prod", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusAccepted, rr.Code)
}

func TestDeletePresetHandler_InvalidName(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusOK, ""))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/genieacs/presets/bad%20name", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestDeletePresetHandler_NBIError(t *testing.T) {
	_, router := setupTestServer(t, presetMockHandler(http.StatusInternalServerError, ""))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/genieacs/presets/prod", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- presetNBICall / presetQueryNBI direct NewRequest + transport failure tests ---

func TestPresetNBICall_NewRequestFailure(t *testing.T) {
	originalBase := geniesBaseURL
	geniesBaseURL = "http://example.com/\x7f"
	t.Cleanup(func() { geniesBaseURL = originalBase })

	// PUT/DELETE still flow through presetNBICall; GET uses
	// presetQueryNBI (covered separately below).
	_, _, err := presetNBICall(t.Context(), http.MethodPut, "prod", []byte("{}"))
	assert.Error(t, err)
}

func TestPresetNBICall_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })

	_, _, err := presetNBICall(t.Context(), http.MethodPut, "prod", []byte("{}"))
	assert.Error(t, err)
}

func TestPresetQueryNBI_NewRequestFailure(t *testing.T) {
	originalBase := geniesBaseURL
	geniesBaseURL = "http://example.com/\x7f"
	t.Cleanup(func() { geniesBaseURL = originalBase })

	_, _, err := presetQueryNBI(t.Context(), "prod")
	assert.Error(t, err)
}

func TestPresetQueryNBI_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })

	_, _, err := presetQueryNBI(t.Context(), "prod")
	assert.Error(t, err)
}

// --- byteSliceReader direct test (for 100% coverage) ---

func TestBytesReader(t *testing.T) {
	r := bytesReader([]byte("hello world"))
	buf := make([]byte, 5)
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(buf[:n]))
	n, err = r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, " worl", string(buf[:n]))
	n, err = r.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	// Final read → EOF
	_, err = r.Read(buf)
	assert.Error(t, err)
}

// --- validateTagsRequest JSON decode path sanity ---

func TestTagsResponse_Unmarshal(t *testing.T) {
	var env Response
	body := `{"code":202,"status":"success","data":{"message":"ok","device_id":"d","ip":"1.1.1.1","added":["a"]}}`
	require.NoError(t, json.Unmarshal([]byte(body), &env))
	dataBytes, _ := json.Marshal(env.Data)
	var resp SetTagsResponse
	require.NoError(t, json.Unmarshal(dataBytes, &resp))
	assert.Equal(t, "d", resp.DeviceID)
}
