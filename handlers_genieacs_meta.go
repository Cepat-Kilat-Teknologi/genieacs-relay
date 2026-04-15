package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// handlers_genieacs_meta.go contains the v2.2.0 GenieACS-side metadata
// management endpoints — these do NOT use TR-069 / SetParameterValues
// at all. Instead they call the GenieACS NBI directly to manage
// device tags (L9) and provisioning presets (L10).
//
//	PUT /api/v1/genieacs/tags/{ip}     — L9: add/remove device tags
//	GET /api/v1/genieacs/presets/{name} — L10: read a preset
//	PUT /api/v1/genieacs/presets/{name} — L10: create or update a preset
//	DELETE /api/v1/genieacs/presets/{name} — L10: remove a preset

// --- L9: PUT /tags/{ip} ---

// SetTagsRequest is the body shape for PUT /tags/{ip}.
//
// @Description Tag management — add and remove are both optional but at least one must be non-empty. Tags must match [a-zA-Z0-9_-]{1,64}.
type SetTagsRequest struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// SetTagsResponse is the shape returned by PUT /tags/{ip}.
//
// @Description Tag update response.
type SetTagsResponse struct {
	Message  string   `json:"message"`
	DeviceID string   `json:"device_id"`
	IP       string   `json:"ip"`
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
}

var (
	_ = SetTagsRequest{}
	_ = SetTagsResponse{}
)

// tagNameRegex validates GenieACS tag names: alphanumeric, underscore,
// hyphen, 1-64 chars.
var tagNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// setTagsHandler updates device tags via the GenieACS NBI. Tags are
// metadata only — they don't trigger TR-069 RPCs. Used by ops to
// group devices for bulk operations, alerting, or fleet rollouts.
//
//	@Summary		Add and remove GenieACS device tags
//	@Description	Updates device tags via the GenieACS NBI. Tags are metadata only and don't trigger TR-069 RPCs. Wraps NBI `PUT /devices/{id}/tags/{tag}` and `DELETE /devices/{id}/tags/{tag}`. Tag names must match `[a-zA-Z0-9_-]{1,64}`.
//	@Tags			Metadata
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string			true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetTagsRequest	true	"Tag operations"
//	@Success		202		{object}	Response{data=SetTagsResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/tags/{ip} [put]
func setTagsHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetTagsRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateTagsRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	if err := applyTagsNBI(r.Context(), deviceID, req.Add, req.Remove); err != nil {
		logger.Error("Tags NBI dispatch failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrTagsDispatchFailed)
		return
	}
	sendResponse(w, http.StatusAccepted, SetTagsResponse{
		Message:  MsgTagsUpdated,
		DeviceID: deviceID,
		IP:       getIPParam(r),
		Added:    req.Add,
		Removed:  req.Remove,
	})
}

// validateTagsRequest applies field rules for L9. Pure function.
func validateTagsRequest(req *SetTagsRequest) string {
	if len(req.Add) == 0 && len(req.Remove) == 0 {
		return ErrTagsAddRemoveEmpty
	}
	for _, t := range req.Add {
		if !tagNameRegex.MatchString(t) {
			return ErrTagsInvalidName
		}
	}
	for _, t := range req.Remove {
		if !tagNameRegex.MatchString(t) {
			return ErrTagsInvalidName
		}
	}
	return ""
}

// applyTagsNBI dispatches the add/remove tag operations against the
// GenieACS NBI sequentially. Each tag is one HTTP call:
//   - add:    POST /devices/{id}/tags/{tag}
//   - remove: DELETE /devices/{id}/tags/{tag}
//
// The first failure aborts the operation. Caller sees a partial state
// in that case — there is no transactional rollback because the
// GenieACS NBI doesn't expose one.
func applyTagsNBI(ctx context.Context, deviceID string, add, remove []string) error {
	for _, tag := range add {
		if err := tagNBICall(ctx, http.MethodPost, deviceID, tag); err != nil {
			return fmt.Errorf("add tag %q: %w", tag, err)
		}
	}
	for _, tag := range remove {
		if err := tagNBICall(ctx, http.MethodDelete, deviceID, tag); err != nil {
			return fmt.Errorf("remove tag %q: %w", tag, err)
		}
	}
	return nil
}

// tagNBICall executes one tag NBI request.
func tagNBICall(ctx context.Context, method, deviceID, tag string) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tags/%s",
		geniesBaseURL, url.PathEscape(deviceID), url.PathEscape(tag))
	//nolint:gosec // G107: URL built from trusted internal config (geniesBaseURL)
	req, err := http.NewRequestWithContext(ctx, method, urlQ, http.NoBody)
	if err != nil {
		return err
	}
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set(HeaderXAPIKey, nbiAuthKey)
	}
	// gosec G704: tag name is validated by tagNameRegex in
	// validateTagsRequest AND url.PathEscape'd below, so the
	// SSRF taint is already sanitized before reaching this call.
	//nolint:gosec // G704: validated + path-escaped
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer safeClose(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %s: %s", resp.Status, string(body))
	}
	return nil
}

// --- L10: GET/PUT/DELETE /presets/{name} ---

// PresetResponse is the shape returned by /presets/{name} GET.
//
// @Description GenieACS provisioning preset payload.
type PresetResponse struct {
	Name string                 `json:"name"`
	Body map[string]interface{} `json:"body"`
}

// PresetOperationResponse is the shape returned by PUT/DELETE
// /presets/{name}.
//
// @Description Preset operation response.
type PresetOperationResponse struct {
	Message string `json:"message"`
	Name    string `json:"name"`
}

var (
	_ = PresetResponse{}
	_ = PresetOperationResponse{}
)

// presetNameRegex validates GenieACS preset names.
var presetNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// getPresetHandler reads a single GenieACS provisioning preset by
// name via the NBI.
//
// **GenieACS NBI quirk:** the NBI does NOT support
// `GET /presets/{id}` as a direct path lookup — that method returns
// 405 Method Not Allowed. Instead, reads must use the collection
// query `GET /presets/?query={"_id":"<name>"}` and unwrap the
// resulting JSON array. This handler does that unwrap internally so
// the caller sees a clean GET-by-name API. Empty array → 404.
//
//	@Summary		Read a GenieACS provisioning preset
//	@Description	Reads a single GenieACS provisioning preset by name via the NBI query syntax. Returns the raw preset body as `body`. Returns 404 when no preset with that name exists.
//	@Tags			Metadata
//	@Produce		json
//	@Param			name	path		string	true	"Preset name (alphanumeric, underscore, hyphen, 1-64 chars)"
//	@Success		200		{object}	Response{data=PresetResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/presets/{name} [get]
func getPresetHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !presetNameRegex.MatchString(name) {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrPresetNameInvalid)
		return
	}
	body, status, err := presetQueryNBI(r.Context(), name)
	if err != nil {
		logger.Error("Preset GET failed", zap.String("name", name), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrPresetDispatchFailed)
		return
	}
	if status >= http.StatusBadRequest {
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrPresetDispatchFailed)
		return
	}
	// NBI query returns a JSON array of presets. Empty → 404.
	var raw []map[string]interface{}
	if uErr := json.Unmarshal(body, &raw); uErr != nil {
		// Malformed body — don't blow up, just return empty.
		raw = nil
	}
	if len(raw) == 0 {
		sendError(w, r, http.StatusNotFound, ErrCodeNotFound, "preset not found")
		return
	}
	sendResponse(w, http.StatusOK, PresetResponse{Name: name, Body: raw[0]})
}

// presetQueryNBI executes a `GET /presets/?query={"_id":"<name>"}`
// call against the GenieACS NBI and returns the response body and
// status code. Used by getPresetHandler to work around the NBI's
// lack of direct `GET /presets/{id}` support.
func presetQueryNBI(ctx context.Context, name string) ([]byte, int, error) {
	queryBytes, _ := json.Marshal(map[string]string{"_id": name})
	urlQ := fmt.Sprintf("%s/presets/?query=%s",
		geniesBaseURL, url.QueryEscape(string(queryBytes)))
	//nolint:gosec // G107: URL built from trusted internal config + regex-validated name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlQ, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set(HeaderXAPIKey, nbiAuthKey)
	}
	//nolint:gosec // G704: name is regex-validated + query-escaped above
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer safeClose(resp.Body)
	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, nil
}

// putPresetHandler creates or updates a GenieACS provisioning preset.
//
//	@Summary		Create or update a GenieACS provisioning preset
//	@Description	Creates or updates a GenieACS provisioning preset via the NBI. Body is forwarded as-is.
//	@Tags			Metadata
//	@Accept			json
//	@Produce		json
//	@Param			name	path		string					true	"Preset name (alphanumeric, underscore, hyphen, 1-64 chars)"
//	@Param			body	body		object					true	"Preset body (forwarded as-is to GenieACS NBI)"
//	@Success		202		{object}	Response{data=PresetOperationResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/presets/{name} [put]
func putPresetHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !presetNameRegex.MatchString(name) {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrPresetNameInvalid)
		return
	}
	// Preset bodies can be several KB (genieacs-stack v1.3.0
	// `isp-saas-default.json` is ~6KB with 51 entries). Use the
	// dedicated MaxPresetBodySize cap rather than the 1KB
	// MaxRequestBodySize used for simple WLAN writes.
	bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPresetBodySize))
	if err != nil || len(bodyBytes) == 0 {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrPresetBodyRequired)
		return
	}
	_, status, err := presetNBICall(r.Context(), http.MethodPut, name, bodyBytes)
	if err != nil || status >= http.StatusBadRequest {
		logger.Error("Preset PUT failed", zap.String("name", name), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrPresetDispatchFailed)
		return
	}
	sendResponse(w, http.StatusAccepted, PresetOperationResponse{
		Message: MsgPresetUpdated,
		Name:    name,
	})
}

// deletePresetHandler removes a GenieACS provisioning preset.
//
//	@Summary		Remove a GenieACS provisioning preset
//	@Description	Removes a GenieACS provisioning preset via the NBI.
//	@Tags			Metadata
//	@Produce		json
//	@Param			name	path		string	true	"Preset name (alphanumeric, underscore, hyphen, 1-64 chars)"
//	@Success		202		{object}	Response{data=PresetOperationResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/presets/{name} [delete]
func deletePresetHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if !presetNameRegex.MatchString(name) {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrPresetNameInvalid)
		return
	}
	_, status, err := presetNBICall(r.Context(), http.MethodDelete, name, nil)
	if err != nil || status >= http.StatusBadRequest {
		logger.Error("Preset DELETE failed", zap.String("name", name), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrPresetDispatchFailed)
		return
	}
	sendResponse(w, http.StatusAccepted, PresetOperationResponse{
		Message: MsgPresetUpdated,
		Name:    name,
	})
}

// presetNBICall executes one preset NBI request and returns the
// response body, status code, and transport error if any. Used by
// all three preset handlers.
func presetNBICall(ctx context.Context, method, name string, body []byte) ([]byte, int, error) {
	urlQ := fmt.Sprintf("%s/presets/%s", geniesBaseURL, url.PathEscape(name))
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytesReader(body)
	}
	//nolint:gosec // G107: URL built from trusted internal config (geniesBaseURL)
	req, err := http.NewRequestWithContext(ctx, method, urlQ, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set(HeaderXAPIKey, nbiAuthKey)
	}
	// gosec G704: preset name is validated by presetNameRegex in
	// the handler AND url.PathEscape'd above, so the SSRF taint is
	// already sanitized before reaching this call.
	//nolint:gosec // G704: validated + path-escaped
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer safeClose(resp.Body)
	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, nil
}

// bytesReader is a tiny helper to wrap a []byte as an io.Reader
// without dragging the bytes package import to package main.
func bytesReader(b []byte) io.Reader {
	return &byteSliceReader{b: b}
}

type byteSliceReader struct {
	b   []byte
	pos int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}
