package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"go.uber.org/zap"
)

// handlers_devices.go contains the v2.2.0 device collection query
// endpoints — the FIRST endpoints in genieacs-relay that do NOT take
// an `{ip}` URL path parameter. They wrap the GenieACS NBI
// `/devices?query=...` call directly to support pagination and
// alternative-key lookup (MAC / serial / PPPoE username) for the
// admin UI device discovery flow.
//
//	GET /api/v1/genieacs/devices         — M4: paginated list with filters
//	GET /api/v1/genieacs/devices/search  — M5: lookup by MAC / serial / username

// DefaultDevicesPageSize is used when the caller doesn't specify
// page_size on the M4 list endpoint.
const DefaultDevicesPageSize = 50

// MaxDevicesPageSize caps the page_size to avoid pulling tens of
// thousands of device documents in one call.
const MaxDevicesPageSize = 200

// DeviceSummary is the per-row shape returned by /devices and
// /devices/search. We don't echo the full device tree here — that's
// what /params/{ip} or /status/{ip} are for; this is a lightweight
// listing view.
//
// @Description Lightweight per-device summary for the list/search endpoints.
type DeviceSummary struct {
	DeviceID     string `json:"device_id"`
	IP           string `json:"ip,omitempty"`
	LastInform   string `json:"last_inform,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	MAC          string `json:"mac,omitempty"`
}

// DevicesListResponse is the shape returned by GET /devices.
//
// @Description Paginated device listing response. Pagination metadata is best-effort: page and page_size echo the request, has_more is true when the current page returned exactly page_size rows (i.e. there might be more on the next page).
type DevicesListResponse struct {
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
	Count    int             `json:"count"`
	HasMore  bool            `json:"has_more"`
	Devices  []DeviceSummary `json:"devices"`
}

// DeviceSearchResponse is the shape returned by GET /devices/search.
//
// @Description Single-device search result. Returns the matching device or 404.
type DeviceSearchResponse struct {
	Device DeviceSummary `json:"device"`
}

var (
	_ = DeviceSummary{}
	_ = DevicesListResponse{}
	_ = DeviceSearchResponse{}
)

// listDevicesHandler returns a paginated list of devices known to the
// GenieACS NBI. Optional filters: model, online (last inform within 3x
// stale threshold), pppoe_username (substring match).
//
//	@Summary		List devices (paginated)
//	@Description	Returns a paginated list of devices known to GenieACS. Optional filters: model, online, pppoe_username (substring). Used by the admin UI device discovery flow. Pagination metadata: page, page_size, count (rows in this page), has_more (true when count == page_size).
//	@Tags			Devices
//	@Produce		json
//	@Param			page			query		int		false	"Page number (1-indexed)"	default(1)
//	@Param			page_size		query		int		false	"Rows per page (1-200)"		default(50)
//	@Param			model			query		string	false	"Filter by model substring (e.g. F670L)"
//	@Param			online			query		bool	false	"Only include devices that are currently online"
//	@Param			pppoe_username	query		string	false	"Filter by PPPoE username substring"
//	@Success		200				{object}	Response{data=DevicesListResponse}
//	@Failure		400				{object}	Response
//	@Failure		401				{object}	Response
//	@Failure		429				{object}	Response
//	@Failure		500				{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/devices [get]
func listDevicesHandler(w http.ResponseWriter, r *http.Request) {
	page, pageSize, ok := parseDevicesPagination(w, r)
	if !ok {
		return
	}

	filter := buildDevicesListFilter(r)
	skip := (page - 1) * pageSize

	devices, err := queryDevicesNBI(r.Context(), filter, pageSize, skip)
	if err != nil {
		logger.Error("Devices query failed", zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrDevicesQueryFailed)
		return
	}

	resp := DevicesListResponse{
		Page:     page,
		PageSize: pageSize,
		Count:    len(devices),
		HasMore:  len(devices) == pageSize,
		Devices:  devices,
	}
	sendResponse(w, http.StatusOK, resp)
}

// parseDevicesPagination reads the page and page_size query params,
// applying defaults and returning a 400 with a clear error message on
// invalid input.
func parseDevicesPagination(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	page := 1
	if v := r.URL.Query().Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrDevicesPageInvalid)
			return 0, 0, false
		}
		page = n
	}
	pageSize := DefaultDevicesPageSize
	if v := r.URL.Query().Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxDevicesPageSize {
			sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrDevicesPageSizeInvalid)
			return 0, 0, false
		}
		pageSize = n
	}
	return page, pageSize, true
}

// buildDevicesListFilter constructs the GenieACS NBI MongoDB-style
// filter expression for the /devices endpoint based on the query
// parameters.
//
// Returns a `map[string]interface{}` rather than a typed struct so the
// JSON shape can mirror MongoDB's operator syntax (`$regex`, `$gt`).
// Pure function for unit testability.
func buildDevicesListFilter(r *http.Request) map[string]interface{} {
	filter := map[string]interface{}{}
	if v := r.URL.Query().Get("model"); v != "" {
		filter["InternetGatewayDevice.DeviceInfo.ModelName._value"] = map[string]interface{}{
			"$regex": v,
		}
	}
	if v := r.URL.Query().Get("pppoe_username"); v != "" {
		filter["InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username._value"] = map[string]interface{}{
			"$regex": v,
		}
	}
	if r.URL.Query().Get("online") == BoolStrTrue && staleThreshold > 0 {
		// "Online" = last inform within 3x the stale threshold.
		// MongoDB needs an ISO-8601 string + an `$gt` operator. The
		// GenieACS NBI accepts these directly.
		cutoffSeconds := int64(3 * staleThreshold.Seconds())
		filter["_lastInform"] = map[string]interface{}{
			"$gt": fmt.Sprintf("$Date(now-%ds)", cutoffSeconds),
		}
	}
	return filter
}

// queryDevicesNBI executes the GenieACS NBI `/devices?query=...&limit=...&skip=...`
// call and decodes the response into DeviceSummary structs. The
// projection is hardcoded to the lightweight set of identification +
// last_inform fields so we don't pull megabytes of device tree per
// listing call.
func queryDevicesNBI(ctx context.Context, filter map[string]interface{}, limit, skip int) ([]DeviceSummary, error) {
	queryBytes, _ := json.Marshal(filter)
	projection := "_id,_lastInform," +
		"InternetGatewayDevice.DeviceInfo.Manufacturer," +
		"InternetGatewayDevice.DeviceInfo.ModelName," +
		"InternetGatewayDevice.DeviceInfo.SerialNumber," +
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress," +
		"InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress"

	urlQ := fmt.Sprintf("%s/devices/?query=%s&projection=%s&limit=%d&skip=%d",
		geniesBaseURL,
		url.QueryEscape(string(queryBytes)),
		url.QueryEscape(projection),
		limit,
		skip,
	)
	//nolint:gosec // G107: URL built from trusted internal config (geniesBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlQ, http.NoBody)
	if err != nil {
		return nil, err
	}
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set(HeaderXAPIKey, nbiAuthKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer safeClose(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GenieACS devices query failed with status %s: %s", resp.Status, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make([]DeviceSummary, 0, len(raw))
	for _, doc := range raw {
		out = append(out, deviceSummaryFromTree(doc))
	}
	return out, nil
}

// deviceSummaryFromTree builds a DeviceSummary from a partial device
// document returned by the GenieACS NBI projection.
func deviceSummaryFromTree(doc map[string]interface{}) DeviceSummary {
	d := DeviceSummary{}
	if v, ok := doc["_id"].(string); ok {
		d.DeviceID = v
	}
	if v, ok := doc["_lastInform"].(string); ok {
		d.LastInform = v
	}
	if v, ok := LookupString(doc, "InternetGatewayDevice.DeviceInfo.Manufacturer"); ok {
		d.Manufacturer = v
	}
	if v, ok := LookupString(doc, "InternetGatewayDevice.DeviceInfo.ModelName"); ok {
		d.Model = v
	}
	if v, ok := LookupString(doc, "InternetGatewayDevice.DeviceInfo.SerialNumber"); ok {
		d.Serial = v
	}
	if v, ok := LookupString(doc,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress"); ok {
		d.IP = v
	}
	if v, ok := LookupString(doc,
		"InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress"); ok {
		d.MAC = v
	}
	return d
}

// --- M5: GET /devices/search ---

// searchDevicesHandler looks up a single device by alternative key:
// MAC address, serial number, or PPPoE username. Returns 404 if no
// device matches. Used in the customer onboarding flow when the IP
// is not yet known.
//
//	@Summary		Search for a device by alternative key
//	@Description	Looks up a single device by MAC address, serial number, or PPPoE username. Exactly one of the three query params must be provided. Returns 404 if no device matches. Used in the customer onboarding flow when the IP is not yet known.
//	@Tags			Devices
//	@Produce		json
//	@Param			mac				query		string	false	"MAC address (case-insensitive, AA:BB:CC:DD:EE:FF format)"
//	@Param			serial			query		string	false	"Serial number from device info"
//	@Param			pppoe_username	query		string	false	"PPPoE username (exact match)"
//	@Success		200				{object}	Response{data=DeviceSearchResponse}
//	@Failure		400				{object}	Response
//	@Failure		401				{object}	Response
//	@Failure		404				{object}	Response
//	@Failure		429				{object}	Response
//	@Failure		500				{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/devices/search [get]
func searchDevicesHandler(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Query().Get("mac")
	serial := r.URL.Query().Get("serial")
	pppoe := r.URL.Query().Get("pppoe_username")
	if mac == "" && serial == "" && pppoe == "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrDevicesSearchKeyMissing)
		return
	}

	filter := buildDevicesSearchFilter(mac, serial, pppoe)
	devices, err := queryDevicesNBI(r.Context(), filter, 1, 0)
	if err != nil {
		logger.Error("Devices search query failed", zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrDevicesQueryFailed)
		return
	}
	if len(devices) == 0 {
		sendError(w, r, http.StatusNotFound, ErrCodeNotFound, ErrDevicesNotFound)
		return
	}
	sendResponse(w, http.StatusOK, DeviceSearchResponse{Device: devices[0]})
}

// buildDevicesSearchFilter builds a MongoDB-style filter for the
// /devices/search endpoint. Pure function for unit testability.
//
// Precedence: mac → serial → pppoe_username. Only the first non-empty
// key produces a filter clause; the other two are ignored.
func buildDevicesSearchFilter(mac, serial, pppoe string) map[string]interface{} {
	if mac != "" {
		return map[string]interface{}{
			"InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress._value": mac,
		}
	}
	if serial != "" {
		return map[string]interface{}{
			"InternetGatewayDevice.DeviceInfo.SerialNumber._value": serial,
		}
	}
	return map[string]interface{}{
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username._value": pppoe,
	}
}
