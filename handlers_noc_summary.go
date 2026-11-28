package main

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// nocMCPAuthMiddleware enforces the dedicated NOC_MCP_API_KEY secret for
// internal NOC MCP routes. Always fails closed (503) when NOC_MCP_API_KEY is
// empty so the shared AUTH_KEY / go-gateway credential can never access it.
func nocMCPAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if nocMCPAPIKey == "" {
			sendError(w, r, http.StatusServiceUnavailable, ErrCodeInternal, "NOC MCP endpoint not configured")
			return
		}
		provided := r.Header.Get(HeaderXAPIKey)
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(nocMCPAPIKey)) != 1 {
			sendError(w, r, http.StatusUnauthorized, ErrCodeUnauthorized, "invalid NOC MCP API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NOCRadioSummary is the password-free per-WLAN summary returned by
// GET /api/v1/genieacs/devices/{deviceID}/noc-summary.
type NOCRadioSummary struct {
	WLAN        int    `json:"wlan"`
	Band        string `json:"band,omitempty"`
	Channel     *int   `json:"channel"`
	ClientCount int    `json:"client_count"`
}

// NOCSummaryResponse is the single-read, trimmed CPE diagnostic summary for
// noc-mcp-svc. Pointer fields preserve null (unavailable) separately from 0.
type NOCSummaryResponse struct {
	DeviceID       string            `json:"device_id"`
	Online         bool              `json:"online"`
	LastInform     string            `json:"last_inform,omitempty"`
	Model          string            `json:"model,omitempty"`
	Manufacturer   string            `json:"manufacturer,omitempty"`
	Serial         string            `json:"serial,omitempty"`
	UptimeSeconds  *int              `json:"uptime_seconds"`
	ConnectedHosts *int              `json:"connected_hosts"`
	Radios         []NOCRadioSummary `json:"radios"`
}

// extractDeviceIDParam extracts and validates {deviceID} from
// /devices/{deviceID}/noc-summary without double-unescaping literal '%' sequences.
func extractDeviceIDParam(r *http.Request) (string, bool) {
	raw := ""
	if r.URL.RawPath != "" {
		const prefix = "/devices/"
		const suffix = "/noc-summary"
		if idx := strings.Index(r.URL.RawPath, prefix); idx >= 0 {
			rest := r.URL.RawPath[idx+len(prefix):]
			if end := strings.LastIndex(rest, suffix); end >= 0 {
				unescaped, err := url.PathUnescape(rest[:end])
				if err != nil {
					return "", false
				}
				raw = unescaped
			}
		}
	}
	if raw == "" {
		raw = chi.URLParam(r, "deviceID")
	}
	if raw == "" || len(raw) > 128 {
		return "", false
	}
	if strings.Contains(raw, "..") || strings.ContainsAny(raw, "$") {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", false
		}
	}
	return raw, true
}

// getDeviceNOCSummaryByIDHandler handles GET /api/v1/genieacs/devices/{deviceID}/noc-summary.
func getDeviceNOCSummaryByIDHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := extractDeviceIDParam(r)
	if !ok {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, "invalid device_id")
		return
	}

	// Read uncached: a tree cached by another route may predate the CPE moving
	// to another installation, and noc-mcp-svc checks ownership around this read.
	tree, err := fetchDeviceData(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, errDeviceNotFound) {
			sendError(w, r, http.StatusNotFound, ErrCodeNotFound, ErrDevicesNotFound)
			return
		}
		logger.Error("Failed to read device tree for NOC summary",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrStatusReadFailed)
		return
	}

	resp := buildNOCSummaryResponse(tree, deviceID)
	sendResponse(w, http.StatusOK, resp)
}

// buildNOCSummaryResponse builds a trimmed, password-free NOC summary from a
// single device tree read. Distinguishes missing TR-098 WLAN tables (nil) from
// an observed empty WLAN table (0 hosts / empty slice).
func buildNOCSummaryResponse(tree map[string]interface{}, deviceID string) NOCSummaryResponse {
	status := buildDeviceStatusResponse(tree, deviceID, "")
	resp := NOCSummaryResponse{
		DeviceID:     deviceID,
		Online:       status.Online,
		LastInform:   status.LastInform,
		Model:        status.Model,
		Manufacturer: status.Manufacturer,
	}
	if v, ok := LookupString(tree, "InternetGatewayDevice.DeviceInfo.SerialNumber"); ok {
		resp.Serial = v
	} else if v, ok := LookupString(tree, "Device.DeviceInfo.SerialNumber"); ok {
		resp.Serial = v
	}

	if v, ok := lookupFirstInt(tree,
		"InternetGatewayDevice.DeviceInfo.UpTime",
		"Device.DeviceInfo.UpTime",
	); ok {
		resp.UptimeSeconds = &v
	}

	// TR-181-only devices without a TR-098 WLANConfiguration object leave
	// ConnectedHosts and Radios nil; an object with no instances is an observed
	// empty table and reports 0 hosts and no radios.
	wlanParent := PathWLANConfigRefresh
	if !ObjectExists(tree, wlanParent) {
		return resp
	}
	wlanIDs := EnumerateInstances(tree, wlanParent)
	if len(wlanIDs) == 0 {
		zero := 0
		resp.ConnectedHosts = &zero
		resp.Radios = []NOCRadioSummary{}
		return resp
	}

	clientsResp := buildWifiClientsResponse(tree, deviceID, "")
	statsResp := buildWifiStatsResponse(tree, deviceID, "")

	clientsByWLAN := make(map[int]int, len(wlanIDs))
	for _, c := range clientsResp.Clients {
		clientsByWLAN[c.WLAN]++
	}
	totalHosts := len(clientsResp.Clients)
	resp.ConnectedHosts = &totalHosts

	radios := make([]NOCRadioSummary, 0, len(statsResp.Radios))
	for _, st := range statsResp.Radios {
		radio := NOCRadioSummary{
			WLAN:        st.WLAN,
			Band:        st.Band,
			ClientCount: clientsByWLAN[st.WLAN],
		}
		if st.Channel > 0 {
			ch := st.Channel
			radio.Channel = &ch
		}
		radios = append(radios, radio)
	}
	resp.Radios = radios
	return resp
}
