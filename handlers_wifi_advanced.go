package main

import (
	"net/http"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// handlers_wifi_advanced.go contains the v2.2.0 advanced WiFi
// configuration endpoints — wifi schedule (L4) and MAC filter (L5).
// Both are vendor-specific in real CPEs; v2.2.0 ships the most common
// path family and surfaces vendor incompatibility as a 503 from the
// GenieACS layer. v2.3.0 will add vendor detection.

// --- L4: PUT /wifi-schedule/{ip} ---

// WifiScheduleEntry is one entry in the schedules array.
//
// @Description WiFi schedule entry — day of week (0=Sun..6=Sat), start_time / end_time HH:MM, enabled flag.
type WifiScheduleEntry struct {
	Day       int    `json:"day"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Enabled   bool   `json:"enabled"`
}

// SetWifiScheduleRequest is the body shape for PUT /wifi-schedule/{ip}.
//
// @Description WiFi schedule update — list of per-day on/off windows. wlan_index defaults to 1.
type SetWifiScheduleRequest struct {
	Schedules []WifiScheduleEntry `json:"schedules"`
	WLANIndex int                 `json:"wlan_index,omitempty"`
}

// SetWifiScheduleResponse is the shape returned by PUT /wifi-schedule/{ip}.
//
// @Description WiFi schedule update response.
type SetWifiScheduleResponse struct {
	Message   string `json:"message"`
	DeviceID  string `json:"device_id"`
	IP        string `json:"ip"`
	Count     int    `json:"count"`
	WLANIndex int    `json:"wlan_index"`
}

var (
	_ = WifiScheduleEntry{}
	_ = SetWifiScheduleRequest{}
	_ = SetWifiScheduleResponse{}
)

// MaxWifiScheduleEntries caps the number of schedule entries per
// request. 14 = 2 windows per day for 7 days.
const MaxWifiScheduleEntries = 14

// timeHHMMRegex validates the HH:MM time format used by schedule
// start/end fields.
var timeHHMMRegex = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// setWifiScheduleHandler updates the WiFi schedule on the CPE via
// TR-069 SetParameterValues.
//
//	@Summary		Set WiFi schedule (parental control)
//	@Description	Updates the WiFi schedule (parental control) on the CPE via TR-069 SetParameterValues. Vendor variation is wide; v2.2.0 uses the most common vendor extension path family.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetWifiScheduleRequest	true	"WiFi schedule entries"
//	@Success		202		{object}	Response{data=SetWifiScheduleResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wifi-schedule/{ip} [put]
func setWifiScheduleHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetWifiScheduleRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateWifiScheduleRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := buildWifiScheduleParameterValues(req.Schedules, req.WLANIndex)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("WiFi schedule task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrWifiScheduleDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetWifiScheduleResponse{
		Message:   MsgWifiScheduleUpdated,
		DeviceID:  deviceID,
		IP:        getIPParam(r),
		Count:     len(req.Schedules),
		WLANIndex: req.WLANIndex,
	})
}

// validateWifiScheduleRequest applies field rules for L4. Pure function.
func validateWifiScheduleRequest(req *SetWifiScheduleRequest) string {
	if len(req.Schedules) == 0 {
		return ErrWifiScheduleEmpty
	}
	if len(req.Schedules) > MaxWifiScheduleEntries {
		return ErrWifiScheduleTooMany
	}
	for _, s := range req.Schedules {
		if s.Day < 0 || s.Day > 6 {
			return ErrWifiScheduleInvalidDay
		}
		if !timeHHMMRegex.MatchString(s.StartTime) || !timeHHMMRegex.MatchString(s.EndTime) {
			return ErrWifiScheduleInvalidTime
		}
	}
	if req.WLANIndex == 0 {
		req.WLANIndex = 1
	}
	return ""
}

// buildWifiScheduleParameterValues constructs the SetParameterValues
// payload for the WiFi schedule entries. Pure function.
//
// Uses a vendor-extension path that's common across ZTE, Huawei, and
// some FiberHome ONUs. v2.3.0 will add per-vendor detection.
func buildWifiScheduleParameterValues(schedules []WifiScheduleEntry, wlanIndex int) [][]interface{} {
	values := make([][]interface{}, 0, 4*len(schedules))
	wlanBase := "InternetGatewayDevice.LANDevice.1.WLANConfiguration." + intToStr(wlanIndex) + "."
	for i, s := range schedules {
		base := wlanBase + "X_TimerSchedule." + intToStr(i+1) + "."
		values = append(values,
			[]interface{}{base + "Enable", s.Enabled, XSDBoolean},
			[]interface{}{base + "Day", s.Day, XSDUnsignedInt},
			[]interface{}{base + "StartTime", s.StartTime, XSDString},
			[]interface{}{base + "EndTime", s.EndTime, XSDString},
		)
	}
	return values
}

// --- L5: PUT /mac-filter/{ip} ---

// SetMACFilterRequest is the body shape for PUT /mac-filter/{ip}.
//
// @Description MAC filter rule update. mode = "allow" (whitelist) or "deny" (blacklist). wlan_index defaults to 1.
type SetMACFilterRequest struct {
	Mode      string   `json:"mode"`
	MACs      []string `json:"macs"`
	WLANIndex int      `json:"wlan_index,omitempty"`
}

// SetMACFilterResponse is the shape returned by PUT /mac-filter/{ip}.
//
// @Description MAC filter update response.
type SetMACFilterResponse struct {
	Message   string `json:"message"`
	DeviceID  string `json:"device_id"`
	IP        string `json:"ip"`
	Mode      string `json:"mode"`
	Count     int    `json:"count"`
	WLANIndex int    `json:"wlan_index"`
}

var (
	_ = SetMACFilterRequest{}
	_ = SetMACFilterResponse{}
)

// MaxMacFilterEntries caps the number of MAC entries per request.
const MaxMacFilterEntries = 32

// setMACFilterHandler updates the WLAN MAC filter on the CPE via
// TR-069 SetParameterValues.
//
//	@Summary		Set WLAN MAC filter
//	@Description	Updates the WLAN MAC filter on the CPE via TR-069 SetParameterValues. mode allow = whitelist, deny = blacklist. Standard TR-098 path: `LANDevice.1.WLANConfiguration.{wlan}.WLANAccessControl.*`. Vendor variation may apply for the entry list format.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetMACFilterRequest		true	"MAC filter list"
//	@Success		202		{object}	Response{data=SetMACFilterResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/mac-filter/{ip} [put]
func setMACFilterHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetMACFilterRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateMACFilterRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := buildMACFilterParameterValues(req)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("MAC filter task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrMacFilterDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetMACFilterResponse{
		Message:   MsgMacFilterUpdated,
		DeviceID:  deviceID,
		IP:        getIPParam(r),
		Mode:      req.Mode,
		Count:     len(req.MACs),
		WLANIndex: req.WLANIndex,
	})
}

// validateMACFilterRequest applies field rules for L5. Pure function.
func validateMACFilterRequest(req *SetMACFilterRequest) string {
	mode := strings.ToLower(req.Mode)
	if mode != "allow" && mode != "deny" {
		return ErrMacFilterModeInvalid
	}
	req.Mode = mode
	if len(req.MACs) == 0 {
		return ErrMacFilterMacsEmpty
	}
	if len(req.MACs) > MaxMacFilterEntries {
		return ErrMacFilterMacsTooMany
	}
	for _, m := range req.MACs {
		if !macRegex.MatchString(m) {
			return ErrMacFilterInvalidMAC
		}
	}
	if req.WLANIndex == 0 {
		req.WLANIndex = 1
	}
	return ""
}

// buildMACFilterParameterValues constructs the SetParameterValues
// payload for the MAC filter list. Pure function.
//
// TR-098 standard mode field accepts "Allow" or "Deny" (capitalized).
// We capitalize the lowercase API mode here.
func buildMACFilterParameterValues(req SetMACFilterRequest) [][]interface{} {
	wlanBase := "InternetGatewayDevice.LANDevice.1.WLANConfiguration." + intToStr(req.WLANIndex) + "."
	modeCanonical := "Allow"
	if req.Mode == "deny" {
		modeCanonical = "Deny"
	}
	values := make([][]interface{}, 0, 1+len(req.MACs))
	values = append(values, []interface{}{
		wlanBase + "WLANAccessControlMode", modeCanonical, XSDString,
	})
	for i, m := range req.MACs {
		entryPath := wlanBase + "WLANAccessControlEntry." + intToStr(i+1) + "."
		values = append(values,
			[]interface{}{entryPath + "MACAddress", m, XSDString},
		)
	}
	return values
}
