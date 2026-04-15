package main

import (
	"net/http"

	"go.uber.org/zap"
)

// handlers_admin.go contains the v2.2.0 administrative provisioning
// endpoints — NTP / timezone (L7) and admin web password (L8). Both
// are simple SetParameterValues writes against TR-098 standard paths.

// --- L7: PUT /ntp/{ip} ---

// SetNTPRequest is the body shape for PUT /ntp/{ip}.
//
// @Description NTP / timezone update request. At least one of ntp_servers or timezone must be provided.
type SetNTPRequest struct {
	NTPServers []string `json:"ntp_servers,omitempty"`
	Timezone   string   `json:"timezone,omitempty"`
}

// SetNTPResponse is the shape returned by PUT /ntp/{ip}.
//
// @Description NTP / timezone update response.
type SetNTPResponse struct {
	Message    string   `json:"message"`
	DeviceID   string   `json:"device_id"`
	IP         string   `json:"ip"`
	NTPServers []string `json:"ntp_servers,omitempty"`
	Timezone   string   `json:"timezone,omitempty"`
}

var (
	_ = SetNTPRequest{}
	_ = SetNTPResponse{}
)

// MaxNTPServers caps the number of NTP server entries per request.
// TR-098 standard exposes NTPServer1..NTPServer5.
const MaxNTPServers = 5

// setNTPHandler updates NTP server list and timezone via TR-069
// SetParameterValues on the standard TR-098 paths.
//
//	@Summary		Set CPE NTP servers and timezone
//	@Description	Updates the CPE NTP server list (max 5 entries) and/or timezone via TR-069 SetParameterValues. Standard TR-098 paths: `InternetGatewayDevice.Time.NTPServer{1..5}` and `InternetGatewayDevice.Time.LocalTimeZoneName`. At least one of ntp_servers or timezone must be provided.
//	@Tags			Admin
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string			true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetNTPRequest	true	"NTP / timezone payload"
//	@Success		202		{object}	Response{data=SetNTPResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/ntp/{ip} [put]
func setNTPHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetNTPRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateNTPRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := buildNTPParameterValues(req.NTPServers, req.Timezone)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("NTP task submission failed", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrNTPDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetNTPResponse{
		Message:    MsgNTPUpdated,
		DeviceID:   deviceID,
		IP:         getIPParam(r),
		NTPServers: req.NTPServers,
		Timezone:   req.Timezone,
	})
}

// validateNTPRequest applies field rules for L7. Pure function.
//
// Note: an explicit empty `ntp_servers: []` with a non-empty timezone
// is treated as "update only timezone" — we allow it rather than
// rejecting, because it's a reasonable caller intent. The only
// rejection is "neither field set" (ErrNTPNoFields).
func validateNTPRequest(req *SetNTPRequest) string {
	if len(req.NTPServers) == 0 && req.Timezone == "" {
		return ErrNTPNoFields
	}
	if len(req.NTPServers) > MaxNTPServers {
		return ErrNTPServersTooMany
	}
	return ""
}

// buildNTPParameterValues constructs the TR-069 SetParameterValues
// payload for NTP server list + optional timezone. Pure function.
//
// TR-098 indexes NTP servers 1-5; we map the input slice positionally.
func buildNTPParameterValues(servers []string, timezone string) [][]interface{} {
	var values [][]interface{}
	for i, s := range servers {
		path := "InternetGatewayDevice.Time.NTPServer" + intToStr(i+1)
		values = append(values, []interface{}{path, s, XSDString})
	}
	if timezone != "" {
		values = append(values,
			[]interface{}{"InternetGatewayDevice.Time.LocalTimeZoneName", timezone, XSDString},
		)
	}
	return values
}

// intToStr is a tiny helper to convert positional indexes to strings
// without dragging strconv into hot paths. Used by NTP and any future
// helper that needs `1..N` instance suffixes. Pure function.
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToStr(-n)
	}
	out := ""
	for n > 0 {
		out = string(rune('0'+n%10)) + out
		n /= 10
	}
	return out
}

// --- L8: PUT /admin-password/{ip} ---

// SetAdminPasswordRequest is the body shape for PUT /admin-password/{ip}.
//
// @Description Admin web password update request. The password is the new value to set on the CPE's local web admin interface — it does NOT change PPPoE credentials (use /pppoe/{ip} for that) or TR-069 ACS auth.
type SetAdminPasswordRequest struct {
	Password string `json:"password"`
}

// SetAdminPasswordResponse is the shape returned by PUT /admin-password/{ip}.
//
// @Description Admin web password update response. Does NOT echo the password value back to keep it out of relay audit logs.
type SetAdminPasswordResponse struct {
	Message  string `json:"message"`
	DeviceID string `json:"device_id"`
	IP       string `json:"ip"`
}

var (
	_ = SetAdminPasswordRequest{}
	_ = SetAdminPasswordResponse{}
)

// AdminPasswordMaxLength matches the TR-098 schema for
// `InternetGatewayDevice.UserInterface.WebPassword` (string up to 64).
const AdminPasswordMaxLength = 64

// setAdminPasswordHandler updates the CPE local web admin password
// via TR-069 SetParameterValues on
// `InternetGatewayDevice.UserInterface.WebPassword`.
//
// Distinct from PPPoE credentials (/pppoe/{ip}) and from the
// TR-069 ACS authentication credentials (which live on the GenieACS
// server side, not the CPE).
//
//	@Summary		Set CPE admin web password
//	@Description	Updates the CPE local web admin password via TR-069 SetParameterValues on `InternetGatewayDevice.UserInterface.WebPassword`. Distinct from PPPoE credentials and TR-069 ACS auth. Password is NOT echoed in the response or audit logs.
//	@Tags			Admin
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetAdminPasswordRequest	true	"New admin password"
//	@Success		202		{object}	Response{data=SetAdminPasswordResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/admin-password/{ip} [put]
func setAdminPasswordHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetAdminPasswordRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateAdminPasswordRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := [][]interface{}{
		{"InternetGatewayDevice.UserInterface.WebPassword", req.Password, XSDString},
	}
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("Admin password task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrAdminPasswordDispatch)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetAdminPasswordResponse{
		Message:  MsgAdminPasswordUpdated,
		DeviceID: deviceID,
		IP:       getIPParam(r),
	})
}

// validateAdminPasswordRequest applies field rules for L8. Pure function.
func validateAdminPasswordRequest(req *SetAdminPasswordRequest) string {
	if req.Password == "" {
		return ErrAdminPasswordRequired
	}
	if len(req.Password) > AdminPasswordMaxLength {
		return ErrAdminPasswordTooLong
	}
	return ""
}
