package main

import (
	"net"
	"net/http"

	"go.uber.org/zap"
)

// handlers_dmz_ddns.go contains the v2.2.0 NAT-side WAN configuration
// endpoints — DMZ host (L2) and DDNS (L3). Both are simple
// SetParameterValues writes against TR-098 standard paths.
//
// **Vendor caveat:** DMZ and DDNS paths vary by vendor. v2.2.0 uses
// the TR-098 IGD model paths (most common) and accepts the GenieACS
// SetParameterValues failure as the "vendor doesn't support" signal.
// v2.3.0 will add vendor detection.

// --- L2: PUT /dmz/{ip} ---

// SetDMZRequest is the body shape for PUT /dmz/{ip}.
//
// @Description DMZ host configuration. enabled=true requires host_ip; enabled=false clears the DMZ. wan_instance defaults to 1.
type SetDMZRequest struct {
	Enabled     *bool  `json:"enabled"`
	HostIP      string `json:"host_ip,omitempty"`
	WANInstance int    `json:"wan_instance,omitempty"`
}

// SetDMZResponse is the shape returned by PUT /dmz/{ip}.
//
// @Description DMZ host configuration response.
type SetDMZResponse struct {
	Message     string `json:"message"`
	DeviceID    string `json:"device_id"`
	IP          string `json:"ip"`
	Enabled     bool   `json:"enabled"`
	HostIP      string `json:"host_ip,omitempty"`
	WANInstance int    `json:"wan_instance"`
}

var (
	_ = SetDMZRequest{}
	_ = SetDMZResponse{}
)

// setDMZHandler sets the DMZ host on the CPE WAN connection.
//
//	@Summary		Set CPE DMZ host
//	@Description	Sets the DMZ host on the CPE WAN connection via TR-069 SetParameterValues. enabled=true requires host_ip; enabled=false clears the DMZ. v2.2.0 uses TR-098 IGD paths; v2.3.0 will add vendor detection.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string			true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetDMZRequest	true	"DMZ configuration"
//	@Success		202		{object}	Response{data=SetDMZResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/dmz/{ip} [put]
func setDMZHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetDMZRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateDMZRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := buildDMZParameterValues(*req.Enabled, req.HostIP, req.WANInstance)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("DMZ task submission failed", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrDMZDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetDMZResponse{
		Message:     MsgDMZUpdated,
		DeviceID:    deviceID,
		IP:          getIPParam(r),
		Enabled:     *req.Enabled,
		HostIP:      req.HostIP,
		WANInstance: req.WANInstance,
	})
}

// validateDMZRequest applies field rules for L2. Pure function.
func validateDMZRequest(req *SetDMZRequest) string {
	if req.Enabled == nil {
		return ErrEnabledRequired
	}
	if *req.Enabled {
		if req.HostIP == "" || net.ParseIP(req.HostIP) == nil {
			return ErrDMZHostInvalid
		}
	}
	if req.WANInstance == 0 {
		req.WANInstance = 1
	}
	if req.WANInstance < 1 || req.WANInstance > PPPoEMaxWANInstance {
		return ErrPPPoEInvalidWanInstance
	}
	return ""
}

// buildDMZParameterValues constructs the TR-069 SetParameterValues
// payload for DMZ host configuration. Pure function.
func buildDMZParameterValues(enabled bool, hostIP string, wanInstance int) [][]interface{} {
	enabledPath := "InternetGatewayDevice.WANDevice." + intToStr(wanInstance) +
		".WANConnectionDevice.1.WANIPConnection.1.X_DMZEnable"
	hostPath := "InternetGatewayDevice.WANDevice." + intToStr(wanInstance) +
		".WANConnectionDevice.1.WANIPConnection.1.X_DMZHost"
	return [][]interface{}{
		{enabledPath, enabled, XSDBoolean},
		{hostPath, hostIP, XSDString},
	}
}

// --- L3: PUT /ddns/{ip} ---

// SetDDNSRequest is the body shape for PUT /ddns/{ip}.
//
// @Description DDNS configuration. provider, hostname, username, password are required when enabled=true.
type SetDDNSRequest struct {
	Enabled  *bool  `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// SetDDNSResponse is the shape returned by PUT /ddns/{ip}.
//
// @Description DDNS configuration response. Does NOT echo username/password back.
type SetDDNSResponse struct {
	Message  string `json:"message"`
	DeviceID string `json:"device_id"`
	IP       string `json:"ip"`
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

var (
	_ = SetDDNSRequest{}
	_ = SetDDNSResponse{}
)

// setDDNSHandler updates DDNS configuration on the CPE.
//
//	@Summary		Set CPE DDNS configuration
//	@Description	Updates DDNS configuration on the CPE via TR-069 SetParameterValues on the standard `Services.X_DynDNS` paths. Vendor variation is wide; v2.2.0 uses the most common paths and surfaces vendor incompatibility as a 503 from the GenieACS layer.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string			true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetDDNSRequest	true	"DDNS configuration"
//	@Success		202		{object}	Response{data=SetDDNSResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/ddns/{ip} [put]
func setDDNSHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetDDNSRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateDDNSRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := buildDDNSParameterValues(req)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("DDNS task submission failed", zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrDDNSDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetDDNSResponse{
		Message:  MsgDDNSUpdated,
		DeviceID: deviceID,
		IP:       getIPParam(r),
		Enabled:  *req.Enabled,
		Provider: req.Provider,
		Hostname: req.Hostname,
	})
}

// validateDDNSRequest applies field rules for L3. Pure function.
func validateDDNSRequest(req *SetDDNSRequest) string {
	if req.Enabled == nil {
		return ErrEnabledRequired
	}
	if *req.Enabled {
		if req.Provider == "" {
			return ErrDDNSProviderRequired
		}
		if req.Hostname == "" {
			return ErrDDNSHostnameRequired
		}
	}
	return ""
}

// buildDDNSParameterValues constructs the TR-069 SetParameterValues
// payload for DDNS configuration. Pure function.
//
// Uses the TR-098 standard `Services.X_DynDNS.1.*` paths which are
// the most common across consumer ONUs. Some vendors (Huawei, ZTE)
// expose vendor-specific shortcuts at
// `InternetGatewayDevice.X_HW_DDNS` etc. — those are deferred to
// v2.3.0 vendor detection.
func buildDDNSParameterValues(req SetDDNSRequest) [][]interface{} {
	base := "InternetGatewayDevice.Services.X_DynDNS.1."
	values := [][]interface{}{
		{base + "Enable", *req.Enabled, XSDBoolean},
	}
	if *req.Enabled {
		values = append(values,
			[]interface{}{base + "Server", req.Provider, XSDString},
			[]interface{}{base + "DomainName", req.Hostname, XSDString},
			[]interface{}{base + "Username", req.Username, XSDString},
			[]interface{}{base + "Password", req.Password, XSDString},
		)
	}
	return values
}
