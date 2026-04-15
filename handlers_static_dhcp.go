package main

import (
	"net"
	"net/http"
	"regexp"

	"go.uber.org/zap"
)

// handlers_static_dhcp.go contains the v2.2.0 static DHCP lease
// management endpoint (L6). Same set-at-index pattern as port
// forwarding — caller specifies the lease slot indexes.

// StaticDHCPLease is one entry in the leases array.
//
// @Description One static DHCP lease — binds a MAC address to a fixed IP.
type StaticDHCPLease struct {
	Index    int    `json:"index"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
}

// SetStaticDHCPRequest is the body shape for PUT /static-dhcp/{ip}.
//
// @Description Set static DHCP leases. Caller specifies slot indexes.
type SetStaticDHCPRequest struct {
	Leases []StaticDHCPLease `json:"leases"`
}

// SetStaticDHCPResponse is the shape returned by PUT /static-dhcp/{ip}.
//
// @Description Static DHCP lease update response.
type SetStaticDHCPResponse struct {
	Message     string `json:"message"`
	DeviceID    string `json:"device_id"`
	IP          string `json:"ip"`
	LeasesCount int    `json:"leases_count"`
}

var (
	_ = StaticDHCPLease{}
	_ = SetStaticDHCPRequest{}
	_ = SetStaticDHCPResponse{}
)

// MaxStaticDHCPLeases caps the number of static DHCP leases per request.
const MaxStaticDHCPLeases = 32

// macRegex validates AA:BB:CC:DD:EE:FF and aa-bb-cc-dd-ee-ff formats.
var macRegex = regexp.MustCompile(`^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$`)

// setStaticDHCPHandler updates static DHCP lease entries via TR-069
// SetParameterValues on the standard DHCPStaticAddress paths.
//
//	@Summary		Set static DHCP leases
//	@Description	Updates static DHCP lease entries via TR-069 SetParameterValues. Caller specifies the slot index for each lease. Standard TR-098 path: `LANDevice.1.LANHostConfigManagement.IPInterface.1.DHCPStaticAddress.{index}.*`.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetStaticDHCPRequest	true	"Static DHCP leases"
//	@Success		202		{object}	Response{data=SetStaticDHCPResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/static-dhcp/{ip} [put]
func setStaticDHCPHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetStaticDHCPRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateStaticDHCPRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := buildStaticDHCPParameterValues(req.Leases)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("Static DHCP task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrStaticDHCPDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetStaticDHCPResponse{
		Message:     MsgStaticDHCPUpdated,
		DeviceID:    deviceID,
		IP:          getIPParam(r),
		LeasesCount: len(req.Leases),
	})
}

// validateStaticDHCPRequest applies field rules for L6. Pure function.
func validateStaticDHCPRequest(req *SetStaticDHCPRequest) string {
	if len(req.Leases) == 0 {
		return ErrStaticDHCPLeasesEmpty
	}
	if len(req.Leases) > MaxStaticDHCPLeases {
		return ErrStaticDHCPLeasesTooMany
	}
	for _, lease := range req.Leases {
		if lease.Index < 1 || lease.Index > MaxStaticDHCPLeases {
			return ErrStaticDHCPLeasesTooMany
		}
		if !macRegex.MatchString(lease.MAC) {
			return ErrStaticDHCPInvalidMAC
		}
		if net.ParseIP(lease.IP) == nil {
			return ErrStaticDHCPInvalidIP
		}
	}
	return ""
}

// buildStaticDHCPParameterValues constructs the TR-069
// SetParameterValues payload for static DHCP leases. Pure function.
func buildStaticDHCPParameterValues(leases []StaticDHCPLease) [][]interface{} {
	var values [][]interface{}
	for _, lease := range leases {
		base := "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.DHCPStaticAddress." +
			intToStr(lease.Index) + "."
		values = append(values,
			[]interface{}{base + "Enable", true, XSDBoolean},
			[]interface{}{base + "Chaddr", lease.MAC, XSDString},
			[]interface{}{base + "Yiaddr", lease.IP, XSDString},
		)
		if lease.Hostname != "" {
			values = append(values, []interface{}{
				base + "X_Hostname", lease.Hostname, XSDString,
			})
		}
	}
	return values
}
