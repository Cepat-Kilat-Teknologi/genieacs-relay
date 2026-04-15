package main

import (
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// handlers_portforward.go contains the v2.2.0 port forwarding rule
// management endpoint (L1). Uses "set-at-index" semantics: the caller
// specifies which slot indexes to write, and the relay submits one
// SetParameterValues task containing all rule fields. The caller is
// responsible for tracking which indexes are in use; the v2.2.0 first
// iteration does NOT auto-create new instances via addObject (that's
// a v2.3.0 enhancement).

// PortForwardRule is one entry in the rules array.
//
// @Description One port forwarding rule. Index is the TR-069 PortMapping instance number (1-based). Use enabled=false to disable a slot without removing it.
type PortForwardRule struct {
	Index        int    `json:"index"`
	Name         string `json:"name,omitempty"`
	Protocol     string `json:"protocol"`
	ExternalPort int    `json:"external_port"`
	InternalIP   string `json:"internal_ip"`
	InternalPort int    `json:"internal_port"`
	Enabled      bool   `json:"enabled"`
	WANInstance  int    `json:"wan_instance,omitempty"`
}

// SetPortForwardingRequest is the body shape for PUT /port-forwarding/{ip}.
//
// @Description Set port forwarding rules. Caller specifies the rule indexes. v2.2.0 does NOT auto-create new instances — see V2.2.0-DESIGN.md §Phase 4.
type SetPortForwardingRequest struct {
	Rules []PortForwardRule `json:"rules"`
}

// SetPortForwardingResponse is the shape returned by PUT /port-forwarding/{ip}.
//
// @Description Port forwarding rule update response.
type SetPortForwardingResponse struct {
	Message    string `json:"message"`
	DeviceID   string `json:"device_id"`
	IP         string `json:"ip"`
	RulesCount int    `json:"rules_count"`
}

var (
	_ = PortForwardRule{}
	_ = SetPortForwardingRequest{}
	_ = SetPortForwardingResponse{}
)

// MaxPortForwardRules caps the number of rules per request.
const MaxPortForwardRules = 32

// validProtocols is the set of acceptable protocol strings for port
// forwarding rules. "both" is mapped to TR-069 standard "TCP AND UDP".
var validProtocols = map[string]string{
	"tcp":  "TCP",
	"udp":  "UDP",
	"both": "TCP AND UDP",
}

// setPortForwardingHandler updates port forwarding rules at the given
// PortMapping slot indexes via TR-069 SetParameterValues.
//
//	@Summary		Set port forwarding rules
//	@Description	Updates port forwarding rules at the given PortMapping slot indexes via TR-069 SetParameterValues. Caller specifies the index for each rule. v2.2.0 first iteration does NOT auto-create new instances — use enabled=false to disable a slot without removing it.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string						true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetPortForwardingRequest	true	"Port forwarding rules"
//	@Success		202		{object}	Response{data=SetPortForwardingResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/port-forwarding/{ip} [put]
func setPortForwardingHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req SetPortForwardingRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validatePortForwardingRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}
	parameterValues := buildPortForwardingParameterValues(req.Rules)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("Port forwarding task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrPortFwdDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, SetPortForwardingResponse{
		Message:    MsgPortFwdUpdated,
		DeviceID:   deviceID,
		IP:         getIPParam(r),
		RulesCount: len(req.Rules),
	})
}

// validatePortForwardingRequest applies field rules for L1. Pure function.
func validatePortForwardingRequest(req *SetPortForwardingRequest) string {
	if len(req.Rules) == 0 {
		return ErrPortFwdRulesEmpty
	}
	if len(req.Rules) > MaxPortForwardRules {
		return ErrPortFwdRulesTooMany
	}
	for i := range req.Rules {
		if errMsg := validatePortForwardRule(&req.Rules[i]); errMsg != "" {
			return errMsg
		}
	}
	return ""
}

// validatePortForwardRule validates a single rule. Pure function.
func validatePortForwardRule(rule *PortForwardRule) string {
	if rule.Index < 1 || rule.Index > MaxPortForwardRules {
		return ErrPortFwdRulesTooMany
	}
	if _, ok := validProtocols[strings.ToLower(rule.Protocol)]; !ok {
		return ErrPortFwdInvalidProto
	}
	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 {
		return ErrPortFwdInvalidPort
	}
	if rule.InternalPort < 1 || rule.InternalPort > 65535 {
		return ErrPortFwdInvalidPort
	}
	if net.ParseIP(rule.InternalIP) == nil {
		return ErrPortFwdInvalidIP
	}
	if rule.WANInstance == 0 {
		rule.WANInstance = 1
	}
	if rule.WANInstance < 1 || rule.WANInstance > PPPoEMaxWANInstance {
		return ErrPPPoEInvalidWanInstance
	}
	return ""
}

// buildPortForwardingParameterValues constructs the TR-069
// SetParameterValues payload for the port forwarding rules.
// Pure function.
//
// Uses TR-098 standard path family
// `WANConnectionDevice.1.WANIPConnection.1.PortMapping.{index}.*`.
func buildPortForwardingParameterValues(rules []PortForwardRule) [][]interface{} {
	var values [][]interface{}
	for _, rule := range rules {
		base := "InternetGatewayDevice.WANDevice." + intToStr(rule.WANInstance) +
			".WANConnectionDevice.1.WANIPConnection.1.PortMapping." + intToStr(rule.Index) + "."
		protoCanonical := validProtocols[strings.ToLower(rule.Protocol)]
		values = append(values,
			[]interface{}{base + "PortMappingEnabled", rule.Enabled, XSDBoolean},
			[]interface{}{base + "PortMappingProtocol", protoCanonical, XSDString},
			[]interface{}{base + "ExternalPort", rule.ExternalPort, XSDUnsignedInt},
			[]interface{}{base + "InternalClient", rule.InternalIP, XSDString},
			[]interface{}{base + "InternalPort", rule.InternalPort, XSDUnsignedInt},
		)
		if rule.Name != "" {
			values = append(values, []interface{}{
				base + "PortMappingDescription", rule.Name, XSDString,
			})
		}
	}
	return values
}
