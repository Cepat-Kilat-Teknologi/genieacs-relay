package main

import (
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// handlers_pppoe.go contains the v2.2.0 PPPoE credential management
// endpoint:
//
//	PUT /api/v1/genieacs/pppoe/{ip}  — H3: set PPPoE username + password
//
// Critical for ISP deployments where PPPoE termination happens on the
// CPE side (some Indonesian ISPs use this model so the BNG can be a
// generic L3 router instead of a PPPoE-aware BRAS). Without this
// endpoint, activate-customer flows in auto-learning OLT scenarios
// have no way to provision the customer credentials onto the CPE.
//
// **Vendor path note:** v2.2.0 hardcodes the TR-098 standard path
// `InternetGatewayDevice.WANDevice.{n}.WANConnectionDevice.1.WANPPPConnection.1`.
// The TR-181 equivalent is `Device.PPP.Interface.{n}` and is not
// auto-detected. Vendor detection is a v2.3.0 enhancement modeled on
// the optical health 5-vendor pattern.

// SetPPPoERequest is the body shape for PUT /pppoe/{ip}.
//
// @Description PPPoE credential update request — username and password are required, wan_instance is optional and defaults to 1.
type SetPPPoERequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	WANInstance int    `json:"wan_instance,omitempty"`
}

// SetPPPoEResponse is the shape returned by PUT /pppoe/{ip}.
//
// @Description PPPoE credential update response — confirms the device, IP, and which WAN instance was updated.
type SetPPPoEResponse struct {
	Message     string `json:"message" example:"PPPoE credentials updated. Device will reconnect within 30s."`
	DeviceID    string `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	IP          string `json:"ip" example:"192.168.1.1"`
	WANInstance int    `json:"wan_instance" example:"1"`
}

var (
	_ = SetPPPoERequest{}
	_ = SetPPPoEResponse{}
)

// PPPoEMaxFieldLength is the maximum allowed length for username and
// password fields. 64 characters is comfortably above any real PPPoE
// auth setup (typical 16-32 chars) and matches the TR-098 schema.
const PPPoEMaxFieldLength = 64

// PPPoEMaxWANInstance caps the optional wan_instance field. Real CPEs
// rarely expose more than 4 WANDevice instances; 8 is a safety ceiling.
const PPPoEMaxWANInstance = 8

// setPPPoECredentialsHandler updates PPPoE username and password on
// the CPE via TR-069 SetParameterValues. Submits the task through the
// existing worker pool so the handler returns 202 immediately while
// the actual GenieACS NBI dispatch happens asynchronously.
//
// Validation rules: username non-empty + max 64 chars + no whitespace;
// password non-empty + max 64 chars; wan_instance 1-8 if specified,
// defaults to 1.
//
//	@Summary		Set PPPoE credentials on CPE
//	@Description	Updates the PPPoE username and password on the CPE via TR-069 SetParameterValues. Critical for auto-learning OLT deployments where the OLT does not push customer profile config and PPPoE termination happens on the CPE side. The device will drop and re-establish its WAN connection within ~30 seconds of the task being applied.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string			true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetPPPoERequest	true	"PPPoE credentials"
//	@Success		202		{object}	Response{data=SetPPPoEResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/pppoe/{ip} [put]
func setPPPoECredentialsHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	var req SetPPPoERequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}

	if errMsg := validatePPPoERequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}

	parameterValues := buildPPPoEParameterValues(req.Username, req.Password, req.WANInstance)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("PPPoE credential update task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrPPPoEDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusAccepted, SetPPPoEResponse{
		Message:     MsgPPPoEUpdated,
		DeviceID:    deviceID,
		IP:          getIPParam(r),
		WANInstance: req.WANInstance,
	})
}

// validatePPPoERequest applies the field-level validation rules and
// also fills in the wan_instance default (1) so the response can echo
// it back without ambiguity. Returns "" on success or a user-facing
// error message string on failure. Pure function for unit testability.
func validatePPPoERequest(req *SetPPPoERequest) string {
	if req.Username == "" {
		return ErrPPPoEUsernameRequired
	}
	if req.Password == "" {
		return ErrPPPoEPasswordRequired
	}
	if len(req.Username) > PPPoEMaxFieldLength {
		return ErrPPPoEUsernameTooLong
	}
	if len(req.Password) > PPPoEMaxFieldLength {
		return ErrPPPoEPasswordTooLong
	}
	if strings.ContainsAny(req.Username, " \t\n\r") {
		return ErrPPPoEUsernameWhitespace
	}
	if req.WANInstance == 0 {
		req.WANInstance = 1
	}
	if req.WANInstance < 1 || req.WANInstance > PPPoEMaxWANInstance {
		return ErrPPPoEInvalidWanInstance
	}
	return ""
}

// buildPPPoEParameterValues constructs the TR-069 setParameterValues
// payload for updating PPPoE credentials on the given WAN instance.
// Returns the same `[][]interface{}` shape that SubmitWLANUpdate
// expects (see utils.go SubmitWLANUpdate). Pure function for unit testability.
func buildPPPoEParameterValues(username, password string, wanInstance int) [][]interface{} {
	usernamePath := fmt.Sprintf(
		"InternetGatewayDevice.WANDevice.%d.WANConnectionDevice.1.WANPPPConnection.1.Username",
		wanInstance,
	)
	passwordPath := fmt.Sprintf(
		"InternetGatewayDevice.WANDevice.%d.WANConnectionDevice.1.WANPPPConnection.1.Password",
		wanInstance,
	)
	return [][]interface{}{
		{usernamePath, username, XSDString},
		{passwordPath, password, XSDString},
	}
}
