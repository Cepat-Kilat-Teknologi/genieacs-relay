package main

import (
	"context"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

// handlers_qos_bridge.go contains the v2.2.0 WAN provisioning writes
// that complement the PPPoE handler:
//
//	PUT /api/v1/genieacs/qos/{ip}          — M6: bandwidth rate-limit
//	PUT /api/v1/genieacs/bridge-mode/{ip}  — M8: toggle bridge / router mode
//
// Both are simple TR-069 SetParameterValues operations, dispatched
// through the existing taskWorkerPool so the handlers return 202
// immediately. v2.2.0 hardcodes the TR-098 standard paths;
// vendor-specific QoS extensions (`X_HW_BandwidthLimit`,
// `X_TPLINK_QoSManagement`, etc) and bridge-mode toggles are
// candidates for v2.3.0 vendor detection modeled on the optical-health
// 5-vendor pattern.

// --- M6: PUT /qos/{ip} ---

// SetQoSRequest is the body shape for PUT /qos/{ip}.
//
// @Description Bandwidth rate-limit request. At least one of download_kbps or upload_kbps must be provided. Rates of 0 mean "no limit" (clears the cap). wan_instance defaults to 1.
type SetQoSRequest struct {
	DownloadKbps *int `json:"download_kbps,omitempty"`
	UploadKbps   *int `json:"upload_kbps,omitempty"`
	WANInstance  int  `json:"wan_instance,omitempty"`
}

// SetQoSResponse is the shape returned by PUT /qos/{ip}.
//
// @Description Bandwidth rate-limit response.
type SetQoSResponse struct {
	Message      string `json:"message" example:"QoS rate limit updated."`
	DeviceID     string `json:"device_id"`
	IP           string `json:"ip"`
	WANInstance  int    `json:"wan_instance" example:"1"`
	DownloadKbps *int   `json:"download_kbps,omitempty"`
	UploadKbps   *int   `json:"upload_kbps,omitempty"`
}

var (
	_ = SetQoSRequest{}
	_ = SetQoSResponse{}
)

// setQoSHandler updates the per-WAN bandwidth rate limit on the CPE
// via TR-069 SetParameterValues on the standard
// `WANPPPConnection.{n}.X_DownStreamMaxBitRate` and
// `X_UpStreamMaxBitRate` paths.
//
//	@Summary		Set CPE bandwidth rate limit (QoS)
//	@Description	Updates the per-WAN download / upload rate limit on the CPE via TR-069 SetParameterValues. At least one of download_kbps or upload_kbps must be provided. Rates of 0 clear the cap. v2.2.0 uses the standard `X_DownStreamMaxBitRate` / `X_UpStreamMaxBitRate` paths; vendor-specific QoS extensions are deferred to v2.3.0.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string			true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetQoSRequest	true	"QoS rates"
//	@Success		202		{object}	Response{data=SetQoSResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/qos/{ip} [put]
func setQoSHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	var req SetQoSRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}

	if errMsg := validateQoSRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}

	// Capability probe — v2.2 QoS writes to the X_DownStreamMaxBitRate /
	// X_UpStreamMaxBitRate vendor extension, which is present on Huawei
	// HG-series, TP-Link business CPE and most prosumer ONTs but ABSENT
	// on consumer ZTE F670L (which uses the full TR-098 QueueManagement
	// model instead). Dispatching anyway silently no-ops on the CPE
	// because CWMP fault 9005 InvalidParameterName lands in a fault
	// document that the caller never sees. Probe once upfront and fail
	// with 501 so the caller knows to use OLT-side RADIUS CoA or wait
	// for the v2.3 TR-098 QueueManagement handler.
	supported, err := cpeSupportsXStreamBitRate(r.Context(), deviceID, req.WANInstance)
	if err != nil {
		logger.Error("QoS capability probe failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeInternal, ErrQosCapabilityProbeFailed)
		return
	}
	if !supported {
		sendError(w, r, http.StatusNotImplemented, ErrCodeQoSUnsupported, ErrQosUnsupportedByDevice)
		return
	}

	parameterValues := buildQoSParameterValues(req.DownloadKbps, req.UploadKbps, req.WANInstance)
	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("QoS task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrQosDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusAccepted, SetQoSResponse{
		Message:      MsgQoSUpdated,
		DeviceID:     deviceID,
		IP:           getIPParam(r),
		WANInstance:  req.WANInstance,
		DownloadKbps: req.DownloadKbps,
		UploadKbps:   req.UploadKbps,
	})
}

// validateQoSRequest applies field rules and fills in the
// wan_instance default. Pure function for unit testability.
func validateQoSRequest(req *SetQoSRequest) string {
	if req.DownloadKbps == nil && req.UploadKbps == nil {
		return ErrQosNoFieldsProvided
	}
	if req.DownloadKbps != nil && *req.DownloadKbps < 0 {
		return ErrQosNegativeRate
	}
	if req.UploadKbps != nil && *req.UploadKbps < 0 {
		return ErrQosNegativeRate
	}
	if req.WANInstance == 0 {
		req.WANInstance = 1
	}
	if req.WANInstance < 1 || req.WANInstance > PPPoEMaxWANInstance {
		return ErrPPPoEInvalidWanInstance
	}
	return ""
}

// buildQoSParameterValues constructs the TR-069 setParameterValues
// payload for the rate limit fields the caller supplied. Pure
// function for unit testability.
func buildQoSParameterValues(downloadKbps, uploadKbps *int, wanInstance int) [][]interface{} {
	var values [][]interface{}
	if downloadKbps != nil {
		path := fmt.Sprintf(
			"InternetGatewayDevice.WANDevice.%d.WANConnectionDevice.1.WANPPPConnection.1.X_DownStreamMaxBitRate",
			wanInstance,
		)
		values = append(values, []interface{}{path, *downloadKbps, XSDUnsignedInt})
	}
	if uploadKbps != nil {
		path := fmt.Sprintf(
			"InternetGatewayDevice.WANDevice.%d.WANConnectionDevice.1.WANPPPConnection.1.X_UpStreamMaxBitRate",
			wanInstance,
		)
		values = append(values, []interface{}{path, *uploadKbps, XSDUnsignedInt})
	}
	return values
}

// cpeSupportsXStreamBitRate returns true iff the CPE's device tree
// already contains the `X_DownStreamMaxBitRate` or `X_UpStreamMaxBitRate`
// vendor parameter under
// `InternetGatewayDevice.WANDevice.{n}.WANConnectionDevice.1.WANPPPConnection.1`.
// Presence of the parameter node implies GenieACS has seen the CPE
// report it at least once, which is a reliable proxy for "the CPE
// accepts a write to it".
//
// A simple projection query is enough — if either field is missing
// from the tree, the CPE never announced support for it and we should
// not attempt to write. The check costs one NBI GET; results are cached
// via getDeviceData so repeated QoS calls to the same device are cheap.
func cpeSupportsXStreamBitRate(ctx context.Context, deviceID string, wanInstance int) (bool, error) {
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return false, err
	}
	wanKey := fmt.Sprintf("%d", wanInstance)
	ppp := navigateNested(deviceData,
		"InternetGatewayDevice", "WANDevice", wanKey,
		"WANConnectionDevice", "1", "WANPPPConnection", "1")
	if ppp == nil {
		return false, nil
	}
	if _, ok := ppp["X_DownStreamMaxBitRate"].(map[string]interface{}); ok {
		return true, nil
	}
	if _, ok := ppp["X_UpStreamMaxBitRate"].(map[string]interface{}); ok {
		return true, nil
	}
	return false, nil
}

// --- M8: PUT /bridge-mode/{ip} ---

// SetBridgeModeRequest is the body shape for PUT /bridge-mode/{ip}.
//
// @Description Bridge mode toggle. enabled=true puts the CPE in pure bridge mode (PPPoE termination on customer router). enabled=false reverts to router mode.
type SetBridgeModeRequest struct {
	Enabled     *bool `json:"enabled"`
	WANInstance int   `json:"wan_instance,omitempty"`
}

// SetBridgeModeResponse is the shape returned by PUT /bridge-mode/{ip}.
//
// @Description Bridge mode toggle response.
type SetBridgeModeResponse struct {
	Message     string `json:"message" example:"Bridge mode toggled."`
	DeviceID    string `json:"device_id"`
	IP          string `json:"ip"`
	WANInstance int    `json:"wan_instance" example:"1"`
	Enabled     bool   `json:"enabled" example:"true"`
}

var (
	_ = SetBridgeModeRequest{}
	_ = SetBridgeModeResponse{}
)

// setBridgeModeHandler toggles bridge / router mode on the CPE WAN
// connection by setting the WANPPPConnection.Enable parameter:
// false = bridge mode (no PPPoE on CPE, customer's downstream router
// handles PPPoE termination), true = router mode.
//
// **Coarse approximation.** Real bridge-mode toggling on most consumer
// CPEs requires multiple parameter writes (disable PPPoE, enable IP
// passthrough, switch L2 forwarding mode) and varies by vendor.
// v2.2.0 ships the simplest standard-path approximation; v2.3.0 will
// add vendor detection.
//
//	@Summary		Toggle CPE bridge / router mode
//	@Description	Toggles bridge / router mode on the CPE WAN connection by setting WANPPPConnection.Enable. Coarse approximation — real bridge-mode toggling varies by vendor and may require multiple parameter writes. v2.3.0 adds vendor detection.
//	@Tags			Provisioning
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		SetBridgeModeRequest	true	"Bridge mode toggle"
//	@Success		202		{object}	Response{data=SetBridgeModeResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/bridge-mode/{ip} [put]
func setBridgeModeHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	var req SetBridgeModeRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}

	if errMsg := validateBridgeModeRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}

	// In bridge mode the CPE has Enable=false on its PPPoE connection
	// (so the customer's router takes over PPPoE termination); router
	// mode means Enable=true. The TR-069 enable flag accepts the
	// standard true/false values via xsd:boolean.
	pppEnable := *req.Enabled
	parameterValues := buildBridgeModeParameterValues(pppEnable, req.WANInstance)

	if err := SubmitWLANUpdate(deviceID, parameterValues); err != nil {
		logger.Error("Bridge mode task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrBridgeModeDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusAccepted, SetBridgeModeResponse{
		Message:     MsgBridgeModeUpdated,
		DeviceID:    deviceID,
		IP:          getIPParam(r),
		WANInstance: req.WANInstance,
		Enabled:     *req.Enabled,
	})
}

// validateBridgeModeRequest applies field rules. Pure function.
func validateBridgeModeRequest(req *SetBridgeModeRequest) string {
	if req.Enabled == nil {
		return ErrEnabledRequired
	}
	if req.WANInstance == 0 {
		req.WANInstance = 1
	}
	if req.WANInstance < 1 || req.WANInstance > PPPoEMaxWANInstance {
		return ErrPPPoEInvalidWanInstance
	}
	return ""
}

// buildBridgeModeParameterValues constructs the TR-069 setParameterValues
// payload to toggle the WANPPPConnection enable flag. Pure function.
//
// Note: `bridgeEnabled=true` from the API means "put CPE in bridge
// mode" which means setting WANPPPConnection.Enable=false. The
// inversion is handled here so the buildParameterValues caller passes
// the user-facing intent and gets the TR-069-side parameter shape.
func buildBridgeModeParameterValues(bridgeEnabled bool, wanInstance int) [][]interface{} {
	pppEnable := !bridgeEnabled
	path := fmt.Sprintf(
		"InternetGatewayDevice.WANDevice.%d.WANConnectionDevice.1.WANPPPConnection.1.Enable",
		wanInstance,
	)
	return [][]interface{}{
		{path, pppEnable, XSDBoolean},
	}
}
