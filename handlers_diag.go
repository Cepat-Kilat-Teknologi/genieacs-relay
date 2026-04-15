package main

import (
	"context"
	"net/http"

	"go.uber.org/zap"
)

// handlers_diag.go contains the v2.2.0 TR-069 diagnostic dispatch
// endpoints:
//
//	POST /api/v1/genieacs/diag/ping/{ip}        — M1: IPPingDiagnostics
//	POST /api/v1/genieacs/diag/traceroute/{ip}  — M2: TraceRouteDiagnostics
//
// TR-069 diagnostics are 2-stage:
//   1. SetParameterValues to configure target host, count, timeout, +
//      `DiagnosticsState=Requested` (the trigger flag).
//   2. CPE runs the diagnostic, populates result fields, sets
//      `DiagnosticsState=Complete` and informs back to the ACS.
//
// v2.2.0 ships ONLY the dispatch step. Result polling is delegated to
// the existing `/params/{ip}` endpoint — callers POST a list of result
// paths after a few seconds and read the values from the cached tree.
// Future v2.3.0 may add a relay-side wait+result endpoint if field
// experience shows the polling pattern is too painful.
//
// **Idempotency.** TR-069 diagnostics overwrite the previous run's
// result fields, so the second call replaces the first — there is no
// per-run task ID to track. The relay's request-level idempotency
// middleware applies, so saga retries within the dedup TTL replay the
// same response.

// PingDiagRequest is the body shape for POST /diag/ping/{ip}.
//
// @Description IPPingDiagnostics request — host is required (target IP or DNS name), count and timeout_ms are optional with sensible defaults.
type PingDiagRequest struct {
	Host          string `json:"host"`
	Count         int    `json:"count,omitempty"`
	TimeoutMs     int    `json:"timeout_ms,omitempty"`
	DataBlockSize int    `json:"data_block_size,omitempty"`
	DSCP          int    `json:"dscp,omitempty"`
}

// TraceRouteDiagRequest is the body shape for POST /diag/traceroute/{ip}.
//
// @Description TraceRouteDiagnostics request — host is required, max_hops and timeout_ms are optional.
type TraceRouteDiagRequest struct {
	Host          string `json:"host"`
	MaxHops       int    `json:"max_hops,omitempty"`
	TimeoutMs     int    `json:"timeout_ms,omitempty"`
	DataBlockSize int    `json:"data_block_size,omitempty"`
	DSCP          int    `json:"dscp,omitempty"`
}

// DiagDispatchResponse is the shape returned by either /diag endpoint
// once the trigger task is queued.
//
// @Description Diagnostic dispatch response — confirms the trigger task is queued, plus a list of result parameter paths the caller should poll via /params/{ip}.
type DiagDispatchResponse struct {
	Message     string   `json:"message"`
	DeviceID    string   `json:"device_id"`
	IP          string   `json:"ip"`
	Diagnostic  string   `json:"diagnostic"`
	ResultPaths []string `json:"result_paths"`
}

var (
	_ = PingDiagRequest{}
	_ = TraceRouteDiagRequest{}
	_ = DiagDispatchResponse{}
)

// Default and bounds for diagnostic params.
const (
	DefaultPingCount          = 4
	DefaultPingTimeoutMs      = 5000
	DefaultTraceMaxHops       = 30
	DefaultTraceTimeoutMs     = 5000
	MinDiagCount              = 1
	MaxDiagCount              = 64
	MinDiagTimeoutMs          = 100
	MaxDiagTimeoutMs          = 60000
	IPPingDiagnosticsBase     = "InternetGatewayDevice.IPPingDiagnostics"
	TraceRouteDiagnosticsBase = "InternetGatewayDevice.TraceRouteDiagnostics"
)

// dispatchPingHandler triggers a TR-069 IPPingDiagnostics task.
//
//	@Summary		Dispatch IP ping diagnostic
//	@Description	Triggers a TR-069 IPPingDiagnostics task against the CPE. v2.2.0 ships ONLY the dispatch step — poll result fields via /params/{ip} after 5-15 seconds (the response includes the list of result parameter paths). Standard TR-098 path: `InternetGatewayDevice.IPPingDiagnostics.*`.
//	@Tags			Diagnostics
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string			true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		PingDiagRequest	true	"Ping diagnostic parameters"
//	@Success		202		{object}	Response{data=DiagDispatchResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/diag/ping/{ip} [post]
func dispatchPingHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req PingDiagRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validatePingRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}

	parameterValues := buildPingParameterValues(req)
	if err := setParameterValues(r.Context(), deviceID, parameterValues); err != nil {
		logger.Error("Ping diag dispatch failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrDiagDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusAccepted, DiagDispatchResponse{
		Message:    MsgDiagDispatched,
		DeviceID:   deviceID,
		IP:         getIPParam(r),
		Diagnostic: "ping",
		ResultPaths: []string{
			IPPingDiagnosticsBase + ".DiagnosticsState",
			IPPingDiagnosticsBase + ".SuccessCount",
			IPPingDiagnosticsBase + ".FailureCount",
			IPPingDiagnosticsBase + ".AverageResponseTime",
			IPPingDiagnosticsBase + ".MinimumResponseTime",
			IPPingDiagnosticsBase + ".MaximumResponseTime",
		},
	})
}

// validatePingRequest applies field rules + fills in defaults.
func validatePingRequest(req *PingDiagRequest) string {
	if req.Host == "" {
		return ErrDiagInvalidHost
	}
	if req.Count == 0 {
		req.Count = DefaultPingCount
	}
	if req.Count < MinDiagCount || req.Count > MaxDiagCount {
		return ErrDiagInvalidCount
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = DefaultPingTimeoutMs
	}
	if req.TimeoutMs < MinDiagTimeoutMs || req.TimeoutMs > MaxDiagTimeoutMs {
		return ErrDiagInvalidTimeout
	}
	return ""
}

// buildPingParameterValues constructs the SetParameterValues payload
// for IPPingDiagnostics. The DiagnosticsState=Requested entry is the
// trigger — it MUST be the last entry per TR-069 §A.4.1 so the CPE
// applies all the input params before starting the diagnostic run.
func buildPingParameterValues(req PingDiagRequest) [][]interface{} {
	values := [][]interface{}{
		{IPPingDiagnosticsBase + ".Host", req.Host, XSDString},
		{IPPingDiagnosticsBase + ".NumberOfRepetitions", req.Count, XSDUnsignedInt},
		{IPPingDiagnosticsBase + ".Timeout", req.TimeoutMs, XSDUnsignedInt},
	}
	if req.DataBlockSize > 0 {
		values = append(values, []interface{}{
			IPPingDiagnosticsBase + ".DataBlockSize", req.DataBlockSize, XSDUnsignedInt,
		})
	}
	if req.DSCP > 0 {
		values = append(values, []interface{}{
			IPPingDiagnosticsBase + ".DSCP", req.DSCP, XSDUnsignedInt,
		})
	}
	values = append(values, []interface{}{
		IPPingDiagnosticsBase + ".DiagnosticsState", "Requested", XSDString,
	})
	return values
}

// dispatchTraceRouteHandler triggers a TR-069 TraceRouteDiagnostics
// task.
//
//	@Summary		Dispatch traceroute diagnostic
//	@Description	Triggers a TR-069 TraceRouteDiagnostics task against the CPE. v2.2.0 ships ONLY the dispatch step — poll result fields via /params/{ip} after 5-15 seconds (the response includes the list of result parameter paths). Standard TR-098 path: `InternetGatewayDevice.TraceRouteDiagnostics.*`.
//	@Tags			Diagnostics
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		TraceRouteDiagRequest	true	"Traceroute diagnostic parameters"
//	@Success		202		{object}	Response{data=DiagDispatchResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/diag/traceroute/{ip} [post]
func dispatchTraceRouteHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	var req TraceRouteDiagRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}
	if errMsg := validateTraceRouteRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}

	parameterValues := buildTraceRouteParameterValues(req)
	if err := setParameterValues(r.Context(), deviceID, parameterValues); err != nil {
		logger.Error("Traceroute diag dispatch failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrDiagDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusAccepted, DiagDispatchResponse{
		Message:    MsgDiagDispatched,
		DeviceID:   deviceID,
		IP:         getIPParam(r),
		Diagnostic: "traceroute",
		ResultPaths: []string{
			TraceRouteDiagnosticsBase + ".DiagnosticsState",
			TraceRouteDiagnosticsBase + ".ResponseTime",
			TraceRouteDiagnosticsBase + ".RouteHopsNumberOfEntries",
		},
	})
}

func validateTraceRouteRequest(req *TraceRouteDiagRequest) string {
	if req.Host == "" {
		return ErrDiagInvalidHost
	}
	if req.MaxHops == 0 {
		req.MaxHops = DefaultTraceMaxHops
	}
	if req.MaxHops < MinDiagCount || req.MaxHops > MaxDiagCount {
		return ErrDiagInvalidCount
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = DefaultTraceTimeoutMs
	}
	if req.TimeoutMs < MinDiagTimeoutMs || req.TimeoutMs > MaxDiagTimeoutMs {
		return ErrDiagInvalidTimeout
	}
	return ""
}

func buildTraceRouteParameterValues(req TraceRouteDiagRequest) [][]interface{} {
	values := [][]interface{}{
		{TraceRouteDiagnosticsBase + ".Host", req.Host, XSDString},
		{TraceRouteDiagnosticsBase + ".MaxHopCount", req.MaxHops, XSDUnsignedInt},
		{TraceRouteDiagnosticsBase + ".Timeout", req.TimeoutMs, XSDUnsignedInt},
	}
	if req.DataBlockSize > 0 {
		values = append(values, []interface{}{
			TraceRouteDiagnosticsBase + ".DataBlockSize", req.DataBlockSize, XSDUnsignedInt,
		})
	}
	if req.DSCP > 0 {
		values = append(values, []interface{}{
			TraceRouteDiagnosticsBase + ".DSCP", req.DSCP, XSDUnsignedInt,
		})
	}
	values = append(values, []interface{}{
		TraceRouteDiagnosticsBase + ".DiagnosticsState", "Requested", XSDString,
	})
	return values
}

// Compile-time guard that the package-level setParameterValues
// function (defined in client.go) is consumed by this file. Catches
// future refactors that drop the setParameterValues path.
var _ = func(ctx context.Context) error {
	return setParameterValues(ctx, "", nil)
}
