package main

import (
	"encoding/json"
	"io"
	"net/http"

	"go.uber.org/zap"
)

// encodeJSON encodes v as JSON to w. Used by health/readiness handlers that bypass
// the standard Response envelope.
func encodeJSON(w io.Writer, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}

// sendResponse emits a standardized success envelope with status "success".
// Per isp-adapter-standard, success responses do not include error_code or request_id
// in the body (request_id is still echoed via the X-Request-ID response header).
func sendResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(Response{
		Code:   code,
		Status: StatusSuccess,
		Data:   data,
	}); err != nil {
		logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// sendError emits a standardized error envelope with error_code, human-readable
// data, and request_id per isp-adapter-standard. The `status` field is derived
// from the HTTP status code via http.StatusText so callers only need to provide
// code + error code + message.
//
// The request parameter is used to extract the request_id from the context.
// Passing a nil request is supported for non-request contexts (e.g. panic handlers)
// but will result in an empty request_id field.
func sendError(w http.ResponseWriter, r *http.Request, code int, errorCode string, data interface{}) {
	reqID := ""
	if r != nil {
		reqID = RequestIDFromContext(r.Context())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(Response{
		Code:      code,
		Status:    http.StatusText(code),
		ErrorCode: errorCode,
		Data:      data,
		RequestID: reqID,
	}); err != nil {
		logger.Error("Failed to encode JSON error response", zap.Error(err))
	}
}
