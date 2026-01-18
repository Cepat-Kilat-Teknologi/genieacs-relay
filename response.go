package main

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// sendResponse sends a standardized success response with JSON formatting
func sendResponse(w http.ResponseWriter, code int, status string, data interface{}) {
	w.Header().Set("Content-Type", "application/json") // Set response content type
	w.WriteHeader(code)                                // Set HTTP status code
	// Encode and send JSON response
	if err := json.NewEncoder(w).Encode(Response{Code: code, Status: status, Data: data}); err != nil {
		logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// sendError sends a standardized error response with JSON formatting
func sendError(w http.ResponseWriter, code int, status string, errorMsg string) {
	w.Header().Set("Content-Type", "application/json") // Set response content type
	w.WriteHeader(code)                                // Set HTTP status code
	// Encode and send JSON error response
	if err := json.NewEncoder(w).Encode(Response{Code: code, Status: status, Error: errorMsg}); err != nil {
		logger.Error("Failed to encode JSON error response", zap.Error(err))
	}
}
