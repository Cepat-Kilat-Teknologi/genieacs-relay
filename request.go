package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// GetClientIP returns the client address for audit logs, auth lockout and
// rate limiting. Forwarding headers count only from RATE_LIMIT_TRUSTED_PROXIES.
func GetClientIP(r *http.Request) string {
	return trustedProxies.ClientIP(r)
}

// safeClose safely closes an io.Closer resource and logs any errors
func safeClose(closer io.Closer) {
	if closer != nil {
		if err := closer.Close(); err != nil {
			logger.Warn("Failed to close resource", zap.Error(err))
		}
	}
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}

// --- HTTP Handler Helpers ---

// ExtractDeviceIDByIP is a helper that extracts device ID from IP and handles common error responses
// Returns the device ID and true if successful, or sends an error response and returns false
func ExtractDeviceIDByIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip := chi.URLParam(r, "ip")
	if err := validateIP(ip); err != nil {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ipValidationMessage(err))
		return "", false
	}
	deviceID, err := getDeviceIDByIP(r.Context(), ip)
	if err != nil {
		logger.Error("Failed to get device ID by IP", zap.String("ip", ip), zap.Error(err))
		status, code, msg := lookupErrorResponse(err)
		sendError(w, r, status, code, msg)
		return "", false
	}
	return deviceID, true
}

// nbiLookupFailed reports whether an NBI status on the device lookup is an
// upstream failure: a 5xx, or a 401/403 from the NBI auth proxy, which means
// NBI_AUTH_KEY is wrong rather than that the device is missing.
func nbiLookupFailed(status int) bool {
	return status >= http.StatusInternalServerError ||
		status == http.StatusUnauthorized || status == http.StatusForbidden
}

// ipValidationMessage returns the client message for a validateIP error. The
// format error embeds the raw path value, so it is replaced by a fixed text;
// the other validateIP errors are fixed strings already.
func ipValidationMessage(err error) string {
	if strings.HasPrefix(err.Error(), "invalid IP address format") {
		return "Invalid IP address format"
	}
	return err.Error()
}

// lookupErrorResponse maps a device lookup error to the HTTP status, error
// code and message sent to the client. Only a lookup that reached GenieACS
// and found no usable device is a 404; timeouts, an open circuit and NBI
// server errors say so, so callers do not mistake them for a missing device.
func lookupErrorResponse(err error) (int, string, string) {
	var statusErr *nbiStatusError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusRequestTimeout, ErrCodeTimeout, ErrDeviceLookupTimeout
	case errors.Is(err, ErrCircuitOpen):
		return http.StatusServiceUnavailable, ErrCodeServiceUnavailable, ErrDeviceLookupUnavailable
	case errors.As(err, &statusErr) && nbiLookupFailed(statusErr.StatusCode):
		return http.StatusBadGateway, ErrCodeGenieACS, ErrDeviceLookupUpstream
	default:
		return http.StatusNotFound, ErrCodeNotFound, sanitizeErrorMessage(err)
	}
}

// getIPParam returns the `{ip}` URL path parameter from the request.
// Used by handlers that need to echo the original IP back in the
// response body. Centralized to avoid `chi.URLParam` calls scattered
// through handler files.
func getIPParam(r *http.Request) string {
	return chi.URLParam(r, "ip")
}

// ParseJSONRequest parses a JSON request body with size limiting and Content-Type validation.
// Returns true if successful, false if an error response was sent.
func ParseJSONRequest(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	// Validate Content-Type header to prevent non-JSON payloads
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		sendError(w, r, http.StatusUnsupportedMediaType, ErrCodeValidation, ErrInvalidContentType)
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		if err.Error() == ErrBodyTooLarge {
			sendError(w, r, http.StatusRequestEntityTooLarge, ErrCodeValidation, ErrRequestBodyTooLarge)
			return false
		}
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrInvalidJSON)
		return false
	}
	return true
}
