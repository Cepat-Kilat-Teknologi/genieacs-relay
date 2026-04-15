package main

// Machine-readable error codes per isp-adapter-standard §2.
// These populate the `error_code` field in error responses so clients (especially
// billing-agent) can branch on error type without parsing the human-readable `data` message.
const (
	ErrCodeValidation         = "VALIDATION_ERROR"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeNotFound           = "NOT_FOUND"
	ErrCodeConflict           = "CONFLICT"
	ErrCodeTimeout            = "TIMEOUT"
	ErrCodeRateLimited        = "RATE_LIMITED"
	ErrCodeInternal           = "INTERNAL_ERROR"
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	// GenieACS-specific error code for upstream TR-069 / NBI failures.
	ErrCodeGenieACS = "GENIEACS_ERROR"
	// QoS-specific: CPE model lacks the X_*StreamMaxBitRate vendor
	// extension the v2.2 QoS handler writes to. Returned with HTTP 501
	// Not Implemented (not 400/404) because the request is valid but
	// the feature is unimplemented for this specific device.
	ErrCodeQoSUnsupported = "QOS_UNSUPPORTED_BY_DEVICE"
)
