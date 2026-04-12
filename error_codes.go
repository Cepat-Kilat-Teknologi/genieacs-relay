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
)
