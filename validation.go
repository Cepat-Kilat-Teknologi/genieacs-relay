package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// validateIP validates that the provided string is a valid IP address.
// It rejects loopback, multicast, and unspecified addresses for security.
func validateIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf(ErrInvalidIPAddress, ip)
	}

	// Reject loopback addresses (127.0.0.0/8, ::1)
	if parsed.IsLoopback() {
		return errors.New("loopback addresses are not allowed")
	}

	// Reject multicast addresses
	if parsed.IsMulticast() {
		return errors.New("multicast addresses are not allowed")
	}

	// Reject unspecified addresses (0.0.0.0, ::)
	if parsed.IsUnspecified() {
		return errors.New("unspecified addresses are not allowed")
	}

	// Reject IPv6 — GenieACS NBI queries only search IPv4 WAN fields
	if parsed.To4() == nil {
		return errors.New("IPv6 addresses are not supported, use IPv4")
	}

	return nil
}

// validateWLANID validates that the WLAN ID is a numeric value between 1 and 8
// IDs 1-4 are for 2.4GHz, IDs 5-8 are for 5GHz (dual-band devices only)
func validateWLANID(wlanID string) error {
	num, err := strconv.Atoi(wlanID)
	if err != nil {
		return errors.New(ErrInvalidWLANID)
	}
	if num < WLAN24GHzMin || num > WLAN5GHzMax {
		return errors.New(ErrInvalidWLANID)
	}
	return nil
}

// validateSSIDCharacters validates that the SSID contains only allowed characters
// SSIDs should only contain printable ASCII characters (0x20-0x7E) to prevent
// control character injection and display issues on various devices
func validateSSIDCharacters(ssid string) error {
	for _, r := range ssid {
		// Allow only printable ASCII characters (space to tilde)
		// This excludes control characters (0x00-0x1F) and DEL (0x7F)
		// as well as non-ASCII characters that may cause compatibility issues
		if r < 0x20 || r > 0x7E {
			return errors.New(ErrSSIDInvalidChars)
		}
	}
	return nil
}

// --- Band-Specific WLAN Validation ---

// ValidateWLANChannel validates channel for the specified band.
// Returns error if channel is invalid for the band.
func ValidateWLANChannel(channel string, is5GHz bool) error {
	if is5GHz {
		if !ValidChannels5GHz[channel] {
			return errors.New(ErrInvalidChannel5GHz)
		}
	} else {
		if !ValidChannels24GHz[channel] {
			return errors.New(ErrInvalidChannel24GHz)
		}
	}
	return nil
}

// ValidateWLANMode validates WiFi mode for the specified band.
// Returns the TR-069 mode value and error if mode is invalid.
func ValidateWLANMode(mode string, is5GHz bool) (string, error) {
	if is5GHz {
		tr069Mode, valid := ValidModes5GHz[mode]
		if !valid {
			return "", errors.New(ErrInvalidMode5GHz)
		}
		return tr069Mode, nil
	}
	tr069Mode, valid := ValidModes24GHz[mode]
	if !valid {
		return "", errors.New(ErrInvalidMode24GHz)
	}
	return tr069Mode, nil
}

// ValidateWLANBandwidth validates bandwidth for the specified band.
// Returns error if bandwidth is invalid for the band.
func ValidateWLANBandwidth(bandwidth string, is5GHz bool) error {
	if is5GHz {
		if !ValidBandwidth5GHz[bandwidth] {
			return errors.New(ErrInvalidBandwidth5GHz)
		}
	} else {
		if !ValidBandwidth24GHz[bandwidth] {
			return errors.New(ErrInvalidBandwidth24GHz)
		}
	}
	return nil
}

// sanitizeErrorMessage removes potentially sensitive information from error messages
func sanitizeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	errMsg := err.Error()

	// Safe validation errors - pass through as-is
	// These are pre-sanitized and contain no user input or sensitive data
	safePatterns := []string{
		"invalid channel for",
		"invalid mode for",
		"invalid bandwidth for",
		"invalid transmit power",
		"WLAN ID must be between",
		"does not support 5GHz WLAN",
		"unable to verify device capability",
	}
	for _, pattern := range safePatterns {
		if strings.Contains(errMsg, pattern) {
			return errMsg
		}
	}

	// List of patterns that might contain sensitive info
	// Remove device IDs from error messages
	if strings.Contains(errMsg, "device not found with IP") {
		return "Device not found"
	}
	if strings.Contains(errMsg, "no device found with ID") {
		return "Device not found"
	}
	if strings.Contains(errMsg, "device with IP") && strings.Contains(errMsg, "is stale") {
		return "Device is offline or unresponsive"
	}
	if strings.Contains(errMsg, "invalid IP address format") {
		return "Invalid IP address format"
	}
	if strings.Contains(errMsg, "GenieACS returned non-OK status") {
		return "Backend service error"
	}
	if strings.Contains(errMsg, "HTTP error") {
		return "Backend service error"
	}

	// Return generic message for unknown errors to prevent info leakage
	return "An error occurred processing your request"
}
