package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// handlers_firmware.go contains the v2.2.0 firmware upgrade endpoint:
//
//	POST /api/v1/genieacs/firmware/{ip}  — H5: TR-069 Download RPC
//
// Long-running operation. The handler validates the firmware URL (HTTPS
// only, no private IP / metadata service hosts as a basic SSRF guard),
// dispatches the GenieACS Download task, and returns 202 + the GenieACS
// task ID immediately. Callers (typically isp-agent v0.2+ UpgradeFirmware
// workflow) poll the task status separately via the GenieACS NBI.
//
// **DO NOT TEST IN REAL LAB.** A wrong firmware image bricks the CPE.
// Real-lab validation is gated until at least one customer-supplied
// firmware blob is verified offline against the target ONU model.

// FirmwareUpgradeRequest is the body shape for POST /firmware/{ip}.
//
// @Description Firmware upgrade request — file_url is required and must be HTTPS. file_size, target_filename, username, password, and command_key are optional.
type FirmwareUpgradeRequest struct {
	// FileURL must be HTTPS. Plaintext HTTP is rejected to avoid
	// MITM firmware swaps.
	FileURL string `json:"file_url"`

	// FileType defaults to "1 Firmware Upgrade Image" if blank. Other
	// TR-069 standard values are passed through verbatim — see Annex G
	// of the TR-069 spec for the full list.
	FileType string `json:"file_type,omitempty"`

	// FileSize is optional. When provided, lets the CPE pre-allocate
	// storage and reject trivially malformed payloads.
	FileSize int `json:"file_size,omitempty"`

	// TargetFilename is optional. CPE chooses if blank.
	TargetFilename string `json:"target_filename,omitempty"`

	// Username/Password are optional HTTP basic credentials for
	// fetching the file from a private firmware mirror.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// CommandKey is an optional client correlation tag echoed back in
	// TransferComplete events. ≤ 256 chars.
	CommandKey string `json:"command_key,omitempty"`
}

// FirmwareUpgradeResponse is the shape returned by POST /firmware/{ip}.
//
// @Description Firmware upgrade response — returns the GenieACS task ID and an estimated duration so callers can poll the task status.
type FirmwareUpgradeResponse struct {
	Message                  string `json:"message" example:"Firmware download dispatched."`
	DeviceID                 string `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	IP                       string `json:"ip" example:"192.168.1.1"`
	TaskID                   string `json:"task_id" example:"task-67abc1234567890"`
	EstimatedDurationSeconds int    `json:"estimated_duration_seconds" example:"180"`
}

var (
	_ = FirmwareUpgradeRequest{}
	_ = FirmwareUpgradeResponse{}
)

// FirmwareCommandKeyMaxLength caps the optional command_key field so a
// malicious client can't push large strings through the audit log.
const FirmwareCommandKeyMaxLength = 256

// firmwareUpgradeHandler dispatches a TR-069 Download RPC against the
// CPE. Returns 202 + GenieACS task ID immediately; does NOT block
// waiting for the download to complete.
//
//	@Summary		Dispatch firmware upgrade to CPE
//	@Description	Dispatches a TR-069 Download RPC against the CPE. Validates the firmware URL is HTTPS and that the host is not a private IP or metadata service (basic SSRF guard). Returns 202 + GenieACS task ID immediately so the caller can poll task status. Typical duration 60-300 seconds depending on file size and CPE link speed. **DO NOT TEST IN REAL LAB** — a wrong firmware image bricks the CPE.
//	@Tags			Lifecycle
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		FirmwareUpgradeRequest	true	"Firmware download request"
//	@Success		202		{object}	Response{data=FirmwareUpgradeResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/firmware/{ip} [post]
func firmwareUpgradeHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	var req FirmwareUpgradeRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}

	if errMsg := validateFirmwareRequest(&req); errMsg != "" {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, errMsg)
		return
	}

	taskID, err := downloadFile(r.Context(), deviceID, DownloadRequest{
		FileType:       req.FileType,
		URL:            req.FileURL,
		FileSize:       req.FileSize,
		TargetFilename: req.TargetFilename,
		Username:       req.Username,
		Password:       req.Password,
		CommandKey:     req.CommandKey,
	})
	if err != nil {
		logger.Error("Firmware download dispatch failed",
			zap.String("deviceID", deviceID),
			zap.String("file_url", req.FileURL),
			zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrFirmwareDispatchFailed)
		return
	}
	deviceCacheInstance.clear(deviceID)

	sendResponse(w, http.StatusAccepted, FirmwareUpgradeResponse{
		Message:                  MsgFirmwareDispatched,
		DeviceID:                 deviceID,
		IP:                       getIPParam(r),
		TaskID:                   taskID,
		EstimatedDurationSeconds: estimatedDownloadDuration(req.FileSize),
	})
}

// validateFirmwareRequest applies field-level rules and also fills in
// the file_type default. Returns "" on success or a user-facing error
// message on failure. Pure function for unit testability.
func validateFirmwareRequest(req *FirmwareUpgradeRequest) string {
	if req.FileURL == "" {
		return ErrFirmwareURLRequired
	}
	if req.FileSize < 0 {
		return ErrFirmwareFileSizeNegative
	}
	if len(req.CommandKey) > FirmwareCommandKeyMaxLength {
		return ErrFirmwareCommandKeyTooLong
	}
	if req.FileType == "" {
		req.FileType = DefaultFirmwareFileType
	}
	if errMsg := validateFirmwareURL(req.FileURL); errMsg != "" {
		return errMsg
	}
	return ""
}

// validateFirmwareURL enforces the basic safety rules for a firmware
// fetch URL:
//
//   - Must parse as a valid URL with a host
//   - Scheme must be exactly "https" (no plain HTTP, no FTP, no file://)
//   - Host must not be a private IP, loopback, link-local, or metadata
//     service (basic SSRF guard against fetching from internal
//     infrastructure)
//
// This is NOT a full SSRF defense — a malicious DNS server can still
// resolve a public hostname to a private IP at fetch time on the CPE
// side. But it catches the obvious mistakes (file:///, http://localhost,
// http://169.254.169.254, etc.) at the relay boundary so they never
// reach GenieACS.
func validateFirmwareURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ErrFirmwareURLMalformed
	}
	if u.Scheme != "https" {
		return ErrFirmwareURLNotHTTPS
	}
	if u.Host == "" {
		return ErrFirmwareURLMissingHost
	}

	// Strip optional port.
	host := u.Hostname()

	// Reject obvious metadata service hostnames.
	switch strings.ToLower(host) {
	case "localhost", "metadata", "metadata.google.internal":
		return ErrFirmwareURLPrivateHost
	}

	// Reject private / loopback / link-local IPs if the host is a
	// literal IP. (Hostname-resolved-to-private-IP is NOT caught here.)
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return ErrFirmwareURLPrivateHost
		}
	}
	return ""
}

// estimatedDownloadDuration returns a rough estimate of the firmware
// download duration in seconds, given the file size in bytes. Used
// for the response field so callers know roughly when to poll. Not
// authoritative — actual duration depends on CPE link speed and
// flash write speed, which we have no visibility into.
//
// Heuristic: assume 200 KB/s sustained (a slow ADSL2+ uplink) plus a
// 30-second flash write window. Caps at 600s to avoid suggesting
// callers wait 10 minutes for a 100MB file when in practice the
// transfer would have failed long before then.
func estimatedDownloadDuration(fileSize int) int {
	const minDuration = 60  // floor: assume at least 60s for handshake + small file
	const maxDuration = 600 // ceiling: 10 minutes is a sane upper bound
	const flashWriteWindow = 30
	const bytesPerSecond = 200 * 1024

	if fileSize <= 0 {
		return minDuration
	}
	d := flashWriteWindow + (fileSize / bytesPerSecond)
	if d < minDuration {
		return minDuration
	}
	if d > maxDuration {
		return maxDuration
	}
	return d
}
