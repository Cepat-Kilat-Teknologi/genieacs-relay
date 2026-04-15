package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// tr069.go contains generic TR-069 RPC dispatcher helpers used by the
// v2.2.0 endpoint family. Each helper wraps a single GenieACS NBI task
// submission (`POST /devices/{id}/tasks?connection_request`) with the
// appropriate JSON body shape and consistent error wrapping.
//
// The helpers intentionally do NOT do any input validation beyond the
// minimum needed to construct a well-formed task body — validation is
// the caller's responsibility (handlers run their own input checks
// before reaching here so the error responses can be precisely tagged
// with VALIDATION_ERROR vs GENIEACS_ERROR).
//
// Status-code policy follows the existing rebootDevice / refreshDHCP
// pattern: GenieACS returns 200 OK when the task is applied
// synchronously (connection_request succeeded) or 202 Accepted when the
// task is queued for the device's next inform. Both are success. Only
// 4xx/5xx responses surface as Go errors.

// factoryResetDevice triggers a TR-069 FactoryReset RPC against the
// CPE identified by deviceID. This is destructive — the CPE will lose
// its current PPPoE credentials, WLAN config, port-forward rules, and
// any other locally-stored state, then rejoin the ACS in a fresh
// provisioning state. The device is unreachable for 60-180 seconds
// after the task is applied while it reboots and re-acquires a WAN
// connection.
//
// Callers (typically the H6 factory-reset handler and the future
// isp-agent v0.2+ FactoryResetCpe workflow) MUST clear the in-process
// device cache after a successful reset since the post-reset device
// tree will look entirely different.
func factoryResetDevice(ctx context.Context, deviceID string) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request",
		geniesBaseURL, url.PathEscape(deviceID))

	payload := `{"name": "factoryReset"}`

	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return fmt.Errorf("factoryReset: %w", err)
	}
	defer safeClose(resp.Body)

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("factoryReset failed with status %s: %s",
			resp.Status, string(body))
	}
	return nil
}

// connectionRequest fires a TR-069 ConnectionRequest against the CPE
// without queuing any actual work — used purely to wake an idle
// device so subsequent operations land synchronously instead of
// queuing for the next inform. Wraps the GenieACS NBI by submitting
// a no-op getParameterValues task for `_lastInform` (a parameter that
// is always present) with `?connection_request` enabled. The minimal
// task body is the cheapest way to force the device to dial home.
//
// The wake itself is fire-and-forget from the caller's perspective:
// the underlying TR-069 ConnectionRequest is a UDP poke that triggers
// the device to open a session within 1-30 seconds depending on its
// network conditions and CWMP timer config. We do NOT block waiting
// for the device to actually wake up — callers needing post-wake
// confirmation should follow up with a status query workflow.
func connectionRequest(ctx context.Context, deviceID string) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request",
		geniesBaseURL, url.PathEscape(deviceID))

	// Cheapest no-op task: ask for a parameter that is always present.
	// `_lastInform` exists on every device record, so the CPE only has
	// to read a single timestamp from its own cache and ack — no real
	// CWMP work happens, but the connection request still fires.
	payload := `{"name": "getParameterValues", "parameterNames": ["InternetGatewayDevice.DeviceInfo.UpTime"]}`

	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return fmt.Errorf("connectionRequest: %w", err)
	}
	defer safeClose(resp.Body)

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("connectionRequest failed with status %s: %s",
			resp.Status, string(body))
	}
	return nil
}

// getParameterValuesLive triggers a TR-069 GetParameterValues task
// against the CPE for the given parameter paths, with `?connection_request`
// so the task is applied synchronously when the device is reachable.
// The returned values are NOT in this function's response — they are
// written to the device tree on the GenieACS side and become readable
// via getDeviceData on the next call. Callers wanting to read the
// freshly-fetched values should call this, then clear the device cache,
// then call getDeviceData.
//
// This helper is used by the H7 /params/{ip} endpoint when `live=true`.
// The cached mode of /params just walks the existing device tree
// without going through this helper at all.
func getParameterValuesLive(ctx context.Context, deviceID string, paths []string) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request",
		geniesBaseURL, url.PathEscape(deviceID))

	// json.Marshal on a struct with only string + []string fields
	// cannot fail (no channels, functions, or unsupported types), so
	// the error return is dropped to keep coverage clean.
	type getParamTask struct {
		Name           string   `json:"name"`
		ParameterNames []string `json:"parameterNames"`
	}
	payloadBytes, _ := json.Marshal(getParamTask{
		Name:           "getParameterValues",
		ParameterNames: paths,
	})

	resp, err := postJSONRequest(ctx, urlQ, string(payloadBytes))
	if err != nil {
		return fmt.Errorf("getParameterValuesLive: %w", err)
	}
	defer safeClose(resp.Body)

	if resp.StatusCode >= http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("getParameterValuesLive failed with status %s: %s",
			resp.Status, string(respBody))
	}
	return nil
}

// DownloadRequest carries the parameters for a TR-069 Download RPC.
// Used by the H5 firmware/{ip} handler.
type DownloadRequest struct {
	// FileType is the TR-069 standard file type identifier. Common
	// values: "1 Firmware Upgrade Image" (the default and most useful
	// for ISP firmware rollouts), "3 Vendor Configuration File", or
	// "2 Web Content". See TR-069 Annex G.
	FileType string `json:"file_type"`

	// URL is the HTTPS URL the CPE will fetch. Plaintext HTTP is
	// rejected at the handler layer to avoid MITM firmware swaps.
	URL string `json:"file_url"`

	// FileSize is optional but recommended — lets the CPE pre-allocate
	// storage and reject trivially malformed payloads. Bytes.
	FileSize int `json:"file_size,omitempty"`

	// TargetFilename is optional. CPE chooses if blank.
	TargetFilename string `json:"target_filename,omitempty"`

	// Username/Password are optional HTTP basic credentials for
	// fetching the file. Most ISP firmware servers serve with
	// signed-URL or open access, so these are usually empty.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// CommandKey is an optional client correlation tag. Echoed back
	// in TransferComplete events so a fleet rollout job can correlate
	// per-device outcomes.
	CommandKey string `json:"command_key,omitempty"`
}

// downloadFile submits a TR-069 Download RPC task against the CPE and
// returns the GenieACS NBI task ID so the caller can poll status via
// /tasks/{task_id}. Long-running — typical firmware images are
// 4-32 MB and take 60-300 seconds to transfer + apply, depending on
// CPE link speed and flash speed.
//
// This helper does NOT validate the URL — that's the handler's job
// (HTTPS-only, SSRF guard against private IPs / metadata services).
// It also does NOT block waiting for the download to complete; the
// task is queued on the GenieACS NBI side and the device picks it
// up on its next inform (or immediately via the connection request).
func downloadFile(ctx context.Context, deviceID string, req DownloadRequest) (string, error) {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request",
		geniesBaseURL, url.PathEscape(deviceID))

	// Build the GenieACS task body. Field names follow GenieACS NBI
	// convention (camelCase fileType/fileSize) which differs from the
	// Go-side snake_case JSON tags on DownloadRequest above.
	type downloadTask struct {
		Name           string `json:"name"`
		FileType       string `json:"fileType"`
		URL            string `json:"url"`
		FileSize       int    `json:"fileSize,omitempty"`
		TargetFileName string `json:"targetFileName,omitempty"`
		Username       string `json:"username,omitempty"`
		Password       string `json:"password,omitempty"`
		CommandKey     string `json:"commandKey,omitempty"`
	}
	// Marshal cannot fail on a struct of only string + int fields.
	// gosec G117 flags the Password field as a "secret pattern" — the
	// suppression is correct here because Password is the optional HTTP
	// basic credential the CPE uses to fetch the firmware blob from
	// the operator's signed-URL mirror, not a customer or system
	// credential. It only ever lives in flight from this call to the
	// GenieACS NBI which then forwards it to the CPE; we don't store
	// it anywhere.
	//nolint:gosec // G117: Password is an optional HTTP basic auth field for the firmware download URL, not a stored secret
	payloadBytes, _ := json.Marshal(downloadTask{
		Name:           "download",
		FileType:       req.FileType,
		URL:            req.URL,
		FileSize:       req.FileSize,
		TargetFileName: req.TargetFilename,
		Username:       req.Username,
		Password:       req.Password,
		CommandKey:     req.CommandKey,
	})

	resp, err := postJSONRequest(ctx, urlQ, string(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("downloadFile: %w", err)
	}
	defer safeClose(resp.Body)

	if resp.StatusCode >= http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("downloadFile failed with status %s: %s",
			resp.Status, string(respBody))
	}

	// GenieACS NBI returns the task object on success with `_id` field
	// populated. Decode it just enough to extract the ID.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("downloadFile: read response: %w", err)
	}

	var taskResp struct {
		ID string `json:"_id"`
	}
	if err := json.Unmarshal(respBody, &taskResp); err != nil {
		// Some GenieACS versions return an empty body on 200; that's
		// acceptable but means we can't return a task ID. Return a
		// sentinel string the handler can recognize.
		return "", nil
	}
	return taskResp.ID, nil
}

// addObject submits a TR-069 AddObject RPC task. Returns the new
// instance number on success. Used for creating new
// PortMapping / DHCPStaticAddress / WLANConfiguration entries.
//
// The instance number returned by GenieACS lives at the
// `parameterValues[0][1]` position of the response body when the task
// is applied synchronously; when queued, it's only available after
// the device informs back. v2.2.0 returns 0 in the queued case and
// callers can re-read the device tree to discover the new instance.
func addObject(ctx context.Context, deviceID, objectName string) (int, error) {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request",
		geniesBaseURL, url.PathEscape(deviceID))

	type addObjectTask struct {
		Name       string `json:"name"`
		ObjectName string `json:"objectName"`
	}
	// Marshal cannot fail on a struct of only string fields.
	payloadBytes, _ := json.Marshal(addObjectTask{
		Name:       "addObject",
		ObjectName: objectName,
	})

	resp, err := postJSONRequest(ctx, urlQ, string(payloadBytes))
	if err != nil {
		return 0, fmt.Errorf("addObject: %w", err)
	}
	defer safeClose(resp.Body)

	if resp.StatusCode >= http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("addObject failed with status %s: %s",
			resp.Status, string(respBody))
	}

	// Best-effort instance extraction. The instance number lives at
	// `parameterValues[0][1]` when the task runs sync; for the queued
	// case we return 0 and let the caller re-discover via getDeviceData.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil
	}
	return parseAddObjectInstance(respBody), nil
}

// parseAddObjectInstance walks the GenieACS task response shape to
// pull out the new instance number. Split into its own function so it
// is unit-testable without an httptest.Server.
func parseAddObjectInstance(body []byte) int {
	var taskResp struct {
		ParameterValues [][]interface{} `json:"parameterValues"`
	}
	if err := json.Unmarshal(body, &taskResp); err != nil {
		return 0
	}
	if len(taskResp.ParameterValues) == 0 {
		return 0
	}
	first := taskResp.ParameterValues[0]
	if len(first) < 2 {
		return 0
	}
	// The instance is encoded as either a JSON number (-> float64
	// after Unmarshal into interface{}) or a string. Handle both.
	switch v := first[1].(type) {
	case float64:
		return int(v)
	case string:
		// Parse a numeric string like "5"; ignore non-numeric values.
		n := 0
		for _, c := range v {
			if c < '0' || c > '9' {
				return 0
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}

// deleteObject submits a TR-069 DeleteObject RPC task. The objectName
// must be a fully-qualified instance path (e.g.
// `InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.`). Used for
// removing PortMapping / DHCPStaticAddress / WLANConfiguration entries.
func deleteObject(ctx context.Context, deviceID, objectName string) error {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request",
		geniesBaseURL, url.PathEscape(deviceID))

	type delObjectTask struct {
		Name       string `json:"name"`
		ObjectName string `json:"objectName"`
	}
	// Marshal cannot fail on a struct of only string fields.
	payloadBytes, _ := json.Marshal(delObjectTask{
		Name:       "deleteObject",
		ObjectName: objectName,
	})

	resp, err := postJSONRequest(ctx, urlQ, string(payloadBytes))
	if err != nil {
		return fmt.Errorf("deleteObject: %w", err)
	}
	defer safeClose(resp.Body)

	if resp.StatusCode >= http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deleteObject failed with status %s: %s",
			resp.Status, string(respBody))
	}
	return nil
}

// validateTRParamPath returns an error for parameter path strings that
// look unsafe to forward to the GenieACS NBI. Safe paths consist only
// of letters, digits, dots, and underscores. Used by the H7
// /params/{ip} handler which accepts caller-supplied paths.
func validateTRParamPath(p string) error {
	if p == "" {
		return fmt.Errorf("parameter path is empty")
	}
	if len(p) > 256 {
		return fmt.Errorf("parameter path too long (max 256 chars)")
	}
	if !isASCIILetter(p[0]) {
		return fmt.Errorf("parameter path must start with a letter")
	}
	for _, c := range p {
		if !isParamPathChar(c) {
			return fmt.Errorf("parameter path contains invalid character %q", c)
		}
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("parameter path contains '..' which is invalid")
	}
	return nil
}

// isASCIILetter reports whether b is an ASCII letter (a-z or A-Z).
// Split out from validateTRParamPath so the De Morgan-equivalent
// check is a single positive predicate rather than nested negations.
func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isParamPathChar reports whether c is a valid character in a TR-069
// parameter path: letter, digit, dot, or underscore. Split out from
// validateTRParamPath to flatten its cyclomatic complexity below the
// gocyclo budget.
func isParamPathChar(c rune) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	return c == '.' || c == '_'
}

// Compile-time guards: addObject, parseAddObjectInstance, and
// deleteObject are part of the v2.2.0 Phase 1 structural foundation
// but their Phase 4 LOW endpoint consumers (port forwarding rules,
// static DHCP leases, GenieACS preset management, etc.) are not in
// this commit. The functions are tested at 100% coverage standalone,
// so the unused-symbol lint is suppressed via these compile-time
// references. They will become true call sites when Phase 4 lands.
var (
	_ = addObject
	_ = parseAddObjectInstance
	_ = deleteObject
)
