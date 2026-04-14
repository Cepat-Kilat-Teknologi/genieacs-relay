package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// rebootDevice triggers a TR-069 Reboot RPC against the CPE identified by
// deviceID. The call is dispatched through the GenieACS NBI as a `reboot`
// task with `?connection_request` so the call blocks until either the task
// is applied synchronously (200 OK) or queued asynchronously when the
// connection request fails (202 Accepted). Both status codes indicate
// successful task submission per the NBI contract — only 4xx/5xx responses
// are treated as errors.
//
// The actual CPE reboot takes 30-90 seconds before the device reconnects to
// GenieACS. Callers (typically the isp-agent v2+ RestartOnu workflow)
// should NOT block waiting for the device to come back — the workflow's
// retry policy or a follow-up health check is the right tool for that.
func rebootDevice(ctx context.Context, deviceID string) error {
	// Build URL for the GenieACS task creation endpoint with
	// connection_request enabled so the NBI blocks until the task is
	// applied (or queued on failure).
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))

	// TR-069 Reboot task — no parameters required.
	payload := `{"name": "reboot"}`

	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	defer safeClose(resp.Body)

	// 200 OK = task applied sync; 202 Accepted = task queued; both are success.
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("reboot failed with status: %s", resp.Status)
	}
	return nil
}
