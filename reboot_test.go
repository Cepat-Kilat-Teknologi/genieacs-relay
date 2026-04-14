package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- rebootDevice unit tests ---
//
// Mirrors the existing TestRefreshDHCP pattern: stand up an httptest
// server posing as the GenieACS NBI, point geniesBaseURL at it, call
// rebootDevice, assert behavior. No real GenieACS or CPE involved.

func TestRebootDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("Success_200_task_applied_synchronously", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the request shape: POST to /devices/{id}/tasks?connection_request
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.URL.Path, "/devices/"+mockDeviceID+"/tasks")
			assert.Equal(t, "", r.URL.Query().Get("connection_request"), "connection_request flag should be present (empty value)")
			// connection_request param is present as a flag; URL.Query() returns "" for valueless flags.
			// We can also verify it appears in the raw query string.
			assert.Contains(t, r.URL.RawQuery, "connection_request")
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL

		err := rebootDevice(ctx, mockDeviceID)
		assert.NoError(t, err)
	})

	t.Run("Success_202_task_queued", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL

		err := rebootDevice(ctx, mockDeviceID)
		assert.NoError(t, err, "202 Accepted is a successful task submission per NBI contract")
	})

	t.Run("Failure_500_NBI_error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL

		err := rebootDevice(ctx, mockDeviceID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "reboot failed with status")
	})

	t.Run("Failure_404_device_not_in_GenieACS", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL

		err := rebootDevice(ctx, mockDeviceID)
		assert.Error(t, err)
	})

	t.Run("RequestPayload_isReboot", func(t *testing.T) {
		// Verify that the JSON payload posted is `{"name": "reboot"}`.
		// Without this assertion a typo like `{"name": "Reboot"}` (capitalized)
		// would pass all status-only tests but fail at the real GenieACS NBI.
		var capturedBody []byte
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			capturedBody = body
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL

		err := rebootDevice(ctx, mockDeviceID)
		assert.NoError(t, err)
		// postJSONRequest serializes the string payload as a JSON-encoded string.
		// The reboot.go payload literal is `{"name": "reboot"}`, which after
		// JSON encoding becomes a quoted string `"{\"name\": \"reboot\"}"`.
		// We assert the inner literal is present somewhere in the captured body.
		assert.Contains(t, string(capturedBody), `"name": "reboot"`)
	})
}
