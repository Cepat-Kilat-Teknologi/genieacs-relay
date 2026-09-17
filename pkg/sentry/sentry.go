// Package sentry provides a thin wrapper around the sentry-go SDK.
// When SENTRY_DSN is empty, Init is a no-op — the service runs without
// error tracking, which is the expected local-dev default.
package sentry

import (
	"time"

	sentrygo "github.com/getsentry/sentry-go"
)

// Init configures the global Sentry client. If dsn is empty the call is
// a no-op so callers do not need to guard on "is Sentry configured?".
func Init(dsn, env, release string) error {
	if dsn == "" {
		return nil // disabled — no DSN provided
	}
	return sentrygo.Init(sentrygo.ClientOptions{
		Dsn:              dsn,
		Environment:      env,
		Release:          release,
		TracesSampleRate: 0.1,
		EnableTracing:    true,
	})
}

// CaptureException sends an error to Sentry as an exception event.
// When Sentry is not initialized (no DSN) the call is a silent no-op.
func CaptureException(err error) {
	sentrygo.CaptureException(err)
}

// CaptureMessage sends a text message to Sentry.
// When Sentry is not initialized (no DSN) the call is a silent no-op.
func CaptureMessage(msg string) {
	sentrygo.CaptureMessage(msg)
}

// Flush waits up to 2 seconds for buffered events to be sent to Sentry.
// Call it in a defer from main() to avoid losing events on shutdown.
func Flush() {
	sentrygo.Flush(2 * time.Second)
}
