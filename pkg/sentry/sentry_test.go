package sentry

import (
	"errors"
	"testing"
)

func TestInit_EmptyDSN(t *testing.T) {
	// Empty DSN should be a no-op and return nil.
	if err := Init("", "test", "v0.0.0"); err != nil {
		t.Fatalf("Init with empty DSN should return nil, got: %v", err)
	}
}

func TestInit_InvalidDSN(t *testing.T) {
	// A malformed DSN should return an error from the SDK.
	err := Init("not-a-valid-dsn", "test", "v0.0.0")
	if err == nil {
		t.Fatal("Init with invalid DSN should return an error")
	}
}

func TestFlush(t *testing.T) {
	// Flush should not panic even when no client is initialised (empty DSN).
	_ = Init("", "test", "v0.0.0")
	Flush() // must not panic
}

func TestCaptureException_NoPanic(t *testing.T) {
	// CaptureException should not panic when no client is initialised.
	_ = Init("", "test", "v0.0.0")
	CaptureException(errors.New("test error"))
}

func TestCaptureMessage_NoPanic(t *testing.T) {
	// CaptureMessage should not panic when no client is initialised.
	_ = Init("", "test", "v0.0.0")
	CaptureMessage("test message")
}
