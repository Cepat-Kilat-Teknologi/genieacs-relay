package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// --- Environment Variable Tests ---

func TestGetEnv(t *testing.T) {
	key := "TEST_ENV_VAR"
	expectedValue := "hello_world"
	err := os.Setenv(key, expectedValue)
	if err != nil {
		return
	}
	defer func(key string) {
		err := os.Unsetenv(key)
		if err != nil {
			t.Fatalf("Failed to unset env var: %v", err)
		}
	}(key)
	val := getEnv(key, "default")
	assert.Equal(t, expectedValue, val)
}

func TestInitEnvFallback(t *testing.T) {
	oldGenie := os.Getenv("GENIEACS_BASE_URL")
	oldNBI := os.Getenv("NBI_AUTH_KEY")
	oldAPI := os.Getenv("API_KEY")
	defer func() {
		_ = os.Setenv("GENIEACS_BASE_URL", oldGenie)
		_ = os.Setenv("NBI_AUTH_KEY", oldNBI)
		_ = os.Setenv("API_KEY", oldAPI)
	}()

	_ = os.Unsetenv("GENIEACS_BASE_URL")
	_ = os.Unsetenv("NBI_AUTH_KEY")
	_ = os.Unsetenv("API_KEY")
	loadConfigFromEnv()

	assert.NotEmpty(t, geniesBaseURL)
	// nbiAuthKey gets a mock value from loadConfigFromEnv for testing purposes
	assert.NotEmpty(t, nbiAuthKey)
}

func TestInit_WithEnvVars(t *testing.T) {
	t.Setenv("GENIEACS_URL", "http://env-url")
	t.Setenv("NBI_AUTH_KEY", "env-nbi")
	t.Setenv("API_KEY", "env-api")

	loadEnv()
	if geniesBaseURL != "http://env-url" {
		t.Errorf("expected %q, got %q", "http://env-url", geniesBaseURL)
	}
	if nbiAuthKey != "env-nbi" {
		t.Errorf("expected %q, got %q", "env-nbi", nbiAuthKey)
	}
}

// --- Logger Initialization Tests ---

func TestLoggerInitialization_ErrorCase(t *testing.T) {
	// Save original logger and function
	originalLogger := logger
	originalNewProduction := newProductionFunc

	// Override zap.NewProduction forcing it to return error
	newProductionFunc = func(...zap.Option) (*zap.Logger, error) {
		return nil, fmt.Errorf("simulated logger error")
	}

	// Capture log output
	var logOutput bytes.Buffer
	log.SetOutput(&logOutput)
	defer func() {
		log.SetOutput(os.Stderr)
		newProductionFunc = originalNewProduction
		logger = originalLogger

		// Restore original logger if it was set
		if originalLogger != nil {
			logger = originalLogger
		} else {
			// If original was nil, create a default logger
			logger, _ = zap.NewProduction()
		}
	}()

	// Call logger initialization
	initializeLogger()

	// Check if the error was logged
	if !strings.Contains(logOutput.String(), "Failed to initialize logger") {
		t.Error("Expected logger initialization error to be logged")
	}

	// Ensure logger is still nil
	if logger != nil {
		t.Error("Expected logger to be nil after initialization error")
	}
}

func TestMainFunctionWithLoggerError(t *testing.T) {
	// Test specific scenario for main error handling
	oldInitLogger := initLogger
	defer func() { initLogger = oldInitLogger }()

	initLogger = func() (*zap.Logger, error) {
		return nil, errors.New("test error")
	}

	// Since we can't easily test main() directly, test the component it calls
	err := initLoggerWrapper()
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "failed to initialize logger")
	}
}

// Test for logger initialization failure handling
func TestLoggerInitializationFailure(t *testing.T) {
	// Test scenario where logger initialization fails
	//  to Backup original logger

	tempLogger := logger
	logger = nil // Simulate uninitialized logger

	// Test function that uses logger
	assert.NotPanics(t, func() {
		safeClose(nil) // Should handle nil logger gracefully
	})

	logger = tempLogger // Restore
}

func TestInitLoggerWrapperError(t *testing.T) {
	// Backup original function
	originalInitLogger := initLogger
	defer func() {
		initLogger = originalInitLogger
		// Reset logger for other tests
		logger, _ = zap.NewDevelopment()
	}()

	// Mock initLogger to return error
	initLogger = func() (*zap.Logger, error) {
		return nil, errors.New("mock logger error")
	}

	err := initLoggerWrapper()

	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "failed to initialize logger")
		assert.Contains(t, err.Error(), "mock logger error")
	}

	// Verify logger is still nil (not initialized)
	assert.Nil(t, logger)
}

func TestInitLoggerWrapperSuccess(t *testing.T) {
	// Backup original function
	originalInitLogger := initLogger
	defer func() {
		initLogger = originalInitLogger
	}()

	// Mock initLogger to return success
	testLogger, _ := zap.NewDevelopment()
	initLogger = func() (*zap.Logger, error) {
		return testLogger, nil
	}

	err := initLoggerWrapper()

	assert.NoError(t, err)
	assert.NotNil(t, logger)
	assert.Equal(t, testLogger, logger)

}
