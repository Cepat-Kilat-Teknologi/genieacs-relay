package main

import (
	"fmt"
	"os"
)

// getEnv retrieves environment variable value with fallback to default if not set
func getEnv(key, defaultValue string) string {
	// Check if environment variable exists
	if value, exists := os.LookupEnv(key); exists {
		return value // Return environment variable value
	}
	return defaultValue // Return default value if environment variable not set
}

// initLoggerWrapper handles logger initialization and returns error
func initLoggerWrapper() error {
	var err error
	logger, err = initLogger()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	_ = logger.Sugar()
	return nil
}

// initLogger is the package-level logger factory, overridable in tests.
// Delegates to initProductionLogger() which attaches the standardized base fields
// (service, version) per isp-logging-standard. Tests override this to capture logs.
var initLogger = initProductionLogger
