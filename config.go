package main

import (
	"fmt"
	"os"

	"go.uber.org/zap"
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

// Function to initialize logger (package-level variable for testing)
var initLogger = func() (*zap.Logger, error) {
	return zap.NewProduction() // Use production configuration for logger
}
