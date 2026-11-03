package main

import (
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestIsProductionEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset", nil, false},
		{"app env production", map[string]string{"APP_ENV": "production"}, true},
		{"legacy environment prod", map[string]string{"ENVIRONMENT": "prod"}, true},
		{"sentry prod-jkt", map[string]string{"SENTRY_ENVIRONMENT": "prod-jkt"}, true},
		{"sentry prod-pml mixed case", map[string]string{"SENTRY_ENVIRONMENT": " Prod-PML "}, true},
		{"staging", map[string]string{"APP_ENV": "staging", "SENTRY_ENVIRONMENT": "staging"}, false},
		{"development", map[string]string{"APP_ENV": "development"}, false},
		{"dev", map[string]string{"SENTRY_ENVIRONMENT": "dev"}, false},
		{"not a prod prefix", map[string]string{"APP_ENV": "producer"}, false},
		{"any variable wins", map[string]string{"APP_ENV": "staging", "SENTRY_ENVIRONMENT": "prod-jkt"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProductionEnv(envMap(tt.env)); got != tt.want {
				t.Errorf("isProductionEnv(%v) = %v, want %v", tt.env, got, tt.want)
			}
		})
	}
}

func clearProductionEnv(t *testing.T) {
	t.Helper()
	for _, name := range productionEnvVars {
		t.Setenv(name, "")
	}
}

func TestLoadMiddlewareAuthConfig_ProductionRequiresAuth(t *testing.T) {
	clearProductionEnv(t)
	t.Setenv("SENTRY_ENVIRONMENT", "prod-jkt")
	t.Setenv("MIDDLEWARE_AUTH", "false")
	t.Setenv("AUTH_KEY", "")

	err := loadMiddlewareAuthConfig()
	if err == nil {
		t.Fatal("expected error when MIDDLEWARE_AUTH is false in production")
	}
	if !strings.Contains(err.Error(), "MIDDLEWARE_AUTH") {
		t.Errorf("error should name MIDDLEWARE_AUTH, got: %v", err)
	}
}

func TestLoadMiddlewareAuthConfig_ProductionUnsetAuth(t *testing.T) {
	clearProductionEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("AUTH_KEY", "")
	// MIDDLEWARE_AUTH unset entirely: the default is false.
	t.Setenv("MIDDLEWARE_AUTH", "")

	if err := loadMiddlewareAuthConfig(); err == nil {
		t.Fatal("expected error when MIDDLEWARE_AUTH is unset in production")
	}
}

func TestLoadMiddlewareAuthConfig_ProductionEmptyKey(t *testing.T) {
	clearProductionEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MIDDLEWARE_AUTH", "true")
	t.Setenv("AUTH_KEY", "")

	err := loadMiddlewareAuthConfig()
	if err == nil {
		t.Fatal("expected error when AUTH_KEY is empty in production")
	}
	if !strings.Contains(err.Error(), "AUTH_KEY") {
		t.Errorf("error should name AUTH_KEY, got: %v", err)
	}
}

func TestLoadMiddlewareAuthConfig_ProductionWithAuth(t *testing.T) {
	const key = "prod-test-key-value"
	clearProductionEnv(t)
	t.Setenv("SENTRY_ENVIRONMENT", "prod-jkt")
	t.Setenv("MIDDLEWARE_AUTH", "true")
	t.Setenv("AUTH_KEY", key)

	if err := loadMiddlewareAuthConfig(); err != nil {
		t.Fatalf("expected production with auth to start, got: %v", err)
	}
}

func TestLoadMiddlewareAuthConfig_NonProductionAllowsNoAuth(t *testing.T) {
	for _, env := range []string{"", "staging", "development"} {
		t.Run("env="+env, func(t *testing.T) {
			clearProductionEnv(t)
			t.Setenv("APP_ENV", env)
			t.Setenv("MIDDLEWARE_AUTH", "false")
			t.Setenv("AUTH_KEY", "")

			if err := loadMiddlewareAuthConfig(); err != nil {
				t.Fatalf("expected %q without auth to start, got: %v", env, err)
			}
		})
	}
}

func TestLoadMiddlewareAuthConfig_ErrorOmitsKeyValue(t *testing.T) {
	const key = "secret-value-must-not-leak"
	clearProductionEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("MIDDLEWARE_AUTH", "false")
	t.Setenv("AUTH_KEY", key)

	err := loadMiddlewareAuthConfig()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), key) {
		t.Error("error message must not contain the AUTH_KEY value")
	}
}
