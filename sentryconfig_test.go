package main

import "testing"

func TestResolveSentryConfig(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		version     string
		wantEnv     string
		wantRelease string
	}{
		{
			name:        "defaults with no env and dev build",
			env:         map[string]string{},
			version:     "dev",
			wantEnv:     "",
			wantRelease: "genieacs-relay@dev",
		},
		{
			name:        "empty version falls back to dev",
			env:         map[string]string{},
			version:     "",
			wantEnv:     "",
			wantRelease: "genieacs-relay@dev",
		},
		{
			name:        "tag build version",
			env:         map[string]string{"APP_ENV": "production"},
			version:     "2.3.0",
			wantEnv:     "production",
			wantRelease: "genieacs-relay@2.3.0",
		},
		{
			name:        "main build short sha",
			env:         map[string]string{"APP_ENV": "production"},
			version:     "a1b2c3d",
			wantEnv:     "production",
			wantRelease: "genieacs-relay@a1b2c3d",
		},
		{
			name:        "SENTRY_ENVIRONMENT overrides APP_ENV",
			env:         map[string]string{"SENTRY_ENVIRONMENT": "prod-jkt", "APP_ENV": "production"},
			version:     "a1b2c3d",
			wantEnv:     "prod-jkt",
			wantRelease: "genieacs-relay@a1b2c3d",
		},
		{
			name:        "SENTRY_RELEASE overrides built-in release",
			env:         map[string]string{"SENTRY_RELEASE": "genieacs-relay@custom"},
			version:     "a1b2c3d",
			wantEnv:     "",
			wantRelease: "genieacs-relay@custom",
		},
		{
			name:        "both overrides set",
			env:         map[string]string{"SENTRY_ENVIRONMENT": "prod-jkt", "SENTRY_RELEASE": "r1", "APP_ENV": "production", "ENVIRONMENT": "legacy"},
			version:     "2.3.0",
			wantEnv:     "prod-jkt",
			wantRelease: "r1",
		},
		{
			name:        "APP_ENV preferred over legacy ENVIRONMENT",
			env:         map[string]string{"APP_ENV": "production", "ENVIRONMENT": "legacy"},
			version:     "dev",
			wantEnv:     "production",
			wantRelease: "genieacs-relay@dev",
		},
		{
			name:        "legacy ENVIRONMENT used when nothing else set",
			env:         map[string]string{"ENVIRONMENT": "legacy"},
			version:     "dev",
			wantEnv:     "legacy",
			wantRelease: "genieacs-relay@dev",
		},
		{
			name:        "empty overrides are ignored",
			env:         map[string]string{"SENTRY_ENVIRONMENT": "", "SENTRY_RELEASE": "", "APP_ENV": "staging"},
			version:     "a1b2c3d",
			wantEnv:     "staging",
			wantRelease: "genieacs-relay@a1b2c3d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string { return tt.env[key] }
			gotEnv, gotRelease := resolveSentryConfig(getenv, tt.version)
			if gotEnv != tt.wantEnv {
				t.Errorf("environment = %q, want %q", gotEnv, tt.wantEnv)
			}
			if gotRelease != tt.wantRelease {
				t.Errorf("release = %q, want %q", gotRelease, tt.wantRelease)
			}
		})
	}
}
