package main

import "time"

// Build metadata. These are populated at startup from the main.version/main.commit/main.buildTime
// ldflags-injected variables via setBuildInfo(). Accessors below return the current values.
var (
	buildVersion   = "dev"
	buildCommit    = "none"
	buildDate      = "unknown"
	buildStartedAt = time.Now().UTC()
)

// setBuildInfo propagates ldflags-injected metadata from main.go into buildinfo package vars.
// Called once at startup from main().
func setBuildInfo(ver, sha, ts string) {
	if ver != "" {
		buildVersion = ver
	}
	if sha != "" {
		buildCommit = sha
	}
	if ts != "" {
		buildDate = ts
	}
}

// BuildVersion returns the binary semver version (ldflags-injected, "dev" in local builds).
func BuildVersion() string { return buildVersion }

// BuildCommit returns the short git commit SHA (ldflags-injected, "none" in local builds).
func BuildCommit() string { return buildCommit }

// BuildDate returns the ISO8601 UTC build timestamp (ldflags-injected, "unknown" in local builds).
func BuildDate() string { return buildDate }

// Uptime returns the duration since process start as a human-readable string.
func Uptime() string { return time.Since(buildStartedAt).Round(time.Second).String() }
