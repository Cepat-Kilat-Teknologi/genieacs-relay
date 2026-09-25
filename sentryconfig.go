package main

// sentryServiceName prefixes the Sentry release so events from every CKT
// service share the "<service>@<version>" format.
const sentryServiceName = "genieacs-relay"

// resolveSentryConfig returns the Sentry environment and release.
//
// Environment: SENTRY_ENVIRONMENT, then APP_ENV, then the legacy ENVIRONMENT
// variable this service read before SENTRY_ENVIRONMENT existed.
//
// Release: SENTRY_RELEASE, then "genieacs-relay@<version>" where version is
// the ldflags-injected build version (tag on tag builds, short SHA on main
// builds, "dev" locally). An empty version falls back to "dev".
func resolveSentryConfig(getenv func(string) string, version string) (environment, release string) {
	environment = firstNonEmpty(getenv("SENTRY_ENVIRONMENT"), getenv("APP_ENV"), getenv("ENVIRONMENT"))

	release = getenv("SENTRY_RELEASE")
	if release == "" {
		release = sentryServiceName + "@" + firstNonEmpty(version, "dev")
	}
	return environment, release
}

// firstNonEmpty returns the first argument that is not the empty string.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
