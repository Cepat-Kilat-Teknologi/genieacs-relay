package main

import "strings"

// productionEnvVars are the variables that can mark a deploy as production.
// prod-jkt sets only SENTRY_ENVIRONMENT ("prod-jkt"); APP_ENV and the legacy
// ENVIRONMENT are the platform-wide names. Any one of them is enough, so a
// deploy cannot opt out of the production checks by leaving one unset.
var productionEnvVars = []string{"APP_ENV", "ENVIRONMENT", "SENTRY_ENVIRONMENT"}

// isProductionEnv reports whether any of productionEnvVars names a production
// environment: "production", "prod", or a "prod-<site>" name (ADR-012).
func isProductionEnv(getenv func(string) string) bool {
	for _, name := range productionEnvVars {
		v := strings.ToLower(strings.TrimSpace(getenv(name)))
		if v == "production" || v == "prod" || strings.HasPrefix(v, "prod-") {
			return true
		}
	}
	return false
}
