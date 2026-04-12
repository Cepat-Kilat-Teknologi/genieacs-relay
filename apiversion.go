package main

import "net/http"

// apiVersionHeadersMiddleware attaches X-API-Version / X-App-Version / X-Build-Commit
// headers to every response per isp-adapter-standard §3. Values are read from the
// buildinfo package so ldflags-injected metadata is exposed consistently across
// both response headers and the /version endpoint.
func apiVersionHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", APIVersion)
		w.Header().Set("X-App-Version", BuildVersion())
		w.Header().Set("X-Build-Commit", BuildCommit())
		next.ServeHTTP(w, r)
	})
}
