package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestRegisterMetricsIdempotent(t *testing.T) {
	// Safe to call twice thanks to sync.Once + AlreadyRegisteredError tolerance.
	assert.NotPanics(t, func() {
		registerMetrics()
		registerMetrics()
	})
}

// doRegisterMetrics: exercise the AlreadyRegisteredError tolerance branch by
// calling the inner function a second time after the first call registered the
// collectors. sync.Once guards the public registerMetrics() path, so we call
// the inner function directly.
func TestDoRegisterMetricsIdempotent(t *testing.T) {
	// First call may or may not have happened depending on earlier tests —
	// sync.Once path ensures the public call is a no-op on repeats. We invoke
	// the inner function directly to hit the AlreadyRegisteredError branch.
	assert.NotPanics(t, func() {
		doRegisterMetrics()
		doRegisterMetrics() // Second call must hit AlreadyRegisteredError path.
	})
}

// metricsMiddleware: exercise the non-skip path and the empty-RoutePattern fallback
// via real ServeHTTP invocation. Does NOT go through chi router so RoutePattern
// returns "" and the middleware falls back to "unknown".
func TestMetricsMiddlewareInvokes(t *testing.T) {
	// Ensure collectors are registered so WithLabelValues doesn't panic.
	registerMetrics()

	called := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(200)
	})
	mw := metricsMiddleware(inner)

	// Skip path: /metrics itself — bypasses accounting.
	reqSkip := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mw.ServeHTTP(httptest.NewRecorder(), reqSkip)

	// Non-skip path: normal request → full accounting branch (including the
	// `path == ""` fallback to "unknown" since there's no chi router in scope).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/ssid/1.2.3.4", nil)
	// Inject a minimal chi RouteContext so chi.RouteContext() doesn't return nil.
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, chi.NewRouteContext())
	mw.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))

	assert.Equal(t, 2, called)
}
