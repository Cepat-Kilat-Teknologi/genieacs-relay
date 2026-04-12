package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

// skipRequestLogPaths contains URL paths that should not emit per-request zap logs.
// Health/metrics/version endpoints are polled frequently by k8s probes and Prometheus
// scrape jobs, and logging them would flood the aggregation backend.
var skipRequestLogPaths = map[string]bool{
	"/health":  true,
	"/healthz": true,
	"/ready":   true,
	"/readyz":  true,
	"/version": true,
	"/metrics": true,
}

// structuredLoggerMiddleware emits one zap log line per HTTP request with correlation,
// and skips the well-known health/probe paths to keep logs signal-heavy.
// It composes with chi.middleware.WrapResponseWriter to capture status and bytes written.
func structuredLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skipRequestLogPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		log := WithRequestIDLogger(r.Context())
		log.Info("incoming_request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", ww.Status()),
			zap.Int64("duration_ms", time.Since(start).Milliseconds()),
			zap.Int("size_bytes", ww.BytesWritten()),
			zap.String("ip", GetClientIP(r)),
			zap.String("user_agent", r.UserAgent()),
		)
	})
}
