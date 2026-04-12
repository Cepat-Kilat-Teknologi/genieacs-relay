package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

// auditMiddleware emits one audit log line per write request (POST/PUT/PATCH/DELETE)
// via the "audit" named sub-logger per isp-logging-standard §Audit Log. Complements the
// existing AuditLog()/AuditLogWithFields() helpers which are still used for security
// events (auth success/failure/block) inside apiKeyAuthMiddleware.
func auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWriteMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		// Lazy sub-logger creation — defer until audit actually emits.
		audit := logger.Named("audit")
		audit.Info("audit_log",
			zap.String("request_id", RequestIDFromContext(r.Context())),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", ww.Status()),
			zap.String("client_ip", GetClientIP(r)),
			zap.String("user_agent", r.UserAgent()),
			zap.Int64("duration_ms", time.Since(start).Milliseconds()),
			zap.Int("body_size", ww.BytesWritten()),
		)
	})
}

// isWriteMethod reports whether the HTTP method mutates state and should be audit-logged.
func isWriteMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
