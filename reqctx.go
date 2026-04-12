package main

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// requestIDKeyType is an unexported type used as the context key for the request ID.
// Using a dedicated type prevents collisions with other packages' context keys.
type requestIDKeyType struct{}

// requestIDCtxKey is the context value key under which the per-request correlation ID is stored.
// Handlers retrieve the ID via RequestIDFromContext(r.Context()).
var requestIDCtxKey = requestIDKeyType{}

// WithRequestID returns a derived context carrying the given request ID.
// Used by the request-id middleware to bridge chi's RequestID output into
// logger.WithRequestID(ctx) and any downstream code that needs the correlation ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDCtxKey, id)
}

// RequestIDFromContext extracts the request ID previously stored by WithRequestID.
// Returns "" when the context has no request ID (e.g. background jobs, tests).
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDCtxKey).(string); ok {
		return v
	}
	return ""
}

// requestIDMiddleware wraps chi's built-in middleware.RequestID and additionally stores
// the generated (or incoming X-Request-ID) value under our typed context key so that
// WithRequestIDLogger(ctx) and error responses can include it.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		if reqID == "" {
			// Shouldn't happen when chi middleware.RequestID runs first, but keep a safe fallback.
			reqID = r.Header.Get("X-Request-ID")
		}
		ctx := WithRequestID(r.Context(), reqID)
		// Echo back to client for end-to-end tracing even if chi middleware didn't.
		if w.Header().Get("X-Request-ID") == "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
