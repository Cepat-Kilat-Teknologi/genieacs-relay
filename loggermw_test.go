package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// structuredLoggerMiddleware: exercise both the skip and non-skip branches via
// real ServeHTTP invocation.
func TestStructuredLoggerMiddlewareInvokes(t *testing.T) {
	l, _ := initProductionLogger()
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	called := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(200)
	})
	mw := structuredLoggerMiddleware(inner)

	// Skip path: /healthz is in skipRequestLogPaths → fast-path, no log emission.
	reqSkip := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	mw.ServeHTTP(httptest.NewRecorder(), reqSkip)

	// Non-skip path: /api/v1/genieacs/... → full logging branch executes.
	ctx := WithRequestID(context.Background(), "struct-log-test")
	reqLog := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/ssid/1.2.3.4", nil).WithContext(ctx)
	mw.ServeHTTP(httptest.NewRecorder(), reqLog)

	assert.Equal(t, 2, called)
}
