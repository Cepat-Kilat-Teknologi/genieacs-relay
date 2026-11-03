package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIVersionHeadersMiddleware(t *testing.T) {
	origV, origC := buildVersion, buildCommit
	setBuildInfo("9.9.9", "cafef00d", "2026-01-01T00:00:00Z")
	defer func() { buildVersion, buildCommit = origV, origC }()

	h := apiVersionHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, "v1", rr.Header().Get("X-API-Version"))
	assert.Equal(t, "9.9.9", rr.Header().Get("X-App-Version"))
	assert.Equal(t, "cafef00d", rr.Header().Get("X-Build-Commit"))
}
