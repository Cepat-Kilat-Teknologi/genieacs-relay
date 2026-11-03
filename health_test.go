package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHealthzHandler(t *testing.T) {
	rr := httptest.NewRecorder()
	healthzHandler(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, 200, rr.Code)
	assert.Contains(t, rr.Body.String(), "healthy")
}

func TestHealthCheckerPingUp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	origURL := geniesBaseURL
	geniesBaseURL = ts.URL
	defer func() { geniesBaseURL = origURL }()

	hc := &healthChecker{cacheTTL: 0, httpDo: http.DefaultClient.Do}
	state := hc.check(context.Background())
	assert.Equal(t, "ready", state.Status)
	assert.Equal(t, "up", state.Dependencies["genieacs"].State)
}

func TestHealthCheckerPingDown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	origURL := geniesBaseURL
	geniesBaseURL = ts.URL
	defer func() { geniesBaseURL = origURL }()

	hc := &healthChecker{cacheTTL: 0, httpDo: http.DefaultClient.Do}
	state := hc.check(context.Background())
	assert.Equal(t, "not_ready", state.Status)
	assert.Equal(t, "down", state.Dependencies["genieacs"].State)
}

func TestHealthCheckerPingAuthRejected(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))

		origURL := geniesBaseURL
		geniesBaseURL = ts.URL

		hc := &healthChecker{cacheTTL: 0, httpDo: http.DefaultClient.Do}
		state := hc.check(context.Background())
		assert.Equal(t, "not_ready", state.Status, "status %d", code)
		assert.Equal(t, "down", state.Dependencies["genieacs"].State, "status %d", code)
		assert.Contains(t, state.Dependencies["genieacs"].Error, "auth rejected", "status %d", code)

		geniesBaseURL = origURL
		ts.Close()
	}
}

func TestHealthCheckerPingNotFoundIsUp(t *testing.T) {
	// GenieACS NBI answers 404 on GET / once the nginx auth proxy lets the
	// request through; that proves both reachability and a valid key.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	origURL := geniesBaseURL
	geniesBaseURL = ts.URL
	defer func() { geniesBaseURL = origURL }()

	hc := &healthChecker{cacheTTL: 0, httpDo: http.DefaultClient.Do}
	state := hc.check(context.Background())
	assert.Equal(t, "ready", state.Status)
	assert.Equal(t, "up", state.Dependencies["genieacs"].State)
}

func TestHealthCheckerCache(t *testing.T) {
	calls := 0
	hc := &healthChecker{
		cacheTTL: time.Hour,
		httpDo: func(_ *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		},
	}
	origURL := geniesBaseURL
	geniesBaseURL = "http://stub"
	defer func() { geniesBaseURL = origURL }()

	hc.check(context.Background())
	hc.check(context.Background())
	hc.check(context.Background())
	// Second+third calls served from cache.
	assert.Equal(t, 1, calls)
}

func TestReadyzHandlerDown(t *testing.T) {
	// Point at unreachable URL so ping fails fast.
	origURL := geniesBaseURL
	geniesBaseURL = "http://127.0.0.1:1"
	defer func() { geniesBaseURL = origURL }()
	// Use a fresh checker to avoid cache interference with other tests.
	defaultHealthChecker = &healthChecker{cacheTTL: 0, httpDo: httpClient.Do}

	rr := httptest.NewRecorder()
	readyzHandler(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// pingGenieACS: exercise the http.NewRequestWithContext error path by supplying
// an invalid URL character that makes the request constructor fail.
func TestHealthCheckerPingInvalidURL(t *testing.T) {
	origURL := geniesBaseURL
	geniesBaseURL = "http://[invalid"
	defer func() { geniesBaseURL = origURL }()

	hc := &healthChecker{cacheTTL: 0, httpDo: http.DefaultClient.Do}
	state := hc.pingGenieACS(context.Background())
	assert.Equal(t, "down", state.State)
	assert.Contains(t, state.Error, "build request")
}

// pingGenieACS: exercise the NBI auth header injection branch by enabling
// nbiAuth + setting nbiAuthKey. The upstream test server verifies the header is
// forwarded.
func TestHealthCheckerPingForwardsNBIAuth(t *testing.T) {
	var receivedKey string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get(HeaderXAPIKey)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	origURL, origAuth, origKey := geniesBaseURL, nbiAuth, nbiAuthKey
	geniesBaseURL = ts.URL
	nbiAuth = true
	nbiAuthKey = "secret-key"
	defer func() {
		geniesBaseURL = origURL
		nbiAuth = origAuth
		nbiAuthKey = origKey
	}()

	hc := &healthChecker{cacheTTL: 0, httpDo: http.DefaultClient.Do}
	state := hc.pingGenieACS(context.Background())
	assert.Equal(t, "up", state.State)
	assert.Equal(t, "secret-key", receivedKey)
}
