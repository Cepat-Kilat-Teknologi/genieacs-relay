package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gobreaker "github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testBreakerConfig(threshold uint32) BreakerConfig {
	return BreakerConfig{
		Enabled:       true,
		MaxRequests:   1,
		Interval:      60 * time.Second,
		Timeout:       100 * time.Millisecond, // short for tests
		TripThreshold: threshold,
	}
}

func TestInitBreaker_Enabled(t *testing.T) {
	cfg := testBreakerConfig(3)
	initBreaker(cfg, zap.NewNop())
	defer func() { nbiBreaker = nil }()

	require.NotNil(t, nbiBreaker, "breaker should be initialized when enabled")
	assert.Equal(t, gobreaker.StateClosed, nbiState())
}

func TestInitBreaker_Disabled(t *testing.T) {
	cfg := testBreakerConfig(3)
	cfg.Enabled = false
	initBreaker(cfg, zap.NewNop())
	defer func() { nbiBreaker = nil }()

	assert.Nil(t, nbiBreaker, "breaker should be nil when disabled")
	assert.Equal(t, gobreaker.StateClosed, nbiState(), "disabled breaker reports closed")
}

func TestNbiDo_PassThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	initBreaker(testBreakerConfig(3), zap.NewNop())
	defer func() { nbiBreaker = nil }()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/test", http.NoBody)
	require.NoError(t, err)

	resp, err := nbiDo(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	safeClose(resp.Body)
}

func TestNbiDo_DisabledPassThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	cfg := testBreakerConfig(3)
	cfg.Enabled = false
	initBreaker(cfg, zap.NewNop())
	defer func() { nbiBreaker = nil }()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/test", http.NoBody)
	require.NoError(t, err)

	resp, err := nbiDo(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	safeClose(resp.Body)
}

func TestNbiDo_TripsAfterThreshold(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	threshold := uint32(3)
	initBreaker(testBreakerConfig(threshold), zap.NewNop())
	defer func() { nbiBreaker = nil }()

	// Exhaust the threshold with consecutive 500 responses.
	for i := uint32(0); i < threshold; i++ {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/fail", http.NoBody)
		require.NoError(t, err)
		resp, _ := nbiDo(req)
		if resp != nil {
			safeClose(resp.Body)
		}
	}

	// Circuit should now be open — next call rejected immediately.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/fail", http.NoBody)
	require.NoError(t, err)

	_, err = nbiDo(req)
	assert.True(t, errors.Is(err, ErrCircuitOpen), "expected ErrCircuitOpen, got %v", err)
	assert.Equal(t, gobreaker.StateOpen, nbiState())
}

func TestNbiDo_HalfOpenAfterTimeout(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	cfg := testBreakerConfig(2)
	cfg.Timeout = 50 * time.Millisecond
	initBreaker(cfg, zap.NewNop())
	defer func() { nbiBreaker = nil }()

	// Trip the breaker with 2 failures.
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/fail", http.NoBody)
		resp, _ := nbiDo(req)
		if resp != nil {
			safeClose(resp.Body)
		}
	}
	assert.Equal(t, gobreaker.StateOpen, nbiState())

	// Wait for timeout → half-open.
	time.Sleep(80 * time.Millisecond)

	// Probe request should succeed → circuit closes.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/probe", http.NoBody)
	resp, err := nbiDo(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	safeClose(resp.Body)

	assert.Equal(t, gobreaker.StateClosed, nbiState())
}

func TestNbiDo_TransportError(t *testing.T) {
	// Point at a closed server to trigger transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srvURL := srv.URL
	srv.Close() // close immediately

	origClient := httpClient
	httpClient = &http.Client{Timeout: 1 * time.Second}
	defer func() { httpClient = origClient }()

	initBreaker(testBreakerConfig(3), zap.NewNop())
	defer func() { nbiBreaker = nil }()

	req, err := http.NewRequest(http.MethodGet, srvURL+"/dead", http.NoBody)
	require.NoError(t, err)

	_, err = nbiDo(req)
	assert.Error(t, err, "transport error should propagate")
	assert.False(t, errors.Is(err, ErrCircuitOpen), "should not be ErrCircuitOpen on first failure")
}

func TestNbiDo_4xxDoesNotTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	threshold := uint32(2)
	initBreaker(testBreakerConfig(threshold), zap.NewNop())
	defer func() { nbiBreaker = nil }()

	// Send many 404s — should NOT trip the breaker (only 5xx counts).
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/notfound", http.NoBody)
		resp, err := nbiDo(req)
		require.NoError(t, err)
		safeClose(resp.Body)
	}

	assert.Equal(t, gobreaker.StateClosed, nbiState(), "4xx should not trip the breaker")
}

func TestDefaultBreakerConfig(t *testing.T) {
	cfg := DefaultBreakerConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, uint32(1), cfg.MaxRequests)
	assert.Equal(t, 60*time.Second, cfg.Interval)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.Equal(t, uint32(5), cfg.TripThreshold)
}

func TestLoadBreakerConfigFromEnv_Defaults(t *testing.T) {
	// With no env vars set, should return defaults.
	cfg := LoadBreakerConfigFromEnv()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, uint32(5), cfg.TripThreshold)
}

func TestStateFloat(t *testing.T) {
	tests := []struct {
		state gobreaker.State
		want  float64
	}{
		{gobreaker.StateClosed, 0},
		{gobreaker.StateHalfOpen, 1},
		{gobreaker.StateOpen, 2},
	}
	for _, tt := range tests {
		got := cbStateFloat(tt.state)
		assert.Equal(t, tt.want, got, "cbStateFloat(%v)", tt.state)
	}
}

func TestStateName(t *testing.T) {
	tests := []struct {
		state gobreaker.State
		want  string
	}{
		{gobreaker.StateClosed, "closed"},
		{gobreaker.StateHalfOpen, "half-open"},
		{gobreaker.StateOpen, "open"},
	}
	for _, tt := range tests {
		got := cbStateName(tt.state)
		assert.Equal(t, tt.want, got, "cbStateName(%v)", tt.state)
	}
}
