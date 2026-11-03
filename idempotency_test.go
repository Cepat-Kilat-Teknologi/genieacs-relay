package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStoreSetGetExpire(t *testing.T) {
	s := NewMemoryStore()
	s.Set("k1", storedResponse{Status: 200, Body: []byte("ok"), ExpiresAt: time.Now().Add(time.Hour)})

	got, ok := s.Get("k1")
	require.True(t, ok)
	assert.Equal(t, 200, got.Status)
	assert.Equal(t, []byte("ok"), got.Body)

	// Expired entry is evicted on read.
	s.Set("k2", storedResponse{Status: 200, ExpiresAt: time.Now().Add(-time.Second)})
	_, ok = s.Get("k2")
	assert.False(t, ok)

	// Missing key.
	_, ok = s.Get("missing")
	assert.False(t, ok)
}

func TestMemoryStoreEvict(t *testing.T) {
	s := NewMemoryStore()
	s.Set("fresh", storedResponse{ExpiresAt: time.Now().Add(time.Hour)})
	s.Set("stale", storedResponse{ExpiresAt: time.Now().Add(-time.Hour)})
	s.Evict()
	_, fresh := s.Get("fresh")
	_, stale := s.Get("stale")
	assert.True(t, fresh)
	assert.False(t, stale)
}

func TestIdempotencyMiddlewareReplaysOnHit(t *testing.T) {
	store := NewMemoryStore()
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("X-Custom", "v1")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"n":%d}`, calls)
	})
	h := idempotencyMiddleware(store)(inner)

	// First call executes handler.
	req1 := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{}"))
	req1.Header.Set("X-Idempotency-Key", "abc")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	assert.Equal(t, 201, rr1.Code)
	assert.Equal(t, `{"n":1}`, rr1.Body.String())

	// Second call with same key replays cached response — handler not invoked again.
	req2 := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{}"))
	req2.Header.Set("X-Idempotency-Key", "abc")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	assert.Equal(t, 201, rr2.Code)
	assert.Equal(t, `{"n":1}`, rr2.Body.String())
	assert.Equal(t, "v1", rr2.Header().Get("X-Custom"))
	assert.Equal(t, 1, calls, "handler should be called only once")
}

func TestIdempotencyMiddlewareBypassesGET(t *testing.T) {
	store := NewMemoryStore()
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(200)
	})
	h := idempotencyMiddleware(store)(inner)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("X-Idempotency-Key", "abc")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	assert.Equal(t, 3, calls)
}

func TestIdempotencyMiddlewareNoKeyBypass(t *testing.T) {
	store := NewMemoryStore()
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(200)
	})
	h := idempotencyMiddleware(store)(inner)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{}"))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	assert.Equal(t, 3, calls)
}

func TestIdempotencyMiddlewareSkipsServerErrors(t *testing.T) {
	store := NewMemoryStore()
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	})
	h := idempotencyMiddleware(store)(inner)

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{}"))
	req.Header.Set("X-Idempotency-Key", "abc")
	h.ServeHTTP(httptest.NewRecorder(), req)
	// Retry same key — 5xx not cached, handler re-runs.
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, 2, calls)
}
