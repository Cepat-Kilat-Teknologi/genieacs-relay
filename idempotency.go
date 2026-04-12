package main

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"
)

// IdempotencyTTL is the default cache lifetime for idempotency-key results.
// Set to 7 days to match the NATS COMMANDS retention window — any saga retry
// arriving within that window will receive the cached response.
const IdempotencyTTL = 7 * 24 * time.Hour

// idempotencyHeader is the HTTP header clients send to deduplicate retried writes.
const idempotencyHeader = "X-Idempotency-Key"

// storedResponse snapshots a response for replay on idempotent retries.
type storedResponse struct {
	Status    int
	Header    http.Header
	Body      []byte
	ExpiresAt time.Time
}

// MemoryStore is a simple in-process TTL cache for idempotent request replay.
// It does NOT survive restarts or share across replicas; billing-agent v2 deployments
// that need cross-instance dedupe should migrate to a Redis-backed store.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]storedResponse
}

// NewMemoryStore returns an initialized in-memory idempotency store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]storedResponse)}
}

// Get returns a cached response if the key is present and not expired.
// Expired entries are evicted lazily on read.
func (m *MemoryStore) Get(key string) (storedResponse, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[key]
	if !ok {
		return storedResponse{}, false
	}
	if time.Now().After(v.ExpiresAt) {
		delete(m.entries, key)
		return storedResponse{}, false
	}
	return v, true
}

// Set stores a response snapshot under key with the configured TTL.
func (m *MemoryStore) Set(key string, s storedResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = s
}

// Evict removes stale entries. Call periodically from a cleanup goroutine
// to prevent unbounded growth on pathological traffic patterns.
func (m *MemoryStore) Evict() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, v := range m.entries {
		if now.After(v.ExpiresAt) {
			delete(m.entries, k)
		}
	}
}

// defaultIdempotencyStore is the package-level store wired from server.go at startup.
var defaultIdempotencyStore = NewMemoryStore()

// captureResponseWriter buffers the response body so it can be cached after the
// downstream handler writes it. Preserves status code and headers.
type captureResponseWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *captureResponseWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureResponseWriter) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

// idempotencyMiddleware short-circuits retried requests that carry the same
// X-Idempotency-Key within the TTL window by replaying the cached response.
// GET/HEAD requests flow through unchanged since they are naturally idempotent.
func idempotencyMiddleware(store *MemoryStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if store == nil || !isWriteMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Header.Get(idempotencyHeader)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Replay cached response on hit.
			if cached, ok := store.Get(key); ok {
				for k, vs := range cached.Header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(cached.Status)
				_, _ = io.Copy(w, bytes.NewReader(cached.Body))
				return
			}
			// Capture and store on first hit for this key.
			capture := &captureResponseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(capture, r)
			// Only cache successful + client-error responses; server errors should be retryable.
			if capture.status < http.StatusInternalServerError {
				store.Set(key, storedResponse{
					Status:    capture.status,
					Header:    cloneHeader(w.Header()),
					Body:      capture.buf.Bytes(),
					ExpiresAt: time.Now().Add(IdempotencyTTL),
				})
			}
		})
	}
}

// cloneHeader returns a deep copy of an http.Header for safe long-term storage.
func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}
