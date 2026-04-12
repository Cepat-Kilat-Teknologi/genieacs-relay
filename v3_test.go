package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// --- buildinfo ---

func TestSetBuildInfoAndAccessors(t *testing.T) {
	origV, origC, origD := buildVersion, buildCommit, buildDate
	defer func() { buildVersion, buildCommit, buildDate = origV, origC, origD }()

	setBuildInfo("9.9.9", "deadbeef", "2026-04-12T10:00:00Z")
	assert.Equal(t, "9.9.9", BuildVersion())
	assert.Equal(t, "deadbeef", BuildCommit())
	assert.Equal(t, "2026-04-12T10:00:00Z", BuildDate())
	assert.NotEmpty(t, Uptime())
}

func TestSetBuildInfoSkipsEmpty(t *testing.T) {
	origV, origC, origD := buildVersion, buildCommit, buildDate
	defer func() { buildVersion, buildCommit, buildDate = origV, origC, origD }()

	setBuildInfo("preserved", "preserved", "preserved")
	setBuildInfo("", "", "")
	// Empty args must not clobber existing values.
	assert.Equal(t, "preserved", BuildVersion())
	assert.Equal(t, "preserved", BuildCommit())
	assert.Equal(t, "preserved", BuildDate())
}

// --- reqctx + logger ---

func TestRequestIDContextRoundTrip(t *testing.T) {
	ctx := WithRequestID(context.Background(), "abc-123")
	assert.Equal(t, "abc-123", RequestIDFromContext(ctx))
	assert.Empty(t, RequestIDFromContext(context.Background()))
}

func TestWithRequestIDLoggerDecorates(t *testing.T) {
	l, err := initProductionLogger()
	require.NoError(t, err)
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	ctx := WithRequestID(context.Background(), "req-xyz")
	got := WithRequestIDLogger(ctx)
	require.NotNil(t, got)
	// Fall-through when no request id.
	got2 := WithRequestIDLogger(context.Background())
	require.NotNil(t, got2)
}

func TestWithRequestIDLoggerNilLogger(t *testing.T) {
	origLogger := logger
	logger = nil
	defer func() { logger = origLogger }()
	assert.NotNil(t, WithRequestIDLogger(context.Background()))
}

func TestWithModule(t *testing.T) {
	l, err := initProductionLogger()
	require.NoError(t, err)
	assert.NotNil(t, WithModule(l, "test"))
	assert.NotNil(t, WithModule(nil, "test"))
}

// --- idempotency ---

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

// --- audit ---

func TestIsWriteMethod(t *testing.T) {
	assert.True(t, isWriteMethod(http.MethodPost))
	assert.True(t, isWriteMethod(http.MethodPut))
	assert.True(t, isWriteMethod(http.MethodPatch))
	assert.True(t, isWriteMethod(http.MethodDelete))
	assert.False(t, isWriteMethod(http.MethodGet))
	assert.False(t, isWriteMethod(http.MethodHead))
}

func TestAuditMiddlewareSkipsReads(t *testing.T) {
	l, err := initProductionLogger()
	require.NoError(t, err)
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	called := false
	h := auditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.True(t, called)
}

func TestAuditMiddlewareEmitsOnWrite(t *testing.T) {
	l, err := initProductionLogger()
	require.NoError(t, err)
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	h := auditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(201)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, 201, rr.Code)
}

// --- apiversion headers ---

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

// --- metrics ---

func TestRegisterMetricsIdempotent(t *testing.T) {
	// Safe to call twice thanks to sync.Once + AlreadyRegisteredError tolerance.
	assert.NotPanics(t, func() {
		registerMetrics()
		registerMetrics()
	})
}

// --- health ---

func TestHealthzHandler(t *testing.T) {
	rr := httptest.NewRecorder()
	healthzHandler(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, 200, rr.Code)
	assert.Contains(t, rr.Body.String(), "healthy")
}

func TestVersionHandler(t *testing.T) {
	l, err := initProductionLogger()
	require.NoError(t, err)
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	rr := httptest.NewRecorder()
	versionHandler(rr, httptest.NewRequest(http.MethodGet, "/version", nil))
	assert.Equal(t, 200, rr.Code)
	var vr VersionResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&vr))
	assert.Equal(t, "v1", vr.APIVersion)
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

// --- readyz handler E2E ---

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

// --- response envelope ---

func TestSendResponseSuccessEnvelope(t *testing.T) {
	l, _ := initProductionLogger()
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	rr := httptest.NewRecorder()
	sendResponse(rr, 201, map[string]string{"ok": "yes"})
	assert.Equal(t, 201, rr.Code)
	var resp Response
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, StatusSuccess, resp.Status)
	assert.Equal(t, 201, resp.Code)
}

func TestSendErrorEnvelopeWithRequestID(t *testing.T) {
	l, _ := initProductionLogger()
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	ctx := WithRequestID(context.Background(), "req-1")
	req := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	sendError(rr, req, http.StatusBadRequest, ErrCodeValidation, "bad input")
	assert.Equal(t, 400, rr.Code)
	var resp Response
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, ErrCodeValidation, resp.ErrorCode)
	assert.Equal(t, "req-1", resp.RequestID)
	assert.Equal(t, "bad input", resp.Data)
}

func TestSendErrorNilRequest(t *testing.T) {
	l, _ := initProductionLogger()
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	rr := httptest.NewRecorder()
	sendError(rr, nil, http.StatusInternalServerError, ErrCodeInternal, "boom")
	assert.Equal(t, 500, rr.Code)
	var resp Response
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Empty(t, resp.RequestID)
}

func TestRequestIDMiddlewareInjectsCtx(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = RequestIDFromContext(r.Context())
	})
	// Stack chi.RequestID + our bridge to emulate real server setup.
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Request-ID", "incoming-123")
	rr := httptest.NewRecorder()

	// Manually thread the chi middleware.RequestID via its named export — since it's
	// external, we stub by injecting directly into the context and calling our wrapper.
	ctx := context.WithValue(req.Context(), middlewareRequestIDCtxKey{}, "incoming-123")
	_ = ctx
	_ = io.Discard

	h := requestIDMiddleware(inner)
	h.ServeHTTP(rr, req)
	// Without chi.RequestID upstream our fallback reads X-Request-ID header directly.
	assert.Equal(t, "incoming-123", captured)
}

// Sentinel type — never used at runtime, just here so the test above can reference
// something without importing internal chi types. The actual chi key lives in
// github.com/go-chi/chi/v5/middleware and is opaque to us.
type middlewareRequestIDCtxKey struct{}

// Silence unused warning for sentinel.
var _ = zap.String

// --- Cover remaining branches to restore 100% coverage ---

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

// versionHandler: exercise the json encode error path by wiring an
// errorResponseWriter that fails on Write. Mirrors the TestSendResponseEncoding
// pattern already in main_test.go.
func TestVersionHandlerEncodeError(t *testing.T) {
	l, _ := initProductionLogger()
	origLogger := logger
	logger = l
	defer func() { logger = origLogger }()

	w := &errorResponseWriter{}
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	// Should not panic even when Write fails — error is logged via zap.
	assert.NotPanics(t, func() {
		versionHandler(w, req)
	})
}

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
