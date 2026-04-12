package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// healthChecker probes downstream dependencies for /readyz with per-dependency TTL caching.
// Caching prevents k8s readiness probes (typically every 10s) from hammering GenieACS.
type healthChecker struct {
	mu sync.Mutex
	// cached result; regenerated when older than cacheTTL
	lastCheck time.Time
	lastState ReadinessResponse
	cacheTTL  time.Duration
	httpDo    func(req *http.Request) (*http.Response, error)
}

// defaultHealthChecker is the package-level checker wired from server.go at startup.
var defaultHealthChecker = &healthChecker{
	cacheTTL: 5 * time.Second,
	httpDo:   httpClient.Do,
}

// pingGenieACS hits the GenieACS base URL with a cheap GET and reports reachable/not-reachable.
// Uses a short timeout (2s) so k8s readiness probes don't stall on slow upstream.
func (h *healthChecker) pingGenieACS(ctx context.Context) DependencyState {
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	//nolint:gosec // G107: URL built from trusted internal config (geniesBaseURL)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, geniesBaseURL+"/", http.NoBody)
	if err != nil {
		return DependencyState{State: "down", Error: fmt.Sprintf("build request: %v", err)}
	}
	if nbiAuth && nbiAuthKey != "" {
		req.Header.Set(HeaderXAPIKey, nbiAuthKey)
	}
	resp, err := h.httpDo(req)
	if err != nil {
		return DependencyState{State: "down", Error: fmt.Sprintf("request failed: %v", err)}
	}
	defer safeClose(resp.Body)
	// GenieACS NBI returns 200 on GET /; any 2xx/3xx/4xx means the process is up
	// (auth errors still confirm reachability). Only connection-level errors count as down.
	if resp.StatusCode >= http.StatusInternalServerError {
		return DependencyState{State: "down", Error: fmt.Sprintf("status %d", resp.StatusCode)}
	}
	return DependencyState{State: "up"}
}

// check returns the current readiness snapshot, using cached results when fresh.
func (h *healthChecker) check(ctx context.Context) ReadinessResponse {
	h.mu.Lock()
	defer h.mu.Unlock()

	if time.Since(h.lastCheck) < h.cacheTTL && h.lastState.Status != "" {
		return h.lastState
	}

	genieState := h.pingGenieACS(ctx)
	status := "ready"
	if genieState.State != "up" {
		status = "not_ready"
	}

	h.lastState = ReadinessResponse{
		Status: status,
		Dependencies: map[string]DependencyState{
			"genieacs": genieState,
		},
	}
	h.lastCheck = time.Now()
	return h.lastState
}

// healthzHandler is the minimal k8s liveness probe endpoint.
//
//	@Summary		Liveness probe
//	@Description	Kubernetes liveness probe — returns 200 when the process is running. Does not check downstream dependencies.
//	@Tags			Health
//	@Produce		json
//	@Success		200	{object}	HealthResponse
//	@Router			/healthz [get]
func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	sendResponse(w, http.StatusOK, HealthResponse{Status: "healthy"})
}

// readyzHandler is the k8s readiness probe endpoint with cached dependency probes.
//
//	@Summary		Readiness probe
//	@Description	Kubernetes readiness probe — returns 200 when all upstream dependencies (GenieACS) are reachable, 503 when any dependency is down. Results cached with TTL to avoid probe storms.
//	@Tags			Health
//	@Produce		json
//	@Success		200	{object}	ReadinessResponse
//	@Failure		503	{object}	ReadinessResponse
//	@Router			/readyz [get]
func readyzHandler(w http.ResponseWriter, r *http.Request) {
	state := defaultHealthChecker.check(r.Context())
	w.Header().Set("Content-Type", "application/json")
	code := http.StatusOK
	if state.Status != "ready" {
		code = http.StatusServiceUnavailable
	}
	// Bypass sendResponse to preserve the ReadinessResponse shape at the top level
	// (readiness doesn't conform to the {status, data, code} envelope per isp-adapter-standard §5).
	w.WriteHeader(code)
	_ = encodeJSON(w, state)
}
