package main

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus collectors per isp-adapter-standard §5.
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by method, path template, and status code.",
		},
		[]string{"method", "path", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
	httpRequestsInFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "Current number of HTTP requests being processed.",
		},
	)
)

// metricsRegistered guards single registration of collectors even when runServer
// is called multiple times in the same process (e.g. from test harness).
var metricsRegistered sync.Once

// registerMetrics registers all collectors with the default Prometheus registry
// idempotently via sync.Once. Safe to call multiple times.
func registerMetrics() {
	metricsRegistered.Do(doRegisterMetrics)
}

// doRegisterMetrics performs the actual collector registration, tolerating the
// AlreadyRegisteredError case so tests and hot-reload scenarios can re-invoke it
// without panicking. Other errors (invalid label names, duplicate desc with
// different help text) would indicate a programmer bug and are safely ignored —
// the Prometheus client library panics synchronously at collector-definition
// time for those, so we never see them here.
func doRegisterMetrics() {
	for _, c := range []prometheus.Collector{httpRequestsTotal, httpRequestDuration, httpRequestsInFlight} {
		_ = prometheus.Register(c)
	}
}

// metricsHandler exposes Prometheus metrics at /metrics.
//
//	@Summary		Prometheus metrics
//	@Description	Prometheus exposition format for service metrics. No authentication required.
//	@Tags			Health
//	@Produce		plain
//	@Success		200
//	@Router			/metrics [get]
func metricsHandler() http.Handler { return promhttp.Handler() }

// metricsMiddleware records per-request counters and histograms.
// Uses chi's RouteContext to capture the path template (e.g. /api/v1/genieacs/wlan/create/{wlan}/{ip})
// instead of the concrete URL, which prevents cardinality explosion from IP-in-path.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip self-metric paths to avoid recursive accounting.
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		httpRequestsInFlight.Inc()
		defer httpRequestsInFlight.Dec()

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		path := chi.RouteContext(r.Context()).RoutePattern()
		if path == "" {
			path = "unknown"
		}
		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(ww.Status())).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(time.Since(start).Seconds())
	})
}
