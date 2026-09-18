package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	gobreaker "github.com/sony/gobreaker/v2"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Circuit breaker configuration
// ---------------------------------------------------------------------------

// BreakerConfig controls the circuit breaker protecting GenieACS NBI calls.
type BreakerConfig struct {
	// Enabled gates the circuit breaker entirely. When false, nbiDo is a
	// straight pass-through to httpClient.Do.
	Enabled bool

	// MaxRequests is the number of requests allowed in the half-open state
	// before deciding whether to close or re-open the circuit (default 1).
	MaxRequests uint32

	// Interval is the cyclic time window in the closed state. Counts reset
	// after this duration if the circuit stays closed (default 60s).
	Interval time.Duration

	// Timeout is how long the circuit stays open before transitioning to
	// half-open and allowing a probe request (default 30s).
	Timeout time.Duration

	// TripThreshold is the number of consecutive failures required to open
	// the circuit (default 5).
	TripThreshold uint32
}

// DefaultBreakerConfig returns production-safe defaults.
func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{
		Enabled:       true,
		MaxRequests:   1,
		Interval:      60 * time.Second,
		Timeout:       30 * time.Second,
		TripThreshold: 5,
	}
}

// LoadBreakerConfigFromEnv builds a BreakerConfig from environment variables,
// falling back to DefaultBreakerConfig for any value not set or unparseable.
//
// Env vars: CB_ENABLED, CB_MAX_REQUESTS, CB_INTERVAL, CB_TIMEOUT, CB_TRIP_THRESHOLD
func LoadBreakerConfigFromEnv() BreakerConfig {
	cfg := DefaultBreakerConfig()

	if v := getEnv("CB_ENABLED", "true"); v == BoolStrFalse {
		cfg.Enabled = false
	}
	if v := getEnv("CB_MAX_REQUESTS", ""); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil && n > 0 {
			cfg.MaxRequests = uint32(n)
		}
	}
	if v := getEnv("CB_INTERVAL", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Interval = d
		}
	}
	if v := getEnv("CB_TIMEOUT", ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Timeout = d
		}
	}
	if v := getEnv("CB_TRIP_THRESHOLD", ""); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil && n > 0 {
			cfg.TripThreshold = uint32(n)
		}
	}

	return cfg
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

var (
	cbStateGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "outbound_circuit_breaker_state",
			Help: "Current circuit breaker state for GenieACS NBI (0=closed, 1=half-open, 2=open).",
		},
		[]string{"target"},
	)
	cbTripsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "outbound_circuit_breaker_trips_total",
			Help: "Total circuit breaker state transitions by target and state.",
		},
		[]string{"target", "to"},
	)
)

// cbMetricsRegistered guards one-time registration so tests and hot-reload
// scenarios don't panic on duplicate collectors.
var cbMetricsRegistered sync.Once

func registerBreakerMetrics() {
	cbMetricsRegistered.Do(func() {
		for _, c := range []prometheus.Collector{cbStateGauge, cbTripsTotal} {
			_ = prometheus.Register(c)
		}
	})
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

func cbStateFloat(s gobreaker.State) float64 {
	switch s {
	case gobreaker.StateClosed:
		return 0
	case gobreaker.StateHalfOpen:
		return 1
	case gobreaker.StateOpen:
		return 2
	default:
		return -1
	}
}

func cbStateName(s gobreaker.State) string {
	switch s {
	case gobreaker.StateClosed:
		return "closed"
	case gobreaker.StateHalfOpen:
		return "half-open"
	case gobreaker.StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// Circuit breaker instance
// ---------------------------------------------------------------------------

// ErrCircuitOpen is returned when the NBI circuit breaker is open and the
// request is rejected without attempting the upstream call.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// nbiBreaker is the circuit breaker wrapping outbound calls to GenieACS NBI.
// It is nil when the breaker is disabled.
var nbiBreaker *gobreaker.CircuitBreaker[*http.Response]

// nbiCBTarget is the Prometheus label value for the GenieACS NBI breaker.
const nbiCBTarget = "genieacs-nbi"

// initBreaker creates the circuit breaker for the GenieACS NBI upstream.
func initBreaker(cfg BreakerConfig, log *zap.Logger) {
	registerBreakerMetrics()

	if !cfg.Enabled {
		log.Info("circuit breaker disabled")
		nbiBreaker = nil
		return
	}

	settings := gobreaker.Settings{
		Name:        nbiCBTarget,
		MaxRequests: cfg.MaxRequests,
		Interval:    cfg.Interval,
		Timeout:     cfg.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= cfg.TripThreshold
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			cbStateGauge.WithLabelValues(name).Set(cbStateFloat(to))
			cbTripsTotal.WithLabelValues(name, cbStateName(to)).Inc()
			log.Warn("circuit breaker state change",
				zap.String("target", name),
				zap.String("from", cbStateName(from)),
				zap.String("to", cbStateName(to)),
			)
		},
		IsSuccessful: func(err error) bool {
			return err == nil
		},
	}

	nbiBreaker = gobreaker.NewCircuitBreaker[*http.Response](settings) //nolint:bodyclose // body closed by callers of nbiDo
	cbStateGauge.WithLabelValues(nbiCBTarget).Set(0)                   // initialize to closed

	log.Info("circuit breaker initialized",
		zap.String("target", nbiCBTarget),
		zap.Uint32("trip_threshold", cfg.TripThreshold),
		zap.Duration("timeout", cfg.Timeout),
		zap.Duration("interval", cfg.Interval),
		zap.Uint32("max_requests", cfg.MaxRequests),
	)
}

// nbiDo executes an HTTP request through the NBI circuit breaker. If the
// breaker is disabled (nil), it falls through to httpClient.Do directly.
//
// The breaker counts 5xx responses as failures (toward the trip threshold)
// but still returns the response to callers so their existing status-code
// handling works unchanged. Only transport-level errors and circuit-open
// rejections return a nil response.
func nbiDo(req *http.Request) (*http.Response, error) {
	if nbiBreaker == nil {
		return httpClient.Do(req) //nolint:gosec // G107: URL from trusted internal config
	}

	resp, err := nbiBreaker.Execute(func() (*http.Response, error) {
		r, doErr := httpClient.Do(req) //nolint:gosec // G107: URL from trusted internal config
		if doErr != nil {
			return nil, doErr
		}
		// Count 5xx as a breaker failure so sustained server errors trip the
		// circuit, but return the response so callers can read the body.
		if r.StatusCode >= http.StatusInternalServerError {
			return r, fmt.Errorf("genieacs-nbi returned %d", r.StatusCode)
		}
		return r, nil
	})

	// Circuit is open — reject immediately.
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, ErrCircuitOpen
	}

	// 5xx path: resp is non-nil (the upstream responded), err is non-nil
	// (the breaker recorded a failure). Return just the response so callers
	// handle the status code through their existing paths.
	if resp != nil {
		return resp, nil
	}

	return nil, err
}
