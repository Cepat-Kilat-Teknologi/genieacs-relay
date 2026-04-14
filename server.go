package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"go.uber.org/zap"

	_ "github.com/Cepat-Kilat-Teknologi/genieacs-relay/docs"
)

// serverConfig holds all server configuration
type serverConfig struct {
	corsOrigins       []string
	corsMaxAge        int
	rateLimitRequests int
	rateLimitWindow   time.Duration
}

// loadNBIAuthConfig loads and validates NBI authentication configuration
func loadNBIAuthConfig() error {
	nbiAuth = getEnv(EnvNBIAuth, BoolStrFalse) == BoolStrTrue
	nbiAuthKey = getEnv(EnvNBIAuthKey, DefaultNBIAuthKey)

	if nbiAuth && nbiAuthKey == "" {
		return fmt.Errorf("NBI_AUTH is enabled but NBI_AUTH_KEY is not set. " +
			"Set NBI_AUTH_KEY environment variable or disable NBI_AUTH")
	}

	logger.Info("NBI authentication", zap.Bool("enabled", nbiAuth))
	return nil
}

// loadMiddlewareAuthConfig loads and validates middleware authentication configuration
func loadMiddlewareAuthConfig() error {
	middlewareAuth = getEnv(EnvMiddlewareAuth, BoolStrFalse) == BoolStrTrue
	authKey = getEnv(EnvAuthKey, DefaultAuthKey)

	if middlewareAuth && authKey == "" {
		return fmt.Errorf("MIDDLEWARE_AUTH is enabled but AUTH_KEY is not set. " +
			"Set AUTH_KEY environment variable or disable MIDDLEWARE_AUTH")
	}

	logger.Info("Middleware authentication", zap.Bool("enabled", middlewareAuth))
	return nil
}

// loadStaleThresholdConfig loads stale threshold configuration
func loadStaleThresholdConfig() {
	staleThreshold = DefaultStaleThreshold
	if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
		if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
			staleThreshold = time.Duration(staleMin) * time.Minute
		}
	}
	logger.Info("Stale device threshold", zap.Duration("threshold", staleThreshold))
}

// loadCORSConfig loads CORS configuration and returns origins slice
func loadCORSConfig() []string {
	originsStr := getEnv(EnvCORSAllowedOrigins, DefaultCORSAllowedOrigins)
	corsOrigins := strings.Split(originsStr, ",")
	for i := range corsOrigins {
		corsOrigins[i] = strings.TrimSpace(corsOrigins[i])
	}

	if originsStr == "*" {
		logger.Info("CORS enabled", zap.String("allowed_origins", "*"))
	} else {
		logger.Info("CORS enabled", zap.Strings("allowed_origins", corsOrigins))
	}
	return corsOrigins
}

// loadRateLimitConfig loads rate limiting configuration
func loadRateLimitConfig() (int, time.Duration) {
	rateLimitRequests := DefaultRateLimitRequests
	if rlReqStr := getEnv(EnvRateLimitRequests, ""); rlReqStr != "" {
		if rlReq, err := strconv.Atoi(rlReqStr); err == nil && rlReq > 0 {
			rateLimitRequests = rlReq
		}
	}

	rateLimitWindow := time.Duration(DefaultRateLimitWindow) * time.Second
	if rlWinStr := getEnv(EnvRateLimitWindow, ""); rlWinStr != "" {
		if rlWin, err := strconv.Atoi(rlWinStr); err == nil && rlWin > 0 {
			rateLimitWindow = time.Duration(rlWin) * time.Second
		}
	}

	logger.Info("Rate limiting configured",
		zap.Int("requests", rateLimitRequests),
		zap.Duration("window", rateLimitWindow))

	return rateLimitRequests, rateLimitWindow
}

// loadCORSMaxAgeConfig loads CORS max-age configuration
func loadCORSMaxAgeConfig() int {
	corsMaxAge := DefaultCORSMaxAge
	if corsMaxAgeStr := getEnv(EnvCORSMaxAge, ""); corsMaxAgeStr != "" {
		if maxAge, err := strconv.Atoi(corsMaxAgeStr); err == nil && maxAge > 0 {
			corsMaxAge = maxAge
		}
	}
	return corsMaxAge
}

// loadOpticalThresholdConfig reads the four optical health classification
// thresholds from env vars OPTICAL_RX_NO_SIGNAL_DBM / _CRITICAL_DBM /
// _WARNING_DBM / _OVERLOAD_DBM. Invalid or empty env vars fall back to
// the package-level defaults from constants.go. Logged once at startup
// so ops can verify the active classification policy.
func loadOpticalThresholdConfig() {
	parseFloat := func(envName string, defaultVal float64) float64 {
		raw := getEnv(envName, "")
		if raw == "" {
			return defaultVal
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			logger.Warn("Invalid optical threshold env var, using default",
				zap.String("env", envName),
				zap.String("value", raw),
				zap.Float64("default", defaultVal),
				zap.Error(err))
			return defaultVal
		}
		return v
	}
	opticalRxNoSignalDBm = parseFloat(EnvOpticalRxNoSignalDBm, DefaultOpticalRxNoSignalDBm)
	opticalRxCriticalDBm = parseFloat(EnvOpticalRxCriticalDBm, DefaultOpticalRxCriticalDBm)
	opticalRxWarningDBm = parseFloat(EnvOpticalRxWarningDBm, DefaultOpticalRxWarningDBm)
	opticalRxOverloadDBm = parseFloat(EnvOpticalRxOverloadDBm, DefaultOpticalRxOverloadDBm)
	logger.Info("Optical health thresholds (dBm)",
		zap.Float64("no_signal", opticalRxNoSignalDBm),
		zap.Float64("critical", opticalRxCriticalDBm),
		zap.Float64("warning", opticalRxWarningDBm),
		zap.Float64("overload", opticalRxOverloadDBm))
}

// loadServerConfig loads all server configuration
func loadServerConfig(addr string) (*serverConfig, error) {
	serverAddr = getEnv("SERVER_ADDR", addr)
	geniesBaseURL = getEnv("GENIEACS_BASE_URL", DefaultGenieACSURL)

	if err := loadNBIAuthConfig(); err != nil {
		return nil, err
	}

	if err := loadMiddlewareAuthConfig(); err != nil {
		return nil, err
	}

	loadStaleThresholdConfig()
	loadOpticalThresholdConfig()

	return &serverConfig{
		corsOrigins: loadCORSConfig(),
		corsMaxAge:  loadCORSMaxAgeConfig(),
	}, nil
}

func runServer(addr string) error {
	// Load all configuration
	cfg, err := loadServerConfig(addr)
	if err != nil {
		return err
	}

	// Load rate limit config separately (needs to be used for middleware)
	cfg.rateLimitRequests, cfg.rateLimitWindow = loadRateLimitConfig()

	logger.Info("Starting server", zap.String("genieacs_url", geniesBaseURL))

	// Start worker pool for async task processing (setParameterValues, applyChanges, refreshWLAN)
	taskWorkerPool.Start()
	defer taskWorkerPool.Stop()

	// Register Prometheus collectors once at startup.
	registerMetrics()

	// router
	r := chi.NewRouter()
	// chi.RequestID generates the correlation ID; requestIDMiddleware bridges it into our
	// typed context key so WithRequestIDLogger(ctx) and error bodies can include it.
	// structuredLoggerMiddleware replaces chi's middleware.Logger so we can emit zap-structured
	// logs with request_id and skip noisy health/probe paths.
	r.Use(
		middleware.RequestID,
		requestIDMiddleware,
		middleware.RealIP,
		apiVersionHeadersMiddleware,
		structuredLoggerMiddleware,
		metricsMiddleware,
		auditMiddleware,
		middleware.Recoverer,
	)
	r.Use(middleware.Timeout(60 * time.Second))
	// Apply rate limiting middleware
	rl := newRateLimiter(cfg.rateLimitRequests, cfg.rateLimitWindow)
	rl.StartCleanup() // Start background cleanup to prevent memory leaks
	defer rl.StopCleanup()
	r.Use(rateLimitMiddleware(rl))

	// Start auth attempt tracker cleanup for brute force protection
	authTracker.StartCleanup()
	defer authTracker.StopCleanup()
	r.Use(securityHeadersMiddleware)
	// Apply CORS middleware
	r.Use(corsMiddleware(cfg.corsOrigins, cfg.corsMaxAge))

	// Health check endpoints - intentionally outside authentication
	// This allows load balancers and monitoring systems to check service health
	// without requiring API credentials. It returns minimal info (status only).
	r.Get("/health", healthCheckHandler) // backwards-compat liveness alias
	r.Get("/healthz", healthzHandler)    // k8s liveness probe
	r.Get("/ready", readyzHandler)       // Fiber-convention readiness alias
	r.Get("/readyz", readyzHandler)      // k8s readiness probe with cached GenieACS ping

	// Version endpoint - build metadata exposed publicly for release verification.
	// Returns real ldflags-injected values when built via Docker CI pipeline,
	// or "dev"/"none"/"unknown" defaults when built locally without ldflags.
	r.Get("/version", versionHandler)

	// Prometheus metrics endpoint - unauthenticated per isp-adapter-standard §5.
	r.Handle("/metrics", metricsHandler())

	// Swagger documentation endpoint - also outside authentication
	// Allows developers to access API documentation without credentials
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/api/v1/genieacs", func(r chi.Router) {
		// Apply API key authentication middleware if enabled
		if middlewareAuth {
			r.Use(apiKeyAuthMiddleware)
		}
		// Idempotency middleware for write operations. Clients (billing-agent saga retries,
		// NATS redelivery) send X-Idempotency-Key; repeated keys replay the cached response
		// within the TTL window, preventing duplicate WLAN provisioning jobs.
		r.Use(idempotencyMiddleware(defaultIdempotencyStore))
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Get("/force"+"/ssid/{ip}", getSSIDByIPForceHandler)
		r.Post("/ssid/{ip}/refresh", refreshSSIDHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/dhcp/{ip}/refresh", refreshDHCPHandler)
		r.Post("/cache/clear", clearCacheHandler)
		// CPE lifecycle operations (v2.1.0)
		r.Post("/reboot/{ip}", rebootDeviceHandler)
		r.Get("/optical/{ip}", getOpticalStatsHandler)
		// Device capability and WLAN management endpoints
		r.Get("/capability/{ip}", getDeviceCapabilityHandler)
		r.Get("/wlan/available/{ip}", getAvailableWLANHandler)
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)
		r.Put("/wlan/update/{wlan}/{ip}", updateWLANHandler)
		r.Delete("/wlan/delete/{wlan}/{ip}", deleteWLANHandler)
		r.Put("/wlan/optimize/{wlan}/{ip}", optimizeWLANHandler)
	})

	// server
	server := newHTTPServer(serverAddr, r)

	// start server
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server listening", zap.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return err
	case <-quit:
		logger.Info("Shutdown signal received, starting graceful shutdown...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := serverShutdown(ctx, server); err != nil {
			return err
		}

		logger.Info("Server exited properly")
		return nil
	}
}
