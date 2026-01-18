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

func runServer(addr string) error {
	// load config
	serverAddr = getEnv("SERVER_ADDR", addr)
	geniesBaseURL = getEnv("GENIEACS_BASE_URL", DefaultGenieACSURL)

	// Load NBI authentication config (for GenieACS API calls)
	// By default, GenieACS NBI has no authentication, so NBI_AUTH defaults to false
	nbiAuth = getEnv(EnvNBIAuth, "false") == "true"
	nbiAuthKey = getEnv(EnvNBIAuthKey, DefaultNBIAuthKey)

	// Return error if NBI auth is enabled but NBI_AUTH_KEY is not set
	if nbiAuth && nbiAuthKey == "" {
		return fmt.Errorf("NBI_AUTH is enabled but NBI_AUTH_KEY is not set. " +
			"Set NBI_AUTH_KEY environment variable or disable NBI_AUTH")
	}

	// Log NBI auth status
	logger.Info("NBI authentication", zap.Bool("enabled", nbiAuth))

	// Load middleware authentication config (for incoming API requests)
	middlewareAuth = getEnv(EnvMiddlewareAuth, "false") == "true"
	authKey = getEnv(EnvAuthKey, DefaultAuthKey)

	// Return error if middleware auth is enabled but AUTH_KEY is not set
	// This prevents the server from starting in an insecure state
	if middlewareAuth && authKey == "" {
		return fmt.Errorf("MIDDLEWARE_AUTH is enabled but AUTH_KEY is not set. " +
			"Set AUTH_KEY environment variable or disable MIDDLEWARE_AUTH")
	}

	// Log middleware auth status
	logger.Info("Middleware authentication", zap.Bool("enabled", middlewareAuth))

	// Load stale threshold config (default: 10 minutes)
	staleThreshold = DefaultStaleThreshold
	if staleMinStr := getEnv(EnvStaleThreshold, ""); staleMinStr != "" {
		if staleMin, err := strconv.Atoi(staleMinStr); err == nil && staleMin > 0 {
			staleThreshold = time.Duration(staleMin) * time.Minute
		}
	}
	logger.Info("Stale device threshold", zap.Duration("threshold", staleThreshold))

	// Load CORS config - default to "*" (allow all origins)
	originsStr := getEnv(EnvCORSAllowedOrigins, DefaultCORSAllowedOrigins)
	corsOrigins := strings.Split(originsStr, ",")
	// Trim spaces from each origin
	for i := range corsOrigins {
		corsOrigins[i] = strings.TrimSpace(corsOrigins[i])
	}
	if originsStr == "*" {
		logger.Info("CORS enabled", zap.String("allowed_origins", "*"))
	} else {
		logger.Info("CORS enabled", zap.Strings("allowed_origins", corsOrigins))
	}

	// start worker pool
	taskWorkerPool.Start()
	defer taskWorkerPool.Stop()

	// Load rate limit configuration
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

	// Load CORS max-age configuration
	corsMaxAge := DefaultCORSMaxAge
	if corsMaxAgeStr := getEnv(EnvCORSMaxAge, ""); corsMaxAgeStr != "" {
		if maxAge, err := strconv.Atoi(corsMaxAgeStr); err == nil && maxAge > 0 {
			corsMaxAge = maxAge
		}
	}

	logger.Info("Starting server", zap.String("genieacs_url", geniesBaseURL))

	// router
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	// Apply rate limiting middleware
	rl := newRateLimiter(rateLimitRequests, rateLimitWindow)
	rl.StartCleanup() // Start background cleanup to prevent memory leaks
	defer rl.StopCleanup()
	r.Use(rateLimitMiddleware(rl))

	// Start auth attempt tracker cleanup for brute force protection
	authTracker.StartCleanup()
	defer authTracker.StopCleanup()
	r.Use(securityHeadersMiddleware)
	// Apply CORS middleware
	r.Use(corsMiddleware(corsOrigins, corsMaxAge))

	// Health check endpoint - intentionally outside authentication
	// This allows load balancers and monitoring systems to check service health
	// without requiring API credentials. It returns minimal info (status only).
	r.Get("/health", healthCheckHandler)

	// Swagger documentation endpoint - also outside authentication
	// Allows developers to access API documentation without credentials
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/api/v1/genieacs", func(r chi.Router) {
		// Apply API key authentication middleware if enabled
		if middlewareAuth {
			r.Use(apiKeyAuthMiddleware)
		}
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Get("/force"+"/ssid/{ip}", getSSIDByIPForceHandler)
		r.Post("/ssid/{ip}/refresh", refreshSSIDHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/cache/clear", clearCacheHandler)
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
