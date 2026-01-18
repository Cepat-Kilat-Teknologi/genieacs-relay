package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// authAttemptTracker tracks failed authentication attempts per IP for brute force protection
type authAttemptTracker struct {
	mu              sync.RWMutex
	attempts        map[string]*authAttempt
	stopCh          chan struct{}
	cleanupOnce     sync.Once     // Ensures StartCleanup is only called once
	stopOnce        sync.Once     // Ensures StopCleanup is only called once
	cleanupInterval time.Duration // Cleanup interval (defaults to AuthAttemptWindow)
}

// authAttempt tracks failed attempts and lockout status for an IP
type authAttempt struct {
	failedCount int
	firstFailed time.Time
	lockedUntil time.Time
}

// Global auth attempt tracker instance
var authTracker = newAuthAttemptTracker()

// newAuthAttemptTracker creates a new auth attempt tracker
func newAuthAttemptTracker() *authAttemptTracker {
	return &authAttemptTracker{
		attempts: make(map[string]*authAttempt),
	}
}

// isBlocked checks if an IP is currently blocked due to too many failed attempts
func (at *authAttemptTracker) isBlocked(ip string) bool {
	at.mu.RLock()
	defer at.mu.RUnlock()

	attempt, exists := at.attempts[ip]
	if !exists {
		return false
	}

	// Check if still in a lockout period
	if time.Now().Before(attempt.lockedUntil) {
		return true
	}

	return false
}

// recordFailure records a failed authentication attempt for an IP
func (at *authAttemptTracker) recordFailure(ip string) {
	at.mu.Lock()
	defer at.mu.Unlock()

	now := time.Now()
	attempt, exists := at.attempts[ip]

	if !exists {
		at.attempts[ip] = &authAttempt{
			failedCount: 1,
			firstFailed: now,
		}
		return
	}

	// Reset if outside the attempt window
	if now.Sub(attempt.firstFailed) > AuthAttemptWindow {
		attempt.failedCount = 1
		attempt.firstFailed = now
		attempt.lockedUntil = time.Time{}
		return
	}

	// Increment failure count
	attempt.failedCount++

	// Lock out if max attempts exceeded
	if attempt.failedCount >= MaxFailedAuthAttempts {
		attempt.lockedUntil = now.Add(AuthLockoutDuration)
	}
}

// recordSuccess clears failed attempts for an IP on successful auth
func (at *authAttemptTracker) recordSuccess(ip string) {
	at.mu.Lock()
	defer at.mu.Unlock()
	delete(at.attempts, ip)
}

// getRemainingLockout returns the remaining lockout duration for an IP
func (at *authAttemptTracker) getRemainingLockout(ip string) time.Duration {
	at.mu.RLock()
	defer at.mu.RUnlock()

	attempt, exists := at.attempts[ip]
	if !exists {
		return 0
	}

	remaining := time.Until(attempt.lockedUntil)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// StartCleanup starts periodic cleanup of stale entries
// Uses sync.Once to prevent multiple cleanup goroutines from being started
func (at *authAttemptTracker) StartCleanup() {
	at.cleanupOnce.Do(func() {
		at.stopCh = make(chan struct{})

		// Use custom interval if set, otherwise use default
		interval := at.cleanupInterval
		if interval == 0 {
			interval = AuthAttemptWindow
		}

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					at.cleanup()
				case <-at.stopCh:
					return
				}
			}
		}()
	})
}

// StopCleanup stops the cleanup goroutine
// Uses sync.Once to prevent double-closing the channel
func (at *authAttemptTracker) StopCleanup() {
	at.stopOnce.Do(func() {
		if at.stopCh != nil {
			close(at.stopCh)
		}
	})
}

// cleanup removes expired entries
func (at *authAttemptTracker) cleanup() {
	at.mu.Lock()
	defer at.mu.Unlock()

	now := time.Now()
	for ip, attempt := range at.attempts {
		// Remove if lockout expired and outside the attempt window
		if now.After(attempt.lockedUntil) && now.Sub(attempt.firstFailed) > AuthAttemptWindow {
			delete(at.attempts, ip)
		}
	}
}

// AuditLog logs security-relevant events for audit trail
func AuditLog(eventType, clientIP, deviceID, details string) {
	logger.Info("AUDIT",
		zap.String("event", eventType),
		zap.String("client_ip", clientIP),
		zap.String("device_id", deviceID),
		zap.String("details", details),
		zap.Time("timestamp", time.Now()),
	)
}

// AuditLogWithFields logs security-relevant events with additional fields
func AuditLogWithFields(eventType, clientIP, deviceID string, fields map[string]interface{}) {
	zapFields := []zap.Field{
		zap.String("event", eventType),
		zap.String("client_ip", clientIP),
		zap.String("device_id", deviceID),
		zap.Time("timestamp", time.Now()),
	}

	for k, v := range fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}

	logger.Info("AUDIT", zapFields...)
}

// rateLimiter implements a simple token bucket rate limiter per IP
type rateLimiter struct {
	mu       sync.RWMutex
	requests map[string]*tokenBucket
	rate     int           // requests per window
	window   time.Duration // time window
	stopCh   chan struct{} // channel to signal cleanup goroutine to stop
}

// tokenBucket tracks request counts for rate limiting
type tokenBucket struct {
	tokens    int
	lastReset time.Time
}

// the newRateLimiter creates a new rate limiter with a specified rate and window
func newRateLimiter(rate int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string]*tokenBucket),
		rate:     rate,
		window:   window,
	}
}

// Allow checks if a request from the given IP is allowed
func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.requests[ip]

	if !exists {
		// Check if we've reached the maximum number of entries to prevent memory exhaustion
		// If at max capacity, reject new IPs (they can retry after cleanup runs)
		if len(rl.requests) >= MaxRateLimiterEntries {
			logger.Warn("Rate limiter at max capacity, rejecting new IP",
				zap.String("ip", ip),
				zap.Int("current_entries", len(rl.requests)))
			return false
		}
		// Create a new bucket for this IP
		rl.requests[ip] = &tokenBucket{
			tokens:    rl.rate - 1, // Use one token
			lastReset: now,
		}
		return true
	}

	// Check if a window has passed, reset tokens
	if now.Sub(bucket.lastReset) >= rl.window {
		bucket.tokens = rl.rate - 1
		bucket.lastReset = now
		return true
	}

	// Check if tokens available
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

// StartCleanup starts a background goroutine that periodically removes stale IP entries
// to prevent memory leaks from accumulating IP addresses that no longer make requests
func (rl *rateLimiter) StartCleanup() {
	rl.stopCh = make(chan struct{})
	cleanupInterval := rl.window * 2 // Run cleanup at 2x the window interval

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				rl.cleanup()
			case <-rl.stopCh:
				return
			}
		}
	}()
}

// StopCleanup stops the background cleanup goroutine
func (rl *rateLimiter) StopCleanup() {
	if rl.stopCh != nil {
		close(rl.stopCh)
	}
}

// Cleanup removes stale entries from the rate limiter map
// Note: This is thread-safe as it uses the same mutex as Allow().
// The cleanup only removes entries older than 2x the window, so any entry
// accessed within the window will not be cleaned up (no TOCTOU issue).
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, bucket := range rl.requests {
		// Remove entries that haven't been accessed in 2x the window period
		if now.Sub(bucket.lastReset) >= rl.window*2 {
			delete(rl.requests, ip)
		}
	}
}

// apiKeyAuthMiddleware validates X-API-Key header for incoming requests
// Uses constant-time comparison to prevent timing attacks
// Implements brute force protection with per-IP lockout after max failed attempts
// Logs authentication events for security auditing
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP for logging and rate limiting
		clientIP := r.RemoteAddr
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			if parsedIP := net.ParseIP(realIP); parsedIP != nil {
				clientIP = realIP
			}
		}

		// Check if IP is blocked due to too many failed attempts
		if authTracker.isBlocked(clientIP) {
			remaining := authTracker.getRemainingLockout(clientIP)
			AuditLog(AuditEventAuthBlocked, clientIP, "", "IP temporarily blocked due to too many failed attempts")
			logger.Warn("Authentication blocked: IP temporarily banned",
				zap.String("ip", clientIP),
				zap.Duration("remaining", remaining))
			w.Header().Set("Retry-After", strconv.Itoa(int(remaining.Seconds())))
			sendError(w, http.StatusTooManyRequests, "Too Many Requests",
				"Too many failed authentication attempts. Please try again later.")
			return
		}

		// Get API key from the header
		apiKey := r.Header.Get(HeaderXAPIKey)

		// Check if an API key is provided
		if apiKey == "" {
			authTracker.recordFailure(clientIP)
			AuditLog(AuditEventAuthFailure, clientIP, "", "Missing API key")
			logger.Warn("Authentication failed: missing API key",
				zap.String("ip", clientIP),
				zap.String("method", r.Method))
			sendError(w, http.StatusUnauthorized, StatusUnauthorized, ErrMissingAPIKey)
			return
		}

		// Validate an API key using constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(authKey)) != 1 {
			authTracker.recordFailure(clientIP)
			AuditLog(AuditEventAuthFailure, clientIP, "", "Invalid API key")
			logger.Warn("Authentication failed: invalid API key",
				zap.String("ip", clientIP),
				zap.String("method", r.Method))
			sendError(w, http.StatusUnauthorized, StatusUnauthorized, ErrInvalidAPIKey)
			return
		}

		// API key is valid - clear any previous failed attempts and record success
		authTracker.recordSuccess(clientIP)
		AuditLog(AuditEventAuthSuccess, clientIP, "", "Authentication successful")

		// Proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware creates a middleware that limits requests per IP
func rateLimitMiddleware(rl *rateLimiter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP - use RemoteAddr as default
			ip := r.RemoteAddr

			// Only trust X-Real-IP if it contains a valid IP address
			// This prevents IP spoofing attacks to bypass rate limiting
			if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
				if parsedIP := net.ParseIP(realIP); parsedIP != nil {
					ip = realIP
				}
				// If X-Real-IP is invalid, fall back to RemoteAddr (don't trust spoofed header)
			}

			// Check rate limit
			if !rl.Allow(ip) {
				sendError(w, http.StatusTooManyRequests, "Too Many Requests", "Rate limit exceeded. Please try again later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// corsMiddleware handles Cross-Origin Resource Sharing (CORS) for the API.
// It reads allowed origins from the CORS_ALLOWED_ORIGINS environment variable (comma-separated).
// Use "*" to allow all origins (default), or specify specific origins.
// maxAge specifies how long preflight responses can be cached (in seconds).
func corsMiddleware(allowedOrigins []string, maxAge int) func(next http.Handler) http.Handler {
	// Check if wildcard is used (allow all origins)
	allowAll := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"

	// Build a map for fast origin lookup (only if not allowing all)
	originMap := make(map[string]bool)
	if !allowAll {
		for _, origin := range allowedOrigins {
			if origin != "" {
				originMap[origin] = true
			}
		}
	}

	// Pre-format max-age header value
	maxAgeStr := strconv.Itoa(maxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Set CORS headers if origin is present
			if origin != "" {
				if allowAll {
					// Allow all origins - use the requesting origin for proper credential handling
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
					w.Header().Set("Access-Control-Max-Age", maxAgeStr)
				} else if originMap[origin] {
					// Specific origin is allowed
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
					w.Header().Set("Access-Control-Max-Age", maxAgeStr)
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// securityHeadersMiddleware adds security headers to all responses
// to protect against common web vulnerabilities like XSS, clickjacking, etc.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTP Strict Transport Security (HSTS) - enforce HTTPS connections
		// max-age=31536000 (1 year), includeSubDomains for all subdomains
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking by denying iframe embedding
		w.Header().Set("X-Frame-Options", "DENY")
		// Enable XSS filter in browsers (legacy browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Referrer Policy - don't leak referrer information
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Permissions Policy - disable unnecessary browser features
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Content Security Policy - use relaxed CSP for Swagger UI, strict for API
		if strings.HasPrefix(r.URL.Path, "/swagger") {
			// Swagger UI needs inline styles/scripts and data URIs for images
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		} else {
			// Strict CSP for API endpoints
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}

		next.ServeHTTP(w, r)
	})
}
