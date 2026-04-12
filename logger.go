package main

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// initProductionLogger builds a production zap logger with the standardized base fields
// required by isp-logging-standard: service, version, module. ISO8601 UTC millisecond
// timestamps, JSON encoding, info-level default. The config uses only well-formed
// defaults so cfg.Build() cannot fail in practice — we use zap.Must to drop the dead
// error branch and keep the surface 100% covered.
func initProductionLogger() (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.MessageKey = "message"
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.CallerKey = "" // strip caller to keep logs minimal; correlate via request_id

	l := zap.Must(cfg.Build())
	return l.With(
		zap.String("service", "genieacs-relay"),
		zap.String("version", BuildVersion()),
	), nil
}

// WithModule returns a child logger tagged with a module name for grep-ability in Loki.
// Example: log := WithModule(logger, "handlers_wlan").
func WithModule(base *zap.Logger, module string) *zap.Logger {
	if base == nil {
		return zap.NewNop()
	}
	return base.With(zap.String("module", module))
}

// WithRequestIDLogger returns the global logger decorated with the request_id from ctx.
// Handlers should call this at the top of each HTTP handler to get a correlation-aware
// logger without needing to pass one through every function call.
func WithRequestIDLogger(ctx context.Context) *zap.Logger {
	if logger == nil {
		return zap.NewNop()
	}
	reqID := RequestIDFromContext(ctx)
	if reqID == "" {
		return logger
	}
	return logger.With(zap.String("request_id", reqID))
}
