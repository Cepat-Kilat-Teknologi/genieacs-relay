package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
