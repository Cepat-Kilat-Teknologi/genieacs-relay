package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
