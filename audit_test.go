package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
