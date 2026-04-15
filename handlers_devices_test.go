package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handlers_devices_test.go covers M4 (listDevicesHandler) and
// M5 (searchDevicesHandler) plus their pure helper functions.

// --- buildDevicesListFilter ---

func TestBuildDevicesListFilter_Empty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices", nil)
	filter := buildDevicesListFilter(r)
	assert.Empty(t, filter)
}

func TestBuildDevicesListFilter_Model(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices?model=F670L", nil)
	filter := buildDevicesListFilter(r)
	require.Contains(t, filter, "InternetGatewayDevice.DeviceInfo.ModelName._value")
	clause := filter["InternetGatewayDevice.DeviceInfo.ModelName._value"].(map[string]interface{})
	assert.Equal(t, "F670L", clause["$regex"])
}

func TestBuildDevicesListFilter_PPPoEUsername(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices?pppoe_username=cust-001", nil)
	filter := buildDevicesListFilter(r)
	require.Contains(t, filter,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username._value")
}

func TestBuildDevicesListFilter_OnlineWithStaleThreshold(t *testing.T) {
	original := staleThreshold
	staleThreshold = 600 * 1000 * 1000 * 1000 // 10 minutes in ns
	t.Cleanup(func() { staleThreshold = original })

	r := httptest.NewRequest(http.MethodGet, "/devices?online=true", nil)
	filter := buildDevicesListFilter(r)
	require.Contains(t, filter, "_lastInform")
}

func TestBuildDevicesListFilter_OnlineNoThreshold(t *testing.T) {
	original := staleThreshold
	staleThreshold = 0
	t.Cleanup(func() { staleThreshold = original })

	r := httptest.NewRequest(http.MethodGet, "/devices?online=true", nil)
	filter := buildDevicesListFilter(r)
	assert.NotContains(t, filter, "_lastInform")
}

func TestBuildDevicesListFilter_AllFilters(t *testing.T) {
	original := staleThreshold
	staleThreshold = 600 * 1000 * 1000 * 1000
	t.Cleanup(func() { staleThreshold = original })

	r := httptest.NewRequest(http.MethodGet,
		"/devices?model=F670L&pppoe_username=cust&online=true", nil)
	filter := buildDevicesListFilter(r)
	assert.Len(t, filter, 3)
}

// --- parseDevicesPagination ---

func TestParseDevicesPagination_Defaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices", nil)
	rr := httptest.NewRecorder()
	page, pageSize, ok := parseDevicesPagination(rr, r)
	assert.True(t, ok)
	assert.Equal(t, 1, page)
	assert.Equal(t, DefaultDevicesPageSize, pageSize)
}

func TestParseDevicesPagination_Explicit(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices?page=3&page_size=20", nil)
	rr := httptest.NewRecorder()
	page, pageSize, ok := parseDevicesPagination(rr, r)
	assert.True(t, ok)
	assert.Equal(t, 3, page)
	assert.Equal(t, 20, pageSize)
}

func TestParseDevicesPagination_BadPage(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices?page=0", nil)
	rr := httptest.NewRecorder()
	_, _, ok := parseDevicesPagination(rr, r)
	assert.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestParseDevicesPagination_NonNumericPage(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices?page=abc", nil)
	rr := httptest.NewRecorder()
	_, _, ok := parseDevicesPagination(rr, r)
	assert.False(t, ok)
}

func TestParseDevicesPagination_BadPageSize(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices?page_size=999", nil)
	rr := httptest.NewRecorder()
	_, _, ok := parseDevicesPagination(rr, r)
	assert.False(t, ok)
}

func TestParseDevicesPagination_NonNumericPageSize(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/devices?page_size=xyz", nil)
	rr := httptest.NewRecorder()
	_, _, ok := parseDevicesPagination(rr, r)
	assert.False(t, ok)
}

// --- buildDevicesSearchFilter ---

func TestBuildDevicesSearchFilter_MAC(t *testing.T) {
	filter := buildDevicesSearchFilter("AA:BB:CC:DD:EE:FF", "", "")
	assert.Equal(t, "AA:BB:CC:DD:EE:FF",
		filter["InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress._value"])
}

func TestBuildDevicesSearchFilter_Serial(t *testing.T) {
	filter := buildDevicesSearchFilter("", "ZTEGCFLN12345678", "")
	assert.Equal(t, "ZTEGCFLN12345678",
		filter["InternetGatewayDevice.DeviceInfo.SerialNumber._value"])
}

func TestBuildDevicesSearchFilter_PPPoE(t *testing.T) {
	filter := buildDevicesSearchFilter("", "", "cust-001")
	assert.Equal(t, "cust-001",
		filter["InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username._value"])
}

func TestBuildDevicesSearchFilter_Precedence(t *testing.T) {
	// MAC wins when all 3 are provided
	filter := buildDevicesSearchFilter("AA", "BB", "CC")
	assert.Len(t, filter, 1)
	assert.Contains(t, filter, "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress._value")
}

// --- deviceSummaryFromTree ---

func TestDeviceSummaryFromTree_Full(t *testing.T) {
	doc := map[string]interface{}{
		"_id":         "device-001",
		"_lastInform": "2026-04-14T11:35:21Z",
		"InternetGatewayDevice": map[string]interface{}{
			"DeviceInfo": map[string]interface{}{
				"Manufacturer": map[string]interface{}{"_value": "ZTE"},
				"ModelName":    map[string]interface{}{"_value": "F670L"},
				"SerialNumber": map[string]interface{}{"_value": "SN-12345"},
			},
			"WANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WANConnectionDevice": map[string]interface{}{
						"1": map[string]interface{}{
							"WANPPPConnection": map[string]interface{}{
								"1": map[string]interface{}{
									"ExternalIPAddress": map[string]interface{}{"_value": "203.0.113.45"},
								},
							},
						},
					},
				},
			},
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"LANEthernetInterfaceConfig": map[string]interface{}{
						"1": map[string]interface{}{
							"MACAddress": map[string]interface{}{"_value": "AA:BB:CC:DD:EE:FF"},
						},
					},
				},
			},
		},
	}
	d := deviceSummaryFromTree(doc)
	assert.Equal(t, "device-001", d.DeviceID)
	assert.Equal(t, "2026-04-14T11:35:21Z", d.LastInform)
	assert.Equal(t, "ZTE", d.Manufacturer)
	assert.Equal(t, "F670L", d.Model)
	assert.Equal(t, "SN-12345", d.Serial)
	assert.Equal(t, "203.0.113.45", d.IP)
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", d.MAC)
}

func TestDeviceSummaryFromTree_Empty(t *testing.T) {
	d := deviceSummaryFromTree(map[string]interface{}{})
	assert.Empty(t, d.DeviceID)
}

func TestDeviceSummaryFromTree_MalformedID(t *testing.T) {
	// _id not a string → should be skipped without panicking
	d := deviceSummaryFromTree(map[string]interface{}{
		"_id":         float64(123),
		"_lastInform": float64(456),
	})
	assert.Empty(t, d.DeviceID)
	assert.Empty(t, d.LastInform)
}

// --- listDevicesHandler ---

// devicesMockHandler handles the GenieACS devices NBI query for
// list/search tests. Returns the supplied devices array.
func devicesMockHandler(devices []map[string]interface{}, status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/devices/") && r.URL.Path != "/devices/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if status >= 400 {
			return
		}
		body, _ := json.Marshal(devices)
		_, _ = w.Write(body)
	}
}

func TestListDevicesHandler_Success(t *testing.T) {
	devices := []map[string]interface{}{
		{
			"_id":         "device-001",
			"_lastInform": "2026-04-14T11:00:00Z",
		},
		{
			"_id":         "device-002",
			"_lastInform": "2026-04-14T11:01:00Z",
		},
	}
	_, router := setupTestServer(t, devicesMockHandler(devices, http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices?page=1&page_size=10", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "device-001")
	assert.Contains(t, rr.Body.String(), "device-002")
}

func TestListDevicesHandler_BadPage(t *testing.T) {
	_, router := setupTestServer(t, devicesMockHandler(nil, http.StatusOK))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices?page=0", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestListDevicesHandler_NBIError(t *testing.T) {
	_, router := setupTestServer(t, devicesMockHandler(nil, http.StatusInternalServerError))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- searchDevicesHandler ---

func TestSearchDevicesHandler_ByMAC(t *testing.T) {
	devices := []map[string]interface{}{
		{"_id": "device-001"},
	}
	_, router := setupTestServer(t, devicesMockHandler(devices, http.StatusOK))

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/devices/search?mac=AA:BB:CC:DD:EE:FF", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "device-001")
}

func TestSearchDevicesHandler_ByPPPoE(t *testing.T) {
	devices := []map[string]interface{}{
		{"_id": "device-002"},
	}
	_, router := setupTestServer(t, devicesMockHandler(devices, http.StatusOK))

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/devices/search?pppoe_username=cust-001", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestSearchDevicesHandler_NoKey(t *testing.T) {
	_, router := setupTestServer(t, devicesMockHandler(nil, http.StatusOK))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/search", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "mac, serial")
}

func TestSearchDevicesHandler_NotFound(t *testing.T) {
	_, router := setupTestServer(t, devicesMockHandler(nil, http.StatusOK))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/devices/search?mac=AA:BB:CC:DD:EE:FF", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSearchDevicesHandler_NBIError(t *testing.T) {
	_, router := setupTestServer(t, devicesMockHandler(nil, http.StatusInternalServerError))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/genieacs/devices/search?mac=AA:BB:CC:DD:EE:FF", nil)
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- queryDevicesNBI direct error paths (transport / decode failures) ---

func TestQueryDevicesNBI_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })

	_, err := queryDevicesNBI(context.Background(), nil, 10, 0)
	assert.Error(t, err)
}

func TestQueryDevicesNBI_BadJSON(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not-json`))
	})
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)
	originalBase := geniesBaseURL
	originalClient := httpClient
	geniesBaseURL = srv.URL
	httpClient = srv.Client()
	t.Cleanup(func() {
		geniesBaseURL = originalBase
		httpClient = originalClient
	})

	_, err := queryDevicesNBI(context.Background(), nil, 10, 0)
	assert.Error(t, err)
}

func TestQueryDevicesNBI_BodyReadError(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &errorBodyTransport{statusCode: http.StatusOK}}
	t.Cleanup(func() { httpClient = originalClient })

	_, err := queryDevicesNBI(context.Background(), nil, 10, 0)
	assert.Error(t, err)
}

func TestQueryDevicesNBI_NewRequestFailure(t *testing.T) {
	// geniesBaseURL with a control character makes NewRequestWithContext fail
	// before the call ever leaves the helper.
	originalBase := geniesBaseURL
	geniesBaseURL = "http://example.com/\x7f"
	t.Cleanup(func() { geniesBaseURL = originalBase })

	_, err := queryDevicesNBI(context.Background(), nil, 10, 0)
	assert.Error(t, err)
}
