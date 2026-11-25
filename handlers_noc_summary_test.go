package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

func setupNOCTestRouter(t *testing.T, nbiHandler http.HandlerFunc, sharedKey, nocKey string) (*chi.Mux, func()) {
	t.Helper()
	origBase := geniesBaseURL
	origAuth := middlewareAuth
	origKey := authKey
	origNOCKey := nocMCPAPIKey
	origLogger := logger

	srv := httptest.NewServer(nbiHandler)
	geniesBaseURL = srv.URL
	middlewareAuth = true
	authKey = sharedKey
	nocMCPAPIKey = nocKey
	logger = zap.NewNop()
	deviceCacheInstance.clearAll()

	r := chi.NewRouter()
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(nocMCPAuthMiddleware)
			r.Get("/devices/{deviceID}/noc-summary", getDeviceNOCSummaryByIDHandler)
		})
		r.Group(func(r chi.Router) {
			r.Use(apiKeyAuthMiddleware)
			r.Get("/devices/search", searchDevicesHandler)
		})
	})

	cleanup := func() {
		srv.Close()
		geniesBaseURL = origBase
		middlewareAuth = origAuth
		authKey = origKey
		nocMCPAPIKey = origNOCKey
		logger = origLogger
		deviceCacheInstance.clearAll()
	}
	return r, cleanup
}

func TestNOCSummary_DedicatedAuthAndSingleTreeRead(t *testing.T) {
	var nbiCalls atomic.Int32
	nowStr := time.Now().UTC().Format(time.RFC3339)

	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		nbiCalls.Add(1)
		q := req.URL.Query().Get("query")
		if strings.Contains(q, "MISSING-ID") {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if strings.Contains(q, "TR181-ONLY") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"_id":         "00259E-TR181-ONLY",
					"_lastInform": nowStr,
					"Device": map[string]interface{}{
						"DeviceInfo": map[string]interface{}{
							"Manufacturer": map[string]interface{}{"_value": "Huawei"},
							"ModelName":    map[string]interface{}{"_value": "HG8145X6"},
							"SerialNumber": map[string]interface{}{"_value": "HWTR181"},
							"UpTime":       map[string]interface{}{"_value": 3600},
						},
					},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"_id":         "00259E-F609%2D1-1234",
				"_lastInform": nowStr,
				"InternetGatewayDevice": map[string]interface{}{
					"DeviceInfo": map[string]interface{}{
						"Manufacturer": map[string]interface{}{"_value": "ZTE"},
						"ModelName":    map[string]interface{}{"_value": "F609"},
						"SerialNumber": map[string]interface{}{"_value": "ZTEGC1234"},
						"UpTime":       map[string]interface{}{"_value": 86400},
					},
					"LANDevice": map[string]interface{}{
						"1": map[string]interface{}{
							"WLANConfiguration": map[string]interface{}{
								"1": map[string]interface{}{
									"SSID":          map[string]interface{}{"_value": "RumahBudi"},
									"PreSharedKey":  map[string]interface{}{"1": map[string]interface{}{"KeyPassphrase": map[string]interface{}{"_value": "SUPER-SECRET-WIFI"}}},
									"KeyPassphrase": map[string]interface{}{"_value": "SUPER-SECRET-WIFI"},
									"Channel":       map[string]interface{}{"_value": 6},
									"Standard":      map[string]interface{}{"_value": "b,g,n"},
									"AssociatedDevice": map[string]interface{}{
										"1": map[string]interface{}{"AssociatedDeviceMACAddress": map[string]interface{}{"_value": "AA:BB:CC:DD:EE:01"}},
										"2": map[string]interface{}{"AssociatedDeviceMACAddress": map[string]interface{}{"_value": "AA:BB:CC:DD:EE:02"}},
									},
								},
							},
						},
					},
				},
			},
		})
	}, "shared-gw-key", "dedicated-noc-key")
	defer cleanup()

	// 1. Shared gateway AUTH_KEY must be rejected (401).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-F609-1234/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "shared-gw-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for shared AUTH_KEY, got %d", w.Code)
	}

	// 2. Literal '%' in deviceID (sent as %252D) unescapes once without corruption,
	//    calls NBI once, and scrubs Wi-Fi passwords.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-F609%252D1-1234/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if nbiCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 NBI read, got %d", nbiCalls.Load())
	}
	if strings.Contains(w.Body.String(), "SUPER-SECRET-WIFI") || strings.Contains(w.Body.String(), "KeyPassphrase") {
		t.Fatalf("Wi-Fi password leaked in response: %s", w.Body.String())
	}
	var env struct {
		Data NOCSummaryResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.DeviceID != "00259E-F609%2D1-1234" {
		t.Fatalf("expected preserved literal percent deviceID, got %q", env.Data.DeviceID)
	}
	if env.Data.UptimeSeconds == nil || *env.Data.UptimeSeconds != 86400 {
		t.Fatalf("expected uptime_seconds=86400, got %v", env.Data.UptimeSeconds)
	}
	if env.Data.ConnectedHosts == nil || *env.Data.ConnectedHosts != 2 {
		t.Fatalf("expected connected_hosts=2, got %v", env.Data.ConnectedHosts)
	}
	if len(env.Data.Radios) != 1 || env.Data.Radios[0].ClientCount != 2 {
		t.Fatalf("unexpected radios: %+v", env.Data.Radios)
	}

	// 3. TR-181-only tree preserves nil (null) connected_hosts & radios instead of 0.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-TR181-ONLY/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for TR-181, got %d", w.Code)
	}
	var env181 struct {
		Data NOCSummaryResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env181); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env181.Data.ConnectedHosts != nil || env181.Data.Radios != nil {
		t.Fatalf("expected nil WLAN metrics on TR-181-only device, got hosts=%v radios=%v", env181.Data.ConnectedHosts, env181.Data.Radios)
	}

	// 4. Missing device returns 404 (not 500).
	req = httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/MISSING-ID/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing device, got %d", w.Code)
	}

	// 5. Invalid deviceID ($ operator or ..) returns 400.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/bad$ne/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid deviceID, got %d", w.Code)
	}
}

func TestExactSerialSearch_CollisionAndTR181(t *testing.T) {
	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query().Get("query")
		if strings.Contains(q, `"_id"`) {
			t.Errorf("exact=true must NOT query _id: %s", q)
		}
		if !strings.Contains(q, `"$options":"i"`) || !strings.Contains(q, `"^`) {
			t.Errorf("exact=true must use anchored case-insensitive match: %s", q)
		}
		if strings.Contains(q, "COLLIDE") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"_id": "OUI-A-COLLIDE", "Device": map[string]interface{}{"DeviceInfo": map[string]interface{}{"SerialNumber": map[string]interface{}{"_value": "COLLIDE"}}}},
				{"_id": "OUI-B-COLLIDE", "Device": map[string]interface{}{"DeviceInfo": map[string]interface{}{"SerialNumber": map[string]interface{}{"_value": "COLLIDE"}}}},
			})
			return
		}
		if strings.Contains(q, "HW181") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"_id": "OUI-HG-HW181", "Device": map[string]interface{}{"DeviceInfo": map[string]interface{}{
					"Manufacturer": map[string]interface{}{"_value": "Huawei"},
					"ModelName":    map[string]interface{}{"_value": "HG8145X6"},
					"SerialNumber": map[string]interface{}{"_value": "HW181"},
				}}},
			})
			return
		}
		if strings.Contains(q, "MISMATCH") {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"_id": "OUI-X-OTHER", "InternetGatewayDevice": map[string]interface{}{"DeviceInfo": map[string]interface{}{"SerialNumber": map[string]interface{}{"_value": "OTHERSERIAL"}}}},
			})
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}, "shared-gw-key", "dedicated-noc-key")
	defer cleanup()

	// Colliding serial returns 409 Conflict.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/search?serial=COLLIDE&exact=true", nil)
	req.Header.Set(HeaderXAPIKey, "shared-gw-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 on serial collision, got %d: %s", w.Code, w.Body.String())
	}

	// TR-181 exact match returns 200 with decoded serial.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/search?serial=HW181&exact=true", nil)
	req.Header.Set(HeaderXAPIKey, "shared-gw-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on TR-181 exact serial, got %d: %s", w.Code, w.Body.String())
	}
	var env struct {
		Data DeviceSearchResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.Device.Manufacturer != "Huawei" || env.Data.Device.Model != "HG8145X6" {
		t.Fatalf("expected TR-181 manufacturer and model, got %+v", env.Data.Device)
	}

	// A row whose serial is not the requested one is not an exact match.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/search?serial=MISMATCH&exact=true", nil)
	req.Header.Set(HeaderXAPIKey, "shared-gw-key")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when the returned serial differs, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNOCSummary_EmptyKeyFailsClosed(t *testing.T) {
	var nbiCalls atomic.Int32
	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		nbiCalls.Add(1)
		_, _ = w.Write([]byte(`[]`))
	}, "shared-gw-key", "")
	defer cleanup()

	for _, key := range []string{"", "shared-gw-key"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-F609-1234/noc-summary", nil)
		if key != "" {
			req.Header.Set(HeaderXAPIKey, key)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("key %q: expected 503 with NOC_MCP_API_KEY unset, got %d", key, w.Code)
		}
	}
	if nbiCalls.Load() != 0 {
		t.Fatalf("expected no NBI read without NOC_MCP_API_KEY, got %d", nbiCalls.Load())
	}
}

func TestNOCSummary_DeviceIDDecoding(t *testing.T) {
	var lastQuery atomic.Value
	var nbiCalls atomic.Int32
	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		nbiCalls.Add(1)
		lastQuery.Store(req.URL.Query().Get("query"))
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"_id": "00259E-F609/1-1234"}})
	}, "shared-gw-key", "dedicated-noc-key")
	defer cleanup()

	send := func(req *http.Request) *httptest.ResponseRecorder {
		req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// An encoded '/' keeps RawPath set; the ID is unescaped exactly once.
	w := send(httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-F609%2F1-1234/noc-summary", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for an encoded slash, got %d: %s", w.Code, w.Body.String())
	}
	if q, _ := lastQuery.Load().(string); !strings.Contains(q, `"00259E-F609/1-1234"`) {
		t.Fatalf("expected the decoded ID in the NBI query, got %s", q)
	}
	if !strings.Contains(w.Body.String(), `"device_id":"00259E-F609/1-1234"`) {
		t.Fatalf("expected the decoded device_id, got %s", w.Body.String())
	}

	nbiCalls.Store(0)
	badEscape := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/placeholder/noc-summary", nil)
	badEscape.URL.RawPath = "/api/v1/genieacs/devices/bad%zz/noc-summary"
	rejected := map[string]*http.Request{
		"invalid escape": badEscape,
		"too long":       httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/"+strings.Repeat("A", 129)+"/noc-summary", nil),
		"control char":   httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/bad%01id/noc-summary", nil),
		"DEL char":       httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/bad%7Fid/noc-summary", nil),
		"dot segment":    httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/a..b/noc-summary", nil),
	}
	for name, req := range rejected {
		if w := send(req); w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", name, w.Code, w.Body.String())
		}
	}
	if nbiCalls.Load() != 0 {
		t.Fatalf("expected no NBI read for rejected IDs, got %d", nbiCalls.Load())
	}
}

func TestNOCSummary_NBIFailureIs500(t *testing.T) {
	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, "shared-gw-key", "dedicated-noc-key")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-F609-1234/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), ErrCodeGenieACS) {
		t.Fatalf("expected 500 %s when NBI fails, got %d: %s", ErrCodeGenieACS, w.Code, w.Body.String())
	}
}

func TestNOCSummary_EmptyWLANTableReportsZero(t *testing.T) {
	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
			"_id": "00259E-EMPTY-WLAN",
			"InternetGatewayDevice": map[string]interface{}{
				"LANDevice": map[string]interface{}{
					"1": map[string]interface{}{
						"WLANConfiguration": map[string]interface{}{"_object": true, "_writable": false},
					},
				},
			},
		}})
	}, "shared-gw-key", "dedicated-noc-key")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-EMPTY-WLAN/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"connected_hosts":0`) || !strings.Contains(body, `"radios":[]`) {
		t.Fatalf("expected connected_hosts=0 and radios=[] for an observed empty WLAN table, got %s", body)
	}
}

func TestDevicesSearch_OversizedNBIBodyFails(t *testing.T) {
	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`[{"_id":"`))
		_, _ = w.Write([]byte(strings.Repeat("A", MaxResponseBodySize+1)))
		_, _ = w.Write([]byte(`"}]`))
	}, "shared-gw-key", "dedicated-noc-key")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/search?serial=ZTEGC1234&exact=true", nil)
	req.Header.Set(HeaderXAPIKey, "shared-gw-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for an NBI body over MaxResponseBodySize, got %d", w.Code)
	}
}

func TestNOCSummary_BypassesSharedDeviceCache(t *testing.T) {
	var nbiCalls atomic.Int32
	r, cleanup := setupNOCTestRouter(t, func(w http.ResponseWriter, req *http.Request) {
		nbiCalls.Add(1)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{
			"_id": "00259E-MOVED-1",
			"InternetGatewayDevice": map[string]interface{}{
				"DeviceInfo": map[string]interface{}{"ModelName": map[string]interface{}{"_value": "FRESH"}},
			},
		}})
	}, "shared-gw-key", "dedicated-noc-key")
	defer cleanup()

	// A tree cached by another route while the CPE served a different installation.
	deviceCacheInstance.set("00259E-MOVED-1", map[string]interface{}{
		"_id": "00259E-MOVED-1",
		"InternetGatewayDevice": map[string]interface{}{
			"DeviceInfo": map[string]interface{}{"ModelName": map[string]interface{}{"_value": "STALE"}},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/genieacs/devices/00259E-MOVED-1/noc-summary", nil)
	req.Header.Set(HeaderXAPIKey, "dedicated-noc-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if nbiCalls.Load() != 1 || strings.Contains(w.Body.String(), "STALE") || !strings.Contains(w.Body.String(), "FRESH") {
		t.Fatalf("noc-summary must read the device fresh from NBI, calls=%d body=%s", nbiCalls.Load(), w.Body.String())
	}
}
