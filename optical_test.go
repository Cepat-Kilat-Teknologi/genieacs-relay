package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- optical fixture-based unit tests ---
//
// We don't have a real CPE in the dev lab to test against, so the
// strategy here is to build realistic GenieACS device-tree fixtures
// matching real production samples for each vendor (ZTE CT-COM EPON +
// GPON, Huawei HW_DEBUG, Realtek EPON, standard TR-181) and assert the
// extractor + classifier produce the expected output.
//
// These fixtures are based on actual `curl
// http://genieacs:7557/devices/?query=...` responses from production
// deployments — preserve verbatim if updating.

// fixtureZTECTComEpon is a minimal device tree containing the ZTE
// CT-COM EPON optical stats subtree. Real responses have hundreds of
// other parameters; we keep only what's relevant to optical extraction.
func fixtureZTECTComEpon() map[string]interface{} {
	return map[string]interface{}{
		"_id": "001141-F670L-ZTEGCFLN794B3A1",
		"InternetGatewayDevice": map[string]interface{}{
			"X_CT-COM_EponInterfaceConfig": map[string]interface{}{
				"Stats": map[string]interface{}{
					"TxPower": map[string]interface{}{
						"_value":     2.5,
						"_type":      "xsd:float",
						"_timestamp": "2026-04-14T13:00:00.000Z",
					},
					"RxPower": map[string]interface{}{
						"_value":     -21.3,
						"_type":      "xsd:float",
						"_timestamp": "2026-04-14T13:00:00.000Z",
					},
					"Temperature": map[string]interface{}{
						"_value":     45.0,
						"_type":      "xsd:float",
						"_timestamp": "2026-04-14T13:00:00.000Z",
					},
					"Voltage": map[string]interface{}{
						"_value":     3.3,
						"_type":      "xsd:float",
						"_timestamp": "2026-04-14T13:00:00.000Z",
					},
					"BiasCurrent": map[string]interface{}{
						"_value":     12.5,
						"_type":      "xsd:float",
						"_timestamp": "2026-04-14T13:00:00.000Z",
					},
				},
			},
		},
	}
}

// fixtureZTECTComGpon is the GPON variant — same shape as EPON but
// under X_CT-COM_GponInterfaceConfig. Real ZTE F670L can be configured
// for either EPON or GPON depending on ISP infrastructure.
func fixtureZTECTComGpon() map[string]interface{} {
	return map[string]interface{}{
		"_id": "001141-F670L-ZTEGCFLN794B3A1",
		"InternetGatewayDevice": map[string]interface{}{
			"X_CT-COM_GponInterfaceConfig": map[string]interface{}{
				"Stats": map[string]interface{}{
					"TxPower":     map[string]interface{}{"_value": 1.8},
					"RxPower":     map[string]interface{}{"_value": -19.7},
					"Temperature": map[string]interface{}{"_value": 47.5},
					"Voltage":     map[string]interface{}{"_value": 3.31},
					"BiasCurrent": map[string]interface{}{"_value": 11.2},
				},
			},
		},
	}
}

// fixtureHuaweiHWDebug is the Huawei HG-series tree. Note: Huawei
// typically only exposes TxPower and RxPower in HW_DEBUG, not the full
// optical health quintet.
func fixtureHuaweiHWDebug() map[string]interface{} {
	return map[string]interface{}{
		"_id": "00E0FC-HG8245H-AB12CD",
		"InternetGatewayDevice": map[string]interface{}{
			"X_HW_DEBUG": map[string]interface{}{
				"AdminTR069": map[string]interface{}{
					"TxPower": map[string]interface{}{"_value": 2.1},
					"RxPower": map[string]interface{}{"_value": -22.5},
				},
			},
		},
	}
}

// fixtureRealtekEpon is a Realtek/PMC OEM tree. Used by various noname
// ONTs that bundle the Realtek RTL96xx chipset.
func fixtureRealtekEpon() map[string]interface{} {
	return map[string]interface{}{
		"_id": "0019AA-OEMEPON-12345",
		"InternetGatewayDevice": map[string]interface{}{
			"X_Realtek_EponInterfaceConfig": map[string]interface{}{
				"Stats": map[string]interface{}{
					"TxPower":     map[string]interface{}{"_value": 0.5},
					"RxPower":     map[string]interface{}{"_value": -25.8},
					"Temperature": map[string]interface{}{"_value": 52.0},
					"Voltage":     map[string]interface{}{"_value": 3.28},
					"BiasCurrent": map[string]interface{}{"_value": 14.7},
				},
			},
		},
	}
}

// fixtureStandardTR181 is the standard Broadband Forum TR-181
// Device.Optical.Interface tree. Rare in consumer CPE but seen in some
// enterprise gateways.
func fixtureStandardTR181() map[string]interface{} {
	return map[string]interface{}{
		"_id": "BIZGW-001-XYZ",
		"Device": map[string]interface{}{
			"Optical": map[string]interface{}{
				"Interface": map[string]interface{}{
					"1": map[string]interface{}{
						"Stats": map[string]interface{}{
							"TxPower":     map[string]interface{}{"_value": 3.2},
							"RxPower":     map[string]interface{}{"_value": -18.1},
							"Temperature": map[string]interface{}{"_value": 41.0},
							"Voltage":     map[string]interface{}{"_value": 3.32},
							"BiasCurrent": map[string]interface{}{"_value": 9.8},
						},
					},
				},
			},
		},
	}
}

// fixtureDualBandWLANOnly is a device that has WLAN data but NO
// optical tree at all. Used to test the not-supported path.
func fixtureNoOpticalTree() map[string]interface{} {
	return map[string]interface{}{
		"_id": "WIFIONLY-001-XYZ",
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{},
					},
				},
			},
		},
	}
}

// stubGenieACSWithDeviceData returns an httptest.Server that responds
// to GET /devices/ with a JSON array containing the given device data.
// Use this to drive getDeviceData → getOpticalStats end-to-end without
// needing a real GenieACS instance.
func stubGenieACSWithDeviceData(t *testing.T, deviceData map[string]interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{deviceData})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// resetCacheForTest clears the device cache to avoid cross-test pollution.
// The cache is a package singleton so tests must clear before/after each
// run that exercises getDeviceData.
func resetCacheForTest(t *testing.T) {
	t.Helper()
	deviceCacheInstance.clear(mockDeviceID)
}

// --- getOpticalStats integration tests via httptest stub ---

func TestGetOpticalStats_ZTECTComEpon(t *testing.T) {
	resetCacheForTest(t)
	srv := stubGenieACSWithDeviceData(t, fixtureZTECTComEpon())
	geniesBaseURL = srv.URL

	stats, err := getOpticalStats(context.Background(), mockDeviceID)
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, opticalSourceZTECTComEpon, stats.Source)
	assert.InDelta(t, 2.5, stats.TxPowerDBm, 0.001)
	assert.InDelta(t, -21.3, stats.RxPowerDBm, 0.001)
	assert.InDelta(t, 45.0, stats.TemperatureC, 0.001)
	assert.InDelta(t, 3.3, stats.VoltageV, 0.001)
	assert.InDelta(t, 12.5, stats.BiasCurrentMA, 0.001)
	// -21.3 dBm is in the "good" range (-24 < rx < -8 with overload >= -8)
	assert.Equal(t, "good", stats.Health)
	assert.NotEmpty(t, stats.FetchedAt)
}

func TestGetOpticalStats_ZTECTComGpon(t *testing.T) {
	resetCacheForTest(t)
	srv := stubGenieACSWithDeviceData(t, fixtureZTECTComGpon())
	geniesBaseURL = srv.URL

	stats, err := getOpticalStats(context.Background(), mockDeviceID)
	require.NoError(t, err)
	assert.Equal(t, opticalSourceZTECTComGpon, stats.Source)
	assert.InDelta(t, 1.8, stats.TxPowerDBm, 0.001)
	assert.InDelta(t, -19.7, stats.RxPowerDBm, 0.001)
	assert.Equal(t, "good", stats.Health)
}

func TestGetOpticalStats_HuaweiHWDebug(t *testing.T) {
	resetCacheForTest(t)
	srv := stubGenieACSWithDeviceData(t, fixtureHuaweiHWDebug())
	geniesBaseURL = srv.URL

	stats, err := getOpticalStats(context.Background(), mockDeviceID)
	require.NoError(t, err)
	assert.Equal(t, opticalSourceHuaweiHWDbg, stats.Source)
	assert.InDelta(t, 2.1, stats.TxPowerDBm, 0.001)
	assert.InDelta(t, -22.5, stats.RxPowerDBm, 0.001)
	// Huawei HW_DEBUG doesn't expose temp/voltage/bias — they should be 0.
	assert.Equal(t, 0.0, stats.TemperatureC)
	assert.Equal(t, 0.0, stats.VoltageV)
	assert.Equal(t, 0.0, stats.BiasCurrentMA)
	assert.Equal(t, "good", stats.Health)
}

func TestGetOpticalStats_RealtekEpon(t *testing.T) {
	resetCacheForTest(t)
	srv := stubGenieACSWithDeviceData(t, fixtureRealtekEpon())
	geniesBaseURL = srv.URL

	stats, err := getOpticalStats(context.Background(), mockDeviceID)
	require.NoError(t, err)
	assert.Equal(t, opticalSourceRealtekEpon, stats.Source)
	assert.InDelta(t, -25.8, stats.RxPowerDBm, 0.001)
	// -25.8 dBm is in the "warning" range (-27 < rx <= -24).
	assert.Equal(t, "warning", stats.Health)
}

func TestGetOpticalStats_StandardTR181(t *testing.T) {
	resetCacheForTest(t)
	srv := stubGenieACSWithDeviceData(t, fixtureStandardTR181())
	geniesBaseURL = srv.URL

	stats, err := getOpticalStats(context.Background(), mockDeviceID)
	require.NoError(t, err)
	assert.Equal(t, opticalSourceStandardTR181, stats.Source)
	assert.InDelta(t, -18.1, stats.RxPowerDBm, 0.001)
	assert.Equal(t, "good", stats.Health)
}

func TestGetOpticalStats_NotSupported(t *testing.T) {
	resetCacheForTest(t)
	srv := stubGenieACSWithDeviceData(t, fixtureNoOpticalTree())
	geniesBaseURL = srv.URL

	stats, err := getOpticalStats(context.Background(), mockDeviceID)
	assert.Nil(t, stats)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errOpticalNotSupported), "expected errOpticalNotSupported sentinel")
}

// --- classifyOpticalHealth pure unit tests ---
//
// These don't touch the network or cache — pure logic on the
// thresholds. Thresholds are package vars defaulted from constants
// (opticalRxNoSignalDBm = -30, opticalRxCriticalDBm = -27,
// opticalRxWarningDBm = -24, opticalRxOverloadDBm = -8). Tests use
// the defaults; per-deployment env tuning is exercised separately.

func TestClassifyOpticalHealth(t *testing.T) {
	cases := []struct {
		name       string
		rxPowerDBm float64
		want       string
	}{
		{"good_strong_signal", -10.0, "good"},     // -24 < -10 < -8
		{"good_normal_pon", -20.0, "good"},        // -24 < -20 < -8
		{"good_lower_normal", -23.5, "good"},      // -24 < -23.5 < -8
		{"warning_attenuated", -25.0, "warning"},  // -27 < -25 <= -24
		{"warning_marginal_top", -24.1, "warning"}, // -27 < -24.1 <= -24
		{"critical_low_signal", -28.0, "critical"}, // -30 < -28 <= -27
		{"critical_marginal_top", -27.0, "critical"}, // -30 < -27 <= -27
		{"no_signal_dark_fiber", -35.0, "no_signal"}, // -35 <= -30
		{"no_signal_threshold", -30.0, "no_signal"},  // -30 <= -30
		{"warning_overload_close_to_olt", -7.5, "warning"}, // -7.5 >= -8
		{"unknown_zero_value_unset_field", 0.0, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stats := &OpticalStats{RxPowerDBm: tc.rxPowerDBm}
			classifyOpticalHealth(stats)
			assert.Equal(t, tc.want, stats.Health)
		})
	}
}

// --- navigateNested + readFloat helper unit tests ---

func TestNavigateNested_HappyPath(t *testing.T) {
	root := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": "leaf",
			},
		},
	}
	leaf := navigateNested(root, "a", "b")
	require.NotNil(t, leaf)
	assert.Equal(t, "leaf", leaf["c"])
}

func TestNavigateNested_MissingKey(t *testing.T) {
	root := map[string]interface{}{
		"a": map[string]interface{}{},
	}
	leaf := navigateNested(root, "a", "missing", "deeper")
	assert.Nil(t, leaf)
}

func TestNavigateNested_WrongType(t *testing.T) {
	root := map[string]interface{}{
		"a": "not a map",
	}
	leaf := navigateNested(root, "a", "b")
	assert.Nil(t, leaf)
}

func TestReadFloat_Float64Value(t *testing.T) {
	parent := map[string]interface{}{
		"TxPower": map[string]interface{}{"_value": 2.5},
	}
	assert.InDelta(t, 2.5, readFloat(parent, "TxPower"), 0.001)
}

func TestReadFloat_IntValue(t *testing.T) {
	parent := map[string]interface{}{
		"Temperature": map[string]interface{}{"_value": 45},
	}
	assert.InDelta(t, 45.0, readFloat(parent, "Temperature"), 0.001)
}

func TestReadFloat_MissingKey(t *testing.T) {
	parent := map[string]interface{}{}
	assert.Equal(t, 0.0, readFloat(parent, "Missing"))
}

func TestReadFloat_WrongValueType(t *testing.T) {
	parent := map[string]interface{}{
		"BadField": map[string]interface{}{"_value": "string-not-float"},
	}
	assert.Equal(t, 0.0, readFloat(parent, "BadField"))
}

// --- refreshOpticalStats integration test ---
//
// The function tries every known vendor subtree in sequence. We assert
// the success-count logic: as long as at least one subtree returns a
// non-error status, the overall call succeeds.

func TestRefreshOpticalStats_AllSubtreesAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	geniesBaseURL = srv.URL

	err := refreshOpticalStats(context.Background(), mockDeviceID)
	assert.NoError(t, err)
}

func TestRefreshOpticalStats_AllSubtreesFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	geniesBaseURL = srv.URL

	err := refreshOpticalStats(context.Background(), mockDeviceID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all known subtrees")
}

func TestRefreshOpticalStats_PartialSuccess(t *testing.T) {
	// First call succeeds, rest 404. Should still succeed overall.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	geniesBaseURL = srv.URL

	err := refreshOpticalStats(context.Background(), mockDeviceID)
	assert.NoError(t, err)
	assert.Equal(t, len(opticalSubtreePathsToRefresh), callCount, "all subtrees should be tried even on partial failure")
}

// --- v2.1.0 coverage closure tests ---

func TestReadFloat_Int64Value(t *testing.T) {
	// The int64 branch fires when GenieACS serializes an integer
	// parameter as int64 (e.g. after json.UseNumber). Since
	// json.Unmarshal into interface{} never produces int64 directly,
	// we construct the map manually to exercise that code path.
	parent := map[string]interface{}{
		"BiasCurrent": map[string]interface{}{"_value": int64(42)},
	}
	assert.InDelta(t, 42.0, readFloat(parent, "BiasCurrent"), 0.001)
}

func TestRefreshOneOpticalSubtree_TransportError(t *testing.T) {
	// Point at a closed server so postJSONRequest returns a transport
	// error — covers the `if err != nil` path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	geniesBaseURL = srv.URL

	_, err := refreshOneOpticalSubtree(context.Background(), mockDeviceID, "TestSubtree")
	require.Error(t, err)
}

func TestRefreshOpticalStats_TransportErrorFallback(t *testing.T) {
	// Every subtree attempt returns a transport error, so lastErr is
	// set via the err branch (not the status branch).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	geniesBaseURL = srv.URL

	err := refreshOpticalStats(context.Background(), mockDeviceID)
	require.Error(t, err)
}

func TestRefreshOpticalStats_EmptySubtreeList(t *testing.T) {
	// Swap the package-level subtree list to an empty slice so the
	// loop makes zero attempts and successCount stays at 0 with
	// lastErr also nil — this exercises the `if lastErr == nil`
	// defensive branch that otherwise is unreachable.
	orig := opticalSubtreePathsToRefresh
	opticalSubtreePathsToRefresh = nil
	t.Cleanup(func() { opticalSubtreePathsToRefresh = orig })

	err := refreshOpticalStats(context.Background(), mockDeviceID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no subtrees attempted")
}

func TestOpticalStatsJSONShape(t *testing.T) {
	// Sanity: the serialized envelope keys are snake_case so admin-UI
	// callers can rely on the naming.
	stats := OpticalStats{
		DeviceID:      mockDeviceID,
		Source:        "zte-ct-com-epon",
		RxPowerDBm:    -21.3,
		TxPowerDBm:    2.5,
		Health:        "good",
		TemperatureC:  45.0,
		VoltageV:      3.3,
		BiasCurrentMA: 12.0,
		FetchedAt:     "2026-04-15T13:00:00Z",
	}
	raw, err := json.Marshal(stats)
	require.NoError(t, err)
	s := string(raw)
	for _, key := range []string{"rx_power_dbm", "tx_power_dbm", "health", "source"} {
		assert.Contains(t, s, key)
	}
}
