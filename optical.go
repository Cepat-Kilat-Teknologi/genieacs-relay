package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// OpticalStats describes the optical interface health of a CPE/ONT,
// extracted from whichever vendor-specific TR-069 parameter tree the
// device exposes. Fields use SI/standard units to make ops dashboards
// deterministic across vendors.
type OpticalStats struct {
	DeviceID string `json:"device_id"`

	// TxPowerDBm — optical transmit power in dBm. Normal PON ONU range
	// is roughly -1 to +5 dBm. Lower values may indicate laser bias
	// degradation or power supply issues.
	TxPowerDBm float64 `json:"tx_power_dbm"`

	// RxPowerDBm — optical receive power in dBm. Normal PON ONU range
	// is roughly -8 to -27 dBm depending on splitter ratio + distance.
	// Below -27: marginal. Below -30: no signal (fiber broken/disconnected).
	// Above -8: overloaded (CPE may be too close to OLT or splitter ratio wrong).
	RxPowerDBm float64 `json:"rx_power_dbm"`

	// BiasCurrentMA — laser driver bias current in milliamps. Normal
	// range is roughly 5-30 mA depending on optics module. Rising bias
	// over time indicates laser aging.
	BiasCurrentMA float64 `json:"bias_current_ma,omitempty"`

	// TemperatureC — internal optics module temperature in Celsius.
	// Normal range is 0-80°C. Above 85°C may trigger thermal shutdown.
	TemperatureC float64 `json:"temperature_c,omitempty"`

	// VoltageV — optics module supply voltage in Volts. Normal range
	// is 3.0-3.6V (3.3V nominal). Out-of-range = power supply issue.
	VoltageV float64 `json:"voltage_v,omitempty"`

	// Health — categorical classification derived from RxPowerDBm using
	// configurable thresholds. Values: "good", "warning", "critical",
	// "no_signal", "unknown".
	Health string `json:"health"`

	// Source — which parameter tree the values came from. Useful for
	// debugging and vendor-mix analytics. Possible values:
	// "zte_ct_com_epon", "zte_ct_com_gpon", "huawei_hw_debug",
	// "realtek_epon", "standard_tr181".
	Source string `json:"source"`

	// FetchedAt — RFC3339 timestamp of when the data was read from
	// GenieACS. Combine with `?refresh=true` for guaranteed freshness.
	FetchedAt string `json:"fetched_at"`
}

// errOpticalNotSupported is the sentinel error returned when no known
// vendor parameter tree is found in the device data. Caller (handler)
// translates this to HTTP 404 with error_code OPTICAL_NOT_SUPPORTED.
var errOpticalNotSupported = errors.New("optical interface stats not supported by this device")

// opticalSource is the categorical label for which vendor parameter
// tree the values came from. Stable strings — used in the response
// payload `source` field for analytics.
const (
	opticalSourceZTECTComEpon  = "zte_ct_com_epon"
	opticalSourceZTECTComGpon  = "zte_ct_com_gpon"
	opticalSourceHuaweiHWDbg   = "huawei_hw_debug"
	opticalSourceRealtekEpon   = "realtek_epon"
	opticalSourceStandardTR181 = "standard_tr181"
)

// opticalSubtreePathsToRefresh lists the parameter subtrees we ask
// GenieACS to refresh when the caller passes ?refresh=true. We refresh
// ALL known vendor subtrees because we don't know which the CPE
// supports until we parse the response — and refresh requests against
// unsupported subtrees return harmlessly. Order is best-effort: most
// common (ZTE EPON in Indonesian deployments) first.
var opticalSubtreePathsToRefresh = []string{
	"InternetGatewayDevice.X_CT-COM_EponInterfaceConfig",
	"InternetGatewayDevice.X_CT-COM_GponInterfaceConfig",
	"InternetGatewayDevice.X_HW_DEBUG.AdminTR069",
	"InternetGatewayDevice.X_Realtek_EponInterfaceConfig",
	"Device.Optical.Interface",
}

// refreshOpticalStats triggers a refreshObject task on each known
// optical parameter subtree, with `?connection_request` so each call
// blocks until the task is applied (or queued). Errors on individual
// subtrees are logged and swallowed — many CPEs only expose one of
// these trees, and a 404 from GenieACS for the wrong vendor tree is
// expected and harmless.
//
// Success contract: as long as at least one subtree returned a 2xx/3xx
// status, the overall call succeeds. Only when ALL subtrees fail (every
// one returned 4xx/5xx or had a transport error) does the function
// return an error.
func refreshOpticalStats(ctx context.Context, deviceID string) error {
	var lastErr error
	successCount := 0
	for _, subtree := range opticalSubtreePathsToRefresh {
		statusCode, err := refreshOneOpticalSubtree(ctx, deviceID, subtree)
		if err != nil {
			lastErr = err
			continue
		}
		if statusCode < http.StatusBadRequest {
			successCount++
			continue
		}
		// 4xx/5xx — record the latest bad status as the surfaceable
		// error in case every subtree fails.
		lastErr = fmt.Errorf("subtree %q: status %d", subtree, statusCode)
	}
	if successCount == 0 {
		if lastErr == nil {
			lastErr = errors.New("no subtrees attempted")
		}
		return fmt.Errorf("optical refresh failed for all known subtrees: %w", lastErr)
	}
	return nil
}

// refreshOneOpticalSubtree posts a single refreshObject task for the
// given subtree and returns the response status code (along with any
// transport error). Extracted from refreshOpticalStats so the linter
// can see the deferred body close — the inline loop variant tripped
// bodyclose due to the early `continue` paths.
func refreshOneOpticalSubtree(ctx context.Context, deviceID, subtree string) (int, error) {
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))
	payload := fmt.Sprintf(`{"name": "refreshObject", "objectName": %q}`, subtree)
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return 0, err
	}
	defer safeClose(resp.Body)
	return resp.StatusCode, nil
}

// getOpticalStats reads optical interface stats from GenieACS for the
// given device, automatically detecting which vendor parameter tree
// the CPE exposes. Returns errOpticalNotSupported (sentinel) if no
// known tree is found.
//
// Detection order: ZTE CT-COM EPON → ZTE CT-COM GPON → Huawei HW_DEBUG
// → Realtek EPON → standard TR-181. The order matches typical Indonesian
// ISP deployment frequency (most ZTE F670L/F660 ONTs in residential
// PON deployments).
func getOpticalStats(ctx context.Context, deviceID string) (*OpticalStats, error) {
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	stats := &OpticalStats{
		DeviceID:  deviceID,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Try each vendor extractor in order. First one that returns true
	// wins — sets the source and returns the populated struct.
	if extractZTECTComEpon(deviceData, stats) {
		classifyOpticalHealth(stats)
		return stats, nil
	}
	if extractZTECTComGpon(deviceData, stats) {
		classifyOpticalHealth(stats)
		return stats, nil
	}
	if extractHuaweiHWDebug(deviceData, stats) {
		classifyOpticalHealth(stats)
		return stats, nil
	}
	if extractRealtekEpon(deviceData, stats) {
		classifyOpticalHealth(stats)
		return stats, nil
	}
	if extractStandardTR181(deviceData, stats) {
		classifyOpticalHealth(stats)
		return stats, nil
	}

	return nil, errOpticalNotSupported
}

// extractZTECTComEpon reads optical stats from the ZTE CT-COM EPON
// parameter tree (`InternetGatewayDevice.X_CT-COM_EponInterfaceConfig.Stats`).
// This is the most common tree in Indonesian residential PON deployments
// (ZTE F670L, F660, F670Lv9 — all China Telecom OEM-branded).
func extractZTECTComEpon(deviceData map[string]interface{}, stats *OpticalStats) bool {
	statsTree := navigateNested(deviceData,
		"InternetGatewayDevice", "X_CT-COM_EponInterfaceConfig", "Stats")
	if statsTree == nil {
		return false
	}
	stats.Source = opticalSourceZTECTComEpon
	stats.TxPowerDBm = readFloat(statsTree, "TxPower")
	stats.RxPowerDBm = readFloat(statsTree, "RxPower")
	stats.BiasCurrentMA = readFloat(statsTree, "BiasCurrent")
	stats.TemperatureC = readFloat(statsTree, "Temperature")
	stats.VoltageV = readFloat(statsTree, "Voltage")
	return true
}

// extractZTECTComGpon reads optical stats from the GPON variant of the
// ZTE CT-COM tree. Same shape as EPON but used by GPON ONTs.
func extractZTECTComGpon(deviceData map[string]interface{}, stats *OpticalStats) bool {
	statsTree := navigateNested(deviceData,
		"InternetGatewayDevice", "X_CT-COM_GponInterfaceConfig", "Stats")
	if statsTree == nil {
		return false
	}
	stats.Source = opticalSourceZTECTComGpon
	stats.TxPowerDBm = readFloat(statsTree, "TxPower")
	stats.RxPowerDBm = readFloat(statsTree, "RxPower")
	stats.BiasCurrentMA = readFloat(statsTree, "BiasCurrent")
	stats.TemperatureC = readFloat(statsTree, "Temperature")
	stats.VoltageV = readFloat(statsTree, "Voltage")
	return true
}

// extractHuaweiHWDebug reads optical stats from the Huawei HW_DEBUG
// parameter tree (`InternetGatewayDevice.X_HW_DEBUG.AdminTR069`).
// Used by HG8245, HG8546, HN8145, and other Huawei HG-series ONTs.
func extractHuaweiHWDebug(deviceData map[string]interface{}, stats *OpticalStats) bool {
	statsTree := navigateNested(deviceData,
		"InternetGatewayDevice", "X_HW_DEBUG", "AdminTR069")
	if statsTree == nil {
		return false
	}
	stats.Source = opticalSourceHuaweiHWDbg
	stats.TxPowerDBm = readFloat(statsTree, "TxPower")
	stats.RxPowerDBm = readFloat(statsTree, "RxPower")
	// Huawei usually doesn't expose bias/temp/voltage in HW_DEBUG.
	// Leave them zero (omitempty in JSON).
	return true
}

// extractRealtekEpon reads optical stats from the Realtek/PMC EPON
// chipset parameter tree. Used by various noname OEM ONTs that bundle
// the Realtek RTL96xx series.
func extractRealtekEpon(deviceData map[string]interface{}, stats *OpticalStats) bool {
	statsTree := navigateNested(deviceData,
		"InternetGatewayDevice", "X_Realtek_EponInterfaceConfig", "Stats")
	if statsTree == nil {
		return false
	}
	stats.Source = opticalSourceRealtekEpon
	stats.TxPowerDBm = readFloat(statsTree, "TxPower")
	stats.RxPowerDBm = readFloat(statsTree, "RxPower")
	stats.BiasCurrentMA = readFloat(statsTree, "BiasCurrent")
	stats.TemperatureC = readFloat(statsTree, "Temperature")
	stats.VoltageV = readFloat(statsTree, "Voltage")
	return true
}

// extractStandardTR181 reads optical stats from the standard TR-181
// `Device.Optical.Interface.1.Stats.*` tree. Rarely supported in
// consumer-grade CPE but present in some enterprise/business gateways.
func extractStandardTR181(deviceData map[string]interface{}, stats *OpticalStats) bool {
	statsTree := navigateNested(deviceData,
		"Device", "Optical", "Interface", "1", "Stats")
	if statsTree == nil {
		return false
	}
	stats.Source = opticalSourceStandardTR181
	stats.TxPowerDBm = readFloat(statsTree, "TxPower")
	stats.RxPowerDBm = readFloat(statsTree, "RxPower")
	stats.BiasCurrentMA = readFloat(statsTree, "BiasCurrent")
	stats.TemperatureC = readFloat(statsTree, "Temperature")
	stats.VoltageV = readFloat(statsTree, "Voltage")
	return true
}

// navigateNested walks a chain of map[string]interface{} keys and
// returns the leaf map, or nil if any step is missing/wrong-typed.
// Convenience for the deeply nested GenieACS device tree.
func navigateNested(root map[string]interface{}, path ...string) map[string]interface{} {
	current := root
	for _, key := range path {
		next, ok := current[key].(map[string]interface{})
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

// readFloat extracts a numeric `_value` from a GenieACS parameter
// node. GenieACS stores all parameter values as objects shaped like
// `{"_value": 3.14, "_type": "xsd:float", "_timestamp": "..."}`.
// Returns 0 if the key is missing, the node isn't a map, or the value
// is not a float64. Callers treat 0 as "not reported".
func readFloat(parent map[string]interface{}, key string) float64 {
	node, ok := parent[key].(map[string]interface{})
	if !ok {
		return 0
	}
	switch v := node["_value"].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}

// classifyOpticalHealth derives the categorical Health field from
// RxPowerDBm using configurable thresholds. Defaults match typical PON
// ONT operating ranges; tunable per deployment via env vars
// OPTICAL_RX_NO_SIGNAL_DBM, OPTICAL_RX_CRITICAL_DBM, OPTICAL_RX_WARNING_DBM,
// OPTICAL_RX_OVERLOAD_DBM (read at startup, cached in the package vars).
func classifyOpticalHealth(stats *OpticalStats) {
	rx := stats.RxPowerDBm
	switch {
	case rx == 0:
		// 0 is the zero-value sentinel — extractor didn't find an RxPower
		// field. Don't classify; mark unknown.
		stats.Health = "unknown"
	case rx <= opticalRxNoSignalDBm:
		stats.Health = "no_signal"
	case rx <= opticalRxCriticalDBm:
		stats.Health = "critical"
	case rx <= opticalRxWarningDBm:
		stats.Health = "warning"
	case rx >= opticalRxOverloadDBm:
		// Above overload threshold = receiver too hot, unusual but
		// happens on misconfigured short-haul links.
		stats.Health = "warning"
	default:
		stats.Health = "good"
	}
}
