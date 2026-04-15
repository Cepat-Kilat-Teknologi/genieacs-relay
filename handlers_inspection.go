package main

import (
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// handlers_inspection.go contains the v2.2.0 read-side device inspection
// endpoints:
//
//	GET  /api/v1/genieacs/status/{ip}  — H1: last_inform / online / uptime
//	GET  /api/v1/genieacs/wan/{ip}     — H4: WAN connection state + external IP
//	POST /api/v1/genieacs/params/{ip}  — H7: generic GetParameterValues passthrough
//
// All three are read-only against the cached GenieACS device tree.
// They reuse `getDeviceData` for the cached fetch and the
// `param_walker.go` helpers for typed parameter extraction.

// --- H1: GET /status/{ip} ---

// DeviceStatusResponse is the shape returned by GET /status/{ip}.
//
// @Description Device status response — last inform timestamp, computed online flag, uptime, and identification fields parsed from the cached device tree.
type DeviceStatusResponse struct {
	DeviceID            string `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	IP                  string `json:"ip" example:"192.168.1.1"`
	LastInform          string `json:"last_inform" example:"2026-04-14T11:35:21Z"`
	LastInformAgeSecond int64  `json:"last_inform_age_seconds" example:"42"`
	Online              bool   `json:"online" example:"true"`
	UptimeSeconds       int    `json:"uptime_seconds,omitempty" example:"1234567"`
	Manufacturer        string `json:"manufacturer,omitempty" example:"ZTE"`
	Model               string `json:"model,omitempty" example:"F670L"`
	SoftwareVersion     string `json:"software_version,omitempty" example:"V9.0.10P5N12"`
	HardwareVersion     string `json:"hardware_version,omitempty" example:"V1.0"`
}

// Compile-time guard so swaggo doesn't drop the type.
var _ = DeviceStatusResponse{}

// getDeviceStatusHandler returns a status snapshot for the CPE
// identified by IP. Read-only against the cached device tree —
// ~50ms typical response time.
//
//	@Summary		Get CPE status (last inform, uptime, identity)
//	@Description	Returns last inform timestamp, computed online flag, uptime, and identification fields (manufacturer, model, software/hardware version) parsed from the cached GenieACS device tree.
//	@Tags			Inspection
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200	{object}	Response{data=DeviceStatusResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/status/{ip} [get]
func getDeviceStatusHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	tree, err := getDeviceData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to read device tree for status",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrStatusReadFailed)
		return
	}
	resp := buildDeviceStatusResponse(tree, deviceID, getIPParam(r))
	sendResponse(w, http.StatusOK, resp)
}

// buildDeviceStatusResponse extracts the status fields from a device
// tree. Pure function — no I/O. Split out for unit testability.
func buildDeviceStatusResponse(tree map[string]interface{}, deviceID, ip string) DeviceStatusResponse {
	resp := DeviceStatusResponse{
		DeviceID: deviceID,
		IP:       ip,
	}
	applyLastInform(tree, &resp)

	// Uptime — try TR-098 then TR-181 paths.
	if v, ok := lookupFirstInt(tree,
		"InternetGatewayDevice.DeviceInfo.UpTime",
		"Device.DeviceInfo.UpTime"); ok {
		resp.UptimeSeconds = v
	}

	// Identification fields — try TR-098 then TR-181 for each.
	resp.Manufacturer, _ = lookupFirstString(tree,
		"InternetGatewayDevice.DeviceInfo.Manufacturer",
		"Device.DeviceInfo.Manufacturer")
	resp.Model, _ = lookupFirstString(tree,
		"InternetGatewayDevice.DeviceInfo.ModelName",
		"Device.DeviceInfo.ModelName")
	resp.SoftwareVersion, _ = lookupFirstString(tree,
		"InternetGatewayDevice.DeviceInfo.SoftwareVersion",
		"Device.DeviceInfo.SoftwareVersion")
	resp.HardwareVersion, _ = lookupFirstString(tree,
		"InternetGatewayDevice.DeviceInfo.HardwareVersion",
		"Device.DeviceInfo.HardwareVersion")
	return resp
}

// applyLastInform reads the top-level _lastInform field from the
// device tree and populates LastInform, LastInformAgeSecond, and
// Online on the response. _lastInform is a bare RFC3339 string at
// the top of the device document, NOT a {"_value": "..."} wrapper.
//
// Split out from buildDeviceStatusResponse so the parent function
// stays under the gocyclo budget, and so the early-return logic for
// each malformed shape (missing field, wrong type, unparseable
// timestamp) is one focused function.
func applyLastInform(tree map[string]interface{}, resp *DeviceStatusResponse) {
	rawLastInform, ok := tree["_lastInform"]
	if !ok {
		return
	}
	s, isString := rawLastInform.(string)
	if !isString {
		return
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return
	}
	resp.LastInform = t.UTC().Format(time.RFC3339)
	age := time.Since(t).Seconds()
	if age < 0 {
		age = 0
	}
	resp.LastInformAgeSecond = int64(age)
	// Online if the last inform is within 3x the stale threshold.
	// Falls back to a 30-minute window when the stale check is
	// disabled so callers always get a meaningful flag.
	threshold := staleThreshold
	if threshold <= 0 {
		threshold = 30 * time.Minute
	}
	resp.Online = time.Since(t) < 3*threshold
}

// lookupFirstInt walks each candidate path in order and returns the
// first int value found. Used for TR-098 → TR-181 fallback chains.
func lookupFirstInt(tree map[string]interface{}, paths ...string) (int, bool) {
	for _, p := range paths {
		if v, ok := LookupInt(tree, p); ok {
			return v, true
		}
	}
	return 0, false
}

// lookupFirstString is the string equivalent of lookupFirstInt.
func lookupFirstString(tree map[string]interface{}, paths ...string) (string, bool) {
	for _, p := range paths {
		if v, ok := LookupString(tree, p); ok {
			return v, true
		}
	}
	return "", false
}

// --- H4: GET /wan/{ip} ---

// WANConnectionInfo is one entry in WANConnectionsResponse.WANConnections.
//
// @Description One WAN connection's state — type (pppoe/dhcp/static), connection status, external IP, uptime, optional username (PPPoE only).
type WANConnectionInfo struct {
	Instance         int    `json:"instance" example:"1"`
	Type             string `json:"type" example:"pppoe"`
	ConnectionStatus string `json:"connection_status" example:"Connected"`
	ExternalIP       string `json:"external_ip,omitempty" example:"203.0.113.45"`
	UptimeSeconds    int    `json:"uptime_seconds,omitempty" example:"12345"`
	Username         string `json:"username,omitempty" example:"pppoe-customer-001"`
	LastError        string `json:"last_connection_error,omitempty" example:""`
}

// WANConnectionsResponse is the shape returned by GET /wan/{ip}.
//
// @Description WAN connection state response — array of WAN connections (some CPE models expose multiple WANPPPConnection / WANIPConnection instances for multi-WAN or dual-stack).
type WANConnectionsResponse struct {
	DeviceID       string              `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	IP             string              `json:"ip" example:"192.168.1.1"`
	WANConnections []WANConnectionInfo `json:"wan_connections"`
}

var _ = WANConnectionsResponse{}

// getWanStatusHandler returns the WAN connection state(s) for the CPE.
// Walks both PPP and IP modes across all WANDevice / WANConnectionDevice
// instances so multi-WAN or dual-stack devices are surfaced as separate
// entries in the response.
//
//	@Summary		Get CPE WAN connection state
//	@Description	Returns WAN connection state(s) for the CPE — connection type (pppoe/dhcp/static), connection status, external IP, uptime, optional PPPoE username. Walks all WANDevice / WANConnectionDevice instances so multi-WAN devices are surfaced as separate entries.
//	@Tags			Inspection
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200	{object}	Response{data=WANConnectionsResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wan/{ip} [get]
func getWanStatusHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	tree, err := getDeviceData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to read device tree for WAN status",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrWanReadFailed)
		return
	}
	resp := buildWanConnectionsResponse(tree, deviceID, getIPParam(r))
	sendResponse(w, http.StatusOK, resp)
}

// buildWanConnectionsResponse walks the device tree and pulls every
// WANPPPConnection and WANIPConnection instance into the response.
// Pure function for unit testability.
func buildWanConnectionsResponse(tree map[string]interface{}, deviceID, ip string) WANConnectionsResponse {
	resp := WANConnectionsResponse{
		DeviceID:       deviceID,
		IP:             ip,
		WANConnections: []WANConnectionInfo{},
	}

	// TR-098 path family: InternetGatewayDevice.WANDevice.{n}.WANConnectionDevice.{m}.
	wanDevs := EnumerateInstances(tree, "InternetGatewayDevice.WANDevice")
	for _, wd := range wanDevs {
		wcdParent := joinPath("InternetGatewayDevice.WANDevice", wd, "WANConnectionDevice")
		wcds := EnumerateInstances(tree, wcdParent)
		for _, wcd := range wcds {
			pppParent := joinPath(wcdParent, wcd, "WANPPPConnection")
			for _, ppp := range EnumerateInstances(tree, pppParent) {
				resp.WANConnections = append(resp.WANConnections,
					extractPPPConnection(tree, joinInstance(pppParent, ppp), ppp))
			}
			ipParent := joinPath(wcdParent, wcd, "WANIPConnection")
			for _, ipi := range EnumerateInstances(tree, ipParent) {
				resp.WANConnections = append(resp.WANConnections,
					extractIPConnection(tree, joinInstance(ipParent, ipi), ipi))
			}
		}
	}
	return resp
}

// extractPPPConnection pulls one WANPPPConnection instance into a
// WANConnectionInfo struct. Marked as type=pppoe.
func extractPPPConnection(tree map[string]interface{}, base string, instance int) WANConnectionInfo {
	info := WANConnectionInfo{Instance: instance, Type: "pppoe"}
	if v, ok := LookupString(tree, base+".ConnectionStatus"); ok {
		info.ConnectionStatus = v
	}
	if v, ok := LookupString(tree, base+".ExternalIPAddress"); ok {
		info.ExternalIP = v
	}
	if v, ok := LookupInt(tree, base+".Uptime"); ok {
		info.UptimeSeconds = v
	}
	if v, ok := LookupString(tree, base+".Username"); ok {
		info.Username = v
	}
	if v, ok := LookupString(tree, base+".LastConnectionError"); ok {
		info.LastError = v
	}
	return info
}

// extractIPConnection pulls one WANIPConnection instance into a
// WANConnectionInfo struct. Type is "dhcp" or "static" depending on
// the AddressingType parameter when present.
func extractIPConnection(tree map[string]interface{}, base string, instance int) WANConnectionInfo {
	info := WANConnectionInfo{Instance: instance, Type: "dhcp"}
	if v, ok := LookupString(tree, base+".AddressingType"); ok {
		// Common AddressingType values: "DHCP", "Static", "IPCP".
		// Lowercase for the API contract.
		switch v {
		case "Static":
			info.Type = "static"
		case "IPCP":
			info.Type = "ipcp"
		case "DHCP":
			info.Type = "dhcp"
		}
	}
	if v, ok := LookupString(tree, base+".ConnectionStatus"); ok {
		info.ConnectionStatus = v
	}
	if v, ok := LookupString(tree, base+".ExternalIPAddress"); ok {
		info.ExternalIP = v
	}
	if v, ok := LookupInt(tree, base+".Uptime"); ok {
		info.UptimeSeconds = v
	}
	if v, ok := LookupString(tree, base+".LastConnectionError"); ok {
		info.LastError = v
	}
	return info
}

// --- H7: POST /params/{ip} ---

// GenericParamsRequest is the body shape for POST /params/{ip}.
//
// @Description Generic parameter passthrough request — list of TR-069 parameter paths to read from the cached device tree, plus an optional `live` flag to trigger a fresh GetParameterValues task before reading.
type GenericParamsRequest struct {
	Paths []string `json:"paths"`
	Live  bool     `json:"live,omitempty"`
}

// GenericParamsResponse is the shape returned by POST /params/{ip}.
//
// @Description Generic parameter passthrough response — map of path → string value for found parameters, plus a list of paths that did not exist in the device tree.
type GenericParamsResponse struct {
	DeviceID     string            `json:"device_id" example:"001141-F670L-ZTEGCFLN794B3A1"`
	IP           string            `json:"ip" example:"192.168.1.1"`
	Params       map[string]string `json:"params"`
	MissingPaths []string          `json:"missing_paths"`
	Live         bool              `json:"live" example:"false"`
}

var (
	_ = GenericParamsRequest{}
	_ = GenericParamsResponse{}
)

// MaxGenericParamPathsPerRequest caps the number of parameter paths
// allowed in a single POST /params/{ip} request, so a single client
// can't cause a fan-out walk over thousands of tree paths.
const MaxGenericParamPathsPerRequest = 50

// getGenericParamsHandler reads arbitrary TR-069 parameter values from
// the cached device tree (or, when `live=true`, dispatches a fresh
// GetParameterValues task first). Used by the NOC L2/L3 debugging
// workflow — operators can inspect any parameter without the relay
// needing a dedicated endpoint per parameter.
//
// Cached mode is sub-100ms and serves the common case. Live mode
// forces a fresh fetch from the CPE and waits a bounded amount of
// time for the device to inform back; in v2.2.0 the live mode
// dispatches the task and returns the cached values immediately
// (callers can re-poll for updated values), since adding a wait loop
// here would couple the relay's request-handling thread to CPE inform
// latency. A future v2.3.0 enhancement may add a relay-side wait
// with timeout if field demand emerges.
//
//	@Summary		Generic GetParameterValues passthrough
//	@Description	Reads arbitrary TR-069 parameter values from the cached device tree (or dispatches a fresh GetParameterValues task with `live=true`). Each path is validated for safe characters before forwarding. Up to 50 paths per request.
//	@Tags			Inspection
//	@Accept			json
//	@Produce		json
//	@Param			ip		path		string					true	"Device IP address"	example(192.168.1.1)
//	@Param			body	body		GenericParamsRequest	true	"Parameter paths to read"
//	@Success		200		{object}	Response{data=GenericParamsResponse}
//	@Failure		400		{object}	Response
//	@Failure		401		{object}	Response
//	@Failure		404		{object}	Response
//	@Failure		413		{object}	Response
//	@Failure		429		{object}	Response
//	@Failure		500		{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/params/{ip} [post]
func getGenericParamsHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}

	var req GenericParamsRequest
	if !ParseJSONRequest(w, r, &req) {
		return
	}

	if len(req.Paths) == 0 {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrPathListEmpty)
		return
	}
	if len(req.Paths) > MaxGenericParamPathsPerRequest {
		sendError(w, r, http.StatusBadRequest, ErrCodeValidation, ErrPathListTooLong)
		return
	}
	for _, p := range req.Paths {
		if err := validateTRParamPath(p); err != nil {
			sendError(w, r, http.StatusBadRequest, ErrCodeValidation,
				formatInvalidParamPath(p))
			return
		}
	}

	// Live mode: dispatch a GetParameterValues task. Best-effort —
	// errors here are logged but not fatal because the cached read
	// below may still produce useful values from the previous tree.
	if req.Live {
		if err := getParameterValuesLive(r.Context(), deviceID, req.Paths); err != nil {
			logger.Warn("Live param fetch dispatch failed",
				zap.String("deviceID", deviceID), zap.Error(err))
			sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrParamLiveFetchFailed)
			return
		}
		// Clear cache so the next getDeviceData call hits GenieACS fresh.
		deviceCacheInstance.clear(deviceID)
	}

	tree, err := getDeviceData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to read device tree for params",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrParamReadFailed)
		return
	}

	found, missing := CollectPaths(tree, req.Paths)
	resp := GenericParamsResponse{
		DeviceID:     deviceID,
		IP:           getIPParam(r),
		Params:       found,
		MissingPaths: missing,
		Live:         req.Live,
	}
	if resp.MissingPaths == nil {
		resp.MissingPaths = []string{}
	}
	sendResponse(w, http.StatusOK, resp)
}

// formatInvalidParamPath builds the user-facing error message for a
// rejected parameter path. Split out so its single-line escape sequence
// is exercised by a unit test.
func formatInvalidParamPath(path string) string {
	// Trim long paths so the error message stays one-line readable.
	if len(path) > 80 {
		path = path[:77] + "..."
	}
	return "Invalid parameter path: " + path
}

// --- M3: GET /wifi-clients/{ip} ---

// WiFiClientInfo is one entry in WiFiClientsResponse.Clients.
//
// @Description Associated WiFi client — distinct from a DHCP lease in `/dhcp-client/{ip}` which only sees clients that asked for DHCP. WiFi clients are read from the WLAN association table on the CPE radio.
type WiFiClientInfo struct {
	MAC               string `json:"mac" example:"AA:BB:CC:DD:EE:FF"`
	WLAN              int    `json:"wlan" example:"1"`
	SSID              string `json:"ssid,omitempty" example:"MyWiFi-2.4GHz"`
	Band              string `json:"band,omitempty" example:"2.4GHz"`
	SignalStrengthDBm int    `json:"signal_strength_dbm,omitempty" example:"-55"`
	Authenticated     bool   `json:"authenticated,omitempty" example:"true"`
}

// WiFiClientsResponse is the shape returned by GET /wifi-clients/{ip}.
//
// @Description Associated WiFi clients per radio. Distinct from `/dhcp-client/{ip}` which only sees clients that asked for DHCP.
type WiFiClientsResponse struct {
	DeviceID string           `json:"device_id"`
	IP       string           `json:"ip"`
	Clients  []WiFiClientInfo `json:"clients"`
}

var (
	_ = WiFiClientInfo{}
	_ = WiFiClientsResponse{}
)

// getWifiClientsHandler returns the associated WiFi clients across
// all WLAN radios on the CPE. Walks
// `LANDevice.1.WLANConfiguration.{n}.AssociatedDevice.{m}` (TR-098).
//
//	@Summary		Get associated WiFi clients
//	@Description	Returns the associated WiFi clients across all WLAN radios on the CPE. Distinct from `/dhcp-client/{ip}` which only sees clients that asked for DHCP — this endpoint reads the WLAN association table directly.
//	@Tags			Inspection
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200	{object}	Response{data=WiFiClientsResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wifi-clients/{ip} [get]
func getWifiClientsHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	tree, err := getDeviceData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to read device tree for wifi clients",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrWifiClientsReadFailed)
		return
	}
	resp := buildWifiClientsResponse(tree, deviceID, getIPParam(r))
	sendResponse(w, http.StatusOK, resp)
}

// buildWifiClientsResponse walks the WLAN association table for every
// WLAN instance on the CPE and returns the merged client list.
func buildWifiClientsResponse(tree map[string]interface{}, deviceID, ip string) WiFiClientsResponse {
	resp := WiFiClientsResponse{
		DeviceID: deviceID,
		IP:       ip,
		Clients:  []WiFiClientInfo{},
	}
	wlanParent := "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
	for _, wlanID := range EnumerateInstances(tree, wlanParent) {
		wlanBase := joinInstance(wlanParent, wlanID)
		ssid, _ := LookupString(tree, wlanBase+".SSID")
		band := classifyWLANBand(tree, wlanBase)
		assocBase := wlanBase + ".AssociatedDevice"
		for _, assocID := range EnumerateInstances(tree, assocBase) {
			clientBase := joinInstance(assocBase, assocID)
			resp.Clients = append(resp.Clients,
				extractWifiClient(tree, clientBase, wlanID, ssid, band))
		}
	}
	return resp
}

// extractWifiClient pulls one AssociatedDevice instance into a
// WiFiClientInfo struct.
func extractWifiClient(tree map[string]interface{}, base string, wlanID int, ssid, band string) WiFiClientInfo {
	c := WiFiClientInfo{WLAN: wlanID, SSID: ssid, Band: band}
	if v, ok := LookupString(tree, base+".AssociatedDeviceMACAddress"); ok {
		c.MAC = v
	}
	if v, ok := LookupInt(tree, base+".X_SignalStrength"); ok {
		c.SignalStrengthDBm = v
	} else if v, ok := LookupInt(tree, base+".SignalStrength"); ok {
		c.SignalStrengthDBm = v
	}
	if v, ok := LookupBool(tree, base+".AssociatedDeviceAuthenticationState"); ok {
		c.Authenticated = v
	}
	return c
}

// classifyWLANBand inspects the WLAN's `Standard` parameter and returns
// a short band label. 802.11a/n/ac → 5GHz; everything else → 2.4GHz.
// Best-effort heuristic; returns "" when no Standard is present.
func classifyWLANBand(tree map[string]interface{}, wlanBase string) string {
	std, ok := LookupString(tree, wlanBase+".Standard")
	if !ok {
		return ""
	}
	if strings.ContainsAny(std, "aA") || strings.Contains(strings.ToLower(std), "ac") {
		return Band5GHz
	}
	return Band2_4GHz
}

// --- M7: GET /wifi-stats/{ip} ---

// WiFiRadioStats is one entry in WiFiStatsResponse.Radios.
//
// @Description Per-radio WiFi statistics — channel, tx power, byte/packet counters, and error rates.
type WiFiRadioStats struct {
	WLAN          int    `json:"wlan" example:"1"`
	SSID          string `json:"ssid,omitempty" example:"MyWiFi-2.4GHz"`
	Band          string `json:"band,omitempty" example:"2.4GHz"`
	Channel       int    `json:"channel,omitempty" example:"6"`
	TxPowerLevel  int    `json:"tx_power_percent,omitempty" example:"100"`
	BytesSent     int    `json:"bytes_sent,omitempty"`
	BytesReceived int    `json:"bytes_received,omitempty"`
	PacketsSent   int    `json:"packets_sent,omitempty"`
	PacketsRecv   int    `json:"packets_received,omitempty"`
	ErrorsSent    int    `json:"errors_sent,omitempty"`
	ErrorsRecv    int    `json:"errors_received,omitempty"`
}

// WiFiStatsResponse is the shape returned by GET /wifi-stats/{ip}.
//
// @Description Per-radio WiFi statistics for the CPE.
type WiFiStatsResponse struct {
	DeviceID string           `json:"device_id"`
	IP       string           `json:"ip"`
	Radios   []WiFiRadioStats `json:"radios"`
}

var (
	_ = WiFiRadioStats{}
	_ = WiFiStatsResponse{}
)

// getWifiStatsHandler returns per-radio WiFi statistics for the CPE.
//
//	@Summary		Get per-radio WiFi statistics
//	@Description	Returns per-radio WiFi statistics for the CPE — channel, tx power, bytes/packets sent and received, and error counters. Used by WiFi optimization recommendations and "my wifi is slow" customer support tickets.
//	@Tags			Inspection
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		200	{object}	Response{data=WiFiStatsResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wifi-stats/{ip} [get]
func getWifiStatsHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	tree, err := getDeviceData(r.Context(), deviceID)
	if err != nil {
		logger.Error("Failed to read device tree for wifi stats",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrWifiStatsReadFailed)
		return
	}
	resp := buildWifiStatsResponse(tree, deviceID, getIPParam(r))
	sendResponse(w, http.StatusOK, resp)
}

// buildWifiStatsResponse walks every WLANConfiguration instance on the
// CPE and pulls the channel, tx power, and Stats subtree fields into
// the response.
func buildWifiStatsResponse(tree map[string]interface{}, deviceID, ip string) WiFiStatsResponse {
	resp := WiFiStatsResponse{
		DeviceID: deviceID,
		IP:       ip,
		Radios:   []WiFiRadioStats{},
	}
	wlanParent := "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
	for _, wlanID := range EnumerateInstances(tree, wlanParent) {
		wlanBase := joinInstance(wlanParent, wlanID)
		resp.Radios = append(resp.Radios, extractWifiRadioStats(tree, wlanBase, wlanID))
	}
	return resp
}

// extractWifiRadioStats reads the channel, tx power, and Stats fields
// for one WLAN instance.
func extractWifiRadioStats(tree map[string]interface{}, base string, wlanID int) WiFiRadioStats {
	r := WiFiRadioStats{WLAN: wlanID, Band: classifyWLANBand(tree, base)}
	if v, ok := LookupString(tree, base+".SSID"); ok {
		r.SSID = v
	}
	if v, ok := LookupInt(tree, base+".Channel"); ok {
		r.Channel = v
	}
	if v, ok := LookupInt(tree, base+".TransmitPower"); ok {
		r.TxPowerLevel = v
	} else if v, ok := LookupInt(tree, base+".X_TXPower"); ok {
		r.TxPowerLevel = v
	}
	statsBase := base + ".Stats"
	if v, ok := LookupInt(tree, statsBase+".TotalBytesSent"); ok {
		r.BytesSent = v
	}
	if v, ok := LookupInt(tree, statsBase+".TotalBytesReceived"); ok {
		r.BytesReceived = v
	}
	if v, ok := LookupInt(tree, statsBase+".TotalPacketsSent"); ok {
		r.PacketsSent = v
	}
	if v, ok := LookupInt(tree, statsBase+".TotalPacketsReceived"); ok {
		r.PacketsRecv = v
	}
	if v, ok := LookupInt(tree, statsBase+".ErrorsSent"); ok {
		r.ErrorsSent = v
	}
	if v, ok := LookupInt(tree, statsBase+".ErrorsReceived"); ok {
		r.ErrorsRecv = v
	}
	return r
}
