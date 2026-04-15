package main

import (
	"net/http"

	"go.uber.org/zap"
)

// handlers_lifecycle.go contains the v2.2.0 CPE lifecycle endpoints:
//
//	POST /api/v1/genieacs/factory-reset/{ip}  — H6: TR-069 FactoryReset RPC
//	POST /api/v1/genieacs/wake/{ip}           — H2: ConnectionRequest wake-up
//
// Both are thin wrappers over the generic TR-069 RPC dispatchers in
// tr069.go. The handlers themselves only do: extract device ID from
// IP, dispatch the RPC, return 202 on success. No vendor-specific
// path detection because the underlying TR-069 RPCs are dialect-agnostic.

// factoryResetDeviceHandler triggers a TR-069 FactoryReset RPC against
// the CPE. Destructive — wipes all locally-stored config (PPPoE creds,
// WLAN, port-forward rules, etc) and reboots the device. The CPE is
// unreachable for 60-180 seconds during the reset cycle, then rejoins
// the ACS in a fresh provisioning state. Used by RMA flows and
// customer-requested "reset my modem to factory" support tickets.
//
//	@Summary		Factory reset CPE
//	@Description	Triggers a TR-069 FactoryReset RPC against the CPE identified by IP. Destructive — the CPE will lose its current PPPoE credentials, WLAN config, port-forward rules, and any other locally-stored state, then rejoin the ACS in a fresh provisioning state. The device is unreachable for 60-180 seconds after the task is applied.
//	@Tags			Lifecycle
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		202	{object}	Response{data=MessageResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/factory-reset/{ip} [post]
func factoryResetDeviceHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	if err := factoryResetDevice(r.Context(), deviceID); err != nil {
		logger.Error("FactoryReset task submission failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrFactoryResetFailed)
		return
	}
	// Clear cached device tree — the post-reset device tree will look
	// completely different and stale cached values would be misleading.
	deviceCacheInstance.clear(deviceID)
	sendResponse(w, http.StatusAccepted, MessageResponse{
		Message: MsgFactoryResetSubmitted,
	})
}

// wakeDeviceHandler fires a TR-069 ConnectionRequest against the CPE
// without queuing any actual work. Used to:
//
//   - Wake a freshly-installed CPE so the first config push lands
//     synchronously instead of waiting for the next periodic inform.
//   - Wake an idle device for diagnostics.
//   - Probe responsiveness as part of a health check.
//
// Fire-and-forget — does NOT block waiting for the device to actually
// dial home. Typical wake takes 1-30 seconds depending on CPE CWMP
// timer config and current network conditions.
//
//	@Summary		Wake CPE via TR-069 ConnectionRequest
//	@Description	Fires a TR-069 ConnectionRequest against the CPE without queuing any actual work. Used to wake a freshly-installed CPE so the first config push lands synchronously, wake an idle device for diagnostics, or probe responsiveness. Fire-and-forget — does NOT block waiting for the device to actually dial home. Typical wake takes 1-30 seconds.
//	@Tags			Lifecycle
//	@Produce		json
//	@Param			ip	path		string	true	"Device IP address"	example(192.168.1.1)
//	@Success		202	{object}	Response{data=MessageResponse}
//	@Failure		400	{object}	Response
//	@Failure		401	{object}	Response
//	@Failure		404	{object}	Response
//	@Failure		429	{object}	Response
//	@Failure		500	{object}	Response
//	@Security		ApiKeyAuth
//	@Router			/wake/{ip} [post]
func wakeDeviceHandler(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := ExtractDeviceIDByIP(w, r)
	if !ok {
		return
	}
	if err := connectionRequest(r.Context(), deviceID); err != nil {
		logger.Error("ConnectionRequest dispatch failed",
			zap.String("deviceID", deviceID), zap.Error(err))
		sendError(w, r, http.StatusInternalServerError, ErrCodeGenieACS, ErrWakeFailed)
		return
	}
	sendResponse(w, http.StatusAccepted, MessageResponse{
		Message: MsgWakeDispatched,
	})
}
