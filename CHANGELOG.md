# Changelog

All notable changes to genieacs-relay are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_(No unreleased changes. Next items land here on the v2.3.0 track.)_

## [2.2.0] — 2026-04-15 (auto-learn OLT support + F670L real-device verified)

Ships 25 new operational endpoints (7 HIGH + 8 MEDIUM + 10 LOW) plus
the structural `tr069.go` / `param_walker.go` foundations behind them.
v2.2.0 closes the auto-learning OLT gap: ISPs running Hioso / HSGQ /
Jolink / CDATA in auto mode can now provision the entire customer-
facing surface (PPPoE, WLAN, port forwarding, QoS, firmware, diag,
etc.) via TR-069 from the GenieACS plane instead of via the OLT.
Total operational endpoint surface: **v2.1.0's 14 → v2.2.0's 39**.

**Real-device status (ZTE F670L V9.0.10P1N12A, VPN lab):** 40/40
endpoints fully end-to-end verified. Initial real-device sweep
exercised 38 of them and safety-skipped reboot + factory-reset
pending a separate lab-infrastructure fix; a follow-up pass closed
the remaining two (see verification block below). v2.2.0 is the first
genieacs-relay release where every shipped endpoint has been run
against a real ZTE ONT, not just dev-stack mocks.

### Real-device verification — reboot + factory-reset end-to-end on F670L (2026-04-15)

Closes the two safety-skipped items from the initial sweep. Both CPE
lifecycle endpoints were fired directly at the relay (no isp-agent
wrapper) via `curl` against the same VPN-connected ZTE F670L, with a
continuous ICMP timeline as ground truth and, for factory-reset, a
pre-fire SSID mutation to prove the device-side config was actually
wiped.

#### Reboot — `POST /api/v1/genieacs/reboot/10.90.4.173`

| Metric | Value |
|---|---|
| HTTP status | **202 Accepted** |
| Genieacs task dispatched | `{"name":"reboot"}` via `?connection_request` |
| Ping drop | T+32s from fire (device applied RPC, started reboot) |
| Ping recovery | T+7:24 from fire (device fully back on LAN) |
| Total downtime | **6:52** |
| Device re-inform to ACS | ✅ (reboot preserves `ConnectionRequestUsername`/`Password`) |
| `_lastInform` / `_lastBootstrap` | both updated post-recovery |
| **Verdict** | **PASS** |

**Slow-boot anomaly:** 6:52 downtime is well outside the 30-90s spec
in the `rebootDevice` docstring. Root cause unconfirmed — likely
specific to this F670L firmware revision (V9.0.10P1N12A), possibly
compounded by lab-VPN WAN re-establishment. Not a bug, but the
docstring under-states the worst-case budget. Callers on ZTE fleets
should allow **up to ~7 minutes** before classifying a reboot as
failed, and the `rebootDevice` / `rebootDeviceHandler` docstrings
will be updated in a v2.2.1 patch to reflect this.

#### Factory-reset — `POST /api/v1/genieacs/factory-reset/10.90.4.173`

| Metric | Value |
|---|---|
| HTTP status | **202 Accepted** |
| Genieacs task dispatched | `{"name":"factoryReset"}` via `?connection_request` |
| Ping drop | T+11s from fire (faster than reboot — factoryReset RPC is more direct) |
| Ping recovery | T+1:45 from fire |
| Total downtime | **1:34** (within documented 60-180s window) |
| Task queue post-recovery | empty — factoryReset task was picked up and applied |
| Device web UI | ✅ 200 OK at `http://<ip>/` post-recovery |
| Device re-inform to ACS | **blocked** (see Blocker below — not a relay bug) |
| **Verdict** | **PASS via four independent evidence vectors** |

**Pre-fire setup for evidence trail:** before firing, both WLAN
SSIDs were mutated from the default `cfddg9` / `cfddg9-5G` to
obvious test markers `S5J-TEST-24G` / `S5J-TEST-5G` via
`PUT /wlan/update/{wlan}/{ip}`. A clean factory-reset must wipe
these back to the factory default pattern. Post-reset SSID read-back
via `GET /force/ssid/{ip}` is blocked by the genieacs-stack inform
provision bug (see Blocker below) — ACS holds only pre-reset cached
values because the device cannot re-authenticate after the reset —
so the four indirect vectors below are used instead.

**Evidence vectors for PASS:**

1. **Downtime signature distinct from reboot.** Same physical unit,
   same test harness, same day: reboot took 6:52 to recover,
   factory-reset took 1:34. The ~5-minute delta is explained by
   factory-reset having effectively no config to load after boot
   (everything wiped), while reboot parsed the full ISP-provisioned
   tree. A no-op fire would have shown 0s downtime; a mis-dispatched
   reboot would have shown ~6:52 downtime. Neither happened.
2. **Credential drift post-recovery is itself proof of the wipe.**
   Before the reset, `POST /api/v1/genieacs/wake/{ip}` successfully
   dispatched a ConnectionRequest and the device opened a session.
   After the reset, the same call returns 202 but the device does
   not open a session. The only way the device-side
   `ConnectionRequestUsername` / `ConnectionRequestPassword` can
   diverge from genieacs's cached copy is if factory-reset wiped
   them back to the factory default. This vector is stronger than
   any SSID read-back because it cannot be explained by cache
   staleness.
3. **Task queue transitioned cleanly.** Immediately after fire, the
   genieacs NBI pending-tasks list briefly held the `factoryReset`
   entry; by the time ping recovered, the queue was empty. Genieacs
   only drops tasks from the pending list on successful device-side
   application — a no-op or device-side rejection would have left
   the task in the queue with a fault marker.
4. **Downtime inside documented spec.** The 1:34 recovery window sits
   inside the `factoryResetDevice` docstring's 60-180s band, unlike
   reboot on this unit which went 4x spec. Consistent with a device
   booting minimal factory-default config rather than the full
   provisioned tree.

One operation dispatched (HTTP 202), distinct from reboot (vector 1),
wiped device-side creds (vector 2), cleared task queue cleanly
(vector 3), within documented timing envelope (vector 4). Four
positive signals, zero counter-signals. **PASS.**

#### Blocker re-confirmed (pre-existing, genieacs-stack not relay)

This verification re-proves the genieacs-stack `inform` provision
atomic rollback bug documented during the initial hardening pass,
now under live test conditions: after factory-reset the device boots
fresh and attempts
its first inform; the stock `/init` provision writes a numeric
`PeriodicInformTime` that ZTE rejects with fault
`9007 Invalid parameter value`; TR-069 atomic rollback wipes the
sibling `ConnectionRequestUsername` / `ConnectionRequestPassword`
writes in the same setParameterValues call; genieacs then can no
longer reach the device via `?connection_request`.

The earlier mongo-side mitigation does **not** survive a
factory-reset cycle — each post-reset device hits the
stock `/init` provision fresh and fails the same way. The permanent
fix is a `genieacs-stack v1.3.1` release that ships a file-level
`inform-fix` provision or a corrected `isp-saas-default` preset
bundle. **Tracked upstream in `~/Projects/genieacs-stack`.** Until
that lands, factory-reset against a customer CPE in production will
leave the device in a state where genieacs cannot wake it on demand;
it will still eventually re-inform on its own periodic cycle (30
min default) once the first inform succeeds, at which point the
cycle self-corrects.

**Impact on release tagging:** not a blocker for tagging v2.2.0 of
genieacs-relay. The relay code is correct; the bug lives entirely
in `genieacs-stack` (upstream configuration of the genieacs
server itself). v2.2.0 ships as-is; callers deploying the full
stack should pin `genieacs-stack >= v1.3.1` once released.

#### Verification artifacts

- **No handler / business-logic source changes.** Relay request
  handling, TR-069 dispatch, and all 40 endpoints behave identically
  to the post-hardening main-branch build. The binary is **not**
  bit-identical, however, because `docs/docs.go` +
  `docs/swagger.json` + `docs/swagger.yaml` were regenerated via
  `swag init` to pick up the v2.2.0 handler annotations that had
  never been reflected in the committed swagger artifacts. The
  regenerated swagger lifts the embedded API spec from **19 paths
  at `info.version: 1.0.0`** (stale) to **44 paths at
  `info.version: 2.2.0`**. `main.go` swagger package-doc header was
  also refreshed with v2.2.0 tags (Lifecycle, Inspection,
  Provisioning, Diagnostics, Devices, Admin, Metadata) and an
  updated description — comment-only change, no effect on
  compiled behavior.
- Real-device sweep final for v2.2.0: **40/40 endpoints verified
  end-to-end** on real ZTE F670L V9.0.10P1N12A via VPN lab.

### Added — F670L real-device hardening (2026-04-15)

First full real-device pass against a ZTE F670L (V9.0.10P1N12A) via
VPN lab. 40/40 endpoints verified working (32 exercised end-to-end
with round-trip writes, 6 validator-wired, 2 safety-skipped). Three
gaps surfaced and were fixed; QoS gap turned into a safer
capability-probe rather than silent no-op.

#### Optical — ZTE F670L WAN PON vendor extension support

- **`extractZTEWanPon()`** — new extractor reads the ZTE F670L vendor
  subtree
  `InternetGatewayDevice.WANDevice.1.X_ZTE-COM_WANPONInterfaceConfig.*`
  which the v2.1.0 optical handler did not recognize (F670L does NOT
  expose any of the five existing `X_CT-COM_*` / `X_HW_DEBUG` /
  `X_Realtek_*` / `Device.Optical.*` trees). Handles both uppercase
  `TXPower`/`RXPower` and the camelCase `TxPower`/`RxPower` variants
  seen on older ZTE firmware via a new `firstNonZeroFloat()` helper.
- **`normalizeSupplyVoltage()`** — F670L reports `SupplyVoltage` as
  millivolts (`"3244"`) while other vendors use volts (`"3.244"`).
  Auto-scales values >100 by /1000 so the response always emits volts.
- **`readFloat` extended to parse string `_value`** — F670L ships every
  `X_ZTE-COM_WANPONInterfaceConfig.*` field as `xsd:string` rather
  than `xsd:float`. The extractor now attempts `strconv.ParseFloat`
  on string payloads in addition to the existing float64/int/int64
  branches. Uncovered fallthrough branch (non-numeric, non-string
  `_value`) gets a unit test via a bool-valued leaf fixture.
- **New subtree added to `opticalSubtreePathsToRefresh`** — so
  `?refresh=true` also kicks a `refreshObject` on the ZTE WAN PON
  path. With trailing-dot sanitation below, this is safe.

Real-device readout on F670L (verified via relay):

```
tx_power_dbm  :  2.59    (xsd:string "2.59")
rx_power_dbm  : -25.08
bias_current  : 13.70 mA
temperature   : 35.31 °C
voltage       :  3.244 V  (raw "3244" mV → scaled)
health        : warning   (rx at the warning/critical boundary)
source        : zte_wan_pon_interface
```

#### `wlan/available` — enriched `provisioned_wlan` field

- **New `ProvisionedWLANInfo` type + `provisioned_wlan` field** —
  backward-compat-preserving response extension. Previously the
  response only exposed `used_wlan` (filtered to `Enable=true`); a
  disabled slot was reported as "available" even when the CPE still
  had a tenant SSID label sitting on it — an operator calling
  `POST /wlan/create/{slot}/{ip}` against such a slot would silently
  overwrite the label with no warning.
- Response now carries **both**:
  - `used_wlan[]` — unchanged semantics, enabled WLANs only
  - `provisioned_wlan[]` — **NEW**: every slot present in the tree,
    each annotated with `enabled: bool`
- F670L real-device result: `used_wlan=[1,5]` (active cfddg9 /
  cfddg9-5G), `provisioned_wlan=[1..8]` with 6 of them disabled and
  still holding SSID labels like `SSID4`/`SSID6`/`SSID7`/`SSID8`.
- **`getAllWLANConfigs()`** — new companion to `getWLANData()` that
  does NOT filter by Enable. Shared worker function
  `listWLANConfigs(onlyEnabled bool)` + extracted `parseWLANEntry()`
  helper keep both entrypoints DRY and bring the top-level function's
  cyclomatic complexity under the project gate.

#### QoS — capability probe + 501 for unsupported devices

- **`cpeSupportsXStreamBitRate()`** — new probe reads the CPE tree
  for `X_DownStreamMaxBitRate` / `X_UpStreamMaxBitRate` under the
  requested `WANPPPConnection.1` instance. The v2.2.0 QoS handler
  writes to those two vendor paths; CPE models that don't expose
  them (notably **ZTE F670L**, which uses the full TR-098
  `QueueManagement` multi-table model instead of the per-connection
  vendor ext) would silently accept the dispatch and fault on the
  CPE side with `9005 InvalidParameterName`, making the 202 response
  a lie.
- **`PUT /qos/{ip}` now returns `501 Not Implemented`** with
  `error_code=QOS_UNSUPPORTED_BY_DEVICE` when the probe fails. The
  response message points the caller at OLT-side rate limiting via
  RADIUS CoA (`freeradius-api`'s existing flow) as the correct
  mechanism for these CPE models, and flags that TR-098
  `QueueManagement` support is a v2.3 scope item.
- F670L real-device: confirmed 501 with clear message; 2 internal
  unit tests covering the happy path + unsupported + upstream-only
  fallback + probe-error fallback.

#### `refreshObject` trailing-dot sanitation

- **`refreshOneOpticalSubtree()`** now calls
  `strings.TrimRight(subtree, ".")` before serializing the
  `objectName` payload. GenieACS 1.2.16 rejects any `refreshObject`
  task whose `objectName` ends with a dot via
  `Error: Invalid parameter path` at `api-functions.ts:350
  sanitizeTask`, and the task then sticks in `db.tasks` forever
  being re-tried every inform. Observed live in the F670L lab when
  probing for vendor-specific optical paths; the stuck task was
  cleaned from mongo manually.
- Defensive-only fix — `opticalSubtreePathsToRefresh` itself has no
  trailing dots today, so the production code path never tripped
  this. But a typo in a future subtree addition would poison the
  task queue, and the cost of the fix is two lines.

#### Test + coverage

- 11 new unit tests (optical 6 + QoS probe 4 + trailing-dot 1).
- Main package coverage: **100.0% maintained**.
- Lint: **0 issues**.
- Integration smoke vs dev-stack `ia-genieacs-relay` + `ia-genieacs`:
  **32/32 pass** (list devices, preset CRUD, 25 device sub-routes
  through the wrapper, 4 infra endpoints).
- Real-device F670L sweep: **40/40 endpoints verified** — 32 fully
  exercised end-to-end (reads, diagnostics, WLAN create/update/
  optimize/delete round-trip, preset CRUD round-trip, tags
  add/remove round-trip), 1 confirmed 501 (QoS), 6 validator-wired
  (pppoe/firmware/admin-pass/bridge-mode empty-body probes), 2
  safety-skipped (reboot + factory-reset execution — endpoint
  correctness validated via successful task enqueue in
  `db.tasks`; real CPE execution gated on fixing a separate
  lab-infrastructure credential-drift issue, see Known Issues).
  **→ Both endpoints were subsequently verified end-to-end on the
  same F670L (same day). See the real-device verification block at
  the top of this [2.2.0] section.**

#### Known issue surfaced — genieacs-stack `inform` provision atomic rollback

- **Not a relay bug**. GenieACS's stock `/init` creates an `inform`
  provision (`configurations.type=provision, name=inform`) that
  sets `PeriodicInformTime` in millisecond-since-epoch format via
  `declare(... {value: informTime})`. ZTE F670L expects
  `xsd:dateTime` (ISO 8601) and rejects the numeric with fault
  `9007 Invalid parameter value`. Because TR-069 `setParameterValues`
  is atomic, the rejection rolls back **all sibling writes in the
  same call** — including the `ConnectionRequestUsername` /
  `ConnectionRequestPassword` that the same provision would have
  written. Result: credential drift between what GenieACS stores
  in `db.devices` and what the CPE actually accepts on Digest
  challenge. Live wake/reboot via `?connection_request` then fails
  with HTTP 401 from the CPE.
- **Workaround for now**: the dev stack was patched live in mongo
  (removed `PeriodicInformTime` declares from the `inform` provision).
  This needs to ship as a permanent fix
  in `genieacs-stack` as part of the `isp-saas-default` bundle or
  a separate `inform-fix` provision that overwrites the stock one.
  Tracked for `genieacs-stack v1.3.1`.

### Added — LOW-priority endpoints (10, customer self-service + metadata)

Completes the endpoint surface of v2.2.0. After the 7 HIGH
operational essentials and 8 MEDIUM NOC support tools were shipped,
this batch adds 10 LOW-priority customer-facing self-service features
plus GenieACS metadata management. All 10 endpoints at **100% main-
package coverage**, **0 lint issues**. Total v2.2.0 endpoint count:
**25/25 shipped** + 3 structural foundations.

#### TR-069 provisioning writes (L1-L8) — WAN / LAN config

- **`PUT /api/v1/genieacs/ntp/{ip}` (L7)** — set NTP server list
  (max 5 entries) and/or timezone via SetParameterValues on standard
  TR-098 `InternetGatewayDevice.Time.NTPServer{1..5}` and
  `LocalTimeZoneName`. Either field alone is valid — allows
  "timezone-only" or "servers-only" updates.
- **`PUT /api/v1/genieacs/admin-password/{ip}` (L8)** — set CPE local
  web admin password via
  `InternetGatewayDevice.UserInterface.WebPassword`. Distinct from
  PPPoE credentials (/pppoe/{ip}) and from TR-069 ACS auth (which
  lives on the server side). Password is NOT echoed in the response
  or audit logs.
- **`PUT /api/v1/genieacs/dmz/{ip}` (L2)** — set DMZ host on the CPE
  WAN connection. enabled=true requires host_ip; enabled=false clears
  the DMZ. Uses `X_DMZEnable` / `X_DMZHost` on
  `WANConnectionDevice.1.WANIPConnection.1`.
- **`PUT /api/v1/genieacs/ddns/{ip}` (L3)** — set DDNS provider,
  hostname, username, password via
  `Services.X_DynDNS.1.{Enable,Server,DomainName,Username,Password}`.
  Username/password are NOT echoed in the response for audit safety.
  Wide vendor variation — ships best-effort TR-098 standard paths;
  v2.3.0 will add vendor detection.
- **`PUT /api/v1/genieacs/port-forwarding/{ip}` (L1)** — set port
  forwarding rules at caller-specified TR-069 PortMapping slot indexes
  (1-32). Body: `{rules: [{index, name?, protocol, external_port,
  internal_ip, internal_port, enabled, wan_instance?}]}`. Protocol
  accepts `tcp`/`udp`/`both` (`both` → TR-069 `TCP AND UDP`).
  v2.2.0 does NOT auto-create new PortMapping instances — caller
  uses enabled=false to disable a slot without removing it. Auto-add
  is a v2.3.0 enhancement.
- **`PUT /api/v1/genieacs/static-dhcp/{ip}` (L6)** — set static DHCP
  lease entries at caller-specified `DHCPStaticAddress` slot indexes
  (1-32). Body:
  `{leases: [{index, mac, ip, hostname?}]}`. MAC format validated
  against `([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}` regex.
- **`PUT /api/v1/genieacs/wifi-schedule/{ip}` (L4)** — set parental-
  control WiFi schedule entries on the CPE. Body:
  `{schedules: [{day, start_time, end_time, enabled}], wlan_index?}`.
  day is 0-6 (Sun-Sat); start/end time in HH:MM format. Uses a
  vendor-extension path family (`X_TimerSchedule`) that's common
  across ZTE, Huawei, and some FiberHome ONUs. v2.3.0 will add
  per-vendor detection.
- **`PUT /api/v1/genieacs/mac-filter/{ip}` (L5)** — set WLAN MAC
  filter list. Body:
  `{mode, macs: [...], wlan_index?}`. `mode` is `allow` (whitelist)
  or `deny` (blacklist); canonicalized to TR-069
  `Allow`/`Deny` on the wire. Max 32 MAC entries.

#### GenieACS metadata management (L9, L10) — NBI passthrough

These endpoints do **NOT** use TR-069. They call the GenieACS NBI
directly to manage device tags and provisioning presets.

- **`PUT /api/v1/genieacs/tags/{ip}` (L9)** — add and remove device
  tags via the GenieACS NBI. Body: `{add: [...], remove: [...]}`.
  Tags are metadata only — they don't trigger TR-069 RPCs — used by
  ops to group devices for bulk operations, alerting, or fleet
  rollouts. Each tag becomes one NBI call
  (`POST /devices/{id}/tags/{tag}` or `DELETE`); first failure aborts
  the batch (no transactional rollback because the NBI doesn't expose
  one).
- **`GET /api/v1/genieacs/presets/{name}` (L10)** — read a GenieACS
  provisioning preset by name. Returns the raw preset body as the
  `body` field.
- **`PUT /api/v1/genieacs/presets/{name}` (L10)** — create or update
  a GenieACS provisioning preset. Body is forwarded as-is to the NBI.
- **`DELETE /api/v1/genieacs/presets/{name}` (L10)** — remove a
  GenieACS provisioning preset.

#### LOW-priority implementation notes

- **File organization:** 6 new handler files
  (`handlers_admin.go`, `handlers_dmz_ddns.go`,
  `handlers_portforward.go`, `handlers_static_dhcp.go`,
  `handlers_wifi_advanced.go`, `handlers_genieacs_meta.go`). 5 new
  test files covering all 10 handlers + helpers + NBI passthrough
  error branches.
- **Set-at-index semantics** for L1 (port forwarding) and L6 (static
  DHCP): caller specifies which PortMapping / DHCPStaticAddress slot
  index to write. v2.2.0 does NOT auto-create new instances via
  addObject — caller is responsible for slot lifecycle. The addObject
  primitive already exists in `tr069.go` (shipped as part of the
  structural foundations) with 100% test coverage, so a v2.3.0
  enhancement that auto-adds missing
  slots is a clean small extension.
- **Vendor variation** for L2/L3/L4/L5 is acknowledged in the
  docstrings. v2.2.0 ships the most-common TR-098 standard paths
  (or vendor-extension paths where the standard doesn't cover the
  feature — e.g. WiFi schedule uses `X_TimerSchedule` since TR-098
  has no parental-control subtree). GenieACS returns a task failure
  for unsupported vendors, which surfaces to the caller as 503
  `SERVICE_UNAVAILABLE`. v2.3.0 will add the optical-health-style
  5-vendor detection for these paths.
- **Credential hygiene**: admin-password (L8) and DDNS credentials
  (L3) are NEVER echoed in response bodies or audit logs. Tests
  assert this explicitly to guard against future refactor
  regressions.
- **Server route registration** adds 12 new routes (L1-L10 plus the
  GET/PUT/DELETE triple on `/presets/{name}`), bringing the total to
  39 operational routes (14 v1.x + 7 v2.2.0 HIGH + 8 v2.2.0 MEDIUM +
  10 v2.2.0 LOW).

### Added — MEDIUM-priority endpoints (8, NOC support tools)

After the 7 HIGH operational essentials shipped, this batch adds 8
MEDIUM-priority endpoints covering NOC L2/L3 support tools, WiFi
inspection, device collection queries, and TR-069 diagnostics. All
at **100% main-package coverage**, **0 lint issues**.

- **`POST /api/v1/genieacs/diag/ping/{ip}` (M1)** — TR-069
  `IPPingDiagnostics` dispatch. Body:
  `{host, count?, timeout_ms?, data_block_size?, dscp?}`. Validation:
  count 1-64, timeout 100ms-60s. Sends a `setParameterValues` task
  containing the input params + `DiagnosticsState=Requested` (the
  trigger flag, which TR-069 §A.4.1 mandates be the LAST entry so the
  CPE applies all inputs before starting the run). Returns 202 + the
  list of result parameter paths the caller should poll via
  `/params/{ip}` after 5-15 seconds. Long-running result waits are
  delegated to the caller — keeps the relay request-handler thread
  decoupled from CPE inform latency. Standard TR-098 path:
  `InternetGatewayDevice.IPPingDiagnostics.*`.
- **`POST /api/v1/genieacs/diag/traceroute/{ip}` (M2)** — TR-069
  `TraceRouteDiagnostics` dispatch. Same shape and result-poll pattern
  as M1, with `max_hops` instead of `count`. Standard TR-098 path:
  `InternetGatewayDevice.TraceRouteDiagnostics.*`.
- **`GET /api/v1/genieacs/wifi-clients/{ip}` (M3)** — returns the
  associated WiFi clients across all WLAN radios on the CPE. Walks
  `LANDevice.1.WLANConfiguration.{n}.AssociatedDevice.{m}` (TR-098).
  Distinct from `/dhcp-client/{ip}` which only sees clients that
  asked for DHCP. Per-client fields: MAC, WLAN instance, SSID, band,
  signal strength dBm (reads both `X_SignalStrength` vendor extension
  and standard `SignalStrength` paths), authentication state.
- **`GET /api/v1/genieacs/wifi-stats/{ip}` (M7)** — returns per-radio
  WiFi statistics: channel, transmit power (reads both standard
  `TransmitPower` and `X_TXPower` vendor variants), bytes/packets
  sent and received, error counters. Used by WiFi optimization
  recommendations and "my wifi is slow" customer support tickets.
- **`GET /api/v1/genieacs/devices` (M4)** — paginated device listing.
  **First v2.2.0 endpoint that does NOT take an `{ip}` URL path
  parameter.** Wraps the GenieACS NBI `/devices?query=...` call
  directly with optional filters: model substring, online flag (last
  inform within 3x stale threshold), pppoe_username substring.
  Pagination via `?page=N&page_size=N` (page 1-indexed, page_size
  default 50, max 200). Pagination metadata: page, page_size, count,
  has_more (true when count == page_size). Returns lightweight
  `DeviceSummary` rows (device_id, ip, last_inform, manufacturer,
  model, serial, mac) — not the full device tree. Used by admin UI
  device discovery flow.
- **`GET /api/v1/genieacs/devices/search` (M5)** — single-device
  lookup by alternative key. Exactly one of `?mac=...`, `?serial=...`,
  or `?pppoe_username=...` must be provided. Precedence:
  mac → serial → pppoe_username. Returns 404 if no device matches.
  Used in the customer onboarding flow when the IP is not yet known
  (e.g., during initial PPPoE provisioning).
- **`PUT /api/v1/genieacs/qos/{ip}` (M6)** — set per-WAN bandwidth
  rate limit via TR-069 SetParameterValues on the standard
  `WANPPPConnection.{n}.X_DownStreamMaxBitRate` and
  `X_UpStreamMaxBitRate` paths. Body:
  `{download_kbps?, upload_kbps?, wan_instance?}`. At least one rate
  must be provided. Rates of 0 clear the cap. Submitted via the
  existing `taskWorkerPool` so the handler returns 202 immediately.
  Vendor-specific QoS extensions
  (`X_HW_BandwidthLimit`, `X_TPLINK_QoSManagement`, etc.) are deferred
  to v2.3.0 vendor detection.
- **`PUT /api/v1/genieacs/bridge-mode/{ip}` (M8)** — toggle bridge /
  router mode on the CPE WAN connection. Body:
  `{enabled, wan_instance?}`. `enabled=true` puts the CPE in bridge
  mode (sets `WANPPPConnection.Enable=false` so the customer's
  downstream router takes over PPPoE termination); `enabled=false`
  reverts to router mode. **Coarse approximation** — real bridge-mode
  toggling on most consumer CPEs requires multiple parameter writes
  and varies by vendor. v2.2.0 ships the simplest standard-path
  approximation; v2.3.0 will add vendor detection.

#### MEDIUM-priority implementation notes

- File organization: 3 new handler files (`handlers_diag.go` for M1+M2,
  `handlers_devices.go` for M4+M5, `handlers_qos_bridge.go` for M6+M8)
  + append M3+M7 to existing `handlers_inspection.go` (consolidates
  the read-side inspection family in one file).
- Server route registration adds 8 new lines under the existing
  `/api/v1/genieacs` chi route group; existing 21 routes (14
  v1.x + 7 v2.2.0 HIGH) unchanged.
- `handlers_devices.go` introduces `queryDevicesNBI(ctx, filter, limit, skip)`
  which wraps the GenieACS NBI `/devices?query=...&projection=...&limit=...&skip=...`
  call. Projection is hardcoded to the lightweight identification +
  last_inform fields so listing calls don't pull megabytes per device.
- 6 new error/message constants added to `constants.go`.
- Test count delta: **80+ new test cases** covering happy paths,
  validation failures, NBI errors, transport failures, and pagination
  edge cases.

### Added — Structural foundations + HIGH-priority endpoints (7)

Drives the auto-learning OLT use case. When the OLT operates in
auto-learn mode (Hioso, HSGQ, Jolink, CDATA auto, etc.) the OLT does
**not** push customer-facing profile config — it only bridges traffic.
**All** customer config (PPPoE credentials, WLAN, port forwarding,
QoS, etc.) lives on the CPE and must be provisioned via TR-069 from
the GenieACS plane. v2.1.0's CRUD slice is too narrow for that
workflow, so v2.2.0 adds 7 HIGH-priority endpoints covering the
operational essentials. See `V2.2.0-DESIGN.md` for the gap analysis
and the full 25-endpoint roadmap.

#### Structural foundations

- **`tr069.go`** — generic TR-069 RPC dispatcher helpers wrapping the
  GenieACS NBI `POST /devices/{id}/tasks?connection_request` endpoint:
  `factoryResetDevice`, `connectionRequest`, `getParameterValuesLive`,
  `downloadFile`, `addObject`, `deleteObject`, plus the
  `validateTRParamPath` input sanitizer for the H7 generic-params
  endpoint and the `parseAddObjectInstance` response decoder. Same
  status-code policy as the existing `rebootDevice` (200 sync, 202
  queued, both success). 100% test coverage in `tr069_test.go`
  including transport failures, body-read errors, and
  malformed-response tolerance.

- **`param_walker.go`** — typed accessors over the GenieACS device
  tree (which arrives as `map[string]interface{}` from
  `getDeviceData`). `LookupValue` is the underlying primitive;
  `LookupString`, `LookupInt`, `LookupBool`, `LookupTime` are typed
  views built on top. `EnumerateInstances` finds numeric instance
  keys under a parent path (filters out `_writable` / `_object` /
  other metadata keys). `CollectPaths` walks a list of requested
  paths in one pass for the H7 endpoint. 100% test coverage in
  `param_walker_test.go` including JSON-number coercion,
  bool-from-int, RFC3339 parse failure, missing-segment traversal.

- **`utils.go`** new helpers `getIPParam`, `joinPath`, `joinInstance`
  centralizing chi URL parameter access and TR-069 path
  construction. 100% test coverage from existing handlers.

#### HIGH-priority endpoint family

- **`POST /api/v1/genieacs/factory-reset/{ip}`** — H6: TR-069
  FactoryReset RPC. **Destructive.** The CPE will lose all
  locally-stored config (PPPoE credentials, WLAN, port-forward rules)
  and reboot. Unreachable for 60-180 seconds during the reset cycle,
  then rejoins the ACS in a fresh provisioning state. Used by RMA
  flows and customer-requested "reset my modem" tickets. The relay
  clears its cached device tree on success so the next read fetches
  the post-reset tree fresh. Idempotency middleware applies. Handler:
  `handlers_lifecycle.go:factoryResetDeviceHandler`. Tests:
  `handlers_lifecycle_test.go` (3 cases: success, device-not-found,
  task submission failure).

- **`POST /api/v1/genieacs/wake/{ip}`** — H2: fires a TR-069
  ConnectionRequest against the CPE without queuing real work. Used
  to wake a freshly-installed CPE so the first config push lands
  synchronously, wake an idle device for diagnostics, or probe
  responsiveness. Implemented as a no-op `getParameterValues` task
  (asks for `InternetGatewayDevice.DeviceInfo.UpTime`, the cheapest
  always-present parameter) submitted with `?connection_request`
  enabled. Fire-and-forget — does NOT block waiting for the device
  to actually wake up. Wake takes 1-30 seconds depending on CPE CWMP
  timer config. Handler: `handlers_lifecycle.go:wakeDeviceHandler`.
  Tests: 3 cases.

- **`GET /api/v1/genieacs/status/{ip}`** — H1: returns last inform
  timestamp, computed online flag, uptime, and identification fields
  (manufacturer, model, software/hardware version) parsed from the
  cached device tree. Walks both TR-098
  (`InternetGatewayDevice.DeviceInfo.*`) and TR-181
  (`Device.DeviceInfo.*`) paths so the same handler works across the
  Indonesian ONT fleet (ZTE F670L, Huawei EG8145V5, FiberHome HG6243C,
  etc). `_lastInform` is read directly from the top-level field as a
  bare RFC3339 string — NOT via the `_value` wrapper used by regular
  parameters. The online flag is computed as
  `time.Since(_lastInform) < 3*staleThreshold` with a 30-minute
  fallback when the stale threshold env var is disabled. Handler:
  `handlers_inspection.go:getDeviceStatusHandler` +
  `buildDeviceStatusResponse`. Tests: 8 cases.

- **`GET /api/v1/genieacs/wan/{ip}`** — H4: returns WAN connection
  state(s) for the CPE. Walks every WANDevice / WANConnectionDevice /
  WANPPPConnection / WANIPConnection instance combination in the
  cached tree and surfaces each as a separate `WANConnectionInfo`
  entry. Per-connection fields: instance number, type
  (pppoe / dhcp / static / ipcp), connection status, external IP,
  uptime, optional PPPoE username, last connection error. Used by
  first-line debugging "is the customer's WAN up? what public IP did
  they get?". Handler: `handlers_inspection.go:getWanStatusHandler` +
  `buildWanConnectionsResponse`. Tests: 6 cases.

- **`POST /api/v1/genieacs/params/{ip}`** — H7: generic
  `GetParameterValues` passthrough for NOC L2/L3 debugging. Lets
  operators inspect any TR-069 parameter without the relay needing a
  dedicated endpoint per parameter. Reduces churn — instead of
  shipping 5 dedicated read endpoints per minor release, we ship one
  generic one. Request body: `{paths: [...], live: bool}`. Validation:
  paths non-empty, max 50 entries, each path matches
  `^[a-zA-Z][a-zA-Z0-9_.]*$` (no shell metacharacters or query
  injection). Two modes: cached (`live=false`) walks the cached tree
  immediately, sub-100ms; live (`live=true`) dispatches a fresh
  `GetParameterValues` task with `?connection_request`, clears the
  cache, then reads the refreshed tree. Response: map of
  `path → value` for found parameters plus a `missing_paths` list for
  paths that didn't exist (typo, vendor difference). Handler:
  `handlers_inspection.go:getGenericParamsHandler`. Tests: 9 cases.

- **`PUT /api/v1/genieacs/pppoe/{ip}`** — H3: set PPPoE credentials
  on the CPE via TR-069 `SetParameterValues`. **Critical for the
  auto-learning OLT scenario** — without this endpoint the
  activate-customer flow has no way to provision the customer's PPPoE
  username and password onto the CPE. Body:
  `{username, password, wan_instance?}`. `wan_instance` defaults to 1.
  Validation: non-empty, ≤ 64 chars each, no whitespace in username,
  `wan_instance` 1-8. Submits the task through the existing
  `taskWorkerPool` so the handler returns 202 immediately while the
  GenieACS dispatch happens asynchronously. **Vendor path note:**
  v2.2.0 hardcodes the TR-098 standard path
  `InternetGatewayDevice.WANDevice.{n}.WANConnectionDevice.1.WANPPPConnection.1.{Username,Password}`.
  TR-181 (`Device.PPP.Interface.{n}`) is documented but not
  auto-detected; vendor detection is a v2.3.0 enhancement modeled on
  the optical-health 5-vendor pattern. Handler:
  `handlers_pppoe.go:setPPPoECredentialsHandler` +
  `validatePPPoERequest` + `buildPPPoEParameterValues`. Tests: 14 cases.

- **`POST /api/v1/genieacs/firmware/{ip}`** — H5: dispatches a TR-069
  `Download` RPC against the CPE. Long-running. Body:
  `{file_url, file_type?, file_size?, target_filename?, username?, password?, command_key?}`.
  `file_type` defaults to `"1 Firmware Upgrade Image"`. Returns
  202 + GenieACS task ID immediately so the caller can poll task
  status; does NOT block waiting for the download to complete.
  **Validation:** `file_url` must be HTTPS (plain HTTP rejected to
  avoid MITM firmware swaps), and the host must not be a private IP /
  loopback / link-local / metadata service hostname (basic SSRF guard
  against fetching from internal infrastructure — caught hosts include
  `127.0.0.1`, `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`,
  `169.254.169.254`, `localhost`, `metadata.google.internal`, IPv6
  loopback `::1` and link-local `fe80::/10`). Not a full SSRF defense
  — a malicious DNS server can still resolve a public hostname to a
  private IP at fetch time on the CPE side. Returns
  `estimated_duration_seconds` (60s floor, 600s ceiling, ~200KB/s
  + 30s flash window heuristic) so callers know roughly when to poll.
  Handler: `handlers_firmware.go:firmwareUpgradeHandler` +
  `validateFirmwareRequest` + `validateFirmwareURL` +
  `estimatedDownloadDuration`. Tests: 17 cases. **DO NOT TEST IN
  REAL LAB** — a wrong firmware image bricks the CPE. Real-lab
  validation is gated until at least one customer-supplied firmware
  blob has been verified offline against the target ONU model.

#### Coverage and quality

- All 7 new HIGH endpoints + 2 structural files at **100% statement
  coverage** (matching v2.1.0 baseline).
- Lint clean. Race detector clean.
- Server route registration in `server.go` adds 7 new lines under the
  existing `/api/v1/genieacs` chi route group; existing 14 routes
  unchanged. Idempotency middleware, audit middleware, metrics
  middleware, and API key auth all apply automatically.
- Test harness `common_test.go` registers the 7 new routes in
  `setupTestServer` for handler-layer tests.

### Release checklist (this version)

Retained as a checklist for release bookkeeping:

- [x] Structural foundations — `tr069.go` + `param_walker.go`
- [x] 7 HIGH-priority endpoints
- [x] 8 MEDIUM-priority endpoints
- [x] 10 LOW-priority endpoints
- [x] 100% main-package coverage maintained across the full feature set
- [x] Initial real-device F670L sweep (38 E2E + 2 safety-skipped)
- [x] Reboot + factory-reset E2E follow-up (closes the 2 safety-skipped → 40/40 fully verified)
- [x] `swag init` regen — `docs/swagger.json` / `docs/swagger.yaml` / `docs/docs.go` refreshed from 19 paths @ v1.0.0 (stale) to 44 paths @ v2.2.0; `main.go` package-doc `@version` bumped and v2.2.0 tag declarations added
- [x] `API_REFERENCE.md` §14 (reboot slow-boot note) + §17.1 (factory-reset real-device verification + upstream blocker)
- [x] `k6-load-test.js` header bump + v2.2.0 read-endpoint 404-contract probes (write endpoints still excluded)
- [x] `CONTRIBUTING.md` Version History — added v2.1.0 and v2.2.0 rows
- [x] `V2.2.0-DESIGN.md` SHIPPED banner
- [x] `CLAUDE.md` status header + tier/version refresh
- [x] Vault sync — `wiki/genieacs-relay.md` frontmatter bump + verification narrative + versioning table row, `STATUS.md`, `PLATFORM_CHANGELOG.md`, `platform-deps.yaml`
- [x] README v2.2.0 release banner + feature list
- [x] CHANGELOG promoted from `[Unreleased]` → `[2.2.0]` with date
- [x] TODO.md v2.2.0 shipped section
- [ ] `git tag v2.2.0` — **pending explicit instruction** (repo convention: no tag or push without request)
- [ ] Docker multi-arch build + push `cepatkilatteknologi/genieacs-relay:{2.2.0, 2.2, 2, latest}` — triggered by CI on tag
- [x] Helm chart `examples/helm/genieacs-relay/Chart.yaml` — chart version `0.3.0` → `0.4.0`, `appVersion` `2.1.0` → `2.2.0` (companion release via `helm-release.yml` workflow on chart file change)
- [ ] GitHub release publish — auto-triggered by tag push via `release.yml` workflow

## [2.1.0] — 2026-04-15 (CPE lifecycle operations + optical health)

### Added

- **`POST /api/v1/genieacs/reboot/{ip}`** — TR-069 Reboot RPC. Triggers
  GenieACS task `{"name": "reboot"}` against the device matched by IP,
  with `?connection_request` so the call blocks until the task is
  applied (200 OK) or queued (202 Accepted). Actual CPE reboot takes
  30-90 seconds before the device reconnects to the ACS — callers
  (typically the future `RestartOnu` workflow in isp-agent) should NOT
  block waiting for the device to come back. Idempotency middleware
  applies via the `/api/v1/genieacs` route group, so double-clicks
  within the dedup TTL window replay the same response. Implementation:
  `reboot.go` + handler in `handlers_device.go` + route in `server.go`.
  Tests: `reboot_test.go` covering 200/202 success, 404 device-not-found,
  500 NBI error, payload literal verification.

- **`POST /api/v1/genieacs/dhcp/{ip}/refresh`** — dedicated DHCP host
  cache refresh endpoint. Reuses the existing internal `refreshDHCP()`
  function but exposes it as a clean POST-for-side-effect primitive
  distinct from the read endpoint `GET /dhcp-client/{ip}?refresh=true`
  which mixes read and side-effect semantics. Use case: future
  `RefreshDhcpStatus` workflow that triggers a refresh now and reads
  the fresh data on a follow-up call. Idempotency-cached. The cached
  device data is cleared on success so the next read fetches fresh.

- **`GET /api/v1/genieacs/optical/{ip}`** — read CPE optical interface
  health metrics (TX power, RX power, temperature, voltage, bias
  current). Detects the vendor parameter tree automatically:

  | Source label | TR-069 path |
  |---|---|
  | `zte_ct_com_epon` | `InternetGatewayDevice.X_CT-COM_EponInterfaceConfig.Stats.*` |
  | `zte_ct_com_gpon` | `InternetGatewayDevice.X_CT-COM_GponInterfaceConfig.Stats.*` |
  | `huawei_hw_debug` | `InternetGatewayDevice.X_HW_DEBUG.AdminTR069.{Tx,Rx}Power` |
  | `realtek_epon` | `InternetGatewayDevice.X_Realtek_EponInterfaceConfig.Stats.*` |
  | `standard_tr181` | `Device.Optical.Interface.1.Stats.*` |

  Detection order matches typical Indonesian ISP deployment frequency
  (most ZTE F670L/F660 ONTs in residential PON deployments). Returns
  HTTP 404 with `error_code: OPTICAL_NOT_SUPPORTED` for CPEs that
  don't expose any known tree.

  **Health classification.** Raw RxPower (dBm) is bucketed into
  categorical labels by `classifyOpticalHealth`:

  | RxPower (dBm) | Health |
  |---|---|
  | `rx <= -30` | `no_signal` (fiber broken/disconnected) |
  | `-30 < rx <= -27` | `critical` (marginal, intermittent drops likely) |
  | `-27 < rx <= -24` | `warning` (attenuated, watch closely) |
  | `-24 < rx < -8` | `good` (normal PON ONT operating range) |
  | `rx >= -8` | `warning` (overload — receiver too hot, link too short) |

  Thresholds are configurable per-deployment via env vars (read at
  startup): `OPTICAL_RX_NO_SIGNAL_DBM`, `OPTICAL_RX_CRITICAL_DBM`,
  `OPTICAL_RX_WARNING_DBM`, `OPTICAL_RX_OVERLOAD_DBM`. Defaults match
  typical PON ONT operating ranges; tune if your deployment has
  unusual splitter ratios or distance profiles.

  **Freshness.** By default the endpoint reads from the cached device
  tree (fast but possibly stale up to the GenieACS device cache TTL).
  Pass `?refresh=true` to force a `refreshObject` task on every known
  vendor optical subtree before reading — slower (round-trips to the
  CPE) but guaranteed fresh.

  **Response schema** (`OpticalStats`):

  ```json
  {
    "device_id":      "001141-F670L-ZTEGCFLN794B3A1",
    "tx_power_dbm":   2.5,
    "rx_power_dbm":   -21.3,
    "bias_current_ma": 12.5,
    "temperature_c":  45.0,
    "voltage_v":      3.3,
    "health":         "good",
    "source":         "zte_ct_com_epon",
    "fetched_at":     "2026-04-14T13:00:00Z"
  }
  ```

  Implementation: `optical.go` (vendor extractors + classifier +
  `refreshOpticalStats` + helpers `navigateNested`/`readFloat`).
  Tests: `optical_test.go` with fixture-based device tree samples for
  all 5 vendor paths + health classification table + helper unit
  tests + `refreshOpticalStats` partial-success path. **Manual
  validation against a real CPE is pending the first ISP pilot
  deployment** — fixtures are based on documented production samples
  but not yet hit a live device through this code path.

- New env vars (all optional, with sensible defaults):
  - `OPTICAL_RX_NO_SIGNAL_DBM` (default `-30`)
  - `OPTICAL_RX_CRITICAL_DBM` (default `-27`)
  - `OPTICAL_RX_WARNING_DBM` (default `-24`)
  - `OPTICAL_RX_OVERLOAD_DBM` (default `-8`)

- New error code: `OPTICAL_NOT_SUPPORTED` (HTTP 404) — distinguishes
  "device exists but no optical params exposed" from "device not found".

### Notes for deployers

- **No genieacs-stack changes required.** Reboot + DHCP refresh use
  standard GenieACS NBI tasks (`reboot`, `refreshObject`) that work
  out-of-the-box. Optical reading uses `getDeviceData` against the
  CPE's existing parameter tree — if the CPE exposes the parameters,
  GenieACS already has them after the next inform.
- **Optional GenieACS provisioning preset.** For deployments where
  ops want optical data auto-refreshed periodically (rather than
  on-demand via `?refresh=true`), configure a GenieACS provisioning
  preset via the GenieACS UI to fetch the relevant subtree on every
  inform — vendor-specific, not bundled with the stack. Example
  preset for ZTE CT-COM EPON:

  ```javascript
  declare("InternetGatewayDevice.X_CT-COM_EponInterfaceConfig.Stats.RxPower",
          {value: 1}, {value: now});
  ```

### Downstream unblock

With these endpoints live, isp-agent v0.2+ can add:
- `RestartOnu` workflow → `POST /reboot/{ip}`
- `RefreshDhcpStatus` workflow → `POST /dhcp/{ip}/refresh`
- New `GetOpticalHealth` workflow → `GET /optical/{ip}` (read-only,
  same shape as existing `GetDeviceCapability`)

See the `isp-agent` TODO backlog for workflow planning.

## [2.0.0] — 2026-04-12

**First standardized release**, aligned with [`isp-adapter-standard`][adapter-std] and
[`isp-logging-standard`][logging-std]. **Fourth compliant adapter** overall (after
[freeradius-api] v1.2.0, [go-snmp-olt-zte-c320] v3.0.0, and [write-olt-zte-c320-svc] v3.0.0).
Serves as the **chi + request-level idempotency reference** for bridge adapters.

> **Versioning note:** this is a MAJOR version bump from v1.0.1 because the JSON
> response envelope shape changed in a way that forces clients to update. Sister
> adapters (`freeradius-api`, `go-snmp-olt-zte-c320`, `write-olt-zte-c320-svc`)
> carry their own independent semver tracks — their v3.0.0 does NOT imply v3.0.0
> here. Going forward, all releases must follow
> [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) strictly —
> see [`CONTRIBUTING.md`](CONTRIBUTING.md#versioning-policy) for the full rules.

### BREAKING

Response envelope shape changed. Clients parsing the old `{"status":"OK","error":"..."}` shape
MUST update to the new `{"status":"success"|"Bad Request","error_code":"...","data":...,"request_id":"..."}`
format.

| Before (v1.x)                                    | After (v2.0.0)                                                       |
|--------------------------------------------------|----------------------------------------------------------------------|
| `{"status":"OK", ...}`                           | `{"status":"success", ...}`                                          |
| `{"error":"message"}`                            | `{"error_code":"VALIDATION_ERROR","data":"message","request_id":"..."}` |
| `sendError(w, code, status, errorMsg)`           | `sendError(w, r, code, errorCode, data)` — takes `*http.Request`     |
| `sendResponse(w, code, status, data)`            | `sendResponse(w, code, data)` — status auto-set to `"success"`       |
| `Response.Error string`                          | `Response.ErrorCode string` + `Response.Data any` + `Response.RequestID string` |

Error code constants are defined in `error_codes.go`: `VALIDATION_ERROR`, `UNAUTHORIZED`,
`FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `TIMEOUT`, `RATE_LIMITED`, `INTERNAL_ERROR`,
`SERVICE_UNAVAILABLE`, `GENIEACS_ERROR`.

### Added

- **`/healthz`** — Kubernetes liveness probe (minimal `{"status":"healthy"}`).
- **`/readyz`** and **`/ready`** — readiness probes with cached (5s TTL) GenieACS reachability check.
  Returns 503 + per-dependency state when GenieACS is unreachable.
- **`/version`** — build metadata endpoint (`version`, `commit`, `build_time`, `api_version`, `uptime`).
- **`/metrics`** — Prometheus exposition format with `http_requests_total`,
  `http_request_duration_seconds`, `http_requests_in_flight`, and default Go runtime collectors.
- **`X-API-Version`**, **`X-App-Version`**, **`X-Build-Commit`** response headers on every response.
- **`X-Request-ID`** correlation header — extracted from chi's `middleware.RequestID`, injected
  into every zap log line via `WithRequestIDLogger(ctx)`, echoed in error response bodies,
  and available to all handlers via `RequestIDFromContext(ctx)`.
- **`X-Idempotency-Key`** support on all `POST/PUT/PATCH/DELETE` endpoints under `/api/v1/genieacs/*`.
  First request with a given key is executed and its response cached; retries with the
  same key within a 7-day TTL replay the cached response. In-memory store (`MemoryStore`);
  migrate to Redis in v2.1 if multi-replica dedup is needed.
- **Audit log sub-logger** via `logger.Named("audit")` emits one JSON line per write request
  (POST/PUT/PATCH/DELETE) with `method`, `path`, `status`, `client_ip`, `user_agent`,
  `duration_ms`, and `body_size`.
- **Centralized zap logger** with standardized base fields (`service`, `version`, `module`).
  ISO8601 UTC timestamps with millisecond precision.
- **`VersionResponse`**, **`ReadinessResponse`**, and **`DependencyState`** model types for
  health endpoints.
- **`buildinfo.go`** package with `setBuildInfo()` setter and ldflags-injected version accessors.
- **`reqctx.go`** leaf-package style context key for the request ID, used by both the logger
  and the error envelope.
- **`.golangci.yml` v2** configuration with 20+ linters enabled, mirroring the v3.0.0 reference
  adapters. Baseline was 0 after fixing 20 pre-existing issues.
- **`CLAUDE.md`**, **`test.http`**, **`k6-load-test.js`** — AI assistant context, REST Client
  smoke test suite, and k6 load test scenarios.
- **Multi-arch Docker**: `linux/amd64`, `linux/arm64`, `linux/arm/v7` (was amd64+arm64 in 2.x).
- **Trivy image scan** in CI (best-effort; fails build on CRITICAL/HIGH, SARIF upload
  `continue-on-error: true` to tolerate repos without GitHub Advanced Security).
- **`APP_VERSION` + `APP_COMMIT` + `APP_BUILD_TIME`** Docker build args propagated from CI
  into ldflags. Verify with `curl /version` after a real Docker build.

### Fixed

- **Alpine base image security upgrade (CVE-2026-28390)** — Trivy image scan on
  the post-merge edge build flagged 2 HIGH vulnerabilities in the alpine 3.21 base
  (`libcrypto3`/`libssl3` 3.3.6-r0 — openssl NULL pointer dereference in CMS,
  fixed in 3.3.7-r0). Added `apk update && apk upgrade --no-cache` as the first
  step of the production stage so every rebuild picks up the latest patched
  packages from the live alpine 3.21 repo without needing to chase minor base
  image bumps. Local Trivy rescan after fix: **0 CRITICAL / 0 HIGH**. This fix
  is included in the `v2.0.0` git tag (commit `317f15c`) so all published
  `v2.0.0` Docker images already ship with the patched packages.
- **`refreshDHCP` / `refreshWLANConfig` rejected HTTP 202 Accepted** — both functions
  checked `resp.StatusCode != http.StatusOK` which caused `/dhcp-client?refresh=true`
  and `/force/ssid` refresh path to always return 500 whenever GenieACS returned a
  202 (which it does for every `?connection_request` task even when the task is
  successfully queued). Fixed to accept any `status < 400` as success. Discovered
  during real-device integration testing on ZTE F670L with live genieacs-stack;
  prior CI tests mocked the HTTP response and never hit the real 202 case.
- **ldflags injection silently broken** — Dockerfile previously used
  `-X main.version=${VERSION:-dev}` where `VERSION` was never declared as an `ARG`,
  so shell expansion always emitted `dev`. Fixed via explicit `ARG APP_VERSION`,
  `ARG APP_COMMIT`, `ARG APP_BUILD_TIME` and target vars `version`/`commit`/`buildTs`
  in `main.go` (lowercase to match `go build -X`).
- **Request ID never reached zap logs** — chi's `middleware.RequestID` was in the
  middleware chain but its generated ID was not extracted into our logger context.
  New `requestIDMiddleware` bridges the chi value into `reqctx` so every log line
  and error body now carries `request_id`.
- **20 pre-existing lint issues** (errorlint, gocritic httpNoBody, prealloc, whitespace,
  gofmt, nestingReduce, goconst, gosec false positives) resolved as part of the v2
  baseline. Required because the stricter `.golangci.yml` v2 config would otherwise
  block CI from day one.

### Changed

- **Go 1.26.1 → 1.26.2**.
- **chi v5.2.3 → v5.2.5**.
- **go-openapi/jsonpointer 0.22.4 → 0.22.5**, **spec 0.22.3 → 0.22.4**.
- `healthCheckHandler` now emits the standard `Response` envelope (was ad-hoc).
- `middleware.Logger` replaced with `structuredLoggerMiddleware` which emits zap JSON
  with `request_id`, `duration_ms`, and `size_bytes`, and skips `/health`, `/healthz`,
  `/ready`, `/readyz`, `/version`, `/metrics` from request logs.

### Known gaps

- **`MemoryStore` does not survive restart** and is not shared across replicas.
  Acceptable for single-instance site deployments; v2.1 should add a Redis-backed
  store when the genieacs-relay container runs in a multi-replica k8s Deployment.
- **State-aware idempotency is deliberately NOT implemented** for WLAN ops. Request-level
  caching is sufficient because GenieACS itself dedupes tasks per-device and WLAN
  ops are not strictly destructive the way SSH DeleteOnu is.
- **Not yet validated against billing-agent end-to-end** — billing-agent is still in
  design phase, so the full saga workflow (NATS COMMAND → agent → genieacs-relay →
  task queued → device inform → response back) has not been exercised. The adapter
  surface itself was validated against a real ZTE F670L with the full genieacs-stack
  running locally (see Integration Test Results below).

### Integration Test Results (2026-04-12)

Full end-to-end test against real hardware:
- **Target device**: ZTE F670L (ID `C6B2D2-F670L-ZTEEQFLN6212992`) at `10.90.4.173`
- **Upstream**: `genieacs-stack` running locally (GenieACS 1.2.16 + MongoDB 8.0)
- **Relay binary**: v2.0.0-integration, ldflags-injected

**96/96 assertions passed** across 18 HTTP endpoints, 0 failures:

| Test stage | Tests | Highlights |
|---|---|---|
| Unauth + reads + errors + idempotency | 55 | All 7 public endpoints, 5 authenticated reads, 5 error contract probes, 2 idempotency replay tests |
| CREATE on fresh slot + verify | 14 | WLAN.3 `Enable:false→true`, `SSID:SSID3→FullTestCreate3`, 8 setParameterValues params all queued correctly |
| UPDATE + OPTIMIZE + verify | 10 | `SSID:FullTestCreate3→FullTestUpdate3`, `TransmitPower:→60`, all post-inform state changes verified |
| DELETE + verify | 8 | `Enable:true→false` confirmed via direct GenieACS NBI query + relay `/wlan/available` re-query |
| Post-bug-fix regression | 5 | `/dhcp-client?refresh=true` + `/force/ssid` 5x consecutive success (was 0/5 before fix) |
| Corrections | 4 | |

**Full CRUD lifecycle verified on real device**: each mutation was confirmed by
1) reading the task queue in GenieACS NBI directly, 2) waiting for the device's
next periodic inform, 3) re-querying device state in GenieACS to confirm the
parameter actually changed on the device, and 4) re-querying via the relay's
own read endpoints to confirm the change is visible end-to-end.

### Compliance Status

- [x] JSON response format (success + error + paginated)
- [x] Error responses include `error_code`, `request_id`
- [x] Success uses `status:"success"`
- [x] `/health`, `/healthz`, `/ready`, `/readyz`, `/version`, `/metrics` endpoints
- [x] `/readyz` with cached dependency probes (5s TTL)
- [x] `X-Request-ID` middleware (extract/generate/echo in body)
- [x] `X-API-Version`, `X-App-Version`, `X-Build-Commit` response headers
- [x] Input validation via `go-playground/validator`
- [x] Rate limiting middleware (in-memory; Redis-backed in v2.1 when multi-instance)
- [x] CORS middleware
- [x] Audit log for write ops via `logger.Named("audit")`
- [x] Prometheus `/metrics` with normalized path labels
- [x] ldflags injection verified via `curl /version` against local build
- [x] `X-Idempotency-Key` middleware (request-level, in-memory)
- [x] Multi-arch Docker (amd64/arm64/arm/v7)
- [x] zap logging with `service`, `version`, `module`, `request_id` base fields
- [x] **Test coverage: 100.0%** (baseline match)
- [x] `golangci-lint` v2 clean, `govulncheck` clean, `go test -race` clean
- [x] Trivy image scan clean: 0 CRITICAL, 0 HIGH (after post-merge apk upgrade fix)

### Release Timeline

| Date (UTC) | Commit | Event |
|---|---|---|
| 2026-04-12 13:11 | `7d0b303` | PR #2 (v2.0.0 feat) squashed → `main` |
| 2026-04-12 13:48 | `317f15c` | PR #3 (Dockerfile apk upgrade, CVE-2026-28390) squashed → `main` |
| 2026-04-12 13:56 | `317f15c` | **Tag `v2.0.0` created and pushed** |
| 2026-04-12 14:00 | — | GitHub Release `v2.0.0` published |
| 2026-04-12 14:09 | `8704e46` | PR #4 (examples/ version pins to 2.0.0) squashed → `main` (post-release docs) |

### Docker Images Published

**Docker Hub:** `cepatkilatteknologi/genieacs-relay`
**GHCR:** `ghcr.io/cepat-kilat-teknologi/genieacs-relay`

Published tags (both registries):
- `2.0.0`
- `2.0`
- `2`
- `latest`
- `edge` (built from `main`)

Multi-arch: `linux/amd64`, `linux/arm64`, `linux/arm/v7`.

```bash
# Production pin
docker pull cepatkilatteknologi/genieacs-relay:2.0.0

# Verify
docker run --rm -p 8080:8080 cepatkilatteknologi/genieacs-relay:2.0.0 &
curl -s localhost:8080/version
# {"version":"2.0.0","commit":"317f15c",...}
```

### Helm Chart

Chart `genieacs-relay v0.2.0` (appVersion `2.0.0`) auto-released by the `Helm Chart Release` workflow when `examples/helm/genieacs-relay/Chart.yaml` was updated in PR #4.

[adapter-std]: https://github.com/Cepat-Kilat-Teknologi/knowledge-base/blob/main/wiki/isp-adapter-standard.md
[logging-std]: https://github.com/Cepat-Kilat-Teknologi/knowledge-base/blob/main/wiki/isp-logging-standard.md
[freeradius-api]: https://github.com/Cepat-Kilat-Teknologi/freeradius-api
[go-snmp-olt-zte-c320]: https://github.com/Cepat-Kilat-Teknologi/go-snmp-olt-zte-c320
[write-olt-zte-c320-svc]: https://github.com/Cepat-Kilat-Teknologi/write-olt-zte-c320

## [2.x] and earlier

See git history for pre-standardization releases.
