# GenieACS Relay — Issue Tracker

> Hasil review menyeluruh codebase pada 2026-04-05.
> Total: 28 issues ditemukan.

---

## CRITICAL — Harus Segera Diperbaiki

### C-01: Go Version 1.25 Tidak Exist

- **File**: `Dockerfile:4,14`, `.github/workflows/ci.yml:19`
- **Detail**: `FROM golang:1.25-alpine` dan `GO_VERSION: '1.25'` — Go 1.25 belum dirilis. Docker build dan CI pipeline akan **gagal**.
- **Impact**: Build failure di local dan CI. Tidak bisa deploy image baru.
- **Fix**: Ganti ke `1.24` sesuai `go.mod` (`go 1.24.2`).

### C-02: Worker Pool `Start()` Tidak Pernah Dipanggil

- **File**: `main.go`, `server.go`, `worker.go`
- **Detail**: `NewWorkerPool()` dipanggil untuk inisialisasi, tetapi `Start()` yang menjalankan goroutines tidak pernah dipanggil. Worker goroutines tidak pernah berjalan.
- **Impact**: Semua task (`setParameterValues`, `applyChanges`, `refreshWLAN`) masuk channel buffer (cap: 100) tapi **tidak pernah diproses**. Setelah buffer penuh, semua task berikutnya silently dropped. Artinya semua operasi WLAN create/update/delete/optimize **tidak pernah dieksekusi** ke GenieACS. API return 200 tapi device tidak berubah — **silent data loss**.
- **Fix**: Panggil `taskWorkerPool.Start()` setelah inisialisasi di `main.go` atau `server.go`.

### C-03: Helm Secret Regeneration on Upgrade

- **File**: `examples/helm/genieacs-relay/templates/secret.yaml:20`
- **Detail**: `randAlphaNum 64 | b64enc` menghasilkan random key baru setiap kali `helm upgrade` dijalankan. Tidak ada `lookup` untuk reuse existing secret.
- **Impact**: NBI auth key dan middleware auth key berubah setiap upgrade. Semua authenticated request **gagal** setelah upgrade hingga client di-update dengan key baru.
- **Fix**: Gunakan Helm `lookup` function untuk mengecek existing secret sebelum generate baru:
  ```
  {{ $existing := lookup "v1/Secret" (include "..fullname" .) .Release.Namespace }}
  {{ if $existing }}{{ index $existing.data "nbi-auth-key" }}{{ else }}{{ randAlphaNum 64 | b64enc }}{{ end }}
  ```

---

## HIGH — Prioritas Tinggi

### H-01: Worker Tasks Silently Dropped When Queue Full

- **File**: `worker.go:85`
- **Detail**: Ketika task channel buffer (100 slots) penuh, `Submit()` masuk ke `default` case dan hanya log warning. HTTP response sudah terkirim (200) sebelum task di-submit.
- **Impact**: Caller menerima response sukses padahal operasi tidak dijalankan. Tidak ada mekanisme retry atau notification ke caller.
- **Fix**: Pertimbangkan: (1) synchronous fallback jika queue penuh, (2) return error dari `Submit()` agar handler bisa kirim 503, atau (3) perbesar buffer dengan monitoring.

### H-02: Shallow Cache Copy — Potential Data Corruption

- **File**: `cache.go:33`
- **Detail**: `deviceCache.get()` hanya melakukan single-level map copy. Nested maps (e.g., `deviceData["InternetGatewayDevice"]`) masih shared reference ke cached data.
- **Impact**: Jika caller memodifikasi nested map, cached data ikut berubah — data corruption untuk request berikutnya yang baca dari cache. Saat ini parsers hanya read, tapi ini fragile invariant tanpa enforcement.
- **Fix**: Implement deep copy (JSON marshal/unmarshal round-trip) atau gunakan copy-on-write pattern.

### H-03: WLAN ID Validation Inconsistency

- **File**: `validation.go` (`validateWLANID`), `capability.go` (`validateWLANIDForDevice`)
- **Detail**: `validateWLANID` menerima range 1–99, tetapi `validateWLANIDForDevice` hanya menerima 1–8. Outer validator loloskan nilai 9–99 yang inner validator selalu tolak.
- **Impact**: Confusing error messages — user mendapat generic error dari inner validator setelah outer validator sudah lolos. Wasted processing.
- **Fix**: Seragamkan range di `validateWLANID` ke 1–8, atau gunakan single validation point.

### H-04: Force Handler Blocking Sleep in HTTP Goroutine

- **File**: `handlers_ssid.go:157`
- **Detail**: `executeWLANRetryLoop` menggunakan `time.Sleep(retryDelay)` dalam loop (hingga 12 x 5s = 60s) di dalam HTTP handler goroutine. Context timeout 30 detik seharusnya cancel loop, tapi goroutine tetap hidup selama context window.
- **Impact**: Satu request force-refresh bisa menahan goroutine selama 30–60 detik. Pada concurrent load tinggi, bisa exhaust goroutine pool dan menyebabkan server unresponsive.
- **Fix**: Gunakan `context.Done()` channel select dengan `time.After()` untuk proper cancellation, atau pindahkan ke async pattern dengan polling endpoint.

### H-05: No WLAN 1 Deletion Protection

- **File**: `handlers_wlan.go`
- **Detail**: WLAN 1 adalah primary SSID pada sebagian besar ONU/ONT. API mengizinkan `DELETE /wlan/delete/1/{ip}` tanpa warning atau konfirmasi.
- **Impact**: User bisa tidak sengaja disable primary WiFi SSID pada device — device kehilangan konektivitas WiFi dan harus di-reset manual atau via TR-069 direct.
- **Fix**: Tambahkan guard atau warning header untuk WLAN ID 1. Opsi: tolak deletion, require force flag, atau return warning di response.

### H-06: Makefile Path Typo

- **File**: `Makefile:8`
- **Detail**: `DOCKER_COMPOSE_PROD = example/docker/docker-compose.yml` (singular `example`). Path yang benar adalah `examples/docker/docker-compose.yml` (plural).
- **Impact**: `make prod-up`, `make prod-down`, dan target production docker-compose lainnya **gagal**.
- **Fix**: Ganti `example/` ke `examples/`.

---

## MEDIUM — Perlu Diperbaiki

### M-01: HSTS Header on HTTP

- **File**: `middleware.go:452`
- **Detail**: `Strict-Transport-Security` header selalu di-set, termasuk saat service berjalan di plain HTTP (service ini tidak melakukan TLS termination).
- **Impact**: HSTS pada HTTP tidak berfungsi dan bisa menyebabkan browser memaksa HTTPS pada development/testing environment yang tidak punya TLS.
- **Fix**: Hanya set HSTS jika request datang via HTTPS (check `r.TLS != nil` atau `X-Forwarded-Proto` header).

### M-02: `getBand` Returns "Unknown" untuk WiFi N-only Standard

- **File**: `wlan.go:174`
- **Detail**: `strings.ContainsAny(std, "bg")` untuk deteksi 2.4GHz. Pure `"n"` mode pada 2.4GHz tidak mengandung `"b"` atau `"g"`, sehingga band dilaporkan `"Unknown"`.
- **Impact**: Device dengan mode WiFi N-only pada 2.4GHz menampilkan band "Unknown" di response API.
- **Fix**: Tambahkan logic untuk handle `"n"` mode berdasarkan WLAN key range (1–4 = 2.4GHz, 5–8 = 5GHz), atau gunakan WLAN key sebagai primary indicator.

### M-03: Stale Device Detection Bypass

- **File**: `client.go`
- **Detail**: Ketika `device.LastInform == nil` (device belum pernah mengirim inform), stale validation di-skip. Device dianggap selalu fresh.
- **Impact**: API bisa return data dari device yang belum pernah terhubung ke GenieACS. Data bisa stale atau default values.
- **Fix**: Treat `nil` lastInform sebagai stale (device belum pernah connect), atau return warning di response.

### M-04: `applyChanges` dan `refreshWLAN` Task Type Identik

- **File**: `worker.go:62-65`
- **Detail**: `taskTypeApplyChanges` dan `taskTypeRefreshWLAN` keduanya memanggil `refreshWLANConfig()`. Dua constant berbeda dengan behavior identik.
- **Impact**: Confusing codebase — developer bisa salah asumsi bahwa ada perbedaan behavior. Jika GenieACS mengubah API, perubahan harus diterapkan di satu tempat tapi ada dua entry point.
- **Fix**: Gabungkan ke satu task type, atau implementasikan `applyChanges` yang benar-benar memanggil GenieACS `addObject`/`setParameterValues` apply flow terpisah dari refresh.

### M-05: Alpine 3.19 Outdated di Dockerfile

- **File**: `Dockerfile`
- **Detail**: Base image production menggunakan `alpine:3.19`. Alpine 3.21 sudah tersedia.
- **Impact**: Potential unpatched CVEs pada base image. Security scanner akan flag ini.
- **Fix**: Update ke `alpine:3.21` atau latest stable.

### M-06: `go mod tidy` di Builder Stage

- **File**: `Dockerfile:20`
- **Detail**: `go mod tidy` dijalankan di builder stage. Ini bisa memodifikasi `go.mod`/`go.sum` saat build.
- **Impact**: Non-reproducible builds — output bisa berbeda tergantung waktu build dan available module versions.
- **Fix**: Hapus `go mod tidy` dari Dockerfile. Pastikan `go.mod` dan `go.sum` sudah clean sebelum commit.

### M-07: Linter Version Inconsistency

- **File**: `Makefile` (line 168) vs `.github/workflows/ci.yml`
- **Detail**: Makefile pin golangci-lint ke `v1.59.0` untuk local install. CI menggunakan `@latest`.
- **Impact**: Lint rules bisa berbeda antara local dan CI. Code yang lolos local lint bisa gagal di CI, atau sebaliknya.
- **Fix**: Pin versi yang sama di kedua tempat. Gunakan `.golangci-lint-version` file atau variable.

### M-08: No `helm lint` di Helm Release Workflow

- **File**: `.github/workflows/helm-release.yml`
- **Detail**: Workflow langsung `helm package` tanpa menjalankan `helm lint` terlebih dahulu.
- **Impact**: Chart dengan template error bisa terpublish ke Helm repository.
- **Fix**: Tambahkan `helm lint examples/helm/genieacs-relay` sebelum `helm package`.

### M-09: `git push --force` pada gh-pages Branch

- **File**: `.github/workflows/helm-release.yml:283`
- **Detail**: Workflow force-push ke `gh-pages` branch, menimpa seluruh history.
- **Impact**: Chart version lama bisa hilang dari index. User yang depend pada version lama tidak bisa download. Conventional approach menggunakan `chart-releaser-action` yang merge index.
- **Fix**: Gunakan `helm/chart-releaser-action` atau implementasikan proper index merging.

### M-10: `X-Real-IP` Header Trust

- **File**: `middleware.go:313,376`
- **Detail**: Code memvalidasi bahwa `X-Real-IP` adalah parseable IP, tapi tidak ada trusted proxy configuration. Dalam multi-hop proxy environment, attacker bisa inject header.
- **Impact**: Attacker bisa bypass rate limiting dan brute-force protection dengan spoofed IP addresses jika request melewati proxy yang tidak strip header.
- **Fix**: Implement trusted proxy list, atau gunakan chi `RealIP` middleware configuration untuk specify trusted proxies.

### M-11: Production Docker Compose Image Hardcoded

- **File**: `examples/docker/docker-compose.yml`
- **Detail**: Image di-pin ke `cepatkilatteknologi/genieacs-relay:1.0.0` — hardcoded, bukan variable.
- **Impact**: User harus manual edit file untuk setiap upgrade. Mudah lupa update.
- **Fix**: Gunakan environment variable atau `.env` file: `image: cepatkilatteknologi/genieacs-relay:${VERSION:-latest}`.

---

## LOW — Nice to Have

### L-01: `strconv.Atoi` Error Ignored di `buildChannelParams`

- **File**: `utils.go:503`
- **Detail**: `strconv.Atoi(channel)` error di-ignore dengan `_`. Upstream `ValidateWLANChannel` sudah memastikan channel valid, tapi ini code smell.
- **Impact**: Minimal — guarded oleh upstream validation. Tapi jika validation path berubah, ini bisa jadi silent bug.
- **Fix**: Handle error explicitly, atau tambahkan comment menjelaskan kenapa aman.

### L-02: Global Variables di `main.go`

- **File**: `main.go`
- **Detail**: `serverAddr`, `geniesBaseURL`, `nbiAuth`, `nbiAuthKey`, `middlewareAuth`, `authKey`, `staleThreshold`, `logger` semua package-level globals. Dependency di-pass via global state, bukan config struct.
- **Impact**: Testing lebih sulit (harus swap globals), dependency tracing tidak obvious, race condition potential jika diakses dari multiple goroutines tanpa synchronization.
- **Fix**: Kumpulkan ke config struct dan pass melalui dependency injection. Ini refactor besar, prioritas rendah.

### L-03: `loadServerConfig` Redundant Zero Values

- **File**: `server.go:135-140`
- **Detail**: Struct literal menginisialisasi `rateLimitRequests` dan `rateLimitWindow` ke 0, lalu langsung di-override. Minor dead-code smell.
- **Impact**: Tidak ada impact fungsional. Readability saja.
- **Fix**: Hapus zero-value fields dari struct literal, atau langsung assign parsed values.

### L-04: `curl` di Production Image

- **File**: `Dockerfile`
- **Detail**: `curl` di-install di production image hanya untuk HEALTHCHECK. Menambahkan ~3.5 MB dan network-capable binary ke hardened image.
- **Impact**: Sedikit memperbesar attack surface dan image size.
- **Fix**: Gunakan Go-based healthcheck binary, `wget` (sudah ada di BusyBox), atau Kubernetes liveness probe sebagai pengganti Docker HEALTHCHECK.

### L-05: `docker/build-push-action@v5` Outdated

- **File**: `.github/workflows/ci.yml`
- **Detail**: Menggunakan v5, sedangkan v6 sudah tersedia.
- **Impact**: Tidak ada breaking issue, tapi v6 mungkin punya bugfix dan improvements.
- **Fix**: Update ke `@v6`.

### L-06: No Benchmark Tests

- **File**: Seluruh codebase
- **Detail**: `make test-bench` terdefinisi di Makefile, tapi tidak ada benchmark function (`func BenchmarkXxx`) di test files manapun.
- **Impact**: Tidak bisa mengukur performance regressions secara automated.
- **Fix**: Tambahkan benchmark tests untuk hot paths: `getDeviceData`, `getWLANData`, `validateIP`, rate limiter `Allow()`.

### L-07: `models_test.go` Kosong

- **File**: `models_test.go`
- **Detail**: Hanya berisi comment bahwa struct tests dicakup oleh integration tests. Tidak ada direct test.
- **Impact**: Struct serialization/deserialization tidak di-test secara explicit. Edge cases (nil fields, zero values) bisa terlewat.
- **Fix**: Tambahkan basic serialization round-trip tests, atau hapus file jika memang tidak diperlukan.

### L-08: `cache_test.go` Incomplete

- **File**: `cache_test.go`
- **Detail**: Hanya test `set()`/`get()` happy path dan TTL expiry. Tidak ada test untuk `clearAll()`, `clear(deviceID)`, atau concurrent access.
- **Impact**: Cache clearing bugs dan race conditions tidak terdeteksi oleh tests.
- **Fix**: Tambahkan test untuk clear operations dan concurrent goroutine access patterns.

### L-09: Helm `values.yaml` — `pullPolicy: Always` dengan Semver Tags

- **File**: `examples/helm/genieacs-relay/values.yaml`
- **Detail**: `image.pullPolicy: Always` meskipun production menggunakan semver-pinned tags.
- **Impact**: Unnecessary image pulls pada setiap pod restart. Sedikit memperlambat startup dan menambah registry load.
- **Fix**: Ubah default ke `IfNotPresent` untuk pinned tags. User bisa override jika pakai `latest`.

### L-10: Helm Chart — No `helm test` Hook

- **File**: `examples/helm/genieacs-relay/templates/`
- **Detail**: Tidak ada test Pod dengan `helm.sh/hook: test` annotation. `helm test <release>` adalah no-op.
- **Impact**: Tidak bisa memverifikasi deployment health via Helm.
- **Fix**: Tambahkan test Pod yang hit `/health` endpoint.

### L-11: IPv6 Partial Support

- **File**: `validation.go`, `client.go`
- **Detail**: `validateIP` menerima IPv6, tapi GenieACS query hanya search IPv4 fields (`WANPPPConnection.1.ExternalIPAddress`, `WANPPPConnection.2.ExternalIPAddress`). IPv6 device hanya match via `summary.ip`.
- **Impact**: IPv6 device lookup mungkin gagal jika `summary.ip` tidak mengandung IPv6 address yang di-query.
- **Fix**: Tambahkan IPv6 WAN connection fields ke query, atau reject IPv6 di validator dengan pesan jelas.

---

## Summary

| Level | Count | Status |
|-------|-------|--------|
| **CRITICAL** | 3 | Harus segera diperbaiki |
| **HIGH** | 6 | Prioritas tinggi |
| **MEDIUM** | 11 | Perlu diperbaiki |
| **LOW** | 11 | Nice to have |
| **Total** | **31** | — |
