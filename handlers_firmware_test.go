package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// handlers_firmware_test.go covers the v2.2.0 firmware upgrade handler
// (H5) and its helper functions validateFirmwareRequest,
// validateFirmwareURL, and estimatedDownloadDuration.
//
// The handler is intentionally NOT exercised against real devices in
// the project's e2e harness — a wrong firmware image bricks the CPE.
// All real-lab validation is gated until at least one customer-supplied
// firmware blob has been verified offline against the target ONU model.

// --- validateFirmwareURL ---

func TestValidateFirmwareURL_Valid(t *testing.T) {
	cases := []string{
		"https://firmware.example.com/zte-f670l-v9.0.11.bin",
		"https://cdn.example.com:8443/path/to/file.bin",
		"https://example.com/file?token=abc",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			assert.Equal(t, "", validateFirmwareURL(u))
		})
	}
}

func TestValidateFirmwareURL_Malformed(t *testing.T) {
	assert.Equal(t, ErrFirmwareURLMalformed, validateFirmwareURL("ht!tps://bad url with spaces"))
}

func TestValidateFirmwareURL_NotHTTPS(t *testing.T) {
	cases := []string{
		"http://firmware.example.com/file.bin",
		"ftp://firmware.example.com/file.bin",
		"file:///etc/passwd",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			assert.Equal(t, ErrFirmwareURLNotHTTPS, validateFirmwareURL(u))
		})
	}
}

func TestValidateFirmwareURL_MissingHost(t *testing.T) {
	assert.Equal(t, ErrFirmwareURLMissingHost, validateFirmwareURL("https:///path/to/file.bin"))
}

func TestValidateFirmwareURL_PrivateHost_Names(t *testing.T) {
	cases := []string{
		"https://localhost/file.bin",
		"https://Localhost/file.bin",
		"https://metadata/file.bin",
		"https://metadata.google.internal/file.bin",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			assert.Equal(t, ErrFirmwareURLPrivateHost, validateFirmwareURL(u))
		})
	}
}

func TestValidateFirmwareURL_PrivateHost_IPs(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/file.bin",        // loopback
		"https://10.0.0.1/file.bin",         // private
		"https://192.168.1.1/file.bin",      // private
		"https://172.16.5.4/file.bin",       // private
		"https://169.254.169.254/file.bin",  // link-local (AWS metadata)
		"https://0.0.0.0/file.bin",          // unspecified
		"https://[::1]/file.bin",            // IPv6 loopback
		"https://[fe80::1]/file.bin",        // IPv6 link-local
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			assert.Equal(t, ErrFirmwareURLPrivateHost, validateFirmwareURL(u))
		})
	}
}

// --- validateFirmwareRequest ---

func TestValidateFirmwareRequest_HappyPath(t *testing.T) {
	req := FirmwareUpgradeRequest{
		FileURL:  "https://firmware.example.com/x.bin",
		FileSize: 1024,
	}
	errMsg := validateFirmwareRequest(&req)
	assert.Equal(t, "", errMsg)
	assert.Equal(t, DefaultFirmwareFileType, req.FileType, "default file_type filled in")
}

func TestValidateFirmwareRequest_PreservesNonDefaultFileType(t *testing.T) {
	req := FirmwareUpgradeRequest{
		FileURL:  "https://firmware.example.com/cfg.xml",
		FileType: "3 Vendor Configuration File",
	}
	errMsg := validateFirmwareRequest(&req)
	assert.Equal(t, "", errMsg)
	assert.Equal(t, "3 Vendor Configuration File", req.FileType)
}

func TestValidateFirmwareRequest_URLRequired(t *testing.T) {
	req := FirmwareUpgradeRequest{}
	assert.Equal(t, ErrFirmwareURLRequired, validateFirmwareRequest(&req))
}

func TestValidateFirmwareRequest_NegativeFileSize(t *testing.T) {
	req := FirmwareUpgradeRequest{
		FileURL:  "https://firmware.example.com/x.bin",
		FileSize: -1,
	}
	assert.Equal(t, ErrFirmwareFileSizeNegative, validateFirmwareRequest(&req))
}

func TestValidateFirmwareRequest_CommandKeyTooLong(t *testing.T) {
	req := FirmwareUpgradeRequest{
		FileURL:    "https://firmware.example.com/x.bin",
		CommandKey: strings.Repeat("k", FirmwareCommandKeyMaxLength+1),
	}
	assert.Equal(t, ErrFirmwareCommandKeyTooLong, validateFirmwareRequest(&req))
}

func TestValidateFirmwareRequest_BadURL(t *testing.T) {
	req := FirmwareUpgradeRequest{FileURL: "http://example.com/file.bin"}
	assert.Equal(t, ErrFirmwareURLNotHTTPS, validateFirmwareRequest(&req))
}

// --- estimatedDownloadDuration ---

func TestEstimatedDownloadDuration_ZeroOrNegative(t *testing.T) {
	assert.Equal(t, 60, estimatedDownloadDuration(0))
	assert.Equal(t, 60, estimatedDownloadDuration(-1))
}

func TestEstimatedDownloadDuration_SmallFile(t *testing.T) {
	// 1 KB → way below the 60s floor → returns 60
	assert.Equal(t, 60, estimatedDownloadDuration(1024))
}

func TestEstimatedDownloadDuration_MediumFile(t *testing.T) {
	// 4 MB → 30 (flash) + 4*1024*1024/(200*1024) = 30 + 20 = 50s,
	// which is below the 60 floor → returns 60.
	assert.Equal(t, 60, estimatedDownloadDuration(4*1024*1024))
}

func TestEstimatedDownloadDuration_LargeFile(t *testing.T) {
	// 16 MB → 30 + 16*1024*1024/(200*1024) = 30 + 81 = 111s
	got := estimatedDownloadDuration(16 * 1024 * 1024)
	assert.Equal(t, 111, got)
}

func TestEstimatedDownloadDuration_HugeFile(t *testing.T) {
	// 200 MB → 30 + 200*1024*1024/(200*1024) = 30 + 1024 = 1054s,
	// capped at 600.
	assert.Equal(t, 600, estimatedDownloadDuration(200*1024*1024))
}

// --- firmwareUpgradeHandler ---

// firmwareMockHandler handles the device-id projection lookup and the
// downloadFile task submission for the happy path.
func firmwareMockHandler(downloadStatus int, taskID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("projection"), "_id") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/tasks") {
			w.WriteHeader(downloadStatus)
			if downloadStatus < 400 && taskID != "" {
				_, _ = w.Write([]byte(`{"_id": "` + taskID + `"}`))
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestFirmwareUpgradeHandler_Success(t *testing.T) {
	deviceCacheInstance.clearAll()
	_, router := setupTestServer(t, firmwareMockHandler(http.StatusOK, "task-firmware-001"))

	body := `{
		"file_url": "https://firmware.example.com/zte-f670l-v9.0.11.bin",
		"file_size": 16777216,
		"command_key": "fleet-rollout-2026-04-14"
	}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/firmware/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusAccepted, rr.Code)
	assert.Contains(t, rr.Body.String(), "task-firmware-001")
	assert.Contains(t, rr.Body.String(), "Firmware download dispatched")
}

func TestFirmwareUpgradeHandler_DeviceNotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	_, router := setupTestServer(t, mock)

	body := `{"file_url":"https://firmware.example.com/x.bin"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/firmware/192.0.2.99", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestFirmwareUpgradeHandler_BadJSON(t *testing.T) {
	_, router := setupTestServer(t, firmwareMockHandler(http.StatusOK, "x"))

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/firmware/"+mockDeviceIP, strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestFirmwareUpgradeHandler_ValidationError(t *testing.T) {
	_, router := setupTestServer(t, firmwareMockHandler(http.StatusOK, "x"))

	body := `{"file_url":"http://insecure.example.com/x.bin"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/firmware/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "https scheme")
}

func TestFirmwareUpgradeHandler_DispatchFails(t *testing.T) {
	deviceCacheInstance.clearAll()
	// downloadFile returns an error when GenieACS responds 4xx
	_, router := setupTestServer(t, firmwareMockHandler(http.StatusBadGateway, ""))

	body := `{"file_url":"https://firmware.example.com/x.bin"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/genieacs/firmware/"+mockDeviceIP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", mockAPIKey)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to dispatch firmware")
}
