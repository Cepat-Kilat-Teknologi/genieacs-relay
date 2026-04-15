package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tr069_test.go covers the generic TR-069 RPC dispatcher helpers in
// tr069.go. Tests use httptest.Server to mock the GenieACS NBI and
// assert both the request shape (URL path, query params, body JSON)
// and the response classification (success on 200/202, error on 4xx/5xx).

// withMockGenieACS wires the package-level geniesBaseURL to a fresh
// httptest.Server for the duration of one test. Returns the server so
// tests can introspect captured requests via the recorder. Mirrors the
// setupTestServer pattern in common_test.go but scoped to a single
// helper rather than a full router.
func withMockGenieACS(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	originalBase := geniesBaseURL
	originalClient := httpClient
	geniesBaseURL = srv.URL
	httpClient = srv.Client()
	t.Cleanup(func() {
		geniesBaseURL = originalBase
		httpClient = originalClient
	})
	return srv
}

// --- factoryResetDevice ---

func TestFactoryResetDevice_Success200(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/devices/")
		assert.Contains(t, r.URL.Path, "/tasks")
		assert.Contains(t, r.URL.RawQuery, "connection_request")

		body := readBody(t, r)
		assert.JSONEq(t, `{"name": "factoryReset"}`, body)

		w.WriteHeader(http.StatusOK)
	})
	err := factoryResetDevice(context.Background(), "device-001")
	assert.NoError(t, err)
}

func TestFactoryResetDevice_Success202(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	err := factoryResetDevice(context.Background(), "device-001")
	assert.NoError(t, err)
}

func TestFactoryResetDevice_4xx(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "bad task"}`))
	})
	err := factoryResetDevice(context.Background(), "device-001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factoryReset failed")
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "bad task")
}

func TestFactoryResetDevice_5xx(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := factoryResetDevice(context.Background(), "device-001")
	assert.Error(t, err)
}

func TestFactoryResetDevice_TransportFailure(t *testing.T) {
	originalBase := geniesBaseURL
	originalClient := httpClient
	geniesBaseURL = "http://127.0.0.1:1" // guaranteed connection refused
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() {
		geniesBaseURL = originalBase
		httpClient = originalClient
	})

	err := factoryResetDevice(context.Background(), "device-001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factoryReset")
}

// --- connectionRequest ---

func TestConnectionRequest_Success(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.RawQuery, "connection_request")

		body := readBody(t, r)
		assert.Contains(t, body, "getParameterValues")
		assert.Contains(t, body, "UpTime")

		w.WriteHeader(http.StatusOK)
	})
	err := connectionRequest(context.Background(), "device-001")
	assert.NoError(t, err)
}

func TestConnectionRequest_Failure(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream down"))
	})
	err := connectionRequest(context.Background(), "device-001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connectionRequest")
	assert.Contains(t, err.Error(), "503")
}

func TestConnectionRequest_TransportFailure(t *testing.T) {
	originalBase := geniesBaseURL
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() {
		geniesBaseURL = originalBase
		httpClient = originalClient
	})
	err := connectionRequest(context.Background(), "device-001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connectionRequest")
}

// --- getParameterValuesLive ---

func TestGetParameterValuesLive_Success(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, r *http.Request) {
		body := readBody(t, r)
		assert.Contains(t, body, `"name":"getParameterValues"`)
		assert.Contains(t, body, "InternetGatewayDevice.DeviceInfo.UpTime")
		assert.Contains(t, body, "InternetGatewayDevice.DeviceInfo.Manufacturer")
		w.WriteHeader(http.StatusAccepted)
	})
	err := getParameterValuesLive(context.Background(), "device-001", []string{
		"InternetGatewayDevice.DeviceInfo.UpTime",
		"InternetGatewayDevice.DeviceInfo.Manufacturer",
	})
	assert.NoError(t, err)
}

func TestGetParameterValuesLive_Failure(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("nbi error"))
	})
	err := getParameterValuesLive(context.Background(), "device-001", []string{"X.Y"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getParameterValuesLive")
	assert.Contains(t, err.Error(), "502")
}

func TestGetParameterValuesLive_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })
	err := getParameterValuesLive(context.Background(), "device-001", []string{"X.Y"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getParameterValuesLive")
}

// --- downloadFile ---

func TestDownloadFile_Success_WithTaskID(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, r *http.Request) {
		body := readBody(t, r)
		assert.Contains(t, body, `"name":"download"`)
		assert.Contains(t, body, `"fileType":"1 Firmware Upgrade Image"`)
		assert.Contains(t, body, `"url":"https://firmware.example.com/zte.bin"`)
		assert.Contains(t, body, `"fileSize":12345678`)
		assert.Contains(t, body, `"commandKey":"fleet-rollout-001"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"_id": "task-67abc1234567890abcdef123"}`))
	})
	taskID, err := downloadFile(context.Background(), "device-001", DownloadRequest{
		FileType:   "1 Firmware Upgrade Image",
		URL:        "https://firmware.example.com/zte.bin",
		FileSize:   12345678,
		CommandKey: "fleet-rollout-001",
	})
	assert.NoError(t, err)
	assert.Equal(t, "task-67abc1234567890abcdef123", taskID)
}

func TestDownloadFile_Success_EmptyBody(t *testing.T) {
	// Some GenieACS versions return an empty body on success; the
	// helper should still report success but with an empty task ID.
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	taskID, err := downloadFile(context.Background(), "device-001", DownloadRequest{
		FileType: "1 Firmware Upgrade Image",
		URL:      "https://firmware.example.com/x.bin",
	})
	assert.NoError(t, err)
	assert.Equal(t, "", taskID)
}

func TestDownloadFile_Success_MalformedBody(t *testing.T) {
	// Malformed body should also be tolerated — return empty task ID
	// instead of erroring, since the task was nominally accepted.
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not-valid-json`))
	})
	taskID, err := downloadFile(context.Background(), "device-001", DownloadRequest{
		URL: "https://firmware.example.com/x.bin",
	})
	assert.NoError(t, err)
	assert.Equal(t, "", taskID)
}

func TestDownloadFile_HTTP4xx(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"invalid task"}`))
	})
	_, err := downloadFile(context.Background(), "device-001", DownloadRequest{
		URL: "https://firmware.example.com/x.bin",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downloadFile failed")
	assert.Contains(t, err.Error(), "422")
}

func TestDownloadFile_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })
	_, err := downloadFile(context.Background(), "device-001", DownloadRequest{
		URL: "https://firmware.example.com/x.bin",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downloadFile")
}

// --- addObject ---

func TestAddObject_Success_NumericInstance(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, r *http.Request) {
		body := readBody(t, r)
		assert.Contains(t, body, `"name":"addObject"`)
		assert.Contains(t, body, `"objectName":"InternetGatewayDevice.LANDevice.1.WLANConfiguration."`)
		w.WriteHeader(http.StatusOK)
		// Instance number returned at parameterValues[0][1] as a JSON number
		_, _ = w.Write([]byte(`{"parameterValues": [["instance", 5, "xsd:unsignedInt"]]}`))
	})
	instance, err := addObject(context.Background(), "device-001",
		"InternetGatewayDevice.LANDevice.1.WLANConfiguration.")
	assert.NoError(t, err)
	assert.Equal(t, 5, instance)
}

func TestAddObject_Success_StringInstance(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"parameterValues": [["instance", "7", "xsd:string"]]}`))
	})
	instance, err := addObject(context.Background(), "device-001", "X.Y.")
	assert.NoError(t, err)
	assert.Equal(t, 7, instance)
}

func TestAddObject_Success_QueuedNoInstance(t *testing.T) {
	// Task queued (202) with no parameterValues yet → instance 0
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{}`))
	})
	instance, err := addObject(context.Background(), "device-001", "X.Y.")
	assert.NoError(t, err)
	assert.Equal(t, 0, instance)
}

func TestAddObject_Success_EmptyBody(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	instance, err := addObject(context.Background(), "device-001", "X.Y.")
	assert.NoError(t, err)
	assert.Equal(t, 0, instance)
}

func TestAddObject_HTTPError(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad object name"))
	})
	_, err := addObject(context.Background(), "device-001", "X.Y.")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "addObject failed")
}

func TestAddObject_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })
	_, err := addObject(context.Background(), "device-001", "X.Y.")
	assert.Error(t, err)
}

// --- parseAddObjectInstance ---

func TestParseAddObjectInstance_NumericFloat(t *testing.T) {
	body := []byte(`{"parameterValues": [["instance", 12, "xsd:unsignedInt"]]}`)
	assert.Equal(t, 12, parseAddObjectInstance(body))
}

func TestParseAddObjectInstance_NumericString(t *testing.T) {
	body := []byte(`{"parameterValues": [["instance", "34", "xsd:string"]]}`)
	assert.Equal(t, 34, parseAddObjectInstance(body))
}

func TestParseAddObjectInstance_NonNumericString(t *testing.T) {
	body := []byte(`{"parameterValues": [["instance", "abc", "xsd:string"]]}`)
	assert.Equal(t, 0, parseAddObjectInstance(body))
}

func TestParseAddObjectInstance_UnsupportedType(t *testing.T) {
	// nil at position [0][1] is not a recognized type
	body := []byte(`{"parameterValues": [["instance", null, "xsd:any"]]}`)
	assert.Equal(t, 0, parseAddObjectInstance(body))
}

func TestParseAddObjectInstance_NotEnoughElements(t *testing.T) {
	body := []byte(`{"parameterValues": [["instance"]]}`)
	assert.Equal(t, 0, parseAddObjectInstance(body))
}

func TestParseAddObjectInstance_EmptyParameterValues(t *testing.T) {
	body := []byte(`{"parameterValues": []}`)
	assert.Equal(t, 0, parseAddObjectInstance(body))
}

func TestParseAddObjectInstance_MalformedJSON(t *testing.T) {
	body := []byte(`{not-json`)
	assert.Equal(t, 0, parseAddObjectInstance(body))
}

// --- deleteObject ---

func TestDeleteObject_Success(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, r *http.Request) {
		body := readBody(t, r)
		assert.Contains(t, body, `"name":"deleteObject"`)
		assert.Contains(t, body, `"objectName":"InternetGatewayDevice.LANDevice.1.WLANConfiguration.5."`)
		w.WriteHeader(http.StatusOK)
	})
	err := deleteObject(context.Background(), "device-001",
		"InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.")
	assert.NoError(t, err)
}

func TestDeleteObject_Success202(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	err := deleteObject(context.Background(), "device-001", "X.Y.5.")
	assert.NoError(t, err)
}

func TestDeleteObject_HTTPError(t *testing.T) {
	withMockGenieACS(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("not allowed"))
	})
	err := deleteObject(context.Background(), "device-001", "X.Y.5.")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deleteObject failed")
	assert.Contains(t, err.Error(), "403")
}

func TestDeleteObject_TransportFailure(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &failingTransport{}}
	t.Cleanup(func() { httpClient = originalClient })
	err := deleteObject(context.Background(), "device-001", "X.Y.5.")
	assert.Error(t, err)
}

// --- validateTRParamPath ---

func TestValidateTRParamPath_Valid(t *testing.T) {
	cases := []string{
		"InternetGatewayDevice.DeviceInfo.UpTime",
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
		"Device.PPP.Interface.1.Username",
		"X",
		"X.Y_Z.A1.B2_3",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			assert.NoError(t, validateTRParamPath(p))
		})
	}
}

func TestValidateTRParamPath_Empty(t *testing.T) {
	err := validateTRParamPath("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateTRParamPath_TooLong(t *testing.T) {
	long := strings.Repeat("X.", 200) + "End"
	err := validateTRParamPath(long)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestValidateTRParamPath_StartsWithDigit(t *testing.T) {
	err := validateTRParamPath("1Device.X")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start with a letter")
}

func TestValidateTRParamPath_StartsWithDot(t *testing.T) {
	err := validateTRParamPath(".Device.X")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "start with a letter")
}

func TestValidateTRParamPath_InvalidCharacter(t *testing.T) {
	cases := map[string]rune{
		"X.Y/Z":    '/',
		"X.Y;Z":    ';',
		"X.Y'Z":    '\'',
		"X.Y\"Z":   '"',
		"X.Y$Z":    '$',
		"X.Y Z":    ' ',
		"X.Y-Z":    '-',
		"InvalidÜ": 'Ü',
	}
	for input := range cases {
		t.Run(input, func(t *testing.T) {
			err := validateTRParamPath(input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid character")
		})
	}
}

func TestValidateTRParamPath_DoubleDots(t *testing.T) {
	err := validateTRParamPath("InternetGatewayDevice..DeviceInfo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'..'")
}

// --- helpers ---

// errorBodyTransport is a test http.RoundTripper that returns a
// Response whose Body fails on Read with a simulated error. Used to
// cover the io.ReadAll error branches in downloadFile / addObject.
type errorBodyTransport struct {
	statusCode int
}

func (e *errorBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: e.statusCode,
		Status:     http.StatusText(e.statusCode),
		Body:       &errorReader{},
		Header:     make(http.Header),
	}, nil
}

func TestDownloadFile_BodyReadError(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &errorBodyTransport{statusCode: http.StatusOK}}
	t.Cleanup(func() { httpClient = originalClient })

	taskID, err := downloadFile(context.Background(), "device-001", DownloadRequest{
		URL: "https://firmware.example.com/x.bin",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downloadFile: read response")
	assert.Equal(t, "", taskID)
}

func TestAddObject_BodyReadError(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: &errorBodyTransport{statusCode: http.StatusOK}}
	t.Cleanup(func() { httpClient = originalClient })

	// Body read error on the success path → returns instance 0 with
	// no error (best-effort instance extraction).
	instance, err := addObject(context.Background(), "device-001", "X.Y.")
	assert.NoError(t, err)
	assert.Equal(t, 0, instance)
}

// readBody reads and returns the request body as a string. Used by
// the assertions above to inspect outgoing JSON task payloads.
func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	defer func() { _ = r.Body.Close() }()
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 256)
	for {
		n, err := r.Body.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf)
}
