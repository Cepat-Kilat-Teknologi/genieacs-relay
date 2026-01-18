package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// --- Mock Data Constants ---

const (
	mockDeviceID = "002568-BCM963268-684752"
	mockDeviceIP = "192.168.1.100"
	mockAPIKey   = "test-secret-key"
)

// mockDeviceResponseWithLastInform returns a mock device response with a recent _lastInform timestamp
func mockDeviceResponseWithLastInform() string {
	lastInform := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(`[{"_id": "%s", "_lastInform": "%s"}]`, mockDeviceID, lastInform)
}

var httpListenAndServe = http.ListenAndServe

var mockDeviceDataJSON = `
{
    "_id": "002568-BCM963268-684752",
    "InternetGatewayDevice": {
        "LANDevice": {
            "1": {
                "Hosts": {
                    "Host": {
                        "1": {
                            "IPAddress": { "_value": "192.168.1.2" },
                            "MACAddress": { "_value": "AA:BB:CC:DD:EE:FF" },
                            "HostName": { "_value": "My-Phone" }
                        }
                    }
                },
                "WLANConfiguration": {
                    "1": {
                        "Enable": { "_value": true },
                        "SSID": { "_value": "MyWiFi-2.4GHz" },
                        "Standard": { "_value": "b,g,n" },
                        "PreSharedKey": {
                            "1": {
                                "PreSharedKey": { "_value": "password123" }
                            }
                        }
                    },
                    "5": {
                        "Enable": { "_value": true },
                        "SSID": { "_value": "MyWiFi-5GHz" },
                        "Standard": { "_value": "a,n,ac" },
                        "X_CMS_KeyPassphrase": { "_value": "password5G" }
                    },
                    "2": {
                        "Enable": { "_value": false },
                        "SSID": { "_value": "Disabled-WiFi" }
                    }
                }
            }
        }
    }
}
`

// --- Test Setup Functions ---

func setupTestServer(t *testing.T, mockHandler http.Handler) (*httptest.Server, *chi.Mux) {
	mockGenieServer := httptest.NewServer(mockHandler)
	t.Cleanup(mockGenieServer.Close)

	geniesBaseURL = mockGenieServer.URL
	nbiAuthKey = "mock-nbi-key"

	originalHTTPClient := httpClient
	t.Cleanup(func() { httpClient = originalHTTPClient })

	httpClient = mockGenieServer.Client()

	taskWorkerPool = &workerPool{
		workers: 1,
		queue:   make(chan task, 10),
		wg:      sync.WaitGroup{},
	}
	taskWorkerPool.Start()
	t.Cleanup(taskWorkerPool.Stop)

	deviceCacheInstance = &deviceCache{
		data:    make(map[string]cachedDeviceData),
		timeout: 30 * time.Second,
	}

	r := chi.NewRouter()
	r.Route("/api/v1/genieacs", func(r chi.Router) {
		r.Get("/ssid/{ip}", getSSIDByIPHandler)
		r.Get("/force/ssid/{ip}", getSSIDByIPForceHandler)
		r.Post("/ssid/{ip}/refresh", refreshSSIDHandler)
		r.Get("/dhcp-client/{ip}", getDHCPClientByIPHandler)
		r.Post("/cache/clear", clearCacheHandler)
		r.Get("/capability/{ip}", getDeviceCapabilityHandler)
		r.Get("/wlan/available/{ip}", getAvailableWLANHandler)
		r.Post("/wlan/create/{wlan}/{ip}", createWLANHandler)
		r.Put("/wlan/update/{wlan}/{ip}", updateWLANHandler)
		r.Delete("/wlan/delete/{wlan}/{ip}", deleteWLANHandler)
		r.Put("/wlan/optimize/{wlan}/{ip}", optimizeWLANHandler)
	})
	r.Get("/health", healthCheckHandler)

	return mockGenieServer, r
}

// --- Mock Types ---

type errorCloser struct{}

func (ec *errorCloser) Read([]byte) (n int, err error) { return 0, io.EOF }
func (ec *errorCloser) Close() error                   { return errors.New("mock close error") }

type errorResponseWriter struct{ httptest.ResponseRecorder }

func (e *errorResponseWriter) Write([]byte) (int, error) { return 0, errors.New("mock write error") }

type errorResponseRecorder struct {
	httptest.ResponseRecorder
}

func (e *errorResponseRecorder) Write([]byte) (int, error) {
	return 0, errors.New("write error")
}

type failingTransport struct{}

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network failure")
}

type errorReader struct{}

func (e *errorReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated read error")
}

func (e *errorReader) Close() error {
	return nil
}

type failingBodyTransport struct{}

func (f *failingBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
		Status:     "500 Internal Server Error",
		Body:       &errorReader{},
	}, nil
}

// --- Config Helpers ---

func loadConfigFromEnv() {
	geniesBaseURL = getEnv("GENIEACS_BASE_URL", "http://127.0.0.1:7557")
	nbiAuthKey = getEnv("NBI_AUTH_KEY", "mock-nbi-key")
}

func loadEnv() {
	geniesBaseURL = getEnv("GENIEACS_URL", geniesBaseURL)
	nbiAuthKey = getEnv("NBI_AUTH_KEY", nbiAuthKey)
}

var newProductionFunc = zap.NewProduction

func initializeLogger() {
	var err error
	logger, err = newProductionFunc()
	if err != nil {
		log.Printf("Failed to initialize logger: %v", err)
		return
	}
	_ = logger.Sugar()
}

// --- Test Main ---

func TestMain(m *testing.M) {
	// Setup global logger for all tests
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Fatalf("Failed to create test logger: %v", err)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	if logger != nil {
		_ = logger.Sync()
	}
	os.Exit(code)
}

func init() {
	loadConfigFromEnv()
}
