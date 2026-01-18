package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- GenieACS Client Tests ---

func TestRefreshDHCP(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		err := refreshDHCP(ctx, mockDeviceID)
		assert.NoError(t, err)
	})
	t.Run("Non-OK Status", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		err := refreshDHCP(ctx, mockDeviceID)
		assert.Error(t, err)
	})
}

func TestGetDeviceIDByIP_ErrorCases(t *testing.T) {
	ctx := context.Background()
	t.Run("Server Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})
	t.Run("Unmarshal Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid-json"))
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})
	t.Run("Empty Array", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[]"))
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})
}

func TestPostJSONRequest_ErrorCases(t *testing.T) {
	ctx := context.Background()
	t.Run("Unmarshallable body", func(t *testing.T) {
		_, err := postJSONRequest(ctx, "http://dummyurl", make(chan int))
		assert.Error(t, err)
	})
	t.Run("Invalid URL", func(t *testing.T) {
		_, err := postJSONRequest(ctx, "://invalid", nil)
		assert.Error(t, err)
	})
}

func TestSetParameterValues_Success(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	err := setParameterValues(ctx, mockDeviceID, nil)
	assert.NoError(t, err)
}

func TestRefreshWLANConfig_Success(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	err := refreshWLANConfig(ctx, mockDeviceID)
	assert.NoError(t, err)
}

func TestGetDeviceIDByIP_ReadAllError(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestGetDeviceIDByIP_ExtraCases(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestRefreshWLANConfig_ExtraCases(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	err := refreshWLANConfig(ctx, mockDeviceID)
	assert.Error(t, err)
}

func TestRefreshDHCP_ExtraCases(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	err := refreshDHCP(ctx, mockDeviceID)
	assert.Error(t, err)
}

func TestGetDeviceData_Success(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	data, err := getDeviceData(ctx, mockDeviceID)
	assert.NoError(t, err)
	assert.NotNil(t, data)
}

func TestGetDeviceIDByIP_Success(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockDeviceResponseWithLastInform()))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	deviceID, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.NoError(t, err)
	assert.Equal(t, mockDeviceID, deviceID)
}

func TestGetDeviceIDByIP_StaleDevice(t *testing.T) {
	ctx := context.Background()

	// Save original staleThreshold
	originalThreshold := staleThreshold
	defer func() { staleThreshold = originalThreshold }()

	// Set stale threshold to 10 minutes so the 2020 date will be considered stale
	staleThreshold = 10 * time.Minute

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := []map[string]interface{}{
			{
				"_id":         mockDeviceID,
				"_lastInform": "2020-01-01T00:00:00.000Z",
			},
		}
		data, _ := json.Marshal(response)
		_, _ = w.Write(data)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stale")
}

func TestGetDeviceData_Non200(t *testing.T) {
	ctx := context.Background()
	originalBaseURL := geniesBaseURL
	defer func() { geniesBaseURL = originalBaseURL }()

	// Clear cache to force network request
	deviceCacheInstance.clearAll()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceData(ctx, mockDeviceID)
	assert.Error(t, err)
}

func TestGetDeviceIDByIP_NoID(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"_lastInform": "2099-01-01T00:00:00.000Z"}]`))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	deviceID, err := getDeviceIDByIP(ctx, mockDeviceIP)
	// Returns empty string without error when _id is missing
	assert.NoError(t, err)
	assert.Equal(t, "", deviceID)
}

func TestRefreshWLANConfig_AllPaths(t *testing.T) {
	ctx := context.Background()
	t.Run("non-ok status", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		err := refreshWLANConfig(ctx, mockDeviceID)
		assert.Error(t, err)
	})
}

func TestGetDeviceIDByIP_EmptyArray(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestRefreshWLANConfig_ErrorStatus(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	err := refreshWLANConfig(ctx, mockDeviceID)
	assert.Error(t, err)
}

func TestRefreshDHCP_ErrorPath(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	err := refreshDHCP(ctx, mockDeviceID)
	assert.Error(t, err)
}

func Test_getDeviceData_Error(t *testing.T) {
	ctx := context.Background()
	originalBaseURL := geniesBaseURL
	defer func() { geniesBaseURL = originalBaseURL }()

	// Clear cache to force network request
	deviceCacheInstance.clearAll()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	_, err := getDeviceData(ctx, mockDeviceID)
	assert.Error(t, err)
}

func Test_getDeviceIDByIP_Error(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func Test_refreshWLANConfig_Error(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	err := refreshWLANConfig(ctx, mockDeviceID)
	assert.Error(t, err)
}

func Test_refreshDHCP_Error(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	err := refreshDHCP(ctx, mockDeviceID)
	assert.Error(t, err)
}

func TestGetDeviceIDByIP_UnmarshalError(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"_id": "test", "_lastInform": invalid}]`))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestGetDeviceIDByIP_ReadBodyError(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestGetDeviceIDByIPEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("HTTP Client Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		geniesBaseURL = mockServer.URL
		mockServer.Close()
		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})

	t.Run("Non-OK Status with Body", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error": "access denied"}`))
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})

	t.Run("Missing _id field in response", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_lastInform": "2099-01-01T00:00:00.000Z", "someField": "value"}]`))
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		deviceID, err := getDeviceIDByIP(ctx, mockDeviceIP)
		// The function returns empty deviceID when _id is missing, not an error
		assert.NoError(t, err)
		assert.Equal(t, "", deviceID)
	})

	t.Run("_id field is not string", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"_id": 12345, "_lastInform": "2099-01-01T00:00:00.000Z"}]`))
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		_, err := getDeviceIDByIP(ctx, mockDeviceIP)
		assert.Error(t, err)
	})
}

func TestGetDeviceIDByIPNonOKStatus(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "bad request"}`))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "returned non-OK status")
}

func TestGetDeviceIDByIPInvalidJSON(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not a json`))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestGetDeviceIDByIPHTTPClientError(t *testing.T) {
	ctx := context.Background()

	originalClient := httpClient
	httpClient = &http.Client{
		Transport: &failingTransport{},
	}
	defer func() { httpClient = originalClient }()

	geniesBaseURL = "http://localhost:12345"
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestSetParameterValuesErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("HTTP Client Error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		geniesBaseURL = mockServer.URL
		mockServer.Close()
		err := setParameterValues(ctx, mockDeviceID, [][]interface{}{{"param", "value", "type"}})
		assert.Error(t, err)
	})

	t.Run("Non-OK Status", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		err := setParameterValues(ctx, mockDeviceID, [][]interface{}{{"param", "value", "type"}})
		assert.Error(t, err)
	})
}

func TestSetParameterValuesMoreErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("Request body error with failing transport", func(t *testing.T) {
		originalClient := httpClient
		httpClient = &http.Client{
			Transport: &failingTransport{},
		}
		defer func() { httpClient = originalClient }()

		geniesBaseURL = "http://localhost:12345"
		err := setParameterValues(ctx, mockDeviceID, [][]interface{}{{"param", "value", "type"}})
		assert.Error(t, err)
	})
}

func TestSetParameterValuesBodyReadError(t *testing.T) {
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	geniesBaseURL = mockServer.URL

	err := setParameterValues(ctx, mockDeviceID, [][]interface{}{{"param", "value", "type"}})
	assert.NoError(t, err)
}

func TestPostJSONRequest_ExtraCases(t *testing.T) {
	ctx := context.Background()
	t.Run("Server returns error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockServer.Close()
		resp, err := postJSONRequest(ctx, mockServer.URL, map[string]string{"key": "value"})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		resp.Body.Close()
	})

	t.Run("Invalid URL", func(t *testing.T) {
		_, err := postJSONRequest(ctx, "://invalid", map[string]string{"key": "value"})
		assert.Error(t, err)
	})
}

func Test_postJSONRequest_BadPayload(t *testing.T) {
	ctx := context.Background()
	_, err := postJSONRequest(ctx, "http://dummyurl", make(chan int))
	assert.Error(t, err)
}

func TestGetDeviceIDByIPJSONMarshalError(t *testing.T) {
	ctx := context.Background()

	// Save original jsonMarshal function
	originalMarshal := jsonMarshal
	defer func() { jsonMarshal = originalMarshal }()

	// Mock jsonMarshal to return an error
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, errors.New("mock marshal error")
	}

	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

func TestGetDeviceIDByIPJSONMarshalSuccess(t *testing.T) {
	ctx := context.Background()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"_id": "test", "_lastInform": "2099-01-01T00:00:00.000Z"}]`))
	}))
	defer mockServer.Close()

	geniesBaseURL = mockServer.URL

	deviceID, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.NoError(t, err)
	assert.Equal(t, "test", deviceID)
}

// --- WLAN Data Tests ---

func TestGetWLANData_ExtraCases(t *testing.T) {
	ctx := context.Background()
	originalBaseURL := geniesBaseURL
	defer func() { geniesBaseURL = originalBaseURL }()

	// Clear cache to force network request
	deviceCacheInstance.clearAll()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	geniesBaseURL = mockServer.URL
	mockServer.Close()
	_, err := getWLANData(ctx, mockDeviceID)
	assert.Error(t, err)
}

func Test_getWLANData_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("Device data not found", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))
		defer mockServer.Close()
		geniesBaseURL = mockServer.URL
		deviceCacheInstance.clearAll()
		_, err := getWLANData(ctx, mockDeviceID)
		assert.Error(t, err)
	})

	t.Run("InternetGatewayDevice not found", func(t *testing.T) {
		deviceData := map[string]interface{}{}
		deviceCacheInstance.set("test-no-igd", deviceData)
		_, err := getWLANData(ctx, "test-no-igd")
		assert.Error(t, err)
	})
}

func TestGetWLANData_Success(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[" + mockDeviceDataJSON + "]"))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	deviceCacheInstance.clearAll()
	wlanData, err := getWLANData(ctx, mockDeviceID)
	assert.NoError(t, err)
	assert.NotEmpty(t, wlanData)
}

func TestGetWLANData_DisabledOrMalformed(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": false},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-disabled-wlan", deviceData)
	result, err := getWLANData(ctx, "test-disabled-wlan")
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestGetWLANData_DisabledAndMalformed(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": "not-a-map",
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-malformed", deviceData)
	_, err := getWLANData(ctx, "test-malformed")
	assert.NoError(t, err)
}

func TestGetWLANData_LANDeviceMissing(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{},
	}
	deviceCacheInstance.set("test-no-landevice", deviceData)
	_, err := getWLANData(ctx, "test-no-landevice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LANDevice")
}

func TestGetWLANData_SortInvalidKeys(t *testing.T) {
	ctx := context.Background()

	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"abc": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "TestSSID"},
						},
						"2": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "TestSSID2"},
						},
						"1": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "TestSSID1"},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-sort-keys", deviceData)
	wlanData, err := getWLANData(ctx, "test-sort-keys")
	assert.NoError(t, err)
	// All enabled WLANs are included (numeric keys sorted first, then non-numeric)
	assert.Len(t, wlanData, 3)
}

func TestGetWLANData_NonNumericKeys(t *testing.T) {
	ctx := context.Background()

	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"a": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "SSID-A"},
						},
						"3": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "SSID-3"},
						},
						"z": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "SSID-Z"},
						},
						"1": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "SSID-1"},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-non-numeric", deviceData)
	wlanData, err := getWLANData(ctx, "test-non-numeric")
	assert.NoError(t, err)
	// All enabled WLANs are included (numeric keys sorted first, then non-numeric alphabetically)
	assert.Len(t, wlanData, 4)
}

func TestGetWLANData_DeviceNotFound(t *testing.T) {
	ctx := context.Background()
	deviceCacheInstance.clearAll()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	_, err := getWLANData(ctx, "non-existent-device")
	assert.Error(t, err)
}

func TestGetWLANData_NoInternetGatewayDevice(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{}
	deviceCacheInstance.set("test-no-igd", deviceData)
	_, err := getWLANData(ctx, "test-no-igd")
	assert.Error(t, err)
}

func TestGetWLANData_NoWLANConfig(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{},
			},
		},
	}
	deviceCacheInstance.set("test-no-wlan", deviceData)
	wlanData, err := getWLANData(ctx, "test-no-wlan")
	assert.NoError(t, err)
	assert.Empty(t, wlanData)
}

func TestGetWLANData_NoLANDevice1(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{},
		},
	}
	deviceCacheInstance.set("test-no-landevice1", deviceData)
	_, err := getWLANData(ctx, "test-no-landevice1")
	assert.Error(t, err)
}

func TestGetWLANData_MissingEnable(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{
							"SSID": map[string]interface{}{"_value": "TestSSID"},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-no-enable", deviceData)
	wlanData, err := getWLANData(ctx, "test-no-enable")
	assert.NoError(t, err)
	assert.Empty(t, wlanData)
}

func TestGetWLANData_MissingSSID(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-no-ssid", deviceData)
	wlanData, err := getWLANData(ctx, "test-no-ssid")
	assert.NoError(t, err)
	if len(wlanData) > 0 {
		// When SSID field is missing, the actual code returns empty string
		assert.Equal(t, "", wlanData[0].SSID)
	}
}

func TestGetWLANData_InvalidEntryType(t *testing.T) {
	ctx := context.Background()

	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": "invalid-type",
						"2": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
							"SSID":   map[string]interface{}{"_value": "ValidSSID"},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-invalid-entry", deviceData)
	wlanData, err := getWLANData(ctx, "test-invalid-entry")
	assert.NoError(t, err)
	assert.Len(t, wlanData, 1)
}

// --- DHCP Clients Tests ---

func TestGetDHCPClients_Success(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"Hosts": map[string]interface{}{
						"Host": map[string]interface{}{
							"1": map[string]interface{}{
								"IPAddress":  map[string]interface{}{"_value": "192.168.1.100"},
								"MACAddress": map[string]interface{}{"_value": "AA:BB:CC:DD:EE:FF"},
								"HostName":   map[string]interface{}{"_value": "TestHost"},
							},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-dhcp-clients", deviceData)
	clients, err := getDHCPClients(ctx, "test-dhcp-clients")
	assert.NoError(t, err)
	assert.Len(t, clients, 1)
	assert.Equal(t, "192.168.1.100", clients[0].IP)
}

func TestGetDHCPClients_MalformedHosts(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"Hosts": map[string]interface{}{
						"Host": map[string]interface{}{
							"1": "not-a-map",
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-malformed-hosts", deviceData)
	clients, err := getDHCPClients(ctx, "test-malformed-hosts")
	assert.NoError(t, err)
	assert.Empty(t, clients)
}

func TestGetDHCPClients_InvalidHosts(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"Hosts": map[string]interface{}{
						"Host": "invalid-type",
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-invalid-hosts", deviceData)
	clients, err := getDHCPClients(ctx, "test-invalid-hosts")
	assert.NoError(t, err)
	assert.Empty(t, clients)
}

func TestGetDHCPClients_InternetGatewayMissing(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{}
	deviceCacheInstance.set("test-no-gateway", deviceData)
	_, err := getDHCPClients(ctx, "test-no-gateway")
	assert.Error(t, err)
}

func TestGetDHCPClients_LANDevice1Missing(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{},
		},
	}
	deviceCacheInstance.set("test-no-landevice1-dhcp", deviceData)
	_, err := getDHCPClients(ctx, "test-no-landevice1-dhcp")
	assert.Error(t, err)
}

// --- isWLANValid Tests ---

func TestIsWLANValid_OutOfRange(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": true},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-wlan-range", deviceData)
	valid, err := isWLANValid(ctx, "test-wlan-range", "99")
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestIsWLANValid_ExtraCases(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{}
	deviceCacheInstance.set("test-wlan-extra", deviceData)
	_, err := isWLANValid(ctx, "test-wlan-extra", "1")
	assert.Error(t, err)
}

func TestIsWLANValid_Disabled(t *testing.T) {
	ctx := context.Background()
	deviceData := map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"1": map[string]interface{}{
							"Enable": map[string]interface{}{"_value": false},
							"SSID":   map[string]interface{}{"_value": "DisabledSSID"},
						},
					},
				},
			},
		},
	}
	deviceCacheInstance.set("test-wlan-disabled", deviceData)
	valid, err := isWLANValid(ctx, "test-wlan-disabled", "1")
	assert.NoError(t, err)
	// isWLANValid returns false for disabled WLANs (Enable._value = false)
	assert.False(t, valid)
}

// --- getPassword Tests ---

func TestGetPassword_XCMSKeyPassphraseEmpty(t *testing.T) {
	// Test X_CMS_KeyPassphrase with empty value
	wlanData := map[string]interface{}{
		"X_CMS_KeyPassphrase": map[string]interface{}{
			"_value": "",
		},
	}
	password := getPassword(wlanData)
	assert.Equal(t, "********", password)
}

func TestGetPassword_XCMSKeyPassphraseWithValue(t *testing.T) {
	// Test X_CMS_KeyPassphrase with actual value
	wlanData := map[string]interface{}{
		"X_CMS_KeyPassphrase": map[string]interface{}{
			"_value": "myPassword123",
		},
	}
	password := getPassword(wlanData)
	assert.Equal(t, "myPassword123", password)
}

func TestGetPassword_PreSharedKeyEmpty(t *testing.T) {
	// Test PreSharedKey.1.PreSharedKey with empty value
	wlanData := map[string]interface{}{
		"PreSharedKey": map[string]interface{}{
			"1": map[string]interface{}{
				"PreSharedKey": map[string]interface{}{"_value": ""},
			},
		},
	}
	password := getPassword(wlanData)
	assert.Equal(t, "********", password)
}

// --- setParameterValues Additional Tests ---

func TestSetParameterValuesNonOKWithBodyReadError(t *testing.T) {
	ctx := context.Background()

	// Use failingBodyTransport which returns 500 status with errorReader body
	originalClient := httpClient
	httpClient = &http.Client{
		Transport: &failingBodyTransport{},
	}
	defer func() { httpClient = originalClient }()

	geniesBaseURL = "http://localhost:12345"
	err := setParameterValues(ctx, mockDeviceID, [][]interface{}{{"param", "value", "type"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read response body")
}

func TestSetParameterValuesStatusAccepted(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	err := setParameterValues(ctx, mockDeviceID, nil)
	assert.NoError(t, err)
}

func TestSetParameterValuesNonOKStatusWithBody(t *testing.T) {
	ctx := context.Background()
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "bad request"}`))
	}))
	defer mockServer.Close()
	geniesBaseURL = mockServer.URL
	err := setParameterValues(ctx, mockDeviceID, [][]interface{}{{"param", "value", "type"}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "set parameter values failed")
}

// TestGetDeviceDataRequestCreationError tests getDeviceData when request creation fails
func TestGetDeviceDataRequestCreationError(t *testing.T) {
	ctx := context.Background()
	originalBaseURL := geniesBaseURL
	defer func() { geniesBaseURL = originalBaseURL }()

	// Clear cache to force network request
	deviceCacheInstance.clearAll()

	// Use invalid URL to cause request creation error
	geniesBaseURL = "://invalid-url"
	_, err := getDeviceData(ctx, mockDeviceID)
	assert.Error(t, err)
}

// TestGetDeviceDataJSONMarshalError tests getDeviceData when JSON marshal fails
func TestGetDeviceDataJSONMarshalError(t *testing.T) {
	ctx := context.Background()

	// Clear cache to force the marshal path
	deviceCacheInstance.clearAll()

	// Save original jsonMarshal function
	originalMarshal := jsonMarshal
	defer func() { jsonMarshal = originalMarshal }()

	// Mock jsonMarshal to return an error
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, errors.New("mock marshal error")
	}

	_, err := getDeviceData(ctx, mockDeviceID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal query")
}

// TestGetDeviceIDByIPRequestCreationError tests getDeviceIDByIP when request creation fails
func TestGetDeviceIDByIPRequestCreationError(t *testing.T) {
	ctx := context.Background()
	originalBaseURL := geniesBaseURL
	defer func() { geniesBaseURL = originalBaseURL }()

	// Use invalid URL to cause request creation error
	geniesBaseURL = "://invalid-url"
	_, err := getDeviceIDByIP(ctx, mockDeviceIP)
	assert.Error(t, err)
}

// TestGetDeviceIDByIP_InvalidIP tests getDeviceIDByIP with invalid IP format
func TestGetDeviceIDByIP_InvalidIP(t *testing.T) {
	ctx := context.Background()
	_, err := getDeviceIDByIP(ctx, "not-an-ip-address")
	assert.Error(t, err)
}
