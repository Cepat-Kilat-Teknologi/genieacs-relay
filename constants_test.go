package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTaskTypeConstants(t *testing.T) {
	assert.Equal(t, "setParameterValues", TaskTypeSetParams)
	assert.Equal(t, "applyChanges", TaskTypeApplyChanges)
	assert.Equal(t, "refreshWLAN", TaskTypeRefreshWLAN)
}

func TestLegacyTaskTypeConstants(t *testing.T) {
	// Test backward compatibility
	assert.Equal(t, TaskTypeSetParams, taskTypeSetParams)
	assert.Equal(t, TaskTypeApplyChanges, taskTypeApplyChanges)
	assert.Equal(t, TaskTypeRefreshWLAN, taskTypeRefreshWLAN)
}

func TestGenieACSPathConstants(t *testing.T) {
	assert.Equal(t, "InternetGatewayDevice", PathInternetGatewayDevice)
	assert.Equal(t, "LANDevice", PathLANDevice)
	assert.Equal(t, "WLANConfiguration", PathWLANConfiguration)
	assert.Equal(t, "Hosts", PathHosts)
	assert.Equal(t, "Host", PathHost)
}

func TestWLANPathFormats(t *testing.T) {
	assert.Contains(t, PathWLANSSIDFormat, "SSID")
	assert.Contains(t, PathWLANPasswordFormat, "PreSharedKey")
	assert.Contains(t, PathWLANConfigRefresh, "WLANConfiguration")
	assert.Contains(t, PathLANDeviceRefresh, "LANDevice")
}

func TestFieldNameConstants(t *testing.T) {
	assert.Equal(t, "_id", FieldID)
	assert.Equal(t, "_value", FieldValue)
	assert.Equal(t, "Enable", FieldEnable)
	assert.Equal(t, "SSID", FieldSSID)
	assert.Equal(t, "Standard", FieldStandard)
	assert.Equal(t, "PreSharedKey", FieldPreSharedKey)
	assert.Equal(t, "KeyPassphrase", FieldKeyPassphrase)
	assert.Equal(t, "X_CMS_KeyPassphrase", FieldXCMSPassphrase)
	assert.Equal(t, "MACAddress", FieldMACAddress)
	assert.Equal(t, "HostName", FieldHostName)
	assert.Equal(t, "IPAddress", FieldIPAddress)
}

func TestTimeoutConstants(t *testing.T) {
	assert.Equal(t, 15*time.Second, DefaultHTTPTimeout)
	assert.Equal(t, 30*time.Second, DefaultCacheTimeout)
	assert.Equal(t, 30*time.Second, DefaultShutdownTimeout)
	assert.Equal(t, 60*time.Second, DefaultRequestTimeout)
	assert.Equal(t, 30*time.Second, DefaultIdleConnTimeout)
}

func TestPoolConstants(t *testing.T) {
	assert.Equal(t, 100, DefaultMaxIdleConns)
	assert.Equal(t, 20, DefaultIdleConnsPerHost)
	assert.Equal(t, 10, DefaultWorkerCount)
	assert.Equal(t, 100, DefaultQueueSize)
}

func TestRetryConstants(t *testing.T) {
	assert.Equal(t, 12, DefaultMaxRetries)
	assert.Equal(t, 5*time.Second, DefaultRetryDelay)
	assert.Equal(t, "max_retries", QueryMaxRetries)
	assert.Equal(t, "retry_delay_ms", QueryRetryDelayMs)
	assert.Equal(t, "refresh", QueryRefresh)
	assert.Equal(t, "device_id", QueryDeviceID)
}

func TestBandConstants(t *testing.T) {
	assert.Equal(t, "2.4GHz", Band2_4GHz)
	assert.Equal(t, "5GHz", Band5GHz)
	assert.Equal(t, "Unknown", BandUnknown)
}

func TestPasswordConstants(t *testing.T) {
	assert.Equal(t, "********", PasswordMasked)
	assert.Equal(t, "N/A", PasswordNA)
}

func TestVendorConstants(t *testing.T) {
	assert.Equal(t, "ZTE", VendorZTE)
	assert.Equal(t, "ZT", VendorZT)
}

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, "OK", StatusOK)
	assert.Equal(t, "Accepted", StatusAccepted)
	assert.Equal(t, "Not Found", StatusNotFound)
	assert.Equal(t, "Bad Request", StatusBadRequest)
	assert.Equal(t, "Internal Server Error", StatusInternalError)
	assert.Equal(t, "Timeout", StatusTimeout)
}

func TestErrorMessageConstants(t *testing.T) {
	assert.Equal(t, "Invalid JSON format", ErrInvalidJSON)
	assert.Equal(t, "SSID value required", ErrSSIDRequired)
	assert.Equal(t, "Password value required", ErrPasswordRequired)
	assert.Equal(t, "Could not verify WLAN status.", ErrWLANValidationFailed)
	assert.Contains(t, ErrOperationTimeout, "timed out")
}

func TestSuccessMessageConstants(t *testing.T) {
	assert.Contains(t, MsgCacheCleared, "Cache")
	assert.Contains(t, MsgRefreshSubmitted, "Refresh")
	assert.Contains(t, MsgSSIDUpdateSubmitted, "SSID")
	assert.Contains(t, MsgPasswordUpdateSubmitted, "Password")
}

func TestXSDConstants(t *testing.T) {
	assert.Equal(t, "xsd:string", XSDString)
}

func TestDefaultConfigConstants(t *testing.T) {
	assert.Equal(t, ":8080", DefaultServerAddr)
	assert.Equal(t, "http://localhost:7557", DefaultGenieACSURL)
	assert.Equal(t, "ThisIsNBIAuthKey", DefaultNBIAuthKey)
}
