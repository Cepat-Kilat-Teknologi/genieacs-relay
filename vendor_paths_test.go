package main

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- globalPathRegistry smoke tests ---

func TestGlobalPathRegistryLoaded(t *testing.T) {
	require.NotNil(t, globalPathRegistry, "globalPathRegistry must be populated by init()")
}

func TestGlobalRegistryDefaultVendorSet(t *testing.T) {
	assert.Equal(t, "default", globalPathRegistry.defaultCfg.Vendor)
}

// --- FormatPath ---

func TestFormatPathSingleVar(t *testing.T) {
	tmpl := "InternetGatewayDevice.WANDevice.{wan}.WANConnectionDevice.1.WANPPPConnection.1.Username"
	result := FormatPath(tmpl, map[string]string{"wan": "2"})
	assert.Equal(t,
		"InternetGatewayDevice.WANDevice.2.WANConnectionDevice.1.WANPPPConnection.1.Username",
		result,
	)
}

func TestFormatPathMultipleVars(t *testing.T) {
	tmpl := "IGD.WANDevice.{wan}.WANConnectionDevice.1.WANIPConnection.1.PortMapping.{index}"
	result := FormatPath(tmpl, map[string]string{"wan": "1", "index": "3"})
	assert.Equal(t,
		"IGD.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.PortMapping.3",
		result,
	)
}

func TestFormatPathNilVars(t *testing.T) {
	tmpl := "InternetGatewayDevice.WANDevice.{wan}"
	assert.Equal(t, tmpl, FormatPath(tmpl, nil))
}

func TestFormatPathEmptyVars(t *testing.T) {
	tmpl := "InternetGatewayDevice.WANDevice.{wan}"
	assert.Equal(t, tmpl, FormatPath(tmpl, map[string]string{}))
}

func TestFormatPathUnmatchedPlaceholderPreserved(t *testing.T) {
	tmpl := "IGD.WANDevice.{wan}.X_{unknown}"
	result := FormatPath(tmpl, map[string]string{"wan": "1"})
	assert.Equal(t, "IGD.WANDevice.1.X_{unknown}", result)
}

func TestFormatPathNoPlaceholders(t *testing.T) {
	tmpl := "InternetGatewayDevice.UserInterface.WebPassword"
	result := FormatPath(tmpl, map[string]string{"wan": "1"})
	assert.Equal(t, tmpl, result)
}

// --- DetectVendor ---

func TestDetectVendorByOUI(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("001141", "")
	assert.Equal(t, "zte", vendor)
}

func TestDetectVendorByOUICaseInsensitive(t *testing.T) {
	// OUI matching is normalised to uppercase. Use an OUI with hex letters (00E0FC)
	// to confirm that a lowercase input still resolves to the correct vendor.
	assert.Equal(t, "huawei", globalPathRegistry.DetectVendor("00e0fc", "")) // lowercase
	assert.Equal(t, "huawei", globalPathRegistry.DetectVendor("00E0FC", "")) // uppercase
}

func TestDetectVendorByProductClass(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("", "F670L")
	assert.Equal(t, "zte", vendor)
}

func TestDetectVendorProductClassCaseInsensitive(t *testing.T) {
	assert.Equal(t, "zte", globalPathRegistry.DetectVendor("", "f670l"))
	assert.Equal(t, "zte", globalPathRegistry.DetectVendor("", "F670L"))
}

func TestDetectVendorHuaweiByOUI(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("00E0FC", "")
	assert.Equal(t, "huawei", vendor)
}

func TestDetectVendorHuaweiByProductClass(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("", "EG8145V5")
	assert.Equal(t, "huawei", vendor)
}

func TestDetectVendorRealtekByOUI(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("00E04C", "")
	assert.Equal(t, "realtek", vendor)
}

func TestDetectVendorTPLinkByOUI(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("B0BE76", "")
	assert.Equal(t, "tp-link", vendor)
}

func TestDetectVendorIntelbras(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("000B82", "")
	assert.Equal(t, "intelbras", vendor)
}

func TestDetectVendorFiberHome(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("0019E0", "")
	assert.Equal(t, "fiberhome", vendor)
}

func TestDetectVendorUnknownFallsBackToDefault(t *testing.T) {
	vendor := globalPathRegistry.DetectVendor("FFFFFF", "UnknownDevice")
	assert.Equal(t, "default", vendor)
}

func TestDetectVendorOUIPriorityOverProductClass(t *testing.T) {
	// OUI "001141" → zte, product class "EG8145V5" → huawei.
	// OUI must win.
	vendor := globalPathRegistry.DetectVendor("001141", "EG8145V5")
	assert.Equal(t, "zte", vendor)
}

// --- Lookup ---

func TestLookupDefaultPPPoEUsername(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "pppoe", "username")
	require.True(t, ok)
	assert.Contains(t, tmpl, "WANPPPConnection")
	assert.Contains(t, tmpl, "{wan}")
	assert.Contains(t, tmpl, "Username")
}

func TestLookupDefaultPPPoEPassword(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "pppoe", "password")
	require.True(t, ok)
	assert.Contains(t, tmpl, "WANPPPConnection")
	assert.Contains(t, tmpl, "Password")
}

func TestLookupDefaultDMZ(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "dmz", "enabled")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_DMZEnable")
}

func TestLookupDefaultDDNS(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "ddns", "enable")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_DynDNS")
}

func TestLookupDefaultPortForwardingBase(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "port_forwarding", "base")
	require.True(t, ok)
	assert.Contains(t, tmpl, "PortMapping")
	assert.Contains(t, tmpl, "{wan}")
	assert.Contains(t, tmpl, "{index}")
}

func TestLookupDefaultWLANBase(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "wlan", "base")
	require.True(t, ok)
	assert.Contains(t, tmpl, "WLANConfiguration")
}

func TestLookupDefaultStaticDHCPBase(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "static_dhcp", "base")
	require.True(t, ok)
	assert.Contains(t, tmpl, "DHCPStaticAddress")
}

func TestLookupDefaultNTPServer(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "ntp", "server")
	require.True(t, ok)
	assert.Contains(t, tmpl, "NTPServer")
}

func TestLookupDefaultAdminPassword(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "admin", "web_password")
	require.True(t, ok)
	assert.Contains(t, tmpl, "WebPassword")
}

func TestLookupDefaultOpticalEPON(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "optical", "epon_stats")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_CT-COM_EponInterfaceConfig")
}

func TestLookupDefaultTR181PPPoE(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "pppoe", "tr181_username")
	require.True(t, ok)
	assert.Contains(t, tmpl, "Device.PPP.Interface")
}

func TestLookupZTEFallsBackToDefaultForPPPoE(t *testing.T) {
	// ZTE does not override pppoe paths — must fall back to default.
	tmpl, ok := globalPathRegistry.Lookup("zte", "pppoe", "username")
	require.True(t, ok)
	assert.Contains(t, tmpl, "WANPPPConnection")
}

func TestLookupZTEVendorSpecificOptical(t *testing.T) {
	// ZTE explicitly defines its optical paths.
	tmpl, ok := globalPathRegistry.Lookup("zte", "optical", "epon_stats")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_CT-COM_EponInterfaceConfig")
}

func TestLookupZTEWanPon(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("zte", "optical", "wan_pon")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_ZTE-COM_WANPONInterfaceConfig")
}

func TestLookupHuaweiOpticalHWDebug(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("huawei", "optical", "hw_debug")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_HW_DEBUG")
}

func TestLookupHuaweiFallsBackToDefaultForDMZ(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("huawei", "dmz", "enabled")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_DMZEnable")
}

func TestLookupRealtekOptical(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("realtek", "optical", "realtek_epon")
	require.True(t, ok)
	assert.Contains(t, tmpl, "X_Realtek_EponInterfaceConfig")
}

func TestLookupUnknownFeatureReturnsFalse(t *testing.T) {
	_, ok := globalPathRegistry.Lookup("default", "nonexistent_feature", "nonexistent_param")
	assert.False(t, ok)
}

func TestLookupUnknownParamReturnsFalse(t *testing.T) {
	_, ok := globalPathRegistry.Lookup("default", "pppoe", "nonexistent_param")
	assert.False(t, ok)
}

func TestLookupUnknownVendorFallsBackToDefault(t *testing.T) {
	// An unregistered vendor string falls through to default.
	tmpl, ok := globalPathRegistry.Lookup("unknown_vendor", "pppoe", "username")
	require.True(t, ok)
	assert.Contains(t, tmpl, "WANPPPConnection")
}

// --- MustLookup ---

func TestMustLookupFound(t *testing.T) {
	result := globalPathRegistry.MustLookup("default", "pppoe", "username")
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "WANPPPConnection")
}

func TestMustLookupNotFoundReturnsEmpty(t *testing.T) {
	// When the path is missing, MustLookup logs a warning and returns "".
	result := globalPathRegistry.MustLookup("default", "nonexistent", "param")
	assert.Empty(t, result)
}

// --- Nil receiver safety ---

func TestNilRegistryDetectVendor(t *testing.T) {
	var r *PathRegistry
	assert.Equal(t, "default", r.DetectVendor("001141", "F670L"))
}

func TestNilRegistryLookup(t *testing.T) {
	var r *PathRegistry
	_, ok := r.Lookup("default", "pppoe", "username")
	assert.False(t, ok)
}

// --- newPathRegistry error paths ---

// errReadFS is a minimal fs.FS that returns an error for all Open calls.
// Used to exercise the "read file failed" error path in newPathRegistry.
type errReadFS struct {
	base      fs.FS
	failPath  string // exact path that triggers the error
	failErr   error
}

func (e *errReadFS) Open(name string) (fs.File, error) {
	if name == e.failPath {
		return nil, e.failErr
	}
	return e.base.Open(name)
}

func TestNewPathRegistryMissingDefault(t *testing.T) {
	// FS with no paths/default.yaml — must return a descriptive error.
	fsys := fstest.MapFS{
		"paths/vendors/zte.yaml": {Data: []byte("vendor: zte\n")},
	}
	_, err := newPathRegistry(fsys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load default paths")
}

func TestNewPathRegistryBadDefaultYAML(t *testing.T) {
	fsys := fstest.MapFS{
		"paths/default.yaml": {Data: []byte("{bad yaml: [unclosed")},
	}
	_, err := newPathRegistry(fsys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse default.yaml")
}

func TestNewPathRegistryNoVendorsDir(t *testing.T) {
	// FS with only default.yaml and no paths/vendors/ — must succeed.
	fsys := fstest.MapFS{
		"paths/default.yaml": {Data: []byte("vendor: default\n")},
	}
	reg, err := newPathRegistry(fsys)
	require.NoError(t, err)
	assert.NotNil(t, reg)
	assert.Equal(t, "default", reg.defaultCfg.Vendor)
}

func TestNewPathRegistryReadVendorsDirError(t *testing.T) {
	// ReadDir on paths/vendors fails with a non-ErrNotExist error.
	base := fstest.MapFS{
		"paths/default.yaml": {Data: []byte("vendor: default\n")},
		// Include a file so the vendors dir is "real" in the base FS.
		"paths/vendors/placeholder": {Data: []byte{}},
	}
	// Wrap with an errReadFS that injects a custom error for paths/vendors.
	fsys := &errReadFS{
		base:     base,
		failPath: "paths/vendors",
		failErr:  errors.New("simulated dir read error"),
	}
	_, err := newPathRegistry(fsys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read vendors dir")
}

func TestNewPathRegistryReadVendorFileError(t *testing.T) {
	// ReadFile on a vendor YAML file fails mid-iteration.
	base := fstest.MapFS{
		"paths/default.yaml":      {Data: []byte("vendor: default\n")},
		"paths/vendors/zte.yaml":  {Data: []byte("vendor: zte\n")},
	}
	fsys := &errReadFS{
		base:     base,
		failPath: "paths/vendors/zte.yaml",
		failErr:  errors.New("simulated file read error"),
	}
	_, err := newPathRegistry(fsys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load zte.yaml")
}

func TestNewPathRegistryBadVendorYAML(t *testing.T) {
	fsys := fstest.MapFS{
		"paths/default.yaml":     {Data: []byte("vendor: default\n")},
		"paths/vendors/bad.yaml": {Data: []byte("{broken yaml: [unclosed")},
	}
	_, err := newPathRegistry(fsys)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse bad.yaml")
}

func TestNewPathRegistrySkipsVendorWithNoID(t *testing.T) {
	// A vendor YAML without a "vendor" field is silently skipped.
	fsys := fstest.MapFS{
		"paths/default.yaml":        {Data: []byte("vendor: default\n")},
		"paths/vendors/noname.yaml": {Data: []byte("oui:\n  - \"AABBCC\"\n")},
	}
	reg, err := newPathRegistry(fsys)
	require.NoError(t, err)
	assert.Empty(t, reg.vendors)
}

func TestNewPathRegistrySkipsNonYAMLFiles(t *testing.T) {
	// Files that don't end in .yaml are skipped.
	fsys := fstest.MapFS{
		"paths/default.yaml":     {Data: []byte("vendor: default\n")},
		"paths/vendors/notes.md": {Data: []byte("# notes\n")},
	}
	reg, err := newPathRegistry(fsys)
	require.NoError(t, err)
	assert.Empty(t, reg.vendors)
}

func TestNewPathRegistrySkipsSubdirectories(t *testing.T) {
	// Subdirectories inside paths/vendors/ are ignored.
	fsys := fstest.MapFS{
		"paths/default.yaml":             {Data: []byte("vendor: default\n")},
		"paths/vendors/sub/nested.yaml":  {Data: []byte("vendor: nested\n")},
	}
	reg, err := newPathRegistry(fsys)
	require.NoError(t, err)
	// "sub" is a directory entry in paths/vendors — it must be skipped.
	assert.NotContains(t, reg.vendors, "nested")
}

func TestNewPathRegistryDefaultVendorFilledWhenEmpty(t *testing.T) {
	// YAML without a "vendor" key gets "default" filled in automatically.
	fsys := fstest.MapFS{
		"paths/default.yaml": {Data: []byte("description: bare\n")},
	}
	reg, err := newPathRegistry(fsys)
	require.NoError(t, err)
	assert.Equal(t, "default", reg.defaultCfg.Vendor)
}

// TestMustInitPathRegistryPanicsOnError exercises the panic path in
// mustInitPathRegistry, which is called by init() with the embedded FS.
// We can only reach the panic branch with a synthetic broken FS.
func TestMustInitPathRegistryPanicsOnError(t *testing.T) {
	orig := globalPathRegistry
	defer func() { globalPathRegistry = orig }()

	assert.Panics(t, func() {
		mustInitPathRegistry(fstest.MapFS{}) // empty FS → no default.yaml → error → panic
	})
}

// --- Integration: FormatPath with looked-up templates ---

func TestFormatPathPPPoEWANInstance(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "pppoe", "username")
	require.True(t, ok)
	path := FormatPath(tmpl, map[string]string{"wan": "2"})
	assert.Equal(t,
		"InternetGatewayDevice.WANDevice.2.WANConnectionDevice.1.WANPPPConnection.1.Username",
		path,
	)
}

func TestFormatPathPortForwardingBase(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "port_forwarding", "base")
	require.True(t, ok)
	base := FormatPath(tmpl, map[string]string{"wan": "1", "index": "5"})
	assert.Equal(t,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.PortMapping.5",
		base,
	)
	// Callers append the field name; verify the resulting path is correct.
	assert.Equal(t,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.PortMapping.5.PortMappingEnabled",
		base+".PortMappingEnabled",
	)
}

func TestFormatPathWLANScheduleEntry(t *testing.T) {
	tmpl, ok := globalPathRegistry.Lookup("default", "wlan", "schedule_entry")
	require.True(t, ok)
	path := FormatPath(tmpl, map[string]string{"index": "1", "entry": "3"})
	assert.Contains(t, path, "WLANConfiguration.1.X_TimerSchedule.3")
}
