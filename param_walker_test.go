package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// param_walker_test.go covers the typed accessors over the GenieACS
// device tree. Tests use a synthetic minimal tree rather than the
// shared mockDeviceDataJSON fixture so each test exercises a specific
// shape and the failure modes are unambiguous.

func makeTestTree() map[string]interface{} {
	return map[string]interface{}{
		"InternetGatewayDevice": map[string]interface{}{
			"DeviceInfo": map[string]interface{}{
				"UpTime": map[string]interface{}{
					"_value":     float64(1234567),
					"_type":      "xsd:unsignedInt",
					"_timestamp": "2026-04-14T11:35:21Z",
				},
				"Manufacturer": map[string]interface{}{
					"_value": "ZTE",
				},
				"ModelName": map[string]interface{}{
					"_value": "F670L",
				},
				"SoftwareVersion": map[string]interface{}{
					"_value": "V9.0.10P5N12",
				},
			},
			"WANDevice": map[string]interface{}{
				"_object":   true,
				"_writable": false,
				"1": map[string]interface{}{
					"WANConnectionDevice": map[string]interface{}{
						"_object": true,
						"1": map[string]interface{}{
							"WANPPPConnection": map[string]interface{}{
								"_object": true,
								"1": map[string]interface{}{
									"ConnectionStatus": map[string]interface{}{
										"_value": "Connected",
									},
									"ExternalIPAddress": map[string]interface{}{
										"_value": "203.0.113.45",
									},
									"Username": map[string]interface{}{
										"_value": "pppoe-customer-001",
									},
									"Uptime": map[string]interface{}{
										"_value": float64(98765),
									},
									"Enable": map[string]interface{}{
										"_value": true,
									},
								},
							},
						},
						"2": map[string]interface{}{
							// Empty instance for enumeration test
						},
					},
				},
				"2": map[string]interface{}{
					// Second WANDevice instance
				},
			},
			"LANDevice": map[string]interface{}{
				"1": map[string]interface{}{
					"WLANConfiguration": map[string]interface{}{
						"_object": true,
						"1": map[string]interface{}{
							"SSID": map[string]interface{}{
								"_value": "MyWiFi-2.4",
							},
						},
						"5": map[string]interface{}{
							"SSID": map[string]interface{}{
								"_value": "MyWiFi-5",
							},
						},
						// non-numeric key — should be filtered out by EnumerateInstances
						"_writable": false,
					},
				},
			},
		},
		"PathWithNumericString": map[string]interface{}{
			"_value": "42",
		},
		"PathWithNumericFloat": map[string]interface{}{
			"_value": float64(3.14),
		},
		"PathWithBoolString": map[string]interface{}{
			"_value": "true",
		},
		"PathWithIntZero": map[string]interface{}{
			"_value": float64(0),
		},
		"PathWithIntOne": map[string]interface{}{
			"_value": float64(1),
		},
		"PathWithIntTwo": map[string]interface{}{
			"_value": float64(2),
		},
		"PathWithBadTimestamp": map[string]interface{}{
			"_value": "not-a-date",
		},
		"PathWithUnsupportedType": map[string]interface{}{
			"_value": []interface{}{"unsupported"},
		},
		"PathWithMissingValueField": map[string]interface{}{
			"_type": "xsd:string",
		},
		"NotALeaf": "this-is-not-a-map",
	}
}

// --- LookupValue ---

func TestLookupValue_HappyPath(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupValue(tree, "InternetGatewayDevice.DeviceInfo.Manufacturer")
	assert.True(t, ok)
	assert.Equal(t, "ZTE", v)
}

func TestLookupValue_NilTree(t *testing.T) {
	v, ok := LookupValue(nil, "InternetGatewayDevice.DeviceInfo.Manufacturer")
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestLookupValue_EmptyPath(t *testing.T) {
	v, ok := LookupValue(makeTestTree(), "")
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestLookupValue_MissingSegment(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupValue(tree, "InternetGatewayDevice.DeviceInfo.NonExistent")
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestLookupValue_MissingValueField(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupValue(tree, "PathWithMissingValueField")
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestLookupValue_NotALeafMap(t *testing.T) {
	// The path "NotALeaf" resolves to a string, not a map → cannot extract _value
	tree := makeTestTree()
	v, ok := LookupValue(tree, "NotALeaf")
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestLookupValue_TraverseHitsNonMap(t *testing.T) {
	// Traversing INTO a non-map should fail cleanly. NotALeaf is a
	// string, so descending past it must return false.
	tree := makeTestTree()
	v, ok := LookupValue(tree, "NotALeaf.Child")
	assert.False(t, ok)
	assert.Nil(t, v)
}

// --- LookupString ---

func TestLookupString_String(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupString(tree, "InternetGatewayDevice.DeviceInfo.Manufacturer")
	assert.True(t, ok)
	assert.Equal(t, "ZTE", v)
}

func TestLookupString_IntegerFloat(t *testing.T) {
	// UpTime is float64(1234567); should round-trip as "1234567" not "1.234567e+06"
	tree := makeTestTree()
	v, ok := LookupString(tree, "InternetGatewayDevice.DeviceInfo.UpTime")
	assert.True(t, ok)
	assert.Equal(t, "1234567", v)
}

func TestLookupString_FractionalFloat(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupString(tree, "PathWithNumericFloat")
	assert.True(t, ok)
	assert.Equal(t, "3.14", v)
}

func TestLookupString_Bool(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupString(tree,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enable")
	assert.True(t, ok)
	assert.Equal(t, "true", v)
}

func TestLookupString_UnsupportedType(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupString(tree, "PathWithUnsupportedType")
	assert.False(t, ok)
	assert.Equal(t, "", v)
}

func TestLookupString_Missing(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupString(tree, "Does.Not.Exist")
	assert.False(t, ok)
	assert.Equal(t, "", v)
}

// --- LookupInt ---

func TestLookupInt_Float(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupInt(tree, "InternetGatewayDevice.DeviceInfo.UpTime")
	assert.True(t, ok)
	assert.Equal(t, 1234567, v)
}

func TestLookupInt_NumericString(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupInt(tree, "PathWithNumericString")
	assert.True(t, ok)
	assert.Equal(t, 42, v)
}

func TestLookupInt_NativeInt(t *testing.T) {
	// Synthetic tree with a real int (rare but the type switch should handle it).
	tree := map[string]interface{}{
		"X": map[string]interface{}{
			"_value": 99,
		},
	}
	v, ok := LookupInt(tree, "X")
	assert.True(t, ok)
	assert.Equal(t, 99, v)
}

func TestLookupInt_NonNumericString(t *testing.T) {
	tree := map[string]interface{}{
		"X": map[string]interface{}{
			"_value": "abc",
		},
	}
	v, ok := LookupInt(tree, "X")
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}

func TestLookupInt_Bool(t *testing.T) {
	// LookupInt does NOT coerce bools — should return false.
	tree := makeTestTree()
	v, ok := LookupInt(tree,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enable")
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}

func TestLookupInt_Missing(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupInt(tree, "Does.Not.Exist")
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}

// --- LookupBool ---

func TestLookupBool_NativeBool(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupBool(tree,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enable")
	assert.True(t, ok)
	assert.True(t, v)
}

func TestLookupBool_String(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupBool(tree, "PathWithBoolString")
	assert.True(t, ok)
	assert.True(t, v)
}

func TestLookupBool_FloatZero(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupBool(tree, "PathWithIntZero")
	assert.True(t, ok)
	assert.False(t, v)
}

func TestLookupBool_FloatOne(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupBool(tree, "PathWithIntOne")
	assert.True(t, ok)
	assert.True(t, v)
}

func TestLookupBool_FloatOther(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupBool(tree, "PathWithIntTwo")
	assert.False(t, ok)
	assert.False(t, v)
}

func TestLookupBool_BadString(t *testing.T) {
	tree := map[string]interface{}{
		"X": map[string]interface{}{
			"_value": "not-a-bool",
		},
	}
	v, ok := LookupBool(tree, "X")
	assert.False(t, ok)
	assert.False(t, v)
}

func TestLookupBool_UnsupportedType(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupBool(tree, "PathWithUnsupportedType")
	assert.False(t, ok)
	assert.False(t, v)
}

func TestLookupBool_Missing(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupBool(tree, "Does.Not.Exist")
	assert.False(t, ok)
	assert.False(t, v)
}

// --- LookupTime ---

func TestLookupTime_Valid(t *testing.T) {
	tree := map[string]interface{}{
		"LastInform": map[string]interface{}{
			"_value": "2026-04-14T11:35:21Z",
		},
	}
	v, ok := LookupTime(tree, "LastInform")
	assert.True(t, ok)
	expected, _ := time.Parse(time.RFC3339, "2026-04-14T11:35:21Z")
	assert.True(t, v.Equal(expected))
}

func TestLookupTime_BadFormat(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupTime(tree, "PathWithBadTimestamp")
	assert.False(t, ok)
	assert.True(t, v.IsZero())
}

func TestLookupTime_Missing(t *testing.T) {
	tree := makeTestTree()
	v, ok := LookupTime(tree, "Does.Not.Exist")
	assert.False(t, ok)
	assert.True(t, v.IsZero())
}

// --- EnumerateInstances ---

func TestEnumerateInstances_HappyPath(t *testing.T) {
	tree := makeTestTree()
	instances := EnumerateInstances(tree,
		"InternetGatewayDevice.WANDevice.1.WANConnectionDevice")
	assert.Equal(t, []int{1, 2}, instances)
}

func TestEnumerateInstances_FilterMetadata(t *testing.T) {
	// WLANConfiguration has keys "1", "5", and "_writable". Only the
	// numeric ones should come back.
	tree := makeTestTree()
	instances := EnumerateInstances(tree,
		"InternetGatewayDevice.LANDevice.1.WLANConfiguration")
	assert.Equal(t, []int{1, 5}, instances)
}

func TestEnumerateInstances_TopLevel(t *testing.T) {
	tree := makeTestTree()
	instances := EnumerateInstances(tree, "InternetGatewayDevice.WANDevice")
	assert.Equal(t, []int{1, 2}, instances)
}

func TestEnumerateInstances_NilTree(t *testing.T) {
	instances := EnumerateInstances(nil, "InternetGatewayDevice")
	assert.Nil(t, instances)
}

func TestEnumerateInstances_EmptyPath(t *testing.T) {
	instances := EnumerateInstances(makeTestTree(), "")
	assert.Nil(t, instances)
}

func TestEnumerateInstances_MissingSegment(t *testing.T) {
	tree := makeTestTree()
	instances := EnumerateInstances(tree, "Does.Not.Exist")
	assert.Nil(t, instances)
}

func TestEnumerateInstances_NotAMap(t *testing.T) {
	tree := makeTestTree()
	// NotALeaf is a string, not a map → cannot enumerate its children
	instances := EnumerateInstances(tree, "NotALeaf")
	assert.Nil(t, instances)
}

func TestEnumerateInstances_TraverseHitsNonMap(t *testing.T) {
	tree := makeTestTree()
	instances := EnumerateInstances(tree, "NotALeaf.Child")
	assert.Nil(t, instances)
}

func TestEnumerateInstances_NoChildren(t *testing.T) {
	tree := map[string]interface{}{
		"Empty": map[string]interface{}{},
	}
	instances := EnumerateInstances(tree, "Empty")
	assert.Nil(t, instances)
}

func TestEnumerateInstances_NonNumericNonMetadataKey(t *testing.T) {
	// Key that is neither a metadata field (no _ prefix) nor numeric.
	// Real GenieACS trees occasionally have keys like "Stats" or
	// "Hosts" mixed with numeric instance keys; the non-numeric ones
	// must be filtered out by the Atoi check, not the underscore check.
	tree := map[string]interface{}{
		"Mixed": map[string]interface{}{
			"1":     map[string]interface{}{},
			"Stats": map[string]interface{}{},
			"3":     map[string]interface{}{},
		},
	}
	instances := EnumerateInstances(tree, "Mixed")
	assert.Equal(t, []int{1, 3}, instances)
}

func TestEnumerateInstances_OnlyMetadataKeys(t *testing.T) {
	tree := map[string]interface{}{
		"OnlyMeta": map[string]interface{}{
			"_object":   true,
			"_writable": false,
		},
	}
	instances := EnumerateInstances(tree, "OnlyMeta")
	assert.Nil(t, instances)
}

// --- CollectPaths ---

func TestCollectPaths_AllFound(t *testing.T) {
	tree := makeTestTree()
	found, missing := CollectPaths(tree, []string{
		"InternetGatewayDevice.DeviceInfo.Manufacturer",
		"InternetGatewayDevice.DeviceInfo.ModelName",
	})
	assert.Equal(t, "ZTE", found["InternetGatewayDevice.DeviceInfo.Manufacturer"])
	assert.Equal(t, "F670L", found["InternetGatewayDevice.DeviceInfo.ModelName"])
	assert.Empty(t, missing)
}

func TestCollectPaths_Mixed(t *testing.T) {
	tree := makeTestTree()
	found, missing := CollectPaths(tree, []string{
		"InternetGatewayDevice.DeviceInfo.Manufacturer",
		"Does.Not.Exist.1",
		"InternetGatewayDevice.DeviceInfo.ModelName",
		"Does.Not.Exist.2",
	})
	assert.Len(t, found, 2)
	assert.Equal(t, "ZTE", found["InternetGatewayDevice.DeviceInfo.Manufacturer"])
	assert.Equal(t, "F670L", found["InternetGatewayDevice.DeviceInfo.ModelName"])
	assert.ElementsMatch(t, []string{"Does.Not.Exist.1", "Does.Not.Exist.2"}, missing)
}

func TestCollectPaths_AllMissing(t *testing.T) {
	tree := makeTestTree()
	found, missing := CollectPaths(tree, []string{"X.Y.Z", "A.B.C"})
	assert.Empty(t, found)
	assert.ElementsMatch(t, []string{"X.Y.Z", "A.B.C"}, missing)
}

func TestCollectPaths_EmptyInput(t *testing.T) {
	tree := makeTestTree()
	found, missing := CollectPaths(tree, nil)
	assert.Empty(t, found)
	assert.Nil(t, missing)
}
