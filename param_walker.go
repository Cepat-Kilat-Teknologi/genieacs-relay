package main

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// param_walker.go provides typed accessors over the GenieACS device
// tree (which arrives as `map[string]interface{}` from getDeviceData).
// Centralizes the "walk a Genie tree" logic so the v2.2.0 endpoint
// family (status, wan, params, wifi-stats, ...) doesn't open-code it
// 25 times.
//
// GenieACS encodes TR-069 parameter values as nested maps with a
// `_value` leaf. For example, the device tree for
// `InternetGatewayDevice.DeviceInfo.UpTime` looks like:
//
//	{
//	  "InternetGatewayDevice": {
//	    "DeviceInfo": {
//	      "UpTime": {
//	        "_value": 1234567,
//	        "_type": "xsd:unsignedInt",
//	        "_timestamp": "2026-04-14T11:35:21Z"
//	      }
//	    }
//	  }
//	}
//
// The walker functions split the dotted path on '.' and traverse the
// nested map structure, ultimately fetching the `_value` field and
// converting it to the requested Go type. Type mismatches and missing
// paths return zero + false rather than panicking.

// LookupValue walks a dotted parameter path through a GenieACS device
// tree and returns the raw `_value` field as `interface{}`. Returns
// (nil, false) if any path segment is missing or if the leaf does not
// contain a `_value` field.
//
// This is the underlying primitive that LookupString / LookupInt /
// LookupBool / LookupTime build on. Exported separately so callers
// that need a different type conversion (e.g. float64) can do it
// themselves without going through string round-tripping.
func LookupValue(tree map[string]interface{}, path string) (interface{}, bool) {
	if tree == nil || path == "" {
		return nil, false
	}

	cursor := interface{}(tree)
	start := 0
	for i := 0; i <= len(path); i++ {
		if i < len(path) && path[i] != '.' {
			continue
		}
		segment := path[start:i]
		start = i + 1

		m, ok := cursor.(map[string]interface{})
		if !ok {
			return nil, false
		}
		next, exists := m[segment]
		if !exists {
			return nil, false
		}
		cursor = next
	}

	// Cursor now points at the leaf (a map containing _value, _type,
	// _timestamp). Extract the _value field.
	leaf, ok := cursor.(map[string]interface{})
	if !ok {
		return nil, false
	}
	v, exists := leaf["_value"]
	if !exists {
		return nil, false
	}
	return v, true
}

// LookupString walks a dotted parameter path and returns the leaf
// `_value` as a string. JSON numbers and booleans are coerced to
// their canonical string form. Returns ("", false) if missing.
func LookupString(tree map[string]interface{}, path string) (string, bool) {
	v, ok := LookupValue(tree, path)
	if !ok {
		return "", false
	}
	switch x := v.(type) {
	case string:
		return x, true
	case float64:
		// JSON Unmarshal decodes all numbers as float64; produce an
		// int representation when the value is integral so callers
		// don't see "1234567.0" for an obviously-integer parameter
		// like UpTime.
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10), true
		}
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

// LookupInt walks a dotted parameter path and returns the leaf as an
// int. Accepts JSON numbers (the common case) and numeric strings.
// Returns (0, false) for non-numeric or missing values.
func LookupInt(tree map[string]interface{}, path string) (int, bool) {
	v, ok := LookupValue(tree, path)
	if !ok {
		return 0, false
	}
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case string:
		n, err := strconv.Atoi(x)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// LookupBool walks a dotted parameter path and returns the leaf as a
// bool. Accepts native bools, "true"/"false" strings, and numeric
// 0/1 (some CPEs encode booleans as strings or ints). Returns
// (false, false) for unrecognized values.
func LookupBool(tree map[string]interface{}, path string) (bool, bool) {
	v, ok := LookupValue(tree, path)
	if !ok {
		return false, false
	}
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(x)
		if err != nil {
			return false, false
		}
		return b, true
	case float64:
		if x == 0 {
			return false, true
		}
		if x == 1 {
			return true, true
		}
	}
	return false, false
}

// LookupTime walks a dotted parameter path and returns the leaf as a
// time.Time, expecting an RFC3339 string. Returns (zero, false) for
// unparseable or missing values.
func LookupTime(tree map[string]interface{}, path string) (time.Time, bool) {
	s, ok := LookupString(tree, path)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// EnumerateInstances finds all numeric instance keys under a parent
// dotted path and returns them sorted ascending.
//
// TR-069 multi-instance objects (e.g. WANConnectionDevice.{1,2,3},
// WLANConfiguration.{1,5,8}) are stored in GenieACS as nested maps
// where the instance numbers appear as string keys alongside the
// `_object` / `_writable` metadata keys. This helper filters out the
// metadata keys (which start with `_`) and parses the rest as ints.
//
// Returns nil if the parent path is missing or contains no numeric
// children.
func EnumerateInstances(tree map[string]interface{}, parentPath string) []int {
	if tree == nil || parentPath == "" {
		return nil
	}

	cursor := interface{}(tree)
	start := 0
	for i := 0; i <= len(parentPath); i++ {
		if i < len(parentPath) && parentPath[i] != '.' {
			continue
		}
		segment := parentPath[start:i]
		start = i + 1

		m, ok := cursor.(map[string]interface{})
		if !ok {
			return nil
		}
		next, exists := m[segment]
		if !exists {
			return nil
		}
		cursor = next
	}

	parent, ok := cursor.(map[string]interface{})
	if !ok {
		return nil
	}

	var instances []int
	for key := range parent {
		if strings.HasPrefix(key, "_") {
			continue
		}
		n, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		instances = append(instances, n)
	}
	sort.Ints(instances)
	return instances
}

// CollectPaths walks every requested path against the device tree and
// returns two maps: found paths with their stringified values, and
// missing paths. Used by the H7 /params/{ip} handler.
func CollectPaths(tree map[string]interface{}, paths []string) (found map[string]string, missing []string) {
	found = make(map[string]string, len(paths))
	missing = nil
	for _, p := range paths {
		if v, ok := LookupString(tree, p); ok {
			found[p] = v
			continue
		}
		missing = append(missing, p)
	}
	return found, missing
}
