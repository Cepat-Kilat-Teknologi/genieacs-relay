package main

import "strconv"

// joinPath builds a TR-069 parameter path segment from a base path,
// a numeric instance index, and a child name. Used by the WAN
// connection walker in handlers_inspection.go to construct paths like
// `InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANPPPConnection`.
//
// Centralized rather than inline `fmt.Sprintf` so the test suite can
// assert path construction in isolation and the format string lives
// in one place if TR-069 path conventions ever shift.
func joinPath(base string, instance int, child string) string {
	return base + "." + strconv.Itoa(instance) + "." + child
}

// joinInstance builds a TR-069 path segment by appending a numeric
// instance index to a base path, without a trailing child name.
// Returns "InternetGatewayDevice.WANDevice.1" for joinInstance("InternetGatewayDevice.WANDevice", 1).
// Used by the WAN walker to derive the per-instance leaf path.
func joinInstance(base string, instance int) string {
	return base + "." + strconv.Itoa(instance)
}
