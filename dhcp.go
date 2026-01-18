package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// getDHCPClients retrieves DHCP client information from device data
func getDHCPClients(ctx context.Context, deviceID string) ([]DHCPClient, error) {
	// Retrieve device data from cache or GenieACS API
	deviceData, err := getDeviceData(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// Safely extract InternetGatewayDevice section with type assertion
	internetGateway, ok := deviceData["InternetGatewayDevice"].(map[string]interface{})
	if !ok {
		// Return error if InternetGatewayDevice section is missing or invalid format
		return nil, fmt.Errorf("InternetGatewayDevice data not found")
	}

	// Safely extract LANDevice section with type assertion
	lanDeviceMap, ok := internetGateway["LANDevice"].(map[string]interface{})
	if !ok {
		// Return error if LANDevice section is missing or invalid format
		return nil, fmt.Errorf("LANDevice data not found")
	}

	// Safely extract LANDevice.1 section (first LAN device) with type assertion
	lanDevice, ok := lanDeviceMap["1"].(map[string]interface{})
	if !ok {
		// Return error if LANDevice.1 section is missing
		return nil, fmt.Errorf("LANDevice.1 data not found")
	}

	// Extract Hosts section (optional - may not exist if no DHCP clients)
	hostsMap, ok := lanDevice["Hosts"].(map[string]interface{})
	if !ok {
		// Return empty slice if no Hosts section found (no DHCP clients)
		return []DHCPClient{}, nil
	}

	// Extract Host subsection containing individual client information
	hosts, ok := hostsMap["Host"].(map[string]interface{})
	if !ok {
		// Return empty slice if no Host entries found
		return []DHCPClient{}, nil
	}

	// Process each DHCP client entry
	var clients []DHCPClient
	for _, host := range hosts {
		// Type assert to map for individual host data
		if hostData, ok := host.(map[string]interface{}); ok {
			var client DHCPClient

			// Extract MAC address from host data
			if valMap, ok := hostData["MACAddress"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.MAC = val
				}
			}

			// Extract hostname from host data
			if valMap, ok := hostData["HostName"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.Hostname = val
				}
			}

			// Extract IP address from host data
			if valMap, ok := hostData["IPAddress"].(map[string]interface{}); ok {
				if val, ok := valMap["_value"].(string); ok {
					client.IP = val
				}
			}

			// Add client to results slice
			clients = append(clients, client)
		}
	}
	return clients, nil
}

// refreshDHCP triggers a refresh of DHCP client information from the device
func refreshDHCP(ctx context.Context, deviceID string) error {
	// Build URL for refresh task endpoint targeting LANDevice.1
	urlQ := fmt.Sprintf("%s/devices/%s/tasks?connection_request", geniesBaseURL, url.PathEscape(deviceID))
	// Prepare refresh task payload for LANDevice section
	payload := `{"name": "refreshObject", "objectName": "InternetGatewayDevice.LANDevice.1"}`
	// Send POST request to trigger DHCP data refresh
	resp, err := postJSONRequest(ctx, urlQ, payload)
	if err != nil {
		return err
	}
	// Ensure the response body is properly closed
	defer safeClose(resp.Body)
	// Check for a successful HTTP response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %s", resp.Status)
	}
	return nil
}
