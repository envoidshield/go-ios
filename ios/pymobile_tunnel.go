// Package ios provides integration with pymobiledevice3's tunnel daemon
// to enable go-ios to use existing tunnel infrastructure.
package ios

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// DefaultPyMobileTunnelPort is the default port for pymobiledevice3's tunnel daemon
	DefaultPyMobileTunnelPort = 49151
)

// PyMobileTunnelInfo represents tunnel information from pymobiledevice3
type PyMobileTunnelInfo struct {
	TaskIdentifier     string                 `json:"task_identifier,omitempty"`
	DeviceIdentifier   string                 `json:"device_identifier,omitempty"`
	TunnelAddress      string                 `json:"tunnel-address"`
	TunnelPort         int                    `json:"tunnel-port"`
	Interface          string                 `json:"interface"`
	Protocol           string                 `json:"protocol,omitempty"`
	DirectIPAddr       string                 `json:"direct_ip_addr,omitempty"`
	DeviceInformation  map[string]interface{} `json:"device_information,omitempty"`
	ConnectionProtocol string                 `json:"connection_protocol,omitempty"`
}

// PyMobileTunnelClient connects to pymobiledevice3's tunnel daemon
type PyMobileTunnelClient struct {
	baseURL string
}

// NewPyMobileTunnelClient creates a client for pymobiledevice3's tunnel daemon.
// The default port for pymobiledevice3's tunnel daemon is 49151.
func NewPyMobileTunnelClient(port int) *PyMobileTunnelClient {
	return &PyMobileTunnelClient{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
	}
}

// GetTunnelInfo retrieves tunnel information for all connected devices
func (c *PyMobileTunnelClient) GetTunnelInfo() (map[string][]PyMobileTunnelInfo, error) {
	resp, err := http.Get(c.baseURL + "/")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to pymobiledevice3 tunnel: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tunnel API returned status %d: %s", resp.StatusCode, string(body))
	}

	var tunnelInfo map[string][]PyMobileTunnelInfo
	if err := json.NewDecoder(resp.Body).Decode(&tunnelInfo); err != nil {
		return nil, fmt.Errorf("failed to decode tunnel info: %w", err)
	}

	return tunnelInfo, nil
}

// GetDeviceWithPyMobileTunnel creates a DeviceEntry that uses pymobiledevice3's tunnel.
// This is an alternative to the standard tunnel connection and allows reusing
// existing pymobiledevice3 infrastructure.
//
// Usage:
//   device, err := ios.GetDeviceWithPyMobileTunnel("00008130-000418901E93803A", 49151)
//   if err != nil {
//       log.Fatal(err)
//   }
//   // Now use device with any service
//   conn, err := ostrace.New(device)
func GetDeviceWithPyMobileTunnel(udid string, tunnelPort int) (DeviceEntry, error) {
	// First get the regular device
	device, err := GetDevice(udid)
	if err != nil {
		return DeviceEntry{}, err
	}

	// Get tunnel info from pymobiledevice3
	client := NewPyMobileTunnelClient(tunnelPort)
	tunnelInfo, err := client.GetTunnelInfo()
	if err != nil {
		return DeviceEntry{}, err
	}

	// Find tunnel info for this device
	deviceTunnels, ok := tunnelInfo[udid]
	if !ok || len(deviceTunnels) == 0 {
		return DeviceEntry{}, fmt.Errorf("GetDeviceWithPyMobileTunnel: no tunnel found for device %s. Make sure pymobiledevice3 tunnel is running and device is connected", udid)
	}

	// Use the first tunnel
	tunnel := deviceTunnels[0]

	// Create RSD connection to the tunnel
	// IPv6 addresses need to be cleaned up
	tunnelAddr := strings.Trim(tunnel.TunnelAddress, "[]")
	
	rsdService, err := NewWithAddrPortDevice(tunnelAddr, tunnel.TunnelPort, device)
	if err != nil {
		return DeviceEntry{}, fmt.Errorf("failed to create RSD service: %w", err)
	}
	defer rsdService.Close()

	// Perform RSD handshake
	handshakeResp, err := rsdService.Handshake()
	if err != nil {
		return DeviceEntry{}, fmt.Errorf("RSD handshake failed: %w", err)
	}

	// Get device with RSD provider
	tunnelDevice, err := GetDeviceWithAddress(udid, tunnelAddr, handshakeResp)
	if err != nil {
		return DeviceEntry{}, fmt.Errorf("failed to get device with RSD: %w", err)
	}

	return tunnelDevice, nil
}

// ListDevicesWithPyMobileTunnel lists all devices available through pymobiledevice3's tunnel.
// This provides an alternative device discovery mechanism when using pymobiledevice3's infrastructure.
func ListDevicesWithPyMobileTunnel(tunnelPort int) (DeviceList, error) {
	client := NewPyMobileTunnelClient(tunnelPort)
	tunnelInfo, err := client.GetTunnelInfo()
	if err != nil {
		return DeviceList{}, err
	}

	var devices []DeviceEntry
	for udid := range tunnelInfo {
		device, err := GetDeviceWithPyMobileTunnel(udid, tunnelPort)
		if err != nil {
			// Skip devices that fail to connect
			// This matches the behavior of regular device discovery
			continue
		}
		devices = append(devices, device)
	}

	return DeviceList{DeviceList: devices}, nil
}
