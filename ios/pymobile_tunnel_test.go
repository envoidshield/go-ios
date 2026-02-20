package ios_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/stretchr/testify/assert"
)

func TestPyMobileTunnelClient(t *testing.T) {
	// Mock pymobiledevice3 tunnel response
	mockResponse := `{
		"00008130-000418901E93803A": [{
			"tunnel-address": "fd2f:926e:f944::1",
			"tunnel-port": 64639,
			"interface": "usbmux-00008130-000418901E93803A-Network"
		}],
		"00008112-000869810A83A01E": [{
			"tunnel-address": "fd7e:6d7a:ebfb::1",
			"tunnel-port": 49536,
			"interface": "192.168.1.179"
		}]
	}`

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(mockResponse))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Extract port from test server
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	portInt, _ := strconv.Atoi(port)

	// Test GetTunnelInfo
	client := ios.NewPyMobileTunnelClient(portInt)
	tunnelInfo, err := client.GetTunnelInfo()
	assert.NoError(t, err)
	assert.Len(t, tunnelInfo, 2)

	// Verify first device
	device1 := tunnelInfo["00008130-000418901E93803A"]
	assert.Len(t, device1, 1)
	assert.Equal(t, "fd2f:926e:f944::1", device1[0].TunnelAddress)
	assert.Equal(t, 64639, device1[0].TunnelPort)

	// Verify second device
	device2 := tunnelInfo["00008112-000869810A83A01E"]
	assert.Len(t, device2, 1)
	assert.Equal(t, "fd7e:6d7a:ebfb::1", device2[0].TunnelAddress)
	assert.Equal(t, 49536, device2[0].TunnelPort)
}

func TestPyMobileTunnelClient_ErrorHandling(t *testing.T) {
	// Test connection refused
	client := ios.NewPyMobileTunnelClient(9999) // Use port that's likely not in use
	_, err := client.GetTunnelInfo()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to pymobiledevice3 tunnel")

	// Test non-JSON response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	portInt, _ := strconv.Atoi(port)

	client = ios.NewPyMobileTunnelClient(portInt)
	_, err = client.GetTunnelInfo()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode tunnel info")
}
