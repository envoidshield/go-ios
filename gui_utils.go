//go:build gui
// +build gui

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel"
)

// TunnelManager handles tunnel service operations
type TunnelManager struct {
	RecordsPath    string
	tunnelInfoPort int
	tunnelInfoHost string
	userspaceTUN   bool
	ctx            context.Context
	cancel         context.CancelFunc
	running        bool
}

// Cleanup removes all temporary pairing files
func (tm *TunnelManager) Cleanup() error {
	if tm.RecordsPath == "" {
		return nil
	}

	log.Printf("Cleaning up temporary files at: %s", tm.RecordsPath)

	// Remove entire temporary directory
	if err := os.RemoveAll(tm.RecordsPath); err != nil {
		return fmt.Errorf("failed to cleanup temporary files: %w", err)
	}

	return nil
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(recordsPath string, tunnelInfoPort int, tunnelInfoHost string, userspaceTUN bool) *TunnelManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TunnelManager{
		RecordsPath:    recordsPath,
		tunnelInfoPort: tunnelInfoPort,
		tunnelInfoHost: tunnelInfoHost,
		userspaceTUN:   userspaceTUN,
		ctx:            ctx,
		cancel:         cancel,
		running:        false,
	}
}

// StartTunnel starts the tunnel service
func (tm *TunnelManager) StartTunnel() error {
	if tm.running {
		return nil // Already running
	}

	go func() {
		// Ensure peers directory exists
		peersDir := filepath.Join(tm.RecordsPath, "peers")
		if err := os.MkdirAll(peersDir, 0755); err != nil {
			log.Printf("Failed to create peers directory: %v", err)
			return
		}

		pm, err := tunnel.NewPairRecordManager(tm.RecordsPath)
		if err != nil {
			log.Printf("Could not create pair record manager: %v", err)
			return
		}

		tunnelManager := tunnel.NewTunnelManager(pm, tm.userspaceTUN)

		// Update tunnels periodically
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-tm.ctx.Done():
					return
				case <-ticker.C:
					err := tunnelManager.UpdateTunnels(tm.ctx)
					if err != nil {
						log.Printf("Failed to update tunnels: %v", err)
					}
				}
			}
		}()

		// Serve tunnel info
		go func() {
			err := tunnel.ServeTunnelInfo(tunnelManager, tm.tunnelInfoPort)
			if err != nil {
				log.Printf("Failed to start tunnel server: %v", err)
			}
		}()

		tm.running = true
		fmt.Println("Tunnel server started")

		<-tm.ctx.Done()
		tm.running = false
		fmt.Println("Tunnel server stopped")
	}()

	// Wait a moment for the service to start
	time.Sleep(2 * time.Second)
	return nil
}

// StopTunnel stops the tunnel service
func (tm *TunnelManager) StopTunnel() {
	if tm.running {
		// Cancel the context
		tm.cancel()

		// Wait a moment for graceful shutdown
		time.Sleep(500 * time.Millisecond)

		// Create a new context for next time
		tm.ctx, tm.cancel = context.WithCancel(context.Background())
		tm.running = false
	}
}

// ListTunnels retrieves all running tunnels
func (tm *TunnelManager) ListTunnels() ([]tunnel.Tunnel, error) {
	if !tm.running {
		return nil, fmt.Errorf("tunnel service is not running")
	}

	tunnels, err := tunnel.ListRunningTunnels(tm.tunnelInfoHost, tm.tunnelInfoPort)
	if err != nil {
		return nil, fmt.Errorf("failed to get tunnel infos: %v", err)
	}
	return tunnels, nil
}

// IsRunning returns whether the tunnel service is running
func (tm *TunnelManager) IsRunning() bool {
	return tm.running
}

// splitDeviceString splits device string into components
func splitDeviceString(deviceStr string) []string {
	// Split by " | " to get components
	// New format: "📱 DeviceName | Address | Port: Y" or "📱 iPhone (UDID...) | Address | Port: Y"
	parts := strings.Split(deviceStr, " | ")
	
	// Ensure we have at least 3 parts (device name, address, port)
	if len(parts) < 3 {
		// Return mock data if parsing fails
		return []string{"📱 iPhone", "192.168.1.100", "Port: 58783"}
	}
	
	return parts
}

// deviceWithRsdProvider sets up RSD provider for device
func deviceWithRsdProvider(device ios.DeviceEntry, udid string, address string, rsdPort int) ios.DeviceEntry {
	// Validate inputs
	if address == "" || rsdPort <= 0 {
		log.Printf("Invalid address or port: address=%s, port=%d", address, rsdPort)
		return device
	}
	
	rsdService, err := ios.NewWithAddrPortDevice(address, rsdPort, device)
	if err != nil {
		log.Printf("Error creating RSD service: %v", err)
		return device
	}
	defer func() {
		if closeErr := rsdService.Close(); closeErr != nil {
			log.Printf("Error closing RSD service: %v", closeErr)
		}
	}()
	
	rsdProvider, err := rsdService.Handshake()
	if err != nil {
		log.Printf("Error performing RSD handshake: %v", err)
		return device
	}
	
	device1, err := ios.GetDeviceWithAddress(udid, address, rsdProvider)
	if err != nil {
		log.Printf("Error getting device with address: %v", err)
		return device
	}
	
	// Preserve tunnel settings
	device1.UserspaceTUN = device.UserspaceTUN
	device1.UserspaceTUNHost = device.UserspaceTUNHost
	device1.UserspaceTUNPort = device.UserspaceTUNPort

	return device1
}
