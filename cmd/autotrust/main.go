//go:build !gui
// +build !gui

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel"
	"howett.net/plist"
)

// AutoTrustService manages automatic device pairing and trust storage
type AutoTrustService struct {
	tunnelManager  *tunnel.TunnelManager
	recordsPath    string
	pairedDevices  map[string]bool
	deviceMutex    sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	userspaceTUN   bool
	pymobiledevDir string
}

// TrustRecord represents the plist structure for pymobiledevice3 compatibility
type TrustRecord struct {
	PrivateKey          []byte `plist:"private_key"`
	PublicKey           []byte `plist:"public_key"`
	RemoteUnlockHostKey string `plist:"remote_unlock_host_key"`
}

// NewAutoTrustService creates a new auto-trust service
func NewAutoTrustService(userspaceTUN bool) (*AutoTrustService, error) {
	// Create temporary directory for pairing records
	tempDir := os.TempDir()
	pairingDir := fmt.Sprintf("envoid-autotrust-%d", time.Now().Unix())
	recordsPath := filepath.Join(tempDir, pairingDir)

	if err := os.MkdirAll(recordsPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Create pymobiledevice3 directory if it doesn't exist
	pymobiledevDir := filepath.Join(os.ExpandEnv("$HOME"), ".pymobiledevice3")
	if err := os.MkdirAll(pymobiledevDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pymobiledevice3 directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create pair record manager
	pm, err := tunnel.NewPairRecordManager(recordsPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create pair record manager: %w", err)
	}

	// Create tunnel manager
	tunnelMgr := tunnel.NewTunnelManager(pm, userspaceTUN)

	service := &AutoTrustService{
		tunnelManager:  tunnelMgr,
		recordsPath:    recordsPath,
		pairedDevices:  make(map[string]bool),
		ctx:            ctx,
		cancel:         cancel,
		userspaceTUN:   userspaceTUN,
		pymobiledevDir: pymobiledevDir,
	}

	return service, nil
}

// Start begins the auto-trust service
func (s *AutoTrustService) Start() error {
	log.Println("Starting Auto-Trust Service...")

	// Start tunnels update loop
	go s.updateTunnelsLoop()

	// Start device monitoring loop
	go s.monitorDevicesLoop()

	return nil
}

// Stop gracefully stops the service
func (s *AutoTrustService) Stop() error {
	log.Println("Stopping Auto-Trust Service...")
	s.cancel()

	if err := s.tunnelManager.Close(); err != nil {
		log.Printf("Error closing tunnel manager: %v", err)
	}

	// Cleanup temp directory
	if err := os.RemoveAll(s.recordsPath); err != nil {
		log.Printf("Warning: failed to cleanup temp directory: %v", err)
	}

	return nil
}

// updateTunnelsLoop periodically updates tunnel status
func (s *AutoTrustService) updateTunnelsLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.tunnelManager.UpdateTunnels(s.ctx); err != nil {
				log.Printf("Error updating tunnels: %v", err)
			}
		}
	}
}

// monitorDevicesLoop periodically checks for new devices and pairs with them
func (s *AutoTrustService) monitorDevicesLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkAndPairDevices()
		}
	}
}

// checkAndPairDevices checks for new devices and pairs with them
func (s *AutoTrustService) checkAndPairDevices() {
	tunnels, err := s.tunnelManager.ListTunnels()
	if err != nil {
		log.Printf("Error listing tunnels: %v", err)
		return
	}

	for _, t := range tunnels {
		udid := t.Udid

		s.deviceMutex.Lock()
		alreadyPaired := s.pairedDevices[udid]
		s.deviceMutex.Unlock()

		if alreadyPaired {
			continue
		}

		log.Printf("New device detected: %s (%s:%d)", udid, t.Address, t.RsdPort)
		go s.pairAndTrustDevice(udid, t.Address, t.RsdPort)
	}
}

// pairAndTrustDevice handles pairing with a device and saving trust credentials
func (s *AutoTrustService) pairAndTrustDevice(udid string, address string, rsdPort int) {
	// Mark device as being processed
	s.deviceMutex.Lock()
	s.pairedDevices[udid] = true
	s.deviceMutex.Unlock()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic while pairing device %s: %v", udid, r)
		}
	}()

	log.Printf("[%s] Getting device information...", udid)
	device, err := ios.GetDevice(udid)
	if err != nil {
		log.Printf("[%s] Error getting device: %v", udid, err)
		return
	}

	log.Printf("[%s] Connecting to lockdown...", udid)
	lockdown, err := ios.ConnectLockdownWithSession(device)
	if err != nil {
		log.Printf("[%s] Error connecting to lockdown: %v", udid, err)
		return
	}
	defer lockdown.Close()

	log.Printf("[%s] Enabling WiFi connections...", udid)
	err = lockdown.SetValueForDomain("EnableWifiConnections", "com.apple.mobile.wireless_lockdown", true)
	if err != nil {
		log.Printf("[%s] Error enabling WiFi connections: %v", udid, err)
		return
	}

	log.Printf("[%s] Getting tunnel information...", udid)
	info, err := tunnel.TunnelInfoForDevice(udid, ios.HttpApiHost(), 28100)
	if err != nil {
		log.Printf("[%s] Error getting tunnel info: %v", udid, err)
		return
	}

	device.UserspaceTUNPort = info.UserspaceTUNPort
	device.UserspaceTUN = info.UserspaceTUN

	log.Printf("[%s] Setting up RSD provider...", udid)
	device = deviceWithRsdProvider(device, udid, address, rsdPort)

	log.Printf("[%s] Starting pairing...", udid)
	pm, err := tunnel.NewPairRecordManager(s.recordsPath)
	if err != nil {
		log.Printf("[%s] Error creating pair record manager: %v", udid, err)
		return
	}

	hostKey, err := tunnel.PairAndGetHostKey(address, device, pm)
	if err != nil {
		log.Printf("[%s] Error pairing: %v", udid, err)
		return
	}

	log.Printf("[%s] Pairing successful! Extracting keys...", udid)

	// Read selfIdentity.plist to extract private and public keys
	plistPath := filepath.Join(s.recordsPath, "selfIdentity.plist")
	content, err := os.ReadFile(plistPath)
	if err != nil {
		log.Printf("[%s] Error reading selfIdentity.plist: %v", udid, err)
		return
	}

	var identityData map[string]interface{}
	_, err = plist.Unmarshal(content, &identityData)
	if err != nil {
		log.Printf("[%s] Error parsing selfIdentity.plist: %v", udid, err)
		return
	}

	// Extract private key
	privateKeyBytes := getKeyBytes(identityData, "privateKey")
	if privateKeyBytes == nil {
		log.Printf("[%s] Error: private key not found or invalid", udid)
		return
	}

	// Extract public key
	publicKeyBytes := getKeyBytes(identityData, "publicKey")
	if publicKeyBytes == nil {
		log.Printf("[%s] Error: public key not found or invalid", udid)
		return
	}

	// Save trust record to pymobiledevice3 format
	trustRecord := TrustRecord{
		PrivateKey:          privateKeyBytes,
		PublicKey:           publicKeyBytes,
		RemoteUnlockHostKey: hostKey,
	}

	recordFileName := fmt.Sprintf("remote_%s.plist", udid)
	recordPath := filepath.Join(s.pymobiledevDir, recordFileName)

	log.Printf("[%s] Saving trust record to %s", udid, recordPath)
	if err := saveTrustRecord(recordPath, trustRecord); err != nil {
		log.Printf("[%s] Error saving trust record: %v", udid, err)
		return
	}

	log.Printf("[%s] ✓ Successfully paired and saved trust credentials!", udid)
}

// getKeyBytes extracts key bytes from plist data, handling both []byte and string formats
func getKeyBytes(data map[string]interface{}, keyName string) []byte {
	raw, ok := data[keyName]
	if !ok {
		return nil
	}

	// If it's already bytes, return as is
	if keyBytes, ok := raw.([]byte); ok {
		return keyBytes
	}

	// If it's a string, decode from base64
	if keyStr, ok := raw.(string); ok {
		decoded, err := base64.StdEncoding.DecodeString(keyStr)
		if err == nil {
			return decoded
		}
		// If base64 decode fails, return as raw bytes
		return []byte(keyStr)
	}

	return nil
}

// saveTrustRecord saves the trust record as a plist file
func saveTrustRecord(path string, record TrustRecord) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer f.Close()

	encoder := plist.NewEncoderForFormat(f, plist.XMLFormat)
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("failed to encode plist: %w", err)
	}

	return nil
}

// deviceWithRsdProvider sets up RSD provider for device
func deviceWithRsdProvider(device ios.DeviceEntry, udid string, address string, rsdPort int) ios.DeviceEntry {
	if address == "" || rsdPort <= 0 {
		log.Printf("Invalid address or port: address=%s, port=%d", address, rsdPort)
		return device
	}

	rsdService, err := ios.NewWithAddrPortDevice(address, rsdPort, device)
	if err != nil {
		log.Printf("Error creating RSD service: %v", err)
		return device
	}
	defer rsdService.Close()

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

func main() {
	// Parse CLI flags
	userspaceTUN := flag.Bool("userspace", false, "Run tunnel in userspace mode (no root required)")
	flag.Parse()

	// Create service
	service, err := NewAutoTrustService(*userspaceTUN)
	if err != nil {
		log.Fatalf("Failed to create auto-trust service: %v", err)
	}

	// Start service
	if err := service.Start(); err != nil {
		log.Fatalf("Failed to start service: %v", err)
	}

	log.Printf("Auto-Trust Service running (userspace=%v)", *userspaceTUN)
	log.Printf("Trust records will be saved to: %s", service.pymobiledevDir)

	// Setup signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	<-signalCh
	if err := service.Stop(); err != nil {
		log.Printf("Error stopping service: %v", err)
	}

	log.Println("Auto-Trust Service stopped")
}
