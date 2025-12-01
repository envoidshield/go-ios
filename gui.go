package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel"
	"howett.net/plist"
)

var (
	// debugEnabled controls whether debug logs are shown
	// Set via DEBUG environment variable (any non-empty value enables debug)
	debugEnabled = os.Getenv("DEBUG") != ""
)

// debugLog logs at debug level (only if DEBUG environment variable is set)
func debugLog(format string, v ...interface{}) {
	if debugEnabled {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// GUIApp represents the main GUI application
type GUIApp struct {
	app            fyne.App
	window         fyne.Window
	tunnelManager  *TunnelManager
	tunnelStatus   binding.String
	deviceList     binding.StringList
	selectedDevice *tunnel.Tunnel
	statusLabel    *widget.Label
	deviceListBox  *widget.List
	startButton    *widget.Button
	stopButton     *widget.Button
	refreshButton  *widget.Button
	pairButton     *widget.Button
	progressBar    *widget.ProgressBar
	// New status indicators
	pairingStatusLabel *widget.Label
	balenaStatusLabel  *widget.Label
	lastPairingInfo    *widget.Label
}

// NewGUIApp creates a new GUI application
func NewGUIApp() *GUIApp {
	myApp := app.NewWithID("com.tunnelmanager.app")
	myApp.SetIcon(theme.ComputerIcon())
	
	window := myApp.NewWindow("iOS Tunnel Manager")
	window.Resize(fyne.NewSize(900, 700))
	window.CenterOnScreen()
	
	// Set Windows-specific properties
	window.SetFixedSize(false)
	window.SetMaster()

	// Create tunnel manager
	tunnelManager := NewTunnelManager(".", 28100, "localhost", false)

	gui := &GUIApp{
		app:           myApp,
		window:        window,
		tunnelManager: tunnelManager,
		tunnelStatus:  binding.NewString(),
		deviceList:    binding.NewStringList(),
	}

	gui.setupUI()
	gui.setupEventHandlers()
	
	// Auto-start the service when app starts
	go func() {
		time.Sleep(1 * time.Second) // Small delay to let UI initialize
		gui.startTunnel()
	}()
	
	return gui
}

// setupUI creates the user interface
func (g *GUIApp) setupUI() {
	// Title
	title := widget.NewLabelWithStyle("iOS Tunnel Manager", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	title.TextStyle = fyne.TextStyle{Bold: true}

	// Status section
	statusCard := g.createStatusCard()
	
	// Device discovery section
	deviceCard := g.createDeviceCard()
	
	// Control buttons
	controlCard := g.createControlCard()

	// Progress indicator
	g.progressBar = widget.NewProgressBar()
	g.progressBar.Hide()

	// Main layout
	content := container.NewVBox(
		title,
		widget.NewSeparator(),
		statusCard,
		widget.NewSeparator(),
		deviceCard,
		widget.NewSeparator(),
		controlCard,
		g.progressBar,
	)

	// Add padding
	paddedContent := container.NewPadded(content)
	g.window.SetContent(paddedContent)
}

// createStatusCard creates the tunnel status section
func (g *GUIApp) createStatusCard() *widget.Card {
	// Main status label
	g.statusLabel = widget.NewLabel("🔴 Service: Stopped")
	g.statusLabel.Alignment = fyne.TextAlignCenter
	g.statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	// Current instruction (one line only)
	g.pairingStatusLabel = widget.NewLabel("Starting service...")
	g.pairingStatusLabel.Alignment = fyne.TextAlignCenter
	g.pairingStatusLabel.TextStyle = fyne.TextStyle{Bold: true}

	// Status container
	statusContainer := container.NewVBox(
		g.statusLabel,
		widget.NewSeparator(),
		g.pairingStatusLabel,
	)

	card := widget.NewCard("📋 Process Status", "", statusContainer)
	return card
}

// createDeviceCard creates the device discovery section
func (g *GUIApp) createDeviceCard() *widget.Card {
	// Device list
	g.deviceListBox = widget.NewListWithData(
		g.deviceList,
		func() fyne.CanvasObject {
			return widget.NewLabel("Device")
		},
		func(item binding.DataItem, obj fyne.CanvasObject) {
			deviceInfo := item.(binding.String)
			deviceStr, _ := deviceInfo.Get()
			
			label := obj.(*widget.Label)
			label.SetText(deviceStr)
		},
	)

	// Device info
	deviceInfoLabel := widget.NewLabel("No device selected")
	deviceInfoLabel.Wrapping = fyne.TextWrapWord

	// Device selection handler
	g.deviceListBox.OnSelected = func(id widget.ListItemID) {
		deviceStr, _ := g.deviceList.GetValue(id)
		deviceInfoLabel.SetText(fmt.Sprintf("Selected: %s", deviceStr))
		
		// Parse and store selected device
		g.parseSelectedDevice(deviceStr)
		
		// Update instruction based on new state
		g.updateInstructionBasedOnState()
	}

	deviceContainer := container.NewBorder(
		widget.NewLabel("Available Devices:"),
		deviceInfoLabel,
		nil,
		nil,
		g.deviceListBox,
	)

	card := widget.NewCard("Device Discovery", "", deviceContainer)
	return card
}

// createControlCard creates the control buttons section
func (g *GUIApp) createControlCard() *widget.Card {
	// Service controls
	g.startButton = widget.NewButtonWithIcon("Start Service", theme.MediaPlayIcon(), g.startTunnel)
	g.stopButton = widget.NewButtonWithIcon("Stop Service", theme.MediaStopIcon(), g.stopTunnel)
	g.stopButton.Disable()

	// Device controls
	g.refreshButton = widget.NewButtonWithIcon("Refresh Devices", theme.ViewRefreshIcon(), g.refreshDevices)
	g.pairButton = widget.NewButtonWithIcon("Pair Device", theme.ConfirmIcon(), g.pairDevice)
	g.pairButton.Disable()
	deleteButton := widget.NewButtonWithIcon("Delete All Devices", theme.DeleteIcon(), g.deleteAllDevices)

	// Button styling
	g.startButton.Importance = widget.HighImportance
	g.stopButton.Importance = widget.MediumImportance
	g.pairButton.Importance = widget.HighImportance
	deleteButton.Importance = widget.DangerImportance

	// Layout buttons
	tunnelControls := container.NewHBox(g.startButton, g.stopButton)
	deviceControls := container.NewHBox(g.refreshButton, g.pairButton)
	deleteControls := container.NewHBox(deleteButton)
	
	allControls := container.NewVBox(
		widget.NewLabel("Service Controls:"),
		tunnelControls,
		widget.NewSeparator(),
		widget.NewLabel("Device Controls:"),
		deviceControls,
		widget.NewSeparator(),
		widget.NewLabel("Danger Zone:"),
		deleteControls,
	)

	card := widget.NewCard("Controls", "", allControls)
	return card
}

// setupEventHandlers sets up event handlers
func (g *GUIApp) setupEventHandlers() {
	// Update tunnel status periodically
	go g.updateTunnelStatus()
	
	// Auto-refresh devices when tunnel is running
	go g.autoRefreshDevices()
}

// updateTunnelStatus updates the tunnel status display
func (g *GUIApp) updateTunnelStatus() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if g.tunnelManager.IsRunning() {
			g.tunnelStatus.Set("Service Status: Running")
			g.statusLabel.SetText("🟢 Service: Running")
			g.startButton.Disable()
			g.stopButton.Enable()
			// Update instruction based on current state
			g.updateInstructionBasedOnState()
		} else {
			g.tunnelStatus.Set("Service Status: Stopped")
			g.statusLabel.SetText("🔴 Service: Stopped")
			g.startButton.Enable()
			g.stopButton.Disable()
			g.pairButton.Disable()
			// Reset instruction when service stops
			g.resetAllSteps()
		}
	}
}

// updateCurrentInstruction updates the current instruction for the user
func (g *GUIApp) updateCurrentInstruction(instruction string) {
	g.pairingStatusLabel.SetText(instruction)
}

// updateInstructionBasedOnState determines the correct instruction based on current state
func (g *GUIApp) updateInstructionBasedOnState() {
	// Check if we already have a final status message (success or failure)
	currentText := g.pairingStatusLabel.Text
	if strings.Contains(currentText, "✅ All done!") || strings.Contains(currentText, "⚠️ Device paired but failed") {
		// Don't change the final status message
		return
	}
	
	// Check if service is running
	if !g.tunnelManager.IsRunning() {
		g.updateCurrentInstruction("Starting service...")
		return
	}
	
	// Service is running, check if we have devices
	tunnels, err := g.tunnelManager.ListTunnels()
	if err != nil || len(tunnels) == 0 {
		g.updateCurrentInstruction("Connect device")
		return
	}
	
	// We have devices, show that we're auto-pairing
	if g.selectedDevice == nil {
		g.updateCurrentInstruction("Device found, auto-pairing...")
		return
	}
	
	// Device is selected, show pairing status
	g.updateCurrentInstruction("Pairing device...")
}

// resetAllSteps resets the instruction
func (g *GUIApp) resetAllSteps() {
	g.updateCurrentInstruction("Starting service...")
}

// autoRefreshDevices automatically refreshes device list when tunnel is running
func (g *GUIApp) autoRefreshDevices() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if g.tunnelManager.IsRunning() {
			g.refreshDevices()
		}
	}
}

// startTunnel starts the tunnel service
func (g *GUIApp) startTunnel() {
	g.progressBar.Show()
	g.progressBar.SetValue(0.3)
	
	// Show status update
	g.statusLabel.SetText("Starting service...")
	
	go func() {
		err := g.tunnelManager.StartTunnel()
		if err != nil {
			g.progressBar.Hide()
			g.statusLabel.SetText("Service Status: Failed to start")
			dialog.ShowError(fmt.Errorf("Failed to start service: %v", err), g.window)
			return
		}
		
		g.progressBar.SetValue(1.0)
		g.statusLabel.SetText("Service Status: Starting...")
		time.Sleep(500 * time.Millisecond)
		g.progressBar.Hide()
		
		// Auto-refresh devices after starting service
		time.Sleep(2 * time.Second)
		g.refreshDevices()
		
		// No popup - just update the instruction automatically
	}()
}

// stopTunnel stops the tunnel service
func (g *GUIApp) stopTunnel() {
	g.tunnelManager.StopTunnel()
	g.deviceList.Set([]string{})
	g.selectedDevice = nil
}

// refreshDevices refreshes the device list
func (g *GUIApp) refreshDevices() {
	if !g.tunnelManager.IsRunning() {
		return
	}

	go func() {
		tunnels, err := g.tunnelManager.ListTunnels()
		if err != nil {
			debugLog("Error listing tunnels: %v", err)
			return
		}

		deviceStrings := make([]string, len(tunnels))
		for i, tunnel := range tunnels {
			// Try to get device name for better display
			deviceName := g.getDeviceName(tunnel.Udid)
			if deviceName != "" {
				deviceStrings[i] = fmt.Sprintf("📱 %s | %s | Port: %d", 
					deviceName, tunnel.Address, tunnel.RsdPort)
			} else {
				deviceStrings[i] = fmt.Sprintf("📱 iPhone (%s) | %s | Port: %d", 
					tunnel.Udid[:8]+"...", tunnel.Address, tunnel.RsdPort)
			}
		}

		g.deviceList.Set(deviceStrings)
		
		// Auto-select first device if none selected and devices are available
		if g.selectedDevice == nil && len(tunnels) > 0 {
			// Auto-select the first device
			firstDeviceStr := deviceStrings[0]
			g.parseSelectedDevice(firstDeviceStr)
			
			// Auto-start pairing process
			go func() {
				time.Sleep(1 * time.Second) // Small delay to let UI update
				g.pairDevice()
			}()
		}
		
		// Update instruction based on current state
		g.updateInstructionBasedOnState()
	}()
}

// getDeviceName attempts to get the device name from lockdown
func (g *GUIApp) getDeviceName(udid string) string {
	device, err := ios.GetDevice(udid)
	if err != nil {
		return ""
	}
	
	lockdown, err := ios.ConnectLockdownWithSession(device)
	if err != nil {
		return ""
	}
	defer lockdown.Close()
	
	deviceName, err := lockdown.GetValue("DeviceName")
	if err != nil {
		return ""
	}
	
	if name, ok := deviceName.(string); ok {
		return name
	}
	return ""
}

// parseSelectedDevice parses the selected device string
func (g *GUIApp) parseSelectedDevice(deviceStr string) {
	// Parse device string to extract tunnel information
	// New format: "📱 DeviceName | Address | Port: Y" or "📱 iPhone (UDID...) | Address | Port: Y"
	parts := splitDeviceString(deviceStr)
	if len(parts) >= 3 {
		// Parse the RsdPort from the last part
		rsdPort := 0
		if len(parts) >= 3 {
			// Extract port number from "Port: Y" format
			portStr := strings.TrimPrefix(parts[2], "Port: ")
			if port, err := strconv.Atoi(portStr); err == nil {
				rsdPort = port
			}
		}
		
		// Extract UDID from the device string or get it from the tunnel list
		udid := g.extractUdidFromDeviceString(deviceStr)
		if udid == "" {
			// Fallback: try to get UDID from tunnel list
			tunnels, err := g.tunnelManager.ListTunnels()
			if err == nil && len(tunnels) > 0 {
				// Find tunnel by address
				address := parts[1] // Address is the second part
				for _, t := range tunnels {
					if t.Address == address {
						udid = t.Udid
						break
					}
				}
			}
		}
		
		if udid != "" {
			// Create a tunnel object for pairing
			g.selectedDevice = &tunnel.Tunnel{
				Udid:    udid,
				Address: parts[1], // Address
				RsdPort: rsdPort,  // Parsed port
			}
			g.pairButton.Enable()
		}
	}
}

// extractUdidFromDeviceString tries to extract UDID from device string
func (g *GUIApp) extractUdidFromDeviceString(deviceStr string) string {
	// If the string contains "iPhone (UDID...)", extract the UDID
	if strings.Contains(deviceStr, "iPhone (") {
		start := strings.Index(deviceStr, "iPhone (") + 8
		end := strings.Index(deviceStr[start:], ")")
		if end > 0 {
			udidPart := deviceStr[start : start+end]
			// Remove the "..." if present
			udidPart = strings.TrimSuffix(udidPart, "...")
			// Try to find the full UDID from tunnel list
			tunnels, err := g.tunnelManager.ListTunnels()
			if err == nil {
				for _, t := range tunnels {
					if strings.HasPrefix(t.Udid, udidPart) {
						return t.Udid
					}
				}
			}
		}
	}
	return ""
}

// postToBalena posts device information to the Balena endpoint
func (g *GUIApp) postToBalena(device *tunnel.Tunnel, hostKey string, privateKey string, publicKey string) (bool, string) {
	// Balena endpoint configuration
	balenaURL := "http://192.168.42.1:8000/devices/trust"
	
	// Prepare device data with all required fields
	deviceData := map[string]interface{}{
		"udid":                   device.Udid,
		"address":                device.Address,
		"rsdPort":                device.RsdPort,
		"hostKey":                hostKey,
		"pairedAt":               time.Now().Format(time.RFC3339),
		"deviceName":             g.getDeviceName(device.Udid),
		"device_type":            "iPhone", // Required field
		"private_key":            privateKey, // Ed25519 private key (base64 encoded)
		"public_key":             publicKey,  // Ed25519 public key (base64 encoded)
		"remote_unlock_host_key": hostKey, // Use hostKey as remote unlock host key
	}
	
	// Convert to JSON
	jsonData, err := json.Marshal(deviceData)
	if err != nil {
		debugLog("Error marshaling device data: %v", err)
		return false, fmt.Sprintf("JSON marshaling error: %v", err)
	}
	
	// Print the POST request data
	debugLog("===== POST Request to Balena =====")
	debugLog("URL: %s", balenaURL)
	debugLog("JSON Data: %s", string(jsonData))
	debugLog("=================================")
	
	// Create HTTP request
	req, err := http.NewRequest("POST", balenaURL, bytes.NewBuffer(jsonData))
	if err != nil {
		debugLog("Error creating request: %v", err)
		return false, fmt.Sprintf("Request creation error: %v", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "iOS-Tunnel-Manager/1.0")
	
	// Set Basic Authentication
	req.SetBasicAuth("admin", "XLQS8Rv07N7dBshRZifP")
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		debugLog("Error sending request to Balena: %v", err)
		return false, fmt.Sprintf("Network error: %v", err)
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		debugLog("Error reading response: %v", err)
		return false, fmt.Sprintf("Response reading error: %v", err)
	}
	
	// Check response status
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		debugLog("Successfully posted to Balena. Response: %s", string(body))
		return true, string(body)
	} else {
		debugLog("Balena endpoint returned error. Status: %d, Response: %s", resp.StatusCode, string(body))
		return false, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
	}
}

// fetchAllDeviceIDs fetches all device IDs from the API
func (g *GUIApp) fetchAllDeviceIDs() []int {
	apiBase := "http://192.168.42.1:8000/api/devices"
	url := fmt.Sprintf("%s?page=1&size=500", apiBase)
	
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		debugLog("[!] Failed to create request: %v", err)
		return []int{}
	}
	
	req.SetBasicAuth("admin", "XLQS8Rv07N7dBshRZifP")
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		debugLog("[!] Failed to list devices: %v", err)
		return []int{}
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		debugLog("[!] Failed to list devices: HTTP %d", resp.StatusCode)
		return []int{}
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		debugLog("[!] Failed to read response: %v", err)
		return []int{}
	}
	
	// Debug: log the raw response
	debugLog("Raw API response: %s", string(body))
	
	var data struct {
		Items []struct {
			DeviceID int `json:"device_id"`
		} `json:"items"`
	}
	
	if err := json.Unmarshal(body, &data); err != nil {
		debugLog("[!] Failed to parse response: %v", err)
		debugLog("Response body was: %s", string(body))
		return []int{}
	}
	
	deviceIDs := make([]int, 0, len(data.Items))
	for _, item := range data.Items {
		if item.DeviceID > 0 { // Only include valid device IDs (skip 0 or negative)
			deviceIDs = append(deviceIDs, item.DeviceID)
			debugLog("Found device_id: %d", item.DeviceID)
		} else {
			debugLog("Skipping invalid device_id: %d", item.DeviceID)
		}
	}
	
	debugLog("[+] Found %d valid devices", len(deviceIDs))
	return deviceIDs
}

// deleteDevice deletes a single device by ID
func (g *GUIApp) deleteDevice(deviceID int) bool {
	apiBase := "http://192.168.42.1:8000/api/devices"
	url := fmt.Sprintf("%s/remove", apiBase)
	
	debugLog("[•] Deleting device %d...", deviceID)
	
	payload := map[string]int{"device_id": deviceID}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		debugLog("[✗] Failed to marshal request: %v", err)
		return false
	}
	
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		debugLog("[✗] Failed to create request: %v", err)
		return false
	}
	
	req.SetBasicAuth("admin", "XLQS8Rv07N7dBshRZifP")
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		debugLog("[✗] Failed to delete %d: %v", deviceID, err)
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		debugLog("[✓] Deleted %d", deviceID)
		return true
	} else {
		body, _ := io.ReadAll(resp.Body)
		debugLog("[✗] Failed to delete %d: HTTP %d - %s", deviceID, resp.StatusCode, string(body))
		return false
	}
}

// deleteAllDevices deletes all devices from the Balena endpoint
func (g *GUIApp) deleteAllDevices() {
	// Show confirmation dialog
	dialog.ShowConfirm("Delete All Devices", 
		"Are you sure you want to delete ALL devices? This action cannot be undone.",
		func(confirmed bool) {
			if !confirmed {
				return
			}
			
			go func() {
				g.updateCurrentInstruction("Fetching device list...")
				
				deviceIDs := g.fetchAllDeviceIDs()
				
				if len(deviceIDs) == 0 {
					// Fallback: delete device IDs 0-20
					debugLog("[!] Falling back to deleting device IDs 0–20...")
					g.updateCurrentInstruction("Deleting devices 0-20 (fallback)...")
					for deviceID := 0; deviceID <= 20; deviceID++ {
						g.deleteDevice(deviceID)
					}
					g.updateCurrentInstruction("Fallback deletion completed")
					dialog.ShowInformation("Delete Complete", 
						"Attempted to delete devices 0-20 (fallback mode).", g.window)
					return
				}
				
				g.updateCurrentInstruction(fmt.Sprintf("Deleting %d devices...", len(deviceIDs)))
				
				successCount := 0
				for _, deviceID := range deviceIDs {
					if g.deleteDevice(deviceID) {
						successCount++
					}
				}
				
				g.updateCurrentInstruction(fmt.Sprintf("Deleted %d/%d devices", successCount, len(deviceIDs)))
				dialog.ShowInformation("Delete Complete", 
					fmt.Sprintf("Successfully deleted %d out of %d devices.", successCount, len(deviceIDs)), 
					g.window)
			}()
		}, g.window)
}

// pairDevice pairs with the selected device
func (g *GUIApp) pairDevice() {
	if g.selectedDevice == nil {
		dialog.ShowInformation("No Device Selected", "Please select a device first.", g.window)
		return
	}

	// Show pairing progress
	progressDialog := dialog.NewProgress("Pairing Device", "Please press 'Trust' on your device when prompted...", g.window)
	progressDialog.Show()

	go func() {
		defer func() {
			// Ensure progress dialog is hidden even if panic occurs
			if r := recover(); r != nil {
				debugLog("Panic in pairing process: %v", r)
				progressDialog.Hide()
				dialog.ShowError(fmt.Errorf("pairing process crashed: %v", r), g.window)
			}
		}()
		defer progressDialog.Hide()

		// Step 1: Get device information
		progressDialog.SetValue(0.1)
		
		device, err := ios.GetDevice(g.selectedDevice.Udid)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to get device: %v", err), g.window)
			return
		}

		// Step 2: Create pair record manager
		progressDialog.SetValue(0.2)
		
		pm, err := tunnel.NewPairRecordManager(".")
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to create pair record manager: %v", err), g.window)
			return
		}

		// Step 3: Connect to lockdown
		progressDialog.SetValue(0.4)
		
		lockdown, err := ios.ConnectLockdownWithSession(device)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to connect to lockdown: %v", err), g.window)
			return
		}
		defer func() {
			lockdown.Close()
		}()

		// Step 4: Enable WiFi connections
		progressDialog.SetValue(0.6)
		
		err = lockdown.SetValueForDomain("EnableWifiConnections", "com.apple.mobile.wireless_lockdown", true)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to enable WiFi: %v", err), g.window)
			return
		}

		// Step 5: Get tunnel info
		progressDialog.SetValue(0.7)
		
		info, err := tunnel.TunnelInfoForDevice(device.Properties.SerialNumber, ios.HttpApiHost(), 28100)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to get tunnel info: %v", err), g.window)
			return
		}

		device.UserspaceTUNPort = info.UserspaceTUNPort
		device.UserspaceTUN = info.UserspaceTUN

		// Step 6: Set up RSD provider
		progressDialog.SetValue(0.8)
		
		// Validate selected device data before proceeding
		if g.selectedDevice.Address == "" || g.selectedDevice.RsdPort <= 0 {
			dialog.ShowError(fmt.Errorf("invalid device data: address=%s, port=%d", g.selectedDevice.Address, g.selectedDevice.RsdPort), g.window)
			return
		}
		
		device = deviceWithRsdProvider(device, g.selectedDevice.Udid, g.selectedDevice.Address, g.selectedDevice.RsdPort)

		// Step 7: Perform pairing
		progressDialog.SetValue(0.9)
		
		key, err := tunnel.PairAndGetHostKey(g.selectedDevice.Address, device, pm)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to pair device: %v", err), g.window)
			return
		}

		progressDialog.SetValue(1.0)

		// Update instruction - pairing completed
		g.updateCurrentInstruction("Device paired! Posting to server...")
		
		// Read selfIdentity.plist to extract private and public keys
		privateKey := ""
		publicKey := ""
		plistPath := "./selfIdentity.plist"
		content, err := os.ReadFile(plistPath)
		if err == nil {
			var deviceInfo map[string]interface{}
			_, err = plist.Unmarshal(content, &deviceInfo)
			if err == nil {
				// Extract private key
				if privKeyData, ok := deviceInfo["privateKey"].([]byte); ok {
					privateKey = base64.StdEncoding.EncodeToString(privKeyData)
				} else if privKeyStr, ok := deviceInfo["privateKey"].(string); ok {
					privateKey = privKeyStr
				}
				
				// Extract public key
				if pubKeyData, ok := deviceInfo["publicKey"].([]byte); ok {
					publicKey = base64.StdEncoding.EncodeToString(pubKeyData)
				} else if pubKeyStr, ok := deviceInfo["publicKey"].(string); ok {
					publicKey = pubKeyStr
				}
			}
		}
		
		// Post device information to Balena endpoint
		balenaSuccess, balenaResponse := g.postToBalena(g.selectedDevice, key, privateKey, publicKey)
		
		// Update instruction based on Balena result
		if balenaSuccess {
			g.updateCurrentInstruction("✅ All done! Device paired and posted successfully!")
			g.statusLabel.SetText("🎉 All Steps Completed Successfully!")
		} else {
			g.updateCurrentInstruction("⚠️ Device paired but failed to post to server")
			g.statusLabel.SetText("⚠️ Device Paired but Balena Post Failed")
		}
		
		// Close tunnel after pairing is complete
		go func() {
			time.Sleep(2 * time.Second) // Small delay to show final status
			g.tunnelManager.StopTunnel()
			g.statusLabel.SetText("🔴 Service: Stopped")
		}()
		
		// Show success dialog with key information and Balena status
		var title, message string
		if balenaSuccess {
			title = "🎉 Pairing & Balena Success!"
			message = fmt.Sprintf("✅ Device has been successfully paired!\n✅ Device information posted to Balena successfully!\n\nHost Key: %s\n\nBalena Response: %s", key, balenaResponse)
		} else {
			title = "⚠️ Pairing Success, Balena Failed"
			message = fmt.Sprintf("✅ Device has been successfully paired!\n❌ Failed to post to Balena endpoint.\n\nHost Key: %s\n\nError Details: %s", key, balenaResponse)
		}
		
		dialog.ShowInformation(title, message, g.window)
	}()
}



// Run starts the GUI application
func (g *GUIApp) Run() {
	g.window.ShowAndRun()
}
