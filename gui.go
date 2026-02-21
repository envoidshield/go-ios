//go:build gui
// +build gui

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
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

// isAdmin checks if the program is running with administrator privileges on Windows
func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

// UIState represents the current state of the UI wizard
type UIState int

const (
	StateIdle UIState = iota
	StateServiceStarting
	StateWaitingForDevice
	StatePairing
	StateSuccess
	StateError
)

// GUIApp represents the main GUI application
type GUIApp struct {
	app            fyne.App
	window         fyne.Window
	tunnelManager  *TunnelManager
	tunnelStatus   binding.String
	deviceList     binding.StringList
	selectedDevice *tunnel.Tunnel
	currentState   UIState

	// UI components
	mainContainer     *fyne.Container
	logoImage         *fyne.Container
	titleLabel        *widget.Label
	stepLabel         *widget.Label
	progressIndicator *widget.ProgressBar
	statusCard        *widget.Card
	instructionLabel  *widget.Label
	deviceNameLabel   *widget.Label
	actionButton      *widget.Button
	cancelButton      *widget.Button
	closeButton       *widget.Button
	detailsLabel      *widget.Label
	spinner           *widget.ProgressBarInfinite
	mainMenu          *fyne.MainMenu

	// Legacy components (for compatibility)
	statusLabel        *widget.Label
	deviceListBox      *widget.List
	startButton        *widget.Button
	stopButton         *widget.Button
	refreshButton      *widget.Button
	pairButton         *widget.Button
	progressBar        *widget.ProgressBar
	pairingStatusLabel *widget.Label
	balenaStatusLabel  *widget.Label
	lastPairingInfo    *widget.Label
}

// forceLight is a custom theme that forces light mode with opaque progress bar
type forceLight struct{}

func (f *forceLight) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// Make progress bar more opaque
	if name == theme.ColorNamePrimary {
		return color.RGBA{R: 0, G: 122, B: 255, A: 255} // Solid blue
	}
	return theme.DefaultTheme().Color(name, theme.VariantLight)
}

func (f *forceLight) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (f *forceLight) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (f *forceLight) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

// NewGUIApp creates a new GUI application
func NewGUIApp() *GUIApp {
	myApp := app.NewWithID("com.tunnelmanager.app")

	// Force light theme regardless of system settings
	myApp.Settings().SetTheme(&forceLight{})

	// Use embedded favicon.ico as app icon
	myApp.SetIcon(resourceFaviconIco)

	window := myApp.NewWindow("ENVOID Pairing Assistant")
	window.Resize(fyne.NewSize(500, 700))
	window.CenterOnScreen()

	// Set Windows-specific properties
	window.SetFixedSize(false)
	window.SetMaster()

	// Create temporary directory for pairing records
	tempDir := os.TempDir()
	pairingDir := fmt.Sprintf("envoid-pairing-%d", time.Now().Unix())
	recordsPath := fmt.Sprintf("%s/%s", tempDir, pairingDir)

	// Create the directory
	if err := os.MkdirAll(recordsPath, 0755); err != nil {
		log.Printf("Warning: failed to create temporary directory: %v", err)
		recordsPath = "." // Fallback to current directory
	} else {
		log.Printf("Using temporary directory: %s", recordsPath)
	}

	// Create tunnel manager
	tunnelManager := NewTunnelManager(recordsPath, 28100, "localhost", false)

	gui := &GUIApp{
		app:           myApp,
		window:        window,
		tunnelManager: tunnelManager,
		tunnelStatus:  binding.NewString(),
		deviceList:    binding.NewStringList(),
		currentState:  StateIdle,
	}

	gui.setupUI()
	gui.setupEventHandlers()

	// Setup cleanup on window close
	window.SetOnClosed(func() {
		log.Println("Window closing, cleaning up...")
		if err := tunnelManager.Cleanup(); err != nil {
			log.Printf("Error during cleanup: %v", err)
		}
	})

	// Check for administrator privileges
	if !isAdmin() {
		dialog.ShowInformation("Administrator Privileges Required",
			"This application requires administrator privileges to function properly.\n\n"+
				"Please close this window and restart the program by:\n"+
				"1. Right-click on the program icon\n"+
				"2. Select 'Run as administrator'\n\n"+
				"The program will continue but some features may not work correctly.",
			window)
	}

	return gui
}

// setupUI creates the user interface
func (g *GUIApp) setupUI() {
	// Create menu bar
	g.createMenuBar()

	// === HEADER SECTION - Logo prominente ===
	g.logoImage = g.createLogoHeader()

	// === PROGRESS SECTION - Diseño limpio y moderno ===
	g.stepLabel = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: false})

	g.progressIndicator = widget.NewProgressBar()
	g.progressIndicator.SetValue(0.0)

	// Wrap progress bar to ensure full opacity
	progressContainer := container.NewStack(
		canvas.NewRectangle(color.Transparent),
		g.progressIndicator,
	)

	progressSection := container.NewVBox(
		container.NewPadded(g.stepLabel),
		container.NewPadded(progressContainer),
	)

	// === STATUS SECTION - Mensajes centrados y claros ===
	g.instructionLabel = widget.NewLabelWithStyle(
		"Connect your iPhone via USB to get started",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: false},
	)
	g.instructionLabel.Wrapping = fyne.TextWrapWord

	g.deviceNameLabel = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	g.deviceNameLabel.Hide()

	g.spinner = widget.NewProgressBarInfinite()
	g.spinner.Hide()

	g.detailsLabel = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	g.detailsLabel.Wrapping = fyne.TextWrapWord
	g.detailsLabel.Hide()

	statusSection := container.NewVBox(
		g.instructionLabel,
		g.deviceNameLabel,
		g.spinner,
		g.detailsLabel,
	)

	// === ACTION BUTTON - Grande y prominente ===
	g.actionButton = widget.NewButton("Start Pairing", g.startPairingFlow)
	g.actionButton.Importance = widget.HighImportance

	g.cancelButton = widget.NewButton("Cancel", g.cancelPairingFlow)
	g.cancelButton.Hide()

	g.closeButton = widget.NewButton("Close", func() {
		g.window.Close()
	})
	g.closeButton.Importance = widget.HighImportance
	g.closeButton.Hide()

	buttonContainer := container.NewVBox(
		g.actionButton,
		g.cancelButton,
		g.closeButton,
	)

	// === LAYOUT PRINCIPAL - Espaciado vertical elegante ===
	content := container.NewVBox(
		layout.NewSpacer(),
		g.logoImage,
		layout.NewSpacer(),
		container.NewPadded(progressSection),
		layout.NewSpacer(),
		container.NewPadded(statusSection),
		layout.NewSpacer(),
		container.NewCenter(buttonContainer),
		layout.NewSpacer(),
		layout.NewSpacer(),
		layout.NewSpacer(),
		layout.NewSpacer(),
	)

	// Padding generoso
	paddedContent := container.NewPadded(
		container.NewPadded(content),
	)

	// === WATERMARK BACKGROUND - Aligned to bottom ===
	watermarkImg := canvas.NewImageFromResource(resourceWatermarkPng)
	watermarkImg.FillMode = canvas.ImageFillContain
	watermarkImg.Translucency = 0.83                // Transparent watermark
	watermarkImg.SetMinSize(fyne.NewSize(450, 450)) // Set minimum size

	// Create a centered container for the watermark at bottom
	watermarkCentered := container.NewCenter(watermarkImg)

	// Position watermark at bottom
	watermarkBox := container.NewVBox(
		layout.NewSpacer(),
		watermarkCentered,
	)

	// Stack background behind content
	stackedContent := container.NewStack(
		watermarkBox,
		paddedContent,
	)

	g.window.SetContent(stackedContent)

	// Initialize legacy components for compatibility
	g.statusLabel = widget.NewLabel("")
	g.progressBar = widget.NewProgressBar()
	g.pairingStatusLabel = widget.NewLabel("")
	g.statusCard = widget.NewCard("", "", container.NewVBox())
	g.titleLabel = widget.NewLabel("")
}

// createLogoHeader creates the logo header section
func (g *GUIApp) createLogoHeader() *fyne.Container {
	// Use embedded ENVOID logo - MUCH larger and hero-style
	img := canvas.NewImageFromResource(resourceENVOIDPng)
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(350, 120))
	return container.NewCenter(img)
}

// createMenuBar creates the application menu bar
func (g *GUIApp) createMenuBar() {
	// Devices menu
	devicesMenu := fyne.NewMenu("Devices",
		fyne.NewMenuItem("Delete All Devices", func() {
			g.deleteAllDevices()
		}),
	)

	// Help menu
	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("How to Use", func() {
			g.showHelpDialog()
		}),
		fyne.NewMenuItem("About", func() {
			g.showAboutDialog()
		}),
	)

	// Create main menu (without File menu to avoid duplicate Quit/Exit)
	g.mainMenu = fyne.NewMainMenu(devicesMenu, helpMenu)
	g.window.SetMainMenu(g.mainMenu)
}

// showHelpDialog displays comprehensive help information
func (g *GUIApp) showHelpDialog() {
	helpText := `HOW TO PAIR YOUR DEVICE

1. Click "Start Pairing Process"
2. Connect iPhone via USB cable
3. Unlock iPhone and tap "Trust This Computer"
4. Wait for pairing to complete

REQUIREMENTS
• Run as Administrator
• USB cable connection
• iPhone unlocked during pairing
• Network connection

TROUBLESHOOTING
• Check USB cable connection
• Ensure iPhone is unlocked
• Verify you tapped "Trust"
• Run as Administrator

Contact ENVOID support for help.`

	dialog.ShowInformation("How to Use", helpText, g.window)
}

// showAboutDialog displays about information
func (g *GUIApp) showAboutDialog() {
	aboutText := `iOS Device Pairing Assistant

Version: 2.5.0
Developed by: ENVOID

This application facilitates iOS device pairing
for the ENVOID platform.

© 2025 ENVOID. All rights reserved.`

	content := container.NewVBox(
		widget.NewLabel(aboutText),
	)

	customDialog := dialog.NewCustom("About", "OK", content, g.window)
	customDialog.Show()
}

// showPrivacyPolicy displays the privacy policy in a scrollable dialog (embedded in exe)
func (g *GUIApp) showPrivacyPolicy() {
	privacyText := `Privacy Policy

Last Updated: December 1, 2025

This Privacy Policy describes how Envoid Shield Limited ("Company," "We," "Us," or "Our") operates the Envoid Pairing Assistant application (the "Application") and protects your privacy through secure, isolated local network communication.

By using the Application, you acknowledge that you have read and understood this Privacy Policy. If you do not agree with any part of this policy, you should refrain from using the Application.

1. DEFINITIONS

• Company: Envoid Shield Limited, with its principal office at 7700 Broadway St, Ste 104 PMB1064, San Antonio, TX 78209, United States.
• Application: The Envoid Pairing Assistant desktop software for Windows.
• Envoid System: The EnPort device or Envoid infrastructure that manages iOS devices within your organization.
• Personal Data: Device identifiers (UDID), device name, and pairing certificates necessary for device management.
• You: Any individual or entity using the Application, either personally or as a representative of an organization.

2. HOW THIS APPLICATION WORKS

The Envoid Pairing Assistant is designed as a secure bridge that connects your iOS device to your Envoid system through an isolated WiFi Direct network, with no internet connection required or used.

Isolated Network Architecture:
• WiFi Direct Only: All communication occurs exclusively over the isolated WiFi Direct network generated by your Envoid device
• No Internet: The Application does not connect to the internet and cannot transmit data outside the local network
• Closed Environment: Data remains within the secure local environment at all times
• Direct Connection: Your device communicates directly with your Envoid system only

What This Means for Your Privacy:
If you are not connected to the Envoid WiFi Direct network, the Application cannot function and no data is shared with anyone. The Application is specifically designed to communicate only within this isolated network environment.

3. SECURE PAIRING PROCESS

The Application facilitates a secure pairing between your iOS device and your Envoid system:
1. Device Connection: You connect your iPhone via USB cable
2. Trust Establishment: You authorize the connection by tapping "Trust" on your device
3. Certificate Exchange: Secure pairing certificates are exchanged using Apple's encrypted pairing protocol
4. Registration: Your device is registered with your local Envoid system for management

Temporary Data During Pairing:
• Location: System temporary directory on your computer
• Duration: Only while the Application is running
• Automatic Deletion: All temporary data is automatically deleted when you close the Application
• No Permanent Storage: The Application does not permanently store any information on your computer

4. DATA TRANSMISSION SECURITY

Local Network Only:
All data transmission occurs exclusively within your local network:
• Communication is limited to: your computer ↔ your iOS device ↔ your Envoid system
• Zero internet traffic - no data leaves the local environment
• Zero third-party access - no external services or servers involved
• Zero cloud storage - everything remains on-premises

Encryption and Authentication:
• Apple Secure Pairing Protocol: Uses industry-standard 2048-bit RSA encryption
• Physical Authentication Required: Requires USB connection, device unlock, and explicit user consent ("Trust" prompt)
• Administrator Protection: Application requires elevated privileges to prevent unauthorized access

5. DATA STORAGE AND RETENTION

On Your Computer:
• Nothing is permanently stored - all data is automatically deleted when you close the Application
• Temporary pairing certificates exist only in memory and system temp directory during operation

On Your Envoid System:
• Device identification and pairing information is stored on your local Envoid system only
• This enables your organization to manage your device
• Data never leaves your local network environment
• Retention is controlled by your organization's policies

6. SHARING OF DATA

We do not share your personal data with any third parties. All data is transmitted solely to your paired Envoid system within your local network environment.

Your data remains under your or your organization's control and is not accessed or disclosed externally unless required by law or with your explicit consent.

7. TRACKING TECHNOLOGIES & COOKIES

We do not use tracking technologies, cookies, or analytics tools in the Application.

8. NETWORK ISOLATION = PRIVACY PROTECTION

The Application's security architecture ensures privacy through isolation:
• Cannot operate without WiFi Direct connection - if not connected to your Envoid network, no communication occurs
• Cannot access internet - designed exclusively for local network operation
• Cannot transmit externally - no mechanism exists to send data outside the local environment
• Cannot share with third parties - no third-party services, analytics, or tracking

9. USER RIGHTS (GDPR & CCPA)

For Users in the European Union (GDPR):
You have the right to:
• Right to be informed: Know what personal data is collected and how it is used
• Access your data: Request access to the personal data we process about you
• Request corrections: Request correction of any incomplete or inaccurate data
• Request deletion: Request deletion of your personal data
• Restrict processing: Request that we restrict processing of your personal data
• Object to processing: Object to processing where we rely on legitimate interests
• Data portability: Request transfer of your data in a machine-readable format
• Withdraw consent: Withdraw your consent at any time
• File complaints: Make a complaint to your local data protection authority

For Users in California (CCPA):
California residents have additional rights under the California Consumer Privacy Act.

Your Control Over Data:
You maintain complete control:
• Close the Application: All local data is immediately and automatically deleted
• Disconnect from Network: Application cannot function without the isolated WiFi Direct connection
• Remove Device Registration: Use the "Delete All Devices" feature or contact your administrator
• Revoke Trust: Use iOS Settings → General → Transfer or Reset iPhone → Reset Location & Privacy

To exercise your privacy rights, contact us at info@envoid.com or contact your organization's administrator.

10. SPECIAL CATEGORIES OF PERSONAL DATA

We do not collect any special categories of personal data about you, including details about your race or ethnicity, religious or philosophical beliefs, sex life, sexual orientation, or political opinions.

11. WHAT WE DO NOT DO

The Application does not:
• Access personal content (photos, messages, documents, contacts, etc.)
• Connect to the internet
• Transmit data outside the local network
• Share data with third parties
• Use analytics, tracking, or telemetry services
• Store data permanently on your computer
• Upload data to cloud services

12. CHILDREN'S PRIVACY

This Application is designed for enterprise use and does not access any personal content from iOS devices. It only facilitates secure device pairing.

13. INTERNATIONAL TRANSFERS

By default, the Application transmits data only to your local Envoid system within your network environment. No international data transfers occur because all communication is confined to your isolated local network.

14. TECHNICAL COMPLIANCE

This Application's architecture inherently complies with data protection regulations (GDPR, CCPA, etc.) because:
• All processing occurs within your local, isolated network
• No data is transmitted to external parties
• No cloud processing or storage
• No cross-border data transfers
• Minimal data collection by design

15. THIRD-PARTY LINKS AND SITES

The Application does not contain links to third-party websites or services. All functionality is self-contained and operates exclusively within your local network environment.

16. CHANGES TO THIS POLICY

We may update this Privacy Policy to reflect changes to the Application. The "Effective Date" above indicates the last revision. Continued use of the Application constitutes acceptance of the updated policy.

17. CONTACT US

For any questions regarding this Privacy Policy, you can contact us at:

Envoid Shield Limited
7700 Broadway St, Ste 104 PMB1064
San Antonio, TX 78209
United States

Email: info@envoid.com
Website: https://www.envoid.com

For questions about data stored on your Envoid system, contact your organization's administrator.

18. YOUR CONSENT

By using the Envoid Pairing Assistant, you acknowledge that you have read and understood this Privacy Policy and agree to its terms.

You understand that:
• The Application operates exclusively within an isolated local network
• No data is transmitted outside this secure environment
• All local data is automatically deleted when you close the Application
• The Application cannot function without connection to your Envoid WiFi Direct network

If you do not agree with this policy, please discontinue use of the Application immediately.

© 2025 Envoid Shield Limited. All rights reserved.

Designed for Privacy. Built for Security. Operates in Isolation.`

	// Create scrollable content with RichText for better performance
	richText := widget.NewRichTextFromMarkdown(privacyText)
	richText.Wrapping = fyne.TextWrapWord

	scroll := container.NewScroll(richText)
	scroll.SetMinSize(fyne.NewSize(600, 500))

	customDialog := dialog.NewCustom("Privacy Policy", "Close", scroll, g.window)
	customDialog.Resize(fyne.NewSize(650, 550))
	customDialog.Show()
}

// startPairingFlow starts the pairing wizard flow
func (g *GUIApp) startPairingFlow() {
	// Reset selected device if starting new pairing
	g.selectedDevice = nil

	g.currentState = StateServiceStarting
	g.updateUIForState()

	// Hide action button and close button, show cancel button
	g.actionButton.Hide()
	g.closeButton.Hide()
	g.cancelButton.Show()

	// Start the service
	go g.startTunnel()
}

// cancelPairingFlow cancels the pairing process
func (g *GUIApp) cancelPairingFlow() {
	g.stopTunnel()
	g.currentState = StateIdle
	g.updateUIForState()

	// Show action button, hide cancel button
	g.actionButton.Show()
	g.cancelButton.Hide()
}

// updateUIForState updates the UI based on current state
func (g *GUIApp) updateUIForState() {
	switch g.currentState {
	case StateIdle:
		g.stepLabel.SetText("")
		g.progressIndicator.SetValue(0.0)
		g.instructionLabel.SetText("Connect your iPhone to get started")
		g.deviceNameLabel.Hide()
		g.spinner.Hide()
		g.detailsLabel.Hide()
		g.actionButton.SetText("Start Pairing")
		g.actionButton.Show()
		g.cancelButton.Hide()
		g.closeButton.Hide()

	case StateServiceStarting:
		g.stepLabel.SetText("Starting...")
		g.progressIndicator.SetValue(0.33)
		g.instructionLabel.SetText("Initializing pairing service")
		g.deviceNameLabel.Hide()
		g.spinner.Show()
		g.spinner.Start()
		g.detailsLabel.Hide()

	case StateWaitingForDevice:
		g.stepLabel.SetText("Waiting for device")
		g.progressIndicator.SetValue(0.5)
		g.instructionLabel.SetText("Connect iPhone via USB")
		g.deviceNameLabel.SetText("Unlock your iPhone and tap 'Trust This Computer', then enter passcode")
		g.deviceNameLabel.Show()
		g.spinner.Show()
		g.spinner.Start()
		g.detailsLabel.Hide()

	case StatePairing:
		g.stepLabel.SetText("Pairing device")
		g.progressIndicator.SetValue(0.8)
		g.instructionLabel.SetText("Finalizing connection")
		g.deviceNameLabel.SetText("Tap 'Trust' for ENVOID if prompted, then enter passcode")
		g.deviceNameLabel.Show()
		g.spinner.Show()
		g.spinner.Start()
		g.detailsLabel.Hide()

	case StateSuccess:
		g.stepLabel.SetText("Success")
		g.progressIndicator.SetValue(1.0)
		g.instructionLabel.SetText("Your device has been paired!")
		g.deviceNameLabel.SetText("Connect your iPhone to EnvoidDirect WiFi to be protected by the EnPortable")
		g.deviceNameLabel.Show()
		g.spinner.Stop()
		g.spinner.Hide()
		g.detailsLabel.Hide()
		g.actionButton.SetText("Pair Another Device")
		g.actionButton.Importance = widget.MediumImportance
		g.actionButton.Show()
		g.cancelButton.Hide()
		g.closeButton.SetText("Done")
		g.closeButton.Importance = widget.HighImportance
		g.closeButton.Show()

	case StateError:
		g.stepLabel.SetText("Connection Error")
		g.progressIndicator.SetValue(0.0)
		g.instructionLabel.SetText("Unable to complete pairing")
		g.deviceNameLabel.SetText("Please check:\n• Computer is connected to EnvoidDirect WiFi\n• iPhone is unlocked\n• Trust prompt was accepted with the correct passcode")
		g.deviceNameLabel.Show()
		g.spinner.Stop()
		g.spinner.Hide()
		g.detailsLabel.Hide()
		g.actionButton.SetText("Try Again")
		g.actionButton.Importance = widget.HighImportance
		g.actionButton.Show()
		g.cancelButton.Hide()
		g.closeButton.SetText("Close")
		g.closeButton.Show()
	}
}

// setupEventHandlers sets up event handlers
func (g *GUIApp) setupEventHandlers() {
	// Monitor service and device status
	go g.monitorPairingFlow()
}

// monitorPairingFlow monitors the service and device status
func (g *GUIApp) monitorPairingFlow() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Only monitor if we're in an active state
		if g.currentState == StateServiceStarting || g.currentState == StateWaitingForDevice {
			if g.tunnelManager.IsRunning() {
				// Service is running, check for devices
				if g.currentState == StateServiceStarting {
					g.currentState = StateWaitingForDevice
					g.updateUIForState()
				}

				// Check for devices
				go g.checkForDevices()
			}
		}
	}
}

// checkForDevices checks for connected devices
func (g *GUIApp) checkForDevices() {
	if g.currentState != StateWaitingForDevice {
		return
	}

	tunnels, err := g.tunnelManager.ListTunnels()
	if err != nil || len(tunnels) == 0 {
		return
	}

	// Device found! Update UI and start pairing
	firstTunnel := tunnels[0]
	deviceName := g.getDeviceName(firstTunnel.Udid)
	if deviceName == "" {
		deviceName = fmt.Sprintf("iPhone (%s...)", firstTunnel.Udid[:8])
	}

	g.deviceNameLabel.SetText(fmt.Sprintf("Device detected: %s", deviceName))
	g.deviceNameLabel.Show()

	// Store selected device
	g.selectedDevice = &firstTunnel

	// Transition to pairing state
	g.currentState = StatePairing
	g.updateUIForState()

	// Start pairing after a short delay
	time.Sleep(1 * time.Second)
	go g.pairDevice()
}

// startTunnel starts the tunnel service
func (g *GUIApp) startTunnel() {
	err := g.tunnelManager.StartTunnel()
	if err != nil {
		g.currentState = StateError
		g.updateUIForState()
		g.detailsLabel.SetText(fmt.Sprintf("Error: %v", err))
		g.detailsLabel.Show()
	}
}

// stopTunnel stops the tunnel service
func (g *GUIApp) stopTunnel() {
	g.tunnelManager.StopTunnel()
	g.selectedDevice = nil
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
		"device_type":            "iPhone",   // Required field
		"private_key":            privateKey, // Ed25519 private key (base64 encoded)
		"public_key":             publicKey,  // Ed25519 public key (base64 encoded)
		"remote_unlock_host_key": hostKey,    // Use hostKey as remote unlock host key
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

			// Show progress dialog
			progressDialog := dialog.NewProgress("Deleting Devices", "Fetching device list...", g.window)
			progressDialog.Show()

			go func() {
				defer progressDialog.Hide()

				deviceIDs := g.fetchAllDeviceIDs()

				if len(deviceIDs) == 0 {
					// Fallback: delete device IDs 0-20
					debugLog("[!] Falling back to deleting device IDs 0–20...")
					progressDialog.SetValue(0.5)
					for deviceID := 0; deviceID <= 20; deviceID++ {
						g.deleteDevice(deviceID)
					}
					progressDialog.SetValue(1.0)
					dialog.ShowInformation("Delete Complete",
						"Attempted to delete devices 0-20 (fallback mode).", g.window)
					return
				}

				successCount := 0
				total := len(deviceIDs)
				for i, deviceID := range deviceIDs {
					if g.deleteDevice(deviceID) {
						successCount++
					}
					progressDialog.SetValue(float64(i+1) / float64(total))
				}

				dialog.ShowInformation("Delete Complete",
					fmt.Sprintf("Successfully deleted %d out of %d devices.", successCount, total),
					g.window)
			}()
		}, g.window)
}

// pairDevice pairs with the selected device
func (g *GUIApp) pairDevice() {
	if g.selectedDevice == nil {
		g.currentState = StateError
		g.updateUIForState()
		g.detailsLabel.SetText("No device selected")
		return
	}

	go func() {
		defer func() {
			// Ensure recovery from panics
			if r := recover(); r != nil {
				debugLog("Panic in pairing process: %v", r)
				g.currentState = StateError
				g.updateUIForState()
				g.detailsLabel.SetText(fmt.Sprintf("Pairing crashed: %v", r))
			}
		}()

		// Update status: Getting device information
		g.detailsLabel.SetText("Getting device information...")

		device, err := ios.GetDevice(g.selectedDevice.Udid)
		if err != nil {
			g.handlePairingError("Failed to get device", err)
			return
		}

		// Update status: Creating pair record manager
		g.detailsLabel.SetText("Initializing pairing...")

		pm, err := tunnel.NewPairRecordManager(g.tunnelManager.RecordsPath)
		if err != nil {
			g.handlePairingError("Failed to create pair record manager", err)
			return
		}

		// Update status: Connecting to device
		g.detailsLabel.SetText("Connecting to device...")

		lockdown, err := ios.ConnectLockdownWithSession(device)
		if err != nil {
			g.handlePairingError("Failed to connect. Please check:\n• USB cable is connected\n• Device is unlocked\n• You tapped Trust on device", err)
			return
		}
		defer lockdown.Close()

		// Update status: Enabling WiFi connections
		g.detailsLabel.SetText("Enabling WiFi connections...")

		err = lockdown.SetValueForDomain("EnableWifiConnections", "com.apple.mobile.wireless_lockdown", true)
		if err != nil {
			g.handlePairingError("Failed to enable WiFi", err)
			return
		}

		// Update status: Getting tunnel information
		g.detailsLabel.SetText("Getting tunnel information...")

		info, err := tunnel.TunnelInfoForDevice(device.Properties.SerialNumber, ios.HttpApiHost(), 28100)
		if err != nil {
			g.handlePairingError("Failed to get tunnel info", err)
			return
		}

		device.UserspaceTUNPort = info.UserspaceTUNPort
		device.UserspaceTUN = info.UserspaceTUN

		// Update status: Setting up RSD provider
		g.detailsLabel.SetText("Setting up RSD provider...")

		// Validate selected device data
		if g.selectedDevice.Address == "" || g.selectedDevice.RsdPort <= 0 {
			g.handlePairingError("Invalid device data", fmt.Errorf("address=%s, port=%d", g.selectedDevice.Address, g.selectedDevice.RsdPort))
			return
		}

		device = deviceWithRsdProvider(device, g.selectedDevice.Udid, g.selectedDevice.Address, g.selectedDevice.RsdPort)

		// Update status: Exchanging certificates
		g.detailsLabel.SetText("Exchanging certificates...")

		key, err := tunnel.PairAndGetHostKey(g.selectedDevice.Address, device, pm)
		if err != nil {
			g.handlePairingError("Failed to pair device", err)
			return
		}

		// Update status: Pairing completed, posting to server
		g.detailsLabel.SetText("Posting to server...")

		// Read selfIdentity.plist to extract private and public keys
		privateKey := ""
		publicKey := ""
		plistPath := fmt.Sprintf("%s/selfIdentity.plist", g.tunnelManager.RecordsPath)
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

		// Update state based on result
		if balenaSuccess {
			g.currentState = StateSuccess
			g.updateUIForState()
		} else {
			g.currentState = StateError
			g.updateUIForState()
			g.detailsLabel.SetText(fmt.Sprintf("Device paired but server post failed:\n%s", balenaResponse))
		}

		// Close tunnel after completion
		time.Sleep(2 * time.Second)
		g.tunnelManager.StopTunnel()

		// Show simple final dialog (no technical details)
		if balenaSuccess {
			dialog.ShowInformation("Success",
				"Device paired and registered successfully.\n\nYou can now close this window or pair another device.",
				g.window)
		} else {
			dialog.ShowInformation("Pairing Completed",
				"Device paired but server communication failed.\n\nMake sure your computer is connected to the EnvoidDirect network.",
				g.window)
		}
	}()
}

// handlePairingError handles errors during pairing
func (g *GUIApp) handlePairingError(userMessage string, err error) {
	debugLog("Pairing error: %s - %v", userMessage, err)
	g.currentState = StateError
	g.updateUIForState()
	g.instructionLabel.SetText(userMessage)

	if err != nil {
		// Create user-friendly error message
		errorMsg := err.Error()

		// Detect common error patterns and provide helpful messages
		if strings.Contains(errorMsg, "failed to pair device") ||
			strings.Contains(errorMsg, "setupSessionKey") ||
			strings.Contains(errorMsg, "pairingData") {
			g.detailsLabel.SetText("Please ensure:\n• Device is unlocked\n• You tapped 'Trust' on device\n• Try unplugging and reconnecting")
		} else if strings.Contains(errorMsg, "connection refused") {
			g.detailsLabel.SetText("Connection failed. Please check USB cable.")
		} else if strings.Contains(errorMsg, "timeout") {
			g.detailsLabel.SetText("Connection timeout. Please try again.")
		} else {
			// Truncate long technical errors
			maxLen := 100
			if len(errorMsg) > maxLen {
				errorMsg = errorMsg[:maxLen] + "..."
			}
			g.detailsLabel.SetText(fmt.Sprintf("Error: %s", errorMsg))
		}
	}
	g.detailsLabel.Show()
}

// Run starts the GUI application
func (g *GUIApp) Run() {
	g.window.ShowAndRun()
}
