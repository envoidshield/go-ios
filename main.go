package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"  // Added for base64 encoding
	"encoding/json"  // Added for JSON marshaling
	"fmt"
	"io"            // Added for reading response body
	"log"
	"net/http"      // Added for HTTP POST request
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel"
	"howett.net/plist"
)

// TunnelManager handles tunnel service operations
type TunnelManager struct {
	recordsPath    string
	tunnelInfoPort int
	tunnelInfoHost string
	userspaceTUN   bool
	ctx            context.Context
	cancel         context.CancelFunc
	running        bool
}

type CLI struct {
	tunnelManager *TunnelManager
	reader        *bufio.Reader
	running       bool
}


// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(recordsPath string, tunnelInfoPort int, tunnelInfoHost string, userspaceTUN bool) *TunnelManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TunnelManager{
		recordsPath:    recordsPath,
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
		filePath := "selfIdentity.plist"

    // Check if the file exists
    if _, err := os.Stat(filePath); err == nil {
        // File exists, so delete it
        err := os.Remove(filePath)
        if err != nil {
            fmt.Printf("Error deleting file: %v\n", err)
            return // Exit the program if deletion fails
        }
        fmt.Printf("File '%s' deleted successfully.\n", filePath)
    } else {
        fmt.Printf("File '%s' does not exist.\n", filePath)
    }
		pm, err := tunnel.NewPairRecordManager(tm.recordsPath)
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
		tm.cancel()
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


// NewCLI creates a new CLI instance
func NewCLI(tunnelManager *TunnelManager) *CLI {
	return &CLI{
		tunnelManager: tunnelManager,
		reader:        bufio.NewReader(os.Stdin),
		running:       true,
	}
}

// printMenu displays the main menu
func (c *CLI) printMenu() {
	fmt.Println("\n===== Tunnel Manager =====")
	statusText := "Stopped"
	if c.tunnelManager.IsRunning() {
		statusText = "Running"
	}
	fmt.Printf("Service Status: %s\n\n", statusText)
	
	fmt.Println("1. Start Tunnel Service")
	fmt.Println("2. Stop Tunnel Service")
	fmt.Println("3. List Tunnels")
	fmt.Println("4. Pair with Device")
	fmt.Println("5. Read Device Plist")
	fmt.Println("6. Settings")
	fmt.Println("0. Exit")
	fmt.Print("\nEnter your choice: ")
}

// readInput reads user input
func (c *CLI) readInput() string {
	input, _ := c.reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// listTunnels displays all available tunnels
func (c *CLI) listTunnels() ([]tunnel.Tunnel, error) {
	if !c.tunnelManager.IsRunning() {
		fmt.Println("Tunnel service is not running. Start it first.")
		return nil, fmt.Errorf("service not running")
	}

	tunnels, err := c.tunnelManager.ListTunnels()
	if err != nil {
		fmt.Printf("Error listing tunnels: %v\n", err)
		return nil, err
	}

	if len(tunnels) == 0 {
		fmt.Println("No tunnels found.")
		return tunnels, nil
	}

	fmt.Println("\n===== Available Tunnels =====")
	for i, t := range tunnels {
		fmt.Printf("%d. UDID: %s, Address: %s, RSD Port: %d\n", i+1, t.Udid, t.Address, t.RsdPort)
	}
	fmt.Println("===========================")
	
	return tunnels, nil
}

// showSettings displays and modifies settings
func (c *CLI) showSettings() {
	fmt.Println("\n===== Settings =====")
	fmt.Printf("1. Records Path: %s\n", c.tunnelManager.recordsPath)
	fmt.Printf("2. Tunnel Info Port: %d\n", c.tunnelManager.tunnelInfoPort)
	fmt.Printf("3. Tunnel Info Host: %s\n", c.tunnelManager.tunnelInfoHost)
	fmt.Printf("4. Userspace TUN: %v\n", c.tunnelManager.userspaceTUN)
	fmt.Println("0. Back to Main Menu")
	
	fmt.Print("\nEnter setting number to change (0 to go back): ")
	input := c.readInput()
	
	switch input {
	case "1":
		fmt.Printf("Current Records Path: %s\n", c.tunnelManager.recordsPath)
		fmt.Print("Enter new Records Path: ")
		c.tunnelManager.recordsPath = c.readInput()
	case "2":
		fmt.Printf("Current Tunnel Info Port: %d\n", c.tunnelManager.tunnelInfoPort)
		fmt.Print("Enter new Tunnel Info Port: ")
		portStr := c.readInput()
		port, err := strconv.Atoi(portStr)
		if err != nil {
			fmt.Println("Invalid port number")
		} else {
			c.tunnelManager.tunnelInfoPort = port
		}
	case "3":
		fmt.Printf("Current Tunnel Info Host: %s\n", c.tunnelManager.tunnelInfoHost)
		fmt.Print("Enter new Tunnel Info Host: ")
		c.tunnelManager.tunnelInfoHost = c.readInput()
	case "4":
		c.tunnelManager.userspaceTUN = !c.tunnelManager.userspaceTUN
		fmt.Printf("Userspace TUN set to: %v\n", c.tunnelManager.userspaceTUN)
	}
}

// Run starts the CLI application
func (c *CLI) Run() {
	// Setup signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-signalCh
		fmt.Println("\nShutting down...")
		c.tunnelManager.StopTunnel()
		c.running = false
	}()
	
	fmt.Println("Welcome to Tunnel Manager")
	fmt.Println("Press Ctrl+C to exit at any time")
	
	for c.running {
		c.printMenu()
		choice := c.readInput()
		
		switch choice {
		case "0":
			c.running = false
			c.tunnelManager.StopTunnel()
			fmt.Println("Exiting...")
		case "1":
			if c.tunnelManager.IsRunning() {
				fmt.Println("Tunnel service is already running")
			} else {
				fmt.Println("Starting tunnel service...")
				err := c.tunnelManager.StartTunnel()
				if err != nil {
					fmt.Printf("Error starting tunnel service: %v\n", err)
				}
			}
		case "2":
			if !c.tunnelManager.IsRunning() {
				fmt.Println("Tunnel service is not running")
			} else {
				fmt.Println("Stopping tunnel service...")
				c.tunnelManager.StopTunnel()
			}
		case "3":
			c.listTunnels()
		case "4":
			c.pairWithDevice()
		case "5":
			c.readDevicePlist()
		case "6":
			c.showSettings()
		default:
			fmt.Println("Invalid choice, please try again")
		}
	}
}

func (c *CLI) readDevicePlist() {
	fmt.Print("\nEnter path to device plist file: ")
	plistPath := c.readInput()
	
	content, err := os.ReadFile(plistPath)
	if err != nil {
		fmt.Printf("Error reading plist file: %v\n", err)
		return
	}
	
	var deviceInfo map[string]interface{}
	_, err = plist.Unmarshal(content, &deviceInfo)
	if err != nil {
		fmt.Printf("Error parsing plist file: %v\n", err)
		return
	}
	
	// Convert to XML format for display
	var xmlBuf bytes.Buffer
	encoder := plist.NewEncoderForFormat(&xmlBuf, plist.XMLFormat)
	err = encoder.Encode(deviceInfo)
	if err != nil {
		fmt.Printf("Error converting to XML format: %v\n", err)
		return
	}
	
	fmt.Println("\n===== Device Information (XML Format) =====")
	fmt.Println(xmlBuf.String())
	fmt.Println("==========================================")
}

func (c *CLI) pairWithDevice() {
	tunnels, err := c.listTunnels()
	if err != nil || len(tunnels) == 0 {
		return
	}

	fmt.Print("\nEnter tunnel number to pair with (0 to cancel): ")
	input := c.readInput()
	
	if input == "0" {
		return
	} 
	
	index, err := strconv.Atoi(input)
	if err != nil || index < 1 || index > len(tunnels) {
		fmt.Println("Invalid selection")
		return
	}
	
	selectedTunnel := tunnels[index-1]
	fmt.Printf("\nPairing with device UDID: %s, Address: %s\n", selectedTunnel.Udid, selectedTunnel.Address)

	recordsPath := "."
	pm, err := tunnel.NewPairRecordManager(recordsPath)

	if err != nil {
		fmt.Printf("Error creating pair record manager: %v\n", err)
		return
	}
	
	device, err := ios.GetDevice(selectedTunnel.Udid)
	if err != nil {
		log.Fatalf("Error getting device with UDID %s: %v", selectedTunnel.Udid, err)
	}

	// First get a lockdown connection
	lockdown, err := ios.ConnectLockdownWithSession(device)
	if err != nil {
		log.Fatalf("Error connecting to lockdown session: %v", err)
	}
	defer lockdown.Close()

	// Then set the value
	err = lockdown.SetValueForDomain("EnableWifiConnections", "com.apple.mobile.wireless_lockdown", true)
	if err != nil {
		log.Fatalf("Error setting value for domain: %v", err)
	}

	info, err := tunnel.TunnelInfoForDevice(device.Properties.SerialNumber, ios.HttpApiHost(), 28100)
	if err != nil {
		fmt.Printf("Error getting tunnel info: %v\n", err)
		return 
	}

	device.UserspaceTUNPort = info.UserspaceTUNPort
	device.UserspaceTUN = info.UserspaceTUN

	device = deviceWithRsdProvider(device, selectedTunnel.Udid, selectedTunnel.Address, selectedTunnel.RsdPort)

	fmt.Printf("Device: %+v\n", device)
	key, err := tunnel.PairAndGetHostKey(selectedTunnel.Address, device, pm)
	if err != nil {
		fmt.Printf("Error pairing with device: %v\n", err)
		return
	}
	
	fmt.Printf("Successfully paired with device!\n")
	
	// Now read the plist to extract private and public keys
	plistPath := fmt.Sprintf("./selfIdentity.plist")
	content, err := os.ReadFile(plistPath)
	if err != nil {
		fmt.Printf("Error reading device plist: %v\n", err)
		return
	}
	
	var deviceInfo map[string]interface{}
	_, err = plist.Unmarshal(content, &deviceInfo)
	if err != nil {
		fmt.Printf("Error parsing plist: %v\n", err)
		return
	}
	
	// Extract private and public keys
	privateKey := ""
	publicKey := ""
	
	// Check if privateKey exists as data and encode to base64 string
	if privKeyData, ok := deviceInfo["privateKey"].([]byte); ok {
		privateKey = base64.StdEncoding.EncodeToString(privKeyData)
	} else if privKeyStr, ok := deviceInfo["privateKey"].(string); ok {
		privateKey = privKeyStr
	}
	
	// Check if publicKey exists as data and encode to base64 string
	if pubKeyData, ok := deviceInfo["publicKey"].([]byte); ok {
		publicKey = base64.StdEncoding.EncodeToString(pubKeyData)
	} else if pubKeyStr, ok := deviceInfo["publicKey"].(string); ok {
		publicKey = pubKeyStr
	}
	
	// Add the host key to the device info (for display purposes)
	deviceInfo["hostKey"] = key
	
	// Convert to XML format for display
	var xmlBuf bytes.Buffer
	encoder := plist.NewEncoderForFormat(&xmlBuf, plist.XMLFormat)
	err = encoder.Encode(deviceInfo)
	if err != nil {
		fmt.Printf("Error converting to XML format: %v\n", err)
		return
	}
	
	fmt.Println("\n===== Device Information with Host Key (XML Format) =====")
	fmt.Println(xmlBuf.String())
	fmt.Println("=======================================================")
	
	// Ask for the POST endpoint
	fmt.Print("\nEnter the URL to POST device data to (or leave empty to skip): ")
	postURL := c.readInput()

	if postURL != "" {
		postURL = postURL + "/api/devices/trust"
		// Prepare the data for POST request
		postData := struct {
			PrivateKey string `json:"private_key"`
			PublicKey  string `json:"public_key"`
			HostKey    string `json:"remote_unlock_host_key"`
			Udid			 string `json:"udid"`
			DeviceType string `json:"device_type"`
		}{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			HostKey:    key,
			Udid: selectedTunnel.Udid,
			DeviceType: "iPhone",
		}
		
		// Print the data that will be sent
		fmt.Println("\n===== Data to be sent (POST) =====")
		fmt.Printf("PrivateKey: %s\n", postData.PrivateKey)
		fmt.Printf("PublicKey: %s\n", postData.PublicKey)
		fmt.Printf("HostKey: %s\n", postData.HostKey)
		fmt.Println("=================================")
		
		// Convert to JSON
		jsonData, err := json.Marshal(postData)
		if err != nil {
			fmt.Printf("Error marshaling JSON: %v\n", err)
			return
		}
		
		// Also print the JSON representation
		fmt.Printf("\nJSON representation:\n%s\n", string(jsonData))
		
		// Send POST request
		resp, err := http.Post(postURL, "application/json", bytes.NewReader(jsonData))
		if err != nil {
			fmt.Printf("Error sending POST request: %v\n", err)
			return
		}
		defer resp.Body.Close()
		
		// Read response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response: %v\n", err)
			return
		}
		
		fmt.Printf("\nPOST request sent successfully!\n")
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Printf("Response: %s\n", string(body))
	}
}
func deviceWithRsdProvider(device ios.DeviceEntry, udid string, address string, rsdPort int) ios.DeviceEntry {
	rsdService, _ := ios.NewWithAddrPortDevice(address, rsdPort, device)
	defer rsdService.Close()
	rsdProvider, _ := rsdService.Handshake()
	device1, _ := ios.GetDeviceWithAddress(udid, address, rsdProvider)
	device1.UserspaceTUN = device.UserspaceTUN
	device1.UserspaceTUNHost = device.UserspaceTUNHost
	device1.UserspaceTUNPort = device.UserspaceTUNPort

	return device1
}

func main() {
	// Create the tunnel manager with default settings
	tunnelManager := NewTunnelManager(
		".",                 // Records path
		28100,               // Tunnel info port
		"localhost",         // Tunnel info host
		false,               // Userspace TUN
	)

	// Create and run the CLI
	cli := NewCLI(tunnelManager)
	cli.Run()
}
