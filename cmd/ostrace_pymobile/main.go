package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/ostrace"
	"github.com/sirupsen/logrus"
)

func main() {
	var (
		udid           = flag.String("udid", "", "Device UDID")
		pymobileTunnel = flag.Int("pymobile-tunnel", ios.DefaultPyMobileTunnelPort, "Port of pymobiledevice3 tunnel daemon")
		rsdHost        = flag.String("rsd-host", "", "RSD host address (e.g., IPv6 address)")
		rsdPort        = flag.Int("rsd-port", 58783, "RSD port (default 58783)")
		listProcesses  = flag.Bool("list", false, "List all processes")
		processName    = flag.String("process", "", "Filter logs by process name")
		pid            = flag.Int("pid", -1, "Filter logs by process ID")
		archive        = flag.Bool("archive", false, "Download archived logs")
		archiveFile    = flag.String("archive-file", "logs.pax", "Output file for archived logs")
		verbose        = flag.Bool("v", false, "Enable verbose logging")
		help           = flag.Bool("h", false, "Show help")
	)
	flag.Parse()

	if *help {
		fmt.Println("ostrace_pymobile - Stream logs from iOS devices using pymobiledevice3's tunnel")
		fmt.Println("\nThis tool allows go-ios to use pymobiledevice3's tunnel daemon for accessing")
		fmt.Println("os_trace_relay service, avoiding the 16KB limitation of direct USB connections.")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  # List processes")
		fmt.Println("  ostrace_pymobile -list")
		fmt.Println("  # Stream logs from specific process")
		fmt.Println("  ostrace_pymobile -process SpringBoard")
		fmt.Println("  # Use different tunnel port")
		fmt.Println("  ostrace_pymobile -pymobile-tunnel 12345 -list")
		os.Exit(0)
	}

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// Try to get device through pymobiledevice3 tunnel
	var device ios.DeviceEntry
	var err error

	if *pymobileTunnel > 0 {
		logrus.Infof("Connecting through pymobiledevice3 tunnel on port %d...", *pymobileTunnel)
		
		if *udid == "" {
			// List devices from tunnel
			deviceList, err := ios.ListDevicesWithPyMobileTunnel(*pymobileTunnel)
			if err != nil {
				logrus.Fatalf("Failed to list devices from tunnel: %v", err)
			}
			if len(deviceList.DeviceList) == 0 {
				logrus.Fatal("No devices found in tunnel")
			}
			device = deviceList.DeviceList[0]
			logrus.Infof("no udid specified using first device in list")
			logrus.Infof("Device: %s", device.Properties.SerialNumber)
		} else {
			device, err = ios.GetDeviceWithPyMobileTunnel(*udid, *pymobileTunnel)
			if err != nil {
				logrus.Fatalf("Failed to get device through tunnel: %v", err)
			}
		}
		
		logrus.Infof("Connected to device %s through pymobiledevice3 tunnel", device.Properties.SerialNumber)
	} else if *rsdHost != "" {
		logrus.Infof("Connecting through RSD at %s:%d...", *rsdHost, *rsdPort)
		
		if *udid == "" {
			logrus.Fatal("UDID is required when using RSD connection")
		}
		
		// Create RSD service connection
		rsdService, err := ios.NewWithAddrPort(*rsdHost, *rsdPort)
		if err != nil {
			logrus.Fatalf("Failed to connect to RSD service: %v", err)
		}
		defer rsdService.Close()
		
		// Perform RSD handshake
		rsdProvider, err := rsdService.Handshake()
		if err != nil {
			logrus.Fatalf("Failed to perform RSD handshake: %v", err)
		}
		
		// Get device with RSD provider
		device, err = ios.GetDeviceWithAddress(*udid, *rsdHost, rsdProvider)
		if err != nil {
			logrus.Fatalf("Failed to get device via RSD: %v", err)
		}
		
		logrus.Infof("Connected to device %s through RSD", device.Properties.SerialNumber)
	} else {
		// Fall back to regular connection
		device, err = ios.GetDevice(*udid)
		if err != nil {
			logrus.Fatalf("Failed to get device: %v", err)
		}
		logrus.Infof("Connected to device: %s", device.Properties.SerialNumber)
	}

	// Create os_trace connection
	conn, err := ostrace.New(device)
	if err != nil {
		logrus.Fatalf("Failed to connect to os_trace_relay: %v", err)
	}
	defer conn.Close()

	// List processes if requested
	if *listProcesses {
		processes, err := conn.GetProcessList()
		if err != nil {
			logrus.Fatalf("Failed to get process list: %v", err)
		}

		fmt.Printf("\n%-50s %s\n", "Process Name", "PID")
		fmt.Println("------------------------------------------------------------")
		for _, proc := range processes {
			fmt.Printf("%-50s %d\n", proc.Label, proc.PID)
		}
		fmt.Printf("\nTotal: %d processes\n", len(processes))
		return
	}

	// Download archived logs if requested
	if *archive {
		fmt.Printf("Downloading archived logs to %s...\n", *archiveFile)
		startTime := time.Now()
		
		archiveData, err := conn.GetArchivedLogsWithProgress(func(current, total int) {
			if total > 0 {
				progress := float64(current) / float64(total) * 100
				fmt.Printf("\rProgress: %.2f%% (%d/%d bytes)", progress, current, total)
			} else {
				fmt.Printf("\rDownloaded: %d bytes", current)
			}
		})
		
		if err != nil {
			logrus.Fatalf("\nFailed to get archived logs: %v", err)
		}

		// Save to file
		file, err := os.Create(*archiveFile)
		if err != nil {
			logrus.Fatalf("\nFailed to create file: %v", err)
		}
		defer file.Close()

		_, err = file.Write(archiveData)
		if err != nil {
			logrus.Fatalf("\nFailed to write to file: %v", err)
		}

		duration := time.Since(startTime)
		fmt.Printf("\n\nDownloaded %d bytes in %.2f seconds\n", len(archiveData), duration.Seconds())
		fmt.Printf("Saved to: %s\n", *archiveFile)
		fmt.Println("\nExtract with:")
		fmt.Printf("  pax -r < %s\n", *archiveFile)
		fmt.Printf("  tar -xf %s\n", *archiveFile)
		return
	}

	// If process name is specified, look up its PID
	if *processName != "" {
		processes, err := conn.GetProcessList()
		if err != nil {
			logrus.Printf("Warning: Failed to get process list: %v", err)
			logrus.Println("Streaming all logs without filtering")
		} else {
			found := false
			for _, proc := range processes {
				if proc.Label == *processName {
					*pid = proc.PID
					found = true
					logrus.Printf("Found process '%s' with PID %d", *processName, *pid)
					break
				}
			}
			if !found {
				logrus.Printf("Warning: Process '%s' not found", *processName)
				logrus.Println("Streaming all logs without filtering")
			}
		}
	}

	// Stream logs
	config := ostrace.StreamConfig{
		PID: *pid,
	}

	fmt.Println("\nStreaming logs... (Press Ctrl+C to stop)")
	fmt.Println("------------------------------------------------------------")

	err = conn.StartStreaming(config)
	if err != nil {
		logrus.Fatalf("Failed to start streaming: %v", err)
	}

	// Read and display log entries
	for {
		entry, err := conn.ReadLogEntry()
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println("\nLog stream ended")
				break
			}
			logrus.Printf("Error reading log entry: %v", err)
			continue
		}

		// Format and display the log entry
		timestamp := entry.Timestamp.Format("15:04:05.000")
		fmt.Printf("[%s] %-16s %-7s %s\n", 
			timestamp, 
			entry.ImageName,
			entry.Level,
			entry.Message)
	}
}
