package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/ostrace"
	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		udid          = flag.String("udid", "", "Device UDID (optional, uses first device if not specified)")
		pidFilter     = flag.Int("pid", 0, "Filter logs by process ID (0 for no filter)")
		processName   = flag.String("process", "", "Filter logs by process name (will look up PID)")
		errorsOnly    = flag.Bool("errors-only", false, "Show only error and fault logs")
		debugLevel    = flag.Bool("debug", false, "Include debug level logs")
		infoLevel     = flag.Bool("info", true, "Include info level logs")
		listProcesses = flag.Bool("list", false, "List running processes and exit")
		archive       = flag.Bool("archive", false, "Download archived logs to file")
		archiveFile   = flag.String("archive-file", "device_logs.pax", "Archive file name")
		verbose       = flag.Bool("v", false, "Verbose logging")
	)

	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	// Get device
	device, err := ios.GetDevice(*udid)
	if err != nil {
		log.Errorf("Failed to get device: %v", err)
		os.Exit(1)
	}

	log.Infof("Connected to device: %s", device.Properties.SerialNumber)

	// Create connection
	conn, err := ostrace.New(device)
	if err != nil {
		log.Errorf("Failed to create ostrace connection: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// List processes if requested
	if *listProcesses {
		processes, err := conn.GetProcessList()
		if err != nil {
			log.WithError(err).Warn("Failed to get process list via os_trace_relay")
			log.Info("")
			log.Info("You can use 'ios ps' command as an alternative:")
			log.Info("  ios ps --nojson              # Human-readable process list")
			log.Info("  ios ps --apps --nojson       # Only application processes")
			return
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
			log.Errorf("\nFailed to get archived logs: %v", err)
			return
		}

		// Save to file
		file, err := os.Create(*archiveFile)
		if err != nil {
			log.Errorf("\nFailed to create file: %v", err)
			return
		}
		defer file.Close()

		_, err = file.Write(archiveData)
		if err != nil {
			log.Errorf("\nFailed to write to file: %v", err)
			return
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
			log.WithError(err).Error("Failed to get process list")
			log.Info("Please use 'ios ps --nojson' to find the PID for your process,")
			log.Info("then run: ostrace -pid <PID>")
			return
		}

		found := false
		for _, proc := range processes {
			if proc.Label == *processName {
				*pidFilter = proc.PID
				found = true
				log.Infof("Found process '%s' with PID %d", *processName, *pidFilter)
				break
			}
		}

		if !found {
			log.Errorf("Process '%s' not found", *processName)
			log.Info("Available processes:")
			for _, proc := range processes {
				if len(proc.Label) > 0 {
					fmt.Printf("  %s (PID: %d)\n", proc.Label, proc.PID)
				}
			}
			return
		}
	}

	// Configure streaming
	config := ostrace.StreamConfig{
		PID:        *pidFilter,
		ErrorsOnly: *errorsOnly,
		DebugLevel: *debugLevel,
		InfoLevel:  *infoLevel,
	}

	// Start streaming
	err = conn.StartStreaming(config)
	if err != nil {
		log.Errorf("Failed to start streaming: %v", err)
		return
	}
	defer conn.StopStreaming()

	if *pidFilter > 0 {
		log.Infof("Streaming logs from PID %d...", *pidFilter)
	} else {
		log.Info("Streaming all logs...")
	}
	if *errorsOnly {
		log.Info("Showing errors only")
	}
	fmt.Println()

	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Stream logs
	go func() {
		for {
			entry, err := conn.ReadLogEntry()
			if err != nil {
				log.Debugf("Error reading log entry: %v", err)
				continue
			}

			if entry != nil {
				fmt.Println(ostrace.FormatLogEntry(entry))
			}
		}
	}()

	// Wait for interrupt
	<-sigChan
	fmt.Println("\n\nStopping log stream...")
}

