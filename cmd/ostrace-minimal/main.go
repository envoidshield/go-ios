package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/ostrace"
)

func main() {
	var (
		udid       = flag.String("udid", "", "Device UDID")
		filter     = flag.String("filter", "", "Simple content filter")
		filterFile = flag.String("filter-config", "", "YAML filter config file")
		list       = flag.Bool("list", false, "List processes")
		help       = flag.Bool("h", false, "Show help")
	)
	flag.Parse()

	if *help {
		fmt.Println("ostrace-minimal - Minimal iOS log streaming")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Get device
	device, err := ios.GetDevice(*udid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get device: %v\n", err)
		os.Exit(1)
	}

	// Connect to ostrace
	conn, err := ostrace.New(device)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// List processes if requested
	if *list {
		processes, err := conn.GetProcessList()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get process list: %v\n", err)
			os.Exit(1)
		}
		for _, p := range processes {
			fmt.Printf("%d\t%s\n", p.PID, p.Label)
		}
		return
	}

	// Load filters
	var filterConfig *ostrace.FilterConfig
	if *filter != "" {
		filterConfig = ostrace.CreateSimpleFilter(*filter)
	} else if *filterFile != "" {
		filterConfig, err = ostrace.LoadFilterConfig(*filterFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load filter: %v\n", err)
			os.Exit(1)
		}
	}

	// Start streaming
	config := ostrace.StreamConfig{PID: -1}
	if err := conn.StartStreaming(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start streaming: %v\n", err)
		conn.Close()
		os.Exit(1)
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	done := make(chan bool)

	// Stream logs in goroutine
	go func() {
		for {
			entry, err := conn.ReadLogEntry()
			if err != nil {
				if err == io.EOF {
					done <- true
					return
				}
				continue
			}

			// Apply filter
			if filterConfig != nil && !ostrace.EvaluateFilters(entry, filterConfig) {
				continue
			}

			// Simple output
			fmt.Printf("[%s] %s[%d]: %s\n",
				entry.Timestamp.Format("15:04:05.000"),
				entry.ImageName,
				entry.ProcessID,
				entry.Message)
		}
	}()

	// Wait for signal or EOF
	select {
	case <-sigChan:
		fmt.Fprintf(os.Stderr, "\nInterrupted, shutting down...\n")
	case <-done:
		// EOF received
	}

	// Proper cleanup (defer will also run)
	conn.StopStreaming()
}
