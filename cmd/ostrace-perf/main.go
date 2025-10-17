// High-performance ostrace for processing massive log volumes
// Build with: go build -tags perf -ldflags="-s -w" ./cmd/ostrace-perf
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/ostrace"
	jsoniter "github.com/json-iterator/go"
)

var (
	// High-performance JSON encoder
	json = jsoniter.ConfigFastest
	
	// Performance counters
	logsProcessed uint64
	bytesWritten  uint64
	
	// Output buffer with writer
	outputBuffer = bufio.NewWriterSize(os.Stdout, 64*1024) // 64KB buffer
	outputMutex  sync.Mutex
)

func main() {
	var (
		udid          = flag.String("udid", "", "Device UDID")
		filter        = flag.String("filter", "", "Simple content filter")
		filterFile    = flag.String("filter-config", "", "YAML filter config file")
		list          = flag.Bool("list", false, "List processes")
		jsonOutput    = flag.Bool("json", false, "Output as JSON")
		workers       = flag.Int("workers", runtime.NumCPU(), "Number of worker goroutines")
		bufferSize    = flag.Int("buffer", 1000, "Log entry buffer size")
		stats         = flag.Bool("stats", false, "Show performance statistics")
		help          = flag.Bool("h", false, "Show help")
		pymobileTunnel = flag.Int("pymobile-tunnel", 0, "Use pymobiledevice3 tunnel on specified port (e.g., 49151)")
		pid           = flag.Int("pid", -1, "Filter by process ID (device-side filtering)")
		processName   = flag.String("process", "", "Filter by process name (requires process lookup)")
	)
	flag.Parse()

	if *help {
		fmt.Println("ostrace-perf - High-performance iOS log streaming")
		fmt.Println("\nOptimized for processing massive log volumes with:")
		fmt.Println("- Zero-copy string handling")
		fmt.Println("- Object pooling")
		fmt.Println("- High-performance JSON encoding (jsoniter)")
		fmt.Println("- Parallel processing")
		fmt.Println("- Large output buffering")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set GOMAXPROCS for maximum performance
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Get device
	var device ios.DeviceEntry
	var err error
	
	if *pymobileTunnel > 0 {
		// Use pymobiledevice3 tunnel
		if *udid == "" {
			// Get first device from tunnel
			devices, err := ios.ListDevicesWithPyMobileTunnel(*pymobileTunnel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to list devices via pymobile tunnel: %v\n", err)
				os.Exit(1)
			}
			if len(devices.DeviceList) == 0 {
				fmt.Fprintf(os.Stderr, "No devices found via pymobile tunnel\n")
				os.Exit(1)
			}
			device = devices.DeviceList[0]
		} else {
			// Get specific device from tunnel
			device, err = ios.GetDeviceWithPyMobileTunnel(*udid, *pymobileTunnel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get device via pymobile tunnel: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "Using device %s via pymobiledevice3 tunnel\n", device.Properties.SerialNumber)
	} else {
		// Use regular connection
		device, err = ios.GetDevice(*udid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get device: %v\n", err)
			os.Exit(1)
		}
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

	// Handle process name to PID conversion
	targetPID := *pid
	if *processName != "" && targetPID == -1 {
		fmt.Fprintf(os.Stderr, "Looking up process '%s'...\n", *processName)
		
		// Create a separate connection for process lookup to avoid interfering with streaming
		lookupConn, err := ostrace.New(device)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create lookup connection: %v\n", err)
			fmt.Fprintf(os.Stderr, "You can use 'ios ps' to find the PID and use --pid instead\n")
		} else {
			processes, err := lookupConn.GetProcessList()
			lookupConn.Close() // Close immediately after use
			
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to get process list: %v\n", err)
				fmt.Fprintf(os.Stderr, "You can use 'ios ps' to find the PID and use --pid instead\n")
			} else {
				found := false
				for _, p := range processes {
					if p.Label == *processName {
						targetPID = p.PID
						found = true
						fmt.Fprintf(os.Stderr, "Found process '%s' with PID %d\n", *processName, targetPID)
						break
					}
				}
				if !found {
					fmt.Fprintf(os.Stderr, "Process '%s' not found. Available processes:\n", *processName)
					for _, p := range processes {
						fmt.Fprintf(os.Stderr, "  %d: %s\n", p.PID, p.Label)
					}
					os.Exit(1)
				}
			}
		}
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

	// Start streaming with device-side PID filtering
	config := ostrace.StreamConfig{PID: targetPID}
	if targetPID != -1 {
		fmt.Fprintf(os.Stderr, "Starting stream with device-side PID filter: %d\n", targetPID)
	}
	if err := conn.StartStreaming(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start streaming: %v\n", err)
		os.Exit(1)
	}

	// Create worker pool
	entryChan := make(chan *ostrace.LogEntry, *bufferSize)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(entryChan, filterConfig, *jsonOutput, &wg)
	}

	// Start stats reporter if enabled
	if *stats {
		go statsReporter()
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Start output flusher
	go outputFlusher()

	// Main reading loop
	go func() {
		for {
			entry, err := conn.FastReadLogEntry()
			if err != nil {
				if err == io.EOF {
					close(entryChan)
					return
				}
				// Skip errors and continue
				continue
			}
			
			// Send to workers
			select {
			case entryChan <- entry:
				atomic.AddUint64(&logsProcessed, 1)
			default:
				// Buffer full, drop log
				ostrace.PutLogEntry(entry)
			}
		}
	}()

	// Wait for signal
	<-sigChan
	
	// Cleanup
	conn.StopStreaming()
	close(entryChan)
	wg.Wait()
	
	// Final flush
	outputMutex.Lock()
	outputBuffer.Flush()
	outputMutex.Unlock()
	
	if *stats {
		fmt.Fprintf(os.Stderr, "\nFinal stats: %d logs processed, %d MB written\n", 
			atomic.LoadUint64(&logsProcessed),
			atomic.LoadUint64(&bytesWritten)/(1024*1024))
	}
}

func worker(entryChan <-chan *ostrace.LogEntry, filterConfig *ostrace.FilterConfig, jsonOutput bool, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Local buffer to reduce lock contention
	localBuf := make([]byte, 0, 4096)
	
	for entry := range entryChan {
		// Apply filter
		if filterConfig != nil && !ostrace.EvaluateFilters(entry, filterConfig) {
			ostrace.PutLogEntry(entry)
			continue
		}
		
		// Format output
		localBuf = localBuf[:0]
		if jsonOutput {
			// High-performance JSON encoding
			data, _ := json.Marshal(entry)
			localBuf = append(localBuf, data...)
			localBuf = append(localBuf, '\n')
		} else {
			// Simple format with string builder
			localBuf = fmt.Appendf(localBuf, "[%s] %s[%d]: %s\n",
				entry.Timestamp.Format("15:04:05.000"),
				entry.ImageName,
				entry.ProcessID,
				entry.Message)
		}
		
		// Write to output buffer
		outputMutex.Lock()
		outputBuffer.Write(localBuf)
		outputMutex.Unlock()
		
		atomic.AddUint64(&bytesWritten, uint64(len(localBuf)))
		
		// Return entry to pool
		ostrace.PutLogEntry(entry)
	}
}

func outputFlusher() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for range ticker.C {
		outputMutex.Lock()
		outputBuffer.Flush()
		outputMutex.Unlock()
	}
}

func statsReporter() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	var lastLogs uint64
	var lastBytes uint64
	
	for range ticker.C {
		currentLogs := atomic.LoadUint64(&logsProcessed)
		currentBytes := atomic.LoadUint64(&bytesWritten)
		
		logsPerSec := (currentLogs - lastLogs) / 5
		mbPerSec := float64(currentBytes-lastBytes) / (5 * 1024 * 1024)
		
		fmt.Fprintf(os.Stderr, "Stats: %d logs/sec, %.2f MB/sec, Total: %d logs\n", 
			logsPerSec, mbPerSec, currentLogs)
		
		lastLogs = currentLogs
		lastBytes = currentBytes
	}
}
