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
	
	// Ping tracking
	lastPingTime atomic.Value // stores time.Time
	pingInterval time.Duration
	
	// Connection health monitoring
	lastLogReceived atomic.Value // stores time.Time
	readTimeout     time.Duration
	
	// Non-blocking stderr channel to prevent reader goroutine blocking
	// Critical: reader must never block on stderr or socket reads will stall
	stderrChan = make(chan string, 1000)
	stderrDone = make(chan struct{})
)

// formattedLog represents a formatted log entry ready for output
type formattedLog struct {
	data []byte
}

// logStderr writes to stderr asynchronously to prevent blocking the reader goroutine
// If channel is full, message is dropped (better than blocking socket reads)
func logStderr(format string, args ...interface{}) {
	select {
	case stderrChan <- fmt.Sprintf(format, args...):
		// Message queued successfully
	default:
		// Channel full - drop message to avoid blocking
		// This is intentional: socket reads are more important than stderr messages
	}
}

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
		rsdHost       = flag.String("rsd-host", "", "RSD host address (e.g., IPv6 address)")
		rsdPort       = flag.Int("rsd-port", 58783, "RSD port (default 58783)")
		pid           = flag.Int("pid", -1, "Filter by process ID (device-side filtering)")
		processName   = flag.String("process", "", "Filter by process name (requires process lookup)")
		pingSeconds   = flag.Int("ping-interval", 5, "Send ping when logs are received but not matching filter (seconds, 0 to disable)")
		watchdogSeconds = flag.Int("watchdog", 30, "Watchdog timeout: exit if no logs received for N seconds (0 to disable)")
		readTimeoutSeconds = flag.Int("read-timeout", 0, "Read timeout: fail read operations after N seconds (0 to disable, prevents indefinite blocking)")
		diagnostics   = flag.Bool("diagnostics", false, "Enable diagnostic mode with detailed connection state logging")
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
		fmt.Println("- Connection health monitoring with watchdog")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Set GOMAXPROCS for maximum performance
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Start async stderr writer to prevent reader goroutine from blocking
	go func() {
		for {
			select {
			case msg := <-stderrChan:
				fmt.Fprint(os.Stderr, msg)
			case <-stderrDone:
				// Drain remaining messages
				for {
					select {
					case msg := <-stderrChan:
						fmt.Fprint(os.Stderr, msg)
					default:
						return
					}
				}
			}
		}
	}()

	// Initialize ping interval
	pingInterval = time.Duration(*pingSeconds) * time.Second
	if pingInterval > 0 {
		lastPingTime.Store(time.Time{}) // Initialize with zero time
		fmt.Fprintf(os.Stderr, "Ping enabled: will send ping every %d seconds when logs are received\n", *pingSeconds)
	}
	
	// Initialize watchdog
	readTimeout = time.Duration(*watchdogSeconds) * time.Second
	if readTimeout > 0 {
		lastLogReceived.Store(time.Now())
		fmt.Fprintf(os.Stderr, "Watchdog enabled: will exit if no logs received for %d seconds\n", *watchdogSeconds)
	}
	
	// Enable diagnostics if requested
	if *diagnostics {
		fmt.Fprintf(os.Stderr, "Diagnostics mode enabled: detailed connection state logging active\n")
	}

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
	} else if *rsdHost != "" {
		// Use RSD connection
		if *udid == "" {
			fmt.Fprintf(os.Stderr, "UDID is required when using RSD connection\n")
			os.Exit(1)
		}
		
		// Create RSD service connection
		rsdService, err := ios.NewWithAddrPort(*rsdHost, *rsdPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to RSD service: %v\n", err)
			os.Exit(1)
		}
		defer rsdService.Close()
		
		// Perform RSD handshake
		// Use a conservative timeout to avoid indefinite blocking
		rsdProvider, err := rsdService.HandshakeWithTimeout(15 * time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to perform RSD handshake: %v\n", err)
			os.Exit(1)
		}
		
		// Get device with RSD provider
		device, err = ios.GetDeviceWithAddress(*udid, *rsdHost, rsdProvider)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get device via RSD: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Using device %s via RSD (%s:%d)\n", device.Properties.SerialNumber, *rsdHost, *rsdPort)
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
	
	// Set read timeout on connection if configured
	if *readTimeoutSeconds > 0 {
		connReadTimeout := time.Duration(*readTimeoutSeconds) * time.Second
		conn.SetReadTimeout(connReadTimeout)
		fmt.Fprintf(os.Stderr, "Read timeout set: %v (prevents indefinite blocking on stalled connections)\n", connReadTimeout)
	}

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
	// Reset watchdog timer at the moment streaming actually starts
	if readTimeout > 0 {
		lastLogReceived.Store(time.Now())
	}

	// Create worker pool
	entryChan := make(chan *ostrace.LogEntry, *bufferSize)
	outputChan := make(chan formattedLog, *bufferSize*2) // Larger output buffer
	outputDone := make(chan struct{})
	var wg sync.WaitGroup
	
	// Use sync.Once to prevent double-close panics
	var closeEntryChanOnce sync.Once
	var closeOutputChanOnce sync.Once
	var closeOutputDoneOnce sync.Once

	// Start dedicated output writer (eliminates mutex contention!)
	go dedicatedWriter(outputChan, outputDone, *stats)

	// Start workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(entryChan, outputChan, filterConfig, *jsonOutput, &wg)
	}

	// Start stats reporter if enabled
	if *stats {
		go statsReporter()
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Start watchdog if enabled
	watchdogChan := make(chan struct{})
	if readTimeout > 0 {
		go watchdogMonitor(watchdogChan)
	}

	// Main reading loop
	readErrorChan := make(chan error, 1)
	go func() {
		consecutiveErrors := 0
		lastDiagnostic := time.Now()
		
		for {
			// Diagnostic logging (non-blocking)
			if *diagnostics && time.Since(lastDiagnostic) >= 10*time.Second {
				logStderr("[DIAG] Reading logs... Total processed: %d, Errors: %d\n", 
					atomic.LoadUint64(&logsProcessed), consecutiveErrors)
				lastDiagnostic = time.Now()
			}
			
			entry, err := conn.FastReadLogEntry()
			if err != nil {
				consecutiveErrors++
				
				if err == io.EOF {
					logStderr("[DIAG] Connection closed (EOF) after %d consecutive errors\n", consecutiveErrors)
					readErrorChan <- io.EOF
					return
				}
				
				// Check if it's a timeout error
				if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
					logStderr("Error: Read timeout after %v - connection appears stalled\n", time.Duration(*readTimeoutSeconds)*time.Second)
					readErrorChan <- fmt.Errorf("read timeout: %w", err)
					return
				}
				
				// Log the error (non-blocking, rate-limited to every 10th error)
				if consecutiveErrors % 10 == 1 {
					logStderr("Warning: Failed to read log entry (error #%d): %v\n", consecutiveErrors, err)
				}
				
				// If too many consecutive errors, bail out
				if consecutiveErrors > 100 {
					logStderr("Error: Too many consecutive read errors (%d), giving up\n", consecutiveErrors)
					readErrorChan <- fmt.Errorf("too many consecutive errors: %w", err)
					closeEntryChanOnce.Do(func() { close(entryChan) })
					return
				}
				continue
			}
			
			// Reset error counter on successful read
			if consecutiveErrors > 0 {
				if *diagnostics {
					logStderr("[DIAG] Recovered after %d errors\n", consecutiveErrors)
				}
				consecutiveErrors = 0
			}
			
			// Update last log received time for watchdog
			if readTimeout > 0 {
				lastLogReceived.Store(time.Now())
			}
			
			// Send to workers
			select {
			case entryChan <- entry:
				atomic.AddUint64(&logsProcessed, 1)
			default:
				// Buffer full, drop log
				if *diagnostics {
					logStderr("[DIAG] Warning: Buffer full, dropping log entry\n")
				}
				ostrace.PutLogEntry(entry)
			}
		}
	}()

	// Wait for signal, EOF, or watchdog timeout
	exitCode := 0
	select {
	case <-sigChan:
		fmt.Fprintf(os.Stderr, "\nReceived interrupt signal, shutting down...\n")
		exitCode = 0 // Normal shutdown via signal
	case err := <-readErrorChan:
		if err == io.EOF {
			fmt.Fprintf(os.Stderr, "\nConnection closed by device (EOF)\n")
			exitCode = 0 // Normal EOF is not an error
		} else {
			fmt.Fprintf(os.Stderr, "\nRead error: %v\n", err)
			exitCode = 1 // Read errors are abnormal
		}
	case <-watchdogChan:
		fmt.Fprintf(os.Stderr, "\nWatchdog timeout: No logs received for %v\n", readTimeout)
		fmt.Fprintf(os.Stderr, "Connection may be stalled. Exiting...\n")
		exitCode = 2 // Watchdog timeout indicates connection issue
	}
	
	// Cleanup (graceful shutdown regardless of exit reason)
	conn.StopStreaming()
	closeEntryChanOnce.Do(func() { close(entryChan) })
	wg.Wait()
	
	// Signal output writer to drain and finish
	closeOutputChanOnce.Do(func() { close(outputChan) })
	closeOutputDoneOnce.Do(func() { close(outputDone) })
	time.Sleep(200 * time.Millisecond) // Give output writer time to drain
	
	if *stats {
		fmt.Fprintf(os.Stderr, "\nFinal stats: %d logs processed, %d MB written\n", 
			atomic.LoadUint64(&logsProcessed),
			atomic.LoadUint64(&bytesWritten)/(1024*1024))
	}
	
	// Signal stderr writer to drain and exit
	close(stderrDone)
	time.Sleep(100 * time.Millisecond) // Give it time to drain
	
	// Exit with appropriate code
	os.Exit(exitCode)
}

func worker(entryChan <-chan *ostrace.LogEntry, outputChan chan<- formattedLog, filterConfig *ostrace.FilterConfig, jsonOutput bool, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Local buffer for formatting (reused across entries)
	localBuf := make([]byte, 0, 4096)
	
	for entry := range entryChan {
		// Check if we should send a ping (log received but may not match filter)
		shouldSendPing := false
		if pingInterval > 0 {
			lastPing := lastPingTime.Load().(time.Time)
			if time.Since(lastPing) >= pingInterval {
				shouldSendPing = true
			}
		}
		
		// Apply filter
		matchesFilter := filterConfig == nil || ostrace.EvaluateFilters(entry, filterConfig)
		
		if !matchesFilter {
			// Log doesn't match filter, but send ping if needed
			if shouldSendPing {
				sendPing(outputChan, jsonOutput)
			}
			ostrace.PutLogEntry(entry)
			continue
		}
		
		// Log matches filter - format and output
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
		
		// Send to output channel (NO LOCK! - eliminates mutex contention)
		// Make a copy since localBuf is reused
		outputData := make([]byte, len(localBuf))
		copy(outputData, localBuf)
		outputChan <- formattedLog{data: outputData}
		
		// Return entry to pool
		ostrace.PutLogEntry(entry)
	}
}

// sendPing sends a ping message and updates the last ping time
func sendPing(outputChan chan<- formattedLog, jsonOutput bool) {
	// Update last ping time atomically
	now := time.Now()
	lastPingTime.Store(now)
	
	// Format ping message
	var pingMsg []byte
	if jsonOutput {
		pingMsg = []byte(`{"type":"ping","timestamp":"` + now.Format(time.RFC3339Nano) + `"}` + "\n")
	} else {
		pingMsg = []byte("PING\n")
	}
	
	// Send ping to output channel (NO LOCK!)
	outputChan <- formattedLog{data: pingMsg}
}

// dedicatedWriter is a single goroutine that drains the output channel
// This eliminates all mutex contention - only ONE writer, no locks needed!
func dedicatedWriter(outputChan <-chan formattedLog, doneChan <-chan struct{}, enableStats bool) {
	buf := bufio.NewWriterSize(os.Stdout, 256*1024) // Larger buffer than before
	ticker := time.NewTicker(500 * time.Millisecond) // Less frequent flushing
	defer ticker.Stop()
	defer buf.Flush()
	
	for {
		select {
		case log, ok := <-outputChan:
			if !ok {
				// Channel closed, drain remaining and exit
				return
			}
			n, _ := buf.Write(log.data)
			atomic.AddUint64(&bytesWritten, uint64(n))
			
		case <-ticker.C:
			buf.Flush()
			
		case <-doneChan:
			// Drain any remaining logs
			for {
				select {
				case log := <-outputChan:
					buf.Write(log.data)
				default:
					buf.Flush()
					return
				}
			}
		}
	}
}

func watchdogMonitor(timeoutChan chan<- struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		lastLog := lastLogReceived.Load().(time.Time)
		timeSinceLastLog := time.Since(lastLog)
		
		if timeSinceLastLog >= readTimeout {
			// Timeout reached - signal main goroutine
			close(timeoutChan)
			return
		}
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
		
		// Add connection health info
		healthInfo := ""
		if readTimeout > 0 {
			lastLog := lastLogReceived.Load().(time.Time)
			timeSinceLastLog := time.Since(lastLog)
			healthInfo = fmt.Sprintf(", Last log: %v ago", timeSinceLastLog.Round(time.Second))
		}
		
		fmt.Fprintf(os.Stderr, "Stats: %d logs/sec, %.2f MB/sec, Total: %d logs%s\n", 
			logsPerSec, mbPerSec, currentLogs, healthInfo)
		
		lastLogs = currentLogs
		lastBytes = currentBytes
	}
}
