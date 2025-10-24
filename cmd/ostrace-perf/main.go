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

// logStartupProgress logs startup progress when diagnostics enabled
func logStartupProgress(phase string, diagnostics bool) {
	if diagnostics {
		fmt.Fprintf(os.Stderr, "[STARTUP] %s\n", phase)
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
		startupTimeoutSeconds = flag.Int("startup-timeout", 30, "Startup timeout: fail if streaming doesn't start within N seconds (default 30, 0 to disable)")
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
		fmt.Println("- Startup timeout protection (default 30s)")
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

	// Setup startup timeout monitoring with clean exit
	startupTimeout := time.Duration(*startupTimeoutSeconds) * time.Second
	startupCancelChan := make(chan struct{})
	
	if startupTimeout > 0 {
		// Only log if diagnostics enabled to avoid stderr noise
		if *diagnostics {
			fmt.Fprintf(os.Stderr, "Startup timeout: %v\n", startupTimeout)
		}
		
		// Start startup watchdog
		go func() {
			timer := time.NewTimer(startupTimeout)
			defer timer.Stop()
			
			select {
			case <-timer.C:
				// Timeout reached - clean exit
				fmt.Fprintf(os.Stderr, "ERROR: Startup timeout after %v\n", startupTimeout)
				fmt.Fprintf(os.Stderr, "Device not responding or connection issues\n")
				os.Exit(3) // Exit code 3 for startup timeout
			case <-startupCancelChan:
				// Startup completed successfully
				return
			}
		}()
	}

	// Get device
	var device ios.DeviceEntry
	var err error
	
	if *pymobileTunnel > 0 {
		logStartupProgress("Connecting via pymobiledevice3 tunnel", *diagnostics)
		
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
		logStartupProgress("Connecting via RSD", *diagnostics)
		
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
		
		logStartupProgress("Performing RSD handshake", *diagnostics)
		
		// Perform RSD handshake
		// Use a conservative timeout to avoid indefinite blocking
		rsdProvider, err := rsdService.HandshakeWithTimeout(15 * time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to perform RSD handshake: %v\n", err)
			rsdService.Close()
			os.Exit(1)
		}
		
		// Get device with RSD provider
		device, err = ios.GetDeviceWithAddress(*udid, *rsdHost, rsdProvider)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get device via RSD: %v\n", err)
			rsdService.Close()
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Using device %s via RSD (%s:%d)\n", device.Properties.SerialNumber, *rsdHost, *rsdPort)
	} else {
		logStartupProgress("Connecting to device", *diagnostics)
		
		// Use regular connection
		device, err = ios.GetDevice(*udid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get device: %v\n", err)
			os.Exit(1)
		}
	}

	logStartupProgress("Connecting to ostrace service", *diagnostics)
	
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
		logStartupProgress("Retrieving process list", *diagnostics)
		
		processes, err := conn.GetProcessList()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get process list: %v\n", err)
			conn.Close()
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
		logStartupProgress("Looking up process by name", *diagnostics)
		
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
					conn.Close()
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
		logStartupProgress("Loading filter configuration", *diagnostics)
		
		filterConfig, err = ostrace.LoadFilterConfig(*filterFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load filter: %v\n", err)
			conn.Close()
			os.Exit(1)
		}
	}

	logStartupProgress("Starting log streaming", *diagnostics)
	
	// Start streaming with device-side PID filtering
	config := ostrace.StreamConfig{PID: targetPID}
	if targetPID != -1 {
		fmt.Fprintf(os.Stderr, "Starting stream with device-side PID filter: %d\n", targetPID)
	}
	if err := conn.StartStreaming(config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start streaming: %v\n", err)
		conn.Close()
		os.Exit(1)
	}
	
	// CRITICAL: Streaming started - cancel startup timeout
	if startupTimeout > 0 {
		close(startupCancelChan)
		if *diagnostics {
			fmt.Fprintf(os.Stderr, "[STARTUP] Streaming started, timeout canceled\n")
		}
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

	// Main reading loop with inline fast-path filtering for high-volume scenarios
	readErrorChan := make(chan error, 1)
	go func() {
		consecutiveErrors := 0
		lastDiagnostic := time.Now()
		logsReadTotal := uint64(0)
		logsFilteredOut := uint64(0)
		lastPingCheck := time.Now()
		
		for {
			// Diagnostic logging (non-blocking)
			if *diagnostics && time.Since(lastDiagnostic) >= 10*time.Second {
				filterRatio := float64(0)
				if logsReadTotal > 0 {
					filterRatio = float64(logsFilteredOut) / float64(logsReadTotal) * 100
				}
				logStderr("[DIAG] Reading logs... Total: %d, Filtered out: %d (%.1f%%), Sent to workers: %d, Errors: %d\n", 
					logsReadTotal, logsFilteredOut, filterRatio, atomic.LoadUint64(&logsProcessed), consecutiveErrors)
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
			
			logsReadTotal++
			
			// Update last log received time for watchdog
			if readTimeout > 0 {
				lastLogReceived.Store(time.Now())
			}
			
			// CRITICAL: Reader must NEVER block on CPU-intensive work
			// Strategy: Apply fast pre-filters in reader, send rest to workers
			// This keeps socket draining at maximum speed
			
			shouldSkip := false
			
			// Fast-path optimization: Simple content filters only (not regex/complex)
			// Only apply if filter is simple string matching to avoid blocking reader
			if filterConfig != nil && isSimpleFilter(filterConfig) {
				matchesFilter := ostrace.EvaluateFilters(entry, filterConfig)
				
				if !matchesFilter {
					logsFilteredOut++
					shouldSkip = true
					
					// Handle ping even for filtered-out logs (but don't check on every iteration)
					// Only check every Nth log to avoid time.Since() overhead in hot path
					if pingInterval > 0 && logsReadTotal % 1000 == 0 && time.Since(lastPingCheck) >= pingInterval {
						sendPingDirect(outputChan, *jsonOutput)
						lastPingCheck = time.Now()
					}
				}
			}
			
			if shouldSkip {
				// Fast path: discard without worker overhead
				ostrace.PutLogEntry(entry)
				continue
			}
			
			// Send to workers for filtering (if complex) and formatting
			// Workers will re-evaluate filter if needed (parallel processing)
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
	
	// Determine if we need to re-evaluate filters (complex filters only)
	needsFiltering := filterConfig != nil && !isSimpleFilter(filterConfig)
	
	for entry := range entryChan {
		// Re-evaluate filter if it's complex (regex, AND/OR, etc.)
		// Simple filters were already evaluated in reader (fast path)
		if needsFiltering {
			matchesFilter := ostrace.EvaluateFilters(entry, filterConfig)
			if !matchesFilter {
				ostrace.PutLogEntry(entry)
				continue
			}
		}
		
		// Format and output
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

// isSimpleFilter determines if a filter is "simple" enough to evaluate in the reader
// Simple filters: fast string operations that won't block socket reads
// Complex filters: AND logic, REGEX, deep nesting (need parallel workers for best perf)
//
// Strategy: OR-only filters with simple CONTAINS are fast enough for reader
// because they short-circuit on first match (common case: match early in OR list)
func isSimpleFilter(config *ostrace.FilterConfig) bool {
	if config == nil || len(config.Filters) == 0 {
		return true
	}
	
	// Single filter - check if it's simple
	if len(config.Filters) == 1 {
		return isSimpleFilterNode(&config.Filters[0], 0)
	}
	
	// Multiple top-level filters act as OR (any match = accept)
	// Check if all are simple - if so, it's fast enough for reader
	for i := range config.Filters {
		if !isSimpleFilterNode(&config.Filters[i], 0) {
			return false // One complex filter = use workers
		}
	}
	
	return true // All simple = can use reader fast path
}

// isSimpleFilterNode checks if a single filter node is simple
// maxDepth limits how deep we'll go before calling it "complex"
func isSimpleFilterNode(filter *ostrace.Filter, depth int) bool {
	// Too deep = complex (use workers for parallelism)
	// Allow up to 3 levels: OR -> AND -> OR -> CONTAINS
	if depth > 3 {
		return false
	}
	
	// REGEX is CPU-intensive, always use workers
	if filter.Operator == "REGEX" {
		return false
	}
	
	// AND logic requires ALL children to pass = more work
	// However, simple AND (2-3 simple CONTAINS checks) is still fast
	// Example: AND([Recording Indicator], sensor: camera) = ~40ns
	if filter.Type == "AND" {
		// Only allow AND if it has few simple children
		if len(filter.Children) > 3 {
			return false // Too many checks
		}
		// Check all children are simple (no nested logic)
		for i := range filter.Children {
			if !isSimpleFilterNode(&filter.Children[i], depth+1) {
				return false
			}
		}
		return true // Simple AND with few children = acceptable
	}
	
	// NOT logic is rare and typically slower
	if filter.Type == "NOT" {
		return false
	}
	
	// OR logic with simple children is acceptable because:
	// 1. Short-circuits on first match (often matches early)
	// 2. SpringBoard filters typically match frequently
	// 3. String CONTAINS is ~20ns, even 10 checks = 200ns
	if filter.Type == "OR" {
		// Check all children are simple
		for i := range filter.Children {
			if !isSimpleFilterNode(&filter.Children[i], depth+1) {
				return false
			}
		}
		return true // OR of simple filters = simple
	}
	
	// Field-based filter - check operator
	// CONTAINS, EQUALS, STARTS_WITH, ENDS_WITH, NOT_CONTAINS are fast
	// These are just string comparisons, safe for reader goroutine
	switch filter.Operator {
	case "CONTAINS", "EQUALS", "NOT_CONTAINS", "STARTS_WITH", "ENDS_WITH":
		return true
	default:
		return false
	}
}

// sendPing sends a ping message and updates the last ping time
// DEPRECATED: Use sendPingDirect instead for non-blocking operation
func sendPing(outputChan chan<- formattedLog, jsonOutput bool) {
	sendPingDirect(outputChan, jsonOutput)
}

// sendPingDirect sends a ping message without blocking
// Used by the reader goroutine to avoid blocking on channel sends
func sendPingDirect(outputChan chan<- formattedLog, jsonOutput bool) {
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
	
	// Try to send ping to output channel (non-blocking)
	// If channel is full, skip ping to avoid blocking the reader
	select {
	case outputChan <- formattedLog{data: pingMsg}:
		// Ping sent successfully
	default:
		// Channel full - skip ping to avoid blocking
		// Reader goroutine must NEVER block
	}
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
