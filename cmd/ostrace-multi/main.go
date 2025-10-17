// Multi-device ostrace optimized for resource-constrained environments
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/ostrace"
	jsoniter "github.com/json-iterator/go"
	"gopkg.in/yaml.v3"
)

var fastJSON = jsoniter.ConfigFastest

// StreamConfig represents configuration for a single stream
type StreamConfig struct {
	Name       string `yaml:"name"`
	UDID       string `yaml:"udid"`
	FilterFile string `yaml:"filter_file"`
	OutputFile string `yaml:"output_file"`
	PID        int    `yaml:"pid,omitempty"`
}

// MultiConfig represents configuration for multiple streams
type MultiConfig struct {
	PyMobileTunnel int            `yaml:"pymobile_tunnel"`
	MaxWorkers     int            `yaml:"max_workers"`
	BufferSize     int            `yaml:"buffer_size"`
	Streams        []StreamConfig `yaml:"streams"`
}

// StreamHandler manages a single log stream
type StreamHandler struct {
	config   StreamConfig
	device   ios.DeviceEntry
	conn     *ostrace.Connection
	filter   *ostrace.FilterConfig
	output   *os.File
	writer   *json.Encoder
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func main() {
	var (
		configFile = flag.String("config", "", "YAML configuration file")
		help       = flag.Bool("h", false, "Show help")
	)
	flag.Parse()

	if *help || *configFile == "" {
		fmt.Println("ostrace-multi - Multi-device/stream ostrace for IoT")
		fmt.Println("\nOptimized for resource-constrained environments")
		fmt.Println("\nUsage:")
		fmt.Println("  ostrace-multi -config streams.yaml")
		fmt.Println("\nExample config:")
		fmt.Println(`
pymobile_tunnel: 49151
max_workers: 2  # Keep low for dual-core
buffer_size: 100  # Small buffer to save memory
streams:
  - name: "device1_system"
    udid: "00008112-000869810A83A01E"
    filter_file: "filters/system.yaml"
    output_file: "logs/device1_system.jsonl"
  - name: "device1_apps"
    udid: "00008112-000869810A83A01E"
    filter_file: "filters/apps.yaml"
    output_file: "logs/device1_apps.jsonl"
`)
		os.Exit(0)
	}

	// Limit CPU usage for IoT
	runtime.GOMAXPROCS(2)
	
	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Get devices via pymobile tunnel
	devices := make(map[string]ios.DeviceEntry)
	for _, stream := range config.Streams {
		if _, exists := devices[stream.UDID]; !exists {
			device, err := ios.GetDeviceWithPyMobileTunnel(stream.UDID, config.PyMobileTunnel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get device %s: %v\n", stream.UDID, err)
				os.Exit(1)
			}
			devices[stream.UDID] = device
		}
	}

	// Create stream handlers
	handlers := make([]*StreamHandler, 0, len(config.Streams))
	for _, streamConfig := range config.Streams {
		handler, err := newStreamHandler(streamConfig, devices[streamConfig.UDID])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create handler for %s: %v\n", streamConfig.Name, err)
			continue
		}
		handlers = append(handlers, handler)
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start all streams with worker pool
	fmt.Printf("Starting %d streams with %d workers...\n", len(handlers), config.MaxWorkers)
	
	// Use a worker pool to limit concurrent processing
	workChan := make(chan *ostrace.LogEntry, config.BufferSize)
	var workersWg sync.WaitGroup
	
	// Start worker pool
	for i := 0; i < config.MaxWorkers; i++ {
		workersWg.Add(1)
		go worker(workChan, &workersWg)
	}

	// Start stream readers
	for _, handler := range handlers {
		handler.start(workChan)
	}

	// Wait for signal
	<-sigChan
	fmt.Println("\nShutting down...")

	// Stop all handlers
	for _, handler := range handlers {
		handler.stop()
	}

	// Close work channel and wait for workers
	close(workChan)
	workersWg.Wait()

	fmt.Println("All streams stopped")
}

func loadConfig(filename string) (*MultiConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config MultiConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 2 // Good for dual-core
	}
	if config.BufferSize == 0 {
		config.BufferSize = 100 // Small buffer for low memory
	}

	return &config, nil
}

func newStreamHandler(config StreamConfig, device ios.DeviceEntry) (*StreamHandler, error) {
	handler := &StreamHandler{
		config:   config,
		device:   device,
		stopChan: make(chan struct{}),
	}

	// Load filter if specified
	if config.FilterFile != "" {
		filter, err := ostrace.LoadFilterConfig(config.FilterFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load filter: %w", err)
		}
		handler.filter = filter
	}

	// Create output file
	if err := os.MkdirAll(filepath.Dir(config.OutputFile), 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	output, err := os.Create(config.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	handler.output = output
	handler.writer = json.NewEncoder(output)

	// Connect to device
	conn, err := ostrace.New(device)
	if err != nil {
		output.Close()
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	handler.conn = conn

	return handler, nil
}

type LogEntryWithStream struct {
	*ostrace.LogEntry
	Stream string `json:"stream"`
}

func (h *StreamHandler) start(workChan chan<- *ostrace.LogEntry) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		
		// Start streaming
		config := ostrace.StreamConfig{PID: h.config.PID}
		if err := h.conn.StartStreaming(config); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Failed to start streaming: %v\n", h.config.Name, err)
			return
		}

		fmt.Printf("[%s] Started streaming to %s\n", h.config.Name, h.config.OutputFile)

		// Read loop
		for {
			select {
			case <-h.stopChan:
				return
			default:
				entry, err := h.conn.ReadLogEntry()
				if err != nil {
					if err != io.EOF {
						fmt.Fprintf(os.Stderr, "[%s] Read error: %v\n", h.config.Name, err)
					}
					return
				}

				// Apply filter
				if h.filter != nil && !ostrace.EvaluateFilters(entry, h.filter) {
					continue
				}

				// Send to worker pool for processing
				select {
				case workChan <- entry:
				case <-h.stopChan:
					return
				default:
					// Buffer full, drop log
				}
			}
		}
	}()
}

func (h *StreamHandler) stop() {
	close(h.stopChan)
	h.wg.Wait()
	
	if h.conn != nil {
		h.conn.StopStreaming()
		h.conn.Close()
	}
	
	if h.output != nil {
		h.output.Sync()
		h.output.Close()
	}
}

func worker(workChan <-chan *ostrace.LogEntry, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Reuse buffer for JSON encoding
	buf := make([]byte, 0, 1024)
	
	for entry := range workChan {
		// Process entry (already filtered)
		// This is where you could add additional processing
		
		// For now, just format as needed
		_ = buf // In real implementation, use this for efficient encoding
		_ = entry
	}
}
