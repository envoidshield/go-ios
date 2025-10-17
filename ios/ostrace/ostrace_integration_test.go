//go:build !fast
// +build !fast

package ostrace_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/ostrace"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetProcessList(t *testing.T) {
	device, err := ios.GetDevice("")
	if err != nil {
		t.Skip("No device connected")
		return
	}

	conn, err := ostrace.New(device)
	if err != nil {
		t.Fatalf("Failed to create ostrace connection: %v", err)
	}
	defer conn.Close()

	processes, err := conn.GetProcessList()
	if err != nil {
		t.Fatalf("Failed to get process list: %v", err)
	}

	assert.Greater(t, len(processes), 0, "Should have at least one process")
	
	log.Infof("Found %d processes", len(processes))
	for i, proc := range processes {
		if i < 5 { // Log first 5 for debugging
			log.Debugf("Process: %s (PID: %d)", proc.Label, proc.PID)
		}
	}
}

func TestStreamLogs(t *testing.T) {
	device, err := ios.GetDevice("")
	if err != nil {
		t.Skip("No device connected")
		return
	}

	conn, err := ostrace.New(device)
	if err != nil {
		t.Fatalf("Failed to create ostrace connection: %v", err)
	}
	defer conn.Close()

	config := ostrace.StreamConfig{
		DebugLevel: true,
		InfoLevel:  true,
	}

	err = conn.StartStreaming(config)
	if err != nil {
		t.Fatalf("Failed to start streaming: %v", err)
	}
	defer conn.StopStreaming()

	// Read a few log entries
	entriesRead := 0
	timeout := time.After(10 * time.Second)
	
readLoop:
	for entriesRead < 5 {
		select {
		case <-timeout:
			if entriesRead == 0 {
				t.Fatal("Timeout: No log entries received")
			}
			break readLoop
		default:
			entry, err := conn.ReadLogEntry()
			if err != nil {
				log.Warnf("Error reading log entry: %v", err)
				continue
			}
			
			if entry != nil {
				entriesRead++
				log.Debug(ostrace.FormatLogEntry(entry))
				assert.NotEmpty(t, entry.Message, "Log message should not be empty")
			}
		}
	}

	assert.Greater(t, entriesRead, 0, "Should have read at least one log entry")
}

func TestStreamLogsWithPIDFilter(t *testing.T) {
	device, err := ios.GetDevice("")
	if err != nil {
		t.Skip("No device connected")
		return
	}

	conn, err := ostrace.New(device)
	if err != nil {
		t.Fatalf("Failed to create ostrace connection: %v", err)
	}
	defer conn.Close()

	// First get a process list to find a PID
	processes, err := conn.GetProcessList()
	if err != nil {
		t.Fatalf("Failed to get process list: %v", err)
	}

	if len(processes) == 0 {
		t.Skip("No processes found")
		return
	}

	// Use the first process PID for filtering
	testPID := processes[0].PID
	log.Infof("Testing with PID filter: %d (%s)", testPID, processes[0].Label)

	config := ostrace.StreamConfig{
		PID:        testPID,
		DebugLevel: true,
		InfoLevel:  true,
	}

	err = conn.StartStreaming(config)
	if err != nil {
		t.Fatalf("Failed to start streaming with PID filter: %v", err)
	}
	defer conn.StopStreaming()

	// Try to read a few entries (may timeout if process is not logging)
	timeout := time.After(5 * time.Second)
	entriesRead := 0

	for entriesRead < 3 {
		select {
		case <-timeout:
			log.Warnf("Timeout: Only read %d entries for PID %d", entriesRead, testPID)
			return
		default:
			entry, err := conn.ReadLogEntry()
			if err != nil {
				continue
			}
			
			if entry != nil {
				entriesRead++
				assert.Equal(t, testPID, entry.ProcessID, "Entry should be from filtered PID")
				log.Debug(ostrace.FormatLogEntry(entry))
			}
		}
	}
}

func TestGetArchivedLogs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping archived logs test in short mode (can be slow)")
	}

	device, err := ios.GetDevice("")
	if err != nil {
		t.Skip("No device connected")
		return
	}

	conn, err := ostrace.New(device)
	if err != nil {
		t.Fatalf("Failed to create ostrace connection: %v", err)
	}
	defer conn.Close()

	progressCalled := false
	archiveData, err := conn.GetArchivedLogsWithProgress(func(current, total int) {
		progressCalled = true
		if total > 0 {
			progress := float64(current) / float64(total) * 100
			log.Infof("Archive download progress: %.2f%% (%d/%d bytes)", progress, current, total)
		} else {
			log.Infof("Archive download progress: %d bytes", current)
		}
	})

	if err != nil {
		t.Fatalf("Failed to get archived logs: %v", err)
	}

	assert.Greater(t, len(archiveData), 0, "Archive data should not be empty")
	assert.True(t, progressCalled, "Progress callback should have been called")
	
	log.Infof("Received %d bytes of archived log data (PAX format)", len(archiveData))
}

func TestFilterFunctions(t *testing.T) {
	// Create some test entries
	now := time.Now()
	entries := []*ostrace.LogEntry{
		{
			Timestamp: now,
			ProcessID: 123,
			Level:     "error",
			Subsystem: "com.apple.test",
			Message:   "Test error message",
		},
		{
			Timestamp: now,
			ProcessID: 456,
			Level:     "info",
			Subsystem: "com.apple.test",
			Message:   "Test info message",
		},
		{
			Timestamp: now,
			ProcessID: 123,
			Level:     "debug",
			Subsystem: "com.apple.other",
			Message:   "Test debug message",
		},
	}

	// Test PID filtering
	filteredByPID := ostrace.FilterLogsByProcess(entries, 123)
	assert.Equal(t, 2, len(filteredByPID), "Should have 2 entries with PID 123")

	// Test level filtering
	filteredByLevel := ostrace.FilterLogsByLevel(entries, "error")
	assert.Equal(t, 1, len(filteredByLevel), "Should have 1 error entry")

	// Test subsystem filtering
	filteredBySubsystem := ostrace.FilterLogsBySubsystem(entries, "com.apple.test")
	assert.Equal(t, 2, len(filteredBySubsystem), "Should have 2 entries from com.apple.test")
}

func TestFormatLogEntry(t *testing.T) {
	entry := &ostrace.LogEntry{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Level:     "error",
		ProcessID: 123,
		Subsystem: "com.apple.test",
		Category:  "networking",
		Message:   "Test message",
	}

	formatted := ostrace.FormatLogEntry(entry)
	assert.Contains(t, formatted, "error", "Should contain log level")
	assert.Contains(t, formatted, "123", "Should contain PID")
	assert.Contains(t, formatted, "com.apple.test", "Should contain subsystem")
	assert.Contains(t, formatted, "Test message", "Should contain message")
	
	fmt.Println(formatted)
}

