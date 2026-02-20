# OS Trace Package

The `ostrace` package provides access to iOS's `com.apple.os_trace_relay` service, offering advanced logging and diagnostic capabilities beyond the basic `syslog_relay` service.

## Features

This implementation is competitive with [pymobiledevice3's os_trace.py](https://github.com/doronz88/pymobiledevice3) and provides:

1. **Process List Display** - Get a list of all running processes with their names and PIDs
2. **Advanced Log Streaming** - Stream system logs in binary format with rich metadata
3. **PID Filtering** - Filter logs by specific process IDs
4. **Log Level Filtering** - Filter by log levels (debug, info, error, fault)
5. **Archived Logs Retrieval** - Download archived diagnostic logs in PAX format from `/var/db/diagnostics`

## Comparison with syslog

| Feature | syslog | ostrace |
|---------|--------|---------|
| Service | `com.apple.syslog_relay` | `com.apple.os_trace_relay` |
| Format | Plain text | Binary with rich metadata |
| Process List | ❌ | ✅ |
| PID Filtering | ❌ | ✅ |
| Level Filtering | Manual parsing | ✅ Built-in |
| Subsystem Info | Limited | ✅ Full |
| Activity Tracking | ❌ | ✅ |
| Trace IDs | ❌ | ✅ |
| Archived Logs | ❌ | ✅ |

## Usage Examples

### 1. Get Process List

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

func main() {
    device, err := ios.GetDevice("")
    if err != nil {
        log.Fatal(err)
    }
    
    conn, err := ostrace.New(device)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    processes, err := conn.GetProcessList()
    if err != nil {
        log.Fatal(err)
    }
    
    for _, proc := range processes {
        fmt.Printf("%s (PID: %d)\n", proc.Label, proc.PID)
    }
}
```

### 2. Stream All Logs

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

func main() {
    device, err := ios.GetDevice("")
    if err != nil {
        log.Fatal(err)
    }
    
    conn, err := ostrace.New(device)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    config := ostrace.StreamConfig{
        DebugLevel: true,
        InfoLevel:  true,
    }
    
    err = conn.StartStreaming(config)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.StopStreaming()
    
    // Stream logs indefinitely
    for {
        entry, err := conn.ReadLogEntry()
        if err != nil {
            log.Printf("Error reading log: %v", err)
            continue
        }
        
        fmt.Println(ostrace.FormatLogEntry(entry))
    }
}
```

### 3. Stream Logs from Specific Process

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

func main() {
    device, err := ios.GetDevice("")
    if err != nil {
        log.Fatal(err)
    }
    
    conn, err := ostrace.New(device)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    // Get process list first
    processes, err := conn.GetProcessList()
    if err != nil {
        log.Fatal(err)
    }
    
    // Find the process you're interested in
    var targetPID int
    for _, proc := range processes {
        if proc.Label == "SpringBoard" {
            targetPID = proc.PID
            break
        }
    }
    
    if targetPID == 0 {
        log.Fatal("Process not found")
    }
    
    config := ostrace.StreamConfig{
        PID:        targetPID,
        DebugLevel: true,
        InfoLevel:  true,
    }
    
    err = conn.StartStreaming(config)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.StopStreaming()
    
    for {
        entry, err := conn.ReadLogEntry()
        if err != nil {
            log.Printf("Error: %v", err)
            continue
        }
        
        fmt.Println(ostrace.FormatLogEntry(entry))
    }
}
```

### 4. Stream Errors Only

```go
config := ostrace.StreamConfig{
    ErrorsOnly: true,
}

err = conn.StartStreaming(config)
if err != nil {
    log.Fatal(err)
}
defer conn.StopStreaming()

for {
    entry, err := conn.ReadLogEntry()
    if err != nil {
        continue
    }
    
    fmt.Printf("[ERROR] %s\n", ostrace.FormatLogEntry(entry))
}
```

### 5. Download Archived Logs

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

func main() {
    device, err := ios.GetDevice("")
    if err != nil {
        log.Fatal(err)
    }
    
    conn, err := ostrace.New(device)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    // Download with progress tracking
    archiveData, err := conn.GetArchivedLogsWithProgress(func(current, total int) {
        if total > 0 {
            progress := float64(current) / float64(total) * 100
            fmt.Printf("\rDownloading: %.2f%%", progress)
        } else {
            fmt.Printf("\rDownloaded: %d bytes", current)
        }
    })
    
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("\nDownloaded %d bytes\n", len(archiveData))
    
    // Save to file
    err = conn.SaveArchivedLogsToFile("device_logs.pax")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("Saved to device_logs.pax")
    fmt.Println("Extract with: pax -r < device_logs.pax")
}
```

### 6. Filter Log Entries

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

func main() {
    device, err := ios.GetDevice("")
    if err != nil {
        log.Fatal(err)
    }
    
    conn, err := ostrace.New(device)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    config := ostrace.StreamConfig{
        DebugLevel: true,
        InfoLevel:  true,
    }
    
    err = conn.StartStreaming(config)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.StopStreaming()
    
    var entries []*ostrace.LogEntry
    
    // Collect some entries
    for i := 0; i < 100; i++ {
        entry, err := conn.ReadLogEntry()
        if err != nil {
            continue
        }
        entries = append(entries, entry)
    }
    
    // Filter by subsystem
    networkEntries := ostrace.FilterLogsBySubsystem(entries, "com.apple.network")
    fmt.Printf("Network entries: %d\n", len(networkEntries))
    
    // Filter by level
    errorEntries := ostrace.FilterLogsByLevel(entries, "error")
    fmt.Printf("Error entries: %d\n", len(errorEntries))
    
    // Filter by PID
    pidEntries := ostrace.FilterLogsByProcess(entries, 123)
    fmt.Printf("Entries from PID 123: %d\n", len(pidEntries))
}
```

## Log Entry Structure

Each log entry contains rich metadata:

```go
type LogEntry struct {
    Timestamp       time.Time              // When the log was generated
    ProcessID       int                    // Process ID
    ThreadID        uint64                 // Thread ID
    Level           string                 // Log level: default, info, debug, error, fault
    Message         string                 // The actual log message
    Category        string                 // Log category
    Subsystem       string                 // Log subsystem (e.g., com.apple.network)
    ActivityID      uint64                 // Activity identifier
    ParentActivityID uint64                // Parent activity identifier
    TraceID         uint64                 // Trace identifier
    RawData         map[string]interface{} // Raw data from the device
}
```

## Stream Configuration

```go
type StreamConfig struct {
    PID        int    // Filter by process ID (0 = no filter)
    LogLevel   string // Filter by log level
    DebugLevel bool   // Include debug messages
    InfoLevel  bool   // Include info messages
    ErrorsOnly bool   // Include errors only
}
```

## Extracting PAX Archives

The archived logs are in PAX format. To extract them:

```bash
# On macOS/Linux with pax command
pax -r < device_logs.pax

# Or using tar (PAX is compatible with tar)
tar -xf device_logs.pax

# The extracted files will be from /var/db/diagnostics
```

## Connection Methods

The package supports both connection methods:

- **USB/Lightning**: Uses `com.apple.os_trace_relay` via usbmuxd (iOS < 17)
- **RSD/Tunnel**: Uses `com.apple.os_trace_relay.shim.remote` via tunnel (iOS 17+)

The `New()` function automatically selects the appropriate method based on device capabilities.

## Performance Notes

1. **Streaming**: The binary format is more efficient than plain text syslog
2. **Filtering**: Server-side filtering (PID, level) is more efficient than client-side filtering
3. **Archived Logs**: Can be large (hundreds of MB), use progress callback for long operations

## Compatibility with pymobiledevice3

This implementation provides the same core functionality as pymobiledevice3's `os_trace.py`:

| pymobiledevice3 | go-ios ostrace |
|----------------|----------------|
| `show_process_list()` | `GetProcessList()` |
| `syslog()` | `StartStreaming()` + `ReadLogEntry()` |
| `collect_archive()` | `GetArchivedLogs()` |
| PID filtering | ✅ `StreamConfig.PID` |
| Archive extraction | Save to file, extract with `pax` |

## License

This package is part of go-ios and follows the same license.

