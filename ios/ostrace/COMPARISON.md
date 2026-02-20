# Comparison: go-ios ostrace vs pymobiledevice3 os_trace.py

This document provides a detailed comparison between the go-ios `ostrace` package and pymobiledevice3's `os_trace.py` module.

## Overview

Both implementations provide access to Apple's `com.apple.os_trace_relay` service, which offers advanced logging and diagnostic capabilities for iOS devices.

## Feature Comparison

| Feature | pymobiledevice3 | go-ios ostrace | Notes |
|---------|----------------|----------------|-------|
| **Core Functionality** | | | |
| Process list display | ✅ `show_process_list()` | ✅ `GetProcessList()` | Both retrieve running processes with PIDs |
| Log streaming | ✅ `syslog()` | ✅ `StartStreaming()` + `ReadLogEntry()` | Both support real-time log streaming |
| Archived logs | ✅ `collect_archive()` | ✅ `GetArchivedLogs()` | Both retrieve PAX-format archives |
| **Filtering** | | | |
| Filter by PID | ✅ | ✅ `StreamConfig.PID` | Both support server-side PID filtering |
| Filter by log level | ✅ | ✅ `StreamConfig.ErrorsOnly` | Both support level-based filtering |
| Filter by subsystem | ⚠️ Limited | ✅ `FilterLogsBySubsystem()` | go-ios provides client-side filtering |
| **Progress & Monitoring** | | | |
| Archive progress callback | ✅ | ✅ `GetArchivedLogsWithProgress()` | Both support progress monitoring |
| Real-time streaming | ✅ | ✅ | Both support real-time log consumption |
| **Data Format** | | | |
| Binary plist parsing | ✅ | ✅ | Both parse binary plist messages |
| Structured log entries | ✅ | ✅ `LogEntry` struct | Both provide structured data |
| Metadata extraction | ✅ | ✅ | Activity IDs, trace IDs, thread IDs |
| **Connection Methods** | | | |
| USB/Lightning | ✅ via usbmuxd | ✅ via usbmuxd | iOS < 17 |
| Tunnel/RSD | ✅ | ✅ via shim service | iOS 17+ |
| Auto-detection | ✅ | ✅ `New()` auto-selects | Both detect best method |
| **CLI Tools** | | | |
| Command-line interface | ✅ `pymobiledevice3 syslog` | ✅ `ostrace` binary | Both provide CLI access |
| Process listing | ✅ | ✅ `-list` flag | |
| Archive download | ✅ | ✅ `-archive` flag | |
| **Programming API** | | | |
| Language | Python 3 | Go | |
| Async/Sync | Async (asyncio) | Sync (goroutines) | Different concurrency models |
| Type safety | ⚠️ Dynamic | ✅ Strongly typed | Go provides compile-time safety |
| Error handling | Exceptions | Error returns | Idiomatic to each language |

## Implementation Details

### Service Names

Both implementations use the same service identifiers:

- **USB/Lightning**: `com.apple.os_trace_relay`
- **Tunnel/RSD**: `com.apple.os_trace_relay.shim.remote`

### Protocol

Both implementations use the same protocol:
1. Length-prefixed plist messages (4 bytes big-endian length + plist payload)
2. Binary plist encoding
3. Request-response pattern for commands
4. Streaming responses for logs

### Commands

| Command | pymobiledevice3 | go-ios |
|---------|----------------|--------|
| Get process list | `PidList` | `PidList` |
| Start streaming | `StartActivity` | `StartActivity` |
| Stop streaming | `StopActivity` | `StopActivity` |
| Collect archive | `CollectArchive` | `CollectArchive` |

## Code Examples Comparison

### Get Process List

**pymobiledevice3:**
```python
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.lockdown import create_using_usbmux

lockdown = create_using_usbmux()
with OsTraceService(lockdown=lockdown) as service:
    processes = service.show_process_list()
    for proc in processes:
        print(f"{proc['Label']} (PID: {proc['Pid']})")
```

**go-ios:**
```go
import (
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

device, _ := ios.GetDevice("")
conn, _ := ostrace.New(device)
defer conn.Close()

processes, _ := conn.GetProcessList()
for _, proc := range processes {
    fmt.Printf("%s (PID: %d)\n", proc.Label, proc.PID)
}
```

### Stream Logs

**pymobiledevice3:**
```python
with OsTraceService(lockdown=lockdown) as service:
    for entry in service.syslog():
        print(entry)
```

**go-ios:**
```go
config := ostrace.StreamConfig{
    DebugLevel: true,
    InfoLevel:  true,
}

conn.StartStreaming(config)
defer conn.StopStreaming()

for {
    entry, err := conn.ReadLogEntry()
    if err != nil {
        continue
    }
    fmt.Println(ostrace.FormatLogEntry(entry))
}
```

### Stream Logs with PID Filter

**pymobiledevice3:**
```python
with OsTraceService(lockdown=lockdown) as service:
    for entry in service.syslog(pid=123):
        print(entry)
```

**go-ios:**
```go
config := ostrace.StreamConfig{
    PID:        123,
    DebugLevel: true,
    InfoLevel:  true,
}

conn.StartStreaming(config)
defer conn.StopStreaming()

for {
    entry, _ := conn.ReadLogEntry()
    fmt.Println(ostrace.FormatLogEntry(entry))
}
```

### Download Archived Logs

**pymobiledevice3:**
```python
with OsTraceService(lockdown=lockdown) as service:
    archive = service.collect_archive()
    with open('logs.pax', 'wb') as f:
        f.write(archive)
```

**go-ios:**
```go
conn, _ := ostrace.New(device)
defer conn.Close()

err := conn.SaveArchivedLogsToFile("logs.pax")
```

## CLI Usage Comparison

### List Processes

**pymobiledevice3:**
```bash
pymobiledevice3 syslog live --process-list
```

**go-ios:**
```bash
./ostrace -list
```

### Stream All Logs

**pymobiledevice3:**
```bash
pymobiledevice3 syslog live
```

**go-ios:**
```bash
./ostrace
```

### Stream Logs from Specific Process

**pymobiledevice3:**
```bash
pymobiledevice3 syslog live --pid 123
# or
pymobiledevice3 syslog live --process SpringBoard
```

**go-ios:**
```bash
./ostrace -pid 123
# or
./ostrace -process SpringBoard
```

### Download Archived Logs

**pymobiledevice3:**
```bash
pymobiledevice3 syslog collect --out logs.pax
```

**go-ios:**
```bash
./ostrace -archive -archive-file logs.pax
```

### Show Errors Only

**pymobiledevice3:**
```bash
pymobiledevice3 syslog live --level error
```

**go-ios:**
```bash
./ostrace -errors-only
```

## Performance Comparison

| Metric | pymobiledevice3 | go-ios | Winner |
|--------|----------------|--------|--------|
| Memory usage | Higher (Python runtime) | Lower (compiled binary) | go-ios |
| CPU usage | Higher (interpreted) | Lower (compiled) | go-ios |
| Startup time | Slower (Python import) | Faster (native binary) | go-ios |
| Binary size | Large (Python + deps) | Small (~10MB static) | go-ios |
| Concurrency | asyncio (event loop) | Goroutines (native) | Tie |

## Advantages

### pymobiledevice3 Advantages

1. **Ecosystem**: Part of a larger Python toolset with many other iOS utilities
2. **Scripting**: Easy to integrate into Python scripts and automation
3. **Community**: Large Python community and extensive documentation
4. **Prototyping**: Faster for quick experiments and one-off scripts

### go-ios ostrace Advantages

1. **Performance**: Faster execution, lower memory usage
2. **Deployment**: Single binary with no dependencies
3. **Type Safety**: Compile-time type checking prevents many errors
4. **Concurrency**: Native goroutines for efficient parallel processing
5. **Cross-compilation**: Easy to build for any platform
6. **Integration**: Natural fit for Go-based tooling and applications

## Use Cases

### Choose pymobiledevice3 when:

- You're already using Python for iOS automation
- You need other pymobiledevice3 features (debugging, etc.)
- You're prototyping or doing quick experiments
- Your team is Python-focused

### Choose go-ios ostrace when:

- You need maximum performance
- You want a standalone binary with no dependencies
- You're building production tooling
- You need strong type safety
- Your application is in Go
- You need cross-platform distribution

## Data Structure Comparison

### Process Info

**pymobiledevice3:**
```python
{
    'Label': 'SpringBoard',
    'Pid': 123
}
```

**go-ios:**
```go
type ProcessInfo struct {
    Label string `plist:"Label" json:"label"`
    PID   int    `plist:"Pid" json:"pid"`
}
```

### Log Entry

**pymobiledevice3:**
```python
{
    'timestamp': <timestamp>,
    'processID': 123,
    'threadID': 456,
    'messageType': 'error',
    'eventMessage': 'Error occurred',
    'subsystem': 'com.apple.example',
    'category': 'networking',
    # ... more fields
}
```

**go-ios:**
```go
type LogEntry struct {
    Timestamp       time.Time
    ProcessID       int
    ThreadID        uint64
    Level           string
    Message         string
    Category        string
    Subsystem       string
    ActivityID      uint64
    ParentActivityID uint64
    TraceID         uint64
    RawData         map[string]interface{}
}
```

## Compatibility

Both implementations:
- Support iOS 10+
- Work with both USB and network connections
- Support iOS 17+ RSD/tunnel connections
- Handle PAX format archives the same way
- Are compatible with each other's output formats

## Conclusion

Both implementations are feature-complete and production-ready. The choice between them depends primarily on:

1. **Language preference**: Python vs Go
2. **Performance requirements**: go-ios is faster
3. **Deployment model**: Python package vs standalone binary
4. **Existing toolchain**: Integration with other tools

For new projects requiring maximum performance and easy deployment, **go-ios ostrace** is recommended.

For quick scripting and Python-based automation, **pymobiledevice3** is recommended.

Both are actively maintained and provide full access to iOS's os_trace_relay service.

