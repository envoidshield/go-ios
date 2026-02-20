# os_trace Design Documentation

## Overview

The `ostrace` package implements Apple's `com.apple.os_trace_relay` service following go-ios design patterns. It provides functionality for:

- Real-time log streaming from iOS devices
- Process enumeration
- Archived log retrieval

## Design Patterns

### 1. Service Connection Pattern

The package follows go-ios's standard connection pattern:

```go
// Standard pattern: New() function that handles both USB and tunnel
func New(device ios.DeviceEntry) (*Connection, error) {
    if device.SupportsRsd() {
        return NewWithShimConnection(device)
    }
    return NewWithUsbmuxdConnection(device)
}

// Specific connection methods for different transports
func NewWithUsbmuxdConnection(device ios.DeviceEntry) (*Connection, error)
func NewWithShimConnection(device ios.DeviceEntry) (*Connection, error)
```

This matches the pattern used by other services like `syslog`, `zipconduit`, etc.

### 2. Connection Structure

```go
type Connection struct {
    deviceConn ios.DeviceConnectionInterface
    codec      *OsTraceCodec
}
```

- Uses `ios.DeviceConnectionInterface` for abstraction over different connection types
- Encapsulates protocol-specific logic in a custom codec

### 3. Protocol Handling

The `OsTraceCodec` handles the custom binary protocol:

```go
type OsTraceCodec struct{}

// Request: 4-byte big-endian length + binary plist
func (c *OsTraceCodec) WriteRequest(w io.Writer, request interface{}) error

// Streaming: Status byte + 4-byte little-endian length + data
func (c *OsTraceCodec) ReadStreamChunk(r io.Reader) (status byte, data []byte, err error)
```

### 4. Error Handling

All errors follow go-ios conventions:

```go
return nil, fmt.Errorf("function_name: descriptive message: %w", err)
```

Special handling for known limitations:

```go
if errStr := err.Error(); contains(errStr, "16384") || contains(errStr, "unexpected EOF") {
    return nil, fmt.Errorf("failed to read response: %w. This often happens with direct USB connections when the response exceeds 16KB. Solutions: 1) Use 'ios tunnel start' to enable tunnel connection, 2) Use 'ios ps' command instead", err)
}
```

### 5. Public API Design

Methods follow clear, descriptive naming:

```go
// Process management
func (c *Connection) GetProcessList() ([]ProcessInfo, error)

// Log streaming
func (c *Connection) StartStreaming(config StreamConfig) error
func (c *Connection) ReadLogEntry() (*LogEntry, error)
func (c *Connection) StopStreaming() error

// Archive management
func (c *Connection) GetArchivedLogs() ([]byte, error)
```

## Protocol Details

### Binary Log Format

The log format is manually parsed based on pymobiledevice3's structure:

```go
// Fixed offsets discovered through analysis
pidOffset := 4
timestampSecondsOffset := 8
timestampSubsecondsOffset := 16
levelOffset := 24
// ... variable length strings follow
```

### Connection Limitations

**16KB TLS Record Limit**: Direct USB connections to `os_trace_relay` have a hard limit of 16KB for responses. This is a limitation in iOS's implementation, not go-ios.

**Workarounds**:
1. Use tunnel connections (RSD/`.shim.remote` services)
2. Use alternative services (e.g., `instruments` for process listing)

## Integration Points

### PyMobileDevice3 Tunnel Support

The package works seamlessly with the pymobiledevice3 tunnel integration:

```go
// Get device through pymobiledevice3 tunnel
device, err := ios.GetDeviceWithPyMobileTunnel(udid, 49151)

// Use with ostrace - automatically uses tunnel connection
conn, err := ostrace.New(device)
```

### CLI Tool Pattern

The `cmd/ostrace` follows go-ios CLI patterns:

- Uses `flag` for argument parsing
- Uses `logrus` for logging
- Provides `-h` help flag
- Supports both interactive and batch operations

## Testing Considerations

1. **Unit Testing**: Protocol parsing is testable in isolation
2. **Integration Testing**: Requires real device connection
3. **Cross-platform**: Protocol is platform-independent

## Future Enhancements

1. **Filtering**: Server-side filtering could be enhanced with more predicate options
2. **Performance**: Batch reading of multiple log entries
3. **Compression**: Support for compressed log streams
