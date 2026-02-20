# PyMobileDevice3 Tunnel Integration for go-ios

This integration allows go-ios to use pymobiledevice3's tunnel daemon to connect to iOS devices. This is particularly useful for:

1. **Avoiding the 16KB limitation** in direct USB connections for services like `os_trace_relay`
2. **Using existing pymobiledevice3 infrastructure** without running separate tunnel daemons
3. **Accessing iOS 17+ devices** through the tunnel interface

## How It Works

When iOS devices (especially iOS 17+) are connected, they expose services through a tunnel interface. PyMobileDevice3's tunnel daemon creates IPv6 tunnels to these devices and exposes them via an HTTP API.

The integration adds:
- `ios.GetDeviceWithPyMobileTunnel()` - Connect to a device through pymobiledevice3's tunnel
- `ios.ListDevicesWithPyMobileTunnel()` - List all devices available through the tunnel
- `ostrace_pymobile` - A modified ostrace command that uses the tunnel

## Setup

1. **Start pymobiledevice3's tunnel daemon:**
   ```bash
   sudo python3 -m pymobiledevice3 remote tunneld
   ```
   
   By default, it runs on port 49151. You can verify it's running:
   ```bash
   curl http://127.0.0.1:49151/
   ```

2. **Build the pymobile-aware ostrace:**
   ```bash
   go build ./cmd/ostrace_pymobile
   ```

## Usage

### Using the wrapper script:
```bash
# List processes
./ostrace-pymobile.sh -list

# Stream logs
./ostrace-pymobile.sh

# Filter by process
./ostrace-pymobile.sh -process SpringBoard

# Get archived logs
./ostrace-pymobile.sh -archive
```

### Using the binary directly:
```bash
# List processes through tunnel
./ostrace_pymobile -list -pymobile-tunnel 49151

# Use a specific device
./ostrace_pymobile -udid 00008130-000418901E93803A -list

# If pymobiledevice3 tunnel is on a different port
./ostrace_pymobile -list -pymobile-tunnel 12345
```

### Programmatic usage:
```go
import (
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

// Connect to device through pymobiledevice3 tunnel
// This follows the same pattern as regular device connections
device, err := ios.GetDeviceWithPyMobileTunnel(udid, 49151)
if err != nil {
    log.Fatal(err)
}

// Use with ostrace
conn, err := ostrace.New(device)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

// Get process list (works even with >16KB responses!)
processes, err := conn.GetProcessList()
```

## Why Use This?

### The 16KB Problem

When using direct USB connections, iOS has a limitation where some services (like `os_trace_relay`) close the connection after sending exactly 16KB (one TLS record). This makes it impossible to retrieve process lists or logs when the response exceeds this size.

### The Solution

PyMobileDevice3's tunnel connection uses a different protocol path (`.shim.remote` services) that doesn't have this limitation. By routing through the tunnel, you can:

- Get complete process lists (even with 300+ processes)
- Stream logs without interruption
- Access all services reliably

## Technical Details

The tunnel provides access to services with `.shim.remote` suffix:
- `com.apple.os_trace_relay` → `com.apple.os_trace_relay.shim.remote`
- `com.apple.syslog_relay` → `com.apple.syslog_relay.shim.remote`
- etc.

Each device gets a unique IPv6 address and port through the tunnel, and the integration handles all the connection details automatically.

## Design Patterns

This integration follows go-ios design patterns:

1. **Service Pattern**: The `GetDeviceWithPyMobileTunnel()` function returns a standard `DeviceEntry` that works with all existing services
2. **Error Handling**: All errors include context and follow the `fmt.Errorf("function: %w", err)` pattern
3. **Connection Abstraction**: Once connected, the device behaves identically to regular connections
4. **Logging**: Uses `logrus` for consistent logging across the project
5. **Constants**: Default ports and service names are defined as constants

## Comparison

| Feature | Direct USB | PyMobile Tunnel |
|---------|------------|-----------------|
| Process list >16KB | ❌ Fails | ✅ Works |
| Connection type | USB/Network | IPv6 Tunnel |
| Service names | Standard | .shim.remote |
| iOS 17+ support | Limited | Full |
| Setup required | None | Tunnel daemon |

## Integration Architecture

The pymobiledevice3 tunnel integration is designed as a drop-in alternative to regular device connections:

```
Application Code
    ↓
ios.GetDevice() / ios.GetDeviceWithPyMobileTunnel()
    ↓
DeviceEntry (with RSD support)
    ↓
Service.New(device) - Works with any service
    ↓
Service-specific operations
```

This means any service that supports RSD/tunnel connections will automatically work with pymobiledevice3's tunnel.
