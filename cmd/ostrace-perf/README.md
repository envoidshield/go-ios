# ostrace-perf

High-performance iOS system log streaming tool with zero-copy parsing, object pooling, and advanced filtering capabilities.

## Overview

`ostrace-perf` is an optimized version of the iOS system log streaming tool designed for high-throughput log processing. It features:

- **Zero-copy parsing** for minimal memory allocations
- **Object pooling** to reduce garbage collection overhead
- **Fast JSON encoding** with jsoniter
- **Backend PID filtering** for device-side filtering (reduces bandwidth)
- **Advanced client-side filtering** with YAML configuration
- **Multi-worker processing** for parallel log handling

### When to use ostrace-perf vs regular ostrace

- **Use ostrace-perf** for: High-volume log processing, production monitoring, IoT deployments, performance-critical applications
- **Use regular ostrace** for: Simple debugging, low-volume logs, development testing

## Installation

### Download pre-built binaries

Download the latest binaries from GitHub Actions:
```bash
# Example for macOS ARM64
wget https://github.com/envoidshield/go-ios/releases/download/latest/ostrace-perf-darwin-arm64
chmod +x ostrace-perf-darwin-arm64
```

### Build from source

```bash
git clone https://github.com/envoidshield/go-ios.git
cd go-ios
go build -tags perf -ldflags="-s -w" -o ostrace-perf ./cmd/ostrace-perf
```

## Basic Usage

### Stream all logs via pymobiledevice3 tunnel

```bash
ostrace-perf -pymobile-tunnel 49151 -json
```

### Stream all logs via RSD connection

```bash
ostrace-perf -rsd-host fd7e:6d7a:ebfb::1 -rsd-port 49536 -udid 00008112-000869810A83A01E -json
```

### Filter by process name (backend filtering)

```bash
ostrace-perf -pymobile-tunnel 49151 -process SpringBoard -json
```

### Filter by PID (kernel = 0)

```bash
ostrace-perf -pymobile-tunnel 49151 -pid 0 -json
```

### List available processes

```bash
ostrace-perf -pymobile-tunnel 49151 -list
```

## Command-line Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-pymobile-tunnel` | int | 0 | Port for pymobiledevice3 tunnel (e.g., 49151) |
| `-rsd-host` | string | "" | RSD host address (e.g., IPv6 address) |
| `-rsd-port` | int | 58783 | RSD port (default 58783) |
| `-udid` | string | "" | Device UDID (optional, auto-selects if only one device) |
| `-pid` | int | -1 | Backend PID filter (device-side filtering for performance) |
| `-process` | string | "" | Process name filter (looks up PID, then applies backend filter) |
| `-json` | bool | false | Output as JSON format |
| `-filter` | string | "" | Inline client-side content filter (simple substring match on message) |
| `-filter-config` | string | "" | YAML config file for advanced client-side filtering |
| `-list` | bool | false | List available processes and exit |
| `-workers` | int | NumCPU() | Number of worker goroutines for parallel processing |
| `-buffer` | int | 1000 | Log entry buffer size |
| `-stats` | bool | false | Show performance statistics |
| `-h` | bool | false | Show help |

## Filtering Guide

ostrace-perf supports two types of filtering:

1. **Backend filtering** (`-pid`, `-process`): Device-side filtering that reduces bandwidth
2. **Client-side filtering** (`-filter`, `-filter-config`): Post-processing filtering for complex logic

### Inline Filtering (`-filter`)

Simple substring match on the message field:

```bash
# Filter for microphone-related logs
ostrace-perf -pymobile-tunnel 49151 -filter "Microphone" -json

# Filter for keyboard events
ostrace-perf -pymobile-tunnel 49151 -filter "keyboard" -json
```

### YAML Config Filtering (`-filter-config`)

Advanced multi-field filtering with logical operators.

#### Available Fields

- `message` - The log message content
- `pid` - Numeric process ID
- `level` - Log level (info, debug, error, warning, etc.)
- `image_name` - Process/binary name (e.g., SpringBoard, bluetoothd)
- `filename` - Source file name
- `category` - Log category
- `subsystem` - Subsystem identifier (e.g., com.apple.bluetooth)

#### Operators

- `CONTAINS` - Field contains substring
- `EQUALS` - Field equals exact value
- `NOT_CONTAINS` - Field does not contain substring
- `STARTS_WITH` - Field starts with substring
- `ENDS_WITH` - Field ends with substring
- `REGEX` - Field matches regular expression

#### Logical Operations

- `AND` - All child filters must match
- `OR` - Any child filter must match
- `NOT` - Child filter must not match

#### Example Configurations

**Example 1: Simple field filter** (`bluetooth.yaml`)
```yaml
filters:
  - field: subsystem
    operator: EQUALS
    value: com.apple.bluetooth
```

**Example 2: Multiple conditions with AND** (`microphone-activated.yaml`)
```yaml
filters:
  - type: AND
    children:
      - field: message
        operator: CONTAINS
        value: Microphone
      - field: message
        operator: CONTAINS
        value: Activated
```

**Example 3: OR with NOT** (`microphone-complex.yaml`)
```yaml
filters:
  - type: OR
    children:
      - type: AND
        children:
          - field: message
            operator: CONTAINS
            value: Microphone
          - field: message
            operator: CONTAINS
            value: Activated
      - type: AND
        children:
          - field: message
            operator: CONTAINS
            value: Microphone
          - type: NOT
            children:
              - field: message
                operator: CONTAINS
                value: Disabled
```

**Example 4: Multi-field filters** (`system-errors.yaml`)
```yaml
filters:
  - type: AND
    children:
      - field: subsystem
        operator: STARTS_WITH
        value: com.apple.
      - field: level
        operator: EQUALS
        value: error
      - field: category
        operator: CONTAINS
        value: Network
```

**Usage:**
```bash
ostrace-perf -pymobile-tunnel 49151 -filter-config bluetooth.yaml -json
```

## Examples

### Stream kernel logs only
```bash
ostrace-perf -pymobile-tunnel 49151 -pid 0 -json
```

### Stream kernel logs via RSD
```bash
ostrace-perf -rsd-host fd7e:6d7a:ebfb::1 -rsd-port 49536 -udid 00008112-000869810A83A01E -pid 0 -json
```

### Monitor SpringBoard with inline filtering
```bash
ostrace-perf -pymobile-tunnel 49151 -process SpringBoard -filter "keyboard" -json
```

### Bluetooth subsystem logs with config
```bash
ostrace-perf -pymobile-tunnel 49151 -filter-config examples/filters/bluetooth-errors.yaml -json
```

### Critical errors only
```bash
ostrace-perf -pymobile-tunnel 49151 -filter-config examples/filters/critical-only.yaml -json
```

### High-performance processing with statistics
```bash
ostrace-perf -pymobile-tunnel 49151 -workers 8 -buffer 5000 -stats -json
```

### Combine backend and client-side filtering
```bash
# Backend filter by PID, client-side filter by content
ostrace-perf -pymobile-tunnel 49151 -pid 35 -filter-config examples/filters/springboard-gestures.yaml -json
```

## Performance Tips

### Backend vs Client-side Filtering

- **Use backend filtering** (`-pid`, `-process`) when possible - reduces bandwidth and improves performance
- **Use client-side filtering** (`-filter`, `-filter-config`) for complex logic that can't be done device-side
- **Combine both** for optimal performance: `-pid 35 -filter-config advanced.yaml`

### Tuning Parameters

- **`-workers`**: Set to number of CPU cores for maximum parallelism
- **`-buffer`**: Increase for high-volume logs (1000-10000), decrease for low-memory systems
- **`-stats`**: Enable to monitor performance and tune parameters

### Memory Optimization

- JSON output is optimized with jsoniter for high throughput
- Object pooling reduces garbage collection overhead
- Zero-copy parsing minimizes memory allocations

## Troubleshooting

### "Failed to create connection"
- **For pymobile tunnel**: Ensure pymobiledevice3 tunnel is running, verify tunnel port with `pymobiledevice3 remote tunneld`
- **For RSD**: Verify RSD host and port are correct, check device network connectivity
- **For regular connection**: Check device USB connection

### "Device not found" with RSD
- Verify the UDID matches exactly (case-sensitive)
- Check if the device is connected via USB vs network tunnel
- For USB devices, use regular connection instead of RSD

### "Process not found: SpringBoard"
- Process may not be running
- Use `-list` to see available processes
- Use `-pid` directly if you know the PID

### Logs stop streaming
- Device may have disconnected from tunnel
- Restart pymobiledevice3 tunnel
- Check device USB connection

### No output with filters
- Filters may be too restrictive
- Test without filters first: `ostrace-perf -pymobile-tunnel 49151 -json`
- Check filter syntax in YAML config
- Use `-stats` to verify logs are being processed

### Performance issues
- Increase `-workers` for more parallelism
- Increase `-buffer` for high-volume logs
- Use backend filtering (`-pid`, `-process`) to reduce bandwidth
- Monitor with `-stats` to identify bottlenecks

## JSON Output Format

```json
{
  "timestamp": "2025-10-17T19:58:32.343435+03:00",
  "pid": 35,
  "level": "debug",
  "image_name": "/System/Library/Frameworks/CoreMotion.framework/CoreMotion",
  "message": "Ping timer fired, resetting watchdog",
  "filename": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
  "category": "Motion",
  "subsystem": "com.apple.locationd.Motion"
}
```

## See Also

- [`ios/ostrace/FILTERING.md`](../../ios/ostrace/FILTERING.md) - Detailed filtering documentation
- [`examples/filters/`](../../examples/filters/) - Sample filter configurations
- [`cmd/ostrace-multi/`](../ostrace-multi/) - IoT multi-stream version for multiple devices
- [`cmd/ostrace/`](../ostrace/) - Standard ostrace for simple use cases

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
