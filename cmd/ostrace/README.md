# ostrace - iOS Advanced Logging CLI Tool

`ostrace` is a command-line tool for advanced iOS system logging using the `com.apple.os_trace_relay` service.

## Features

- List all running processes with their PIDs
- Stream system logs in real-time
- Filter logs by process ID or process name
- Filter by log level (errors only, debug, info)
- Download archived diagnostic logs
- Works with both USB and network (iOS 17+) connections

## Installation

```bash
cd cmd/ostrace
go build
```

Or from the project root:

```bash
make ostrace  # if Makefile target exists
```

## Usage

### List All Running Processes

```bash
./ostrace -list
```

Output:
```
Process Name                                       PID
------------------------------------------------------------
SpringBoard                                        123
backboardd                                         456
...
```

### Stream All Logs

```bash
./ostrace
```

### Stream Logs from Specific Process (by PID)

```bash
./ostrace -pid 123
```

### Stream Logs from Specific Process (by name)

```bash
./ostrace -process SpringBoard
```

### Show Only Errors

```bash
./ostrace -errors-only
```

### Include Debug Logs

```bash
./ostrace -debug
```

### Download Archived Logs

```bash
./ostrace -archive
```

Or specify a custom filename:

```bash
./ostrace -archive -archive-file my_logs.pax
```

The downloaded file is in PAX format. Extract with:

```bash
# Using pax
pax -r < my_logs.pax

# Or using tar
tar -xf my_logs.pax
```

### Specify Device by UDID

```bash
./ostrace -udid 00008030-XXXXXXXXXXXXX -list
```

### Verbose Output

```bash
./ostrace -v
```

## Command-Line Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-udid` | string | "" | Device UDID (uses first device if empty) |
| `-pid` | int | 0 | Filter logs by process ID (0 = no filter) |
| `-process` | string | "" | Filter logs by process name |
| `-errors-only` | bool | false | Show only error and fault logs |
| `-debug` | bool | false | Include debug level logs |
| `-info` | bool | true | Include info level logs |
| `-list` | bool | false | List running processes and exit |
| `-archive` | bool | false | Download archived logs to file |
| `-archive-file` | string | "device_logs.pax" | Archive file name |
| `-v` | bool | false | Verbose logging |

## Examples

### Example 1: Monitor All System Logs

```bash
./ostrace
```

Press `Ctrl+C` to stop.

### Example 2: Debug a Specific App

First, find the app's PID:

```bash
./ostrace -list | grep MyApp
```

Output:
```
MyApp                                              1234
```

Then stream its logs:

```bash
./ostrace -pid 1234 -debug
```

Or directly by name:

```bash
./ostrace -process MyApp -debug
```

### Example 3: Monitor System Errors

```bash
./ostrace -errors-only
```

### Example 4: Collect Diagnostic Archive

```bash
./ostrace -archive -archive-file diagnostics_$(date +%Y%m%d).pax
```

Then extract:

```bash
tar -xf diagnostics_20240115.pax
```

The extracted files will be from `/var/db/diagnostics` on the device.

### Example 5: Monitor SpringBoard (Home Screen)

```bash
./ostrace -process SpringBoard -debug
```

This is useful for debugging UI issues, app launches, etc.

### Example 6: Monitor with Verbose Output

```bash
./ostrace -v -process backboardd
```

Shows additional debug information about the connection and data flow.

## Output Format

Logs are displayed in the following format:

```
[timestamp] [level] [PID] [subsystem/category] message
```

Example:
```
[2024-01-15 10:30:45.123] [error] [123] [com.apple.UIKit/Views] Failed to load view
[2024-01-15 10:30:45.456] [info] [456] [com.apple.system/network] Connected to WiFi
```

## Log Levels

- `default` - Default level messages
- `info` - Informational messages
- `debug` - Debug messages (verbose)
- `error` - Error messages
- `fault` - Critical faults

## Integration with Other Tools

### Save to File

```bash
./ostrace > logs.txt
```

### Filter with grep

```bash
./ostrace | grep error
```

### Watch for Specific Pattern

```bash
./ostrace -process MyApp | grep -i "network"
```

### JSON Processing

The tool outputs human-readable format by default. For programmatic use, consider using the Go API directly.

## Comparison with Apple's log Tool

On macOS, you might use:
```bash
log stream --predicate 'process == "MyApp"'
```

With ostrace on iOS:
```bash
./ostrace -process MyApp
```

Benefits of ostrace:
- Works on Linux and Windows (not just macOS)
- Direct device connection (no Mac required)
- Faster and lighter weight
- Archive download capability

## Troubleshooting

### "No device connected"

Make sure your iOS device is:
1. Connected via USB or network
2. Trusted (check device screen for trust prompt)
3. Visible to `ios-deploy --detect` or similar tools

### "Failed to create ostrace connection"

This service requires:
- iOS 10 or later
- Developer mode enabled (iOS 16+)
- Device paired and trusted

### No Logs Appearing

- Try with `-debug` flag to see all log levels
- Make sure the process is actually running (use `-list`)
- Some system processes may have restricted logging

### Archive Download is Slow

Diagnostic archives can be large (hundreds of MB). Be patient and watch the progress indicator.

## Advanced Usage

### Monitor Multiple Processes

You can run multiple instances in different terminals:

```bash
# Terminal 1
./ostrace -process SpringBoard > springboard.log

# Terminal 2
./ostrace -process backboardd > backboardd.log
```

### Continuous Monitoring

```bash
while true; do
    ./ostrace -errors-only >> system_errors.log
    sleep 1
done
```

### Extract Specific Files from Archive

```bash
./ostrace -archive -archive-file diag.pax
tar -xf diag.pax --wildcards "*.ips"  # Extract only crash reports
```

## License

Part of the go-ios project. See LICENSE in the project root.

## See Also

- [ostrace Package Documentation](../../ios/ostrace/README.md)
- [ostrace vs pymobiledevice3 Comparison](../../ios/ostrace/COMPARISON.md)
- [go-ios Main Documentation](../../README.md)

