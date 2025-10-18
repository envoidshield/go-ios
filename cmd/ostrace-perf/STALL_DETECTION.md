# Connection Stall Detection Methods

This document describes the multiple methods implemented to detect when the ostrace connection stops providing logs without throwing exceptions.

## Problem

In some scenarios, the iOS device may stop sending logs without closing the connection or raising any errors. The process remains idle, blocking indefinitely on `io.ReadFull()` calls, with no indication that something is wrong.

## Implemented Solutions

We've implemented **multiple complementary approaches** based on industry best practices and Go-specific patterns:

### 1. **Read Timeout with SetReadDeadline** (Most Direct)

**How it works:**
- Uses Go's `net.Conn.SetReadDeadline()` to set a deadline on the underlying network connection
- If no data arrives within the timeout, `io.ReadFull()` returns a timeout error
- This is the most direct way to prevent indefinite blocking in Go

**Usage:**
```bash
./ostrace-perf --read-timeout 30
```

**Advantages:**
- Built into Go's networking stack
- No overhead - handled at the OS level
- Immediate detection when timeout expires
- Works at the lowest level (prevents actual blocking)

**When to use:**
- When you want guaranteed timeout behavior
- For production systems that must never hang
- When running in automated/unattended environments

### 2. **Watchdog Timer** (Application Level)

**How it works:**
- Tracks the time since the last successfully received log entry
- A separate goroutine checks this timestamp every second
- If no logs received for N seconds, exits gracefully
- Provides warnings at 80% of timeout threshold

**Usage:**
```bash
./ostrace-perf --watchdog 30
```

**Advantages:**
- Works even if read timeout isn't set
- Can track application-level activity (not just network activity)
- Provides early warning before timeout
- Shows time since last log in stats

**When to use:**
- When you want to detect "no logs" vs "connection stalled"
- For monitoring and alerting
- When you need graceful shutdown on inactivity

### 3. **Diagnostic Mode** (Troubleshooting)

**How it works:**
- Enables detailed logging of connection state
- Logs every 10 seconds showing:
  - Total logs processed
  - Number of consecutive errors
  - Buffer state
  - Recovery events

**Usage:**
```bash
./ostrace-perf --diagnostics
```

**Advantages:**
- Helps identify patterns before complete stall
- Tracks error recovery
- Shows buffer overflow issues
- Useful for debugging intermittent problems

**When to use:**
- During development and testing
- When investigating reported stalls
- For long-running monitoring to identify patterns

### 4. **Consecutive Error Detection**

**How it works:**
- Counts consecutive read errors
- Exits after 100 consecutive errors
- Logs each error with count
- Resets counter on successful read

**Advantages:**
- Catches degrading connections
- Prevents infinite error loops
- Automatic recovery detection

**When to use:**
- Always enabled (no flag needed)
- Provides safety net for unexpected error conditions

### 5. **Timeout Error Detection**

**How it works:**
- Specifically detects `net.Error` with `Timeout() == true`
- Provides clear error message about stalled connection
- Distinguishes timeout from other errors

**Advantages:**
- Clear error reporting
- Helps with troubleshooting
- Integrates with read timeout feature

## Comparison with Alternative Approaches

Based on research of industry best practices, here are other methods we considered:

### Not Implemented (But Possible)

1. **Thread/Goroutine Stack Traces (SIGQUIT)**
   - **How:** Send `SIGQUIT` to get goroutine dumps
   - **Why not:** Requires external intervention, doesn't auto-recover
   - **When useful:** Manual debugging of hung processes

2. **Runtime Profiling (pprof)**
   - **How:** HTTP endpoint serving `/debug/pprof/goroutine`
   - **Why not:** Requires external monitoring, adds complexity
   - **When useful:** Analyzing production issues post-mortem

3. **System Resource Monitoring**
   - **How:** Monitor CPU/memory usage patterns
   - **Why not:** Requires external tools, indirect detection
   - **When useful:** System-wide monitoring dashboards

4. **Protocol-Level Heartbeat**
   - **How:** Device sends periodic keepalive messages
   - **Why not:** Requires device support, not in os_trace protocol
   - **When useful:** If Apple adds it to the protocol

## Recommended Configuration

### For Production/Automated Systems
```bash
./ostrace-perf --read-timeout 30 --watchdog 60 --stats
```
- Read timeout: Prevents indefinite blocking
- Watchdog: Detects no-log scenarios
- Stats: Monitor health

### For Development/Testing
```bash
./ostrace-perf --diagnostics --watchdog 30 --stats
```
- Diagnostics: Detailed logging
- Watchdog: Safety net
- Stats: Performance monitoring

### For Maximum Reliability
```bash
./ostrace-perf --read-timeout 20 --watchdog 30 --diagnostics --stats
```
- All features enabled
- Read timeout shorter than watchdog (catches blocking first)
- Full visibility into connection state

## How They Work Together

```
Time: 0s
├─ Connection established
├─ Read timeout: 20s deadline set
├─ Watchdog: Started, last log = now
└─ Diagnostics: Logging enabled

Time: 10s
├─ Diagnostics: "[DIAG] Reading logs... Total: 1000"
└─ Stats: "200 logs/sec, 0.5 MB/sec"

Time: 16s (80% of watchdog)
└─ Watchdog: "Warning: No logs for 16s (timeout in 14s)"

Time: 20s
├─ Read timeout: io.ReadFull returns timeout error
├─ Main loop: Detects timeout error
├─ Main loop: "Error: Read timeout after 20s - connection stalled"
└─ Process exits cleanly

Alternative: If read timeout not set
Time: 30s
├─ Watchdog: Timeout reached
├─ Watchdog: Closes watchdogChan
├─ Main: "Watchdog timeout: No logs for 30s"
└─ Process exits cleanly
```

## Error Messages Guide

| Message | Cause | Solution |
|---------|-------|----------|
| `Read timeout after Xs - connection stalled` | No data from device for X seconds | Check device connection, USB cable, or increase timeout |
| `Watchdog timeout: No logs for Xs` | Device not generating logs | Check if device is active, app running, or filters too restrictive |
| `Too many consecutive errors (100)` | Persistent read failures | Check device connection, restart device/service |
| `Connection closed (EOF)` | Device disconnected cleanly | Normal when device unplugged or service stopped |
| `Warning: No logs for Xs (timeout in Ys)` | Approaching watchdog timeout | Early warning - logs may resume |

## Performance Impact

| Feature | CPU Impact | Memory Impact | Latency Impact |
|---------|------------|---------------|----------------|
| Read Timeout | None (OS-level) | None | None |
| Watchdog | Minimal (1 check/sec) | ~100 bytes | None |
| Diagnostics | Low (1 log/10sec) | ~1KB/log | None |
| Error Counting | None | ~8 bytes | None |

## Implementation Details

### Read Timeout Architecture

```go
// 1. Connection stores timeout duration
type Connection struct {
    readTimeout time.Duration
}

// 2. Before each read, deadline is updated
func (c *Connection) updateReadDeadline() error {
    deadline := time.Now().Add(c.readTimeout)
    return conn.SetReadDeadline(deadline)
}

// 3. ReadStreamChunk uses deadline
chunkBytes, err := c.codec.ReadStreamChunkWithDeadline(
    c.deviceConn.Reader(), 
    c.updateReadDeadline,
)
```

### Watchdog Architecture

```go
// 1. Track last log time
lastLogReceived.Store(time.Now())

// 2. Monitor in separate goroutine
func watchdogMonitor(timeoutChan chan<- struct{}) {
    for range time.Tick(1 * time.Second) {
        if time.Since(lastLog) >= timeout {
            close(timeoutChan) // Signal main
            return
        }
    }
}

// 3. Main loop waits on multiple channels
select {
case <-sigChan:        // User interrupt
case <-readErrorChan:  // Read error
case <-watchdogChan:   // Watchdog timeout
}
```

## Testing Stall Detection

### Simulate Connection Stall

1. **Using network tools:**
   ```bash
   # Start ostrace-perf
   ./ostrace-perf --read-timeout 10 --watchdog 15 --diagnostics
   
   # In another terminal, suspend the device connection
   # (This simulates a stalled connection)
   ```

2. **Using filters:**
   ```bash
   # Use very restrictive filter that matches nothing
   ./ostrace-perf --filter "IMPOSSIBLE_STRING_MATCH" --watchdog 10
   ```

3. **Expected behavior:**
   - With read-timeout: Exits after timeout with clear message
   - With watchdog: Exits after watchdog period
   - With diagnostics: Shows periodic status updates

## Troubleshooting

### "Process hangs indefinitely"
- ✅ Add `--read-timeout 30`
- ✅ Add `--watchdog 60` as backup
- ✅ Enable `--diagnostics` to see what's happening

### "False positives - exits when device is just quiet"
- ⚙️ Increase `--watchdog` value
- ⚙️ Remove `--read-timeout` (only use watchdog)
- ⚙️ Check if filters are too restrictive

### "Want to know connection is alive even when no matching logs"
- ✅ Use `--ping-interval 5` to get periodic pings
- ✅ Combine with `--watchdog` for safety

## References

- [Go net.Conn SetReadDeadline](https://pkg.go.dev/net#Conn)
- [io.ReadFull behavior](https://pkg.go.dev/io#ReadFull)
- [Detecting Hanging Processes (Apache)](https://chestofbooks.com/computers/webservers/apache/Stas-Bekman/Practical-mod_perl/21-7-3-Detecting-Hanging-Processes.html)
- [Linux Watchdog Documentation](https://lyz-code.github.io/blue-book/watchdog/)

