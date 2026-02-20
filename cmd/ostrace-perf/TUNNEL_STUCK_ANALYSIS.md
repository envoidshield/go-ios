# Tunnel Stuck Analysis

## Problem Statement

The tunnel becomes fully stuck and unable to make any more connections. This is new behavior not seen in pymobiledevice3.

## Root Cause Analysis

### 1. Connection Lifecycle Issues

**Current Flow:**
```
ostrace-perf spawn
  ↓
NewWithAddrPort(rsdHost, 58783)  // TCP connection #1 to port 58783
  ↓
HandshakeWithTimeout()           // Use connection #1
  ↓
defer rsdService.Close()         // Close connection #1
  ↓
ostrace.New(device)              // TCP connection #2 to port N (os_trace service)
  ↓
[Binary runs]
  ↓
SIGKILL (from supervisor)        // defer DOES NOT RUN
  ↓
Connection #2 left in ESTABLISHED/CLOSE_WAIT state on device
```

**Key Issues:**
1. **SIGKILL doesn't trigger defer**: When Python supervisor kills with SIGKILL, Go's `defer conn.Close()` never runs
2. **Each crash leaks a TCP socket** on the device side
3. **iOS has per-service connection limits**: Typically 5-10 connections per service port
4. **Orphaned connections accumulate** until limit is reached
5. **Tunnel becomes unable to accept new connections**

### 2. Evidence from Code

**In `cmd/ostrace-perf/main.go`:**
```go
// Line 169-174
conn, err := ostrace.New(device)
if err != nil {
    fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
    os.Exit(1)
}
defer conn.Close()  // ← This NEVER runs on SIGKILL
```

**In `ios/connect.go` - `ConnectToShimService`:**
```go
// Line 125-134
conn, err := ConnectTUNDevice(device.Address, port, device)  // New TCP socket
if err != nil {
    return nil, err
}
err = RsdCheckin(conn)
if err != nil {
    _ = conn.Close()
    return nil, err
}
return NewDeviceConnectionWithRWC(conn), nil  // Wraps TCP socket
```

Each call creates a **brand new TCP connection** - no pooling or reuse.

### 3. How Connections Accumulate

**Scenario:** Binary is restarted 10 times (crashes or supervisor kills it)

```
Device perspective (port 54321 - os_trace service):

Attempt 1: [::1]:54321 ← [::1]:50001  ESTABLISHED  (binary killed, socket orphaned)
Attempt 2: [::1]:54321 ← [::1]:50002  ESTABLISHED  (binary killed, socket orphaned)
Attempt 3: [::1]:54321 ← [::1]:50003  ESTABLISHED  (binary killed, socket orphaned)
...
Attempt 10: [::1]:54321 ← [::1]:50010 ESTABLISHED  (binary killed, socket orphaned)
Attempt 11: [::1]:54321 ← REFUSED (limit reached)
```

Device-side sockets stay in ESTABLISHED/CLOSE_WAIT for:
- **2+ hours** (default TCP keepalive timeout)
- **Until device reboot**
- **Until manual cleanup**

### 4. Comparison with pymobiledevice3

**pymobiledevice3 advantages:**
1. **Context managers** (`with` statement) ensure cleanup even on exceptions
2. **Python's signal handlers** can trigger cleanup on SIGTERM
3. **Possible connection pooling/reuse** (need to verify)
4. **Shorter-lived connections** if they reconnect frequently

**go-ios disadvantages:**
1. **SIGKILL bypasses all cleanup** (defer, signal handlers, everything)
2. **No connection pooling** - every `ostrace.New()` = new TCP socket
3. **Long-lived connections** - binary runs until killed
4. **No orphan connection tracking**

## Proposed Solutions

### Solution 1: Use SIGTERM Instead of SIGKILL (Immediate)

**In Python supervisor:**
```python
# Instead of:
process.kill()  # SIGKILL

# Use:
process.terminate()  # SIGTERM
process.wait(timeout=5)
if process.poll() is None:
    process.kill()  # Only SIGKILL after timeout
```

**Pros:**
- Simple change
- Allows Go's defer to run
- Properly closes sockets

**Cons:**
- Doesn't fix hard crashes
- Binary must respond to SIGTERM within timeout

### Solution 2: Add SO_LINGER Socket Option (Recommended)

**In `ios/connect.go` - `connectTUN` and `ConnectTUNDevice`:**
```go
func connectTUN(address string, port int) (*net.TCPConn, error) {
    // ... existing dial code ...
    
    // Force immediate RST on close (don't wait in CLOSE_WAIT)
    err = conn.SetLinger(0)
    if err != nil {
        _ = conn.Close()
        return nil, fmt.Errorf("ConnectToHttp2WithAddr: failed to set linger: %w", err)
    }
    
    // ... rest of code ...
}
```

**Pros:**
- Closes sockets immediately with RST
- Works even on SIGKILL (kernel handles it)
- Prevents CLOSE_WAIT accumulation

**Cons:**
- Abrupt close (may lose data in flight)
- Need to verify iOS handles RST properly

### Solution 3: Add Connection Keepalive Monitoring

**Enhance existing keepalive:**
```go
// Current: KeepAlivePeriod = 1 second
// Add: Detect dead connections faster

conn.SetKeepAlive(true)
conn.SetKeepAlivePeriod(1 * time.Second)

// Linux-specific (need syscall):
// TCP_KEEPIDLE = 10    (start probing after 10s idle)
// TCP_KEEPINTVL = 1    (probe every 1s)
// TCP_KEEPCNT = 3      (close after 3 failed probes)
```

**Pros:**
- Detects stalled connections
- Device will close orphaned sockets faster

**Cons:**
- Platform-specific (Linux, macOS differ)
- Only helps with dead connections, not SIGKILL

### Solution 4: Connection Pool/Registry (Complex)

**Track all active connections:**
```go
var activeConnections sync.Map  // map[*net.TCPConn]time.Time

func registerConnection(conn *net.TCPConn) {
    activeConnections.Store(conn, time.Now())
}

func init() {
    // Background goroutine to cleanup on shutdown signal
    go func() {
        <-shutdownChan
        activeConnections.Range(func(key, value interface{}) bool {
            conn := key.(*net.TCPConn)
            conn.Close()
            return true
        })
    }()
}
```

**Pros:**
- Can cleanup even on crashes (if separate process)
- Can track connection stats

**Cons:**
- Complex implementation
- Doesn't help with SIGKILL (same process)
- Memory overhead

### Solution 5: Add Connection Diagnostics

**Add socket tracking to debug:**
```go
// At connection creation:
fmt.Fprintf(os.Stderr, "[CONN] Opening TCP %s:%d → local port %d\n", 
    device.Address, port, conn.LocalAddr().(*net.TCPAddr).Port)

// At close:
fmt.Fprintf(os.Stderr, "[CONN] Closing TCP local port %d\n",
    conn.LocalAddr().(*net.TCPAddr).Port)
```

**Pros:**
- Helps diagnose issues
- Can correlate with `netstat`/`lsof` output

**Cons:**
- Doesn't fix the problem
- Just diagnostic tool

## Recommended Implementation Plan

### Phase 1: Immediate Fixes (Today)
1. **Change Python supervisor to use SIGTERM** with 5s grace period
2. **Add SO_LINGER(0) to all TCP connections** in `connectTUN` and `ConnectTUNDevice`
3. **Add connection diagnostics** (optional, for debugging)

### Phase 2: Monitoring (This Week)
1. **Add metrics** for connection count
2. **Monitor device-side sockets** with periodic `lsof` or equivalent
3. **Add alerts** for connection limit approaching

### Phase 3: Long-term (If Needed)
1. **Investigate connection pooling** - can we reuse HTTP/2 connections?
2. **Add health checks** - periodic ping to detect dead connections
3. **Implement graceful shutdown** - cleanup before exit

## Testing Strategy

### 1. Reproduce the Issue
```bash
# Spawn binary repeatedly with SIGKILL
for i in {1..20}; do
    ./ostrace-perf --rsd-host fd9b:76af:2cf::1 --rsd-port 58783 --udid XXX &
    PID=$!
    sleep 2
    kill -9 $PID  # SIGKILL
    sleep 1
done

# Check device-side sockets:
# (need device shell access or instrument logs)
```

### 2. Verify SIGTERM Fix
```bash
# Same test with SIGTERM
for i in {1..20}; do
    ./ostrace-perf --rsd-host fd9b:76af:2cf::1 --rsd-port 58783 --udid XXX &
    PID=$!
    sleep 2
    kill -15 $PID  # SIGTERM
    wait $PID
    sleep 1
done
```

### 3. Verify SO_LINGER Fix
```bash
# Monitor sockets during test
watch -n 1 'netstat -an | grep 58783'

# Should see immediate close, not CLOSE_WAIT
```

## Questions for Investigation

1. **How many connections before tunnel stuck?** (5? 10? 20?)
2. **Does pymobiledevice3 reuse connections?** (check their code)
3. **What is iOS's actual connection limit per service?**
4. **Do CLOSE_WAIT sockets count against the limit?**
5. **Can we query device for socket state?** (via diagnostics service?)

## References

- SO_LINGER: https://www.nybek.com/blog/2015/04/29/so_linger-on-non-blocking-sockets/
- TCP Keepalive: https://tldp.org/HOWTO/TCP-Keepalive-HOWTO/overview.html
- Go signal handling: https://gobyexample.com/signals

