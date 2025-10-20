# Stdout/Stderr Blocking Analysis

## Can stdout/stderr blocking delay socket operations?

**Short answer:** Yes, but **indirectly**. The blocking happens in **different goroutines**, but they can interact in problematic ways.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│ Main Goroutine (setup)                                      │
└─────────────────────────────────────────────────────────────┘
                           │
                           ├── spawns ──┐
                           │             │
       ┌───────────────────┴────┐       │
       │ Reader Goroutine       │       │
       │ (line 291-358)         │       │
       │                        │       │
       │ while true:            │       │
       │   entry ← socket       │◄──────┼── SOCKET READ
       │   entryChan ← entry    │       │
       │   [stderr writes]──────┼───────┼── STDERR (can block)
       └────────────────────────┘       │
                │                        │
                │ entryChan              │
                ▼                        │
       ┌────────────────────┐           │
       │ Worker Goroutines  │◄──────────┼── spawns
       │ (N instances)      │           │
       │ (line 392-446)     │           │
       │                    │           │
       │ for entry in chan: │           │
       │   format entry     │           │
       │   outputBuffer ←───┼───────────┼── STDOUT (can block on flush)
       └────────────────────┘           │
                                        │
       ┌────────────────────┐           │
       │ Output Flusher     │◄──────────┘
       │ (line 470-479)     │
       │                    │
       │ every 100ms:       │
       │   flush stdout─────┼── STDOUT (can block)
       └────────────────────┘
```

## Blocking Scenarios

### Scenario 1: Stderr Blocks in Reader Goroutine (CRITICAL)

**Lines 298-299, 308, 315, 321:**
```go
// In the main reading loop
fmt.Fprintf(os.Stderr, "[DIAG] Reading logs... Total processed: %d, Errors: %d\n", ...)
```

**Problem:**
- Reader goroutine writes to stderr **synchronously**
- If Python parent isn't reading stderr, the pipe buffer fills (~65KB)
- `fmt.Fprintf(os.Stderr, ...)` **blocks indefinitely**
- While blocked on stderr, **socket read stops** (same goroutine)
- Device keeps sending data → TCP receive buffer fills
- Eventually triggers TCP flow control → device slows/stops sending
- Connection appears "stalled"

**Impact:**
```
Time 0:    Reader: socket.Read() → success
Time 1:    Reader: fmt.Fprintf(stderr) → blocks (pipe full)
Time 2-∞:  Reader: BLOCKED on stderr, can't read from socket
           Socket: receive buffer fills
           Device: TCP window closes, stops sending
```

**Current Frequency:**
- Every 10 seconds if `--diagnostics` enabled (line 297)
- On every error (line 308, 315, 321, 325, 336)
- If device is noisy/flaky, can be **hundreds per second**

### Scenario 2: Stdout Blocks in Worker Goroutine (LESS CRITICAL)

**Lines 437-439:**
```go
outputMutex.Lock()
outputBuffer.Write(localBuf)
outputMutex.Unlock()
```

**Problem:**
- Worker writes to buffered stdout (64KB buffer)
- Buffer flushes every 100ms (line 473)
- If Python isn't reading stdout, flush blocks
- `outputBuffer.Flush()` holds `outputMutex` while blocked
- Other workers waiting for mutex accumulate
- `entryChan` fills up (default 1000 entries)
- Reader starts dropping logs (line 352-355)

**But:** Reader goroutine continues reading from socket!

**Impact:**
```
Time 0:    Flusher: outputBuffer.Flush() → blocks (pipe full)
           Flusher: holds outputMutex
Time 1:    Worker: outputMutex.Lock() → waits
Time 2:    Reader: entryChan ← entry → success (for now)
Time 3:    entryChan fills (1000 entries)
Time 4:    Reader: drops logs, BUT keeps reading from socket
```

**Socket is NOT affected** - reader continues consuming data.

### Scenario 3: Cascading Failure

**Worst case combination:**
1. Stdout buffer full → workers blocked on mutex
2. `entryChan` fills → reader starts dropping logs
3. Reader writes diagnostic to stderr (line 353)
4. **Stderr also full** → reader blocks on stderr
5. **Now socket read stops!**

## Evidence from Code

### Critical stderr writes in Reader Goroutine:

```go
// Line 298-300: Every 10 seconds if diagnostics enabled
if *diagnostics && time.Since(lastDiagnostic) >= 10*time.Second {
    fmt.Fprintf(os.Stderr, "[DIAG] Reading logs... Total processed: %d, Errors: %d\n", 
        atomic.LoadUint64(&logsProcessed), consecutiveErrors)
    lastDiagnostic = time.Now()
}

// Line 308: On EOF (rare)
fmt.Fprintf(os.Stderr, "[DIAG] Connection closed (EOF) after %d consecutive errors\n", consecutiveErrors)

// Line 315: On timeout (rare)
fmt.Fprintf(os.Stderr, "Error: Read timeout after %v - connection appears stalled\n", time.Duration(*readTimeoutSeconds)*time.Second)

// Line 321: ON EVERY ERROR (DANGEROUS!)
fmt.Fprintf(os.Stderr, "Warning: Failed to read log entry (error #%d): %v\n", consecutiveErrors, err)

// Line 325: After 100 errors (rare)
fmt.Fprintf(os.Stderr, "Error: Too many consecutive read errors (%d), giving up\n", consecutiveErrors)

// Line 336: On recovery from errors (if diagnostics)
if *diagnostics {
    fmt.Fprintf(os.Stderr, "[DIAG] Recovered after %d errors\n", consecutiveErrors)
}

// Line 353: When dropping logs (if diagnostics)
if *diagnostics {
    fmt.Fprintf(os.Stderr, "[DIAG] Warning: Buffer full, dropping log entry\n")
}
```

**Most dangerous:** Line 321 runs **on every read error**.

If device/connection is flaky:
- 100 errors × stderr write = 100 blocking opportunities
- Each block stops socket reading for duration of block

## Solutions

### Solution 1: Make stderr writes non-blocking (RECOMMENDED)

**Replace synchronous stderr with async channel:**

```go
// Global
var stderrChan = make(chan string, 100)  // Buffered channel

func init() {
    go func() {
        for msg := range stderrChan {
            fmt.Fprint(os.Stderr, msg)
        }
    }()
}

// In reader goroutine, replace:
fmt.Fprintf(os.Stderr, "Warning: Failed to read log entry (error #%d): %v\n", consecutiveErrors, err)

// With:
select {
case stderrChan <- fmt.Sprintf("Warning: Failed to read log entry (error #%d): %v\n", consecutiveErrors, err):
default:
    // Drop stderr message if channel full - CRITICAL PATH CANNOT BLOCK
}
```

**Pros:**
- Reader never blocks on stderr
- Socket reads continue uninterrupted
- Stderr messages may drop, but that's better than stalling

**Cons:**
- Adds complexity
- Can lose error messages

### Solution 2: Remove stderr from critical path

**Only write to stderr outside the read loop:**

```go
// Instead of logging errors immediately, count them
var recentErrors atomic.Uint64

// In reader:
if err != nil {
    recentErrors.Add(1)
    // NO stderr write here!
    continue
}

// Separate goroutine reports errors periodically:
go func() {
    ticker := time.NewTicker(5 * time.Second)
    for range ticker.C {
        errCount := recentErrors.Swap(0)
        if errCount > 0 {
            fmt.Fprintf(os.Stderr, "Errors in last 5s: %d\n", errCount)
        }
    }
}()
```

**Pros:**
- Simple
- No blocking in critical path
- Still get error visibility

**Cons:**
- Delayed error reporting
- Less detailed error information

### Solution 3: Rate limit stderr writes

```go
var lastStderrWrite time.Time
var stderrMutex sync.Mutex

func tryStderrWrite(format string, args ...interface{}) {
    stderrMutex.Lock()
    defer stderrMutex.Unlock()
    
    // Only write if at least 1 second since last write
    if time.Since(lastStderrWrite) < time.Second {
        return  // Drop message
    }
    
    fmt.Fprintf(os.Stderr, format, args...)
    lastStderrWrite = time.Now()
}
```

**Pros:**
- Reduces frequency of blocking
- Still get some error visibility

**Cons:**
- Still can block (just less often)
- May miss important errors

### Solution 4: Use SetDeadline on stderr (if possible)

**Attempt to set write deadline on stderr pipe:**

```go
// At startup
if f, ok := os.Stderr.(*os.File); ok {
    if err := f.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err == nil {
        // Supported! Stderr writes will timeout after 100ms
    }
}
```

**Pros:**
- Prevents indefinite blocking
- Keeps synchronous writes

**Cons:**
- May not work on all platforms
- Pipe writes don't always support deadlines

## Testing Strategy

### Test 1: Reproduce stderr blocking

```python
# supervisor.py
import subprocess
import time

# Start binary but DON'T read stderr
proc = subprocess.Popen(
    ['./ostrace-perf', '--diagnostics', '--rsd-host', 'fd9b:76af:2cf::1', '--udid', 'XXX'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE  # Created but not read
)

# Read stdout continuously
while True:
    line = proc.stdout.readline()
    if not line:
        break
    # Process stdout
    
# After 65KB of stderr, binary should block
```

### Test 2: Verify socket continues with async stderr

```bash
# Monitor socket activity while stderr is blocked
watch -n 1 'netstat -an | grep <port>'

# Socket should show continuous data transfer even if stderr blocked
```

## Recommendations

### Immediate (Phase 1):
1. **Remove stderr writes from error loop** (line 321) - only log every 10th error
2. **Add rate limiting** to diagnostic messages
3. **Test with stderr blocked** to confirm socket impact

### Short-term (Phase 2):
1. **Implement async stderr channel** for all reader goroutine messages
2. **Keep only critical errors** on stderr (EOF, fatal errors)
3. **Move verbose diagnostics to optional log file**

### Long-term (Phase 3):
1. **Structured logging** (JSON logs to file, minimal stderr)
2. **Metrics endpoint** instead of stderr spam
3. **Separate health monitoring** goroutine

## Current Risk Assessment

**High Risk (stderr in reader):**
- Line 321: Error logging in tight loop
- Line 353: Buffer full warning (if diagnostics)
- Line 298: Periodic diagnostics (every 10s)

**Low Risk (stdout in workers):**
- Buffered + separate goroutines
- Reader can continue even if workers blocked

**Mitigation Priority:**
1. **Fix line 321 immediately** - rate limit error logging
2. Make all reader stderr writes non-blocking
3. Test with blocked pipes to verify

## Conclusion

**Yes, stderr blocking CAN delay socket operations**, specifically when:
1. Reader goroutine writes to stderr
2. Stderr pipe is full (Python not reading)
3. Write blocks indefinitely
4. Same goroutine can't read from socket

**Current code is vulnerable** especially at line 321 (error logging in tight loop).

**Recommended fix:** Make all stderr writes in reader goroutine non-blocking or remove them entirely.

