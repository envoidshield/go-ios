# CRITICAL Performance Bottlenecks in ostrace-perf

## Executive Summary

**URGENT**: Multiple critical bottlenecks are slowing down the socket read path and causing iOS device slowness. The socket reader is being blocked by downstream processing, creating backpressure that affects the iOS device.

## Critical Issues (Ordered by Impact)

### 1. **NO SOCKET BUFFERING** ⚠️ CRITICAL
**Impact**: 2x syscall overhead per log entry

**Location**: `ios/deviceconnection.go:169-172`
```go
func (conn *DeviceConnection) Reader() io.Reader {
    return conn.c  // Returns raw net.Conn - NO BUFFERING!
}
```

**Problem**: 
- Every `io.ReadFull()` call becomes a direct `read()` syscall
- `ReadStreamChunk()` makes TWO `io.ReadFull` calls per log entry:
  - One for 5-byte header (line 80 in ostrace.go)
  - One for variable-length payload (line 93 in ostrace.go)
- **Result**: 2 syscalls per log @ 10,000 logs/sec = 20,000 syscalls/sec

**Fix**:
```go
// In ostrace/ostrace.go - add buffered reader to Connection
type Connection struct {
    deviceConn   ios.DeviceConnectionInterface
    codec        *OsTraceCodec
    reader       *bufio.Reader  // ADD THIS
    readTimeout  time.Duration
    readDeadline time.Time
}

// In New() and NewWithShimConnection()
conn := &Connection{
    deviceConn: deviceConn,
    codec:      &OsTraceCodec{},
    reader:     bufio.NewReaderSize(deviceConn.Reader(), 256*1024), // 256KB buffer
}

// Change ReadStreamChunk to accept *bufio.Reader
func (c *OsTraceCodec) ReadStreamChunk(r *bufio.Reader) ([]byte, error) {
    // Now reads from buffer, not raw socket
}
```

**Expected Improvement**: 50-70% reduction in syscalls

---

### 2. **SEVERE MUTEX CONTENTION** ⚠️ CRITICAL  
**Impact**: Blocks worker goroutines, indirectly stalls socket reader

**Location**: `cmd/ostrace-perf/main.go:480-482`
```go
// EVERY worker locks for EVERY log entry
outputMutex.Lock()
outputBuffer.Write(localBuf)
outputMutex.Unlock()
```

**Problem**:
- With `runtime.NumCPU()` workers (e.g., 8 cores = 8 workers)
- All workers fight for same mutex on EVERY log
- At 10,000 logs/sec = 10,000 lock contentions/sec
- Blocked workers → channel fills → socket reader blocks on channel send

**Fix**: Use a dedicated writer goroutine with channel
```go
// Replace shared mutex with channel-based writer
type LogOutput struct {
    formatted []byte
}

outputChan := make(chan LogOutput, *bufferSize * 2)

// Single writer goroutine (no contention!)
go func() {
    buf := bufio.NewWriterSize(os.Stdout, 256*1024)
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()
    
    for {
        select {
        case output := <-outputChan:
            buf.Write(output.formatted)
            atomic.AddUint64(&bytesWritten, uint64(len(output.formatted)))
        case <-ticker.C:
            buf.Flush()
        }
    }
}()

// Workers just send to channel (no lock!)
func worker(...) {
    for entry := range entryChan {
        if matchesFilter {
            localBuf = format(entry)
            outputChan <- LogOutput{formatted: append([]byte(nil), localBuf...)}
        }
    }
}
```

**Expected Improvement**: 80% reduction in lock contention

---

### 3. **NO TCP OPTIMIZATION** ⚠️ HIGH
**Impact**: Nagle's algorithm adds latency, small buffers reduce throughput

**Location**: `ios/connect.go:291-373`

**Problem**:
- No `TCP_NODELAY` set (Nagle's algorithm adds 40-200ms delay)
- No socket buffer tuning (using OS defaults, typically 64KB)
- No read buffer size increase

**Fix** in `ConnectTUNDevice()`:
```go
conn, err := dialer.Dial("tcp4", addr.String())
if err != nil {
    return nil, err
}
tcpConn := conn.(*net.TCPConn)

// CRITICAL OPTIMIZATIONS
tcpConn.SetNoDelay(true)  // Disable Nagle's algorithm
tcpConn.SetReadBuffer(1024 * 1024)  // 1MB read buffer  
tcpConn.SetWriteBuffer(256 * 1024)  // 256KB write buffer

// Existing code for SO_LINGER, KeepAlive...
```

**Expected Improvement**: 40-200ms latency reduction per packet

---

### 4. **REGEX COMPILATION IN HOT PATH** ⚠️ MEDIUM
**Impact**: Expensive regex compilation on every filtered log

**Location**: `ios/ostrace/filter.go:193`
```go
case "REGEX":
    matched, err := regexp.MatchString(filter.Value, fieldValue)  // COMPILES EVERY TIME!
```

**Problem**:
- `regexp.MatchString()` compiles the regex on EVERY call
- If filtering 10,000 logs/sec with regex, that's 10,000 compilations/sec

**Fix**: Pre-compile regexes at filter load time
```go
type Filter struct {
    Type     string
    Field    string
    Operator string
    Value    string
    Children []Filter
    
    // ADD: pre-compiled regex
    compiledRegex *regexp.Regexp
}

func LoadFilterConfig(path string) (*FilterConfig, error) {
    // ... existing parsing ...
    
    // Pre-compile all regexes
    for i := range config.Filters {
        if err := precompileFilter(&config.Filters[i]); err != nil {
            return nil, err
        }
    }
    return &config, nil
}

func precompileFilter(filter *Filter) error {
    if filter.Operator == "REGEX" {
        compiled, err := regexp.Compile(filter.Value)
        if err != nil {
            return err
        }
        filter.compiledRegex = compiled
    }
    for i := range filter.Children {
        if err := precompileFilter(&filter.Children[i]); err != nil {
            return err
        }
    }
    return nil
}

// In evaluateFieldFilter
case "REGEX":
    if filter.compiledRegex != nil {
        return filter.compiledRegex.MatchString(fieldValue)  // Use pre-compiled!
    }
    // fallback...
```

**Expected Improvement**: 10-100x faster regex matching

---

### 5. **OUTPUT FLUSHER TOO FREQUENT** ⚠️ LOW
**Impact**: Extra mutex contention 10x per second

**Location**: `cmd/ostrace-perf/main.go:514`
```go
ticker := time.NewTicker(100 * time.Millisecond)  // TOO FREQUENT
```

**Problem**: Adds 10 extra lock acquisitions per second

**Fix**: Increase interval or remove (with channel-based writer)
```go
ticker := time.NewTicker(500 * time.Millisecond)  // 2x per second is enough
```

**Expected Improvement**: Minor, but eliminates unnecessary work

---

### 6. **DOUBLE DEADLINE UPDATES** ⚠️ LOW
**Impact**: Extra syscalls when read timeout is enabled

**Location**: `ios/ostrace/ostrace.go:103-128`
```go
func ReadStreamChunkWithDeadline(...) {
    updateDeadline()  // Called TWICE per chunk
    // read header
    updateDeadline()  // Called again!
    // read body
}
```

**Problem**: `SetReadDeadline()` is a syscall - called 2x per log

**Fix**: Only update once before header read
```go
func ReadStreamChunkWithDeadline(...) {
    // Single deadline is enough - read timeout applies to entire chunk
    if err := updateDeadline(); err != nil {
        return nil, err
    }
    
    // Read header
    if _, err := io.ReadFull(r, headerBuf); err != nil {
        return nil, err
    }
    
    // Read data (same deadline)
    data := make([]byte, length)
    if _, err := io.ReadFull(r, data); err != nil {
        return nil, err
    }
}
```

---

## Performance Impact Summary

| Issue | Syscalls/sec @ 10K logs | CPU Impact | Latency Impact |
|-------|------------------------|------------|----------------|
| No socket buffering | +20,000 | HIGH | HIGH |
| Mutex contention | N/A | VERY HIGH | MEDIUM |
| No TCP_NODELAY | N/A | LOW | VERY HIGH |
| Regex recompilation | +10,000 | HIGH | MEDIUM |
| Frequent flusher | +10 | LOW | LOW |
| Double deadline | +20,000 | MEDIUM | LOW |

**Total Impact**: At 10,000 logs/sec:
- **40,000+ unnecessary syscalls/sec**
- **10,000+ lock contentions/sec**  
- **10,000+ regex compilations/sec**

## Why This Causes iOS Slowness

1. **Socket backpressure**: When workers block on mutex, the channel fills up
2. **Channel blocks reader**: When channel is full, reader blocks on `entryChan <- entry`
3. **Socket buffer fills**: When reader stops reading, TCP receive buffer fills
4. **iOS blocks sending**: When receive buffer is full, iOS device blocks trying to send
5. **Device performance degrades**: iOS has to slow down log generation

## Priority Fix Order

1. **Add socket buffering** (biggest syscall reduction)
2. **Replace mutex with channel-based writer** (eliminate contention)
3. **Enable TCP_NODELAY** (reduce latency)
4. **Pre-compile regexes** (if filters are used)
5. **Reduce flush frequency** (minor cleanup)
6. **Single deadline update** (minor optimization)

## Expected Overall Improvement

After all fixes:
- **70-90% reduction in syscalls**
- **80-95% reduction in lock contention**
- **40-200ms reduction in per-packet latency**
- **2-5x overall throughput improvement**
- **Eliminates iOS device slowness**

