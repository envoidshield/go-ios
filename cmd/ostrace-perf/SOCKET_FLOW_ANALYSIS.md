# Socket Data Flow Analysis - Critical Path Performance

## The Complete Data Path

```
┌─────────────────────────────────────────────────────────────────────┐
│                        iOS Device                                    │
│  Generates logs → TCP Send Buffer → Network                         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   OS Kernel TCP Stack                                │
│  Network → TCP Receive Buffer (default ~64KB)                       │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼ read() syscall x2 per log ⚠️
┌─────────────────────────────────────────────────────────────────────┐
│              net.Conn (raw socket, NO BUFFERING) ⚠️                  │
│  deviceConn.Reader() → returns raw conn                             │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼ io.ReadFull #1 (5 bytes header)
┌─────────────────────────────────────────────────────────────────────┐
│                    OsTraceCodec.ReadStreamChunk()                   │
│  Line 80: io.ReadFull(r, headerBuf[5])  ← syscall #1 ⚠️             │
│  Line 93: io.ReadFull(r, data[length])  ← syscall #2 ⚠️             │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Returns []byte
┌─────────────────────────────────────────────────────────────────────┐
│              Connection.FastReadLogEntry() [READER GOROUTINE]       │
│  - Parses binary format                                              │
│  - Gets LogEntry from pool                                           │
│  - Uses unsafe string conversions (good!)                            │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Try to send to channel
┌─────────────────────────────────────────────────────────────────────┐
│                     entryChan (buffered channel)                    │
│  Size: --buffer flag (default 1000)                                 │
│  ⚠️ BLOCKS HERE if channel full!                                    │
│     → Reader stops reading from socket                               │
│     → TCP buffer fills up                                            │
│     → iOS device blocks trying to send                               │
└─────────────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┼─────────────┬─────────────┐
                ▼             ▼             ▼             ▼
         ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐
         │ Worker 1  │ │ Worker 2  │ │ Worker 3  │ │ Worker N  │
         │ goroutine │ │ goroutine │ │ goroutine │ │ goroutine │
         └───────────┘ └───────────┘ └───────────┘ └───────────┘
                │             │             │             │
                │   Each worker does:                     │
                │   1. Receive entry from channel         │
                │   2. Check ping timing                  │
                │   3. Evaluate filters (regex?)          │
                │   4. Format to string                   │
                │   5. ⚠️ LOCK MUTEX ⚠️                  │
                └─────────────┼─────────────┴─────────────┘
                              ▼
                    ┌─────────────────────┐
                    │   outputMutex.Lock() │ ⚠️ CONTENTION!
                    │                      │
                    │ ALL workers fight    │
                    │ for this SINGLE lock │
                    │ on EVERY log entry   │
                    │                      │
                    │ 8 workers @ 10K/sec  │
                    │ = 10K contentions/s  │
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  outputBuffer.Write()│
                    │  (64KB bufio.Writer) │
                    └─────────────────────┘
                              │
                              ▼ outputMutex.Unlock()
                    ┌─────────────────────┐
                    │   Flusher goroutine  │
                    │   Every 100ms:       │
                    │   - Lock mutex ⚠️    │
                    │   - Flush buffer     │
                    │   - Unlock           │
                    └─────────────────────┘
                              │
                              ▼
                         os.Stdout
```

## The Blocking Chain Reaction

When logs come in fast (10,000/sec):

```
1. All 8 workers process logs simultaneously
   
2. Worker 1 tries to write:
   outputMutex.Lock() ← ACQUIRES LOCK
   outputBuffer.Write()
   outputMutex.Unlock()

3. Workers 2-8 all try to write at same time:
   outputMutex.Lock() ← BLOCKED! (lock held by Worker 1)
   
   Workers 2-8 are now SLEEPING, waiting for lock

4. While workers are blocked:
   - They can't pull from entryChan
   - entryChan fills up (1000 entries)
   - Reader goroutine tries: entryChan <- entry
   - Reader BLOCKS because channel is full!

5. While reader is blocked:
   - No more read() syscalls
   - TCP receive buffer fills up
   - iOS device tries to send → BLOCKS!
   - iOS has to slow down or drop logs

6. iOS performance degrades:
   - Device sees backpressure
   - Has to throttle log generation
   - System appears slow
```

## Syscall Analysis @ 10,000 logs/sec

### Current Implementation (NO BUFFERING)

```
Per Log Entry:
├─ SetReadDeadline() syscall (if timeout enabled)  ← 1 syscall
├─ read() for 5-byte header                        ← 2 syscalls  
├─ SetReadDeadline() syscall again                 ← 3 syscalls
└─ read() for payload (variable size)              ← 4 syscalls

Total: 4 syscalls per log (with timeout)
       2 syscalls per log (without timeout)

At 10,000 logs/sec:
- With timeout: 40,000 syscalls/sec
- Without timeout: 20,000 syscalls/sec
```

### With Buffered Reader (PROPOSED)

```
Per Log Entry:
├─ SetReadDeadline() syscall (once per buffer fill) ← amortized ~0.001
├─ Buffer read for header (in userspace!)           ← 0 syscalls
└─ Buffer read for payload (in userspace!)          ← 0 syscalls

Behind the scenes:
- bufio reads 256KB at once
- ~1000 logs fit in one read()
- 1 syscall serves 1000 logs

At 10,000 logs/sec with 256KB buffer:
- ~10 read() syscalls/sec
- 99.95% reduction in syscalls!
```

## Lock Contention Analysis @ 10,000 logs/sec

### Current: Shared Mutex (8 workers)

```
Scenario: 10,000 logs/sec, 8 workers, 100μs formatting time

Timeline (simplified):
T=0μs:    Worker 1 locks, Worker 2-8 all try to lock → BLOCK
T=100μs:  Worker 1 unlocks, Worker 2 acquires lock, 3-8 still blocked
T=200μs:  Worker 2 unlocks, Worker 3 acquires lock, 4-8 still blocked
T=300μs:  Worker 3 unlocks, Worker 4 acquires lock, 5-8 still blocked
...

Result:
- Workers spend 75% of time waiting for lock
- Only 1 worker active at a time
- 7 workers idle/blocked most of time
- Channel backs up → reader blocks → iOS slows down
```

### Proposed: Channel-Based Writer (8 workers)

```
Scenario: 10,000 logs/sec, 8 workers, 100μs formatting time

Timeline:
T=0μs:    All 8 workers processing in parallel
          Worker 1-8 all send to outputChan (no blocking!)
          Single writer goroutine reads from channel

Result:
- All 8 workers active 100% of time
- No lock contention
- Channel rarely fills (single fast writer)
- Reader never blocks
- iOS device happy!
```

## TCP/Network Analysis

### Without TCP_NODELAY (Current)

```
Nagle's Algorithm ENABLED (default):

iOS sends 200-byte log:
T=0ms:    Small packet arrives → Nagle says "wait, might be more"
T=0-40ms: TCP waits for either:
          - More data to fill packet (1460 bytes)
          - Or 40-200ms timeout
T=40ms:   Timeout expires → packet sent → syscall returns

Result: 40-200ms latency added per packet!
```

### With TCP_NODELAY (Proposed)

```
Nagle's Algorithm DISABLED:

iOS sends 200-byte log:
T=0ms:    Small packet arrives → Send immediately!
T=<1ms:   Packet sent → syscall returns

Result: <1ms latency, immediate delivery
```

## Memory Allocation Hotspots

### Current Allocations (per 10,000 logs)

```go
// ReadStreamChunk - EVERY log allocates:
data := make([]byte, length)  // ~200 bytes avg = 2MB/10K logs

// Worker formatting:
localBuf := make([]byte, 0, 4096)  // Reused (good!)

// JSON encoding (if --json):
json.Marshal(entry)  // Internal allocations = ~500 bytes/log = 5MB/10K logs

Total: ~7MB allocated per 10,000 logs
```

### Optimization Opportunities

1. **Pool the chunk buffers** (if sizes are predictable)
2. **Avoid JSON allocation** with streaming encoder
3. **Pre-allocate output strings** based on average size

## CPU Profile Prediction

Based on analysis, expected CPU hotspots:

```
40% - syscall overhead (read() calls)
25% - mutex lock contention + context switches  
15% - memory allocation/GC
10% - string formatting
5%  - filter evaluation
5%  - JSON encoding (if enabled)
```

After optimizations:

```
50% - actual log processing (formatting, filtering)
20% - memory allocation/GC (harder to optimize)
15% - string operations
10% - channel operations
5%  - syscall overhead (reduced from 40%!)
```

## Verification Commands

To see the actual impact, run with profiling:

```bash
# Before optimizations
go build -o ostrace-perf-before ./cmd/ostrace-perf
./ostrace-perf-before --stats --diagnostics 2> stats_before.txt

# Monitor system calls
sudo dtrace -n 'syscall::read:entry /execname == "ostrace-perf-before"/ { @reads = count(); }'

# Profile CPU
go tool pprof -http=:8080 cpu_before.prof
```

## Conclusion

The critical path bottlenecks are:

1. **Unbuffered socket reads** → 20,000-40,000 extra syscalls/sec
2. **Shared mutex in workers** → 10,000 lock contentions/sec  
3. **No TCP_NODELAY** → 40-200ms latency per log

All three create backpressure that blocks the socket reader, which fills the TCP buffer, which makes iOS device slow down.

**The fix is simple**: Buffer the socket, eliminate the shared lock, enable TCP_NODELAY.

