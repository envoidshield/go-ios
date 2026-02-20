# ostrace Performance Analysis

## Memory Usage

The `ostrace` command uses approximately 26-27MB of RSS memory, which breaks down as:

1. **Go runtime overhead**: ~6MB (baseline for any Go program)
2. **Binary size**: The go-ios binary is large (~17MB) due to all included functionality
3. **Network buffers**: iOS streaming connections and TLS buffers
4. **String allocations**: Log entry parsing creates strings for each field

## CPU Usage

- **Without filtering**: 0.6% CPU (processing ~680 logs/second)
- **With simple filter**: 0.1% CPU (due to reduced output)
- **With complex YAML filter**: 0.1-0.3% CPU (regex matching adds overhead)

## Optimization Opportunities

### Current Optimizations

1. **Buffer pooling**: Reuse small buffers for header reading
2. **Single allocation**: Read header in one syscall instead of multiple
3. **Efficient parsing**: Binary parsing without intermediate structs

### Potential Future Optimizations

1. **String interning**: Cache common strings (process names, subsystems)
2. **Zero-copy parsing**: Use unsafe string conversions for read-only data
3. **Streaming JSON**: Write JSON directly without intermediate structs
4. **Compile regex once**: Pre-compile regex patterns in filters

### Memory Profile

The majority of memory is from:
- Static binary size (not reducible without splitting functionality)
- Go runtime (garbage collector, goroutines)
- Network connection buffers

The actual log processing adds minimal overhead (~3-4MB).

## Recommendations

For memory-constrained environments:

1. Build a standalone `ostrace` binary without other go-ios functionality
2. Use process filtering (`--pid` or `--process`) to reduce log volume
3. Avoid complex regex filters when simple string matching suffices
4. Consider increasing GOGC to reduce GC frequency if latency isn't critical

```bash
# For lower memory usage at the cost of more GC pauses
GOGC=50 ios ostrace --filter "error"

# For better performance with more memory usage
GOGC=200 ios ostrace --filter-config complex-filter.yaml
```
