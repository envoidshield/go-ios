# Binary Descriptions

This release includes four different binaries, each optimized for specific use cases:

## 1. `go-ios-{platform}`
The main go-ios CLI tool with all features including:
- Full device management capabilities
- Built-in pymobiledevice3 tunnel support (`--pymobile-tunnel`)
- All standard commands (ps, syslog, crash, etc.)
- ostrace functionality built-in

**Use when**: You need the full go-ios toolkit with all features.

## 2. `ostrace-{platform}`
Standalone ostrace tool for iOS log streaming:
- Standard performance
- Basic filtering support
- Minimal dependencies

**Use when**: You only need log streaming without other go-ios features.

## 3. `ostrace-perf-{platform}`
High-performance ostrace with optimizations:
- **28% faster JSON encoding** with jsoniter
- **Pymobiledevice3 tunnel support** (`--pymobile-tunnel`)
- Object pooling for reduced GC pressure
- Parallel processing with worker pools
- Can handle **500,000+ logs/second**

**Use when**: You need to process massive log volumes or use pymobile tunnel.

## 4. `ostrace-multi-{platform}`
IoT-optimized multi-stream ostrace:
- Single process handling multiple device streams
- **Optimized for weak processors** (dual-core IoT)
- Minimal memory footprint
- YAML-based configuration
- Perfect for running 6+ streams on resource-constrained devices

**Use when**: Running on IoT devices or need multiple filtered streams from one process.

## Quick Start Examples

```bash
# Full go-ios with pymobile tunnel
./go-ios-darwin-arm64 --pymobile-tunnel 49151 ostrace --json

# High-performance logging
./ostrace-perf-darwin-arm64 --pymobile-tunnel 49151 --workers 8 --json

# IoT multi-stream
./ostrace-multi-linux-arm64 -config multi-stream.yaml
```
