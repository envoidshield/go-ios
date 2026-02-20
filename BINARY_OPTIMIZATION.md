# Go Binary Optimization Guide for go-ios

## Current Situation
The go-ios binary is approximately 17MB, which includes functionality for 50+ iOS operations. The ostrace feature adds minimal overhead (~3-4MB at runtime).

## Optimization Techniques

### 1. Strip Debug Information (Immediate ~30% reduction)
```bash
# Current build
go build -o go-ios .

# Optimized build
go build -ldflags="-s -w" -o go-ios .
```
- `-s`: Strip symbol table
- `-w`: Strip DWARF debug info

### 2. Disable CGO (if possible)
```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o go-ios .
```
Benefits:
- Smaller binary
- Better cross-platform compatibility
- Faster compilation

### 3. Use Build Tags for Modular Builds
Create feature-specific builds to reduce binary size:

```go
// +build ostrace

package main
```

Build only ostrace functionality:
```bash
go build -tags="ostrace" -ldflags="-s -w" -o go-ios-ostrace ./cmd/ostrace
```

### 4. Binary Compression with UPX
```bash
# Install UPX
brew install upx

# Compress binary (50-70% reduction)
upx --best --lzma go-ios

# Ultra compression (slower decompression)
upx --ultra-brute go-ios
```

### 5. Optimize Imports
Replace heavy imports with lightweight alternatives:
- Use `log` instead of `logrus` where possible
- Use `encoding/json` instead of third-party JSON libraries
- Avoid importing `fmt` for simple operations

### 6. Profile Binary Size
```bash
# Analyze binary composition
go tool nm -size go-ios | head -20

# Visualize package sizes
go get -u github.com/Zxilly/go-size-analyzer/cmd/gsa
gsa go-ios -o treemap.html
```

### 7. Create Minimal Standalone Binaries
For specific features like ostrace:

```go
// cmd/ostrace-minimal/main.go
package main

import (
    "flag"
    "github.com/danielpaulus/go-ios/ios"
    "github.com/danielpaulus/go-ios/ios/ostrace"
)

// Minimal implementation without other go-ios features
```

## Recommended Build Pipeline

### Development Build
```bash
go build -o go-ios .
```

### Production Build (Full Features)
```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o go-ios .
upx --best go-ios
```

### Minimal Feature Build (e.g., ostrace only)
```bash
# Create separate cmd/ostrace-standalone
CGO_ENABLED=0 go build -ldflags="-s -w" -o ostrace ./cmd/ostrace-standalone
upx --best ostrace
```

## Expected Results

| Build Type | Original | Stripped | UPX Compressed |
|------------|----------|----------|----------------|
| Full go-ios | 17MB | 12MB | 4-5MB |
| ostrace-only | N/A | 4-5MB | 1-2MB |

## Trade-offs

### Pros:
- Significantly smaller binaries
- Faster downloads and deployments
- Lower memory footprint
- Better for embedded/constrained environments

### Cons:
- No debug symbols (harder debugging)
- UPX adds decompression overhead at startup
- UPX may trigger antivirus false positives
- Build complexity increases with modular builds

## Implementation Plan

1. **Quick Win**: Add `-ldflags="-s -w"` to all builds
2. **Medium Term**: Create build tags for major features
3. **Long Term**: Separate binaries for different use cases

## Example Makefile

```makefile
.PHONY: build build-prod build-minimal

# Development build
build:
	go build -o go-ios .

# Production build (stripped + compressed)
build-prod:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o go-ios .
	upx --best go-ios

# Minimal ostrace build
build-ostrace:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o ostrace ./cmd/ostrace
	upx --best ostrace

# Size comparison
size-compare:
	@echo "Original size:"
	@ls -lh go-ios
	@echo "\nStripped size:"
	@go build -ldflags="-s -w" -o go-ios-stripped .
	@ls -lh go-ios-stripped
	@echo "\nCompressed size:"
	@upx --best -o go-ios-compressed go-ios-stripped
	@ls -lh go-ios-compressed
```
