# Makefile to build and run go-ios and the cdc-ncm network driver
# cdc-ncm needs to be executed with sudo on Linux for USB Access and setting
# up virtual TAP network devices.
# use Make build to build both binaries. 
# Make run is a simple target that just runs the cdc-ncm driver with sudo
# For development, use "make up" to rebuild and run cdc-ncm quickly

# Name of your Go binaries
GO_IOS_BINARY_NAME=ios
NCM_BINARY_NAME=go-ncm

# Define only if compiling for system different than our own
OS=
ARCH=

# Prepend each non-empty OS/ARCH definition to "go" command
GOEXEC=$(strip $(foreach v,OS ARCH,$(and $($v),GO$v=$($v) )) go)

# Build the Go program
build:
	@$(GOEXEC) work use .
	@$(GOEXEC) build -o $(GO_IOS_BINARY_NAME) ./main.go
	@$(GOEXEC) work use ./ncm
	@CGO_ENABLED=1 $(GOEXEC) build -o $(NCM_BINARY_NAME) ./cmd/cdc-ncm/main.go

# Run the Go program with sudo
run: build
	@sudo ./$(NCM_BINARY_NAME) --prometheusport=8080

# Build and run
up: build run

# Phony targets
.PHONY: build run up

# ============================================================================
# AUTOTRUST CROSS-PLATFORM BUILD
# ============================================================================

AUTOTRUST_BINARY_NAME=autotrust
AUTOTRUST_DIST_DIR=./dist/autotrust

# Cross-platform targets
AUTOTRUST_TARGETS = \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Define OS/ARCH if compiling for different system
OS=
ARCH=

# Prepend each non-empty OS/ARCH definition to "go" command
GOEXEC=$(strip $(foreach v,OS ARCH,$(and $($v),GO$v=$($v) )) go)

.PHONY: autotrust-build autotrust-build-all autotrust-clean autotrust-test

# Build autotrust for current platform
autotrust-build:
	@echo "Building autotrust for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(AUTOTRUST_DIST_DIR)
	@$(GOEXEC) build -o $(AUTOTRUST_BINARY_NAME) ./cmd/autotrust
	@echo "✓ Built: $(AUTOTRUST_BINARY_NAME)"

# Build autotrust for all platforms
autotrust-build-all:
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║      Building autotrust for all platforms                     ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@mkdir -p $(AUTOTRUST_DIST_DIR)
	@for target in $(AUTOTRUST_TARGETS); do \
		os=$$(echo $$target | cut -d/ -f1); \
		arch=$$(echo $$target | cut -d/ -f2); \
		output=$(AUTOTRUST_DIST_DIR)/autotrust-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then \
			output="$$output.exe"; \
		fi; \
		echo "  Building $$os/$$arch → $$output"; \
		GOOS=$$os GOARCH=$$arch $(GOEXEC) build \
			-ldflags "-s -w" \
			-o "$$output" ./cmd/autotrust || exit 1; \
		if [ -f "$$output" ]; then \
			size=$$(ls -lh "$$output" | awk '{print $$5}'); \
			echo "    ✓ Success ($$size)"; \
		else \
			echo "    ✗ Failed"; \
			exit 1; \
		fi; \
	done
	@echo ""
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║                    BUILD SUMMARY                              ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Built binaries:"
	@ls -lh $(AUTOTRUST_DIST_DIR)/autotrust-* | awk '{printf "  %-50s %s\n", $$9, $$5}'
	@echo ""
	@echo "Total size: $$(du -sh $(AUTOTRUST_DIST_DIR) | awk '{print $$1}')"

# Test autotrust
autotrust-test:
	@echo "Testing autotrust..."
	@./autotrust -h
	@echo "✓ CLI flags working"
	@echo "✓ autotrust ready"

# Clean autotrust builds
autotrust-clean:
	@echo "Cleaning autotrust builds..."
	@rm -rf $(AUTOTRUST_DIST_DIR)
	@rm -f $(AUTOTRUST_BINARY_NAME)
	@echo "✓ Cleaned"

# Run autotrust (kernel mode - requires sudo)
autotrust-run: autotrust-build
	@echo "Running autotrust (kernel mode)..."
	@sudo ./$(AUTOTRUST_BINARY_NAME)

# Run autotrust (userspace mode - no sudo)
autotrust-run-userspace: autotrust-build
	@echo "Running autotrust (userspace mode)..."
	@./$(AUTOTRUST_BINARY_NAME) --userspace

# Help for autotrust targets
autotrust-help:
	@echo "autotrust build targets:"
	@echo "  make autotrust-build         - Build for current platform"
	@echo "  make autotrust-build-all     - Build for all platforms (Linux/macOS/Windows)"
	@echo "  make autotrust-test          - Test autotrust CLI"
	@echo "  make autotrust-run           - Run autotrust (kernel mode, requires sudo)"
	@echo "  make autotrust-run-userspace - Run autotrust (userspace mode)"
	@echo "  make autotrust-clean         - Clean autotrust builds"
	@echo "  make autotrust-help          - Show this help"
	@echo ""
	@echo "Cross-platform build example:"
	@echo "  make autotrust-build-all    # Builds for Linux/macOS/Windows x86_64/ARM64"

# ============================================================================
# NCM CROSS-PLATFORM BUILD
# ============================================================================

NCM_DIST_DIR=./dist/ncm

# Cross-platform targets for NCM
NCM_TARGETS = \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.PHONY: ncm-build ncm-build-all ncm-clean

# Build NCM for current platform
ncm-build:
	@echo "Building go-ncm for current platform..."
	@mkdir -p $(NCM_DIST_DIR)
	@cd ncm && CGO_ENABLED=1 go build -ldflags "-s -w" -o ../$(NCM_DIST_DIR)/go-ncm ../cmd/cdc-ncm/main.go
	@echo "✓ Built: $(NCM_DIST_DIR)/go-ncm"

# Build NCM for all platforms
ncm-build-all:
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║      Building go-ncm for all platforms                        ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@mkdir -p $(NCM_DIST_DIR)
	@for target in $(NCM_TARGETS); do \
		os=$$(echo $$target | cut -d/ -f1); \
		arch=$$(echo $$target | cut -d/ -f2); \
		output=$(NCM_DIST_DIR)/go-ncm-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then \
			output="$$output.exe"; \
		fi; \
		echo "  Building $$os/$$arch → $$output"; \
		cd ncm && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build \
			-ldflags "-s -w" \
			-o ../$$output ../cmd/cdc-ncm/main.go || exit 1; \
		cd ..; \
		if [ -f "$$output" ]; then \
			size=$$(ls -lh "$$output" | awk '{print $$5}'); \
			echo "    ✓ Success ($$size)"; \
		else \
			echo "    ✗ Failed"; \
			exit 1; \
		fi; \
	done
	@echo ""
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║                    BUILD SUMMARY                              ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Built binaries:"
	@ls -lh $(NCM_DIST_DIR)/go-ncm-* | awk '{printf "  %-50s %s\n", $$9, $$5}'
	@echo ""
	@echo "Total size: $$(du -sh $(NCM_DIST_DIR) | awk '{print $$1}')"

# Clean NCM builds
ncm-clean:
	@echo "Cleaning go-ncm builds..."
	@rm -rf $(NCM_DIST_DIR)
	@echo "✓ Cleaned"

