#!/bin/bash
# Setup script for IoT deployment

# Create RAM-based log directory (uses only 10MB RAM)
sudo mkdir -p /run/ostrace-logs
sudo mount -t tmpfs -o size=10M tmpfs /run/ostrace-logs

# Create filter directory
sudo mkdir -p /etc/ostrace/filters

# Copy filters
sudo cp examples/filters/*.yaml /etc/ostrace/filters/

# Set up log rotation
cat > /etc/logrotate.d/ostrace << EOF
/run/ostrace-logs/*.jsonl {
    size 1M
    rotate 2
    compress
    delaycompress
    notifempty
    create 0644 nobody nogroup
}
EOF

# Build optimized binary with minimal features
echo "Building IoT-optimized binary..."
CGO_ENABLED=0 go build -tags perf \
    -ldflags="-s -w -X main.version=iot" \
    -o ostrace-iot \
    ./cmd/ostrace-multi

# Strip binary further
strip ostrace-iot

echo "IoT setup complete. Binary size: $(du -h ostrace-iot | cut -f1)"
