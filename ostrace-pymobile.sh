#!/bin/bash
# Wrapper script to use go-ios ostrace with pymobiledevice3's tunnel

# Default tunnel port
TUNNEL_PORT=49151

# Check if pymobiledevice3 tunnel is running
if ! curl -s "http://127.0.0.1:$TUNNEL_PORT/" > /dev/null 2>&1; then
    echo "Error: pymobiledevice3 tunnel is not running on port $TUNNEL_PORT"
    echo ""
    echo "Please start the tunnel with:"
    echo "  sudo python3 -m pymobiledevice3 remote tunneld"
    echo ""
    echo "Or if it's running on a different port, set PYMOBILE_TUNNEL_PORT environment variable:"
    echo "  export PYMOBILE_TUNNEL_PORT=<port>"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Build if binary doesn't exist
if [ ! -f "$SCRIPT_DIR/ostrace_pymobile" ]; then
    echo "Building ostrace_pymobile..."
    (cd "$SCRIPT_DIR" && go build ./cmd/ostrace_pymobile)
fi

# Use custom port if set
if [ ! -z "$PYMOBILE_TUNNEL_PORT" ]; then
    TUNNEL_PORT=$PYMOBILE_TUNNEL_PORT
fi

# Run ostrace with pymobile tunnel
"$SCRIPT_DIR/ostrace_pymobile" -pymobile-tunnel $TUNNEL_PORT "$@"
