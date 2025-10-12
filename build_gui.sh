#!/bin/bash

# Build script for iOS Tunnel Manager GUI

echo "Building iOS Tunnel Manager GUI..."

# Check if Fyne is installed
if ! command -v fyne &> /dev/null; then
    echo "Installing Fyne CLI tool..."
    go install fyne.io/fyne/v2/cmd/fyne@latest
fi

# Install dependencies
echo "Installing dependencies..."
go mod tidy

# Build the GUI application
echo "Building GUI application..."
go build -o tunnel-manager-gui.exe gui_main.go gui.go gui_utils.go

# Create Windows app bundle
echo "Creating Windows app bundle..."
fyne package -os windows -icon icon.png

echo "Build completed!"
echo "Run with: ./tunnel-manager-gui.exe"
