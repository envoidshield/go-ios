# iOS Tunnel Manager GUI

A modern graphical user interface for the iOS Tunnel Manager, built with Fyne framework.

## Features

### 🚀 **Easy Tunnel Management**
- **One-click tunnel start/stop** with visual status indicators
- **Real-time status updates** showing tunnel state
- **Progress indicators** for all operations

### 📱 **Device Discovery & Pairing**
- **Automatic device discovery** when tunnel is running
- **Visual device list** with UDID, address, and port information
- **One-click device pairing** with secure authentication
- **Progress tracking** during pairing process

### 🎨 **Modern UI/UX**
- **Clean, intuitive interface** designed for ease of use
- **Responsive layout** that adapts to different screen sizes
- **Visual feedback** for all user actions
- **Error handling** with user-friendly messages

## Installation

### Prerequisites
- Go 1.22 or later
- Windows 10/11 (for Windows builds)

### Building from Source

#### Option 1: Using Batch File (Windows)
```cmd
build_gui.bat
```

#### Option 2: Using PowerShell
```powershell
# Install Fyne CLI
go install fyne.io/fyne/v2/cmd/fyne@latest

# Install dependencies
go mod tidy

# Build the application
go build -o tunnel-manager-gui.exe main_gui.go gui.go main.go

# Create Windows app bundle
fyne package -os windows -icon icon.png
```

#### Option 3: Using Bash (Git Bash/WSL)
```bash
./build_gui.sh
```

## Usage

### Starting the Application
```cmd
tunnel-manager-gui.exe
```

### Basic Workflow

1. **Start Tunnel Service**
   - Click "Start Tunnel" button
   - Wait for "Tunnel Status: Running" indicator
   - Tunnel service will automatically discover devices

2. **Discover Devices**
   - Devices will appear automatically in the device list
   - Click "Refresh Devices" to manually refresh
   - Each device shows UDID, address, and port information

3. **Pair with Device**
   - Select a device from the list
   - Click "Pair Device" button
   - Follow the pairing progress dialog
   - Success message will show the host key

4. **Stop Tunnel Service**
   - Click "Stop Tunnel" button when done
   - All connections will be closed

## GUI Components

### Main Window Layout
```
┌─────────────────────────────────────────┐
│           iOS Tunnel Manager            │
├─────────────────────────────────────────┤
│  Tunnel Status: [Running/Stopped]      │
├─────────────────────────────────────────┤
│  Available Devices:                     │
│  ┌─────────────────────────────────────┐ │
│  │ 📱 Device 1 | UDID123 | 192.168.1.1 │ │
│  │ 📱 Device 2 | UDID456 | 192.168.1.2 │ │
│  └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│  [Start Tunnel] [Stop Tunnel]          │
│  [Refresh Devices] [Pair Device]       │
└─────────────────────────────────────────┘
```

### Status Indicators
- **🟢 Running**: Tunnel service is active
- **🔴 Stopped**: Tunnel service is inactive
- **🟡 Starting**: Tunnel service is starting up
- **❌ Failed**: Tunnel service failed to start

## Troubleshooting

### Common Issues

#### "Failed to start tunnel"
- **Solution**: Run as Administrator
- **Check**: Ensure no other tunnel services are running
- **Verify**: Windows Defender isn't blocking the application

#### "No devices found"
- **Solution**: Ensure iOS device is connected via USB
- **Check**: Device is in developer mode
- **Verify**: Tunnel service is running

#### "Pairing failed"
- **Solution**: Trust the computer on the iOS device
- **Check**: Device is unlocked
- **Verify**: Network connection is stable

### Windows-Specific Notes

- **Administrator Rights**: May be required for tunnel operations
- **Windows Defender**: May need to add exception for the application
- **Firewall**: Ensure port 28100 is not blocked
- **Antivirus**: Some antivirus software may interfere with tunnel operations

## Development

### Project Structure
```
├── main_gui.go          # GUI entry point
├── gui.go              # Main GUI implementation
├── main.go             # Original CLI implementation
├── build_gui.bat       # Windows build script
├── build_gui.sh        # Cross-platform build script
└── README_GUI.md       # This file
```

### Key Components
- **GUIApp**: Main application structure
- **TunnelManager**: Tunnel service management
- **Device Discovery**: Automatic device detection
- **Pairing Process**: Secure device pairing

## Security Features

- **Secure Pairing**: Uses SRP protocol for authentication
- **Encrypted Communication**: TLS encryption for all connections
- **Key Management**: Secure key extraction and storage
- **Trust Verification**: Device trust establishment

## License

Same as the main go-ios project (MIT License).

## Support

For issues and questions:
- Check the troubleshooting section above
- Review the original go-ios documentation
- Create an issue in the project repository
