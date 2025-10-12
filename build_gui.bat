@echo off
REM Build script for iOS Tunnel Manager GUI on Windows

echo Building iOS Tunnel Manager GUI...

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Go is not installed or not in PATH
    pause
    exit /b 1
)

REM Install Fyne CLI tool if not present
where fyne >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Fyne CLI tool...
    go install fyne.io/fyne/v2/cmd/fyne@latest
)

REM Install dependencies
echo Installing dependencies...
go mod tidy

REM Build the GUI application
echo Building GUI application...
go build -o tunnel-manager-gui.exe gui_main.go gui.go gui_utils.go

REM Create Windows app bundle
echo Creating Windows app bundle...
fyne package -os windows -icon icon.png

echo Build completed!
echo Run with: tunnel-manager-gui.exe
pause
