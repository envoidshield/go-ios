# ENVOID Pairing Assistant - User Guide

## What This Does

Pairs your iPhone/iPad with your EnPortable device via WiFi Direct (no internet needed). This enables your device to be protected by ENVOID when connected to EnvoidDirect WiFi.

---

## Before You Start

### 1. Install iTunes
- Download and install iTunes from https://www.apple.com/itunes/
- Use the desktop version (not Microsoft Store version)
- Restart your computer

### 2. Connect to WiFi
- Connect your computer to the **EnvoidDirect** WiFi network
- This network is created by your EnPortable device

### 3. Check Files
- Make sure `Pairing-Assistant.exe` and `wintun.dll` are in the same folder

---

## How to Use

### Step 1: Launch Application
1. Double-click `Pairing-Assistant.exe`
2. Click **"Yes"** when Windows asks for administrator permission
3. The ENVOID Pairing Assistant window will open

### Step 2: Start Pairing
1. Click the **"Start Pairing"** button

### Step 3: Connect Your iPhone
1. When prompted, connect your iPhone/iPad via USB cable
2. Unlock your device
3. When "Trust This Computer?" appears on your iPhone, tap **"Trust"**
4. Enter your device passcode

### Step 4: Trust for ENVOID (if prompted)
1. A second trust prompt may appear on your iPhone
2. Tap **"Trust"** and enter your passcode again
3. The app will automatically complete the pairing

### Step 5: Done
1. When you see **"Success"** - your device is paired!
2. You'll see: "Connect your iPhone to EnvoidDirect WiFi to be protected by the EnPortable"
3. Click **"Done"** to close, or **"Pair Another Device"** to continue pairing

---

## Problems?

**Device not detected?**
- Unplug and replug USB cable
- Make sure iPhone is unlocked
- Check you tapped "Trust"

**Trust prompt not showing?**
- Disconnect USB
- iPhone: Settings → General → Transfer or Reset iPhone → Reset → Reset Location & Privacy
- Reconnect and try again

**Connection failed?**
- Verify you're on EnvoidDirect WiFi
- Check iTunes is installed
- Make sure you clicked "Yes" to administrator permission

**Server post failed?**
- Check EnPortable is powered on
- Verify WiFi connection
- Try pairing again

---

## Quick Checklist

Before starting:
- [ ] iTunes installed
- [ ] Connected to EnvoidDirect WiFi
- [ ] Both `Pairing-Assistant.exe` and `wintun.dll` in same folder

During pairing:
- [ ] Double-click `Pairing-Assistant.exe`
- [ ] Click "Yes" to administrator prompt
- [ ] Click "Start Pairing"
- [ ] Connect iPhone via USB when prompted
- [ ] Tap "Trust" on iPhone (with passcode)
- [ ] Wait for "Success"

---

## Important

- ✅ iTunes **must** be installed
- ✅ **Must** be on EnvoidDirect WiFi
- ✅ **Must** have `wintun.dll` in same folder as `.exe`
- ✅ Click "Yes" to administrator prompt when launching
- ✅ You may need to trust **twice** on iPhone
- ✅ No internet needed

---

**Debug Mode:** Open Command Prompt as admin → type `set DEBUG=1` → run app from that window to see detailed logs.
