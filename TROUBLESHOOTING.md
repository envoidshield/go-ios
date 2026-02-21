# iOS Tunnel Manager - Troubleshooting Guide

## 🚨 Common Error: "InvalidHostID"

### **Error Message:**
```
failed to start tunnel: StartSession failed: {EnableSessionSSL:false Request: SessionID: Error:} error: failed to start new lockdown session: InvalidHostID
```

### **What This Means:**
The iOS device doesn't recognize your computer as a trusted host. This happens when:
- The device hasn't been paired with this computer before
- The pairing record is corrupted or missing
- The device was reset or restored

## 🔧 Solutions

### **Solution 1: Manual Device Pairing (Recommended)**

1. **Connect your iOS device via USB**
2. **Unlock your device** and keep it awake
3. **On your iOS device**, you should see a popup asking "Trust This Computer?"
4. **Tap "Trust"** and enter your passcode if prompted
5. **Wait for the "Trusted" confirmation**
6. **Try starting the tunnel again**

### **Solution 2: Reset Pairing Records**

If the trust dialog doesn't appear:

1. **On your iOS device:**
   - Go to Settings → General → Reset → Reset Location & Privacy
   - This will clear all trusted computers

2. **On your computer:**
   - Delete any existing pairing records:
   ```cmd
   del selfIdentity.plist
   rmdir /s /q .\pairing_records
   ```

3. **Reconnect the device** and follow Solution 1

### **Solution 3: Use iTunes/Finder for Initial Pairing**

1. **Open iTunes (Windows) or Finder (Mac)**
2. **Connect your iOS device**
3. **Complete the trust process in iTunes/Finder first**
4. **Then try the tunnel manager**

### **Solution 4: Check Device Developer Mode**

For iOS 16+ devices:

1. **Enable Developer Mode:**
   - Settings → Privacy & Security → Developer Mode → Turn On
   - Restart the device when prompted

2. **Trust the computer again** after restart

## 🛠️ Advanced Troubleshooting

### **Check Device Status**
```cmd
# List connected devices
ios list

# Check device details
ios info
```

### **Manual Pairing via CLI**
```cmd
# Try manual pairing first
ios pair

# Then start tunnel
ios tunnel start
```

### **Reset Everything**
```cmd
# Stop any running tunnels
ios tunnel stop

# Clear all pairing data
del selfIdentity.plist
rmdir /s /q .\pairing_records

# Restart the GUI
tunnel-manager-gui.exe
```

## 🔍 Debug Information

### **Check These:**
- ✅ Device is unlocked and awake
- ✅ USB cable is working (try different cable)
- ✅ Device is in developer mode (iOS 16+)
- ✅ No other iOS tools are using the device
- ✅ Computer has proper drivers installed

### **Common Issues:**
- **"Device not found"** → Check USB connection
- **"Permission denied"** → Run as Administrator
- **"Port already in use"** → Stop other tunnel services
- **"InvalidHostID"** → Device trust issue (see solutions above)

## 📱 Device-Specific Notes

### **iPhone/iPad:**
- Must be unlocked during pairing
- Developer mode required for iOS 16+
- Trust dialog must be accepted

### **Windows:**
- May need Administrator rights
- iTunes must be installed for drivers
- Windows Defender may block connections

### **macOS:**
- Xcode command line tools recommended
- May need to disable SIP for some operations

## 🆘 Still Having Issues?

### **Try This Sequence:**
1. **Disconnect device completely**
2. **Restart your computer**
3. **Reconnect device**
4. **Accept trust dialog on device**
5. **Run tunnel manager as Administrator**
6. **Start tunnel service**

### **Alternative: Use CLI First**
```cmd
# Test with command line first
ios list
ios pair
ios tunnel start
```

If CLI works, then the GUI should work too.

## 📞 Getting Help

If none of these solutions work:
1. Check the device logs on iOS
2. Try with a different iOS device
3. Verify your go-ios installation
4. Check Windows event logs for USB errors

The "InvalidHostID" error is almost always a device trust issue that can be resolved by following the pairing steps above.
