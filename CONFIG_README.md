# Configuration Setup

## 🔒 **Secure Authentication Setup**

The application uses a `config.json` file to store sensitive authentication credentials. This keeps your credentials out of the compiled binary.

### **Setup Steps:**

1. **Create `config.json`** in the same folder as the executable:
```json
{
  "balena_url": "https://your-balena-endpoint.com/api/devices/trust",
  "username": "your-username",
  "password": "your-password"
}
```

2. **Replace the values:**
   - `balena_url`: Your Balena endpoint URL
   - `username`: Your authentication username
   - `password`: Your authentication password

3. **Keep the file secure:**
   - Don't share `config.json` with others
   - Don't commit it to version control
   - Keep it in the same folder as the executable

### **Security Benefits:**
- ✅ Credentials not in the binary
- ✅ Easy to change without recompiling
- ✅ Can be different for each client
- ✅ File can be encrypted if needed

### **File Structure:**
```
tunnel-manager-gui.exe
config.json          ← Your credentials here
```

### **Example config.json:**
```json
{
  "balena_url": "https://382eaabb23507794da78c3a2ef0e0940.balena-devices.com/api/devices/trust",
  "username": "admin",
  "password": "tdaxH9vwRqMly4nBBtEc"
}
```

The application will automatically load these credentials when it runs!
