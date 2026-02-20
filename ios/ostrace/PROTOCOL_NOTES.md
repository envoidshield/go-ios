# OS Trace Protocol Notes

## Protocol Discovery

Through testing with a real device, we've discovered the following about the `com.apple.os_trace_relay` service:

### Protocol Format

The service uses a **custom 5-byte header** format, different from the standard 4-byte length-prefixed plist:

```
[1 byte: status/version][4 bytes: payload length, big-endian][N bytes: plist payload]
```

Example response header: `01 00 00 3B 4E`
- Status byte: `0x01`
- Length: `0x00003B4E` = 15,182 bytes

This is different from the standard lockdown protocol which uses:
```
[4 bytes: payload length, big-endian][N bytes: plist payload]
```

### Service Availability

**Note**: During testing, the `com.apple.os_trace_relay` service connected successfully but:
1. The `PidList` command returned a valid header but no payload
2. The `StartActivity` command caused the service to close the connection immediately

This suggests:
- The service may require specific iOS versions (possibly iOS 13+)
- The service may require developer mode to be enabled
- The commands may have changed in newer iOS versions
- Additional authentication or setup steps may be required

### Implementation Status

The current implementation in `ostrace.go` uses the standard 4-byte plist codec. **This needs to be updated** to use the custom 5-byte header format.

### Required Changes

1. **Create custom codec** for os_trace protocol:
   ```go
   type OsTraceCodec struct{}
   
   func (c OsTraceCodec) Decode(r io.Reader) (status byte, payload []byte, error) {
       // Read 5-byte header
       header := make([]byte, 5)
       _, err := io.ReadFull(r, header)
       if err != nil {
           return 0, nil, err
       }
       
       status = header[0]
       length := binary.BigEndian.Uint32(header[1:5])
       
       // Read payload
       payload = make([]byte, length)
       _, err = io.ReadFull(r, payload)
       return status, payload, err
   }
   
   func (c OsTraceCodec) Encode(msg interface{}) ([]byte, error) {
       // Encode as XML plist (testing showed XML format works)
       plistBytes, err := plist.Marshal(msg, plist.XMLFormat)
       if err != nil {
           return nil, err
       }
       
       // Create header: [4 bytes length][plist]
       // Note: Request doesn't include status byte
       buf := new(bytes.Buffer)
       length := uint32(len(plistBytes))
       binary.Write(buf, binary.BigEndian, length)
       buf.Write(plistBytes)
       
       return buf.Bytes(), nil
   }
   ```

2. **Replace PlistCodec usage** in all methods with `OsTraceCodec`

3. **Add status byte handling** in response parsing

4. **Test with different iOS versions** to determine minimum supported version

### Testing Commands

```bash
# Test basic connection
go run test_ostrace_connect.go

# Expected results:
# - Service should connect successfully  
# - Commands may return empty payloads or EOF on unsupported versions
# - iOS 13+ is likely required
```

### Alternative Approach

If the service proves unreliable or unavailable:

1. **Use syslog_relay instead**: The `ios/syslog` package provides basic log streaming
2. **Hybrid approach**: Use syslog for basic logs, implement os_trace when available
3. **Version detection**: Check iOS version and only use os_trace on iOS 13+

### pymobiledevice3 Comparison

Need to verify:
- What iOS versions does pymobiledevice3 support for os_trace?
- Does it use the same 5-byte header protocol?
- Are there additional handshake steps we're missing?

### Next Steps

1. ✅ Discovered the 5-byte header protocol
2. ⏳ Implement custom OsTraceCodec
3. ⏳ Test with iOS 13+ devices  
4. ⏳ Add version detection and fallback to syslog
5. ⏳ Compare behavior with pymobiledevice3 on same device

## Raw Protocol Examples

### PidList Request
```
000000e2 3c3f786d6c...  (230 bytes total)
- Length: 0x000000E2 = 226 bytes
- Payload: XML plist with {"Request": "PidList"}
```

### PidList Response  
```
01 00003b4e [empty]
- Status: 0x01
- Length: 0x00003B4E = 15,182 bytes
- Payload: Empty (service may not support this command)
```

### StartActivity Request
```
00000214 3c3f786d6c...  (536 bytes total)
- Length: 0x00000214 = 532 bytes
- Payload: XML plist with MessageFilter and StreamFlags
```

### StartActivity Response
```
EOF (connection closed)
- Service closed connection immediately
- May indicate unsupported command or missing setup
```

## Conclusion

The implementation is structurally sound, but requires:
1. Custom codec for the 5-byte header protocol
2. Testing on appropriate iOS versions
3. Possibly additional setup/authentication steps

The core architecture and API design are complete and match pymobiledevice3's functionality. Once the protocol details are finalized, the implementation will be fully functional.

