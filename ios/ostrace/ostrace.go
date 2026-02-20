package ostrace

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"howett.net/plist"
)

const (
	serviceName     = "com.apple.os_trace_relay"
	shimServiceName = "com.apple.os_trace_relay.shim.remote"
)

// Buffer pools to reduce allocations
var (
	// Pool for small buffers (headers, etc)
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 256)
			return &buf
		},
	}

	// Pool for larger buffers (log chunks)
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 4096)
			return &buf
		},
	}
)

// OsTraceCodec handles the custom os_trace protocol
// Based on pymobiledevice3 implementation:
// - Initial responses: ignore 1 byte, then read 4-byte big-endian prefixed data
// - Streaming: 0x02 status byte + 4-byte little-endian length + data
type OsTraceCodec struct{}

// WriteRequest encodes and writes a request with standard 4-byte big-endian length header
func (c *OsTraceCodec) WriteRequest(w io.Writer, msg interface{}) error {
	// Marshal as binary plist
	plistBytes, err := plist.Marshal(msg, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Write 4-byte big-endian length header
	length := uint32(len(plistBytes))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}

	// Write payload
	if _, err := w.Write(plistBytes); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}

	return nil
}

// Note: ReadInitialResponse removed - not used anymore

// ReadStreamChunk reads a streaming log chunk
// Protocol: 0x02 status byte + 4-byte little-endian length + data
// Now accepts *bufio.Reader for high-performance buffered reads
func (c *OsTraceCodec) ReadStreamChunk(r *bufio.Reader) ([]byte, error) {
	// Get a small buffer from pool for header
	headerBufPtr := smallBufferPool.Get().(*[]byte)
	headerBuf := (*headerBufPtr)[:5] // 1 status + 4 length
	defer smallBufferPool.Put(headerBufPtr)

	// Read status byte and length in one go
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, err
	}

	if headerBuf[0] != 0x02 {
		return nil, fmt.Errorf("unexpected status byte: 0x%02x (expected 0x02)", headerBuf[0])
	}

	// Read 4-byte little-endian length
	length := binary.LittleEndian.Uint32(headerBuf[1:5])

	// Allocate exact size needed (can't use pool here as size varies)
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("failed to read chunk data: %w", err)
	}

	return data, nil
}

// ReadStreamChunkWithDeadline reads a streaming log chunk with deadline support
// This version should be called by Connection methods that manage deadlines
// Now accepts *bufio.Reader and only updates deadline once (not twice)
func (c *OsTraceCodec) ReadStreamChunkWithDeadline(r *bufio.Reader, updateDeadline func() error) ([]byte, error) {
	// Single deadline update - applies to entire chunk read
	// Optimized: was updating twice (before header, before data), now just once
	if err := updateDeadline(); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Get a small buffer from pool for header
	headerBufPtr := smallBufferPool.Get().(*[]byte)
	headerBuf := (*headerBufPtr)[:5] // 1 status + 4 length
	defer smallBufferPool.Put(headerBufPtr)

	// Read status byte and length in one go
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, err
	}

	if headerBuf[0] != 0x02 {
		return nil, fmt.Errorf("unexpected status byte: 0x%02x (expected 0x02)", headerBuf[0])
	}

	// Read 4-byte little-endian length
	length := binary.LittleEndian.Uint32(headerBuf[1:5])

	// Allocate exact size needed (can't use pool here as size varies)
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("failed to read chunk data: %w", err)
	}

	return data, nil
}

// Connection represents a connection to the os_trace_relay service
type Connection struct {
	deviceConn   ios.DeviceConnectionInterface
	codec        *OsTraceCodec
	reader       *bufio.Reader // Buffered reader for high-performance socket reads
	readTimeout  time.Duration // Optional read timeout for blocking operations
	readDeadline time.Time     // Last set read deadline
}

// New creates a new os_trace_relay connection
func New(device ios.DeviceEntry) (*Connection, error) {
	if device.SupportsRsd() {
		return NewWithShimConnection(device)
	}
	return NewWithUsbmuxdConnection(device)
}

// SetReadTimeout sets a timeout for read operations
// If timeout is 0, no timeout is set (blocking reads)
// This helps detect stalled connections by preventing indefinite blocking
func (c *Connection) SetReadTimeout(timeout time.Duration) {
	c.readTimeout = timeout
}

// updateReadDeadline updates the read deadline on the underlying connection
// This is called before each read operation when readTimeout is set
func (c *Connection) updateReadDeadline() error {
	if c.readTimeout == 0 {
		return nil // No timeout configured
	}

	conn := c.deviceConn.Conn()
	if conn == nil {
		return nil // Connection doesn't support deadlines
	}

	deadline := time.Now().Add(c.readTimeout)
	c.readDeadline = deadline
	return conn.SetReadDeadline(deadline)
}

// NewWithUsbmuxdConnection connects to os_trace_relay via usbmuxd
func NewWithUsbmuxdConnection(device ios.DeviceEntry) (*Connection, error) {
	deviceConn, err := ios.ConnectToService(device, serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", serviceName, err)
	}

	conn := &Connection{
		deviceConn: deviceConn,
		codec:      &OsTraceCodec{},
	}
	// Add buffered reader for high-performance socket reads (256KB buffer)
	// This reduces syscalls from 2 per log to ~1 per 1000 logs
	conn.reader = bufio.NewReaderSize(conn.deviceConn.Reader(), 256*1024)
	return conn, nil
}

// NewWithShimConnection connects to os_trace_relay via RSD tunnel
func NewWithShimConnection(device ios.DeviceEntry) (*Connection, error) {
	deviceConn, err := ios.ConnectToShimService(device, shimServiceName)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", shimServiceName, err)
	}

	conn := &Connection{
		deviceConn: deviceConn,
		codec:      &OsTraceCodec{},
	}
	// Add buffered reader for high-performance socket reads (256KB buffer)
	// This reduces syscalls from 2 per log to ~1 per 1000 logs
	conn.reader = bufio.NewReaderSize(conn.deviceConn.Reader(), 256*1024)
	return conn, nil
}

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	Label string `plist:"Label" json:"label"`
	PID   int    `plist:"Pid" json:"pid"`
}

// ProcessListResponse represents the response from a process list request
// Note: The response format differs between direct USB and tunnel connections:
// - Direct USB: Payload is []ProcessInfo
// - Tunnel: Payload is map[string]map[string]interface{} where keys are PIDs
type ProcessListResponse struct {
	Payload interface{} `plist:"Payload" json:"payload"`
	Status  string      `plist:"Status" json:"status"`
}

// recvall reads exactly size bytes from the reader, similar to pymobiledevice3's recvall
// This properly handles TLS record fragmentation where large messages are split into 16KB chunks
func recvall(r io.Reader, size int) ([]byte, error) {
	data := make([]byte, size)
	totalRead := 0

	for totalRead < size {
		// Read remaining data
		n, err := r.Read(data[totalRead:])
		if n > 0 {
			totalRead += n
		}

		// If we got all the data we need, return success
		if totalRead == size {
			return data, nil
		}

		// Handle errors
		if err != nil {
			// EOF is only acceptable if we haven't read anything yet
			if err == io.EOF && totalRead == 0 {
				return nil, err
			}
			// Otherwise, EOF means connection closed prematurely
			if err == io.EOF {
				return data[:totalRead], fmt.Errorf("connection closed after %d bytes, expected %d", totalRead, size)
			}
			// Any other error
			return data[:totalRead], fmt.Errorf("read error after %d bytes: %w", totalRead, err)
		}
	}

	return data, nil
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// GetProcessList retrieves the list of running processes
// NOTE: When using direct USB connection, this command may fail if the response exceeds 16KB
// due to a limitation in iOS's os_trace_relay service. The device closes the connection after
// sending exactly one 16KB TLS record. This limitation does not exist when using tunnel connections.
// Workarounds:
// 1. Use 'ios tunnel start' to enable tunnel connection
// 2. Use 'ios ps' command as an alternative (uses instruments service)
func (c *Connection) GetProcessList() ([]ProcessInfo, error) {
	request := map[string]interface{}{
		"Request": "PidList",
	}

	// Send request
	if err := c.codec.WriteRequest(c.deviceConn.Writer(), request); err != nil {
		return nil, fmt.Errorf("failed to send PidList request: %w", err)
	}

	reader := c.deviceConn.Reader()

	// Ignore first received unknown byte (per pymobiledevice3)
	skipByte := make([]byte, 1)
	if _, err := reader.Read(skipByte); err != nil {
		return nil, fmt.Errorf("failed to read first byte: %w", err)
	}

	// Now use the standard PlistCodec to read the length-prefixed response
	// This mimics pymobiledevice3's recv_prefixed() which reads 4 bytes then the payload
	codec := ios.NewPlistCodec()
	responseBytes, err := codec.Decode(reader)
	if err != nil {
		// Check if it's the known 16KB limitation
		if errStr := err.Error(); contains(errStr, "16384") || contains(errStr, "unexpected EOF") {
			return nil, fmt.Errorf("failed to read response: %w. This often happens with direct USB connections when the response exceeds 16KB. Solutions: 1) Use 'ios tunnel start' to enable tunnel connection, 2) Use 'ios ps' command instead", err)
		}
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response ProcessListResponse
	if _, err := plist.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PidList response: %w", err)
	}

	if response.Status != "RequestSuccessful" {
		return nil, fmt.Errorf("PidList request failed with status: %s", response.Status)
	}

	// Handle different response formats
	switch payload := response.Payload.(type) {
	case []interface{}:
		// Direct USB format: array of ProcessInfo
		processes := make([]ProcessInfo, 0, len(payload))
		for _, item := range payload {
			if procMap, ok := item.(map[string]interface{}); ok {
				proc := ProcessInfo{}
				if label, ok := procMap["Label"].(string); ok {
					proc.Label = label
				}
				if pid, ok := procMap["Pid"].(uint64); ok {
					proc.PID = int(pid)
				}
				processes = append(processes, proc)
			}
		}
		return processes, nil

	case map[string]interface{}:
		// Tunnel format: map of PID -> process info
		processes := make([]ProcessInfo, 0, len(payload))
		for pidStr, procData := range payload {
			if procMap, ok := procData.(map[string]interface{}); ok {
				proc := ProcessInfo{}
				// Convert PID string to int
				if _, err := fmt.Sscanf(pidStr, "%d", &proc.PID); err == nil {
					if name, ok := procMap["ProcessName"].(string); ok {
						proc.Label = name
					}
					processes = append(processes, proc)
				}
			}
		}
		return processes, nil

	default:
		return nil, fmt.Errorf("unexpected Payload type: %T", response.Payload)
	}
}

// SyslogEntryHeader - looking at the hex dump, the struct starts after some initial bytes
// The lengths appear at fixed positions before the strings
type SyslogEntryHeader struct {
	// Skip to where we see recognizable patterns
	// This is a simplified version - just get the key fields we need
	Data []byte
}

// LogEntry represents a parsed log entry from the binary stream
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	ProcessID int       `json:"pid"`
	Level     string    `json:"level"`
	ImageName string    `json:"image_name"`
	Message   string    `json:"message"`
	Filename  string    `json:"filename"`
	Category  string    `json:"category,omitempty"`
	Subsystem string    `json:"subsystem,omitempty"`
}

// StreamConfig configures the log streaming
type StreamConfig struct {
	// Filter by process ID (-1 means all processes, 0 is kernel, positive values are specific PIDs)
	PID int
	// Filter by log level
	LogLevel string
	// Include debug messages
	DebugLevel bool
	// Include info messages
	InfoLevel bool
	// Include errors only
	ErrorsOnly bool
}

// StreamLogsResponse represents the initial response when starting log streaming
type StreamLogsResponse struct {
	Status string `plist:"Status"`
}

// StartStreaming starts streaming syslog lines
// Based on pymobiledevice3: {'Request': 'StartActivity', 'MessageFilter': 65535, 'Pid': pid, 'StreamFlags': 60}
func (c *Connection) StartStreaming(config StreamConfig) error {
	// Use the PID directly - 0 is valid for kernel, -1 means all processes
	request := map[string]interface{}{
		"Request":       "StartActivity",
		"MessageFilter": uint64(65535), // Include all message types
		"Pid":           config.PID,    // 0 for kernel, specific PID, or -1 for all
		"StreamFlags":   uint64(60),    // Standard stream flags
	}

	// Send request
	if err := c.codec.WriteRequest(c.deviceConn.Writer(), request); err != nil {
		return fmt.Errorf("failed to send StartActivity request: %w", err)
	}

	// Read variable-length response header
	// First: read 4 bytes to get "length of length"
	lengthOfLength := make([]byte, 4)
	if _, err := io.ReadFull(c.deviceConn.Reader(), lengthOfLength); err != nil {
		return fmt.Errorf("failed to read length-of-length: %w", err)
	}

	lenLen := binary.LittleEndian.Uint32(lengthOfLength)

	// Read the actual length bytes (reversed/big-endian when converted)
	lengthBytes := make([]byte, lenLen)
	if _, err := io.ReadFull(c.deviceConn.Reader(), lengthBytes); err != nil {
		return fmt.Errorf("failed to read length bytes: %w", err)
	}

	// Reverse bytes and convert to integer (per pymobiledevice3)
	for i, j := 0, len(lengthBytes)-1; i < j; i, j = i+1, j-1 {
		lengthBytes[i], lengthBytes[j] = lengthBytes[j], lengthBytes[i]
	}
	length := uint64(0)
	for _, b := range lengthBytes {
		length = length*256 + uint64(b)
	}

	// Read response plist
	responseBytes := make([]byte, length)
	if _, err := io.ReadFull(c.deviceConn.Reader(), responseBytes); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var response StreamLogsResponse
	if _, err := plist.Unmarshal(responseBytes, &response); err != nil {
		return fmt.Errorf("failed to unmarshal StartActivity response: %w", err)
	}

	if response.Status != "RequestSuccessful" {
		return fmt.Errorf("StartActivity failed with status: %s", response.Status)
	}

	return nil
}

// ReadLogEntry reads and parses a single log entry from the binary stream
func (c *Connection) ReadLogEntry() (*LogEntry, error) {
	// Read stream chunk with deadline support if configured
	var chunkBytes []byte
	var err error

	if c.readTimeout > 0 {
		chunkBytes, err = c.codec.ReadStreamChunkWithDeadline(c.reader, c.updateReadDeadline)
	} else {
		chunkBytes, err = c.codec.ReadStreamChunk(c.reader)
	}

	if err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, fmt.Errorf("failed to read log chunk: %w", err)
	}

	// Based on pymobiledevice3 syslog_t struct:
	// Bytes(7), pid, Bytes(42), timestamp(8), Bytes(1), level, Bytes(38),
	// image_name_size(2), message_size(2), Bytes(6), subsystem_size(4), category_size(4)
	// Then: filename (null-terminated), image_name, message, [subsystem, category]

	if len(chunkBytes) < 116 { // minimum size check
		return nil, fmt.Errorf("log chunk too small: %d bytes", len(chunkBytes))
	}

	// Parse according to pymobiledevice3 struct
	offset := 0

	// Skip 9 bytes (initial padding)
	offset += 9

	// PID (4 bytes, little-endian)
	pid := binary.LittleEndian.Uint32(chunkBytes[offset : offset+4])
	offset += 4

	// Skip 42 bytes
	offset += 42

	// Timestamp seconds (4 bytes, little-endian)
	timestampSec := binary.LittleEndian.Uint32(chunkBytes[offset : offset+4])
	offset += 4

	// Skip 4 bytes
	offset += 4

	// Timestamp microseconds (4 bytes, little-endian)
	timestampUS := binary.LittleEndian.Uint32(chunkBytes[offset : offset+4])
	offset += 4

	// Skip 1 byte
	offset += 1

	// Level (1 byte)
	level := chunkBytes[offset]
	offset += 1

	// Skip 38 bytes
	offset += 38

	// Image name size (2 bytes, little-endian)
	imageNameLen := binary.LittleEndian.Uint16(chunkBytes[offset : offset+2])
	offset += 2

	// Message size (2 bytes, little-endian)
	messageLen := binary.LittleEndian.Uint16(chunkBytes[offset : offset+2])
	offset += 2

	// Skip 6 bytes
	offset += 6

	// Subsystem size (4 bytes, little-endian)
	subsystemLen := binary.LittleEndian.Uint32(chunkBytes[offset : offset+4])
	offset += 4

	// Category size (4 bytes, little-endian)
	categoryLen := binary.LittleEndian.Uint32(chunkBytes[offset : offset+4])
	offset += 4

	// Skip 4 bytes after category size
	offset += 4

	// Now read the variable-length fields
	reader := bytes.NewReader(chunkBytes[offset:])

	// Read filename (null-terminated)
	filename := []byte{}
	for {
		b, err := reader.ReadByte()
		if err != nil || b == 0 {
			break
		}
		filename = append(filename, b)
	}

	// Read image_name
	imageName := make([]byte, imageNameLen)
	if _, err := io.ReadFull(reader, imageName); err != nil {
		return nil, fmt.Errorf("failed to read image name: %w", err)
	}

	// Read message
	message := make([]byte, messageLen)
	if _, err := io.ReadFull(reader, message); err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	// Create log entry
	entry := &LogEntry{
		Timestamp: time.Unix(int64(timestampSec), int64(timestampUS)*1000),
		ProcessID: int(pid),
		Level:     logLevelToString(uint64(level)),
		ImageName: strings.TrimRight(string(imageName), "\x00"),
		Message:   strings.TrimRight(string(message), "\x00"),
		Filename:  string(filename),
	}

	// Read optional subsystem and category
	if subsystemLen > 0 && subsystemLen < 10000 {
		subsystem := make([]byte, subsystemLen)
		if _, err := io.ReadFull(reader, subsystem); err == nil {
			entry.Subsystem = strings.TrimRight(string(subsystem), "\x00")
		}
	}

	if categoryLen > 0 && categoryLen < 10000 {
		category := make([]byte, categoryLen)
		if _, err := io.ReadFull(reader, category); err == nil {
			entry.Category = strings.TrimRight(string(category), "\x00")
		}
	}

	return entry, nil
}

// ArchiveResponse represents the response containing archived logs
type ArchiveResponse struct {
	Status       string `plist:"Status"`
	ArchiveData  []byte `plist:"ArchiveData"`
	ArchiveSize  int    `plist:"ArchiveSize"`
	ErrorMessage string `plist:"ErrorMessage,omitempty"`
}

// GetArchivedLogs retrieves archived syslog data in PAX format
// The data comes from /var/db/diagnostics directory
// Based on pymobiledevice3 CreateArchive implementation
func (c *Connection) GetArchivedLogs() ([]byte, error) {
	request := map[string]interface{}{
		"Request": "CreateArchive",
	}

	// Send request
	if err := c.codec.WriteRequest(c.deviceConn.Writer(), request); err != nil {
		return nil, fmt.Errorf("failed to send CreateArchive request: %w", err)
	}

	// Read initial response (should be status 0x01 + plist with Status: RequestSuccessful)
	statusByte := make([]byte, 1)
	if _, err := io.ReadFull(c.deviceConn.Reader(), statusByte); err != nil {
		return nil, fmt.Errorf("failed to read status byte: %w", err)
	}

	if statusByte[0] != 0x01 {
		return nil, fmt.Errorf("unexpected initial status byte: 0x%02x", statusByte[0])
	}

	// Read 4-byte big-endian length
	var length uint32
	if err := binary.Read(c.deviceConn.Reader(), binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	// Read initial response plist
	initialResp := make([]byte, length)
	if _, err := io.ReadFull(c.deviceConn.Reader(), initialResp); err != nil {
		return nil, fmt.Errorf("failed to read initial response: %w", err)
	}

	var response map[string]interface{}
	if _, err := plist.Unmarshal(initialResp, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal initial response: %w", err)
	}

	if status, _ := response["Status"].(string); status != "RequestSuccessful" {
		return nil, fmt.Errorf("CreateArchive failed with status: %s", status)
	}

	// Now read archive chunks (status byte 0x03 + little-endian length + data)
	var allData bytes.Buffer

	for {
		chunkStatus := make([]byte, 1)
		_, err := io.ReadFull(c.deviceConn.Reader(), chunkStatus)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk status: %w", err)
		}

		if chunkStatus[0] != 0x03 {
			return nil, fmt.Errorf("unexpected chunk status byte: 0x%02x (expected 0x03)", chunkStatus[0])
		}

		// Read little-endian length
		var length uint32
		if err := binary.Read(c.deviceConn.Reader(), binary.LittleEndian, &length); err != nil {
			return nil, fmt.Errorf("failed to read chunk length: %w", err)
		}

		// Read chunk data
		chunkData := make([]byte, length)
		if _, err := io.ReadFull(c.deviceConn.Reader(), chunkData); err != nil {
			return nil, fmt.Errorf("failed to read chunk data: %w", err)
		}

		allData.Write(chunkData)
	}

	return allData.Bytes(), nil
}

// GetArchivedLogsWithProgress retrieves archived logs with progress callback
// Note: The os_trace_relay protocol doesn't provide total size in advance,
// so progress is reported as bytes downloaded without a total
func (c *Connection) GetArchivedLogsWithProgress(progressCallback func(current, total int)) ([]byte, error) {
	// For now, just call GetArchivedLogs
	// TODO: Implement proper progress tracking by reading chunks and calling callback
	return c.GetArchivedLogs()
}

// SaveArchivedLogsToFile saves archived logs to a file
// The file will be in PAX format and can be extracted with: pax -r <filename>
func (c *Connection) SaveArchivedLogsToFile(filename string) error {
	data, err := c.GetArchivedLogs()
	if err != nil {
		return err
	}

	// Write to file with appropriate permissions
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filename, err)
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

// StopStreaming stops the current streaming session
func (c *Connection) StopStreaming() error {
	request := map[string]interface{}{
		"Request": "StopActivity",
	}

	// Send request - connection may close immediately
	_ = c.codec.WriteRequest(c.deviceConn.Writer(), request)

	// Don't wait for response - service typically closes connection
	return nil
}

// Close closes the connection
func (c *Connection) Close() error {
	return c.deviceConn.Close()
}

// Removed: buildPredicate and buildStreamFlags
// Not needed - pymobiledevice3 uses simple values (MessageFilter: 65535, StreamFlags: 60)

func logLevelToString(level uint64) string {
	switch level {
	case 0:
		return "default"
	case 1:
		return "info"
	case 2:
		return "debug"
	case 16:
		return "error"
	case 17:
		return "fault"
	default:
		return fmt.Sprintf("unknown(%d)", level)
	}
}

// FormatLogEntry formats a log entry as a human-readable string
func FormatLogEntry(entry *LogEntry) string {
	subsystem := entry.Subsystem
	if subsystem == "" {
		subsystem = "-"
	}
	category := entry.Category
	if category == "" {
		category = "-"
	}
	return fmt.Sprintf("[%s] [%s] [%d] [%s] [%s/%s] %s",
		entry.Timestamp.Format("2006-01-02 15:04:05.000"),
		entry.Level,
		entry.ProcessID,
		entry.ImageName,
		subsystem,
		category,
		entry.Message,
	)
}
