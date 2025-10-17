// +build perf

package ostrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// High-performance optimizations for massive log processing

// LogEntryPool provides zero-allocation log entry reuse
var logEntryPool = sync.Pool{
	New: func() interface{} {
		return &LogEntry{}
	},
}

// GetLogEntry gets a reusable LogEntry from the pool
func GetLogEntry() *LogEntry {
	return logEntryPool.Get().(*LogEntry)
}

// PutLogEntry returns a LogEntry to the pool for reuse
func PutLogEntry(entry *LogEntry) {
	// Clear the entry
	entry.Timestamp = entry.Timestamp.Truncate(0)
	entry.ProcessID = 0
	entry.Level = ""
	entry.ImageName = ""
	entry.Message = ""
	entry.Filename = ""
	entry.Category = ""
	entry.Subsystem = ""
	logEntryPool.Put(entry)
}

// StringBuffer is a reusable buffer for string building
type StringBuffer struct {
	buf []byte
}

var stringBufferPool = sync.Pool{
	New: func() interface{} {
		return &StringBuffer{
			buf: make([]byte, 0, 1024),
		}
	},
}

// GetStringBuffer gets a reusable string buffer
func GetStringBuffer() *StringBuffer {
	return stringBufferPool.Get().(*StringBuffer)
}

// PutStringBuffer returns a string buffer to the pool
func PutStringBuffer(sb *StringBuffer) {
	sb.buf = sb.buf[:0]
	stringBufferPool.Put(sb)
}

// unsafeString converts bytes to string without allocation
// ONLY use for read-only strings that won't be modified
func unsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// FastReadLogEntry is a zero-copy version of ReadLogEntry for maximum performance
// The returned LogEntry should be processed immediately and then returned to the pool
func (c *Connection) FastReadLogEntry() (*LogEntry, error) {
	// Read the chunk
	chunkBytes, err := c.codec.ReadStreamChunk(c.deviceConn.Reader())
	if err != nil {
		return nil, err
	}

	// Get entry from pool
	entry := GetLogEntry()

	// Parse using unsafe string conversions (zero-copy)
	if len(chunkBytes) < 116 {
		PutLogEntry(entry)
		return nil, fmt.Errorf("log chunk too small: %d bytes", len(chunkBytes))
	}

	// Same parsing logic but with zero-copy strings
	offset := 9
	
	// PID
	entry.ProcessID = int(binary.LittleEndian.Uint32(chunkBytes[offset:offset+4]))
	offset += 4 + 42
	
	// Timestamp
	timestampSec := binary.LittleEndian.Uint32(chunkBytes[offset:offset+4])
	offset += 8
	timestampUS := binary.LittleEndian.Uint32(chunkBytes[offset:offset+4])
	offset += 5
	
	entry.Timestamp = time.Unix(int64(timestampSec), int64(timestampUS)*1000)
	
	// Level
	levelMap := [...]string{
		0x00: "default",
		0x01: "info",
		0x02: "debug",
		0x10: "error",
		0x11: "fault",
	}
	
	level := chunkBytes[offset]
	offset += 1
	if int(level) < len(levelMap) {
		entry.Level = levelMap[level]
	} else {
		entry.Level = "unknown"
	}
	
	offset += 38
	
	// String lengths
	imageNameLen := int(binary.LittleEndian.Uint16(chunkBytes[offset:offset+2]))
	offset += 2
	messageLen := int(binary.LittleEndian.Uint16(chunkBytes[offset:offset+2]))
	offset += 2 + 6  // 2 for the field, 6 bytes skip
	subsystemLen := int(binary.LittleEndian.Uint32(chunkBytes[offset:offset+4]))
	offset += 4
	categoryLen := int(binary.LittleEndian.Uint32(chunkBytes[offset:offset+4]))
	offset += 4
	
	// Skip 4 bytes after category size
	offset += 4
	
	// Find null-terminated filename
	filenameStart := offset
	filenameEnd := offset
	for filenameEnd < len(chunkBytes) && chunkBytes[filenameEnd] != 0 {
		filenameEnd++
	}
	
	// Use unsafe string conversions (zero-copy)
	if filenameEnd > filenameStart {
		entry.Filename = unsafeString(chunkBytes[filenameStart:filenameEnd])
	}
	offset = filenameEnd + 1
	
	// Read other strings with bounds checking
	if offset+imageNameLen <= len(chunkBytes) {
		entry.ImageName = unsafeString(chunkBytes[offset:offset+imageNameLen])
		offset += imageNameLen
	}
	
	if offset+messageLen <= len(chunkBytes) {
		// Clean up message
		msg := chunkBytes[offset:offset+messageLen]
		if idx := bytes.IndexByte(msg, 0); idx >= 0 {
			msg = msg[:idx]
		}
		entry.Message = unsafeString(msg)
		offset += messageLen
	}
	
	if subsystemLen > 0 && offset+int(subsystemLen) <= len(chunkBytes) {
		sub := chunkBytes[offset:offset+int(subsystemLen)]
		if idx := bytes.IndexByte(sub, 0); idx >= 0 {
			sub = sub[:idx]
		}
		entry.Subsystem = unsafeString(sub)
		offset += int(subsystemLen)
	}
	
	if categoryLen > 0 && offset+int(categoryLen) <= len(chunkBytes) {
		cat := chunkBytes[offset:offset+int(categoryLen)]
		if idx := bytes.IndexByte(cat, 0); idx >= 0 {
			cat = cat[:idx]
		}
		entry.Category = unsafeString(cat)
	}
	
	return entry, nil
}
