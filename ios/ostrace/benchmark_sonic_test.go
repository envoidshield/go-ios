//go:build sonic
// +build sonic

package ostrace_test

import (
	"testing"
	"time"

	"reflect"

	"github.com/bytedance/sonic"
	"github.com/danielpaulus/go-ios/ios/ostrace"
)

// Benchmark Sonic JSON encoding
func BenchmarkSonicJSON(b *testing.B) {
	entry := &ostrace.LogEntry{
		Timestamp: time.Now(),
		ProcessID: 1234,
		Level:     "info",
		ImageName: "SpringBoard",
		Message:   "This is a sample log message that might contain various information about the system state and operations",
		Filename:  "/System/Library/PrivateFrameworks/SpringBoard.framework/SpringBoard",
		Category:  "UI",
		Subsystem: "com.apple.springboard",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		data, _ := sonic.Marshal(entry)
		_ = data
	}
}

// Benchmark Sonic with pretouch (pre-compile reflection)
func BenchmarkSonicJSONPretouch(b *testing.B) {
	// Pretouch the type for better performance
	sonic.Pretouch(reflect.TypeOf(ostrace.LogEntry{}))

	entry := &ostrace.LogEntry{
		Timestamp: time.Now(),
		ProcessID: 1234,
		Level:     "info",
		ImageName: "SpringBoard",
		Message:   "This is a sample log message that might contain various information about the system state and operations",
		Filename:  "/System/Library/PrivateFrameworks/SpringBoard.framework/SpringBoard",
		Category:  "UI",
		Subsystem: "com.apple.springboard",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, _ := sonic.Marshal(entry)
		_ = data
	}
}
