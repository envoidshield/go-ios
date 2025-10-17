package ostrace_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios/ostrace"
	jsoniter "github.com/json-iterator/go"
)

var fastJSON = jsoniter.ConfigFastest

// Sample log entry for benchmarking
var sampleEntry = &ostrace.LogEntry{
	Timestamp: time.Now(),
	ProcessID: 1234,
	Level:     "info",
	ImageName: "SpringBoard",
	Message:   "This is a sample log message that might contain various information about the system state and operations",
	Filename:  "/System/Library/PrivateFrameworks/SpringBoard.framework/SpringBoard",
	Category:  "UI",
	Subsystem: "com.apple.springboard",
}

// Benchmark standard JSON encoding
func BenchmarkStandardJSON(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		data, _ := json.Marshal(sampleEntry)
		_ = data
	}
}

// Benchmark jsoniter encoding
func BenchmarkJsoniterJSON(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		data, _ := fastJSON.Marshal(sampleEntry)
		_ = data
	}
}

// Benchmark filter evaluation
func BenchmarkSimpleFilter(b *testing.B) {
	filter := ostrace.CreateSimpleFilter("SpringBoard")
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = ostrace.EvaluateFilters(sampleEntry, filter)
	}
}

// Benchmark complex filter evaluation
func BenchmarkComplexFilter(b *testing.B) {
	config := &ostrace.FilterConfig{
		Filters: []ostrace.Filter{
			{
				Type: "AND",
				Children: []ostrace.Filter{
					{Field: "image_name", Operator: "EQUALS", Value: "SpringBoard"},
					{Field: "level", Operator: "EQUALS", Value: "info"},
					{Field: "message", Operator: "CONTAINS", Value: "system"},
				},
			},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_ = ostrace.EvaluateFilters(sampleEntry, config)
	}
}

// Benchmark string formatting
func BenchmarkLogFormatting(b *testing.B) {
	b.ReportAllocs()
	var buf bytes.Buffer
	
	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.WriteString("[")
		buf.WriteString(sampleEntry.Timestamp.Format("15:04:05.000"))
		buf.WriteString("] ")
		buf.WriteString(sampleEntry.ImageName)
		buf.WriteString("[")
		buf.WriteString(strconv.Itoa(sampleEntry.ProcessID))
		buf.WriteString("]: ")
		buf.WriteString(sampleEntry.Message)
		buf.WriteString("\n")
	}
}
