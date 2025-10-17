package ostrace

// This file contains example code for documentation purposes
// These examples demonstrate how to use the ostrace package

/*
Example 1: Get Process List

	package main

	import (
		"fmt"
		"log"

		"github.com/danielpaulus/go-ios/ios"
		"github.com/danielpaulus/go-ios/ios/ostrace"
	)

	func main() {
		device, err := ios.GetDevice("")
		if err != nil {
			log.Fatal(err)
		}

		conn, err := ostrace.New(device)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		processes, err := conn.GetProcessList()
		if err != nil {
			log.Fatal(err)
		}

		for _, proc := range processes {
			fmt.Printf("%s (PID: %d)\n", proc.Label, proc.PID)
		}
	}

Example 2: Stream Logs from Specific Process

	package main

	import (
		"fmt"
		"log"

		"github.com/danielpaulus/go-ios/ios"
		"github.com/danielpaulus/go-ios/ios/ostrace"
	)

	func main() {
		device, err := ios.GetDevice("")
		if err != nil {
			log.Fatal(err)
		}

		conn, err := ostrace.New(device)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		config := ostrace.StreamConfig{
			PID:        123, // Replace with actual PID
			DebugLevel: true,
			InfoLevel:  true,
		}

		err = conn.StartStreaming(config)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.StopStreaming()

		for {
			entry, err := conn.ReadLogEntry()
			if err != nil {
				log.Printf("Error: %v", err)
				continue
			}

			fmt.Println(ostrace.FormatLogEntry(entry))
		}
	}

Example 3: Download Archived Logs

	package main

	import (
		"fmt"
		"log"

		"github.com/danielpaulus/go-ios/ios"
		"github.com/danielpaulus/go-ios/ios/ostrace"
	)

	func main() {
		device, err := ios.GetDevice("")
		if err != nil {
			log.Fatal(err)
		}

		conn, err := ostrace.New(device)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		err = conn.SaveArchivedLogsToFile("device_logs.pax")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Saved to device_logs.pax")
		fmt.Println("Extract with: pax -r < device_logs.pax")
	}
*/

