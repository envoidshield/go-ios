package main

import (
	"log"
)

func main() {
	// Create and run the GUI application
	guiApp := NewGUIApp()
	
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	// Run the GUI
	guiApp.Run()
}
