//go:build windows

package tunnel

import (
	"os/exec"
	"syscall"
)

// setSysProcAttr sets Windows-specific process attributes to hide the console window
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
