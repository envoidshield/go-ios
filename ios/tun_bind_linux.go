//go:build linux

package ios

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func dialBindControl(ifName string) func(network, address string, c syscall.RawConn) error {
	if ifName == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
