//go:build darwin

package ios

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func dialBindControl(ifName string) func(network, address string, c syscall.RawConn) error {
	if ifName == "" {
		return nil
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return func(network, address string, c syscall.RawConn) error {
			return fmt.Errorf("dialBindControl: %w", err)
		}
	}
	idx := iface.Index
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
