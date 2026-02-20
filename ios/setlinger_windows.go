//go:build windows

package ios

import "syscall"

func setSOLinger(rawConn syscall.RawConn) {
	rawConn.Control(func(fd uintptr) { //nolint:errcheck
		syscall.SetsockoptLinger(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0}) //nolint:errcheck
	})
}
