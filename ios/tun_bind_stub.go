//go:build !linux && !darwin

package ios

import "syscall"

func dialBindControl(ifName string) func(network, address string, c syscall.RawConn) error {
	return nil
}
