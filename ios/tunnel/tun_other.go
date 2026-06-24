//go:build !linux

package tunnel

import "io"

func wrapLinuxTunCloser(rwc io.ReadWriteCloser, ifName, clientAddr, serverAddr string, usedPeer bool) io.ReadWriteCloser {
	return rwc
}

func linuxTunnelAddrAdd(ifName, clientAddr, serverAddr string) error {
	return nil
}

func linuxTuneInterface(string) {}
