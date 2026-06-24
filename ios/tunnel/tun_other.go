//go:build !linux

package tunnel

import (
	"fmt"
	"io"
)

// openLinuxPITun is linux-only; this stub keeps the package building on other
// platforms. setupTunnelInterface only calls it under runtime.GOOS == "linux".
func openLinuxPITun() (io.ReadWriteCloser, string, error) {
	return nil, "", fmt.Errorf("openLinuxPITun: not supported on this platform")
}

func wrapLinuxTunCloser(rwc io.ReadWriteCloser, ifName, clientAddr, serverAddr string, usedPeer bool) io.ReadWriteCloser {
	return rwc
}

func linuxTunnelAddrAdd(ifName, clientAddr, serverAddr string) error {
	return nil
}

func linuxTuneInterface(string) {}
