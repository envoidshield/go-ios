//go:build linux

package tunnel

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// linuxTun closes the water TUN and deletes the host-side /128 assignment (and
// any explicit device /128 route left from older builds).
type linuxTun struct {
	io.ReadWriteCloser
	ifName     string
	clientAddr string
	serverAddr string
	usedPeer   bool
}

func (t *linuxTun) Close() error {
	ifName := t.ifName
	if ifName != "" {
		if addr := strings.TrimSpace(t.serverAddr); addr != "" {
			_ = runCmd(exec.Command("ip", "-6", "route", "del", addr+"/128", "dev", ifName))
		}
		if addr := strings.TrimSpace(t.clientAddr); addr != "" {
			_ = runCmd(exec.Command("ip", "-6", "addr", "del", addr+"/128", "dev", ifName))
		}
	}
	return t.ReadWriteCloser.Close()
}

func wrapLinuxTunCloser(rwc io.ReadWriteCloser, ifName, clientAddr, serverAddr string, usedPeer bool) io.ReadWriteCloser {
	return &linuxTun{
		ReadWriteCloser: rwc,
		ifName:          ifName,
		clientAddr:      clientAddr,
		serverAddr:      serverAddr,
		usedPeer:        usedPeer,
	}
}

func linuxTunnelAddrAdd(ifName, clientAddr, serverAddr string) error {
	clientAddr = strings.TrimSpace(clientAddr)
	if clientAddr == "" {
		return fmt.Errorf("setupTunnelInterface: empty client address")
	}
	// ponytail: skip `peer` on Linux. Peer /128 makes the kernel treat the iface as
	// pointopoint and locally-generated tcp6 to the device ULA bypasses TUN read
	// (RX ~0, TX high). Host /128 + explicit device /128 route in setupTunnelInterface.
	_ = serverAddr
	cmd := exec.Command("ip", "-6", "addr", "add", clientAddr+"/128", "dev", ifName)
	return runCmd(cmd)
}

func linuxTuneInterface(ifName string) {
	if ifName == "" {
		return
	}
	_ = runCmd(exec.Command("sysctl", "-q", "-w", "net.ipv6.conf."+ifName+".accept_local=1"))
	_ = runCmd(exec.Command("sysctl", "-q", "-w", "net.ipv6.conf."+ifName+".accept_ra=0"))
}
