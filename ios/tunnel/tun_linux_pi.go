//go:build linux

package tunnel

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

const cIFFTUN = 0x0001

const (
	linuxPIHeaderLen = 4
)

var linuxPIHeaderPrefix = []byte{0x00, 0x00, 0x86, 0xdd}

// linuxPITun is a Linux TUN fd opened without IFF_NO_PI, matching pymobiledevice3
// (PI header 0x000086dd before each IPv6 frame).
type linuxPITun struct {
	f *os.File
}

func openLinuxPITun() (*linuxPITun, string, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("openLinuxPITun: %w", err)
	}
	var ifr struct {
		Name  [16]byte
		Flags uint16
		_     [0x28 - 0x10 - 2]byte
	}
	ifr.Flags = cIFFTUN
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		_ = f.Close()
		return nil, "", fmt.Errorf("openLinuxPITun: TUNSETIFF: %w", errno)
	}
	name := string(bytesTrimZero(ifr.Name[:]))
	return &linuxPITun{f: f}, name, nil
}

func bytesTrimZero(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

func (t *linuxPITun) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	tmp := make([]byte, linuxPIHeaderLen+len(p))
	n, err := t.f.Read(tmp)
	if err != nil {
		return 0, err
	}
	if n <= linuxPIHeaderLen {
		return 0, fmt.Errorf("openLinuxPITun: short read %d", n)
	}
	return copy(p, tmp[linuxPIHeaderLen:n]), nil
}

func (t *linuxPITun) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	buf := make([]byte, linuxPIHeaderLen+len(p))
	copy(buf, linuxPIHeaderPrefix)
	copy(buf[linuxPIHeaderLen:], p)
	if _, err := t.f.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *linuxPITun) Close() error {
	return t.f.Close()
}

var _ io.ReadWriteCloser = (*linuxPITun)(nil)
