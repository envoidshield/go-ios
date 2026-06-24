package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/sirupsen/logrus"
)

const coreDeviceProxy = "com.apple.internal.devicecompute.CoreDeviceProxy"

// maxTunnelPacket bounds the forwarding buffers. The IPv6 payload length is a
// 16-bit field, so 0xffff + the 40-byte header covers any non-jumbo frame the
// device can send, regardless of the negotiated MTU. Sizing to the MTU instead
// risks a slice overflow when the device emits a larger frame.
const maxTunnelPacket = 0xffff + 40

func ConnectTunnelLockdown(device ios.DeviceEntry) (Tunnel, error) {
	conn, err := ios.ConnectToService(device, coreDeviceProxy)
	if err != nil {
		return Tunnel{}, err
	}
	return connectToTunnelLockdown(context.TODO(), device, conn)
}

func connectToTunnelLockdown(ctx context.Context, device ios.DeviceEntry, connToDevice io.ReadWriteCloser) (Tunnel, error) {
	logrus.Info("connect to lockdown tunnel endpoint on device")

	tunnelInfo, err := exchangeCoreTunnelParametersWithContext(ctx, connToDevice)
	if err != nil {
		return Tunnel{}, fmt.Errorf("could not exchange tunnel parameters. %w", err)
	}

	utunIface, ifName, err := setupTunnelInterface(tunnelInfo)
	if err != nil {
		return Tunnel{}, fmt.Errorf("could not setup tunnel interface. %w", err)
	}

	// we want a copy of the parent ctx here, but it shouldn't time out/be cancelled at the same time.
	// doing it like this allows us to have a context with a timeout for the tunnel creation, but the tunnel itself
	tunnelCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	go func() {
		err := forwardTCPToInterface(tunnelCtx, tunnelInfo.ClientParameters.Mtu, connToDevice, utunIface)
		if err != nil && tunnelCtx.Err() == nil && !isExpectedTunnelCloseErr(err) {
			logrus.WithError(err).Error("failed to forward data to tunnel interface")
		}
	}()

	go func() {
		err := forwardTUNToDevice(tunnelCtx, tunnelInfo.ClientParameters.Mtu, utunIface, connToDevice)
		if err != nil && tunnelCtx.Err() == nil && !isExpectedTunnelCloseErr(err) {
			logrus.WithError(err).Error("failed to forward data to the device")
		}
	}()

	closeFunc := func() error {
		cancel()
		return errors.Join(utunIface.Close(), connToDevice.Close())
	}
	return Tunnel{
		Address:       tunnelInfo.ServerAddress,
		ClientAddress: tunnelInfo.ClientParameters.Address,
		RsdPort:       int(tunnelInfo.ServerRSDPort),
		Udid:          device.Properties.SerialNumber,
		KernelTunIf:   ifName,
		closer:        closeFunc,
	}, nil
}

func forwardTUNToDevice(ctx context.Context, mtu uint64, tun io.Reader, deviceConn io.Writer) error {
	packet := make([]byte, maxTunnelPacket)
	for {

		select {
		case <-ctx.Done():
			return nil
		default:

			n, err := tun.Read(packet)

			if err != nil {
				return fmt.Errorf("could not read packet. %w", err)
			}

			// The CoreDevice tunnel stream is IPv6-only and the device parses it
			// by reading each IPv6 header's payload length. A non-IPv6 packet
			// (e.g. leaked IPv4 mDNS/IGMP from the host) has a bogus "payload
			// length" that makes the device read thousands of stray bytes and
			// permanently desync the stream, swallowing every subsequent packet
			// including RSD SYNs. Forward only well-formed IPv6 packets.
			if n < 40 || packet[0]>>4 != 6 {
				continue
			}

			_, err = deviceConn.Write(packet[:n])
			if err != nil {
				return fmt.Errorf("could not write packet. %w", err)
			}
		}

	}
}

func forwardTCPToInterface(ctx context.Context, mtu uint64, deviceConn io.Reader, tun io.Writer) error {
	// One contiguous buffer per packet. A TUN requires exactly one complete IP
	// packet per Write() syscall; a bufio.Writer would split any packet larger
	// than its buffer across multiple writes, producing malformed fragments the
	// kernel silently drops (breaks device->host forwarding for big frames).
	pkt := make([]byte, maxTunnelPacket)
	header := pkt[:40]

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if _, err := io.ReadFull(deviceConn, header); err != nil {
				return fmt.Errorf("failed to read IPv6 header: %w", err)
			}
			if header[0]>>4 != 6 {
				return fmt.Errorf("not an IPv6 packet. expected version 6, but got 0x%02x", header[0])
			}
			payloadLength := int(binary.BigEndian.Uint16(header[4:6]))
			if payloadLength < 0 || 40+payloadLength > len(pkt) {
				return fmt.Errorf("invalid IPv6 payload length %d", payloadLength)
			}
			if _, err := io.ReadFull(deviceConn, pkt[40:40+payloadLength]); err != nil {
				return fmt.Errorf("failed to read payload of length %d: %w", payloadLength, err)
			}
			if _, err := tun.Write(pkt[:40+payloadLength]); err != nil {
				return fmt.Errorf("could not write packet to interface: %w", err)
			}
		}
	}
}
