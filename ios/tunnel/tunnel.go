package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os/exec"
	"runtime"
	"time"
	"encoding/base64"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/http"

	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

// Tunnel describes the parameters of an established tunnel to the device
type Tunnel struct {
	// Address is the IPv6 address of the device over the tunnel
	Address string `json:"address"`
	// RsdPort is the port on which remote service discover is reachable
	RsdPort int `json:"rsdPort"`
	// Udid is the id of the device for this tunnel
	Udid string `json:"udid"`
	// Userspace TUN device is used, connect to the local tcp port at Default
	UserspaceTUN     bool `json:"userspaceTun"`
	UserspaceTUNPort int  `json:"userspaceTunPort"`
	closer           func() error
}

// Close closes the connection to the device and removes the virtual network interface from the host
func (t Tunnel) Close() error {
	return t.closer()
}

func ManualPairAndConnectToTunnel2(ctx context.Context, device ios.DeviceEntry, p PairRecordManager, addr string) (Tunnel, error) {
	log.Info("ManualPairAndConnectToTunnel: starting manual pairing and tunnel connection.")
	log.Info("Reminder: stop remoted first with 'sudo pkill -SIGSTOP remoted' and run this with sudo.")

	log.Infof("Getting untrusted tunnel service port for address %s", addr)
  port := device.Rsd.GetPort("com.apple.internal.dt.coredevice.untrusted.tunnelservice")
	log.Infof("Got untrusted tunnel service port: %d", port)

	log.Infof("Connecting to TUN device at %s:%d", addr, port)
	conn, err := ios.ConnectTUNDevice(addr, port, device)
	if err != nil {
		log.Errorf("Failed to connect to TUN device: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to connect to TUN device: %w", err)
	}
	log.Info("Connected to TUN device successfully.")

	log.Info("Creating HTTP2 connection over TUN device.")
	h, err := http.NewHttpConnection(conn)
	if err != nil {
		log.Errorf("Failed to create HTTP2 connection: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create HTTP2 connection: %w", err)
	}
	log.Info("HTTP2 connection created successfully.")

	log.Info("Creating RemoteXPC connection.")
	xpcConn, err := ios.CreateXpcConnection(h)
	if err != nil {
		log.Errorf("Failed to create RemoteXPC connection: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create RemoteXPC connection: %w", err)
	}
	log.Info("RemoteXPC connection created successfully.")

	log.Info("Initializing tunnel service with XPC connection.")
	ts := newTunnelServiceWithXpc(xpcConn, h, p)

	log.Info("Starting manual pairing process.")
	err = ts.ManualPair()
	if err != nil {
		log.Errorf("Manual pairing failed: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to pair device: %w", err)
	}
	log.Info("Manual pairing completed successfully.")

	log.Info("Creating tunnel listener.")
	tunnelInfo, err := ts.createTunnelListener()
	if err != nil {
		log.Errorf("Failed to create tunnel listener: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create tunnel listener: %w", err)
	}
	log.Infof("Tunnel listener created successfully: %+v", tunnelInfo)

	log.Infof("Connecting to the tunnel with address %s", addr)
	t, err := connectToTunnel(ctx, tunnelInfo, addr, device)
	if err != nil {
		log.Errorf("Failed to connect to tunnel: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to connect to tunnel: %w", err)
	}
	log.Info("Connected to tunnel successfully.")

	return t, nil
}



// ManualPairAndConnectToTunnel tries to verify an existing pairing, and if this fails it triggers a new manual pairing process.
// After a successful pairing a tunnel for this device gets started and the tunnel information is returned
func ManualPairAndConnectToTunnel(ctx context.Context, device ios.DeviceEntry, p PairRecordManager) (Tunnel, error) {
	log.Info("ManualPairAndConnectToTunnel: starting manual pairing and tunnel connection.")
	log.Info("Reminder: stop remoted first with 'sudo pkill -SIGSTOP remoted' and run this with sudo.")

	log.Infof("Finding device interface address for device: %+v", device)
	addr, err := ios.FindDeviceInterfaceAddress(ctx, device)
	if err != nil {
		log.Errorf("Failed to find device ethernet interface: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to find device ethernet interface: %w", err)
	}
	log.Infof("Found device interface address: %s", addr)

	log.Infof("Getting untrusted tunnel service port for address %s", addr)
	port, err := getUntrustedTunnelServicePort(addr, device)
	if err != nil {
		log.Errorf("Could not find port for '%s': %v", untrustedTunnelServiceName, err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: could not find port for '%s'", untrustedTunnelServiceName)
	}
	log.Infof("Got untrusted tunnel service port: %d", port)

	log.Infof("Connecting to TUN device at %s:%d", addr, port)
	conn, err := ios.ConnectTUNDevice(addr, port, device)
	if err != nil {
		log.Errorf("Failed to connect to TUN device: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to connect to TUN device: %w", err)
	}
	log.Info("Connected to TUN device successfully.")

	log.Info("Creating HTTP2 connection over TUN device.")
	h, err := http.NewHttpConnection(conn)
	if err != nil {
		log.Errorf("Failed to create HTTP2 connection: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create HTTP2 connection: %w", err)
	}
	log.Info("HTTP2 connection created successfully.")

	log.Info("Creating RemoteXPC connection.")
	xpcConn, err := ios.CreateXpcConnection(h)
	if err != nil {
		log.Errorf("Failed to create RemoteXPC connection: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create RemoteXPC connection: %w", err)
	}
	log.Info("RemoteXPC connection created successfully.")

	log.Info("Initializing tunnel service with XPC connection.")
	ts := newTunnelServiceWithXpc(xpcConn, h, p)

	log.Info("Starting manual pairing process.")
	err = ts.ManualPair()
	if err != nil {
		log.Errorf("Manual pairing failed: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to pair device: %w", err)
	}
	log.Info("Manual pairing completed successfully.")

	log.Info("Creating tunnel listener.")
	tunnelInfo, err := ts.createTunnelListener()
	if err != nil {
		log.Errorf("Failed to create tunnel listener: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to create tunnel listener: %w", err)
	}
	log.Infof("Tunnel listener created successfully: %+v", tunnelInfo)

	log.Infof("Connecting to the tunnel with address %s", addr)
	t, err := connectToTunnel(ctx, tunnelInfo, addr, device)
	if err != nil {
		log.Errorf("Failed to connect to tunnel: %v", err)
		return Tunnel{}, fmt.Errorf("ManualPairAndConnectToTunnel: failed to connect to tunnel: %w", err)
	}
	log.Info("Connected to tunnel successfully.")

	return t, nil
}



func RemotePair(ctx context.Context, device ios.DeviceEntry, p PairRecordManager, addr string) (RemotePairResult, error) {
	log.Info("Remote Pair: starting manual pairing and tunnel connection.")

	//devConn, err := ios.ConnectToShimService(device, "com.apple.syslog_relay.shim.remote")
	//if err != nil{
	//	return RemotePairResult{}, fmt.Errorf("Remote Pair: failed to device connect: %w", err)
	//}


	port := device.Rsd.GetPort("com.apple.internal.dt.coredevice.untrusted.tunnelservice")

	conn, err := ios.ConnectTUNDevice(addr, port, device)

	if err != nil {
		return RemotePairResult{}, fmt.Errorf("Remote Pair: failed to connect to TUN device: %w", err)
	}

	h, err := http.NewHttpConnection(conn)
	if err != nil {
		return RemotePairResult{}, fmt.Errorf("Remote Pair: failed to create HTTP2 connection: %w", err)
	}
	
	xpcConn, err := ios.CreateXpcConnection(h)
	if err != nil {
		return RemotePairResult{}, fmt.Errorf("Remote Pair: failed to create RemoteXPC connection: %w", err)
	}

	ts := newTunnelServiceWithXpc(xpcConn, h, p)

	publicKeyB64 := base64.StdEncoding.EncodeToString(ts.pairRecords.selfId.PublicKey)
	privateKeyB64 := base64.StdEncoding.EncodeToString(ts.pairRecords.selfId.PrivateKey)

	fmt.Printf("[DEBUG] PublicKey (base64): %s\n", publicKeyB64)
	fmt.Printf("[DEBUG] PrivateKey (base64): %s\n", privateKeyB64)

	hostKey, err := ts.ManualPairGetHostKey()
	if err != nil {
		return RemotePairResult{}, fmt.Errorf("Remote Pair: failed to pair device: %w", err)
	}
	//hostKeyB64 := base64.StdEncoding.EncodeToString(hostKey)

	result := RemotePairResult{
		PublicKey:           publicKeyB64,
		PrivateKey:          privateKeyB64,
		RemoteUnlockHostKey: hostKey,
	}

	return result, nil
}

func getUntrustedTunnelServicePort(addr string, device ios.DeviceEntry) (int, error) {
	rsdService, err := ios.NewWithAddrDevice(addr, device)
	if err != nil {
		return 0, fmt.Errorf("getUntrustedTunnelServicePort: failed to connect to RSD service: %w", err)
	}
	defer rsdService.Close()
	handshakeResponse, err := rsdService.Handshake()
	if err != nil {
		return 0, fmt.Errorf("getUntrustedTunnelServicePort: failed to perform RSD handshake: %w", err)
	}

	port := handshakeResponse.GetPort(untrustedTunnelServiceName)
	if port == 0 {
		return 0, fmt.Errorf("getUntrustedTunnelServicePort: could not find port for '%s'", untrustedTunnelServiceName)
	}
	return port, nil
}

func connectToTunnel(ctx context.Context, info tunnelListener, addr string, device ios.DeviceEntry) (Tunnel, error) {
	logrus.WithField("address", addr).WithField("port", info.TunnelPort).Info("connect to tunnel endpoint on device")

	conf, err := createTlsConfig(info)
	if err != nil {
		return Tunnel{}, err
	}

	conn, err := quic.DialAddr(ctx, fmt.Sprintf("[%s]:%d", addr, info.TunnelPort), conf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 1 * time.Second,
	})
	if err != nil {
		return Tunnel{}, err
	}

	err = conn.SendDatagram(make([]byte, 1024))
	if err != nil {
		return Tunnel{}, err
	}

	stream, err := conn.OpenStream()
	if err != nil {
		return Tunnel{}, err
	}

	tunnelInfo, err := exchangeCoreTunnelParameters(stream)
	stream.Close()
	if err != nil {
		return Tunnel{}, fmt.Errorf("could not exchange tunnel parameters. %w", err)
	}

	utunIface, err := setupTunnelInterface(tunnelInfo)
	if err != nil {
		return Tunnel{}, fmt.Errorf("could not setup tunnel interface. %w", err)
	}

	// we want a copy of the parent ctx here, but it shouldn't time out/be cancelled at the same time.
	// doing it like this allows us to have a context with a timeout for the tunnel creation, but the tunnel itself
	tunnelCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	go func() {
		err := forwardDataToInterface(tunnelCtx, conn, utunIface)
		if err != nil {
			logrus.WithError(err).Error("failed to forward data to tunnel interface")
		}
	}()

	go func() {
		err := forwardDataToDevice(tunnelCtx, tunnelInfo.ClientParameters.Mtu, utunIface, conn)
		if err != nil {
			logrus.WithError(err).Error("failed to forward data to the device")
		}
	}()

	closeFunc := func() error {
		cancel()
		quicErr := conn.CloseWithError(0, "")
		utunErr := utunIface.Close()
		return errors.Join(quicErr, utunErr)
	}

	return Tunnel{
		Address: tunnelInfo.ServerAddress,
		RsdPort: int(tunnelInfo.ServerRSDPort),
		Udid:    device.Properties.SerialNumber,
		closer:  closeFunc,
	}, nil
}

func setupTunnelInterface(tunnelInfo tunnelParameters) (io.ReadWriteCloser, error) {
	if runtime.GOOS == "windows" {
		return setupWindowsTUN(tunnelInfo)
	}
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, fmt.Errorf("setupTunnelInterface: failed creating TUN device %w", err)
	}

	const prefixLength = 64 // TODO: this could be calculated from the netmask provided by the device

	setIpAddr := exec.Command("ifconfig", ifce.Name(), "inet6", "add", fmt.Sprintf("%s/%d", tunnelInfo.ClientParameters.Address, prefixLength))
	err = runCmd(setIpAddr)
	if err != nil {
		return nil, fmt.Errorf("setupTunnelInterface: failed to set IP address for interface: %w", err)
	}

	// FIXME: we need to reduce the tunnel interface MTU so that the OS takes care of splitting the payloads into
	// smaller packets. If we use a larger number here, the QUIC tunnel won't send the packets properly
	// This is only necessary on MacOS, on Linux we can't set the MTU to a value less than 1280 (minimum for IPv6)
	if runtime.GOOS == "darwin" {
		ifceMtu := 1202
		setMtu := exec.Command("ifconfig", ifce.Name(), "mtu", fmt.Sprintf("%d", ifceMtu), "up")
		err = runCmd(setMtu)
		if err != nil {
			return nil, fmt.Errorf("setupTunnelInterface: failed to configure MTU: %w", err)
		}
	}

	enableIfce := exec.Command("ifconfig", ifce.Name(), "up")
	err = runCmd(enableIfce)
	if err != nil {
		return nil, fmt.Errorf("setupTunnelInterface: failed to enable interface %s: %w", ifce.Name(), err)
	}

	return ifce, nil
}

func runCmd(cmd *exec.Cmd) error {
	buf := new(bytes.Buffer)
	cmd.Stderr = buf
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("runCmd: failed to exeute command (stderr: %s): %w", buf.String(), err)
	}
	return nil
}

func createTlsConfig(info tunnelListener) (*tls.Config, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &info.PrivateKey.PublicKey, info.PrivateKey)
	if err != nil {
		return nil, err
	}
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(info.PrivateKey),
		},
	)
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	cert5, err := tls.X509KeyPair(certPem, privateKeyPem)

	conf := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert5},
		ClientAuth:         tls.NoClientCert,
		NextProtos:         []string{"RemotePairingTunnelProtocol"},
		CurvePreferences:   []tls.CurveID{tls.CurveP256},
	}
	return conf, nil
}

func forwardDataToDevice(ctx context.Context, mtu uint64, r io.Reader, conn quic.Connection) error {
	packet := make([]byte, mtu)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, err := r.Read(packet)
			if err != nil {
				return fmt.Errorf("could not read packet. %w", err)
			}
			err = conn.SendDatagram(packet[:n])
			if err != nil {
				return fmt.Errorf("could not write packet. %w", err)
			}
		}
	}
}

func forwardDataToInterface(ctx context.Context, conn quic.Connection, w io.Writer) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			b, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return fmt.Errorf("failed to read datagram. %w", err)
			}
			_, err = w.Write(b)
			if err != nil {
				return fmt.Errorf("failed to forward data. %w", err)
			}
		}
	}
}

func exchangeCoreTunnelParameters(stream io.ReadWriteCloser) (tunnelParameters, error) {
	rq, err := json.Marshal(map[string]interface{}{
		"type": "clientHandshakeRequest",
		"mtu":  16000,
	})
	if err != nil {
		return tunnelParameters{}, err
	}

	buf := bytes.NewBuffer(nil)
	// Write on bytes.Buffer never returns an error
	_, _ = buf.Write([]byte("CDTunnel\000"))
	_ = buf.WriteByte(byte(len(rq)))
	_, _ = buf.Write(rq)

	_, err = stream.Write(buf.Bytes())
	if err != nil {
		return tunnelParameters{}, err
	}

	header := make([]byte, len("CDTunnel")+2)
	n, err := stream.Read(header)
	if err != nil {
		return tunnelParameters{}, fmt.Errorf("could not header read from stream. %w", err)
	}

	bodyLen := header[len(header)-1]

	res := make([]byte, bodyLen)
	n, err = stream.Read(res)
	if err != nil {
		return tunnelParameters{}, fmt.Errorf("could not read from stream. %w", err)
	}

	var parameters tunnelParameters
	err = json.Unmarshal(res[:n], &parameters)
	if err != nil {
		return tunnelParameters{}, err
	}
	return parameters, nil
}
