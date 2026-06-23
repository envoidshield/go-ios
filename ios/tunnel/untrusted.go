package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"io"

	"github.com/danielpaulus/go-ios/ios/opack"
	"github.com/danielpaulus/go-ios/ios/xpc"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
)

// untrustedTunnelServiceName is the service name that is described in the Remote Service Discovery of the
// ethernet interface of the device (not the tunnel interface)
const untrustedTunnelServiceName = "com.apple.internal.dt.coredevice.untrusted.tunnelservice"

func newTunnelServiceWithXpc(xpcConn *xpc.Connection, c io.Closer, pairRecords PairRecordManager) *tunnelService {
	return &tunnelService{
		xpcConn:        xpcConn,
		c:              c,
		controlChannel: newControlChannelReadWriter(xpcConn),
		pairRecords:    pairRecords,
	}
}

func newTunnelServiceWithRPPairing(conn xpcConn, c io.Closer, pairRecords PairRecordManager) *tunnelService {
	return &tunnelService{
		c:              c,
		controlChannel: newControlChannelReadWriter(conn),
		pairRecords:    pairRecords,
		jsonWire:       true,
	}
}

type tunnelService struct {
	xpcConn *xpc.Connection
	c       io.Closer

	controlChannel *controlChannelReadWriter
	cipher         *cipherStream

	pairRecords PairRecordManager
	deviceUDID  string
	jsonWire    bool
	// sharedSecret is the raw X25519 ECDH secret from pair-verify; TLS-PSK key for TCP tunnels.
	sharedSecret []byte
}

func (t *tunnelService) Close() error {
	return t.c.Close()
}

func (t *tunnelService) DeviceUDID() string {
	return t.deviceUDID
}

// readHandshakeResponse reads the device handshake reply and stores peer UDID.
func (t *tunnelService) readHandshakeResponse() error {
	resp, err := t.controlChannel.read()
	if err != nil {
		return fmt.Errorf("readHandshakeResponse: %w", err)
	}
	if udid := parseHandshakeUDID(resp); udid != "" {
		t.deviceUDID = udid
	}
	return nil
}

func parseHandshakeUDID(message map[string]interface{}) string {
	handshake, err := getChildMap(message, "plain", "_0", "response", "_1", "handshake", "_0", "deviceOptions", "peerDeviceInfo")
	if err != nil {
		return ""
	}
	udid, _ := handshake["udid"].(string)
	if udid == "" {
		if id, ok := handshake["identifier"].(string); ok {
			udid = id
		}
	}
	return udid
}

type RemotePairResult struct {
	PublicKey           string `json:"public_key"`
	PrivateKey          string `json:"private_key"`
	RemoteUnlockHostKey string `json:"remote_unlock_host_key"`
}

func (t *tunnelService) ManualPair() error {
	err := t.controlChannel.writeRequest(map[string]interface{}{
		"handshake": map[string]interface{}{
			"_0": map[string]interface{}{
				"hostOptions": map[string]interface{}{
					"attemptPairVerify": true,
				},
				"wireProtocolVersion": int64(19),
			},
		},
	})

	if err != nil {
		return fmt.Errorf("ManualPair: failed to send 'attemptPairVerify' request: %w", err)
	}
	// ignore the response for now
	_, err = t.controlChannel.read()
	if err != nil {
		return fmt.Errorf("ManualPair: failed to read 'attemptPairVerify' response: %w", err)
	}

	err = t.verifyPair()
	if err == nil {
		return nil
	}
	log.WithError(err).Debug("pair verify failed")

	err = t.setupManualPairing()
	if err != nil {
		return fmt.Errorf("ManualPair: failed to initiate manual pairing: %w", err)
	}

	sessionKey, err := t.setupSessionKey()
	if err != nil {
		return fmt.Errorf("ManualPair: failed to setup SRP session key: %w", err)
	}

	err = t.exchangeDeviceInfo(sessionKey)
	if err != nil {
		return fmt.Errorf("ManualPair: failed to exchange device info: %w", err)
	}

	err = t.setupCiphers(sessionKey)
	if err != nil {
		return fmt.Errorf("ManualPair: failed to setup session ciphers: %w", err)
	}

	_, err = t.createUnlockKey()
	if err != nil {
		return fmt.Errorf("ManualPair: failed to create unlock key: %w", err)
	}

	return nil
}

func (t *tunnelService) ManualPairGetHostKey() (string, error) {
	err := t.controlChannel.writeRequest(map[string]interface{}{
		"handshake": map[string]interface{}{
			"_0": map[string]interface{}{
				"hostOptions": map[string]interface{}{
					"attemptPairVerify": true,
				},
				"wireProtocolVersion": int64(19),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ManualPair: failed to send 'attemptPairVerify' request: %w", err)
	}
	// ignore the response for now
	_, err = t.controlChannel.read()
	if err != nil {
		return "", fmt.Errorf("ManualPair: failed to read 'attemptPairVerify' response: %w", err)
	}
	err = t.verifyPair()
	if err == nil {
		return "", nil
	}
	log.WithError(err).Debug("pair verify failed")
	err = t.setupManualPairing()
	if err != nil {
		return "", fmt.Errorf("ManualPair: failed to initiate manual pairing: %w", err)
	}
	sessionKey, err := t.setupSessionKey()
	if err != nil {
		return "", fmt.Errorf("ManualPair: failed to setup SRP session key: %w", err)
	}
	err = t.exchangeDeviceInfo(sessionKey)
	if err != nil {
		return "", fmt.Errorf("ManualPair: failed to exchange device info: %w", err)
	}
	err = t.setupCiphers(sessionKey)
	if err != nil {
		return "", fmt.Errorf("ManualPair: failed to setup session ciphers: %w", err)
	}

	unlockKey, err := t.createUnlockKeyAsString()
	if err != nil {
		return "", fmt.Errorf("ManualPair: failed to create unlock key: %w", err)
	}
	return unlockKey, nil
}

// verifyExistingPairing performs only the handshake + pair-verify step. It
// returns nil when an existing pairing is valid (no on-device prompt), and an
// error when this host is not yet trusted - in which case the device RSTs the
// control channel and a fresh connection is required for manual setup.
func (t *tunnelService) verifyExistingPairing() error {
	err := t.controlChannel.writeRequest(map[string]interface{}{
		"handshake": map[string]interface{}{
			"_0": map[string]interface{}{
				"hostOptions": map[string]interface{}{
					"attemptPairVerify": true,
				},
				"wireProtocolVersion": int64(19),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("verifyExistingPairing: failed to send handshake: %w", err)
	}
	if err = t.readHandshakeResponse(); err != nil {
		return fmt.Errorf("verifyExistingPairing: failed to read handshake response: %w", err)
	}
	return t.verifyPair()
}

// setupNewPairingGetHostKey runs full manual pairing on a fresh control channel
// and returns the remote unlock host key. It triggers the on-device Trust
// prompt. The handshake declares attemptPairVerify=false so the device goes
// straight to setup instead of expecting (and rejecting) a verify exchange.
func (t *tunnelService) setupNewPairingGetHostKey() (string, error) {
	err := t.controlChannel.writeRequest(map[string]interface{}{
		"handshake": map[string]interface{}{
			"_0": map[string]interface{}{
				"hostOptions": map[string]interface{}{
					"attemptPairVerify": false,
				},
				"wireProtocolVersion": int64(19),
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("setupNewPairing: failed to send handshake: %w", err)
	}
	if _, err = t.controlChannel.read(); err != nil {
		return "", fmt.Errorf("setupNewPairing: failed to read handshake response: %w", err)
	}
	if err = t.setupManualPairing(); err != nil {
		return "", fmt.Errorf("setupNewPairing: failed to initiate manual pairing: %w", err)
	}
	sessionKey, err := t.setupSessionKey()
	if err != nil {
		return "", fmt.Errorf("setupNewPairing: failed to setup SRP session key: %w", err)
	}
	if err = t.exchangeDeviceInfo(sessionKey); err != nil {
		return "", fmt.Errorf("setupNewPairing: failed to exchange device info: %w", err)
	}
	if err = t.setupCiphers(sessionKey); err != nil {
		return "", fmt.Errorf("setupNewPairing: failed to setup session ciphers: %w", err)
	}
	return t.createUnlockKeyAsString()
}

func (t *tunnelService) createTunnelListener() (tunnelListener, error) {
	log.Info("create tunnel listener")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return tunnelListener{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return tunnelListener{}, err
	}

	// Create a base64 encoded string from the DER bytes
	base64Key := base64.StdEncoding.EncodeToString(der)

	// Use the base64 encoded string in the request
	err = t.cipher.write(map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createListener": map[string]interface{}{
					"key": base64Key,
					"peerConnectionsInfo": []map[string]interface{}{
						{
							"owningPID":         1348,
							"owningProcessName": "CoreDeviceService",
						},
					},
					"transportProtocolType": "quic",
				},
			},
		},
	})
	if err != nil {
		return tunnelListener{}, err
	}

	var listenerRes map[string]interface{}
	err = t.cipher.read(&listenerRes)
	if err != nil {
		return tunnelListener{}, err
	}

	createListener, err := getChildMap(listenerRes, "response", "_1", "createListener")
	if err != nil {
		return tunnelListener{}, err
	}
	port := createListener["port"].(float64)
	devPublicKeyRaw, found := createListener["devicePublicKey"]
	if !found {
		return tunnelListener{}, fmt.Errorf("no public key found")
	}
	devPublicKey, isString := devPublicKeyRaw.(string)
	if !isString {
		return tunnelListener{}, fmt.Errorf("public key is not a string")
	}
	devPK, err := base64.StdEncoding.DecodeString(devPublicKey)
	if err != nil {
		return tunnelListener{}, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(devPK)
	if err != nil {
		return tunnelListener{}, err
	}
	return tunnelListener{
		PrivateKey:      privateKey,
		DevicePublicKey: publicKey,
		TunnelPort:      uint64(port),
	}, nil
}

func (t *tunnelService) createTcpTunnelListener() (uint16, error) {
	log.Info("create tcp tunnel listener")
	if len(t.sharedSecret) == 0 {
		return 0, fmt.Errorf("createTcpTunnelListener: no pair-verify shared secret")
	}
	err := t.cipher.write(map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createListener": map[string]interface{}{
					"key":                   t.sharedSecret,
					"transportProtocolType": "tcp",
				},
			},
		},
	})
	if err != nil {
		return 0, err
	}
	var listenerRes map[string]interface{}
	if err = t.cipher.read(&listenerRes); err != nil {
		return 0, err
	}
	createListener, err := getChildMap(listenerRes, "response", "_1", "createListener")
	if err != nil {
		return 0, err
	}
	port, ok := createListener["port"].(float64)
	if !ok {
		return 0, fmt.Errorf("createTcpTunnelListener: no port in response")
	}
	return uint16(port), nil
}

func (t *tunnelService) setupCiphers(sessionKey []byte) error {
	clientKey := make([]byte, 32)
	_, err := hkdf.New(sha512.New, sessionKey, nil, []byte("ClientEncrypt-main")).Read(clientKey)
	if err != nil {
		return err
	}

	serverKey := make([]byte, 32)
	_, err = hkdf.New(sha512.New, sessionKey, nil, []byte("ServerEncrypt-main")).Read(serverKey)
	if err != nil {
		return err
	}

	server, err := chacha20poly1305.New(serverKey)
	if err != nil {
		return err
	}

	client, err := chacha20poly1305.New(clientKey)
	if err != nil {
		return err
	}

	t.cipher = newCipherStream(t.controlChannel, client, server)
	return nil
}

func (t *tunnelService) setupManualPairing() error {
	buf := newTlvBuffer()
	buf.writeByte(typeMethod, 0x00)
	buf.writeByte(typeState, 0x01)

	event := pairingData{
		data:            buf.bytes(),
		kind:            "setupManualPairing",
		sendingHost:     "EnVoid",
		startNewSession: true,
	}

	err := t.controlChannel.writeEvent(&event)
	if err != nil {
		return err
	}

	_, err = t.controlChannel.read()
	return err
}

func (t *tunnelService) readDeviceKey() (publicKey []byte, salt []byte, err error) {
	var pairingData pairingData
	err = t.controlChannel.readEvent(&pairingData)
	if err != nil {
		return
	}
	publicKey, err = tlvReader(pairingData.data).readCoalesced(typePublicKey)
	if err != nil {
		return
	}
	salt, err = tlvReader(pairingData.data).readCoalesced(typeSalt)
	if err != nil {
		return
	}
	return
}

func (t *tunnelService) createUnlockKey() ([]byte, error) {
	req := map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createRemoteUnlockKey": map[string]interface{}{},
			},
		},
	}

	err := t.cipher.write(req)
	if err != nil {
		return nil, err
	}

	var res map[string]interface{}
	err = t.cipher.read(&res)
	if err != nil {
		return nil, err
	}

	// TODO: extract the actual unlock key from `res` if available.
	return nil, nil
}

func (t *tunnelService) createUnlockKeyAsString() (string, error) {
	req := map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createRemoteUnlockKey": map[string]interface{}{},
			},
		},
	}

	err := t.cipher.write(req)
	if err != nil {
		return "", err
	}

	var res map[string]interface{}
	err = t.cipher.read(&res)
	if err != nil {
		return "", err
	}

	response, ok := res["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("createUnlockKey: missing or invalid 'response' field")
	}

	inner, ok := response["_1"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("createUnlockKey: missing or invalid '_1' field")
	}

	createRemoteUnlockKey, ok := inner["createRemoteUnlockKey"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("createUnlockKey: missing or invalid 'createRemoteUnlockKey' field")
	}

	hostKeyStr, ok := createRemoteUnlockKey["hostKey"].(string)
	if !ok {
		return "", fmt.Errorf("createUnlockKey: missing or invalid 'hostKey' field")
	}

	return hostKeyStr, nil
}

func (t *tunnelService) verifyPair() error {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	tlv := newTlvBuffer()
	tlv.writeByte(typeState, pairStateStartRequest)
	tlv.writeData(typePublicKey, key.PublicKey().Bytes())
	event := pairingData{
		data:            tlv.bytes(),
		kind:            "verifyManualPairing",
		startNewSession: true,
	}
	err := t.controlChannel.writeEvent(&event)
	if err != nil {
		return err
	}
	var devP pairingData
	err = t.controlChannel.readEvent(&devP)
	if err != nil {
		return err
	}
	devicePublicKeyBytes, err := tlvReader(devP.data).readCoalesced(typePublicKey)
	if err != nil {
		return err
	}
	if devicePublicKeyBytes == nil {
		_ = t.controlChannel.writeEvent(pairVerifyFailed{})
		return fmt.Errorf("verifyPair: did not get public key from device. Can not verify pairing")
	}
	devicePublicKey, err := ecdh.X25519().NewPublicKey(devicePublicKeyBytes)
	if err != nil {
		return err
	}
	sharedSecret, err := key.ECDH(devicePublicKey)
	if err != nil {
		return err
	}
	derived := make([]byte, 32)
	_, err = hkdf.New(sha512.New, sharedSecret, []byte("Pair-Verify-Encrypt-Salt"), []byte("Pair-Verify-Encrypt-Info")).Read(derived)
	if err != nil {
		return err
	}
	ci, err := chacha20poly1305.New(derived)
	if err != nil {
		return err
	}
	signBuf := bytes.NewBuffer(nil)
	_, _ = signBuf.Write(key.PublicKey().Bytes())
	_, _ = signBuf.Write([]byte(t.pairRecords.selfId.Identifier))
	_, _ = signBuf.Write(devicePublicKeyBytes)
	signature := ed25519.Sign(t.pairRecords.selfId.privateKey(), signBuf.Bytes())
	cTlv := newTlvBuffer()
	cTlv.writeData(typeSignature, signature)
	cTlv.writeData(typeIdentifier, []byte(t.pairRecords.selfId.Identifier))
	nonce := make([]byte, 12)
	copy(nonce[4:], "PV-Msg03")
	encrypted := ci.Seal(nil, nonce, cTlv.bytes(), nil)
	if encrypted == nil {
		return fmt.Errorf("encryption failed")
	}

	tlvEncrypted := newTlvBuffer()
	tlvEncrypted.writeByte(typeState, pairStateVerifyRequest)
	tlvEncrypted.writeData(typeEncryptedData, encrypted)
	verifyKind := "verifyPairing"
	if t.jsonWire {
		verifyKind = "verifyManualPairing"
	}
	eventEncrypted := pairingData{
		data:            tlvEncrypted.bytes(),
		kind:            verifyKind,
		startNewSession: false,
	}

	err = t.controlChannel.writeEvent(&eventEncrypted)
	if err != nil {
		return err
	}

	var responseP pairingData
	err = t.controlChannel.readEvent(&responseP)
	if err != nil {
		return err
	}

	respTLV := tlvReader(responseP.data)
	if state, _ := respTLV.readCoalesced(typeState); len(state) > 0 && state[0] == pairStateVerifyResponse {
		return t.finishVerifySuccess(sharedSecret)
	}

	errRes, err := respTLV.readCoalesced(typeError)
	if err != nil {
		return err
	}
	if errRes != nil && len(errRes) > 0 {
		return fmt.Errorf("received error from response: %v", errRes)
	}
	return t.finishVerifySuccess(sharedSecret)
}

func (t *tunnelService) finishVerifySuccess(sharedSecret []byte) error {
	t.sharedSecret = sharedSecret
	if err := t.setupCiphers(sharedSecret); err != nil {
		return fmt.Errorf("verifyPair: setup ciphers: %w", err)
	}
	return nil
}

type tunnelListener struct {
	PrivateKey      *rsa.PrivateKey
	DevicePublicKey interface{}
	TunnelPort      uint64
}

type tunnelParameters struct {
	ServerAddress    string
	ServerRSDPort    uint64
	ClientParameters struct {
		Address string
		Netmask string
		Mtu     uint64
	}
}

func (t *tunnelService) setupSessionKey() ([]byte, error) {
	devicePublicKey, deviceSalt, err := t.readDeviceKey()
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to read device public key and salt value: %w", err)
	}

	srp, err := newSrpInfo(deviceSalt, devicePublicKey)
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to setup SRP: %w", err)
	}

	proofTlv := newTlvBuffer()
	proofTlv.writeByte(typeState, pairStateVerifyRequest)
	proofTlv.writeData(typePublicKey, srp.ClientPublic)
	proofTlv.writeData(typeProof, srp.ClientProof)

	err = t.controlChannel.writeEvent(&pairingData{
		data: proofTlv.bytes(),
		kind: "setupManualPairing",
	})
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to send SRP proof: %w", err)
	}

	var proofPairingData pairingData
	err = t.controlChannel.readEvent(&proofPairingData)
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to read device SRP proof: %w", err)
	}

	serverProof, err := tlvReader(proofPairingData.data).readCoalesced(typeProof)
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to parse device proof: %w", err)
	}

	if !srp.verifyServerProof(serverProof) {
		return nil, fmt.Errorf("setupSessionKey: could not verify server proof")
	}

	return srp.SessionKey, nil
}

func (t *tunnelService) exchangeDeviceInfo(sessionKey []byte) error {
	hkdfPairSetup := hkdf.New(sha512.New, sessionKey, []byte("Pair-Setup-Controller-Sign-Salt"), []byte("Pair-Setup-Controller-Sign-Info"))
	buf := bytes.NewBuffer(nil)
	_, _ = io.CopyN(buf, hkdfPairSetup, 32)
	_, _ = buf.WriteString(t.pairRecords.selfId.Identifier)
	_, _ = buf.Write(t.pairRecords.selfId.publicKey())

	signature := ed25519.Sign(t.pairRecords.selfId.privateKey(), buf.Bytes())

	deviceInfo, err := opack.Encode(map[string]interface{}{
		"accountID":                   t.pairRecords.selfId.Identifier,
		"altIRK":                      []byte{0xe9, 0xe8, 0x2d, 0xc0, 0x6a, 0x49, 0x79, 0x4b, 0x56, 0x4f, 0x00, 0x19, 0xb1, 0xc7, 0x7b},
		"btAddr":                      "11:22:33:44:55:66",
		"mac":                         []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		"model":                       "computer-model",
		"name":                        "EnVoid",
		"remotepairing_serial_number": "AAAAAAAAAAAA",
	})
	if err != nil {
		return err
	}

	deviceInfoTlv := newTlvBuffer()
	deviceInfoTlv.writeData(typeSignature, signature)
	deviceInfoTlv.writeData(typePublicKey, t.pairRecords.selfId.publicKey())
	deviceInfoTlv.writeData(typeIdentifier, []byte(t.pairRecords.selfId.Identifier))
	deviceInfoTlv.writeData(typeInfo, deviceInfo)

	sessionKeyBuf := bytes.NewBuffer(nil)
	_, err = io.CopyN(sessionKeyBuf, hkdf.New(sha512.New, sessionKey, []byte("Pair-Setup-Encrypt-Salt"), []byte("Pair-Setup-Encrypt-Info")), 32)
	if err != nil {
		return err
	}
	setupKey := sessionKeyBuf.Bytes()

	cipher, err := chacha20poly1305.New(setupKey)
	if err != nil {
		return err
	}

	nonce := make([]byte, cipher.NonceSize())
	copy(nonce[4:], "PS-Msg05")
	x := cipher.Seal(nil, nonce, deviceInfoTlv.bytes(), nil)

	encryptedTlv := newTlvBuffer()
	encryptedTlv.writeByte(typeState, 0x05)
	encryptedTlv.writeData(typeEncryptedData, x)

	err = t.controlChannel.writeEvent(&pairingData{
		data:        encryptedTlv.bytes(),
		kind:        "setupManualPairing",
		sendingHost: "SL-1876",
	})
	if err != nil {
		return err
	}

	var encRes pairingData
	err = t.controlChannel.readEvent(&encRes)
	if err != nil {
		return err
	}

	encrData, err := tlvReader(encRes.data).readCoalesced(typeEncryptedData)
	if err != nil {
		return err
	}

	copy(nonce[4:], "PS-Msg06")
	_, err = cipher.Open(nil, nonce, encrData, nil)
	return err
}
