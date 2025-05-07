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

type tunnelService struct {
	xpcConn *xpc.Connection
	c       io.Closer

	controlChannel *controlChannelReadWriter
	cipher         *cipherStream

	pairRecords PairRecordManager
}

func (t *tunnelService) Close() error {
	return t.c.Close()
}

// ManualPair triggers a device pairing that requires the user to press the 'Trust' button on the device that appears
// when this operation is triggered
// If there is already an active pairing with the credentials stored in PairRecordManager this call does not trigger
// anything on the device and returns with an error
func (t *tunnelService) ManualPair() error {
  log.Debug("Init connection phase")

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
	log.WithError(err).Info("pair verify failed")

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

  key, err := t.createUnlockKey()
	if err != nil {
		return fmt.Errorf("ManualPair: failed to create unlock key: %w", err)
	}
  fmt.Printf("Unlock Key: %s\n", key)

	return nil
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

	err = t.cipher.write(map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createListener": map[string]interface{}{
					"key":                   der,
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
  log.Debug("Manual Pairing Init")
	buf := newTlvBuffer()
	buf.writeByte(typeMethod, 0x00)
	buf.writeByte(typeState, pairStateStartRequest)

	event := pairingData{
		data:            buf.bytes(),
		kind:            "setupManualPairing",
    sendingHost:     "EnVoid",
		startNewSession: true,
	}

  log.Debugf("[>] Created pairing event: kind=%s, sendingHost=%s, startNewSession=%t, TLV data=%x",
	event.kind, event.sendingHost, event.startNewSession, event.data)

	err := t.controlChannel.writeEvent(&event)
	if err != nil {
		return err
	}
	_, err = t.controlChannel.read()
	if err != nil {
		return err
	}
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

func (t *tunnelService) createUnlockKey() (string, error) {
	err := t.cipher.write(map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createRemoteUnlockKey": map[string]interface{}{},
			},
		},
	})
	if err != nil {
		return "", err
	}

	var res map[string]interface{}
	err = t.cipher.read(&res)
	if err != nil {
		return "", err
	}

	// Extract the key from the response
	response, ok := res["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format: missing 'response' object")
	}
	
	inner, ok := response["_1"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format: missing '_0' object")
	}
	
  createKeyResponse, ok := inner["createRemoteUnlockKey"].(map[string]interface{})
  if !ok {
      return "", fmt.Errorf("invalid response format: missing 'createRemoteUnlockKey' object")
  }

  // Fix the hostKey extraction - no need for type assertion in the variable declaration
  hostKey, ok := createKeyResponse["hostKey"]
  if !ok {
      return "", fmt.Errorf("hostKey not found in response")
  }

  // Add the type assertion when converting the interface{} to string
  unlockKey, ok := hostKey.(string)
  if !ok {
      return "", fmt.Errorf("hostKey is not a string")
  }

  return unlockKey, nil
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

	selfId := t.pairRecords.selfId

	err := t.controlChannel.writeEvent(&event)

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
	// Write on bytes.Buffer never returns an error
	_, _ = signBuf.Write(key.PublicKey().Bytes())
	_, _ = signBuf.Write([]byte(selfId.Identifier))
	_, _ = signBuf.Write(devicePublicKeyBytes)

	signature := ed25519.Sign(selfId.privateKey(), signBuf.Bytes())

	cTlv := newTlvBuffer()
	cTlv.writeData(typeSignature, signature)
	cTlv.writeData(typeIdentifier, []byte(selfId.Identifier))

	nonce := make([]byte, 12)
	copy(nonce[4:], "PV-Msg03")
	encrypted := ci.Seal(nil, nonce, cTlv.bytes(), nil)

	tlvOut := newTlvBuffer()
	tlvOut.writeByte(typeState, pairStateVerifyRequest)
	tlvOut.writeData(typeEncryptedData, encrypted)

	pd := pairingData{
		data:            tlvOut.bytes(),
		kind:            "verifyManualPairing",
		startNewSession: false,
	}

	err = t.controlChannel.writeEvent(&pd)
	if err != nil {
		return err
	}

	var responseEvent pairingData
	err = t.controlChannel.readEvent(&responseEvent)
	if err != nil {
		return err
	}

	errRes, err := tlvReader(responseEvent.data).readCoalesced(typeError)
	if err != nil {
		return err
	}
	if len(errRes) > 0 {
    // Print the private and public keys in base64 format
    privateKeyBytes := key.Bytes() // Get private key bytes
    publicKeyBytes := key.PublicKey().Bytes() // Get public key bytes

    // Encode to base64
    privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKeyBytes)
    publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

    // Print the keys
    fmt.Printf("Private Key (Base64): %s\n", privateKeyBase64)
    fmt.Printf("Public Key (Base64): %s\n", publicKeyBase64)
		log.Debug("send pair verify failed event")
		err := t.controlChannel.writeEvent(pairVerifyFailed{})
		if err != nil {
			return err
		}
		return tlvError(errRes[0])
	}

	err = t.setupCiphers(sharedSecret)
	if err != nil {
		return err
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

  log.Debugf("[<] PublicKey: %x | Salt: %x", devicePublicKey, deviceSalt)
  log.Debug("SRP Auth phase")
	srp, err := newSrpInfo(deviceSalt, devicePublicKey)
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to setup SRP: %w", err)
	}

	proofTlv := newTlvBuffer()
	proofTlv.writeByte(typeState, pairStateVerifyRequest)
	proofTlv.writeData(typePublicKey, srp.ClientPublic)
	proofTlv.writeData(typeProof, srp.ClientProof)
  log.Debugf("[>] TLV buffer and writing: state=%d, publicKey=%x, proof=%x", pairStateVerifyRequest, srp.ClientPublic, srp.ClientProof)
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

  log.Debugf("[<] Reading proof: %w, server proof: %w", proofPairingData, serverProof)

	verified := srp.verifyServerProof(serverProof)
	if !verified {
		return nil, fmt.Errorf("setupSessionKey: could not verify server proof")
	}
  log.Debugf("verified: %w", verified)
	return srp.SessionKey, nil
}

func (t *tunnelService) exchangeDeviceInfo(sessionKey []byte) error {
	log.Debug("🔁 Exchange Identity Phase started")

	// Derive signature key
	log.Debug("🔐 Deriving Controller signature key with HKDF")
	hkdfPairSetup := hkdf.New(sha512.New, sessionKey,
		[]byte("Pair-Setup-Controller-Sign-Salt"),
		[]byte("Pair-Setup-Controller-Sign-Info"))

	buf := bytes.NewBuffer(nil)
	_, _ = io.CopyN(buf, hkdfPairSetup, 32)
	log.Debugf("HKDF key material: %x", buf.Bytes())

	// Add identifier and public key
	log.Debugf("📛 Adding host identifier: %s", t.pairRecords.selfId.Identifier)
	_, _ = buf.WriteString(t.pairRecords.selfId.Identifier)
	log.Debugf("🔑 Adding host public key: %x", t.pairRecords.selfId.publicKey())
	_, _ = buf.Write(t.pairRecords.selfId.publicKey())

	// Sign input
	signature := ed25519.Sign(t.pairRecords.selfId.privateKey(), buf.Bytes())
	log.Debugf("✍️  Created signature: %x", signature)

	// Build device info payload
	log.Debug("🛠️ Building device info object")
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
		log.WithError(err).Error("Failed to encode device info")
		return err
	}
	log.Debugf("📦 Encoded device info: %x", deviceInfo)

	deviceInfoTlv := newTlvBuffer()
	deviceInfoTlv.writeData(typeSignature, signature)
	deviceInfoTlv.writeData(typePublicKey, t.pairRecords.selfId.publicKey())
	deviceInfoTlv.writeData(typeIdentifier, []byte(t.pairRecords.selfId.Identifier))
	deviceInfoTlv.writeData(typeInfo, deviceInfo)
	log.Debug("📄 Constructed TLV8 with identifier, public key, signature, and info")

	// Encrypt the device info TLV
	log.Debug("🔐 Deriving encryption key with HKDF for ChaCha20Poly1305")
	sessionKeyBuf := bytes.NewBuffer(nil)
	_, err = io.CopyN(sessionKeyBuf,
		hkdf.New(sha512.New, sessionKey,
			[]byte("Pair-Setup-Encrypt-Salt"),
			[]byte("Pair-Setup-Encrypt-Info")), 32)
	if err != nil {
		log.WithError(err).Error("Failed to derive encryption key")
		return err
	}
	setupKey := sessionKeyBuf.Bytes()
	log.Debugf("Derived setup encryption key: %x", setupKey)

	cipher, err := chacha20poly1305.New(setupKey)
	if err != nil {
		log.WithError(err).Error("Failed to create ChaCha20Poly1305 cipher")
		return err
	}

	nonce := make([]byte, cipher.NonceSize())
	copy(nonce[4:], "PS-Msg05")
	log.Debugf("Using nonce for encryption: %x", nonce)

	x := cipher.Seal(nil, nonce, deviceInfoTlv.bytes(), nil)
	log.Debugf("🔒 Encrypted TLV: %x", x)

	encryptedTlv := newTlvBuffer()
	encryptedTlv.writeByte(typeState, 0x05)
	encryptedTlv.writeData(typeEncryptedData, x)

	log.Debug("📤 Sending encrypted TLV to device")
	err = t.controlChannel.writeEvent(&pairingData{
		data:        encryptedTlv.bytes(),
		kind:        "setupManualPairing",
		sendingHost: "SL-1876",
	})
	if err != nil {
		log.WithError(err).Error("Failed to send pairing data to device")
		return err
	}

	// Receive device's response
	log.Debug("📥 Waiting for device encrypted response")
	var encRes pairingData
	err = t.controlChannel.readEvent(&encRes)
	if err != nil {
		log.WithError(err).Error("Failed to read pairing response")
		return err
	}

	encrData, err := tlvReader(encRes.data).readCoalesced(typeEncryptedData)
	if err != nil {
		log.WithError(err).Error("Failed to extract encrypted data from TLV")
		return err
	}
	copy(nonce[4:], "PS-Msg06")
	log.Debugf("Using nonce for decrypting device response: %x", nonce)

	_, err = cipher.Open(nil, nonce, encrData, nil)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt device response")
		return err
	}

	log.Debug("✅ Device response decrypted successfully")
	return nil
}
