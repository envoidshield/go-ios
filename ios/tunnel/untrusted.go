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
    log.WithError(err).Info("pair verify failed")
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
                  "key":                   base64Key,
                  "peerConnectionsInfo": []map[string]interface{}{
                      {
                          "owningPID": 1348,
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

func (t *tunnelService) setupCiphers(sessionKey []byte) error {
	fmt.Println("[DEBUG] setupCiphers: initializing cipher setup")

	clientKey := make([]byte, 32)
	_, err := hkdf.New(sha512.New, sessionKey, nil, []byte("ClientEncrypt-main")).Read(clientKey)
	if err != nil {
		fmt.Printf("[DEBUG] setupCiphers: failed to derive clientKey: %v\n", err)
		return err
	}
	fmt.Printf("[DEBUG] setupCiphers: derived clientKey: %x\n", clientKey)

	serverKey := make([]byte, 32)
	_, err = hkdf.New(sha512.New, sessionKey, nil, []byte("ServerEncrypt-main")).Read(serverKey)
	if err != nil {
		fmt.Printf("[DEBUG] setupCiphers: failed to derive serverKey: %v\n", err)
		return err
	}
	fmt.Printf("[DEBUG] setupCiphers: derived serverKey: %x\n", serverKey)

	server, err := chacha20poly1305.New(serverKey)
	if err != nil {
		fmt.Printf("[DEBUG] setupCiphers: failed to create server cipher: %v\n", err)
		return err
	}
	fmt.Println("[DEBUG] setupCiphers: server cipher created successfully")

	client, err := chacha20poly1305.New(clientKey)
	if err != nil {
		fmt.Printf("[DEBUG] setupCiphers: failed to create client cipher: %v\n", err)
		return err
	}
	fmt.Println("[DEBUG] setupCiphers: client cipher created successfully")

	t.cipher = newCipherStream(t.controlChannel, client, server)
	fmt.Println("[DEBUG] setupCiphers: cipher streams assigned to tunnelService")

	return nil
}


func (t *tunnelService) setupManualPairing() error {
	fmt.Println("[DEBUG] setupManualPairing: starting manual pairing setup")

	buf := newTlvBuffer()
	buf.writeByte(typeMethod, 0x00)
	buf.writeByte(typeState, 0x01)
	fmt.Printf("[DEBUG] setupManualPairing: TLV buffer prepared, bytes=%x\n", buf.bytes())

	event := pairingData{
		data:            buf.bytes(),
		kind:            "setupManualPairing",
		sendingHost: "EnVoid",
		startNewSession: true,
	}
	fmt.Println("[DEBUG] setupManualPairing: pairingData event created")

	err := t.controlChannel.writeEvent(&event)
	if err != nil {
		fmt.Printf("[DEBUG] setupManualPairing: failed to write event: %v\n", err)
		return err
	}
	fmt.Println("[DEBUG] setupManualPairing: event written to control channel")

	_, err = t.controlChannel.read()
	if err != nil {
		fmt.Printf("[DEBUG] setupManualPairing: failed to read response: %v\n", err)
		return err
	}
	fmt.Println("[DEBUG] setupManualPairing: response read successfully")

	return nil
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
	fmt.Println("[DEBUG] createUnlockKey: starting unlock key creation")

	req := map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createRemoteUnlockKey": map[string]interface{}{},
			},
		},
	}
	fmt.Printf("[DEBUG] createUnlockKey: sending request: %+v\n", req)

	err := t.cipher.write(req)
	if err != nil {
		fmt.Printf("[DEBUG] createUnlockKey: failed to write request: %v\n", err)
		return nil, err
	}
	fmt.Println("[DEBUG] createUnlockKey: request sent successfully")

	var res map[string]interface{}
	err = t.cipher.read(&res)
	if err != nil {
		fmt.Printf("[DEBUG] createUnlockKey: failed to read response: %v\n", err)
		return nil, err
	}
	fmt.Printf("[DEBUG] createUnlockKey: received response: %+v\n", res)

	// TODO: extract the actual unlock key from `res` if available.
	return nil, nil
}

func (t *tunnelService) createUnlockKeyAsString() (string, error) {
	fmt.Println("[DEBUG] createUnlockKey: starting unlock key creation")

	req := map[string]interface{}{
		"request": map[string]interface{}{
			"_0": map[string]interface{}{
				"createRemoteUnlockKey": map[string]interface{}{},
			},
		},
	}
	fmt.Printf("[DEBUG] createUnlockKey: sending request: %+v\n", req)

	err := t.cipher.write(req)
	if err != nil {
		fmt.Printf("[DEBUG] createUnlockKey: failed to write request: %v\n", err)
		return "", err
  }
	fmt.Println("[DEBUG] createUnlockKey: request sent successfully")

	var res map[string]interface{}
	err = t.cipher.read(&res)
	if err != nil {
		fmt.Printf("[DEBUG] createUnlockKey: failed to read response: %v\n", err)
		return "", err
	}
	fmt.Printf("[DEBUG] createUnlockKey: received response: %+v\n", res)

	// Navigate the nested map to extract the hostKey string
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

	fmt.Printf("[DEBUG] createUnlockKey: extracted hostKey string: %s\n", hostKeyStr)
	return hostKeyStr, nil
}

func (t *tunnelService) verifyPair() error {
    log.Debug("verifyPair called")
    key, _ := ecdh.X25519().GenerateKey(rand.Reader)
    tlv := newTlvBuffer()
    tlv.writeByte(typeState, pairStateStartRequest)
    tlv.writeData(typePublicKey, key.PublicKey().Bytes())
    event := pairingData{
        data:            tlv.bytes(),
        kind:            "verifyManualPairing",
        startNewSession: true,
    }
    log.Debug("Sending Start Request event")
    err := t.controlChannel.writeEvent(&event)
    if err != nil {
        log.Printf("Error writing start request event: %v", err)
        return err
    }
    var devP pairingData
    log.Debug("Waiting for Device Pair Response")
    err = t.controlChannel.readEvent(&devP)
    if err != nil {
        log.Printf("Error reading device pair response: %v", err)
        return err
    }
    devicePublicKeyBytes, err := tlvReader(devP.data).readCoalesced(typePublicKey)
    log.Printf("Reading device public key from response, err: %v", err)

    if err != nil {
        log.Printf("Error reading device public key: %v", err)
        return err
    }
    log.Printf("Device Public Key Bytes: %v", devicePublicKeyBytes)
    if devicePublicKeyBytes == nil {
        log.Printf("Did not get public key from device")
        _ = t.controlChannel.writeEvent(pairVerifyFailed{})
        return fmt.Errorf("verifyPair: did not get public key from device. Can not verify pairing")
    }
    devicePublicKey, err := ecdh.X25519().NewPublicKey(devicePublicKeyBytes)
    log.Printf("Creating device public key, err: %v", err)
    if err != nil {
        log.Printf("Error creating device public key: %v", err)
        return err
    }
    sharedSecret, err := key.ECDH(devicePublicKey)
    log.Printf("Performing ECDH, err: %v", err)
    if err != nil {
        log.Printf("Error performing ECDH: %v", err)
        return err
    }
    derived := make([]byte, 32)
    _, err = hkdf.New(sha512.New, sharedSecret, []byte("Pair-Verify-Encrypt-Salt"), []byte("Pair-Verify-Encrypt-Info")).Read(derived)
    log.Printf("Deriving key, err: %v", err)
    if err != nil {
        log.Printf("Error deriving key: %v", err)
        return err
    }
    ci, err := chacha20poly1305.New(derived)
    log.Printf("Creating cipher, err: %v", err)
    if err != nil {
        log.Printf("Error creating cipher: %v", err)
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
    log.Printf("Sealing data, err: %v", encrypted)

    if encrypted == nil {
        log.Println("Encryption failed")
        return fmt.Errorf("encryption failed")
    }
    
    tlvEncrypted := newTlvBuffer()
    tlvEncrypted.writeByte(typeState, pairStateVerifyRequest)
    tlvEncrypted.writeData(typeEncryptedData, encrypted)
    eventEncrypted := pairingData{
        data: tlvEncrypted.bytes(),
        kind: "verifyPairing",
        startNewSession: false,
    }

    log.Debug("Sending Verify Request event")
    err = t.controlChannel.writeEvent(&eventEncrypted)
    if err != nil {
        log.Printf("Error writing verify request event: %v", err)
        return err
    }

    var responseP pairingData
    log.Debug("Waiting for Verify Response")
    err = t.controlChannel.readEvent(&responseP)
    if err != nil {
        log.Printf("Error reading verify response: %v", err)
        return err
    }

    errRes, err := tlvReader(responseP.data).readCoalesced(typeError)

    log.Printf("Reading error from response, err: %v, errRes: %v", err, errRes)
    if err != nil {
        log.Printf("Error reading error from response: %v", err)
        return err
    }
    if errRes != nil {
        log.Printf("Received error from response: %v", errRes)
        return fmt.Errorf("received error from response: %v", errRes)
    }
    log.Debug("Verify Pair successful")
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
	fmt.Println("[DEBUG] setupSessionKey: starting session key setup")

	devicePublicKey, deviceSalt, err := t.readDeviceKey()
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to read device public key and salt value: %w", err)
	}
	fmt.Printf("[DEBUG] setupSessionKey: devicePublicKey=%x, deviceSalt=%x\n", devicePublicKey, deviceSalt)

	srp, err := newSrpInfo(deviceSalt, devicePublicKey)
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to setup SRP: %w", err)
	}
	fmt.Printf("[DEBUG] setupSessionKey: SRP setup complete, ClientPublic=%x, ClientProof=%x\n", srp.ClientPublic, srp.ClientProof)

	proofTlv := newTlvBuffer()
	proofTlv.writeByte(typeState, pairStateVerifyRequest)
	proofTlv.writeData(typePublicKey, srp.ClientPublic)
	proofTlv.writeData(typeProof, srp.ClientProof)
	fmt.Printf("[DEBUG] setupSessionKey: proof TLV buffer prepared, bytes=%x\n", proofTlv.bytes())

	err = t.controlChannel.writeEvent(&pairingData{
		data: proofTlv.bytes(),
		kind: "setupManualPairing",
	})
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to send SRP proof: %w", err)
	}
	fmt.Println("[DEBUG] setupSessionKey: SRP proof sent to device")

	var proofPairingData pairingData
	err = t.controlChannel.readEvent(&proofPairingData)
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to read device SRP proof: %w", err)
	}
	fmt.Printf("[DEBUG] setupSessionKey: received device response, bytes=%x\n", proofPairingData.data)

	serverProof, err := tlvReader(proofPairingData.data).readCoalesced(typeProof)
	if err != nil {
		return nil, fmt.Errorf("setupSessionKey: failed to parse device proof: %w", err)
	}
	fmt.Printf("[DEBUG] setupSessionKey: extracted serverProof=%x\n", serverProof)

	verified := srp.verifyServerProof(serverProof)
	if !verified {
		fmt.Println("[DEBUG] setupSessionKey: server proof verification failed")
		return nil, fmt.Errorf("setupSessionKey: could not verify server proof")
	}
	fmt.Println("[DEBUG] setupSessionKey: server proof verified successfully")

	return srp.SessionKey, nil
}

func (t *tunnelService) exchangeDeviceInfo(sessionKey []byte) error {
	fmt.Println("[DEBUG] exchangeDeviceInfo: starting device info exchange")

	hkdfPairSetup := hkdf.New(sha512.New, sessionKey, []byte("Pair-Setup-Controller-Sign-Salt"), []byte("Pair-Setup-Controller-Sign-Info"))
	buf := bytes.NewBuffer(nil)
	_, _ = io.CopyN(buf, hkdfPairSetup, 32)
	_, _ = buf.WriteString(t.pairRecords.selfId.Identifier)
	_, _ = buf.Write(t.pairRecords.selfId.publicKey())

	fmt.Printf("[DEBUG] exchangeDeviceInfo: prepared signature buffer: %x\n", buf.Bytes())

	signature := ed25519.Sign(t.pairRecords.selfId.privateKey(), buf.Bytes())
	fmt.Printf("[DEBUG] exchangeDeviceInfo: signature: %x\n", signature)

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
		fmt.Printf("[DEBUG] exchangeDeviceInfo: failed to encode device info: %v\n", err)
		return err
	}
	fmt.Printf("[DEBUG] exchangeDeviceInfo: encoded deviceInfo (%d bytes)\n", len(deviceInfo))

	deviceInfoTlv := newTlvBuffer()
	deviceInfoTlv.writeData(typeSignature, signature)
	deviceInfoTlv.writeData(typePublicKey, t.pairRecords.selfId.publicKey())
	deviceInfoTlv.writeData(typeIdentifier, []byte(t.pairRecords.selfId.Identifier))
	deviceInfoTlv.writeData(typeInfo, deviceInfo)

	fmt.Printf("[DEBUG] exchangeDeviceInfo: constructed deviceInfo TLV (%d bytes)\n", len(deviceInfoTlv.bytes()))

	sessionKeyBuf := bytes.NewBuffer(nil)
	_, err = io.CopyN(sessionKeyBuf, hkdf.New(sha512.New, sessionKey, []byte("Pair-Setup-Encrypt-Salt"), []byte("Pair-Setup-Encrypt-Info")), 32)
	if err != nil {
		fmt.Printf("[DEBUG] exchangeDeviceInfo: failed to derive encryption key: %v\n", err)
		return err
	}
	setupKey := sessionKeyBuf.Bytes()
	fmt.Printf("[DEBUG] exchangeDeviceInfo: derived encryption key: %x\n", setupKey)

	cipher, err := chacha20poly1305.New(setupKey)
	if err != nil {
		fmt.Printf("[DEBUG] exchangeDeviceInfo: failed to create cipher: %v\n", err)
		return err
	}
	fmt.Println("[DEBUG] exchangeDeviceInfo: ChaCha20-Poly1305 cipher created")

	nonce := make([]byte, cipher.NonceSize())
	copy(nonce[4:], "PS-Msg05")
	x := cipher.Seal(nil, nonce, deviceInfoTlv.bytes(), nil)
	fmt.Printf("[DEBUG] exchangeDeviceInfo: encrypted deviceInfo TLV (%d bytes)\n", len(x))

	encryptedTlv := newTlvBuffer()
	encryptedTlv.writeByte(typeState, 0x05)
	encryptedTlv.writeData(typeEncryptedData, x)

	err = t.controlChannel.writeEvent(&pairingData{
		data:        encryptedTlv.bytes(),
		kind:        "setupManualPairing",
		sendingHost: "SL-1876",
	})
	if err != nil {
		fmt.Printf("[DEBUG] exchangeDeviceInfo: failed to send encrypted device info: %v\n", err)
		return err
	}
	fmt.Println("[DEBUG] exchangeDeviceInfo: sent encrypted device info")

	var encRes pairingData
	err = t.controlChannel.readEvent(&encRes)
	if err != nil {
		fmt.Printf("[DEBUG] exchangeDeviceInfo: failed to read encrypted response: %v\n", err)
		return err
	}
	fmt.Printf("[DEBUG] exchangeDeviceInfo: received response TLV (%d bytes)\n", len(encRes.data))

	encrData, err := tlvReader(encRes.data).readCoalesced(typeEncryptedData)
	if err != nil {
		fmt.Printf("[DEBUG] exchangeDeviceInfo: failed to parse encrypted response: %v\n", err)
		return err
	}
	fmt.Printf("[DEBUG] exchangeDeviceInfo: extracted encrypted data (%d bytes)\n", len(encrData))

	copy(nonce[4:], "PS-Msg06")
	_, err = cipher.Open(nil, nonce, encrData, nil)
	if err != nil {
		fmt.Printf("[DEBUG] exchangeDeviceInfo: failed to decrypt response: %v\n", err)
		return err
	}
	fmt.Println("[DEBUG] exchangeDeviceInfo: successfully decrypted device response")

	return nil
}
