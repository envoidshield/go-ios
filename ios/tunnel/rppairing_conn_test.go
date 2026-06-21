package tunnel

import (
	"encoding/base64"
	"net"
	"testing"
)

func TestRPPairingConn_roundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := newRPPairingConn(clientConn)
	s := newRPPairingConn(serverConn)

	go func() {
		_, _ = s.ReceiveOnClientServerStream()
		_ = s.Send(map[string]interface{}{
			"value": map[string]interface{}{
				"message": map[string]interface{}{
					"plain": map[string]interface{}{
						"_0": map[string]interface{}{
							"response": map[string]interface{}{
								"_1": map[string]interface{}{
									"handshake": map[string]interface{}{
										"_0": map[string]interface{}{
											"deviceOptions": map[string]interface{}{
												"peerDeviceInfo": map[string]interface{}{
													"udid": "00008150-001E159E2187801C",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				"originatedBy":   "device",
				"sequenceNumber": float64(1),
			},
		})
	}()

	err := c.Send(map[string]interface{}{
		"value": map[string]interface{}{
			"message": map[string]interface{}{
				"plain": map[string]interface{}{
					"_0": map[string]interface{}{
						"request": map[string]interface{}{
							"_0": map[string]interface{}{
								"handshake": map[string]interface{}{
									"_0": map[string]interface{}{
										"hostOptions": map[string]interface{}{
											"attemptPairVerify": true,
										},
									},
								},
							},
						},
					},
				},
			},
			"originatedBy":   "host",
			"sequenceNumber": float64(1),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ReceiveOnClientServerStream()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := getChildMap(got, "value", "message")
	if err != nil {
		t.Fatal(err)
	}
	if udid := parseHandshakeUDID(msg); udid != "00008150-001E159E2187801C" {
		t.Fatalf("udid = %q", udid)
	}
}

func TestPairingDataDecode_base64String(t *testing.T) {
	var pd pairingData
	err := pd.Decode(map[string]interface{}{
		"pairingData": map[string]interface{}{
			"_0": map[string]interface{}{
				"data":            base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
				"kind":            "verifyManualPairing",
				"startNewSession": true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pd.data) != 3 || pd.data[0] != 1 {
		t.Fatalf("data = %v", pd.data)
	}
}
