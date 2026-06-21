package tunnel

import "testing"

func handshakeResponse(udid, identifier string) map[string]interface{} {
	peer := map[string]interface{}{}
	if udid != "" {
		peer["udid"] = udid
	}
	if identifier != "" {
		peer["identifier"] = identifier
	}
	return map[string]interface{}{
		"plain": map[string]interface{}{
			"_0": map[string]interface{}{
				"response": map[string]interface{}{
					"_1": map[string]interface{}{
						"handshake": map[string]interface{}{
							"_0": map[string]interface{}{
								"deviceOptions": map[string]interface{}{
									"peerDeviceInfo": peer,
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestParseHandshakeUDID_fromUDIDField(t *testing.T) {
	want := "00008030-1234567890123456"
	if got := parseHandshakeUDID(handshakeResponse(want, "")); got != want {
		t.Fatalf("parseHandshakeUDID = %q, want %q", got, want)
	}
}

func TestParseHandshakeUDID_fromIdentifierFallback(t *testing.T) {
	want := "00008030-1234567890123456"
	if got := parseHandshakeUDID(handshakeResponse("", want)); got != want {
		t.Fatalf("parseHandshakeUDID = %q, want %q", got, want)
	}
}

func TestParseHandshakeUDID_missing(t *testing.T) {
	if got := parseHandshakeUDID(map[string]interface{}{}); got != "" {
		t.Fatalf("parseHandshakeUDID = %q, want empty", got)
	}
}
