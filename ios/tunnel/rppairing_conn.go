package tunnel

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

var rpPairingMagic = []byte("RPPairing")

// rppairingConn speaks the JSON RPPairing socket protocol used by
// _remotepairing._tcp (WiFi/BT-PAN). RemoteXPC/HTTP/2 is for USB tunnel paths only.
type rppairingConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func newRPPairingConn(conn net.Conn) *rppairingConn {
	return &rppairingConn{conn: conn}
}

func (r *rppairingConn) Send(envelope map[string]interface{}, _ ...uint32) error {
	value, ok := envelope["value"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("rppairingConn.Send: missing value")
	}
	payload, err := json.Marshal(normalizeOutgoing(value))
	if err != nil {
		return fmt.Errorf("rppairingConn.Send: marshal: %w", err)
	}
	return r.writeFrame(payload)
}

func (r *rppairingConn) ReceiveOnClientServerStream() (map[string]interface{}, error) {
	payload, err := r.readFrame()
	if err != nil {
		return nil, err
	}
	var msg map[string]interface{}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("rppairingConn.Receive: unmarshal: %w", err)
	}
	normalizeIncoming(msg)
	return map[string]interface{}{
		"mangledTypeName": "RemotePairingDevice.ControlChannelMessageEnvelope",
		"value":           msg,
	}, nil
}

func (r *rppairingConn) writeFrame(payload []byte) error {
	if len(payload) > 0xffff {
		return fmt.Errorf("rppairingConn: frame too large")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	header := make([]byte, 11)
	copy(header, rpPairingMagic)
	binary.BigEndian.PutUint16(header[9:], uint16(len(payload)))
	if _, err := r.conn.Write(header); err != nil {
		return err
	}
	_, err := r.conn.Write(payload)
	return err
}

func (r *rppairingConn) readFrame() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	magic := make([]byte, 9)
	if _, err := io.ReadFull(r.conn, magic); err != nil {
		return nil, err
	}
	if string(magic) != string(rpPairingMagic) {
		return nil, fmt.Errorf("rppairingConn: bad magic %q", magic)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(r.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n <= 0 || n > 1<<20 {
		return nil, fmt.Errorf("rppairingConn: invalid frame length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r.conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func normalizeOutgoing(v map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(v))
	for k, val := range v {
		out[k] = normalizeValue(val, true)
	}
	return out
}

func normalizeIncoming(v map[string]interface{}) {
	for k, val := range v {
		v[k] = normalizeValue(val, false)
	}
}

func normalizeValue(v interface{}, out bool) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		if out {
			m := make(map[string]interface{}, len(x))
			for k, val := range x {
				m[k] = normalizeValue(val, true)
			}
			return m
		}
		for k, val := range x {
			x[k] = normalizeValue(val, false)
		}
		return x
	case []interface{}:
		for i, val := range x {
			x[i] = normalizeValue(val, out)
		}
		return x
	case []byte:
		if out {
			return base64.StdEncoding.EncodeToString(x)
		}
		return x
	case string:
		if !out {
			if b, err := base64.StdEncoding.DecodeString(x); err == nil {
				return b
			}
		}
		return x
	default:
		return v
	}
}
