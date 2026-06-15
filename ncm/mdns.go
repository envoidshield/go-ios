package ncm

import (
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// Minimal mDNS responder.
//
// iOS over the CDC-NCM link stays IPv6 link-local only (no SLAAC, no Router
// Solicitations), but it does run Bonjour/mDNS on the cable. So instead of
// trying to give the phone a routable address, we let it resolve a *.local name
// to the host's link-local address. When iOS receives the AAAA over mDNS on its
// NCM interface it uses that interface as the IPv6 zone, so Safari can reach
// http://<name>/ even though the address is link-local.
//
// We answer AAAA queries for the configured hostname with the host's link-local
// address on the interface, and also push an unsolicited announcement.

const (
	mdnsPort    = 5353
	mdnsGroupV6 = "ff02::fb"

	typeAAAA   = 28
	typeANY    = 255
	classIN    = 1
	cacheFlush = 0x8000

	// DefaultMDNSName is advertised when PUBLIC_HOSTNAME is unset or empty.
	DefaultMDNSName = "envoid.local"
)

// MDNSName returns the hostname to advertise: $PUBLIC_HOSTNAME, or
// DefaultMDNSName when it is unset or empty.
func MDNSName() string {
	if h := strings.TrimSpace(os.Getenv("PUBLIC_HOSTNAME")); h != "" {
		return h
	}
	return DefaultMDNSName
}

// StartMDNS waits for the interface to get a link-local address, then runs an
// mDNS responder advertising host on it. It blocks, so run it in a goroutine.
func StartMDNS(ifaceName, host string) {
	var iface *net.Interface
	var ll net.IP
	for i := 0; i < 30; i++ {
		ifc, err := net.InterfaceByName(ifaceName)
		if err == nil {
			if ip := linkLocalOf(ifc); ip != nil {
				iface = ifc
				ll = ip
				break
			}
		}
		time.Sleep(time.Second)
	}
	if iface == nil || ll == nil {
		slog.Error("mdns: no link-local address found", "iface", ifaceName)
		return
	}
	runMDNS(iface, host, ll)
}

func runMDNS(iface *net.Interface, host string, ip net.IP) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	fqdn := host + "."

	group := &net.UDPAddr{IP: net.ParseIP(mdnsGroupV6), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp6", iface, group)
	if err != nil {
		slog.Error("mdns listen failed", "err", err, "iface", iface.Name)
		return
	}
	slog.Info("mdns responder up", "name", fqdn, "addr", ip.String(), "iface", iface.Name)

	answer := buildAAAAResponse(fqdn, ip)
	dst := &net.UDPAddr{IP: net.ParseIP(mdnsGroupV6), Port: mdnsPort, Zone: iface.Name}

	if _, err := conn.WriteToUDP(answer, dst); err != nil {
		slog.Error("mdns announce failed", "err", err)
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("mdns read failed", "err", err)
			return
		}
		if queriesName(buf[:n], fqdn) {
			if _, err := conn.WriteToUDP(answer, dst); err != nil {
				slog.Error("mdns respond failed", "err", err)
			}
		}
	}
}

// queriesName reports whether the mDNS packet contains a question for name with
// an AAAA/ANY type.
func queriesName(pkt []byte, name string) bool {
	if len(pkt) < 12 {
		return false
	}
	qd := int(pkt[4])<<8 | int(pkt[5])
	off := 12
	for i := 0; i < qd; i++ {
		qname, next, ok := decodeName(pkt, off)
		if !ok || next+4 > len(pkt) {
			return false
		}
		qtype := int(pkt[next])<<8 | int(pkt[next+1])
		off = next + 4
		if strings.EqualFold(qname, name) && (qtype == typeAAAA || qtype == typeANY) {
			return true
		}
	}
	return false
}

func decodeName(pkt []byte, off int) (string, int, bool) {
	var labels []string
	jumped := false
	next := off
	for {
		if off >= len(pkt) {
			return "", 0, false
		}
		l := int(pkt[off])
		if l == 0 {
			off++
			if !jumped {
				next = off
			}
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer
			if off+1 >= len(pkt) {
				return "", 0, false
			}
			ptr := (l&0x3F)<<8 | int(pkt[off+1])
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = ptr
			continue
		}
		if off+1+l > len(pkt) {
			return "", 0, false
		}
		labels = append(labels, string(pkt[off+1:off+1+l]))
		off += 1 + l
	}
	return strings.Join(labels, ".") + ".", next, true
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func buildAAAAResponse(fqdn string, ip net.IP) []byte {
	// Header: response, authoritative, 1 answer.
	pkt := []byte{
		0, 0, // ID
		0x84, 0x00, // flags: QR=1, AA=1
		0, 0, // QDCOUNT
		0, 1, // ANCOUNT
		0, 0, // NSCOUNT
		0, 0, // ARCOUNT
	}
	pkt = append(pkt, encodeName(fqdn)...)
	t := uint16(typeAAAA)
	c := uint16(classIN | cacheFlush)
	pkt = append(pkt, byte(t>>8), byte(t))
	pkt = append(pkt, byte(c>>8), byte(c))
	pkt = append(pkt, 0, 0, 0, 120) // TTL 120s
	pkt = append(pkt, 0, 16)        // RDLENGTH
	pkt = append(pkt, ip.To16()...)
	return pkt
}

func linkLocalOf(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip := ipnet.IP.To16(); ip != nil && ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	return nil
}
