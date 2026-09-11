package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// mdnsHostname asks a host directly (unicast, port 5353) for the PTR record
// of its own reverse-DNS name. Most mDNS/Bonjour responders (macOS, iOS,
// Android, printers, smart-home gear, anything running avahi) answer this
// even though routers rarely set up real reverse DNS, which is why it
// catches far more devices than a plain LookupAddr call.
func mdnsHostname(ip string, timeout time.Duration) string {
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return ""
	}
	qname := fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0])

	query, err := buildDNSQuery(qname, 12 /* PTR */, true /* request unicast reply */)
	if err != nil {
		return ""
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "5353"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	name := parseDNSPTRResponse(buf[:n])
	if name == "" {
		return ""
	}
	return strings.TrimSuffix(name, ".")
}

// parseDNSPTRResponse extracts the first PTR record's target name from a
// raw DNS/mDNS response message.
func parseDNSPTRResponse(buf []byte) string {
	if len(buf) < 12 {
		return ""
	}
	qdcount := int(binary.BigEndian.Uint16(buf[4:6]))
	ancount := int(binary.BigEndian.Uint16(buf[6:8]))
	if ancount == 0 {
		return ""
	}

	off := 12
	for i := 0; i < qdcount; i++ {
		next, ok := skipDNSName(buf, off)
		if !ok || next+4 > len(buf) {
			return ""
		}
		off = next + 4 // QTYPE + QCLASS
	}

	for i := 0; i < ancount; i++ {
		_, next, ok := readDNSName(buf, off)
		if !ok {
			return ""
		}
		off = next
		if off+10 > len(buf) {
			return ""
		}
		rtype := binary.BigEndian.Uint16(buf[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
		off += 10
		if off+rdlen > len(buf) {
			return ""
		}
		if rtype == 12 { // PTR
			if name, _, ok := readDNSName(buf, off); ok && name != "" {
				return name
			}
		}
		off += rdlen
	}
	return ""
}

// buildDNSQuery encodes a single-question DNS query message. When
// unicastResponse is true, the top bit of the question's class is set to
// ask an mDNS responder to reply via unicast (RFC 6762 §5.4) rather than
// re-multicasting its answer.
func buildDNSQuery(qname string, qtype uint16, unicastResponse bool) ([]byte, error) {
	buf := make([]byte, 0, 32+len(qname))
	buf = append(buf, 0x00, 0x00)                         // transaction ID
	buf = append(buf, 0x00, 0x00)                         // flags: standard query
	buf = append(buf, 0x00, 0x01)                         // QDCOUNT = 1
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // ANCOUNT/NSCOUNT/ARCOUNT = 0

	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q", label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)

	qtypeBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(qtypeBuf, qtype)
	buf = append(buf, qtypeBuf...)

	class := uint16(0x0001) // IN
	if unicastResponse {
		class |= 0x8000
	}
	classBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(classBuf, class)
	buf = append(buf, classBuf...)

	return buf, nil
}
