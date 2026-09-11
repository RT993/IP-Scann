package scanner

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// nbnsHostname queries a host's NetBIOS Name Service (UDP/137) for its
// node status, which reliably returns the computer name for Windows PCs
// and most NAS/printer appliances that still speak NetBIOS/SMB, even when
// they have no DNS or mDNS record at all.
func nbnsHostname(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(buildNBNSQuery()); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	return parseNBNSResponse(buf[:n])
}

// buildNBNSQuery builds a NetBIOS Name Service Node Status ("NBSTAT")
// query for the wildcard name "*", the standard way to ask a host to list
// all of its registered NetBIOS names.
func buildNBNSQuery() []byte {
	buf := make([]byte, 0, 50)
	buf = append(buf, 0x82, 0x28) // transaction ID
	buf = append(buf, 0x00, 0x00) // flags: standard query, non-recursive
	buf = append(buf, 0x00, 0x01) // QDCOUNT = 1
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// First-level encoded NetBIOS name: the 16-byte wildcard name
	// ('*' followed by 15 NUL bytes), each byte split into two nibbles
	// mapped onto 'A'..'P'.
	buf = append(buf, 0x20)
	raw := [16]byte{0: '*'}
	for _, b := range raw {
		buf = append(buf, 'A'+(b>>4), 'A'+(b&0x0F))
	}
	buf = append(buf, 0x00) // root label terminator

	buf = append(buf, 0x00, 0x21) // QTYPE = NBSTAT
	buf = append(buf, 0x00, 0x01) // QCLASS = IN
	return buf
}

// parseNBNSResponse extracts the "workstation" (computer) name from a
// NBSTAT response's list of registered names.
func parseNBNSResponse(buf []byte) string {
	if len(buf) < 12 {
		return ""
	}
	ancount := int(binary.BigEndian.Uint16(buf[6:8]))
	if ancount == 0 {
		return ""
	}

	off, ok := skipDNSName(buf, 12)
	if !ok || off+10 > len(buf) {
		return ""
	}
	off += 8 // TYPE + CLASS + TTL
	rdlen := int(binary.BigEndian.Uint16(buf[off : off+2]))
	off += 2
	if off+rdlen > len(buf) || off >= len(buf) {
		return ""
	}

	numNames := int(buf[off])
	off++
	for i := 0; i < numNames; i++ {
		if off+18 > len(buf) {
			break
		}
		rawName := buf[off : off+15]
		suffix := buf[off+15]
		flags := binary.BigEndian.Uint16(buf[off+16 : off+18])
		off += 18

		const suffixWorkstation = 0x00
		const flagGroup = 0x8000
		if suffix != suffixWorkstation || flags&flagGroup != 0 {
			continue
		}
		name := strings.TrimRight(string(rawName), " \x00")
		if name != "" {
			return name
		}
	}
	return ""
}
