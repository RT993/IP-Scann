package scanner

import "testing"

func encodeName(labels ...string) []byte {
	var buf []byte
	for _, l := range labels {
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0x00)
	return buf
}

func TestReadDNSName_Uncompressed(t *testing.T) {
	buf := encodeName("myhost", "local")
	name, next, ok := readDNSName(buf, 0)
	if !ok {
		t.Fatal("expected ok")
	}
	if name != "myhost.local" {
		t.Errorf("got %q", name)
	}
	if next != len(buf) {
		t.Errorf("next = %d, want %d", next, len(buf))
	}
}

func TestReadDNSName_Compressed(t *testing.T) {
	// Layout: [0:] "myhost.local\0"  [after:] pointer back to offset 0.
	base := encodeName("myhost", "local")
	buf := append([]byte{}, base...)
	ptrOffset := len(buf)
	buf = append(buf, 0xC0, 0x00) // pointer to offset 0

	name, next, ok := readDNSName(buf, ptrOffset)
	if !ok {
		t.Fatal("expected ok")
	}
	if name != "myhost.local" {
		t.Errorf("got %q", name)
	}
	if next != ptrOffset+2 {
		t.Errorf("next = %d, want %d", next, ptrOffset+2)
	}
}

func TestSkipDNSName(t *testing.T) {
	buf := encodeName("a", "bc", "def")
	next, ok := skipDNSName(buf, 0)
	if !ok || next != len(buf) {
		t.Errorf("skipDNSName = (%d, %v), want (%d, true)", next, ok, len(buf))
	}
}

func TestBuildDNSQuery_UnicastBit(t *testing.T) {
	q, err := buildDNSQuery("1.0.168.192.in-addr.arpa.", 12, true)
	if err != nil {
		t.Fatal(err)
	}
	// Last two bytes are QCLASS; top bit set means "unicast response".
	class := uint16(q[len(q)-2])<<8 | uint16(q[len(q)-1])
	if class&0x8000 == 0 {
		t.Error("expected unicast-response bit set in QCLASS")
	}
	if class&0x7FFF != 1 {
		t.Errorf("expected class IN (1), got %d", class&0x7FFF)
	}
}

func TestParseDNSPTRResponse(t *testing.T) {
	// Build a minimal DNS response: 1 question, 1 PTR answer.
	var buf []byte
	buf = append(buf, 0x00, 0x00, 0x84, 0x00) // ID, flags
	buf = append(buf, 0x00, 0x01)             // QDCOUNT=1
	buf = append(buf, 0x00, 0x01)             // ANCOUNT=1
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // NSCOUNT/ARCOUNT

	q := encodeName("1", "0", "168", "192", "in-addr", "arpa")
	buf = append(buf, q...)
	buf = append(buf, 0x00, 0x0C) // QTYPE PTR
	buf = append(buf, 0x00, 0x01) // QCLASS IN

	// Answer: name = pointer to question name, type PTR, class IN, TTL, RDATA.
	buf = append(buf, 0xC0, 0x0C)             // pointer to offset 12 (start of question name)
	buf = append(buf, 0x00, 0x0C)             // TYPE PTR
	buf = append(buf, 0x00, 0x01)             // CLASS IN
	buf = append(buf, 0x00, 0x00, 0x00, 0x78) // TTL

	rdata := encodeName("kitchen-printer", "local")
	rdlen := make([]byte, 2)
	rdlen[0] = byte(len(rdata) >> 8)
	rdlen[1] = byte(len(rdata))
	buf = append(buf, rdlen...)
	buf = append(buf, rdata...)

	name := parseDNSPTRResponse(buf)
	if name != "kitchen-printer.local" {
		t.Errorf("got %q", name)
	}
}

func TestBuildNBNSQuery_Shape(t *testing.T) {
	q := buildNBNSQuery()
	if len(q) != 50 {
		t.Fatalf("expected 50-byte query, got %d", len(q))
	}
	if q[12] != 0x20 {
		t.Errorf("expected encoded-name length byte 0x20, got %#x", q[12])
	}
	// QTYPE (NBSTAT=0x21) and QCLASS (IN=1) are the last 4 bytes.
	if q[len(q)-4] != 0x00 || q[len(q)-3] != 0x21 {
		t.Errorf("unexpected QTYPE bytes: %#x %#x", q[len(q)-4], q[len(q)-3])
	}
}

func TestParseNBNSResponse(t *testing.T) {
	var buf []byte
	buf = append(buf, 0x82, 0x28, 0x84, 0x00) // ID, flags
	buf = append(buf, 0x00, 0x00)             // QDCOUNT=0
	buf = append(buf, 0x00, 0x01)             // ANCOUNT=1
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)

	// RR name: encoded wildcard name (same shape as the query name).
	buf = append(buf, 0x20)
	for i := 0; i < 32; i++ {
		buf = append(buf, 'A')
	}
	buf = append(buf, 0x00)

	buf = append(buf, 0x00, 0x21)             // TYPE NBSTAT
	buf = append(buf, 0x00, 0x01)             // CLASS IN
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // TTL

	// RDATA: NUM_NAMES=1, then one 18-byte entry for "DESKTOP-ABC" suffix 0x00, unique.
	var rdata []byte
	rdata = append(rdata, 0x01)
	nameField := make([]byte, 15)
	copy(nameField, "DESKTOP-ABC")
	for i := len("DESKTOP-ABC"); i < 15; i++ {
		nameField[i] = ' '
	}
	rdata = append(rdata, nameField...)
	rdata = append(rdata, 0x00)       // suffix: workstation
	rdata = append(rdata, 0x04, 0x00) // flags: unique (group bit clear)

	rdlen := make([]byte, 2)
	rdlen[0] = byte(len(rdata) >> 8)
	rdlen[1] = byte(len(rdata))
	buf = append(buf, rdlen...)
	buf = append(buf, rdata...)

	name := parseNBNSResponse(buf)
	if name != "DESKTOP-ABC" {
		t.Errorf("got %q", name)
	}
}

func TestParseNBNSResponse_SkipsGroupNames(t *testing.T) {
	var buf []byte
	buf = append(buf, 0x82, 0x28, 0x84, 0x00)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x20)
	for i := 0; i < 32; i++ {
		buf = append(buf, 'A')
	}
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)

	var rdata []byte
	rdata = append(rdata, 0x01)
	nameField := make([]byte, 15)
	copy(nameField, "WORKGROUP")
	for i := len("WORKGROUP"); i < 15; i++ {
		nameField[i] = ' '
	}
	rdata = append(rdata, nameField...)
	rdata = append(rdata, 0x00)       // suffix: workstation, but...
	rdata = append(rdata, 0x84, 0x00) // flags: group bit SET -> must be skipped

	rdlen := make([]byte, 2)
	rdlen[0] = byte(len(rdata) >> 8)
	rdlen[1] = byte(len(rdata))
	buf = append(buf, rdlen...)
	buf = append(buf, rdata...)

	if name := parseNBNSResponse(buf); name != "" {
		t.Errorf("expected group name to be skipped, got %q", name)
	}
}
