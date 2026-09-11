package scanner

import "testing"

const sampleNmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -oX - -T4 -F -sV -O 192.168.1.15">
<host starttime="0" endtime="0">
<status state="up" reason="echo-reply" reason_ttl="64"/>
<address addr="192.168.1.15" addrtype="ipv4"/>
<address addr="3C:06:30:AA:BB:CC" addrtype="mac" vendor="Apple"/>
<hostnames>
<hostname name="Johns-MacBook-Pro.local" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="9.0" extrainfo="protocol 2.0" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="80">
<state state="closed" reason="conn-refused" reason_ttl="64"/>
<service name="http" method="table" conf="3"/>
</port>
</ports>
<os>
<osmatch name="Apple macOS 11.0 (Big Sur) - 13.0 (Ventura)" accuracy="95" line="12345">
</osmatch>
<osmatch name="Apple Mac OS X 10.15 (Catalina)" accuracy="90" line="23456">
</osmatch>
</os>
</host>
</nmaprun>
`

func TestParseNmapXML(t *testing.T) {
	result, err := parseNmapXML([]byte(sampleNmapXML), "192.168.1.15")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IP != "192.168.1.15" {
		t.Errorf("IP = %q", result.IP)
	}
	if result.State != "up" {
		t.Errorf("State = %q", result.State)
	}
	if result.Hostname != "Johns-MacBook-Pro.local" {
		t.Errorf("Hostname = %q", result.Hostname)
	}

	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 open port (closed port excluded), got %d: %+v", len(result.Ports), result.Ports)
	}
	p := result.Ports[0]
	if p.Port != 22 || p.Protocol != "tcp" || p.Service != "ssh" || p.Product != "OpenSSH" || p.Version != "9.0" {
		t.Errorf("unexpected port info: %+v", p)
	}

	if len(result.OSMatches) != 2 {
		t.Fatalf("expected 2 OS matches, got %d", len(result.OSMatches))
	}
	if result.OSMatches[0].Name != "Apple macOS 11.0 (Big Sur) - 13.0 (Ventura)" || result.OSMatches[0].Accuracy != 95 {
		t.Errorf("unexpected top OS match: %+v", result.OSMatches[0])
	}
}

func TestParseNmapXML_NoMatchingHost(t *testing.T) {
	if _, err := parseNmapXML([]byte(sampleNmapXML), "10.0.0.99"); err == nil {
		t.Fatal("expected error when the requested IP isn't in the report")
	}
}

func TestParseNmapXML_InvalidXML(t *testing.T) {
	if _, err := parseNmapXML([]byte("not xml"), "192.168.1.15"); err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestDeepScan_NmapNotAvailable(t *testing.T) {
	// This test only checks the not-installed error path is reachable and
	// well-formed; it does not assert on NmapAvailable() itself, since
	// that depends on the environment nmap is (or isn't) installed in.
	if NmapAvailable() {
		t.Skip("nmap is installed in this environment; not-found path not exercised")
	}
	_, err := DeepScan(t.Context(), "127.0.0.1", DeepScanOptions{})
	if err == nil {
		t.Fatal("expected error when nmap is not installed")
	}
}
