package scanner

import "testing"

func TestParseARPOutput_MacOSFormat(t *testing.T) {
	out := `? (192.168.1.1) at 8:0:27:aa:bb:cc on en0 ifscope [ethernet]
router.local (192.168.1.254) at a4:83:e7:12:34:56 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]`

	table := parseARPOutput(out)
	if len(table) != 2 {
		t.Fatalf("expected 2 entries (broadcast excluded), got %d: %+v", len(table), table)
	}
	if table["192.168.1.1"] != "08:00:27:aa:bb:cc" {
		t.Errorf("expected zero-padded MAC, got %q", table["192.168.1.1"])
	}
	if table["192.168.1.254"] != "a4:83:e7:12:34:56" {
		t.Errorf("unexpected MAC for .254: %q", table["192.168.1.254"])
	}
}

func TestParseARPOutput_LinuxFormat(t *testing.T) {
	out := `? (192.168.1.10) at aa:bb:cc:dd:ee:ff [ether] on eth0
? (192.168.1.11) at <incomplete> on eth0`

	table := parseARPOutput(out)
	if len(table) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(table), table)
	}
	if table["192.168.1.10"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("unexpected MAC: %q", table["192.168.1.10"])
	}
}

func TestParseIPNeighOutput(t *testing.T) {
	out := `192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE
192.168.1.3 dev eth0 FAILED`

	table := parseIPNeighOutput(out)
	if len(table) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(table), table)
	}
	if table["192.168.1.1"] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("unexpected MAC: %q", table["192.168.1.1"])
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"8:0:27:aa:bb:cc":    "08:00:27:aa:bb:cc",
		"AA:BB:CC:DD:EE:FF":  "aa:bb:cc:dd:ee:ff",
		"aa:bb:cc:dd:ee:ff":  "aa:bb:cc:dd:ee:ff",
		"aa:bb:cc:dd:ee":     "",
		"gg:bb:cc:dd:ee:ff":  "",
		"aaa:bb:cc:dd:ee:ff": "",
	}
	for in, want := range cases {
		if got := normalizeMAC(in); got != want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}
