package netutil

import "testing"

func TestHostsInCIDR_Slash24(t *testing.T) {
	addrs, err := HostsInCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 254 {
		t.Fatalf("expected 254 hosts, got %d", len(addrs))
	}
	if addrs[0].String() != "192.168.1.1" {
		t.Errorf("expected first host 192.168.1.1, got %s", addrs[0])
	}
	last := addrs[len(addrs)-1]
	if last.String() != "192.168.1.254" {
		t.Errorf("expected last host 192.168.1.254, got %s", last)
	}
}

func TestHostsInCIDR_Slash30(t *testing.T) {
	addrs, err := HostsInCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 has 4 addresses, network + broadcast excluded leaves 2 usable.
	if len(addrs) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(addrs))
	}
}

func TestHostsInCIDR_Slash31(t *testing.T) {
	addrs, err := HostsInCIDR("10.0.0.0/31")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// RFC 3021: both addresses in a /31 are usable point-to-point hosts.
	if len(addrs) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(addrs))
	}
}

func TestHostsInCIDR_TooLarge(t *testing.T) {
	_, err := HostsInCIDR("10.0.0.0/8")
	if err == nil {
		t.Fatal("expected error for oversized network, got nil")
	}
}

func TestHostsInCIDR_InvalidCIDR(t *testing.T) {
	if _, err := HostsInCIDR("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestHostsInCIDR_IPv6Rejected(t *testing.T) {
	if _, err := HostsInCIDR("2001:db8::/64"); err == nil {
		t.Fatal("expected error for IPv6 CIDR")
	}
}

func TestBroadcastAddr(t *testing.T) {
	cases := map[string]string{
		"192.168.1.0/24":   "192.168.1.255",
		"192.168.1.128/25": "192.168.1.255",
		"10.0.0.0/16":      "10.0.255.255",
		"10.0.0.5/32":      "10.0.0.5",
	}
	for cidr, want := range cases {
		got, err := BroadcastAddr(cidr)
		if err != nil {
			t.Fatalf("BroadcastAddr(%q): %v", cidr, err)
		}
		if got != want {
			t.Errorf("BroadcastAddr(%q) = %q, want %q", cidr, got, want)
		}
	}
}
