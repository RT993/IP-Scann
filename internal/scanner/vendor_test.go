package scanner

import "testing"

func TestVendorLookup(t *testing.T) {
	cases := []struct {
		mac  string
		want string
	}{
		{"b8:27:eb:11:22:33", "Raspberry Pi Foundation"},
		{"B8:27:EB:11:22:33", "Raspberry Pi Foundation"},
		{"080027aabbcc", "PCS Systemtechnik GmbH"}, // VirtualBox's default OUI
		{"ff:ff:ff:ff:ff:ff", "Unknown"},
		{"", "Unknown"},
	}
	for _, c := range cases {
		if got := VendorLookup(c.mac); got != c.want {
			t.Errorf("VendorLookup(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}
