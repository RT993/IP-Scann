package netutil

import (
	"fmt"
	"net/netip"
)

// MaxHosts caps how many addresses a single scan is allowed to enumerate.
// This keeps a mistyped CIDR (e.g. a /8) from spawning an unbounded number
// of probes; /16 (65 534 usable hosts) already covers any realistic LAN.
const MaxHosts = 65536

// HostsInCIDR expands an IPv4 CIDR into the list of addresses that should be
// probed. The network and broadcast addresses are skipped for prefixes
// shorter than /31, matching how every other IP scanner treats a subnet.
func HostsInCIDR(cidr string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 networks are supported")
	}
	prefix = prefix.Masked()
	bits := prefix.Bits()
	total := 1 << uint(32-bits)
	if total > MaxHosts {
		return nil, fmt.Errorf("network too large to scan: %d addresses (max %d, use a smaller subnet such as /16 or shorter)", total, MaxHosts)
	}

	addrs := make([]netip.Addr, 0, total)
	cur := prefix.Addr()
	for i := 0; i < total; i++ {
		skip := bits < 31 && (i == 0 || i == total-1)
		if !skip {
			addrs = append(addrs, cur)
		}
		if i < total-1 {
			cur = cur.Next()
		}
	}
	return addrs, nil
}
