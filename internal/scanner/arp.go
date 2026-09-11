package scanner

import (
	"os/exec"
	"regexp"
	"strings"
)

// arpLineRe matches the "(ip) at mac" fragment that both macOS's and
// Linux's "arp -a" output share, e.g.:
//
//	macOS:  hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
//	Linux:  ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
var arpLineRe = regexp.MustCompile(`\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{1,17})`)

// ipNeighRe matches "ip neigh show" output, the Linux fallback when the
// legacy "arp" binary isn't installed, e.g.:
//
//	192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
var ipNeighRe = regexp.MustCompile(`^(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{1,17})`)

// ReadARPTable returns the current OS ARP/neighbor cache as ip -> MAC.
// A ping sweep populates this cache for every host on the local L2 segment,
// so reading it back is how MAC addresses and duplicate-IP conflicts are
// discovered without needing raw sockets or elevated privileges.
func ReadARPTable() (map[string]string, error) {
	if out, err := exec.Command("arp", "-a").Output(); err == nil {
		return parseARPOutput(string(out)), nil
	}
	// Fall back to iproute2, common on Linux systems without net-tools.
	if out, err := exec.Command("ip", "neigh", "show").Output(); err == nil {
		return parseIPNeighOutput(string(out)), nil
	}
	return map[string]string{}, nil
}

func parseARPOutput(out string) map[string]string {
	table := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		m := arpLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		addMAC(table, m[1], m[2])
	}
	return table
}

func parseIPNeighOutput(out string) map[string]string {
	table := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "FAILED") || strings.Contains(line, "INCOMPLETE") {
			continue
		}
		m := ipNeighRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		addMAC(table, m[1], m[2])
	}
	return table
}

func addMAC(table map[string]string, ip, rawMAC string) {
	mac := normalizeMAC(rawMAC)
	if mac == "" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return
	}
	table[ip] = mac
}

// normalizeMAC lowercases a MAC and zero-pads any single-digit octet, since
// macOS's "arp -a" prints e.g. "8:0:27:..." rather than "08:00:27:...".
func normalizeMAC(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	parts := strings.Split(raw, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		switch len(p) {
		case 1:
			parts[i] = "0" + p
		case 2:
			// already fine
		default:
			return ""
		}
		for _, c := range parts[i] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return ""
			}
		}
	}
	return strings.Join(parts, ":")
}
