package scanner

import "sort"

// ConflictReport summarizes duplicate-address findings across all
// observation passes of a scan.
type ConflictReport struct {
	// DuplicateIPs maps an IP address that answered from more than one MAC
	// address (across passes) to the sorted list of MACs seen -- a genuine
	// IP conflict.
	DuplicateIPs map[string][]string
	// DuplicateMACs maps a MAC address that was seen behind more than one
	// IP address to the sorted list of IPs -- typically a cloned MAC,
	// misconfigured static IP, or a moving DHCP lease caught mid-scan.
	DuplicateMACs map[string][]string
}

// DetectConflicts merges a series of ip->MAC observations (one map per scan
// pass) and reports every IP or MAC seen more than once with a different
// partner. Running several passes a little apart in time is what makes this
// possible without raw ARP sockets: a live conflict causes the OS ARP cache
// to flip between the two contending MAC addresses from one pass to the
// next.
func DetectConflicts(passes []map[string]string) ConflictReport {
	ipToMACs := make(map[string]map[string]bool)
	macToIPs := make(map[string]map[string]bool)

	for _, pass := range passes {
		for ip, mac := range pass {
			if mac == "" {
				continue
			}
			if ipToMACs[ip] == nil {
				ipToMACs[ip] = make(map[string]bool)
			}
			ipToMACs[ip][mac] = true

			if macToIPs[mac] == nil {
				macToIPs[mac] = make(map[string]bool)
			}
			macToIPs[mac][ip] = true
		}
	}

	report := ConflictReport{
		DuplicateIPs:  make(map[string][]string),
		DuplicateMACs: make(map[string][]string),
	}
	for ip, macs := range ipToMACs {
		if len(macs) > 1 {
			report.DuplicateIPs[ip] = sortedKeys(macs)
		}
	}
	for mac, ips := range macToIPs {
		if len(ips) > 1 {
			report.DuplicateMACs[mac] = sortedKeys(ips)
		}
	}
	return report
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
