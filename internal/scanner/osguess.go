package scanner

import (
	"fmt"
	"strings"
)

// OSGuess is a best-effort, heuristic guess at what a host is running.
//
// Real OS fingerprinting (nmap/p0f-style) inspects the exact ordering and
// values of TCP options in a SYN/ACK, which needs a raw socket and
// root/admin privileges. This app deliberately never requires elevated
// privileges, so it settles for weaker but still genuinely useful signals
// that are available from ordinary sockets and the OS ping binary: the
// reply's TTL (different OS families ship different default initial TTLs),
// the MAC vendor, and which well-known ports are open. It is a guess, and
// is reported as one -- never treated as a confirmed OS.
type OSGuess struct {
	Label      string   `json:"label,omitempty"`
	Confidence string   `json:"confidence,omitempty"` // "low" | "medium" | "high"
	Signals    []string `json:"signals,omitempty"`
}

var routerVendorHints = []string{
	"ubiquiti", "netgear", "tp-link", "tp link", "d-link", "cisco",
	"asustek", "mikrotik", "aruba", "juniper", "linksys", "belkin", "fortinet",
}

// GuessOS combines a host's ping TTL, MAC vendor, and any open ports known
// so far into a single labeled guess with the evidence ("signals") that led
// to it, so the UI can show its reasoning rather than an unexplained label.
func GuessOS(ttl int, vendor string, openPorts []int) OSGuess {
	var g OSGuess

	switch {
	case ttl <= 0:
		// No ICMP reply to read a TTL from (host was found via TCP only).
	case ttl <= 64:
		g.Label = "Linux / macOS / Unix"
		g.Confidence = "medium"
		g.Signals = append(g.Signals, fmt.Sprintf("ping TTL %d (≤64: default on Linux, macOS, BSD, and most routers)", ttl))
	case ttl <= 128:
		g.Label = "Windows"
		g.Confidence = "medium"
		g.Signals = append(g.Signals, fmt.Sprintf("ping TTL %d (≤128: default on Windows)", ttl))
	default:
		g.Label = "Network device"
		g.Confidence = "low"
		g.Signals = append(g.Signals, fmt.Sprintf("ping TTL %d (>128: often a router, switch, or appliance default)", ttl))
	}

	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "apple"):
		g.Label = "macOS / iOS (Apple device)"
		g.Confidence = "high"
		g.Signals = append(g.Signals, "MAC vendor: Apple")
	case strings.Contains(v, "raspberry pi"):
		g.Label = "Linux (Raspberry Pi)"
		g.Confidence = "high"
		g.Signals = append(g.Signals, "MAC vendor: Raspberry Pi Foundation")
	case isRouterVendor(v):
		if g.Label == "" || g.Confidence == "low" {
			g.Label = "Network device (" + vendor + ")"
			g.Confidence = "medium"
		}
		g.Signals = append(g.Signals, "MAC vendor: "+vendor+" (networking equipment maker)")
	}

	hasPort := func(p int) bool {
		for _, x := range openPorts {
			if x == p {
				return true
			}
		}
		return false
	}
	if hasPort(3389) {
		g.Label = "Windows"
		g.Confidence = "high"
		g.Signals = append(g.Signals, "port 3389 open (Remote Desktop)")
	}
	if hasPort(22) && !hasPort(3389) {
		if g.Label == "" {
			g.Label = "Linux / macOS / Unix"
			g.Confidence = "medium"
		}
		g.Signals = append(g.Signals, "port 22 open (SSH)")
	}
	if hasPort(445) || hasPort(139) {
		g.Signals = append(g.Signals, "SMB/file-sharing port open")
	}
	if hasPort(631) || hasPort(9100) || hasPort(515) {
		g.Signals = append(g.Signals, "printing port open (this may be a printer rather than a general-purpose OS)")
	}

	if g.Label == "" {
		g.Label = "Unknown"
		g.Confidence = "low"
	}
	return g
}

func isRouterVendor(vendorLower string) bool {
	for _, hint := range routerVendorHints {
		if strings.Contains(vendorLower, hint) {
			return true
		}
	}
	return false
}
