package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DeepScanResult is the output of an nmap-backed deep scan for one host:
// genuine raw-packet OS fingerprinting and nmap's full version-detection
// probe database, well beyond the heuristic OS guess and banner-grabbing
// this app otherwise uses to stay root-free.
type DeepScanResult struct {
	IP        string         `json:"ip"`
	State     string         `json:"state,omitempty"`
	Hostname  string         `json:"hostname,omitempty"`
	Ports     []DeepScanPort `json:"ports,omitempty"`
	OSMatches []DeepScanOS   `json:"osMatches,omitempty"`
}

type DeepScanPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Service   string `json:"service,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extraInfo,omitempty"`
}

type DeepScanOS struct {
	Name     string `json:"name"`
	Accuracy int    `json:"accuracy"`
}

// DeepScanOptions configures one nmap run.
type DeepScanOptions struct {
	ServiceVersion bool // -sV
	OSDetection    bool // -O (needs root/admin to do anything useful)
}

// NmapAvailable reports whether the nmap binary can be found on PATH.
func NmapAvailable() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// IsRoot reports whether the current process is running as root/admin,
// which nmap needs for OS detection (-O) and raw-packet SYN scans to work.
// On platforms without the concept (Windows), os.Geteuid returns -1, so
// this simply reports false there.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// DeepScan shells out to nmap for one host and parses its XML output. This
// is the one tool in this app that both depends on an external binary and
// benefits from -- but doesn't require -- root privileges (OS detection is
// skipped, with a warning on nmap's side, when unprivileged).
func DeepScan(ctx context.Context, ip string, opts DeepScanOptions) (*DeepScanResult, error) {
	if !NmapAvailable() {
		return nil, fmt.Errorf(`nmap not found in PATH -- install it (e.g. "brew install nmap") to use deep scan`)
	}

	args := []string{"-oX", "-", "-T4", "-F"} // -F: fast mode, top 100 ports
	if opts.ServiceVersion {
		args = append(args, "-sV")
	}
	if opts.OSDetection {
		args = append(args, "-O")
	}
	args = append(args, ip)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("nmap failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("nmap failed: %w", err)
	}
	return parseNmapXML(out, ip)
}

// ---------- nmap -oX XML shape (only the fields this app uses) ----------

type nmapXMLRun struct {
	Hosts []nmapXMLHost `xml:"host"`
}

type nmapXMLHost struct {
	Status    nmapXMLStatus    `xml:"status"`
	Addresses []nmapXMLAddress `xml:"address"`
	Hostnames struct {
		Hostname []nmapXMLHostname `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Port []nmapXMLPort `xml:"port"`
	} `xml:"ports"`
	OS struct {
		OSMatch []nmapXMLOSMatch `xml:"osmatch"`
	} `xml:"os"`
}

type nmapXMLStatus struct {
	State string `xml:"state,attr"`
}

type nmapXMLAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapXMLHostname struct {
	Name string `xml:"name,attr"`
}

type nmapXMLPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name      string `xml:"name,attr"`
		Product   string `xml:"product,attr"`
		Version   string `xml:"version,attr"`
		ExtraInfo string `xml:"extrainfo,attr"`
	} `xml:"service"`
}

type nmapXMLOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

// parseNmapXML converts nmap's XML report into a DeepScanResult for wantIP.
func parseNmapXML(data []byte, wantIP string) (*DeepScanResult, error) {
	var run nmapXMLRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap output: %w", err)
	}

	for _, h := range run.Hosts {
		var ip string
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
			}
		}
		if ip != wantIP {
			continue
		}

		result := &DeepScanResult{IP: ip, State: h.Status.State}
		if len(h.Hostnames.Hostname) > 0 {
			result.Hostname = h.Hostnames.Hostname[0].Name
		}
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			result.Ports = append(result.Ports, DeepScanPort{
				Port:      p.PortID,
				Protocol:  p.Protocol,
				Service:   p.Service.Name,
				Product:   p.Service.Product,
				Version:   p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo,
			})
		}
		for _, m := range h.OS.OSMatch {
			result.OSMatches = append(result.OSMatches, DeepScanOS{Name: m.Name, Accuracy: m.Accuracy})
		}
		return result, nil
	}
	return nil, fmt.Errorf("nmap returned no results for %s", wantIP)
}
