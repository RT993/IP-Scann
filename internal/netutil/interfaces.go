// Package netutil provides helpers for discovering local network interfaces
// and enumerating the addresses within a subnet.
package netutil

import (
	"fmt"
	"net"
	"sort"
)

// Interface describes a local, active IPv4-capable network interface.
type Interface struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	CIDR    string `json:"cidr"`
	Primary bool   `json:"primary"`
}

// ListInterfaces returns all "up", non-loopback interfaces that carry an
// IPv4 address, along with the subnet each address belongs to.
func ListInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			network := ipNet.IP.Mask(ipNet.Mask)
			result = append(result, Interface{
				Name:    iface.Name,
				IP:      ip4.String(),
				CIDR:    fmt.Sprintf("%s/%d", network.String(), ones),
				Primary: isPrivate(ip4),
			})
		}
	}

	// Prefer private/LAN-style addresses first, since those are almost
	// always what someone scanning "their network" wants to see up top.
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Primary != result[j].Primary {
			return result[i].Primary
		}
		return result[i].Name < result[j].Name
	})

	return result, nil
}

func isPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
