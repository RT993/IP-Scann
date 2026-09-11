package scanner

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// pingOnce shells out to the system "ping" binary for a single echo request.
// Using the OS binary (rather than a raw ICMP socket) is what lets this run
// without root/admin privileges on both Intel and Apple Silicon Macs.
func pingOnce(ctx context.Context, ip string, timeout time.Duration) (bool, time.Duration) {
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	timeoutSec := int(timeout.Round(time.Second) / time.Second)
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	// Guarantee the subprocess can't outlive the requested timeout even if
	// the platform's flag for it behaves unexpectedly.
	cmdCtx, cancel := context.WithTimeout(ctx, timeout+250*time.Millisecond)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		// macOS ping: -W is in milliseconds.
		cmd = exec.CommandContext(cmdCtx, "ping", "-c", "1", "-W", strconv.Itoa(int(timeout.Milliseconds())), ip)
	case "windows":
		cmd = exec.CommandContext(cmdCtx, "ping", "-n", "1", "-w", strconv.Itoa(int(timeout.Milliseconds())), ip)
	default:
		// Linux/BSD: -W is in whole seconds.
		cmd = exec.CommandContext(cmdCtx, "ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), ip)
	}

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		return false, 0
	}
	return true, elapsed
}

// tcpProbe attempts a TCP connect against a set of common ports. Many hosts
// (and most firewalls) drop ICMP but still answer on an open TCP port, so
// this doubles as both a liveness fallback and the basis of the open-port
// column in the UI.
func tcpProbe(ctx context.Context, ip string, ports []int, timeout time.Duration) (alive bool, open []int, latency time.Duration) {
	if timeout <= 0 {
		timeout = 350 * time.Millisecond
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	dialer := net.Dialer{Timeout: timeout}

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err != nil {
				return
			}
			d := time.Since(start)
			conn.Close()
			mu.Lock()
			open = append(open, port)
			if !alive || d < latency {
				latency = d
			}
			alive = true
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return alive, open, latency
}

// lookupHostname tries several ways to name a device, in order of how
// likely each is to actually be configured on a home/office LAN:
//
//  1. Reverse DNS (net.LookupAddr) -- works when the router runs a DNS
//     server that publishes DHCP client names (many do, some don't).
//  2. mDNS/Bonjour reverse lookup -- covers Apple devices, phones,
//     printers, smart-home gear, and anything else running an mDNS
//     responder (avahi is extremely common on embedded Linux), regardless
//     of what the router's DNS knows.
//  3. NetBIOS Name Service -- covers Windows PCs and older NAS/printer
//     appliances that speak SMB/NetBIOS but not mDNS.
//
// Each step is short and only runs if the previous one came up empty, so
// well-behaved devices resolve fast and only silent ones pay the full cost.
func lookupHostname(ctx context.Context, ip string) string {
	if name := reverseDNSLookup(ctx, ip); name != "" {
		return name
	}
	if name := mdnsHostname(ip, 350*time.Millisecond); name != "" {
		return name
	}
	if name := nbnsHostname(ip, 300*time.Millisecond); name != "" {
		return name
	}
	return ""
}

func reverseDNSLookup(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	// Trim the trailing dot DNS answers normally carry.
	if n := len(name); n > 0 && name[n-1] == '.' {
		name = name[:n-1]
	}
	return name
}
