package scanner

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

var ttlRe = regexp.MustCompile(`(?i)ttl=(\d+)`)

// pingOnce shells out to the system "ping" binary for a single echo request.
// Using the OS binary (rather than a raw ICMP socket) is what lets this run
// without root/admin privileges on both Intel and Apple Silicon Macs. It
// also reports the reply's TTL, parsed from ping's own output -- the
// cheapest signal available (without raw sockets) for guessing a host's OS,
// since Linux/macOS/BSD, Windows, and networking gear each ship with a
// different default initial TTL.
func pingOnce(ctx context.Context, ip string, timeout time.Duration) (alive bool, latency time.Duration, ttl int) {
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

	var out bytes.Buffer
	cmd.Stdout = &out

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		return false, 0, 0
	}
	if m := ttlRe.FindSubmatch(out.Bytes()); m != nil {
		ttl, _ = strconv.Atoi(string(m[1]))
	}
	return true, elapsed, ttl
}

// PingStats is the result of sending several echo requests to one host, in
// the same shape "ping -c N" itself reports (sent/received/loss, min/avg/max).
type PingStats struct {
	Sent      int       `json:"sent"`
	Received  int       `json:"received"`
	LossPct   float64   `json:"lossPct"`
	MinMs     float64   `json:"minMs,omitempty"`
	AvgMs     float64   `json:"avgMs,omitempty"`
	MaxMs     float64   `json:"maxMs,omitempty"`
	TTL       int       `json:"ttl,omitempty"`
	SamplesMs []float64 `json:"samplesMs,omitempty"`
}

// Ping sends count echo requests to ip, spaced slightly apart, and
// summarizes the round-trip times -- the on-demand "ping / latency check"
// tool, as opposed to the single best-effort probe used during a sweep.
func Ping(ctx context.Context, ip string, count int, timeout time.Duration) PingStats {
	if count <= 0 {
		count = 4
	}
	if count > 10 {
		count = 10
	}
	stats := PingStats{Sent: count}

	var sum, min, max float64
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		alive, latency, ttl := pingOnce(ctx, ip, timeout)
		if alive {
			ms := round1(float64(latency.Microseconds()) / 1000.0)
			stats.SamplesMs = append(stats.SamplesMs, ms)
			stats.Received++
			sum += ms
			if stats.Received == 1 || ms < min {
				min = ms
			}
			if ms > max {
				max = ms
			}
			if ttl > 0 {
				stats.TTL = ttl
			}
		}
		if i < count-1 {
			select {
			case <-time.After(200 * time.Millisecond):
			case <-ctx.Done():
			}
		}
	}

	stats.LossPct = round1(100 * float64(stats.Sent-stats.Received) / float64(stats.Sent))
	if stats.Received > 0 {
		stats.MinMs = min
		stats.MaxMs = max
		stats.AvgMs = round1(sum / float64(stats.Received))
	}
	return stats
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

// ScanPorts checks each of ports concurrently and returns the ones that are
// open, sorted ascending. This is the on-demand per-host "port scanner"
// tool -- thorough and possibly large port lists are fine here, unlike the
// small default list used during a whole-network sweep.
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	_, open, _ := tcpProbe(ctx, ip, ports, timeout)
	sort.Ints(open)
	return open
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
