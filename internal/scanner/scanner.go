package scanner

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rt993/ip-scann/internal/netutil"
)

// DefaultPorts is the set of commonly-open ports probed when port scanning
// is enabled: a broad, fast mix covering file sharing, remote access, web
// admin UIs, and printers -- similar to what Advanced IP Scanner checks by
// default.
var DefaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 631, 3306, 3389, 5000, 5432, 5900, 8000, 8080, 8443, 9100}

const gapBetweenPasses = 1500 * time.Millisecond

// Run performs a full network scan and reports progress/results through
// publish as it goes. It blocks until the scan finishes, is cancelled via
// ctx, or fails outright, and returns the final Status either way.
func Run(ctx context.Context, id string, opts Options, publish func(Event)) Status {
	status := Status{ID: id, State: StateRunning, CIDR: opts.CIDR, StartedAt: time.Now()}

	addrs, err := netutil.HostsInCIDR(opts.CIDR)
	if err != nil {
		status.State = StateError
		status.Error = err.Error()
		status.ElapsedMs = time.Since(status.StartedAt).Milliseconds()
		publish(Event{Type: "status", Status: cloneStatus(status)})
		return status
	}

	passes := clampInt(opts.Passes, 2, 1, 5)
	concurrency := clampInt(opts.Concurrency, 128, 1, 512)
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}

	status.Total = len(addrs)
	status.Passes = passes
	publish(Event{Type: "status", Status: cloneStatus(status)})

	var hostsMu sync.Mutex
	hosts := make(map[string]*Host)
	passResults := make([]map[string]string, passes)

	var found int64
	sendStatus := func(pass, scanned int) {
		status.Pass = pass + 1
		status.Scanned = scanned
		status.Found = int(atomic.LoadInt64(&found))
		status.ElapsedMs = time.Since(status.StartedAt).Milliseconds()
		publish(Event{Type: "status", Status: cloneStatus(status)})
	}

passLoop:
	for p := 0; p < passes; p++ {
		if ctx.Err() != nil {
			break passLoop
		}

		passResults[p] = make(map[string]string)
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		var scanned int64
		statusEvery := progressThrottle(len(addrs))

		for _, addr := range addrs {
			if ctx.Err() != nil {
				break
			}
			ip := addr.String()
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string) {
				defer wg.Done()
				defer func() { <-sem }()

				alive, latency := pingOnce(ctx, ip, timeout)
				method := "icmp"
				var openPorts []int
				if opts.PortScan {
					if !alive {
						var lat time.Duration
						alive, openPorts, lat = tcpProbe(ctx, ip, ports, 350*time.Millisecond)
						if alive {
							method = "tcp"
							latency = lat
						}
					} else {
						_, openPorts, _ = tcpProbe(ctx, ip, ports, 350*time.Millisecond)
					}
				} else if !alive {
					// Even without a full port scan, try a couple of the
					// most common ports so devices that block ICMP are
					// still discovered.
					var lat time.Duration
					alive, _, lat = tcpProbe(ctx, ip, []int{80, 443, 22, 445}, 300*time.Millisecond)
					if alive {
						method = "tcp"
						latency = lat
					}
				}

				n := atomic.AddInt64(&scanned, 1)
				if p == 0 && (int(n)%statusEvery == 0 || int(n) == len(addrs)) {
					sendStatus(p, int(n))
				}

				if !alive {
					return
				}

				hostsMu.Lock()
				h, exists := hosts[ip]
				if !exists {
					h = &Host{IP: ip}
					hosts[ip] = h
				}
				h.Alive = true
				h.Method = method
				if latency > 0 {
					h.LatencyMs = round1(float64(latency.Microseconds()) / 1000.0)
				}
				if len(openPorts) > 0 {
					h.OpenPorts = mergeInts(h.OpenPorts, openPorts)
				}
				hostsMu.Unlock()

				if !exists {
					atomic.AddInt64(&found, 1)
					hostname := lookupHostname(ctx, ip)
					hostsMu.Lock()
					h.Hostname = hostname
					snap := *h
					hostsMu.Unlock()
					publish(Event{Type: "host", Host: &snap})
				}
			}(ip)
		}
		wg.Wait()

		if ctx.Err() != nil {
			break passLoop
		}

		arpTable, _ := ReadARPTable()
		hostsMu.Lock()
		var newlyEnriched []Host
		for ip, h := range hosts {
			if mac, ok := arpTable[ip]; ok {
				passResults[p][ip] = mac
				if h.MAC == "" {
					h.MAC = mac
					h.Vendor = VendorLookup(mac)
					newlyEnriched = append(newlyEnriched, *h)
				}
			}
		}
		hostsMu.Unlock()

		// The MAC/vendor lookup above happens after the initial "host"
		// event for each address was already sent (a ping success alone
		// doesn't tell us the MAC yet), so push an update now that it's
		// known -- otherwise the UI and CSV export would show every host
		// with a permanently blank MAC/vendor.
		for i := range newlyEnriched {
			publish(Event{Type: "host", Host: &newlyEnriched[i]})
		}

		sendStatus(p, len(addrs))

		if p < passes-1 {
			select {
			case <-time.After(gapBetweenPasses):
			case <-ctx.Done():
				break passLoop
			}
		}
	}

	if ctx.Err() != nil {
		status.State = StateCancelled
		status.ElapsedMs = time.Since(status.StartedAt).Milliseconds()
		publish(Event{Type: "status", Status: cloneStatus(status)})
		return status
	}

	report := DetectConflicts(passResults)
	hostsMu.Lock()
	for ip, macs := range report.DuplicateIPs {
		h, ok := hosts[ip]
		if !ok {
			continue
		}
		h.Conflict = true
		h.ConflictReason = "duplicate-ip"
		h.ConflictWith = macs
	}
	for mac, ips := range report.DuplicateMACs {
		for _, ip := range ips {
			h, ok := hosts[ip]
			if !ok || h.Conflict {
				continue
			}
			h.Conflict = true
			h.ConflictReason = "duplicate-mac"
			h.ConflictWith = removeValue(ips, ip)
			_ = mac
		}
	}
	var conflicts int
	var finalHosts []*Host
	for _, h := range hosts {
		finalHosts = append(finalHosts, h)
		if h.Conflict {
			conflicts++
		}
	}
	sort.Slice(finalHosts, func(i, j int) bool { return finalHosts[i].IP < finalHosts[j].IP })
	hostsMu.Unlock()

	for _, h := range finalHosts {
		if h.Conflict {
			snap := *h
			publish(Event{Type: "host", Host: &snap})
		}
	}

	status.State = StateDone
	status.Scanned = len(addrs)
	status.Found = len(finalHosts)
	status.Conflicts = conflicts
	status.ElapsedMs = time.Since(status.StartedAt).Milliseconds()
	publish(Event{Type: "status", Status: cloneStatus(status)})
	return status
}

func cloneStatus(s Status) *Status {
	c := s
	return &c
}

func clampInt(v, def, min, max int) int {
	if v <= 0 {
		v = def
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v
}

// progressThrottle decides how many completed probes should pass between
// progress events, so a large /16 scan doesn't flood the UI with thousands
// of near-identical status updates.
func progressThrottle(total int) int {
	step := total / 100
	if step < 1 {
		step = 1
	}
	return step
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

func mergeInts(existing, add []int) []int {
	set := make(map[int]bool, len(existing)+len(add))
	for _, v := range existing {
		set[v] = true
	}
	for _, v := range add {
		set[v] = true
	}
	out := make([]int, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func removeValue(list []string, value string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != value {
			out = append(out, v)
		}
	}
	return out
}
