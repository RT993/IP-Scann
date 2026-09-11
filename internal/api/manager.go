package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rt993/ip-scann/internal/scanner"
)

// job tracks one in-flight or completed scan.
type job struct {
	id     string
	cancel context.CancelFunc
	bc     *broadcaster

	mu     sync.Mutex
	status scanner.Status
	hosts  map[string]*scanner.Host
}

func (j *job) snapshotStatus() scanner.Status {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status
}

func (j *job) snapshotHosts() []*scanner.Host {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*scanner.Host, 0, len(j.hosts))
	for _, h := range j.hosts {
		c := *h
		out = append(out, &c)
	}
	sort.Slice(out, func(i, k int) bool { return lessIP(out[i].IP, out[k].IP) })
	return out
}

// manager owns every scan job for the lifetime of the server process. This
// is a local, single-user desktop tool, so an in-memory map (rather than a
// database) is all that's needed.
type manager struct {
	mu   sync.Mutex
	jobs map[string]*job
}

func newManager() *manager {
	return &manager{jobs: make(map[string]*job)}
}

var errMissingCIDR = fmt.Errorf("cidr is required")

func (m *manager) start(opts scanner.Options) (*job, error) {
	if opts.CIDR == "" {
		return nil, errMissingCIDR
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{
		id:     id,
		cancel: cancel,
		bc:     newBroadcaster(),
		hosts:  make(map[string]*scanner.Host),
		status: scanner.Status{ID: id, State: scanner.StateRunning, CIDR: opts.CIDR, StartedAt: time.Now()},
	}

	m.mu.Lock()
	m.jobs[id] = j
	m.mu.Unlock()

	publish := func(e scanner.Event) {
		j.mu.Lock()
		if e.Host != nil {
			h := *e.Host
			j.hosts[h.IP] = &h
		}
		if e.Status != nil {
			j.status = *e.Status
		}
		j.mu.Unlock()
		j.bc.publish(e)
	}

	go func() {
		final := scanner.Run(ctx, id, opts, publish)
		j.mu.Lock()
		j.status = final
		j.mu.Unlock()
		j.bc.publish(scanner.Event{Type: "done", Status: &final})
		j.bc.close()
	}()

	return j, nil
}

func (m *manager) get(id string) (*job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	return j, ok
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// lessIP compares dotted-quad IPv4 strings numerically per octet so the
// results table sorts 10.0.0.2 before 10.0.0.10.
func lessIP(a, b string) bool {
	pa, pb := splitIP(a), splitIP(b)
	for i := 0; i < 4 && i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return a < b
}

func splitIP(s string) [4]int {
	var out [4]int
	var part, idx int
	for _, c := range s {
		if c == '.' {
			if idx < 4 {
				out[idx] = part
			}
			idx++
			part = 0
			continue
		}
		if c >= '0' && c <= '9' {
			part = part*10 + int(c-'0')
		}
	}
	if idx < 4 {
		out[idx] = part
	}
	return out
}
