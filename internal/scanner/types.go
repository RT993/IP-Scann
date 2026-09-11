// Package scanner implements the actual network discovery: ping/TCP probing,
// ARP table inspection, vendor lookup, and duplicate-IP conflict detection.
package scanner

import "time"

// Host is everything known about one responding address.
type Host struct {
	IP             string   `json:"ip"`
	Alive          bool     `json:"alive"`
	MAC            string   `json:"mac,omitempty"`
	Vendor         string   `json:"vendor,omitempty"`
	Hostname       string   `json:"hostname,omitempty"`
	LatencyMs      float64  `json:"latencyMs,omitempty"`
	OpenPorts      []int    `json:"openPorts,omitempty"`
	Method         string   `json:"method,omitempty"` // "icmp" or "tcp"
	Conflict       bool     `json:"conflict"`
	ConflictReason string   `json:"conflictReason,omitempty"` // "duplicate-ip" | "duplicate-mac"
	ConflictWith   []string `json:"conflictWith,omitempty"`   // the other MACs (or IPs) involved
}

// Options configures a single scan run.
type Options struct {
	CIDR        string `json:"cidr"`
	PortScan    bool   `json:"portScan"`
	Ports       []int  `json:"ports,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
	TimeoutMs   int    `json:"timeoutMs,omitempty"`
	// Passes controls how many ARP observation rounds are made. Running more
	// than one pass, spaced a little apart, is what lets the scanner catch
	// an IP address that answers from two different MAC addresses -- a
	// classic IP conflict -- without needing raw-socket/root privileges.
	Passes int `json:"passes,omitempty"`
}

// State is the lifecycle of a scan job.
type State string

const (
	StateRunning   State = "running"
	StateDone      State = "done"
	StateCancelled State = "cancelled"
	StateError     State = "error"
)

// Status is a point-in-time snapshot of scan progress.
type Status struct {
	ID        string    `json:"id"`
	State     State     `json:"state"`
	CIDR      string    `json:"cidr"`
	Total     int       `json:"total"`
	Scanned   int       `json:"scanned"`
	Found     int       `json:"found"`
	Conflicts int       `json:"conflicts"`
	Pass      int       `json:"pass"`
	Passes    int       `json:"passes"`
	StartedAt time.Time `json:"startedAt"`
	ElapsedMs int64     `json:"elapsedMs"`
	Error     string    `json:"error,omitempty"`
}

// Event is one item in the live scan stream sent to the UI over SSE.
type Event struct {
	Type   string  `json:"type"` // "status" | "host" | "done"
	Host   *Host   `json:"host,omitempty"`
	Status *Status `json:"status,omitempty"`
}
