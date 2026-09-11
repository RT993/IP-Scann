package api

import (
	"context"
	"sync"
	"time"

	"github.com/rt993/ip-scann/internal/scanner"
)

// tracerouteEvent is one item in a traceroute's live SSE stream.
type tracerouteEvent struct {
	Type  string       `json:"type"` // "hop" | "done" | "error"
	Hop   *scanner.Hop `json:"hop,omitempty"`
	Error string       `json:"error,omitempty"`
}

type traceJob struct {
	id string
	bc *broadcaster[tracerouteEvent]
}

// toolsManager tracks in-flight traceroute runs, the one per-host tool
// action that's slow enough to need its own SSE stream rather than a plain
// synchronous JSON response.
type toolsManager struct {
	mu     sync.Mutex
	traces map[string]*traceJob
}

func newToolsManager() *toolsManager {
	return &toolsManager{traces: make(map[string]*traceJob)}
}

func (m *toolsManager) startTraceroute(ip string) (*traceJob, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	tj := &traceJob{id: id, bc: newBroadcaster[tracerouteEvent]()}

	m.mu.Lock()
	m.traces[id] = tj
	m.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		err := scanner.Traceroute(ctx, ip, 20, func(hop scanner.Hop) {
			h := hop
			tj.bc.publish(tracerouteEvent{Type: "hop", Hop: &h})
		})
		if err != nil {
			tj.bc.publish(tracerouteEvent{Type: "error", Error: err.Error()})
		} else {
			tj.bc.publish(tracerouteEvent{Type: "done"})
		}
		tj.bc.close()
	}()

	return tj, nil
}

func (m *toolsManager) getTraceroute(id string) (*traceJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tj, ok := m.traces[id]
	return tj, ok
}
