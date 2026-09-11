package api

import (
	"context"
	"sync"

	"github.com/rt993/ip-scann/internal/scanner"
)

// broadcaster keeps the full event log for one scan job and lets any number
// of SSE clients subscribe. A late subscriber first replays everything that
// already happened, then blocks for new events -- so refreshing the browser
// mid-scan still shows every host found so far.
type broadcaster struct {
	mu     sync.Mutex
	cond   *sync.Cond
	events []scanner.Event
	closed bool
}

func newBroadcaster() *broadcaster {
	b := &broadcaster{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *broadcaster) publish(e scanner.Event) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.events = append(b.events, e)
	b.mu.Unlock()
	b.cond.Broadcast()
}

func (b *broadcaster) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cond.Broadcast()
}

// subscribe streams every event (past and future) to fn, in order, until
// ctx is cancelled, the job finishes, or fn returns false.
func (b *broadcaster) subscribe(ctx context.Context, fn func(scanner.Event) bool) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			b.mu.Lock()
			b.cond.Broadcast()
			b.mu.Unlock()
		case <-stop:
		}
	}()

	idx := 0
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		for idx < len(b.events) {
			e := b.events[idx]
			idx++
			b.mu.Unlock()
			cont := fn(e)
			b.mu.Lock()
			if !cont {
				return
			}
		}
		if b.closed || ctx.Err() != nil {
			return
		}
		b.cond.Wait()
	}
}
