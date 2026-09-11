package api

import (
	"context"
	"sync"
)

// broadcaster keeps the full event log for one job (a scan, or a
// traceroute run) and lets any number of SSE clients subscribe. A late
// subscriber first replays everything that already happened, then blocks
// for new events -- so refreshing the browser mid-run still shows
// everything found so far. It's generic so the same implementation backs
// both scanner.Event streams and traceroute hop streams.
type broadcaster[T any] struct {
	mu     sync.Mutex
	cond   *sync.Cond
	events []T
	closed bool
}

func newBroadcaster[T any]() *broadcaster[T] {
	b := &broadcaster[T]{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *broadcaster[T]) publish(e T) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.events = append(b.events, e)
	b.mu.Unlock()
	b.cond.Broadcast()
}

func (b *broadcaster[T]) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cond.Broadcast()
}

// subscribe streams every event (past and future) to fn, in order, until
// ctx is cancelled, the job finishes, or fn returns false.
func (b *broadcaster[T]) subscribe(ctx context.Context, fn func(T) bool) {
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
