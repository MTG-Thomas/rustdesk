package transport

import (
	"context"
	"time"
)

// Bind owns a cancellable child lifetime bounded by this authenticated lease.
// The caller must cancel it after teardown. It grants no receiver permission.
func (l *Lease) Bind(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil {
		return nil, nil, ErrRejected
	}
	l.mu.Lock()
	if l.closed || !time.Now().Before(l.expires) {
		l.mu.Unlock()
		return nil, nil, ErrRejected
	}
	if l.done == nil {
		l.done = make(chan struct{})
	}
	done, expires := l.done, l.expires
	l.mu.Unlock()
	ctx, cancel := context.WithDeadline(parent, expires)
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel, nil
}
