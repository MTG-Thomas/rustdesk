package transport

import (
	"context"
	"testing"
	"time"
)

func TestBoundLeaseTerminatesOnCloseExpiryAndParentCancellation(t *testing.T) {
	for _, reason := range []string{"close", "expiry", "parent"} {
		t.Run(reason, func(t *testing.T) {
			lease := &Lease{expires: time.Now().Add(100 * time.Millisecond)}
			parent, stop := context.WithCancel(context.Background())
			defer stop()
			ctx, cancel, err := lease.Bind(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			if reason == "close" {
				lease.Close()
			}
			if reason == "parent" {
				stop()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("lease child outlived terminal event")
			}
		})
	}
	lease := &Lease{expires: time.Now().Add(-time.Second)}
	if _, _, err := lease.Bind(context.Background()); err == nil {
		t.Fatal("expired lease bound child")
	}
	lease.expires = time.Now().Add(time.Minute)
	lease.Close()
	if _, _, err := lease.Bind(context.Background()); err == nil {
		t.Fatal("closed lease bound child")
	}
}
