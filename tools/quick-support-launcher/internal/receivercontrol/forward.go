// Package receivercontrol carries opaque issuer envelopes on a dedicated pipe.
// It never authenticates a control, creates a grant or represents local consent.
package receivercontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
	"unicode/utf8"
)

var ErrStopped = errors.New("receiver control forwarding stopped")

// Forward owns connection. Source EOF, malformed input, timeout or cancellation
// closes it terminally; the launcher must then stop its transport and child job.
// The receiver independently verifies every signature, binding and sequence.
func Forward(ctx context.Context, connection net.Conn, source <-chan string) error {
	if connection == nil {
		return ErrStopped
	}
	defer connection.Close()
	if ctx == nil || source == nil || ctx.Err() != nil {
		return ErrStopped
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour {
		return ErrStopped
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return ErrStopped
		case token, open := <-source:
			if !open || ctx.Err() != nil || len(token) == 0 || len(token) > 16384 || !utf8.ValidString(token) {
				return ErrStopped
			}
			limit := time.Now().Add(10 * time.Second)
			if deadline.Before(limit) {
				limit = deadline
			}
			if connection.SetWriteDeadline(limit) != nil {
				return ErrStopped
			}
			frame := make([]byte, 4+len(token))
			binary.BigEndian.PutUint32(frame[:4], uint32(len(token)))
			copy(frame[4:], token)
			for len(frame) > 0 {
				if ctx.Err() != nil {
					return ErrStopped
				}
				count, err := connection.Write(frame)
				if err != nil || count <= 0 || count > len(frame) {
					return ErrStopped
				}
				frame = frame[count:]
			}
		}
	}
}
