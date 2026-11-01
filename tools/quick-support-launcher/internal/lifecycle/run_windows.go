package lifecycle

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/artifact"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/contained"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/privateipc"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/sessiondir"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/transport"
	"golang.org/x/sys/windows"
)

var ErrStopped = errors.New("quick support launcher stopped")

// Run consumes the lease and owns all created resources until teardown finishes.
// Trust must be pinned by the signed launcher. The reviewed child must implement
// these private-pipe arguments and enforce signed receiver grants and local
// consent itself. This API supplies transport only; no control is authorized.
func Run(parent context.Context, release string, trust artifact.ReleaseTrust, lease *transport.Lease) (result error) {
	if lease == nil {
		return ErrStopped
	}
	defer lease.Close()
	ctx, cancel, err := lease.Bind(parent)
	if err != nil {
		return ErrStopped
	}
	defer cancel()
	directory, err := sessiondir.New()
	if err != nil {
		return ErrStopped
	}
	defer func() {
		if directory.Cleanup() != nil {
			result = errors.Join(result, ErrStopped)
		}
	}()
	path, err := directory.Path()
	if err != nil {
		return ErrStopped
	}
	executable, err := directory.FilePath("support.exe")
	if err != nil {
		return ErrStopped
	}
	policy, err := artifact.VerifyRelease(release, trust)
	if err != nil {
		return ErrStopped
	}
	client := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second}}
	defer client.CloseIdleConnections()
	if artifact.Fetch(ctx, client, policy, executable, artifact.VerifyWindowsAuthenticode) != nil {
		return ErrStopped
	}
	var pipes [2]*privateipc.Pipe
	var sockets [2]bridge
	defer func() {
		for i := range pipes {
			if sockets[i] != nil {
				sockets[i].Close()
			}
			if pipes[i] != nil {
				pipes[i].Close()
			}
		}
	}()
	for i, route := range []transport.Route{transport.Rendezvous, transport.Relay} {
		pipes[i], err = privateipc.New()
		if err != nil {
			return ErrStopped
		}
		sockets[i], err = lease.Dial(ctx, route)
		if err != nil {
			return ErrStopped
		}
	}
	child, err := contained.StartSuspended(ctx, executable, []string{"--quick-support-private-pipes", pipes[0].Path(), pipes[1].Path()}, path)
	if err != nil {
		return ErrStopped
	}
	defer func() {
		if child.Close() != nil {
			result = errors.Join(result, ErrStopped)
		}
	}()
	handle, err := child.ProcessHandle()
	if err != nil {
		return ErrStopped
	}
	defer windows.CloseHandle(handle)
	return serve(ctx, cancel, child, handle, pipes, sockets)
}

type bridge interface {
	Bridge(net.Conn) error
	Close()
}

func serve(ctx context.Context, cancel context.CancelFunc, child *contained.Child, handle windows.Handle, pipes [2]*privateipc.Pipe, sockets [2]bridge) error {
	results := make(chan error, 2)
	for i := range pipes {
		go func(i int) {
			connection, err := pipes[i].AcceptChild(ctx, handle)
			if err == nil {
				err = sockets[i].Bridge(connection)
			}
			results <- err
		}(i)
	}
	if child.Resume() != nil {
		cancel()
	}
	finished := 0
	select {
	case <-ctx.Done():
	case <-results:
		finished++
	}
	cancel()
	for i := range pipes {
		pipes[i].Close()
		sockets[i].Close()
	}
	// Closing the job before joining also unblocks a child stalled on private IPC.
	child.Close()
	// Each worker reports once; a first result may already have been consumed.
	// Drain is bounded by cancellation and close, which unblock both transports.
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for finished < 2 {
		select {
		case <-results:
			finished++
		case <-timer.C:
			return ErrStopped
		}
	}
	return ErrStopped
}
