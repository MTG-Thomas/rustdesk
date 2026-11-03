package lifecycle

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/artifact"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/contained"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/privateipc"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/receivercontrol"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/sessiondir"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/transport"
	"golang.org/x/sys/windows"
)

// RunWithReceiverControl adds a dedicated issuer-envelope pipe and retained
// parent handoff. Source controls are opaque here: the qualified receiver must
// verify them and require separate real local consent before privileged dispatch.
// The existing Run path is unchanged; this API is not a default entry point.
func RunWithReceiverControl(parent context.Context, release string, trust artifact.ReleaseTrust, lease *transport.Lease, controls <-chan string) (result error) {
	if lease == nil {
		return ErrStopped
	}
	defer lease.Close()
	if controls == nil {
		return ErrStopped
	}
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
	control, err := privateipc.New()
	if err != nil {
		return ErrStopped
	}
	defer control.Close()
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
	profile, err := directory.ProfileHandle()
	if err != nil {
		return ErrStopped
	}
	child, err := contained.StartSuspendedWithProfile(ctx, executable, []string{"--quick-support-private-pipes", pipes[0].Path(), pipes[1].Path(), "--quick-support-control-pipe", control.Path()}, path, profile)
	profileErr := windows.CloseHandle(profile)
	if profileErr != nil && child != nil {
		child.Close()
		return ErrStopped
	}
	if err != nil || profileErr != nil {
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
	return serveReceiverControl(ctx, cancel, child, handle, pipes, sockets, control, controls)
}

func serveReceiverControl(ctx context.Context, cancel context.CancelFunc, child *contained.Child, handle windows.Handle, pipes [2]*privateipc.Pipe, sockets [2]bridge, control *privateipc.Pipe, source <-chan string) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		connection, err := control.AcceptChild(ctx, handle)
		if err == nil {
			receivercontrol.Forward(ctx, connection, source)
		}
	}()
	serve(ctx, cancel, child, handle, pipes, sockets)
	cancel()
	control.Close()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return ErrStopped
	case <-timer.C:
		return ErrStopped
	}
}
