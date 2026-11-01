package lifecycle

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/contained"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/privateipc"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/sessiondir"
	"golang.org/x/sys/windows"
)

type heldBridge struct {
	ctx      context.Context
	accepted chan<- struct{}
}

func (b heldBridge) Bridge(c net.Conn) error {
	defer c.Close()
	b.accepted <- struct{}{}
	<-b.ctx.Done()
	return io.EOF
}
func (b heldBridge) Close() {}

func TestOwnedLifecycleStopsAuthenticatedPipesChildAndDirectory(t *testing.T) {
	for _, reason := range []string{"stop", "expiry"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			directory, err := sessiondir.New()
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Cleanup()
			path, err := directory.Path()
			if err != nil {
				t.Fatal(err)
			}
			var pipes [2]*privateipc.Pipe
			for i := range pipes {
				pipes[i], err = privateipc.New()
				if err != nil {
					t.Fatal(err)
				}
				defer pipes[i].Close()
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child, err := contained.StartSuspended(ctx, executable, []string{"-test.run=^TestOwnedLifecycleChild$", "--", "qs-lifecycle", pipes[0].Path(), pipes[1].Path()}, path)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			handle, err := child.ProcessHandle()
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(handle)
			accepted := make(chan struct{}, 2)
			bridges := [2]bridge{heldBridge{ctx, accepted}, heldBridge{ctx, accepted}}
			done := make(chan error, 1)
			go func() { done <- serve(ctx, cancel, child, handle, pipes, bridges) }()
			for i := 0; i < 2; i++ {
				select {
				case <-accepted:
				case <-ctx.Done():
					t.Fatal("child did not authenticate both pipes")
				}
			}
			if reason == "stop" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Fatal("teardown did not join")
			}
			status, err := windows.WaitForSingleObject(handle, 0)
			if err != nil || status != windows.WAIT_OBJECT_0 {
				t.Fatal("owned process still running", err)
			}
			if err := directory.Cleanup(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("private directory retained")
			}
		})
	}
}

func TestOwnedLifecycleChild(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "qs-lifecycle" {
		t.Skip("owned child entry")
	}
	parent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getppid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(parent)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, path := range os.Args[len(os.Args)-2:] {
		c, err := privateipc.DialParent(ctx, path, parent)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	time.Sleep(30 * time.Second)
}
