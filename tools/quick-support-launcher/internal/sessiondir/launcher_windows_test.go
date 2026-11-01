package sessiondir

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/contained"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/privateipc"
	"golang.org/x/sys/windows"
)

// This composes the real Windows components with the test binary as the owned
// child. It does not qualify artifact signing, RustDesk startup, or receiver consent.
func TestPrivateDirectoryContainedChildAndAuthenticatedPipeCompose(t *testing.T) {
	directory, err := newAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Cleanup()
	path, err := directory.Path()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := directory.FilePath("composed-proof")
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := privateipc.New()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child, err := contained.StartSuspended(ctx, executable,
		[]string{"-test.run=^TestOwnedComposedLauncherChild$", "--", "qs-composed", pipe.Path(), proof}, path)
	if err != nil {
		t.Fatal("private directory could not be used by the contained child", err)
	}
	defer child.Close()
	handle, err := child.ProcessHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	type accepted struct {
		connection net.Conn
		err        error
	}
	result := make(chan accepted, 1)
	go func() { connection, err := pipe.AcceptChild(ctx, handle); result <- accepted{connection, err} }()
	if err := child.Resume(); err != nil {
		t.Fatal(err)
	}
	var connection net.Conn
	select {
	case ready := <-result:
		if ready.err != nil {
			t.Fatal(ready.err)
		}
		connection = ready.connection
	case <-ctx.Done():
		t.Fatal("owned child did not authenticate its pipe")
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil || string(reply[:]) != "pong" {
		t.Fatal("composed private IPC failed", err)
	}
	if data, err := os.ReadFile(proof); err != nil || string(data) != "private cwd" {
		t.Fatal("child did not confirm the owned working directory", err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := directory.Cleanup(); err != nil {
		t.Fatal("composed child left the session directory uncleared", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("composed session directory still exists")
	}
}

func TestOwnedComposedLauncherChild(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "qs-composed" {
		t.Skip("owned subprocess entry")
	}
	pipePath, proof := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	parent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getppid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(parent)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := privateipc.DialParent(ctx, pipePath, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var request [4]byte
	if _, err := io.ReadFull(connection, request[:]); err != nil || string(request[:]) != "ping" {
		t.Fatal("unexpected composed request", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(cwd)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(filepath.Dir(proof))
	if err != nil || !os.SameFile(current, expected) {
		t.Fatal("child is using another working directory", err)
	}
	if os.WriteFile(proof, []byte("private cwd"), 0600) != nil {
		t.Fatal("owned child could not write its private proof")
	}
	if _, err := connection.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second) // The parent must terminate this owned child.
}
