package lifecycle

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/contained"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/privateipc"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/sessiondir"
	"golang.org/x/sys/windows"
)

func TestControlEOFStopsBothNativeRoutesAndContainedChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
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
	control, err := privateipc.New()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "control.received")
	child, err := contained.StartSuspendedWithParent(ctx, executable, []string{"-test.run=^TestControlledLifecycleChild$", "--", "qs-controlled", pipes[0].Path(), pipes[1].Path(), control.Path(), marker}, path)
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
	source := make(chan string, 1)
	source <- "synthetic-control"
	done := make(chan error, 1)
	go func() { done <- serveReceiverControl(ctx, cancel, child, handle, pipes, bridges, control, source) }()
	for i := 0; i < 2; i++ {
		select {
		case <-accepted:
		case <-ctx.Done():
			t.Fatal("child did not bind both native routes")
		}
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "synthetic-control" {
		t.Fatal("dedicated control frame not received", err)
	}
	close(source)
	select {
	case err := <-done:
		if err != ErrStopped {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("control EOF did not join teardown")
	}
	if status, err := windows.WaitForSingleObject(handle, 0); err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatal("contained child survived control EOF", err)
	}
	if err := directory.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("private directory retained")
	}
}

func TestControlledLifecycleChild(t *testing.T) {
	if len(os.Args) < 6 || os.Args[len(os.Args)-5] != "qs-controlled" {
		t.Skip("owned subprocess entry")
	}
	value, err := strconv.ParseUint(os.Getenv("BIFROST_QS_PARENT_HANDLE"), 10, 64)
	if err != nil || value == 0 {
		t.Fatal("parent handoff missing")
	}
	parent := windows.Handle(value)
	defer windows.CloseHandle(parent)
	if windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0) != nil {
		t.Fatal("cannot clear inherited flag")
	}
	os.Unsetenv("BIFROST_QS_PARENT_HANDLE")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	control, err := privateipc.DialParent(ctx, os.Args[len(os.Args)-2], parent)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var header [4]byte
	if _, err := io.ReadFull(control, header[:]); err != nil {
		t.Fatal(err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 16384 {
		t.Fatal("invalid control length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(control, payload); err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(os.Args[len(os.Args)-1], payload, 0600) != nil {
		t.Fatal("cannot record control receipt")
	}
	for _, path := range os.Args[len(os.Args)-4 : len(os.Args)-2] {
		connection, err := privateipc.DialParent(ctx, path, parent)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
	}
	time.Sleep(30 * time.Second)
}
