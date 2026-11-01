package privateipc

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestOwnedChildPipeAndBothPeerIdentityDenials(t *testing.T) {
	for _, mode := range []string{"roundtrip", "wrong-server", "wrong-client"} {
		t.Run(mode, func(t *testing.T) {
			pipe, err := New()
			if err != nil {
				t.Fatal(err)
			}
			defer pipe.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, executable, "-test.run=^TestPrivatePipeChildProcess$")
			command.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot"), "WINDIR=" + os.Getenv("WINDIR"),
				"TEMP=" + t.TempDir(), "TMP=" + t.TempDir(), "QS_PIPE_TEST_PATH=" + pipe.Path(), "QS_PIPE_TEST_MODE=" + mode}
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if command.ProcessState == nil {
					command.Process.Kill()
					command.Wait()
				}
			}()
			child, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(command.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(child)
			expected := child
			if mode == "wrong-client" {
				expected = windows.CurrentProcess()
			}
			connection, err := pipe.AcceptChild(ctx, expected)
			if mode == "wrong-client" {
				if err != ErrRejected || connection != nil {
					t.Fatal("wrong child accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if mode == "wrong-server" {
					data, err := io.ReadAll(connection)
					if err != nil || len(data) != 0 {
						t.Fatal("wrong server received application data", err)
					}
				} else {
					file := connection.(interface{ Fd() uintptr })
					sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
					if err != nil {
						t.Fatal(err)
					}
					control, _, err := sd.Control()
					if err != nil || control&windows.SE_DACL_PROTECTED == 0 || strings.Count(sd.String(), "(A;") != 1 || !strings.Contains(sd.String(), "S-1-5-5-") {
						t.Fatal("pipe does not retain the protected logon-only DACL")
					}
					if _, err := connection.Write([]byte("ping")); err != nil {
						t.Fatal(err)
					}
					var reply [4]byte
					if _, err := io.ReadFull(connection, reply[:]); err != nil || string(reply[:]) != "pong" {
						t.Fatal("private roundtrip failed", err)
					}
				}
			}
			if err := command.Wait(); err != nil {
				t.Fatal(err, output.String())
			}
			if connection, err := pipe.AcceptChild(ctx, child); err != ErrRejected || connection != nil {
				t.Fatal("consumed endpoint accepted again")
			}
		})
	}
}

func TestPrivatePipeChildProcess(t *testing.T) {
	mode := os.Getenv("QS_PIPE_TEST_MODE")
	if mode == "" {
		t.Skip("owned subprocess entry")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := os.Getenv("QS_PIPE_TEST_PATH")
	if mode == "wrong-client" {
		connection, err := winio.DialPipeContext(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(connection)
		if err != nil || len(data) != 0 {
			t.Fatal("rejected client received application data", err)
		}
		return
	}
	parent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getppid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(parent)
	expected := parent
	if mode == "wrong-server" {
		expected = windows.CurrentProcess()
	}
	connection, err := DialParent(ctx, path, expected)
	if mode == "wrong-server" {
		if err != ErrRejected || connection != nil {
			t.Fatal("wrong server accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var payload [4]byte
	if _, err := io.ReadFull(connection, payload[:]); err != nil || string(payload[:]) != "ping" {
		t.Fatal("private request failed", err)
	}
	if _, err := connection.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledPipeAndUntrustedPathFailClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pipe, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if connection, err := pipe.AcceptChild(ctx, windows.CurrentProcess()); err != ErrRejected || connection != nil {
		t.Fatal("cancelled accept succeeded")
	}
	if connection, err := DialParent(ctx, `\\other-host\pipe\untrusted`, windows.CurrentProcess()); err != ErrRejected || connection != nil {
		t.Fatal("untrusted path accepted")
	}
}
