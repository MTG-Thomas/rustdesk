package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/contained"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/privateipc"
	"github.com/MTG-Thomas/rustdesk/tools/quick-support-launcher/internal/sessiondir"
	"golang.org/x/sys/windows"
)

func waitFixture(ctx context.Context, path string) ([]byte, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := os.Stat(strings.TrimSuffix(path, filepath.Ext(path)) + ".complete")
		if err == nil {
			return os.ReadFile(path)
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

type fixtureNativeBridge struct {
	ctx       context.Context
	accepted  chan<- struct{}
	directory string
	relay     bool
}

func (b fixtureNativeBridge) Bridge(connection net.Conn) error {
	defer connection.Close()
	b.accepted <- struct{}{}
	if b.relay {
		if _, err := waitFixture(b.ctx, filepath.Join(b.directory, "approval.ready")); err != nil {
			return err
		}
		if _, err := connection.Write([]byte{4, 7}); err != nil {
			return err
		}
	}
	// Hold synthetic transport ownership until the controller has collected the
	// receiver's assertion receipt, then prove explicit Job Object teardown.
	<-b.ctx.Done()
	return io.EOF
}
func (b fixtureNativeBridge) Close() {}

func TestGoRustReceiverInteroperability(t *testing.T) {
	executable := os.Getenv("BIFROST_QS_TEST_RECEIVER_EXE")
	if executable == "" {
		if os.Getenv("BIFROST_QS_REQUIRE_NATIVE_INTEROP") == "1" {
			t.Fatal("required Rust fixture binary missing")
		}
		t.Skip("requires the separately compiled synthetic Rust receiver fixture")
	}
	if info, err := os.Stat(executable); err != nil || !info.Mode().IsRegular() {
		t.Fatal("invalid Rust fixture executable", err)
	}
	var vector struct {
		Bootstrap, Grant, Renew, Revoke string
		ReceiverID                      string `json:"receiver_id"`
	}
	data, err := os.ReadFile("../../../../libs/base/quick_support_guard/tests/fixtures/receiver-control-v1.json")
	if err != nil || json.Unmarshal(data, &vector) != nil {
		t.Fatal("signed fixture unavailable", err)
	}
	for _, approved := range []bool{false, true} {
		t.Run(map[bool]string{false: "consent-denied", true: "synthetic-consent-and-revoke"}[approved], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
			input := struct {
				ParentPID  int    `json:"parent_pid"`
				Control    string `json:"control"`
				Rendezvous string `json:"rendezvous"`
				Relay      string `json:"relay"`
				Allow      bool   `json:"allow_consent"`
			}{os.Getpid(), control.Path(), pipes[0].Path(), pipes[1].Path(), approved}
			encoded, err := json.Marshal(input)
			if err != nil || os.WriteFile(filepath.Join(path, "receiver.fixture.json"), encoded, 0600) != nil {
				t.Fatal("cannot stage fixture input")
			}
			child, err := contained.StartSuspendedWithParent(ctx, executable, []string{"--ignored", "--exact", "receiver_interop_child", "--nocapture"}, path)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			handle, err := child.ProcessHandle()
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(handle)
			source := make(chan string, 3)
			source <- vector.Bootstrap
			accepted := make(chan struct{}, 2)
			bridges := [2]bridge{fixtureNativeBridge{ctx, accepted, path, false}, fixtureNativeBridge{ctx, accepted, path, true}}
			done := make(chan error, 1)
			go func() { done <- serveReceiverControl(ctx, cancel, child, handle, pipes, bridges, control, source) }()
			for i := 0; i < 2; i++ {
				select {
				case <-accepted:
				case <-ctx.Done():
					t.Fatal("receiver did not bind native routes")
				}
			}
			challenge, err := waitFixture(ctx, filepath.Join(path, "challenge.ready"))
			if err != nil || len(challenge) < 32 || len(challenge) > 256 {
				t.Fatal("invalid receiver challenge", err)
			}
			message := []byte("rustdesk-quick-support-proof/v1\x00")
			for _, part := range [][]byte{[]byte(vector.Grant), challenge, []byte(vector.ReceiverID)} {
				message = binary.BigEndian.AppendUint64(message, uint64(len(part)))
				message = append(message, part...)
			}
			// Reuse the existing deterministic workstation identity; no production key.
			proof := ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), message)
			if os.WriteFile(filepath.Join(path, "grant.proof"), proof, 0600) != nil || os.WriteFile(filepath.Join(path, "grant.complete"), nil, 0600) != nil {
				t.Fatal("cannot deliver synthetic proof")
			}
			if approved {
				if _, err := waitFixture(ctx, filepath.Join(path, "native.accepted")); err != nil {
					t.Fatal("verified dispatch missing", err)
				}
				source <- vector.Renew
				source <- vector.Revoke
			}
			result, err := waitFixture(ctx, filepath.Join(path, "receiver.finished"))
			var receipt struct{ Dispatched, Steps int }
			expectedData, expectedSteps := 0, 2
			if approved {
				expectedData, expectedSteps = 1, 5
			}
			if err != nil || json.Unmarshal(result, &receipt) != nil || receipt.Dispatched != expectedData || receipt.Steps != expectedSteps {
				t.Fatal("receiver assertion receipt missing/invalid", err, string(result))
			}
			close(source)
			select {
			case err := <-done:
				if err != ErrStopped {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("composed teardown did not finish")
			}
			if status, err := windows.WaitForSingleObject(handle, 0); err != nil || status != windows.WAIT_OBJECT_0 {
				t.Fatal("synthetic Rust receiver survived teardown", err)
			}
			if err := directory.Cleanup(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("fixture directory retained")
			}
		})
	}
}
