package privateipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var ErrRejected = errors.New("quick support private IPC rejected")

const prefix = `\\.\pipe\mtg-quick-support-`

type Pipe struct {
	mu       sync.Mutex
	listener net.Listener
	path     string
	consumed bool
}

// New creates a local-only, current-logon pipe with an unpredictable name.
// Both peers must additionally authenticate the other's pinned process handle.
func New() (*Pipe, error) {
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return nil, ErrRejected
	}
	logon := ""
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			if logon != "" {
				return nil, ErrRejected
			}
			logon = group.Sid.String()
		}
	}
	if logon == "" {
		return nil, ErrRejected
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrRejected
	}
	path := prefix + hex.EncodeToString(nonce[:])
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;" + logon + ")",
		InputBufferSize:    64 * 1024, OutputBufferSize: 64 * 1024,
	})
	if err != nil {
		return nil, ErrRejected
	}
	return &Pipe{listener: listener, path: path}, nil
}

func (p *Pipe) Path() string { return p.path }
func (p *Pipe) Close() error { return p.listener.Close() }

func pinProcess(process windows.Handle) (windows.Handle, uint32, error) {
	var pinned windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), process, windows.CurrentProcess(), &pinned,
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, 0) != nil {
		return 0, 0, ErrRejected
	}
	id, err := windows.GetProcessId(pinned)
	if err != nil || id == 0 || !alive(pinned) {
		windows.CloseHandle(pinned)
		return 0, 0, ErrRejected
	}
	return pinned, id, nil
}

func alive(process windows.Handle) bool {
	status, err := windows.WaitForSingleObject(process, 0)
	return err == nil && status == uint32(windows.WAIT_TIMEOUT)
}

// AcceptChild consumes the endpoint once. child must be a handle retained from
// the launcher's own process creation, never a PID supplied by an IPC client.
// The returned connection belongs to the caller's session teardown/Bridge.
func (p *Pipe) AcceptChild(ctx context.Context, child windows.Handle) (net.Conn, error) {
	p.mu.Lock()
	if p.consumed {
		p.mu.Unlock()
		return nil, ErrRejected
	}
	p.consumed = true
	p.mu.Unlock()
	defer p.Close()
	if ctx == nil {
		return nil, ErrRejected
	}
	pinned, expected, err := pinProcess(child)
	if err != nil {
		return nil, ErrRejected
	}
	defer windows.CloseHandle(pinned)
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(bounded, func() { p.Close() })
	defer stop()
	connection, err := p.listener.Accept()
	if err != nil {
		return nil, ErrRejected
	}
	file, ok := connection.(interface{ Fd() uintptr })
	var actual uint32
	if !ok || windows.GetNamedPipeClientProcessId(windows.Handle(file.Fd()), &actual) != nil ||
		actual != expected || !alive(pinned) || bounded.Err() != nil {
		connection.Close()
		return nil, ErrRejected
	}
	return connection, nil
}

// DialParent requires the expected parent's stable process handle and verifies
// the server before any application payload is sent. A name alone is not trust.
func DialParent(ctx context.Context, path string, parent windows.Handle) (net.Conn, error) {
	if ctx == nil || !strings.HasPrefix(path, prefix) || len(path) != len(prefix)+64 {
		return nil, ErrRejected
	}
	name := strings.TrimPrefix(path, prefix)
	nonce, err := hex.DecodeString(name)
	if err != nil || hex.EncodeToString(nonce) != name {
		return nil, ErrRejected
	}
	pinned, expected, err := pinProcess(parent)
	if err != nil {
		return nil, ErrRejected
	}
	defer windows.CloseHandle(pinned)
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	connection, err := winio.DialPipeContext(bounded, path)
	if err != nil {
		return nil, ErrRejected
	}
	file, ok := connection.(interface{ Fd() uintptr })
	var actual uint32
	if !ok || windows.GetNamedPipeServerProcessId(windows.Handle(file.Fd()), &actual) != nil ||
		actual != expected || !alive(pinned) || bounded.Err() != nil {
		connection.Close()
		return nil, ErrRejected
	}
	return connection, nil
}

func (p *Pipe) String() string   { return "QuickSupportPrivatePipe(redacted)" }
func (p *Pipe) GoString() string { return p.String() }
