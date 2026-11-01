package contained

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrRejected = errors.New("quick support child rejected")

// Windows SDK WinBase.h: ProcThreadAttributeJobList (13), input attribute.
const jobListAttribute = 0x0002000d

type Child struct {
	mu           sync.Mutex
	once         sync.Once
	job, process windows.Handle
	thread       windows.Handle
	ctx          context.Context
	stop         func() bool
	closed       bool
	resumed      bool
	closeErr     error
}

// StartSuspended requires an already verified executable and an owner-only
// session directory. It does not authenticate either, issue consent, or elevate.
// The context must carry the authenticated session's bounded hard deadline.
func StartSuspended(ctx context.Context, executable string, args []string, directory string) (*Child, error) {
	if ctx == nil || ctx.Err() != nil || !localAbsolute(executable) || !localAbsolute(directory) ||
		!strings.HasSuffix(strings.ToLower(executable), ".exe") {
		return nil, ErrRejected
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour {
		return nil, ErrRejected
	}
	application, err := windows.UTF16FromString(executable)
	if err != nil {
		return nil, ErrRejected
	}
	command, err := windows.UTF16FromString(windows.ComposeCommandLine(append([]string{executable}, args...)))
	if err != nil || len(command) > 32767 {
		return nil, ErrRejected
	}
	cwd, err := windows.UTF16FromString(directory)
	if err != nil {
		return nil, ErrRejected
	}
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		return nil, ErrRejected
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, ErrRejected
	}
	// Do not copy the caller's credential-bearing environment or search PATH.
	environment := utf16.Encode([]rune(strings.Join([]string{
		"APPDATA=" + directory, "LOCALAPPDATA=" + directory, "PATH=" + system,
		"SystemRoot=" + root, "TEMP=" + directory, "TMP=" + directory,
		"USERPROFILE=" + directory, "WINDIR=" + root,
	}, "\x00") + "\x00\x00"))
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, ErrRejected
	}
	owned := true
	defer func() {
		if owned {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	var pins runtime.Pinner
	pins.Pin(&limits)
	pins.Pin(&job)
	defer pins.Unpin()
	if result, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil || result == 0 {
		return nil, ErrRejected
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, ErrRejected
	}
	defer attributes.Delete()
	if attributes.Update(jobListAttribute, unsafe.Pointer(&job), unsafe.Sizeof(job)) != nil {
		return nil, ErrRejected // Never fall back to post-creation job assignment.
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.ProcThreadAttributeList = attributes.List()
	var process windows.ProcessInformation
	if windows.CreateProcess(&application[0], &command[0], nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		&environment[0], &cwd[0], &startup.StartupInfo, &process) != nil {
		return nil, ErrRejected
	}
	child := &Child{job: job, process: process.Process, thread: process.Thread, ctx: ctx}
	owned = false
	child.mu.Lock()
	child.stop = context.AfterFunc(ctx, func() { child.Close() })
	child.mu.Unlock()
	if ctx.Err() != nil {
		child.Close()
		return nil, ErrRejected
	}
	return child, nil
}

func localAbsolute(path string) bool {
	return filepath.IsAbs(path) && !strings.HasPrefix(path, `\\`) && !strings.ContainsRune(path, 0)
}

// ProcessHandle returns a caller-owned query/synchronization handle for peer
// authentication. It never transfers the job or execution-control handles.
func (c *Child) ProcessHandle() (windows.Handle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return 0, ErrRejected
	}
	var handle windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), c.process, windows.CurrentProcess(), &handle,
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, 0) != nil {
		return 0, ErrRejected
	}
	return handle, nil
}

// Resume is separate so the launcher can establish private IPC/bootstrap while
// the contained child still has not executed any application code.
func (c *Child) Resume() error {
	c.mu.Lock()
	if c.closed || c.resumed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return ErrRejected
	}
	previous, err := windows.ResumeThread(c.thread)
	if err == nil && previous == 1 {
		c.resumed = true
	}
	c.mu.Unlock()
	if err != nil || previous != 1 {
		c.Close()
		return ErrRejected
	}
	return nil
}

// Close kills the owned job and waits boundedly for its direct child to exit.
// Kernel job semantics cover descendants; real process-tree tests remain a gate.
func (c *Child) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		job, process, thread, stop := c.job, c.process, c.thread, c.stop
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
		if windows.CloseHandle(job) != nil {
			c.closeErr = ErrRejected
		}
		status, err := windows.WaitForSingleObject(process, 5000)
		if err != nil || status != windows.WAIT_OBJECT_0 {
			c.closeErr = ErrRejected
		}
		if windows.CloseHandle(thread) != nil {
			c.closeErr = ErrRejected
		}
		if windows.CloseHandle(process) != nil {
			c.closeErr = ErrRejected
		}
	})
	return c.closeErr
}

func (c *Child) String() string   { return "QuickSupportContainedChild(redacted)" }
func (c *Child) GoString() string { return c.String() }
