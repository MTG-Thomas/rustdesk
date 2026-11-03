package contained

import (
	"context"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const parentHandleEnvironment = "BIFROST_QS_PARENT_HANDLE"

// StartSuspendedWithParent preserves atomic Job Object containment and supplies
// only an inherited query/synchronization handle to the launcher process. The
// child must adopt it before spawning descendants and independently verify its
// signed configuration; the environment value is an identifier, never authority.
func StartSuspendedWithParent(ctx context.Context, executable string, args []string, directory string) (*Child, error) {
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
	var parent windows.Handle
	if windows.DuplicateHandle(windows.CurrentProcess(), windows.CurrentProcess(), windows.CurrentProcess(), &parent,
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, true, 0) != nil {
		return nil, ErrRejected
	}
	defer windows.CloseHandle(parent)
	// Do not copy the caller's credential-bearing environment or search PATH.
	environment := utf16.Encode([]rune(strings.Join([]string{
		"APPDATA=" + directory, parentHandleEnvironment + "=" + strconv.FormatUint(uint64(parent), 10),
		"LOCALAPPDATA=" + directory, "PATH=" + system,
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
	pins.Pin(&parent)
	defer pins.Unpin()
	if result, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil || result == 0 {
		return nil, ErrRejected
	}
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, ErrRejected
	}
	defer attributes.Delete()
	if attributes.Update(jobListAttribute, unsafe.Pointer(&job), unsafe.Sizeof(job)) != nil {
		return nil, ErrRejected // Never fall back to post-creation job assignment.
	}
	if attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&parent), unsafe.Sizeof(parent)) != nil {
		return nil, ErrRejected // Do not fall back to unrestricted handle inheritance.
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.ProcThreadAttributeList = attributes.List()
	var process windows.ProcessInformation
	if windows.CreateProcess(&application[0], &command[0], nil, nil, true,
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
