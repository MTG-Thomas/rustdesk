package contained

import (
	"context"
	"runtime"
	"slices"
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
	return startSuspendedWithProfile(ctx, executable, args, directory, 0)
}

// StartSuspendedWithProfile additionally inherits a restricted duplicate of the
// pinned profile object. The caller retains ownership of its source handle.
func StartSuspendedWithProfile(ctx context.Context, executable string, args []string, directory string, profile windows.Handle) (*Child, error) {
	if profile == 0 || profile == windows.InvalidHandle {
		return nil, ErrRejected
	}
	return startSuspendedWithProfile(ctx, executable, args, directory, profile)
}

func startSuspendedWithProfile(ctx context.Context, executable string, args []string, directory string, profile windows.Handle) (*Child, error) {
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
	inherited := []windows.Handle{parent}
	var profileCopy windows.Handle
	if profile != 0 {
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(profile, &info) != nil ||
			info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, ErrRejected
		}
		// Compare with cwd while the source handle keeps its object pinned.
		view, err := windows.CreateFile(&cwd[0], windows.GENERIC_READ,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return nil, ErrRejected
		}
		var cwdInfo windows.ByHandleFileInformation
		readErr := windows.GetFileInformationByHandle(view, &cwdInfo)
		closeErr := windows.CloseHandle(view)
		if readErr != nil || closeErr != nil || info.VolumeSerialNumber != cwdInfo.VolumeSerialNumber ||
			info.FileIndexHigh != cwdInfo.FileIndexHigh || info.FileIndexLow != cwdInfo.FileIndexLow {
			return nil, ErrRejected
		}
		if windows.DuplicateHandle(windows.CurrentProcess(), profile, windows.CurrentProcess(), &profileCopy,
			windows.GENERIC_READ|windows.SYNCHRONIZE, true, 0) != nil {
			return nil, ErrRejected
		}
		defer windows.CloseHandle(profileCopy)
		inherited = append(inherited, profileCopy)
	}
	// Do not copy the caller's credential-bearing environment or search PATH.
	environmentValues := []string{
		"APPDATA=" + directory, parentHandleEnvironment + "=" + strconv.FormatUint(uint64(parent), 10),
		"LOCALAPPDATA=" + directory, "PATH=" + system,
		"SystemRoot=" + root, "TEMP=" + directory, "TMP=" + directory,
		"USERPROFILE=" + directory, "WINDIR=" + root,
	}
	if profileCopy != 0 {
		environmentValues = append(environmentValues, "BIFROST_QS_PROFILE_HANDLE="+strconv.FormatUint(uint64(profileCopy), 10))
	}
	slices.Sort(environmentValues)
	environment := utf16.Encode([]rune(strings.Join(environmentValues, "\x00") + "\x00\x00"))
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
	pins.Pin(&inherited[0])
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
	if attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])) != nil {
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
