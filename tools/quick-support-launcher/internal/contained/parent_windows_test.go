package contained

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type handoffReceipt struct {
	Parent         uint32
	Access         uint32
	StrayInherited bool
}

func TestParentHandleHandoffAndContainedCleanup(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		directory := t.TempDir()
		marker := filepath.Join(directory, "handoff.json")
		name, err := windows.UTF16FromString(`Local\mtg-qs-handoff-` + strconv.Itoa(os.Getpid()) + "-" + filepath.Base(directory))
		if err != nil {
			t.Fatal(err)
		}
		attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
		stray, err := windows.CreateEvent(&attributes, 0, 0, &name[0])
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(stray)
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("QS_INHERIT_SECRET", "synthetic-not-a-credential")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		child, err := StartSuspendedWithParent(ctx, executable, []string{"-test.run=^TestParentHandoffChild$", "--", "qs-parent", marker, strconv.FormatUint(uint64(stray), 10), windows.UTF16ToString(name)}, directory)
		if err != nil {
			t.Fatal(err)
		}
		defer child.Close()
		handle, err := child.ProcessHandle()
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		var membership struct {
			Assigned, Count uint32
			IDs             [1]uintptr
		}
		var pin runtime.Pinner
		pin.Pin(&membership)
		err = windows.QueryInformationJobObject(child.job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&membership)), uint32(unsafe.Sizeof(membership)), nil)
		pin.Unpin()
		if err != nil || membership.Count != 1 {
			t.Fatal("child not atomically contained", err)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("child executed while suspended")
		}
		if err := child.Resume(); err != nil {
			t.Fatal(err)
		}
		var data []byte
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			data, err = os.ReadFile(marker)
			if err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		var receipt handoffReceipt
		if json.Unmarshal(data, &receipt) != nil || receipt.Parent != uint32(os.Getpid()) || receipt.Access != windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE || receipt.StrayInherited {
			t.Fatal("restricted handoff receipt missing or invalid", string(data))
		}
		if cancelled {
			cancel()
		} else if err := child.Close(); err != nil {
			t.Fatal(err)
		}
		if status, err := windows.WaitForSingleObject(handle, 5000); err != nil || status != windows.WAIT_OBJECT_0 {
			t.Fatal("owned child survived teardown", err)
		}
		if err := child.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParentHandoffChild(t *testing.T) {
	if len(os.Args) < 5 || os.Args[len(os.Args)-4] != "qs-parent" {
		t.Skip("owned subprocess entry")
	}
	if os.Getenv("QS_INHERIT_SECRET") != "" {
		t.Fatal("caller environment leaked")
	}
	value, err := strconv.ParseUint(os.Getenv(parentHandleEnvironment), 10, 64)
	if err != nil || value == 0 {
		t.Fatal("inherited parent identifier missing")
	}
	parent := windows.Handle(value)
	defer windows.CloseHandle(parent)
	if err := windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		t.Fatal(err)
	}
	pid, err := windows.GetProcessId(parent)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := windows.WaitForSingleObject(parent, 0); err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("parent is not live")
	}
	var info struct {
		Attributes, GrantedAccess, HandleCount, PointerCount uint32
		Reserved                                             [10]uint32
	}
	var size uint32
	var pin runtime.Pinner
	pin.Pin(&info)
	pin.Pin(&size)
	query := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject")
	status, _, _ := query.Call(uintptr(parent), 0, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&size)))
	pin.Unpin()
	if status != 0 {
		t.Fatal("cannot inspect inherited rights", status)
	}
	// Capture any same-number handle before opening the named fixture object;
	// otherwise a newly opened handle could itself reuse the parent's number.
	strayValue, err := strconv.ParseUint(os.Args[len(os.Args)-2], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	var captured windows.Handle
	inherited := false
	if windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(strayValue), windows.CurrentProcess(), &captured, 0, false, windows.DUPLICATE_SAME_ACCESS) == nil {
		defer windows.CloseHandle(captured)
		name, err := windows.UTF16FromString(os.Args[len(os.Args)-1])
		if err != nil {
			t.Fatal(err)
		}
		expected, err := windows.OpenEvent(windows.SYNCHRONIZE, false, &name[0])
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(expected)
		same, _, _ := windows.NewLazySystemDLL("kernelbase.dll").NewProc("CompareObjectHandles").Call(uintptr(captured), uintptr(expected))
		inherited = same != 0
	}
	data, err := json.Marshal(handoffReceipt{Parent: pid, Access: info.GrantedAccess, StrayInherited: inherited})
	marker := os.Args[len(os.Args)-3]
	if err != nil || os.WriteFile(marker+".tmp", data, 0600) != nil || os.Rename(marker+".tmp", marker) != nil {
		t.Fatal("cannot publish synthetic receipt")
	}
	time.Sleep(30 * time.Second)
}

func TestParentHandoffRejectsUnboundedOrRemoteLaunch(t *testing.T) {
	if child, err := StartSuspendedWithParent(context.Background(), `C:\unused.exe`, nil, `C:\`); child != nil || err != ErrRejected {
		t.Fatal("unbounded handoff accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if child, err := StartSuspendedWithParent(ctx, `\\server\share\unused.exe`, nil, `C:\`); child != nil || err != ErrRejected {
		t.Fatal("remote executable accepted")
	}
}
