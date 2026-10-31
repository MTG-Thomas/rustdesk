package contained

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestAtomicJobAssignmentAndTreeCleanupOnCloseOrExpiry(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		directory := t.TempDir()
		marker := filepath.Join(directory, "grandchild.pid")
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("QS_INHERIT_SECRET", "synthetic-not-a-credential")
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		child, err := StartSuspended(ctx, executable, []string{"-test.run=^TestOwnedContainedChild$", "--", "qs-owned", "tree", marker}, directory)
		if err != nil {
			t.Fatal(err)
		}
		defer child.Close()
		handle, err := child.ProcessHandle()
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		id, err := windows.GetProcessId(handle)
		if err != nil {
			t.Fatal(err)
		}
		var membership struct {
			Assigned, Count uint32
			IDs             [1]uintptr
		}
		var pin runtime.Pinner
		pin.Pin(&membership)
		queryErr := windows.QueryInformationJobObject(child.job, windows.JobObjectBasicProcessIdList,
			uintptr(unsafe.Pointer(&membership)), uint32(unsafe.Sizeof(membership)), nil)
		pin.Unpin()
		if queryErr != nil ||
			membership.Count != 1 || membership.IDs[0] != uintptr(id) {
			t.Fatal("suspended child was not already assigned to the owned job")
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("child ran before explicit resume")
		}
		if err := child.Resume(); err != nil {
			t.Fatal(err)
		}
		if child.Resume() != ErrRejected {
			t.Fatal("second resume accepted")
		}
		deadline := time.Now().Add(3 * time.Second)
		var grandchild windows.Handle
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(marker)
			if err == nil {
				pid, parseErr := strconv.ParseUint(string(data), 10, 32)
				if parseErr == nil && pid != 0 {
					grandchild, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
					if err != nil {
						t.Fatal(err)
					}
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if grandchild == 0 {
			t.Fatal("owned child did not create its test descendant")
		}
		defer windows.CloseHandle(grandchild)
		if !expiry {
			if err := child.Close(); err != nil {
				t.Fatal(err)
			}
		}
		for _, process := range []windows.Handle{handle, grandchild} {
			status, err := windows.WaitForSingleObject(process, 10000)
			if err != nil || status != windows.WAIT_OBJECT_0 {
				t.Fatal("session-owned process survived teardown", err)
			}
		}
		if err := child.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := child.ProcessHandle(); err != ErrRejected {
			t.Fatal("closed child exposed a process handle")
		}
	}
}

func TestOwnedContainedChild(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "qs-owned" {
		t.Skip("owned subprocess entry")
	}
	if os.Getenv("QS_INHERIT_SECRET") != "" {
		t.Fatal("caller environment leaked to child")
	}
	mode, marker := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if mode == "leaf" {
		time.Sleep(30 * time.Second)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestOwnedContainedChild$", "--", "qs-owned", "leaf", marker)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	if os.WriteFile(marker, []byte(strconv.Itoa(command.Process.Pid)), 0600) != nil {
		t.Fatal("failed to record owned descendant")
	}
	time.Sleep(30 * time.Second)
}

func TestUnboundedOrUntrustedLaunchIsRejected(t *testing.T) {
	if child, err := StartSuspended(context.Background(), `C:\unused.exe`, nil, `C:\`); child != nil || err != ErrRejected {
		t.Fatal("unbounded launch accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if child, err := StartSuspended(ctx, `\\server\share\untrusted.exe`, nil, `C:\`); child != nil || err != ErrRejected {
		t.Fatal("remote executable accepted")
	}
}
