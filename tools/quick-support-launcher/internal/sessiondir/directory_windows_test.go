package sessiondir

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestAtomicOwnerDirectoryInheritanceAndLockedIdentity(t *testing.T) {
	directory, err := newAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Cleanup()
	path, err := directory.Path()
	if err != nil {
		t.Fatal(err)
	}
	if os.Rename(path, path+"-moved") == nil {
		os.Rename(path+"-moved", path)
		t.Fatal("owned directory could be renamed while locked")
	}
	for _, name := range []string{"", ".", "..", "../escape", `..\escape`, `C:\escape`, "NUL", "file:stream", "nul\x00byte"} {
		if _, err := directory.FilePath(name); err != ErrRejected {
			t.Fatal("untrusted artifact name accepted")
		}
	}
	filePath, err := directory.FilePath("client.exe")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	var ace *windows.ACCESS_ALLOWED_ACE
	if err != nil || acl == nil || acl.AceCount != 1 || windows.GetAce(acl, 0, &ace) != nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
		file.Close()
		t.Fatal("artifact did not inherit an owner-only DACL")
	}
	file.Close()
	if directory.Cleanup() != nil || directory.Cleanup() != nil {
		t.Fatal("owned directory cleanup failed")
	}
	if _, err := directory.Path(); err != ErrRejected {
		t.Fatal("cleaned directory remained usable")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("owned directory still exists")
	}
}

func TestCleanupKeepsOutsideJunctionTargetAndRetriesOwnedBusyFile(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if os.WriteFile(sentinel, []byte("preserve"), 0600) != nil {
		t.Fatal("failed to create outside sentinel")
	}
	directory, err := newAt(base)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Cleanup()
	path, _ := directory.Path()
	link := filepath.Join(path, "outside-junction")
	if os.Mkdir(link, 0700) != nil {
		t.Fatal("failed to create owned junction directory")
	}
	linkName, err := windows.UTF16FromString(link)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(&linkName[0], windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	data := winio.EncodeReparsePoint(&winio.ReparsePoint{Target: outside, IsMountPoint: true})
	var returned uint32
	err = windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &returned, nil)
	windows.CloseHandle(handle)
	if err != nil {
		t.Fatal("could not prepare the junction acceptance case", err)
	}
	busyPath, _ := directory.FilePath("busy.exe")
	busy, err := os.OpenFile(busyPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if directory.Cleanup() != ErrRejected {
		busy.Close()
		t.Fatal("busy artifact cleanup was reported successful")
	}
	if _, err := directory.FilePath("new.exe"); err != ErrRejected {
		busy.Close()
		t.Fatal("cleanup failure allowed new artifacts")
	}
	busy.Close()
	if directory.Cleanup() != nil {
		t.Fatal("known owned directory could not be cleaned after closing its file")
	}
	if contents, err := os.ReadFile(sentinel); err != nil || string(contents) != "preserve" {
		t.Fatal("cleanup escaped through the junction", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("owned root was not removed")
	}
}
