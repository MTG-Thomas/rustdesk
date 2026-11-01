package sessiondir

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrRejected = errors.New("quick support session directory rejected")

type Directory struct {
	mu            sync.Mutex
	parent        *os.Root
	parentHandle  windows.Handle
	handle        windows.Handle
	name, path    string
	closing, done bool
	result        error
}

func New() (*Directory, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		return nil, ErrRejected
	}
	return newAt(base)
}

func newAt(base string) (*Directory, error) {
	if !filepath.IsAbs(base) || strings.HasPrefix(base, `\\`) {
		return nil, fmt.Errorf("%w: base-path", ErrRejected)
	}
	baseName, err := windows.UTF16FromString(base)
	if err != nil {
		return nil, fmt.Errorf("%w: base-encoding", ErrRejected)
	}
	parentHandle, err := windows.CreateFile(&baseName[0], windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: parent-handle", ErrRejected)
	}
	var baseInfo windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(parentHandle, &baseInfo) != nil ||
		baseInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		baseInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(parentHandle)
		return nil, fmt.Errorf("%w: parent-attributes", ErrRejected)
	}
	parent, err := os.OpenRoot(base)
	if err != nil {
		windows.CloseHandle(parentHandle)
		return nil, fmt.Errorf("%w: parent-root", ErrRejected)
	}
	d := &Directory{parent: parent, parentHandle: parentHandle}
	ready := false
	defer func() {
		if !ready {
			if d.handle != 0 {
				markEmptyForDeletion(d.handle)
				windows.CloseHandle(d.handle)
			}
			parent.Close()
			windows.CloseHandle(parentHandle)
		}
	}()
	view, err := parent.Open(".")
	if err != nil {
		return nil, fmt.Errorf("%w: parent-view", ErrRejected)
	}
	var viewInfo windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(windows.Handle(view.Fd()), &viewInfo)
	view.Close()
	if err != nil || baseInfo.VolumeSerialNumber != viewInfo.VolumeSerialNumber ||
		baseInfo.FileIndexHigh != viewInfo.FileIndexHigh || baseInfo.FileIndexLow != viewInfo.FileIndexLow {
		return nil, fmt.Errorf("%w: parent-identity", ErrRejected)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("%w: token-user", ErrRejected)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, fmt.Errorf("%w: security-descriptor", ErrRejected)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("%w: random-name", ErrRejected)
	}
	d.name = "mtg-quick-support-" + hex.EncodeToString(nonce[:])
	d.path = filepath.Join(base, d.name)
	name, err := windows.NewNTUnicodeString(d.name)
	if err != nil {
		return nil, fmt.Errorf("%w: relative-name", ErrRejected)
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: parentHandle, ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var status windows.IO_STATUS_BLOCK
	var created windows.Handle
	// FILE_CREATE returns the fresh directory handle atomically. Never reopen or
	// adopt an existing name, and never allow rename/delete while this handle lives.
	if err := windows.NtCreateFile(&created, windows.GENERIC_READ|windows.DELETE|windows.SYNCHRONIZE, &attributes, &status, nil,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0); err != nil {
		return nil, fmt.Errorf("%w: atomic-create: %v", ErrRejected, err)
	}
	d.handle = created
	if !ownerOnly(d.handle, user.User.Sid) {
		return nil, fmt.Errorf("%w: owner-acl", ErrRejected)
	}
	ready = true
	return d, nil
}

func ownerOnly(handle windows.Handle, expected *windows.SID) bool {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(expected) {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
		return false
	}
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(expected)
}

func (d *Directory) Path() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing || d.done {
		return "", ErrRejected
	}
	return d.path, nil
}

func (d *Directory) FilePath(name string) (string, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." || strings.ContainsAny(name, `\/:`) || strings.ContainsRune(name, 0) {
		return "", ErrRejected
	}
	path, err := d.Path()
	if err != nil {
		return "", ErrRejected
	}
	return filepath.Join(path, name), nil
}

func markEmptyForDeletion(handle windows.Handle) error {
	remove := byte(1) // FILE_DISPOSITION_INFO.DeleteFile
	return windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &remove, 1)
}

// Cleanup requires the owned child/job to have stopped first. Content-removal
// failure retains the locked directory for a deliberate retry. Handle-release
// failures are reported, never converted to success by another call. This never
// recursively deletes by an absolute name. A process crash does not run it.
func (d *Directory) Cleanup() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return d.result
	}
	d.closing = true
	root, err := d.parent.OpenRoot(d.name)
	if err != nil {
		return ErrRejected
	}
	defer root.Close()
	list, err := root.Open(".")
	if err != nil {
		return ErrRejected
	}
	entries, err := list.ReadDir(-1)
	list.Close()
	if err != nil {
		return ErrRejected
	}
	for _, entry := range entries {
		if root.RemoveAll(entry.Name()) != nil {
			return ErrRejected
		}
	}
	if root.Close() != nil || markEmptyForDeletion(d.handle) != nil {
		return ErrRejected
	}
	if windows.CloseHandle(d.handle) != nil {
		return ErrRejected
	}
	d.handle = 0
	d.done = true
	parentErr := d.parent.Close()
	handleErr := windows.CloseHandle(d.parentHandle)
	if parentErr != nil || handleErr != nil {
		d.result = ErrRejected
	}
	return d.result
}

func (d *Directory) String() string   { return "QuickSupportSessionDirectory(redacted)" }
func (d *Directory) GoString() string { return d.String() }
