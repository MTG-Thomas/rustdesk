//go:build windows

package artifact

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// VerifyWindowsAuthenticode uses Windows' own Authenticode verification in the
// protected system PowerShell. The script is constant; the path and expected
// certificate travel in child environment fields rather than interpolated code.
func VerifyWindowsAuthenticode(ctx context.Context, file, publisher string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	kernel := syscall.NewLazyDLL("kernel32.dll")
	getDirectory := kernel.NewProc("GetSystemWindowsDirectoryW")
	buffer := make([]uint16, 32768)
	length, _, _ := getDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if length == 0 || length >= uintptr(len(buffer)) {
		return ErrRejected
	}
	windowsDirectory := syscall.UTF16ToString(buffer[:length])
	powershellDirectory := filepath.Join(windowsDirectory, "System32", "WindowsPowerShell", "v1.0")
	script := `$ErrorActionPreference = 'Stop'
Import-Module -Name ($PSHOME + '\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $env:BIFROST_QS_ARTIFACT
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -cne $env:BIFROST_QS_PUBLISHER -or $null -eq $signature.TimeStamperCertificate) { exit 1 }
exit 0`
	encoded := utf16.Encode([]rune(script))
	bytes := make([]byte, len(encoded)*2)
	for index, character := range encoded {
		binary.LittleEndian.PutUint16(bytes[index*2:], character)
	}
	command := exec.CommandContext(ctx, filepath.Join(powershellDirectory, "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(bytes))
	command.Dir = powershellDirectory
	command.Env = []string{
		"SystemRoot=" + windowsDirectory, "windir=" + windowsDirectory,
		"PSModulePath=" + filepath.Join(powershellDirectory, "Modules"),
		"BIFROST_QS_ARTIFACT=" + file, "BIFROST_QS_PUBLISHER=" + publisher,
	}
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Never relay OS output containing local paths or other customer information.
	if command.Run() != nil {
		return ErrRejected
	}
	return nil
}
