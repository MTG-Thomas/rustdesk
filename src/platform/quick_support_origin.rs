//! Independent launcher-origin checks. Pins belong to the signed application,
//! never the environment, customer link, pipe payload or file being verified.
use hbb_common::base64::{engine::general_purpose::STANDARD, Engine};
use quick_support_guard::Denied;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::windows::{
        ffi::OsStringExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, BorrowedHandle},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf, Prefix},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{HANDLE, WAIT_TIMEOUT},
        Storage::FileSystem::{GetDriveTypeW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
        System::{
            SystemInformation::GetSystemWindowsDirectoryW,
            Threading::{
                GetCurrentProcessId, GetProcessId, QueryFullProcessImageNameW, WaitForSingleObject,
                CREATE_NO_WINDOW, PROCESS_NAME_WIN32,
            },
        },
    },
};

pub struct ParentTrust {
    sha256: String,
    publisher: String,
    bytes: u64,
}
impl ParentTrust {
    pub fn new(sha256: String, publisher: String, bytes: u64) -> Result<Self, Denied> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || publisher.len() != 40
            || !publisher
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
            || bytes == 0
            || bytes > 512 * 1024 * 1024
        {
            return Err(Denied);
        }
        Ok(Self {
            sha256,
            publisher,
            bytes,
        })
    }
}

/// Blocking verification: invoke before async startup or on a blocking worker.
/// An image match establishes origin only, never session authority or consent.
pub fn verify_parent(parent: BorrowedHandle<'_>, trust: &ParentTrust) -> Result<(), Denied> {
    let handle = HANDLE(parent.as_raw_handle());
    let alive = || unsafe { WaitForSingleObject(handle, 0) } == WAIT_TIMEOUT;
    let id = unsafe { GetProcessId(handle) };
    if id == 0 || id == unsafe { GetCurrentProcessId() } || !alive() {
        return Err(Denied);
    }
    let mut name = vec![0u16; 32768];
    let mut length = name.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(name.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|_| Denied)?;
    if length == 0 || length as usize >= name.len() {
        return Err(Denied);
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(&name[..length as usize]));
    verify_file(&path, trust)?;
    if !alive() || unsafe { GetProcessId(handle) } != id {
        return Err(Denied);
    }
    Ok(())
}

fn verify_file(path: &Path, trust: &ParentTrust) -> Result<(), Denied> {
    use std::os::windows::fs::MetadataExt;
    let root = drive_root(path)?;
    // DRIVE_FIXED; refuse mapped/UNC/removable locations before reading an image.
    if unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } != 3 {
        return Err(Denied);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|_| Denied)?;
    let metadata = file.metadata().map_err(|_| Denied)?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() != trust.bytes
    {
        return Err(Denied);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let n = file.read(&mut buffer).map_err(|_| Denied)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    if format!("{:x}", hash.finalize()) != trust.sha256 {
        return Err(Denied);
    }
    // Keep the file open without write/delete sharing through OS verification.
    let directory = system_directory()?;
    let powershell = directory.join("System32/WindowsPowerShell/v1.0");
    const SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
Import-Module -Name ($PSHOME + '\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $env:BIFROST_QS_ORIGIN_FILE
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -cne $env:BIFROST_QS_ORIGIN_PUBLISHER -or $null -eq $signature.TimeStamperCertificate) { exit 1 }
exit 0"#;
    let encoded = STANDARD.encode(
        SCRIPT
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let mut child = Command::new(powershell.join("powershell.exe"))
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded,
        ])
        .current_dir(&powershell)
        .env_clear()
        .env("SystemRoot", &directory)
        .env("windir", &directory)
        .env("PSModulePath", powershell.join("Modules"))
        .env("BIFROST_QS_ORIGIN_FILE", path)
        .env("BIFROST_QS_ORIGIN_PUBLISHER", &trust.publisher)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW.0)
        .spawn()
        .map_err(|_| Denied)?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(Denied)
                }
            }
            Ok(None) if started.elapsed() < Duration::from_secs(30) => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                terminate(&mut child)?;
                return Err(Denied);
            }
        }
    }
}

pub(super) fn drive_root(path: &Path) -> Result<[u16; 4], Denied> {
    if !path.is_absolute() {
        return Err(Denied);
    }
    let letter = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err(Denied),
        },
        _ => return Err(Denied),
    };
    Ok([u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0])
}

fn terminate(child: &mut Child) -> Result<(), Denied> {
    let kill = child.kill();
    let wait = child.wait();
    if kill.is_err() || wait.is_err() {
        return Err(Denied);
    }
    Ok(())
}
fn system_directory() -> Result<PathBuf, Denied> {
    let mut name = vec![0u16; 32768];
    let len = unsafe { GetSystemWindowsDirectoryW(Some(&mut name)) } as usize;
    if len == 0 || len >= name.len() {
        return Err(Denied);
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&name[..len])))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_signed_fixture_verifies_without_executing_it() {
        let Some(path) = std::env::var_os("BIFROST_QS_TEST_SIGNED_ARTIFACT") else {
            assert_ne!(
                std::env::var("BIFROST_QS_REQUIRE_NATIVE_INTEROP").as_deref(),
                Ok("1"),
                "required signed fixture missing"
            );
            return;
        };
        let path = PathBuf::from(path);
        let bytes = std::fs::metadata(&path).unwrap().len();
        let digest = "8555777215510d83d2d61c9dc984e4fcc838bd7e79f9d18a42585431f5e8bb47";
        let pin = ParentTrust::new(
            digest.into(),
            "4230334F8A7DD84E50D0273EF379E8B4A82F5DA5".into(),
            bytes,
        )
        .unwrap();
        verify_file(&path, &pin).unwrap();
        let wrong = ParentTrust::new(digest.into(), "0".repeat(40), bytes).unwrap();
        assert!(verify_file(&path, &wrong).is_err());
        let wrong = ParentTrust::new("0".repeat(64), pin.publisher, bytes).unwrap();
        assert!(verify_file(&path, &wrong).is_err());
    }
    #[test]
    fn origin_requires_pins_and_a_retained_foreign_live_parent() {
        assert!(ParentTrust::new(String::new(), "0".repeat(40), 1).is_err());
        assert!(drive_root(Path::new("relative.exe")).is_err());
        assert!(drive_root(Path::new(r"\\server\share\launcher.exe")).is_err());
        assert!(drive_root(Path::new(r"\\.\pipe\launcher")).is_err());
        assert_eq!(
            drive_root(Path::new(r"C:\launcher.exe")).unwrap(),
            [67, 58, 92, 0]
        );
        assert!(ParentTrust::new("0".repeat(64), "0".repeat(40), 0).is_err());
        use std::os::windows::io::AsHandle;
        let current =
            std::process::Command::new(system_directory().unwrap().join("System32/cmd.exe"))
                .args(["/c", "exit", "0"])
                .spawn()
                .unwrap();
        let mut child = current;
        let handle = child.as_handle().try_clone_to_owned().unwrap();
        child.wait().unwrap();
        let pin = ParentTrust::new("0".repeat(64), "0".repeat(40), 1).unwrap();
        assert!(verify_parent(handle.as_handle(), &pin).is_err());
    }
}
