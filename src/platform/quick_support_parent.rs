use quick_support_guard::{ControlIdentity, Denied, VerifiedLaunch};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, OwnedHandle},
    },
};
use windows::Win32::{
    Foundation::{HANDLE, WAIT_TIMEOUT},
    Storage::FileSystem::{SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT},
    System::{
        Pipes::{GetNamedPipeInfo, GetNamedPipeServerProcessId, NAMED_PIPE_MODE, PIPE_SERVER_END},
        Threading::{GetProcessId, WaitForSingleObject},
    },
};

pub struct LocalPipe(File);

impl LocalPipe {
    /// Open only the launcher's local namespace. Disable server impersonation
    /// before opening, since the server is not authenticated until verification.
    pub fn connect(path: &str) -> Result<Self, Denied> {
        let nonce = path
            .strip_prefix(r"\\.\pipe\mtg-quick-support-")
            .ok_or(Denied)?;
        if nonce.len() != 64
            || !nonce
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err(Denied);
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_SQOS_PRESENT.0 | SECURITY_ANONYMOUS.0)
            .open(path)
            .map(Self)
            .map_err(|_| Denied)
    }
}

impl Read for LocalPipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}

/// Requires a process handle retained from trusted launch/handoff, never one
/// opened by resolving a peer-supplied PID. Ownership pins the process object.
pub struct ParentLaunch<C> {
    parent: OwnedHandle,
    configuration: C,
}

impl<C> ParentLaunch<C> {
    pub fn new(parent: OwnedHandle, configuration: C) -> Self {
        Self {
            parent,
            configuration,
        }
    }
}

impl<C: FnMut() -> Result<(ControlIdentity, String), Denied>> VerifiedLaunch<LocalPipe, LocalPipe>
    for ParentLaunch<C>
{
    fn verify_parent_and_config(
        &mut self,
        control: &LocalPipe,
        native: &LocalPipe,
    ) -> Result<(ControlIdentity, String), Denied> {
        verify_pipe_parent(self.parent.as_handle(), &control.0, &native.0)?;
        // This callback must independently verify signed, application-pinned
        // configuration and challenge. Peer ownership alone grants no authority.
        let configuration = (self.configuration)()?;
        verify_pipe_parent(self.parent.as_handle(), &control.0, &native.0)?;
        Ok(configuration)
    }
}

fn verify_pipe_parent(
    parent: BorrowedHandle<'_>,
    control: &File,
    native: &File,
) -> Result<(), Denied> {
    let parent = HANDLE(parent.as_raw_handle());
    // All handles remain borrowed from live owned objects throughout these calls.
    let expected = unsafe { GetProcessId(parent) };
    if expected == 0 || unsafe { WaitForSingleObject(parent, 0) } != WAIT_TIMEOUT {
        return Err(Denied);
    }
    for pipe in [control, native] {
        let mut actual = 0;
        let handle = HANDLE(pipe.as_raw_handle());
        let mut flags = NAMED_PIPE_MODE(0);
        unsafe { GetNamedPipeInfo(handle, Some(&mut flags), None, None, None) }
            .map_err(|_| Denied)?;
        if flags.0 & PIPE_SERVER_END.0 != 0 {
            return Err(Denied);
        }
        unsafe { GetNamedPipeServerProcessId(handle, &mut actual) }.map_err(|_| Denied)?;
        if actual != expected {
            return Err(Denied);
        }
    }
    if unsafe { WaitForSingleObject(parent, 0) } != WAIT_TIMEOUT {
        return Err(Denied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::io::FromRawHandle,
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
    };
    use windows::{
        core::PCWSTR,
        Win32::{
            Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
            System::{
                Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE},
                Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE},
            },
        },
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn pipe_pair() -> (File, LocalPipe) {
        let name = format!(
            r"\\.\pipe\mtg-quick-support-{:032x}{:032x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let raw = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                1000,
                None,
            )
        };
        assert!(!raw.is_invalid());
        let server = unsafe { File::from_raw_handle(raw.0) };
        let client = LocalPipe::connect(&name).unwrap();
        (server, client)
    }

    fn current_parent() -> OwnedHandle {
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                std::process::id(),
            )
        }
        .unwrap();
        unsafe { OwnedHandle::from_raw_handle(raw.0) }
    }

    struct WaitingProcess(Child);
    impl WaitingProcess {
        fn new() -> Self {
            Self(
                Command::new("powershell.exe")
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "[Console]::In.ReadLine() | Out-Null",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }
    }
    impl Drop for WaitingProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn local_clients_match_retained_parent_but_do_not_supply_configuration() {
        let (_a, control) = pipe_pair();
        let (_b, native) = pipe_pair();
        let parent = current_parent();
        assert!(verify_pipe_parent(parent.as_handle(), &control.0, &native.0).is_ok());
        let called = std::cell::Cell::new(false);
        let mut launch = ParentLaunch::new(parent, || {
            called.set(true);
            Err(Denied)
        });
        assert!(launch.verify_parent_and_config(&control, &native).is_err());
        assert!(
            called.get(),
            "configuration is still independently required"
        );
    }

    #[test]
    fn wrong_dead_or_inadequate_parent_handles_fail_closed() {
        let (_a, control) = pipe_pair();
        let (_b, native) = pipe_pair();
        let mut other = WaitingProcess::new();
        let retained = other.0.as_handle().try_clone_to_owned().unwrap();
        let called = std::cell::Cell::new(false);
        let mut launch = ParentLaunch::new(retained, || {
            called.set(true);
            Err(Denied)
        });
        assert!(launch.verify_parent_and_config(&control, &native).is_err());
        assert!(!called.get());
        other.0.kill().unwrap();
        other.0.wait().unwrap();
        assert!(launch.verify_parent_and_config(&control, &native).is_err());
        assert!(!called.get());
        let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, std::process::id()) }.unwrap();
        let inadequate = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        assert!(verify_pipe_parent(inadequate.as_handle(), &control.0, &native.0).is_err());
    }

    #[test]
    fn server_endpoints_and_nonlocal_or_malformed_names_are_rejected() {
        let (server, control) = pipe_pair();
        let (_b, native) = pipe_pair();
        let parent = current_parent();
        assert!(verify_pipe_parent(parent.as_handle(), &server, &native.0).is_err());
        assert!(verify_pipe_parent(parent.as_handle(), &control.0, &server).is_err());
        let nonpipe = File::open("NUL").unwrap();
        assert!(verify_pipe_parent(parent.as_handle(), &control.0, &nonpipe).is_err());
        for name in [
            r"\\remote\pipe\mtg-quick-support-",
            r"\\.\pipe\other",
            r"\\.\pipe\mtg-quick-support-00",
        ] {
            assert!(LocalPipe::connect(name).is_err());
        }
        let upper = format!(r"\\.\pipe\mtg-quick-support-{}", "A".repeat(64));
        assert!(LocalPipe::connect(&upper).is_err());
    }
}
