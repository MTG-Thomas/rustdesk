use quick_support_guard::{ControlIdentity, Denied, VerifiedLaunch};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
};
use windows::Win32::{
    Foundation::{
        DuplicateHandle, GetHandleInformation, SetHandleInformation, DUPLICATE_HANDLE_OPTIONS,
        HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT},
    System::{
        Pipes::{GetNamedPipeInfo, GetNamedPipeServerProcessId, NAMED_PIPE_MODE, PIPE_SERVER_END},
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetProcessId, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    },
};

#[path = "quick_support_origin.rs"]
pub mod origin;

pub struct LocalPipe(File);

#[path = "quick_support_bounded_pipe.rs"]
pub mod bounded_pipe;

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

    /// Consume only a candidate handle identifier. Actual peer/configuration
    /// authentication still happens inside the adapter before payload reads.
    /// `authenticate` must establish the expected trusted launch origin using
    /// independent authority; repeating PID/name/environment checks is not proof.
    pub fn from_environment(
        mut authenticate: impl FnMut(BorrowedHandle<'_>) -> Result<(), Denied>,
        configuration: C,
    ) -> Result<Self, Denied> {
        let parent = capture_parent()?;
        authenticate(parent.as_handle())?;
        Ok(Self::new(parent, configuration))
    }
}

fn capture_parent() -> Result<OwnedHandle, Denied> {
    const VARIABLE: &str = "BIFROST_QS_PARENT_HANDLE";
    let value = std::env::var(VARIABLE);
    std::env::remove_var(VARIABLE);
    let value = value.map_err(|_| Denied)?;
    let number = value.parse::<usize>().map_err(|_| Denied)?;
    if number == 0 || number == usize::MAX || number.to_string() != value {
        return Err(Denied);
    }
    let source = HANDLE(number as *mut std::ffi::c_void);
    let mut flags = 0;
    unsafe { GetHandleInformation(source, &mut flags) }.map_err(|_| Denied)?;
    if flags & HANDLE_FLAG_INHERIT.0 == 0 {
        return Err(Denied);
    }
    let expected = unsafe { GetProcessId(source) };
    if expected == 0
        || expected == unsafe { GetCurrentProcessId() }
        || unsafe { WaitForSingleObject(source, 0) } != WAIT_TIMEOUT
    {
        return Err(Denied);
    }
    let mut copy = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut copy,
            (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0,
            false,
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    }
    .map_err(|_| Denied)?;
    // DuplicateHandle returned a fresh, uniquely owned handle. Never adopt or
    // close the untrusted numeric source: it could alias another Rust owner.
    let owned = unsafe { OwnedHandle::from_raw_handle(copy.0) };
    let id = unsafe { GetProcessId(copy) };
    if id != expected
        || unsafe { WaitForSingleObject(copy, 0) } != WAIT_TIMEOUT
        || unsafe { GetProcessId(source) } != id
    {
        return Err(Denied);
    }
    unsafe { SetHandleInformation(source, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
        .map_err(|_| Denied)?;
    Ok(owned)
}

/// OS entry API for one receiver connection; not registered by default startup.
/// The caller supplies independent parent-origin and signed-configuration
/// verifiers, isolated consent and a bounded/cancellable scheduler/dispatcher.
pub fn run_inherited(
    control_path: &str,
    native_path: &str,
    verification: (
        impl FnMut(BorrowedHandle<'_>) -> Result<(), Denied>,
        impl FnMut() -> Result<(ControlIdentity, String), Denied>,
    ),
    consent: &mut impl quick_support_guard::LocalConsent,
    next: impl FnMut() -> Result<super::Event, Denied>,
    clock: impl FnMut() -> (u64, std::time::Instant),
    dispatch: impl FnMut(&[u8]) -> Result<(), Denied>,
) -> Result<(), Denied> {
    let (authenticate, configuration) = verification;
    let mut launch = ParentLaunch::from_environment(authenticate, configuration)?;
    if control_path == native_path {
        return Err(Denied);
    }
    let control = LocalPipe::connect(control_path)?;
    let native = LocalPipe::connect(native_path)?;
    super::run(control, native, &mut launch, consent, next, clock, dispatch)
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

    pub(super) fn pipe_server() -> (File, String) {
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
        (server, name)
    }

    fn pipe_pair() -> (File, LocalPipe) {
        let (server, name) = pipe_server();
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

    #[test]
    fn inherited_identifier_is_one_use_and_never_authenticates_a_wrong_peer() {
        const VARIABLE: &str = "BIFROST_QS_PARENT_HANDLE";
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var(VARIABLE, value),
                    None => std::env::remove_var(VARIABLE),
                }
            }
        }
        let _restore = Restore(std::env::var_os(VARIABLE));
        std::env::remove_var(VARIABLE);
        assert!(capture_parent().is_err());
        for value in [
            "0",
            "01",
            "+1",
            "-1",
            "not-a-handle",
            "18446744073709551615",
        ] {
            std::env::set_var(VARIABLE, value);
            assert!(capture_parent().is_err());
            assert!(std::env::var_os(VARIABLE).is_none());
        }
        let mut other = WaitingProcess::new();
        for (pid, rights) in [
            (
                std::process::id(),
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            ),
            (other.0.id(), PROCESS_SYNCHRONIZE),
        ] {
            let raw = unsafe { OpenProcess(rights, true, pid) }.unwrap();
            let handle = unsafe { OwnedHandle::from_raw_handle(raw.0) };
            std::env::set_var(VARIABLE, (handle.as_raw_handle() as usize).to_string());
            assert!(capture_parent().is_err());
        }
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                true,
                other.0.id(),
            )
        }
        .unwrap();
        let source = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        let value = (source.as_raw_handle() as usize).to_string();
        std::env::set_var(VARIABLE, &value);
        let copy = capture_parent().unwrap();
        assert_eq!(
            unsafe { GetProcessId(HANDLE(copy.as_raw_handle())) },
            other.0.id()
        );
        let mut flags = 0;
        unsafe { GetHandleInformation(HANDLE(copy.as_raw_handle()), &mut flags) }.unwrap();
        assert_eq!(flags & HANDLE_FLAG_INHERIT.0, 0);
        unsafe { GetHandleInformation(raw, &mut flags) }.unwrap();
        assert_eq!(flags & HANDLE_FLAG_INHERIT.0, 0);
        assert!(capture_parent().is_err());

        // Re-introducing the number cannot reuse the now non-inheritable slot.
        std::env::set_var(VARIABLE, &value);
        assert!(capture_parent().is_err());
        struct Consent;
        impl quick_support_guard::LocalConsent for Consent {
            fn receiver_approved(
                &mut self,
                _request: &quick_support_guard::ConsentRequest,
            ) -> Result<(), Denied> {
                panic!("unverified launch reached consent")
            }
        }
        for allow_origin in [false, true] {
            unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
                .unwrap();
            std::env::set_var(VARIABLE, &value);
            let (_a, control) = pipe_server();
            let (_b, native) = pipe_server();
            let called = std::cell::Cell::new(false);
            let origin = std::cell::Cell::new(false);
            assert!(run_inherited(
                &control,
                &native,
                (
                    |parent: BorrowedHandle<'_>| {
                        origin.set(true);
                        assert_eq!(
                            unsafe { GetProcessId(HANDLE(parent.as_raw_handle())) },
                            other.0.id()
                        );
                        if allow_origin {
                            Ok(())
                        } else {
                            Err(Denied)
                        }
                    },
                    || {
                        called.set(true);
                        Err(Denied)
                    }
                ),
                &mut Consent,
                || panic!("unverified launch reached event loop"),
                || (1000, std::time::Instant::now()),
                |_| panic!("unverified launch reached native dispatch")
            )
            .is_err());
            assert!(origin.get());
            assert!(!called.get());
            assert!(std::env::var_os(VARIABLE).is_none());
        }
        other.0.kill().unwrap();
        other.0.wait().unwrap();
        unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }.unwrap();
        std::env::set_var(VARIABLE, &value);
        assert!(capture_parent().is_err());
    }
}
