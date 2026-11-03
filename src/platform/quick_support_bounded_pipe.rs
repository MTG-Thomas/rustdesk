//! Single-reader overlapped I/O for the private receiver, with terminal bounds.
use super::{verify_pipe_parent, ParentLaunch};
use quick_support_guard::{ControlIdentity, Denied, VerifiedLaunch};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use windows::Win32::{
    Foundation::{ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::FileSystem::{
        ReadFile, FILE_FLAG_OVERLAPPED, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT,
    },
    System::{
        Threading::{CreateEventW, WaitForSingleObject},
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

pub struct CancellablePipe {
    file: File,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    stopped: bool,
}

/// Parallel opt-in host entry. Bounds come from the authoritative launch lease;
/// they are never read from peer traffic. No production startup hook is installed.
pub fn run_inherited(
    paths: (&str, &str),
    bounds: (Instant, Arc<AtomicBool>),
    verification: (
        impl FnMut(std::os::windows::io::BorrowedHandle<'_>) -> Result<(), Denied>,
        impl FnMut() -> Result<(ControlIdentity, String), Denied>,
    ),
    consent: &mut impl quick_support_guard::LocalConsent,
    next: impl FnMut() -> Result<super::super::Event, Denied>,
    clock: impl FnMut() -> (u64, Instant),
    dispatch: impl FnMut(&[u8]) -> Result<(), Denied>,
) -> Result<(), Denied> {
    let mut launch = ParentLaunch::from_environment(verification.0, verification.1)?;
    if paths.0 == paths.1 {
        return Err(Denied);
    }
    let control = CancellablePipe::connect(paths.0, bounds.0, bounds.1.clone())?;
    let native = CancellablePipe::connect(paths.1, bounds.0, bounds.1)?;
    super::super::run(control, native, &mut launch, consent, next, clock, dispatch)
}

impl CancellablePipe {
    pub fn connect(
        path: &str,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, Denied> {
        let nonce = path
            .strip_prefix(r"\\.\pipe\mtg-quick-support-")
            .ok_or(Denied)?;
        if nonce.len() != 64
            || !nonce
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            || deadline <= Instant::now()
            || cancelled.load(Ordering::Acquire)
        {
            return Err(Denied);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED.0)
            .security_qos_flags(SECURITY_SQOS_PRESENT.0 | SECURITY_ANONYMOUS.0)
            .open(path)
            .map_err(|_| Denied)?;
        Ok(Self {
            file,
            deadline,
            cancelled,
            stopped: false,
        })
    }

    fn bounds(&self) -> io::Result<()> {
        if self.stopped || self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "receiver stopped",
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "receiver deadline"));
        }
        Ok(())
    }

    fn read_once(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.bounds()?;
        let event = unsafe { CreateEventW(None, true, false, None) }.map_err(io::Error::other)?;
        let event = unsafe { OwnedHandle::from_raw_handle(event.0) };
        let handle = HANDLE(self.file.as_raw_handle());
        let mut operation = OVERLAPPED {
            hEvent: HANDLE(event.as_raw_handle()),
            ..Default::default()
        };
        let mut count = 0;
        match unsafe { ReadFile(handle, Some(buffer), None, Some(&mut operation)) } {
            Ok(()) => {
                unsafe { GetOverlappedResult(handle, &operation, &mut count, false) }
                    .map_err(io::Error::other)?;
                self.bounds()?;
                return Ok(count as usize);
            }
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {}
            Err(error) => return Err(io::Error::other(error)),
        }
        // The buffer and OVERLAPPED must stay alive until completion, including
        // cancellation. Parent Job Object termination remains the final OS-level
        // containment bound if the kernel cannot complete cancellation promptly.
        let result = loop {
            if let Err(error) = self.bounds() {
                break Err(error);
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            let milliseconds = remaining.as_millis().clamp(1, 10) as u32;
            match unsafe { WaitForSingleObject(HANDLE(event.as_raw_handle()), milliseconds) } {
                WAIT_OBJECT_0 => {
                    break unsafe { GetOverlappedResult(handle, &operation, &mut count, false) }
                        .map(|_| count as usize)
                        .map_err(io::Error::other)
                }
                WAIT_TIMEOUT => {}
                _ => break Err(io::Error::last_os_error()),
            }
        };
        if result.is_err() {
            // ERROR_NOT_FOUND means it already completed; either way, join the
            // exact operation before releasing its storage or caller's buffer.
            let _ = unsafe { CancelIoEx(handle, Some(&operation)) };
            let _ = unsafe { GetOverlappedResult(handle, &operation, &mut count, true) };
        }
        self.bounds()?;
        result
    }
}

impl Read for CancellablePipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let result = self.read_once(buffer);
        if result.is_err() || matches!(result, Ok(0)) {
            self.stopped = true;
        }
        result
    }
}

impl<C: FnMut() -> Result<(ControlIdentity, String), Denied>>
    VerifiedLaunch<CancellablePipe, CancellablePipe> for ParentLaunch<C>
{
    fn verify_parent_and_config(
        &mut self,
        control: &CancellablePipe,
        native: &CancellablePipe,
    ) -> Result<(ControlIdentity, String), Denied> {
        verify_pipe_parent(self.parent.as_handle(), &control.file, &native.file)?;
        let configuration = (self.configuration)()?;
        verify_pipe_parent(self.parent.as_handle(), &control.file, &native.file)?;
        Ok(configuration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, time::Duration};

    #[test]
    fn stalled_partial_reads_expire_and_cannot_resume() {
        let (mut server, path) = super::super::tests::pipe_server();
        let mut client = CancellablePipe::connect(
            &path,
            Instant::now() + Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        server.write_all(&[7]).unwrap();
        let mut frame = [0; 2];
        assert_eq!(
            client.read_exact(&mut frame).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(frame[0], 7);
        assert_eq!(
            client.read(&mut frame).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn cancellation_wakes_pending_read_and_is_terminal() {
        let (_server, path) = super::super::tests::pipe_server();
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut client = CancellablePipe::connect(
            &path,
            Instant::now() + Duration::from_secs(5),
            cancelled.clone(),
        )
        .unwrap();
        let signal = cancelled.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            signal.store(true, Ordering::Release);
        });
        let mut byte = [0];
        assert_eq!(
            client.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        worker.join().unwrap();
        cancelled.store(false, Ordering::Release);
        assert_eq!(
            client.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
