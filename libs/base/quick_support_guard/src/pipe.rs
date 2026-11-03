use super::{ChildConnection, ConsentRequest, ControlIdentity, Denied};
use std::{io::Read, time::Instant};

const MAX_CONTROL_BYTES: usize = 16384;
const MAX_NATIVE_BYTES: usize = 4 * 1024 * 1024;

/// Injected trust boundary, not an implementation of Windows peer verification.
/// Implementations must verify the retained parent process and independently
/// authenticated configuration; neither pipe bytes nor a PID argument is trust.
pub trait VerifiedLaunch<P, N> {
    fn verify_parent_and_config(
        &mut self,
        parent: &P,
        native: &N,
    ) -> Result<(ControlIdentity, String), Denied>;
}

/// Must be implemented by an isolated receiver-local event source, never IPC
/// from an installed client, the parent control stream or remote peer packets.
pub trait LocalConsent {
    fn receiver_approved(&mut self, request: &ConsentRequest) -> Result<(), Denied>;
}

/// Offline stream adapter. Own both streams; errors/EOF/exit drop them after
/// terminal authorization shutdown. Reads must be externally bounded/cancellable.
/// No OS pipe opening, startup hook, event loop or production trust is provided.
pub struct PipeAdapter<P, N> {
    streams: Option<(P, N)>,
    child: ChildConnection,
}

impl<P: Read, N: Read> PipeAdapter<P, N> {
    pub fn new(
        parent: P,
        native: N,
        launch: &mut impl VerifiedLaunch<P, N>,
    ) -> Result<Self, Denied> {
        let (identity, challenge) = launch.verify_parent_and_config(&parent, &native)?;
        Ok(Self {
            streams: Some((parent, native)),
            child: ChildConnection::new(identity, challenge)?,
        })
    }

    /// Dedicated parent stream: u32 big-endian byte length followed by one UTF-8
    /// signed control envelope. This source-only framing is separate from native
    /// RustDesk frames and is not wired into the launcher's existing two pipes.
    pub fn parent_control(&mut self, clock: impl FnOnce() -> (u64, Instant)) -> Result<(), Denied> {
        let result = (|| {
            let (parent, _) = self.streams.as_mut().ok_or(Denied)?;
            let mut header = [0; 4];
            parent.read_exact(&mut header).map_err(|_| Denied)?;
            let token = read_payload(
                parent,
                u32::from_be_bytes(header) as usize,
                MAX_CONTROL_BYTES,
            )?;
            let token = std::str::from_utf8(&token).map_err(|_| Denied)?;
            let (wall, now) = clock();
            self.child.parent_control(token, wall, now)
        })();
        self.finish(result)
    }

    pub fn request(
        &mut self,
        token: &str,
        proof: &[u8],
        wall: u64,
        now: Instant,
    ) -> Result<(), Denied> {
        let result = if self.streams.is_some() {
            self.child.request(token, proof, wall, now)
        } else {
            Err(Denied)
        };
        self.finish(result)
    }

    pub fn approve_locally(
        &mut self,
        source: &mut impl LocalConsent,
        mut clock: impl FnMut() -> Instant,
    ) -> Result<(), Denied> {
        let result = (|| {
            self.streams.as_ref().ok_or(Denied)?;
            let request = self.child.consent_request(clock())?;
            source.receiver_approved(&request)?;
            self.child.approve_locally(clock())
        })();
        self.finish(result)
    }

    /// Decode exactly one BytesCodec frame. Sample time after the blocking read
    /// so a frame completed after expiry never uses an earlier admission time.
    pub fn dispatch_next<T>(
        &mut self,
        clock: impl FnOnce() -> Instant,
        dispatch: impl FnOnce(&[u8]) -> Result<T, Denied>,
    ) -> Result<T, Denied> {
        let result = (|| {
            let (_, native) = self.streams.as_mut().ok_or(Denied)?;
            let mut header = [0; 4];
            native.read_exact(&mut header[..1]).map_err(|_| Denied)?;
            let width = usize::from((header[0] & 3) + 1);
            native
                .read_exact(&mut header[1..width])
                .map_err(|_| Denied)?;
            let length = (u32::from_le_bytes(header) >> 2) as usize;
            let payload = read_payload(native, length, MAX_NATIVE_BYTES)?;
            let mut frame = Vec::with_capacity(width + payload.len());
            frame.extend_from_slice(&header[..width]);
            frame.extend_from_slice(&payload);
            self.child.dispatch_frame(&frame, clock(), dispatch)
        })();
        self.finish(result)
    }

    /// Owner invokes on child exit, either stream EOF, cancellation or rejection.
    /// Actual process/job cancellation and bounded cleanup remain owner duties.
    pub fn stop(&mut self) {
        self.child.stop();
        self.streams.take();
    }

    /// Called by the independent application timer even while consent is pending.
    pub fn check_lease(&mut self, now: Instant) -> Result<(), Denied> {
        let result = self.child.check_lease(now);
        self.finish(result)
    }

    fn finish<T>(&mut self, result: Result<T, Denied>) -> Result<T, Denied> {
        if result.is_err() || self.child.is_stopped() {
            self.stop();
        }
        result
    }
}

fn read_payload(source: &mut impl Read, length: usize, maximum: usize) -> Result<Vec<u8>, Denied> {
    if length == 0 || length > maximum {
        return Err(Denied);
    }
    let mut payload = Vec::new();
    let mut chunk = [0; 8192];
    while payload.len() < length {
        let count = (length - payload.len()).min(chunk.len());
        source.read_exact(&mut chunk[..count]).map_err(|_| Denied)?;
        payload.extend_from_slice(&chunk[..count]);
    }
    Ok(payload)
}

impl<P, N> Drop for PipeAdapter<P, N> {
    fn drop(&mut self) {
        self.child.stop();
        self.streams.take();
    }
}
