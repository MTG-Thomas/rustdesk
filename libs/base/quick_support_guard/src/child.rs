use super::{Admission, ControlIdentity, ControlSession, Denied};
use std::time::Instant;

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Source-only connection boundary. The caller must authenticate the parent
/// process/channel and supply trusted launch identity before constructing this.
/// Parent control and local UI callbacks must never be reachable from peer data.
pub struct ChildConnection {
    control: ControlSession,
    admission: Admission,
}

impl ChildConnection {
    pub fn new(identity: ControlIdentity, fresh_challenge: String) -> Result<Self, Denied> {
        Ok(Self {
            control: ControlSession::new(identity)?,
            admission: Admission::new(fresh_challenge)?,
        })
    }

    /// Only the authenticated parent-control channel may invoke this method.
    /// An invalid control closes the connection; do not fall back to peer input.
    pub fn parent_control(&mut self, token: &str, wall: u64, now: Instant) -> Result<(), Denied> {
        if self.control.apply(token, wall, now).is_err() {
            self.stop();
            return Err(Denied);
        }
        Ok(())
    }

    pub fn request(
        &mut self,
        token: &str,
        proof: &[u8],
        wall: u64,
        now: Instant,
    ) -> Result<(), Denied> {
        if self
            .control
            .request(&mut self.admission, token, proof, wall, now)
            .is_err()
        {
            self.stop();
            return Err(Denied);
        }
        Ok(())
    }

    /// Only the isolated receiver-local UI event may approve a pending request.
    pub fn approve_locally(&mut self, now: Instant) -> Result<(), Denied> {
        self.control.approve_locally(&mut self.admission, now)
    }

    /// Pass exactly one complete RustDesk BytesCodec frame, retaining ownership
    /// until dispatch returns. No buffered privileged packet survives denial.
    /// This is an authorization boundary, not a packet capability classifier.
    pub fn dispatch_frame<T>(
        &mut self,
        frame: &[u8],
        now: Instant,
        dispatch: impl FnOnce(&[u8]) -> Result<T, Denied>,
    ) -> Result<T, Denied> {
        let result = if self.control.can_control(&self.admission, now) {
            payload(frame).and_then(dispatch)
        } else {
            Err(Denied)
        };
        if result.is_err() {
            self.stop();
        }
        result
    }

    /// Rejection, disconnect, control EOF, callback failure and local stop all
    /// require transport/process teardown by the owner after this latch closes.
    pub fn stop(&mut self) {
        self.admission.close();
        self.control.stop();
    }
}

impl Drop for ChildConnection {
    fn drop(&mut self) {
        self.stop();
    }
}

fn payload(frame: &[u8]) -> Result<&[u8], Denied> {
    let first = *frame.first().ok_or(Denied)?;
    let header_len = usize::from((first & 3) + 1);
    let header = frame.get(..header_len).ok_or(Denied)?;
    let mut encoded = 0u32;
    for (index, value) in header.iter().enumerate() {
        encoded |= u32::from(*value) << (8 * index);
    }
    let length = (encoded >> 2) as usize;
    if length == 0 || length > MAX_FRAME_BYTES || frame.len() != header_len + length {
        return Err(Denied);
    }
    Ok(&frame[header_len..])
}
