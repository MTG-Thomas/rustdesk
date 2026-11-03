//! Adopt only the retained, verified native pipe; never reopen its path.
use hbb_common::tokio::net::windows::named_pipe::NamedPipeClient;
use quick_support_guard::Denied;
use std::{fs::File, os::windows::io::IntoRawHandle};

/// # Safety
/// `file` must be the verified local duplex named-pipe handle opened overlapped
/// by CancellablePipe, with no pending operation or borrowed I/O buffer.
pub(crate) unsafe fn attach(file: File) -> Result<NamedPipeClient, Denied> {
    // Tokio/mio takes sole ownership on both success and registration failure.
    // The handle was opened overlapped; no synchronous read remains in flight.
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }.map_err(|_| Denied)
}
