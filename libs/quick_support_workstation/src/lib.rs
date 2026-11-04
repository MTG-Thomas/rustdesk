//! Protected workstation identity storage.
//!
//! Explicit setup supplies and wipes an OS seed; ordinary loading never
//! regenerates a missing or corrupt identity. The Windows host retains verified
//! owner-only directory and file handles and refuses reparse points, inherited
//! broad access and replacement while these operations run.

use quick_support_guard::WorkstationKey;
use std::io;

/// The OS host must retain verified owner-only directory/file handles and refuse
/// reparse points, inherited broad access and replacement while these operations
/// run.
pub trait ProtectedKeyStore {
    /// Only genuine absence returns None. Corruption or access denial is Err.
    fn load(&mut self) -> io::Result<Option<WorkstationKey>>;
    /// Atomic create-new, never replace; report uncertain persistence as Err.
    fn create_new(&mut self, seed: &[u8; 32]) -> io::Result<WorkstationKey>;
}

/// Ordinary startup never creates a replacement identity on missing/corrupt data.
pub fn load_existing(store: &mut impl ProtectedKeyStore) -> io::Result<WorkstationKey> {
    store
        .load()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "workstation key missing"))
}

/// Explicit setup only. The injected initializer is not called after denial,
/// corruption or an existing identity; callers may supply synthetic test seeds.
/// Enrollment/grant issuance may begin only after create-new succeeds.
pub fn initialize_explicitly(
    store: &mut impl ProtectedKeyStore,
    initialize: impl FnOnce() -> io::Result<[u8; 32]>,
) -> io::Result<WorkstationKey> {
    if let Some(key) = store.load()? {
        return Ok(key);
    }
    let mut seed = initialize()?;
    let result = store.create_new(&seed);
    for byte in &mut seed {
        // Clear the transient seed on both successful and uncertain persistence.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    result
}

#[cfg(windows)]
mod windows_store;

#[cfg(windows)]
pub use windows_store::{drive_root, information, owner_only, WorkstationStore};
