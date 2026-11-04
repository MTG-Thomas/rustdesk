use quick_support_guard::WorkstationKey;
use std::io;

/// The OS host must retain verified owner-only directory/file handles and refuse
/// reparse points, inherited broad access and replacement while these operations
/// run. No filesystem implementation is enabled until Windows ACL qualification.
pub(crate) trait ProtectedKeyStore {
    /// Only genuine absence returns None. Corruption or access denial is Err.
    fn load(&mut self) -> io::Result<Option<WorkstationKey>>;
    /// Atomic create-new, never replace; report uncertain persistence as Err.
    fn create_new(&mut self, key: &WorkstationKey) -> io::Result<()>;
}

/// Ordinary startup never creates a replacement identity on missing/corrupt data.
pub(crate) fn load_existing(store: &mut impl ProtectedKeyStore) -> io::Result<WorkstationKey> {
    store
        .load()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "workstation key missing"))
}

/// Explicit setup only. The injected initializer is not called after denial,
/// corruption or an existing identity; callers may supply synthetic test seeds.
/// Enrollment/grant issuance may begin only after create-new succeeds.
pub(crate) fn initialize_explicitly(
    store: &mut impl ProtectedKeyStore,
    initialize: impl FnOnce() -> io::Result<WorkstationKey>,
) -> io::Result<WorkstationKey> {
    if let Some(key) = store.load()? {
        return Ok(key);
    }
    let key = initialize()?;
    store.create_new(&key)?;
    Ok(key)
}
