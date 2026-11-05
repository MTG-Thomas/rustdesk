// Private launcher invocations must never fall through to the ordinary server,
// installer or GUI path while the authenticated child entry point is unavailable.

/// Isolated private entry. Signed release configuration, parent verification and
/// the issuer are not installed, so this always refuses; it must not fall through
/// to ordinary startup while those prerequisites are missing.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn private_launch() -> Option<Vec<String>> {
    log::warn!(
        "Quick Support private launch refused: signed configuration and issuer are not installed"
    );
    None
}
pub(crate) fn is_private_launch(
    args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
) -> bool {
    args.into_iter().any(|arg| {
        let arg = arg.as_ref().to_string_lossy();
        arg == "--quick-support-private-pipes"
            || arg.starts_with("--quick-support-private-pipes=")
            || arg == "--quick-support-control-pipe"
            || arg.starts_with("--quick-support-control-pipe=")
    })
}
