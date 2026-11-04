// Private launcher invocations must never fall through to the ordinary server,
// installer or GUI path while the authenticated child entry point is unavailable.
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
