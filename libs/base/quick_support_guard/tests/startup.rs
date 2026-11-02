#[path = "../../../../src/quick_support_startup.rs"]
mod startup;

#[test]
fn private_launch_never_selects_legacy_startup() {
    for args in [
        vec!["--quick-support-private-pipes"],
        vec!["--quick-support-private-pipes", "pipe-a", "pipe-b"],
        vec!["--server", "--quick-support-private-pipes", "a", "b"],
        vec!["--install", "--quick-support-private-pipes=a"],
        vec!["--", "--quick-support-private-pipes", "a", "b"],
    ] {
        assert!(startup::is_private_launch(args));
    }
}

#[test]
fn ordinary_startup_arguments_keep_the_existing_path() {
    for args in [
        vec![],
        vec!["--server"],
        vec!["--quick_support"],
        vec!["--connect", "123456789"],
    ] {
        assert!(!startup::is_private_launch(args));
    }
}
