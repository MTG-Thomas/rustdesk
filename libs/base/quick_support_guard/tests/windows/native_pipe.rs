#[path = "../../../../../src/platform/quick_support_async_pipe.rs"]
mod async_pipe;

use super::desktop_child::windows_parent::{bounded_pipe::CancellablePipe, ParentLaunch};
use quick_support_guard::{ControlIdentity, Denied, VerifiedLaunch};
use std::{
    io::{BufRead, BufReader},
    os::windows::io::{AsHandle, AsRawHandle},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::ServerOptions,
};

struct Fixture(Child);
impl Drop for Fixture {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn pipe_server_fixture() {
    let Ok(control_path) = std::env::var("QS_NATIVE_PIPE_CONTROL") else {
        return;
    };
    let native_path = std::env::var("QS_NATIVE_PIPE_NATIVE").unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let control = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&control_path)
                .unwrap();
            let mut native = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&native_path)
                .unwrap();
            println!("QS_NATIVE_PIPE_READY");
            control.connect().await.unwrap();
            native.connect().await.unwrap();
            let mut frame = [0; 5];
            if std::env::var_os("QS_NATIVE_PIPE_CANCEL").is_some() {
                assert!(native.read_exact(&mut frame).await.is_err());
                return;
            }
            native.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, b"\x10PING");
            native.write_all(b"\x10PONG").await.unwrap();
            assert_eq!(native.read(&mut [0; 1]).await.unwrap(), 0);
        })
        .await
        .unwrap();
    });
}

fn identity() -> Result<(ControlIdentity, String), Denied> {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/receiver-control-v1.json")).unwrap();
    let key: Vec<u8> = f["issuer_key"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    Ok((
        ControlIdentity {
            issuer: f["issuer"].as_str().unwrap().into(),
            issuer_key: key.try_into().unwrap(),
            organization_id: f["organization_id"].as_str().unwrap().into(),
            solution_id: f["solution_id"].as_str().unwrap().into(),
            session_id: f["session_id"].as_str().unwrap().into(),
            generation: f["generation"].as_str().unwrap().into(),
            receiver_id: f["receiver_id"].as_str().unwrap().into(),
        },
        "01234567890123456789012345678901".into(),
    ))
}

#[test]
fn verified_overlapped_handle_transfers_without_reopen_and_cancelled_handoff_is_denied() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for cancel in [false, true] {
        let nonce = (1u128 << 127) + u128::from(NEXT.fetch_add(2, Ordering::Relaxed));
        let control_path = format!(
            r"\\.\pipe\mtg-quick-support-{:032x}{:032x}",
            std::process::id(),
            nonce
        );
        let native_path = format!(
            r"\\.\pipe\mtg-quick-support-{:032x}{:032x}",
            std::process::id(),
            nonce + 1
        );
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "native_pipe::pipe_server_fixture", "--nocapture"])
            .env("QS_NATIVE_PIPE_CONTROL", &control_path)
            .env("QS_NATIVE_PIPE_NATIVE", &native_path)
            .env_remove("QS_NATIVE_PIPE_CANCEL")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if cancel {
            command.env("QS_NATIVE_PIPE_CANCEL", "1");
        }
        let mut fixture = Fixture(command.spawn().unwrap());
        let stdout = fixture.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut ready = false;
            // Keep stdout open through the fixture's final test-harness output.
            for line in BufReader::new(stdout).lines() {
                if !ready && line.unwrap().contains("QS_NATIVE_PIPE_READY") {
                    let _ = tx.send(true);
                    ready = true;
                }
            }
            if !ready {
                let _ = tx.send(false);
            }
        });
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        let cancelled = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(5);
        let control = CancellablePipe::connect(&control_path, deadline, cancelled.clone()).unwrap();
        let native = CancellablePipe::connect(&native_path, deadline, cancelled.clone()).unwrap();
        let trusted_parent = fixture.0.as_handle().try_clone_to_owned().unwrap();
        let mut launch = ParentLaunch::new(trusted_parent, identity);
        launch.verify_parent_and_config(&control, &native).unwrap();
        if cancel {
            cancelled.store(true, Ordering::Release);
            assert!(native.into_file().is_err());
        } else {
            let file = native.into_file().unwrap();
            let retained_handle = file.as_raw_handle();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let mut stream = unsafe { async_pipe::attach(file) }.unwrap();
                assert_eq!(stream.as_raw_handle(), retained_handle);
                fn native_stream<
                    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync,
                >(
                    _: &T,
                ) {
                }
                native_stream(&stream);
                tokio::time::timeout(Duration::from_secs(5), async {
                    stream.write_all(b"\x10PING").await.unwrap();
                    let mut frame = [0; 5];
                    stream.read_exact(&mut frame).await.unwrap();
                    assert_eq!(&frame, b"\x10PONG");
                })
                .await
                .unwrap();
            });
        }
        drop(control);
        assert!(fixture.0.wait().unwrap().success());
    }
}
