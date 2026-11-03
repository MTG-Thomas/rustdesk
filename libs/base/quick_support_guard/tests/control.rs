#[cfg(windows)]
#[path = "../../../hbb_common/src/private_profile.rs"]
pub mod private_profile;
#[cfg(windows)]
extern crate self as hbb_common;
#[cfg(windows)]
pub use base64;
#[cfg(windows)]
pub use tokio;
#[cfg(windows)]
#[path = "windows/native_pipe.rs"]
mod native_pipe;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use quick_support_guard::{
    proof_message, Admission, ChildConnection, ControlIdentity, ControlSession, Denied,
    LocalConsent, PipeAdapter, VerifiedLaunch,
};
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, Instant};

#[path = "../../../../src/quick_support_child.rs"]
mod desktop_child;

#[derive(Deserialize)]
struct Fixture {
    issuer: String,
    issuer_key: String,
    organization_id: String,
    solution_id: String,
    session_id: String,
    generation: String,
    receiver_id: String,
    bootstrap: String,
    grant: String,
    renew: String,
    revoke: String,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/receiver-control-v1.json")).unwrap()
}
fn identity(f: &Fixture) -> ControlIdentity {
    let key: Vec<u8> = f
        .issuer_key
        .as_bytes()
        .chunks(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect();
    ControlIdentity {
        issuer: f.issuer.clone(),
        issuer_key: key.try_into().unwrap(),
        organization_id: f.organization_id.clone(),
        solution_id: f.solution_id.clone(),
        session_id: f.session_id.clone(),
        generation: f.generation.clone(),
        receiver_id: f.receiver_id.clone(),
    }
}
fn session(f: &Fixture) -> ControlSession {
    ControlSession::new(identity(f)).unwrap()
}
fn nested_bootstrap(token: &str) -> String {
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    claims["bootstrap"].as_str().unwrap().into()
}
fn peer_frame(payload: &[u8]) -> Vec<u8> {
    let width = if payload.len() < 1 << 6 {
        1usize
    } else if payload.len() < 1 << 14 {
        2
    } else {
        3
    };
    let mut frame =
        (((payload.len() as u32) << 2) | (width as u32 - 1)).to_le_bytes()[..width].to_vec();
    frame.extend_from_slice(payload);
    frame
}
fn resign(token: &str, change: impl FnOnce(&mut Value)) -> String {
    let parts: Vec<_> = token.split('.').collect();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    change(&mut claims);
    let input = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[7; 32])
                .sign(input.as_bytes())
                .to_bytes()
        )
    )
}
#[test]
fn worker_control_requires_grant_local_consent_and_terminal_revocation() {
    let f = fixture();
    let mut s = session(&f);
    let start = Instant::now();
    let challenge = "01234567890123456789012345678901";
    let mut admission = Admission::new(challenge.into()).unwrap();
    let proof = SigningKey::from_bytes(&[9; 32])
        .sign(&proof_message(&f.grant, challenge, &f.receiver_id).unwrap())
        .to_bytes();
    assert!(s
        .request(&mut admission, &f.grant, &proof, 1000, start)
        .is_err());
    assert!(s.apply(&f.renew, 1000, start).is_err());
    s.apply(&f.bootstrap, 1000, start).unwrap();
    assert!(s.apply(&f.bootstrap, 1000, start).is_err());
    s.request(
        &mut admission,
        &f.grant,
        &proof,
        1001,
        start + Duration::from_secs(1),
    )
    .unwrap();
    assert!(!s.can_control(&admission, start));
    s.approve_locally(&mut admission, start + Duration::from_secs(1))
        .unwrap();
    assert!(s.can_control(&admission, start + Duration::from_secs(1)));
    s.apply(&f.renew, 1002, start + Duration::from_secs(2))
        .unwrap();
    assert!(s
        .apply(&f.renew, 1002, start + Duration::from_secs(2))
        .is_err());
    s.apply(&f.revoke, 1003, start + Duration::from_secs(3))
        .unwrap();
    assert!(!s.can_control(&admission, start + Duration::from_secs(3)));
    assert!(s
        .approve_locally(&mut admission, start + Duration::from_secs(3))
        .is_err());
    assert!(s
        .apply(&f.renew, 1004, start + Duration::from_secs(4))
        .is_err());
}
#[test]
fn signed_mismatch_malformed_nested_and_out_of_order_control_fail_closed() {
    let f = fixture();
    let start = Instant::now();
    for field in [
        "iss",
        "aud",
        "organization_id",
        "solution_id",
        "session_id",
        "generation",
        "receiver_id",
    ] {
        let bad = resign(&f.bootstrap, |v| {
            v[field] = Value::String("mismatch".into())
        });
        let mut s = session(&f);
        assert!(s.apply(&bad, 1000, start).is_err());
        s.apply(&f.bootstrap, 1000, start).unwrap();
    }
    for bad in [
        resign(&f.bootstrap, |v| v["sequence"] = 2.into()),
        resign(&f.bootstrap, |v| v["lease"] = "invalid".into()),
        resign(&f.bootstrap, |v| {
            v["lease"] = resign(v["lease"].as_str().unwrap(), |lease| {
                lease["sequence"] = 2.into()
            })
            .into();
        }),
        resign(&f.bootstrap, |v| v["bootstrap"] = "invalid".into()),
        "not-a-jws".into(),
    ] {
        let mut s = session(&f);
        assert!(s.apply(&bad, 1000, start).is_err());
        s.apply(&f.bootstrap, 1000, start).unwrap();
    }
    let mut tampered = f.bootstrap.clone().into_bytes();
    let last = tampered.len() - 8;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    assert!(session(&f)
        .apply(std::str::from_utf8(&tampered).unwrap(), 1000, start)
        .is_err());
}
#[test]
fn expired_or_locally_stopped_control_cannot_reactivate() {
    let f = fixture();
    let start = Instant::now();
    assert!(session(&f).apply(&f.bootstrap, 1060, start).is_err());
    let mut s = session(&f);
    s.apply(&f.bootstrap, 1000, start).unwrap();
    assert!(s
        .apply(&f.renew, 1002, start + Duration::from_secs(60))
        .is_err());
    s.stop();
    assert!(s.apply(&f.revoke, 1003, start).is_err());
    let mut fresh = session(&f);
    fresh.stop();
    assert!(fresh.apply(&f.bootstrap, 1000, start).is_err());
}

#[test]
fn child_dispatch_requires_control_grant_and_local_consent() {
    let f = fixture();
    let start = Instant::now();
    let challenge = "01234567890123456789012345678901";
    let proof = SigningKey::from_bytes(&[9; 32])
        .sign(&proof_message(&f.grant, challenge, &f.receiver_id).unwrap())
        .to_bytes();
    let frame = [12, 1, 2, 3];
    for stage in 0..3 {
        let mut child = ChildConnection::new(identity(&f), challenge.into()).unwrap();
        if stage >= 1 {
            child.parent_control(&f.bootstrap, 1000, start).unwrap();
        }
        if stage >= 2 {
            child
                .request(&f.grant, &proof, 1001, start + Duration::from_secs(1))
                .unwrap();
        }
        assert!(child
            .dispatch_frame(
                &frame,
                start + Duration::from_secs(1),
                |_| -> Result<(), Denied> { panic!("premature dispatch") }
            )
            .is_err());
        assert!(child
            .approve_locally(start + Duration::from_secs(1))
            .is_err());
    }
    let mut child = ChildConnection::new(identity(&f), challenge.into()).unwrap();
    child.parent_control(&f.bootstrap, 1000, start).unwrap();
    child
        .request(&f.grant, &proof, 1001, start + Duration::from_secs(1))
        .unwrap();
    child
        .approve_locally(start + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        child
            .dispatch_frame(&frame, start + Duration::from_secs(1), |payload| Ok(
                payload.to_vec()
            ))
            .unwrap(),
        [1, 2, 3]
    );
    child
        .parent_control(&f.revoke, 1003, start + Duration::from_secs(3))
        .unwrap_err(); // Missing sequence 2 closes, rather than skipping control.
    assert!(child
        .dispatch_frame(
            &frame,
            start + Duration::from_secs(3),
            |_| -> Result<(), Denied> { panic!("dispatch after control failure") }
        )
        .is_err());
}

#[test]
fn nested_bootstrap_alone_never_initializes_control() {
    let f = fixture();
    let start = Instant::now();
    let nested = nested_bootstrap(&f.bootstrap);
    // The signed inner bootstrap is a different envelope type than the outer control.
    assert!(session(&f).apply(&nested, 1000, start).is_err());
    let mut child =
        ChildConnection::new(identity(&f), "01234567890123456789012345678901".into()).unwrap();
    assert!(child.parent_control(&nested, 1000, start).is_err());
    assert!(child.parent_control(&f.bootstrap, 1000, start).is_err());
    assert!(!child.can_control(start));
}

#[test]
fn peer_transport_bytes_never_apply_or_replace_parent_control() {
    let f = fixture();
    let start = Instant::now();
    let mut child =
        ChildConnection::new(identity(&f), "01234567890123456789012345678901".into()).unwrap();
    // A valid outer control token delivered as native traffic is still peer data.
    assert!(child
        .dispatch_frame(
            &peer_frame(f.bootstrap.as_bytes()),
            start,
            |_| -> Result<(), Denied> { panic!("peer bytes reached dispatch before control") }
        )
        .is_err());
    assert!(!child.can_control(start));
    assert!(child.parent_control(&f.bootstrap, 1000, start).is_err());
}

#[test]
fn child_teardown_is_terminal_for_expiry_invalid_frames_and_dispatch_failure() {
    let f = fixture();
    let start = Instant::now();
    let challenge = "01234567890123456789012345678901";
    let proof = SigningKey::from_bytes(&[9; 32])
        .sign(&proof_message(&f.grant, challenge, &f.receiver_id).unwrap())
        .to_bytes();
    for reason in 0..7 {
        let mut child = ChildConnection::new(identity(&f), challenge.into()).unwrap();
        child.parent_control(&f.bootstrap, 1000, start).unwrap();
        child
            .request(&f.grant, &proof, 1001, start + Duration::from_secs(1))
            .unwrap();
        child
            .approve_locally(start + Duration::from_secs(1))
            .unwrap();
        let now = start + Duration::from_secs(1);
        match reason {
            0 => {
                assert!(child
                    .dispatch_frame(
                        &[4, 1],
                        start + Duration::from_secs(60),
                        |_| -> Result<(), Denied> { panic!("expired dispatch") }
                    )
                    .is_err());
            }
            1 => {
                child.stop();
            }
            2 => {
                assert!(child
                    .dispatch_frame(&[4, 1], now, |_| -> Result<(), Denied> { Err(Denied) })
                    .is_err());
            }
            3 => {
                assert!(child
                    .dispatch_frame(&[8, 1], now, |_| -> Result<(), Denied> {
                        panic!("truncated dispatch")
                    })
                    .is_err());
            }
            4 => {
                assert!(child
                    .dispatch_frame(&[4, 1, 2], now, |_| -> Result<(), Denied> {
                        panic!("trailing dispatch")
                    })
                    .is_err());
            }
            5 => {
                assert!(child.parent_control(&f.bootstrap, 1001, now).is_err());
            }
            _ => {
                child
                    .parent_control(&f.renew, 1002, start + Duration::from_secs(2))
                    .unwrap();
                child
                    .parent_control(&f.revoke, 1003, start + Duration::from_secs(3))
                    .unwrap();
            }
        }
        assert!(child.approve_locally(now).is_err());
        assert!(child
            .dispatch_frame(&[4, 1], now, |_| -> Result<(), Denied> {
                panic!("reactivated dispatch")
            })
            .is_err());
        assert!(child.parent_control(&f.renew, 1002, now).is_err());
    }
}

struct SyntheticLaunch<'a> {
    fixture: &'a Fixture,
    allowed: bool,
}
impl<P, N> VerifiedLaunch<P, N> for SyntheticLaunch<'_> {
    fn verify_parent_and_config(
        &mut self,
        _parent: &P,
        _native: &N,
    ) -> Result<(ControlIdentity, String), Denied> {
        if !self.allowed {
            return Err(Denied);
        }
        Ok((
            identity(self.fixture),
            "01234567890123456789012345678901".into(),
        ))
    }
}
struct SyntheticConsent(bool);
impl LocalConsent for SyntheticConsent {
    fn receiver_approved(
        &mut self,
        _request: &quick_support_guard::ConsentRequest,
    ) -> Result<(), Denied> {
        if self.0 {
            Ok(())
        } else {
            Err(Denied)
        }
    }
}

#[test]
fn consent_prompt_requires_verified_pending_request_and_rechecks_expiry_after_ui() {
    use std::cell::Cell;
    struct Prompt<'a> {
        calls: &'a Cell<usize>,
        now: &'a Cell<Instant>,
        session: &'a str,
        technician: &'a str,
        reject: bool,
        expire: bool,
    }
    impl LocalConsent for Prompt<'_> {
        fn receiver_approved(
            &mut self,
            request: &quick_support_guard::ConsentRequest,
        ) -> Result<(), Denied> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(request.session_id(), self.session);
            assert_eq!(request.technician_id(), self.technician);
            assert!(request.deadline() > self.now.get());
            if self.expire {
                self.now.set(self.now.get() + Duration::from_secs(61));
            }
            if self.reject {
                Err(Denied)
            } else {
                Ok(())
            }
        }
    }
    let f = fixture();
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(f.grant.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    let technician = claims["sub"].as_str().unwrap();
    for mode in 0..5 {
        let start = Instant::now();
        let now = Cell::new(start + Duration::from_secs(1));
        let calls = Cell::new(0);
        let mut adapter = PipeAdapter::new(
            std::io::Cursor::new(control_frame(&f.bootstrap)),
            std::io::Cursor::new(vec![4, 7]),
            &mut SyntheticLaunch {
                fixture: &f,
                allowed: true,
            },
        )
        .unwrap();
        adapter.parent_control(|| (1000, start)).unwrap();
        if mode != 0 {
            let proof = SigningKey::from_bytes(&[9; 32])
                .sign(
                    &proof_message(&f.grant, "01234567890123456789012345678901", &f.receiver_id)
                        .unwrap(),
                )
                .to_bytes();
            adapter.request(&f.grant, &proof, 1001, now.get()).unwrap();
        }
        if mode == 1 {
            now.set(start + Duration::from_secs(61));
        }
        let mut prompt = Prompt {
            calls: &calls,
            now: &now,
            session: &f.session_id,
            technician,
            reject: mode == 2,
            expire: mode == 3,
        };
        assert_eq!(
            adapter.approve_locally(&mut prompt, || now.get()).is_ok(),
            mode == 4
        );
        let count = usize::from(mode >= 2);
        assert_eq!(calls.get(), count);
        assert!(adapter.approve_locally(&mut prompt, || now.get()).is_err());
        assert_eq!(
            calls.get(),
            count,
            "terminal/approved admission must not prompt again"
        );
    }
}
struct ObservedStream {
    bytes: std::io::Cursor<Vec<u8>>,
    drops: std::rc::Rc<std::cell::Cell<usize>>,
    reads: std::rc::Rc<std::cell::Cell<usize>>,
}
impl std::io::Read for ObservedStream {
    fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        // Fragment even headers into individual bytes, like a byte-mode pipe.
        let count = target.len().min(1);
        std::io::Read::read(&mut self.bytes, &mut target[..count])
    }
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
fn observed(
    bytes: Vec<u8>,
    drops: &std::rc::Rc<std::cell::Cell<usize>>,
    reads: &std::rc::Rc<std::cell::Cell<usize>>,
) -> ObservedStream {
    ObservedStream {
        bytes: std::io::Cursor::new(bytes),
        drops: drops.clone(),
        reads: reads.clone(),
    }
}
fn control_frame(token: &str) -> Vec<u8> {
    let mut frame = (token.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(token.as_bytes());
    frame
}
fn admit_pipe<P: std::io::Read, N: std::io::Read>(
    adapter: &mut PipeAdapter<P, N>,
    f: &Fixture,
    start: Instant,
) {
    adapter.parent_control(|| (1000, start)).unwrap();
    let proof = SigningKey::from_bytes(&[9; 32])
        .sign(&proof_message(&f.grant, "01234567890123456789012345678901", &f.receiver_id).unwrap())
        .to_bytes();
    adapter
        .request(&f.grant, &proof, 1001, start + Duration::from_secs(1))
        .unwrap();
    adapter
        .approve_locally(&mut SyntheticConsent(true), || {
            start + Duration::from_secs(1)
        })
        .unwrap();
}
#[test]
fn pipe_adapter_verifies_launch_before_read_and_requires_separate_local_consent() {
    let f = fixture();
    let start = Instant::now();
    let drops = std::rc::Rc::new(std::cell::Cell::new(0));
    let reads = std::rc::Rc::new(std::cell::Cell::new(0));
    assert!(PipeAdapter::new(
        observed(vec![], &drops, &reads),
        observed(vec![], &drops, &reads),
        &mut SyntheticLaunch {
            fixture: &f,
            allowed: false
        }
    )
    .is_err());
    assert_eq!(reads.get(), 0);
    assert_eq!(drops.get(), 2);
    let mut adapter = PipeAdapter::new(
        observed(control_frame(&f.bootstrap), &drops, &reads),
        observed(vec![4, 7], &drops, &reads),
        &mut SyntheticLaunch {
            fixture: &f,
            allowed: true,
        },
    )
    .unwrap();
    adapter.parent_control(|| (1000, start)).unwrap();
    assert!(adapter
        .approve_locally(&mut SyntheticConsent(false), || start)
        .is_err());
    assert_eq!(drops.get(), 4);
    assert!(adapter
        .dispatch_next(
            || start,
            |_| -> Result<(), Denied> { panic!("consent denial dispatched") }
        )
        .is_err());
}
#[test]
fn pipe_adapter_fragmented_frames_revocation_eof_and_exit_close_both_streams() {
    let f = fixture();
    let start = Instant::now();
    for ending in 0..5 {
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut parent = control_frame(&f.bootstrap);
        if ending != 4 {
            parent.extend(control_frame(&f.renew));
            parent.extend(control_frame(&f.revoke));
        }
        // A fragmented two-byte header followed by a second complete frame.
        let mut native = vec![1, 1];
        native.extend([7; 64]);
        native.extend([4, 3]);
        let mut adapter = PipeAdapter::new(
            observed(parent, &drops, &reads),
            observed(native, &drops, &reads),
            &mut SyntheticLaunch {
                fixture: &f,
                allowed: true,
            },
        )
        .unwrap();
        admit_pipe(&mut adapter, &f, start);
        assert_eq!(
            adapter
                .dispatch_next(|| start + Duration::from_secs(1), |p| Ok(p.to_vec()))
                .unwrap(),
            [7; 64]
        );
        match ending {
            0 => {
                adapter
                    .parent_control(|| (1002, start + Duration::from_secs(2)))
                    .unwrap();
                adapter
                    .parent_control(|| (1003, start + Duration::from_secs(3)))
                    .unwrap();
                assert_eq!(drops.get(), 2, "revoke drops streams before another read");
            }
            1 => {
                adapter.stop();
            } // Injected child exit/cancellation.
            2 => {
                assert!(adapter
                    .dispatch_next(
                        || start + Duration::from_secs(60),
                        |_| -> Result<(), Denied> { panic!("expired during read") }
                    )
                    .is_err());
            }
            3 => {
                assert_eq!(
                    adapter
                        .dispatch_next(|| start + Duration::from_secs(1), |p| Ok(p.to_vec()))
                        .unwrap(),
                    [3]
                );
                assert!(adapter
                    .dispatch_next(
                        || start,
                        |_| -> Result<(), Denied> { panic!("EOF dispatched") }
                    )
                    .is_err());
            }
            _ => {
                assert!(adapter
                    .parent_control(|| (1002, start + Duration::from_secs(2)))
                    .is_err());
            }
        }
        assert!(adapter
            .dispatch_next(
                || start,
                |_| -> Result<(), Denied> { panic!("terminal pipe reopened") }
            )
            .is_err());
        assert_eq!(drops.get(), 2);
        assert!(adapter
            .approve_locally(&mut SyntheticConsent(true), || start)
            .is_err());
    }
}
#[test]
fn pipe_adapter_malformed_truncated_oversized_and_replayed_controls_fail_closed() {
    let f = fixture();
    let start = Instant::now();
    let mut replay = control_frame(&f.bootstrap);
    replay.extend(control_frame(&f.bootstrap));
    let mut mismatch = control_frame(&resign(&f.bootstrap, |v| v["session_id"] = "other".into()));
    mismatch.extend(control_frame(&f.bootstrap));
    let mut bad_utf8 = 1u32.to_be_bytes().to_vec();
    bad_utf8.push(255);
    for (parent, first_ok) in [
        (vec![], false),
        (vec![0, 0], false),
        (vec![0, 0, 0, 0], false),
        (vec![0, 0, 64, 1], false),
        (vec![0, 0, 0, 2, 65], false),
        (bad_utf8, false),
        (replay, true),
        (mismatch, false),
    ] {
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut adapter = PipeAdapter::new(
            observed(parent, &drops, &reads),
            observed(vec![4, 1], &drops, &reads),
            &mut SyntheticLaunch {
                fixture: &f,
                allowed: true,
            },
        )
        .unwrap();
        if first_ok {
            adapter.parent_control(|| (1000, start)).unwrap();
        }
        assert!(adapter.parent_control(|| (1000, start)).is_err());
        assert_eq!(drops.get(), 2);
        assert!(adapter.parent_control(|| (1000, start)).is_err());
    }
    for native in [vec![], vec![1], vec![8, 1], vec![0], vec![7, 0, 0, 1]] {
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut adapter = PipeAdapter::new(
            observed(control_frame(&f.bootstrap), &drops, &reads),
            observed(native, &drops, &reads),
            &mut SyntheticLaunch {
                fixture: &f,
                allowed: true,
            },
        )
        .unwrap();
        admit_pipe(&mut adapter, &f, start);
        assert!(adapter
            .dispatch_next(
                || start + Duration::from_secs(1),
                |_| -> Result<(), Denied> { panic!("invalid native frame dispatched") }
            )
            .is_err());
        assert_eq!(drops.get(), 2);
    }
}

struct FaultStream {
    inner: ObservedStream,
    interrupt_once: bool,
    fail_after: Option<usize>,
    failure: std::io::ErrorKind,
    received: usize,
}
impl std::io::Read for FaultStream {
    fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
        if self.interrupt_once {
            self.interrupt_once = false;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if self.fail_after.is_some_and(|limit| self.received >= limit) {
            return Err(self.failure.into());
        }
        let count = std::io::Read::read(&mut self.inner, target)?;
        self.received += count;
        Ok(count)
    }
}

#[test]
fn pipe_adapter_retries_interruption_but_never_resumes_failed_partial_input() {
    let f = fixture();
    let start = Instant::now();
    for fault in [
        None,
        Some(std::io::ErrorKind::BrokenPipe),
        Some(std::io::ErrorKind::TimedOut),
        Some(std::io::ErrorKind::WouldBlock),
    ] {
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let native = FaultStream {
            inner: observed(vec![8, 5, 6], &drops, &reads),
            interrupt_once: true,
            fail_after: fault.map(|_| 2),
            failure: fault.unwrap_or(std::io::ErrorKind::BrokenPipe),
            received: 0,
        };
        let mut adapter = PipeAdapter::new(
            observed(control_frame(&f.bootstrap), &drops, &reads),
            native,
            &mut SyntheticLaunch {
                fixture: &f,
                allowed: true,
            },
        )
        .unwrap();
        admit_pipe(&mut adapter, &f, start);
        let mut dispatched = false;
        let result = adapter.dispatch_next(
            || start + Duration::from_secs(1),
            |payload| {
                dispatched = true;
                assert_eq!(payload, [5, 6]);
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), fault.is_none());
        assert_eq!(dispatched, fault.is_none());
        if fault.is_some() {
            assert_eq!(drops.get(), 2);
            assert!(adapter
                .dispatch_next(
                    || start,
                    |_| -> Result<(), Denied> { panic!("partial input resumed after failure") }
                )
                .is_err());
        }
        drop(adapter);
        assert_eq!(drops.get(), 2);
    }
}

#[test]
fn desktop_child_requires_separate_consent_and_closes_on_stop_or_failure() {
    use desktop_child::Event;
    let f = fixture();
    let start = Instant::now();
    for mode in 0..6 {
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let expired = std::cell::Cell::new(false);
        let mut parent = control_frame(&f.bootstrap);
        if mode == 3 {
            parent.extend(control_frame(&f.bootstrap));
        } else if mode == 4 {
            let revoke = resign(&f.revoke, |v| {
                v["sequence"] = 2.into();
                v["iat"] = 1001.into();
                v["exp"] = 1061.into();
            });
            let mut verifier = session(&f);
            verifier.apply(&f.bootstrap, 1001, start).unwrap();
            verifier.apply(&revoke, 1001, start).unwrap();
            parent.extend(control_frame(&revoke));
        }
        let proof = SigningKey::from_bytes(&[9; 32])
            .sign(
                &proof_message(&f.grant, "01234567890123456789012345678901", &f.receiver_id)
                    .unwrap(),
            )
            .to_bytes()
            .to_vec();
        let mut events = if mode == 2 {
            vec![Event::NativeFrame]
        } else if mode == 5 {
            vec![Event::Tick]
        } else {
            vec![
                Event::Grant {
                    token: f.grant.clone(),
                    proof,
                },
                Event::LocalApproval,
                if mode == 3 || mode == 4 {
                    Event::ParentControl
                } else {
                    Event::NativeFrame
                },
                Event::Stop,
            ]
        }
        .into_iter();
        let mut dispatched = 0;
        let result = desktop_child::run(
            observed(parent, &drops, &reads),
            observed(vec![4, 7], &drops, &reads),
            &mut SyntheticLaunch {
                fixture: &f,
                allowed: true,
            },
            &mut SyntheticConsent(mode != 1),
            || {
                if mode == 5 {
                    expired.set(true);
                }
                events.next().ok_or(Denied)
            },
            || {
                if expired.get() {
                    (1061, start + Duration::from_secs(61))
                } else {
                    (1001, start + Duration::from_secs(1))
                }
            },
            |payload| {
                assert_eq!(payload, [7]);
                dispatched += 1;
                Ok(())
            },
        );
        assert_eq!(result.is_ok(), mode == 0);
        assert_eq!(dispatched, usize::from(mode == 0));
        assert_eq!(drops.get(), 2);
        if mode == 4 {
            assert!(
                matches!(events.next(), Some(Event::Stop)),
                "revoke must return without another event"
            );
        }
    }
}

// Subprocess entry only. The Windows Go fixture invokes this explicitly and
// checks its receipts; normal Rust test runs do not represent that integration.
#[cfg(windows)]
#[test]
#[ignore = "invoked by the Go/Rust Windows interoperability fixture"]
fn receiver_interop_child() {
    use desktop_child::{
        windows_parent::{bounded_pipe::run_inherited, LocalPipe, ParentLaunch},
        Event,
    };
    use std::{
        cell::{Cell, RefCell},
        fs,
        os::windows::io::{AsHandle, AsRawHandle, OwnedHandle},
        path::{Path, PathBuf},
    };
    use windows::Win32::{Foundation::HANDLE, System::Threading::GetProcessId};

    #[derive(Deserialize)]
    struct Input {
        parent_pid: u32,
        control: String,
        rendezvous: String,
        relay: String,
        allow_consent: bool,
    }
    fn publish(path: &Path, bytes: &[u8]) {
        // The private directory is pinned against rename/delete. Publish a
        // separate empty marker only after the one-shot payload has been closed.
        fs::write(path, bytes).unwrap();
        fs::write(path.with_extension("complete"), []).unwrap();
    }
    let directory = PathBuf::from(std::env::var_os("APPDATA").unwrap());
    let input: Input =
        serde_json::from_slice(&fs::read(directory.join("receiver.fixture.json")).unwrap())
            .unwrap();
    let f = fixture();
    let challenge = "01234567890123456789012345678901";
    let start = Instant::now();
    let phase = Cell::new(0u64);
    let steps = Cell::new(0usize);
    let dispatched = Cell::new(0usize);
    let parent = RefCell::new(None::<OwnedHandle>);
    let configuration = RefCell::new(None::<ControlIdentity>);
    let rendezvous = RefCell::new(None::<LocalPipe>);
    let result = run_inherited(
        (&input.control, &input.relay),
        (
            Instant::now() + Duration::from_secs(10),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ),
        (
            |handle: std::os::windows::io::BorrowedHandle<'_>| {
                // Explicit synthetic expected-parent oracle, not production origin
                // attestation. The fixture controller supplied this known identity.
                assert_eq!(
                    unsafe { GetProcessId(HANDLE(handle.as_raw_handle())) },
                    input.parent_pid
                );
                desktop_child::windows_parent::profile::install_after_parent_verification()?;
                let pins = identity(&f);
                let scope = desktop_child::windows_parent::profile::load_launch_configuration(
                    quick_support_guard::LaunchTrust {
                        issuer: pins.issuer,
                        issuer_key: pins.issuer_key,
                        organization_id: pins.organization_id,
                        solution_id: pins.solution_id,
                    },
                )?;
                assert_eq!(scope.session_id, f.session_id);
                assert_eq!(scope.generation, f.generation);
                assert_eq!(scope.receiver_id, f.receiver_id);
                configuration.replace(Some(scope));
                parent.replace(Some(handle.try_clone_to_owned().unwrap()));
                Ok(())
            },
            || {
                let retained = parent.borrow();
                let retained = retained.as_ref().unwrap();
                let pipe = LocalPipe::connect(&input.rendezvous)?;
                let mut launch =
                    ParentLaunch::new(retained.as_handle().try_clone_to_owned().unwrap(), ())
                        .with_configuration(|| Ok((identity(&f), challenge.to_owned())));
                launch.verify_parent_and_config(&pipe, &pipe)?;
                rendezvous.replace(Some(pipe));
                Ok((
                    configuration.borrow_mut().take().ok_or(Denied)?,
                    challenge.to_owned(),
                ))
            },
        ),
        &mut SyntheticConsent(input.allow_consent),
        || {
            let step = steps.get() + 1;
            steps.set(step);
            match step {
                1 => {
                    phase.set(1);
                    publish(&directory.join("challenge.ready"), challenge.as_bytes());
                    let timeout = Instant::now() + Duration::from_secs(5);
                    let proof = loop {
                        if directory.join("grant.complete").exists() {
                            break fs::read(directory.join("grant.proof")).unwrap();
                        }
                        assert!(Instant::now() < timeout, "fixture proof missing");
                        std::thread::sleep(Duration::from_millis(10));
                    };
                    Ok(Event::Grant {
                        token: f.grant.clone(),
                        proof,
                    })
                }
                2 => Ok(Event::LocalApproval),
                3 => {
                    assert!(input.allow_consent, "denial reached native scheduling");
                    publish(
                        &directory.join("approval.ready"),
                        b"synthetic approval only",
                    );
                    Ok(Event::NativeFrame)
                }
                4 => {
                    phase.set(2);
                    Ok(Event::ParentControl)
                }
                5 => {
                    phase.set(3);
                    Ok(Event::ParentControl)
                }
                _ => panic!("terminal control requested another event"),
            }
        },
        || (1000 + phase.get(), start + Duration::from_secs(phase.get())),
        |payload| {
            assert_eq!(payload, [7]);
            dispatched.set(dispatched.get() + 1);
            publish(
                &directory.join("native.accepted"),
                b"verified synthetic dispatch",
            );
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(dispatched.get(), usize::from(input.allow_consent));
    assert_eq!(steps.get(), if input.allow_consent { 5 } else { 2 });
    let receipt = serde_json::json!({"dispatched":dispatched.get(),"steps":steps.get()});
    publish(
        &directory.join("receiver.finished"),
        &serde_json::to_vec(&receipt).unwrap(),
    );
    // The controller must prove Job Object teardown, rather than letting this
    // synthetic child exit itself and accidentally satisfy the cleanup check.
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn session_length_binding_accepts_only_live_bounded_terminal_revoke() {
    let f = fixture();
    let start = Instant::now();
    for (hard_expiry, now, accepted) in
        [(4600, 1700, true), (1730, 1700, true), (1700, 1700, false)]
    {
        let outer = resign(&f.bootstrap, |control| {
            let bootstrap = control["bootstrap"].as_str().unwrap();
            control["bootstrap"] = resign(bootstrap, |claims| {
                claims["exp"] = hard_expiry.into();
            })
            .into();
        });
        let mut session = session(&f);
        session.apply(&outer, 1000, start).unwrap();
        let revoke = resign(&f.revoke, |control| {
            control["sequence"] = 2.into();
            control["iat"] = now.into();
            control["exp"] = std::cmp::min(now + 60, hard_expiry).into();
        });
        let instant = start + Duration::from_secs(now - 1000);
        assert_eq!(session.apply(&revoke, now, instant).is_ok(), accepted);
        if accepted {
            assert!(session.apply(&outer, now, instant).is_err());
            assert!(session.apply(&revoke, now, instant).is_err());
        }
    }
}
