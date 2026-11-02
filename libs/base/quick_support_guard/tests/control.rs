use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use quick_support_guard::{
    proof_message, Admission, ChildConnection, ControlIdentity, ControlSession, Denied,
};
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, Instant};

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
