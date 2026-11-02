use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use quick_support_guard::{proof_message, Admission, ControlIdentity, ControlSession};
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
fn session(f: &Fixture) -> ControlSession {
    let key: Vec<u8> = f
        .issuer_key
        .as_bytes()
        .chunks(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect();
    ControlSession::new(ControlIdentity {
        issuer: f.issuer.clone(),
        issuer_key: key.try_into().unwrap(),
        organization_id: f.organization_id.clone(),
        solution_id: f.solution_id.clone(),
        session_id: f.session_id.clone(),
        generation: f.generation.clone(),
        receiver_id: f.receiver_id.clone(),
    })
    .unwrap()
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
