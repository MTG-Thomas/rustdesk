use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use quick_support_guard::{LaunchTrust, LaunchVerifier};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn trust() -> LaunchTrust {
    LaunchTrust {
        issuer: "https://support.example.test".into(),
        issuer_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        organization_id: "22222222-2222-4222-8222-222222222222".into(),
        solution_id: "33333333-3333-4333-8333-333333333333".into(),
    }
}
fn token() -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"rd-qs-launch+jwt"}"#),
        URL_SAFE_NO_PAD.encode(include_str!("fixtures/receiver-launch-v1.claims.json").trim())
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
fn verifier() -> LaunchVerifier {
    LaunchVerifier::new(trust(), "a".repeat(64)).unwrap()
}
fn resign(change: impl FnOnce(&mut Value), typ: &str) -> String {
    let mut claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token().split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    change(&mut claims);
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg":"EdDSA","typ":typ})).unwrap()),
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
fn worker_launch_vector_supplies_independent_control_identity_once() {
    assert_eq!(
        format!("{:x}", Sha256::digest(format!("{}\n", token()))),
        include_str!("fixtures/receiver-launch-v1.sha256").trim()
    );
    let mut v = verifier();
    let scope = v.verify(&token(), 1001).unwrap();
    assert_eq!(scope.session_id, "11111111-1111-4111-8111-111111111111");
    assert_eq!(scope.generation, "22222222-2222-4222-8222-222222222222");
    assert_eq!(scope.receiver_id, "123456789");
    assert!(v.verify(&token(), 1001).is_err());
    assert!(verifier().verify(&token(), 1000).is_err());
    assert!(verifier().verify(&token(), 1060).is_err());
    assert!(LaunchVerifier::new(trust(), "b".repeat(64))
        .unwrap()
        .verify(&token(), 1001)
        .is_err());
    let mut wrong = trust();
    wrong.issuer_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert!(LaunchVerifier::new(wrong, "a".repeat(64))
        .unwrap()
        .verify(&token(), 1001)
        .is_err());
}
#[test]
fn forged_cross_scope_and_malformed_launches_fail_terminally() {
    for (field, value) in [
        ("iss", json!("https://foreign.example.test")),
        ("aud", json!("other")),
        (
            "organization_id",
            json!("33333333-3333-4333-8333-333333333333"),
        ),
        ("solution_id", json!("22222222-2222-4222-8222-222222222222")),
        ("session_id", json!("invalid")),
        ("generation", json!("invalid")),
        ("receiver_id", json!("")),
        ("profile_nonce", json!("b".repeat(64))),
        ("iat", json!(1002)),
        ("exp", json!(1001)),
        ("exp", json!(1062)),
        ("unexpected", json!(true)),
    ] {
        let signed = resign(|c| c[field] = value, "rd-qs-launch+jwt");
        let mut v = verifier();
        assert!(v.verify(&signed, 1001).is_err(), "{field}");
        assert!(v.verify(&token(), 1001).is_err());
    }
    for malformed in [
        String::new(),
        "x".repeat(4097),
        format!("{}.", token()),
        resign(|_| {}, "rd-qs-control+jwt"),
        resign(|_| {}, "rd-qs+jwt"),
    ] {
        assert!(verifier().verify(&malformed, 1001).is_err());
    }
    let mut parts: Vec<_> = token().split('.').map(str::to_owned).collect();
    parts[1].replace_range(0..1, "A");
    assert!(verifier().verify(&parts.join("."), 1001).is_err());
}
