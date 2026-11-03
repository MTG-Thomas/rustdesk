use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use quick_support_guard::{proof_message, Denied, WorkstationLogin};

#[test]
fn proof_is_bound_to_native_receiver_and_challenge() {
    let signing = SigningKey::from_bytes(&[9; 32]);
    let verifying = signing.verifying_key();
    let login = WorkstationLogin::new("receiver".into(), "synthetic-grant".into(), move |bytes| {
        Ok(signing.sign(bytes).to_bytes())
    })
    .unwrap();
    let challenge = "0123456789abcdef0123456789abcdef";
    let (grant, proof) = login.authentication("receiver", challenge).unwrap();
    let signature = Signature::from_bytes(&proof);
    verifying
        .verify(
            &proof_message(grant, challenge, "receiver").unwrap(),
            &signature,
        )
        .unwrap();
    assert!(verifying
        .verify(
            &proof_message(grant, &"x".repeat(32), "receiver").unwrap(),
            &signature
        )
        .is_err());
    assert!(login.authentication("other-receiver", challenge).is_err());
    assert!(login
        .authentication("receiver", "legacy-short-challenge")
        .is_err());
}

#[test]
fn unavailable_signer_and_invalid_material_never_produce_authentication() {
    assert!(
        WorkstationLogin::new("receiver".into(), String::new(), |_| panic!(
            "must not sign"
        ))
        .is_err()
    );
    let login = WorkstationLogin::new("receiver".into(), "synthetic-grant".into(), |_| Err(Denied))
        .unwrap();
    assert!(login.authentication("receiver", &"x".repeat(32)).is_err());
}
