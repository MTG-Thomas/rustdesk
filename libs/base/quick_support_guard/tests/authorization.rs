use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use quick_support_guard::{
    proof_message, Bootstrap, Grant, Lease, Receiver, ReceiverIdentity, AUDIENCE,
};
use serde::Serialize;
use std::time::{Duration, Instant};

const SESSION: &str = "76cb30af-bad6-4d79-9f99-d59bced8fe1c";
const GENERATION: &str = "312a1979-0272-5ce4-813b-7e18afba0f13";
const TECHNICIAN: &str = "00000000-0000-0000-0000-000000000002";
const CHALLENGE: &str = "01234567890123456789012345678901";

fn sign<T: Serialize>(value: &T, key: &SigningKey) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"rd-qs+jwt"}"#);
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
    let message = format!("{header}.{claims}");
    let signature = key.sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

struct Fixture {
    issuer: SigningKey,
    workstation: SigningKey,
    receiver: Receiver,
    start: Instant,
}
impl Fixture {
    fn new() -> Self {
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let workstation = SigningKey::from_bytes(&[9; 32]);
        let start = Instant::now();
        let receiver = Receiver::new(
            ReceiverIdentity {
                issuer: "https://support.example.test".into(),
                issuer_key: issuer.verifying_key().to_bytes(),
                session_id: SESSION.into(),
                generation: GENERATION.into(),
                receiver_id: "123456789".into(),
                technician_id: TECHNICIAN.into(),
                workstation_key: workstation.verifying_key().to_bytes(),
                hard_expiry: 87400,
            },
            1000,
            start,
        )
        .unwrap();
        Self {
            issuer,
            workstation,
            receiver,
            start,
        }
    }
    fn lease(&self, sequence: u64, issued: u64) -> String {
        sign(
            &Lease {
                iss: "https://support.example.test".into(),
                aud: AUDIENCE.into(),
                session_id: SESSION.into(),
                generation: GENERATION.into(),
                receiver_id: "123456789".into(),
                sequence,
                iat: issued,
                exp: issued + 60,
            },
            &self.issuer,
        )
    }
    fn grant(&self) -> Grant {
        Grant {
            iss: "https://support.example.test".into(),
            aud: AUDIENCE.into(),
            sub: TECHNICIAN.into(),
            session_id: SESSION.into(),
            generation: GENERATION.into(),
            receiver_id: "123456789".into(),
            workstation_key: URL_SAFE_NO_PAD.encode(self.workstation.verifying_key().to_bytes()),
            jti: URL_SAFE_NO_PAD.encode([11; 32]),
            iat: 1000,
            nbf: 1000,
            exp: 1060,
        }
    }
    fn proof(&self, token: &str, challenge: &str) -> Vec<u8> {
        self.workstation
            .sign(&proof_message(token, challenge, "123456789").unwrap())
            .to_bytes()
            .to_vec()
    }
    fn activate(&mut self) {
        self.receiver
            .renew(&self.lease(1, 1000), 1000, self.start)
            .unwrap();
    }
}

#[test]
fn authorization_requires_active_lease_and_is_one_use() {
    let mut f = Fixture::new();
    let token = sign(&f.grant(), &f.issuer);
    let proof = f.proof(&token, CHALLENGE);
    assert!(f
        .receiver
        .authorize(&token, &proof, CHALLENGE, 1000, f.start)
        .is_err());
    f.activate();
    assert!(f
        .receiver
        .authorize(&token, &proof, CHALLENGE, 1000, f.start)
        .is_ok());
    assert!(f
        .receiver
        .authorize(&token, &proof, CHALLENGE, 1000, f.start)
        .is_err());
}

#[test]
fn challenge_and_workstation_are_authenticated() {
    let mut f = Fixture::new();
    f.activate();
    let token = sign(&f.grant(), &f.issuer);
    let proof = f.proof(&token, CHALLENGE);
    assert!(f
        .receiver
        .authorize(
            &token,
            &proof,
            "different-challenge-01234567890123",
            1000,
            f.start
        )
        .is_err());
    let wrong = SigningKey::from_bytes(&[12; 32])
        .sign(&proof_message(&token, CHALLENGE, "123456789").unwrap());
    assert!(f
        .receiver
        .authorize(&token, &wrong.to_bytes(), CHALLENGE, 1000, f.start)
        .is_err());
    assert!(f
        .receiver
        .authorize(&token, &proof, CHALLENGE, 1000, f.start)
        .is_ok());
}

#[test]
fn grants_cannot_cross_session_generation_owner_or_receiver() {
    for field in 0..5 {
        let mut f = Fixture::new();
        f.activate();
        let mut grant = f.grant();
        match field {
            0 => grant.session_id = GENERATION.into(),
            1 => grant.generation = SESSION.into(),
            2 => grant.sub = GENERATION.into(),
            3 => grant.receiver_id = "987654321".into(),
            _ => grant.aud = "other-service".into(),
        }
        let token = sign(&grant, &f.issuer);
        let proof = f.proof(&token, CHALLENGE);
        assert!(f
            .receiver
            .authorize(&token, &proof, CHALLENGE, 1000, f.start)
            .is_err());
    }
}

#[test]
fn outage_and_clock_rollback_do_not_extend_lease() {
    let mut f = Fixture::new();
    f.activate();
    assert!(f.receiver.active(f.start + Duration::from_secs(59)));
    assert!(!f.receiver.active(f.start + Duration::from_secs(60)));
    let stale = f.lease(2, 1000);
    assert!(f
        .receiver
        .renew(&stale, 900, f.start + Duration::from_secs(61))
        .is_err());
}

#[test]
fn lease_replay_and_hard_expiry_fail_closed() {
    let mut f = Fixture::new();
    f.activate();
    assert!(f
        .receiver
        .renew(&f.lease(1, 1000), 1001, f.start + Duration::from_secs(1))
        .is_err());
    assert!(f
        .receiver
        .renew(&f.lease(2, 1001), 1001, f.start + Duration::from_secs(1))
        .is_ok());
    assert!(!f.receiver.active(f.start + Duration::from_secs(86400)));
}

#[test]
fn forged_and_malformed_tokens_fail_without_panicking() {
    let mut f = Fixture::new();
    f.activate();
    let grant = f.grant();
    let forged = sign(&grant, &SigningKey::from_bytes(&[15; 32]));
    let proof = f.proof(&forged, CHALLENGE);
    assert!(f
        .receiver
        .authorize(&forged, &proof, CHALLENGE, 1000, f.start)
        .is_err());
    for token in ["", "...", "x.y.z", "a.b.c.d", "eyJhbGciOiJub25lIn0.e30."] {
        assert!(f
            .receiver
            .authorize(token, &[0; 64], CHALLENGE, 1000, f.start)
            .is_err());
    }
}

#[test]
fn bootstrap_requires_pinned_issuer_and_signature() {
    let f = Fixture::new();
    let bootstrap = Bootstrap {
        iss: "https://support.example.test".into(),
        aud: AUDIENCE.into(),
        session_id: SESSION.into(),
        generation: GENERATION.into(),
        receiver_id: "123456789".into(),
        technician_id: TECHNICIAN.into(),
        workstation_key: URL_SAFE_NO_PAD.encode(f.workstation.verifying_key().to_bytes()),
        iat: 1000,
        exp: 87400,
    };
    let token = sign(&bootstrap, &f.issuer);
    let pinned = f.issuer.verifying_key().to_bytes();
    assert!(Receiver::from_bootstrap(
        &token,
        "https://support.example.test",
        &pinned,
        1000,
        f.start
    )
    .is_ok());
    assert!(Receiver::from_bootstrap(
        &token,
        "https://attacker.example.test",
        &pinned,
        1000,
        f.start
    )
    .is_err());
    assert!(Receiver::from_bootstrap(
        &token,
        "https://support.example.test",
        &SigningKey::from_bytes(&[16; 32]).verifying_key().to_bytes(),
        1000,
        f.start
    )
    .is_err());
    assert!(Receiver::from_bootstrap(
        &token,
        "https://support.example.test",
        &pinned,
        1061,
        f.start
    )
    .is_err());
}

#[test]
fn clock_forward_then_back_never_resurrects_grant() {
    let mut f = Fixture::new();
    f.activate();
    let token = sign(&f.grant(), &f.issuer);
    let proof = f.proof(&token, CHALLENGE);
    assert!(f
        .receiver
        .authorize(&token, &proof, CHALLENGE, 1061, f.start)
        .is_err());
    assert!(f
        .receiver
        .authorize(&token, &proof, CHALLENGE, 1000, f.start)
        .is_err());
}

#[test]
fn oversized_grants_and_wrong_signature_lengths_fail_closed() {
    let mut f = Fixture::new();
    f.activate();
    assert!(f
        .receiver
        .authorize(&"a".repeat(4097), &[0; 64], CHALLENGE, 1000, f.start)
        .is_err());
    let token = sign(&f.grant(), &f.issuer);
    for length in [0, 1, 63, 65, 1024] {
        assert!(f
            .receiver
            .authorize(&token, &vec![0; length], CHALLENGE, 1000, f.start)
            .is_err());
    }
}

#[test]
fn technician_authorization_does_not_grant_control_without_local_consent() {
    let mut f = Fixture::new();
    f.activate();
    let mut admission = quick_support_guard::Admission::new(CHALLENGE.into()).unwrap();
    assert!(admission.approve_locally(&f.receiver, f.start).is_err());
    let token = sign(&f.grant(), &f.issuer);
    let proof = f.proof(&token, CHALLENGE);
    admission
        .request(&mut f.receiver, &token, &proof, 1000, f.start)
        .unwrap();
    assert!(!admission.can_control(&f.receiver, f.start));
    admission.approve_locally(&f.receiver, f.start).unwrap();
    assert!(admission.can_control(&f.receiver, f.start));
    assert!(!admission.can_control(&f.receiver, f.start + Duration::from_secs(60)));
}

#[test]
fn stale_local_approval_and_second_login_are_rejected() {
    let mut f = Fixture::new();
    f.activate();
    let mut admission = quick_support_guard::Admission::new(CHALLENGE.into()).unwrap();
    let token = sign(&f.grant(), &f.issuer);
    let proof = f.proof(&token, CHALLENGE);
    admission
        .request(&mut f.receiver, &token, &proof, 1000, f.start)
        .unwrap();
    assert!(admission
        .request(&mut f.receiver, &token, &proof, 1000, f.start)
        .is_err());
    assert!(admission
        .approve_locally(&f.receiver, f.start + Duration::from_secs(60))
        .is_err());
}

#[test]
fn nonce_capacity_never_evicts_replay_protection() {
    let mut f = Fixture::new();
    f.activate();
    for index in 0..quick_support_guard::MAX_CONNECTIONS {
        let mut grant = f.grant();
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
        grant.jti = URL_SAFE_NO_PAD.encode(nonce);
        let token = sign(&grant, &f.issuer);
        let proof = f.proof(&token, CHALLENGE);
        assert!(f
            .receiver
            .authorize(&token, &proof, CHALLENGE, 1000, f.start)
            .is_ok());
    }
    let token = sign(&f.grant(), &f.issuer);
    let proof = f.proof(&token, CHALLENGE);
    assert!(f
        .receiver
        .authorize(&token, &proof, CHALLENGE, 1000, f.start)
        .is_err());
}
