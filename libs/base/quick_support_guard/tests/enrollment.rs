#[path = "../../../../src/quick_support_workstation.rs"]
mod desktop;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use desktop::{EnrolledWorkstation, EnrollmentReceipt};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use quick_support_guard::{proof_message, Denied, WorkstationKey};
use sha2::{Digest, Sha256};

fn key() -> WorkstationKey {
    let path = std::env::temp_dir().join(format!(
        "qs-enrollment-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).unwrap();
    std::io::Write::write_all(&mut file, &[9; 32]).unwrap();
    drop(file);
    let loaded = WorkstationKey::load(&path);
    std::fs::remove_file(path).unwrap();
    loaded.unwrap()
}

const TECHNICIAN: &str = "33333333-3333-4333-8333-333333333333";
const OTHER_TECHNICIAN: &str = "44444444-4444-4444-8444-444444444444";
const REQUEST: &str = "11111111-1111-4111-8111-111111111111";

#[test]
fn enrolled_key_signs_exact_native_receiver_proof() {
    let workstation = EnrolledWorkstation::enroll(key(), TECHNICIAN, REQUEST, |request, public| {
        assert_eq!(request, REQUEST);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(public).unwrap(),
            SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes()
        );
        Ok(EnrollmentReceipt {
            technician_id: TECHNICIAN.into(),
            fingerprint: format!("{:x}", Sha256::digest(public.as_bytes())),
        })
    })
    .unwrap();
    let login = workstation
        .login("receiver".into(), "grant".into())
        .unwrap();
    let challenge = "x".repeat(32);
    let (grant, proof) = login.authentication("receiver", &challenge).unwrap();
    SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .verify(
            &proof_message(grant, &challenge, "receiver").unwrap(),
            &Signature::from_bytes(&proof),
        )
        .unwrap();
    assert!(login.authentication("other", &challenge).is_err());
}

#[test]
fn enrollment_failure_or_mismatched_receipt_never_produces_login() {
    for outcome in 0..3 {
        assert!(
            EnrolledWorkstation::enroll(key(), TECHNICIAN, REQUEST, |_, public| {
                if outcome == 0 {
                    return Err(Denied);
                }
                Ok(EnrollmentReceipt {
                    technician_id: if outcome == 1 {
                        OTHER_TECHNICIAN
                    } else {
                        TECHNICIAN
                    }
                    .into(),
                    fingerprint: if outcome == 2 {
                        "wrong".into()
                    } else {
                        format!("{:x}", Sha256::digest(public.as_bytes()))
                    },
                })
            })
            .is_err()
        );
    }
    assert!(
        EnrolledWorkstation::enroll(key(), TECHNICIAN, "", |_, _| panic!("no request")).is_err()
    );
}
