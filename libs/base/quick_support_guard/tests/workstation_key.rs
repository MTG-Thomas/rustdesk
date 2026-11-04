use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use quick_support_guard::{proof_message, WorkstationKey};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "qs-workstation-key-{}-{}-{nanos}",
            process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn generated_public_key_is_base64url_and_verifies_a_proof() {
    let key = WorkstationKey::generate().unwrap();
    let public = key.public_key();
    assert_eq!(public.len(), 43);
    assert!(public
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));

    let encoded = URL_SAFE_NO_PAD.decode(&public).unwrap();
    let verifying = VerifyingKey::from_bytes(&encoded.try_into().unwrap()).unwrap();
    let message = proof_message("synthetic-grant", &"c".repeat(32), "receiver").unwrap();
    let signature = Signature::from_bytes(&key.signer()(&message).unwrap());
    verifying.verify_strict(&message, &signature).unwrap();
    assert!(verifying
        .verify_strict(b"other message", &signature)
        .is_err());
}

#[test]
fn save_and_load_round_trip_preserves_identity() {
    let dir = TempDir::new();
    let path = dir.path().join("workstation.key");
    let key = WorkstationKey::generate().unwrap();
    key.save(&path).unwrap();

    let loaded = WorkstationKey::load(&path).unwrap();
    assert_eq!(key.public_key(), loaded.public_key());
    let message = proof_message("synthetic-grant", &"c".repeat(32), "receiver").unwrap();
    assert_eq!(
        key.signer()(&message).unwrap(),
        loaded.signer()(&message).unwrap()
    );
}

#[test]
fn save_refuses_to_replace_an_existing_key() {
    let dir = TempDir::new();
    let path = dir.path().join("workstation.key");
    let first = WorkstationKey::generate().unwrap();
    first.save(&path).unwrap();

    let second = WorkstationKey::generate().unwrap();
    assert_eq!(
        second.save(&path).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        WorkstationKey::load(&path).unwrap().public_key(),
        first.public_key()
    );
}

#[test]
fn load_rejects_missing_truncated_oversized_and_non_files() {
    let dir = TempDir::new();
    assert!(WorkstationKey::load(&dir.path().join("absent")).is_err());
    assert!(WorkstationKey::load(dir.path()).is_err());

    let seed = [7u8; 32];
    let valid = dir.path().join("valid");
    fs::write(&valid, seed).unwrap();
    assert!(WorkstationKey::load(&valid).is_ok());

    let mut oversized = seed.to_vec();
    oversized.push(0);
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("short", seed[..31].to_vec()),
        ("oversized", oversized),
    ] {
        let path = dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        assert!(
            WorkstationKey::load(&path).is_err(),
            "{name} must be rejected"
        );
    }
}

#[cfg(unix)]
#[test]
fn saved_seed_is_owner_only_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new();
    let path = dir.path().join("workstation.key");
    WorkstationKey::generate().unwrap().save(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
