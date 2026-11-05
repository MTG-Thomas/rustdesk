#[path = "../../../../src/quick_support_enrollment.rs"]
mod enrollment;
#[path = "../../../../src/quick_support_workstation.rs"]
mod quick_support_workstation;

use enrollment::EnrollmentAttempt;
use quick_support_guard::WorkstationKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REQUEST: &str = "11111111-1111-4111-8111-111111111111";
const TECHNICIAN: &str = "22222222-2222-4222-8222-222222222222";
const WORKFLOW: &str = "ed5ebe1c-9326-5863-bccc-c79f3d9f7c38";
const ORG: &str = "33333333-3333-4333-8333-333333333333";

fn attempt() -> (EnrollmentAttempt, Value, WorkstationKey) {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "qs-http-fixture-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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
    let key = loaded.unwrap();
    let result = json!({
        "technician_id": TECHNICIAN,
        "fingerprint": format!("{:x}", Sha256::digest(key.public_key().as_bytes())),
        "enrolled_at": "2026-11-04T00:00:00Z",
    });
    (
        EnrollmentAttempt::new(REQUEST, TECHNICIAN, "synthetic-auth-session", &key).unwrap(),
        result,
        key,
    )
}

#[test]
fn equivalent_technician_identifier_spellings_bind_the_same_receipt() {
    let (_, result, key) = attempt();
    let receipt = quick_support_workstation::EnrollmentReceipt {
        technician_id: TECHNICIAN.into(),
        fingerprint: result["fingerprint"].as_str().unwrap().into(),
    };
    let enrolled = quick_support_workstation::EnrolledWorkstation::enroll(
        key,
        &format!("{{{TECHNICIAN}}}"),
        REQUEST,
        |request, _| {
            assert_eq!(request, REQUEST);
            Ok(receipt)
        },
    )
    .unwrap();
    let login = enrolled
        .login("receiver".into(), "synthetic-grant".into())
        .unwrap();
    assert!(login.authentication("receiver", &"x".repeat(32)).is_ok());
}

#[test]
fn provider_request_retains_id_and_public_key_without_auth_or_private_material() {
    let (attempt, result, key) = attempt();
    let request = attempt.request(WORKFLOW).unwrap();
    assert_eq!(request["workflow_id"], WORKFLOW);
    assert!(request.get("org_id").is_none());
    assert!(request.get("run_as").is_none());
    assert_eq!(request["sync"], true);
    assert_eq!(request["input_data"]["request_id"], REQUEST);
    let public = request["input_data"]["workstation_key"].as_str().unwrap();
    assert_eq!(public.len(), 43);
    assert_eq!(request["input_data"].as_object().unwrap().len(), 2);
    assert!(!request.to_string().contains("synthetic-auth-session"));
    let receipt = attempt
        .complete(REQUEST, "synthetic-auth-session", &result)
        .unwrap();
    assert_eq!(receipt.technician_id, TECHNICIAN);
    assert_eq!(receipt.fingerprint, result["fingerprint"]);
    let enrolled = quick_support_workstation::EnrolledWorkstation::enroll(
        key,
        TECHNICIAN,
        REQUEST,
        |request, _| {
            assert_eq!(request, REQUEST);
            Ok(receipt)
        },
    )
    .unwrap();
    let login = enrolled
        .login("receiver".into(), "synthetic-grant".into())
        .unwrap();
    assert!(login.authentication("receiver", &"x".repeat(32)).is_ok());
}

#[test]
fn response_cannot_cross_pending_request_or_authenticated_session() {
    for (request, auth) in [
        (ORG, "synthetic-auth-session"),
        (REQUEST, "replaced-session"),
    ] {
        let (attempt, result, _) = attempt();
        assert!(attempt.complete(request, auth, &result).is_err());
    }
}

#[test]
fn malformed_or_unqualified_results_are_not_enrollment_receipts() {
    for value in [
        json!({"execution_id": REQUEST, "status": "running"}),
        json!({"technician_id": ORG, "fingerprint": "bad", "enrolled_at": "now"}),
        json!({"status": "failed"}),
        Value::Null,
    ] {
        let (attempt, _, _) = attempt();
        assert!(attempt
            .complete(REQUEST, "synthetic-auth-session", &value)
            .is_err());
    }
    let (attempt, _, _) = attempt();
    assert!(attempt.request("untrusted-workflow-name").is_err());
}

#[path = "../../../../src/quick_support_key_store.rs"]
mod key_store;

struct Store {
    present: bool,
    denied: bool,
    fail_create: bool,
    writes: usize,
}
impl key_store::ProtectedKeyStore for Store {
    fn load(&mut self) -> std::io::Result<Option<WorkstationKey>> {
        if self.denied {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(self.present.then(|| attempt().2))
    }
    fn create_new(&mut self, seed: &[u8; 32]) -> std::io::Result<WorkstationKey> {
        self.writes += 1;
        if self.present || self.fail_create {
            return Err(std::io::ErrorKind::AlreadyExists.into());
        }
        assert_eq!(seed, &[9; 32]);
        self.present = true;
        Ok(attempt().2)
    }
}

#[test]
fn key_startup_and_denied_storage_never_initialize_replacement_identity() {
    let mut store = Store {
        present: false,
        denied: false,
        fail_create: false,
        writes: 0,
    };
    assert!(key_store::load_existing(&mut store).is_err());
    assert_eq!(store.writes, 0);
    store.denied = true;
    assert!(key_store::initialize_explicitly(&mut store, || panic!(
        "denied storage must not generate"
    ))
    .is_err());
    store.denied = false;
    store.present = true;
    let key = key_store::initialize_explicitly(&mut store, || {
        panic!("existing identity must not rotate")
    })
    .unwrap();
    assert_eq!(key.public_key(), attempt().2.public_key());
    assert_eq!(store.writes, 0);
}

#[test]
fn explicit_initialization_requires_persistence_before_enrollment_material_is_returned() {
    let mut store = Store {
        present: false,
        denied: false,
        fail_create: true,
        writes: 0,
    };
    assert!(key_store::initialize_explicitly(&mut store, || Ok([9; 32])).is_err());
    assert_eq!(store.writes, 1);
    store.fail_create = false;
    let key = key_store::initialize_explicitly(&mut store, || Ok([9; 32])).unwrap();
    assert_eq!(
        key_store::load_existing(&mut store).unwrap().public_key(),
        key.public_key()
    );
    assert_eq!(store.writes, 2);
}

#[test]
fn source_http_envelope_requires_success_workflow_and_live_attempt_context() {
    for variant in 0..8 {
        let (attempt, result, _) = attempt();
        let mut response = json!({"execution_id": ORG, "workflow_id": WORKFLOW,
            "status": "Success", "result": result, "error": null, "error_type": null});
        match variant {
            1 => response["status"] = "Running".into(),
            2 => response["status"] = "CompletedWithErrors".into(),
            3 => response["workflow_id"] = ORG.into(),
            4 => response["execution_id"] = "invalid".into(),
            5 => response["error"] = "untrusted failure".into(),
            _ => {}
        }
        let status = if variant == 6 { 302 } else { 200 };
        let context = if variant == 7 {
            "stale-session"
        } else {
            "synthetic-auth-session"
        };
        let result = attempt.complete_http(
            WORKFLOW,
            REQUEST,
            context,
            status,
            &serde_json::to_vec(&response).unwrap(),
        );
        assert_eq!(result.is_ok(), variant == 0);
    }
    for body in [vec![b'x'; 8193], b"not json".to_vec()] {
        let (attempt, _, _) = attempt();
        assert!(attempt
            .complete_http(WORKFLOW, REQUEST, "synthetic-auth-session", 200, &body)
            .is_err());
    }
}
