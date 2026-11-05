use quick_support_guard::{Denied, WorkstationKey, WorkstationLogin};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Receipt returned by the authenticated Provider enrollment action. The caller
/// supplies the current technician independently of this response. This receipt
/// is client-local evidence for one setup attempt, not authority: an issuer must
/// read the active registration server-side.
pub(crate) struct EnrollmentReceipt {
    pub technician_id: String,
    pub fingerprint: String,
}

pub(crate) struct EnrolledWorkstation {
    key: WorkstationKey,
}

impl EnrolledWorkstation {
    /// The host must load the existing key from protected storage, or explicitly
    /// create it during enrollment. This path never regenerates a missing key.
    /// `enroll` must use the authenticated Provider session, not a customer link.
    pub fn enroll(
        key: WorkstationKey,
        technician_id: &str,
        request_id: &str,
        enroll: impl FnOnce(&str, &str) -> Result<EnrollmentReceipt, Denied>,
    ) -> Result<Self, Denied> {
        if technician_id.is_empty() || request_id.is_empty() {
            return Err(Denied);
        }
        let technician = Uuid::parse_str(technician_id).map_err(|_| Denied)?;
        let public_key = key.public_key();
        let receipt = enroll(request_id, &public_key)?;
        let fingerprint = format!("{:x}", Sha256::digest(public_key.as_bytes()));
        let receipt_technician = Uuid::parse_str(&receipt.technician_id).map_err(|_| Denied)?;
        if receipt_technician != technician || receipt.fingerprint != fingerprint {
            return Err(Denied);
        }
        Ok(Self { key })
    }

    pub fn login(&self, receiver: String, grant: String) -> Result<WorkstationLogin, Denied> {
        WorkstationLogin::new(receiver, grant, self.key.signer())
    }
}
