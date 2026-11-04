use crate::quick_support_workstation::EnrollmentReceipt;
use quick_support_guard::{Denied, WorkstationKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Immutable context retained by one authenticated Provider HTTP invocation.
/// This is not a credential or authority; the host owns authentication and must
/// discard pending attempts when its authenticated session changes.
pub(crate) struct EnrollmentAttempt {
    request_id: String,
    technician_id: String,
    authentication_context: String,
    public_key: String,
}

impl EnrollmentAttempt {
    pub fn new(
        request_id: &str,
        technician_id: &str,
        authentication_context: &str,
        key: &WorkstationKey,
    ) -> Result<Self, Denied> {
        if uuid::Uuid::parse_str(request_id).is_err()
            || uuid::Uuid::parse_str(technician_id).is_err()
            || authentication_context.is_empty()
        {
            return Err(Denied);
        }
        Ok(Self {
            request_id: request_id.into(),
            technician_id: technician_id.into(),
            authentication_context: authentication_context.into(),
            public_key: key.public_key(),
        })
    }

    /// Body for POST /api/workflows/execute. Workflow/org IDs are pinned by the
    /// installed Provider configuration, never discovered from a customer URL.
    pub fn request(&self, workflow_id: &str, organization_id: &str) -> Result<Value, Denied> {
        if uuid::Uuid::parse_str(workflow_id).is_err()
            || uuid::Uuid::parse_str(organization_id).is_err()
        {
            return Err(Denied);
        }
        Ok(json!({
            "workflow_id": workflow_id,
            "org_id": organization_id,
            "sync": true,
            "input_data": {
                "request_id": self.request_id,
                "workstation_key": self.public_key,
            },
        }))
    }

    /// Consume only a terminal workflow's inner result, after the HTTP host has
    /// authenticated the response and matched its own request/session context.
    /// The deployed outer execution envelope is deliberately not guessed here.
    pub fn complete(
        self,
        answered_request_id: &str,
        current_authentication_context: &str,
        result: &Value,
    ) -> Result<EnrollmentReceipt, Denied> {
        if answered_request_id != self.request_id
            || current_authentication_context != self.authentication_context
        {
            return Err(Denied);
        }
        let object = result.as_object().ok_or(Denied)?;
        if object.len() != 3
            || object.get("technician_id").and_then(Value::as_str)
                != Some(self.technician_id.as_str())
            || object.get("fingerprint").and_then(Value::as_str)
                != Some(format!("{:x}", Sha256::digest(self.public_key.as_bytes())).as_str())
            || object
                .get("enrolled_at")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .is_none()
        {
            return Err(Denied);
        }
        Ok(EnrollmentReceipt {
            technician_id: self.technician_id,
            fingerprint: format!("{:x}", Sha256::digest(self.public_key.as_bytes())),
        })
    }
}
