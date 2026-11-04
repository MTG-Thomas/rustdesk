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

    /// Body for POST /api/workflows/execute. The authenticated Provider session
    /// selects the organization; no admin-only org override or impersonation.
    pub fn request(&self, workflow_id: &str) -> Result<Value, Denied> {
        if uuid::Uuid::parse_str(workflow_id).is_err() {
            return Err(Denied);
        }
        Ok(json!({
            "workflow_id": workflow_id,
            "sync": true,
            "input_data": {
                "request_id": self.request_id,
                "workstation_key": self.public_key,
            },
        }))
    }

    /// Source-qualified synchronous execution envelope. The network host must
    /// separately enforce HTTPS, pinned Provider origin and current auth context.
    pub fn complete_http(
        self,
        workflow_id: &str,
        answered_request_id: &str,
        current_authentication_context: &str,
        status: u16,
        body: &[u8],
    ) -> Result<EnrollmentReceipt, Denied> {
        if status != 200 || body.len() > 8192 {
            return Err(Denied);
        }
        let response: Value = serde_json::from_slice(body).map_err(|_| Denied)?;
        if response.get("workflow_id").and_then(Value::as_str) != Some(workflow_id)
            || uuid::Uuid::parse_str(workflow_id).is_err()
            || response
                .get("execution_id")
                .and_then(Value::as_str)
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                .is_none()
            || response.get("status").and_then(Value::as_str) != Some("Success")
            || response.get("error").is_some_and(|error| !error.is_null())
            || response
                .get("error_type")
                .is_some_and(|error| !error.is_null())
        {
            return Err(Denied);
        }
        self.complete(
            answered_request_id,
            current_authentication_context,
            response.get("result").ok_or(Denied)?,
        )
    }

    pub fn check_context(&self, request_id: &str, context: &str) -> Result<(), Denied> {
        if request_id != self.request_id || context != self.authentication_context {
            return Err(Denied);
        }
        Ok(())
    }

    /// Consume only a terminal workflow's inner result, after the HTTP host has
    /// authenticated the response and matched its own request/session context.
    /// This inner validator does not itself authenticate a network response.
    pub fn complete(
        self,
        answered_request_id: &str,
        current_authentication_context: &str,
        result: &Value,
    ) -> Result<EnrollmentReceipt, Denied> {
        self.check_context(answered_request_id, current_authentication_context)?;
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
