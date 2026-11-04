use crate::{
    quick_support_enrollment::EnrollmentAttempt, quick_support_workstation::EnrollmentReceipt,
};
use quick_support_guard::Denied;
use reqwest::{
    header::{HeaderValue, AUTHORIZATION},
    redirect::Policy,
    Client, Url,
};
use std::time::Duration;

/// Configured only from the trusted Provider installation, never invitation input.
/// This client is source-only until the authenticated Provider host is wired.
pub(crate) struct ProviderEnrollmentHttp {
    client: Client,
    endpoint: Url,
    workflow_id: String,
}
impl ProviderEnrollmentHttp {
    pub fn new(origin: &str, workflow_id: &str) -> Result<Self, Denied> {
        let origin = Url::parse(origin).map_err(|_| Denied)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || uuid::Uuid::parse_str(workflow_id).is_err()
        {
            return Err(Denied);
        }
        let client = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(25))
            .build()
            .map_err(|_| Denied)?;
        Ok(Self {
            client,
            endpoint: origin.join("/api/workflows/execute").map_err(|_| Denied)?,
            workflow_id: workflow_id.into(),
        })
    }

    /// One POST, no application retry. The host supplies an existing Provider
    /// bearer and reads its live session/org context again after the response.
    /// HTTP success never proves technician eligibility or customer consent.
    pub async fn enroll(
        &self,
        attempt: EnrollmentAttempt,
        provider_bearer: &str,
        mut current_context: impl FnMut() -> String,
    ) -> Result<EnrollmentReceipt, Denied> {
        let authorization = authorization(provider_bearer)?;
        let request = attempt.request(&self.workflow_id)?;
        let request_id = request["input_data"]["request_id"]
            .as_str()
            .ok_or(Denied)?
            .to_owned();
        attempt.check_context(&request_id, &current_context())?;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header(AUTHORIZATION, authorization)
            .json(&request)
            .send()
            .await
            .map_err(|_| Denied)?;
        if response.status().as_u16() != 200
            || response
                .content_length()
                .is_some_and(|length| length > 8192)
        {
            return Err(Denied);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Denied)? {
            if chunk.len() > 8192 - body.len() {
                return Err(Denied);
            }
            body.extend_from_slice(&chunk);
        }
        attempt.complete_http(
            &self.workflow_id,
            &request_id,
            &current_context(),
            200,
            &body,
        )
    }
}

fn authorization(provider_bearer: &str) -> Result<HeaderValue, Denied> {
    if provider_bearer.is_empty() {
        return Err(Denied);
    }
    let mut value =
        HeaderValue::from_str(&format!("Bearer {provider_bearer}")).map_err(|_| Denied)?;
    value.set_sensitive(true);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    const WORKFLOW: &str = "ed5ebe1c-9326-5863-bccc-c79f3d9f7c38";

    #[test]
    fn origin_configuration_refuses_redirectable_or_credential_bearing_inputs() {
        for origin in [
            "http://provider.example.test",
            "https://user@provider.example.test",
            "https://provider.example.test/path",
            "https://provider.example.test/?query=1",
            "https://provider.example.test/#fragment",
        ] {
            assert!(ProviderEnrollmentHttp::new(origin, WORKFLOW).is_err());
        }
        let client =
            ProviderEnrollmentHttp::new("https://provider.example.test", WORKFLOW).unwrap();
        assert_eq!(
            client.endpoint.as_str(),
            "https://provider.example.test/api/workflows/execute"
        );
        assert_eq!(client.workflow_id, WORKFLOW);
        let _ = client.client.clone();
    }

    #[test]
    fn stale_session_refuses_before_the_future_can_send_http() {
        use std::{
            future::Future,
            sync::Arc,
            task::{Context, Poll, Wake, Waker},
        };
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        let path = std::env::temp_dir().join(format!("qs-http-preflight-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, &[9; 32]).unwrap();
        drop(file);
        let loaded = quick_support_guard::WorkstationKey::load(&path);
        std::fs::remove_file(path).unwrap();
        let key = loaded.unwrap();
        let attempt = EnrollmentAttempt::new(WORKFLOW, WORKFLOW, "old-session", &key).unwrap();
        let client =
            ProviderEnrollmentHttp::new("https://provider.example.test", WORKFLOW).unwrap();
        let mut future = Box::pin(client.enroll(attempt, "fixture", || "replaced-session".into()));
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn bearer_is_sensitive_and_header_injection_is_refused() {
        let value = authorization("fixture").unwrap();
        assert!(value.is_sensitive());
        assert_eq!(value.to_str().unwrap(), "Bearer fixture");
        assert!(authorization("").is_err());
        assert!(authorization("fixture\r\nInjected: value").is_err());
    }
}
