use crate::{
    quick_support_enrollment::EnrollmentAttempt,
    quick_support_key_store::{load_existing, ProtectedKeyStore},
    quick_support_workstation::{EnrolledWorkstation, EnrollmentReceipt},
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
/// Borrowed existing Provider session, supplied by the authenticated host. This
/// carries no local eligibility assertion and is never serialized or logged.
pub(crate) struct ProviderSession<'a> {
    pub technician_id: &'a str,
    pub context: &'a str,
    pub bearer: &'a str,
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

    /// Setup coordinator: ordinary enrollment loads an existing protected key.
    /// Hold the store borrow (and therefore its pins) across the HTTP operation.
    /// The host must retain request_id before calling, including on uncertainty.
    pub async fn enroll_existing(
        &self,
        store: &mut impl ProtectedKeyStore,
        request_id: &str,
        session: ProviderSession<'_>,
        current_context: impl FnMut() -> String,
    ) -> Result<EnrolledWorkstation, Denied> {
        let key = load_existing(store).map_err(|_| Denied)?;
        let attempt =
            EnrollmentAttempt::new(request_id, session.technician_id, session.context, &key)?;
        let receipt = self
            .enroll(attempt, session.bearer, current_context)
            .await?;
        EnrolledWorkstation::enroll(key, session.technician_id, request_id, |_, _| Ok(receipt))
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
        struct ExistingKey(Option<quick_support_guard::WorkstationKey>);
        impl ProtectedKeyStore for ExistingKey {
            fn load(&mut self) -> std::io::Result<Option<quick_support_guard::WorkstationKey>> {
                Ok(self.0.take())
            }
            fn create_new(
                &mut self,
                _: &[u8; 32],
            ) -> std::io::Result<quick_support_guard::WorkstationKey> {
                panic!("ordinary enrollment must never initialize a key")
            }
        }
        let mut store = ExistingKey(Some(key));
        let client =
            ProviderEnrollmentHttp::new("https://provider.example.test", WORKFLOW).unwrap();
        let mut future = Box::pin(client.enroll_existing(
            &mut store,
            WORKFLOW,
            ProviderSession {
                technician_id: WORKFLOW,
                context: "old-session",
                bearer: "fixture",
            },
            || "replaced-session".into(),
        ));
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn unavailable_store_stops_before_authentication_or_http() {
        use std::{
            future::Future,
            sync::Arc,
            task::{Context, Poll, Wake, Waker},
        };
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        struct UnavailableStore(bool);
        impl ProtectedKeyStore for UnavailableStore {
            fn load(&mut self) -> std::io::Result<Option<quick_support_guard::WorkstationKey>> {
                if self.0 {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(None)
                }
            }
            fn create_new(
                &mut self,
                _: &[u8; 32],
            ) -> std::io::Result<quick_support_guard::WorkstationKey> {
                panic!("ordinary enrollment must never initialize")
            }
        }
        let client =
            ProviderEnrollmentHttp::new("https://provider.example.test", WORKFLOW).unwrap();
        for denied in [false, true] {
            let mut store = UnavailableStore(denied);
            let mut future = Box::pin(client.enroll_existing(
                &mut store,
                WORKFLOW,
                ProviderSession {
                    technician_id: WORKFLOW,
                    context: "session",
                    bearer: "fixture",
                },
                || panic!("storage failure must precede authentication context access"),
            ));
            let waker = Waker::from(Arc::new(Noop));
            assert!(matches!(
                future.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(_))
            ));
        }
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
