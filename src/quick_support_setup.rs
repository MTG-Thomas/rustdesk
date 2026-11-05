//! Setup UI contract for Quick Support. This slice is fail-closed: the
//! authenticated setup host exists, but release configuration and the
//! issuer/deployment prerequisites are not installed, so sign-in and enrollment
//! report that state and never claim success.

use crate::quick_support_provider_session::{open_system_browser, ProviderConfig, ProviderHost};
use quick_support_guard::Denied;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};

const UNAVAILABLE: &str = "release configuration and issuer deployment are not installed";

struct Setup {
    host: Option<Arc<Mutex<ProviderHost>>>,
    signing_in: bool,
    detail: String,
    fingerprint: Option<String>,
}

impl Setup {
    fn new() -> Self {
        Self {
            host: None,
            signing_in: false,
            detail: UNAVAILABLE.into(),
            fingerprint: None,
        }
    }

    fn with_host(host: ProviderHost) -> Self {
        Self {
            host: Some(Arc::new(Mutex::new(host))),
            signing_in: false,
            detail: "signed out".into(),
            fingerprint: None,
        }
    }

    fn state(&self) -> &'static str {
        if self.signing_in {
            return "signing_in";
        }
        match &self.host {
            None => "unavailable",
            Some(host) => match host.lock().map(|host| host.technician_id().is_some()) {
                Ok(true) => "signed_in",
                _ => "signed_out",
            },
        }
    }

    fn status_json(&self) -> String {
        let state = self.state();
        let technician = match &self.host {
            Some(host) => host
                .lock()
                .ok()
                .and_then(|host| host.technician_id().map(str::to_owned)),
            None => None,
        };
        let body = json!({
            "state": state,
            "detail": self.detail,
            "technician_id": technician,
            "fingerprint": self.fingerprint,
        });
        body.to_string()
    }

    fn sign_in(&mut self) -> String {
        let Some(host) = self.host.clone() else {
            self.detail = UNAVAILABLE.into();
            return self.status_json();
        };
        if !self.signing_in {
            self.signing_in = true;
            self.detail = "waiting for browser sign-in".into();
        }
        let status = self.status_json();
        // Never hold the setup lock while the blocking browser flow runs.
        std::thread::spawn(move || {
            let result = match host.lock() {
                Ok(mut host) => host.login(open_system_browser),
                Err(_) => Err(Denied),
            };
            if let Ok(mut setup) = service().lock() {
                setup.signing_in = false;
                setup.detail = if setup.host.is_none() {
                    "signed out".into()
                } else if result.is_ok() {
                    "signed in".into()
                } else {
                    "sign-in failed or was cancelled".into()
                };
            }
        });
        status
    }

    fn sign_out(&mut self) -> String {
        if let Some(host) = self.host.as_ref() {
            if let Ok(mut host) = host.lock() {
                host.logout();
            }
            self.detail = "signed out".into();
            self.fingerprint = None;
        }
        self.signing_in = false;
        self.status_json()
    }

    fn enroll(&mut self, request_id: &str) -> String {
        if request_id.is_empty() || self.state() != "signed_in" {
            self.detail = "sign in with an installed release configuration before enrolling".into();
            return self.status_json();
        }
        // No enrollment is attempted in this fail-closed slice.
        self.detail = "enrollment is not wired in this build".into();
        self.status_json()
    }
}

static SETUP: OnceLock<Mutex<Setup>> = OnceLock::new();

fn service() -> &'static Mutex<Setup> {
    SETUP.get_or_init(|| Mutex::new(Setup::new()))
}

pub(crate) fn status() -> String {
    match service().lock() {
        Ok(setup) => setup.status_json(),
        Err(_) => unavailable("setup state is unavailable"),
    }
}

pub(crate) fn sign_in() -> String {
    match service().lock() {
        Ok(mut setup) => setup.sign_in(),
        Err(_) => unavailable("setup state is unavailable"),
    }
}

pub(crate) fn sign_out() -> String {
    match service().lock() {
        Ok(mut setup) => setup.sign_out(),
        Err(_) => unavailable("setup state is unavailable"),
    }
}

pub(crate) fn enroll(request_id: &str) -> String {
    match service().lock() {
        Ok(mut setup) => setup.enroll(request_id),
        Err(_) => unavailable("setup state is unavailable"),
    }
}

/// Only a trusted signed installer may call this; it is not exposed to the UI.
/// Wiring it remains part of the release-configuration/issuer slice.
#[allow(dead_code)]
pub(crate) fn install_trusted_config(origin: &str, workflow_id: &str) -> Result<(), Denied> {
    let config = ProviderConfig::new(origin, workflow_id)?;
    match service().lock() {
        Ok(mut setup) => {
            *setup = Setup::with_host(ProviderHost::new(config));
            Ok(())
        }
        Err(_) => Err(Denied),
    }
}

fn unavailable(detail: &str) -> String {
    json!({
        "state": "unavailable",
        "detail": detail,
        "technician_id": Value::Null,
        "fingerprint": Value::Null,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKFLOW: &str = "ed5ebe1c-9326-5863-bccc-c79f3d9f7c38";

    fn host() -> ProviderHost {
        ProviderHost::new(ProviderConfig::new("https://provider.example.test", WORKFLOW).unwrap())
    }

    fn state(status: &str) -> (String, String) {
        let value: Value = serde_json::from_str(status).unwrap();
        (
            value["state"].as_str().unwrap().into(),
            value["detail"].as_str().unwrap().into(),
        )
    }

    #[test]
    fn fresh_setup_reports_unavailable_without_identity() {
        let value: Value = serde_json::from_str(&Setup::new().status_json()).unwrap();
        assert_eq!(value["state"], "unavailable");
        assert!(value["technician_id"].is_null());
        assert!(value["fingerprint"].is_null());
        assert!(!value.to_string().contains("Bearer"));
    }

    #[test]
    fn installed_configuration_is_signed_out_until_a_login_completes() {
        let setup = Setup::with_host(host());
        assert_eq!(state(&setup.status_json()).0, "signed_out");
        assert_eq!(state(&Setup::new().sign_in()).0, "unavailable");
    }

    #[test]
    fn in_flight_sign_in_is_reported_and_logout_clears_it() {
        let mut setup = Setup::with_host(host());
        setup.signing_in = true;
        let value: Value = serde_json::from_str(&setup.status_json()).unwrap();
        assert_eq!(value["state"], "signing_in");
        assert!(value["technician_id"].is_null());
        let value: Value = serde_json::from_str(&setup.sign_out()).unwrap();
        assert_eq!(value["state"], "signed_out");
    }

    #[test]
    fn enrollment_is_refused_without_a_signed_in_host() {
        let mut setup = Setup::with_host(host());
        let value: Value = serde_json::from_str(&setup.enroll("request")).unwrap();
        assert_eq!(value["state"], "signed_out");
        assert!(value["fingerprint"].is_null());
        assert!(value["detail"].as_str().unwrap().contains("sign in"));
        let mut fresh = Setup::new();
        assert!(fresh.enroll("request").contains("unavailable"));
        assert!(fresh.enroll("").contains("sign in"));
    }

    #[test]
    fn sign_out_is_idempotent_and_clears_fingerprint() {
        let mut setup = Setup::with_host(host());
        setup.fingerprint = Some("fingerprint".into());
        let value: Value = serde_json::from_str(&setup.sign_out()).unwrap();
        assert_eq!(value["state"], "signed_out");
        assert!(value["fingerprint"].is_null());
        assert_eq!(state(&setup.sign_out()).0, "signed_out");
    }

    #[test]
    fn trusted_configuration_rejects_untrusted_input() {
        assert!(install_trusted_config("http://provider.example.test", WORKFLOW).is_err());
        assert!(install_trusted_config("https://provider.example.test", "workflow").is_err());
    }
}
