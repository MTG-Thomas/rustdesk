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
    technician_id: Option<String>,
    signing_in: bool,
    detail: String,
    fingerprint: Option<String>,
}

impl Setup {
    fn new() -> Self {
        Self {
            host: None,
            technician_id: None,
            signing_in: false,
            detail: UNAVAILABLE.into(),
            fingerprint: None,
        }
    }

    fn with_host(host: ProviderHost) -> Self {
        Self {
            host: Some(Arc::new(Mutex::new(host))),
            technician_id: None,
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
            Some(_) if self.technician_id.is_some() => "signed_in",
            Some(_) => "signed_out",
        }
    }

    fn status_json(&self) -> String {
        let state = self.state();
        let body = json!({
            "state": state,
            "detail": self.detail,
            "technician_id": self.technician_id,
            "fingerprint": self.fingerprint,
        });
        body.to_string()
    }

    fn sign_in(&mut self) -> String {
        if self.signing_in {
            return self.status_json();
        }
        let Some(host) = self.host.clone() else {
            self.detail = UNAVAILABLE.into();
            return self.status_json();
        };
        self.signing_in = true;
        self.technician_id = None;
        self.fingerprint = None;
        self.detail = "waiting for browser sign-in".into();
        let status = self.status_json();
        // Never hold the setup lock while the blocking browser flow runs.
        std::thread::spawn(move || {
            let (result, technician) = match host.lock() {
                Ok(mut host) => {
                    let result = host.login(open_system_browser);
                    let technician = host.technician_id().map(str::to_owned);
                    (result, technician)
                }
                Err(_) => (Err(Denied), None),
            };
            if let Ok(mut setup) = service().lock() {
                // Ignore a completion from a host that has since been replaced.
                if !setup
                    .host
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &host))
                {
                    return;
                }
                setup.signing_in = false;
                if setup.host.is_none() {
                    setup.detail = "signed out".into();
                } else if result.is_ok() && technician.is_some() {
                    setup.technician_id = technician;
                    setup.detail = "signed in".into();
                } else {
                    setup.technician_id = None;
                    setup.fingerprint = None;
                    setup.detail = "sign-in failed or was cancelled".into();
                }
            }
        });
        status
    }

    fn sign_out(&mut self) -> String {
        if self.signing_in {
            // The worker holds the host lock; drop our reference instead of waiting.
            self.host = None;
        } else if let Some(host) = self.host.as_ref() {
            if let Ok(mut host) = host.lock() {
                host.logout();
            }
        }
        self.technician_id = None;
        self.detail = if self.host.is_some() {
            "signed out".into()
        } else {
            UNAVAILABLE.into()
        };
        self.fingerprint = None;
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
    fn repeated_sign_in_while_running_does_not_admit_another_worker() {
        let mut setup = Setup::with_host(host());
        setup.signing_in = true;
        let status = setup.sign_in();
        assert_eq!(state(&status).0, "signing_in");
        assert_eq!(state(&status).1, "signed out");
    }

    #[test]
    fn in_flight_sign_in_is_reported_and_logout_clears_it() {
        let mut setup = Setup::with_host(host());
        setup.signing_in = true;
        let value: Value = serde_json::from_str(&setup.status_json()).unwrap();
        assert_eq!(value["state"], "signing_in");
        assert!(value["technician_id"].is_null());
        setup.technician_id = Some("33333333-3333-4333-8333-333333333333".into());
        setup.signing_in = false;
        assert_eq!(state(&setup.status_json()).0, "signed_in");
        let value: Value = serde_json::from_str(&setup.sign_out()).unwrap();
        assert_eq!(value["state"], "signed_out");
        assert!(value["technician_id"].is_null());
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
