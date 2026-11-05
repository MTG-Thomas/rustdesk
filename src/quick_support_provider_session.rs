//! Native Provider sign-in and enrollment host. Source-only: no startup route,
//! UI, persisted token or live credential is installed by this module.

use crate::{
    quick_support_key_store::ProtectedKeyStore,
    quick_support_provider_http::{ProviderEnrollmentHttp, ProviderSession},
    quick_support_workstation::EnrolledWorkstation,
};
use quick_support_guard::Denied;
use reqwest::{
    blocking::Client,
    header::{HeaderValue, AUTHORIZATION},
    redirect::Policy,
    Url,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    time::{Duration, Instant},
};
use uuid::Uuid;

const CALLBACK_PATH: &str = "/callback";
const START_TIMEOUT: u64 = 300;
const SSO_PROVIDER: &str = "microsoft";
const SSO_HOST: &str = "login.microsoftonline.com";
const REQUEST_LIMIT: usize = 8192;

/// Release-pinned Provider coordinates. Never invitation, URL or user-setting input.
pub(crate) struct ProviderConfig {
    origin: Url,
    workflow_id: String,
    sso_provider: String,
    sso_hosts: Vec<String>,
}

impl ProviderConfig {
    /// Microsoft Entra ID is the default; other Bifrost SSO providers must pin
    /// their own authorization hosts in signed configuration.
    pub fn new(origin: &str, workflow_id: &str) -> Result<Self, Denied> {
        Self::with_sso(origin, workflow_id, SSO_PROVIDER, &[SSO_HOST])
    }

    pub fn with_sso(
        origin: &str,
        workflow_id: &str,
        provider: &str,
        hosts: &[&str],
    ) -> Result<Self, Denied> {
        let origin = Url::parse(origin).map_err(|_| Denied)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || Uuid::parse_str(workflow_id).is_err()
            || provider.is_empty()
            || provider.len() > 32
            || !provider
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || hosts.is_empty()
            || hosts.iter().any(|host| !qualified_host(host))
        {
            return Err(Denied);
        }
        Ok(Self {
            origin,
            workflow_id: workflow_id.into(),
            sso_provider: provider.into(),
            sso_hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        })
    }

    fn enrollment(&self) -> Result<ProviderEnrollmentHttp, Denied> {
        ProviderEnrollmentHttp::new(self.origin.as_str(), &self.workflow_id)
    }
}

/// One in-memory Provider login. The bearer never leaves this value except into a
/// sensitive request header, and the context changes on every login.
pub(crate) struct ProviderLogin {
    technician_id: String,
    context: String,
    bearer: String,
}

impl ProviderLogin {
    fn session(&self) -> ProviderSession<'_> {
        ProviderSession {
            technician_id: &self.technician_id,
            context: &self.context,
            bearer: &self.bearer,
        }
    }
}

impl std::fmt::Debug for ProviderLogin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderLogin")
            .field("technician_id", &self.technician_id)
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

/// Host boundary for one authenticated technician. The UI host must drop the
/// login on logout/context change and discard any pending enrollment attempt;
/// this type never persists the bearer.
pub(crate) struct ProviderHost {
    config: ProviderConfig,
    login: Option<ProviderLogin>,
}

impl ProviderHost {
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            login: None,
        }
    }

    pub fn logout(&mut self) {
        self.login = None;
    }

    pub fn technician_id(&self) -> Option<&str> {
        self.login
            .as_ref()
            .map(|login| login.technician_id.as_str())
    }

    /// Runs the loopback PKCE flow in the system browser, then verifies the
    /// bearer against `/auth/me`. Blocking: the UI host must call it on a worker
    /// thread, never the UI or async runtime thread. No token is written to disk.
    pub fn login(
        &mut self,
        open_browser: impl FnOnce(&Url) -> Result<(), Denied>,
    ) -> Result<(), Denied> {
        let login = oauth_login(&self.config, open_browser);
        self.replace_login(login)
    }

    fn replace_login(&mut self, login: Result<ProviderLogin, Denied>) -> Result<(), Denied> {
        // A failed replacement must not leave the previous technician signed in.
        self.login = None;
        self.login = Some(login?);
        Ok(())
    }

    /// Ordinary enrollment uses the current login only. The caller retains the
    /// request id before this call and reconciles an uncertain result.
    pub async fn enroll_existing(
        &self,
        store: &mut impl ProtectedKeyStore,
        request_id: &str,
    ) -> Result<EnrolledWorkstation, Denied> {
        let login = self.login.as_ref().ok_or(Denied)?;
        let context = login.context.clone();
        self.config
            .enrollment()?
            .enroll_existing(store, request_id, login.session(), || context.clone())
            .await
    }
}

fn oauth_login(
    config: &ProviderConfig,
    open_browser: impl FnOnce(&Url) -> Result<(), Denied>,
) -> Result<ProviderLogin, Denied> {
    let origin = &config.origin;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| Denied)?;
    let port = listener.local_addr().map_err(|_| Denied)?.port();
    // Microsoft treats loopback redirects as localhost regardless of port.
    let redirect_uri = format!("http://localhost:{port}{CALLBACK_PATH}");
    let client = client()?;

    let mut init = origin
        .join(&format!("/auth/oauth/init/{}", config.sso_provider))
        .map_err(|_| Denied)?;
    init.query_pairs_mut()
        .append_pair("redirect_uri", &redirect_uri);
    let start: Value = client
        .get(init)
        .send()
        .map_err(|_| Denied)?
        .error_for_status()
        .map_err(|_| Denied)?
        .json()
        .map_err(|_| Denied)?;
    let (authorization, state) = authorization_url(origin, &start, &config.sso_hosts)?;
    open_browser(&authorization)?;
    let deadline = Instant::now() + Duration::from_secs(START_TIMEOUT);
    let code = callback(listener, &state, deadline)?;

    let token: Value = client
        .post(origin.join("/auth/oauth/callback").map_err(|_| Denied)?)
        .json(&json!({
            "provider": config.sso_provider,
            "code": code,
            "state": state,
        }))
        .send()
        .map_err(|_| Denied)?
        .error_for_status()
        .map_err(|_| Denied)?
        .json()
        .map_err(|_| Denied)?;
    let bearer = required_text(&token, "access_token", 4096)?;
    let mut authorization =
        HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| Denied)?;
    authorization.set_sensitive(true);
    let me: Value = client
        .get(origin.join("/auth/me").map_err(|_| Denied)?)
        .header(AUTHORIZATION, authorization)
        .send()
        .map_err(|_| Denied)?
        .error_for_status()
        .map_err(|_| Denied)?
        .json()
        .map_err(|_| Denied)?;
    let technician_id = required_text(&me, "id", 36)?;
    Uuid::parse_str(&technician_id).map_err(|_| Denied)?;
    Ok(ProviderLogin {
        technician_id,
        context: Uuid::new_v4().to_string(),
        bearer,
    })
}

fn callback(listener: TcpListener, state: &str, deadline: Instant) -> Result<String, Denied> {
    listener.set_nonblocking(true).map_err(|_| Denied)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return respond(stream, state, deadline),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Denied);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return Err(Denied),
        }
    }
}

fn respond(mut stream: TcpStream, state: &str, deadline: Instant) -> Result<String, Denied> {
    let mut request = Vec::with_capacity(1024);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Denied);
        }
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_secs(5))))
            .map_err(|_| Denied)?;
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).map_err(|_| Denied)?;
        if read == 0 {
            return Err(Denied);
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > REQUEST_LIMIT {
            return Err(Denied);
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = std::str::from_utf8(&request).map_err(|_| Denied)?;
    let line = request.lines().next().ok_or(Denied)?;
    let mut parts = line.split_whitespace();
    if parts.next() != Some("GET") {
        return Err(Denied);
    }
    let target = parts.next().ok_or(Denied)?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(Denied);
    }
    let code = parse_callback(target, state)?;
    let body = b"Quick Support sign-in received. You can close this window.";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).map_err(|_| Denied)?;
    stream.write_all(body).map_err(|_| Denied)?;
    stream.flush().map_err(|_| Denied)?;
    Ok(code)
}

fn parse_callback(target: &str, expected_state: &str) -> Result<String, Denied> {
    if target.len() > 2048 {
        return Err(Denied);
    }
    let url = Url::parse(&format!("http://127.0.0.1{target}")).map_err(|_| Denied)?;
    if url.path() != CALLBACK_PATH {
        return Err(Denied);
    }
    let mut code = None;
    let mut state = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "code" => {
                if code.is_some() || value.is_empty() || value.len() > 4096 {
                    return Err(Denied);
                }
                code = Some(value.into_owned());
            }
            "state" => {
                if state.is_some() || value.is_empty() || value.len() > 512 {
                    return Err(Denied);
                }
                state = Some(value.into_owned());
            }
            // Microsoft returns this opaque session value; it is not authority here.
            "session_state" => {
                if value.len() > 512 {
                    return Err(Denied);
                }
            }
            "error" | "error_description" => return Err(Denied),
            _ => {
                // Providers may echo extra response parameters; they are bounded
                // and carry no authority beyond the validated code/state.
                if value.len() > 512 {
                    return Err(Denied);
                }
            }
        }
    }
    if state.as_deref() != Some(expected_state) {
        return Err(Denied);
    }
    code.ok_or(Denied)
}

fn authorization_url(
    origin: &Url,
    start: &Value,
    allowed_hosts: &[String],
) -> Result<(Url, String), Denied> {
    let raw = required_text(start, "authorization_url", 4096)?;
    let url = Url::parse(&raw)
        .or_else(|_| origin.join(&raw))
        .map_err(|_| Denied)?;
    let host = url.host_str().ok_or(Denied)?;
    if url.scheme() != "https"
        || !allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Denied);
    }
    let state = required_text(start, "state", 512)?;
    Ok((url, state))
}

fn qualified_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

fn required_text(value: &Value, name: &str, maximum: usize) -> Result<String, Denied> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= maximum)
        .map(str::to_owned)
        .ok_or(Denied)
}

fn client() -> Result<Client, Denied> {
    Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|_| Denied)
}

/// System-browser handoff for the UI host; the URL is always the pinned origin.
pub(crate) fn open_system_browser(url: &Url) -> Result<(), Denied> {
    if url.scheme() != "https" {
        return Err(Denied);
    }
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("rundll32");
        command.args(["url.dll,FileProtocolHandler", url.as_str()]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url.as_str());
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url.as_str());
        command
    };
    command.spawn().map(|_| ()).map_err(|_| Denied)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKFLOW: &str = "ed5ebe1c-9326-5863-bccc-c79f3d9f7c38";

    fn config() -> ProviderConfig {
        ProviderConfig::new("https://provider.example.test", WORKFLOW).unwrap()
    }

    #[test]
    fn config_refuses_untrusted_origin_workflow_and_sso_inputs() {
        for origin in [
            "http://provider.example.test",
            "https://user:pass@provider.example.test/",
            "https://provider.example.test/path",
            "https://provider.example.test?query",
            "https://provider.example.test#fragment",
        ] {
            assert!(ProviderConfig::new(origin, WORKFLOW).is_err(), "{origin}");
        }
        assert!(ProviderConfig::new("https://provider.example.test", "workflow").is_err());
        for (provider, hosts) in [
            ("", vec!["login.microsoftonline.com"]),
            ("Microsoft", vec!["login.microsoftonline.com"]),
            ("microsoft", vec![]),
            ("microsoft", vec!["/evil"]),
            ("microsoft", vec!["evil.example/path"]),
            ("microsoft", vec![""]),
        ] {
            assert!(
                ProviderConfig::with_sso(
                    "https://provider.example.test",
                    WORKFLOW,
                    provider,
                    &hosts
                )
                .is_err(),
                "{provider} {hosts:?}"
            );
        }
        assert!(ProviderConfig::with_sso(
            "https://provider.example.test",
            WORKFLOW,
            "google",
            &["accounts.google.com"]
        )
        .is_ok());
    }

    #[test]
    fn callback_requires_the_exact_state_path_and_microsoft_parameters() {
        let ok = "/callback?code=abc&state=expected&session_state=session";
        assert_eq!(parse_callback(ok, "expected").unwrap(), "abc");
        assert_eq!(
            parse_callback(
                "/callback?code=abc&state=expected&scope=openid&authuser=0",
                "expected"
            )
            .unwrap(),
            "abc"
        );
        for target in [
            "/other?code=abc&state=expected",
            "/callback?code=abc&state=wrong",
            "/callback?code=abc",
            "/callback?state=expected",
            "/callback?code=&state=expected",
            "/callback?code=abc&code=def&state=expected",
            "/callback?code=abc&state=expected&error=access_denied",
            "/callback?code=abc&state=expected&error_description=denied",
            "https://evil.example/callback?code=abc&state=expected",
        ] {
            assert!(parse_callback(target, "expected").is_err(), "{target}");
        }
    }

    #[test]
    fn authorization_url_must_be_the_pinned_identity_provider() {
        let origin = config().origin;
        let start = json!({
            "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x",
            "state": "expected",
        });
        let microsoft = vec!["login.microsoftonline.com".into()];
        let (url, state) = authorization_url(&origin, &start, &microsoft).unwrap();
        assert_eq!(state, "expected");
        assert_eq!(url.host_str(), Some("login.microsoftonline.com"));
        let google = vec!["accounts.google.com".into()];
        let google_start = json!({
            "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=x",
            "state": "expected",
        });
        assert!(authorization_url(&origin, &google_start, &google).is_ok());
        assert!(authorization_url(&origin, &google_start, &microsoft).is_err());
        for value in [
            json!({"authorization_url": "https://evil.example/auth", "state": "s"}),
            json!({"authorization_url": "http://login.microsoftonline.com/auth", "state": "s"}),
            json!({"authorization_url": "https://user:pass@login.microsoftonline.com/auth", "state": "s"}),
            json!({"authorization_url": "/auth/oauth/authorize", "state": "s"}),
            json!({"authorization_url": "https://login.microsoftonline.com/auth"}),
            json!({"authorization_url": "", "state": "s"}),
        ] {
            assert!(
                authorization_url(&origin, &value, &microsoft).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn failed_replacement_login_clears_the_previous_technician() {
        let mut host = ProviderHost::new(config());
        host.login = Some(ProviderLogin {
            technician_id: "33333333-3333-4333-8333-333333333333".into(),
            context: "context".into(),
            bearer: "secret-bearer".into(),
        });
        assert!(host.replace_login(Err(Denied)).is_err());
        assert!(host.technician_id().is_none());
    }

    #[test]
    fn callback_rejects_an_oversized_or_slow_request_before_the_deadline_expires() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let chunk = [b'A'; 1024];
            while stream.write_all(&chunk).is_ok() {}
        });
        assert!(callback(listener, "state", Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    fn callback_total_deadline_bounds_a_dripping_sender() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            while stream.write_all(b"A").is_ok() {
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        assert!(callback(
            listener,
            "state",
            Instant::now() + Duration::from_millis(300)
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn login_state_redacts_the_bearer_and_logout_clears_it() {
        let mut host = ProviderHost::new(config());
        assert!(host.technician_id().is_none());
        host.login = Some(ProviderLogin {
            technician_id: "33333333-3333-4333-8333-333333333333".into(),
            context: "context".into(),
            bearer: "secret-bearer".into(),
        });
        assert_eq!(
            host.technician_id(),
            Some("33333333-3333-4333-8333-333333333333")
        );
        assert!(!format!("{:?}", host.login.as_ref().unwrap()).contains("secret-bearer"));
        host.logout();
        assert!(host.technician_id().is_none());
    }

    #[test]
    fn token_and_user_records_require_bounded_non_empty_text() {
        assert_eq!(
            required_text(&json!({"access_token": "token"}), "access_token", 4096).unwrap(),
            "token"
        );
        for value in [
            json!({}),
            json!({"access_token": ""}),
            json!({"access_token": 7}),
            json!({"access_token": "x".repeat(4097)}),
            json!({"technician_id": "not-a-uuid"}),
        ] {
            assert!(required_text(&value, "access_token", 4096).is_err());
        }
        assert!(required_text(&json!({"id": "x".repeat(37)}), "id", 36).is_err());
    }
}
