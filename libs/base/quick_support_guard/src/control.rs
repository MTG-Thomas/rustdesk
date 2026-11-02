use super::*;

const CONTROL_TYPE: &str = "rd-qs-control+jwt";
const MAX_CONTROL_BYTES: usize = 16384;

/// Pinned issuer trust and independently authenticated expected launch identity.
/// None of these fields may be derived from the control token being checked.
pub struct ControlIdentity {
    pub issuer: String,
    pub issuer_key: [u8; 32],
    pub organization_id: String,
    pub solution_id: String,
    pub session_id: String,
    pub generation: String,
    pub receiver_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    Bootstrap,
    Renew,
    Revoke,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    iss: String,
    aud: String,
    organization_id: String,
    solution_id: String,
    session_id: String,
    generation: String,
    receiver_id: String,
    action: Action,
    sequence: u64,
    iat: u64,
    exp: u64,
    bootstrap: Option<String>,
    lease: Option<String>,
}

pub struct ControlSession {
    identity: ControlIdentity,
    receiver: Option<Receiver>,
    sequence: u64,
    stopped: bool,
}

fn verify_control(token: &str, issuer_key: &[u8; 32]) -> Result<Control, Denied> {
    if token.len() > MAX_CONTROL_BYTES {
        return Err(Denied);
    }
    let mut parts = token.split('.');
    let header = parts.next().ok_or(Denied)?;
    let claims = parts.next().ok_or(Denied)?;
    let signature = parts.next().ok_or(Denied)?;
    if parts.next().is_some() {
        return Err(Denied);
    }
    let value: Header = serde_json::from_slice(&decode(header, 256)?).map_err(|_| Denied)?;
    if value.alg != "EdDSA" || value.typ != CONTROL_TYPE {
        return Err(Denied);
    }
    let signature = Signature::from_slice(&decode(signature, 86)?).map_err(|_| Denied)?;
    key(issuer_key)?
        .verify_strict(format!("{header}.{claims}").as_bytes(), &signature)
        .map_err(|_| Denied)?;
    serde_json::from_slice(&decode(claims, MAX_CONTROL_BYTES)?).map_err(|_| Denied)
}

impl ControlSession {
    pub fn new(identity: ControlIdentity) -> Result<Self, Denied> {
        if !identity.issuer.starts_with("https://")
            || identity.issuer.len() > 256
            || [
                &identity.organization_id,
                &identity.solution_id,
                &identity.session_id,
                &identity.generation,
            ]
            .iter()
            .any(|id| Uuid::parse_str(id).is_err())
            || identity.receiver_id.is_empty()
            || identity.receiver_id.len() > 64
        {
            return Err(Denied);
        }
        key(&identity.issuer_key)?;
        Ok(Self {
            identity,
            receiver: None,
            sequence: 0,
            stopped: false,
        })
    }

    pub fn apply(&mut self, token: &str, wall: u64, monotonic: Instant) -> Result<(), Denied> {
        if self.stopped {
            return Err(Denied);
        }
        let control = verify_control(token, &self.identity.issuer_key)?;
        if control.iss != self.identity.issuer
            || control.aud != AUDIENCE
            || control.organization_id != self.identity.organization_id
            || control.solution_id != self.identity.solution_id
            || control.session_id != self.identity.session_id
            || control.generation != self.identity.generation
            || control.receiver_id != self.identity.receiver_id
            || self.sequence.checked_add(1) != Some(control.sequence)
        {
            return Err(Denied);
        }
        let now = match self.receiver.as_mut() {
            Some(receiver) => receiver.effective_time(wall, monotonic)?,
            None => wall,
        };
        if control.iat > now
            || control.exp <= now
            || control
                .exp
                .checked_sub(control.iat)
                .filter(|d| *d > 0 && *d <= MAX_LEASE_SECONDS)
                .is_none()
        {
            return Err(Denied);
        }
        match control.action {
            Action::Bootstrap => {
                if self.receiver.is_some() || control.sequence != 1 {
                    return Err(Denied);
                }
                let bootstrap = control.bootstrap.as_deref().ok_or(Denied)?;
                let claims: Bootstrap = verify_token(bootstrap, &self.identity.issuer_key)?;
                if claims.iat != control.iat || control.exp > claims.exp {
                    return Err(Denied);
                }
                let mut receiver = Receiver::from_bound_bootstrap(
                    bootstrap,
                    &self.identity.issuer,
                    &self.identity.issuer_key,
                    BootstrapBinding {
                        session_id: &self.identity.session_id,
                        generation: &self.identity.generation,
                        receiver_id: &self.identity.receiver_id,
                    },
                    now,
                    monotonic,
                )?;
                self.renew(&mut receiver, &control, now, monotonic)?;
                self.receiver = Some(receiver);
            }
            Action::Renew => {
                if control.bootstrap.is_some() {
                    return Err(Denied);
                }
                let mut receiver = self.receiver.take().ok_or(Denied)?;
                let result = if receiver.active(monotonic) {
                    self.renew(&mut receiver, &control, now, monotonic)
                } else {
                    Err(Denied)
                };
                self.receiver = Some(receiver);
                result?;
            }
            Action::Revoke => {
                if control.bootstrap.is_some() || control.lease.is_some() {
                    return Err(Denied);
                }
                let receiver = self.receiver.as_mut().ok_or(Denied)?;
                if control.exp > receiver.hard_expiry {
                    return Err(Denied);
                }
                receiver.revoke();
                self.stopped = true;
            }
        }
        self.sequence = control.sequence;
        Ok(())
    }
    fn renew(
        &self,
        receiver: &mut Receiver,
        control: &Control,
        now: u64,
        monotonic: Instant,
    ) -> Result<(), Denied> {
        let token = control.lease.as_deref().ok_or(Denied)?;
        let lease: Lease = verify_token(token, &self.identity.issuer_key)?;
        if lease.sequence != control.sequence
            || lease.iat != control.iat
            || lease.exp != control.exp
        {
            return Err(Denied);
        }
        receiver.renew(token, now, monotonic)
    }
    pub fn request(
        &mut self,
        admission: &mut Admission,
        token: &str,
        proof: &[u8],
        now: u64,
        monotonic: Instant,
    ) -> Result<(), Denied> {
        admission.request(
            self.receiver.as_mut().ok_or(Denied)?,
            token,
            proof,
            now,
            monotonic,
        )
    }
    /// Invoke only from the receiver-local, isolated customer approval event.
    pub fn approve_locally(
        &self,
        admission: &mut Admission,
        monotonic: Instant,
    ) -> Result<(), Denied> {
        admission.approve_locally(self.receiver.as_ref().ok_or(Denied)?, monotonic)
    }
    pub fn can_control(&self, admission: &Admission, monotonic: Instant) -> bool {
        self.receiver
            .as_ref()
            .is_some_and(|receiver| admission.can_control(receiver, monotonic))
    }
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped
    }

    pub(crate) fn active(&self, now: Instant) -> bool {
        !self.stopped
            && self
                .receiver
                .as_ref()
                .is_some_and(|receiver| receiver.active(now))
    }

    pub fn stop(&mut self) {
        self.stopped = true;
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.revoke();
        }
    }
}
