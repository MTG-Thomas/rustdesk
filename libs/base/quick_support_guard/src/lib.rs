//! Receiver-enforced, one-use grants. Successful authorization still requires local consent.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const AUDIENCE: &str = "rustdesk-quick-support";
pub const TOKEN_TYPE: &str = "rd-qs+jwt";
pub const MAX_GRANT_SECONDS: u64 = 60;
pub const MAX_LEASE_SECONDS: u64 = 60;
pub const MAX_CONNECTIONS: usize = 128;
const MAX_TOKEN_BYTES: usize = 4096;
const PROOF_DOMAIN: &[u8] = b"rustdesk-quick-support-proof/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denied;
impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Quick Support authorization denied")
    }
}
impl std::error::Error for Denied {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub session_id: String,
    pub generation: String,
    pub receiver_id: String,
    pub workstation_key: String,
    pub jti: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub iss: String,
    pub aud: String,
    pub session_id: String,
    pub generation: String,
    pub receiver_id: String,
    pub sequence: u64,
    pub iat: u64,
    pub exp: u64,
}

/// Public, issuer-signed receiver settings. Never accept unsigned local configuration.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub iss: String,
    pub aud: String,
    pub session_id: String,
    pub generation: String,
    pub receiver_id: String,
    pub technician_id: String,
    pub workstation_key: String,
    pub iat: u64,
    pub exp: u64,
}

pub struct Receiver {
    issuer: String,
    issuer_key: VerifyingKey,
    session_id: String,
    generation: String,
    receiver_id: String,
    technician_id: String,
    workstation_key: [u8; 32],
    hard_expiry: u64,
    clock_anchor: u64,
    monotonic_anchor: Instant,
    clock_floor: u64,
    hard_deadline: Instant,
    lease_deadline: Option<Instant>,
    lease_sequence: Option<u64>,
    used: HashSet<String>,
}

fn decode(value: &str, max: usize) -> Result<Vec<u8>, Denied> {
    if value.is_empty() || value.len() > max || value.contains('=') {
        return Err(Denied);
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| Denied)
}

fn key(value: &[u8; 32]) -> Result<VerifyingKey, Denied> {
    let key = VerifyingKey::from_bytes(value).map_err(|_| Denied)?;
    if key.is_weak() {
        return Err(Denied);
    }
    Ok(key)
}

pub fn verify_token<T: DeserializeOwned>(token: &str, issuer_key: &[u8; 32]) -> Result<T, Denied> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Denied);
    }
    let mut parts = token.split('.');
    let header = parts.next().ok_or(Denied)?;
    let claims = parts.next().ok_or(Denied)?;
    let signature = parts.next().ok_or(Denied)?;
    if parts.next().is_some() {
        return Err(Denied);
    }
    let header_value: Header = serde_json::from_slice(&decode(header, 256)?).map_err(|_| Denied)?;
    if header_value.alg != "EdDSA" || header_value.typ != TOKEN_TYPE {
        return Err(Denied);
    }
    let signature = Signature::from_slice(&decode(signature, 86)?).map_err(|_| Denied)?;
    key(issuer_key)?
        .verify_strict(format!("{header}.{claims}").as_bytes(), &signature)
        .map_err(|_| Denied)?;
    serde_json::from_slice(&decode(claims, MAX_TOKEN_BYTES)?).map_err(|_| Denied)
}

pub fn proof_message(token: &str, challenge: &str, receiver_id: &str) -> Result<Vec<u8>, Denied> {
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || challenge.len() < 32
        || challenge.len() > 256
        || receiver_id.is_empty()
        || receiver_id.len() > 64
    {
        return Err(Denied);
    }
    let mut out = PROOF_DOMAIN.to_vec();
    for value in [
        token.as_bytes(),
        challenge.as_bytes(),
        receiver_id.as_bytes(),
    ] {
        out.extend_from_slice(&(value.len() as u64).to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

pub struct ReceiverIdentity {
    pub issuer: String,
    pub issuer_key: [u8; 32],
    pub session_id: String,
    pub generation: String,
    pub receiver_id: String,
    pub technician_id: String,
    pub workstation_key: [u8; 32],
    pub hard_expiry: u64,
}

impl Receiver {
    /// The issuer URL and verification key must come from the signed application,
    /// not from the customer link or downloaded configuration.
    pub fn from_bootstrap(
        token: &str,
        pinned_issuer: &str,
        pinned_key: &[u8; 32],
        now: u64,
        monotonic: Instant,
    ) -> Result<Self, Denied> {
        let bootstrap: Bootstrap = verify_token(token, pinned_key)?;
        if bootstrap.iss != pinned_issuer
            || bootstrap.aud != AUDIENCE
            || bootstrap.iat > now
            || now.saturating_sub(bootstrap.iat) > MAX_GRANT_SECONDS
            || bootstrap
                .exp
                .checked_sub(bootstrap.iat)
                .filter(|duration| *duration > 0 && *duration <= 24 * 3600)
                .is_none()
        {
            return Err(Denied);
        }
        let workstation_key: [u8; 32] = decode(&bootstrap.workstation_key, 43)?
            .try_into()
            .map_err(|_| Denied)?;
        Self::new(
            ReceiverIdentity {
                issuer: bootstrap.iss,
                issuer_key: *pinned_key,
                session_id: bootstrap.session_id,
                generation: bootstrap.generation,
                receiver_id: bootstrap.receiver_id,
                technician_id: bootstrap.technician_id,
                workstation_key,
                hard_expiry: bootstrap.exp,
            },
            now,
            monotonic,
        )
    }

    pub fn new(identity: ReceiverIdentity, now: u64, monotonic: Instant) -> Result<Self, Denied> {
        if !identity.issuer.starts_with("https://")
            || identity.issuer.len() > 256
            || Uuid::parse_str(&identity.session_id).is_err()
            || Uuid::parse_str(&identity.generation).is_err()
            || Uuid::parse_str(&identity.technician_id).is_err()
            || identity.receiver_id.is_empty()
            || identity.receiver_id.len() > 64
            || identity.hard_expiry <= now
            || identity.hard_expiry - now > 24 * 3600
        {
            return Err(Denied);
        }
        key(&identity.workstation_key)?;
        Ok(Self {
            issuer: identity.issuer,
            issuer_key: key(&identity.issuer_key)?,
            session_id: identity.session_id,
            generation: identity.generation,
            receiver_id: identity.receiver_id,
            technician_id: identity.technician_id,
            workstation_key: identity.workstation_key,
            hard_expiry: identity.hard_expiry,
            clock_anchor: now,
            monotonic_anchor: monotonic,
            clock_floor: now,
            hard_deadline: monotonic
                .checked_add(Duration::from_secs(identity.hard_expiry - now))
                .ok_or(Denied)?,
            lease_deadline: None,
            lease_sequence: None,
            used: HashSet::new(),
        })
    }

    fn effective_time(&mut self, wall: u64, monotonic: Instant) -> Result<u64, Denied> {
        let elapsed = monotonic
            .checked_duration_since(self.monotonic_anchor)
            .ok_or(Denied)?;
        let floor = self
            .clock_anchor
            .checked_add(elapsed.as_secs())
            .ok_or(Denied)?;
        self.clock_floor = self.clock_floor.max(wall).max(floor);
        Ok(self.clock_floor)
    }

    pub fn renew(&mut self, token: &str, now: u64, monotonic: Instant) -> Result<(), Denied> {
        let now = self.effective_time(now, monotonic)?;
        let lease: Lease = verify_token(token, self.issuer_key.as_bytes())?;
        if lease.iss != self.issuer
            || lease.aud != AUDIENCE
            || lease.session_id != self.session_id
            || lease.generation != self.generation
            || lease.receiver_id != self.receiver_id
            || lease.iat > now
            || lease.exp <= now
            || lease.exp > self.hard_expiry
            || lease
                .exp
                .checked_sub(lease.iat)
                .filter(|d| *d <= MAX_LEASE_SECONDS && *d > 0)
                .is_none()
            || now - lease.iat > MAX_LEASE_SECONDS
            || monotonic >= self.hard_deadline
            || self
                .lease_sequence
                .is_some_and(|sequence| lease.sequence <= sequence)
        {
            return Err(Denied);
        }
        let deadline = monotonic
            .checked_add(Duration::from_secs(lease.exp - now))
            .ok_or(Denied)?;
        self.lease_deadline = Some(deadline.min(self.hard_deadline));
        self.lease_sequence = Some(lease.sequence);
        Ok(())
    }

    pub fn active(&self, monotonic: Instant) -> bool {
        monotonic >= self.monotonic_anchor
            && monotonic < self.hard_deadline
            && self
                .lease_deadline
                .is_some_and(|deadline| monotonic < deadline)
    }

    pub fn authorize(
        &mut self,
        token: &str,
        proof: &[u8],
        challenge: &str,
        now: u64,
        monotonic: Instant,
    ) -> Result<(), Denied> {
        let now = self.effective_time(now, monotonic)?;
        if !self.active(monotonic) || self.used.len() >= MAX_CONNECTIONS {
            return Err(Denied);
        }
        let grant: Grant = verify_token(token, self.issuer_key.as_bytes())?;
        if grant.iss != self.issuer
            || grant.aud != AUDIENCE
            || grant.sub != self.technician_id
            || grant.session_id != self.session_id
            || grant.generation != self.generation
            || grant.receiver_id != self.receiver_id
            || grant.iat > now
            || grant.nbf > now
            || grant.nbf > grant.iat
            || grant.exp <= now
            || grant.exp > self.hard_expiry
            || grant
                .exp
                .checked_sub(grant.iat)
                .filter(|d| *d <= MAX_GRANT_SECONDS && *d > 0)
                .is_none()
            || decode(&grant.jti, 43)?.len() != 32
            || self.used.contains(&grant.jti)
            || decode(&grant.workstation_key, 43)?.as_slice() != self.workstation_key
        {
            return Err(Denied);
        }
        let signature = Signature::from_slice(proof).map_err(|_| Denied)?;
        key(&self.workstation_key)?
            .verify_strict(
                &proof_message(token, challenge, &self.receiver_id)?,
                &signature,
            )
            .map_err(|_| Denied)?;
        self.used.insert(grant.jti);
        Ok(())
    }
}

/// One transport connection. A verified grant only opens the local consent prompt.
/// Keep this state private to the receiving connection; never serialize approval.
pub struct Admission {
    challenge: String,
    grant_verified: bool,
    customer_approved: bool,
}

impl Admission {
    /// The transport must supply a new OS-random challenge for every connection.
    pub fn new(challenge: String) -> Result<Self, Denied> {
        if !(32..=256).contains(&challenge.len()) {
            return Err(Denied);
        }
        Ok(Self {
            challenge,
            grant_verified: false,
            customer_approved: false,
        })
    }

    pub fn request(
        &mut self,
        receiver: &mut Receiver,
        token: &str,
        proof: &[u8],
        now: u64,
        monotonic: Instant,
    ) -> Result<(), Denied> {
        // A second login cannot replace the identity behind an existing prompt.
        if self.grant_verified {
            return Err(Denied);
        }
        receiver.authorize(token, proof, &self.challenge, now, monotonic)?;
        self.grant_verified = true;
        Ok(())
    }

    /// Invoke only from the receiver's local customer-approval event.
    pub fn approve_locally(
        &mut self,
        receiver: &Receiver,
        monotonic: Instant,
    ) -> Result<(), Denied> {
        if !self.grant_verified || !receiver.active(monotonic) {
            return Err(Denied);
        }
        self.customer_approved = true;
        Ok(())
    }

    pub fn can_control(&self, receiver: &Receiver, monotonic: Instant) -> bool {
        self.grant_verified && self.customer_approved && receiver.active(monotonic)
    }
}
