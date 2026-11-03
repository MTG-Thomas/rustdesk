//! Separately signed launch identity; never infer expected scope from control JWS.
use super::*;

pub struct LaunchTrust {
    pub issuer: String,
    pub issuer_key: [u8; 32],
    pub organization_id: String,
    pub solution_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    iss: String,
    aud: String,
    organization_id: String,
    solution_id: String,
    session_id: String,
    generation: String,
    receiver_id: String,
    profile_nonce: String,
    iat: u64,
    exp: u64,
}

/// One attempt per authenticated process launch. Pins come from the release;
/// nonce comes from the independently pinned fresh profile directory.
pub struct LaunchVerifier {
    trust: Option<LaunchTrust>,
    nonce: String,
}
impl LaunchVerifier {
    pub fn new(trust: LaunchTrust, nonce: String) -> Result<Self, Denied> {
        if !trust.issuer.starts_with("https://")
            || trust.issuer.len() > 256
            || Uuid::parse_str(&trust.organization_id).is_err()
            || Uuid::parse_str(&trust.solution_id).is_err()
            || nonce.len() != 64
            || !nonce
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err(Denied);
        }
        key(&trust.issuer_key)?;
        Ok(Self {
            trust: Some(trust),
            nonce,
        })
    }
    pub fn verify(&mut self, token: &str, wall: u64) -> Result<ControlIdentity, Denied> {
        let trust = self.trust.take().ok_or(Denied)?;
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
        let value: Header = serde_json::from_slice(&decode(header, 256)?).map_err(|_| Denied)?;
        if value.alg != "EdDSA" || value.typ != "rd-qs-launch+jwt" {
            return Err(Denied);
        }
        let signature = Signature::from_slice(&decode(signature, 86)?).map_err(|_| Denied)?;
        key(&trust.issuer_key)?
            .verify_strict(format!("{header}.{claims}").as_bytes(), &signature)
            .map_err(|_| Denied)?;
        let claims: Launch =
            serde_json::from_slice(&decode(claims, MAX_TOKEN_BYTES)?).map_err(|_| Denied)?;
        if claims.iss != trust.issuer
            || claims.aud != AUDIENCE
            || claims.organization_id != trust.organization_id
            || claims.solution_id != trust.solution_id
            || claims.profile_nonce != self.nonce
            || claims.iat > wall
            || claims.exp <= wall
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > 60
            || Uuid::parse_str(&claims.session_id).is_err()
            || Uuid::parse_str(&claims.generation).is_err()
            || claims.receiver_id.is_empty()
            || claims.receiver_id.len() > 64
        {
            return Err(Denied);
        }
        Ok(ControlIdentity {
            issuer: trust.issuer,
            issuer_key: trust.issuer_key,
            organization_id: trust.organization_id,
            solution_id: trust.solution_id,
            session_id: claims.session_id,
            generation: claims.generation,
            receiver_id: claims.receiver_id,
        })
    }
}
