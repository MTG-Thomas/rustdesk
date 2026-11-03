use super::{proof_message, Denied};

type Signer = dyn Fn(&[u8]) -> Result<[u8; 64], Denied> + Send + Sync;

/// In-memory login material supplied by an eligible workstation host. This does
/// not establish eligibility: the receiver must verify the grant and signature.
/// The signer is supplied by the host; this module creates or persists no keys.
pub struct WorkstationLogin {
    receiver: String,
    grant: String,
    sign: Box<Signer>,
}

impl WorkstationLogin {
    pub fn new(
        receiver: String,
        grant: String,
        sign: impl Fn(&[u8]) -> Result<[u8; 64], Denied> + Send + Sync + 'static,
    ) -> Result<Self, Denied> {
        proof_message(&grant, &"0".repeat(32), &receiver)?;
        Ok(Self {
            receiver,
            grant,
            sign: Box::new(sign),
        })
    }

    /// Bind the proof to the exact receiver and fresh receiver challenge. Never
    /// send the opaque grant through password storage or remember-device paths.
    pub fn authentication(
        &self,
        receiver: &str,
        challenge: &str,
    ) -> Result<(&str, [u8; 64]), Denied> {
        if receiver != self.receiver {
            return Err(Denied);
        }
        let message = proof_message(&self.grant, challenge, receiver)?;
        Ok((&self.grant, (self.sign)(&message)?))
    }
}
