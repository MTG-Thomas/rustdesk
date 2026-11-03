//! Opt-in desktop child driver. OS startup must supply verified handles/config,
//! bounded cancellable I/O, isolated local consent and a trusted event scheduler.
//! No production host or activation is installed by this module.

use quick_support_guard::{Denied, LocalConsent, PipeAdapter, VerifiedLaunch};
use std::{io::Read, time::Instant};

#[cfg(windows)]
#[path = "platform/quick_support_parent.rs"]
pub mod windows_parent;

pub enum Event {
    ParentControl,
    Grant { token: String, proof: Vec<u8> },
    LocalApproval,
    NativeFrame,
    Tick,
    Stop,
}

/// Events are readiness notifications from the local host, never peer commands.
/// The host must prioritize control/expiry and wake on disconnect/child exit.
/// Native dispatch must remain confined to the reviewed child connection.
pub fn run<P: Read, N: Read>(
    parent: P,
    native: N,
    launch: &mut impl VerifiedLaunch<P, N>,
    consent: &mut impl LocalConsent,
    mut next: impl FnMut() -> Result<Event, Denied>,
    mut clock: impl FnMut() -> (u64, Instant),
    mut dispatch: impl FnMut(&[u8]) -> Result<(), Denied>,
) -> Result<(), Denied> {
    let mut child = PipeAdapter::new(parent, native, launch)?;
    // Only the separately authenticated parent stream can initialize authority.
    child.parent_control(&mut clock)?;
    loop {
        let event = next()?;
        child.check_lease(clock().1)?;
        match event {
            Event::ParentControl => {
                child.parent_control(&mut clock)?;
                child.check_lease(clock().1)?;
            }
            Event::Grant { token, proof } => {
                let (wall, now) = clock();
                child.request(&token, &proof, wall, now)?;
            }
            Event::LocalApproval => child.approve_locally(consent, || clock().1)?,
            Event::NativeFrame => child.dispatch_next(|| clock().1, &mut dispatch)?,
            Event::Tick => {}
            Event::Stop => {
                child.stop();
                return Ok(());
            }
        }
    }
}
