//! Connection-local native authorization. No startup, keys or trust defaults.
use base::message_proto::{
    key_event, message, misc, option_message::BoolOption, ControlKey, LoginRequest, Message,
    OptionMessage,
};
use quick_support_guard::{ChildConnection, Denied, LocalConsent, VerifiedLaunch};
use std::{
    io::Read,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

// RustDesk encodes each permission in two bits: 01 denies, 10 allows.
// Deny every slot (including future ones), then allow only keyboard/input.
pub(crate) const DESKTOP_PERMISSIONS: u64 = 0x5555_5555_5555_5556;

/// Fresh receiver challenge, independent of parent or peer-provided strings.
#[cfg(any(windows, test))]
pub(crate) fn fresh_challenge() -> Result<String, Denied> {
    let mut bytes = [0; 32];
    hbb_common::rand::RngCore::try_fill_bytes(&mut hbb_common::rand::rngs::OsRng, &mut bytes)
        .map_err(|_| Denied)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) struct Receiver {
    child: Mutex<ChildConnection>,
    receiver_id: String,
    challenge: String,
    cancelled: Arc<AtomicBool>,
    #[cfg(windows)]
    support_ui: Mutex<Option<crate::quick_support_child::windows_consent::WindowsSessionConsent>>,
}

impl Receiver {
    /// The same retained native stream must subsequently be given to RustDesk.
    /// VerifiedLaunch authenticates the parent and independent configuration;
    /// the opaque control token is never allowed to provide its own trust root.
    pub(crate) fn verified<P, N>(
        parent: &P,
        native: &N,
        launch: &mut impl VerifiedLaunch<P, N>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, Denied> {
        let (identity, challenge) = launch.verify_parent_and_config(parent, native)?;
        let receiver_id = identity.receiver_id.clone();
        Ok(Self {
            child: Mutex::new(ChildConnection::new(identity, challenge.clone())?),
            receiver_id,
            challenge,
            cancelled,
            #[cfg(windows)]
            support_ui: Mutex::new(None),
        })
    }

    pub(crate) fn challenge(&self) -> &str {
        &self.challenge
    }

    pub(crate) fn control(&self, token: &str, wall: u64, now: Instant) -> Result<(), Denied> {
        let result = (|| {
            let mut child = self.child.lock().map_err(|_| Denied)?;
            child.parent_control(token, wall, now)?;
            child.check_lease(now)
        })();
        self.finish(result)
    }

    pub(crate) fn read_control(
        &self,
        parent: &mut impl Read,
        clock: impl FnOnce() -> Result<(u64, Instant), Denied>,
    ) -> Result<(), Denied> {
        let result = (|| {
            let mut header = [0; 4];
            parent.read_exact(&mut header).map_err(|_| Denied)?;
            let len = u32::from_be_bytes(header) as usize;
            if len == 0 || len > 16384 {
                return Err(Denied);
            }
            let mut bytes = vec![0; len];
            parent.read_exact(&mut bytes).map_err(|_| Denied)?;
            let token = std::str::from_utf8(&bytes).map_err(|_| Denied)?;
            let (wall, now) = clock()?;
            self.control(token, wall, now)
        })();
        self.finish(result)
    }

    /// Consume authentication before the login is retained for native auditing
    /// or service subscriptions. Mixed legacy authorization is refused.
    pub(crate) fn request(
        &self,
        request: &mut LoginRequest,
        wall: u64,
        now: Instant,
    ) -> Result<(), Denied> {
        let result = (|| {
            if request.username != self.receiver_id
                || request.union.is_some()
                || !request.password.is_empty()
                || !request.hwid.is_empty()
                || request.os_login.is_some()
                || request.option.is_some()
            {
                return Err(Denied);
            }
            let auth = request.quick_support_auth.take().ok_or(Denied)?;
            self.child.lock().map_err(|_| Denied)?.request(
                &auth.grant,
                &auth.workstation_proof,
                wall,
                now,
            )
        })();
        // Never leave grant material in a rejected native login either.
        request.quick_support_auth = Default::default();
        self.finish(result)
    }

    /// No guard lock is held over the modal dialog: independent parent control
    /// can cancel it, and approval is checked against the current lease again.
    pub(crate) fn consent(
        &self,
        source: &mut impl LocalConsent,
        mut clock: impl FnMut() -> Instant,
    ) -> Result<(), Denied> {
        let result = (|| {
            let request = self
                .child
                .lock()
                .map_err(|_| Denied)?
                .consent_request(clock())?;
            source.receiver_approved(&request)?;
            self.child
                .lock()
                .map_err(|_| Denied)?
                .approve_locally(clock())
        })();
        self.finish(result)
    }

    #[cfg(windows)]
    pub(crate) fn prompt(&self) -> Result<(), Denied> {
        let mut source = crate::quick_support_child::windows_consent::WindowsSessionConsent::new(
            self.cancelled.clone(),
        );
        let result = self.consent(&mut source, Instant::now);
        let stored = (|| {
            let mut ui = self.support_ui.lock().map_err(|_| Denied)?;
            if ui.is_some() {
                return Err(Denied);
            }
            *ui = Some(source);
            Ok(())
        })();
        self.finish(stored)?;
        self.finish(result)?;
        if self.authorized(Instant::now()) {
            Ok(())
        } else {
            self.finish(Err(Denied))
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn prompt(&self) -> Result<(), Denied> {
        self.finish(Err(Denied))
    }

    #[cfg(windows)]
    pub(crate) fn finish_ui(&self) -> Result<(), Denied> {
        let ui = self.support_ui.lock().map_err(|_| Denied)?.take();
        if let Some(ui) = ui {
            ui.finish()?;
        }
        Ok(())
    }

    pub(crate) fn active(&self, now: Instant) -> bool {
        if self.cancelled.load(Ordering::Acquire) {
            return false;
        }
        let result = self
            .child
            .lock()
            .map_err(|_| Denied)
            .and_then(|mut child| child.check_lease(now));
        self.finish(result).is_ok()
    }

    pub(crate) fn authorized(&self, now: Instant) -> bool {
        self.active(now)
            && self
                .child
                .lock()
                .map(|child| child.can_control(now))
                .unwrap_or(false)
    }

    pub(crate) fn inbound(&self, message: &Message, now: Instant) -> bool {
        if matches!(message.union.as_ref(), Some(message::Union::TestDelay(_)))
            || matches!(message.union.as_ref(), Some(message::Union::Misc(value)) if matches!(value.union.as_ref(), Some(misc::Union::CloseReason(_))))
        {
            return self.active(now);
        }
        if !self.authorized(now) {
            return false;
        }
        if let Some(message::Union::KeyEvent(key)) = message.union.as_ref() {
            // These native commands invoke OS/service actions, rather than the
            // ordinary input sink, and can remove the local Stop surface.
            let restricted = |value: ControlKey| {
                matches!(
                    value,
                    ControlKey::CtrlAltDel | ControlKey::LockScreen | ControlKey::Power
                )
            };
            if matches!(key.union.as_ref(), Some(key_event::Union::ControlKey(value))
                if value.enum_value().map(restricted).unwrap_or(true))
                || key
                    .modifiers
                    .iter()
                    .any(|value| value.enum_value().map(restricted).unwrap_or(true))
            {
                return false;
            }
        }
        if let Some(message::Union::Misc(value)) = message.union.as_ref() {
            if let Some(misc::Union::Option(option)) = value.union.as_ref() {
                return safe_desktop_option(option);
            }
        }
        matches!(
            message.union.as_ref(),
            Some(
                message::Union::TestDelay(_)
                    | message::Union::MouseEvent(_)
                    | message::Union::KeyEvent(_)
                    | message::Union::PointerDeviceEvent(_)
            )
        ) || matches!(message.union.as_ref(), Some(message::Union::Misc(value)) if matches!(value.union.as_ref(),
                Some(misc::Union::CloseReason(_) | misc::Union::SwitchDisplay(_)
                    | misc::Union::RefreshVideo(_) | misc::Union::VideoReceived(_)
                    | misc::Union::RefreshVideoDisplay(_) | misc::Union::SupportedEncoding(_)
                    | misc::Union::RequestCursorData(_))))
    }

    /// Recheck at the final native input sink, after queueing. Serialize one
    /// bounded OS input dispatch with control updates; buffered input cannot
    /// survive terminal shutdown. The callback must not wait for consent/I/O.
    pub(crate) fn dispatch<T>(
        &self,
        now: Instant,
        apply: impl FnOnce() -> Result<T, Denied>,
    ) -> Result<T, Denied> {
        let result = (|| {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(Denied);
            }
            let child = self.child.lock().map_err(|_| Denied)?;
            if !child.can_control(now) {
                return Err(Denied);
            }
            apply()
        })();
        self.finish(result)
    }

    pub(crate) fn outbound(&self, message: &Message, now: Instant) -> bool {
        if !self.authorized(now) {
            return false;
        }
        matches!(
            message.union.as_ref(),
            Some(
                message::Union::VideoFrame(_)
                    | message::Union::CursorData(_)
                    | message::Union::CursorPosition(_)
                    | message::Union::CursorId(_)
                    | message::Union::PeerInfo(_)
                    | message::Union::TestDelay(_)
            )
        ) || matches!(message.union.as_ref(), Some(message::Union::Misc(value)) if matches!(value.union.as_ref(),
                Some(misc::Union::CloseReason(_) | misc::Union::PermissionInfo(_)
                    | misc::Union::Uac(_) | misc::Union::ForegroundWindowElevated(_))))
    }

    pub(crate) fn stop(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Ok(mut child) = self.child.lock() {
            child.stop();
        }
    }

    fn finish<T>(&self, result: Result<T, Denied>) -> Result<T, Denied> {
        if result.is_err() {
            self.stop();
        }
        result
    }
}

fn safe_desktop_option(option: &OptionMessage) -> bool {
    let disabled = |value| {
        if value == BoolOption::Yes.into() {
            value
        } else {
            Default::default()
        }
    };
    option
        == &OptionMessage {
            image_quality: option.image_quality,
            custom_image_quality: option.custom_image_quality,
            custom_fps: option.custom_fps,
            supported_decoding: option.supported_decoding.clone(),
            show_remote_cursor: option.show_remote_cursor,
            show_my_cursor: option.show_my_cursor,
            follow_remote_cursor: option.follow_remote_cursor,
            follow_remote_window: option.follow_remote_window,
            disable_keyboard: option.disable_keyboard,
            disable_audio: disabled(option.disable_audio),
            disable_clipboard: disabled(option.disable_clipboard),
            disable_camera: disabled(option.disable_camera),
            ..Default::default()
        }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop();
    }
}

// Only the trusted native host registers an internally allocated connection ID.
// A peer packet, connection address or login cannot select this context.
static PENDING: Mutex<Option<(i32, Arc<Receiver>)>> = Mutex::new(None);
pub(crate) struct Registration {
    id: i32,
    receiver: Arc<Receiver>,
}
impl Registration {
    pub(crate) fn new(id: i32, receiver: Arc<Receiver>) -> Result<Self, Denied> {
        let mut pending = PENDING.lock().map_err(|_| Denied)?;
        if pending.is_some() {
            return Err(Denied);
        }
        *pending = Some((id, receiver.clone()));
        Ok(Self { id, receiver })
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.receiver.stop();
        if let Ok(mut pending) = PENDING.lock() {
            if pending.as_ref().map(|(id, _)| *id) == Some(self.id) {
                pending.take();
            }
        }
    }
}
pub(crate) fn take(id: i32) -> Result<Option<Arc<Receiver>>, Denied> {
    let mut pending = PENDING.lock().map_err(|_| Denied)?;
    if pending.as_ref().map(|(registered, _)| *registered) == Some(id) {
        Ok(pending.take().map(|(_, receiver)| receiver))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::QuickSupportAuthentication;
    use quick_support_guard::{ConsentRequest, ControlIdentity};
    use serde_json::Value;
    use std::time::Duration;

    const CHALLENGE: &str = "01234567890123456789012345678901";
    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../libs/base/quick_support_guard/tests/fixtures/receiver-control-v1.json"
        ))
        .unwrap()
    }
    fn decode(hex: &str) -> Vec<u8> {
        hex.trim()
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    struct Trust;
    impl VerifiedLaunch<(), ()> for Trust {
        fn verify_parent_and_config(
            &mut self,
            _: &(),
            _: &(),
        ) -> Result<(ControlIdentity, String), Denied> {
            let f = fixture();
            Ok((
                ControlIdentity {
                    issuer: f["issuer"].as_str().unwrap().into(),
                    issuer_key: decode(f["issuer_key"].as_str().unwrap())
                        .try_into()
                        .unwrap(),
                    organization_id: f["organization_id"].as_str().unwrap().into(),
                    solution_id: f["solution_id"].as_str().unwrap().into(),
                    session_id: f["session_id"].as_str().unwrap().into(),
                    generation: f["generation"].as_str().unwrap().into(),
                    receiver_id: f["receiver_id"].as_str().unwrap().into(),
                },
                CHALLENGE.into(),
            ))
        }
    }
    fn prepared(now: Instant) -> Receiver {
        let receiver =
            Receiver::verified(&(), &(), &mut Trust, Arc::new(AtomicBool::new(false))).unwrap();
        receiver
            .control(
                fixture()["bootstrap"].as_str().unwrap(),
                1000,
                now - Duration::from_secs(1),
            )
            .unwrap();
        receiver
    }
    fn login() -> LoginRequest {
        LoginRequest {
            username: fixture()["receiver_id"].as_str().unwrap().into(),
            quick_support_auth: Some(QuickSupportAuthentication {
                grant: fixture()["grant"].as_str().unwrap().into(),
                workstation_proof: decode(include_str!(
                    "../libs/base/quick_support_guard/tests/fixtures/native-login-proof.hex"
                ))
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }
    struct Prompt<F>(F);
    impl<F: FnMut(&ConsentRequest) -> Result<(), Denied>> LocalConsent for Prompt<F> {
        fn receiver_approved(&mut self, request: &ConsentRequest) -> Result<(), Denied> {
            (self.0)(request)
        }
    }

    #[test]
    fn native_login_requires_consent_and_limits_desktop_packets_until_terminal_revoke() {
        let first = fresh_challenge().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, fresh_challenge().unwrap());
        let now = Instant::now();
        let receiver = Arc::new(prepared(now));
        let registration = Registration::new(482, receiver.clone()).unwrap();
        assert!(take(483).unwrap().is_none());
        assert!(Arc::ptr_eq(&take(482).unwrap().unwrap(), &receiver));
        assert_eq!(receiver.challenge(), CHALLENGE);
        let mut request = login();
        receiver.request(&mut request, 1001, now).unwrap();
        assert!(request.quick_support_auth.is_none());
        assert!(!receiver.authorized(now));
        receiver
            .consent(
                &mut Prompt(|request: &ConsentRequest| {
                    assert_eq!(
                        request.session_id(),
                        fixture()["session_id"].as_str().unwrap()
                    );
                    Ok(())
                }),
                || now,
            )
            .unwrap();
        assert!(receiver.authorized(now));
        let mut outgoing = Message::new();
        outgoing.set_video_frame(Default::default());
        assert!(receiver.outbound(&outgoing, now));
        outgoing.set_audio_frame(Default::default());
        assert!(!receiver.outbound(&outgoing, now));
        assert_eq!(receiver.dispatch(now, || Ok(7)), Ok(7));
        for slot in 0..32 {
            assert_eq!(
                (DESKTOP_PERMISSIONS >> (slot * 2)) & 3,
                if slot == 0 { 2 } else { 1 }
            );
        }
        let mut message = Message::new();
        message.set_mouse_event(Default::default());
        assert!(receiver.inbound(&message, now));
        let mut key = base::message_proto::KeyEvent::new();
        key.set_unicode(u32::from('a'));
        message.set_key_event(key.clone());
        assert!(receiver.inbound(&message, now));
        for command in [
            ControlKey::CtrlAltDel,
            ControlKey::LockScreen,
            ControlKey::Power,
        ] {
            key.set_control_key(command);
            message.set_key_event(key.clone());
            assert!(!receiver.inbound(&message, now));
            key.set_unicode(u32::from('a'));
            key.modifiers = vec![command.into()];
            message.set_key_event(key.clone());
            assert!(!receiver.inbound(&message, now));
            key.modifiers.clear();
        }
        message.set_file_action(Default::default());
        assert!(!receiver.inbound(&message, now));
        message.set_terminal_action(Default::default());
        assert!(!receiver.inbound(&message, now));
        let mut options = OptionMessage::new();
        options.supported_decoding = Some(Default::default()).into();
        let mut misc = base::message_proto::Misc::new();
        misc.set_option(options.clone());
        message.set_misc(misc.clone());
        assert!(receiver.inbound(&message, now));
        options.block_input = BoolOption::Yes.into();
        misc.set_option(options);
        message.set_misc(misc);
        assert!(!receiver.inbound(&message, now));
        receiver
            .control(
                fixture()["renew"].as_str().unwrap(),
                1002,
                now + Duration::from_secs(2),
            )
            .unwrap();
        assert!(receiver
            .control(
                fixture()["revoke"].as_str().unwrap(),
                1003,
                now + Duration::from_secs(3)
            )
            .is_err());
        assert!(receiver.cancelled.load(Ordering::Acquire));
        assert!(!receiver.authorized(now));
        assert!(receiver
            .dispatch(now, || -> Result<(), Denied> {
                panic!("queued input survived revoke")
            })
            .is_err());
        assert!(receiver.request(&mut login(), 1001, now).is_err());
        drop(registration);
        assert!(!receiver.active(now));
    }

    #[test]
    fn independent_revocation_during_prompt_cannot_become_approval() {
        let now = Instant::now();
        let receiver = prepared(now);
        receiver.request(&mut login(), 1001, now).unwrap();
        let mut prompt = Prompt(|_: &ConsentRequest| {
            receiver
                .control(
                    fixture()["renew"].as_str().unwrap(),
                    1002,
                    now + Duration::from_secs(2),
                )
                .unwrap();
            // This runs while the dialog owns its immutable snapshot. A guard
            // lock held over the prompt would deadlock this control delivery.
            assert!(receiver
                .control(
                    fixture()["revoke"].as_str().unwrap(),
                    1003,
                    now + Duration::from_secs(3)
                )
                .is_err());
            Ok(())
        });
        assert!(receiver
            .consent(&mut prompt, || now + Duration::from_secs(3))
            .is_err());
        assert!(!receiver.authorized(now));
    }

    #[test]
    fn wrong_native_login_replay_expiry_and_control_eof_close_without_legacy_fallback() {
        let now = Instant::now();
        for mixed in [false, true] {
            let receiver = prepared(now);
            let mut request = login();
            if mixed {
                request.password = vec![1].into();
            } else {
                request.username = "wrong-receiver".into();
            }
            assert!(receiver.request(&mut request, 1001, now).is_err());
            assert!(request.quick_support_auth.is_none());
            assert!(!receiver.active(now));
        }
        let receiver = prepared(now);
        receiver.request(&mut login(), 1001, now).unwrap();
        assert!(receiver.request(&mut login(), 1001, now).is_err());
        assert!(!receiver.active(now));
        let receiver = prepared(now);
        assert!(!receiver.active(now + Duration::from_secs(61)));
        for bytes in [
            Vec::new(),
            16385u32.to_be_bytes().to_vec(),
            vec![0, 0, 0, 2, 65],
            vec![0, 0, 0, 1, 255],
        ] {
            let receiver = prepared(now);
            assert!(receiver
                .read_control(&mut std::io::Cursor::new(bytes), || Ok((1001, now)))
                .is_err());
            assert!(!receiver.active(now));
        }
        let receiver = prepared(now);
        receiver.request(&mut login(), 1001, now).unwrap();
        receiver
            .consent(&mut Prompt(|_: &ConsentRequest| Ok(())), || now)
            .unwrap();
        // The local UI cancels before the async connection loop sees the event.
        receiver.cancelled.store(true, Ordering::Release);
        assert!(!receiver.authorized(now));
        assert!(receiver
            .dispatch(now, || -> Result<(), Denied> {
                panic!("input survived customer Stop")
            })
            .is_err());
        // Even an erroneous flag reset cannot restore the closed admission.
        receiver.cancelled.store(false, Ordering::Release);
        assert!(!receiver.authorized(now));
        #[cfg(not(windows))]
        assert!(prepared(now).prompt().is_err());
        let receiver = prepared(now);
        assert!(receiver
            .read_control(&mut std::io::Cursor::new(Vec::<u8>::new()), || Ok((
                1000, now
            )))
            .is_err());
        assert!(!receiver.active(now));
    }
}
