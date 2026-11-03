use quick_support_guard::Denied;

/// Native protocol plumbing only. The receiver still owns authorization and
/// consent; this must never select a remembered-password or alternate service.
pub(crate) fn attach_login(
    login: &quick_support_guard::WorkstationLogin,
    challenge: &str,
    request: &mut base::message_proto::LoginRequest,
) -> Result<(), Denied> {
    if request.union.is_some() {
        return Err(Denied);
    }
    let (grant, proof) = login.authentication(&request.username, challenge)?;
    request.password.clear();
    request.hwid.clear();
    request.os_login = Default::default();
    request.option = Default::default();
    request.quick_support_auth = Some(base::message_proto::QuickSupportAuthentication {
        grant: grant.into(),
        workstation_proof: proof.to_vec().into(),
        ..Default::default()
    })
    .into();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::message_proto::{LoginRequest, OSLogin, OptionMessage};

    #[test]
    fn native_login_uses_dedicated_proof_without_password_or_device_fallback() {
        let login = quick_support_guard::WorkstationLogin::new(
            "receiver".into(),
            "synthetic-grant".into(),
            |_| Ok([7; 64]),
        )
        .unwrap();
        let mut request = LoginRequest {
            username: "receiver".into(),
            password: vec![1, 2].into(),
            hwid: vec![3].into(),
            os_login: Some(OSLogin::new()).into(),
            option: Some(OptionMessage::new()).into(),
            ..Default::default()
        };
        attach_login(&login, &"x".repeat(32), &mut request).unwrap();
        let authentication = request.quick_support_auth.as_ref().unwrap();
        assert_eq!(authentication.grant, "synthetic-grant");
        assert_eq!(authentication.workstation_proof.as_ref(), &[7; 64]);
        assert!(request.password.is_empty());
        assert!(request.hwid.is_empty());
        assert!(request.os_login.is_none());
        assert!(request.option.is_none());
        request.set_terminal(Default::default());
        assert!(attach_login(&login, &"x".repeat(32), &mut request).is_err());
        request.union = None;
        request.username = "other-receiver".into();
        assert!(attach_login(&login, &"x".repeat(32), &mut request).is_err());
    }
}
