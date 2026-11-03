//! Receiver-local attended consent. The native dialog is never an IPC command.
use quick_support_guard::{ConsentRequest, Denied, LocalConsent};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use windows::{
    core::{HRESULT, PCWSTR},
    Win32::{
        Foundation::{HWND, LPARAM, WPARAM},
        UI::{
            Controls::{
                TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TASKDIALOG_NOTIFICATIONS,
                TDCBF_CANCEL_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION, TDF_CALLBACK_TIMER,
                TDM_CLICK_BUTTON, TDN_CREATED, TDN_TIMER,
            },
            WindowsAndMessaging::{SendMessageW, IDCANCEL},
        },
    },
};

const ALLOW_SUPPORT: i32 = 1001;

/// One instance belongs to one authenticated child connection. The host must
/// signal cancellation independently on control loss, revocation or local stop.
pub struct WindowsConsent {
    cancelled: Arc<AtomicBool>,
    used: bool,
}

struct DialogBound {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl DialogBound {
    fn active(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline
    }
    fn accept(&self, button: i32) -> Result<(), Denied> {
        if button == ALLOW_SUPPORT && self.active() {
            Ok(())
        } else {
            Err(Denied)
        }
    }
}

impl WindowsConsent {
    pub fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            used: false,
        }
    }

    fn begin(&mut self, deadline: Instant) -> Result<DialogBound, Denied> {
        if self.used {
            return Err(Denied);
        }
        self.used = true;
        let bound = DialogBound {
            cancelled: self.cancelled.clone(),
            deadline,
        };
        if !bound.active() {
            return Err(Denied);
        }
        Ok(bound)
    }
}

unsafe extern "system" fn callback(
    window: HWND,
    notification: TASKDIALOG_NOTIFICATIONS,
    _wparam: WPARAM,
    _lparam: LPARAM,
    data: isize,
) -> HRESULT {
    if data != 0 && (notification == TDN_CREATED || notification == TDN_TIMER) {
        // TaskDialogIndirect is synchronous; this borrowed context and its
        // cancellation signal outlive every callback until the modal call returns.
        let bound = unsafe { &*(data as *const DialogBound) };
        if !bound.active() {
            unsafe {
                SendMessageW(
                    window,
                    TDM_CLICK_BUTTON.0 as u32,
                    Some(WPARAM(IDCANCEL.0 as usize)),
                    None,
                )
            };
        }
    }
    HRESULT(0)
}

impl LocalConsent for WindowsConsent {
    fn receiver_approved(&mut self, request: &ConsentRequest) -> Result<(), Denied> {
        let bound = self.begin(request.deadline())?;
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let title = wide("MTG Quick Support");
        let instruction = wide("Allow MTG support to view and control your desktop?");
        // These references come from the verified grant/bootstrap, never the
        // native peer's display name. Friendly directory labels need their own
        // authenticated binding before replacing these exact references.
        let details = wide(&format!(
            "Verified technician reference: {}\nSupport request: {}",
            request.technician_id(),
            request.session_id()
        ));
        let content = wide("Only allow support if you contacted MTG and are expecting this request. Closing this window declines access.");
        let expand = wide("Show verified request details");
        let collapse = wide("Hide verified request details");
        let allow = wide("Allow support");
        let button = TASKDIALOG_BUTTON {
            nButtonID: ALLOW_SUPPORT,
            pszButtonText: PCWSTR(allow.as_ptr()),
        };
        let config = TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER,
            dwCommonButtons: TDCBF_CANCEL_BUTTON,
            pszWindowTitle: PCWSTR(title.as_ptr()),
            pszMainInstruction: PCWSTR(instruction.as_ptr()),
            pszContent: PCWSTR(content.as_ptr()),
            pszExpandedInformation: PCWSTR(details.as_ptr()),
            pszExpandedControlText: PCWSTR(expand.as_ptr()),
            pszCollapsedControlText: PCWSTR(collapse.as_ptr()),
            cButtons: 1,
            pButtons: &button,
            nDefaultButton: IDCANCEL.0,
            pfCallback: Some(callback),
            lpCallbackData: &bound as *const DialogBound as isize,
            ..Default::default()
        };
        let mut selected = 0;
        unsafe { TaskDialogIndirect(&config, Some(&mut selected), None, None) }
            .map_err(|_| Denied)?;
        bound.accept(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn native_dialog_api_rejects_invalid_configuration_without_prompting() {
        // Linkage/API failure coverage only, not evidence of customer approval.
        let config = TASKDIALOGCONFIG::default();
        assert!(unsafe { TaskDialogIndirect(&config, None, None, None) }.is_err());
    }

    #[test]
    fn only_explicit_current_allow_succeeds_and_the_prompt_is_one_use() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut consent = WindowsConsent::new(cancelled.clone());
        let bound = consent
            .begin(Instant::now() + Duration::from_secs(5))
            .unwrap();
        for button in [0, IDCANCEL.0, 6, -1] {
            assert!(bound.accept(button).is_err());
        }
        assert!(bound.accept(ALLOW_SUPPORT).is_ok());
        assert!(consent.begin(bound.deadline).is_err());
        cancelled.store(true, Ordering::Release);
        assert!(bound.accept(ALLOW_SUPPORT).is_err());
        cancelled.store(false, Ordering::Release);
        let expired = DialogBound {
            cancelled,
            deadline: Instant::now() - Duration::from_secs(1),
        };
        assert!(expired.accept(ALLOW_SUPPORT).is_err());
    }
}
