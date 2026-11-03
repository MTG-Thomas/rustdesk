//! Receiver-local attended consent. The native dialog is never an IPC command.
use quick_support_guard::{ConsentRequest, Denied, LocalConsent};
use std::{
    cell::Cell,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
        Arc,
    },
    thread::JoinHandle,
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
                TDM_CLICK_BUTTON, TDN_BUTTON_CLICKED, TDN_CREATED, TDN_TIMER,
            },
            WindowsAndMessaging::{
                IsIconic, IsWindowVisible, SendMessageW, SetWindowPos, HWND_TOPMOST, IDCANCEL,
                SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW,
            },
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

const STOP_SUPPORT: i32 = 1002;

/// Keeps a receiver-local Stop surface alive after the existing explicit Allow
/// decision. Readiness is not consent: the native guard still checks the lease.
pub struct WindowsSessionConsent {
    consent: WindowsConsent,
    cancelled: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WindowsSessionConsent {
    pub fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            consent: WindowsConsent::new(cancelled.clone()),
            cancelled,
            thread: None,
        }
    }

    /// Join only on a blocking worker, after signaling native/control shutdown.
    pub fn finish(mut self) -> Result<(), Denied> {
        self.cancelled.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| Denied)?;
        }
        Ok(())
    }
}

impl Drop for WindowsSessionConsent {
    fn drop(&mut self) {
        // Never block an async connection worker in Drop. The host explicitly
        // joins via finish; its enclosing Job Object is the final process bound.
        self.cancelled.store(true, Ordering::Release);
    }
}

impl LocalConsent for WindowsSessionConsent {
    fn receiver_approved(&mut self, request: &ConsentRequest) -> Result<(), Denied> {
        self.consent.receiver_approved(request)?;
        let (sender, ready) = mpsc::sync_channel(1);
        let cancelled = self.cancelled.clone();
        let deadline = request.deadline();
        let technician = request.technician_id().to_owned();
        let session = request.session_id().to_owned();
        self.thread = Some(
            std::thread::Builder::new()
                .name("quick-support-stop".into())
                .spawn(move || stop_window(cancelled, deadline, sender, technician, session))
                .map_err(|_| Denied)?,
        );
        ready
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| Denied)?
    }
}

struct StopBound {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    sender: SyncSender<Result<(), Denied>>,
    ready_sent: Cell<bool>,
}

impl StopBound {
    fn ready(&self, visible: bool, now: Instant) -> Result<(), Denied> {
        if self.ready_sent.replace(true) {
            self.cancelled.store(true, Ordering::Release);
            return Err(Denied);
        }
        let result = if visible && now < self.deadline && !self.cancelled.load(Ordering::Acquire) {
            Ok(())
        } else {
            self.cancelled.store(true, Ordering::Release);
            Err(Denied)
        };
        if self.sender.try_send(result).is_err() {
            self.cancelled.store(true, Ordering::Release);
            return Err(Denied);
        }
        result
    }

    fn ended(&self) {
        self.cancelled.store(true, Ordering::Release);
        if !self.ready_sent.replace(true) && self.sender.try_send(Err(Denied)).is_err() {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

unsafe extern "system" fn stop_callback(
    window: HWND,
    notification: TASKDIALOG_NOTIFICATIONS,
    _wparam: WPARAM,
    _lparam: LPARAM,
    data: isize,
) -> HRESULT {
    if data == 0 {
        return HRESULT(0);
    }
    // Callback data and buffers live on the UI thread until TaskDialog returns.
    // Shared Cell access remains sound even if SendMessage re-enters callbacks.
    let bound = unsafe { &*(data as *const StopBound) };
    let close = if notification == TDN_CREATED {
        let visible = unsafe {
            SetWindowPos(
                window,
                Some(HWND_TOPMOST),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
            )
        }
        .is_ok()
            && unsafe { IsWindowVisible(window) }.as_bool();
        bound.ready(visible, Instant::now()).is_err()
    } else if notification == TDN_BUTTON_CLICKED {
        // Stop, Escape and window-close all revoke before dismissing the UI.
        bound.ended();
        false
    } else if notification == TDN_TIMER
        && (bound.cancelled.load(Ordering::Acquire)
            || !unsafe { IsWindowVisible(window) }.as_bool()
            || unsafe { IsIconic(window) }.as_bool())
    {
        bound.ended();
        true
    } else {
        false
    };
    if close {
        unsafe {
            SendMessageW(
                window,
                TDM_CLICK_BUTTON.0 as u32,
                Some(WPARAM(STOP_SUPPORT as usize)),
                None,
            )
        };
    }
    HRESULT(0)
}

fn stop_window(
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
    sender: SyncSender<Result<(), Denied>>,
    technician: String,
    session: String,
) {
    let bound = StopBound {
        cancelled,
        deadline,
        sender,
        ready_sent: Cell::new(false),
    };
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let title = wide("MTG Quick Support");
    let instruction = wide("You have allowed MTG support");
    let content = wide("Keep this window open during support. Choose Stop support or close this window to end access.");
    let details = wide(&format!(
        "Verified technician reference: {technician}\nSupport request: {session}"
    ));
    let stop = wide("Stop support");
    let button = TASKDIALOG_BUTTON {
        nButtonID: STOP_SUPPORT,
        pszButtonText: PCWSTR(stop.as_ptr()),
    };
    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER,
        pszWindowTitle: PCWSTR(title.as_ptr()),
        pszMainInstruction: PCWSTR(instruction.as_ptr()),
        pszContent: PCWSTR(content.as_ptr()),
        pszExpandedInformation: PCWSTR(details.as_ptr()),
        cButtons: 1,
        pButtons: &button,
        nDefaultButton: STOP_SUPPORT,
        pfCallback: Some(stop_callback),
        lpCallbackData: &bound as *const StopBound as isize,
        ..Default::default()
    };
    // Every exit, including API failure or unexpected destruction, cancels. A
    // failed creation also wakes the native worker without granting approval.
    if unsafe { TaskDialogIndirect(&config, None, None, None) }.is_err() {
        bound.ended();
        return;
    }
    bound.ended();
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
    #[test]
    fn persistent_stop_readiness_is_one_use_and_close_cancels_before_dismissal() {
        let (sender, ready) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let now = Instant::now();
        let bound = StopBound {
            cancelled: cancelled.clone(),
            deadline: now + Duration::from_secs(5),
            sender,
            ready_sent: Cell::new(false),
        };
        assert!(bound.ready(true, now).is_ok());
        assert_eq!(ready.recv().unwrap(), Ok(()));
        assert_eq!(
            unsafe {
                stop_callback(
                    HWND::default(),
                    TDN_BUTTON_CLICKED,
                    WPARAM(STOP_SUPPORT as usize),
                    LPARAM(0),
                    &bound as *const StopBound as isize,
                )
            },
            HRESULT(0)
        );
        assert!(cancelled.load(Ordering::Acquire));
        assert!(bound.ready(true, now).is_err());
        WindowsSessionConsent::new(cancelled.clone())
            .finish()
            .unwrap();
        let mut failed = WindowsSessionConsent::new(cancelled.clone());
        failed.thread = Some(std::thread::spawn(|| panic!("synthetic UI worker failure")));
        assert!(failed.finish().is_err());
        assert!(cancelled.load(Ordering::Acquire));
    }

    #[test]
    fn invisible_expired_cancelled_or_failed_stop_surface_never_reports_ready() {
        let now = Instant::now();
        for (visible, expired, stopped) in [
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            let (sender, ready) = mpsc::sync_channel(1);
            let cancelled = Arc::new(AtomicBool::new(stopped));
            let bound = StopBound {
                cancelled: cancelled.clone(),
                deadline: if expired {
                    now - Duration::from_secs(1)
                } else {
                    now + Duration::from_secs(5)
                },
                sender,
                ready_sent: Cell::new(false),
            };
            assert!(bound.ready(visible, now).is_err());
            assert_eq!(ready.recv().unwrap(), Err(Denied));
            assert!(cancelled.load(Ordering::Acquire));
        }
        let (sender, ready) = mpsc::sync_channel(1);
        let bound = StopBound {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: now + Duration::from_secs(5),
            sender,
            ready_sent: Cell::new(false),
        };
        assert_eq!(
            unsafe {
                stop_callback(
                    HWND::default(),
                    TDN_CREATED,
                    WPARAM(0),
                    LPARAM(0),
                    &bound as *const StopBound as isize,
                )
            },
            HRESULT(0)
        );
        assert_eq!(ready.recv().unwrap(), Err(Denied));
        assert!(bound.cancelled.load(Ordering::Acquire));
    }
}
