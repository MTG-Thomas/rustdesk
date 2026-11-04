//! Process-lifetime profile pin, adopted only after independent parent verification.
#[path = "quick_support_workstation_store.rs"]
pub mod workstation_store;
use quick_support_guard::Denied;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    sync::OnceLock,
};
use windows::Win32::{
    Foundation::{
        DuplicateHandle, GetHandleInformation, LocalFree, SetHandleInformation,
        DUPLICATE_HANDLE_OPTIONS, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HLOCAL,
    },
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation, TokenUser,
        ACCESS_ALLOWED_ACE, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct ProfilePin {
    handle: OwnedHandle,
    root: PathBuf,
    nonce: String,
    _ancestors: Vec<File>,
}
static PIN: OnceLock<ProfilePin> = OnceLock::new();

/// Must run before any Config/Server access, after authenticating the parent.
/// Retain the validated directory object until process exit, including background
/// configuration/log teardown. Isolation alone never grants session authority.
pub fn install_after_parent_verification() -> Result<(), Denied> {
    let pin = ProfilePin::capture()?;
    hbb_common::private_profile::install(pin.root.clone(), pin.nonce.clone())
        .map_err(|_| Denied)?;
    PIN.set(pin).map_err(|_| Denied)
}

/// Load only the fixed file in the pinned private profile. Issuer/install pins
/// are supplied by the signed release, never by this document or parent input.
pub fn load_launch_configuration(
    trust: quick_support_guard::LaunchTrust,
) -> Result<quick_support_guard::ControlIdentity, Denied> {
    use std::os::windows::fs::MetadataExt;
    let pin = PIN.get().ok_or(Denied)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(pin.root.join("receiver-launch.jwt"))
        .map_err(|_| Denied)?;
    let metadata = file.metadata().map_err(|_| Denied)?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() == 0
        || metadata.len() > 4096
    {
        return Err(Denied);
    }
    let mut token = String::new();
    file.by_ref()
        .take(4097)
        .read_to_string(&mut token)
        .map_err(|_| Denied)?;
    if token.len() > 4096 {
        return Err(Denied);
    }
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Denied)?
        .as_secs();
    quick_support_guard::LaunchVerifier::new(trust, pin.nonce.clone())?.verify(&token, wall)
}

impl ProfilePin {
    fn capture() -> Result<Self, Denied> {
        const VARIABLE: &str = "BIFROST_QS_PROFILE_HANDLE";
        let value = std::env::var(VARIABLE);
        std::env::remove_var(VARIABLE);
        let value = value.map_err(|_| Denied)?;
        let number = value.parse::<usize>().map_err(|_| Denied)?;
        if number == 0 || number == usize::MAX || number.to_string() != value {
            return Err(Denied);
        }
        let source = HANDLE(number as *mut std::ffi::c_void);
        let mut flags = 0;
        unsafe { GetHandleInformation(source, &mut flags) }.map_err(|_| Denied)?;
        if flags & HANDLE_FLAG_INHERIT.0 == 0 {
            return Err(Denied);
        }
        let mut copy = HANDLE::default();
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &mut copy,
                FILE_GENERIC_READ.0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| Denied)?;
        // Never adopt/close the untrusted source number: it may alias another owner.
        let handle = unsafe { OwnedHandle::from_raw_handle(copy.0) };
        unsafe { SetHandleInformation(source, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
            .map_err(|_| Denied)?;
        let root = std::env::current_dir().map_err(|_| Denied)?;
        let nonce = profile_nonce(&root)?;
        let mut pin = Self {
            handle,
            root,
            nonce,
            _ancestors: Vec::new(),
        };
        pin._ancestors = pin.validate()?;
        Ok(pin)
    }
    fn validate(&self) -> Result<Vec<File>, Denied> {
        let root = super::origin::drive_root(&self.root)?;
        if unsafe {
            windows::Win32::Storage::FileSystem::GetDriveTypeW(windows::core::PCWSTR(root.as_ptr()))
        } != 3
        {
            return Err(Denied);
        }
        let mut ancestors = Vec::new();
        let paths: Vec<_> = self.root.ancestors().skip(1).collect();
        if paths.len() > 64 {
            return Err(Denied);
        }
        // Pin from the drive root inward so an intermediate reparse point is
        // refused before attempting to traverse it.
        for path in paths.into_iter().rev() {
            let pin = OpenOptions::new()
                .read(true)
                .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(path)
                .map_err(|_| Denied)?;
            information(HANDLE(pin.as_raw_handle()))?;
            ancestors.push(pin);
        }
        let info = information(HANDLE(self.handle.as_raw_handle()))?;
        owner_only(HANDLE(self.handle.as_raw_handle()))?;
        let view = OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(&self.root)
            .map_err(|_| Denied)?;
        same_directory(&info, &information(HANDLE(view.as_raw_handle()))?)?;
        Ok(ancestors)
    }
}
fn profile_nonce(root: &Path) -> Result<String, Denied> {
    let nonce = root
        .file_name()
        .and_then(|v| v.to_str())
        .and_then(|v| v.strip_prefix("mtg-quick-support-"))
        .ok_or(Denied)?;
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Denied);
    }
    Ok(nonce.to_owned())
}
fn information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, Denied> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }.map_err(|_| Denied)?;
    if info.dwFileAttributes & 0x10 == 0 || info.dwFileAttributes & 0x400 != 0 {
        return Err(Denied);
    }
    Ok(info)
}
fn same_directory(
    a: &BY_HANDLE_FILE_INFORMATION,
    b: &BY_HANDLE_FILE_INFORMATION,
) -> Result<(), Denied> {
    if a.dwVolumeSerialNumber != b.dwVolumeSerialNumber
        || a.nFileIndexHigh != b.nFileIndexHigh
        || a.nFileIndexLow != b.nFileIndexLow
    {
        return Err(Denied);
    }
    Ok(())
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}
fn owner_only(handle: HANDLE) -> Result<(), Denied> {
    let mut owner = PSID::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(|_| Denied)?;
    let descriptor = Descriptor(descriptor);
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|_| Denied)?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let mut needed = 0;
    let _ = unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            None,
            0,
            &mut needed,
        )
    };
    if needed == 0 || needed > 65536 {
        return Err(Denied);
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            (buffer.len() * 8) as u32,
            &mut needed,
        )
    }
    .map_err(|_| Denied)?;
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    unsafe { EqualSid(owner, user.User.Sid) }.map_err(|_| Denied)?;
    let mut control = 0;
    let mut revision = 0;
    unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
        .map_err(|_| Denied)?;
    if control & SE_DACL_PROTECTED.0 == 0 || acl.is_null() || unsafe { (*acl).AceCount } != 1 {
        return Err(Denied);
    }
    let mut ace = std::ptr::null_mut();
    unsafe { GetAce(acl, 0, &mut ace) }.map_err(|_| Denied)?;
    let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    // ACCESS_ALLOWED_ACE_TYPE is zero. Require the exact inheritable owner-only ACL.
    if ace.Header.AceType != 0
        || u32::from(ace.Header.AceFlags) != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).0
    {
        return Err(Denied);
    }
    unsafe {
        EqualSid(
            PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast()),
            user.User.Sid,
        )
    }
    .map_err(|_| Denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::{ffi::OsStrExt, io::AsHandle},
        process::Command,
    };
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Security::{
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                },
                SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::CreateDirectoryW,
        },
    };

    fn secure_directory(path: &Path) {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.unwrap();
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let mut needed = 0;
        let _ = unsafe {
            GetTokenInformation(
                HANDLE(token.as_raw_handle()),
                TokenUser,
                None,
                0,
                &mut needed,
            )
        };
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        unsafe {
            GetTokenInformation(
                HANDLE(token.as_raw_handle()),
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                (buffer.len() * 8) as u32,
                &mut needed,
            )
        }
        .unwrap();
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid = PWSTR::null();
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) }.unwrap();
        let sid_string = unsafe { sid.to_string() }.unwrap();
        unsafe { LocalFree(Some(HLOCAL(sid.0.cast()))) };
        let sddl: Vec<u16> = format!("O:{sid_string}D:P(A;OICI;FA;;;{sid_string})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1,
                &mut descriptor,
                None,
            )
        }
        .unwrap();
        let descriptor = Descriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&attributes)) }.unwrap();
    }
    #[test]
    fn workstation_store_pins_private_identity_and_refuses_replacement_or_corruption() {
        use super::workstation_store::WorkstationStore;
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("qs-workstation-{}-{unique}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        assert!(WorkstationStore::open(&base).is_err());
        let root = base.join("private");
        secure_directory(&root);
        let mut store = WorkstationStore::open(&root).unwrap();
        assert!(store.load().unwrap().is_none());
        let public =
            crate::quick_support_key_store::initialize_explicitly(&mut store, || Ok([9; 32]))
                .unwrap()
                .public_key();
        assert_eq!(
            crate::quick_support_key_store::load_existing(&mut store)
                .unwrap()
                .public_key(),
            public
        );
        assert!(store.create_seed(&[7; 32]).is_err());
        assert!(OpenOptions::new()
            .write(true)
            .open(root.join("workstation.key"))
            .is_err());
        assert!(std::fs::rename(&root, base.join("replaced")).is_err());
        drop(store);
        let mut reopened = WorkstationStore::open(&root).unwrap();
        assert_eq!(reopened.load().unwrap().unwrap().public_key(), public);
        drop(reopened);
        std::fs::write(root.join("workstation.key"), [9]).unwrap();
        let mut corrupt = WorkstationStore::open(&root).unwrap();
        assert_eq!(
            corrupt.load().err().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(corrupt.create_seed(&[9; 32]).is_err());
        drop(corrupt);
        assert_eq!(std::fs::read(root.join("workstation.key")).unwrap(), [9]);
        std::fs::remove_dir_all(base).unwrap();
    }

    fn advertise(handle: &OwnedHandle) {
        unsafe {
            SetHandleInformation(
                HANDLE(handle.as_raw_handle()),
                HANDLE_FLAG_INHERIT.0,
                HANDLE_FLAG_INHERIT,
            )
        }
        .unwrap();
        std::env::set_var(
            "BIFROST_QS_PROFILE_HANDLE",
            (handle.as_raw_handle() as usize).to_string(),
        );
    }
    fn open(path: &Path) -> OwnedHandle {
        OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(path)
            .unwrap()
            .into()
    }
    #[test]
    fn directory_pin_binds_identity_acl_and_early_profile_install() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("qs-profile-pin-{}-{unique}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let root = base.join(format!("mtg-quick-support-{unique:064x}"));
        secure_directory(&root);
        let wrong = base.join(format!("mtg-quick-support-{}", "b".repeat(64)));
        std::fs::create_dir(&wrong).unwrap();
        for mode in ["private", "already-set"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "directory_pin_child", "--nocapture"])
                .env("QS_DIRECTORY_PIN_ROOT", &root)
                .env("QS_DIRECTORY_PIN_WRONG", &wrong)
                .env("QS_DIRECTORY_PIN_MODE", mode)
                .status()
                .unwrap();
            assert!(status.success());
        }
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    #[ignore = "owned process for immutable profile and cwd"]
    fn directory_pin_child() {
        let root = PathBuf::from(std::env::var_os("QS_DIRECTORY_PIN_ROOT").unwrap());
        let wrong = PathBuf::from(std::env::var_os("QS_DIRECTORY_PIN_WRONG").unwrap());
        std::env::set_current_dir(&root).unwrap();
        for value in ["", "0", "-1", "01", "not-a-handle"] {
            std::env::set_var("BIFROST_QS_PROFILE_HANDLE", value);
            assert!(ProfilePin::capture().is_err());
            assert!(std::env::var_os("BIFROST_QS_PROFILE_HANDLE").is_none());
        }
        assert!(profile_nonce(Path::new(r"C:\ordinary-profile")).is_err());
        let file_path = root.join("not-a-directory");
        std::fs::write(&file_path, []).unwrap();
        let file: OwnedHandle = File::open(&file_path).unwrap().into();
        advertise(&file);
        assert!(ProfilePin::capture().is_err());
        drop(file);
        std::fs::remove_file(file_path).unwrap();
        let handle = open(&root);
        std::env::set_var(
            "BIFROST_QS_PROFILE_HANDLE",
            (handle.as_raw_handle() as usize).to_string(),
        );
        assert!(ProfilePin::capture().is_err()); // Non-inheritable candidate.
        std::env::set_current_dir(&wrong).unwrap();
        advertise(&handle);
        assert!(ProfilePin::capture().is_err()); // Foreign cwd, despite a valid protected object.
        let wrong_handle = open(&wrong);
        advertise(&wrong_handle);
        assert!(ProfilePin::capture().is_err()); // Inherited ordinary DACL is insufficient.
        std::env::set_current_dir(&root).unwrap();
        advertise(&handle);
        let pin = ProfilePin::capture().unwrap();
        assert!(!pin._ancestors.is_empty());
        assert!(std::fs::rename(&root, root.with_extension("moved")).is_err());
        let mut flags = 0;
        unsafe { GetHandleInformation(HANDLE(pin.handle.as_raw_handle()), &mut flags) }.unwrap();
        assert_eq!(flags & HANDLE_FLAG_INHERIT.0, 0);
        assert!(same_directory(
            &information(HANDLE(handle.as_raw_handle())).unwrap(),
            &information(HANDLE(pin.handle.as_raw_handle())).unwrap()
        )
        .is_ok());
        drop(pin);
        if std::env::var("QS_DIRECTORY_PIN_MODE").unwrap() == "already-set" {
            hbb_common::private_profile::install(root.clone(), "c".repeat(64)).unwrap();
            advertise(&handle);
            assert!(install_after_parent_verification().is_err());
            return;
        }
        advertise(&handle);
        install_after_parent_verification().unwrap();
        assert_eq!(PIN.get().unwrap().root, root);
        let trust = || quick_support_guard::LaunchTrust {
            issuer: "https://support.example.test".into(),
            issuer_key: [0; 32],
            organization_id: "22222222-2222-4222-8222-222222222222".into(),
            solution_id: "33333333-3333-4333-8333-333333333333".into(),
        };
        assert!(load_launch_configuration(trust()).is_err()); // Missing fixed file.
        let launch_file = root.join("receiver-launch.jwt");
        std::fs::write(&launch_file, vec![b'x'; 4097]).unwrap();
        assert!(load_launch_configuration(trust()).is_err());
        std::fs::write(&launch_file, [0xff]).unwrap();
        assert!(load_launch_configuration(trust()).is_err());
        std::fs::remove_file(&launch_file).unwrap();
        assert!(PIN
            .get()
            .unwrap()
            .handle
            .as_handle()
            .try_clone_to_owned()
            .is_ok());
        advertise(&handle);
        assert!(install_after_parent_verification().is_err());
    }
}
