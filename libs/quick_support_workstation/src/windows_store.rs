use quick_support_guard::{Denied, WorkstationKey};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
};
use windows::Win32::{
    Foundation::{LocalFree, HANDLE, HLOCAL},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation, TokenUser,
        ACCESS_ALLOWED_ACE, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, GetDriveTypeW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Selected directory must already have the current user's protected owner-only
/// inheritable ACL. No directory or key is generated here; explicit setup must
/// separately supply and wipe an OS seed.
pub struct WorkstationStore {
    root: PathBuf,
    directory: File,
    _ancestors: Vec<File>,
    key: Option<File>,
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unqualified workstation key storage",
    )
}

/// Fixed-drive root of an absolute local path, for drive-type qualification.
pub fn drive_root(path: &Path) -> Result<[u16; 4], Denied> {
    if !path.is_absolute() {
        return Err(Denied);
    }
    let letter = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err(Denied),
        },
        _ => return Err(Denied),
    };
    Ok([u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0])
}

/// Require a directory handle that is neither a reparse point nor a non-directory.
pub fn information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, Denied> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }.map_err(|_| Denied)?;
    if info.dwFileAttributes & 0x10 == 0 || info.dwFileAttributes & 0x400 != 0 {
        return Err(Denied);
    }
    Ok(info)
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

/// Require the exact protected inheritable owner-only ACL owned by this user.
pub fn owner_only(handle: HANDLE) -> Result<(), Denied> {
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

impl crate::ProtectedKeyStore for WorkstationStore {
    fn load(&mut self) -> io::Result<Option<WorkstationKey>> {
        self.load()
    }
    fn create_new(&mut self, seed: &[u8; 32]) -> io::Result<WorkstationKey> {
        self.create_seed(seed)
    }
}

impl WorkstationStore {
    pub fn open(root: &Path) -> io::Result<Self> {
        if root.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(denied());
        }
        let drive = drive_root(root).map_err(|_| denied())?;
        if unsafe { GetDriveTypeW(windows::core::PCWSTR(drive.as_ptr())) } != 3 {
            return Err(denied());
        }
        let paths: Vec<_> = root.ancestors().collect();
        if paths.len() > 64 {
            return Err(denied());
        }
        let mut ancestors = Vec::new();
        for path in paths.into_iter().rev() {
            let file = OpenOptions::new()
                .read(true)
                .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
                .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
                .open(path)?;
            information(HANDLE(file.as_raw_handle())).map_err(|_| denied())?;
            ancestors.push(file);
        }
        let directory = ancestors.pop().ok_or_else(denied)?;
        owner_only(HANDLE(directory.as_raw_handle())).map_err(|_| denied())?;
        Ok(Self {
            root: root.into(),
            directory,
            _ancestors: ancestors,
            key: None,
        })
    }

    pub fn load(&mut self) -> io::Result<Option<WorkstationKey>> {
        owner_only(HANDLE(self.directory.as_raw_handle())).map_err(|_| denied())?;
        if self.key.is_none() {
            let file = match OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(self.root.join("workstation.key"))
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            self.key = Some(file);
        }
        let file = self.key.as_ref().ok_or_else(denied)?;
        qualify_file(&self.directory, file)?;
        if file.metadata()?.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid workstation key length",
            ));
        }
        // The retained file handle denies write/delete sharing, so the existing
        // primitive's path open cannot observe a replacement or partial write.
        WorkstationKey::load(&self.root.join("workstation.key")).map(Some)
    }

    /// Atomic create-new under the qualified inheritable ACL, before any seed
    /// bytes are written. Failed/uncertain writes remain for reconciliation.
    pub fn create_seed(&mut self, seed: &[u8; 32]) -> io::Result<WorkstationKey> {
        owner_only(HANDLE(self.directory.as_raw_handle())).map_err(|_| denied())?;
        if self.key.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        // Explicitly carry the qualified owner and protected ACL into creation:
        // an elevated token's default owner can be Administrators instead.
        let descriptor = FileDescriptor::read(&self.directory)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.value.0,
            bInheritHandle: false.into(),
        };
        let path: Vec<u16> = self
            .root
            .join("workstation.key")
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(path.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_READ,
                Some(&attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| io::Error::from_raw_os_error(error.code().0 & 0xffff))?;
        let file = unsafe { File::from_raw_handle(handle.0) };
        self.key = Some(file);
        let file = self.key.as_mut().ok_or_else(denied)?;
        qualify_file(&self.directory, file)?;
        file.write_all(seed)?;
        file.sync_all()?;
        self.load()?.ok_or_else(denied)
    }
}

struct FileDescriptor {
    value: PSECURITY_DESCRIPTOR,
    owner: PSID,
    acl: *mut ACL,
}
impl FileDescriptor {
    fn read(file: &File) -> io::Result<Self> {
        let mut result = Self {
            value: PSECURITY_DESCRIPTOR::default(),
            owner: PSID::default(),
            acl: std::ptr::null_mut(),
        };
        unsafe {
            GetSecurityInfo(
                HANDLE(file.as_raw_handle()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut result.owner),
                None,
                Some(&mut result.acl),
                None,
                Some(&mut result.value),
            )
        }
        .ok()
        .map_err(|_| denied())?;
        Ok(result)
    }
}
impl Drop for FileDescriptor {
    fn drop(&mut self) {
        if !self.value.0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(self.value.0))) };
        }
    }
}
fn qualify_file(directory: &File, file: &File) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(|_| denied())?;
    if info.dwFileAttributes & (0x10 | 0x400) != 0 || info.nNumberOfLinks != 1 {
        return Err(denied());
    }
    let root = FileDescriptor::read(directory)?;
    let key = FileDescriptor::read(file)?;
    unsafe { EqualSid(root.owner, key.owner) }.map_err(|_| denied())?;
    if key.acl.is_null() || unsafe { (*key.acl).AceCount } != 1 {
        return Err(denied());
    }
    let mut ace = std::ptr::null_mut();
    unsafe { GetAce(key.acl, 0, &mut ace) }.map_err(|_| denied())?;
    let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    if ace.Header.AceType != 0 {
        return Err(denied());
    }
    unsafe {
        EqualSid(
            PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast()),
            root.owner,
        )
    }
    .map_err(|_| denied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, os::windows::ffi::OsStrExt};
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

    struct TestDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for TestDescriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
        }
    }

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
        let descriptor = TestDescriptor(descriptor);
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
        let public = crate::initialize_explicitly(&mut store, || Ok([9; 32]))
            .unwrap()
            .public_key();
        assert_eq!(
            crate::load_existing(&mut store).unwrap().public_key(),
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
}
