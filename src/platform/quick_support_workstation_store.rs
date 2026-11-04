use quick_support_guard::WorkstationKey;
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Component, Path, PathBuf},
};
use windows::Win32::{
    Foundation::{LocalFree, HANDLE, HLOCAL},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAce, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    },
    Storage::FileSystem::{
        GetDriveTypeW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    },
};

/// Source-only host component. The selected directory must already have the
/// current user's protected owner-only inheritable ACL. No directory or key is
/// generated here; explicit setup must separately supply and wipe an OS seed.
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

impl WorkstationStore {
    pub fn open(root: &Path) -> io::Result<Self> {
        if root.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(denied());
        }
        let drive = super::super::origin::drive_root(root).map_err(|_| denied())?;
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
            super::information(HANDLE(file.as_raw_handle())).map_err(|_| denied())?;
            ancestors.push(file);
        }
        let directory = ancestors.pop().ok_or_else(denied)?;
        super::owner_only(HANDLE(directory.as_raw_handle())).map_err(|_| denied())?;
        Ok(Self {
            root: root.into(),
            directory,
            _ancestors: ancestors,
            key: None,
        })
    }

    pub fn load(&mut self) -> io::Result<Option<WorkstationKey>> {
        super::owner_only(HANDLE(self.directory.as_raw_handle())).map_err(|_| denied())?;
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
        super::owner_only(HANDLE(self.directory.as_raw_handle())).map_err(|_| denied())?;
        if self.key.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(self.root.join("workstation.key"))?;
        self.key = Some(file);
        let file = self.key.as_mut().ok_or_else(denied)?;
        qualify_file(&self.directory, file)?;
        file.write_all(seed)?;
        file.sync_all()?;
        self.load()?.ok_or_else(denied)
    }
}

struct Descriptor {
    value: PSECURITY_DESCRIPTOR,
    owner: PSID,
    acl: *mut ACL,
}
impl Descriptor {
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
impl Drop for Descriptor {
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
    let root = Descriptor::read(directory)?;
    let key = Descriptor::read(file)?;
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
