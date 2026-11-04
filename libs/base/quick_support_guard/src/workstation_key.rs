use super::Denied;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

const SEED_BYTES: usize = 32;

/// Controller-side workstation signing key. The seed stays in memory only as a
/// `SigningKey`, whose `Drop` zeroizes it; the OS CSPRNG supplies new seeds.
///
/// `save` refuses to replace an existing file and creates it owner-only on
/// unix. On Windows the caller must place it in an already protected directory:
/// this module does not set an ACL, and the default inherited ACL of the chosen
/// directory is the only protection the file receives.
pub struct WorkstationKey {
    signing: SigningKey,
}

impl WorkstationKey {
    pub fn generate() -> io::Result<Self> {
        let mut seed = os_seed()?;
        let key = Self::from_seed(&seed);
        wipe(&mut seed);
        Ok(key)
    }

    /// The 32-byte receiver-facing key: unpadded base64url, 43 characters.
    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    /// Owned signer for `WorkstationLogin::new`. Signature failures cannot occur
    /// for a loaded key, so the only error is the type the login path expects.
    pub fn signer(&self) -> impl Fn(&[u8]) -> Result<[u8; 64], Denied> + Send + Sync + 'static {
        let signing = self.signing.clone();
        move |message| Ok(signing.sign(message).to_bytes())
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut seed = self.signing.to_bytes();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = options
            .open(path)
            .and_then(|mut file| file.write_all(&seed));
        wipe(&mut seed);
        result
    }

    /// Rejects a missing, unreadable, truncated or oversized file. A trailing
    /// byte is refused rather than ignored, so one representation cannot be
    /// swapped for another later.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut seed = [0u8; SEED_BYTES];
        let read = file.read_exact(&mut seed).and_then(|()| {
            let mut extra = [0u8; 1];
            match file.read(&mut extra) {
                Ok(0) => Ok(()),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "workstation key file has trailing bytes",
                )),
                Err(error) => Err(error),
            }
        });
        let key = read.map(|()| Self::from_seed(&seed));
        wipe(&mut seed);
        key
    }

    fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }
}

/// `write_volatile` keeps the compiler from eliding the clear of the temporary
/// copy that never reaches the zeroizing `SigningKey`.
fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, uniquely borrowed location.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
fn os_seed() -> io::Result<[u8; SEED_BYTES]> {
    let mut seed = [0u8; SEED_BYTES];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    Ok(seed)
}

#[cfg(windows)]
fn os_seed() -> io::Result<[u8; SEED_BYTES]> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    let mut seed = [0u8; SEED_BYTES];
    // SAFETY: `seed` is writable for `SEED_BYTES`; a null algorithm handle with
    // the system-preferred-RNG flag is the documented usage.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            seed.as_mut_ptr(),
            SEED_BYTES as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(seed)
}

#[cfg(not(any(unix, windows)))]
fn os_seed() -> io::Result<[u8; SEED_BYTES]> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no OS CSPRNG for this target",
    ))
}
