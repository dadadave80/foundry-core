//! Touch ID-protected keystore unlocking on macOS.
//!
//! Enrolling a keystore wraps its password with a P-256 key that lives inside the
//! Secure Enclave and is guarded by an access-control policy (Touch ID by default).
//! The wrapped password and the enclave key's encrypted `dataRepresentation` are
//! stored in a sidecar file next to the keystore JSON, which remains the canonical,
//! portable copy of the key. Unlocking asks the enclave to unwrap the password,
//! which triggers the hardware-enforced Touch ID prompt.
//!
//! This deliberately uses no macOS Keychain items: biometry-protected keychain
//! items require provisioning-profile entitlements that a plain CLI cannot carry,
//! and file-based keychain ACLs break on every binary upgrade. The Secure Enclave
//! blob is device-bound; a Mac migration or (under [`Policy::CurrentBiometry`])
//! a biometric re-enrollment invalidates it, after which the password prompt is
//! the fallback and re-enrollment recreates the sidecar.

use std::{
    ffi::CString,
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use alloy_primitives::hex;
use serde::{Deserialize, Serialize};

/// Extension of the sidecar file stored next to the keystore JSON.
const SIDECAR_EXT: &str = "touchid";
/// Current sidecar format version; bump when the on-disk schema changes.
const SIDECAR_VERSION: u32 = 1;

/// Access-control policy for the Secure Enclave wrap key.
// kebab-case so the persisted values match a future clap `ValueEnum` policy flag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    /// No user interaction; the secret is only bound to this device's Secure Enclave.
    DeviceOnly,
    /// Touch ID, with device password fallback.
    #[default]
    UserPresence,
    /// Strictly the currently enrolled biometrics; re-enrollment invalidates the key.
    CurrentBiometry,
}

impl Policy {
    const fn raw(self) -> i32 {
        match self {
            Self::DeviceOnly => 0,
            Self::UserPresence => 1,
            Self::CurrentBiometry => 2,
        }
    }
}

/// Errors produced by Touch ID keystore enrollment and unlocking.
#[derive(Debug, thiserror::Error)]
pub enum TouchIdError {
    #[error("keystore is not enrolled for Touch ID unlock")]
    NotEnrolled,
    #[error("unsupported Touch ID sidecar version {0}; re-enroll this keystore to regenerate it")]
    UnsupportedVersion(u32),
    #[error("Secure Enclave: {0}")]
    SecureEnclave(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid Touch ID sidecar: {0}")]
    InvalidSidecar(#[from] serde_json::Error),
    #[error("invalid hex in Touch ID sidecar: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("unwrapped password is not valid UTF-8")]
    InvalidPassword,
}

/// Sidecar file contents: the enclave key and the password it wraps.
#[derive(Debug, Serialize, Deserialize)]
struct Sidecar {
    version: u32,
    policy: Policy,
    /// Hex-encoded, enclave-encrypted `dataRepresentation` of the P-256 wrap key.
    se_key: String,
    /// Hex-encoded ECIES ciphertext of the keystore password.
    sealed_password: String,
}

unsafe extern "C" {
    fn foundry_se_available() -> i32;
    fn foundry_se_create(policy: i32, out: *mut *mut u8, out_len: *mut usize) -> i32;
    fn foundry_se_wrap(
        blob: *const u8,
        blob_len: usize,
        plain: *const u8,
        plain_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    fn foundry_se_unwrap(
        blob: *const u8,
        blob_len: usize,
        sealed: *const u8,
        sealed_len: usize,
        reason: *const std::ffi::c_char,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    fn foundry_se_free(ptr: *mut u8, len: usize);
}

/// Copies out a shim result buffer, frees it, and interprets it as data or an
/// error message.
///
/// # Safety
///
/// `ptr` must either be null or, together with `len`, be the out-parameter pair
/// written by a single preceding `foundry_se_*` call and not yet freed.
unsafe fn shim_result(status: i32, ptr: *mut u8, len: usize) -> Result<Vec<u8>, TouchIdError> {
    let bytes = if ptr.is_null() {
        Vec::new()
    } else {
        // SAFETY: per this function's contract, `(ptr, len)` is a live malloc'd
        // shim buffer owned by us until the `foundry_se_free` below.
        unsafe {
            let bytes = std::slice::from_raw_parts(ptr, len).to_vec();
            foundry_se_free(ptr, len);
            bytes
        }
    };
    if status == 0 {
        Ok(bytes)
    } else {
        Err(TouchIdError::SecureEnclave(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

/// Whether this machine has a usable Secure Enclave.
pub fn is_available() -> bool {
    // SAFETY: the shim function takes no arguments and only returns a flag.
    unsafe { foundry_se_available() == 1 }
}

/// Returns the sidecar path for a keystore: the keystore path with `.touchid` appended.
pub fn sidecar_path(keystore: &Path) -> PathBuf {
    let mut path = keystore.as_os_str().to_os_string();
    path.push(".");
    path.push(SIDECAR_EXT);
    PathBuf::from(path)
}

/// Whether the keystore has a Touch ID sidecar.
pub fn is_enrolled(keystore: &Path) -> bool {
    sidecar_path(keystore).exists()
}

/// Enrolls a keystore: creates a Secure Enclave wrap key under `policy` and stores
/// the wrapped `password` in the sidecar file, replacing any existing sidecar (the
/// previous wrap key and its policy are discarded). The caller is responsible for
/// having verified that `password` decrypts the keystore.
pub fn enroll(keystore: &Path, password: &str, policy: Policy) -> Result<(), TouchIdError> {
    let (mut ptr, mut len) = (std::ptr::null_mut(), 0);
    // SAFETY: the out parameters are valid for writes.
    let status = unsafe { foundry_se_create(policy.raw(), &raw mut ptr, &raw mut len) };
    // SAFETY: `(ptr, len)` were just written by `foundry_se_create` and not yet freed.
    let se_key = unsafe { shim_result(status, ptr, len) }?;

    let (mut ptr, mut len) = (std::ptr::null_mut(), 0);
    // SAFETY: input pointers are valid for their lengths for the duration of the call.
    let status = unsafe {
        foundry_se_wrap(
            se_key.as_ptr(),
            se_key.len(),
            password.as_ptr(),
            password.len(),
            &raw mut ptr,
            &raw mut len,
        )
    };
    // SAFETY: `(ptr, len)` were just written by `foundry_se_wrap` and not yet freed.
    let sealed_password = unsafe { shim_result(status, ptr, len) }?;

    let sidecar = Sidecar {
        version: SIDECAR_VERSION,
        policy,
        se_key: hex::encode(se_key),
        sealed_password: hex::encode(sealed_password),
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(sidecar_path(keystore))?;
    // `mode` only applies on creation; re-enrollment must also repair permissions.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut file, &sidecar).map_err(std::io::Error::from)?;
    Ok(())
}

/// Unwraps the keystore password from the sidecar, triggering the enclave's
/// access-control prompt (Touch ID under the default policy).
pub fn unwrap_password(keystore: &Path) -> Result<String, TouchIdError> {
    let path = sidecar_path(keystore);
    if !path.exists() {
        return Err(TouchIdError::NotEnrolled);
    }
    let raw = fs::read_to_string(path)?;
    // Gate on the version before parsing the full schema, so a future format's
    // sidecar reports its version instead of a schema mismatch.
    #[derive(Deserialize)]
    struct VersionOnly {
        version: u32,
    }
    let VersionOnly { version } = serde_json::from_str(&raw)?;
    if version != SIDECAR_VERSION {
        return Err(TouchIdError::UnsupportedVersion(version));
    }
    let sidecar: Sidecar = serde_json::from_str(&raw)?;
    let se_key = hex::decode(&sidecar.se_key)?;
    let sealed = hex::decode(&sidecar.sealed_password)?;

    let name = keystore.file_name().unwrap_or_default().to_string_lossy();
    let reason = CString::new(format!("unlock the `{name}` keystore")).unwrap_or_default();
    let (mut ptr, mut len) = (std::ptr::null_mut(), 0);
    // SAFETY: input pointers are valid for their lengths for the duration of the call.
    let status = unsafe {
        foundry_se_unwrap(
            se_key.as_ptr(),
            se_key.len(),
            sealed.as_ptr(),
            sealed.len(),
            reason.as_ptr(),
            &raw mut ptr,
            &raw mut len,
        )
    };
    // SAFETY: `(ptr, len)` were just written by `foundry_se_unwrap` and not yet freed.
    let password = unsafe { shim_result(status, ptr, len) }?;
    String::from_utf8(password).map_err(|_| TouchIdError::InvalidPassword)
}

/// Removes the keystore's sidecar, if any. Returns whether one existed.
pub fn remove(keystore: &Path) -> Result<bool, TouchIdError> {
    let path = sidecar_path(keystore);
    if path.exists() {
        fs::remove_file(path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_path_appends_extension() {
        assert_eq!(sidecar_path(Path::new("/k/deployer")), Path::new("/k/deployer.touchid"));
        // Dots in keystore names must not be treated as extensions.
        assert_eq!(
            sidecar_path(Path::new("/k/UTC--2026-07-18T00-00-00.0Z--dead")),
            Path::new("/k/UTC--2026-07-18T00-00-00.0Z--dead.touchid")
        );
    }

    #[test]
    fn enroll_and_unwrap_device_only_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = dir.path().join("deployer");
        fs::write(&keystore, "{}").unwrap();

        assert!(!is_enrolled(&keystore));
        assert!(!remove(&keystore).unwrap());
        assert!(matches!(unwrap_password(&keystore), Err(TouchIdError::NotEnrolled)));

        // DeviceOnly avoids a user-interaction prompt, exercising the full
        // create/wrap/unwrap FFI path non-interactively.
        match enroll(&keystore, "hunter2", Policy::DeviceOnly) {
            Ok(()) => {}
            // VMs and CI runners have no usable Secure Enclave; require the
            // hardware path only when explicitly opted in.
            Err(TouchIdError::SecureEnclave(e))
                if std::env::var_os("FOUNDRY_TOUCH_ID_TESTS").is_none() =>
            {
                eprintln!("skipping Secure Enclave roundtrip: {e}");
                return;
            }
            Err(e) => panic!("enroll failed: {e}"),
        }
        assert!(is_enrolled(&keystore));
        assert_eq!(unwrap_password(&keystore).unwrap(), "hunter2");

        assert!(remove(&keystore).unwrap());
        assert!(!is_enrolled(&keystore));
    }

    #[test]
    fn unsupported_sidecar_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = dir.path().join("deployer");
        fs::write(&keystore, "{}").unwrap();
        // A future format: bumped version with a policy this build doesn't know.
        fs::write(
            sidecar_path(&keystore),
            r#"{"version":2,"policy":"watch","se_key":"","sealed_password":""}"#,
        )
        .unwrap();
        assert!(matches!(unwrap_password(&keystore), Err(TouchIdError::UnsupportedVersion(2))));
    }

    /// Requires a Touch ID prompt; run manually:
    /// `cargo test -p foundry-wallets --features touch-id -- --ignored touch_id_interactive`
    #[test]
    #[ignore = "requires Touch ID user interaction"]
    fn touch_id_interactive_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = dir.path().join("deployer");
        fs::write(&keystore, "{}").unwrap();
        enroll(&keystore, "hunter2", Policy::UserPresence).unwrap();
        assert_eq!(unwrap_password(&keystore).unwrap(), "hunter2");
    }
}
