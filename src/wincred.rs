//! Windows Credential Manager: the login Remote Desktop (mstsc) picks up for a host.
//!
//! Written through the Windows API and not through `cmdkey /pass:…`, so the password never
//! appears on a command line that other programs can read. The entry is removed again a moment
//! after the connection started, unless it was there before AdminCraft touched it.
#![allow(unsafe_code)] // Windows credential API; named exception in AGENTS.md

use std::time::Duration;

/// How long Remote Desktop gets to read the login before it is removed again.
const KEEP: Duration = Duration::from_secs(90);

/// Stores user and password for `target` (e.g. `TERMSRV/host`). Returns whether an entry for
/// this target existed before (then it must stay afterwards).
#[cfg(windows)]
pub fn store(target: &str, user: &str, password: &str) -> Result<bool, String> {
    use windows_sys::Win32::Security::Credentials::{CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW};
    let existed = exists(target);
    let mut target_w = wide(target);
    let mut user_w = wide(user);
    // the password as UTF-16 bytes, without the closing zero
    let mut blob: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let size = u32::try_from(blob.len()).map_err(|_| "password too long".to_string())?;
    let cred = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_w.as_mut_ptr(),
        Comment: std::ptr::null_mut(),
        LastWritten: windows_sys::Win32::Foundation::FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 },
        CredentialBlobSize: size,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: std::ptr::null_mut(),
        UserName: user_w.as_mut_ptr(),
    };
    // SAFETY: every pointer in `cred` points into a buffer that lives until after the call;
    // the strings end with a zero and the blob size matches the blob.
    let ok = unsafe { CredWriteW(&cred, 0) } != 0;
    blob.fill(0);
    if ok { Ok(existed) } else { Err(std::io::Error::last_os_error().to_string()) }
}

#[cfg(windows)]
pub fn exists(target: &str) -> bool {
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW};
    let target_w = wide(target);
    let mut found: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target_w` ends with a zero; `found` receives a buffer that is freed right below.
    unsafe {
        if CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut found) != 0 {
            CredFree(found.cast());
            true
        } else {
            false
        }
    }
}

#[cfg(windows)]
pub fn delete(target: &str) -> bool {
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CredDeleteW};
    let target_w = wide(target);
    // SAFETY: `target_w` ends with a zero and lives until after the call.
    unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) != 0 }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
pub fn store(_target: &str, _user: &str, _password: &str) -> Result<bool, String> {
    Err("only on Windows".into())
}

#[cfg(not(windows))]
pub fn delete(_target: &str) -> bool {
    false
}

/// Removes the login entry and the given temporary files a moment later, in the background:
/// the started program has read them by then, and nothing with a login stays behind.
pub fn clean_up_later(target: Option<String>, files: Vec<std::path::PathBuf>) {
    if target.is_none() && files.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(KEEP);
        if let Some(t) = target {
            delete(&t);
        }
        for f in files {
            let _ = std::fs::remove_file(f);
        }
    });
}
