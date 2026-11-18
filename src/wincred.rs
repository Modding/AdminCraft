//! Windows Credential Manager: the login Remote Desktop (mstsc) picks up for a host.
//!
//! Written through the Windows API and not through `cmdkey /pass:…`, so the password never
//! appears on a command line that other programs can read. The entry lives only for this logon
//! session and is removed again a moment after the connection started, or when AdminCraft
//! closes. An entry that was there before is never touched: it stays as the person made it.
#![allow(unsafe_code)] // Windows credential API; named exception in AGENTS.md

use std::sync::Mutex;
use std::time::Duration;

/// How long Remote Desktop gets to read the login before it is removed again.
const KEEP: Duration = Duration::from_secs(90);

/// Entries AdminCraft wrote that are still to be removed.
static PENDING: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Stores user and password for `target` (e.g. `TERMSRV/host`), only for this logon session.
/// Returns whether an entry for this target existed before: then nothing is written (the
/// person's own entry is neither overwritten nor removed) and that entry is used.
#[cfg(windows)]
pub fn store(target: &str, user: &str, password: &str) -> Result<bool, String> {
    use windows_sys::Win32::Security::Credentials::{CRED_PERSIST_SESSION, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW};
    if exists(target) {
        return Ok(true);
    }
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
        // gone at logoff even when AdminCraft can't remove it any more
        Persist: CRED_PERSIST_SESSION,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: std::ptr::null_mut(),
        UserName: user_w.as_mut_ptr(),
    };
    // SAFETY: every pointer in `cred` points into a buffer that lives until after the call;
    // the strings end with a zero and the blob size matches the blob.
    let ok = unsafe { CredWriteW(&cred, 0) } != 0;
    blob.fill(0);
    if ok { Ok(false) } else { Err(std::io::Error::last_os_error().to_string()) }
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

/// The user name stored for `target` (tests check that an existing entry is left as it was).
#[cfg(all(windows, test))]
pub fn user_of(target: &str) -> Option<String> {
    use windows_sys::Win32::Security::Credentials::{CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW};
    let target_w = wide(target);
    let mut found: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `target_w` ends with a zero; on success `found` points to a credential the system
    // allocated, whose `UserName` is null or a zero-terminated string; it is read before the
    // buffer is freed once.
    unsafe {
        if CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut found) == 0 || found.is_null() {
            return None;
        }
        let name = (*found).UserName;
        let mut user = None;
        if !name.is_null() {
            let mut len = 0usize;
            while *name.add(len) != 0 && len < 4096 {
                len += 1;
            }
            user = Some(String::from_utf16_lossy(std::slice::from_raw_parts(name, len)));
        }
        CredFree(found.cast());
        user
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

/// Takes `target` off the list of entries still to remove; true when it was on it.
fn take_pending(target: &str) -> bool {
    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let before = pending.len();
    pending.retain(|t| t != target);
    pending.len() != before
}

/// Removes the login entry and the given temporary files a moment later, in the background:
/// the started program has read them by then, and nothing with a login stays behind. Until
/// then the entry is on the list `forget_pending` empties when AdminCraft closes.
pub fn clean_up_later(target: Option<String>, files: Vec<std::path::PathBuf>) {
    if target.is_none() && files.is_empty() {
        return;
    }
    if let Some(t) = &target {
        PENDING.lock().unwrap_or_else(|e| e.into_inner()).push(t.clone());
    }
    let job = move || {
        std::thread::sleep(KEEP);
        // already removed by `forget_pending` (AdminCraft closing): nothing more to do
        if let Some(t) = target
            && take_pending(&t)
        {
            delete(&t);
        }
        for f in files {
            let _ = std::fs::remove_file(f);
        }
    };
    // a thread that can't start leaves the entry to `forget_pending` and to the logoff
    let _ = std::thread::Builder::new().name("wincred-clean-up".into()).spawn(job);
}

/// Removes every login entry still waiting for its removal now (AdminCraft closes).
pub fn forget_pending() {
    let targets = std::mem::take(&mut *PENDING.lock().unwrap_or_else(|e| e.into_inner()));
    for t in targets {
        delete(&t);
    }
}
