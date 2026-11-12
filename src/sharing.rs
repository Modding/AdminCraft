//! Export connections to hand them to a colleague, and import such a file again.
//! Passwords: left out, in plain text (with a warning), or encrypted with an export password.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::model::{new_salt, Entry, Store, Vault};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const FORMAT: &str = "admincraft-export";
const CHECK: &str = "admincraft-export-ok";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PwMode {
    /// No passwords in the file.
    Without,
    /// Passwords readable by anyone who has the file.
    Plain,
    /// The whole content encrypted with an export password.
    Encrypted,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct ExportFile {
    format: String,
    version: u32,
    /// Seconds since 1970.
    created: u64,
    /// "none", "plain" or "encrypted".
    passwords: String,
    entries: Option<Vec<Entry>>,
    plain_passwords: Option<BTreeMap<u64, String>>,
    salt: Option<String>,
    check: Option<String>,
    payload: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Payload {
    entries: Vec<Entry>,
    passwords: BTreeMap<u64, String>,
}

/// `root` and everything below it, or all entries.
fn collect(store: &Store, root: Option<u64>) -> Vec<Entry> {
    store
        .data
        .entries
        .iter()
        .filter(|e| match root {
            None => true,
            Some(r) => e.id == r || store.is_descendant(e.id, r),
        })
        .cloned()
        .map(|mut e| {
            e.password_enc = None; // encrypted with this PC's key: useless elsewhere
            e
        })
        .collect()
}

/// Writes the export file. Returns how many connections it holds.
pub fn export(store: &Store, root: Option<u64>, mode: PwMode, export_pw: &str, path: &Path) -> Result<usize, String> {
    let entries = collect(store, root);
    if entries.is_empty() {
        return Err(tr("Nothing to export.").into());
    }
    let count = entries.iter().filter(|e| !e.folder).count();
    let passwords: BTreeMap<u64, String> = if mode == PwMode::Without {
        BTreeMap::new()
    } else {
        entries.iter().filter(|e| !e.password.is_empty()).map(|e| (e.id, e.password.clone())).collect()
    };
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut file = ExportFile { format: FORMAT.into(), version: 1, created, ..Default::default() };
    match mode {
        PwMode::Without => {
            file.passwords = "none".into();
            file.entries = Some(entries);
        }
        PwMode::Plain => {
            file.passwords = "plain".into();
            file.entries = Some(entries);
            file.plain_passwords = Some(passwords);
        }
        PwMode::Encrypted => {
            if export_pw.is_empty() {
                return Err(tr("Please enter an export password.").into());
            }
            let salt = new_salt();
            let v = Vault::derive(export_pw, &salt);
            let json = serde_json::to_string(&Payload { entries, passwords }).map_err(|e| e.to_string())?;
            file.passwords = "encrypted".into();
            file.salt = Some(B64.encode(&salt));
            file.check = Some(v.encrypt(CHECK));
            file.payload = Some(v.encrypt(&json));
        }
    }
    let text = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(path, text).map_err(|e| tf("{0}: {1}", &[&path.display(), &e]))?;
    Ok(count)
}

#[derive(Debug, PartialEq)]
pub enum ReadError {
    /// The file is encrypted: ask for the export password.
    NeedPassword,
    WrongPassword,
    Other(String),
}

/// Reads an export file: (entries, their passwords).
pub fn read(text: &str, export_pw: &str) -> Result<(Vec<Entry>, BTreeMap<u64, String>), ReadError> {
    let file: ExportFile = serde_json::from_str(text).map_err(|e| ReadError::Other(e.to_string()))?;
    if file.format != FORMAT {
        return Err(ReadError::Other(tr("This is not an AdminCraft export file.").into()));
    }
    if file.passwords == "encrypted" {
        if export_pw.is_empty() {
            return Err(ReadError::NeedPassword);
        }
        let salt = B64.decode(file.salt.unwrap_or_default()).map_err(|e| ReadError::Other(e.to_string()))?;
        let v = Vault::derive(export_pw, &salt);
        if v.decrypt(&file.check.unwrap_or_default()).as_deref() != Some(CHECK) {
            return Err(ReadError::WrongPassword);
        }
        let json = v.decrypt(&file.payload.unwrap_or_default()).ok_or(ReadError::WrongPassword)?;
        let p: Payload = serde_json::from_str(&json).map_err(|e| ReadError::Other(e.to_string()))?;
        return Ok((p.entries, p.passwords));
    }
    Ok((file.entries.unwrap_or_default(), file.plain_passwords.unwrap_or_default()))
}

#[allow(dead_code)]
pub fn is_encrypted(text: &str) -> bool {
    serde_json::from_str::<ExportFile>(text).map(|f| f.passwords == "encrypted").unwrap_or(false)
}

/// Adds imported entries under a new folder `folder_name`, with fresh ids (folders, parents
/// and jump hosts are kept together). Returns (new folder id, connections added).
pub fn merge(store: &mut Store, entries: Vec<Entry>, passwords: BTreeMap<u64, String>, folder_name: &str) -> (u64, usize) {
    let folder_id = store.next_id();
    store.data.entries.push(Entry { id: folder_id, folder: true, name: folder_name.into(), inherit_credentials: false, ..Default::default() });
    let mut map: HashMap<u64, u64> = HashMap::new();
    for e in &entries {
        map.insert(e.id, store.next_id());
    }
    let mut n = 0;
    for mut e in entries {
        let old = e.id;
        e.id = map[&old];
        e.parent = Some(e.parent.and_then(|p| map.get(&p).copied()).unwrap_or(folder_id));
        e.jump_host = e.jump_host.and_then(|j| map.get(&j).copied());
        e.password = passwords.get(&old).cloned().unwrap_or_default();
        e.password_enc = None;
        if !e.folder {
            n += 1;
        }
        store.data.entries.push(e);
    }
    (folder_id, n)
}

/// Default place for an export: the Desktop (or home).
pub fn default_path(name: &str) -> String {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(std::path::PathBuf::from).unwrap_or_default();
    let dir = if home.join("Desktop").is_dir() { home.join("Desktop") } else { home };
    let safe: String = name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    dir.join(format!("AdminCraft-{safe}.json")).display().to_string()
}
