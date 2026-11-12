//! Central storage of the connection list on a WebDAV server (Nextcloud, ownCloud, IIS,
//! Synology ...). A local copy is kept, so AdminCraft also starts without the server.
//! (A network folder via SMB needs nothing here: see model::set_shared_location.)

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::model::Vault;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
/// The WebDAV password on this PC is only obfuscated with a fixed key (like browsers do
/// without a master password); the list itself can be encrypted with the master password.
const LOCAL_KEY: &str = "admincraft-remote-local";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RemoteConfig {
    /// Full address of the file, or of a folder ending in "/" (connections.json is added).
    pub url: String,
    pub user: String,
    pub password_enc: String,
}

fn local_vault() -> Vault {
    Vault::derive(LOCAL_KEY, b"admincraft-remote-salt")
}

impl RemoteConfig {
    pub fn password(&self) -> String {
        local_vault().decrypt(&self.password_enc).unwrap_or_default()
    }

    pub fn set_password(&mut self, pw: &str) {
        self.password_enc = if pw.is_empty() { String::new() } else { local_vault().encrypt(pw) };
    }

    pub fn file_url(&self) -> String {
        let u = self.url.trim();
        if u.ends_with('/') {
            format!("{u}connections.json")
        } else {
            u.to_string()
        }
    }

    fn auth(&self) -> Option<String> {
        (!self.user.is_empty()).then(|| format!("Basic {}", B64.encode(format!("{}:{}", self.user, self.password()))))
    }
}

pub fn config_path() -> PathBuf {
    crate::model::data_dir(true).join("remote.json")
}

/// Where the local copy of a WebDAV list lives.
pub fn cache_path() -> PathBuf {
    crate::model::data_dir(true).join("connections-webdav.json")
}

pub fn load_config() -> Option<RemoteConfig> {
    let text = std::fs::read_to_string(config_path()).ok()?;
    let c: RemoteConfig = serde_json::from_str(&text).ok()?;
    (!c.url.trim().is_empty()).then_some(c)
}

/// Saves (or with an empty URL removes) the WebDAV settings of this PC.
pub fn save_config(c: &RemoteConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(c).map_err(|e| e.to_string())?;
    std::fs::write(config_path(), json).map_err(|e| e.to_string())
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .http_status_as_error(false)
        .build()
        .into()
}

fn status_error(code: u16) -> String {
    match code {
        401 | 403 => tf("WebDAV server refused the login (HTTP {0}) – check user/password.", &[&code]),
        404 => tr("Folder not found on the WebDAV server (HTTP 404).").to_string(),
        _ => tf("WebDAV server reports HTTP {0}.", &[&code]),
    }
}

/// The list on the server; None when it isn't there yet.
pub fn fetch(c: &RemoteConfig) -> Result<Option<String>, String> {
    let mut req = agent().get(&c.file_url());
    if let Some(a) = c.auth() {
        req = req.header("Authorization", &a);
    }
    let mut resp = req.call().map_err(|e| tf("WebDAV not reachable: {0}", &[&e]))?;
    let code = resp.status().as_u16();
    if code == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&code) {
        return Err(status_error(code));
    }
    resp.body_mut().with_config().limit(64 * 1024 * 1024).read_to_string().map(Some).map_err(|e| e.to_string())
}

/// Writes the list to the server (creating its folder once when needed).
pub fn upload(c: &RemoteConfig, body: &str) -> Result<(), String> {
    let send = || -> Result<u16, String> {
        let mut req = agent().put(&c.file_url()).header("Content-Type", "application/json");
        if let Some(a) = c.auth() {
            req = req.header("Authorization", &a);
        }
        req.send(body).map(|r| r.status().as_u16()).map_err(|e| tf("WebDAV not reachable: {0}", &[&e]))
    };
    let mut code = send()?;
    if code == 409 || code == 404 {
        // the folder doesn't exist yet: MKCOL, then try again
        let url = c.file_url();
        if let Some(dir) = url.rsplit_once('/').map(|(d, _)| format!("{d}/")) {
            let mut b = ureq::http::Request::builder().method("MKCOL").uri(dir);
            if let Some(a) = c.auth() {
                b = b.header("Authorization", a);
            }
            if let Ok(req) = b.body(()) {
                let _ = agent().run(req);
            }
            code = send()?;
        }
    }
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(status_error(code))
    }
}

/// "Test connection": can we read (and is there already a list)?
pub fn test(c: &RemoteConfig) -> Result<String, String> {
    match fetch(c)? {
        Some(text) => Ok(tf("Connected – list found on the server ({0} KB).", &[&(text.len() / 1024).max(1)])),
        None => Ok(tr("Connected – no list on the server yet; it will be created at the next save.").to_string()),
    }
}
