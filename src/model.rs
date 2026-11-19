//! Connections, folders, settings and the encrypted, portable data file.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Generate, KeyInit};
use base64::Engine as _;
use eframe::egui::Color32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const VERIFY_TEXT: &str = "admincraft-ok";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default, Hash, PartialOrd, Ord)]
pub enum Protocol {
    #[default]
    Ssh,
    Sftp,
    Scp,
    Ftp,
    Telnet,
    Rdp,
    Vnc,
    Http,
    Https,
    PowerShell,
    LocalShell,
    Serial,
    Raw,
    Rlogin,
}

impl Protocol {
    pub const ALL: [Protocol; 14] = [
        Protocol::Ssh,
        Protocol::Sftp,
        Protocol::Scp,
        Protocol::Ftp,
        Protocol::Telnet,
        Protocol::Rdp,
        Protocol::Vnc,
        Protocol::Http,
        Protocol::Https,
        Protocol::PowerShell,
        Protocol::LocalShell,
        Protocol::Serial,
        Protocol::Raw,
        Protocol::Rlogin,
    ];

    pub fn label(self) -> &'static str {
        tr(match self {
            Protocol::Ssh => "SSH",
            Protocol::Sftp => "SFTP (files)",
            Protocol::Scp => "SCP (files)",
            Protocol::Ftp => "FTP / FTPS (files)",
            Protocol::Telnet => "Telnet",
            Protocol::Rdp => "RDP (remote desktop)",
            Protocol::Vnc => "VNC",
            Protocol::Http => "HTTP (web)",
            Protocol::Https => "HTTPS (web)",
            Protocol::PowerShell => "PowerShell remoting",
            Protocol::LocalShell => "Local shell",
            Protocol::Serial => "Serial (COM / ttyUSB)",
            Protocol::Raw => "Raw TCP",
            Protocol::Rlogin => "Rlogin",
        })
    }

    pub fn key(self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Sftp => "sftp",
            Protocol::Scp => "scp",
            Protocol::Ftp => "ftp",
            Protocol::Telnet => "telnet",
            Protocol::Rdp => "rdp",
            Protocol::Vnc => "vnc",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::PowerShell => "powershell",
            Protocol::LocalShell => "local",
            Protocol::Serial => "serial",
            Protocol::Raw => "raw",
            Protocol::Rlogin => "rlogin",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Protocol::Ssh => "SSH",
            Protocol::Sftp => "SFTP",
            Protocol::Scp => "SCP",
            Protocol::Ftp => "FTP",
            Protocol::Telnet => "TEL",
            Protocol::Rdp => "RDP",
            Protocol::Vnc => "VNC",
            Protocol::Http => "HTTP",
            Protocol::Https => "WEB",
            Protocol::PowerShell => "PS",
            Protocol::LocalShell => "SH",
            Protocol::Serial => "COM",
            Protocol::Raw => "RAW",
            Protocol::Rlogin => "RLG",
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            Protocol::Ssh => Color32::from_rgb(76, 175, 80),
            Protocol::Sftp => Color32::from_rgb(0, 150, 136),
            Protocol::Scp => Color32::from_rgb(0, 121, 107),
            Protocol::Ftp => Color32::from_rgb(205, 120, 30),
            Protocol::Telnet => Color32::from_rgb(158, 158, 158),
            Protocol::Rdp => Color32::from_rgb(33, 150, 243),
            Protocol::Vnc => Color32::from_rgb(156, 39, 176),
            Protocol::Http => Color32::from_rgb(255, 152, 0),
            Protocol::Https => Color32::from_rgb(255, 112, 67),
            Protocol::PowerShell => Color32::from_rgb(63, 81, 181),
            Protocol::LocalShell => Color32::from_rgb(121, 85, 72),
            Protocol::Serial => Color32::from_rgb(141, 110, 99),
            Protocol::Raw => Color32::from_rgb(120, 144, 156),
            Protocol::Rlogin => Color32::from_rgb(130, 130, 110),
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh | Protocol::Sftp | Protocol::Scp => 22,
            Protocol::Ftp => 21,
            Protocol::Telnet => 23,
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
            Protocol::Http => 80,
            Protocol::Https => 443,
            Protocol::PowerShell => 5985,
            Protocol::LocalShell | Protocol::Serial => 0,
            Protocol::Raw => 23,
            Protocol::Rlogin => 513,
        }
    }

    /// Runs inside a terminal tab of AdminCraft instead of an outside program.
    pub fn embedded(self) -> bool {
        matches!(self, Protocol::Ssh | Protocol::Telnet | Protocol::PowerShell | Protocol::LocalShell)
    }

    /// Opens the two-pane file transfer tab.
    pub fn transfer(self) -> bool {
        matches!(self, Protocol::Sftp | Protocol::Scp | Protocol::Ftp)
    }

    /// Speaks SSH (so it can use a jump host and SFTP/SCP transfers).
    #[allow(dead_code)]
    pub fn ssh_based(self) -> bool {
        matches!(self, Protocol::Ssh | Protocol::Sftp | Protocol::Scp)
    }

    pub fn needs_host(self) -> bool {
        self != Protocol::LocalShell
    }
}

/// Which program opens an SSH connection.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub enum SshClient {
    /// What the settings say.
    #[default]
    Default,
    /// OpenSSH in an AdminCraft terminal tab.
    Builtin,
    /// PuTTY, placed inside a tab on Windows.
    Putty,
    /// OpenSSH in its own terminal window.
    External,
}

impl SshClient {
    pub fn label(self) -> &'static str {
        tr(match self {
            SshClient::Default => "As in the settings",
            SshClient::Builtin => "Built-in terminal (OpenSSH in a tab)",
            SshClient::Putty => "PuTTY (in a tab)",
            SshClient::External => "OpenSSH in its own terminal window",
        })
    }
}

/// How AdminCraft gets from the jump host to the target.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub enum JumpMode {
    /// Logs in to the jump host and types `ssh user@target` there.
    #[default]
    Chain,
    /// OpenSSH ProxyJump (`ssh -J`): the tunnel runs through the jump host.
    ProxyJump,
}

/// Where the password of a connection comes from.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub enum CredSource {
    /// Stored (encrypted) in AdminCraft.
    #[default]
    Stored,
    /// Read from a KeePass / KeePassXC database (.kdbx).
    KeePass,
    /// Asked for every time.
    Ask,
}

impl CredSource {
    pub fn label(self) -> &'static str {
        tr(match self {
            CredSource::Stored => "In AdminCraft (encrypted)",
            CredSource::KeePass => "From KeePass database",
            CredSource::Ask => "Ask every time",
        })
    }
}

/// Which programs the file transfer tab uses for SFTP / SCP.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub enum TransferTool {
    #[default]
    Auto,
    OpenSsh,
    Putty,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeePassRef {
    /// Title or "Group/Title" path.
    Entry(String),
    /// No entry given: the first entry whose URL or title names this host.
    Host(String),
}

/// A password in memory: wiped when it goes away, never shown by `{:?}` (a log line or an error
/// report must not carry it). Reads like a `String` through `Deref`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(zeroize::Zeroizing<String>);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(zeroize::Zeroizing::new(s.into()))
    }
}

impl std::ops::Deref for Secret {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

impl std::ops::DerefMut for Secret {
    fn deref_mut(&mut self) -> &mut String {
        &mut self.0
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Secret {
        Secret::new(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Secret {
        Secret::new(s)
    }
}

impl PartialEq<&str> for Secret {
    fn eq(&self, other: &&str) -> bool {
        self.0.as_str() == *other
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() { "\"\"" } else { "<hidden>" })
    }
}

#[derive(Clone, Debug, Default)]
pub struct CredInfo {
    pub user: String,
    pub domain: String,
    pub password: Secret,
    pub keepass: Option<KeePassRef>,
    pub ask: bool,
}

/// An SSH port forwarding: localhost:local_port -> remote_host:remote_port (seen from the server).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(default)]
pub struct Tunnel {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    /// Start together with the SSH connection.
    pub auto: bool,
}

impl Default for Tunnel {
    fn default() -> Self {
        Tunnel { local_port: 8080, remote_host: "localhost".into(), remote_port: 80, auto: false }
    }
}

/// A saved terminal command; {host} {user} {name} are filled in.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Snippet {
    pub name: String,
    pub command: String,
}

pub fn default_snippets() -> Vec<Snippet> {
    let s = |n: &'static str, c: &str| Snippet { name: tr(n).into(), command: c.into() };
    vec![
        s("Disk space", "df -h"),
        s("System load", "uptime && free -h"),
        s("Updates (Debian/Ubuntu)", "sudo apt update && sudo apt list --upgradable"),
        s("Last logins", "last -n 10"),
        s("Failed services", "systemctl --failed"),
        s("Open ports", "sudo ss -tulpn"),
    ]
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(default)]
pub struct RdpOptions {
    pub width: u32,
    pub height: u32,
    pub fullscreen: bool,
    pub admin_session: bool,
    pub multimon: bool,
    pub pass_credentials: bool,
    pub redirect_drives: bool,
    pub redirect_clipboard: bool,
}

impl Default for RdpOptions {
    fn default() -> Self {
        Self {
            width: 1600,
            height: 900,
            fullscreen: false,
            admin_session: false,
            multimon: false,
            pass_credentials: true,
            redirect_drives: false,
            redirect_clipboard: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(default)]
pub struct Entry {
    pub id: u64,
    pub parent: Option<u64>,
    pub folder: bool,
    pub expanded: bool,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    #[serde(skip)]
    pub password: Secret,
    pub password_enc: Option<String>,
    /// Empty user name / domain / password are taken from the folder above.
    pub inherit_credentials: bool,
    pub description: String,
    pub ssh_key: String,
    pub extra_args: String,
    pub mac: String,
    pub rdp: RdpOptions,
    pub ssh_client: SshClient,
    /// Another connection used as jump host (SSH).
    pub jump_host: Option<u64>,
    pub jump_mode: JumpMode,
    pub cred_source: CredSource,
    /// KeePass entry: title or "Group/Subgroup/Title". Empty = matched by host.
    pub keepass_entry: String,
    /// FTP over TLS (explicit FTPS).
    pub ftp_tls: bool,
    /// Accept a self-signed FTPS certificate.
    pub tls_ignore_cert: bool,
    /// Folder the file transfer starts in (remote side).
    pub start_path: String,
    /// Serial line speed (protocol Serial; the host field holds COM3 or /dev/ttyUSB0).
    pub baud: u32,
    /// Open web pages in a tab (Edge/Chrome app window, Windows) instead of the browser.
    pub web_in_tab: bool,
    /// The browser program for this web interface; empty = the one from the settings.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub web_browser: String,
    /// SSH port forwardings of this connection.
    pub tunnels: Vec<Tunnel>,
    /// The KeePass entry or group this connection is kept in (KeePass as connection list).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub kp_id: String,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            id: 0,
            parent: None,
            folder: false,
            expanded: true,
            name: String::new(),
            protocol: Protocol::Ssh,
            host: String::new(),
            port: 22,
            username: String::new(),
            domain: String::new(),
            password: Secret::default(),
            password_enc: None,
            inherit_credentials: true,
            description: String::new(),
            ssh_key: String::new(),
            extra_args: String::new(),
            mac: String::new(),
            rdp: RdpOptions::default(),
            ssh_client: SshClient::Default,
            jump_host: None,
            jump_mode: JumpMode::Chain,
            cred_source: CredSource::Stored,
            keepass_entry: String::new(),
            ftp_tls: false,
            tls_ignore_cert: false,
            start_path: String::new(),
            baud: 9600,
            web_in_tab: false,
            web_browser: String::new(),
            tunnels: Vec::new(),
            kp_id: String::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct Settings {
    pub dark: bool,
    pub terminal_font_size: f32,
    pub auto_password: bool,
    /// Own command per protocol key (e.g. "rdp" -> "xfreerdp /v:{host}:{port} /u:{user}").
    pub templates: BTreeMap<String, String>,
    /// Own path per helper program (key from programs::PROGRAMS, e.g. "putty").
    pub programs: BTreeMap<String, String>,
    pub default_ssh_client: SshClient,
    /// Place RDP / PuTTY / VNC windows inside AdminCraft tabs (Windows).
    pub embed_windows: bool,
    pub transfer_tool: TransferTool,
    pub keepass_path: String,
    pub keepass_keyfile: String,
    /// Show hidden files (starting with ".") in the file transfer.
    pub show_hidden: bool,
    /// Saved commands for terminals.
    pub snippets: Vec<Snippet>,
    /// Open the last session's connections again at start.
    pub restore_session: bool,
    /// Write terminal sessions to text files (AdminCraftData/logs).
    pub session_log: bool,
    /// Check all hosts every N minutes (0 = off).
    pub monitor_minutes: u32,
    /// Language code ("de", "en" ...); empty = the system's language.
    pub language: String,
    /// Encrypt the whole list (names, hosts, notes) with the master password.
    pub encrypt_file: bool,
    /// The update check also offers test versions (alpha, beta, rc).
    pub update_include_pre: bool,
    /// AI agents and scripts on this computer may control the open window (`admincraft cli window`).
    pub agent_control: bool,
    /// ... and may also type into terminal tabs.
    pub agent_typing: bool,
    /// Record terminal sessions so they can be played back (AdminCraftData/recordings).
    pub record_sessions: bool,
    /// The connections live in the KeePass database `keepass_path` (group "AdminCraft").
    pub keepass_db: bool,
    /// Which kind of browser opens web interfaces in a tab (its program: `programs["browser"]`).
    pub web_family: BrowserFamily,
    /// Which browser profile web interfaces use.
    pub web_profile: WebProfile,
    /// Extra arguments for the browser, separated by spaces.
    pub web_args: String,
    /// Every HTTP/HTTPS connection opens in a tab (Windows), not only those with "Open in a tab".
    pub web_all_in_tab: bool,
}

/// The browser a web interface opens in decides the arguments AdminCraft gives it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub enum BrowserFamily {
    /// Told by the program's file name (firefox, librewolf, waterfox … = Firefox, else Chromium).
    #[default]
    Auto,
    /// Edge, Chrome, Brave, Vivaldi, Chromium, Opera: a window without tabs (`--app`).
    Chromium,
    /// Firefox and its relatives: a normal window with tabs.
    Firefox,
}

/// Where the browser keeps logins and cookies for web interfaces.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub enum WebProfile {
    /// One profile per connection in the data folder: logins stay, and goes along on the USB stick.
    #[default]
    Kept,
    /// A fresh profile per connection in the temp folder, gone after a restart of the computer.
    Temporary,
    /// The browser's normal profile (its passwords and extensions); its window can't be put into a tab.
    Normal,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dark: true,
            terminal_font_size: 14.0,
            auto_password: true,
            templates: BTreeMap::new(),
            programs: BTreeMap::new(),
            default_ssh_client: SshClient::Builtin,
            embed_windows: true,
            transfer_tool: TransferTool::Auto,
            keepass_path: String::new(),
            keepass_keyfile: String::new(),
            show_hidden: false,
            language: String::new(),
            encrypt_file: false,
            update_include_pre: true,
            agent_control: true,
            agent_typing: false,
            record_sessions: false,
            keepass_db: false,
            web_family: BrowserFamily::Auto,
            web_profile: WebProfile::Kept,
            web_args: String::new(),
            web_all_in_tab: true,
            snippets: default_snippets(),
            restore_session: false,
            session_log: false,
            monitor_minutes: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct DataFile {
    pub version: u32,
    pub salt: String,
    pub master: bool,
    pub verifier: String,
    pub next_id: u64,
    pub entries: Vec<Entry>,
    pub settings: Settings,
    /// Connections open when AdminCraft was closed: (id, "default" | "files").
    pub last_session: Vec<(u64, String)>,
}

impl Default for DataFile {
    fn default() -> Self {
        Self {
            version: 1,
            salt: String::new(),
            master: false,
            verifier: String::new(),
            next_id: 1,
            entries: Vec::new(),
            settings: Settings::default(),
            last_session: Vec::new(),
        }
    }
}

/// AES-256-GCM key derived with Argon2 from the master password (or an empty one).
#[derive(Clone)]
pub struct Vault {
    key: [u8; 32],
}

impl Vault {
    /// Fails for a salt Argon2 refuses (shorter than 8 bytes) — a salt read from a file is
    /// input like any other and must not bring the program down.
    pub fn derive(password: &str, salt: &[u8]) -> Result<Vault, String> {
        use zeroize::Zeroize;
        let mut key = [0u8; 32];
        let mut pw = format!("AdminCraft:{password}");
        let done = argon2::Argon2::default().hash_password_into(pw.as_bytes(), salt, &mut key);
        pw.zeroize();
        match done {
            Ok(()) => Ok(Vault { key }),
            Err(e) => {
                key.zeroize();
                Err(e.to_string())
            }
        }
    }

    pub fn encrypt(&self, plain: &str) -> Result<String, String> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::generate();
        let ct = cipher.encrypt(&nonce, plain.as_bytes()).map_err(|e| e.to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(B64.encode(out))
    }

    pub fn decrypt(&self, text: &str) -> Option<String> {
        let raw = B64.decode(text).ok()?;
        if raw.len() < 12 + 16 {
            return None;
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
        let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(&raw[..12]).ok()?;
        let plain = cipher.decrypt(&nonce, &raw[12..]).ok()?;
        String::from_utf8(plain).ok()
    }
}

/// The key is wiped from memory when the vault goes away.
impl Drop for Vault {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

pub fn new_salt() -> Vec<u8> {
    let a = aes_gcm::aead::Nonce::<Aes256Gcm>::generate();
    let b = aes_gcm::aead::Nonce::<Aes256Gcm>::generate();
    let mut s = a.to_vec();
    s.extend_from_slice(&b[..4]);
    s
}

pub struct Store {
    pub path: PathBuf,
    pub data: DataFile,
    pub vault: Option<Vault>,
    /// No writing at all (screenshot / check runs).
    pub read_only: bool,
    backed_up: bool,
    pub last_error: Option<String>,
    /// When the file was last read or written by us (to notice changes by others).
    pub mtime: Option<std::time::SystemTime>,
    /// Encrypted list waiting for the master password: (payload, the file's whole text).
    sealed_payload: Option<(String, String)>,
    /// The list lives on a WebDAV server (local copy in `path`).
    pub remote: Option<crate::remote::RemoteConfig>,
    /// Results of background uploads / downloads.
    pub remote_state: Arc<Mutex<RemoteState>>,
    /// Hash of the text last read or written (to see whether the server has something new,
    /// and whether someone else wrote the shared file since).
    text_hash: u64,
    /// The plain JSON last sealed (or opened) and its sealed text: an unchanged list is written
    /// byte for byte as before instead of with a fresh encryption.
    sealed_cache: Option<(String, String)>,
    /// KeePass as connection list: the key once it was entered.
    pub kdbx_key: Option<crate::kdbx::Key>,
    /// KeePass as connection list, but its password wasn't entered yet.
    kdbx_waiting: bool,
    /// When the KeePass file was last read or written by us.
    kdbx_mtime: Option<std::time::SystemTime>,
    /// KeePass ids (entries and groups) seen in the last load or save: only these may be deleted.
    kdbx_known: HashSet<String>,
    /// The list as last loaded from or saved to KeePass (without `password_enc`): an unchanged
    /// list is not written again (no key derivation for a settings-only change).
    kdbx_snapshot: Option<Vec<Entry>>,
    /// KeePass writes run in the background (a key derivation takes a moment).
    kdbx_job: std::sync::Arc<std::sync::Mutex<KdbxJob>>,
}

/// The background writer of "KeePass as connection list".
#[derive(Default)]
pub struct KdbxJob {
    busy: bool,
    /// The newest list waiting to be written (an older one waiting is replaced).
    pending: Option<KdbxWork>,
    /// What the last write gave back, for the window to take over.
    done: Option<KdbxDone>,
    /// The database as last read or written (`kdbx::save_cached`).
    cache: Option<crate::kdbx::Cache>,
    /// KeePass ids handed out so far, by AdminCraft id: a list queued before a write came back
    /// gets them too, so a new entry isn't written twice.
    ids: HashMap<u64, String>,
}

struct KdbxWork {
    path: String,
    key: crate::kdbx::Key,
    list: Vec<Entry>,
    known: HashSet<String>,
}

struct KdbxDone {
    result: Result<(), String>,
    ids: Vec<(u64, String)>,
    snapshot: Vec<Entry>,
    known: HashSet<String>,
    mtime: Option<std::time::SystemTime>,
}

impl KdbxJob {
    /// Writes queued lists until none is left (runs on the writer thread).
    fn run(job: &std::sync::Arc<std::sync::Mutex<KdbxJob>>) {
        loop {
            let (mut work, mut cache) = {
                let mut j = job.lock().unwrap_or_else(|e| e.into_inner());
                let Some(mut w) = j.pending.take() else {
                    j.busy = false;
                    return;
                };
                for e in &mut w.list {
                    if e.kp_id.is_empty()
                        && let Some(id) = j.ids.get(&e.id)
                    {
                        e.kp_id = id.clone();
                    }
                }
                (w, j.cache.take())
            };
            let result = crate::kdbx::save_cached(&mut cache, &work.path, &work.key, &mut work.list, &work.known);
            let mtime = std::fs::metadata(work.path.trim().trim_matches('"')).and_then(|m| m.modified()).ok();
            let mut j = job.lock().unwrap_or_else(|e| e.into_inner());
            j.cache = cache;
            let ids: Vec<(u64, String)> = work.list.iter().filter(|e| !e.kp_id.is_empty()).map(|e| (e.id, e.kp_id.clone())).collect();
            if result.is_ok() {
                j.ids.extend(ids.iter().cloned());
            }
            j.done = Some(KdbxDone {
                known: if result.is_ok() { kdbx_ids(&work.list) } else { work.known.clone() },
                snapshot: kdbx_snapshot_of(&work.list),
                ids,
                result,
                mtime,
            });
        }
    }
}

#[derive(Default)]
pub struct RemoteState {
    pub busy: bool,
    pub last_error: Option<String>,
    pub last_ok: Option<std::time::SystemTime>,
    /// A newer list fetched from the server, waiting to be applied.
    pub fetched: Option<String>,
    /// Counts saves: a server copy fetched by a request that started before the latest save is
    /// older than what we have and is thrown away.
    pub saves: u64,
    /// The upload worker is running.
    pub uploading: bool,
    /// The newest text waiting for the upload worker.
    pub pending_upload: Option<String>,
    /// The newest text whose upload failed: sent again before the server is asked for news.
    pub unsent: Option<String>,
}

impl RemoteState {
    /// The answer of a poll that started at save count `started`.
    pub fn poll_done(&mut self, started: u64, res: Result<Option<String>, String>) {
        self.busy = false;
        match res {
            Ok(Some(t)) => {
                // a save since the request started (or one still on its way to the server):
                // what came back is older than our list
                if self.saves == started && !self.uploading && self.pending_upload.is_none() && self.unsent.is_none() {
                    self.fetched = Some(t);
                }
                self.last_error = None;
            }
            Ok(None) => self.last_error = None,
            Err(e) => self.last_error = Some(e),
        }
    }
}

/// Sends `text` to the WebDAV server. One worker per store sends the texts in order and always
/// the newest one waiting, so a quick second save never arrives before the first.
fn queue_upload(state: &Arc<Mutex<RemoteState>>, r: crate::remote::RemoteConfig, text: String) {
    {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.pending_upload = Some(text);
        st.unsent = None;
        if st.uploading {
            return;
        }
        st.uploading = true;
    }
    let worker_state = state.clone();
    let spawned = std::thread::Builder::new().name("webdav-upload".into()).spawn(move || {
        loop {
            let next = {
                let mut st = worker_state.lock().unwrap_or_else(|e| e.into_inner());
                match st.pending_upload.take() {
                    Some(t) => t,
                    None => {
                        st.uploading = false;
                        break;
                    }
                }
            };
            let res = crate::remote::upload(&r, &next);
            let mut st = worker_state.lock().unwrap_or_else(|e| e.into_inner());
            match res {
                Ok(()) => {
                    st.last_error = None;
                    st.last_ok = Some(std::time::SystemTime::now());
                }
                Err(e) => {
                    st.last_error = Some(e);
                    if st.pending_upload.is_none() {
                        st.unsent = Some(next);
                    }
                }
            }
        }
    });
    if let Err(e) = spawned {
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.uploading = false;
        st.unsent = st.pending_upload.take();
        st.last_error = Some(e.to_string());
    }
}

/// Writes `text` to a temporary file next to `path` with a name no other instance uses, flushes
/// it to the disk and renames it over `path`: a crash or a second writer never leaves half a file.
pub fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut rnd = [0u8; 8];
    let _ = getrandom::fill(&mut rnd);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let tag: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let base = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "connections.json".into());
    let tmp = path.with_file_name(format!("{base}.{}-{tag}{nanos:x}.tmp", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| e.to_string())
}

/// A free id: above all ids in use and not below `next`; when the ids reach `u64::MAX`, the
/// first unused one from `next` on. Moves `next` past the id it returns.
fn take_free_id(entries: &[Entry], next: &mut u64) -> u64 {
    let max = entries.iter().map(|e| e.id).max().unwrap_or(0);
    let id = match max.checked_add(1) {
        Some(above) => (*next).max(above),
        None => {
            let used: HashSet<u64> = entries.iter().map(|e| e.id).collect();
            let start = (*next).max(1);
            (start..u64::MAX).chain(1..start).find(|i| !used.contains(i)).unwrap_or(0)
        }
    };
    *next = id.saturating_add(1);
    id
}

/// An entry whose parent chain leads back to itself goes to `fallback` (so deleting or drawing
/// it can't loop).
pub fn break_parent_cycles(entries: &mut [Entry], fallback: Option<u64>) {
    let mut parent_of: HashMap<u64, Option<u64>> = entries.iter().map(|e| (e.id, e.parent)).collect();
    let limit = entries.len() + 1;
    for e in entries.iter_mut() {
        let me = e.id;
        let mut cur = e.parent;
        let mut steps = 0;
        let mut looped = false;
        while let Some(p) = cur {
            if p == me {
                looped = true;
                break;
            }
            steps += 1;
            if steps > limit {
                // a loop further up: the entries on it are fixed when they come
                break;
            }
            cur = parent_of.get(&p).copied().flatten();
        }
        if looped {
            e.parent = fallback.filter(|&f| f != me);
            parent_of.insert(me, e.parent);
        }
    }
}

/// The list as KeePass sees it (without what this PC encrypted).
fn kdbx_snapshot_of(list: &[Entry]) -> Vec<Entry> {
    list.iter().map(|e| Entry { password_enc: None, ..e.clone() }).collect()
}

fn same_as_snapshot(snapshot: &[Entry], list: &[Entry]) -> bool {
    snapshot.len() == list.len()
        && snapshot.iter().zip(list).all(|(a, b)| a.password_enc.is_none() && *a == Entry { password_enc: None, ..b.clone() })
}

fn kdbx_ids(list: &[Entry]) -> HashSet<String> {
    list.iter().filter(|e| !e.kp_id.is_empty()).map(|e| e.kp_id.clone()).collect()
}

/// KeePass already holds connections and so does the list: ours stay as they are; theirs that
/// aren't in ours (same KeePass id, or same kind, name and host) are added with new ids. A
/// matching entry of ours takes over the KeePass id, so KeePass gets no copy of it.
fn add_missing_from_keepass(ours: &mut Vec<Entry>, theirs: Vec<Entry>, next: &mut u64) -> usize {
    let their_ids: HashSet<String> = kdbx_ids(&theirs);
    let mut taken: HashSet<usize> = HashSet::new();
    let mut map: HashMap<u64, u64> = HashMap::new();
    let mut new: Vec<Entry> = Vec::new();
    for t in &theirs {
        let by_id = (!t.kp_id.is_empty()).then(|| ours.iter().position(|o| o.kp_id == t.kp_id)).flatten().filter(|i| !taken.contains(i));
        let found = by_id.or_else(|| {
            ours.iter().enumerate().position(|(i, o)| {
                !taken.contains(&i)
                    && (o.kp_id.is_empty() || !their_ids.contains(o.kp_id.as_str()))
                    && o.folder == t.folder
                    && o.name == t.name
                    && o.host == t.host
            })
        });
        match found.and_then(|i| ours.get_mut(i).map(|o| (i, o))) {
            Some((i, o)) => {
                taken.insert(i);
                o.kp_id = t.kp_id.clone();
                map.insert(t.id, o.id);
            }
            None => {
                // `next` moves on with every id, so the new ones never repeat
                let id = take_free_id(ours, next);
                map.insert(t.id, id);
                new.push(Entry { id, ..t.clone() });
            }
        }
    }
    for n in &mut new {
        n.parent = n.parent.and_then(|p| map.get(&p).copied());
        n.jump_host = n.jump_host.and_then(|j| map.get(&j).copied());
    }
    let added = new.len();
    ours.extend(new);
    break_parent_cycles(ours, None);
    added
}

/// The whole list encrypted with the master password (names and hosts too).
#[derive(Serialize, Deserialize)]
struct SealedFile {
    format: String,
    version: u32,
    salt: String,
    verifier: String,
    payload: String,
}

const SEALED_FORMAT: &str = "admincraft-encrypted";

fn hash_text(t: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

/// Portable first: a folder next to the program. Falls back to the home folder when that
/// place can't be written (e.g. inside a macOS app bundle or a read-only share).
pub fn data_dir(create: bool) -> PathBuf {
    if let Some(dir) = std::env::args().skip_while(|a| a != "--data").nth(1) {
        return PathBuf::from(dir);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let d = dir.join("AdminCraftData");
        if d.is_dir() {
            return d;
        }
        if create && std::fs::create_dir_all(&d).is_ok() {
            let probe = d.join(".write-test");
            if std::fs::write(&probe, b"ok").is_ok() {
                let _ = std::fs::remove_file(probe);
                return d;
            }
        } else if !create && dir_writable(dir) {
            return d;
        }
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".admincraft")
}

/// Where the connection list lives: normally the data folder, or the folder named in
/// `location.txt` there (a team list on a network share).
pub fn connections_file(create: bool) -> PathBuf {
    let local = data_dir(create);
    if let Ok(text) = std::fs::read_to_string(local.join("location.txt")) {
        let dir = text.trim().trim_matches('"');
        if !dir.is_empty() {
            return PathBuf::from(dir).join("connections.json");
        }
    }
    local.join("connections.json")
}

/// Points the connection list at another folder (empty = back to the local one). The current
/// list is copied there when that folder has none yet.
pub fn set_shared_location(dir: &str, current: &Path) -> Result<(), String> {
    let local = data_dir(true);
    let dir = dir.trim().trim_matches('"');
    if dir.is_empty() {
        let _ = std::fs::write(local.join("location.txt"), "");
        return Ok(());
    }
    let target = PathBuf::from(dir);
    std::fs::create_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))?;
    let file = target.join("connections.json");
    if !file.exists() && current.exists() {
        std::fs::copy(current, &file).map_err(|e| e.to_string())?;
    }
    std::fs::write(local.join("location.txt"), dir).map_err(|e| e.to_string())
}

pub fn shared_location() -> String {
    std::fs::read_to_string(data_dir(false).join("location.txt")).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn dir_writable(dir: &Path) -> bool {
    std::fs::metadata(dir).map(|m| !m.permissions().readonly()).unwrap_or(false)
}

impl Store {
    pub fn open(read_only: bool) -> Store {
        let remote = crate::remote::load_config();
        let path = if remote.is_some() { crate::remote::cache_path() } else { connections_file(!read_only) };
        // a WebDAV password under the master password opens only with it: then the local copy
        // is shown first and the server asked once the list is unlocked
        let server = remote.as_ref().filter(|r| !r.needs_unlock()).map(crate::remote::fetch);
        let mut store = Store::open_at(path, remote, server, read_only);
        // command line / MCP server: the master password may come from the environment
        if store.vault.is_none()
            && let Ok(pw) = std::env::var("AC_MASTER")
            && store.unlock(&pw)
        {
            // no window that polls later: take the server's list right now
            if let Some(r) = store.remote.clone()
                && let Ok(Some(t)) = crate::remote::fetch(&r)
                && store.replace_if_same_key(&t)
                && !store.read_only
            {
                let _ = write_atomic(&store.path, &t);
            }
        }
        if store.kdbx_waiting
            && let Ok(pw) = std::env::var("AC_KEEPASS")
        {
            store.unlock_keepass(&pw);
        }
        store
    }

    /// Opens the list in `path`. With WebDAV, `server` is the server's answer (`Ok(None)`: it has
    /// no list yet).
    pub fn open_at(
        path: PathBuf,
        remote: Option<crate::remote::RemoteConfig>,
        server: Option<Result<Option<String>, String>>,
        read_only: bool,
    ) -> Store {
        let mut store = Store {
            path: path.clone(),
            data: DataFile::default(),
            vault: None,
            read_only,
            backed_up: false,
            mtime: None,
            last_error: None,
            sealed_payload: None,
            remote,
            remote_state: Default::default(),
            text_hash: 0,
            sealed_cache: None,
            kdbx_key: None,
            kdbx_waiting: false,
            kdbx_mtime: None,
            kdbx_known: HashSet::new(),
            kdbx_snapshot: None,
            kdbx_job: Default::default(),
        };
        // WebDAV: the server's list wins; without the server the local copy is used
        let mut server_has_none = false;
        match server {
            Some(Ok(Some(t))) => {
                match store.load_text(&t) {
                    // the local copy is replaced only by a list that could be read
                    Ok(()) => {
                        if !read_only && let Err(e) = write_atomic(&path, &t) {
                            store.last_error = Some(tf("Saving failed: {0}", &[&e]));
                        }
                    }
                    Err(e) => {
                        store.last_error = Some(tf("File could not be read: {0}", &[&e]));
                        store.read_only = true;
                    }
                }
                store.wait_for_keepass();
                return store;
            }
            Some(Ok(None)) => server_has_none = true,
            Some(Err(e)) => store.last_error = Some(tf("{0} – using the local copy.", &[&e])),
            None => {}
        }
        store.mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                if let Err(e) = store.load_text(&text) {
                    store.last_error = Some(tf("File could not be read: {0}", &[&e]));
                    store.read_only = true;
                }
            }
            // a new installation (with WebDAV: only when the server has no list either)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && (store.remote.is_none() || server_has_none) => {
                store.data = sample_data();
                store.data.salt = B64.encode(new_salt());
                let salt = store.salt();
                store.vault = Vault::derive("", &salt).ok();
                if !read_only {
                    store.save();
                }
            }
            // the list is there but can't be read now (network share away, no rights, damaged):
            // never put the sample list in its place
            Err(e) => {
                let msg = tf("File could not be read: {0}", &[&e]);
                store.last_error = Some(match store.last_error.take() {
                    Some(before) => format!("{before} {msg}"),
                    None => msg,
                });
                store.read_only = true;
                let salt = store.salt();
                store.vault = Vault::derive("", &salt).ok();
            }
        }
        store.wait_for_keepass();
        store
    }

    /// Reads the list from KeePass and keeps the opened database for the next save.
    fn kdbx_load(&mut self, path: &str, key: &crate::kdbx::Key) -> Result<Vec<Entry>, String> {
        let (list, cache) = crate::kdbx::load_cached(path, key)?;
        let mut j = self.kdbx_job.lock().unwrap_or_else(|e| e.into_inner());
        // a write still going on brings its own (newer) database
        if !j.busy {
            j.cache = Some(cache);
        }
        Ok(list)
    }

    /// Hands the list to the KeePass writer (started when it is idle).
    fn queue_kdbx(&mut self, path: String, key: crate::kdbx::Key) -> Result<(), String> {
        let work = KdbxWork { path, key, list: self.data.entries.clone(), known: self.kdbx_known.clone() };
        let start = {
            let mut j = self.kdbx_job.lock().unwrap_or_else(|e| e.into_inner());
            j.pending = Some(work);
            !std::mem::replace(&mut j.busy, true)
        };
        if start {
            let job = self.kdbx_job.clone();
            if std::thread::Builder::new().name("keepass-save".into()).spawn(move || KdbxJob::run(&job)).is_err() {
                // no thread: write it here, as before
                KdbxJob::run(&self.kdbx_job);
            }
        }
        Ok(())
    }

    /// Takes over what the KeePass writer finished: KeePass ids of new entries, the ids KeePass
    /// knows, the file's time, an error. True while a write is still going on.
    pub fn poll_kdbx(&mut self) -> bool {
        let (done, busy) = {
            let mut j = self.kdbx_job.lock().unwrap_or_else(|e| e.into_inner());
            (j.done.take(), j.busy || j.pending.is_some())
        };
        if let Some(d) = done {
            let ids: HashMap<u64, String> = d.ids.into_iter().collect();
            for e in &mut self.data.entries {
                if e.kp_id.is_empty()
                    && let Some(k) = ids.get(&e.id)
                {
                    e.kp_id = k.clone();
                }
            }
            match d.result {
                Ok(()) => {
                    self.kdbx_known = d.known;
                    self.kdbx_mtime = d.mtime;
                    if !busy {
                        self.kdbx_snapshot = Some(d.snapshot);
                    }
                }
                Err(e) => {
                    self.last_error = Some(tf("Saving failed: {0}", &[&e]));
                    // written again with the next save
                    self.kdbx_snapshot = None;
                }
            }
        }
        busy
    }

    /// Waits (at most `max`) for the KeePass writer, e.g. before AdminCraft closes. True when
    /// everything is written.
    pub fn wait_for_kdbx(&mut self, max: std::time::Duration) -> bool {
        let until = std::time::Instant::now() + max;
        while self.poll_kdbx() {
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        true
    }

    /// KeePass as connection list: the connections come from KeePass once its password is given.
    fn wait_for_keepass(&mut self) {
        if self.kdbx_mode() && self.kdbx_key.is_none() && !self.kdbx_waiting {
            self.data.entries.clear();
            self.kdbx_waiting = true;
        }
    }

    /// The connections live in a KeePass database (Settings » Password vault).
    pub fn kdbx_mode(&self) -> bool {
        self.data.settings.keepass_db && !self.data.settings.keepass_path.trim().is_empty()
    }

    /// The list is open, only the KeePass password is still missing.
    pub fn waiting_for_keepass(&self) -> bool {
        self.vault.is_some() && self.kdbx_waiting
    }

    /// Opens the connection list in the KeePass database.
    pub fn unlock_keepass(&mut self, password: &str) -> bool {
        let key = crate::kdbx::Key { password: password.to_string(), keyfile: self.data.settings.keepass_keyfile.clone() };
        match self.kdbx_load(&self.data.settings.keepass_path.clone(), &key) {
            Ok(list) => {
                self.kdbx_loaded(list);
                self.kdbx_key = Some(key);
                self.kdbx_waiting = false;
                self.last_error = None;
                true
            }
            Err(e) => {
                self.last_error = Some(e);
                false
            }
        }
    }

    /// The list as it is in KeePass now (just read or written).
    fn kdbx_loaded(&mut self, list: Vec<Entry>) {
        self.kdbx_known = kdbx_ids(&list);
        self.kdbx_snapshot = Some(kdbx_snapshot_of(&list));
        self.data.entries = list;
        self.kdbx_mtime = std::fs::metadata(self.data.settings.keepass_path.trim().trim_matches('"')).and_then(|m| m.modified()).ok();
    }

    /// Switches to KeePass as connection list. An empty list takes the database's AdminCraft
    /// connections; otherwise the list is written into the database, and connections the
    /// database already holds but the list doesn't are added (nothing is replaced). The list as
    /// it was is kept in a backup file first.
    pub fn use_keepass(&mut self, key: crate::kdbx::Key) -> Result<String, String> {
        let path = self.data.settings.keepass_path.clone();
        let there = self.kdbx_load(&path, &key)?;
        let msg = if self.data.entries.is_empty() {
            let n = there.len();
            self.kdbx_loaded(there);
            tf("{0} entries loaded from the KeePass database.", &[&n])
        } else {
            let mut backup = None;
            let mut list = self.data.entries.clone();
            let mut added = 0;
            if !there.is_empty() {
                backup = Some(self.backup_before_keepass()?);
                added = add_missing_from_keepass(&mut list, there, &mut self.data.next_id);
            }
            // no KeePass id counts as known: this first save deletes nothing in the database
            // from the database just read: one key derivation, not two
            let mut cache = self.kdbx_job.lock().unwrap_or_else(|e| e.into_inner()).cache.take();
            crate::kdbx::save_cached(&mut cache, &path, &key, &mut list, &HashSet::new())?;
            self.kdbx_job.lock().unwrap_or_else(|e| e.into_inner()).cache = cache;
            self.kdbx_loaded(list);
            match backup {
                Some(b) => tf(
                    "{0} entries kept, {1} added from the KeePass database. The list as it was is in {2}.",
                    &[&self.data.entries.len().saturating_sub(added), &added, &b.display()],
                ),
                None => tf("{0} entries moved into the KeePass database (group \"AdminCraft\").", &[&self.data.entries.len()]),
            }
        };
        self.data.settings.keepass_db = true;
        self.kdbx_key = Some(key);
        self.kdbx_waiting = false;
        self.save();
        Ok(msg)
    }

    /// Writes the list as it is now and copies it next to itself before KeePass takes over.
    fn backup_before_keepass(&mut self) -> Result<PathBuf, String> {
        self.save();
        if let Some(e) = self.last_error.clone() {
            return Err(e);
        }
        let to = self.path.with_extension("json.before-keepass");
        std::fs::copy(&self.path, &to).map_err(|e| tf("Backup failed: {0}", &[&e]))?;
        Ok(to)
    }

    /// Back to AdminCraft's own file: the connections now open are kept there.
    pub fn stop_using_keepass(&mut self) {
        self.data.settings.keepass_db = false;
        self.kdbx_key = None;
        self.kdbx_waiting = false;
        self.kdbx_known.clear();
        self.kdbx_snapshot = None;
        self.save();
    }

    /// Reads a list (plain, or sealed with the master password). A vault that still fits is
    /// kept, so a reload doesn't ask for the password again (nor derives the key again).
    fn load_text(&mut self, text: &str) -> Result<(), String> {
        self.text_hash = hash_text(text);
        self.sealed_cache = None;
        if let Ok(sealed) = serde_json::from_str::<SealedFile>(text)
            && sealed.format == SEALED_FORMAT
        {
            let keep = self.vault.clone().filter(|v| self.data.salt == sealed.salt && v.decrypt(&sealed.verifier).as_deref() == Some(VERIFY_TEXT));
            self.data = DataFile { salt: sealed.salt, master: true, verifier: sealed.verifier, ..Default::default() };
            self.sealed_payload = Some((sealed.payload, text.to_string()));
            self.vault = None;
            if let Some(v) = keep {
                self.open_sealed(v)?;
            }
            return Ok(());
        }
        let data = serde_json::from_str::<DataFile>(text).map_err(|e| e.to_string())?;
        let keep = self.vault.clone().filter(|v| {
            data.salt == self.data.salt
                && if data.master {
                    v.decrypt(&data.verifier).as_deref() == Some(VERIFY_TEXT)
                } else {
                    // the vault of a list without master password comes from the empty one
                    !self.data.master
                }
        });
        self.sealed_payload = None;
        self.data = data;
        if !self.data.master {
            self.vault = match keep {
                Some(v) => Some(v),
                None => Vault::derive("", &self.salt()).ok(),
            };
        } else {
            self.vault = keep;
        }
        if self.vault.is_some() {
            self.decrypt_all();
        }
        self.repair_ids();
        Ok(())
    }

    fn open_sealed(&mut self, v: Vault) -> Result<(), String> {
        let Some((payload, text)) = self.sealed_payload.take() else { return Ok(()) };
        let json = v.decrypt(&payload).ok_or_else(|| tr("The encrypted list doesn't match the master password.").to_string())?;
        let data = serde_json::from_str::<DataFile>(&json).map_err(|e| e.to_string())?;
        self.data = data;
        self.vault = Some(v);
        self.decrypt_all();
        self.sealed_cache = Some((json, text));
        self.repair_ids();
        Ok(())
    }

    /// A damaged or hand-edited file: a repeated id gets a new one (nothing is dropped), and an
    /// entry whose parents lead back to itself goes to the top level.
    fn repair_ids(&mut self) {
        let mut seen = HashSet::new();
        let repeated: Vec<usize> = self.data.entries.iter().enumerate().filter(|(_, e)| !seen.insert(e.id)).map(|(i, _)| i).collect();
        for i in repeated {
            let id = self.next_id();
            if let Some(e) = self.data.entries.get_mut(i) {
                e.id = id;
            }
        }
        break_parent_cycles(&mut self.data.entries, None);
    }

    /// Someone else (a colleague on the shared list) saved the file: read it again.
    /// Returns true when the data was replaced.
    pub fn reload_if_changed(&mut self) -> bool {
        // our own KeePass write is still going on: its file is not a change by someone else
        if self.kdbx_mode() && self.poll_kdbx() {
            return false;
        }
        if self.kdbx_mode() {
            // the list is in KeePass: reload when KeePass (or a colleague) saved the file
            let Some(key) = self.kdbx_key.clone() else { return false };
            let path = self.data.settings.keepass_path.trim().trim_matches('"').to_string();
            let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) else { return false };
            if self.kdbx_mtime == Some(m) {
                return false;
            }
            self.kdbx_mtime = Some(m);
            return match self.kdbx_load(&path, &key) {
                Ok(list) if list != self.data.entries => {
                    self.kdbx_loaded(list);
                    true
                }
                _ => false,
            };
        }
        // while locked nothing is taken: the change is read after unlocking
        if self.locked() {
            return false;
        }
        if self.remote.is_some() {
            return self.apply_fetched();
        }
        let Ok(m) = std::fs::metadata(&self.path).and_then(|m| m.modified()) else { return false };
        if self.mtime.is_none() {
            self.mtime = Some(m);
            return false;
        }
        if self.mtime == Some(m) {
            return false;
        }
        self.mtime = Some(m);
        let Ok(text) = std::fs::read_to_string(&self.path) else { return false };
        self.replace_if_same_key(&text)
    }

    fn replace_if_same_key(&mut self, text: &str) -> bool {
        if hash_text(text) == self.text_hash || self.locked() {
            return false;
        }
        let before = (self.data.salt.clone(), self.data.master);
        // what `load_text` compares (salt, master, check text) stays, so the vault can be kept
        let placeholder =
            DataFile { salt: self.data.salt.clone(), master: self.data.master, verifier: self.data.verifier.clone(), ..Default::default() };
        let backup = std::mem::replace(&mut self.data, placeholder);
        let vault = self.vault.clone();
        let hash = self.text_hash;
        let cache = self.sealed_cache.take();
        match self.load_text(text) {
            Ok(()) if self.vault.is_some() && (self.data.salt.clone(), self.data.master) == before => true,
            _ => {
                // another key or unreadable: keep ours (and remember that the file isn't ours)
                self.data = backup;
                self.vault = vault;
                self.sealed_payload = None;
                self.text_hash = hash;
                self.sealed_cache = cache;
                false
            }
        }
    }

    #[cfg(test)]
    pub fn reload_from_disk_for_test(&mut self) -> bool {
        let Ok(text) = std::fs::read_to_string(&self.path) else { return false };
        self.load_text(&text).is_ok()
    }

    /// WebDAV: asks the server in the background whether there is a newer list.
    pub fn poll_remote(&self) {
        let Some(r) = self.remote.clone() else { return };
        let state = self.remote_state.clone();
        let (started, unsent) = {
            let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
            // busy, or our own change is still on its way: the server's copy is older than ours
            if st.busy || st.uploading || st.pending_upload.is_some() {
                return;
            }
            match st.unsent.take() {
                Some(t) => (0, Some(t)),
                None => {
                    st.busy = true;
                    (st.saves, None)
                }
            }
        };
        // an upload failed: send it again before asking the server for news
        if let Some(t) = unsent {
            if !self.read_only {
                queue_upload(&state, r, t);
            }
            return;
        }
        let worker_state = state.clone();
        let spawned = std::thread::Builder::new().name("webdav-poll".into()).spawn(move || {
            let res = crate::remote::fetch(&r);
            worker_state.lock().unwrap_or_else(|e| e.into_inner()).poll_done(started, res);
        });
        if spawned.is_err() {
            state.lock().unwrap_or_else(|e| e.into_inner()).busy = false;
        }
    }

    fn apply_fetched(&mut self) -> bool {
        let fetched = self.remote_state.lock().unwrap_or_else(|e| e.into_inner()).fetched.take();
        match fetched {
            Some(t) => {
                let changed = self.replace_if_same_key(&t);
                // the local copy only takes a list that could be read
                if changed
                    && !self.read_only
                    && let Err(e) = write_atomic(&self.path, &t)
                {
                    self.last_error = Some(tf("Saving failed: {0}", &[&e]));
                }
                changed
            }
            None => false,
        }
    }

    pub fn salt(&self) -> Vec<u8> {
        let s = B64.decode(&self.data.salt).unwrap_or_default();
        if s.len() >= 8 { s } else { b"admincraft-salt!".to_vec() }
    }

    pub fn locked(&self) -> bool {
        self.vault.is_none() || self.kdbx_waiting
    }

    pub fn unlock(&mut self, password: &str) -> bool {
        if self.waiting_for_keepass() {
            return self.unlock_keepass(password);
        }
        let Ok(vault) = Vault::derive(password, &self.salt()) else { return false };
        if vault.decrypt(&self.data.verifier).as_deref() != Some(VERIFY_TEXT) {
            return false;
        }
        if self.sealed_payload.is_some() {
            if let Err(e) = self.open_sealed(vault) {
                self.last_error = Some(e);
                return false;
            }
            // the settings were sealed too: only now it shows that KeePass holds the list
            self.wait_for_keepass();
        } else {
            self.vault = Some(vault);
            self.decrypt_all();
        }
        self.remote_after_unlock();
        true
    }

    /// WebDAV after the master password was entered: open the sealed server password and ask
    /// the server; a password still under the fixed key moves under the list's key.
    fn remote_after_unlock(&mut self) {
        let Some(vault) = self.vault.clone() else { return };
        let master = self.data.master;
        let Some(r) = self.remote.as_mut() else { return };
        if r.needs_unlock() {
            if r.open_sealed(&vault) {
                self.poll_remote();
            } else {
                self.last_error = Some(tr("The WebDAV password doesn't open with this master password (was it changed on another computer?). Enter it again in Settings » Storage location.").into());
            }
        } else if master && !r.password_enc.is_empty() && r.protect(Some(&vault)) && !self.read_only {
            let _ = crate::remote::save_config(r);
        }
    }

    fn decrypt_all(&mut self) {
        let Some(v) = self.vault.clone() else { return };
        for e in &mut self.data.entries {
            e.password = e.password_enc.as_deref().and_then(|p| v.decrypt(p)).map(Secret::new).unwrap_or_default();
        }
    }

    /// Sets, changes (non-empty) or removes (empty) the master password.
    pub fn set_master(&mut self, password: &str) {
        // nothing changes unless the new key and its check text exist (never a half-set password)
        let salt = new_salt();
        let master = !password.is_empty();
        let made = Vault::derive(password, &salt)
            .and_then(|vault| if master { vault.encrypt(VERIFY_TEXT).map(|check| (vault, check)) } else { Ok((vault, String::new())) });
        let (vault, verifier) = match made {
            Ok(v) => v,
            Err(e) => {
                self.last_error = Some(e);
                return;
            }
        };
        self.data.salt = B64.encode(&salt);
        self.data.master = master;
        self.data.verifier = verifier;
        // the WebDAV password follows: under the new key, or back under the fixed one
        if let Some(r) = self.remote.as_mut()
            && r.protect(master.then_some(&vault))
            && !self.read_only
            && let Err(e) = crate::remote::save_config(r)
        {
            self.last_error = Some(e);
        }
        self.vault = Some(vault);
        self.save();
    }

    pub fn save(&mut self) {
        if self.read_only {
            return;
        }
        let Some(v) = self.vault.clone() else { return };
        for e in &mut self.data.entries {
            e.password_enc = if e.password.is_empty() {
                None
            } else if e.password_enc.as_deref().and_then(|p| v.decrypt(p)).as_deref() == Some(e.password.as_str()) {
                // unchanged: the same text again, so an unchanged list is an unchanged file
                e.password_enc.take()
            } else {
                // changed: encrypted anew (fresh nonce); should that ever fail, the stored one stays
                v.encrypt(&e.password).ok().or_else(|| e.password_enc.take())
            };
        }
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if !self.backed_up && self.path.exists() {
            let _ = std::fs::copy(&self.path, self.path.with_extension("json.bak"));
            self.backed_up = true;
        }
        // KeePass as connection list: the connections go there, this file keeps the settings
        let kdbx = self.kdbx_mode();
        let mut kdbx_error = None;
        if kdbx
            && !self.kdbx_waiting
            && let Some(key) = self.kdbx_key.clone()
        {
            // the list as KeePass already has it: no key derivation, no write
            let unchanged = self.kdbx_snapshot.as_deref().is_some_and(|s| same_as_snapshot(s, &self.data.entries));
            if !unchanged {
                let path = self.data.settings.keepass_path.clone();
                // written in the background: the key derivation must not stop the window
                if let Err(e) = self.queue_kdbx(path, key) {
                    kdbx_error = Some(e);
                }
                self.kdbx_snapshot = Some(kdbx_snapshot_of(&self.data.entries));
            }
        }
        let kept = if kdbx { std::mem::take(&mut self.data.entries) } else { Vec::new() };
        let text = self.file_text(&v);
        if kdbx {
            self.data.entries = kept;
        }
        let text = match text {
            Ok(t) => t,
            Err(e) => {
                self.last_error = Some(tf("Saving failed: {0}", &[&e]));
                return;
            }
        };
        // a shared folder: someone else wrote the file since we read or wrote it
        if !kdbx && self.remote.is_none() && self.changed_on_disk() {
            self.keep_theirs(&text);
            return;
        }
        let result = write_atomic(&self.path, &text);
        self.last_error = result.err().map(|e| tf("Saving failed: {0}", &[&e])).or(kdbx_error);
        self.mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        self.text_hash = hash_text(&text);
        // WebDAV: a server copy fetched before this save is older; upload in the background
        if let Some(r) = self.remote.clone() {
            {
                let mut st = self.remote_state.lock().unwrap_or_else(|e| e.into_inner());
                st.fetched = None;
                st.saves = st.saves.wrapping_add(1);
            }
            queue_upload(&self.remote_state, r, text);
        }
    }

    /// The file's text: the list as JSON, or sealed with the master password (names and hosts
    /// too). An unchanged list is sealed as before, so the file doesn't change.
    fn file_text(&mut self, v: &Vault) -> Result<String, String> {
        let json = serde_json::to_string_pretty(&self.data).map_err(|e| e.to_string())?;
        if !(self.data.settings.encrypt_file && self.data.master) {
            return Ok(json);
        }
        if let Some((j, sealed)) = &self.sealed_cache
            && *j == json
        {
            return Ok(sealed.clone());
        }
        let sealed = SealedFile {
            format: SEALED_FORMAT.into(),
            version: 1,
            salt: self.data.salt.clone(),
            verifier: self.data.verifier.clone(),
            payload: v.encrypt(&json)?,
        };
        let text = serde_json::to_string_pretty(&sealed).map_err(|e| e.to_string())?;
        self.sealed_cache = Some((json, text.clone()));
        Ok(text)
    }

    /// The file differs from what we last read or wrote (or can't be read as text).
    fn changed_on_disk(&self) -> bool {
        match std::fs::read(&self.path) {
            Ok(bytes) => String::from_utf8(bytes).map(|t| hash_text(&t) != self.text_hash).unwrap_or(true),
            // no file: nothing of anyone else's to lose
            Err(_) => false,
        }
    }

    /// Someone else saved the shared list in the meantime: their file stays. Ours is kept in a
    /// file next to it, and the list on screen becomes theirs (when it can be read with our key).
    fn keep_theirs(&mut self, ours: &str) {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let side = self.path.with_extension(format!("conflict-{secs}.json"));
        if let Err(e) = write_atomic(&side, ours) {
            // ours stays on screen and is saved again next time
            self.last_error =
                Some(tf("The list was changed elsewhere in the meantime and was not overwritten; your version could not be kept: {0}", &[&e]));
            return;
        }
        let reloaded = std::fs::read_to_string(&self.path).map(|t| self.replace_if_same_key(&t)).unwrap_or(false);
        self.mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        self.last_error = Some(if reloaded {
            tf("The list was changed elsewhere in the meantime and has been reloaded. Your version was kept in {0}.", &[&side.display()])
        } else {
            tf("The list was changed elsewhere in the meantime and was not overwritten. Your version was kept in {0}.", &[&side.display()])
        });
    }

    pub fn next_id(&mut self) -> u64 {
        take_free_id(&self.data.entries, &mut self.data.next_id)
    }

    /// AdminCraft closes: gives a WebDAV upload still on its way up to `max` to finish, so the last
    /// save reaches the server. Returns whether nothing is left to send.
    pub fn wait_for_upload(&self, max: std::time::Duration) -> bool {
        let until = std::time::Instant::now() + max;
        loop {
            let busy = {
                let st = self.remote_state.lock().unwrap_or_else(|e| e.into_inner());
                st.uploading || st.pending_upload.is_some()
            };
            if !busy {
                return true;
            }
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    pub fn index_of(&self, id: u64) -> Option<usize> {
        self.data.entries.iter().position(|e| e.id == id)
    }

    pub fn get(&self, id: u64) -> Option<&Entry> {
        self.data.entries.iter().find(|e| e.id == id)
    }

    pub fn children(&self, parent: Option<u64>) -> Vec<u64> {
        self.data.entries.iter().filter(|e| e.parent == parent).map(|e| e.id).collect()
    }

    /// User, domain and password after following "inherit from folder".
    pub fn credentials(&self, id: u64) -> (String, String, Secret) {
        let mut user = String::new();
        let mut domain = String::new();
        let mut pass = Secret::default();
        let mut cur = self.get(id);
        let mut depth = 0;
        while let Some(e) = cur {
            if user.is_empty() {
                user = e.username.clone();
            }
            if domain.is_empty() {
                domain = e.domain.clone();
            }
            if pass.is_empty() {
                pass = e.password.clone();
            }
            if !e.inherit_credentials || depth > 32 {
                break;
            }
            cur = e.parent.and_then(|p| self.get(p));
            depth += 1;
        }
        (user, domain, pass)
    }

    /// Like `credentials`, but also says where the password has to come from.
    pub fn credential_info(&self, id: u64) -> CredInfo {
        let mut info = CredInfo::default();
        let mut pass_done = false;
        let host = self.get(id).map(|x| x.host.trim().to_string()).unwrap_or_default();
        let mut cur = self.get(id);
        let mut depth = 0;
        while let Some(e) = cur {
            if info.user.is_empty() {
                info.user = e.username.clone();
            }
            if info.domain.is_empty() {
                info.domain = e.domain.clone();
            }
            if !pass_done {
                match e.cred_source {
                    CredSource::Stored => {
                        if !e.password.is_empty() {
                            info.password = e.password.clone();
                            pass_done = true;
                        }
                    }
                    CredSource::KeePass => {
                        info.keepass = Some(if e.keepass_entry.trim().is_empty() {
                            KeePassRef::Host(host.clone())
                        } else {
                            KeePassRef::Entry(e.keepass_entry.trim().to_string())
                        });
                        pass_done = true;
                    }
                    CredSource::Ask => {
                        info.ask = true;
                        pass_done = true;
                    }
                }
            }
            if !e.inherit_credentials || depth > 32 {
                break;
            }
            cur = e.parent.and_then(|p| self.get(p));
            depth += 1;
        }
        info
    }

    /// The chain of jump hosts in front of a connection, outermost first.
    pub fn jump_chain(&self, id: u64) -> Vec<u64> {
        let mut chain = Vec::new();
        let mut cur = self.get(id).and_then(|e| e.jump_host);
        while let Some(j) = cur {
            if j == id || chain.contains(&j) || chain.len() > 8 {
                break;
            }
            chain.push(j);
            cur = self.get(j).and_then(|e| e.jump_host);
        }
        chain.reverse();
        chain
    }

    /// Removes an entry and everything below it.
    pub fn remove(&mut self, id: u64) {
        // every id once: parents that loop (a damaged file) can't make this run forever
        let mut doomed: HashSet<u64> = HashSet::from([id]);
        let mut todo = vec![id];
        while let Some(cur) = todo.pop() {
            for e in self.data.entries.iter().filter(|e| e.parent == Some(cur)) {
                if doomed.insert(e.id) {
                    todo.push(e.id);
                }
            }
        }
        self.data.entries.retain(|e| !doomed.contains(&e.id));
    }

    pub fn is_descendant(&self, id: u64, ancestor: u64) -> bool {
        let mut cur = self.get(id).and_then(|e| e.parent);
        let mut depth = 0;
        while let Some(p) = cur {
            if p == ancestor {
                return true;
            }
            depth += 1;
            if depth > 64 {
                break;
            }
            cur = self.get(p).and_then(|e| e.parent);
        }
        false
    }

    pub fn path_of(&self, id: u64) -> String {
        let mut parts = Vec::new();
        let mut cur = self.get(id);
        while let Some(e) = cur {
            parts.push(e.name.clone());
            cur = e.parent.and_then(|p| self.get(p));
            if parts.len() > 64 {
                break;
            }
        }
        parts.reverse();
        parts.join(" / ")
    }

    pub fn folders(&self) -> Vec<(u64, String)> {
        let mut v: Vec<(u64, String)> = self.data.entries.iter().filter(|e| e.folder).map(|e| (e.id, self.path_of(e.id))).collect();
        v.sort_by_cached_key(|a| a.1.to_lowercase());
        v
    }

    /// Drag & drop: puts `src` into folder `target` (`into`), or before/after `target` in the
    /// same folder; `target` None = last on the top level. Refuses to put a folder into itself.
    pub fn drop_move(&mut self, src: u64, target: Option<u64>, into: bool, after: bool) -> bool {
        if Some(src) == target || self.get(src).is_none() {
            return false;
        }
        let new_parent = match target {
            None => None,
            Some(t) if into => Some(t),
            Some(t) => match self.get(t) {
                Some(e) => e.parent,
                None => return false,
            },
        };
        if new_parent == Some(src) || new_parent.map(|p| self.is_descendant(p, src)).unwrap_or(false) {
            return false;
        }
        let Some(i) = self.index_of(src) else { return false };
        let mut entry = self.data.entries.remove(i);
        entry.parent = new_parent;
        let at = match target {
            Some(t) if !into => self.index_of(t).map(|x| if after { x + 1 } else { x }),
            _ => None,
        }
        .unwrap_or(self.data.entries.len());
        self.data.entries.insert(at, entry);
        true
    }

    /// Moves an entry one place up or down among its siblings.
    pub fn shift(&mut self, id: u64, up: bool) {
        let Some(idx) = self.index_of(id) else { return };
        let parent = self.data.entries[idx].parent;
        let siblings: Vec<usize> = self.data.entries.iter().enumerate().filter(|(_, e)| e.parent == parent).map(|(i, _)| i).collect();
        let pos = siblings.iter().position(|&i| i == idx).unwrap_or(0);
        let other = if up {
            if pos == 0 {
                return;
            }
            siblings[pos - 1]
        } else {
            if pos + 1 >= siblings.len() {
                return;
            }
            siblings[pos + 1]
        };
        self.data.entries.swap(idx, other);
    }
}

fn folder(id: u64, parent: Option<u64>, name: &str) -> Entry {
    Entry { id, parent, folder: true, name: name.into(), inherit_credentials: false, ..Default::default() }
}

fn conn(id: u64, parent: Option<u64>, name: &str, p: Protocol, host: &str, user: &str) -> Entry {
    Entry { id, parent, name: name.into(), protocol: p, host: host.into(), port: p.default_port(), username: user.into(), ..Default::default() }
}

/// What a new, empty installation shows: an example layout the person can edit or delete.
pub fn sample_data() -> DataFile {
    let mut d = DataFile::default();
    let mut f1 = folder(1, None, tr("Data center"));
    f1.domain = "CORP".into();
    f1.username = tr("administrator").into();
    f1.description = tr("Servers in the server room. User and domain are inherited by the connections.").into();
    let mut dc = conn(2, Some(1), tr("DC01 – Domain Controller"), Protocol::Rdp, "10.0.0.10", "");
    dc.rdp.admin_session = true;
    dc.description = tr("Example: user and domain come from the folder.").into();
    let fs = conn(3, Some(1), tr("FS01 – file server"), Protocol::Rdp, "10.0.0.20", "");
    let mut web = conn(4, Some(1), tr("web01 – Linux web server"), Protocol::Ssh, "10.0.0.30", "root");
    web.inherit_credentials = false;
    let mut esx = conn(5, Some(1), tr("ESXi Host"), Protocol::Https, "10.0.0.5", "root");
    esx.inherit_credentials = false;
    let mut ps = conn(6, Some(1), tr("FS01 – PowerShell"), Protocol::PowerShell, "fs01.corp.local", "");
    ps.description = tr("Enter-PSSession over WinRM").into();
    let f2 = folder(7, None, tr("Network"));
    let sw = conn(8, Some(7), tr("Core-Switch"), Protocol::Ssh, "10.0.0.2", "admin");
    let fw = conn(9, Some(7), tr("Firewall"), Protocol::Https, "10.0.0.1", "admin");
    let pr = conn(10, Some(7), tr("Office printer"), Protocol::Http, "10.0.1.50", "");
    let tel = conn(11, Some(7), tr("Old router"), Protocol::Telnet, "10.0.0.254", "");
    let mut f3 = folder(12, None, tr("Workstations"));
    f3.expanded = false;
    let vnc = conn(13, Some(12), tr("Reception PC"), Protocol::Vnc, "10.0.1.21", "");
    let mut bh = conn(14, Some(12), tr("Accounting PC"), Protocol::Rdp, "10.0.1.22", "");
    bh.mac = "00:11:22:33:44:55".into();
    let local = conn(15, None, tr("Local terminal"), Protocol::LocalShell, "", "");
    let mut bastion = conn(16, Some(1), tr("bastion – jump host"), Protocol::Ssh, "203.0.113.10", "jump");
    bastion.inherit_credentials = false;
    bastion.description = tr("Jump server: other connections go through this host.").into();
    let mut db = conn(17, Some(1), tr("db01 – via jump host"), Protocol::Ssh, "10.0.0.40", "root");
    db.inherit_credentials = false;
    db.jump_host = Some(16);
    db.description = tr("Logs in to the jump host first and runs ssh root@10.0.0.40 there.").into();
    let mut files = conn(18, Some(1), tr("web01 – files (SFTP)"), Protocol::Sftp, "10.0.0.30", "root");
    files.inherit_credentials = false;
    files.start_path = tr("/var/www").into();
    let mut ftp = conn(19, None, tr("Webspace (FTP)"), Protocol::Ftp, "ftp.example.com", "web");
    ftp.ftp_tls = true;
    d.entries = vec![f1, dc, fs, web, bastion, db, files, esx, ps, f2, sw, fw, pr, tel, f3, vnc, bh, ftp, local];
    d.next_id = 20;
    d
}
