//! Connections, folders, settings and the encrypted, portable data file.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use aes_gcm::aead::{Aead, Generate, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::Engine as _;
use eframe::egui::Color32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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

#[derive(Clone, Debug, Default)]
pub struct CredInfo {
    pub user: String,
    pub domain: String,
    pub password: String,
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
    pub password: String,
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
            password: String::new(),
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
    pub fn derive(password: &str, salt: &[u8]) -> Vault {
        let mut key = [0u8; 32];
        let pw = format!("AdminCraft:{password}");
        argon2::Argon2::default()
            .hash_password_into(pw.as_bytes(), salt, &mut key)
            .expect("argon2");
        Vault { key }
    }

    pub fn encrypt(&self, plain: &str) -> String {
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("key");
        let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::generate();
        let ct = cipher.encrypt(&nonce, plain.as_bytes()).expect("encrypt");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        B64.encode(out)
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
    /// Encrypted list waiting for the master password.
    sealed_payload: Option<String>,
    /// The list lives on a WebDAV server (local copy in `path`).
    pub remote: Option<crate::remote::RemoteConfig>,
    /// Results of background uploads / downloads.
    pub remote_state: std::sync::Arc<std::sync::Mutex<RemoteState>>,
    /// Hash of the text last read or written (to see whether the server has something new).
    text_hash: u64,
    /// KeePass as connection list: the key once it was entered.
    pub kdbx_key: Option<crate::kdbx::Key>,
    /// KeePass as connection list, but its password wasn't entered yet.
    kdbx_waiting: bool,
    /// When the KeePass file was last read or written by us.
    kdbx_mtime: Option<std::time::SystemTime>,
}

#[derive(Default)]
pub struct RemoteState {
    pub busy: bool,
    pub last_error: Option<String>,
    pub last_ok: Option<std::time::SystemTime>,
    /// A newer list fetched from the server, waiting to be applied.
    pub fetched: Option<String>,
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
    if let Some(dir) = std::env::args()
        .skip_while(|a| a != "--data")
        .nth(1)
    {
        return PathBuf::from(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
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
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
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
        let mut store = Store {
            path: path.clone(),
            data: DataFile::default(),
            vault: None,
            read_only,
            backed_up: false,
            mtime: None,
            last_error: None,
            sealed_payload: None,
            remote: remote.clone(),
            remote_state: Default::default(),
            text_hash: 0,
            kdbx_key: None,
            kdbx_waiting: false,
            kdbx_mtime: None,
        };
        // WebDAV: the server's list wins; without the server the local copy is used
        let mut text = None;
        if let Some(r) = &remote {
            match crate::remote::fetch(r) {
                Ok(Some(t)) => {
                    if !read_only {
                        let _ = std::fs::write(&path, &t);
                    }
                    text = Some(t);
                }
                Ok(None) => {}
                Err(e) => store.last_error = Some(tf("{0} – using the local copy.", &[&e])),
            }
        }
        let text = text.or_else(|| std::fs::read_to_string(&path).ok());
        match text {
            Some(text) => {
                if let Err(e) = store.load_text(&text) {
                    store.last_error = Some(tf("File could not be read: {0}", &[&e]));
                    store.read_only = true;
                }
            }
            None => {
                store.data = sample_data();
                store.data.salt = B64.encode(new_salt());
                let salt = store.salt();
                store.vault = Some(Vault::derive("", &salt));
                if !read_only {
                    store.save();
                }
            }
        }
        // command line / MCP server: the master password may come from the environment
        if store.vault.is_none() {
            if let Ok(pw) = std::env::var("AC_MASTER") {
                store.unlock(&pw);
            }
        }
        if store.kdbx_mode() {
            store.data.entries.clear();
            store.kdbx_waiting = true;
            if let Ok(pw) = std::env::var("AC_KEEPASS") {
                store.unlock_keepass(&pw);
            }
        }
        store
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
        match crate::kdbx::load(&self.data.settings.keepass_path, &key) {
            Ok(list) => {
                self.data.entries = list;
                self.kdbx_key = Some(key);
                self.kdbx_waiting = false;
                self.kdbx_mtime = std::fs::metadata(self.data.settings.keepass_path.trim().trim_matches('"')).and_then(|m| m.modified()).ok();
                self.last_error = None;
                true
            }
            Err(e) => {
                self.last_error = Some(e);
                false
            }
        }
    }

    /// Switches to KeePass as connection list. When the database already holds AdminCraft
    /// connections they are used; otherwise the current list is written into it.
    pub fn use_keepass(&mut self, key: crate::kdbx::Key) -> Result<String, String> {
        let path = self.data.settings.keepass_path.clone();
        let there = crate::kdbx::load(&path, &key)?;
        let msg = if there.is_empty() {
            let mut list = self.data.entries.clone();
            crate::kdbx::save(&path, &key, &mut list)?;
            self.data.entries = list;
            tf("{0} entries moved into the KeePass database (group \"AdminCraft\").", &[&self.data.entries.len()])
        } else {
            self.data.entries = there;
            tf("{0} entries loaded from the KeePass database.", &[&self.data.entries.len()])
        };
        self.data.settings.keepass_db = true;
        self.kdbx_key = Some(key);
        self.kdbx_waiting = false;
        self.save();
        Ok(msg)
    }

    /// Back to AdminCraft's own file: the connections now open are kept there.
    pub fn stop_using_keepass(&mut self) {
        self.data.settings.keepass_db = false;
        self.kdbx_key = None;
        self.kdbx_waiting = false;
        self.save();
    }

    /// Reads a list (plain, or sealed with the master password). A vault that still fits is
    /// kept, so a reload doesn't ask for the password again.
    fn load_text(&mut self, text: &str) -> Result<(), String> {
        self.text_hash = hash_text(text);
        if let Ok(sealed) = serde_json::from_str::<SealedFile>(text) {
            if sealed.format == SEALED_FORMAT {
                let keep = self.vault.clone().filter(|v| self.data.salt == sealed.salt && v.decrypt(&sealed.verifier).as_deref() == Some(VERIFY_TEXT));
                self.data = DataFile { salt: sealed.salt, master: true, verifier: sealed.verifier, ..Default::default() };
                self.sealed_payload = Some(sealed.payload);
                self.vault = None;
                if let Some(v) = keep {
                    self.open_sealed(v)?;
                }
                return Ok(());
            }
        }
        let data = serde_json::from_str::<DataFile>(text).map_err(|e| e.to_string())?;
        let keep = self.vault.clone().filter(|v| data.salt == self.data.salt && (!data.master || v.decrypt(&data.verifier).as_deref() == Some(VERIFY_TEXT)));
        self.sealed_payload = None;
        self.data = data;
        if !self.data.master {
            let salt = self.salt();
            self.vault = Some(Vault::derive("", &salt));
        } else {
            self.vault = keep;
        }
        if self.vault.is_some() {
            self.decrypt_all();
        }
        Ok(())
    }

    fn open_sealed(&mut self, v: Vault) -> Result<(), String> {
        let Some(payload) = self.sealed_payload.take() else { return Ok(()) };
        let json = v.decrypt(&payload).ok_or_else(|| tr("The encrypted list doesn't match the master password.").to_string())?;
        let data = serde_json::from_str::<DataFile>(&json).map_err(|e| e.to_string())?;
        self.data = data;
        self.vault = Some(v);
        self.decrypt_all();
        Ok(())
    }

    /// Someone else (a colleague on the shared list) saved the file: read it again.
    /// Returns true when the data was replaced.
    pub fn reload_if_changed(&mut self) -> bool {
        if self.kdbx_mode() {
            // the list is in KeePass: reload when KeePass (or a colleague) saved the file
            let Some(key) = self.kdbx_key.clone() else { return false };
            let path = self.data.settings.keepass_path.trim().trim_matches('"').to_string();
            let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) else { return false };
            if self.kdbx_mtime == Some(m) {
                return false;
            }
            self.kdbx_mtime = Some(m);
            return match crate::kdbx::load(&path, &key) {
                Ok(list) if list != self.data.entries => {
                    self.data.entries = list;
                    true
                }
                _ => false,
            };
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
        let backup = std::mem::take(&mut self.data);
        let vault = self.vault.clone();
        match self.load_text(text) {
            Ok(()) if self.vault.is_some() && (self.data.salt.clone(), self.data.master) == before => true,
            _ => {
                // another key or unreadable: keep ours
                self.data = backup;
                self.vault = vault;
                self.sealed_payload = None;
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
        {
            let mut st = state.lock().unwrap();
            if st.busy {
                return;
            }
            st.busy = true;
        }
        std::thread::spawn(move || {
            let res = crate::remote::fetch(&r);
            let mut st = state.lock().unwrap();
            st.busy = false;
            match res {
                Ok(Some(t)) => {
                    st.fetched = Some(t);
                    st.last_error = None;
                }
                Ok(None) => st.last_error = None,
                Err(e) => st.last_error = Some(e),
            }
        });
    }

    fn apply_fetched(&mut self) -> bool {
        let fetched = self.remote_state.lock().unwrap().fetched.take();
        match fetched {
            Some(t) => {
                let changed = self.replace_if_same_key(&t);
                if changed && !self.read_only {
                    let _ = std::fs::write(&self.path, &t);
                }
                changed
            }
            None => false,
        }
    }

    pub fn salt(&self) -> Vec<u8> {
        let s = B64.decode(&self.data.salt).unwrap_or_default();
        if s.len() >= 8 {
            s
        } else {
            b"admincraft-salt!".to_vec()
        }
    }

    pub fn locked(&self) -> bool {
        self.vault.is_none() || self.kdbx_waiting
    }

    pub fn unlock(&mut self, password: &str) -> bool {
        if self.waiting_for_keepass() {
            return self.unlock_keepass(password);
        }
        let vault = Vault::derive(password, &self.salt());
        if vault.decrypt(&self.data.verifier).as_deref() != Some(VERIFY_TEXT) {
            return false;
        }
        if self.sealed_payload.is_some() {
            if let Err(e) = self.open_sealed(vault) {
                self.last_error = Some(e);
                return false;
            }
        } else {
            self.vault = Some(vault);
            self.decrypt_all();
        }
        true
    }

    fn decrypt_all(&mut self) {
        let Some(v) = self.vault.clone() else { return };
        for e in &mut self.data.entries {
            e.password = e
                .password_enc
                .as_deref()
                .and_then(|p| v.decrypt(p))
                .unwrap_or_default();
        }
    }

    /// Sets, changes (non-empty) or removes (empty) the master password.
    pub fn set_master(&mut self, password: &str) {
        self.data.salt = B64.encode(new_salt());
        let salt = self.salt();
        let vault = Vault::derive(password, &salt);
        self.data.master = !password.is_empty();
        self.data.verifier = if self.data.master { vault.encrypt(VERIFY_TEXT) } else { String::new() };
        self.vault = Some(vault);
        self.save();
    }

    pub fn save(&mut self) {
        if self.read_only {
            return;
        }
        let Some(v) = self.vault.clone() else { return };
        for e in &mut self.data.entries {
            e.password_enc = if e.password.is_empty() { None } else { Some(v.encrypt(&e.password)) };
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
        if kdbx && !self.kdbx_waiting {
            if let Some(key) = self.kdbx_key.clone() {
                let path = self.data.settings.keepass_path.clone();
                match crate::kdbx::save(&path, &key, &mut self.data.entries) {
                    Ok(()) => self.kdbx_mtime = std::fs::metadata(path.trim().trim_matches('"')).and_then(|m| m.modified()).ok(),
                    Err(e) => kdbx_error = Some(e),
                }
            }
        }
        let kept = if kdbx { std::mem::take(&mut self.data.entries) } else { Vec::new() };
        let tmp = self.path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(&self.data).map_err(|e| e.to_string()).and_then(|json| {
            // whole list encrypted with the master password (names and hosts too)
            if self.data.settings.encrypt_file && self.data.master {
                let sealed = SealedFile {
                    format: SEALED_FORMAT.into(),
                    version: 1,
                    salt: self.data.salt.clone(),
                    verifier: self.data.verifier.clone(),
                    payload: v.encrypt(&json),
                };
                serde_json::to_string_pretty(&sealed).map_err(|e| e.to_string())
            } else {
                Ok(json)
            }
        });
        let result = text.clone().and_then(|json| {
            std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
        });
        if kdbx {
            self.data.entries = kept;
        }
        self.last_error = result.err().map(|e| tf("Saving failed: {0}", &[&e])).or(kdbx_error);
        self.mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if let Ok(t) = text {
            self.text_hash = hash_text(&t);
            // WebDAV: upload in the background
            if let Some(r) = self.remote.clone() {
                let state = self.remote_state.clone();
                std::thread::spawn(move || {
                    let res = crate::remote::upload(&r, &t);
                    let mut st = state.lock().unwrap();
                    match res {
                        Ok(()) => {
                            st.last_error = None;
                            st.last_ok = Some(std::time::SystemTime::now());
                        }
                        Err(e) => st.last_error = Some(e),
                    }
                });
            }
        }
    }

    pub fn next_id(&mut self) -> u64 {
        let max = self.data.entries.iter().map(|e| e.id).max().unwrap_or(0);
        let id = self.data.next_id.max(max + 1);
        self.data.next_id = id + 1;
        id
    }

    pub fn index_of(&self, id: u64) -> Option<usize> {
        self.data.entries.iter().position(|e| e.id == id)
    }

    pub fn get(&self, id: u64) -> Option<&Entry> {
        self.data.entries.iter().find(|e| e.id == id)
    }

    pub fn children(&self, parent: Option<u64>) -> Vec<u64> {
        self.data
            .entries
            .iter()
            .filter(|e| e.parent == parent)
            .map(|e| e.id)
            .collect()
    }

    /// User, domain and password after following "inherit from folder".
    pub fn credentials(&self, id: u64) -> (String, String, String) {
        let mut user = String::new();
        let mut domain = String::new();
        let mut pass = String::new();
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
        let mut doomed = vec![id];
        let mut i = 0;
        while i < doomed.len() {
            let cur = doomed[i];
            doomed.extend(self.data.entries.iter().filter(|e| e.parent == Some(cur)).map(|e| e.id));
            i += 1;
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
        let mut v: Vec<(u64, String)> = self
            .data
            .entries
            .iter()
            .filter(|e| e.folder)
            .map(|e| (e.id, self.path_of(e.id)))
            .collect();
        v.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
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
        let siblings: Vec<usize> = self
            .data
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.parent == parent)
            .map(|(i, _)| i)
            .collect();
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
    Entry {
        id,
        parent,
        folder: true,
        name: name.into(),
        inherit_credentials: false,
        ..Default::default()
    }
}

fn conn(id: u64, parent: Option<u64>, name: &str, p: Protocol, host: &str, user: &str) -> Entry {
    Entry {
        id,
        parent,
        name: name.into(),
        protocol: p,
        host: host.into(),
        port: p.default_port(),
        username: user.into(),
        ..Default::default()
    }
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
