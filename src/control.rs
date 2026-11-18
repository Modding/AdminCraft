//! Control channel into the running window, for AI agents and scripts on this computer.
//!
//! The window listens on 127.0.0.1 (a free port) and writes the port and a random token to a file
//! only this user can read (`control_file`): `control.json` in the data folder with mode 0600 on
//! Linux and macOS; on Windows `control-<hash of the data folder>.json` in the user's own
//! `%LOCALAPPDATA%\AdminCraft`, because a portable data folder may be readable by everybody.
//! A client (`admincraft cli window …`, the MCP server) reads that file and sends one JSON line
//! `{"token": "...", "cmd": "...", "args": {...}}`; the window answers with one JSON line. Only
//! programs of the same user can use it, nothing from other computers. Passwords are never
//! returned; typing into terminals needs its own switch in the settings.

use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

/// Connections served at the same time; more are closed right away (a local program opening
/// connections in a loop must not start a thread for each).
pub const MAX_CONNECTIONS: usize = 16;
/// The whole request line must arrive within this time (not per read: a client sending one byte
/// at a time must not hold a thread for days).
const READ_DEADLINE: Duration = Duration::from_secs(5);
/// A client that doesn't take the answer doesn't hold the thread either.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a connection waits for the window to answer; the window skips requests older than this.
const ANSWER_WAIT: Duration = Duration::from_secs(20);
/// Longest request or answer line.
const LINE_LIMIT: usize = 1 << 20;

/// One request from a client, waiting for the window to answer it.
pub struct Request {
    pub cmd: String,
    pub args: Value,
    pub reply: Sender<Value>,
    /// After this the client has been told "the window did not answer": the request is dropped,
    /// not carried out late.
    pub deadline: Instant,
}

impl Request {
    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

pub struct Server {
    pub requests: Receiver<Request>,
    file: PathBuf,
    port: u16,
    token: String,
    stop: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        // ends the accept loop: the flag, then one connection so `accept` returns
        stop_listener(&self.stop, self.port);
        // the window is gone: nobody should try the old port (unless another window wrote its own)
        let ours = std::fs::read_to_string(&self.file)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .is_some_and(|v| v["port"].as_u64() == Some(u64::from(self.port)) && v["token"].as_str() == Some(self.token.as_str()));
        if ours {
            if cfg!(windows) {
                let _ = std::fs::remove_file(&self.file);
            } else {
                let _ = std::fs::write(&self.file, "{}");
            }
        }
    }
}

fn stop_listener(stop: &AtomicBool, port: u16) {
    stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(1));
}

/// Where port and token are written for this data folder; client and window use the same.
fn control_file() -> Option<PathBuf> {
    let data = crate::model::data_dir(false);
    let data = std::fs::canonicalize(&data).unwrap_or(data);
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    control_file_for(&data, local.as_deref(), cfg!(windows))
}

/// `windows`: in the user's own local application data (never in the data folder, which may be a
/// shared or portable folder others can read); `None` when that folder is unknown, which means no
/// control channel rather than a readable token. Elsewhere `control.json` in the data folder (0600).
pub(crate) fn control_file_for(data: &Path, local_app_data: Option<&Path>, windows: bool) -> Option<PathBuf> {
    if !windows {
        return Some(data.join("control.json"));
    }
    use sha1::Digest;
    let local = local_app_data.filter(|p| p.is_absolute())?;
    let key = data.to_string_lossy().to_lowercase();
    let hash = sha1::Sha1::digest(key.as_bytes());
    let short: String = hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
    Some(local.join("AdminCraft").join(format!("control-{short}.json")))
}

/// A random token; without random numbers there is no control channel (never a guessable token).
fn new_token() -> Result<String, String> {
    let mut b = [0u8; 24];
    getrandom::fill(&mut b).map_err(|e| e.to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Writes the port and token so that only this user can read them (other local users must not
/// be able to steer the window).
fn write_private(file: &Path, text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(file)?;
        // an older file may have been created with wider rights
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    {
        // the folder is the user's own %LOCALAPPDATA% (see `control_file_for`)
        std::fs::write(file, text)
    }
}

/// Compares without stopping at the first difference, so timing tells nothing about the token.
fn same_token(given: &str, token: &str) -> bool {
    given.len() == token.len() && given.bytes().zip(token.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Starts listening. `wake` is called after each request so the window draws (and answers) soon.
pub fn start(wake: impl Fn() + Send + Sync + 'static) -> Result<Server, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = new_token()?;
    let file = control_file().ok_or("no private folder for the control file (LOCALAPPDATA is not set)")?;
    if let Some(d) = file.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let (tx, rx) = channel::<Request>();
    let stop = Arc::new(AtomicBool::new(false));
    accept_loop(listener, token.clone(), tx, Arc::new(wake), stop.clone())?;
    let info = json!({"port": port, "token": token, "pid": std::process::id(), "version": env!("CARGO_PKG_VERSION")});
    if let Err(e) = write_private(&file, &info.to_string()) {
        stop_listener(&stop, port);
        return Err(e.to_string());
    }
    if cfg!(windows) {
        // older versions kept the token in the data folder, where others may read it
        let _ = std::fs::remove_file(crate::model::data_dir(false).join("control.json"));
    }
    Ok(Server { requests: rx, file, port, token, stop })
}

/// Lowers the number of open connections when a connection thread ends (or was never started).
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

type Wake = Arc<dyn Fn() + Send + Sync>;

/// Accepts connections until `stop` is set (and one more connection wakes the loop). At most
/// `MAX_CONNECTIONS` are served at once. A thread that can't be started is an error, not a panic.
pub(crate) fn accept_loop(
    listener: TcpListener,
    token: String,
    tx: Sender<Request>,
    wake: Wake,
    stop: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name("control-listen".into())
        .spawn(move || {
            let active = Arc::new(AtomicUsize::new(0));
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else {
                    // e.g. out of handles: don't spin
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                };
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    drop(stream);
                    continue;
                }
                let slot = Slot(active.clone());
                let (tx, token, wake) = (tx.clone(), token.clone(), wake.clone());
                // on an error the closure (with the slot and the stream) is dropped: the slot is freed
                let _ = std::thread::Builder::new().name("control-conn".into()).spawn(move || {
                    let _slot = slot;
                    serve(stream, &token, &tx, &*wake);
                });
            }
        })
        .map_err(|e| e.to_string())
}

fn serve(mut stream: TcpStream, token: &str, tx: &Sender<Request>, wake: &(dyn Fn() + Send + Sync)) {
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let Ok(line) = read_line(&mut stream, Instant::now() + READ_DEADLINE, LINE_LIMIT) else { return };
    let answer = match serde_json::from_str::<Value>(line.trim_start_matches('\u{feff}')) {
        Err(_) => json!({"error": "not JSON"}),
        Ok(req) if !req["token"].as_str().is_some_and(|t| same_token(t, token)) => json!({"error": "wrong token"}),
        Ok(req) => {
            let (reply, wait) = channel();
            let cmd = req["cmd"].as_str().unwrap_or("").to_string();
            let args = req.get("args").cloned().unwrap_or(json!({}));
            if tx.send(Request { cmd, args, reply, deadline: Instant::now() + ANSWER_WAIT }).is_err() {
                json!({"error": "the window is closing"})
            } else {
                wake();
                wait.recv_timeout(ANSWER_WAIT).unwrap_or_else(|_| json!({"error": "the window did not answer"}))
            }
        }
    };
    let _ = writeln!(stream, "{answer}");
}

/// Reads one line (without the line break) that must be complete by `deadline` and at most
/// `limit` bytes long.
pub(crate) fn read_line(stream: &mut TcpStream, deadline: Instant, limit: usize) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind};
    let mut line = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::new(ErrorKind::TimedOut, "too slow"));
        }
        stream.set_read_timeout(Some(left.max(Duration::from_millis(1))))?;
        let n = stream.read(&mut chunk)?;
        let part = chunk.get(..n).unwrap_or_default();
        if n == 0 {
            break;
        }
        match part.iter().position(|&b| b == b'\n') {
            Some(end) => {
                line.extend_from_slice(part.get(..end).unwrap_or_default());
                break;
            }
            None => line.extend_from_slice(part),
        }
        if line.len() > limit {
            return Err(Error::new(ErrorKind::InvalidData, "line too long"));
        }
    }
    if line.len() > limit {
        return Err(Error::new(ErrorKind::InvalidData, "line too long"));
    }
    String::from_utf8(line).map(|s| s.trim_end_matches('\r').to_string()).map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

/// Client side: sends one command to the running window.
pub fn send(cmd: &str, args: Value) -> Result<Value, String> {
    let file = control_file().ok_or_else(no_window)?;
    let text = std::fs::read_to_string(file).map_err(|_| no_window())?;
    let info: Value = serde_json::from_str(&text).map_err(|_| no_window())?;
    let (Some(port), Some(token)) = (info["port"].as_u64(), info["token"].as_str()) else { return Err(no_window()) };
    let port = u16::try_from(port).ok().filter(|p| *p != 0).ok_or_else(no_window)?;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|_| no_window())?;
    let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
    writeln!(s, "{}", json!({"token": token, "cmd": cmd, "args": args})).map_err(|e| e.to_string())?;
    let line = read_line(&mut s, Instant::now() + ANSWER_WAIT + Duration::from_secs(5), LINE_LIMIT).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    match v.get("error").and_then(|e| e.as_str()) {
        Some(e) => Err(e.to_string()),
        None => Ok(v),
    }
}

/// A new file name in `dir` for an agent's picture of tab `i`; our own pictures older than a day
/// are removed first, so the folder doesn't grow forever.
pub fn new_shot_file(dir: &Path, i: usize) -> PathBuf {
    if let Ok(list) = std::fs::read_dir(dir) {
        let day = Duration::from_secs(24 * 3600);
        for e in list.flatten().take(10_000) {
            let name = e.file_name().to_string_lossy().to_string();
            // only plain files named like ours; links and everything else stay
            if name.starts_with("tab-")
                && name.ends_with(".png")
                && let Ok(m) = std::fs::symlink_metadata(e.path())
                && m.file_type().is_file()
                && m.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > day)
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let n = COUNT.fetch_add(1, Ordering::Relaxed);
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    dir.join(format!("tab-{i}-{ms}-{}-{n}.png", std::process::id()))
}

/// Saves an RGBA picture as PNG into a file that must not exist yet: an existing file, or a link
/// placed there beforehand by someone else, is never replaced or followed.
pub fn save_png_new(file: &Path, w: usize, h: usize, rgba: &[u8]) -> Result<(), String> {
    use image::ImageEncoder as _;
    let (w32, h32) = (u32::try_from(w).map_err(|e| e.to_string())?, u32::try_from(h).map_err(|e| e.to_string())?);
    // the encoder panics on a buffer of the wrong size
    if w.checked_mul(h).and_then(|n| n.checked_mul(4)) != Some(rgba.len()) {
        return Err("the picture has the wrong size".into());
    }
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png).write_image(rgba, w32, h32, image::ExtendedColorType::Rgba8).map_err(|e| e.to_string())?;
    if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(file).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => format!("{} already exists; name a new file", file.display()),
        _ => e.to_string(),
    })?;
    f.write_all(&png).map_err(|e| e.to_string())
}

/// Whether a window is listening right now.
pub fn window_running() -> bool {
    send("status", json!({})).is_ok()
}

fn no_window() -> String {
    "AdminCraft is not open, or control by agents is switched off (Settings » AI agents).".into()
}

/// The commands the window understands (for help texts and the MCP tool list).
pub const COMMANDS: &[(&str, &str)] = &[
    ("status", "version, number of tabs and connections, the active tab"),
    ("list_tabs", "the open tabs: index, title, kind, host, active"),
    ("open_connection", "{name | id}: open a saved connection in a new tab"),
    ("switch_tab", "{index}: bring a tab to the front"),
    ("close_tab", "{index}: close a tab"),
    ("read_tab", "{index?}: the text a tab shows (terminal screen, ping/DNS output, scan results)"),
    ("screenshot", "{index?, path?}: a PNG picture of a tab (embedded PuTTY / Remote Desktop / VNC windows too); answers with the file"),
    ("type_text", "{index?, text, enter?}: type into a terminal tab or an embedded PuTTY window (only when allowed in the settings)"),
    ("open_tool", "{tool, target?}: ping, traceroute, portscan, dns, netscan, subnet, cert, whois, http, snmp, help, settings"),
    ("notify", "{text}: show a short message in the window"),
];
