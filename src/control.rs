//! Control channel into the running window, for AI agents and scripts on this computer.
//!
//! The window listens on 127.0.0.1 (a free port) and writes the port and a random token to
//! `control.json` in the data folder. A client (`admincraft cli window …`, the MCP server)
//! reads that file and sends one JSON line `{"token": "...", "cmd": "...", "args": {...}}`;
//! the window answers with one JSON line. Only programs that can read the data folder can
//! use it, nothing from other computers. Passwords are never returned; typing into terminals
//! needs its own switch in the settings.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

/// One request from a client, waiting for the window to answer it.
pub struct Request {
    pub cmd: String,
    pub args: Value,
    pub reply: Sender<Value>,
}

pub struct Server {
    pub requests: Receiver<Request>,
    file: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        // the window is gone: nobody should try the old port
        let _ = std::fs::write(&self.file, "{}");
    }
}

fn control_file() -> PathBuf {
    crate::model::data_dir(false).join("control.json")
}

fn new_token() -> String {
    let mut b = [0u8; 24];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Starts listening. `wake` is called after each request so the window draws (and answers) soon.
pub fn start(wake: impl Fn() + Send + Sync + 'static) -> Result<Server, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = new_token();
    let file = control_file();
    if let Some(d) = file.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let info = json!({"port": port, "token": token, "pid": std::process::id(), "version": env!("CARGO_PKG_VERSION")});
    std::fs::write(&file, info.to_string()).map_err(|e| e.to_string())?;
    let (tx, rx) = channel::<Request>();
    let wake = std::sync::Arc::new(wake);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (tx, token, wake) = (tx.clone(), token.clone(), wake.clone());
            std::thread::spawn(move || serve(stream, &token, &tx, &*wake));
        }
    });
    Ok(Server { requests: rx, file })
}

fn serve(stream: TcpStream, token: &str, tx: &Sender<Request>, wake: &(dyn Fn() + Send + Sync)) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(mut out) = stream.try_clone() else { return };
    let mut line = String::new();
    if BufReader::new(stream).take_line(&mut line).is_err() {
        return;
    }
    let answer = match serde_json::from_str::<Value>(line.trim_start_matches('\u{feff}')) {
        Err(_) => json!({"error": "not JSON"}),
        Ok(req) if req["token"].as_str() != Some(token) => json!({"error": "wrong token"}),
        Ok(req) => {
            let (reply, wait) = channel();
            let cmd = req["cmd"].as_str().unwrap_or("").to_string();
            let args = req.get("args").cloned().unwrap_or(json!({}));
            if tx.send(Request { cmd, args, reply }).is_err() {
                json!({"error": "the window is closing"})
            } else {
                wake();
                wait.recv_timeout(Duration::from_secs(20)).unwrap_or_else(|_| json!({"error": "the window did not answer"}))
            }
        }
    };
    let _ = writeln!(out, "{answer}");
}

trait TakeLine {
    fn take_line(self, buf: &mut String) -> std::io::Result<usize>;
}

impl<R: std::io::Read> TakeLine for BufReader<R> {
    /// At most 1 MiB, so a broken client can't fill the memory.
    fn take_line(self, buf: &mut String) -> std::io::Result<usize> {
        std::io::Read::take(self, 1 << 20).read_line(buf)
    }
}

/// Client side: sends one command to the running window.
pub fn send(cmd: &str, args: Value) -> Result<Value, String> {
    let text = std::fs::read_to_string(control_file()).map_err(|_| no_window())?;
    let info: Value = serde_json::from_str(&text).map_err(|_| no_window())?;
    let (Some(port), Some(token)) = (info["port"].as_u64(), info["token"].as_str()) else { return Err(no_window()) };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port as u16));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|_| no_window())?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(25)));
    writeln!(s, "{}", json!({"token": token, "cmd": cmd, "args": args})).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).take_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    match v.get("error").and_then(|e| e.as_str()) {
        Some(e) => Err(e.to_string()),
        None => Ok(v),
    }
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
    ("type_text", "{index?, text, enter?}: type into a terminal tab (only when allowed in the settings)"),
    ("open_tool", "{tool, target?}: ping, traceroute, portscan, dns, netscan, subnet, cert, whois, http, snmp, help, settings"),
    ("notify", "{text}: show a short message in the window"),
];
