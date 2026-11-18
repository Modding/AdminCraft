//! Admin tools: ping / traceroute / nslookup runner, port scanner, DNS lookup, Wake-on-LAN,
//! and a quick reachability check for the connection tree.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Decodes console output: UTF-8 when valid, otherwise the old DOS code page (German umlauts).
fn decode(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes
            .iter()
            .map(|&b| match b {
                0x81 => 'ü',
                0x84 => 'ä',
                0x94 => 'ö',
                0x8E => 'Ä',
                0x99 => 'Ö',
                0x9A => 'Ü',
                0xE1 => 'ß',
                0xFF => ' ',
                b if b < 0x80 => b as char,
                _ => '?',
            })
            .collect(),
    }
}

/// Lines a command's output keeps; older ones are dropped (a continuous ping runs for days).
pub const MAX_LINES: usize = 5000;
/// Dropped together, so the list isn't moved for every new line.
const DROP_CHUNK: usize = 500;
/// Longest single line kept from a command's output.
const MAX_LINE_BYTES: u64 = 64 * 1024;

/// Adds a line and keeps at most about `MAX_LINES` (between `MAX_LINES` and
/// `MAX_LINES + DROP_CHUNK`): the oldest are dropped in chunks.
pub fn push_line(lines: &mut Vec<String>, line: String) {
    lines.push(line);
    if lines.len() > MAX_LINES + DROP_CHUNK {
        let extra = lines.len() - MAX_LINES;
        lines.drain(..extra);
    }
}

/// Reads output line by line into `lines` until the pipe ends.
fn pump(pipe: impl Read, lines: &Mutex<Vec<String>>, ctx: &eframe::egui::Context) {
    let mut reader = BufReader::new(pipe);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut reader).take(MAX_LINE_BYTES).read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = decode(&buf).trim_end().to_string();
                push_line(&mut lines.lock().unwrap_or_else(|e| e.into_inner()), line);
                ctx.request_repaint();
            }
        }
    }
}

/// Runs a system command and collects its output line by line.
pub struct CmdRunner {
    pub lines: Arc<Mutex<Vec<String>>>,
    /// The current run's flag; every run gets its own (an old run ending doesn't switch off a new one).
    pub running: Arc<AtomicBool>,
    /// The current run's program; its reader thread takes it out and waits for it (no zombies).
    child: Arc<Mutex<Option<Child>>>,
}

impl Default for CmdRunner {
    fn default() -> Self {
        Self { lines: Arc::new(Mutex::new(Vec::new())), running: Arc::new(AtomicBool::new(false)), child: Arc::new(Mutex::new(None)) }
    }
}

impl Drop for CmdRunner {
    /// A closed tab (or AdminCraft closing) ends a continuous ping too.
    fn drop(&mut self) {
        self.stop();
    }
}

impl CmdRunner {
    pub fn start(&mut self, program: &str, args: &[String], ctx: eframe::egui::Context) {
        self.stop();
        let lines = Arc::new(Mutex::new(vec![format!("> {} {}", program, args.join(" "))]));
        self.lines = lines.clone();
        // a fresh slot and flag for this run: the previous run's thread keeps its own
        self.child = Arc::new(Mutex::new(None));
        self.running = Arc::new(AtomicBool::new(false));
        let mut cmd = Command::new(program);
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        match cmd.spawn() {
            Ok(mut child) => {
                let out = child.stdout.take();
                let err = child.stderr.take();
                *self.child.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
                self.running.store(true, Ordering::SeqCst);
                let running = self.running.clone();
                let child_slot = self.child.clone();
                if let Some(err) = err {
                    let (l2, c2) = (lines.clone(), ctx.clone());
                    // without this thread the error output is closed; the program gets an error writing there
                    let _ = std::thread::Builder::new().name("cmd-stderr".into()).spawn(move || pump(err, &l2, &c2));
                }
                let (l3, c3, slot3) = (lines.clone(), ctx.clone(), child_slot.clone());
                let started = std::thread::Builder::new().name("cmd-stdout".into()).spawn(move || {
                    if let Some(out) = out {
                        pump(out, &l3, &c3);
                    }
                    // reaps the program, also after `stop` killed it
                    let child = slot3.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(mut c) = child {
                        let _ = c.wait();
                    }
                    push_line(&mut l3.lock().unwrap_or_else(|e| e.into_inner()), tr("— done —").into());
                    running.store(false, Ordering::SeqCst);
                    c3.request_repaint();
                });
                if let Err(e) = started {
                    let child = child_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(mut c) = child {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    self.running.store(false, Ordering::SeqCst);
                    lines.lock().unwrap_or_else(|e| e.into_inner()).push(tf("Could not start '{0}': {1}", &[&program, &e]));
                }
            }
            Err(e) => {
                lines.lock().unwrap_or_else(|e| e.into_inner()).push(tf("Could not start '{0}': {1}", &[&program, &e]));
            }
        }
    }

    /// Ends the running program. It stays in its slot: the reader thread waits for it.
    pub fn stop(&mut self) {
        if let Some(c) = self.child.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            let _ = c.kill();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn text(&self) -> String {
        self.lines.lock().unwrap_or_else(|e| e.into_inner()).join("\n")
    }
}

/// Whether a host given by an agent or script may go to ping, traceroute or nslookup as their
/// argument: a leading `-` would make it an option of the system tool, spaces and control
/// characters would make it several arguments or a broken line.
pub fn valid_target(target: &str) -> bool {
    !target.is_empty() && !target.starts_with('-') && !target.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// IPv4 addresses first, otherwise in the resolver's order (`localhost` often gives `::1` first,
/// where many services don't listen).
pub fn prefer_ipv4(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_by_key(|a| !a.is_ipv4());
    addrs
}

pub fn ping_args(host: &str, count: Option<u32>) -> Vec<String> {
    let mut a = Vec::new();
    if cfg!(windows) {
        match count {
            Some(n) => a.extend(["-n".to_string(), n.to_string()]),
            None => a.push("-t".into()),
        }
    } else if let Some(n) = count {
        a.extend(["-c".to_string(), n.to_string()]);
    }
    a.push(host.to_string());
    a
}

pub fn traceroute_cmd(host: &str) -> (String, Vec<String>) {
    let tracepath_only = !cfg!(windows) && crate::launch::which("traceroute").is_none() && crate::launch::which("tracepath").is_some();
    trace_cmd(host, cfg!(windows), tracepath_only)
}

/// `tracert` on Windows, else `traceroute`; many Linux installs only have `tracepath`.
pub fn trace_cmd(host: &str, windows: bool, tracepath_only: bool) -> (String, Vec<String>) {
    let prog = if windows {
        ("tracert", "-d")
    } else if tracepath_only {
        ("tracepath", "-n")
    } else {
        ("traceroute", "-n")
    };
    (prog.0.into(), vec![prog.1.into(), host.into()])
}

pub fn well_known(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 | 587 => "SMTP (TLS)",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MS SQL",
        1521 => "Oracle",
        2049 => "NFS",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900..=5903 => "VNC",
        5985 => "WinRM",
        5986 => "WinRM (TLS)",
        6379 => "Redis",
        8006 => "Proxmox",
        8080 | 8000 | 8008 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        9100 => "Printer (RAW)",
        27017 => "MongoDB",
        _ => "",
    }
}

pub const COMMON_PORTS: &str = "21,22,23,25,53,80,88,110,135,139,143,389,443,445,587,636,993,1433,3306,3389,5432,5900,5985,5986,8006,8080,8443,9100";

pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut v = Vec::new();
    for part in spec.split([',', ';', ' ']).map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().map_err(|_| tf("Invalid port: {0}", &[&part]))?;
            let b: u16 = b.trim().parse().map_err(|_| tf("Invalid port: {0}", &[&part]))?;
            if a > b || a == 0 {
                return Err(tf("Invalid range: {0}", &[&part]));
            }
            v.extend(a..=b);
        } else {
            let p: u16 = part.parse().map_err(|_| tf("Invalid port: {0}", &[&part]))?;
            if p == 0 {
                return Err(tr("Port 0 doesn't exist.").into());
            }
            v.push(p);
        }
    }
    v.sort_unstable();
    v.dedup();
    if v.is_empty() {
        return Err(tr("No ports given.").into());
    }
    if v.len() > 65535 {
        v.truncate(65535);
    }
    Ok(v)
}

pub fn resolve(host: &str) -> Result<Vec<SocketAddr>, String> {
    (host.trim(), 0).to_socket_addrs().map(|i| i.collect()).map_err(|e| tf("Name can't be resolved: {0}", &[&e]))
}

/// Checks TCP ports of one address with up to `workers` threads that take the next port from a
/// shared index, until all are done or `stop` says so. Returns how many ports were checked.
/// Threads that can't be started are fewer workers (none: the calling thread does the work).
pub fn scan_ports(
    addr: IpAddr,
    ports: &[u16],
    timeout: Duration,
    workers: usize,
    stop: &(dyn Fn() -> bool + Sync),
    found: &(dyn Fn(u16, bool) + Sync),
) -> usize {
    let next = AtomicUsize::new(0);
    let checked = AtomicUsize::new(0);
    let work = || {
        while !stop() {
            let Some(&p) = ports.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
            let ok = TcpStream::connect_timeout(&SocketAddr::new(addr, p), timeout).is_ok();
            checked.fetch_add(1, Ordering::Relaxed);
            found(p, ok);
        }
    };
    std::thread::scope(|sc| {
        let mut started = 0;
        for _ in 0..workers.min(ports.len()) {
            match std::thread::Builder::new().name("port-check".into()).spawn_scoped(sc, work) {
                Ok(_) => started += 1,
                Err(_) => break,
            }
        }
        if started == 0 {
            work();
        }
    });
    checked.load(Ordering::Relaxed)
}

#[derive(Default)]
pub struct ScanState {
    pub open: Vec<u16>,
    pub done: usize,
    pub total: usize,
    pub finished: bool,
    pub error: Option<String>,
    pub address: String,
}

pub struct PortScan {
    pub state: Arc<Mutex<ScanState>>,
    cancel: Arc<AtomicBool>,
}

impl PortScan {
    pub fn start(host: &str, ports: Vec<u16>, timeout_ms: u64, ctx: eframe::egui::Context) -> PortScan {
        let state = Arc::new(Mutex::new(ScanState { total: ports.len(), ..Default::default() }));
        let cancel = Arc::new(AtomicBool::new(false));
        let st = state.clone();
        let cc = cancel.clone();
        let host = host.trim().to_string();
        let started = std::thread::Builder::new().name("port-scan".into()).spawn(move || {
            let addr = match resolve(&host).map(prefer_ipv4) {
                Ok(a) => match a.first() {
                    Some(a) => a.ip(),
                    None => {
                        let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
                        s.error = Some(tr("No address found.").into());
                        s.finished = true;
                        ctx.request_repaint();
                        return;
                    }
                },
                Err(e) => {
                    let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
                    s.error = Some(e);
                    s.finished = true;
                    ctx.request_repaint();
                    return;
                }
            };
            st.lock().unwrap_or_else(|e| e.into_inner()).address = addr.to_string();
            let found = |p: u16, ok: bool| {
                let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
                s.done += 1;
                if ok {
                    s.open.push(p);
                    s.open.sort_unstable();
                }
                if s.done.is_multiple_of(16) || ok {
                    ctx.request_repaint();
                }
            };
            scan_ports(addr, &ports, Duration::from_millis(timeout_ms), 128, &|| cc.load(Ordering::Relaxed), &found);
            st.lock().unwrap_or_else(|e| e.into_inner()).finished = true;
            ctx.request_repaint();
        });
        if let Err(e) = started {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.error = Some(tf("No thread could be started: {0}", &[&e]));
            s.finished = true;
        }
        PortScan { state, cancel }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

pub fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return Err(tr("A MAC address needs 12 hex characters, e.g. 00:11:22:33:44:55").into());
    }
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(mac)
}

pub fn wake_on_lan(mac_text: &str, broadcast: &str, port: u16) -> Result<String, String> {
    let mac = parse_mac(mac_text)?;
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_broadcast(true).map_err(|e| e.to_string())?;
    let target = format!("{}:{}", broadcast.trim(), port);
    for _ in 0..3 {
        sock.send_to(&packet, &target).map_err(|e| tf("Sending failed: {0}", &[&e]))?;
    }
    Ok(tf("Magic packet sent to {0} (via {1}).", &[&(mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")), &target]))
}

/// Id -> reachable (None while checking).
pub type StatusMap = Arc<Mutex<HashMap<u64, Option<bool>>>>;

pub fn check_reachability(targets: Vec<(u64, String, u16)>, map: StatusMap, ctx: eframe::egui::Context) {
    {
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        for (id, _, _) in &targets {
            m.insert(*id, None);
        }
    }
    let workers = targets.len().min(24);
    let queue = Arc::new(Mutex::new(targets));
    let mut started = 0;
    for _ in 0..workers {
        let queue = queue.clone();
        let map = map.clone();
        let ctx = ctx.clone();
        let spawned = std::thread::Builder::new().name("reachability".into()).spawn(move || {
            loop {
                let Some((id, host, port)) = queue.lock().unwrap_or_else(|e| e.into_inner()).pop() else { break };
                let ok = match (host.as_str(), port).to_socket_addrs() {
                    Ok(mut addrs) => addrs.next().map(|a| TcpStream::connect_timeout(&a, Duration::from_millis(1500)).is_ok()).unwrap_or(false),
                    Err(_) => false,
                };
                map.lock().unwrap_or_else(|e| e.into_inner()).insert(id, Some(ok));
                ctx.request_repaint();
            }
        });
        match spawned {
            Ok(_) => started += 1,
            Err(_) => break,
        }
    }
    if started == 0 {
        // nobody checks them: unknown again instead of "checking" forever
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        for (id, _, _) in queue.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            m.remove(&id);
        }
    }
}
