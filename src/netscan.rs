//! IP range scanner (like Angry IP Scanner): which addresses answer, their names, MAC
//! addresses and open ports; results can be saved and the next scan shows what changed.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_PORTS: &str = "22,80,443,445,3389";
const MAX_HOSTS: usize = 65_536;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScanHost {
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Default)]
pub struct ScanState {
    pub total: usize,
    pub done: usize,
    pub hosts: Vec<ScanHost>,
    pub finished: bool,
    pub seconds: f32,
}

pub struct NetScan {
    pub state: Arc<Mutex<ScanState>>,
    cancel: Arc<AtomicBool>,
}

fn u32_of(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

/// "10.0.0.0/24", "10.0.0.1-10.0.0.50", "10.0.0.1-50", "10.0.0.7", several separated by commas.
pub fn parse_targets(text: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for part in text.split([',', ';', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((ip, bits)) = part.split_once('/') {
            let ip: Ipv4Addr = ip.trim().parse().map_err(|_| tf("Invalid address: {0}", &[&ip]))?;
            let bits: u32 = bits.trim().parse().ok().filter(|b| *b <= 32).ok_or_else(|| tf("Invalid mask: {0}", &[&part]))?;
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            let net = u32_of(ip) & mask;
            let size = 1u64 << (32 - bits);
            if size as usize > MAX_HOSTS {
                return Err(tr("Range too large (at most /16).").into());
            }
            let (first, last) = if bits >= 31 { (net, net + size as u32 - 1) } else { (net + 1, net + size as u32 - 2) };
            out.extend((first..=last).map(Ipv4Addr::from));
        } else if let Some((a, b)) = part.split_once('-') {
            let start: Ipv4Addr = a.trim().parse().map_err(|_| tf("Invalid address: {0}", &[&a]))?;
            let end: Ipv4Addr = if b.contains('.') {
                b.trim().parse().map_err(|_| tf("Invalid address: {0}", &[&b]))?
            } else {
                let last: u8 = b.trim().parse().map_err(|_| tf("Invalid address: {0}", &[&b]))?;
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            };
            let (s, e) = (u32_of(start), u32_of(end));
            if e < s {
                return Err(tf("Invalid range: {0}", &[&part]));
            }
            if (e - s) as usize >= MAX_HOSTS {
                return Err(tr("Range too large (at most /16).").into());
            }
            out.extend((s..=e).map(Ipv4Addr::from));
        } else {
            out.push(part.parse().map_err(|_| tf("Invalid address: {0}", &[&part]))?);
        }
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(tr("Please enter a range, e.g. 192.168.1.0/24").into());
    }
    if out.len() > MAX_HOSTS {
        return Err(tr("Range too large (at most /16).").into());
    }
    Ok(out)
}

/// The local network(s) of this computer as /24 suggestions.
pub fn local_subnets() -> Vec<String> {
    let mut v = Vec::new();
    // the address used for outgoing traffic, without sending anything
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("192.0.2.1:9").is_ok() {
            if let Ok(SocketAddr::V4(a)) = s.local_addr() {
                let o = a.ip().octets();
                v.push(format!("{}.{}.{}.0/24", o[0], o[1], o[2]));
            }
        }
    }
    v
}

fn hidden(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let _ = cmd;
}

/// One echo request with the system's ping (no admin rights needed). Returns (answered, rtt, name).
fn ping_once(ip: Ipv4Addr, timeout_ms: u64, names: bool) -> (bool, Option<u32>, String) {
    let mut cmd = Command::new("ping");
    if cfg!(windows) {
        if names {
            cmd.arg("-a");
        }
        cmd.args(["-n", "1", "-w", &timeout_ms.to_string()]);
    } else if cfg!(target_os = "macos") {
        cmd.args(["-c", "1", "-t", &(timeout_ms / 1000).max(1).to_string()]);
    } else {
        cmd.args(["-c", "1", "-W", &(timeout_ms / 1000).max(1).to_string()]);
    }
    cmd.arg(ip.to_string()).stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null());
    hidden(&mut cmd);
    let Ok(out) = cmd.output() else { return (false, None, String::new()) };
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let low = text.to_lowercase();
    let alive = low.contains("ttl=") && !low.contains("unreachable") && !low.contains("nicht erreichbar");
    let rtt = parse_rtt(&low);
    let mut name = String::new();
    if names && cfg!(windows) {
        // the header line of Windows ping (any language): "... NAME [10.0.0.5] ..."
        let needle = format!(" [{ip}]");
        if let Some(line) = text.lines().find(|l| l.contains(&needle)) {
            if let Some(end) = line.find(&needle) {
                name = line[..end].rsplit(' ').next().unwrap_or("").to_string();
            }
        }
    }
    (alive, rtt, name)
}

fn parse_rtt(low: &str) -> Option<u32> {
    for key in ["time=", "zeit=", "time<", "zeit<", "temps=", "tiempo="] {
        if let Some(i) = low.find(key) {
            let digits: String = low[i + key.len()..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            if let Ok(v) = digits.parse::<f32>() {
                return Some(v.round() as u32);
            }
        }
    }
    None
}

/// Port open → Some(true); host answered with "refused" → Some(false) (still alive); nothing → None.
fn probe(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<bool> {
    match TcpStream::connect_timeout(&SocketAddr::from((ip, port)), timeout) {
        Ok(_) => Some(true),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(false),
        Err(_) => None,
    }
}

fn reverse_name(ip: Ipv4Addr) -> String {
    if cfg!(windows) {
        return String::new(); // came with ping -a
    }
    let mut cmd = Command::new("getent");
    cmd.args(["hosts", &ip.to_string()]).stdout(Stdio::piped()).stderr(Stdio::null());
    if let Ok(out) = cmd.output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if let Some(name) = s.split_whitespace().nth(1) {
            return name.to_string();
        }
    }
    String::new()
}

/// IP → MAC from the system's neighbour table (filled by the scan itself).
pub fn arp_table() -> BTreeMap<Ipv4Addr, String> {
    let mut map = BTreeMap::new();
    let runs: Vec<Vec<&str>> = if cfg!(windows) {
        vec![vec!["arp", "-a"]]
    } else if cfg!(target_os = "macos") {
        vec![vec!["arp", "-an"]]
    } else {
        vec![vec!["ip", "neigh"], vec!["arp", "-an"]]
    };
    for r in runs {
        let mut cmd = Command::new(r[0]);
        cmd.args(&r[1..]).stdout(Stdio::piped()).stderr(Stdio::null());
        hidden(&mut cmd);
        let Ok(out) = cmd.output() else { continue };
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut ip = None;
            let mut mac = None;
            for tok in line.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
                if ip.is_none() {
                    if let Ok(a) = tok.parse::<Ipv4Addr>() {
                        ip = Some(a);
                        continue;
                    }
                }
                let parts: Vec<&str> = tok.split([':', '-']).collect();
                if parts.len() == 6 && parts.iter().all(|p| !p.is_empty() && p.len() <= 2 && p.chars().all(|c| c.is_ascii_hexdigit())) {
                    let m = parts.iter().map(|p| format!("{:0>2}", p.to_uppercase())).collect::<Vec<_>>().join(":");
                    if m != "FF:FF:FF:FF:FF:FF" && m != "00:00:00:00:00:00" {
                        mac = Some(m);
                    }
                }
            }
            if let (Some(i), Some(m)) = (ip, mac) {
                map.insert(i, m);
            }
        }
        if !map.is_empty() {
            break;
        }
    }
    map
}

impl NetScan {
    pub fn start(targets: Vec<Ipv4Addr>, ports: Vec<u16>, timeout_ms: u64, names: bool, ctx: eframe::egui::Context) -> NetScan {
        let state = Arc::new(Mutex::new(ScanState { total: targets.len(), ..Default::default() }));
        let cancel = Arc::new(AtomicBool::new(false));
        let next = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(targets);
        let ports = Arc::new(ports);
        let started = Instant::now();
        let workers = targets.len().clamp(1, 64);
        let finished_workers = Arc::new(AtomicUsize::new(0));
        for _ in 0..workers {
            let (state, cancel, next, targets, ports, ctx, fw) =
                (state.clone(), cancel.clone(), next.clone(), targets.clone(), ports.clone(), ctx.clone(), finished_workers.clone());
            std::thread::spawn(move || {
                let timeout = Duration::from_millis(timeout_ms);
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ip) = targets.get(i) else { break };
                    // ping and all port probes at the same time: a silent address costs one timeout
                    let ((mut alive, rtt, _), probes) = std::thread::scope(|s| {
                        let handles: Vec<_> = ports.iter().map(|&p| s.spawn(move || (p, probe(ip, p, timeout)))).collect();
                        let ping = ping_once(ip, timeout_ms, false);
                        (ping, handles.into_iter().filter_map(|h| h.join().ok()).collect::<Vec<_>>())
                    });
                    let mut open = Vec::new();
                    for (p, r) in probes {
                        match r {
                            Some(true) => {
                                open.push(p);
                                alive = true;
                            }
                            Some(false) => alive = true,
                            None => {}
                        }
                    }
                    open.sort_unstable();
                    // names only for devices that answered (looking up silent addresses is slow)
                    let mut name = String::new();
                    if alive && names {
                        // at most 1.5 s: addresses without a name make Windows try NetBIOS for long
                        let (tx, rx) = std::sync::mpsc::channel();
                        std::thread::spawn(move || {
                            let n = if cfg!(windows) { ping_once(ip, 300, true).2 } else { reverse_name(ip) };
                            let _ = tx.send(n);
                        });
                        name = rx.recv_timeout(Duration::from_millis(1500)).unwrap_or_default();
                    }
                    if name == ip.to_string() {
                        name.clear();
                    }
                    let mut s = state.lock().unwrap();
                    s.done += 1;
                    if alive {
                        s.hosts.push(ScanHost { ip, name, mac: String::new(), rtt_ms: rtt, ports: open });
                    }
                    drop(s);
                    ctx.request_repaint();
                }
                if fw.fetch_add(1, Ordering::SeqCst) + 1 == workers {
                    // last worker: add MAC addresses and sort
                    let arp = arp_table();
                    let mut s = state.lock().unwrap();
                    for h in &mut s.hosts {
                        if let Some(m) = arp.get(&h.ip) {
                            h.mac = m.clone();
                        }
                    }
                    s.hosts.sort_by_key(|h| u32::from(h.ip));
                    s.finished = true;
                    s.seconds = started.elapsed().as_secs_f32();
                    ctx.request_repaint();
                }
            });
        }
        NetScan { state, cancel }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

// ------------------------------------------------------------------ saved scans and differences

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SavedScan {
    pub range: String,
    /// Seconds since 1970.
    pub time: u64,
    pub hosts: Vec<ScanHost>,
}

pub fn scans_dir() -> PathBuf {
    crate::model::data_dir(false).join("scans")
}

fn file_for(range: &str) -> PathBuf {
    let safe: String = range.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect();
    scans_dir().join(format!("{safe}.json"))
}

pub fn load(range: &str) -> Option<SavedScan> {
    let text = std::fs::read_to_string(file_for(range.trim())).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save(range: &str, hosts: &[ScanHost]) -> Result<SavedScan, String> {
    let scan = SavedScan {
        range: range.trim().to_string(),
        time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        hosts: hosts.to_vec(),
    };
    std::fs::create_dir_all(scans_dir()).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&scan).map_err(|e| e.to_string())?;
    std::fs::write(file_for(range.trim()), json).map_err(|e| e.to_string())?;
    Ok(scan)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Same,
    New,
    Gone,
    /// Same IP, another MAC address (another device took the address).
    Changed,
}

/// Compares a scan with the saved one: every host of both, each with what changed.
pub fn diff(now: &[ScanHost], before: &[ScanHost]) -> Vec<(ScanHost, Change, Option<ScanHost>)> {
    let old: BTreeMap<Ipv4Addr, &ScanHost> = before.iter().map(|h| (h.ip, h)).collect();
    let cur: BTreeMap<Ipv4Addr, &ScanHost> = now.iter().map(|h| (h.ip, h)).collect();
    let mut out = Vec::new();
    for h in now {
        match old.get(&h.ip) {
            None => out.push((h.clone(), Change::New, None)),
            Some(o) => {
                let changed = !o.mac.is_empty() && !h.mac.is_empty() && o.mac != h.mac;
                out.push((h.clone(), if changed { Change::Changed } else { Change::Same }, Some((*o).clone())));
            }
        }
    }
    for h in before {
        if !cur.contains_key(&h.ip) {
            out.push((h.clone(), Change::Gone, None));
        }
    }
    out.sort_by_key(|(h, _, _)| u32::from(h.ip));
    out
}

/// Every connection type the open ports point to, most likely first.
pub fn protocol_candidates(ports: &[u16]) -> Vec<crate::model::Protocol> {
    use crate::model::Protocol;
    let map: [(u16, &[Protocol]); 9] = [
        (3389, &[Protocol::Rdp]),
        (22, &[Protocol::Ssh, Protocol::Sftp]),
        (443, &[Protocol::Https]),
        (80, &[Protocol::Http]),
        (5900, &[Protocol::Vnc]),
        (5985, &[Protocol::PowerShell]),
        (5986, &[Protocol::PowerShell]),
        (23, &[Protocol::Telnet]),
        (21, &[Protocol::Ftp]),
    ];
    let mut v: Vec<Protocol> = Vec::new();
    for (port, protos) in map {
        if ports.contains(&port) {
            for p in protos {
                if !v.contains(p) {
                    v.push(*p);
                }
            }
        }
    }
    v
}

/// The protocol a found device probably wants.
#[allow(dead_code)]
pub fn guess_protocol(ports: &[u16]) -> crate::model::Protocol {
    use crate::model::Protocol;
    if ports.contains(&3389) {
        Protocol::Rdp
    } else if ports.contains(&22) {
        Protocol::Ssh
    } else if ports.contains(&443) {
        Protocol::Https
    } else if ports.contains(&80) {
        Protocol::Http
    } else if ports.contains(&5900) {
        Protocol::Vnc
    } else {
        Protocol::Ssh
    }
}
