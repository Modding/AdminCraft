//! Admin tools: ping / traceroute / nslookup runner, port scanner, DNS lookup, Wake-on-LAN,
//! and a quick reachability check for the connection tree.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
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

/// Runs a system command and collects its output line by line.
pub struct CmdRunner {
    pub lines: Arc<Mutex<Vec<String>>>,
    pub running: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

impl Default for CmdRunner {
    fn default() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            child: Arc::new(Mutex::new(None)),
        }
    }
}

impl CmdRunner {
    pub fn start(&mut self, program: &str, args: &[String], ctx: eframe::egui::Context) {
        self.stop();
        let lines = Arc::new(Mutex::new(vec![format!("> {} {}", program, args.join(" "))]));
        self.lines = lines.clone();
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
                *self.child.lock().unwrap() = Some(child);
                self.running.store(true, Ordering::SeqCst);
                let running = self.running.clone();
                let child_slot = self.child.clone();
                let l2 = lines.clone();
                let c2 = ctx.clone();
                if let Some(mut err) = err {
                    std::thread::spawn(move || {
                        let mut buf = Vec::new();
                        let _ = err.read_to_end(&mut buf);
                        let text = decode(&buf);
                        if !text.trim().is_empty() {
                            l2.lock().unwrap().extend(text.lines().map(|s| s.to_string()));
                            c2.request_repaint();
                        }
                    });
                }
                std::thread::spawn(move || {
                    if let Some(out) = out {
                        let mut reader = BufReader::new(out);
                        let mut buf = Vec::new();
                        loop {
                            buf.clear();
                            match reader.read_until(b'\n', &mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {
                                    let line = decode(&buf).trim_end().to_string();
                                    lines.lock().unwrap().push(line);
                                    ctx.request_repaint();
                                }
                            }
                        }
                    }
                    if let Some(mut c) = child_slot.lock().unwrap().take() {
                        let _ = c.wait();
                    }
                    lines.lock().unwrap().push(tr("— done —").into());
                    running.store(false, Ordering::SeqCst);
                    ctx.request_repaint();
                });
            }
            Err(e) => {
                lines.lock().unwrap().push(tf("Could not start '{0}': {1}", &[&program, &e]));
            }
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn text(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }
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
    if cfg!(windows) {
        ("tracert".into(), vec!["-d".into(), host.into()])
    } else {
        ("traceroute".into(), vec!["-n".into(), host.into()])
    }
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
    (host.trim(), 0)
        .to_socket_addrs()
        .map(|i| i.collect())
        .map_err(|e| tf("Name can't be resolved: {0}", &[&e]))
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
        std::thread::spawn(move || {
            let addr = match resolve(&host) {
                Ok(a) if !a.is_empty() => a.iter().find(|a| a.is_ipv4()).copied().unwrap_or(a[0]).ip(),
                Ok(_) => {
                    let mut s = st.lock().unwrap();
                    s.error = Some(tr("No address found.").into());
                    s.finished = true;
                    return;
                }
                Err(e) => {
                    let mut s = st.lock().unwrap();
                    s.error = Some(e);
                    s.finished = true;
                    ctx.request_repaint();
                    return;
                }
            };
            st.lock().unwrap().address = addr.to_string();
            let ports = Arc::new(ports);
            let next = Arc::new(AtomicUsize::new(0));
            let workers = 128.min(ports.len()).max(1);
            let mut handles = Vec::new();
            for _ in 0..workers {
                let ports = ports.clone();
                let next = next.clone();
                let st = st.clone();
                let cc = cc.clone();
                let ctx = ctx.clone();
                handles.push(std::thread::spawn(move || loop {
                    if cc.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= ports.len() {
                        break;
                    }
                    let p = ports[i];
                    let ok = TcpStream::connect_timeout(&SocketAddr::new(addr, p), Duration::from_millis(timeout_ms)).is_ok();
                    let mut s = st.lock().unwrap();
                    s.done += 1;
                    if ok {
                        s.open.push(p);
                        s.open.sort_unstable();
                    }
                    if s.done % 16 == 0 || ok {
                        ctx.request_repaint();
                    }
                }));
            }
            for h in handles {
                let _ = h.join();
            }
            st.lock().unwrap().finished = true;
            ctx.request_repaint();
        });
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
        let mut m = map.lock().unwrap();
        for (id, _, _) in &targets {
            m.insert(*id, None);
        }
    }
    let queue = Arc::new(Mutex::new(targets));
    for _ in 0..24 {
        let queue = queue.clone();
        let map = map.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || loop {
            let Some((id, host, port)) = queue.lock().unwrap().pop() else { break };
            let ok = match (host.as_str(), port).to_socket_addrs() {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|a| TcpStream::connect_timeout(&a, Duration::from_millis(1500)).is_ok())
                    .unwrap_or(false),
                Err(_) => false,
            };
            map.lock().unwrap().insert(id, Some(ok));
            ctx.request_repaint();
        });
    }
}
