//! Small admin helpers: subnet calculator, TLS certificate check, password generator,
//! two-factor (TOTP) codes.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

// ------------------------------------------------------------------ subnet calculator

#[derive(Clone, Debug, PartialEq)]
pub struct Subnet {
    pub address: Ipv4Addr,
    pub prefix: u32,
    pub mask: Ipv4Addr,
    pub wildcard: Ipv4Addr,
    pub network: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub hosts: u64,
}

fn mask_to_prefix(m: Ipv4Addr) -> Option<u32> {
    let v = u32::from(m);
    let p = v.leading_ones();
    (v.checked_shl(p).unwrap_or(0) == 0).then_some(p)
}

/// "192.168.1.10/24", "192.168.1.10 255.255.255.0" or "192.168.1.10/255.255.255.0".
pub fn subnet(text: &str) -> Result<Subnet, String> {
    let t = text.trim();
    let (a, m) = t.split_once('/').or_else(|| t.split_once(' ')).unwrap_or((t, "24"));
    let address: Ipv4Addr = a.trim().parse().map_err(|_| tf("Invalid address: {0}", &[&a]))?;
    let m = m.trim();
    let prefix = if m.contains('.') {
        mask_to_prefix(m.parse().map_err(|_| tf("Invalid mask: {0}", &[&m]))?).ok_or_else(|| tf("Invalid mask: {0}", &[&m]))?
    } else {
        m.parse::<u32>().ok().filter(|p| *p <= 32).ok_or_else(|| tf("Invalid mask: {0}", &[&m]))?
    };
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let net = u32::from(address) & mask;
    let bc = net | !mask;
    let (first, last, hosts) = match prefix {
        32 => (net, net, 1),
        31 => (net, bc, 2),
        _ => (net + 1, bc - 1, (1u64 << (32 - prefix)) - 2),
    };
    Ok(Subnet {
        address,
        prefix,
        mask: mask.into(),
        wildcard: (!mask).into(),
        network: net.into(),
        broadcast: bc.into(),
        first: first.into(),
        last: last.into(),
        hosts,
    })
}

// ------------------------------------------------------------------ certificate check

#[derive(Clone, Debug)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub serial: String,
    pub trusted: Result<(), String>,
    pub protocol: String,
    pub chain_len: usize,
}

fn handshake(host: &str, port: u16, cfg: Arc<rustls::ClientConfig>) -> Result<rustls::ClientConnection, String> {
    let addr = (host, port).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or_else(|| tr("No address found.").to_string())?;
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(8)).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(8))).ok();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut conn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| e.to_string())?;
    }
    let _ = conn.writer().flush();
    let mut buf = [0u8; 1];
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1)));
    let _ = (&sock).read(&mut buf);
    Ok(conn)
}

fn fmt_ts(ts: i64) -> String {
    crate::timefmt::date(ts)
}

/// Connects with TLS, reads the server certificate and says whether it is trusted.
pub fn check_cert(host: &str, port: u16) -> Result<CertInfo, String> {
    let host = host.trim();
    let any = crate::transfer::tls_config(false)?;
    let conn = handshake(host, port, any)?;
    let certs = conn.peer_certificates().ok_or_else(|| tr("The server sent no certificate.").to_string())?;
    let first = certs.first().ok_or_else(|| tr("The server sent no certificate.").to_string())?;
    let (_, cert) = x509_parser::parse_x509_certificate(first.as_ref()).map_err(|e| e.to_string())?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                x509_parser::extensions::GeneralName::DNSName(d) => names.push(d.to_string()),
                x509_parser::extensions::GeneralName::IPAddress(ip) => names.push(format!("{ip:?}")),
                _ => {}
            }
        }
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let not_after = cert.validity().not_after.timestamp();
    let protocol = conn.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default();
    let trusted = handshake(host, port, crate::transfer::tls_config(true)?).map(|_| ());
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        names,
        not_before: fmt_ts(cert.validity().not_before.timestamp()),
        not_after: fmt_ts(not_after),
        days_left: (not_after - now).div_euclid(86400),
        serial: cert.raw_serial_as_string(),
        trusted,
        protocol,
        chain_len: certs.len(),
    })
}

// ------------------------------------------------------------------ password generator

#[derive(Clone, Debug)]
pub struct PwOptions {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leave out characters that look alike (0 O o l 1 I).
    pub no_similar: bool,
}

impl Default for PwOptions {
    fn default() -> Self {
        PwOptions { length: 20, upper: true, lower: true, digits: true, symbols: true, no_similar: true }
    }
}

/// A password from the system's random numbers. Without them there is an error and no password
/// (never one built from predictable bytes).
pub fn generate_password(o: &PwOptions) -> Result<String, String> {
    generate_password_with(o, &mut |buf| getrandom::fill(buf).map_err(|e| tf("No random numbers available: {0}", &[&e])))
}

/// The same with the random source handed in (tests).
pub fn generate_password_with(o: &PwOptions, random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>) -> Result<String, String> {
    let mut sets: Vec<Vec<char>> = Vec::new();
    let similar = |c: &char| o.no_similar && "0Oo1lI|".contains(*c);
    if o.upper {
        sets.push(('A'..='Z').filter(|c| !similar(c)).collect());
    }
    if o.lower {
        sets.push(('a'..='z').filter(|c| !similar(c)).collect());
    }
    if o.digits {
        sets.push(('0'..='9').filter(|c| !similar(c)).collect());
    }
    if o.symbols {
        sets.push("!#$%&*+-=?@_.:,;~".chars().filter(|c| !similar(c)).collect());
    }
    if sets.is_empty() {
        sets.push(('a'..='z').collect());
    }
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    let len = o.length.clamp(4, 128);
    // bytes at or above `limit` are thrown away, so every character is equally likely
    let limit = 256 - 256 % all.len();
    let mut buf = vec![0u8; len * 2];
    // a random source that keeps answering with unusable bytes ends in an error, not in a hang
    for _ in 0..1000 {
        let mut pw: Vec<char> = Vec::with_capacity(len);
        for _ in 0..64 {
            random(&mut buf)?;
            let missing = len - pw.len();
            pw.extend(buf.iter().filter(|&&b| (b as usize) < limit).filter_map(|&b| all.get(b as usize % all.len())).take(missing));
            if pw.len() == len {
                break;
            }
        }
        // every chosen kind of character must appear at least once
        if pw.len() == len && (sets.iter().all(|s| pw.iter().any(|c| s.contains(c))) || len < sets.len()) {
            return Ok(pw.into_iter().collect());
        }
    }
    Err(tf("No random numbers available: {0}", &[&tr("the random source repeats itself")]))
}

// ------------------------------------------------------------------ TOTP (two-factor codes)

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u64 = 0;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-') {
        let v = A.iter().position(|&x| x as char == c.to_ascii_uppercase())? as u64;
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    Some(out)
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&sha1::Sha1::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = sha1::Sha1::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = sha1::Sha1::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(ih);
    let mut r = [0u8; 20];
    r.copy_from_slice(&outer.finalize());
    r
}

/// Secret from an "otpauth://totp/...?secret=XXX&digits=6&period=30" link or a bare base32 key.
/// Returns (secret, digits, period).
pub fn parse_otp(text: &str) -> Option<(Vec<u8>, u32, u64)> {
    let t = text.trim();
    let (mut secret, mut digits, mut period) = (t.to_string(), 6u32, 30u64);
    if let Some(q) = t.split_once('?').map(|(_, q)| q).filter(|_| t.starts_with("otpauth://")) {
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            match k.to_lowercase().as_str() {
                "secret" => secret = v.replace("%3D", "="),
                "digits" => digits = v.parse().unwrap_or(6),
                "period" => period = v.parse().unwrap_or(30),
                _ => {}
            }
        }
    }
    let key = base32_decode(&secret)?;
    (!key.is_empty()).then_some((key, digits.clamp(6, 8), period.max(1)))
}

/// The code for `unix_time` and the seconds it stays valid.
pub fn totp(secret: &[u8], digits: u32, period: u64, unix_time: u64) -> (String, u64) {
    let counter = unix_time / period;
    let h = hmac_sha1(secret, &counter.to_be_bytes());
    let off = (h[19] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24) | ((h[off + 1] as u32) << 16) | ((h[off + 2] as u32) << 8) | h[off + 3] as u32;
    let code = bin % 10u32.pow(digits);
    (format!("{code:0width$}", width = digits as usize), period - unix_time % period)
}
