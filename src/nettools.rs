//! Network tools: WHOIS lookups, an HTTP header and redirect check, and a small SNMP v2c
//! client with hand-written BER encoding over UDP.
//!
//! Everything here is plain logic without any GUI. All network functions block, so the app
//! calls them from a background thread.

use crate::i18n::{t as tr, tf};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------------------------
// WHOIS
// ---------------------------------------------------------------------------------------------

/// Largest answer kept from one WHOIS server.
const WHOIS_MAX_ANSWER: usize = 256 * 1024;
/// Most WHOIS servers asked for one lookup (IANA, the registry, the registrar).
const WHOIS_MAX_SERVERS: usize = 3;
/// Where every lookup starts.
const WHOIS_ROOT: &str = "whois.iana.org";

/// The outcome of a WHOIS lookup: the servers asked, in order, and their answers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WhoisResult {
    /// Servers asked, in order (the first is always whois.iana.org).
    pub servers: Vec<String>,
    /// Every server's answer, each preceded by a line `--- <server> ---`.
    pub text: String,
}

/// Looks up a domain name or an IP address over WHOIS (TCP port 43).
///
/// Starts at whois.iana.org and follows referrals (`refer:`, `whois:`, `Registrar WHOIS
/// Server:`, `ReferralServer:`) to at most three servers in total. IP queries to ARIN are sent
/// as `n + <ip>`. Each answer is capped at 256 KiB. When a later server fails, the answers
/// collected so far are kept and the error is noted in the text under that server's header.
pub fn whois(query: &str, timeout: Duration) -> Result<WhoisResult, String> {
    let query = query.trim();
    if query.is_empty() {
        return Err(tr("Enter a domain name or IP address.").to_string());
    }
    if query.len() > 255 || query.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(tr("The query must be a single domain name or IP address.").to_string());
    }
    let ip: Option<IpAddr> = query
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok();
    let plain_query = match ip {
        Some(ip) => ip.to_string(),
        None => query.trim_end_matches('.').to_string(),
    };

    let mut result = WhoisResult::default();
    let mut next = Some(WHOIS_ROOT.to_string());
    while let Some(server) = next.take() {
        if result.servers.len() >= WHOIS_MAX_SERVERS {
            break;
        }
        let request = whois_request(&server, &plain_query, ip);
        if !result.text.is_empty() {
            result.text.push('\n');
        }
        match whois_ask(&server, &request, timeout) {
            Ok(answer) => {
                result.text.push_str(&format!("--- {server} ---\n"));
                result.text.push_str(answer.trim_end());
                result.text.push('\n');
                next = parse_referral(&answer)
                    .filter(|r| !r.eq_ignore_ascii_case(&server))
                    .filter(|r| !result.servers.iter().any(|s| s.eq_ignore_ascii_case(r)));
                result.servers.push(server);
            }
            Err(e) if result.servers.is_empty() => return Err(e),
            Err(e) => {
                result.text.push_str(&format!("--- {server} ---\n{e}\n"));
                result.servers.push(server);
            }
        }
    }
    Ok(result)
}

/// The query line sent to one server: ARIN wants `n + <ip>` for addresses.
fn whois_request(server: &str, query: &str, ip: Option<IpAddr>) -> String {
    match ip {
        Some(ip) if server.to_ascii_lowercase().contains("arin.net") => format!("n + {ip}"),
        _ => query.to_string(),
    }
}

/// Finds the next WHOIS server named in an answer.
///
/// Looks, in this order, for `refer:` and `whois:` (IANA), `Registrar WHOIS Server:` (thin
/// registries such as Verisign) and `ReferralServer:` (ARIN). Keys are matched without regard
/// to case or leading spaces; a `whois://` prefix is removed and `rwhois://` or web addresses
/// are skipped. Returns the host (possibly with `:port`) in lower case.
pub fn parse_referral(answer: &str) -> Option<String> {
    const KEYS: [&str; 4] = ["refer", "whois", "registrar whois server", "referralserver"];
    for key in KEYS {
        for line in answer.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            if !k.trim().eq_ignore_ascii_case(key) {
                continue;
            }
            if let Some(host) = clean_referral(v) {
                return Some(host);
            }
        }
    }
    None
}

/// Turns a referral value into a plain host name, or `None` when it isn't one.
fn clean_referral(value: &str) -> Option<String> {
    let mut v = value.trim();
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("rwhois://") || lower.starts_with("http://") || lower.starts_with("https://")
    {
        return None;
    }
    if lower.starts_with("whois://") {
        v = &v["whois://".len()..];
    }
    let v = v.trim_end_matches('/');
    if v.is_empty() || v.len() > 255 || !(v.contains('.') || v.contains(':')) {
        return None;
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
    {
        return None;
    }
    Some(v.to_ascii_lowercase())
}

/// Splits `host`, `host:port` or `[v6]:port` into host and port.
fn split_host_port(server: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = server.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host.to_string(), port);
        }
    }
    if server.matches(':').count() == 1 {
        if let Some((host, port)) = server.split_once(':') {
            if let Ok(port) = port.parse() {
                return (host.to_string(), port);
            }
        }
    }
    (server.to_string(), default_port)
}

/// Sends one query to one WHOIS server and reads its answer (at most 256 KiB).
fn whois_ask(server: &str, request: &str, timeout: Duration) -> Result<String, String> {
    let timeout = timeout.max(Duration::from_millis(1));
    let (host, port) = split_host_port(server, 43);
    let addrs: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| tf("Cannot resolve {0}: {1}", &[&host, &e]))?
        .collect();
    if addrs.is_empty() {
        return Err(tf("No address found for {0}.", &[&host]));
    }
    let mut stream = None;
    let mut last_error = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_error = e.to_string(),
        }
    }
    let Some(mut stream) = stream else {
        return Err(tf("Cannot connect to {0}: {1}", &[&server, &last_error]));
    };
    let _ = stream.set_write_timeout(Some(timeout));
    stream
        .write_all(format!("{request}\r\n").as_bytes())
        .map_err(|e| tf("Cannot send the query to {0}: {1}", &[&server, &e]))?;

    let deadline = Instant::now() + timeout;
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let take = n.min(WHOIS_MAX_ANSWER - data.len());
                data.extend_from_slice(&buf[..take]);
                if data.len() >= WHOIS_MAX_ANSWER {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(e) => {
                if data.is_empty() {
                    return Err(tf("Reading the answer from {0} failed: {1}", &[&server, &e]));
                }
                break;
            }
        }
    }
    if data.is_empty() {
        return Err(tf("No answer from {0} within the time limit.", &[&server]));
    }
    Ok(decode_text(data))
}

/// Decodes a server answer: UTF-8 when valid, otherwise Latin-1; line ends become `\n`.
fn decode_text(data: Vec<u8>) -> String {
    let text = match String::from_utf8(data) {
        Ok(s) => s,
        Err(e) => e.into_bytes().iter().map(|&b| char::from(b)).collect(),
    };
    text.replace("\r\n", "\n").replace('\r', "\n")
}

// ---------------------------------------------------------------------------------------------
// HTTP header check
// ---------------------------------------------------------------------------------------------

/// Most requests made by one check (the first plus redirects).
const HTTP_MAX_HOPS: usize = 10;

/// One request of an HTTP check: the address asked, the answer's status and headers, and how
/// long the answer took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpHop {
    pub url: String,
    pub status: u16,
    /// Header names in lower case, in the order received; repeated headers appear repeatedly.
    pub headers: Vec<(String, String)>,
    pub millis: u128,
}

/// The verdict on one security header of the final answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityHeader {
    /// The header's usual spelling, e.g. `Strict-Transport-Security`.
    pub name: &'static str,
    pub present: bool,
    /// Its value (repeated headers joined with `, `), empty when absent.
    pub value: String,
    /// Short advice, already translated; `OK` when nothing needs doing.
    pub advice: &'static str,
}

/// A cookie the server set: its name and flags only, never its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieInfo {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    /// The SameSite attribute as sent, empty when not set.
    pub same_site: String,
}

/// The result of an HTTP check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReport {
    /// Every request in order; the last one is the final answer.
    pub hops: Vec<HttpHop>,
    /// Security headers of the final answer.
    pub security: Vec<SecurityHeader>,
    /// Cookies set along the way (all hops).
    pub cookies: Vec<CookieInfo>,
}

/// Fetches a URL with GET and reports every redirect hop, the security headers of the final
/// answer and the cookies set along the way.
///
/// `https://` is added when the URL has no scheme. Redirects are followed by hand (relative
/// `Location` values are resolved against the current URL), at most 10 requests in total.
/// Non-2xx statuses are results, not errors. Bodies are never read, cookies and credentials
/// are never sent (user info in the URL is dropped).
pub fn http_check(url: &str, timeout: Duration) -> Result<HttpReport, String> {
    let input = url.trim();
    if input.is_empty() {
        return Err(tr("Enter a URL.").to_string());
    }
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let mut current = Url::parse(&with_scheme)?;
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .user_agent(format!("AdminCraft/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent();

    let mut hops: Vec<HttpHop> = Vec::new();
    loop {
        let address = current.to_string();
        let started = Instant::now();
        let response = agent
            .get(&address)
            .call()
            .map_err(|e| tf("Request to {0} failed: {1}", &[&address, &e]))?;
        let millis = started.elapsed().as_millis();
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        // The body is never read: dropping the response closes the connection.
        drop(response);
        let location = if (300..400).contains(&status) {
            header_values(&headers, "location")
                .into_iter()
                .next()
                .map(str::to_string)
        } else {
            None
        };
        hops.push(HttpHop {
            url: address,
            status,
            headers,
            millis,
        });
        let Some(location) = location else {
            break;
        };
        if hops.len() >= HTTP_MAX_HOPS {
            break;
        }
        match current.join(&location) {
            Some(next) => current = next,
            None => break,
        }
    }

    let cookies = hops.iter().flat_map(|h| parse_cookies(&h.headers)).collect();
    let security = match hops.last() {
        Some(last) => evaluate_security(&last.headers, last.url.starts_with("https://")),
        None => Vec::new(),
    };
    Ok(HttpReport {
        hops,
        security,
        cookies,
    })
}

/// All values of a header (name compared without regard to case), trimmed.
fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect()
}

/// All values of a header joined with `, `, or `None` when it is absent.
fn header_joined(headers: &[(String, String)], name: &str) -> Option<String> {
    let values = header_values(headers, name);
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// The `max-age` of a Strict-Transport-Security value, in seconds.
fn hsts_max_age(value: &str) -> Option<u64> {
    value.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("max-age") {
            v.trim().trim_matches('"').parse().ok()
        } else {
            None
        }
    })
}

/// Rates the security headers of an answer: Strict-Transport-Security (only meaningful over
/// HTTPS), Content-Security-Policy, X-Content-Type-Options, X-Frame-Options (or CSP
/// `frame-ancestors`), Referrer-Policy and Permissions-Policy. Header names are compared
/// without regard to case. The list always has these six entries in this order.
pub fn evaluate_security(headers: &[(String, String)], https: bool) -> Vec<SecurityHeader> {
    let ok = tr("OK");
    let mut out = Vec::with_capacity(6);

    // Strict-Transport-Security
    let hsts = header_joined(headers, "strict-transport-security");
    let advice = if !https {
        tr("Only effective over HTTPS; browsers ignore it on plain HTTP.")
    } else {
        match &hsts {
            None => tr("Missing: add max-age=31536000; includeSubDomains."),
            Some(v) => match hsts_max_age(v) {
                Some(age) if age >= 15_552_000 => ok,
                _ => tr("max-age is missing or short; use at least 180 days."),
            },
        }
    };
    out.push(SecurityHeader {
        name: "Strict-Transport-Security",
        present: hsts.is_some(),
        value: hsts.unwrap_or_default(),
        advice,
    });

    // Content-Security-Policy
    let csp = header_joined(headers, "content-security-policy");
    let advice = match &csp {
        None if header_joined(headers, "content-security-policy-report-only").is_some() => {
            tr("Only a report-only policy is set; it does not block anything.")
        }
        None => tr(
            "Missing: add a policy that limits where scripts and other content may load from.",
        ),
        Some(v) => {
            let lower = v.to_ascii_lowercase();
            if lower.contains("'unsafe-inline'") || lower.contains("'unsafe-eval'") {
                tr("Allows 'unsafe-inline' or 'unsafe-eval', which weakens protection against XSS.")
            } else {
                ok
            }
        }
    };
    let frame_ancestors = csp.as_deref().and_then(|v| {
        v.split([';', ','])
            .map(str::trim)
            .find(|d| d.to_ascii_lowercase().starts_with("frame-ancestors"))
            .map(str::to_string)
    });
    out.push(SecurityHeader {
        name: "Content-Security-Policy",
        present: csp.is_some(),
        value: csp.unwrap_or_default(),
        advice,
    });

    // X-Content-Type-Options
    let xcto = header_joined(headers, "x-content-type-options");
    let advice = match &xcto {
        None => tr("Missing: add X-Content-Type-Options: nosniff."),
        Some(v) if v.trim().eq_ignore_ascii_case("nosniff") => ok,
        Some(_) => tr("The value should be nosniff."),
    };
    out.push(SecurityHeader {
        name: "X-Content-Type-Options",
        present: xcto.is_some(),
        value: xcto.unwrap_or_default(),
        advice,
    });

    // X-Frame-Options or CSP frame-ancestors
    let xfo = header_joined(headers, "x-frame-options");
    let advice = match (&xfo, &frame_ancestors) {
        (_, Some(_)) => ok,
        (Some(v), None) => {
            let v = v.trim();
            if v.eq_ignore_ascii_case("deny") || v.eq_ignore_ascii_case("sameorigin") {
                ok
            } else {
                tr("The value should be DENY or SAMEORIGIN (or use CSP frame-ancestors).")
            }
        }
        (None, None) => {
            tr("Missing: add X-Frame-Options: DENY or a CSP frame-ancestors directive.")
        }
    };
    let value = match (&xfo, &frame_ancestors) {
        (Some(x), Some(f)) => format!("{x}; {f}"),
        (Some(x), None) => x.clone(),
        (None, Some(f)) => f.clone(),
        (None, None) => String::new(),
    };
    out.push(SecurityHeader {
        name: "X-Frame-Options",
        present: xfo.is_some() || frame_ancestors.is_some(),
        value,
        advice,
    });

    // Referrer-Policy (browsers use the last policy they understand)
    let referrer = header_joined(headers, "referrer-policy");
    let advice = match &referrer {
        None => tr("Missing: add e.g. Referrer-Policy: strict-origin-when-cross-origin."),
        Some(v) => {
            let last = v.rsplit(',').next().unwrap_or("").trim().to_ascii_lowercase();
            if last == "unsafe-url" || last == "no-referrer-when-downgrade" {
                tr("This policy sends full URLs to other sites.")
            } else {
                ok
            }
        }
    };
    out.push(SecurityHeader {
        name: "Referrer-Policy",
        present: referrer.is_some(),
        value: referrer.unwrap_or_default(),
        advice,
    });

    // Permissions-Policy
    let permissions = header_joined(headers, "permissions-policy");
    let advice = match &permissions {
        Some(_) => ok,
        None if header_joined(headers, "feature-policy").is_some() => {
            tr("Only the outdated Feature-Policy is set; switch to Permissions-Policy.")
        }
        None => tr("Missing: add it to switch off browser features the site does not use."),
    };
    out.push(SecurityHeader {
        name: "Permissions-Policy",
        present: permissions.is_some(),
        value: permissions.unwrap_or_default(),
        advice,
    });

    out
}

/// Lists the cookies set by `Set-Cookie` headers: names and the Secure, HttpOnly and
/// SameSite attributes. Cookie values are never kept. A header without `=` in its first
/// part, or with an empty name, is ignored.
pub fn parse_cookies(headers: &[(String, String)]) -> Vec<CookieInfo> {
    headers
        .iter()
        .filter(|(n, _)| n.trim().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| {
            let mut parts = v.split(';');
            let (name, _) = parts.next()?.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let mut info = CookieInfo {
                name: name.to_string(),
                secure: false,
                http_only: false,
                same_site: String::new(),
            };
            for attr in parts {
                let (key, value) = attr.split_once('=').unwrap_or((attr, ""));
                match key.trim().to_ascii_lowercase().as_str() {
                    "secure" => info.secure = true,
                    "httponly" => info.http_only = true,
                    "samesite" => info.same_site = value.trim().to_string(),
                    _ => {}
                }
            }
            Some(info)
        })
        .collect()
}

/// A minimal http(s) URL: enough to follow redirects. User info is always dropped and the
/// fragment is never kept.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Url {
    scheme: String,
    authority: String,
    /// Path plus query; always starts with `/`.
    path: String,
}

impl Url {
    fn parse(text: &str) -> Result<Url, String> {
        let invalid = || tf("Not a valid URL: {0}", &[&text]);
        let (scheme, rest) = text.trim().split_once("://").ok_or_else(invalid)?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(tf("Only http and https URLs are supported: {0}", &[&text]));
        }
        let rest = rest.split('#').next().unwrap_or("");
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        if authority.is_empty() || authority.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid());
        }
        let mut path = rest[end..].to_string();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        Ok(Url {
            scheme,
            authority: authority.to_string(),
            path,
        })
    }

    /// Resolves a `Location` value against this URL. `None` when it points somewhere that
    /// isn't http(s).
    fn join(&self, location: &str) -> Option<Url> {
        let loc = location.trim();
        let loc = loc.split('#').next().unwrap_or("");
        if loc.is_empty() {
            return Some(self.clone());
        }
        if let Some(scheme_end) = loc.find("://") {
            let scheme = &loc[..scheme_end];
            if !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            {
                return Url::parse(loc).ok();
            }
        }
        if let Some(rest) = loc.strip_prefix("//") {
            return Url::parse(&format!("{}://{rest}", self.scheme)).ok();
        }
        let (base_path, _) = split_query(&self.path);
        let combined = if loc.starts_with('/') {
            loc.to_string()
        } else if loc.starts_with('?') {
            format!("{base_path}{loc}")
        } else {
            let dir = &base_path[..base_path.rfind('/').map_or(0, |i| i + 1)];
            format!("{dir}{loc}")
        };
        let (path, query) = split_query(&combined);
        let mut path = remove_dot_segments(path);
        if let Some(query) = query {
            path.push('?');
            path.push_str(query);
        }
        Some(Url {
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            path,
        })
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.authority, self.path)
    }
}

fn split_query(path: &str) -> (&str, Option<&str>) {
    match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    }
}

/// Removes `.` and `..` segments from an absolute path (RFC 3986, section 5.2.4).
fn remove_dot_segments(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len().saturating_sub(1);
    let mut out: Vec<&str> = Vec::new();
    for (i, segment) in segments.iter().enumerate().skip(1) {
        match *segment {
            "." => {
                if i == last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if i == last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

// ---------------------------------------------------------------------------------------------
// SNMP v2c
// ---------------------------------------------------------------------------------------------

/// A value in an SNMP answer.
#[derive(Clone, Debug, PartialEq)]
pub enum SnmpValue {
    Int(i64),
    Bytes(Vec<u8>),
    Oid(String),
    Ip([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Counter64(u64),
    Null,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    Other(u8, Vec<u8>),
}

impl fmt::Display for SnmpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpValue::Int(v) => write!(f, "{v}"),
            SnmpValue::Bytes(b) => match std::str::from_utf8(b) {
                Ok(s) if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') => write!(f, "{}", s.trim_end_matches('\0')),
                _ => write!(f, "{}", b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")),
            },
            SnmpValue::Oid(o) => write!(f, "{o}"),
            SnmpValue::Ip(a) => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            SnmpValue::Counter32(v) | SnmpValue::Gauge32(v) => write!(f, "{v}"),
            SnmpValue::TimeTicks(t) => {
                let s = t / 100;
                write!(f, "{}d {:02}:{:02}:{:02}", s / 86400, (s / 3600) % 24, (s / 60) % 60, s % 60)
            }
            SnmpValue::Counter64(v) => write!(f, "{v}"),
            SnmpValue::Null => write!(f, "null"),
            SnmpValue::NoSuchObject => write!(f, "{}", tr("(no such object)")),
            SnmpValue::NoSuchInstance => write!(f, "{}", tr("(no such instance)")),
            SnmpValue::EndOfMibView => write!(f, "{}", tr("(end of MIB)")),
            SnmpValue::Other(tag, b) => write!(f, "[0x{tag:02x}] {}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
        }
    }
}

impl SnmpValue {
    fn as_u64(&self) -> Option<u64> {
        match self {
            SnmpValue::Int(v) if *v >= 0 => Some(*v as u64),
            SnmpValue::Counter32(v) | SnmpValue::Gauge32(v) | SnmpValue::TimeTicks(v) => Some(*v as u64),
            SnmpValue::Counter64(v) => Some(*v),
            _ => None,
        }
    }
}

pub const PDU_GET: u8 = 0xA0;
pub const PDU_GETNEXT: u8 = 0xA1;
const PDU_RESPONSE: u8 = 0xA2;

fn ber_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    ber_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn ber_int(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut i = 0;
    // shortest two's complement form
    while i < 7 && ((bytes[i] == 0 && bytes[i + 1] & 0x80 == 0) || (bytes[i] == 0xff && bytes[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    tlv(0x02, &bytes[i..])
}

/// "1.3.6.1.2.1.1.1.0" as BER (without tag and length).
pub fn encode_oid(oid: &str) -> Result<Vec<u8>, String> {
    let arcs: Vec<u64> = oid.trim().trim_start_matches('.').split('.').map(|a| a.parse::<u64>()).collect::<Result<_, _>>().map_err(|_| tf("Not an OID: {0}", &[&oid]))?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return Err(tf("Not an OID: {0}", &[&oid]));
    }
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        out.extend(tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    Ok(out)
}

pub fn decode_oid(b: &[u8]) -> Result<String, String> {
    let mut arcs: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for (i, &x) in b.iter().enumerate() {
        v = v.checked_shl(7).ok_or("OID too long")? | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (v / 40).min(2);
                arcs.push(first);
                arcs.push(v - first * 40);
            } else {
                arcs.push(v);
            }
            v = 0;
        } else if i == b.len() - 1 {
            return Err("OID cut off".into());
        }
    }
    Ok(arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("."))
}

/// A whole SNMP v2c request message.
pub fn encode_get(community: &str, request_id: i32, pdu_type: u8, oids: &[&str]) -> Result<Vec<u8>, String> {
    let mut binds = Vec::new();
    for o in oids {
        let mut vb = tlv(0x06, &encode_oid(o)?);
        vb.extend(tlv(0x05, &[]));
        binds.extend(tlv(0x30, &vb));
    }
    let mut pdu = ber_int(request_id as i64);
    pdu.extend(ber_int(0));
    pdu.extend(ber_int(0));
    pdu.extend(tlv(0x30, &binds));
    let mut msg = ber_int(1); // version 2c
    msg.extend(tlv(0x04, community.as_bytes()));
    msg.extend(tlv(pdu_type, &pdu));
    Ok(tlv(0x30, &msg))
}

struct Ber<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Ber<'a> {
    fn next(&mut self) -> Result<(u8, &'a [u8]), String> {
        let bad = || tr("The SNMP answer is damaged.").to_string();
        let tag = *self.b.get(self.pos).ok_or_else(bad)?;
        let first = *self.b.get(self.pos + 1).ok_or_else(bad)?;
        self.pos += 2;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(bad());
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *self.b.get(self.pos).ok_or_else(bad)? as usize;
                self.pos += 1;
            }
            l
        };
        let end = self.pos.checked_add(len).filter(|e| *e <= self.b.len()).ok_or_else(bad)?;
        let content = &self.b[self.pos..end];
        self.pos = end;
        Ok((tag, content))
    }

    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }
}

fn be_int(b: &[u8]) -> i64 {
    let mut v: i64 = if b.first().is_some_and(|x| x & 0x80 != 0) { -1 } else { 0 };
    for &x in b.iter().take(8) {
        v = (v << 8) | x as i64;
    }
    v
}

fn be_uint(b: &[u8]) -> u64 {
    b.iter().skip_while(|x| **x == 0).take(8).fold(0u64, |v, x| (v << 8) | *x as u64)
}

fn value_of(tag: u8, c: &[u8]) -> Result<SnmpValue, String> {
    Ok(match tag {
        0x02 => SnmpValue::Int(be_int(c)),
        0x04 => SnmpValue::Bytes(c.to_vec()),
        0x05 => SnmpValue::Null,
        0x06 => SnmpValue::Oid(decode_oid(c)?),
        0x40 if c.len() == 4 => SnmpValue::Ip([c[0], c[1], c[2], c[3]]),
        0x41 => SnmpValue::Counter32(be_uint(c) as u32),
        0x42 => SnmpValue::Gauge32(be_uint(c) as u32),
        0x43 => SnmpValue::TimeTicks(be_uint(c) as u32),
        0x46 => SnmpValue::Counter64(be_uint(c)),
        0x80 => SnmpValue::NoSuchObject,
        0x81 => SnmpValue::NoSuchInstance,
        0x82 => SnmpValue::EndOfMibView,
        other => SnmpValue::Other(other, c.to_vec()),
    })
}

/// Reads a GetResponse: request id, error status and the (OID, value) pairs.
pub fn decode_response(bytes: &[u8]) -> Result<(i32, i64, Vec<(String, SnmpValue)>), String> {
    let bad = || tr("The SNMP answer is damaged.").to_string();
    let (tag, msg) = Ber { b: bytes, pos: 0 }.next()?;
    if tag != 0x30 {
        return Err(bad());
    }
    let mut m = Ber { b: msg, pos: 0 };
    let _version = m.next()?;
    let _community = m.next()?;
    let (ptag, pdu) = m.next()?;
    if ptag != PDU_RESPONSE {
        return Err(bad());
    }
    let mut p = Ber { b: pdu, pos: 0 };
    let id = be_int(p.next()?.1) as i32;
    let err = be_int(p.next()?.1);
    let _index = p.next()?;
    let (_, binds) = p.next()?;
    let mut list = Ber { b: binds, pos: 0 };
    let mut out = Vec::new();
    while !list.done() {
        let (_, vb) = list.next()?;
        let mut v = Ber { b: vb, pos: 0 };
        let (otag, oid) = v.next()?;
        if otag != 0x06 {
            return Err(bad());
        }
        let (vtag, val) = v.next()?;
        out.push((decode_oid(oid)?, value_of(vtag, val)?));
    }
    Ok((id, err, out))
}

static REQUEST_ID: AtomicU32 = AtomicU32::new(0);

fn next_request_id() -> i32 {
    if REQUEST_ID.load(Ordering::Relaxed) == 0 {
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(1) | 1;
        let _ = REQUEST_ID.compare_exchange(0, seed & 0x3fff_ffff, Ordering::Relaxed, Ordering::Relaxed);
    }
    (REQUEST_ID.fetch_add(1, Ordering::Relaxed) & 0x7fff_ffff) as i32
}

fn snmp_exchange(host: &str, port: u16, community: &str, pdu_type: u8, oids: &[&str], timeout: Duration) -> Result<Vec<(String, SnmpValue)>, String> {
    let addr: SocketAddr = (host.trim(), port).to_socket_addrs().map_err(|e| tf("{0}: {1}", &[&host, &e]))?.next().ok_or_else(|| tf("{0}: no address", &[&host]))?;
    let local: SocketAddr = if addr.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let sock = UdpSocket::bind(local).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let id = next_request_id();
    let req = encode_get(community, id, pdu_type, oids)?;
    let mut buf = vec![0u8; 65535];
    for _try in 0..2 {
        sock.send_to(&req, addr).map_err(|e| e.to_string())?;
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from.ip() == addr.ip() => {
                    let (rid, err, binds) = decode_response(&buf[..n])?;
                    if rid != id {
                        continue;
                    }
                    if err != 0 {
                        return Err(tf("The device refused the request (SNMP error {0}).", &[&err]));
                    }
                    return Ok(binds);
                }
                Ok(_) => continue,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                // Windows reports "port unreachable" as a reset: nothing listens there
                Err(e) if e.kind() == ErrorKind::ConnectionReset => return Err(tf("No SNMP service on {0} (port {1} is closed).", &[&host, &port])),
                Err(e) => return Err(e.to_string()),
            }
        }
    }
    Err(tf("No SNMP answer from {0} (wrong community, SNMP off, or a firewall).", &[&host]))
}

pub fn snmp_get(host: &str, port: u16, community: &str, oids: &[&str], timeout: Duration) -> Result<Vec<(String, SnmpValue)>, String> {
    snmp_exchange(host, port, community, PDU_GET, oids, timeout)
}

/// All values below `root` (GETNEXT, one by one), at most `max`.
pub fn snmp_walk(host: &str, port: u16, community: &str, root: &str, max: usize, timeout: Duration) -> Result<Vec<(String, SnmpValue)>, String> {
    let root = root.trim().trim_start_matches('.').to_string();
    encode_oid(&root)?;
    let prefix = format!("{root}.");
    let mut out = Vec::new();
    let mut cur = root.clone();
    while out.len() < max {
        let r = snmp_exchange(host, port, community, PDU_GETNEXT, &[&cur], timeout)?;
        let Some((oid, val)) = r.into_iter().next() else { break };
        if !oid.starts_with(&prefix) || matches!(val, SnmpValue::EndOfMibView) || oid == cur {
            break;
        }
        cur = oid.clone();
        out.push((oid, val));
    }
    Ok(out)
}

#[derive(Clone, Debug, Default)]
pub struct SnmpInterface {
    pub index: u32,
    pub name: String,
    pub admin_up: Option<bool>,
    pub oper_up: Option<bool>,
    pub speed_mbit: Option<u64>,
    pub mac: String,
    pub in_octets: Option<u64>,
    pub out_octets: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct SnmpOverview {
    pub descr: String,
    pub name: String,
    pub uptime: String,
    pub contact: String,
    pub location: String,
    pub object_id: String,
    pub interfaces: Vec<SnmpInterface>,
}

const SYS: [(&str, &str); 6] = [
    ("1.3.6.1.2.1.1.1.0", "sysDescr.0"),
    ("1.3.6.1.2.1.1.2.0", "sysObjectID.0"),
    ("1.3.6.1.2.1.1.3.0", "sysUpTime.0"),
    ("1.3.6.1.2.1.1.4.0", "sysContact.0"),
    ("1.3.6.1.2.1.1.5.0", "sysName.0"),
    ("1.3.6.1.2.1.1.6.0", "sysLocation.0"),
];

const COLUMNS: [(&str, &str); 13] = [
    ("1.3.6.1.2.1.2.2.1.1", "ifIndex"),
    ("1.3.6.1.2.1.2.2.1.2", "ifDescr"),
    ("1.3.6.1.2.1.2.2.1.3", "ifType"),
    ("1.3.6.1.2.1.2.2.1.5", "ifSpeed"),
    ("1.3.6.1.2.1.2.2.1.6", "ifPhysAddress"),
    ("1.3.6.1.2.1.2.2.1.7", "ifAdminStatus"),
    ("1.3.6.1.2.1.2.2.1.8", "ifOperStatus"),
    ("1.3.6.1.2.1.2.2.1.10", "ifInOctets"),
    ("1.3.6.1.2.1.2.2.1.16", "ifOutOctets"),
    ("1.3.6.1.2.1.31.1.1.1.1", "ifName"),
    ("1.3.6.1.2.1.31.1.1.1.6", "ifHCInOctets"),
    ("1.3.6.1.2.1.31.1.1.1.10", "ifHCOutOctets"),
    ("1.3.6.1.2.1.31.1.1.1.15", "ifHighSpeed"),
];

/// A friendly name for the common system and interface OIDs ("1.3.6.1.2.1.1.5.0" → "sysName.0",
/// "1.3.6.1.2.1.2.2.1.2.3" → "ifDescr.3").
pub fn oid_name(oid: &str) -> Option<String> {
    let oid = oid.trim().trim_start_matches('.');
    if let Some((_, n)) = SYS.iter().find(|(o, _)| *o == oid) {
        return Some((*n).to_string());
    }
    COLUMNS.iter().find_map(|(col, n)| oid.strip_prefix(col).and_then(|rest| rest.strip_prefix('.')).map(|idx| format!("{n}.{idx}")))
}

/// Name, description, uptime, contact, location and the interfaces of a device.
pub fn snmp_overview(host: &str, port: u16, community: &str, timeout: Duration) -> Result<SnmpOverview, String> {
    let sys = snmp_get(host, port, community, &SYS.map(|s| s.0), timeout)?;
    let text = |oid: &str| sys.iter().find(|(o, _)| o == oid).map(|(_, v)| v.to_string()).unwrap_or_default();
    let mut ov = SnmpOverview {
        descr: text(SYS[0].0),
        object_id: text(SYS[1].0),
        uptime: text(SYS[2].0),
        contact: text(SYS[3].0),
        name: text(SYS[4].0),
        location: text(SYS[5].0),
        interfaces: Vec::new(),
    };
    let mut by_index: BTreeMap<u32, SnmpInterface> = BTreeMap::new();
    for (col, name) in COLUMNS.iter().skip(1) {
        if *name == "ifType" {
            continue;
        }
        // a device without IF-MIB's extra table just answers nothing there
        let rows = snmp_walk(host, port, community, col, 512, timeout).unwrap_or_default();
        for (oid, val) in rows {
            let Some(idx) = oid.rsplit('.').next().and_then(|i| i.parse::<u32>().ok()) else { continue };
            let i = by_index.entry(idx).or_insert_with(|| SnmpInterface { index: idx, ..Default::default() });
            match *name {
                "ifDescr" if i.name.is_empty() => i.name = val.to_string(),
                "ifName" => {
                    let n = val.to_string();
                    if !n.is_empty() {
                        i.name = n;
                    }
                }
                "ifSpeed" if i.speed_mbit.is_none() => i.speed_mbit = val.as_u64().filter(|s| *s > 0 && *s < u32::MAX as u64).map(|s| s / 1_000_000),
                "ifHighSpeed" => {
                    if let Some(s) = val.as_u64().filter(|s| *s > 0) {
                        i.speed_mbit = Some(s);
                    }
                }
                "ifPhysAddress" => {
                    if let SnmpValue::Bytes(b) = &val {
                        i.mac = b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":");
                    }
                }
                "ifAdminStatus" => i.admin_up = val.as_u64().map(|v| v == 1),
                "ifOperStatus" => i.oper_up = val.as_u64().map(|v| v == 1),
                "ifInOctets" if i.in_octets.is_none() => i.in_octets = val.as_u64(),
                "ifOutOctets" if i.out_octets.is_none() => i.out_octets = val.as_u64(),
                "ifHCInOctets" => i.in_octets = val.as_u64().or(i.in_octets),
                "ifHCOutOctets" => i.out_octets = val.as_u64().or(i.out_octets),
                _ => {}
            }
        }
    }
    ov.interfaces = by_index.into_values().collect();
    Ok(ov)
}