//! Imports an mRemoteNG connection file (confCons.xml): folders, connections and – when the
//! file uses the default or a given password – the saved passwords.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::model::{Entry, Protocol};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::Engine as _;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::HashMap;

pub struct Imported {
    pub entries: Vec<Entry>,
    pub passwords_ok: usize,
    pub passwords_failed: usize,
}

type MremoteGcm = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U16>;

fn decrypt_mremote(text: &str, password: &str, iterations: u32) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD.decode(text.trim()).ok()?;
    if raw.len() < 16 + 16 + 16 {
        return None;
    }
    let salt = &raw[..16];
    let nonce = &raw[16..32];
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), salt, iterations.max(1), &mut key);
    let cipher = MremoteGcm::new_from_slice(&key).ok()?;
    let nonce = aes_gcm::aead::Nonce::<MremoteGcm>::try_from(nonce).ok()?;
    let plain = cipher.decrypt(&nonce, Payload { msg: &raw[32..], aad: salt }).ok()?;
    String::from_utf8(plain).ok()
}

fn attrs(e: &BytesStart) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for a in e.attributes().flatten() {
        let k = a.key.as_ref().to_string();
        #[allow(deprecated)]
        let v = a.unescape_value().map(|v| v.to_string()).unwrap_or_else(|_| a.value.to_string());
        m.insert(k, v);
    }
    m
}

fn protocol(s: &str) -> Protocol {
    match s.to_ascii_uppercase().as_str() {
        "RDP" => Protocol::Rdp,
        "VNC" => Protocol::Vnc,
        "SSH1" | "SSH2" => Protocol::Ssh,
        "SFTP" => Protocol::Sftp,
        "FTP" | "FTPS" => Protocol::Ftp,
        "TELNET" | "RLOGIN" | "RAW" => Protocol::Telnet,
        "HTTP" => Protocol::Http,
        "HTTPS" => Protocol::Https,
        "POWERSHELL" => Protocol::PowerShell,
        _ => Protocol::Ssh,
    }
}

/// `first_id` is the first free id; `parent` is where the imported tree goes.
pub fn import_mremoteng(xml: &str, master: &str, first_id: u64, parent: Option<u64>) -> Result<Imported, String> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<Option<u64>> = vec![parent];
    let mut out = Imported { entries: Vec::new(), passwords_ok: 0, passwords_failed: 0 };
    let mut next = first_id;
    let mut iterations = 1000u32;
    let mut password = if master.is_empty() { "mR3m".to_string() } else { master.to_string() };
    let mut saw_root = false;
    loop {
        let ev = reader.read_event().map_err(|e| tf("XML error: {0}", &[&e]))?;
        let (e, has_children) = match &ev {
            Event::Start(e) => (e.clone(), true),
            Event::Empty(e) => (e.clone(), false),
            Event::End(e) => {
                if e.name().as_ref() == "Node" {
                    stack.pop();
                    if stack.is_empty() {
                        stack.push(parent);
                    }
                }
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        let name = e.name().as_ref().to_string();
        if name == "mrng:Connections" || name == "Connections" {
            saw_root = true;
            let a = attrs(&e);
            if a.get("FullFileEncryption").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                return Err(tr("This file is fully encrypted. Please export it in mRemoteNG without \"full file encryption\".").into());
            }
            if let Some(k) = a.get("KdfIterations").and_then(|v| v.parse().ok()) {
                iterations = k;
            }
            if let Some(p) = a.get("Protected") {
                if decrypt_mremote(p, &password, iterations).is_none() && master.is_empty() {
                    // protected with an own password we don't know: import without passwords
                    password.clear();
                }
            }
            continue;
        }
        if name != "Node" {
            continue;
        }
        let a = attrs(&e);
        let get = |k: &str| a.get(k).cloned().unwrap_or_default();
        let is_folder = get("Type").eq_ignore_ascii_case("Container");
        let id = next;
        next += 1;
        let mut entry = Entry {
            id,
            parent: *stack.last().unwrap_or(&parent),
            folder: is_folder,
            expanded: true,
            name: if get("Name").is_empty() { tr("Unnamed").into() } else { get("Name") },
            description: get("Descr"),
            username: get("Username"),
            domain: get("Domain"),
            inherit_credentials: is_folder.then_some(false).unwrap_or(true),
            ..Default::default()
        };
        if !is_folder {
            entry.protocol = protocol(&get("Protocol"));
            entry.host = get("Hostname");
            entry.port = get("Port").parse().unwrap_or(entry.protocol.default_port());
            if entry.port == 0 {
                entry.port = entry.protocol.default_port();
            }
            entry.inherit_credentials = get("InheritUsername").eq_ignore_ascii_case("true")
                || get("InheritPassword").eq_ignore_ascii_case("true")
                || get("InheritDomain").eq_ignore_ascii_case("true");
            if get("RDPFullscreen") == "true" || get("Resolution") == "Fullscreen" {
                entry.rdp.fullscreen = true;
            }
            entry.rdp.admin_session = get("UseConsoleSession").eq_ignore_ascii_case("true");
            entry.rdp.redirect_drives = get("RedirectDiskDrives").eq_ignore_ascii_case("true");
        }
        let enc = get("Password");
        if !enc.is_empty() {
            match (!password.is_empty()).then(|| decrypt_mremote(&enc, &password, iterations)).flatten() {
                Some(p) => {
                    entry.password = p;
                    out.passwords_ok += 1;
                }
                None => out.passwords_failed += 1,
            }
        }
        out.entries.push(entry);
        if has_children {
            stack.push(Some(id));
        }
    }
    if !saw_root && out.entries.is_empty() {
        return Err(tr("No mRemoteNG connections found in the file.").into());
    }
    Ok(out)
}

/// Reads the hosts of an OpenSSH client configuration (~/.ssh/config) as SSH connections.
/// Wildcard patterns ("Host *") are skipped; ProxyJump to another imported host becomes its jump host.
pub fn import_ssh_config(text: &str, first_id: u64, parent: Option<u64>) -> Vec<Entry> {
    struct H {
        alias: String,
        host: String,
        user: String,
        port: u16,
        key: String,
        jump: String,
    }
    let mut hosts: Vec<H> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim().trim_start_matches('=').trim().trim_matches('"').to_string()),
            None => continue,
        };
        match k.as_str() {
            "host" => {
                current.clear();
                for alias in v.split_whitespace() {
                    if alias.contains('*') || alias.contains('?') || alias.starts_with('!') {
                        continue;
                    }
                    hosts.push(H { alias: alias.to_string(), host: String::new(), user: String::new(), port: 22, key: String::new(), jump: String::new() });
                    current.push(hosts.len() - 1);
                }
            }
            "match" => current.clear(),
            "hostname" => current.iter().for_each(|&i| hosts[i].host = v.clone()),
            "user" => current.iter().for_each(|&i| hosts[i].user = v.clone()),
            "port" => {
                let p = v.parse().unwrap_or(22);
                current.iter().for_each(|&i| hosts[i].port = p);
            }
            "identityfile" => current.iter().for_each(|&i| {
                if hosts[i].key.is_empty() {
                    hosts[i].key = v.clone();
                }
            }),
            "proxyjump" => current.iter().for_each(|&i| hosts[i].jump = v.clone()),
            _ => {}
        }
    }
    let mut out: Vec<Entry> = hosts
        .iter()
        .enumerate()
        .map(|(i, h)| Entry {
            id: first_id + i as u64,
            parent,
            name: h.alias.clone(),
            protocol: Protocol::Ssh,
            host: if h.host.is_empty() { h.alias.clone() } else { h.host.clone() },
            port: h.port,
            username: h.user.clone(),
            ssh_key: h.key.clone(),
            inherit_credentials: false,
            jump_mode: crate::model::JumpMode::ProxyJump,
            description: tr("From ~/.ssh/config").into(),
            ..Default::default()
        })
        .collect();
    for (i, h) in hosts.iter().enumerate() {
        if h.jump.is_empty() || h.jump.eq_ignore_ascii_case("none") {
            continue;
        }
        let first = h.jump.split(',').next().unwrap_or("");
        let alias = first.rsplit('@').next().unwrap_or("").split(':').next().unwrap_or("");
        match hosts.iter().position(|x| x.alias == alias) {
            Some(j) if j != i => out[i].jump_host = Some(first_id + j as u64),
            _ => out[i].extra_args = format!("-J {}", h.jump),
        }
    }
    out
}
