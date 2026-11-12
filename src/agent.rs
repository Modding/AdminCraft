//! Agent-ready: the same tools as a command line with JSON output (`admincraft cli …`) and as an
//! MCP server over stdio (`admincraft mcp`) for AI agents and automation.
//! Nothing here ever returns a password; opening a connection starts the normal window.

use crate::model::{Entry, Store};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Tool name, description, JSON schema of its arguments.
fn tool_list() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "list_connections",
            "List the saved connections (folder path, protocol, host, port, user, notes). Never includes passwords.",
            json!({"type": "object", "properties": {"filter": {"type": "string", "description": "Only entries whose name, host, user or notes contain this text"}}}),
        ),
        (
            "open_connection",
            "Open a saved connection in the AdminCraft window (a new window is started).",
            json!({"type": "object", "properties": {"name": {"type": "string", "description": "Name (or part of it) of the connection"}}, "required": ["name"]}),
        ),
        (
            "scan_network",
            "Scan an IP range (ping + TCP ports): which devices answer, their names, MAC addresses and open ports, and what changed against the saved baseline.",
            json!({"type": "object", "properties": {
                "range": {"type": "string", "description": "e.g. 192.168.1.0/24, 10.0.0.1-50"},
                "ports": {"type": "string", "description": "Ports to check, default 22,80,443,445,3389"},
                "timeout_ms": {"type": "integer", "description": "Per address, default 700"}
            }, "required": ["range"]}),
        ),
        (
            "port_scan",
            "Check which TCP ports of one host are open.",
            json!({"type": "object", "properties": {
                "host": {"type": "string"},
                "ports": {"type": "string", "description": "e.g. 22,80,443 or 1-1024 (default: common admin ports)"},
                "timeout_ms": {"type": "integer"}
            }, "required": ["host"]}),
        ),
        (
            "dns_lookup",
            "Resolve a host name to its IPv4 and IPv6 addresses with this computer's resolver.",
            json!({"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}),
        ),
        (
            "subnet",
            "Subnet calculator: network, mask, wildcard, broadcast, first/last address, usable hosts.",
            json!({"type": "object", "properties": {"cidr": {"type": "string", "description": "e.g. 192.168.10.77/26 or 10.0.0.5 255.255.255.0"}}, "required": ["cidr"]}),
        ),
        (
            "check_certificate",
            "Read a server's TLS certificate: subject, issuer, names, validity, days left, trusted or not.",
            json!({"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer", "description": "default 443"}}, "required": ["host"]}),
        ),
    ]
}

fn entry_json(store: &Store, e: &Entry) -> Value {
    json!({
        "id": e.id,
        "name": e.name,
        "folder": e.parent.map(|p| store.path_of(p)).unwrap_or_default(),
        "protocol": e.protocol.key(),
        "host": e.host,
        "port": e.port,
        "user": store.credential_info(e.id).user,
        "notes": e.description,
        "jump_host": e.jump_host.and_then(|j| store.get(j)).map(|j| j.name.clone()),
    })
}

fn s<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|v| !v.is_empty())
}

fn port_scan(host: &str, ports: &[u16], timeout: Duration) -> Result<Value, String> {
    let addr = (host, 0).to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("no address")?.ip();
    let open: Vec<u16> = std::thread::scope(|sc| {
        let chunks: Vec<Vec<u16>> = ports.chunks(ports.len().div_ceil(64).max(1)).map(|c| c.to_vec()).collect();
        let hs: Vec<_> = chunks
            .into_iter()
            .map(|c| sc.spawn(move || c.into_iter().filter(|&p| TcpStream::connect_timeout(&SocketAddr::new(addr, p), timeout).is_ok()).collect::<Vec<u16>>()))
            .collect();
        let mut v: Vec<u16> = hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect();
        v.sort_unstable();
        v
    });
    Ok(json!({
        "host": host, "address": addr.to_string(), "checked": ports.len(),
        "open": open.iter().map(|p| json!({"port": p, "service": crate::tools::well_known(*p)})).collect::<Vec<_>>()
    }))
}

/// Runs one tool. Errors become `{"error": …}` for the caller.
pub fn call(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "list_connections" => {
            let store = Store::open(true);
            if store.locked() && store.data.entries.is_empty() {
                return Err("The connection list is fully encrypted; set AC_MASTER to the master password.".into());
            }
            let f = s(args, "filter").map(|x| x.to_lowercase());
            let list: Vec<Value> = store
                .data
                .entries
                .iter()
                .filter(|e| !e.folder)
                .filter(|e| match &f {
                    None => true,
                    Some(f) => [&e.name, &e.host, &e.username, &e.description].iter().any(|t| t.to_lowercase().contains(f)),
                })
                .map(|e| entry_json(&store, e))
                .collect();
            Ok(json!({"count": list.len(), "connections": list}))
        }
        "open_connection" => {
            let n = s(args, "name").ok_or("name missing")?;
            let store = Store::open(true);
            let e = store
                .data
                .entries
                .iter()
                .find(|e| !e.folder && e.name.to_lowercase().contains(&n.to_lowercase()))
                .ok_or_else(|| format!("no connection named like '{n}'"))?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            std::process::Command::new(exe).args(["--open", &format!("connect:{}", e.name)]).spawn().map_err(|e| e.to_string())?;
            Ok(json!({"opened": e.name, "protocol": e.protocol.key(), "host": e.host}))
        }
        "scan_network" => {
            let range = s(args, "range").ok_or("range missing")?;
            let targets = crate::netscan::parse_targets(range)?;
            let ports = crate::tools::parse_ports(s(args, "ports").unwrap_or(crate::netscan::DEFAULT_PORTS))?;
            let timeout = args.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(700).clamp(100, 5000);
            let scan = crate::netscan::NetScan::start(targets, ports, timeout, true, eframe::egui::Context::default());
            let t0 = std::time::Instant::now();
            while !scan.state.lock().unwrap().finished && t0.elapsed().as_secs() < 600 {
                std::thread::sleep(Duration::from_millis(100));
            }
            let st = scan.state.lock().unwrap();
            let saved = crate::netscan::load(range);
            let changes: Vec<Value> = match &saved {
                Some(sv) => crate::netscan::diff(&st.hosts, &sv.hosts)
                    .into_iter()
                    .filter(|(_, c, _)| *c != crate::netscan::Change::Same)
                    .map(|(h, c, _)| json!({"ip": h.ip.to_string(), "change": format!("{c:?}").to_lowercase()}))
                    .collect(),
                None => Vec::new(),
            };
            Ok(json!({
                "range": range, "checked": st.total, "seconds": st.seconds,
                "hosts": st.hosts, "baseline_saved": saved.is_some(), "changes": changes
            }))
        }
        "port_scan" => {
            let host = s(args, "host").ok_or("host missing")?;
            let ports = crate::tools::parse_ports(s(args, "ports").unwrap_or(crate::tools::COMMON_PORTS))?;
            let timeout = args.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(600).clamp(100, 5000);
            port_scan(host, &ports, Duration::from_millis(timeout))
        }
        "dns_lookup" => {
            let n = s(args, "name").ok_or("name missing")?;
            let mut ips: Vec<String> = crate::tools::resolve(n)?.iter().map(|a| a.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            Ok(json!({"name": n, "addresses": ips}))
        }
        "subnet" => {
            let c = crate::admintools::subnet(s(args, "cidr").ok_or("cidr missing")?)?;
            Ok(json!({
                "network": format!("{}/{}", c.network, c.prefix), "mask": c.mask.to_string(), "wildcard": c.wildcard.to_string(),
                "broadcast": c.broadcast.to_string(), "first": c.first.to_string(), "last": c.last.to_string(), "usable": c.hosts
            }))
        }
        "check_certificate" => {
            let host = s(args, "host").ok_or("host missing")?;
            let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16;
            let c = crate::admintools::check_cert(host, port)?;
            Ok(json!({
                "subject": c.subject, "issuer": c.issuer, "names": c.names, "valid_from": c.not_before, "valid_until": c.not_after,
                "days_left": c.days_left, "trusted": c.trusted.is_ok(), "trust_error": c.trusted.err(), "protocol": c.protocol,
                "serial": c.serial, "chain_length": c.chain_len
            }))
        }
        _ => Err(format!("unknown tool '{name}'")),
    }
}

// ------------------------------------------------------------------ command line

const HELP: &str = "AdminCraft command line (JSON output)

  admincraft cli list [filter]                 saved connections (no passwords)
  admincraft cli open <name>                   open a connection in the window
  admincraft cli scan <range> [ports]          network scan, e.g. 192.168.1.0/24
  admincraft cli ports <host> [ports]          TCP port scan
  admincraft cli dns <name>                    resolve a host name
  admincraft cli subnet <cidr>                 subnet calculator
  admincraft cli cert <host> [port]            TLS certificate check
  admincraft mcp                               MCP server on stdin/stdout for AI agents
  admincraft --version

A fully encrypted connection list is read with the master password in AC_MASTER.";

pub fn cli(args: &[String]) -> i32 {
    let a = |i: usize| args.get(i).cloned().unwrap_or_default();
    let (tool, params) = match a(0).as_str() {
        "list" => ("list_connections", json!({"filter": a(1)})),
        "open" => ("open_connection", json!({"name": a(1)})),
        "scan" => ("scan_network", if args.len() > 2 { json!({"range": a(1), "ports": a(2)}) } else { json!({"range": a(1)}) }),
        "ports" => ("port_scan", if args.len() > 2 { json!({"host": a(1), "ports": a(2)}) } else { json!({"host": a(1)}) }),
        "dns" => ("dns_lookup", json!({"name": a(1)})),
        "subnet" => ("subnet", json!({"cidr": args[1..].join(" ")})),
        "cert" => ("check_certificate", json!({"host": a(1), "port": a(2).parse::<u16>().unwrap_or(443)})),
        _ => {
            println!("{HELP}");
            return if a(0).is_empty() || a(0) == "help" { 0 } else { 2 };
        }
    };
    match call(tool, &params) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            0
        }
        Err(e) => {
            println!("{}", json!({"error": e}));
            1
        }
    }
}

// ------------------------------------------------------------------ MCP over stdio

fn reply(out: &mut impl Write, id: &Value, result: Value) {
    let msg = json!({"jsonrpc": "2.0", "id": id, "result": result});
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

fn error(out: &mut impl Write, id: &Value, code: i64, text: &str) {
    let msg = json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": text}});
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

/// One JSON-RPC message per line (MCP stdio transport).
pub fn handle(line: &str, out: &mut impl Write) {
    // some shells put a byte-order mark in front of the first line
    let line = line.trim_start_matches('\u{feff}');
    let Ok(req) = serde_json::from_str::<Value>(line) else {
        error(out, &Value::Null, -32700, "parse error");
        return;
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if req.get("id").is_none() {
        return; // notifications (e.g. notifications/initialized) need no answer
    }
    match method {
        "initialize" => {
            let proto = req.pointer("/params/protocolVersion").and_then(|v| v.as_str()).unwrap_or("2025-06-18").to_string();
            reply(
                out,
                &id,
                json!({
                    "protocolVersion": proto,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "admincraft", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "AdminCraft: saved remote connections and network admin tools. Passwords are never returned."
                }),
            );
        }
        "ping" => reply(out, &id, json!({})),
        "tools/list" => {
            let tools: Vec<Value> = tool_list().into_iter().map(|(n, d, sch)| json!({"name": n, "description": d, "inputSchema": sch})).collect();
            reply(out, &id, json!({"tools": tools}));
        }
        "tools/call" => {
            let name = req.pointer("/params/name").and_then(|v| v.as_str()).unwrap_or("");
            let args = req.pointer("/params/arguments").cloned().unwrap_or(json!({}));
            let (text, is_error) = match call(name, &args) {
                Ok(v) => (serde_json::to_string_pretty(&v).unwrap_or_default(), false),
                Err(e) => (e, true),
            };
            reply(out, &id, json!({"content": [{"type": "text", "text": text}], "isError": is_error}));
        }
        _ => error(out, &id, -32601, "method not found"),
    }
}

pub fn mcp_main() -> i32 {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        handle(&line, &mut out);
    }
    0
}
