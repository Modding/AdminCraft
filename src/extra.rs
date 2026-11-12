//! Admin tool tabs: network scanner (with saved scans and differences), subnet calculator,
//! certificate check, password generator, SSH tunnels, Windows management tools.

use crate::admintools::{self, CertInfo, PwOptions};
use crate::i18n::{t as tr, tf};
use crate::launch::{Creds, JumpHop};
use crate::model::{Entry, Protocol, Settings, Tunnel};
use crate::netscan::{self, Change, NetScan, SavedScan, ScanHost};
use eframe::egui::{self, Color32, RichText};
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

pub const ACCENT: Color32 = Color32::from_rgb(33, 132, 230);
pub const OK_GREEN: Color32 = Color32::from_rgb(76, 175, 80);
pub const BAD_RED: Color32 = Color32::from_rgb(229, 72, 77);
pub const WARN: Color32 = Color32::from_rgb(230, 160, 40);

fn hidden(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let _ = cmd;
}

fn fmt_time(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{d:02}.{m:02}.{y} {:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60)
}

// ------------------------------------------------------------------ network scanner

pub struct NetScanTab {
    pub range: String,
    pub ports: String,
    pub timeout: u64,
    pub names: bool,
    pub scan: Option<NetScan>,
    pub error: Option<String>,
    /// The saved state the current result is compared with.
    pub saved: Option<SavedScan>,
    pub only_changes: bool,
    pub msg: Option<String>,
}

impl NetScanTab {
    pub fn new(range: String) -> NetScanTab {
        let range = if range.trim().is_empty() { netscan::local_subnets().into_iter().next().unwrap_or_else(|| "192.168.1.0/24".into()) } else { range };
        let saved = netscan::load(&range);
        NetScanTab { range, ports: netscan::DEFAULT_PORTS.into(), timeout: 700, names: true, scan: None, error: None, saved, only_changes: false, msg: None }
    }
}

pub enum NetScanAct {
    /// Create a connection for this device.
    Add(ScanHost, Protocol),
    /// Open this device right away.
    Connect(ScanHost, Protocol),
}

fn change_badge(ui: &mut egui::Ui, c: Change) {
    let (text, col) = match c {
        Change::New => (tr("NEU"), OK_GREEN),
        Change::Gone => (tr("WEG"), BAD_RED),
        Change::Changed => (tr("GEÄNDERT"), WARN),
        Change::Same => ("", Color32::TRANSPARENT),
    };
    if text.is_empty() {
        ui.label("");
    } else {
        egui::Frame::new().fill(col).corner_radius(3.0).inner_margin(egui::Margin::symmetric(5, 1)).show(ui, |ui| {
            ui.label(RichText::new(text).small().strong().color(Color32::WHITE));
        });
    }
}

pub fn netscan_ui(ui: &mut egui::Ui, t: &mut NetScanTab, ctx: &egui::Context) -> Vec<NetScanAct> {
    let mut acts = Vec::new();
    let running = t.scan.as_ref().map(|s| !s.state.lock().unwrap().finished).unwrap_or(false);
    egui::Grid::new("netscan_form").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
        ui.label(tr("Bereich"));
        ui.horizontal(|ui| {
            let r = ui.add(egui::TextEdit::singleline(&mut t.range).desired_width(240.0).hint_text("192.168.1.0/24"));
            if r.lost_focus() {
                t.saved = netscan::load(&t.range);
            }
            for s in netscan::local_subnets() {
                if ui.small_button(&s).on_hover_text(tr("Netz dieses PCs")).clicked() {
                    t.range = s.clone();
                    t.saved = netscan::load(&t.range);
                }
            }
            ui.weak(tr("z. B. 10.0.0.0/24, 10.0.0.1-50, 10.0.0.1-10.0.1.254"));
        });
        ui.end_row();
        ui.label(tr("Ports"));
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut t.ports).desired_width(240.0));
            ui.weak(tr("werden auf jedem gefundenen Gerät geprüft"));
        });
        ui.end_row();
        ui.label(tr("Wartezeit"));
        ui.horizontal(|ui| {
            ui.add(egui::DragValue::new(&mut t.timeout).range(100..=5000).suffix(" ms"));
            ui.checkbox(&mut t.names, tr("Namen auflösen"));
        });
        ui.end_row();
    });
    ui.horizontal(|ui| {
        if running {
            if ui.button(tr("Abbrechen")).clicked() {
                if let Some(s) = &t.scan {
                    s.cancel();
                }
            }
        } else if ui.add(egui::Button::new(RichText::new(tr("Scannen")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
            match (netscan::parse_targets(&t.range), crate::tools::parse_ports(if t.ports.trim().is_empty() { "80" } else { &t.ports })) {
                (Ok(targets), Ok(ports)) => {
                    t.error = None;
                    t.msg = None;
                    t.saved = netscan::load(&t.range);
                    let ports = if t.ports.trim().is_empty() { Vec::new() } else { ports };
                    t.scan = Some(NetScan::start(targets, ports, t.timeout, t.names, ctx.clone()));
                }
                (Err(e), _) | (_, Err(e)) => t.error = Some(e),
            }
        }
        let finished = t.scan.as_ref().map(|s| s.state.lock().unwrap().finished).unwrap_or(false);
        if ui
            .add_enabled(finished, egui::Button::new(tr("Als Vergleichsstand speichern")))
            .on_hover_text(tr("Der nächste Scan dieses Bereichs zeigt dann, was neu, weg oder geändert ist."))
            .clicked()
        {
            let hosts = t.scan.as_ref().map(|s| s.state.lock().unwrap().hosts.clone()).unwrap_or_default();
            match netscan::save(&t.range, &hosts) {
                Ok(s) => {
                    t.msg = Some(tf("Gespeichert: {0} Geräte.", &[&s.hosts.len()]));
                    t.saved = Some(s);
                }
                Err(e) => t.error = Some(e),
            }
        }
        if ui.add_enabled(finished, egui::Button::new(tr("Als Text kopieren"))).clicked() {
            if let Some(s) = &t.scan {
                let st = s.state.lock().unwrap();
                let text: String = st
                    .hosts
                    .iter()
                    .map(|h| format!("{}\t{}\t{}\t{}\n", h.ip, h.name, h.mac, h.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")))
                    .collect();
                ui.ctx().copy_text(text);
            }
        }
        ui.checkbox(&mut t.only_changes, tr("Nur Änderungen"));
        if let Some(e) = &t.error {
            ui.label(RichText::new(e).color(BAD_RED));
        }
        if let Some(m) = &t.msg {
            ui.label(RichText::new(m).color(OK_GREEN));
        }
    });
    match &t.saved {
        Some(s) => ui.weak(tf("Vergleich mit gespeichertem Stand vom {0} ({1} Geräte).", &[&fmt_time(s.time), &s.hosts.len()])),
        None => ui.weak(tr("Für diesen Bereich ist noch kein Vergleichsstand gespeichert.")),
    };
    ui.separator();
    let Some(scan) = &t.scan else {
        ui.weak(tr("Findet Geräte im Netz per Ping und Port-Abfrage. Nur in eigenen Netzen verwenden."));
        return acts;
    };
    let st = scan.state.lock().unwrap();
    let frac = if st.total == 0 { 0.0 } else { st.done as f32 / st.total as f32 };
    let status = if st.finished {
        tf("{0} Adressen geprüft in {1} s · {2} Geräte gefunden", &[&st.total, &format!("{:.1}", st.seconds), &st.hosts.len()])
    } else {
        tf("{0} / {1} geprüft · {2} gefunden", &[&st.done, &st.total, &st.hosts.len()])
    };
    ui.add(egui::ProgressBar::new(frac).text(status));
    let rows: Vec<(ScanHost, Change, Option<ScanHost>)> = match (&t.saved, st.finished) {
        (Some(s), true) => netscan::diff(&st.hosts, &s.hosts),
        _ => st.hosts.iter().map(|h| (h.clone(), Change::Same, None)).collect(),
    };
    drop(st);
    let (n_new, n_gone, n_chg) = rows.iter().fold((0, 0, 0), |a, r| match r.1 {
        Change::New => (a.0 + 1, a.1, a.2),
        Change::Gone => (a.0, a.1 + 1, a.2),
        Change::Changed => (a.0, a.1, a.2 + 1),
        Change::Same => a,
    });
    if t.saved.is_some() && scan.state.lock().unwrap().finished {
        ui.horizontal(|ui| {
            ui.label(RichText::new(tf("{0} neu", &[&n_new])).color(OK_GREEN).strong());
            ui.label(RichText::new(tf("{0} weg", &[&n_gone])).color(BAD_RED).strong());
            ui.label(RichText::new(tf("{0} geändert", &[&n_chg])).color(WARN).strong());
        });
    }
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("netscan_rows").striped(true).num_columns(7).spacing([16.0, 4.0]).show(ui, |ui| {
            for h in [tr("Status"), tr("IP-Adresse"), tr("Name"), tr("MAC-Adresse"), tr("Antwort"), tr("Offene Ports"), ""] {
                ui.label(RichText::new(h).strong());
            }
            ui.end_row();
            for (h, change, old) in rows.iter().filter(|r| !t.only_changes || r.1 != Change::Same) {
                change_badge(ui, *change);
                ui.label(RichText::new(h.ip.to_string()).monospace());
                ui.label(&h.name);
                let mac = ui.label(RichText::new(&h.mac).monospace());
                if let (Change::Changed, Some(o)) = (change, old) {
                    mac.on_hover_text(tf("Vorher: {0}", &[&o.mac]));
                }
                ui.label(h.rtt_ms.map(|r| format!("{r} ms")).unwrap_or_default());
                ui.label(h.ports.iter().map(|p| format!("{p} {}", crate::tools::well_known(*p))).collect::<Vec<_>>().join(", "));
                ui.horizontal(|ui| {
                    if *change != Change::Gone {
                        // what the open ports offer first, every other type below "Andere"
                        let found = netscan::protocol_candidates(&h.ports);
                        let others: Vec<Protocol> = Protocol::ALL.iter().copied().filter(|p| *p != Protocol::LocalShell && !found.contains(p)).collect();
                        let pick = |ui: &mut egui::Ui, acts: &mut Vec<NetScanAct>, add: bool| {
                            let mut chosen = None;
                            for p in &found {
                                if ui.button(format!("{}  ·  {} {}", p.label(), tr("Port"), p.default_port())).clicked() {
                                    chosen = Some(*p);
                                }
                            }
                            if !found.is_empty() {
                                ui.separator();
                            }
                            ui.menu_button(tr("Andere"), |ui| {
                                for p in &others {
                                    if ui.button(p.label()).clicked() {
                                        chosen = Some(*p);
                                    }
                                }
                            });
                            if let Some(p) = chosen {
                                acts.push(if add { NetScanAct::Add(h.clone(), p) } else { NetScanAct::Connect(h.clone(), p) });
                                ui.close();
                            }
                        };
                        ui.menu_button(tr("Öffnen …"), |ui| pick(ui, &mut acts, false));
                        ui.menu_button(tr("+ Verbindung …"), |ui| pick(ui, &mut acts, true))
                            .response
                            .on_hover_text(tr("Als Verbindung im Ordner „Netzwerk-Scan“ anlegen – Verbindungsart wählen"));
                        if ui.small_button(tr("kopieren")).clicked() {
                            ui.ctx().copy_text(h.ip.to_string());
                        }
                    }
                });
                ui.end_row();
            }
        });
    });
    acts
}

// ------------------------------------------------------------------ subnet calculator

#[derive(Default)]
pub struct SubnetTab {
    pub input: String,
}

pub fn subnet_ui(ui: &mut egui::Ui, t: &mut SubnetTab) -> Option<String> {
    let mut scan = None;
    ui.horizontal(|ui| {
        ui.label(tr("Adresse / Maske"));
        ui.add(egui::TextEdit::singleline(&mut t.input).desired_width(260.0).hint_text("192.168.10.77/26  oder  192.168.10.77 255.255.255.192"));
    });
    ui.separator();
    if t.input.trim().is_empty() {
        ui.weak(tr("Rechnet Netz, Broadcast, Maske und nutzbare Adressen aus."));
        return None;
    }
    match admintools::subnet(&t.input) {
        Ok(s) => {
            egui::Grid::new("subnet_res").num_columns(2).striped(true).spacing([24.0, 6.0]).show(ui, |ui| {
                let rows: Vec<(&str, String)> = vec![
                    (tr("Netz"), format!("{}/{}", s.network, s.prefix)),
                    (tr("Subnetzmaske"), s.mask.to_string()),
                    (tr("Wildcard"), s.wildcard.to_string()),
                    (tr("Broadcast"), s.broadcast.to_string()),
                    (tr("Erste Adresse"), s.first.to_string()),
                    (tr("Letzte Adresse"), s.last.to_string()),
                    (tr("Nutzbare Adressen"), s.hosts.to_string()),
                ];
                for (k, v) in rows {
                    ui.label(k);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&v).monospace().size(15.0));
                        if ui.small_button(tr("kopieren")).clicked() {
                            ui.ctx().copy_text(v.clone());
                        }
                    });
                    ui.end_row();
                }
            });
            ui.add_space(8.0);
            if s.prefix >= 16 && ui.button(tr("Dieses Netz scannen")).clicked() {
                scan = Some(format!("{}/{}", s.network, s.prefix));
            }
        }
        Err(e) => {
            ui.label(RichText::new(e).color(BAD_RED));
        }
    }
    scan
}

// ------------------------------------------------------------------ certificate check

pub type CertSlot = Arc<Mutex<Option<Result<CertInfo, String>>>>;

pub struct CertTab {
    pub host: String,
    pub port: u16,
    pub result: CertSlot,
    pub busy: Arc<Mutex<bool>>,
}

impl CertTab {
    pub fn new(host: String) -> CertTab {
        CertTab { host, port: 443, result: Default::default(), busy: Default::default() }
    }
}

pub fn cert_ui(ui: &mut egui::Ui, t: &mut CertTab, ctx: &egui::Context) {
    let busy = *t.busy.lock().unwrap();
    let mut go = false;
    ui.horizontal(|ui| {
        ui.label(tr("Host"));
        let r = ui.add(egui::TextEdit::singleline(&mut t.host).desired_width(260.0).hint_text("firma.de"));
        go |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.label(tr("Port"));
        ui.add(egui::DragValue::new(&mut t.port).range(1..=65535));
        if ui.add_enabled(!busy, egui::Button::new(RichText::new(tr("Prüfen")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
            go = true;
        }
        if busy {
            ui.spinner();
        }
    });
    if go && !busy && !t.host.trim().is_empty() {
        let (host, port, slot, flag, c2) = (t.host.trim().to_string(), t.port, t.result.clone(), t.busy.clone(), ctx.clone());
        *flag.lock().unwrap() = true;
        std::thread::spawn(move || {
            let r = admintools::check_cert(&host, port);
            *slot.lock().unwrap() = Some(r);
            *flag.lock().unwrap() = false;
            c2.request_repaint();
        });
    }
    ui.separator();
    let res = t.result.lock().unwrap();
    match res.as_ref() {
        None => {
            ui.weak(tr("Zeigt das TLS-Zertifikat eines Servers: für wen, von wem, wie lange gültig, vertrauenswürdig?"));
        }
        Some(Err(e)) => {
            ui.label(RichText::new(e).color(BAD_RED));
        }
        Some(Ok(c)) => {
            let col = if c.days_left < 0 { BAD_RED } else if c.days_left < 30 { WARN } else { OK_GREEN };
            let headline = if c.days_left < 0 { tf("Abgelaufen seit {0} Tagen", &[&-c.days_left]) } else { tf("Noch {0} Tage gültig", &[&c.days_left]) };
            ui.label(RichText::new(headline).size(18.0).strong().color(col));
            match &c.trusted {
                Ok(()) => ui.label(RichText::new(tr("Vertrauenswürdig (Kette und Name passen)")).color(OK_GREEN)),
                Err(e) => ui.label(RichText::new(tf("Nicht vertrauenswürdig: {0}", &[e])).color(WARN)),
            };
            ui.add_space(6.0);
            egui::Grid::new("cert_rows").num_columns(2).striped(true).spacing([20.0, 5.0]).show(ui, |ui| {
                let rows: Vec<(&str, String)> = vec![
                    (tr("Ausgestellt für"), c.subject.clone()),
                    (tr("Ausgestellt von"), c.issuer.clone()),
                    (tr("Namen (SAN)"), c.names.join(", ")),
                    (tr("Gültig ab"), c.not_before.clone()),
                    (tr("Gültig bis"), c.not_after.clone()),
                    (tr("Seriennummer"), c.serial.clone()),
                    (tr("Protokoll"), c.protocol.clone()),
                    (tr("Zertifikate in der Kette"), c.chain_len.to_string()),
                ];
                for (k, v) in rows {
                    ui.label(k);
                    ui.add(egui::Label::new(RichText::new(v).monospace()).wrap());
                    ui.end_row();
                }
            });
        }
    }
}

// ------------------------------------------------------------------ password generator

pub struct PwGen {
    pub open: bool,
    pub opts: PwOptions,
    pub value: String,
    /// Connection whose password field "Übernehmen" fills.
    pub target: Option<u64>,
}

impl Default for PwGen {
    fn default() -> Self {
        PwGen { open: false, opts: PwOptions::default(), value: String::new(), target: None }
    }
}

/// Returns a password to put into the target connection.
pub fn pwgen_window(ctx: &egui::Context, g: &mut PwGen) -> Option<(u64, String)> {
    if !g.open {
        return None;
    }
    if g.value.is_empty() {
        g.value = admintools::generate_password(&g.opts);
    }
    let mut apply = None;
    let mut open = true;
    egui::Window::new(tr("Passwort-Generator")).open(&mut open).resizable(false).show(ctx, |ui| {
        let mut changed = false;
        changed |= ui.add(egui::Slider::new(&mut g.opts.length, 8..=64).text(tr("Länge"))).changed();
        ui.horizontal_wrapped(|ui| {
            changed |= ui.checkbox(&mut g.opts.upper, "A-Z").changed();
            changed |= ui.checkbox(&mut g.opts.lower, "a-z").changed();
            changed |= ui.checkbox(&mut g.opts.digits, "0-9").changed();
            changed |= ui.checkbox(&mut g.opts.symbols, "!#$%").changed();
            changed |= ui.checkbox(&mut g.opts.no_similar, tr("ohne Verwechsler (0 O l 1)")).changed();
        });
        if changed {
            g.value = admintools::generate_password(&g.opts);
        }
        ui.add(egui::TextEdit::singleline(&mut g.value).font(egui::TextStyle::Monospace).desired_width(360.0));
        ui.horizontal(|ui| {
            if ui.button(tr("Neu")).clicked() {
                g.value = admintools::generate_password(&g.opts);
            }
            if ui.button(tr("Kopieren")).clicked() {
                ui.ctx().copy_text(g.value.clone());
            }
            if let Some(id) = g.target {
                if ui.add(egui::Button::new(RichText::new(tr("Für die Verbindung übernehmen")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
                    apply = Some((id, g.value.clone()));
                }
            }
        });
    });
    g.open = open && apply.is_none();
    apply
}

// ------------------------------------------------------------------ SSH tunnels

pub struct TunnelRun {
    pub child: Option<Child>,
    #[allow(dead_code)]
    pub label: String,
    pub error: Option<String>,
}

/// `ssh -N -L local:remote_host:remote_port user@host` in the background (password via
/// AdminCraft's askpass, jump hosts as -J).
pub fn start_tunnel(e: &Entry, c: &Creds, jumps: &[JumpHop], t: &Tunnel, settings: &Settings) -> Result<Child, String> {
    let ssh = crate::programs::find("ssh", settings).ok_or_else(|| tr("OpenSSH (ssh) nicht gefunden.").to_string())?;
    let port = if e.port == 0 { 22 } else { e.port };
    let mut args: Vec<String> = vec![
        "-N".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ServerAliveInterval=30".into(),
        "-o".into(),
        "BatchMode=no".into(),
        "-L".into(),
        format!("{}:{}:{}", t.local_port, t.remote_host.trim(), t.remote_port),
        "-p".into(),
        port.to_string(),
    ];
    if !e.ssh_key.trim().is_empty() {
        args.push("-i".into());
        args.push(e.ssh_key.trim().into());
    }
    let mut hops: Vec<crate::transfer::Hop> = Vec::new();
    if !jumps.is_empty() {
        args.push("-J".into());
        args.push(
            jumps
                .iter()
                .map(|j| {
                    let p = if j.entry.port == 0 { 22 } else { j.entry.port };
                    let uh = if j.creds.user.is_empty() { j.entry.host.trim().to_string() } else { format!("{}@{}", j.creds.user, j.entry.host.trim()) };
                    if p == 22 { uh } else { format!("{uh}:{p}") }
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        for j in jumps {
            hops.push(crate::transfer::Hop { user: j.creds.user.clone(), host: j.entry.host.trim().into(), port: 22, password: j.creds.password.clone() });
        }
    }
    hops.push(crate::transfer::Hop { user: c.user.clone(), host: e.host.trim().into(), port, password: c.password.clone() });
    args.push(if c.user.is_empty() { e.host.trim().to_string() } else { format!("{}@{}", c.user, e.host.trim()) });
    let mut cmd = Command::new(ssh);
    cmd.args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    for (k, v) in crate::transfer::askpass_env(&hops) {
        cmd.env(k, v);
    }
    hidden(&mut cmd);
    cmd.spawn().map_err(|err| err.to_string())
}

pub enum TunnelAct {
    Start(u64, usize),
    Stop(u64, usize),
}

pub fn tunnels_ui(ui: &mut egui::Ui, entries: &[Entry], runs: &mut HashMap<(u64, usize), TunnelRun>) -> Vec<TunnelAct> {
    let mut acts = Vec::new();
    ui.label(tr("Portweiterleitungen über SSH: ein lokaler Port auf diesem PC führt zu einem Dienst hinter dem Server."));
    ui.weak(tr("Tunnel legst du an der SSH-Verbindung an (Eigenschaften » Tunnel)."));
    ui.separator();
    let mut any = false;
    egui::Grid::new("tunnel_rows").striped(true).num_columns(5).spacing([18.0, 6.0]).show(ui, |ui| {
        for h in [tr("Verbindung"), tr("Lokal"), tr("Ziel (vom Server aus)"), tr("Status"), ""] {
            ui.label(RichText::new(h).strong());
        }
        ui.end_row();
        for e in entries.iter().filter(|e| !e.tunnels.is_empty()) {
            for (i, t) in e.tunnels.iter().enumerate() {
                any = true;
                ui.label(&e.name);
                ui.label(RichText::new(format!("localhost:{}", t.local_port)).monospace());
                ui.label(RichText::new(format!("{}:{}", t.remote_host, t.remote_port)).monospace());
                let mut run = runs.get_mut(&(e.id, i));
                let alive = run.as_mut().and_then(|r| r.child.as_mut()).map(|c| matches!(c.try_wait(), Ok(None))).unwrap_or(false);
                if alive {
                    ui.label(RichText::new(tr("läuft")).color(OK_GREEN));
                } else if let Some(err) = run.and_then(|r| r.error.clone()) {
                    ui.label(RichText::new(err).color(BAD_RED));
                } else {
                    ui.label(RichText::new(tr("aus")).weak());
                }
                ui.horizontal(|ui| {
                    if alive {
                        if ui.small_button(tr("Stoppen")).clicked() {
                            acts.push(TunnelAct::Stop(e.id, i));
                        }
                        if ui.small_button(tr("Im Browser")).on_hover_text(tr("http://localhost:<Port> öffnen")).clicked() {
                            let _ = crate::launch::open_url(&format!("http://localhost:{}", t.local_port));
                        }
                    } else if ui.small_button(tr("Starten")).clicked() {
                        acts.push(TunnelAct::Start(e.id, i));
                    }
                });
                ui.end_row();
            }
        }
    });
    if !any {
        ui.add_space(10.0);
        ui.weak(tr("Noch keine Tunnel angelegt."));
    }
    acts
}

/// Watches running tunnels: a tunnel that ended gets the reason from ssh's error output.
pub fn poll_tunnels(runs: &mut HashMap<(u64, usize), TunnelRun>) {
    for r in runs.values_mut() {
        if let Some(c) = r.child.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                let mut text = String::new();
                if let Some(mut err) = c.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_string(&mut text);
                }
                let line = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string();
                r.error = Some(if line.is_empty() { tf("beendet (Code {0})", &[&status.code().unwrap_or(-1)]) } else { line });
                r.child = None;
            }
        }
    }
}

// ------------------------------------------------------------------ Windows management tools

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WinTool {
    Services,
    Events,
    Manage,
    Share,
}

pub fn open_windows_tool(tool: WinTool, host: &str) -> Result<String, String> {
    let host = host.trim().trim_start_matches("\\\\");
    let (prog, args): (&str, Vec<String>) = match tool {
        WinTool::Services => ("mmc", vec!["services.msc".into(), format!("/computer={host}")]),
        WinTool::Events => ("eventvwr", vec![host.to_string()]),
        WinTool::Manage => ("mmc", vec!["compmgmt.msc".into(), format!("/computer=\\\\{host}")]),
        WinTool::Share => ("explorer", vec![format!("\\\\{host}\\c$")]),
    };
    Command::new(prog).args(&args).spawn().map(|_| tf("{0} geöffnet: {1}", &[&prog, &host])).map_err(|e| e.to_string())
}

/// Windows computers: shutdown /r or /s on the remote machine (needs admin rights there).
pub fn windows_power(host: &str, reboot: bool) -> Result<String, String> {
    let mut cmd = Command::new("shutdown");
    cmd.args([if reboot { "/r" } else { "/s" }, "/f", "/t", "0", "/m", &format!("\\\\{}", host.trim())]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    hidden(&mut cmd);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(if reboot { tf("Neustart an {0} geschickt.", &[&host]) } else { tf("Herunterfahren an {0} geschickt.", &[&host]) })
    } else {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if msg.is_empty() { tf("shutdown meldet Code {0} (Rechte? Firewall?)", &[&out.status.code().unwrap_or(-1)]) } else { msg })
    }
}

/// Where a session log is written: AdminCraftData/logs/<name>_<date-time>.log
pub fn session_log_path(name: &str) -> std::path::PathBuf {
    let safe: String = name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let stamp = fmt_time(secs).replace([' ', ':', '.'], "-").replace("-UTC", "");
    crate::model::data_dir(false).join("logs").join(format!("{safe}_{stamp}.log"))
}
