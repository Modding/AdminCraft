//! The AdminCraft window: connection tree, tabs, properties, tools and dialogs.
#![allow(deprecated)]

use crate::i18n::{t as tr, tf};
use crate::embed::{self, Embedded, PxRect};
use crate::extra::{self, NetScanAct, TunnelAct};
use crate::keepass_vault::KeePassVault;
use crate::launch::{self, Creds, JumpHop, Launch};
use crate::model::{CredSource, Entry, JumpMode, Protocol, SshClient, Store, TransferTool};
use crate::programs;
use crate::terminal::Terminal;
use crate::tools::{self, CmdRunner, PortScan, StatusMap};
use crate::transfer::{self, Job, Kind, LocalItem, Transfer};
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Sense, Stroke, Vec2};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Arc, Mutex};

#[path = "app_control.rs"]
mod app_control;

const ACCENT: Color32 = Color32::from_rgb(33, 132, 230);
const OK_GREEN: Color32 = Color32::from_rgb(76, 175, 80);
const BAD_RED: Color32 = Color32::from_rgb(229, 72, 77);
const WARN: Color32 = Color32::from_rgb(230, 160, 40);

// ---------------------------------------------------------------- tabs

struct TermTab {
    entry: Entry,
    creds: Creds,
    jumps: Vec<JumpHop>,
    term: Option<Terminal>,
    error: Option<String>,
    preview: String,
    /// Typing here also goes to every other tab with this switch on.
    broadcast: bool,
}

/// An outside program (Remotedesktop, PuTTY, VNC viewer) – its window sits in the tab on Windows.
struct ProcTab {
    entry: Entry,
    creds: Creds,
    jumps: Vec<JumpHop>,
    child: Option<Child>,
    embed: Option<Embedded>,
    want_embed: bool,
    label: String,
    started: f64,
    last_try: f64,
    exited: Option<String>,
    detached: bool,
}

#[allow(dead_code)]
struct TransferTab {
    entry: Entry,
    creds: Creds,
    jumps: Vec<JumpHop>,
    xfer: Transfer,
    local_dir: PathBuf,
    local_edit: String,
    local_items: Vec<LocalItem>,
    local_err: Option<String>,
    local_sel: BTreeSet<String>,
    remote_edit: String,
    remote_sel: BTreeSet<String>,
    shown_cwd: String,
    dialog: Option<XferDialog>,
}

enum XferDialog {
    Mkdir { remote: bool, name: String },
    Rename { remote: bool, from: String, to: String },
    Delete { remote: bool, names: Vec<(String, bool)> },
}

/// What to do with a connection once its passwords are known.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum How {
    Default,
    Transfer(Kind),
    OpenSshWindow,
    Putty,
    /// Hand the server to WinSCP / FileZilla (program key).
    FileApp(&'static str),
}

#[derive(Clone)]
struct Pending {
    entry: Entry,
    how: How,
}

enum Need {
    KeePass,
    Ask(u64),
}

struct AskState {
    pending: Pending,
    key: u64,
    name: String,
    user: String,
    pw: String,
    focus: bool,
}

struct PingTab {
    host: String,
    continuous: bool,
    mode: PingMode,
    runner: CmdRunner,
}

#[derive(PartialEq, Clone, Copy)]
enum PingMode {
    Ping,
    Trace,
}

struct ScanTab {
    host: String,
    ports: String,
    timeout: u64,
    scan: Option<PortScan>,
    error: Option<String>,
}

type DnsResult = Arc<Mutex<Option<Result<Vec<String>, String>>>>;

struct DnsTab {
    host: String,
    result: DnsResult,
    runner: CmdRunner,
    rtype: String,
    server: String,
}

struct WolTab {
    mac: String,
    broadcast: String,
    port: u16,
    result: Option<Result<String, String>>,
}

enum TabKind {
    Start,
    Settings,
    Term(Box<TermTab>),
    Proc(Box<ProcTab>),
    Transfer(Box<TransferTab>),
    Ping(PingTab),
    Scan(ScanTab),
    Dns(DnsTab),
    Wol(WolTab),
    NetScan(Box<extra::NetScanTab>),
    Subnet(extra::SubnetTab),
    Cert(extra::CertTab),
    Tunnels,
    Help(Box<crate::help::HelpTab>),
    Playback(Box<crate::playback::PlaybackTab>),
    Tool(Box<crate::tooltabs::ToolTab>),
}

#[allow(dead_code)]
struct Tab {
    id: u64,
    title: String,
    color: Color32,
    kind: TabKind,
}

// ---------------------------------------------------------------- tree actions

enum Act {
    Select(u64),
    Connect(u64),
    Toggle(u64),
    NewConn(Option<u64>),
    NewFolder(Option<u64>),
    Duplicate(u64),
    AskDelete(u64),
    MoveTo(u64, Option<u64>),
    Shift(u64, bool),
    ConnectAll(u64),
    Ping(u64),
    Scan(u64),
    Wake(u64),
    Files(u64),
    OpenSsh(u64),
    Putty(u64),
    FileApp(u64, &'static str),
    /// Drag & drop in the tree: (dragged, target, where).
    Drop(u64, u64, DropPos),
    /// Dropped on the empty space below the tree: top level, last.
    DropEnd(u64),
    WinTool(u64, extra::WinTool),
    Power(u64, bool),
    StartTunnels(u64),
    CheckCert(u64),
    /// Whois / HTTP header check / SNMP for a connection's host.
    NetTool(u64, crate::tooltabs::ToolKind),
    /// Export a folder (or everything with None).
    Export(Option<u64>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DropPos {
    Before,
    Into,
    After,
}

struct Toast {
    text: String,
    error: bool,
    until: f64,
}

struct Shot {
    path: PathBuf,
    frames: u32,
    requested: bool,
    image: Arc<Mutex<Option<Arc<egui::ColorImage>>>>,
}

pub struct AdminApp {
    store: Store,
    selected: Option<u64>,
    filter: String,
    tabs: Vec<Tab>,
    active: usize,
    next_tab: u64,
    quick_protocol: Protocol,
    quick_host: String,
    log: Vec<String>,
    status: StatusMap,
    dirty_since: Option<f64>,
    unlock_pw: String,
    unlock_failed: bool,
    show_settings: bool,
    new_master: String,
    new_master2: String,
    settings_msg: Option<String>,
    show_import: bool,
    import_path: String,
    import_pw: String,
    import_msg: Option<(bool, String)>,
    show_about: bool,
    show_keys: bool,
    /// A "?" asked for this chapter of the user guide (opened after the frame's drawing).
    help_request: Option<crate::help::Topic>,
    /// The channel agents use to control this window (None when switched off).
    control: Option<crate::control::Server>,
    /// Result of "Check for updates" (None inside while it runs).
    update_result: Option<std::sync::Arc<std::sync::Mutex<Option<Result<crate::update::Outcome, String>>>>>,
    releases_url: String,
    focus_search: bool,
    close_request: Option<usize>,
    show_props: bool,
    confirm_delete: Option<u64>,
    show_password: bool,
    toast: Option<Toast>,
    pending_connect: Vec<u64>,
    system_check: Vec<(&'static str, String, bool)>,
    applied_dark: Option<bool>,
    shot: Option<Shot>,
    keepass: KeePassVault,
    kp_dialog: bool,
    /// "Save password in KeePass": connection id, the password typed, an error.
    kp_save: Option<(u64, String, Option<String>)>,
    kp_pw: String,
    kp_msg: Option<(bool, String)>,
    kp_pending: Vec<Pending>,
    ask: Option<AskState>,
    session_pw: HashMap<u64, String>,
    /// Where the active tab's content is drawn (points), for placing embedded windows.
    embed_rect: Option<Rect>,
    last_content: Rect,
    parent_hwnd: Option<isize>,
    show_ssh_import: bool,
    ssh_import_path: String,
    ssh_import_msg: Option<(bool, String)>,
    show_export: bool,
    export_root: Option<u64>,
    export_mode: crate::sharing::PwMode,
    export_pw: String,
    export_pw2: String,
    export_ack: bool,
    export_path: String,
    export_msg: Option<(bool, String)>,
    show_ximport: bool,
    ximport_path: String,
    ximport_pw: String,
    ximport_need_pw: bool,
    ximport_msg: Option<(bool, String)>,
    /// 0 = this PC, 1 = network folder (SMB), 2 = WebDAV
    storage_kind: u8,
    dav_url: String,
    dav_user: String,
    dav_pw: String,
    dav_msg: Option<(bool, String)>,
    last_remote_poll: f64,
    prog_cache: HashMap<&'static str, Option<(PathBuf, programs::Source)>>,
    drag_tab: Option<usize>,
    rename_tab: Option<(u64, String)>,
    /// Screenshot of the active tab requested (taken after this frame is drawn).
    shot_tab: Option<Rect>,
    shot_wait: Arc<Mutex<Option<Arc<egui::ColorImage>>>>,
    shot_pending: Option<Rect>,
    pwgen: extra::PwGen,
    tunnels: HashMap<(u64, usize), extra::TunnelRun>,
    confirm_power: Option<(u64, bool)>,
    next_monitor: f64,
    monitor_prev: HashMap<u64, Option<bool>>,
    last_reload_check: f64,
    restored: bool,
    shared_edit: String,
    #[allow(dead_code)]
    shared_msg: Option<(bool, String)>,
}

impl AdminApp {
    pub fn new(cc: &eframe::CreationContext<'_>, screenshot: Option<PathBuf>) -> Self {
        // language: the system's until the saved choice is known (first-run examples use it too)
        let cli_lang = std::env::args().skip_while(|a| a != "--lang").nth(1);
        crate::i18n::set_language(cli_lang.as_deref().unwrap_or(""));
        let store = Store::open(screenshot.is_some());
        crate::i18n::set_language(cli_lang.as_deref().unwrap_or(&store.data.settings.language));
        if !store.read_only {
            crate::i18n::ensure_lang_dir();
        }
        let mut app = AdminApp {
            store,
            selected: None,
            filter: String::new(),
            tabs: vec![Tab { id: 0, title: tr("Home").into(), color: ACCENT, kind: TabKind::Start }],
            active: 0,
            next_tab: 1,
            quick_protocol: Protocol::Ssh,
            quick_host: String::new(),
            log: Vec::new(),
            status: Arc::new(Mutex::new(Default::default())),
            dirty_since: None,
            unlock_pw: String::new(),
            unlock_failed: false,
            show_settings: false,
            new_master: String::new(),
            new_master2: String::new(),
            settings_msg: None,
            show_import: false,
            import_path: String::new(),
            import_pw: String::new(),
            import_msg: None,
            show_about: false,
            show_keys: false,
            help_request: None,
            control: None,
            update_result: None,
            releases_url: crate::update::releases_page(),
            focus_search: false,
            close_request: None,
            show_props: true,
            confirm_delete: None,
            show_password: false,
            toast: None,
            pending_connect: Vec::new(),
            system_check: Vec::new(),
            applied_dark: None,
            shot: screenshot.map(|path| Shot { path, frames: 0, requested: false, image: Default::default() }),
            keepass: KeePassVault::default(),
            kp_dialog: false,
            kp_save: None,
            kp_pw: String::new(),
            kp_msg: None,
            kp_pending: Vec::new(),
            ask: None,
            session_pw: HashMap::new(),
            embed_rect: None,
            last_content: Rect::from_min_size(Pos2::ZERO, Vec2::new(1000.0, 640.0)),
            parent_hwnd: None,
            show_ssh_import: false,
            ssh_import_path: default_ssh_config().display().to_string(),
            ssh_import_msg: None,
            show_export: false,
            export_root: None,
            export_mode: crate::sharing::PwMode::Without,
            export_pw: String::new(),
            export_pw2: String::new(),
            export_ack: false,
            export_path: String::new(),
            export_msg: None,
            show_ximport: false,
            ximport_path: String::new(),
            ximport_pw: String::new(),
            ximport_need_pw: false,
            ximport_msg: None,
            storage_kind: 0,
            dav_url: String::new(),
            dav_user: String::new(),
            dav_pw: String::new(),
            dav_msg: None,
            last_remote_poll: 0.0,
            prog_cache: HashMap::new(),
            drag_tab: None,
            rename_tab: None,
            shot_tab: None,
            shot_wait: Default::default(),
            shot_pending: None,
            pwgen: extra::PwGen::default(),
            tunnels: HashMap::new(),
            confirm_power: None,
            next_monitor: 0.0,
            monitor_prev: HashMap::new(),
            last_reload_check: 0.0,
            restored: false,
            shared_edit: crate::model::shared_location(),
            shared_msg: None,
        };
        app.refresh_programs();
        if let Some(r) = app.store.remote.clone() {
            app.storage_kind = 2;
            app.dav_url = r.url.clone();
            app.dav_user = r.user.clone();
            app.dav_pw = r.password();
        } else if !app.shared_edit.trim().is_empty() {
            app.storage_kind = 1;
        }
        if let Some(err) = app.store.last_error.clone() {
            app.log.push(err);
        }
        if app.shot.is_some() {
            app.selected = app.store.data.entries.iter().find(|e| !e.folder).map(|e| e.id);
            app.log.push(tr("RDP started: 10.0.0.10 (example)").into());
            app.log.push(tr("SSH session to web01 opened (example)").into());
        }
        // `--open shell|ping:<host>|scan:<host>` opens a tab right away (handy for checks).
        let args: Vec<String> = std::env::args().collect();
        if let Some(what) = args.iter().position(|a| a == "--open").and_then(|i| args.get(i + 1)).cloned() {
            let ctx = cc.egui_ctx.clone();
            let (kind, host) = what.split_once(':').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((what.clone(), String::new()));
            match kind.as_str() {
                "shell" => {
                    let e = Entry { name: tr("Local shell").into(), protocol: Protocol::LocalShell, ..Default::default() };
                    app.open_session(e, Creds::default(), Vec::new(), &ctx, 0.0);
                }
                "settings" => app.open_settings(),
                "netscan" => {
                    app.open_netscan(host.clone());
                    if let Some(Tab { kind: TabKind::NetScan(n), .. }) = app.tabs.last_mut() {
                        if let (Ok(t), Ok(p)) = (crate::netscan::parse_targets(&n.range), crate::tools::parse_ports(&n.ports)) {
                            n.scan = Some(crate::netscan::NetScan::start(t, p, n.timeout, n.names, ctx.clone()));
                        }
                    }
                }
                "subnet" => app.add_tab(tr("Subnet calculator").into(), ACCENT, TabKind::Subnet(extra::SubnetTab { input: host.clone() })),
                "cert" => {
                    app.open_cert(host.clone());
                    if let Some(Tab { kind: TabKind::Cert(c), .. }) = app.tabs.last_mut() {
                        let (h, slot, c2) = (c.host.clone(), c.result.clone(), ctx.clone());
                        std::thread::spawn(move || {
                            *slot.lock().unwrap() = Some(crate::admintools::check_cert(&h, 443));
                            c2.request_repaint();
                        });
                    }
                }
                "tunnels" => app.open_tunnels(),
                "recordings" => app.open_recordings((!host.is_empty()).then(|| PathBuf::from(&host))),
                "whois" => app.open_net_tool(crate::tooltabs::ToolKind::Whois, host.clone(), &ctx),
                "http" => app.open_net_tool(crate::tooltabs::ToolKind::Http, host.clone(), &ctx),
                "snmp" => app.open_net_tool(crate::tooltabs::ToolKind::Snmp, host.clone(), &ctx),
                "help" => {
                    app.open_help(None);
                    if let (Ok(n), Some(Tab { kind: TabKind::Help(h), .. })) = (host.parse::<usize>(), app.tabs.get_mut(app.active)) {
                        h.open_section(n);
                    }
                }
                "export" => {
                    app.open_export(None);
                    app.export_mode = crate::sharing::PwMode::Plain;
                }
                "transfer" => {
                    // demo: an FTP server on this computer (usually none, so the log shows the error)
                    let e = Entry {
                        name: tr("Files (example)").into(),
                        protocol: Protocol::Ftp,
                        host: if host.is_empty() { "127.0.0.1".into() } else { host.clone() },
                        port: 21,
                        ..Default::default()
                    };
                    app.open_transfer(e, Creds::default(), Vec::new(), Kind::Ftp, &ctx);
                }
                "embedtest" => {
                    // check of the window embedding with a harmless program (Character Map)
                    let e = Entry { name: tr("Embedding (test)").into(), protocol: Protocol::Vnc, ..Default::default() };
                    let prog = if host.is_empty() { tr("charmap.exe").to_string() } else { host.clone() };
                    match std::process::Command::new(&prog).spawn() {
                        Ok(child) => {
                            let pid = child.id();
                            app.add_tab(
                                e.name.clone(),
                                ACCENT,
                                TabKind::Proc(Box::new(ProcTab {
                                    entry: e,
                                    creds: Creds::default(),
                                    jumps: Vec::new(),
                                    child: Some(child),
                                    embed: Some(Embedded::new(pid, &[])),
                                    want_embed: embed::SUPPORTED,
                                    label: tf("Test: {0}", &[&prog]),
                                    started: 0.0,
                                    last_try: 0.0,
                                    exited: None,
                                    detached: false,
                                })),
                            );
                        }
                        Err(err) => app.log.push(tf("embedtest: {0}", &[&err])),
                    }
                }
                "connect" => {
                    if let Some(id) = app.store.data.entries.iter().find(|e| e.name.to_lowercase().contains(&host.to_lowercase())).map(|e| e.id) {
                        app.selected = Some(id);
                        app.start(id, How::Default, &ctx, 0.0);
                    }
                }
                "ping" => app.open_ping(host, PingMode::Ping, &ctx),
                "scan" => app.open_scan(host),
                "dns" => app.open_dns(host),
                "wol" => app.open_wol(host),
                _ => {}
            }
        }
        app
    }

    fn mark_dirty(&mut self, now: f64) {
        self.dirty_since = Some(now);
    }

    fn note(&mut self, text: impl Into<String>, error: bool, now: f64) {
        let text = text.into();
        self.log.push(text.clone());
        if self.log.len() > 200 {
            self.log.remove(0);
        }
        self.toast = Some(Toast { text, error, until: now + 6.0 });
    }

    fn add_tab(&mut self, title: String, color: Color32, kind: TabKind) {
        self.tabs.push(Tab { id: self.next_tab, title, color, kind });
        self.next_tab += 1;
        self.active = self.tabs.len() - 1;
    }

    /// Opens the user guide (or brings it to the front), optionally at a section (counted from 0;
    /// every language has the same sections, see `help::Topic`).
    pub(crate) fn open_help(&mut self, topic: Option<crate::help::Topic>) {
        if let Some(i) = self.tabs.iter().position(|t| matches!(t.kind, TabKind::Help(_))) {
            self.active = i;
        } else {
            self.add_tab(tr("User guide").into(), Color32::from_rgb(255, 179, 0), TabKind::Help(Box::new(crate::help::HelpTab::new())));
        }
        if let (Some(topic), Some(Tab { kind: TabKind::Help(h), .. })) = (topic, self.tabs.get_mut(self.active)) {
            h.open_section(topic as usize);
        }
    }

    /// Opens Whois, the HTTP header check or SNMP; runs it right away when there is a target.
    pub(crate) fn open_net_tool(&mut self, kind: crate::tooltabs::ToolKind, target: String, ctx: &egui::Context) {
        let mut t = crate::tooltabs::ToolTab::new(kind, target.clone());
        if !target.trim().is_empty() {
            t.start(ctx, false);
        }
        let title = if target.trim().is_empty() { kind.title().to_string() } else { format!("{} {}", kind.title(), target.trim()) };
        self.add_tab(title, kind.color(), TabKind::Tool(Box::new(t)));
    }

    /// The tab with the recorded sessions (one at a time), optionally playing `path`.
    pub(crate) fn open_recordings(&mut self, path: Option<PathBuf>) {
        if let Some(i) = self.tabs.iter().position(|t| matches!(t.kind, TabKind::Playback(_))) {
            self.active = i;
            if let (Some(path), TabKind::Playback(_)) = (path, &self.tabs[i].kind) {
                self.tabs[i].kind = TabKind::Playback(Box::new(crate::playback::PlaybackTab::new(Some(path))));
            }
        } else {
            self.add_tab(tr("Recordings").into(), Color32::from_rgb(229, 57, 53), TabKind::Playback(Box::new(crate::playback::PlaybackTab::new(path))));
        }
    }

    fn open_export(&mut self, root: Option<u64>) {
        let name = root.and_then(|r| self.store.get(r)).map(|e| e.name.clone()).unwrap_or_else(|| tr("Connections").into());
        self.export_root = root;
        self.export_path = crate::sharing::default_path(&name);
        self.export_msg = None;
        self.export_ack = false;
        self.show_export = true;
    }

    fn export_dialog(&mut self, ctx: &egui::Context, now: f64) {
        if !self.show_export {
            return;
        }
        use crate::sharing::PwMode;
        let mut open = true;
        let mut run = false;
        egui::Window::new(tr("Export connections")).open(&mut open).default_width(520.0).show(ctx, |ui| {
            let what = match self.export_root.and_then(|r| self.store.get(r)) {
                Some(e) => tf("Folder \"{0}\" with everything in it", &[&e.name]),
                None => tr("All connections and folders").to_string(),
            };
            ui.label(RichText::new(what).strong());
            if self.export_root.is_some() && ui.small_button(tr("Export everything instead")).clicked() {
                self.export_root = None;
            }
            ui.add_space(6.0);
            ui.label(tr("Passwords:"));
            ui.radio_value(&mut self.export_mode, PwMode::Without, tr("Without passwords (recommended for passing on)"));
            ui.radio_value(&mut self.export_mode, PwMode::Encrypted, tr("With passwords, file encrypted with an export password"));
            ui.radio_value(&mut self.export_mode, PwMode::Plain, tr("With passwords in plain text"));
            match self.export_mode {
                PwMode::Encrypted => {
                    egui::Grid::new("export_pw").num_columns(2).show(ui, |ui| {
                        ui.label(tr("Export password"));
                        ui.add(egui::TextEdit::singleline(&mut self.export_pw).password(true));
                        ui.end_row();
                        ui.label(tr("Repeat"));
                        ui.add(egui::TextEdit::singleline(&mut self.export_pw2).password(true));
                        ui.end_row();
                    });
                    ui.weak(tr("Tell your colleague the password another way (not in the same e-mail)."));
                }
                PwMode::Plain => {
                    egui::Frame::new().fill(BAD_RED.gamma_multiply(0.2)).stroke(Stroke::new(1.0, BAD_RED)).corner_radius(4.0).inner_margin(8).show(ui, |ui| {
                        ui.label(RichText::new(tr("Warning: the passwords will be readable in the file.")).color(BAD_RED).strong());
                        ui.label(tr("Anyone who gets or finds the file can log in with it. Don't e-mail it, don't leave it in cloud folders, and delete it after the import."));
                        ui.checkbox(&mut self.export_ack, tr("Understood – I'll take good care of the file"));
                    });
                }
                PwMode::Without => {
                    ui.weak(tr("Users, hosts, folders, notes and connection settings are included, passwords are not."));
                }
            }
            ui.add_space(6.0);
            ui.label(tr("File"));
            ui.add(egui::TextEdit::singleline(&mut self.export_path).desired_width(f32::INFINITY));
            let ready = match self.export_mode {
                PwMode::Without => true,
                PwMode::Plain => self.export_ack,
                PwMode::Encrypted => !self.export_pw.is_empty() && self.export_pw == self.export_pw2,
            };
            if self.export_mode == PwMode::Encrypted && !self.export_pw2.is_empty() && self.export_pw != self.export_pw2 {
                ui.label(RichText::new(tr("The two entries differ.")).color(BAD_RED));
            }
            if ui.add_enabled(ready && !self.export_path.trim().is_empty(), egui::Button::new(RichText::new(tr("Export")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
                run = true;
            }
            if let Some((ok, m)) = &self.export_msg {
                ui.label(RichText::new(m).color(if *ok { OK_GREEN } else { BAD_RED }));
            }
        });
        if run {
            let path = PathBuf::from(self.export_path.trim().trim_matches('"'));
            self.export_msg = Some(match crate::sharing::export(&self.store, self.export_root, self.export_mode, &self.export_pw, &path) {
                Ok(n) => {
                    self.export_pw.clear();
                    self.export_pw2.clear();
                    self.note(tf("{0} connections exported.", &[&n]), false, now);
                    (true, tf("{0} connections exported: {1}", &[&n, &path.display()]))
                }
                Err(e) => (false, e),
            });
        }
        self.show_export = open;
    }

    fn ximport_dialog(&mut self, ctx: &egui::Context, now: f64) {
        if !self.show_ximport {
            return;
        }
        use crate::sharing::ReadError;
        let mut open = true;
        let mut run = false;
        egui::Window::new(tr("Import AdminCraft export")).open(&mut open).default_width(480.0).show(ctx, |ui| {
            ui.label(tr("A colleague's export file (.json). The connections go into a new folder."));
            ui.add(egui::TextEdit::singleline(&mut self.ximport_path).desired_width(f32::INFINITY).hint_text(r"C:\Users\...\AdminCraft-Connections.json"));
            if self.ximport_need_pw {
                ui.label(tr("The file is encrypted. Export password:"));
                ui.add(egui::TextEdit::singleline(&mut self.ximport_pw).password(true));
            }
            if ui.add(egui::Button::new(RichText::new(tr("Import")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
                run = true;
            }
            if let Some((ok, m)) = &self.ximport_msg {
                ui.label(RichText::new(m).color(if *ok { OK_GREEN } else { BAD_RED }));
            }
        });
        if run {
            let path = self.ximport_path.trim().trim_matches('"').to_string();
            self.ximport_msg = Some(match std::fs::read_to_string(&path) {
                Err(e) => (false, tf("File not readable: {0}", &[&e])),
                Ok(text) => match crate::sharing::read(&text, &self.ximport_pw) {
                    Ok((entries, pws)) => {
                        let stem = std::path::Path::new(&path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                        let with_pw = pws.len();
                        let (fid, n) = crate::sharing::merge(&mut self.store, entries, pws, &tf("Import {0}", &[&stem]));
                        self.selected = Some(fid);
                        self.ximport_pw.clear();
                        self.ximport_need_pw = false;
                        self.mark_dirty(now);
                        (true, tf("{0} connections imported ({1} with password).", &[&n, &with_pw]))
                    }
                    Err(ReadError::NeedPassword) => {
                        self.ximport_need_pw = true;
                        (false, tr("Please enter the export password.").to_string())
                    }
                    Err(ReadError::WrongPassword) => (false, tr("Wrong export password.").to_string()),
                    Err(ReadError::Other(e)) => (false, e),
                },
            });
        }
        self.show_ximport = open;
    }

    /// Keyboard shortcuts. Ctrl+Shift so they don't take keys a shell in a terminal tab needs.
    fn shortcuts(&mut self, ctx: &egui::Context, now: f64) {
        use egui::{Key, KeyboardShortcut, Modifiers};
        let cs = |k| KeyboardShortcut::new(Modifiers::COMMAND | Modifiers::SHIFT, k);
        let hit = |sc: KeyboardShortcut| ctx.input_mut(|i| i.consume_shortcut(&sc));
        let n = self.tabs.len().max(1);
        if hit(cs(Key::Tab)) {
            self.active = (self.active + n - 1) % n;
        } else if hit(KeyboardShortcut::new(Modifiers::COMMAND, Key::Tab)) {
            self.active = (self.active + 1) % n;
        }
        if hit(cs(Key::W)) {
            self.close_request = Some(self.active);
        }
        if hit(cs(Key::N)) {
            let p = self.new_parent_for_selection();
            self.apply(Act::NewConn(p), ctx, now);
        }
        if hit(cs(Key::F)) {
            self.focus_search = true;
        }
        if hit(cs(Key::S)) {
            self.shot_tab = Some(self.last_content);
        }
        if hit(cs(Key::E)) {
            self.open_export(None);
        }
        if hit(cs(Key::L)) {
            self.open_netscan(String::new());
        }
        if hit(KeyboardShortcut::new(Modifiers::COMMAND, Key::Comma)) {
            self.open_settings();
        }
        if hit(KeyboardShortcut::new(Modifiers::NONE, Key::F1)) {
            self.open_help(None);
        }
        if let Some(topic) = self.help_request.take() {
            self.open_help(Some(topic));
        }
        if self.show_keys {
            let mut open = true;
            egui::Window::new(tr("Keyboard shortcuts")).open(&mut open).resizable(false).show(ctx, |ui| {
                egui::Grid::new("keys").num_columns(2).striped(true).spacing([24.0, 6.0]).show(ui, |ui| {
                    for (k, what) in [
                        ("Ctrl+Tab", tr("Next tab")),
                        ("Ctrl+Shift+Tab", tr("Previous tab")),
                        ("Ctrl+Shift+W", tr("Close tab")),
                        ("Ctrl+Shift+N", tr("New connection")),
                        ("Ctrl+Shift+F", tr("Search connections")),
                        ("Ctrl+Shift+S", tr("Screenshot of the tab")),
                        ("Ctrl+Shift+E", tr("Export connections")),
                        ("Ctrl+Shift+L", tr("Network scan")),
                        ("Ctrl+,", tr("Settings")),
                        ("F1", tr("User guide")),
                        (tr("Double-click"), tr("Open connection / rename tab")),
                        (tr("Middle mouse button"), tr("Close tab")),
                    ] {
                        ui.label(RichText::new(k).monospace().strong());
                        ui.label(what);
                        ui.end_row();
                    }
                });
                ui.add_space(4.0);
                ui.weak(tr("With Shift, so terminal programs keep their own Ctrl keys. macOS: Cmd instead of Ctrl."));
            });
            self.show_keys = open;
        }
    }

    fn open_netscan(&mut self, range: String) {
        self.add_tab(tr("Network scan").into(), Color32::from_rgb(3, 169, 244), TabKind::NetScan(Box::new(extra::NetScanTab::new(range))));
    }

    fn open_cert(&mut self, host: String) {
        self.add_tab(tr("Certificate").into(), Color32::from_rgb(139, 195, 74), TabKind::Cert(extra::CertTab::new(host)));
    }

    fn open_tunnels(&mut self) {
        if let Some(i) = self.tabs.iter().position(|t| matches!(t.kind, TabKind::Tunnels)) {
            self.active = i;
        } else {
            self.add_tab(tr("SSH tunnels").into(), Color32::from_rgb(121, 134, 203), TabKind::Tunnels);
        }
    }

    fn set_broadcast_all(&mut self, on: bool) {
        for t in &mut self.tabs {
            if let TabKind::Term(x) = &mut t.kind {
                x.broadcast = on && matches!(x.entry.protocol, Protocol::Ssh | Protocol::Telnet | Protocol::Serial | Protocol::Raw | Protocol::Rlogin);
            }
        }
    }

    fn tunnel_running(&mut self, id: u64, idx: usize) -> bool {
        self.tunnels
            .get_mut(&(id, idx))
            .and_then(|r| r.child.as_mut())
            .map(|c| matches!(c.try_wait(), Ok(None)))
            .unwrap_or(false)
    }

    fn start_tunnel(&mut self, id: u64, idx: usize, now: f64) {
        let Some(e) = self.store.get(id).cloned() else { return };
        let Some(t) = e.tunnels.get(idx).cloned() else { return };
        let label = format!("{} :{} » {}:{}", e.name, t.local_port, t.remote_host, t.remote_port);
        match self.resolve(id) {
            Ok((c, jumps, _)) => match extra::start_tunnel(&e, &c, &jumps, &t, &self.store.data.settings) {
                Ok(child) => {
                    self.tunnels.insert((id, idx), extra::TunnelRun { child: Some(child), label: label.clone(), error: None });
                    self.note(tf("Tunnel started: {0}", &[&label]), false, now);
                }
                Err(err) => {
                    self.tunnels.insert((id, idx), extra::TunnelRun { child: None, label, error: Some(err.clone()) });
                    self.note(err, true, now);
                }
            },
            Err(Need::KeePass) => self.note(tr("Unlock KeePass first for the tunnel."), true, now),
            Err(Need::Ask(_)) => self.note(tr("Connect once first for the tunnel (the password is asked)."), true, now),
        }
    }

    /// Every few minutes: are the hosts still there? Tells when one goes away or comes back.
    fn monitor_step(&mut self, ctx: &egui::Context, now: f64) {
        let mins = self.store.data.settings.monitor_minutes;
        if mins == 0 || self.shot.is_some() {
            return;
        }
        if now >= self.next_monitor {
            self.next_monitor = now + mins as f64 * 60.0;
            self.check_status(ctx);
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(5));
        let cur = self.status.lock().unwrap().clone();
        let mut changes = Vec::new();
        for (id, st) in &cur {
            if let (Some(new), Some(Some(old))) = (st, self.monitor_prev.get(id)) {
                if new != old {
                    let name = self.store.get(*id).map(|e| e.name.clone()).unwrap_or_default();
                    changes.push((name, *new));
                }
            }
        }
        for (k, v) in cur {
            if v.is_some() {
                self.monitor_prev.insert(k, v);
            }
        }
        for (name, up) in changes {
            if up {
                self.note(tf("Reachable again: {0}", &[&name]), false, now);
            } else {
                self.note(tf("No longer reachable: {0}", &[&name]), true, now);
            }
        }
    }

    fn power_dialog(&mut self, ctx: &egui::Context, now: f64) {
        let Some((id, reboot)) = self.confirm_power else { return };
        let Some(e) = self.store.get(id).cloned() else {
            self.confirm_power = None;
            return;
        };
        let mut result = None;
        egui::Modal::new(egui::Id::new("power")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading(if reboot { tr("Really restart?") } else { tr("Really shut down?") });
            ui.label(format!("{} ({})", e.name, e.host));
            ui.weak(if e.protocol == Protocol::Ssh {
                tr("Opens an SSH session and types \"sudo reboot\" or \"sudo poweroff\" there.")
            } else {
                tr("Sends the command with \"shutdown /m\" – needs admin rights on the target computer.")
            });
            ui.horizontal(|ui| {
                let label = if reboot { tr("Restart") } else { tr("Shut down") };
                if ui.add(egui::Button::new(RichText::new(label).color(Color32::WHITE)).fill(BAD_RED)).clicked() {
                    result = Some(true);
                }
                if ui.button(tr("Cancel")).clicked() {
                    result = Some(false);
                }
            });
        });
        match result {
            Some(true) => {
                self.confirm_power = None;
                if e.protocol == Protocol::Ssh {
                    match self.resolve(id) {
                        Ok((c, jumps, _)) => {
                            let mut se = e.clone();
                            se.ssh_client = crate::model::SshClient::Builtin;
                            self.open_session(se, c, jumps, ctx, now);
                            if let Some(Tab { kind: TabKind::Term(t), .. }) = self.tabs.last_mut() {
                                if let Some(term) = &mut t.term {
                                    term.queue_command(if reboot { "sudo reboot".into() } else { "sudo poweroff".into() });
                                }
                            }
                        }
                        Err(_) => self.note(tr("Connect once first (unlock KeePass / enter password)."), true, now),
                    }
                } else {
                    match extra::windows_power(&e.host, reboot) {
                        Ok(m) => self.note(m, false, now),
                        Err(err) => self.note(err, true, now),
                    }
                }
            }
            Some(false) => self.confirm_power = None,
            None => {}
        }
    }

    fn tab_px(&self, ctx: &egui::Context) -> (u32, u32) {
        let ppp = ctx.pixels_per_point();
        let r = self.last_content;
        ((r.width() * ppp).max(0.0) as u32, ((r.height() - 34.0) * ppp).max(0.0) as u32)
    }

    /// Starts a connection in the right kind of tab once its login is known.
    fn open_session(&mut self, entry: Entry, creds: Creds, jumps: Vec<JumpHop>, ctx: &egui::Context, now: f64) {
        let px = self.tab_px(ctx);
        match launch::launch(&entry, &creds, &self.store.data.settings, &jumps, px) {
            Ok(Launch::Terminal { cmd, preview, passwords, chain }) => {
                let (term, error) = match Terminal::spawn(cmd, ctx.clone(), passwords, chain) {
                    Ok(mut t) => {
                        if self.store.data.settings.session_log && !self.store.read_only {
                            let _ = t.start_log(&extra::session_log_path(&entry.name));
                        }
                        if self.store.data.settings.record_sessions && !self.store.read_only {
                            if let Err(e) = t.start_recording(&crate::playback::new_recording_path(&entry.name), &entry.name) {
                                self.log.push(tf("Recording could not start: {0}", &[&e]));
                            }
                        }
                        (Some(t), None)
                    }
                    Err(e) => (None, Some(e)),
                };
                let msg = format!("{} – {}", entry.name, preview);
                let failed = error.is_some();
                let title = entry.name.clone();
                let color = entry.protocol.color();
                self.add_tab(title, color, TabKind::Term(Box::new(TermTab { entry, creds, jumps, term, error, preview, broadcast: false })));
                if failed {
                    self.note(tf("Error: {0}", &[&msg]), true, now);
                } else {
                    self.log.push(tf("Session opened: {0}", &[&msg]));
                }
            }
            Ok(Launch::Process { child, label, embed }) => {
                let pid = child.id();
                let want = embed.is_some() && embed::SUPPORTED;
                let title = entry.name.clone();
                let color = entry.protocol.color();
                self.log.push(label.clone());
                self.add_tab(
                    title,
                    color,
                    TabKind::Proc(Box::new(ProcTab {
                        entry,
                        creds,
                        jumps,
                        child: Some(child),
                        embed: embed.map(|c| Embedded::new(pid, c)),
                        want_embed: want,
                        label,
                        started: now,
                        last_try: 0.0,
                        exited: None,
                        detached: false,
                    })),
                );
            }
            Ok(Launch::Done(msg)) => self.note(msg, false, now),
            Ok(Launch::Transfer) => {
                let kind = match entry.protocol {
                    Protocol::Ftp => Kind::Ftp,
                    Protocol::Scp => Kind::Scp,
                    _ => Kind::Sftp,
                };
                self.open_transfer(entry, creds, jumps, kind, ctx);
            }
            Err(e) => self.note(format!("{}: {e}", entry.name), true, now),
        }
    }

    fn endpoint(&self, e: &Entry, c: &Creds, jumps: &[JumpHop], kind: Kind) -> transfer::Endpoint {
        let s = &self.store.data.settings;
        let port = if e.port != 0 {
            e.port
        } else if kind == Kind::Ftp {
            21
        } else {
            22
        };
        let progs = transfer::Progs {
            ssh: programs::find("ssh", s),
            sftp: programs::find("sftp", s),
            scp: programs::find("scp", s),
            plink: programs::find("plink", s),
            psftp: programs::find("psftp", s),
            pscp: programs::find("pscp", s),
        };
        let tool = match s.transfer_tool {
            TransferTool::Putty => transfer::Tool::Putty,
            TransferTool::OpenSsh => transfer::Tool::OpenSsh,
            TransferTool::Auto => {
                if progs.sftp.is_some() {
                    transfer::Tool::OpenSsh
                } else {
                    transfer::Tool::Putty
                }
            }
        };
        transfer::Endpoint {
            kind,
            target: transfer::Hop { user: c.user.clone(), host: e.host.trim().to_string(), port, password: c.password.clone() },
            key_file: e.ssh_key.clone(),
            jumps: jumps
                .iter()
                .map(|j| transfer::Hop {
                    user: j.creds.user.clone(),
                    host: j.entry.host.trim().to_string(),
                    port: if j.entry.port == 0 { 22 } else { j.entry.port },
                    password: j.creds.password.clone(),
                })
                .collect(),
            tls: e.ftp_tls,
            check_cert: !e.tls_ignore_cert,
            tool,
            progs,
        }
    }

    fn open_transfer(&mut self, entry: Entry, creds: Creds, jumps: Vec<JumpHop>, kind: Kind, ctx: &egui::Context) {
        let ep = self.endpoint(&entry, &creds, &jumps, kind);
        let xfer = Transfer::start(ep, entry.start_path.trim().to_string(), ctx.clone());
        let local_dir = transfer::default_local_dir();
        let title = format!("{} · {}", entry.name, kind.label());
        let color = match kind {
            Kind::Ftp => Protocol::Ftp.color(),
            Kind::Scp => Protocol::Scp.color(),
            Kind::Sftp => Protocol::Sftp.color(),
        };
        let mut tab = TransferTab {
            entry,
            creds,
            jumps,
            xfer,
            local_edit: local_dir.display().to_string(),
            local_dir,
            local_items: Vec::new(),
            local_err: None,
            local_sel: BTreeSet::new(),
            remote_edit: String::new(),
            remote_sel: BTreeSet::new(),
            shown_cwd: String::new(),
            dialog: None,
        };
        refresh_local(&mut tab, self.store.data.settings.show_hidden);
        self.add_tab(title, color, TabKind::Transfer(Box::new(tab)));
    }

    fn refresh_programs(&mut self) {
        self.system_check = launch::system_check(&self.store.data.settings);
        self.prog_cache = programs::PROGRAMS
            .iter()
            .map(|p| (p.key, programs::find_with_source(p.key, &self.store.data.settings)))
            .collect();
    }

    fn open_settings(&mut self) {
        self.refresh_programs();
        if let Some(i) = self.tabs.iter().position(|t| matches!(t.kind, TabKind::Settings)) {
            self.active = i;
        } else {
            self.add_tab(tr("Settings").into(), Color32::from_rgb(120, 130, 145), TabKind::Settings);
        }
    }

    /// Login for one connection: stored, from KeePass, or asked for.
    fn creds_for(&self, id: u64) -> Result<(Creds, Option<String>), Need> {
        let info = self.store.credential_info(id);
        let mut c = Creds { user: info.user, domain: info.domain, password: info.password };
        let mut warn = None;
        if let Some(r) = info.keepass {
            if !self.keepass.unlocked {
                return Err(Need::KeePass);
            }
            match self.keepass.find(&r) {
                Some(k) => {
                    if c.user.is_empty() {
                        c.user = k.user.clone();
                    }
                    c.password = k.password.clone();
                }
                None => {
                    let what = match r {
                        crate::model::KeePassRef::Entry(n) => n,
                        crate::model::KeePassRef::Host(h) => tf("Host {0}", &[&h]),
                    };
                    warn = Some(tf("KeePass: no entry found for \"{0}\" – continuing without password.", &[&what]));
                }
            }
        }
        if info.ask {
            match self.session_pw.get(&id) {
                Some(p) => c.password = p.clone(),
                None => return Err(Need::Ask(id)),
            }
        }
        Ok((c, warn))
    }

    fn resolve(&self, id: u64) -> Result<(Creds, Vec<JumpHop>, Vec<String>), Need> {
        let mut warns = Vec::new();
        let (c, w) = self.creds_for(id)?;
        warns.extend(w);
        let mut jumps = Vec::new();
        for j in self.store.jump_chain(id) {
            let Some(je) = self.store.get(j).cloned() else { continue };
            let (jc, w) = self.creds_for(j)?;
            warns.extend(w);
            jumps.push(JumpHop { entry: je, creds: jc });
        }
        Ok((c, jumps, warns))
    }

    fn start(&mut self, id: u64, how: How, ctx: &egui::Context, now: f64) {
        let Some(e) = self.store.get(id).cloned() else { return };
        if e.folder {
            return;
        }
        match self.resolve(id) {
            Err(Need::KeePass) => {
                self.kp_pending.push(Pending { entry: e, how });
                self.kp_dialog = true;
                self.kp_msg = None;
            }
            Err(Need::Ask(key)) => {
                let name = self.store.get(key).map(|x| x.name.clone()).unwrap_or_default();
                let user = self.store.credential_info(key).user;
                self.ask = Some(AskState { pending: Pending { entry: e, how }, key, name, user, pw: String::new(), focus: true });
            }
            Ok((c, jumps, warns)) => {
                for w in warns {
                    self.note(w, true, now);
                }
                if how == How::Default && e.protocol == Protocol::Ssh {
                    for idx in 0..e.tunnels.len() {
                        if e.tunnels[idx].auto && !self.tunnel_running(id, idx) {
                            self.start_tunnel(id, idx, now);
                        }
                    }
                }
                self.start_resolved(e, c, jumps, how, ctx, now);
            }
        }
    }

    fn start_resolved(&mut self, mut e: Entry, c: Creds, jumps: Vec<JumpHop>, how: How, ctx: &egui::Context, now: f64) {
        match how {
            How::Transfer(kind) => self.open_transfer(e, c, jumps, kind, ctx),
            How::OpenSshWindow => {
                e.ssh_client = SshClient::External;
                self.open_session(e, c, jumps, ctx, now);
            }
            How::Putty => {
                e.ssh_client = SshClient::Putty;
                self.open_session(e, c, jumps, ctx, now);
            }
            How::Default => self.open_session(e, c, jumps, ctx, now),
            How::FileApp(key) => {
                let Some(prog) = programs::find(key, &self.store.data.settings) else {
                    self.note(tf("{0} not found – put it into the programs folder or enter its path in the settings.", &[&key]), true, now);
                    return;
                };
                let scheme = match e.protocol {
                    Protocol::Ftp if e.ftp_tls => "ftpes",
                    Protocol::Ftp => "ftp",
                    Protocol::Scp => "scp",
                    _ => "sftp",
                };
                let mut url = format!("{scheme}://");
                if !c.user.is_empty() {
                    url.push_str(&url_enc(&c.user));
                    if !c.password.is_empty() {
                        url.push(':');
                        url.push_str(&url_enc(&c.password));
                    }
                    url.push('@');
                }
                url.push_str(e.host.trim());
                if e.port != 0 {
                    url.push_str(&format!(":{}", e.port));
                }
                if !e.start_path.trim().is_empty() {
                    url.push_str(&format!("/{}", e.start_path.trim().trim_start_matches('/')));
                }
                match std::process::Command::new(&prog).arg(&url).spawn() {
                    Ok(_) => self.note(tf("{0} opened: {1}", &[&(prog.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()), &(e.host.trim())]), false, now),
                    Err(err) => self.note(tf("{0}: {1}", &[&(prog.display()), &err]), true, now),
                }
            }
        }
    }

    fn connect_id(&mut self, id: u64, ctx: &egui::Context, now: f64) {
        self.start(id, How::Default, ctx, now);
    }

    fn run_kp_pending(&mut self, ctx: &egui::Context, now: f64) {
        let pend = std::mem::take(&mut self.kp_pending);
        for p in pend {
            if p.entry.id != 0 && self.store.get(p.entry.id).is_some() {
                self.start(p.entry.id, p.how, ctx, now);
            }
        }
    }

    fn quick_connect(&mut self, ctx: &egui::Context, now: f64) {
        let text = self.quick_host.trim().to_string();
        if text.is_empty() && self.quick_protocol.needs_host() {
            self.note(tr("Please enter a host or IP."), true, now);
            return;
        }
        let (user, rest) = match text.rsplit_once('@') {
            Some((u, h)) => (u.to_string(), h.to_string()),
            None => (String::new(), text.clone()),
        };
        let mut host = rest.clone();
        let mut port = self.quick_protocol.default_port();
        if rest.matches(':').count() == 1 && !rest.contains("://") {
            if let Some((h, p)) = rest.split_once(':') {
                if let Ok(p) = p.parse() {
                    host = h.to_string();
                    port = p;
                }
            }
        }
        let e = Entry {
            id: 0,
            name: if text.is_empty() { self.quick_protocol.label().to_string() } else { text.clone() },
            protocol: self.quick_protocol,
            host,
            port,
            username: user.clone(),
            inherit_credentials: false,
            ..Default::default()
        };
        if e.protocol.transfer() {
            // no stored login: ask for the password first (empty = SSH key)
            let name = e.name.clone();
            self.ask = Some(AskState { pending: Pending { entry: e, how: How::Default }, key: 0, name, user, pw: String::new(), focus: true });
            return;
        }
        self.open_session(e, Creds { user, ..Default::default() }, Vec::new(), ctx, now);
    }

    fn new_parent_for_selection(&self) -> Option<u64> {
        let id = self.selected?;
        let e = self.store.get(id)?;
        if e.folder {
            Some(id)
        } else {
            e.parent
        }
    }

    fn apply(&mut self, act: Act, ctx: &egui::Context, now: f64) {
        match act {
            Act::Select(id) => self.selected = Some(id),
            Act::Connect(id) => self.connect_id(id, ctx, now),
            Act::Toggle(id) => {
                if let Some(i) = self.store.index_of(id) {
                    let e = &mut self.store.data.entries[i];
                    e.expanded = !e.expanded;
                    self.mark_dirty(now);
                }
            }
            Act::NewConn(parent) => {
                let id = self.store.next_id();
                self.store.data.entries.push(Entry {
                    id,
                    parent,
                    name: tr("New connection").into(),
                    ..Default::default()
                });
                self.expand(parent);
                self.selected = Some(id);
                self.show_props = true;
                self.mark_dirty(now);
            }
            Act::NewFolder(parent) => {
                let id = self.store.next_id();
                self.store.data.entries.push(Entry {
                    id,
                    parent,
                    folder: true,
                    name: tr("New folder").into(),
                    inherit_credentials: false,
                    ..Default::default()
                });
                self.expand(parent);
                self.selected = Some(id);
                self.show_props = true;
                self.mark_dirty(now);
            }
            Act::Duplicate(id) => {
                if let Some(e) = self.store.get(id).cloned() {
                    if e.folder {
                        return;
                    }
                    let nid = self.store.next_id();
                    let mut copy = e;
                    copy.id = nid;
                    copy.name = tf("{0} (copy)", &[&copy.name]);
                    let pos = self.store.index_of(id).map(|i| i + 1).unwrap_or(self.store.data.entries.len());
                    self.store.data.entries.insert(pos, copy);
                    self.selected = Some(nid);
                    self.mark_dirty(now);
                }
            }
            Act::AskDelete(id) => self.confirm_delete = Some(id),
            Act::MoveTo(id, parent) => {
                if parent == Some(id) || parent.map(|p| self.store.is_descendant(p, id)).unwrap_or(false) {
                    return;
                }
                if let Some(i) = self.store.index_of(id) {
                    self.store.data.entries[i].parent = parent;
                    self.expand(parent);
                    self.mark_dirty(now);
                }
            }
            Act::Shift(id, up) => {
                self.store.shift(id, up);
                self.mark_dirty(now);
            }
            Act::Drop(src, target, pos) => {
                if self.drop_entry(src, Some(target), pos) {
                    self.mark_dirty(now);
                }
            }
            Act::DropEnd(src) => {
                if self.drop_entry(src, None, DropPos::After) {
                    self.mark_dirty(now);
                }
            }
            Act::ConnectAll(folder) => {
                let ids: Vec<u64> = self
                    .store
                    .data
                    .entries
                    .iter()
                    .filter(|e| !e.folder && (e.parent == Some(folder)))
                    .map(|e| e.id)
                    .collect();
                self.pending_connect.extend(ids);
            }
            Act::Ping(id) => {
                if let Some(e) = self.store.get(id) {
                    let host = e.host.clone();
                    self.open_ping(host, PingMode::Ping, ctx);
                }
            }
            Act::Scan(id) => {
                if let Some(e) = self.store.get(id) {
                    let host = e.host.clone();
                    self.open_scan(host);
                }
            }
            Act::Wake(id) => {
                if let Some(e) = self.store.get(id) {
                    let mac = e.mac.clone();
                    self.open_wol(mac);
                }
            }
            Act::Files(id) => {
                let kind = match self.store.get(id).map(|e| e.protocol) {
                    Some(Protocol::Ftp) => Kind::Ftp,
                    Some(Protocol::Scp) => Kind::Scp,
                    _ => Kind::Sftp,
                };
                self.start(id, How::Transfer(kind), ctx, now);
            }
            Act::OpenSsh(id) => self.start(id, How::OpenSshWindow, ctx, now),
            Act::FileApp(id, key) => self.start(id, How::FileApp(key), ctx, now),
            Act::WinTool(id, tool) => {
                if let Some(host) = self.store.get(id).map(|e| e.host.clone()) {
                    match extra::open_windows_tool(tool, &host) {
                        Ok(m) => self.note(m, false, now),
                        Err(err) => self.note(err, true, now),
                    }
                }
            }
            Act::Power(id, reboot) => self.confirm_power = Some((id, reboot)),
            Act::StartTunnels(id) => {
                let n = self.store.get(id).map(|e| e.tunnels.len()).unwrap_or(0);
                for idx in 0..n {
                    if !self.tunnel_running(id, idx) {
                        self.start_tunnel(id, idx, now);
                    }
                }
                self.open_tunnels();
            }
            Act::CheckCert(id) => {
                let host = self.store.get(id).map(|e| e.host.clone()).unwrap_or_default();
                self.open_cert(host);
            }
            Act::NetTool(id, kind) => {
                let target = self.store.get(id).map(|e| match (kind, e.protocol) {
                    (crate::tooltabs::ToolKind::Http, Protocol::Http | Protocol::Https) => crate::kdbx::url_of(e),
                    _ => e.host.clone(),
                });
                self.open_net_tool(kind, target.unwrap_or_default(), ctx);
            }
            Act::Export(root) => self.open_export(root),
            Act::Putty(id) => self.start(id, How::Putty, ctx, now),
        }
    }

    /// Moves an entry next to (`Before`/`After`) or into (`Into`) another one; `target` None
    /// = the end of the top level. Keeps folders out of their own children.
    fn drop_entry(&mut self, src: u64, target: Option<u64>, pos: DropPos) -> bool {
        let moved = self.store.drop_move(src, target, pos == DropPos::Into, pos == DropPos::After);
        if moved {
            let parent = self.store.get(src).and_then(|e| e.parent);
            self.expand(parent);
            self.selected = Some(src);
        }
        moved
    }

    fn expand(&mut self, parent: Option<u64>) {
        if let Some(p) = parent.and_then(|p| self.store.index_of(p)) {
            self.store.data.entries[p].expanded = true;
        }
    }

    fn open_ping(&mut self, host: String, mode: PingMode, ctx: &egui::Context) {
        let mut tab = PingTab { host: host.clone(), continuous: false, mode, runner: CmdRunner::default() };
        if !host.trim().is_empty() {
            start_ping(&mut tab, ctx);
        }
        let title = match mode {
            PingMode::Ping => tf("Ping {0}", &[&host]),
            PingMode::Trace => tf("Traceroute {0}", &[&host]),
        };
        self.add_tab(title.trim().to_string(), Color32::from_rgb(0, 150, 136), TabKind::Ping(tab));
    }

    fn open_scan(&mut self, host: String) {
        self.add_tab(
            tf("Port-Scan {0}", &[&host]).trim().to_string(),
            Color32::from_rgb(255, 152, 0),
            TabKind::Scan(ScanTab { host, ports: tools::COMMON_PORTS.into(), timeout: 600, scan: None, error: None }),
        );
    }

    fn open_dns(&mut self, host: String) {
        self.add_tab(
            tr("DNS lookup").into(),
            Color32::from_rgb(156, 39, 176),
            TabKind::Dns(DnsTab { host, result: Default::default(), runner: CmdRunner::default(), rtype: tr("A").into(), server: String::new() }),
        );
    }

    fn open_wol(&mut self, mac: String) {
        self.add_tab(
            tr("Wake-on-LAN").into(),
            Color32::from_rgb(255, 193, 7),
            TabKind::Wol(WolTab { mac, broadcast: "255.255.255.255".into(), port: 9, result: None }),
        );
    }

    fn check_status(&mut self, ctx: &egui::Context) {
        let targets: Vec<(u64, String, u16)> = self
            .store
            .data
            .entries
            .iter()
            .filter(|e| !e.folder && e.protocol.needs_host() && !e.host.trim().is_empty())
            .map(|e| (e.id, e.host.trim().to_string(), if e.port == 0 { e.protocol.default_port() } else { e.port }))
            .collect();
        tools::check_reachability(targets, self.status.clone(), ctx.clone());
    }

    // ------------------------------------------------------------ look

    fn apply_theme(&mut self, ctx: &egui::Context) {
        let dark = self.store.data.settings.dark;
        if self.applied_dark == Some(dark) {
            return;
        }
        self.applied_dark = Some(dark);
        ctx.set_theme(if dark { egui::Theme::Dark } else { egui::Theme::Light });
        let mut v = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
        if dark {
            v.panel_fill = Color32::from_rgb(30, 33, 39);
            v.window_fill = Color32::from_rgb(36, 40, 47);
            v.extreme_bg_color = Color32::from_rgb(20, 22, 27);
            v.faint_bg_color = Color32::from_rgb(38, 42, 50);
        } else {
            v.panel_fill = Color32::from_rgb(244, 246, 249);
            v.faint_bg_color = Color32::from_rgb(234, 238, 244);
        }
        v.selection.bg_fill = ACCENT.gamma_multiply(if dark { 0.75 } else { 0.9 });
        v.hyperlink_color = ACCENT;
        ctx.set_visuals(v);
    }

    // ------------------------------------------------------------ panels

    fn menu_bar(&mut self, ui: &mut egui::Ui, now: f64) {
        let ctx = ui.ctx().clone();
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button(tr("File"), |ui| {
                if ui.button(tr("New connection")).clicked() {
                    let p = self.new_parent_for_selection();
                    self.apply(Act::NewConn(p), &ctx, now);
                }
                if ui.button(tr("New folder")).clicked() {
                    let p = self.new_parent_for_selection();
                    self.apply(Act::NewFolder(p), &ctx, now);
                }
                ui.separator();
                if ui.button(tr("Import mRemoteNG file …")).clicked() {
                    self.show_import = true;
                }
                if ui.button(tr("Import OpenSSH configuration (~/.ssh/config) …")).clicked() {
                    self.show_ssh_import = true;
                    self.ssh_import_msg = None;
                }
                ui.separator();
                if ui.button(tr("Export connections …")).clicked() {
                    self.open_export(None);
                }
                if ui.button(tr("Import AdminCraft export …")).clicked() {
                    self.show_ximport = true;
                    self.ximport_msg = None;
                    self.ximport_need_pw = false;
                }
                if ui.button(tr("Open data folder")).clicked() {
                    if let Some(dir) = self.store.path.parent() {
                        let _ = std::fs::create_dir_all(dir);
                        launch::open_folder(dir);
                    }
                }
                if ui.button(tr("Save now")).clicked() {
                    self.store.save();
                    self.dirty_since = None;
                }
                ui.separator();
                if ui.button(tr("Quit")).clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button(tr("View"), |ui| {
                let mut dark = self.store.data.settings.dark;
                if ui.radio_value(&mut dark, true, tr("Dark theme")).clicked()
                    | ui.radio_value(&mut dark, false, tr("Light theme")).clicked()
                {
                    self.store.data.settings.dark = dark;
                    self.mark_dirty(now);
                }
                ui.separator();
                ui.checkbox(&mut self.show_props, tr("Show properties"));
            });
            ui.menu_button(tr("Tools"), |ui| {
                let host = self.selected.and_then(|id| self.store.get(id)).map(|e| e.host.clone()).unwrap_or_default();
                if ui.button(tr("Ping")).clicked() {
                    self.open_ping(host.clone(), PingMode::Ping, &ctx);
                }
                if ui.button(tr("Traceroute")).clicked() {
                    self.open_ping(host.clone(), PingMode::Trace, &ctx);
                }
                if ui.button(tr("Port scan")).clicked() {
                    self.open_scan(host.clone());
                }
                if ui.button(tr("DNS lookup")).clicked() {
                    self.open_dns(host.clone());
                }
                if ui.button(tr("Wake-on-LAN")).clicked() {
                    let mac = self.selected.and_then(|id| self.store.get(id)).map(|e| e.mac.clone()).unwrap_or_default();
                    self.open_wol(mac);
                }
                ui.separator();
                if ui.button(tr("Network scan (IP range)")).clicked() {
                    self.open_netscan(String::new());
                }
                if ui.button(tr("Subnet calculator")).clicked() {
                    self.add_tab(tr("Subnet calculator").into(), Color32::from_rgb(0, 137, 123), TabKind::Subnet(extra::SubnetTab::default()));
                }
                if ui.button(tr("Check certificate")).clicked() {
                    self.open_cert(host.clone());
                }
                if ui.button(tr("SSH tunnels")).clicked() {
                    self.open_tunnels();
                }
                for k in [crate::tooltabs::ToolKind::Whois, crate::tooltabs::ToolKind::Http, crate::tooltabs::ToolKind::Snmp] {
                    if ui.button(k.title()).clicked() {
                        self.open_net_tool(k, host.clone(), &ctx);
                    }
                }
                if ui.button(tr("Recordings (play back sessions)")).clicked() {
                    self.open_recordings(None);
                }
                if ui.button(tr("Password generator")).clicked() {
                    self.pwgen.open = true;
                    self.pwgen.target = None;
                }
                ui.separator();
                if ui.button(tr("Multi-input: all SSH tabs on")).clicked() {
                    self.set_broadcast_all(true);
                }
                if ui.button(tr("Multi-input: all off")).clicked() {
                    self.set_broadcast_all(false);
                }
                ui.separator();
                if ui.button(tr("Check reachability of all connections")).clicked() {
                    self.check_status(&ctx);
                }
                if ui.button(tr("Open local shell")).clicked() {
                    let e = Entry { name: tr("Local shell").into(), protocol: Protocol::LocalShell, ..Default::default() };
                    self.open_session(e, Creds::default(), Vec::new(), &ctx, now);
                }
                if ui.button(tr("Open programs folder")).on_hover_text(tr("Put PuTTY, VNC viewer, WinSCP … here")).clicked() {
                    launch::open_folder(&programs::ensure_tools_dir());
                }
                ui.separator();
                if self.keepass.unlocked {
                    if ui.button(tr("Lock KeePass")).clicked() {
                        self.keepass.lock();
                    }
                } else if ui.button(tr("Unlock KeePass …")).clicked() {
                    self.kp_dialog = true;
                    self.kp_msg = None;
                }
                ui.separator();
                if ui.button(tr("Settings …")).clicked() {
                    self.show_settings = true;
                }
            });
            ui.menu_button(tr("Help"), |ui| {
                if ui.add(egui::Button::new(tr("User guide")).shortcut_text("F1")).clicked() {
                    self.open_help(None);
                }
                if ui.button(tr("First steps")).clicked() {
                    self.open_help(Some(crate::help::Topic::FirstConnection));
                }
                if ui.button(tr("Keyboard shortcuts")).clicked() {
                    self.show_keys = true;
                }
                ui.separator();
                if ui.button(tr("About AdminCraft")).clicked() {
                    self.show_about = true;
                }
            });
        });
    }

    /// The bar under the menu. Settings and Screenshot are placed first from the right, the rest
    /// gets the space that is left and scrolls sideways when a language's labels are too long.
    fn toolbar(&mut self, ui: &mut egui::Ui, now: f64) {
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(tr("Settings")).clicked() {
                    self.show_settings = true;
                }
                if ui
                    .button(tr("Screenshot"))
                    .on_hover_text(tr("Picture of the active tab (RDP/PuTTY too) to the clipboard"))
                    .clicked()
                {
                    self.shot_tab = Some(self.last_content);
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    egui::ScrollArea::horizontal()
                        .id_salt("toolbar")
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                        .show(ui, |ui| ui.horizontal(|ui| self.toolbar_left(ui, now)));
                });
            });
        });
    }

    fn toolbar_left(&mut self, ui: &mut egui::Ui, now: f64) {
        let ctx = ui.ctx().clone();
        {
            ui.label(RichText::new(tr("Quick connect")).strong());
            egui::ComboBox::from_id_salt("quick_proto")
                .width(150.0)
                .selected_text(self.quick_protocol.label())
                .show_ui(ui, |ui| {
                    for p in Protocol::ALL {
                        ui.selectable_value(&mut self.quick_protocol, p, p.label());
                    }
                });
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.quick_host)
                    .hint_text(tr("Host or IP   (e.g. admin@10.0.0.5:22)"))
                    .desired_width(280.0),
            );
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.add(egui::Button::new(RichText::new(tr("Connect")).color(Color32::WHITE)).fill(ACCENT)).clicked() || enter {
                self.quick_connect(&ctx, now);
            }
            ui.separator();
            let host = if self.quick_host.trim().is_empty() {
                self.selected.and_then(|id| self.store.get(id)).map(|e| e.host.clone()).unwrap_or_default()
            } else {
                self.quick_host.rsplit('@').next().unwrap_or("").split(':').next().unwrap_or("").to_string()
            };
            if ui.button(tr("Ping")).on_hover_text(tr("Ping the host")).clicked() {
                self.open_ping(host.clone(), PingMode::Ping, &ctx);
            }
            if ui.button(tr("Traceroute")).clicked() {
                self.open_ping(host.clone(), PingMode::Trace, &ctx);
            }
            if ui.button(tr("Port scan")).clicked() {
                self.open_scan(host.clone());
            }
            if ui.button(tr("DNS")).clicked() {
                self.open_dns(host.clone());
            }
            if ui.button(tr("Wake-on-LAN")).clicked() {
                let mac = self.selected.and_then(|id| self.store.get(id)).map(|e| e.mac.clone()).unwrap_or_default();
                self.open_wol(mac);
            }
            if ui.button(tr("Network scan")).on_hover_text(tr("Search an IP range for devices")).clicked() {
                self.open_netscan(String::new());
            }
            if ui.button(tr("Shell")).on_hover_text(tr("Local shell in a new tab")).clicked() {
                let e = Entry { name: tr("Local shell").into(), protocol: Protocol::LocalShell, ..Default::default() };
                self.open_session(e, Creds::default(), Vec::new(), &ctx, now);
            }
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui, now: f64) {
        ui.horizontal(|ui| {
            let conns = self.store.data.entries.iter().filter(|e| !e.folder).count();
            let folders = self.store.data.entries.len() - conns;
            ui.label(tf("{0} connections · {1} folders", &[&conns, &folders]));
            ui.separator();
            if self.store.data.master {
                ui.label(RichText::new(tr("Passwords encrypted with master password")).color(OK_GREEN));
            } else {
                ui.label(RichText::new(tr("No master password – passwords only obfuscated")).color(Color32::from_rgb(230, 160, 40)))
                    .on_hover_text(tr("Set a master password in the settings."));
            }
            ui.separator();
            let place = tr(if self.store.read_only { "Read only" } else { "Portable" });
            // short path (folder + file); the full one on hover
            let short: Vec<String> = self.store.path.components().rev().take(2).map(|c| c.as_os_str().to_string_lossy().to_string()).collect();
            let short = short.into_iter().rev().collect::<Vec<_>>().join(std::path::MAIN_SEPARATOR_STR);
            ui.label(tf("{0}: {1}", &[&place, &format!("…{}{short}", std::path::MAIN_SEPARATOR)])).on_hover_text(self.store.path.display().to_string());
            if self.store.remote.is_some() {
                ui.separator();
                match self.store.remote_state.lock().unwrap().last_error.clone() {
                    Some(e) => ui.label(RichText::new(tf("WebDAV: {0}", &[&e])).color(BAD_RED)),
                    None => ui.label(RichText::new(tr("WebDAV connected")).color(OK_GREEN)),
                };
            }
            if let Some(err) = &self.store.last_error {
                ui.separator();
                ui.label(RichText::new(err).color(BAD_RED));
            }
            if let Some(t) = &self.toast {
                if t.until > now {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let color = if t.error { BAD_RED } else { OK_GREEN };
                        ui.label(RichText::new(&t.text).color(color).strong());
                    });
                }
            }
        });
    }

    fn tree_panel(&mut self, ui: &mut egui::Ui, now: f64) {
        let ctx = ui.ctx().clone();
        let mut acts = Vec::new();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading(tr("Connections"));
        });
        let search = ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text(tr("Search (name, host, user) …")).desired_width(f32::INFINITY));
        if std::mem::take(&mut self.focus_search) {
            search.request_focus();
        }
        ui.horizontal(|ui| {
            if ui.button(tr("+ Connection")).clicked() {
                acts.push(Act::NewConn(self.new_parent_for_selection()));
            }
            if ui.button(tr("+ Folder")).clicked() {
                acts.push(Act::NewFolder(self.new_parent_for_selection()));
            }
            if ui.button(tr("Status")).on_hover_text(tr("Checks whether the hosts answer on their port")).clicked() {
                self.check_status(&ctx);
            }
        });
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let filter = self.filter.trim().to_lowercase();
            if filter.is_empty() {
                self.tree_level(ui, None, 0, &mut acts);
            } else {
                let hits: Vec<u64> = self
                    .store
                    .data
                    .entries
                    .iter()
                    .filter(|e| !e.folder)
                    .filter(|e| {
                        e.name.to_lowercase().contains(&filter)
                            || e.host.to_lowercase().contains(&filter)
                            || e.username.to_lowercase().contains(&filter)
                            || e.description.to_lowercase().contains(&filter)
                    })
                    .map(|e| e.id)
                    .collect();
                if hits.is_empty() {
                    ui.weak(tr("Nothing found."));
                }
                for id in hits {
                    self.tree_row(ui, id, 0, &mut acts, true);
                }
            }
            // empty space: right-click to add
            let rest = ui.allocate_response(ui.available_size().max(Vec2::new(10.0, 40.0)), Sense::click());
            if let Some(dragged) = egui::DragAndDrop::payload::<u64>(&ctx).map(|p| *p) {
                if ctx.pointer_hover_pos().map(|p| rest.rect.contains(p)).unwrap_or(false) {
                    ui.painter().hline(rest.rect.x_range(), rest.rect.top() + 2.0, Stroke::new(2.0, ACCENT));
                    if ctx.input(|i| i.pointer.any_released()) {
                        egui::DragAndDrop::clear_payload(&ctx);
                        acts.push(Act::DropEnd(dragged));
                    }
                }
            }
            rest.context_menu(|ui| {
                if ui.button(tr("New connection")).clicked() {
                    acts.push(Act::NewConn(None));
                    ui.close();
                }
                if ui.button(tr("New folder")).clicked() {
                    acts.push(Act::NewFolder(None));
                    ui.close();
                }
            });
        });
        for a in acts {
            self.apply(a, &ctx, now);
        }
    }

    fn tree_level(&self, ui: &mut egui::Ui, parent: Option<u64>, depth: usize, acts: &mut Vec<Act>) {
        for id in self.store.children(parent) {
            self.tree_row(ui, id, depth, acts, false);
            if let Some(e) = self.store.get(id) {
                if e.folder && e.expanded && depth < 32 {
                    self.tree_level(ui, Some(id), depth + 1, acts);
                }
            }
        }
    }

    fn tree_row(&self, ui: &mut egui::Ui, id: u64, depth: usize, acts: &mut Vec<Act>, flat: bool) {
        let Some(e) = self.store.get(id) else { return };
        let selected = self.selected == Some(id);
        let status = self.status.lock().unwrap().get(&id).copied();
        let row = ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.add_space(depth as f32 * 16.0);
            if e.folder {
                let (r, resp) = ui.allocate_exact_size(Vec2::new(12.0, 18.0), Sense::click());
                let c = r.center();
                let col = ui.visuals().text_color();
                let pts = if e.expanded {
                    vec![Pos2::new(c.x - 4.0, c.y - 2.0), Pos2::new(c.x + 4.0, c.y - 2.0), Pos2::new(c.x, c.y + 3.0)]
                } else {
                    vec![Pos2::new(c.x - 2.0, c.y - 4.0), Pos2::new(c.x + 3.0, c.y), Pos2::new(c.x - 2.0, c.y + 4.0)]
                };
                ui.painter().add(egui::Shape::convex_polygon(pts, col, Stroke::NONE));
                if resp.clicked() {
                    acts.push(Act::Toggle(id));
                }
                let (r, _) = ui.allocate_exact_size(Vec2::new(20.0, 18.0), Sense::hover());
                let body = Rect::from_min_size(r.min + Vec2::new(1.0, 4.0), Vec2::new(18.0, 12.0));
                let tab = Rect::from_min_size(r.min + Vec2::new(1.0, 2.0), Vec2::new(8.0, 4.0));
                let folder_col = Color32::from_rgb(232, 180, 60);
                ui.painter().rect_filled(tab, 1.0, folder_col);
                ui.painter().rect_filled(body, 2.0, folder_col);
            } else {
                if !flat {
                    ui.add_space(12.0);
                }
                badge(ui, e.protocol);
            }
            let label = if flat { format!("{}   ", e.name) } else { e.name.clone() };
            let text = if e.folder { RichText::new(label).strong() } else { RichText::new(label) };
            let resp = ui.selectable_label(selected, text).interact(Sense::click_and_drag());
            if resp.drag_started() {
                egui::DragAndDrop::set_payload(ui.ctx(), id);
            }
            if resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
            }
            if flat {
                if let Some(p) = e.parent {
                    ui.weak(self.store.path_of(p));
                }
            }
            if !e.folder {
                if let Some(s) = status {
                    let (r, _) = ui.allocate_exact_size(Vec2::new(10.0, 18.0), Sense::hover());
                    let col = match s {
                        Some(true) => OK_GREEN,
                        Some(false) => BAD_RED,
                        None => Color32::GRAY,
                    };
                    ui.painter().circle_filled(r.center(), 4.0, col);
                }
            }
            let resp = if e.folder {
                resp
            } else {
                let host = if e.protocol.needs_host() { format!("{}:{}", e.host, e.port) } else { tr("local").into() };
                resp.on_hover_text(format!("{} · {}\n{}", e.protocol.label(), host, e.description))
            };
            if resp.clicked() {
                acts.push(Act::Select(id));
            }
            if resp.double_clicked() {
                acts.push(if e.folder { Act::Toggle(id) } else { Act::Connect(id) });
            }
            resp.context_menu(|ui| {
                acts.push(Act::Select(id));
                if e.folder {
                    if ui.button(tr("Open all connections in the folder")).clicked() {
                        acts.push(Act::ConnectAll(id));
                        ui.close();
                    }
                    if ui.button(tr("New connection here")).clicked() {
                        acts.push(Act::NewConn(Some(id)));
                        ui.close();
                    }
                    if ui.button(tr("New subfolder")).clicked() {
                        acts.push(Act::NewFolder(Some(id)));
                        ui.close();
                    }
                    if ui.button(tr("Export folder …")).clicked() {
                        acts.push(Act::Export(Some(id)));
                        ui.close();
                    }
                } else {
                    if ui.button(RichText::new(tr("Connect")).strong()).clicked() {
                        acts.push(Act::Connect(id));
                        ui.close();
                    }
                    if e.protocol == Protocol::Ssh {
                        if ui.button(tr("Transfer files (SFTP)")).clicked() {
                            acts.push(Act::Files(id));
                            ui.close();
                        }
                        if ui.button(tr("Open in own terminal (OpenSSH)")).clicked() {
                            acts.push(Act::OpenSsh(id));
                            ui.close();
                        }
                        if ui.button(tr("Open with PuTTY")).clicked() {
                            acts.push(Act::Putty(id));
                            ui.close();
                        }
                    }
                    if e.protocol == Protocol::Ssh || e.protocol.transfer() {
                        for (key, label) in [("winscp", "Open in WinSCP"), ("filezilla", "Open in FileZilla")] {
                            if self.prog_cache.get(key).map(|x| x.is_some()).unwrap_or(false) && ui.button(tr(label)).clicked() {
                                acts.push(Act::FileApp(id, key));
                                ui.close();
                            }
                        }
                    }
                    if e.protocol.needs_host() {
                        if ui.button(tr("Ping")).clicked() {
                            acts.push(Act::Ping(id));
                            ui.close();
                        }
                        if ui.button(tr("Port scan")).clicked() {
                            acts.push(Act::Scan(id));
                            ui.close();
                        }
                    }
                    if !e.mac.trim().is_empty() && ui.button(tr("Wake up (Wake-on-LAN)")).clicked() {
                        acts.push(Act::Wake(id));
                        ui.close();
                    }
                    if ui.button(tr("Copy / duplicate")).clicked() {
                        acts.push(Act::Duplicate(id));
                        ui.close();
                    }
                    if e.protocol == Protocol::Ssh && !e.tunnels.is_empty() && ui.button(tr("Start SSH tunnels")).clicked() {
                        acts.push(Act::StartTunnels(id));
                        ui.close();
                    }
                    if e.protocol == Protocol::Https && ui.button(tr("Check certificate")).clicked() {
                        acts.push(Act::CheckCert(id));
                        ui.close();
                    }
                    if !e.host.trim().is_empty() && e.protocol.needs_host() {
                        ui.menu_button(tr("More tools"), |ui| {
                            for k in [crate::tooltabs::ToolKind::Whois, crate::tooltabs::ToolKind::Http, crate::tooltabs::ToolKind::Snmp] {
                                if ui.button(k.title()).clicked() {
                                    acts.push(Act::NetTool(id, k));
                                    ui.close();
                                }
                            }
                        });
                    }
                    if cfg!(windows) && matches!(e.protocol, Protocol::Rdp | Protocol::PowerShell | Protocol::Vnc) {
                        ui.menu_button(tr("Windows management"), |ui| {
                            for (tool, label) in [
                                (extra::WinTool::Services, tr("Services")),
                                (extra::WinTool::Events, tr("Event viewer")),
                                (extra::WinTool::Manage, tr("Computer management")),
                                (extra::WinTool::Share, tr("Open drive C$")),
                            ] {
                                if ui.button(label).clicked() {
                                    acts.push(Act::WinTool(id, tool));
                                    ui.close();
                                }
                            }
                        });
                    }
                    if e.protocol.needs_host() && matches!(e.protocol, Protocol::Rdp | Protocol::PowerShell | Protocol::Vnc | Protocol::Ssh) {
                        ui.menu_button(tr("Power"), |ui| {
                            if ui.button(tr("Restart …")).clicked() {
                                acts.push(Act::Power(id, true));
                                ui.close();
                            }
                            if ui.button(tr("Shut down …")).clicked() {
                                acts.push(Act::Power(id, false));
                                ui.close();
                            }
                        });
                    }
                    if ui.button(tr("Copy host")).clicked() {
                        ui.ctx().copy_text(e.host.clone());
                        ui.close();
                    }
                }
                ui.separator();
                ui.menu_button(tr("Move to"), |ui| {
                    if ui.button(tr("(top level)")).clicked() {
                        acts.push(Act::MoveTo(id, None));
                        ui.close();
                    }
                    for (fid, path) in self.store.folders() {
                        if fid == id || self.store.is_descendant(fid, id) {
                            continue;
                        }
                        if ui.button(path).clicked() {
                            acts.push(Act::MoveTo(id, Some(fid)));
                            ui.close();
                        }
                    }
                });
                if ui.button(tr("Move up")).clicked() {
                    acts.push(Act::Shift(id, true));
                    ui.close();
                }
                if ui.button(tr("Move down")).clicked() {
                    acts.push(Act::Shift(id, false));
                    ui.close();
                }
                ui.separator();
                if ui.button(RichText::new(tr("Delete …")).color(BAD_RED)).clicked() {
                    acts.push(Act::AskDelete(id));
                    ui.close();
                }
            });
        });
        // drop target: upper quarter = before, lower quarter = after, middle of a folder = into
        let ctx = ui.ctx().clone();
        if let Some(dragged) = egui::DragAndDrop::payload::<u64>(&ctx).map(|p| *p) {
            if dragged != id {
                let rect = row.response.rect;
                if let Some(pos) = ctx.pointer_hover_pos().filter(|p| rect.contains(*p)) {
                    let f = (pos.y - rect.top()) / rect.height().max(1.0);
                    let where_ = if e.folder {
                        if f < 0.25 {
                            DropPos::Before
                        } else if f > 0.75 {
                            DropPos::After
                        } else {
                            DropPos::Into
                        }
                    } else if f < 0.5 {
                        DropPos::Before
                    } else {
                        DropPos::After
                    };
                    let blocked = self.store.get(dragged).map(|d| d.folder && (id == dragged || self.store.is_descendant(id, dragged))).unwrap_or(true);
                    if !blocked {
                        let painter = ui.painter();
                        let stroke = Stroke::new(2.0, ACCENT);
                        match where_ {
                            DropPos::Before => {
                                painter.hline(rect.x_range(), rect.top(), stroke);
                            }
                            DropPos::After => {
                                painter.hline(rect.x_range(), rect.bottom(), stroke);
                            }
                            DropPos::Into => {
                                painter.rect_stroke(rect, 3.0, stroke, egui::StrokeKind::Inside);
                            }
                        }
                        if ctx.input(|i| i.pointer.any_released()) {
                            egui::DragAndDrop::clear_payload(&ctx);
                            acts.push(Act::Drop(dragged, id, where_));
                        }
                    }
                }
            }
        }
    }

    fn props_panel(&mut self, ui: &mut egui::Ui, now: f64) {
        let ctx = ui.ctx().clone();
        ui.add_space(4.0);
        ui.heading(tr("Properties"));
        ui.separator();
        let Some(id) = self.selected else {
            ui.add_space(20.0);
            ui.weak(tr("Select a connection or folder on the left."));
            ui.add_space(8.0);
            ui.weak(tr("Double-click opens a connection, right-click shows all actions."));
            return;
        };
        let Some(idx) = self.store.index_of(id) else {
            self.selected = None;
            return;
        };
        let folders: Vec<(u64, String)> = self
            .store
            .folders()
            .into_iter()
            .filter(|(fid, _)| *fid != id && !self.store.is_descendant(*fid, id))
            .collect();
        let path = self.store.path_of(id);
        let inherited = self.store.data.entries[idx].parent.map(|p| self.store.credentials(p));
        let mut e = self.store.data.entries[idx].clone();
        let mut act: Option<Act> = None;
        let jump_opts: Vec<(u64, String)> = self
            .store
            .data
            .entries
            .iter()
            .filter(|x| !x.folder && x.protocol == Protocol::Ssh && x.id != id && !self.store.jump_chain(x.id).contains(&id))
            .map(|x| (x.id, format!("{} ({})", x.name, x.host)))
            .collect();
        let kp_unlocked = self.keepass.unlocked;
        let kp_paths: Vec<String> = self.keepass.entries.iter().map(|k| k.path.clone()).collect();
        let kp_configured = !self.store.data.settings.keepass_path.trim().is_empty();
        let kp_otp: Option<(String, u64)> = if self.keepass.unlocked {
            self.store
                .credential_info(id)
                .keepass
                .and_then(|r| self.keepass.find(&r).cloned())
                .filter(|k| !k.otp.trim().is_empty())
                .and_then(|k| crate::admintools::parse_otp(&k.otp))
                .map(|(key, digits, period)| {
                    let now_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                    crate::admintools::totp(&key, digits, period, now_s)
                })
        } else {
            None
        };
        if kp_otp.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
        let mut open_kp = false;
        let mut kp_save = false;
        let mut open_settings = false;
        let default_client = self.store.data.settings.default_ssh_client;

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                if e.folder {
                    ui.label(RichText::new(tr("Folder")).color(Color32::from_rgb(232, 180, 60)).strong());
                } else {
                    badge(ui, e.protocol);
                }
                ui.label(RichText::new(&e.name).size(17.0).strong());
            });
            ui.weak(&path);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if !e.folder
                    && ui
                        .add(egui::Button::new(RichText::new(tr("Connect")).color(Color32::WHITE).strong()).fill(ACCENT))
                        .clicked()
                {
                    act = Some(Act::Connect(id));
                }
                if !e.folder && e.protocol == Protocol::Ssh && ui.button(tr("Files")).on_hover_text(tr("Upload and download files (SFTP)")).clicked() {
                    act = Some(Act::Files(id));
                }
                if e.folder && ui.button(tr("Open all")).clicked() {
                    act = Some(Act::ConnectAll(id));
                }
                if !e.folder && ui.button(tr("Duplicate")).clicked() {
                    act = Some(Act::Duplicate(id));
                }
                if ui.button(RichText::new(tr("Delete")).color(BAD_RED)).clicked() {
                    act = Some(Act::AskDelete(id));
                }
            });
            ui.add_space(8.0);

            section(ui, tr("General"));
            egui::Grid::new(tr("props_general")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label(tr("Name"));
                ui.add(egui::TextEdit::singleline(&mut e.name).desired_width(f32::INFINITY));
                ui.end_row();
                ui.label(tr("Folder"));
                let current = e
                    .parent
                    .and_then(|p| folders.iter().find(|(f, _)| *f == p).map(|(_, n)| n.clone()))
                    .unwrap_or_else(|| tr("(top level)").into());
                egui::ComboBox::from_id_salt("parent_combo").selected_text(current).width(200.0).show_ui(ui, |ui| {
                    ui.selectable_value(&mut e.parent, None, tr("(top level)"));
                    for (fid, name) in &folders {
                        ui.selectable_value(&mut e.parent, Some(*fid), name);
                    }
                });
                ui.end_row();
                if !e.folder {
                    ui.label(tr("Protocol"));
                    let before = e.protocol;
                    egui::ComboBox::from_id_salt("proto_combo").selected_text(e.protocol.label()).width(200.0).show_ui(ui, |ui| {
                        for p in Protocol::ALL {
                            ui.selectable_value(&mut e.protocol, p, p.label());
                        }
                    });
                    if before != e.protocol && (e.port == before.default_port() || e.port == 0) {
                        e.port = e.protocol.default_port();
                    }
                    ui.end_row();
                    if e.protocol.needs_host() {
                        ui.label(tr("Host / IP"));
                        ui.add(egui::TextEdit::singleline(&mut e.host).hint_text("server.corp.local").desired_width(f32::INFINITY));
                        ui.end_row();
                        if e.protocol == Protocol::Serial {
                            ui.label(tr("Speed"));
                            egui::ComboBox::from_id_salt("baud").selected_text(format!("{} Baud", e.baud)).show_ui(ui, |ui| {
                                for b in [1200u32, 2400, 4800, 9600, 19200, 38400, 57600, 115200] {
                                    ui.selectable_value(&mut e.baud, b, format!("{b} Baud"));
                                }
                            });
                            ui.end_row();
                        } else {
                            ui.label(tr("Port"));
                            ui.add(egui::DragValue::new(&mut e.port).range(1..=65535));
                            ui.end_row();
                        }
                    }
                }
            });

            if e.protocol != Protocol::LocalShell || e.folder {
                section_help(ui, tr("Login"), crate::help::Topic::Passwords, &mut self.help_request);
                egui::Grid::new(tr("props_login")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label(tr("User"));
                    ui.add(egui::TextEdit::singleline(&mut e.username).desired_width(f32::INFINITY));
                    ui.end_row();
                    ui.label(tr("Domain"));
                    ui.add(egui::TextEdit::singleline(&mut e.domain).desired_width(f32::INFINITY));
                    ui.end_row();
                    ui.label(tr("Password from"));
                    egui::ComboBox::from_id_salt("cred_src").selected_text(e.cred_source.label()).width(220.0).show_ui(ui, |ui| {
                        for s in [CredSource::Stored, CredSource::KeePass, CredSource::Ask] {
                            ui.selectable_value(&mut e.cred_source, s, s.label());
                        }
                    });
                    ui.end_row();
                    match e.cred_source {
                        CredSource::Stored => {
                            ui.label(tr("Password"));
                            ui.add(egui::TextEdit::singleline(&mut e.password).password(!self.show_password).desired_width(f32::INFINITY));
                            ui.end_row();
                            ui.label("");
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.show_password, tr("Show password"));
                                if ui.small_button(tr("Generate")).on_hover_text(tr("Generate a secure password")).clicked() {
                                    self.pwgen.open = true;
                                    self.pwgen.target = Some(id);
                                    self.pwgen.value.clear();
                                }
                            });
                            ui.end_row();
                        }
                        CredSource::KeePass => {
                            if let Some((code, left)) = &kp_otp {
                                ui.label(tr("2FA code"));
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(code).monospace().size(16.0).strong());
                                    ui.weak(tf("{0} s left", &[left]));
                                    if ui.small_button(tr("copy")).clicked() {
                                        ui.ctx().copy_text(code.clone());
                                    }
                                });
                                ui.end_row();
                            }
                            ui.label(tr("KeePass entry"));
                            ui.add(
                                egui::TextEdit::singleline(&mut e.keepass_entry)
                                    .hint_text(tr("empty = search by host"))
                                    .desired_width(f32::INFINITY),
                            );
                            ui.end_row();
                            ui.label("");
                            ui.horizontal(|ui| {
                                if !kp_configured {
                                    if ui.link(tr("Set up KeePass file")).clicked() {
                                        open_settings = true;
                                    }
                                } else if kp_unlocked {
                                    let filter = e.keepass_entry.to_lowercase();
                                    egui::ComboBox::from_id_salt("kp_pick").selected_text(tr("Choose entry …")).width(200.0).show_ui(ui, |ui| {
                                        for p in kp_paths.iter().filter(|p| filter.is_empty() || p.to_lowercase().contains(&filter)).take(300) {
                                            if ui.selectable_label(false, p).clicked() {
                                                e.keepass_entry = p.clone();
                                            }
                                        }
                                    });
                                    if ui.button(tr("Save password in KeePass …")).on_hover_text(tr("Writes a password for this connection into the KeePass database (group \"AdminCraft\") and uses that entry.")).clicked() {
                                        kp_save = true;
                                    }
                                } else if ui.button(tr("Unlock KeePass")).clicked() {
                                    open_kp = true;
                                }
                            });
                            ui.end_row();
                        }
                        CredSource::Ask => {
                            ui.label("");
                            ui.weak(tr("Asked when connecting and remembered until AdminCraft closes."));
                            ui.end_row();
                        }
                    }
                    if !e.folder {
                        ui.label("");
                        ui.checkbox(&mut e.inherit_credentials, tr("Take empty fields from the folder"));
                        ui.end_row();
                    }
                });
                if e.folder {
                    ui.weak(tr("User, domain and password apply to all connections in this folder that have nothing of their own."));
                } else if e.inherit_credentials {
                    if let Some((u, d, p)) = &inherited {
                        if (e.username.is_empty() && !u.is_empty()) || (e.domain.is_empty() && !d.is_empty()) || (e.password.is_empty() && !p.is_empty()) {
                            let mut parts = Vec::new();
                            if e.username.is_empty() && !u.is_empty() {
                                parts.push(tf("user {0}", &[&u]));
                            }
                            if e.domain.is_empty() && !d.is_empty() {
                                parts.push(tf("domain {0}", &[&d]));
                            }
                            if e.password.is_empty() && !p.is_empty() {
                                parts.push(tr("Password").into());
                            }
                            ui.label(RichText::new(tf("From the folder: {0}", &[&(parts.join(", "))])).italics().color(ACCENT));
                        }
                    }
                }
            }

            if !e.folder {
                match e.protocol {
                    Protocol::Rdp => {
                        section(ui, tr("Remote desktop"));
                        let presets = [(1280, 720), (1366, 768), (1600, 900), (1920, 1080), (2560, 1440)];
                        let current = if e.rdp.fullscreen { tr("Full screen").to_string() } else { format!("{} × {}", e.rdp.width, e.rdp.height) };
                        egui::Grid::new(tr("props_rdp")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                            ui.label(tr("Screen"));
                            egui::ComboBox::from_id_salt("rdp_res").selected_text(current).show_ui(ui, |ui| {
                                if ui.selectable_label(e.rdp.fullscreen, tr("Full screen")).clicked() {
                                    e.rdp.fullscreen = true;
                                }
                                for (w, h) in presets {
                                    let sel = !e.rdp.fullscreen && e.rdp.width == w && e.rdp.height == h;
                                    if ui.selectable_label(sel, format!("{w} × {h}")).clicked() {
                                        e.rdp.fullscreen = false;
                                        e.rdp.width = w;
                                        e.rdp.height = h;
                                    }
                                }
                            });
                            ui.end_row();
                        });
                        ui.checkbox(&mut e.rdp.pass_credentials, tr("Pass the login automatically"))
                            .on_hover_text(tr(if cfg!(windows) {
                                "Stores user and password for this host in the Windows Credential Manager (cmdkey), so Remote Desktop logs in by itself."
                            } else {
                                "Passes user and password to FreeRDP."
                            }));
                        ui.checkbox(&mut e.rdp.admin_session, tr("Admin/console session (/admin)"));
                        ui.checkbox(&mut e.rdp.multimon, tr("Use all monitors"));
                        ui.checkbox(&mut e.rdp.redirect_clipboard, tr("Share clipboard"));
                        ui.checkbox(&mut e.rdp.redirect_drives, tr("Connect local drives"));
                    }
                    Protocol::Ssh | Protocol::Sftp | Protocol::Scp => {
                        section(ui, if e.protocol == Protocol::Ssh { "SSH" } else { "SSH / Dateien" });
                        egui::Grid::new(tr("props_ssh")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                            if e.protocol == Protocol::Ssh {
                                ui.label(tr("Open with"));
                                let shown = if e.ssh_client == SshClient::Default {
                                    tf("Default ({0})", &[&tr(short_client(default_client))])
                                } else {
                                    e.ssh_client.label().to_string()
                                };
                                egui::ComboBox::from_id_salt("ssh_client").selected_text(shown).width(220.0).show_ui(ui, |ui| {
                                    for c in [SshClient::Default, SshClient::Builtin, SshClient::Putty, SshClient::External] {
                                        ui.selectable_value(&mut e.ssh_client, c, c.label());
                                    }
                                });
                                ui.end_row();
                            }
                            ui.label(tr("Jump host"));
                            let cur = e
                                .jump_host
                                .and_then(|j| jump_opts.iter().find(|(x, _)| *x == j).map(|(_, n)| n.clone()))
                                .unwrap_or_else(|| tr("(none – connect directly)").into());
                            egui::ComboBox::from_id_salt("jump_host").selected_text(cur).width(220.0).show_ui(ui, |ui| {
                                ui.selectable_value(&mut e.jump_host, None, tr("(none – connect directly)"));
                                for (jid, name) in &jump_opts {
                                    ui.selectable_value(&mut e.jump_host, Some(*jid), name);
                                }
                            });
                            ui.end_row();
                            if e.jump_host.is_some() && e.protocol == Protocol::Ssh {
                                ui.label(tr("Continue via"));
                                ui.vertical(|ui| {
                                    ui.radio_value(&mut e.jump_mode, JumpMode::Chain, tr("Continue on the jump host: \"ssh user@target\""))
                                        .on_hover_text(tr("AdminCraft logs in to the jump host and runs ssh to the target there right away. Right when the SSH key for the target is ON the jump host. Works with terminal tab, PuTTY and own window."));
                                    ui.radio_value(&mut e.jump_mode, JumpMode::ProxyJump, tr("Tunnel through the jump host (ssh -J)"))
                                        .on_hover_text(tr("The connection runs through the jump host, the login happens from THIS PC (key/password here). PuTTY needs plink for this."));
                                });
                                ui.end_row();
                            }
                            ui.label(tr("Key file"));
                            ui.add(egui::TextEdit::singleline(&mut e.ssh_key).hint_text(tr("~/.ssh/id_ed25519 (optional)")).desired_width(f32::INFINITY));
                            ui.end_row();
                            if e.protocol == Protocol::Ssh {
                                ui.label(tr("Extra options"));
                                ui.add(egui::TextEdit::singleline(&mut e.extra_args).hint_text(tr("e.g. -L 8080:localhost:80")).desired_width(f32::INFINITY));
                                ui.end_row();
                            } else {
                                ui.label(tr("Start folder"));
                                ui.add(egui::TextEdit::singleline(&mut e.start_path).hint_text(tr("/home/user (optional)")).desired_width(f32::INFINITY));
                                ui.end_row();
                            }
                        });
                        if e.jump_host.is_some() && e.protocol != Protocol::Ssh {
                            ui.weak(tr("File transfer through a jump host always uses the tunnel (ssh -J)."));
                        }
                        if e.protocol == Protocol::Ssh {
                            section_help(ui, tr("Tunnels (port forwarding)"), crate::help::Topic::Tools, &mut self.help_request);
                            let mut remove = None;
                            for (i, tun) in e.tunnels.iter_mut().enumerate() {
                                ui.horizontal(|ui| {
                                    ui.label(tr("local"));
                                    ui.add(egui::DragValue::new(&mut tun.local_port).range(1..=65535));
                                    ui.label("»");
                                    ui.add(egui::TextEdit::singleline(&mut tun.remote_host).desired_width(90.0));
                                    ui.label(":");
                                    ui.add(egui::DragValue::new(&mut tun.remote_port).range(1..=65535));
                                    ui.checkbox(&mut tun.auto, tr("auto")).on_hover_text(tr("Start together with the connection"));
                                    if ui.small_button("×").on_hover_text(tr("Remove")).clicked() {
                                        remove = Some(i);
                                    }
                                });
                            }
                            if let Some(i) = remove {
                                e.tunnels.remove(i);
                            }
                            ui.horizontal(|ui| {
                                if ui.button(tr("+ Tunnel")).clicked() {
                                    e.tunnels.push(Default::default());
                                }
                                if !e.tunnels.is_empty() && ui.button(tr("Start tunnels")).clicked() {
                                    act = Some(Act::StartTunnels(id));
                                }
                            });
                            ui.weak(tr("Example: local 8443 » 192.168.1.1:443 – then open https://localhost:8443."));
                        }
                    }
                    Protocol::Ftp => {
                        section(ui, tr("FTP"));
                        ui.checkbox(&mut e.ftp_tls, tr("Encrypted (FTPS, explicit TLS)"));
                        if e.ftp_tls {
                            ui.checkbox(&mut e.tls_ignore_cert, tr("Don't check the certificate (self-signed, e.g. NAS)"))
                                .on_hover_text(tr("Only for your own devices in your own network: the connection stays encrypted, but the server is not verified."));
                        }
                        egui::Grid::new(tr("props_ftp")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                            ui.label(tr("Start folder"));
                            ui.add(egui::TextEdit::singleline(&mut e.start_path).hint_text(tr("/ (optional)")).desired_width(f32::INFINITY));
                            ui.end_row();
                        });
                        ui.weak(tr("Empty user = anonymous FTP."));
                    }
                    Protocol::Http | Protocol::Https => {
                        section(ui, tr("Web"));
                        ui.add_enabled(cfg!(windows), egui::Checkbox::new(&mut e.web_in_tab, tr("Open in a tab (Edge/Chrome window)")))
                            .on_disabled_hover_text(tr("Only possible on Windows."));
                        if e.protocol == Protocol::Https && ui.button(tr("Check certificate")).clicked() {
                            act = Some(Act::CheckCert(id));
                        }
                    }
                    Protocol::Telnet | Protocol::Vnc => {
                        section(ui, tr("Advanced"));
                        egui::Grid::new(tr("props_extra")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                            ui.label(tr("Extra options"));
                            ui.add(egui::TextEdit::singleline(&mut e.extra_args).desired_width(f32::INFINITY));
                            ui.end_row();
                        });
                    }
                    _ => {}
                }

                if e.protocol.needs_host() {
                    section(ui, tr("Network"));
                    egui::Grid::new(tr("props_net")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                        ui.label(tr("MAC address"));
                        ui.add(egui::TextEdit::singleline(&mut e.mac).hint_text(tr("for Wake-on-LAN")).desired_width(f32::INFINITY));
                        ui.end_row();
                    });
                    ui.horizontal(|ui| {
                        if ui.button(tr("Ping")).clicked() {
                            act = Some(Act::Ping(id));
                        }
                        if ui.button(tr("Port scan")).clicked() {
                            act = Some(Act::Scan(id));
                        }
                        if ui.add_enabled(!e.mac.trim().is_empty(), egui::Button::new(tr("Wake up"))).clicked() {
                            act = Some(Act::Wake(id));
                        }
                    });
                }
            }

            section(ui, tr("Notes"));
            ui.add(egui::TextEdit::multiline(&mut e.description).desired_rows(4).desired_width(f32::INFINITY).hint_text(tr("e.g. location, contact person, special notes")));
        });

        if e != self.store.data.entries[idx] {
            if e.parent != self.store.data.entries[idx].parent {
                self.expand(e.parent);
            }
            self.store.data.entries[idx] = e;
            self.mark_dirty(now);
        }
        if let Some(a) = act {
            self.apply(a, &ctx, now);
        }
        if open_kp {
            self.kp_dialog = true;
            self.kp_msg = None;
        }
        if kp_save {
            if let Some(e) = self.store.data.entries.get(idx) {
                self.kp_save = Some((e.id, String::new(), None));
            }
        }
        if open_settings {
            self.open_settings();
        }
    }

    // ------------------------------------------------------------ tab area

    fn swap_tabs(&mut self, a: usize, b: usize) {
        if a == 0 || b == 0 || a >= self.tabs.len() || b >= self.tabs.len() {
            return; // the start page stays first
        }
        self.tabs.swap(a, b);
        if self.active == a {
            self.active = b;
        } else if self.active == b {
            self.active = a;
        }
    }

    fn tab_strip(&mut self, ui: &mut egui::Ui) {
        let mut close: Option<usize> = self.close_request.take().filter(|&i| i > 0 && i < self.tabs.len());
        let mut swap: Option<(usize, usize)> = None;
        let mut rename_start: Option<(u64, String)> = None;
        let mut rename_done: Option<(u64, Option<String>)> = None;
        let mut rects: Vec<Rect> = Vec::new();
        let mut drag_from: Option<usize> = None;
        let mut drag_stop = false;
        egui::ScrollArea::horizontal().id_salt("tabstrip").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, tab) in self.tabs.iter().enumerate() {
                    let active = i == self.active;
                    let fill = if active { ui.visuals().selection.bg_fill } else { ui.visuals().faint_bg_color };
                    let dragging = self.drag_tab == Some(i);
                    let frame_resp = egui::Frame::new()
                        .fill(fill)
                        .stroke(if dragging { Stroke::new(1.5, ACCENT) } else { Stroke::NONE })
                        .corner_radius(egui::CornerRadius { nw: 6, ne: 6, sw: 0, se: 0 })
                        .inner_margin(egui::Margin::symmetric(8, 4))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let (r, _) = ui.allocate_exact_size(Vec2::new(8.0, 14.0), Sense::hover());
                                let mut dot = tab.color;
                                if let TabKind::Term(t) = &tab.kind {
                                    if t.term.as_ref().map(|x| x.exited.is_some()).unwrap_or(true) {
                                        dot = Color32::GRAY;
                                    }
                                }
                                if let TabKind::Proc(p) = &tab.kind {
                                    if p.exited.is_some() {
                                        dot = Color32::GRAY;
                                    }
                                }
                                ui.painter().circle_filled(r.center(), 4.0, dot);
                                if let Some((rid, text)) = self.rename_tab.as_mut().filter(|(rid, _)| *rid == tab.id) {
                                    let r = ui.add(egui::TextEdit::singleline(text).desired_width(160.0));
                                    r.request_focus();
                                    if ui.input(|inp| inp.key_pressed(egui::Key::Escape)) {
                                        rename_done = Some((*rid, None));
                                    } else if r.lost_focus() || ui.input(|inp| inp.key_pressed(egui::Key::Enter)) {
                                        rename_done = Some((*rid, Some(text.clone())));
                                    }
                                } else {
                                    let text = if active { RichText::new(&tab.title).strong().color(Color32::WHITE) } else { RichText::new(&tab.title) };
                                    let r = ui.add(egui::Label::new(text).sense(Sense::click_and_drag()).truncate());
                                    if r.clicked() {
                                        self.active = i;
                                    }
                                    if r.double_clicked() && i != 0 {
                                        rename_start = Some((tab.id, tab.title.clone()));
                                    }
                                    if r.middle_clicked() && i != 0 {
                                        close = Some(i);
                                    }
                                    if r.drag_started() && i != 0 {
                                        drag_from = Some(i);
                                    }
                                    if r.drag_stopped() {
                                        drag_stop = true;
                                    }
                                    if i != 0 {
                                        r.on_hover_text(tr("Double-click: rename · drag: move · right-click: more")).context_menu(|ui| {
                                            if ui.button(tr("Rename")).clicked() {
                                                rename_start = Some((tab.id, tab.title.clone()));
                                                ui.close();
                                            }
                                            if i > 1 && ui.button(tr("Move left")).clicked() {
                                                swap = Some((i, i - 1));
                                                ui.close();
                                            }
                                            if i + 1 < self.tabs.len() && ui.button(tr("Move right")).clicked() {
                                                swap = Some((i, i + 1));
                                                ui.close();
                                            }
                                            ui.separator();
                                            if ui.button(tr("Close tab")).clicked() {
                                                close = Some(i);
                                                ui.close();
                                            }
                                        });
                                    }
                                }
                                if i != 0 && ui.add(egui::Button::new("×").frame(false).small()).on_hover_text(tr("Close tab")).clicked() {
                                    close = Some(i);
                                }
                            });
                        });
                    rects.push(frame_resp.response.rect);
                }
            });
        });
        if let Some(i) = drag_from {
            self.drag_tab = Some(i);
            self.active = i;
        }
        // while a tab is dragged, it trades places with the neighbour it passes
        if let (Some(i), Some(pos)) = (self.drag_tab, ui.ctx().pointer_interact_pos()) {
            if i + 1 < rects.len() && pos.x > rects[i + 1].center().x {
                swap = Some((i, i + 1));
            } else if i > 1 && pos.x < rects[i - 1].center().x {
                swap = Some((i, i - 1));
            }
        }
        if let Some((a, b)) = swap {
            self.swap_tabs(a, b);
            if self.drag_tab == Some(a) {
                self.drag_tab = Some(b);
            }
        }
        if drag_stop || !ui.ctx().input(|i| i.pointer.primary_down()) {
            self.drag_tab = None;
        }
        if let Some(r) = rename_start {
            self.rename_tab = Some(r);
        }
        if let Some((id, text)) = rename_done {
            if let Some(text) = text.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == id) {
                    tab.title = text;
                }
            }
            self.rename_tab = None;
        }
        if let Some(i) = close {
            if let TabKind::Term(t) = &mut self.tabs[i].kind {
                if let Some(term) = &mut t.term {
                    term.kill();
                }
            }
            if let TabKind::Ping(p) = &mut self.tabs[i].kind {
                p.runner.stop();
            }
            if let TabKind::Proc(p) = &mut self.tabs[i].kind {
                stop_proc(p);
            }
            if let TabKind::NetScan(n) = &self.tabs[i].kind {
                if let Some(s) = &n.scan {
                    s.cancel();
                }
            }
            if let TabKind::Scan(s) = &self.tabs[i].kind {
                if let Some(sc) = &s.scan {
                    sc.cancel();
                }
            }
            self.tabs.remove(i);
            if self.active >= i && self.active > 0 {
                self.active -= 1;
            }
        }
        self.active = self.active.min(self.tabs.len().saturating_sub(1));
    }

    fn tab_content(&mut self, ui: &mut egui::Ui, now: f64) {
        let ctx = ui.ctx().clone();
        let settings_font = self.store.data.settings.terminal_font_size;
        let dark = self.store.data.settings.dark;
        let auto_pw = self.store.data.settings.auto_password;
        let active = self.active;
        let mut reconnect: Option<(Entry, Creds, Vec<JumpHop>)> = None;
        let mut start_acts: Vec<StartAct> = Vec::new();
        self.last_content = ui.available_rect_before_wrap();
        self.embed_rect = None;
        let show_hidden = self.store.data.settings.show_hidden;
        let snippets = self.store.data.settings.snippets.clone();
        let mut broadcast: Option<Vec<u8>> = None;
        let mut open_settings_req = false;
        let mut netscan_acts: Vec<NetScanAct> = Vec::new();
        let mut scan_range: Option<String> = None;
        let mut tunnel_acts: Vec<TunnelAct> = Vec::new();
        if matches!(self.tabs[active].kind, TabKind::Start) {
            self.start_page(ui, &mut start_acts);
        } else if matches!(self.tabs[active].kind, TabKind::Tunnels) {
            tunnel_acts = extra::tunnels_ui(ui, &self.store.data.entries, &mut self.tunnels);
        } else if matches!(self.tabs[active].kind, TabKind::Settings) {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.set_max_width(ui.available_width().min(900.0));
                self.settings_ui(ui, now);
            });
        } else {
            let mut embed_rect = None;
            match &mut self.tabs[active].kind {
                TabKind::Start | TabKind::Settings | TabKind::Tunnels => {}
                TabKind::Proc(p) => {
                    let (r, area) = proc_ui(ui, p, now);
                    if let Some(r) = r {
                        reconnect = Some(r);
                    }
                    embed_rect = Some(area);
                }
                TabKind::Transfer(t) => transfer_ui(ui, t, show_hidden),
                TabKind::Help(h) => crate::help::help_ui(ui, h),
                TabKind::Playback(p) => crate::playback::playback_ui(ui, p, settings_font, dark),
                TabKind::Tool(x) => crate::tooltabs::tool_ui(ui, x),
                TabKind::Term(t) => {
                    let mut snippet_cmd: Option<String> = None;
                    ui.horizontal(|ui| {
                        badge(ui, t.entry.protocol);
                        ui.label(RichText::new(&t.preview).monospace().weak());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if t.term.as_ref().is_some_and(|x| x.recording()) {
                                ui.colored_label(Color32::from_rgb(229, 57, 53), tr("• recording"))
                                    .on_hover_text(tr("This session is recorded and can be played back (Tools » Recordings)."));
                            }
                            if ui.button(tr("Reconnect")).clicked() {
                                if let Some(term) = &mut t.term {
                                    term.kill();
                                }
                                reconnect = Some((t.entry.clone(), t.creds.clone(), t.jumps.clone()));
                            }
                            ui.checkbox(&mut t.broadcast, tr("Multi"))
                                .on_hover_text(tr("What you type here also goes to all other tabs with \"Multi\"."));
                            let (entry, creds) = (t.entry.clone(), t.creds.clone());
                            ui.menu_button(tr("Commands"), |ui| {
                                for sn in &snippets {
                                    if ui.button(&sn.name).on_hover_text(&sn.command).clicked() {
                                        snippet_cmd = Some(fill_snippet(&sn.command, &entry, &creds));
                                        ui.close();
                                    }
                                }
                                if snippets.is_empty() {
                                    ui.weak(tr("No commands saved yet."));
                                }
                                ui.separator();
                                if ui.button(tr("Manage commands …")).clicked() {
                                    open_settings_req = true;
                                    ui.close();
                                }
                            });
                            if let Some(term) = &mut t.term {
                                if ui.button(tr("Copy text")).on_hover_text(tr("Screen content to the clipboard")).clicked() {
                                    ui.ctx().copy_text(term.screen_text());
                                }
                                if term.has_password() && ui.button(tr("Send password")).clicked() {
                                    term.send_password();
                                    term.focus_next = true;
                                }
                                if ui.button(tr("Ctrl+C")).on_hover_text(tr("Interrupt")).clicked() {
                                    term.send(&[3]);
                                    term.focus_next = true;
                                }
                            }
                        });
                    });
                    if let Some(err) = &t.error {
                        ui.add_space(20.0);
                        ui.label(RichText::new(err).color(BAD_RED).size(15.0));
                    }
                    if let Some(term) = &mut t.term {
                        term.pump(auto_pw);
                        if let Some(msg) = &term.exited {
                            ui.label(RichText::new(msg).color(WARN));
                        } else if term.chain_left() > 0 {
                            ui.label(
                                RichText::new(tf("Jump host: {0} hop(s) left – ssh is typed at the prompt automatically …", &[&(term.chain_left())]))
                                    .color(ACCENT),
                            );
                        }
                        if let Some(cmd) = snippet_cmd.take() {
                            let mut b = cmd.into_bytes();
                            b.push(b'\r');
                            term.send(&b);
                            term.focus_next = true;
                            if t.broadcast {
                                broadcast = Some(b);
                            }
                        }
                        let typed = term.ui(ui, settings_font, dark);
                        if t.broadcast && !typed.is_empty() {
                            broadcast = Some(typed);
                        }
                    }
                }
                TabKind::Ping(p) => ping_ui(ui, p, &ctx),
                TabKind::Scan(s) => scan_ui(ui, s, &ctx),
                TabKind::Dns(d) => dns_ui(ui, d, &ctx),
                TabKind::Wol(w) => wol_ui(ui, w),
                TabKind::NetScan(n) => netscan_acts = extra::netscan_ui(ui, n, &ctx),
                TabKind::Subnet(s) => scan_range = extra::subnet_ui(ui, s),
                TabKind::Cert(c) => extra::cert_ui(ui, c, &ctx),
            }
            self.embed_rect = embed_rect;
        }
        if let Some((mut e, mut creds, mut jumps)) = reconnect {
            if e.id != 0 {
                if let Some(fresh) = self.store.get(e.id).cloned() {
                    let keep_client = e.ssh_client;
                    e = fresh;
                    e.ssh_client = keep_client;
                }
                if let Ok((c, j, _)) = self.resolve(e.id) {
                    creds = c;
                    jumps = j;
                }
            }
            let px = self.tab_px(&ctx);
            let settings = self.store.data.settings.clone();
            match &mut self.tabs[active].kind {
                TabKind::Term(t) => {
                    match launch::launch(&e, &creds, &settings, &jumps, px) {
                        Ok(Launch::Terminal { cmd, preview, passwords, chain }) => match Terminal::spawn(cmd, ctx.clone(), passwords, chain) {
                            Ok(term) => {
                                t.term = Some(term);
                                t.error = None;
                                t.preview = preview;
                            }
                            Err(err) => t.error = Some(err),
                        },
                        Ok(Launch::Done(m)) => t.error = Some(m),
                        Ok(_) => t.error = Some(tr("Connection type changed – please close the tab and open it again.").into()),
                        Err(err) => t.error = Some(err),
                    }
                    t.entry = e;
                    t.creds = creds;
                    t.jumps = jumps;
                }
                TabKind::Proc(p) => {
                    stop_proc(p);
                    match launch::launch(&e, &creds, &settings, &jumps, px) {
                        Ok(Launch::Process { child, label, embed }) => {
                            let pid = child.id();
                            p.want_embed = embed.is_some() && embed::SUPPORTED;
                            p.embed = embed.map(|c| Embedded::new(pid, c));
                            p.child = Some(child);
                            p.label = label;
                            p.started = now;
                            p.last_try = 0.0;
                            p.exited = None;
                            p.detached = false;
                        }
                        Ok(Launch::Done(m)) => p.exited = Some(m),
                        Ok(_) => p.exited = Some(tr("Connection type changed – please close the tab and open it again.").into()),
                        Err(err) => p.exited = Some(err),
                    }
                    p.entry = e;
                    p.creds = creds;
                    p.jumps = jumps;
                }
                _ => {}
            }
        }
        if let Some(bytes) = broadcast {
            for (i, tab) in self.tabs.iter_mut().enumerate() {
                if i == active {
                    continue;
                }
                if let TabKind::Term(x) = &mut tab.kind {
                    if x.broadcast {
                        if let Some(term) = &mut x.term {
                            term.send(&bytes);
                        }
                    }
                }
            }
        }
        if open_settings_req {
            self.open_settings();
        }
        if let Some(r) = scan_range {
            self.open_netscan(r);
        }
        for a in tunnel_acts {
            match a {
                TunnelAct::Start(id, idx) => self.start_tunnel(id, idx, now),
                TunnelAct::Stop(id, idx) => {
                    if let Some(mut r) = self.tunnels.remove(&(id, idx)) {
                        if let Some(mut c) = r.child.take() {
                            let _ = c.kill();
                        }
                    }
                }
            }
        }
        for a in netscan_acts {
            match a {
                NetScanAct::Add(h, proto) => {
                    let folder = match self.store.data.entries.iter().find(|e| e.folder && e.name == tr("Network scan")).map(|e| e.id) {
                        Some(f) => f,
                        None => {
                            let fid = self.store.next_id();
                            self.store.data.entries.push(Entry { id: fid, folder: true, name: tr("Network scan").into(), inherit_credentials: false, ..Default::default() });
                            fid
                        }
                    };
                    let nid = self.store.next_id();
                    let name = if h.name.is_empty() { h.ip.to_string() } else { format!("{} ({})", h.name, h.ip) };
                    let mut desc = format!("MAC {}", h.mac);
                    if !h.ports.is_empty() {
                        desc.push_str(&format!(" · Ports {}", h.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
                    }
                    self.store.data.entries.push(Entry {
                        id: nid,
                        parent: Some(folder),
                        name,
                        protocol: proto,
                        host: h.ip.to_string(),
                        port: proto.default_port(),
                        mac: h.mac.clone(),
                        description: desc,
                        ..Default::default()
                    });
                    self.expand(Some(folder));
                    self.selected = Some(nid);
                    self.mark_dirty(now);
                    self.note(tf("Connection created: {0}", &[&h.ip]), false, now);
                }
                NetScanAct::Connect(h, proto) => {
                    let e = Entry { name: h.ip.to_string(), protocol: proto, host: h.ip.to_string(), port: proto.default_port(), inherit_credentials: false, ..Default::default() };
                    self.open_session(e, Creds::default(), Vec::new(), &ctx, now);
                }
            }
        }
        for a in start_acts {
            match a {
                StartAct::NewConn => self.apply(Act::NewConn(None), &ctx, now),
                StartAct::Import => self.show_import = true,
                StartAct::Settings => self.show_settings = true,
                StartAct::Ping => self.open_ping(String::new(), PingMode::Ping, &ctx),
                StartAct::Scan => self.open_scan(String::new()),
                StartAct::Dns => self.open_dns(String::new()),
                StartAct::Wol => self.open_wol(String::new()),
                StartAct::Shell => {
                    let e = Entry { name: tr("Local shell").into(), protocol: Protocol::LocalShell, ..Default::default() };
                    self.open_session(e, Creds::default(), Vec::new(), &ctx, now);
                }
                StartAct::Connect(id) => self.connect_id(id, &ctx, now),
                StartAct::Status => self.check_status(&ctx),
                StartAct::Tools => launch::open_folder(&programs::ensure_tools_dir()),
                StartAct::NetScan => self.open_netscan(String::new()),
                StartAct::Subnet => self.add_tab(tr("Subnet calculator").into(), Color32::from_rgb(0, 137, 123), TabKind::Subnet(extra::SubnetTab::default())),
                StartAct::Cert => self.open_cert(String::new()),
                StartAct::Tunnels => self.open_tunnels(),
                StartAct::Help(topic) => self.open_help(topic),
                StartAct::Files => {
                    let target = self
                        .selected
                        .and_then(|id| self.store.get(id))
                        .filter(|e| !e.folder && (e.protocol.transfer() || e.protocol == Protocol::Ssh))
                        .map(|e| e.id);
                    match target {
                        Some(id) => self.apply(Act::Files(id), &ctx, now),
                        None => {
                            self.quick_protocol = Protocol::Sftp;
                            self.note(tr("Pick an SSH/SFTP/FTP server on the left or enter SFTP/FTP + host in quick connect above."), false, now);
                        }
                    }
                }
            }
        }
    }

    fn start_page(&mut self, ui: &mut egui::Ui, acts: &mut Vec<StartAct>) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                logo(ui, 60.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(tr("AdminCraft")).size(28.0).strong());
                    ui.label(tr("All servers, switches and PCs in one place – RDP, SSH, VNC, Telnet, PowerShell and web."));
                    ui.horizontal(|ui| {
                        ui.weak(tr("New here?"));
                        if ui.small_button(tr("First steps")).clicked() {
                            acts.push(StartAct::Help(Some(crate::help::Topic::FirstConnection)));
                        }
                        if ui.small_button(tr("User guide")).on_hover_text("F1").clicked() {
                            acts.push(StartAct::Help(None));
                        }
                    });
                });
            });
            ui.add_space(14.0);

            ui.label(RichText::new(tr("Quick start")).strong().size(15.0));
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                let cards: [(&str, &str, StartAct, Color32); 15] = [
                    ("New connection", "Add a server or device", StartAct::NewConn, ACCENT),
                    ("Transfer files", "SFTP, SCP, FTP – up & down", StartAct::Files, Protocol::Sftp.color()),
                    ("Ping", "Is the host reachable?", StartAct::Ping, Color32::from_rgb(0, 150, 136)),
                    ("Port scan", "Which services are running?", StartAct::Scan, Color32::from_rgb(255, 152, 0)),
                    ("DNS lookup", "Name to IP address", StartAct::Dns, Color32::from_rgb(156, 39, 176)),
                    ("Wake-on-LAN", "Switch a PC on over the network", StartAct::Wol, Color32::from_rgb(255, 193, 7)),
                    ("Local shell", "Terminal on this PC", StartAct::Shell, Color32::from_rgb(121, 85, 72)),
                    ("Check status", "Test all hosts", StartAct::Status, OK_GREEN),
                    ("Network scan", "Find devices in an IP range", StartAct::NetScan, Color32::from_rgb(3, 169, 244)),
                    ("Subnet calculator", "Network, mask, broadcast", StartAct::Subnet, Color32::from_rgb(0, 137, 123)),
                    ("Check certificate", "How long is HTTPS still valid?", StartAct::Cert, Color32::from_rgb(139, 195, 74)),
                    ("SSH tunnels", "Port forwarding", StartAct::Tunnels, Color32::from_rgb(121, 134, 203)),
                    ("Programs folder", "Put PuTTY, VNC … here", StartAct::Tools, Color32::from_rgb(120, 130, 145)),
                    ("Settings", "Paths, SSH, KeePass", StartAct::Settings, Color32::from_rgb(96, 125, 139)),
                    ("Import", "mRemoteNG · ~/.ssh/config", StartAct::Import, Color32::from_rgb(96, 125, 139)),
                ];
                for (title, sub, act, color) in cards {
                    if card(ui, tr(title), tr(sub), color).clicked() {
                        acts.push(act);
                    }
                }
            });

            ui.add_space(16.0);
            ui.columns(2, |cols| {
                let ui = &mut cols[0];
                ui.label(RichText::new(tr("Connections by protocol")).strong().size(15.0));
                ui.add_space(4.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let mut any = false;
                    for p in Protocol::ALL {
                        let n = self.store.data.entries.iter().filter(|e| !e.folder && e.protocol == p).count();
                        if n == 0 {
                            continue;
                        }
                        any = true;
                        ui.horizontal(|ui| {
                            badge(ui, p);
                            ui.label(p.label());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(n.to_string()).strong());
                            });
                        });
                    }
                    if !any {
                        ui.weak(tr("No connections yet."));
                    }
                });
                ui.add_space(10.0);
                ui.label(RichText::new(tr("Recent")).strong().size(15.0));
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if self.log.is_empty() {
                        ui.weak(tr("Nothing opened yet. Double-click a connection on the left."));
                    }
                    for line in self.log.iter().rev().take(8) {
                        ui.label(line);
                    }
                });

                let ui = &mut cols[1];
                ui.label(RichText::new(tr("System check – programs on this computer")).strong().size(15.0));
                ui.add_space(4.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new(tr("syscheck")).num_columns(3).spacing([12.0, 5.0]).show(ui, |ui| {
                        for (what, prog, ok) in &self.system_check {
                            let (r, _) = ui.allocate_exact_size(Vec2::new(10.0, 14.0), Sense::hover());
                            ui.painter().circle_filled(r.center(), 5.0, if *ok { OK_GREEN } else { WARN });
                            ui.label(tr(what));
                            if *ok {
                                ui.label(RichText::new(prog).weak());
                            } else {
                                ui.label(RichText::new(tr("missing")).color(WARN)).on_hover_text(tf("Install or put into the programs folder: {0}", &[&prog]));
                            }
                            ui.end_row();
                        }
                    });
                    if ui.link(tr("Open programs folder")).clicked() {
                        acts.push(StartAct::Tools);
                    }
                });
                ui.add_space(10.0);
                ui.label(RichText::new(tr("Tips")).strong().size(15.0));
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(tr("• Double-click opens a connection, right-click shows all actions."));
                    ui.label(tr("• Drag connections and folders: top/bottom = order, middle of a folder = into it."));
                    ui.label(tr("• SSH, Telnet, PowerShell in the terminal tab; RDP and PuTTY as a window in the tab."));
                    ui.label(tr("• Jump host: choose another SSH server as jump server on a connection."));
                    ui.label(tr("• Passwords: in AdminCraft, from KeePass or asked every time."));
                    ui.label(tr("• The folders \"AdminCraftData\" and \"AdminCraftTools\" sit next to the program – copy them along."));
                });
            });
        });
    }

    // ------------------------------------------------------------ dialogs

    fn dialogs(&mut self, ctx: &egui::Context, now: f64) {
        if let Some(id) = self.confirm_delete {
            let name = self.store.get(id).map(|e| e.name.clone()).unwrap_or_default();
            let is_folder = self.store.get(id).map(|e| e.folder).unwrap_or(false);
            let resp = egui::Modal::new(egui::Id::new(tr("confirm_delete"))).show(ctx, |ui| {
                ui.set_width(360.0);
                ui.heading(tr("Really delete?"));
                ui.add_space(6.0);
                ui.label(if is_folder {
                    tf("The folder \"{0}\" and everything in it will be deleted.", &[&name])
                } else {
                    tf("The connection \"{0}\" will be deleted.", &[&name])
                });
                ui.add_space(10.0);
                let mut result = None;
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new(tr("Delete")).color(Color32::WHITE)).fill(BAD_RED)).clicked() {
                        result = Some(true);
                    }
                    if ui.button(tr("Cancel")).clicked() {
                        result = Some(false);
                    }
                });
                result
            });
            match resp.inner {
                Some(true) => {
                    self.store.remove(id);
                    if self.selected.map(|s| self.store.get(s).is_none()).unwrap_or(false) {
                        self.selected = None;
                    }
                    self.confirm_delete = None;
                    self.mark_dirty(now);
                }
                Some(false) => self.confirm_delete = None,
                None => {
                    if resp.should_close() {
                        self.confirm_delete = None;
                    }
                }
            }
        }

        if self.show_settings {
            self.show_settings = false;
            self.open_settings();
        }

        if let Some((id, mut pw, msg)) = self.kp_save.take() {
            let mut keep = true;
            let mut save = false;
            let name = self.store.get(id).map(|e| e.name.clone()).unwrap_or_default();
            egui::Modal::new(egui::Id::new("kp_save")).show(ctx, |ui| {
                ui.set_width(380.0);
                ui.heading(tr("Save password in KeePass"));
                ui.label(tf("Entry \"{0}\" in the group \"AdminCraft\" (made or updated):", &[&name]));
                let r = ui.add(egui::TextEdit::singleline(&mut pw).password(true).hint_text(tr("Password")).desired_width(f32::INFINITY));
                r.request_focus();
                if let Some(m) = &msg {
                    ui.colored_label(BAD_RED, m);
                }
                let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new(tr("Save")).color(Color32::WHITE)).fill(ACCENT)).clicked() || enter {
                        save = true;
                    }
                    if ui.button(tr("Cancel")).clicked() {
                        keep = false;
                    }
                });
            });
            let mut msg = msg;
            if save {
                let (user, _, _) = self.store.credentials(id);
                let url = self.store.get(id).map(crate::kdbx::url_of).unwrap_or_default();
                let s = self.store.data.settings.clone();
                match self.keepass.key.clone().ok_or_else(|| tr("Unlock KeePass first").to_string()).and_then(|k| crate::kdbx::store_password(&s.keepass_path, &k, &name, &user, &pw, &url).map(|p| (k, p))) {
                    Ok((k, path)) => {
                        if let Some(i) = self.store.index_of(id) {
                            self.store.data.entries[i].keepass_entry = path.clone();
                            self.store.data.entries[i].cred_source = CredSource::KeePass;
                        }
                        let _ = self.keepass.open(&s.keepass_path, &k.password, &k.keyfile);
                        self.mark_dirty(now);
                        self.note(tf("Password saved in KeePass: {0}", &[&path]), false, now);
                        keep = false;
                    }
                    Err(e) => msg = Some(e),
                }
            }
            if keep {
                self.kp_save = Some((id, pw, msg));
            }
        }
        if self.kp_dialog {
            let mut close = false;
            let mut unlock = false;
            egui::Modal::new(egui::Id::new(tr("kp_unlock"))).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.heading(tr("Unlock KeePass"));
                ui.add_space(4.0);
                if self.store.data.settings.keepass_path.trim().is_empty() {
                    ui.label(tr("No KeePass file set yet. Path to the .kdbx file:"));
                } else {
                    ui.label(tr("Database:"));
                }
                ui.add(egui::TextEdit::singleline(&mut self.store.data.settings.keepass_path).hint_text(r"D:\Vault\Passwords.kdbx").desired_width(f32::INFINITY));
                ui.label(tr("Key file (optional):"));
                ui.add(egui::TextEdit::singleline(&mut self.store.data.settings.keepass_keyfile).desired_width(f32::INFINITY));
                ui.label(tr("Master password of the KeePass database:"));
                let r = ui.add(egui::TextEdit::singleline(&mut self.kp_pw).password(true).desired_width(f32::INFINITY));
                if !r.has_focus() && self.kp_pw.is_empty() {
                    r.request_focus();
                }
                let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                if let Some((ok, m)) = &self.kp_msg {
                    ui.label(RichText::new(m).color(if *ok { OK_GREEN } else { BAD_RED }));
                }
                ui.weak(tr("The master password is only kept while AdminCraft runs (to save passwords into KeePass when you ask), never on disk."));
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(RichText::new(tr("Unlock")).color(Color32::WHITE)).fill(ACCENT)).clicked() || enter {
                        unlock = true;
                    }
                    if ui.button(tr("Cancel")).clicked() {
                        close = true;
                    }
                });
            });
            if unlock {
                let pw = std::mem::take(&mut self.kp_pw);
                let s = &self.store.data.settings;
                match self.keepass.open(&s.keepass_path, &pw, &s.keepass_keyfile) {
                    Ok(n) => {
                        self.kp_dialog = false;
                        self.mark_dirty(now);
                        self.note(tf("KeePass unlocked: {0} entries.", &[&n]), false, now);
                        self.run_kp_pending(ctx, now);
                    }
                    Err(e) => self.kp_msg = Some((false, e)),
                }
            }
            if close {
                self.kp_dialog = false;
                self.kp_pending.clear();
            }
        }

        if self.ask.is_some() {
            let mut result: Option<bool> = None;
            if let Some(a) = &mut self.ask {
                egui::Modal::new(egui::Id::new(tr("ask_pw"))).show(ctx, |ui| {
                    ui.set_width(380.0);
                    ui.heading(tr("Login"));
                    ui.label(tf("Password for \"{0}\"", &[&a.name]));
                    egui::Grid::new(tr("ask_grid")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                        ui.label(tr("User"));
                        if a.key == 0 {
                            ui.add(egui::TextEdit::singleline(&mut a.user).desired_width(240.0));
                        } else {
                            ui.label(if a.user.is_empty() { tr("(none)").to_string() } else { a.user.clone() });
                        }
                        ui.end_row();
                        ui.label(tr("Password"));
                        let r = ui.add(egui::TextEdit::singleline(&mut a.pw).password(true).desired_width(240.0));
                        if a.focus {
                            r.request_focus();
                            a.focus = false;
                        }
                        ui.end_row();
                    });
                    ui.weak(tr("Leave empty for SSH key login. Remembered until AdminCraft closes."));
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(RichText::new(tr("Connect")).color(Color32::WHITE)).fill(ACCENT)).clicked() || enter {
                            result = Some(true);
                        }
                        if ui.button(tr("Cancel")).clicked() {
                            result = Some(false);
                        }
                    });
                });
            }
            match result {
                Some(true) => {
                    let a = self.ask.take().unwrap();
                    if a.key == 0 {
                        let c = Creds { user: a.user.clone(), domain: String::new(), password: a.pw.clone() };
                        let mut e = a.pending.entry.clone();
                        e.username = a.user;
                        self.start_resolved(e, c, Vec::new(), a.pending.how, ctx, now);
                    } else {
                        self.session_pw.insert(a.key, a.pw);
                        self.start(a.pending.entry.id, a.pending.how, ctx, now);
                    }
                }
                Some(false) => self.ask = None,
                None => {}
            }
        }

        self.export_dialog(ctx, now);
        self.ximport_dialog(ctx, now);
        if self.show_ssh_import {
            let mut open = true;
            egui::Window::new(tr("Import OpenSSH configuration")).open(&mut open).default_width(480.0).show(ctx, |ui| {
                ui.label(tr("Takes the hosts from the OpenSSH configuration (Host, HostName, User, Port, IdentityFile, ProxyJump)."));
                ui.add(egui::TextEdit::singleline(&mut self.ssh_import_path).desired_width(f32::INFINITY));
                if ui.button(tr("Import")).clicked() {
                    let path = self.ssh_import_path.trim().trim_matches('"').to_string();
                    self.ssh_import_msg = Some(match std::fs::read_to_string(&path) {
                        Err(e) => (false, tf("File not readable: {0}", &[&e])),
                        Ok(text) => {
                            let folder_id = self.store.next_id();
                            let entries = crate::import::import_ssh_config(&text, folder_id + 1, Some(folder_id));
                            if entries.is_empty() {
                                (false, tr("No hosts found.").into())
                            } else {
                                let n = entries.len();
                                let max = entries.iter().map(|e| e.id).max().unwrap_or(folder_id);
                                self.store.data.entries.push(Entry {
                                    id: folder_id,
                                    folder: true,
                                    name: tr("OpenSSH (~/.ssh/config)").into(),
                                    inherit_credentials: false,
                                    ..Default::default()
                                });
                                self.store.data.entries.extend(entries);
                                self.store.data.next_id = max + 1;
                                self.selected = Some(folder_id);
                                self.mark_dirty(now);
                                (true, tf("{0} hosts imported.", &[&n]))
                            }
                        }
                    });
                }
                if let Some((ok, msg)) = &self.ssh_import_msg {
                    ui.label(RichText::new(msg).color(if *ok { OK_GREEN } else { BAD_RED }));
                }
            });
            self.show_ssh_import = open;
        }

        if self.show_import {
            let mut open = true;
            egui::Window::new(tr("Import mRemoteNG file")).open(&mut open).default_width(480.0).show(ctx, |ui| {
                ui.label(tr("Path to confCons.xml (in mRemoteNG: File » Export, or %APPDATA%\\mRemoteNG\\confCons.xml):"));
                ui.add(egui::TextEdit::singleline(&mut self.import_path).desired_width(f32::INFINITY).hint_text(r"C:\Users\...\confCons.xml"));
                ui.label(tr("Password of the file (leave empty if none was set in mRemoteNG):"));
                ui.add(egui::TextEdit::singleline(&mut self.import_pw).password(true).desired_width(f32::INFINITY));
                ui.add_space(6.0);
                if ui.button(tr("Import")).clicked() {
                    let path = self.import_path.trim().trim_matches('"').to_string();
                    self.import_msg = Some(match std::fs::read_to_string(&path) {
                        Err(e) => (false, tf("File not readable: {0}", &[&e])),
                        Ok(xml) => {
                            let folder_id = self.store.next_id();
                            let first = folder_id + 1;
                            match crate::import::import_mremoteng(&xml, &self.import_pw, first, Some(folder_id)) {
                                Err(e) => (false, e),
                                Ok(imp) => {
                                    let n = imp.entries.iter().filter(|e| !e.folder).count();
                                    let max = imp.entries.iter().map(|e| e.id).max().unwrap_or(first);
                                    self.store.data.entries.push(Entry {
                                        id: folder_id,
                                        folder: true,
                                        name: tr("Import mRemoteNG").into(),
                                        inherit_credentials: false,
                                        ..Default::default()
                                    });
                                    self.store.data.entries.extend(imp.entries);
                                    self.store.data.next_id = max + 1;
                                    self.selected = Some(folder_id);
                                    self.mark_dirty(now);
                                    let mut msg = tf("{0} connections imported.", &[&n]);
                                    if imp.passwords_ok > 0 {
                                        msg.push_str(&tf(" {0} passwords taken over.", &[&imp.passwords_ok]));
                                    }
                                    if imp.passwords_failed > 0 {
                                        msg.push_str(&tf(" {0} passwords could not be decrypted.", &[&imp.passwords_failed]));
                                    }
                                    (true, msg)
                                }
                            }
                        }
                    });
                }
                if let Some((ok, msg)) = &self.import_msg {
                    ui.label(RichText::new(msg).color(if *ok { OK_GREEN } else { BAD_RED }));
                }
            });
            self.show_import = open;
        }

        if self.show_about {
            let mut open = true;
            egui::Window::new(tr("About AdminCraft")).open(&mut open).resizable(false).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    logo(ui, 36.0);
                    ui.label(RichText::new(format!("AdminCraft v{}", env!("CARGO_PKG_VERSION"))).size(20.0).strong());
                });
                ui.label(tr("Portable connection manager for Windows, Linux and macOS."));
                ui.label(tr("SSH · SFTP · Telnet · PowerShell in tabs, RDP · VNC · web through the system's programs."));
                ui.label(tr("Tools: ping, traceroute, port scan, DNS, Wake-on-LAN, reachability."));
                ui.add_space(6.0);
                ui.weak(tf("Data: {0}", &[&(self.store.path.display())]));
            });
            self.show_about = open;
        }

        if self.store.locked() {
            egui::Modal::new(egui::Id::new(tr("unlock"))).show(ctx, |ui| {
                ui.set_width(340.0);
                ui.horizontal(|ui| {
                    logo(ui, 28.0);
                    ui.heading(tr("Unlock AdminCraft"));
                });
                ui.add_space(6.0);
                let kp = self.store.waiting_for_keepass();
                if kp {
                    ui.label(tr("The connections are kept in a KeePass database. Its master password:"));
                    ui.weak(self.store.data.settings.keepass_path.clone());
                } else {
                    ui.label(tr("The connections are protected by a master password."));
                }
                let hint = if kp { tr("KeePass master password") } else { tr("Master password") };
                let r = ui.add(egui::TextEdit::singleline(&mut self.unlock_pw).password(true).hint_text(hint).desired_width(f32::INFINITY));
                r.request_focus();
                let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                if self.unlock_failed {
                    let why = if kp { self.store.last_error.clone().unwrap_or_else(|| tr("Wrong password.").into()) } else { tr("Wrong password.").into() };
                    ui.label(RichText::new(why).color(BAD_RED));
                }
                ui.horizontal(|ui| {
                    if ui.button(tr("Unlock")).clicked() || enter {
                        let pw = std::mem::take(&mut self.unlock_pw);
                        self.unlock_failed = !self.store.unlock(&pw);
                        if !self.unlock_failed {
                            // a fully encrypted list brings its settings only now
                            crate::i18n::set_language(&self.store.data.settings.language);
                            self.applied_dark = None;
                        }
                    }
                    if ui.button(tr("Quit")).clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if kp
                        && ui
                            .button(tr("Without KeePass"))
                            .on_hover_text(tr("Uses AdminCraft's own list again (it starts empty). The KeePass database stays as it is."))
                            .clicked()
                    {
                        self.store.stop_using_keepass();
                    }
                });
            });
        }
    }

    fn settings_ui(&mut self, ui: &mut egui::Ui, now: f64) {
        let mut changed = false;
        section_help(ui, tr("Language"), crate::help::Topic::Languages, &mut self.help_request);
        let langs = crate::i18n::available();
        let sys = crate::i18n::system_code();
        let shown = if self.store.data.settings.language.is_empty() {
            tf("System language ({0})", &[&crate::i18n::current()])
        } else {
            langs.iter().find(|l| l.code == self.store.data.settings.language).map(|l| l.name.clone()).unwrap_or_else(|| self.store.data.settings.language.clone())
        };
        ui.horizontal(|ui| {
            let mut pick: Option<String> = None;
            egui::ComboBox::from_id_salt("lang").selected_text(shown).width(220.0).show_ui(ui, |ui| {
                if ui.selectable_label(self.store.data.settings.language.is_empty(), tf("System language ({0})", &[&sys])).clicked() {
                    pick = Some(String::new());
                }
                for l in &langs {
                    if ui.selectable_label(self.store.data.settings.language == l.code, format!("{} ({})", l.name, l.code)).on_hover_text(if l.source == "built in" { tr("built in") } else { l.source.as_str() }).clicked() {
                        pick = Some(l.code.clone());
                    }
                }
            });
            if let Some(code) = pick {
                self.store.data.settings.language = code.clone();
                crate::i18n::set_language(&code);
                changed = true;
            }
            if ui.button(tr("Open language folder")).on_hover_text(tr("Put your own language files (.lang) here")).clicked() {
                launch::open_folder(&crate::i18n::ensure_lang_dir());
            }
        });
        ui.weak(tr("More languages: copy de.lang.example in the language folder to xx.lang and translate the right side."));

        section(ui, tr("Updates"));
        ui.horizontal(|ui| {
            ui.label(tf("This is AdminCraft {0}.", &[&env!("CARGO_PKG_VERSION")]));
            let busy = self.update_result.as_ref().is_some_and(|r| r.lock().map(|g| g.is_none()).unwrap_or(false));
            if ui.add_enabled(!busy, egui::Button::new(tr("Check for updates"))).on_hover_text(tr("Asks GitHub for the newest release. Nothing is downloaded by itself.")).clicked() {
                let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
                let s2 = slot.clone();
                let pre = self.store.data.settings.update_include_pre;
                let ctx = ui.ctx().clone();
                std::thread::spawn(move || {
                    let r = crate::update::check(pre);
                    if let Ok(mut g) = s2.lock() {
                        *g = Some(r);
                    }
                    ctx.request_repaint();
                });
                self.update_result = Some(slot);
            }
            if busy {
                ui.spinner();
            }
        });
        changed |= ui.checkbox(&mut self.store.data.settings.update_include_pre, tr("Also offer test versions (alpha, beta)")).changed();
        let outcome = self.update_result.as_ref().and_then(|r| r.lock().ok().and_then(|g| g.clone()));
        match outcome {
            Some(Ok(o)) => {
                ui.horizontal(|ui| {
                    let newer = matches!(o, crate::update::Outcome::Newer(_));
                    let text = RichText::new(crate::update::describe(&o));
                    ui.label(if newer { text.color(OK_GREEN).strong() } else { text });
                    if let crate::update::Outcome::Newer(r) = &o {
                        if ui.button(tr("Open download page")).clicked() {
                            let _ = launch::open_url(if r.url.is_empty() { &self.releases_url } else { &r.url });
                        }
                    }
                });
            }
            Some(Err(e)) => {
                ui.colored_label(Color32::from_rgb(229, 115, 115), e);
            }
            None => {}
        }

        section_help(ui, tr("AI agents"), crate::help::Topic::Agents, &mut self.help_request);
        changed |= ui
            .checkbox(&mut self.store.data.settings.agent_control, tr("AI agents and scripts on this computer may control this window"))
            .on_hover_text(tr("Only programs on this computer that can read the data folder. Passwords are never given out."))
            .changed();
        ui.add_enabled_ui(self.store.data.settings.agent_control, |ui| {
            changed |= ui.checkbox(&mut self.store.data.settings.agent_typing, tr("… and may type into terminal tabs")).changed();
            if self.store.data.settings.agent_typing {
                ui.colored_label(Color32::from_rgb(255, 183, 77), tr("Careful: an agent can then run commands on your servers. Every typing is shown in the window."));
            }
        });
        ui.horizontal(|ui| {
            ui.weak(tr("Connect an agent:"));
            ui.monospace("admincraft mcp");
            ui.weak(tr("or"));
            ui.monospace("admincraft cli window tabs");
        });
        ui.collapsing(tr("What agents can do"), |ui| {
            for (cmd, what) in crate::control::COMMANDS {
                ui.horizontal(|ui| {
                    ui.monospace(*cmd);
                    ui.weak(*what);
                });
            }
        });

        section(ui, tr("Appearance"));
        ui.horizontal(|ui| {
            changed |= ui.radio_value(&mut self.store.data.settings.dark, true, tr("Dark")).changed();
            changed |= ui.radio_value(&mut self.store.data.settings.dark, false, tr("Light")).changed();
        });
        changed |= ui
            .add(egui::Slider::new(&mut self.store.data.settings.terminal_font_size, 10.0..=24.0).text(tr("Terminal font size")))
            .changed();
        changed |= ui
            .checkbox(&mut self.store.data.settings.auto_password, tr("Type the stored password in the terminal automatically (SSH/Telnet)"))
            .changed();

        section_help(ui, tr("SSH, remote desktop and files"), crate::help::Topic::Protocols, &mut self.help_request);
        egui::Grid::new(tr("ssh_defaults")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            ui.label(tr("Open SSH with"));
            let cur = self.store.data.settings.default_ssh_client;
            egui::ComboBox::from_id_salt("def_client").selected_text(cur.label()).width(300.0).show_ui(ui, |ui| {
                for c in [SshClient::Builtin, SshClient::Putty, SshClient::External] {
                    changed |= ui.selectable_value(&mut self.store.data.settings.default_ssh_client, c, c.label()).changed();
                }
            });
            ui.end_row();
            ui.label(tr("File transfer with"));
            let t = self.store.data.settings.transfer_tool;
            let tl = |t: TransferTool| match t {
                TransferTool::Auto => tr("Automatic (OpenSSH, else PuTTY)"),
                TransferTool::OpenSsh => "OpenSSH (sftp / scp)",
                TransferTool::Putty => "PuTTY (psftp / pscp)",
            };
            egui::ComboBox::from_id_salt("xfer_tool").selected_text(tl(t)).width(300.0).show_ui(ui, |ui| {
                for x in [TransferTool::Auto, TransferTool::OpenSsh, TransferTool::Putty] {
                    changed |= ui.selectable_value(&mut self.store.data.settings.transfer_tool, x, tl(x)).changed();
                }
            });
            ui.end_row();
        });
        changed |= ui
            .add_enabled(
                embed::SUPPORTED,
                egui::Checkbox::new(&mut self.store.data.settings.embed_windows, tr("Embed RDP, PuTTY and VNC windows in the tab")),
            )
            .on_disabled_hover_text(tr("Only possible on Windows – on Linux/macOS they run in their own windows, the tab shows the status."))
            .changed();
        changed |= ui.checkbox(&mut self.store.data.settings.show_hidden, tr("Show hidden files (.name) in the file transfer")).changed();

        section_help(ui, tr("Programs"), crate::help::Topic::Settings, &mut self.help_request);
        ui.label(tr("AdminCraft looks for each program here: 1. own path below, 2. programs folder next to AdminCraft, 3. system."));
        ui.horizontal(|ui| {
            if ui.button(tr("Open programs folder")).clicked() {
                launch::open_folder(&programs::ensure_tools_dir());
            }
            ui.weak(programs::tools_dir().display().to_string());
        });
        ui.add_space(4.0);
        let mut recheck = false;
        egui::Grid::new(tr("progs")).num_columns(4).striped(true).spacing([10.0, 4.0]).show(ui, |ui| {
            ui.label(RichText::new(tr("Program")).strong());
            ui.label(RichText::new(tr("For")).strong());
            ui.label(RichText::new(tr("Found")).strong());
            ui.label(RichText::new(tr("Own path (optional)")).strong());
            ui.end_row();
            for p in programs::PROGRAMS {
                ui.label(tr(p.label));
                ui.weak(tr(p.purpose));
                match self.prog_cache.get(p.key).cloned().flatten() {
                    Some((path, src)) => {
                        ui.label(RichText::new(format!("OK · {}", src.label())).color(OK_GREEN)).on_hover_text(path.display().to_string());
                    }
                    None => {
                        ui.label(RichText::new(tr("missing")).color(WARN));
                    }
                }
                let entry = self.store.data.settings.programs.entry(p.key.to_string()).or_default();
                let r = ui.add(egui::TextEdit::singleline(entry).hint_text(format!("{}{}", p.names[0], if cfg!(windows) { ".exe" } else { "" })).desired_width(260.0));
                if r.changed() {
                    changed = true;
                }
                if r.lost_focus() {
                    recheck = true;
                }
                ui.end_row();
            }
        });
        self.store.data.settings.programs.retain(|_, v| !v.trim().is_empty());
        if ui.button(tr("Search again")).on_hover_text(tr("After programs were put into the folder")).clicked() {
            recheck = true;
        }
        if recheck {
            self.refresh_programs();
        }

        section_help(ui, tr("Password vault: KeePass"), crate::help::Topic::Passwords, &mut self.help_request);
        ui.label(tr("Connections can take their password from a KeePass/KeePassXC database (.kdbx): choose \"Password from » KeePass\" on a connection."));
        egui::Grid::new(tr("kp")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            ui.label(tr("Database (.kdbx)"));
            changed |= ui
                .add(egui::TextEdit::singleline(&mut self.store.data.settings.keepass_path).hint_text(r"D:\Vault\Passwords.kdbx").desired_width(380.0))
                .changed();
            ui.end_row();
            ui.label(tr("Key file"));
            changed |= ui
                .add(egui::TextEdit::singleline(&mut self.store.data.settings.keepass_keyfile).hint_text(tr("optional")).desired_width(380.0))
                .changed();
            ui.end_row();
        });
        ui.horizontal(|ui| {
            if self.keepass.unlocked {
                ui.label(RichText::new(tf("Unlocked – {0} entries", &[&(self.keepass.entries.len())])).color(OK_GREEN));
                if ui.button(tr("Lock")).clicked() {
                    self.keepass.lock();
                }
            } else {
                ui.label(RichText::new(tr("Locked")).color(WARN));
                if ui.button(tr("Unlock …")).clicked() {
                    self.kp_dialog = true;
                    self.kp_msg = None;
                }
            }
        });
        ui.add_space(4.0);
        if self.store.kdbx_mode() {
            ui.label(RichText::new(tr("The connection list is kept in this KeePass database (group \"AdminCraft\").")).color(OK_GREEN));
            ui.weak(tr("Every connection is a KeePass entry: title, user, password, URL and notes can also be changed in KeePass or KeePassXC; AdminCraft reloads them."));
            if ui.button(tr("Back to AdminCraft's own list")).on_hover_text(tr("The connections are copied into AdminCraft's file; the KeePass database stays as it is.")).clicked() {
                self.store.stop_using_keepass();
                self.note(tr("Connections are kept in AdminCraft's own list again."), false, now);
            }
        } else {
            ui.horizontal(|ui| {
                let can = self.keepass.unlocked && self.keepass.key.is_some() && !self.store.data.settings.keepass_path.trim().is_empty();
                if ui
                    .add_enabled(can, egui::Button::new(tr("Keep the connection list in KeePass")))
                    .on_hover_text(tr("Connections become KeePass entries in the group \"AdminCraft\": one place for all passwords, editable in KeePass too."))
                    .on_disabled_hover_text(tr("Set the database and unlock it first."))
                    .clicked()
                {
                    if let Some(key) = self.keepass.key.clone() {
                        match self.store.use_keepass(key) {
                            Ok(msg) => {
                                self.note(msg, false, now);
                                self.selected = None;
                            }
                            Err(e) => self.note(e, true, now),
                        }
                    }
                }
                ui.weak(tr("(the database must be unlocked)"));
            });
        }

        section(ui, tr("Sessions and monitoring"));
        ui.horizontal(|ui| {
            changed |= ui
                .checkbox(&mut self.store.data.settings.record_sessions, tr("Record terminal sessions for playback"))
                .on_hover_text(tr("SSH, Telnet, PowerShell and shell tabs are recorded with their timing and can be played back like a video."))
                .changed();
            if ui.small_button(tr("Recordings")).clicked() {
                self.open_recordings(None);
            }
        });
        changed |= ui.checkbox(&mut self.store.data.settings.restore_session, tr("Reopen the last open connections at start")).changed();
        ui.horizontal(|ui| {
            changed |= ui.checkbox(&mut self.store.data.settings.session_log, tr("Write terminal sessions to text files")).changed();
            if ui.small_button(tr("Open folder")).clicked() {
                let d = crate::model::data_dir(true).join("logs");
                let _ = std::fs::create_dir_all(&d);
                launch::open_folder(&d);
            }
        });
        ui.horizontal(|ui| {
            ui.label(tr("Check all hosts every"));
            changed |= ui.add(egui::DragValue::new(&mut self.store.data.settings.monitor_minutes).range(0..=1440).suffix(" min")).changed();
            ui.weak(tr("(0 = off; reports when a server goes down or comes back)"));
        });

        section(ui, tr("Saved commands"));
        ui.weak(tr("In the terminal tab under \"Commands\". Placeholders: {host} {user} {name}"));
        let mut del = None;
        egui::Grid::new("snippets").num_columns(3).spacing([8.0, 4.0]).show(ui, |ui| {
            for (i, sn) in self.store.data.settings.snippets.iter_mut().enumerate() {
                changed |= ui.add(egui::TextEdit::singleline(&mut sn.name).desired_width(170.0).hint_text(tr("Name"))).changed();
                changed |= ui.add(egui::TextEdit::singleline(&mut sn.command).desired_width(380.0).font(egui::TextStyle::Monospace)).changed();
                if ui.small_button("×").clicked() {
                    del = Some(i);
                }
                ui.end_row();
            }
        });
        if let Some(i) = del {
            self.store.data.settings.snippets.remove(i);
            changed = true;
        }
        if ui.button(tr("+ Command")).clicked() {
            self.store.data.settings.snippets.push(crate::model::Snippet { name: tr("New command").into(), command: String::new() });
            changed = true;
        }

        section_help(ui, tr("Where the connection list is stored"), crate::help::Topic::Sharing, &mut self.help_request);
        ui.label(tr("Store it centrally so the team (or you on several PCs) uses the same list. Changes by others are reloaded automatically."));
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.storage_kind, 0, tr("On this PC"));
            ui.radio_value(&mut self.storage_kind, 1, tr("Network folder (SMB)"));
            ui.radio_value(&mut self.storage_kind, 2, tr("WebDAV server"));
        });
        match self.storage_kind {
            1 => {
                ui.horizontal(|ui| {
                    ui.label(tr("Folder"));
                    ui.add(egui::TextEdit::singleline(&mut self.shared_edit).desired_width(380.0).hint_text(r"\\server\it\AdminCraft"));
                });
            }
            2 => {
                egui::Grid::new("dav").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label(tr("Address"));
                    ui.add(egui::TextEdit::singleline(&mut self.dav_url).desired_width(420.0).hint_text("https://cloud.firma.de/remote.php/dav/files/admin/AdminCraft/"));
                    ui.end_row();
                    ui.label(tr("User"));
                    ui.add(egui::TextEdit::singleline(&mut self.dav_user).desired_width(220.0));
                    ui.end_row();
                    ui.label(tr("Password"));
                    ui.add(egui::TextEdit::singleline(&mut self.dav_pw).password(true).desired_width(220.0));
                    ui.end_row();
                });
                ui.weak(tr("Nextcloud/ownCloud: best create an app password. If the address ends with \"/\", connections.json inside it is used."));
                if ui.button(tr("Test connection")).clicked() {
                    let mut c = crate::remote::RemoteConfig { url: self.dav_url.clone(), user: self.dav_user.clone(), password_enc: String::new() };
                    c.set_password(&self.dav_pw);
                    self.dav_msg = Some(match crate::remote::test(&c) {
                        Ok(m) => (true, m),
                        Err(e) => (false, e),
                    });
                }
            }
            _ => {}
        }
        if ui.button(tr("Apply")).clicked() {
            self.store.save();
            let result = match self.storage_kind {
                1 => crate::model::set_shared_location(&self.shared_edit, &self.store.path).and_then(|_| crate::remote::save_config(&Default::default())),
                2 => {
                    let mut c = crate::remote::RemoteConfig { url: self.dav_url.trim().to_string(), user: self.dav_user.clone(), password_enc: String::new() };
                    c.set_password(&self.dav_pw);
                    // first time: put the current list on the server unless one is there already
                    match crate::remote::fetch(&c) {
                        Ok(None) => std::fs::read_to_string(&self.store.path).map_err(|e| e.to_string()).and_then(|t| crate::remote::upload(&c, &t)),
                        Ok(Some(_)) => Ok(()),
                        Err(e) => Err(e),
                    }
                    .and_then(|_| crate::model::set_shared_location("", &self.store.path))
                    .and_then(|_| crate::remote::save_config(&c))
                }
                _ => crate::model::set_shared_location("", &self.store.path).and_then(|_| crate::remote::save_config(&Default::default())),
            };
            self.dav_msg = Some(match result {
                Ok(()) => (true, tr("Saved – please restart AdminCraft.").to_string()),
                Err(e) => (false, e),
            });
        }
        if let Some((ok, m)) = &self.dav_msg {
            ui.label(RichText::new(m).color(if *ok { OK_GREEN } else { BAD_RED }));
        }
        let can_seal = self.store.data.master;
        changed |= ui
            .add_enabled(can_seal, egui::Checkbox::new(&mut self.store.data.settings.encrypt_file, tr("Encrypt the whole list with the master password (names, hosts, notes too)")))
            .on_disabled_hover_text(tr("Set a master password below first."))
            .changed();
        ui.weak(tr("Recommended for central storage. Everyone in the team needs the same master password; alternatively passwords via KeePass."));

        section_help(ui, tr("Master password"), crate::help::Topic::Passwords, &mut self.help_request);
        ui.label(tr(if self.store.data.master {
            "A master password is set. Without it the passwords can't be read."
        } else {
            "No master password yet: passwords are only obfuscated. Set one for real protection."
        }));
        egui::Grid::new(tr("master")).num_columns(2).show(ui, |ui| {
            ui.label(tr("New password"));
            ui.add(egui::TextEdit::singleline(&mut self.new_master).password(true));
            ui.end_row();
            ui.label(tr("Repeat"));
            ui.add(egui::TextEdit::singleline(&mut self.new_master2).password(true));
            ui.end_row();
        });
        ui.horizontal(|ui| {
            if ui.button(if self.store.data.master { "Change" } else { "Set" }).clicked() {
                if self.new_master.is_empty() {
                    self.settings_msg = Some(tr("Please enter a password.").into());
                } else if self.new_master != self.new_master2 {
                    self.settings_msg = Some(tr("The two entries differ.").into());
                } else {
                    let pw = std::mem::take(&mut self.new_master);
                    self.new_master2.clear();
                    self.store.set_master(&pw);
                    self.settings_msg = Some(tr("Master password saved.").into());
                }
            }
            if self.store.data.master && ui.button(tr("Remove")).clicked() {
                self.store.set_master("");
                self.settings_msg = Some(tr("Master password removed.").into());
            }
        });
        if let Some(m) = &self.settings_msg {
            ui.label(RichText::new(m).color(ACCENT));
        }

        section(ui, tr("Own command per protocol (for experts)"));
        ui.weak(tr("Replaces the built-in start completely. Empty = default. Placeholders: {host} {port} {user} {domain} {password} {name}"));
        egui::Grid::new(tr("templates")).num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
            for p in Protocol::ALL {
                ui.label(p.label());
                let entry = self.store.data.settings.templates.entry(p.key().to_string()).or_default();
                changed |= ui
                    .add(egui::TextEdit::singleline(entry).hint_text(tr(launch::default_hint(p))).desired_width(320.0))
                    .changed();
                ui.end_row();
            }
        });
        self.store.data.settings.templates.retain(|_, v| !v.trim().is_empty());

        section(ui, tr("Storage location"));
        ui.label(self.store.path.display().to_string());
        ui.horizontal(|ui| {
            if ui.button(tr("Open folder")).clicked() {
                if let Some(dir) = self.store.path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                    launch::open_folder(dir);
                }
            }
            if ui.button(tr("Repeat system check")).clicked() {
                self.system_check = launch::system_check(&self.store.data.settings);
            }
        });
        if changed {
            self.mark_dirty(now);
        }
    }

    /// "Screenshot": the active tab's area as a picture in the clipboard. Taken one frame
    /// after the click so the button's own highlight is gone.
    fn tab_screenshot(&mut self, ctx: &egui::Context, now: f64) {
        let ppp = ctx.pixels_per_point();
        if let Some(r) = self.shot_pending.take() {
            let px = PxRect {
                x: (r.min.x * ppp).round() as i32,
                y: (r.min.y * ppp).round() as i32,
                w: (r.width() * ppp).round() as i32,
                h: (r.height() * ppp).round() as i32,
            };
            let screen = self.parent_hwnd.and_then(|h| embed::capture(h, px));
            match screen {
                Some((w, h, rgba)) => {
                    ctx.copy_image(egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba));
                    self.note(tf("Screenshot ({0} × {1}) copied to the clipboard.", &[&w, &h]), false, now);
                }
                None => {
                    // other systems: our own drawing (outside programs' windows are separate there)
                    let slot = self.shot_wait.clone();
                    let c2 = ctx.clone();
                    ctx.request_screenshot(move |img| {
                        let part = img.region(&r, Some(c2.pixels_per_point()));
                        *slot.lock().unwrap() = Some(Arc::new(part));
                        c2.request_repaint();
                    });
                }
            }
        }
        if let Some(r) = self.shot_tab.take() {
            self.shot_pending = Some(r);
            ctx.request_repaint();
        }
        let got = self.shot_wait.lock().unwrap().take();
        if let Some(img) = got {
            let [w, h] = img.size;
            ctx.copy_image((*img).clone());
            self.note(tf("Screenshot ({0} × {1}) copied to the clipboard.", &[&w, &h]), false, now);
        }
    }

    fn screenshot_step(&mut self, ctx: &egui::Context) {
        let Some(shot) = &mut self.shot else { return };
        shot.frames += 1;
        ctx.request_repaint();
        // give outside programs (embedded windows) a few seconds to appear
        let waiting_embed = self.tabs.iter().any(|t| match &t.kind {
            TabKind::Proc(p) => p.want_embed && p.exited.is_none() && !p.embed.as_ref().map(|e| e.attached()).unwrap_or(false),
            TabKind::NetScan(n) => n.scan.as_ref().map(|s| !s.state.lock().unwrap().finished).unwrap_or(false),
            TabKind::Cert(c) => c.result.lock().unwrap().is_none(),
            _ => false,
        });
        let t = ctx.input(|i| i.time);
        if shot.frames >= 120 && !shot.requested && (!waiting_embed || t > 12.0) {
            shot.requested = true;
            let slot = shot.image.clone();
            let c2 = ctx.clone();
            ctx.request_screenshot(move |img| {
                *slot.lock().unwrap() = Some(img);
                c2.request_repaint();
            });
        }
        let got = shot.image.lock().unwrap().take();
        if let Some(img) = got {
            let [w, h] = img.size;
            let mut bytes = Vec::with_capacity(w * h * 4);
            for p in &img.pixels {
                let [r, g, b, _] = p.to_srgba_unmultiplied();
                bytes.extend_from_slice(&[r, g, b, 255]);
            }
            if let Some(dir) = shot.path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Err(e) = image::save_buffer(&shot.path, &bytes, w as u32, h as u32, image::ColorType::Rgba8) {
                eprintln!("Screenshot could not be saved: {e}");
            }
            // report the state of embedded windows next to the picture (for checks)
            let mut report = format!("parent={:?} time={:.1}\n", self.parent_hwnd, ctx.input(|i| i.time));
            for t in &self.tabs {
                if let TabKind::Proc(p) = &t.kind {
                    report.push_str(&format!(
                        "{}: attached={} exited={:?}\n",
                        t.title,
                        p.embed.as_ref().map(|e| e.attached()).unwrap_or(false),
                        p.exited
                    ));
                }
            }
            if self.tabs.iter().any(|t| matches!(t.kind, TabKind::Proc(_))) {
                let _ = std::fs::write(shot.path.with_extension("txt"), report);
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if shot.frames > 900 {
            eprintln!("No screenshot received.");
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

#[allow(dead_code)]
enum StartAct {
    NewConn,
    Import,
    Settings,
    Ping,
    Scan,
    Dns,
    Wol,
    Shell,
    Connect(u64),
    Status,
    Tools,
    Files,
    NetScan,
    Subnet,
    Cert,
    Tunnels,
    Help(Option<crate::help::Topic>),
}

impl eframe::App for AdminApp {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let now = ctx.input(|i| i.time);
        self.apply_theme(&ctx);
        self.shortcuts(&ctx, now);
        self.sync_control(&ctx);
        self.control_requests(&ctx, now);
        if self.parent_hwnd.is_none() {
            self.parent_hwnd = embed::parent_handle(frame);
            if let Some(h) = self.parent_hwnd {
                embed::install_focus_hook(h);
            }
        }

        let pending = std::mem::take(&mut self.pending_connect);
        for id in pending {
            self.connect_id(id, &ctx, now);
        }

        egui::Panel::top("menu").show(ui, |ui| self.menu_bar(ui, now));
        egui::Panel::top("toolbar")
            .frame(egui::Frame::side_top_panel(ui.style()).inner_margin(egui::Margin::symmetric(8, 6)))
            .show(ui, |ui| self.toolbar(ui, now));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui, now));
        egui::Panel::left("tree").resizable(true).default_size(300.0).size_range(200.0..=520.0).show(ui, |ui| self.tree_panel(ui, now));
        // remote desktops and file transfers get the whole width
        let wide_tab = matches!(self.tabs.get(self.active).map(|t| &t.kind), Some(TabKind::Proc(_)) | Some(TabKind::Transfer(_)) | Some(TabKind::NetScan(_)) | Some(TabKind::Tunnels) | Some(TabKind::Help(_)) | Some(TabKind::Playback(_)) | Some(TabKind::Tool(_)));
        if self.show_props && !wide_tab {
            egui::Panel::right("props").resizable(true).default_size(340.0).size_range(260.0..=560.0).show(ui, |ui| self.props_panel(ui, now));
        }
        egui::CentralPanel::default().show(ui, |ui| {
            self.tab_strip(ui);
            ui.separator();
            self.tab_content(ui, now);
        });

        self.dialogs(&ctx, now);

        // files dropped onto the window: upload into the open remote folder
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect());
        if !dropped.is_empty() {
            if let Some(TabKind::Transfer(t)) = self.tabs.get_mut(self.active).map(|t| &mut t.kind) {
                let dir = t.xfer.shared.lock().unwrap().cwd.clone();
                for p in dropped {
                    t.xfer.send(Job::Upload { local: p, remote_dir: dir.clone() });
                }
            }
        }

        // outside programs: did they end, did their window appear, where does it go?
        let overlay = egui::Popup::is_any_open(&ctx)
            || self.confirm_delete.is_some()
            || self.show_import
            || self.show_about
            || self.show_ssh_import
            || self.kp_dialog
            || self.ask.is_some()
            || self.store.locked()
            || self.tabs.iter().any(|t| matches!(&t.kind, TabKind::Transfer(x) if x.dialog.is_some()));
        let ppp = ctx.pixels_per_point();
        let active = self.active;
        let parent = self.parent_hwnd;
        let embed_rect = self.embed_rect;
        let mut active_embed = 0isize;
        for (i, tab) in self.tabs.iter_mut().enumerate() {
            let TabKind::Proc(p) = &mut tab.kind else { continue };
            if p.exited.is_none() {
                if let Some(child) = &mut p.child {
                    if let Ok(Some(status)) = child.try_wait() {
                        // mstsc hands over to an already running copy sometimes: keep the tab if its window is ours
                        if !p.embed.as_ref().map(|e| e.attached()).unwrap_or(false) {
                            p.exited = Some(if status.success() { tr("Session ended.").into() } else { tf("Program ended (code {0}).", &[&(status.code().unwrap_or(-1))]) });
                        }
                    }
                }
                if let Some(em) = &mut p.embed {
                    if em.lost() {
                        p.exited = Some(tr("Window was closed.").into());
                    }
                }
            }
            if p.want_embed && !p.detached && p.exited.is_none() {
                if let (Some(em), Some(par)) = (&mut p.embed, parent) {
                    if !em.attached() && now - p.last_try > 0.25 && now - p.started < 180.0 {
                        p.last_try = now;
                        if em.try_attach(par) {
                            em.focus();
                        }
                    }
                }
            }
            if let Some(em) = &mut p.embed {
                let rect = if i == active && !overlay && !p.detached {
                    embed_rect.map(|r| PxRect {
                        x: (r.min.x * ppp).round() as i32,
                        y: (r.min.y * ppp).round() as i32,
                        w: (r.width() * ppp).round() as i32,
                        h: (r.height() * ppp).round() as i32,
                    })
                } else {
                    None
                };
                if rect.is_some() {
                    active_embed = em.handle();
                }
                em.place(rect);
            }
        }
        embed::set_active(active_embed);
        self.tab_screenshot(&ctx, now);

        // background jobs: tunnels, monitoring, changes by colleagues, dialogs
        extra::poll_tunnels(&mut self.tunnels);
        self.monitor_step(&ctx, now);
        if self.store.remote.is_some() && now - self.last_remote_poll > 30.0 && self.shot.is_none() {
            self.last_remote_poll = now;
            self.store.poll_remote();
        }
        if now - self.last_reload_check > 5.0 && self.dirty_since.is_none() && !self.store.read_only {
            self.last_reload_check = now;
            if self.store.reload_if_changed() {
                self.note(tr("Connection list was changed elsewhere – reloaded."), false, now);
            }
        }
        if let Some((id, pw)) = extra::pwgen_window(&ctx, &mut self.pwgen) {
            if let Some(i) = self.store.index_of(id) {
                self.store.data.entries[i].password = pw;
                self.store.data.entries[i].cred_source = CredSource::Stored;
                self.mark_dirty(now);
                self.note(tr("Password applied."), false, now);
            }
        }
        self.power_dialog(&ctx, now);
        if !self.restored {
            self.restored = true;
            if self.store.data.settings.restore_session && self.shot.is_none() {
                for (id, kind) in self.store.data.last_session.clone() {
                    if self.store.get(id).is_some() {
                        if kind == "files" {
                            self.apply(Act::Files(id), &ctx, now);
                        } else {
                            self.start(id, How::Default, &ctx, now);
                        }
                    }
                }
            }
        }

        // keep terminals and tools alive while running
        let busy = self.tabs.iter().any(|t| match &t.kind {
            TabKind::Term(t) => t.term.as_ref().map(|x| x.exited.is_none()).unwrap_or(false),
            TabKind::Ping(p) => p.runner.is_running(),
            TabKind::Scan(s) => s.scan.as_ref().map(|x| !x.state.lock().unwrap().finished).unwrap_or(false),
            TabKind::Proc(p) => p.exited.is_none(),
            TabKind::Transfer(x) => x.xfer.busy(),
            TabKind::NetScan(n) => n.scan.as_ref().map(|s| !s.state.lock().unwrap().finished).unwrap_or(false),
            TabKind::Cert(c) => *c.busy.lock().unwrap(),
            _ => false,
        });
        if busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        if let Some(t) = &self.toast {
            if t.until > now {
                ctx.request_repaint_after(std::time::Duration::from_millis(500));
            }
        }

        if let Some(since) = self.dirty_since {
            if now - since > 0.8 {
                self.store.save();
                self.dirty_since = None;
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(300));
            }
        }
        self.screenshot_step(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // remember what was open (restored at the next start when switched on)
        let session: Vec<(u64, String)> = self
            .tabs
            .iter()
            .filter_map(|t| match &t.kind {
                TabKind::Term(x) if x.entry.id != 0 => Some((x.entry.id, "default".to_string())),
                TabKind::Proc(x) if x.entry.id != 0 => Some((x.entry.id, "default".to_string())),
                TabKind::Transfer(x) if x.entry.id != 0 => Some((x.entry.id, if x.entry.protocol.transfer() { "default" } else { "files" }.to_string())),
                _ => None,
            })
            .collect();
        if session != self.store.data.last_session {
            self.store.data.last_session = session;
            self.dirty_since = Some(0.0);
        }
        for r in self.tunnels.values_mut() {
            if let Some(mut c) = r.child.take() {
                let _ = c.kill();
            }
        }
        if self.dirty_since.is_some() {
            self.store.save();
        }
        for t in &mut self.tabs {
            if let TabKind::Term(t) = &mut t.kind {
                if let Some(term) = &mut t.term {
                    term.kill();
                }
            }
            if let TabKind::Proc(p) = &mut t.kind {
                if !p.detached {
                    stop_proc(p);
                }
            }
        }
    }
}

fn stop_proc(p: &mut ProcTab) {
    if let Some(em) = &mut p.embed {
        em.close();
    }
    if let Some(mut c) = p.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    p.embed = None;
}

/// A saved command with {host} {user} {name} filled in.
fn fill_snippet(cmd: &str, e: &Entry, c: &Creds) -> String {
    cmd.replace("{host}", e.host.trim()).replace("{user}", &c.user).replace("{name}", &e.name)
}

fn url_enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn short_client(c: SshClient) -> &'static str {
    match c {
        SshClient::Putty => "PuTTY",
        SshClient::External => "own window",
        _ => "terminal tab",
    }
}

fn default_ssh_config() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".ssh")
        .join("config")
}

/// Header of a tab with an outside program; returns a reconnect request.
fn proc_ui(ui: &mut egui::Ui, p: &mut ProcTab, now: f64) -> (Option<(Entry, Creds, Vec<JumpHop>)>, Rect) {
    let mut reconnect = None;
    ui.horizontal(|ui| {
        badge(ui, p.entry.protocol);
        ui.label(RichText::new(&p.label).weak());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(tr("Reconnect")).clicked() {
                reconnect = Some((p.entry.clone(), p.creds.clone(), p.jumps.clone()));
            }
            if p.exited.is_none() {
                if ui.button(RichText::new(tr("Disconnect")).color(BAD_RED)).clicked() {
                    stop_proc(p);
                    p.exited = Some(tr("Disconnected.").into());
                }
                let attached = p.embed.as_ref().map(|e| e.attached()).unwrap_or(false);
                if attached && ui.button(tr("As own window")).on_hover_text(tr("Detach the window from the tab")).clicked() {
                    if let Some(em) = &mut p.embed {
                        em.detach();
                    }
                    p.detached = true;
                }
                if attached && ui.button(tr("Focus")).on_hover_text(tr("Give the keyboard to the window")).clicked() {
                    if let Some(em) = &p.embed {
                        em.focus();
                    }
                }
            }
        });
    });
    let rect = ui.available_rect_before_wrap();
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, ui.visuals().extreme_bg_color);
    let attached = p.embed.as_ref().map(|e| e.attached()).unwrap_or(false);
    let (msg, color) = if let Some(m) = &p.exited {
        (m.clone(), WARN)
    } else if p.detached {
        (tr("Running in its own window (detached from the tab).").to_string(), ui.visuals().text_color())
    } else if attached {
        (String::new(), ui.visuals().text_color())
    } else if p.want_embed {
        let secs = (now - p.started).max(0.0) as u32;
        (
            tf("Connecting … the window will show here in the tab as soon as it appears ({0} s).\nCertificate or login questions briefly appear as their own window.", &[&secs]),
            ACCENT,
        )
    } else {
        (
            tr("Running in its own window. This tab shows the status; \"Disconnect\" ends the session.").to_string(),
            ui.visuals().text_color(),
        )
    };
    if !msg.is_empty() {
        painter.text(rect.center(), egui::Align2::CENTER_CENTER, msg, egui::FontId::proportional(15.0), color);
    }
    ui.allocate_rect(rect, Sense::hover());
    (reconnect, rect)
}

fn refresh_local(t: &mut TransferTab, show_hidden: bool) {
    match transfer::list_local(&t.local_dir, show_hidden) {
        Ok(items) => {
            t.local_items = items;
            t.local_err = None;
        }
        Err(e) => {
            t.local_items.clear();
            t.local_err = Some(e);
        }
    }
    t.local_edit = t.local_dir.display().to_string();
    t.local_sel.clear();
}

/// A clickable file row; returns (clicked, double_clicked, ctrl).
fn file_row(ui: &mut egui::Ui, selected: bool, is_dir: bool, name: &str, size: &str, date: &str) -> (bool, bool, bool) {
    let h = 22.0;
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    let painter = ui.painter_at(rect);
    if selected {
        painter.rect_filled(rect, 3.0, ui.visuals().selection.bg_fill);
    } else if resp.hovered() {
        painter.rect_filled(rect, 3.0, ui.visuals().faint_bg_color);
    }
    let text_col = if selected { Color32::WHITE } else { ui.visuals().text_color() };
    let weak = if selected { Color32::from_gray(230) } else { ui.visuals().weak_text_color() };
    // icon
    let ir = Rect::from_min_size(rect.min + Vec2::new(4.0, 3.0), Vec2::new(16.0, 16.0));
    if is_dir {
        let c = Color32::from_rgb(232, 180, 60);
        painter.rect_filled(Rect::from_min_size(ir.min + Vec2::new(1.0, 2.0), Vec2::new(6.0, 3.0)), 1.0, c);
        painter.rect_filled(Rect::from_min_size(ir.min + Vec2::new(1.0, 4.0), Vec2::new(14.0, 10.0)), 2.0, c);
    } else {
        painter.rect_stroke(Rect::from_min_size(ir.min + Vec2::new(3.0, 1.0), Vec2::new(10.0, 14.0)), 1.0, Stroke::new(1.0, weak), egui::StrokeKind::Inside);
    }
    // columns: date and size on the right when there is room
    let show_date = rect.width() > 380.0;
    let date_w = if show_date { 112.0 } else { 0.0 };
    let size_w = 72.0;
    let font = egui::FontId::proportional(13.5);
    let small = egui::FontId::proportional(12.0);
    let name_right = rect.right() - date_w - size_w - 8.0;
    let name_rect = Rect::from_min_max(Pos2::new(rect.left() + 26.0, rect.top()), Pos2::new(name_right, rect.bottom()));
    let galley = ui.fonts_mut(|f| {
        let mut job = egui::text::LayoutJob::single_section(name.to_string(), egui::TextFormat::simple(font.clone(), text_col));
        job.wrap = egui::text::TextWrapping::truncate_at_width(name_rect.width().max(20.0));
        f.layout_job(job)
    });
    painter.with_clip_rect(name_rect).galley(Pos2::new(name_rect.left(), rect.center().y - galley.size().y / 2.0), galley, text_col);
    painter.text(Pos2::new(rect.right() - date_w - 8.0, rect.center().y), egui::Align2::RIGHT_CENTER, size, small.clone(), weak);
    if show_date {
        painter.text(Pos2::new(rect.right() - 4.0, rect.center().y), egui::Align2::RIGHT_CENTER, date, small, weak);
    }
    let resp = resp.on_hover_text(name);
    let ctrl = ui.input(|i| i.modifiers.command || i.modifiers.ctrl);
    (resp.clicked(), resp.double_clicked(), ctrl)
}

fn transfer_ui(ui: &mut egui::Ui, t: &mut TransferTab, show_hidden: bool) {
    let (cwd, items, busy, queued, log, connected, local_changed) = {
        let mut s = t.xfer.shared.lock().unwrap();
        let lc = std::mem::take(&mut s.local_changed);
        (s.cwd.clone(), s.items.clone(), s.busy.clone(), s.queued, s.log.clone(), s.connected, lc)
    };
    if local_changed {
        refresh_local(t, show_hidden);
    }
    if cwd != t.shown_cwd {
        t.shown_cwd = cwd.clone();
        t.remote_edit = cwd.clone();
        t.remote_sel.clear();
    }
    let ep = &t.xfer.endpoint;
    // header
    ui.horizontal(|ui| {
        badge(ui, t.entry.protocol);
        let mut what = format!("{} {}@{}:{}", ep.kind.label(), ep.target.user, ep.target.host, ep.target.port);
        if ep.kind == Kind::Ftp && ep.tls {
            what = what.replacen("FTP", "FTPS", 1);
        }
        if !ep.jumps.is_empty() {
            what.push_str(&tf("  via {0}", &[&(ep.jumps.iter().map(|j| j.host.clone()).collect::<Vec<_>>().join(" » "))]));
        }
        ui.label(RichText::new(what).monospace().weak());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(b) = &busy {
                ui.label(RichText::new(if queued > 0 { tf("{0} (+{1} waiting)", &[&b, &queued]) } else { b.clone() }).color(ACCENT));
                ui.spinner();
            } else if connected {
                ui.label(RichText::new(tr("Connected")).color(OK_GREEN));
            }
        });
    });
    ui.add_space(2.0);

    let log_h = 96.0;
    let pane_h = (ui.available_height() - log_h - 8.0).max(160.0);
    let mut nav_local: Option<PathBuf> = None;
    let mut nav_remote: Option<String> = None;
    ui.columns(2, |cols| {
        // ---------------- local
        let ui = &mut cols[0];
        ui.set_min_height(pane_h);
        ui.horizontal(|ui| {
            ui.label(RichText::new(tr("This PC")).strong());
            if ui.small_button(tr("Up")).on_hover_text(tr("Folder up")).clicked() {
                if let Some(p) = t.local_dir.parent() {
                    nav_local = Some(p.to_path_buf());
                }
            }
            if cfg!(windows) {
                egui::ComboBox::from_id_salt("drives").selected_text(tr("Drive")).width(70.0).show_ui(ui, |ui| {
                    for d in transfer::drives() {
                        if ui.selectable_label(false, d.display().to_string()).clicked() {
                            nav_local = Some(d);
                        }
                    }
                });
            }
            let r = ui.add(egui::TextEdit::singleline(&mut t.local_edit).desired_width(f32::INFINITY));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                nav_local = Some(PathBuf::from(t.local_edit.trim()));
            }
        });
        egui::Frame::new().fill(ui.visuals().extreme_bg_color).corner_radius(4.0).inner_margin(4).show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt("local_list").max_height(pane_h - 70.0).min_scrolled_height(pane_h - 70.0).auto_shrink([false, false]).show(ui, |ui| {
                if let Some(e) = &t.local_err {
                    ui.label(RichText::new(e).color(BAD_RED));
                }
                for it in &t.local_items {
                    let sel = t.local_sel.contains(&it.name);
                    let size = if it.is_dir { String::new() } else { transfer::human_size(it.size) };
                    let (c, dc, ctrl) = file_row(ui, sel, it.is_dir, &it.name, &size, &it.modified);
                    if dc && it.is_dir {
                        nav_local = Some(it.path.clone());
                    } else if c {
                        if !ctrl {
                            t.local_sel.clear();
                        }
                        if sel && ctrl {
                            t.local_sel.remove(&it.name);
                        } else {
                            t.local_sel.insert(it.name.clone());
                        }
                    }
                }
            });
        });
        ui.horizontal_wrapped(|ui| {
            let n = t.local_sel.len();
            if ui
                .add_enabled(n > 0 && connected, egui::Button::new(RichText::new(tf("Upload » ({0})", &[&n])).color(Color32::WHITE)).fill(ACCENT))
                .on_hover_text(tr("Upload the selection into the right folder. Tip: you can also drag files into the window."))
                .clicked()
            {
                for name in &t.local_sel {
                    t.xfer.send(Job::Upload { local: t.local_dir.join(name), remote_dir: cwd.clone() });
                }
                t.local_sel.clear();
            }
            if ui.button(tr("New folder")).clicked() {
                t.dialog = Some(XferDialog::Mkdir { remote: false, name: String::new() });
            }
            if ui.add_enabled(n == 1, egui::Button::new(tr("Rename"))).clicked() {
                let from = t.local_sel.iter().next().cloned().unwrap_or_default();
                t.dialog = Some(XferDialog::Rename { remote: false, to: from.clone(), from });
            }
            if ui.add_enabled(n > 0, egui::Button::new(tr("Delete"))).clicked() {
                let names = t.local_items.iter().filter(|i| t.local_sel.contains(&i.name)).map(|i| (i.name.clone(), i.is_dir)).collect();
                t.dialog = Some(XferDialog::Delete { remote: false, names });
            }
            if ui.button(tr("Refresh")).clicked() {
                nav_local = Some(t.local_dir.clone());
            }
            if ui.button(tr("Open")).on_hover_text(tr("Open folder in the file manager")).clicked() {
                launch::open_folder(&t.local_dir);
            }
        });

        // ---------------- remote
        let ui = &mut cols[1];
        ui.set_min_height(pane_h);
        ui.horizontal(|ui| {
            ui.label(RichText::new(tf("Server ({0})", &[&ep.target.host])).strong());
            if ui.add_enabled(connected, egui::Button::new(tr("Up")).small()).on_hover_text(tr("Folder up")).clicked() {
                nav_remote = Some(transfer::parent(&cwd));
            }
            let r = ui.add(egui::TextEdit::singleline(&mut t.remote_edit).desired_width(f32::INFINITY));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                nav_remote = Some(t.remote_edit.trim().to_string());
            }
        });
        egui::Frame::new().fill(ui.visuals().extreme_bg_color).corner_radius(4.0).inner_margin(4).show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt("remote_list").max_height(pane_h - 70.0).min_scrolled_height(pane_h - 70.0).auto_shrink([false, false]).show(ui, |ui| {
                if !connected {
                    if busy.is_some() {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(tr("Connecting …"));
                        });
                    } else {
                        ui.label(RichText::new(tr("Not connected – see message below. \"Refresh\" tries again.")).color(WARN));
                    }
                }
                for it in items.iter().filter(|i| show_hidden || !i.name.starts_with('.')) {
                    let sel = t.remote_sel.contains(&it.name);
                    let size = if it.is_dir { String::new() } else { transfer::human_size(it.size) };
                    let (c, dc, ctrl) = file_row(ui, sel, it.is_dir, &it.name, &size, &it.modified);
                    if dc && (it.is_dir || it.is_link) {
                        nav_remote = Some(transfer::join(&cwd, &it.name));
                    } else if c {
                        if !ctrl {
                            t.remote_sel.clear();
                        }
                        if sel && ctrl {
                            t.remote_sel.remove(&it.name);
                        } else {
                            t.remote_sel.insert(it.name.clone());
                        }
                    }
                }
            });
        });
        ui.horizontal_wrapped(|ui| {
            let n = t.remote_sel.len();
            if ui
                .add_enabled(n > 0, egui::Button::new(RichText::new(tf("« Download ({0})", &[&n])).color(Color32::WHITE)).fill(ACCENT))
                .on_hover_text(tr("Download the selection into the left folder"))
                .clicked()
            {
                for it in items.iter().filter(|i| t.remote_sel.contains(&i.name)) {
                    t.xfer.send(Job::Download { remote: transfer::join(&cwd, &it.name), is_dir: it.is_dir, local_dir: t.local_dir.clone() });
                }
                t.remote_sel.clear();
            }
            if ui.add_enabled(connected, egui::Button::new(tr("New folder"))).clicked() {
                t.dialog = Some(XferDialog::Mkdir { remote: true, name: String::new() });
            }
            if ui.add_enabled(n == 1, egui::Button::new(tr("Rename"))).clicked() {
                let from = t.remote_sel.iter().next().cloned().unwrap_or_default();
                t.dialog = Some(XferDialog::Rename { remote: true, to: from.clone(), from });
            }
            if ui.add_enabled(n > 0, egui::Button::new(tr("Delete"))).clicked() {
                let names = items.iter().filter(|i| t.remote_sel.contains(&i.name)).map(|i| (i.name.clone(), i.is_dir && !i.is_link)).collect();
                t.dialog = Some(XferDialog::Delete { remote: true, names });
            }
            if ui.button(tr("Refresh")).on_hover_text(tr("Refresh folder / reconnect")).clicked() {
                nav_remote = Some(if connected { cwd.clone() } else { t.entry.start_path.clone() });
            }
        });
    });

    // log
    egui::Frame::new().fill(ui.visuals().extreme_bg_color).corner_radius(4.0).inner_margin(6).show(ui, |ui| {
        egui::ScrollArea::vertical().id_salt("xfer_log").max_height(log_h - 12.0).auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
            if log.is_empty() {
                ui.weak(tr("Double-click opens folders. Select several entries with Ctrl+click. Drag files from the explorer into the window = upload."));
            }
            for (ok, l) in &log {
                ui.label(RichText::new(l).small().color(if *ok { OK_GREEN } else { BAD_RED }));
            }
        });
    });

    if let Some(p) = nav_local {
        t.local_dir = p;
        refresh_local(t, show_hidden);
    }
    if let Some(p) = nav_remote {
        t.xfer.send(Job::List(p));
    }

    // small dialogs
    let mut close = false;
    if let Some(d) = &mut t.dialog {
        let ctx = ui.ctx().clone();
        egui::Modal::new(egui::Id::new(tr("xfer_dialog"))).show(&ctx, |ui| {
            ui.set_width(380.0);
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
            match d {
                XferDialog::Mkdir { remote, name } => {
                    ui.heading(tr(if *remote { "New folder on the server" } else { "New folder on this PC" }));
                    ui.add(egui::TextEdit::singleline(name).hint_text(tr("Folder name"))).request_focus();
                    ui.horizontal(|ui| {
                        if (ui.button(tr("Create")).clicked() || enter) && !name.trim().is_empty() {
                            if *remote {
                                t.xfer.send(Job::Mkdir(transfer::join(&cwd, name.trim())));
                            } else {
                                let _ = std::fs::create_dir_all(t.local_dir.join(name.trim()));
                            }
                            close = true;
                        }
                        if ui.button(tr("Cancel")).clicked() {
                            close = true;
                        }
                    });
                }
                XferDialog::Rename { remote, from, to } => {
                    ui.heading(tr("Rename"));
                    ui.label(from.as_str());
                    ui.add(egui::TextEdit::singleline(to)).request_focus();
                    ui.horizontal(|ui| {
                        if (ui.button(tr("Rename")).clicked() || enter) && !to.trim().is_empty() && to != from {
                            if *remote {
                                t.xfer.send(Job::Rename { from: transfer::join(&cwd, from), to: transfer::join(&cwd, to.trim()) });
                            } else {
                                let _ = std::fs::rename(t.local_dir.join(&*from), t.local_dir.join(to.trim()));
                            }
                            close = true;
                        }
                        if ui.button(tr("Cancel")).clicked() {
                            close = true;
                        }
                    });
                }
                XferDialog::Delete { remote, names } => {
                    ui.heading(tr("Really delete?"));
                    ui.label(tr(if *remote { "On the server:" } else { "On this PC:" }));
                    for (n, dir) in names.iter().take(8) {
                        ui.label(format!("• {n}{}", if *dir { tr("  (folder with content)") } else { "" }));
                    }
                    if names.len() > 8 {
                        ui.label(tf("… and {0} more", &[&(names.len() - 8)]));
                    }
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(RichText::new(tr("Delete")).color(Color32::WHITE)).fill(BAD_RED)).clicked() {
                            for (n, dir) in names.iter() {
                                if *remote {
                                    t.xfer.send(Job::Delete { path: transfer::join(&cwd, n), is_dir: *dir });
                                } else {
                                    let p = t.local_dir.join(n);
                                    let _ = if *dir { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
                                }
                            }
                            close = true;
                        }
                        if ui.button(tr("Cancel")).clicked() {
                            close = true;
                        }
                    });
                }
            }
        });
    }
    if close {
        let local = matches!(&t.dialog, Some(XferDialog::Mkdir { remote: false, .. }) | Some(XferDialog::Rename { remote: false, .. }) | Some(XferDialog::Delete { remote: false, .. }));
        t.dialog = None;
        if local {
            refresh_local(t, show_hidden);
        }
    }
}

// ---------------------------------------------------------------- tool tabs

fn start_ping(p: &mut PingTab, ctx: &egui::Context) {
    let host = p.host.trim().to_string();
    if host.is_empty() {
        return;
    }
    match p.mode {
        PingMode::Ping => {
            let args = tools::ping_args(&host, if p.continuous { None } else { Some(4) });
            p.runner.start("ping", &args, ctx.clone());
        }
        PingMode::Trace => {
            let (prog, args) = tools::traceroute_cmd(&host);
            p.runner.start(&prog, &args, ctx.clone());
        }
    }
}

fn ping_ui(ui: &mut egui::Ui, p: &mut PingTab, ctx: &egui::Context) {
    ui.horizontal(|ui| {
        ui.selectable_value(&mut p.mode, PingMode::Ping, tr("Ping"));
        ui.selectable_value(&mut p.mode, PingMode::Trace, tr("Traceroute"));
        ui.separator();
        ui.label(tr("Host"));
        let r = ui.add(egui::TextEdit::singleline(&mut p.host).desired_width(220.0).hint_text(tr("Name or IP")));
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if p.mode == PingMode::Ping {
            ui.checkbox(&mut p.continuous, tr("Continuous ping"));
        }
        if p.runner.is_running() {
            if ui.button(tr("Stop")).clicked() {
                p.runner.stop();
            }
        } else if ui.add(egui::Button::new(RichText::new(tr("Start")).color(Color32::WHITE)).fill(ACCENT)).clicked() || enter {
            start_ping(p, ctx);
        }
        if ui.button(tr("Copy")).clicked() {
            ui.ctx().copy_text(p.runner.text());
        }
    });
    ui.separator();
    output_box(ui, &p.runner.lines.lock().unwrap());
}

fn output_box(ui: &mut egui::Ui, lines: &[String]) {
    egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .corner_radius(4.0)
        .inner_margin(8)
        .show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                if lines.is_empty() {
                    ui.weak(tr("Enter a host and press Start."));
                }
                for l in lines {
                    let color = if l.contains("TTL=") || l.contains("ttl=") || l.contains("Antwort von") || l.contains("bytes from") {
                        OK_GREEN
                    } else if l.contains("Zeitüberschreitung") || l.contains("timed out") || l.contains("nicht erreichbar") || l.contains("unreachable") {
                        BAD_RED
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.label(RichText::new(l).monospace().color(color));
                }
            });
        });
}

fn scan_ui(ui: &mut egui::Ui, s: &mut ScanTab, ctx: &egui::Context) {
    let running = s.scan.as_ref().map(|x| !x.state.lock().unwrap().finished).unwrap_or(false);
    egui::Grid::new(tr("scan_form")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
        ui.label(tr("Host"));
        ui.add(egui::TextEdit::singleline(&mut s.host).desired_width(260.0).hint_text(tr("Name or IP")));
        ui.end_row();
        ui.label(tr("Ports"));
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut s.ports).desired_width(420.0));
            if ui.small_button(tr("Common")).clicked() {
                s.ports = tools::COMMON_PORTS.into();
            }
            if ui.small_button("1-1024").clicked() {
                s.ports = "1-1024".into();
            }
            if ui.small_button(tr("All")).clicked() {
                s.ports = "1-65535".into();
            }
        });
        ui.end_row();
        ui.label(tr("Timeout"));
        ui.add(egui::DragValue::new(&mut s.timeout).range(100..=5000).suffix(" ms"));
        ui.end_row();
    });
    ui.horizontal(|ui| {
        if running {
            if ui.button(tr("Cancel")).clicked() {
                if let Some(sc) = &s.scan {
                    sc.cancel();
                }
            }
        } else if ui.add(egui::Button::new(RichText::new(tr("Scan")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
            match tools::parse_ports(&s.ports) {
                Ok(ports) if !s.host.trim().is_empty() => {
                    s.error = None;
                    s.scan = Some(PortScan::start(&s.host, ports, s.timeout, ctx.clone()));
                }
                Ok(_) => s.error = Some(tr("Please enter a host.").into()),
                Err(e) => s.error = Some(e),
            }
        }
        if let Some(err) = &s.error {
            ui.label(RichText::new(err).color(BAD_RED));
        }
    });
    ui.separator();
    if let Some(sc) = &s.scan {
        let st = sc.state.lock().unwrap();
        if let Some(err) = &st.error {
            ui.label(RichText::new(err).color(BAD_RED));
            return;
        }
        let frac = if st.total == 0 { 0.0 } else { st.done as f32 / st.total as f32 };
        ui.add(egui::ProgressBar::new(frac).text(tf("{0} / {1} ports checked · address {2}", &[&st.done, &st.total, &st.address])));
        ui.add_space(6.0);
        ui.label(RichText::new(tf("{0} open ports", &[&(st.open.len())])).strong());
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new(tr("scan_res")).striped(true).num_columns(3).spacing([24.0, 4.0]).show(ui, |ui| {
                ui.label(RichText::new(tr("Port")).strong());
                ui.label(RichText::new(tr("Service")).strong());
                ui.label(RichText::new(tr("Status")).strong());
                ui.end_row();
                for p in &st.open {
                    ui.label(RichText::new(p.to_string()).monospace());
                    ui.label(tools::well_known(*p));
                    ui.label(RichText::new(tr("open")).color(OK_GREEN));
                    ui.end_row();
                }
            });
        });
    } else {
        ui.weak(tr("Checks which TCP ports answer on the host. Only use in your own networks."));
    }
}

const DNS_TYPES: [(&str, &str); 11] = [
    ("A", "IPv4 address"),
    ("AAAA", "IPv6 address"),
    ("MX", "Mail server"),
    ("TXT", "Text (SPF, DKIM, verification)"),
    ("CNAME", "Alias"),
    ("NS", "Name servers of the zone"),
    ("SOA", "Zone authority"),
    ("PTR", "Reverse: IP to name"),
    ("SRV", "Services, e.g. _ldap._tcp.company.local"),
    ("CAA", "Allowed certificate authorities"),
    ("ANY", "Everything (many servers refuse)"),
];

fn dns_query(d: &mut DnsTab, ctx: &egui::Context) {
    let host = d.host.trim().to_string();
    if host.is_empty() {
        return;
    }
    let server = d.server.trim().to_string();
    if d.rtype == "A" || d.rtype == "AAAA" {
        let slot = d.result.clone();
        *slot.lock().unwrap() = None;
        let c2 = ctx.clone();
        let h2 = host.clone();
        let want_v6 = d.rtype == "AAAA";
        std::thread::spawn(move || {
            let r = tools::resolve(&h2).map(|v| {
                let mut ips: Vec<String> = v.iter().filter(|a| a.is_ipv6() == want_v6).map(|a| a.ip().to_string()).collect();
                ips.dedup();
                ips
            });
            *slot.lock().unwrap() = Some(r);
            c2.request_repaint();
        });
    } else {
        *d.result.lock().unwrap() = None;
    }
    // reverse lookups need the PTR name; nslookup does that by itself for an IP
    let rtype = if d.rtype == "PTR" { tr("PTR").to_string() } else { d.rtype.clone() };
    if launch::which("nslookup").is_some() {
        let mut args = vec![format!("-type={rtype}"), host];
        if !server.is_empty() {
            args.push(server);
        }
        d.runner.start("nslookup", &args, ctx.clone());
    } else {
        let mut args = vec![tr("+noall").to_string(), tr("+answer").into()];
        if !server.is_empty() {
            args.push(format!("@{server}"));
        }
        if rtype == "PTR" {
            args.push(tr("-x").into());
            args.push(host);
        } else {
            args.push(host);
            args.push(rtype);
        }
        d.runner.start("dig", &args, ctx.clone());
    }
}

fn dns_ui(ui: &mut egui::Ui, d: &mut DnsTab, ctx: &egui::Context) {
    let mut go = false;
    egui::Grid::new(tr("dns_form")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
        ui.label(tr("Name or IP"));
        ui.horizontal(|ui| {
            let r = ui.add(egui::TextEdit::singleline(&mut d.host).desired_width(260.0).hint_text("example.com"));
            go |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.add(egui::Button::new(RichText::new(tr("Query")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
                go = true;
            }
        });
        ui.end_row();
        ui.label(tr("Type"));
        ui.horizontal_wrapped(|ui| {
            for (ty, what) in DNS_TYPES {
                if ui.selectable_label(d.rtype == ty, ty).on_hover_text(tr(what)).clicked() {
                    d.rtype = ty.to_string();
                    go = true;
                }
            }
        });
        ui.end_row();
        ui.label(tr("DNS server"));
        ui.add(egui::TextEdit::singleline(&mut d.server).desired_width(260.0).hint_text(tr("empty = this PC's default, e.g. 1.1.1.1")));
        ui.end_row();
    });
    if go {
        dns_query(d, ctx);
    }
    ui.separator();
    if let Some(r) = d.result.lock().unwrap().as_ref() {
        match r {
            Ok(ips) => {
                ui.label(RichText::new(tr("Addresses")).strong());
                for ip in ips {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(ip).monospace().size(15.0));
                        if ui.small_button(tr("copy")).clicked() {
                            ui.ctx().copy_text(ip.clone());
                        }
                    });
                }
            }
            Err(e) => {
                ui.label(RichText::new(e).color(BAD_RED));
            }
        }
        ui.add_space(8.0);
    }
    ui.label(RichText::new(tf("Answer ({0} records)", &[&d.rtype])).strong());
    output_box(ui, &d.runner.lines.lock().unwrap());
}

fn wol_ui(ui: &mut egui::Ui, w: &mut WolTab) {
    ui.label(tr("Switches a PC on over the network (Wake-on-LAN must be enabled in BIOS/network adapter)."));
    ui.add_space(6.0);
    egui::Grid::new(tr("wol")).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
        ui.label(tr("MAC address"));
        ui.add(egui::TextEdit::singleline(&mut w.mac).hint_text("00:11:22:33:44:55").desired_width(220.0));
        ui.end_row();
        ui.label(tr("Broadcast"));
        ui.add(egui::TextEdit::singleline(&mut w.broadcast).desired_width(220.0));
        ui.end_row();
        ui.label(tr("Port"));
        ui.add(egui::DragValue::new(&mut w.port).range(1..=65535));
        ui.end_row();
    });
    if ui.add(egui::Button::new(RichText::new(tr("Wake up")).color(Color32::WHITE)).fill(ACCENT)).clicked() {
        w.result = Some(tools::wake_on_lan(&w.mac, &w.broadcast, w.port));
    }
    match &w.result {
        Some(Ok(m)) => {
            ui.label(RichText::new(m).color(OK_GREEN));
        }
        Some(Err(e)) => {
            ui.label(RichText::new(e).color(BAD_RED));
        }
        None => {}
    }
}

// ---------------------------------------------------------------- small widgets

fn badge(ui: &mut egui::Ui, p: Protocol) {
    let (r, _) = ui.allocate_exact_size(Vec2::new(36.0, 16.0), Sense::hover());
    ui.painter().rect_filled(r, 3.0, p.color());
    ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, p.short(), egui::FontId::proportional(10.0), Color32::WHITE);
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).strong().color(ACCENT));
    ui.add_space(2.0);
}

/// A section title with a small "?" that opens the matching chapter of the user guide.
fn section_help(ui: &mut egui::Ui, title: &str, topic: crate::help::Topic, help: &mut Option<crate::help::Topic>) {
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).strong().color(ACCENT));
        if ui.small_button("?").on_hover_text(tr("Explain this in the user guide")).clicked() {
            *help = Some(topic);
        }
    });
    ui.add_space(2.0);
}

fn card(ui: &mut egui::Ui, title: &str, sub: &str, color: Color32) -> egui::Response {
    let size = Vec2::new(190.0, 62.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let hovered = resp.hovered();
    let v = ui.visuals();
    let fill = if hovered { v.widgets.hovered.bg_fill } else { v.faint_bg_color };
    ui.painter().rect_filled(rect, 8.0, fill);
    ui.painter().rect_filled(Rect::from_min_size(rect.min, Vec2::new(5.0, rect.height())), egui::CornerRadius { nw: 8, sw: 8, ne: 0, se: 0 }, color);
    ui.painter().text(rect.min + Vec2::new(16.0, 12.0), egui::Align2::LEFT_TOP, title, egui::FontId::proportional(15.0), v.strong_text_color());
    ui.painter().text(rect.min + Vec2::new(16.0, 35.0), egui::Align2::LEFT_TOP, sub, egui::FontId::proportional(12.0), v.weak_text_color());
    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Simple drawn mark: two linked screens.
/// The AdminCraft logo (honey badger), loaded once into a texture.
fn logo(ui: &mut egui::Ui, size: f32) {
    let ctx = ui.ctx().clone();
    let id = egui::Id::new("admincraft-logo");
    let tex = match ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        Some(t) => t,
        None => {
            let img = match image::load_from_memory(crate::LOGO_PNG) {
                Ok(i) => {
                    let i = i.to_rgba8();
                    egui::ColorImage::from_rgba_unmultiplied([i.width() as usize, i.height() as usize], i.as_raw())
                }
                Err(_) => egui::ColorImage::new([1, 1], vec![ACCENT]),
            };
            let t = ctx.load_texture("admincraft-logo", img, egui::TextureOptions::LINEAR);
            ctx.data_mut(|d| d.insert_temp(id, t.clone()));
            t
        }
    };
    ui.add(egui::Image::new((tex.id(), Vec2::splat(size))));
}
