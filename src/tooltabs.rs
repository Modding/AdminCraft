//! Tabs for the network tools in `nettools.rs`: Whois, the HTTP header check and SNMP.

use crate::i18n::{t as tr, tf};
use crate::nettools::{self, HttpReport, SnmpOverview, SnmpValue, WhoisResult};
use eframe::egui::{self, Color32, RichText};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const OK: Color32 = Color32::from_rgb(102, 187, 106);
const BAD: Color32 = Color32::from_rgb(229, 115, 115);
const WARN: Color32 = Color32::from_rgb(255, 183, 77);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ToolKind {
    Whois,
    Http,
    Snmp,
}

impl ToolKind {
    pub fn title(self) -> &'static str {
        match self {
            ToolKind::Whois => tr("Whois"),
            ToolKind::Http => tr("HTTP header check"),
            ToolKind::Snmp => tr("SNMP query"),
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            ToolKind::Whois => "whois",
            ToolKind::Http => "http",
            ToolKind::Snmp => "snmp",
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            ToolKind::Whois => Color32::from_rgb(141, 110, 99),
            ToolKind::Http => Color32::from_rgb(38, 166, 154),
            ToolKind::Snmp => Color32::from_rgb(92, 107, 192),
        }
    }
}

enum Res {
    Whois(Result<WhoisResult, String>),
    Http(Result<HttpReport, String>),
    Snmp(Result<SnmpOverview, String>),
    Walk(Result<Vec<(String, SnmpValue)>, String>),
}

pub struct ToolTab {
    pub kind: ToolKind,
    pub input: String,
    community: String,
    port: String,
    walk_oid: String,
    result: Arc<Mutex<Option<Res>>>,
    running: Arc<Mutex<bool>>,
}

impl ToolTab {
    pub fn new(kind: ToolKind, input: String) -> ToolTab {
        ToolTab {
            kind,
            input,
            community: "public".into(),
            port: "161".into(),
            walk_oid: "1.3.6.1.2.1.1".into(),
            result: Arc::new(Mutex::new(None)),
            running: Arc::new(Mutex::new(false)),
        }
    }

    fn busy(&self) -> bool {
        self.running.lock().map(|g| *g).unwrap_or(false)
    }

    /// Runs the tool in the background (`walk`: SNMP walk instead of the overview).
    pub fn start(&mut self, ctx: &egui::Context, walk: bool) {
        if self.busy() || self.input.trim().is_empty() {
            return;
        }
        let (slot, running, ctx) = (self.result.clone(), self.running.clone(), ctx.clone());
        let (kind, input, community, walk_oid) = (self.kind, self.input.trim().to_string(), self.community.clone(), self.walk_oid.clone());
        let port = self.port.trim().parse::<u16>().unwrap_or(161);
        *running.lock().unwrap() = true;
        std::thread::spawn(move || {
            let t = Duration::from_secs(8);
            let r = match kind {
                ToolKind::Whois => Res::Whois(nettools::whois(&input, Duration::from_secs(12))),
                ToolKind::Http => Res::Http(nettools::http_check(&input, Duration::from_secs(15))),
                ToolKind::Snmp if walk => Res::Walk(nettools::snmp_walk(&input, port, &community, &walk_oid, 2000, Duration::from_secs(3))),
                ToolKind::Snmp => Res::Snmp(nettools::snmp_overview(&input, port, &community, t.min(Duration::from_secs(3)))),
            };
            *slot.lock().unwrap() = Some(r);
            *running.lock().unwrap() = false;
            ctx.request_repaint();
        });
    }

    /// The result as text (for agents and the copy button).
    pub fn text(&self) -> String {
        let g = self.result.lock().unwrap();
        match &*g {
            None => String::new(),
            Some(Res::Whois(Ok(w))) => w.text.clone(),
            Some(Res::Http(Ok(h))) => {
                let mut s = String::new();
                for (n, hop) in h.hops.iter().enumerate() {
                    s += &format!("{} {} {} ({} ms)\n", n + 1, hop.status, hop.url, hop.millis);
                }
                if let Some(last) = h.hops.last() {
                    for (k, v) in &last.headers {
                        s += &format!("  {k}: {v}\n");
                    }
                }
                for x in &h.security {
                    s += &format!("{} {}: {}\n", if x.present { "+" } else { "-" }, x.name, x.advice);
                }
                for c in &h.cookies {
                    s += &format!("cookie {} secure={} httponly={} samesite={}\n", c.name, c.secure, c.http_only, c.same_site);
                }
                s
            }
            Some(Res::Snmp(Ok(o))) => {
                let mut s = format!("{}\n{}\nuptime {}\ncontact {}\nlocation {}\n", o.name, o.descr, o.uptime, o.contact, o.location);
                for i in &o.interfaces {
                    s += &format!("{} {} oper={:?} speed={:?}Mbit mac={} in={:?} out={:?}\n", i.index, i.name, i.oper_up, i.speed_mbit, i.mac, i.in_octets, i.out_octets);
                }
                s
            }
            Some(Res::Walk(Ok(rows))) => rows.iter().map(|(o, v)| format!("{o} = {v}\n")).collect(),
            Some(Res::Whois(Err(e)) | Res::Http(Err(e)) | Res::Snmp(Err(e)) | Res::Walk(Err(e))) => e.clone(),
        }
    }
}

fn bytes_h(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[i])
    }
}

pub fn tool_ui(ui: &mut egui::Ui, t: &mut ToolTab) {
    let ctx = ui.ctx().clone();
    let busy = t.busy();
    ui.horizontal(|ui| {
        let hint = match t.kind {
            ToolKind::Whois => tr("Domain or IP address, e.g. example.com"),
            ToolKind::Http => tr("Web address, e.g. https://example.com"),
            ToolKind::Snmp => tr("Host or IP of a switch, printer, server"),
        };
        let r = ui.add(egui::TextEdit::singleline(&mut t.input).hint_text(hint).desired_width(320.0));
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if t.kind == ToolKind::Snmp {
            ui.label(tr("Community"));
            let hide = t.community != "public";
            ui.add(egui::TextEdit::singleline(&mut t.community).desired_width(90.0).password(hide));
            ui.label(tr("Port"));
            ui.add(egui::TextEdit::singleline(&mut t.port).desired_width(48.0));
        }
        let go = match t.kind {
            ToolKind::Whois => tr("Look up"),
            ToolKind::Http => tr("Check"),
            ToolKind::Snmp => tr("Query"),
        };
        if ui.add_enabled(!busy, egui::Button::new(go)).clicked() || (enter && !busy) {
            t.start(&ctx, false);
        }
        if busy {
            ui.spinner();
        }
        if ui.button(tr("Copy")).on_hover_text(tr("Copy the result as text")).clicked() {
            ctx.copy_text(t.text());
        }
    });
    if t.kind == ToolKind::Snmp {
        ui.horizontal(|ui| {
            ui.label(tr("Walk from OID"));
            ui.add(egui::TextEdit::singleline(&mut t.walk_oid).desired_width(220.0));
            if ui.add_enabled(!busy, egui::Button::new(tr("Walk"))).on_hover_text(tr("Lists every value below this OID (at most 2000)")).clicked() {
                t.start(&ctx, true);
            }
            ui.weak(tr("SNMP v2c, read only."));
        });
    }
    ui.separator();
    let guard = t.result.lock().unwrap();
    let Some(res) = &*guard else {
        if !busy {
            ui.weak(match t.kind {
                ToolKind::Whois => tr("Shows who a domain or IP address belongs to: registrar, owner network, dates, name servers."),
                ToolKind::Http => tr("Follows every redirect and shows status codes, headers and timings, which security headers are missing and how cookies are protected."),
                ToolKind::Snmp => tr("Asks a device over SNMP for its name, description, uptime and location, and lists its interfaces with status, speed and traffic."),
            });
        }
        return;
    };
    egui::ScrollArea::vertical().id_salt("tool_res").auto_shrink([false, false]).show(ui, |ui| match res {
        Res::Whois(Err(e)) | Res::Http(Err(e)) | Res::Snmp(Err(e)) | Res::Walk(Err(e)) => {
            ui.colored_label(BAD, e);
        }
        Res::Whois(Ok(w)) => {
            ui.weak(tf("Asked: {0}", &[&w.servers.join(" » ")]));
            ui.add(egui::Label::new(RichText::new(&w.text).monospace().size(12.5)).selectable(true));
        }
        Res::Http(Ok(h)) => http_ui(ui, h),
        Res::Snmp(Ok(o)) => snmp_ui(ui, o),
        Res::Walk(Ok(rows)) => {
            ui.weak(tf("{0} values", &[&rows.len()]));
            egui::Grid::new("walk").striped(true).num_columns(3).spacing([14.0, 4.0]).show(ui, |ui| {
                for (oid, v) in rows {
                    ui.monospace(oid);
                    ui.weak(nettools::oid_name(oid).unwrap_or_default());
                    ui.add(egui::Label::new(v.to_string()).selectable(true));
                    ui.end_row();
                }
            });
        }
    });
}

fn status_color(s: u16) -> Color32 {
    match s {
        200..=299 => OK,
        300..=399 => WARN,
        _ => BAD,
    }
}

fn http_ui(ui: &mut egui::Ui, h: &HttpReport) {
    ui.strong(tr("Requests"));
    egui::Grid::new("hops").striped(true).num_columns(4).spacing([14.0, 4.0]).show(ui, |ui| {
        for (n, hop) in h.hops.iter().enumerate() {
            ui.label(format!("{}.", n + 1));
            ui.label(RichText::new(hop.status.to_string()).strong().color(status_color(hop.status)));
            ui.add(egui::Label::new(RichText::new(&hop.url).monospace()).selectable(true));
            ui.weak(format!("{} ms", hop.millis));
            ui.end_row();
        }
    });
    ui.add_space(8.0);
    ui.strong(tr("Security headers"));
    egui::Grid::new("sec").striped(true).num_columns(3).spacing([14.0, 4.0]).show(ui, |ui| {
        for x in &h.security {
            let ok = x.present && x.advice == tr("OK");
            ui.label(RichText::new("•").size(20.0).color(if ok { OK } else if x.present { WARN } else { BAD }));
            ui.label(RichText::new(x.name).monospace());
            ui.vertical(|ui| {
                if !x.value.is_empty() {
                    ui.add(egui::Label::new(RichText::new(&x.value).monospace().size(12.0)).wrap());
                }
                if !ok {
                    ui.weak(x.advice);
                }
            });
            ui.end_row();
        }
    });
    if !h.cookies.is_empty() {
        ui.add_space(8.0);
        ui.strong(tr("Cookies (flags only, never values)"));
        egui::Grid::new("cookies").striped(true).num_columns(4).spacing([14.0, 4.0]).show(ui, |ui| {
            ui.weak(tr("Name"));
            ui.weak("Secure");
            ui.weak("HttpOnly");
            ui.weak("SameSite");
            ui.end_row();
            for c in &h.cookies {
                let flag = |ui: &mut egui::Ui, on: bool| {
                    ui.label(RichText::new(if on { tr("yes") } else { tr("no") }).color(if on { OK } else { BAD }));
                };
                ui.monospace(&c.name);
                flag(ui, c.secure);
                flag(ui, c.http_only);
                ui.label(if c.same_site.is_empty() { "—".to_string() } else { c.same_site.clone() });
                ui.end_row();
            }
        });
    }
    if let Some(last) = h.hops.last() {
        ui.add_space(8.0);
        egui::CollapsingHeader::new(tf("All headers of the last answer ({0})", &[&last.headers.len()])).show(ui, |ui| {
            egui::Grid::new("hdrs").striped(true).num_columns(2).spacing([14.0, 2.0]).show(ui, |ui| {
                for (k, v) in &last.headers {
                    ui.monospace(k);
                    ui.add(egui::Label::new(RichText::new(v).monospace().size(12.0)).wrap().selectable(true));
                    ui.end_row();
                }
            });
        });
    }
}

fn snmp_ui(ui: &mut egui::Ui, o: &SnmpOverview) {
    egui::Grid::new("sys").num_columns(2).spacing([14.0, 4.0]).show(ui, |ui| {
        for (k, v) in [
            (tr("Name"), &o.name),
            (tr("Description"), &o.descr),
            (tr("Uptime"), &o.uptime),
            (tr("Contact"), &o.contact),
            (tr("Location"), &o.location),
            (tr("Object ID"), &o.object_id),
        ] {
            ui.weak(k);
            ui.add(egui::Label::new(v.as_str()).wrap().selectable(true));
            ui.end_row();
        }
    });
    ui.add_space(8.0);
    ui.strong(tf("Interfaces ({0})", &[&o.interfaces.len()]));
    egui::Grid::new("ifs").striped(true).num_columns(7).spacing([14.0, 4.0]).show(ui, |ui| {
        for h in [tr("No."), tr("Name"), tr("Status"), tr("Speed"), tr("MAC address"), tr("Received"), tr("Sent")] {
            ui.weak(h);
        }
        ui.end_row();
        for i in &o.interfaces {
            ui.label(i.index.to_string());
            ui.label(&i.name);
            let (txt, col) = match (i.admin_up, i.oper_up) {
                (Some(false), _) => (tr("off"), Color32::GRAY),
                (_, Some(true)) => (tr("up"), OK),
                (_, Some(false)) => (tr("down"), BAD),
                _ => ("?", Color32::GRAY),
            };
            ui.label(RichText::new(txt).color(col).strong());
            ui.label(i.speed_mbit.map(|s| if s >= 1000 { format!("{} Gbit/s", s / 1000) } else { format!("{s} Mbit/s") }).unwrap_or_default());
            ui.monospace(&i.mac);
            ui.label(i.in_octets.map(bytes_h).unwrap_or_default());
            ui.label(i.out_octets.map(bytes_h).unwrap_or_default());
            ui.end_row();
        }
    });
}
