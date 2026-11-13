//! The window's side of the control channel (see `control.rs`): what agents may ask and do.
//! A child module of `app`, so it can reach the window's state.

use super::*;
use serde_json::{json, Value};

impl AdminApp {
    /// Starts or stops the control channel to match the setting.
    pub(super) fn sync_control(&mut self, ctx: &egui::Context) {
        let want = self.store.data.settings.agent_control && self.shot.is_none();
        if want && self.control.is_none() {
            let c = ctx.clone();
            match crate::control::start(move || c.request_repaint()) {
                Ok(s) => self.control = Some(s),
                Err(e) => {
                    self.log.push(tf("Control by agents could not start: {0}", &[&e]));
                    self.store.data.settings.agent_control = false;
                }
            }
        } else if !want && self.control.is_some() {
            self.control = None;
        }
    }

    /// Answers what agents asked since the last frame.
    pub(super) fn control_requests(&mut self, ctx: &egui::Context, now: f64) {
        let mut reqs = Vec::new();
        if let Some(s) = &self.control {
            while let Ok(r) = s.requests.try_recv() {
                reqs.push(r);
            }
        }
        for r in reqs {
            let v = self.control_answer(&r.cmd, &r.args, ctx, now).unwrap_or_else(|e| json!({ "error": e }));
            let _ = r.reply.send(v);
        }
    }

    fn tab_json(&self, i: usize) -> Value {
        let t = &self.tabs[i];
        let (kind, host) = match &t.kind {
            TabKind::Start => ("home", String::new()),
            TabKind::Settings => ("settings", String::new()),
            TabKind::Term(x) => ("terminal", x.entry.host.clone()),
            TabKind::Proc(x) => ("window", x.entry.host.clone()),
            TabKind::Transfer(x) => ("files", x.entry.host.clone()),
            TabKind::Ping(x) => ("ping", x.host.clone()),
            TabKind::Scan(x) => ("portscan", x.host.clone()),
            TabKind::Dns(x) => ("dns", x.host.clone()),
            TabKind::Wol(x) => ("wake-on-lan", x.mac.clone()),
            TabKind::NetScan(x) => ("netscan", x.range.clone()),
            TabKind::Subnet(x) => ("subnet", x.input.clone()),
            TabKind::Cert(x) => ("certificate", x.host.clone()),
            TabKind::Tunnels => ("tunnels", String::new()),
            TabKind::Help(_) => ("help", String::new()),
            TabKind::Playback(x) => ("recording", x.title()),
            TabKind::Tool(x) => (x.kind.key(), x.input.clone()),
        };
        json!({ "index": i, "title": t.title, "kind": kind, "host": host, "active": i == self.active })
    }

    fn tab_text(&self, i: usize) -> String {
        match &self.tabs[i].kind {
            TabKind::Term(x) => x.term.as_ref().map(|t| t.screen_text()).or_else(|| x.error.clone()).unwrap_or_default(),
            TabKind::Ping(x) => x.runner.text(),
            TabKind::Dns(x) => x.runner.text(),
            TabKind::Proc(x) => x.exited.clone().unwrap_or_else(|| x.label.clone()),
            TabKind::Scan(x) => match &x.scan {
                Some(s) => {
                    let st = s.state.lock().unwrap();
                    let open: Vec<String> = st.open.iter().map(|p| format!("{p} {}", tools::well_known(*p))).collect();
                    format!("{} ({}) {}/{}{}\n{}", x.host, st.address, st.done, st.total, if st.finished { "" } else { " …" }, open.join("\n"))
                }
                None => x.error.clone().unwrap_or_default(),
            },
            TabKind::NetScan(x) => match &x.scan {
                Some(s) => serde_json::to_string_pretty(&s.state.lock().unwrap().hosts).unwrap_or_default(),
                None => x.error.clone().unwrap_or_default(),
            },
            TabKind::Cert(x) => match &*x.result.lock().unwrap() {
                Some(Ok(c)) => format!("{}\n{}\n{} – {} ({} days left)\n{:?}", c.subject, c.issuer, c.not_before, c.not_after, c.days_left, c.trusted),
                Some(Err(e)) => e.clone(),
                None => String::new(),
            },
            TabKind::Subnet(x) => match crate::admintools::subnet(&x.input) {
                Ok(c) => format!("{}/{} mask {} broadcast {} first {} last {} usable {}", c.network, c.prefix, c.mask, c.broadcast, c.first, c.last, c.hosts),
                Err(e) => e,
            },
            TabKind::Transfer(x) => x.shown_cwd.clone(),
            TabKind::Playback(x) => x.screen_text(),
            TabKind::Tool(x) => x.text(),
            _ => String::new(),
        }
    }

    fn tab_index(&self, args: &Value) -> Result<usize, String> {
        let i = args["index"].as_u64().map(|i| i as usize).unwrap_or(self.active);
        if i < self.tabs.len() {
            Ok(i)
        } else {
            Err(format!("no tab {i} (there are {})", self.tabs.len()))
        }
    }

    fn control_answer(&mut self, cmd: &str, args: &Value, ctx: &egui::Context, now: f64) -> Result<Value, String> {
        match cmd {
            "status" => Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "tabs": self.tabs.len(),
                "active": self.tab_json(self.active.min(self.tabs.len().saturating_sub(1))),
                "connections": self.store.data.entries.iter().filter(|e| !e.folder).count(),
                "locked": self.store.locked(),
                "may_type": self.store.data.settings.agent_typing,
            })),
            "list_tabs" => Ok(json!({ "tabs": (0..self.tabs.len()).map(|i| self.tab_json(i)).collect::<Vec<_>>() })),
            "open_connection" => {
                if self.store.locked() {
                    return Err("the connection list is locked (master password)".into());
                }
                let name = args["name"].as_str().unwrap_or("").to_lowercase();
                let id = args["id"].as_u64();
                let conns = || self.store.data.entries.iter().filter(|e| !e.folder);
                let (eid, ename) = conns()
                    .find(|e| Some(e.id) == id || (!name.is_empty() && e.name.to_lowercase() == name))
                    .or_else(|| conns().find(|e| !name.is_empty() && e.name.to_lowercase().contains(&name)))
                    .map(|e| (e.id, e.name.clone()))
                    .ok_or_else(|| "no such connection".to_string())?;
                let before = self.tabs.len();
                self.connect_id(eid, ctx, now);
                Ok(json!({ "opened": ename, "new_tab": self.tabs.len() > before, "active": self.tab_json(self.active.min(self.tabs.len() - 1)) }))
            }
            "switch_tab" => {
                let i = self.tab_index(args)?;
                self.active = i;
                Ok(self.tab_json(i))
            }
            "close_tab" => {
                let i = self.tab_index(args)?;
                if i == 0 {
                    return Err("the home tab can't be closed".into());
                }
                self.close_request = Some(i);
                Ok(json!({ "closing": i }))
            }
            "read_tab" => {
                let i = self.tab_index(args)?;
                Ok(json!({ "tab": self.tab_json(i), "text": self.tab_text(i) }))
            }
            "type_text" => {
                if !self.store.data.settings.agent_typing {
                    return Err("typing into terminals is switched off (Settings » AI agents)".into());
                }
                let i = self.tab_index(args)?;
                let text = args["text"].as_str().unwrap_or("").to_string();
                let enter = args["enter"].as_bool().unwrap_or(false);
                let title = self.tabs[i].title.clone();
                let typed = match &mut self.tabs[i].kind {
                    TabKind::Term(x) => match &mut x.term {
                        Some(t) => {
                            t.send(text.as_bytes());
                            if enter {
                                t.send(b"\r");
                            }
                            Ok(json!({ "typed": text.chars().count(), "enter": enter }))
                        }
                        None => Err("this terminal is not running".to_string()),
                    },
                    _ => Err("only terminal tabs take typing".to_string()),
                }?;
                self.note(tf("An agent typed into \"{0}\".", &[&title]), false, now);
                Ok(typed)
            }
            "open_tool" => {
                let target = args["target"].as_str().unwrap_or("").trim().to_string();
                match args["tool"].as_str().unwrap_or("") {
                    "ping" => self.open_ping(target, PingMode::Ping, ctx),
                    "traceroute" => self.open_ping(target, PingMode::Trace, ctx),
                    "portscan" => self.open_scan(target),
                    "dns" => self.open_dns(target),
                    "netscan" => {
                        self.open_netscan(target);
                        if let Some(Tab { kind: TabKind::NetScan(n), .. }) = self.tabs.last_mut() {
                            if let (Ok(t), Ok(p)) = (crate::netscan::parse_targets(&n.range), crate::tools::parse_ports(&n.ports)) {
                                n.scan = Some(crate::netscan::NetScan::start(t, p, n.timeout, n.names, ctx.clone()));
                            }
                        }
                    }
                    "subnet" => self.add_tab(tr("Subnet calculator").into(), Color32::from_rgb(0, 137, 123), TabKind::Subnet(extra::SubnetTab { input: target })),
                    "cert" => {
                        self.open_cert(target);
                        if let Some(Tab { kind: TabKind::Cert(c), .. }) = self.tabs.last_mut() {
                            let (h, slot, c2) = (c.host.clone(), c.result.clone(), ctx.clone());
                            std::thread::spawn(move || {
                                *slot.lock().unwrap() = Some(crate::admintools::check_cert(&h, 443));
                                c2.request_repaint();
                            });
                        }
                    }
                    "help" => self.open_help(None),
                    "recordings" => self.open_recordings(None),
                    "whois" => self.open_net_tool(crate::tooltabs::ToolKind::Whois, target, ctx),
                    "http" => self.open_net_tool(crate::tooltabs::ToolKind::Http, target, ctx),
                    "snmp" => self.open_net_tool(crate::tooltabs::ToolKind::Snmp, target, ctx),
                    "settings" => self.open_settings(),
                    other => return Err(format!("unknown tool '{other}'")),
                }
                Ok(self.tab_json(self.active))
            }
            "notify" => {
                let text: String = args["text"].as_str().unwrap_or("").chars().take(300).collect();
                self.note(tf("Agent: {0}", &[&text]), false, now);
                Ok(json!({ "shown": true }))
            }
            _ => Err(format!("unknown command '{cmd}'")),
        }
    }
}
