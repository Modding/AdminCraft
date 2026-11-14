//! The window's side of the control channel (see `control.rs`): what agents may ask and do.
//! A child module of `app`, so it can reach the window's state.

use super::*;
use serde_json::{Value, json};

/// A picture of a tab an agent asked for. The tab is brought to the front first; the picture
/// is taken a few frames later, when the tab (and a window embedded in it) is drawn.
pub(super) struct AgentShot {
    reply: std::sync::mpsc::Sender<Value>,
    tab: usize,
    file: PathBuf,
    frames: u32,
}

/// Frames to wait after switching to the tab (an embedded window is placed one frame late).
const SHOT_FRAMES: u32 = 6;
/// Longest text an agent may type into an embedded window at once.
const TYPE_LIMIT: usize = 4000;

fn save_png(file: &std::path::Path, w: usize, h: usize, rgba: &[u8]) -> Result<Value, String> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let (w32, h32) = (u32::try_from(w).map_err(|e| e.to_string())?, u32::try_from(h).map_err(|e| e.to_string())?);
    image::save_buffer(file, rgba, w32, h32, image::ExtendedColorType::Rgba8).map_err(|e| e.to_string())?;
    Ok(json!({ "file": file.display().to_string(), "width": w, "height": h }))
}

impl AdminApp {
    /// "screenshot {index?, path?}": remembers the request; `agent_shot_step` answers it.
    fn start_agent_shot(&mut self, r: crate::control::Request, ctx: &egui::Context) {
        if self.agent_shot.is_some() {
            let _ = r.reply.send(json!({ "error": "another screenshot is being taken" }));
            return;
        }
        let i = match self.tab_index(&r.args) {
            Ok(i) => i,
            Err(e) => {
                let _ = r.reply.send(json!({ "error": e }));
                return;
            }
        };
        let file = match r.args["path"].as_str().map(str::trim).filter(|p| !p.is_empty()) {
            // only ever a picture file: a control command must not be a way to overwrite other files
            Some(p) if !p.to_ascii_lowercase().ends_with(".png") => {
                let _ = r.reply.send(json!({ "error": "the file name must end in .png" }));
                return;
            }
            Some(p) => PathBuf::from(p),
            None => std::env::temp_dir().join("admincraft").join(format!("tab-{}-{i}.png", std::process::id())),
        };
        self.active = i;
        self.agent_shot = Some(AgentShot { reply: r.reply, tab: i, file, frames: 0 });
        ctx.request_repaint();
    }

    /// Takes the picture an agent asked for once the tab has been drawn.
    pub(super) fn agent_shot_step(&mut self, ctx: &egui::Context) {
        let Some(shot) = &mut self.agent_shot else { return };
        shot.frames += 1;
        if shot.frames < SHOT_FRAMES {
            ctx.request_repaint();
            return;
        }
        let Some(shot) = self.agent_shot.take() else { return };
        if shot.tab >= self.tabs.len() || shot.tab != self.active {
            let _ = shot.reply.send(json!({ "error": "the tab was closed or changed meanwhile" }));
            return;
        }
        let tab = self.tab_json(shot.tab);
        let r = self.last_content;
        let ppp = ctx.pixels_per_point();
        let px = PxRect {
            x: (r.min.x * ppp).round() as i32,
            y: (r.min.y * ppp).round() as i32,
            w: (r.width() * ppp).round() as i32,
            h: (r.height() * ppp).round() as i32,
        };
        // from the window itself where the system can do that (embedded windows included, and
        // nothing of a window lying on top); elsewhere our own drawing
        match self.parent_hwnd.and_then(|h| embed::capture_window(h, px)) {
            Some((w, h, rgba)) => {
                let mut answer = save_png(&shot.file, w, h, &rgba).unwrap_or_else(|e| json!({ "error": e }));
                if answer.get("error").is_none() {
                    answer["tab"] = tab;
                }
                let _ = shot.reply.send(answer);
            }
            None => {
                let c2 = ctx.clone();
                ctx.request_screenshot(move |img| {
                    let part = img.region(&r, Some(c2.pixels_per_point()));
                    let [w, h] = part.size;
                    let rgba: Vec<u8> = part.pixels.iter().flat_map(|p| p.to_array()).collect();
                    let mut answer = save_png(&shot.file, w, h, &rgba).unwrap_or_else(|e| json!({ "error": e }));
                    if answer.get("error").is_none() {
                        answer["tab"] = tab.clone();
                    }
                    let _ = shot.reply.send(answer);
                });
                ctx.request_repaint();
            }
        }
    }

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
            if r.cmd == "screenshot" {
                // answered some frames later, when the tab is on the screen
                self.start_agent_shot(r, ctx);
                continue;
            }
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
                    let st = s.state.lock().unwrap_or_else(|e| e.into_inner());
                    let open: Vec<String> = st.open.iter().map(|p| format!("{p} {}", tools::well_known(*p))).collect();
                    format!("{} ({}) {}/{}{}\n{}", x.host, st.address, st.done, st.total, if st.finished { "" } else { " …" }, open.join("\n"))
                }
                None => x.error.clone().unwrap_or_default(),
            },
            TabKind::NetScan(x) => match &x.scan {
                Some(s) => serde_json::to_string_pretty(&s.state.lock().unwrap_or_else(|e| e.into_inner()).hosts).unwrap_or_default(),
                None => x.error.clone().unwrap_or_default(),
            },
            TabKind::Cert(x) => match &*x.result.lock().unwrap_or_else(|e| e.into_inner()) {
                Some(Ok(c)) => {
                    let trust = match &c.trusted {
                        Ok(()) => "trusted".to_string(),
                        Err(e) => format!("not trusted: {e}"),
                    };
                    format!("{}\n{}\n{} – {} ({} days left)\n{trust}", c.subject, c.issuer, c.not_before, c.not_after, c.days_left)
                }
                Some(Err(e)) => e.clone(),
                None => String::new(),
            },
            TabKind::Subnet(x) => match crate::admintools::subnet(&x.input) {
                Ok(c) => format!(
                    "{}/{} mask {} broadcast {} first {} last {} usable {}",
                    c.network, c.prefix, c.mask, c.broadcast, c.first, c.last, c.hosts
                ),
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
        if i < self.tabs.len() { Ok(i) } else { Err(format!("no tab {i} (there are {})", self.tabs.len())) }
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
                    // an embedded PuTTY window takes the characters as messages; Remote Desktop
                    // and VNC viewers don't, they need a real keyboard
                    TabKind::Proc(p) => match &p.embed {
                        Some(em) if em.attached() && em.class() == "PuTTY" => {
                            if text.chars().count() > TYPE_LIMIT {
                                Err(format!("at most {TYPE_LIMIT} characters at once"))
                            } else if em.type_text(&text) && (!enter || em.type_text("\r")) {
                                Ok(json!({ "typed": text.chars().count(), "enter": enter, "window": "PuTTY" }))
                            } else {
                                Err("the PuTTY window did not take the text".to_string())
                            }
                        }
                        Some(em) if em.attached() => Err(format!(
                            "typing works in terminal tabs and embedded PuTTY windows, not in this window ({}); look at it with the screenshot command",
                            em.class()
                        )),
                        _ => Err("this window is not embedded in the tab (its own window, or not started yet)".to_string()),
                    },
                    _ => Err("only terminal tabs and embedded PuTTY windows take typing".to_string()),
                }?;
                self.note(tf("An agent typed into \"{0}\".", &[&title]), false, now);
                Ok(typed)
            }
            "open_tool" => {
                let target = args["target"].as_str().unwrap_or("").trim().to_string();
                match args["tool"].as_str().unwrap_or("") {
                    "ping" => self.open_ping(target, PingMode::Ping, ctx),
                    "traceroute" => self.open_ping(target, PingMode::Trace, ctx),
                    // a person presses "Scan" / "Query" in the tab; for an agent the tool starts
                    // right away, or reading the tab would give nothing
                    "portscan" => {
                        self.open_scan(target);
                        if let Some(Tab { kind: TabKind::Scan(s), .. }) = self.tabs.last_mut()
                            && !s.host.trim().is_empty()
                            && let Ok(ports) = crate::tools::parse_ports(&s.ports)
                        {
                            s.scan = Some(crate::tools::PortScan::start(&s.host, ports, s.timeout, ctx.clone()));
                        }
                    }
                    "dns" => {
                        self.open_dns(target);
                        if let Some(Tab { kind: TabKind::Dns(d), .. }) = self.tabs.last_mut()
                            && !d.host.trim().is_empty()
                        {
                            dns_query(d, ctx);
                        }
                    }
                    "netscan" => {
                        self.open_netscan(target);
                        if let Some(Tab { kind: TabKind::NetScan(n), .. }) = self.tabs.last_mut()
                            && let (Ok(t), Ok(p)) = (crate::netscan::parse_targets(&n.range), crate::tools::parse_ports(&n.ports))
                        {
                            n.scan = Some(crate::netscan::NetScan::start(t, p, n.timeout, n.names, ctx.clone()));
                        }
                    }
                    "subnet" => self.add_tab(
                        tr("Subnet calculator").into(),
                        Color32::from_rgb(0, 137, 123),
                        TabKind::Subnet(extra::SubnetTab { input: target }),
                    ),
                    "cert" => {
                        self.open_cert(target);
                        if let Some(Tab { kind: TabKind::Cert(c), .. }) = self.tabs.last_mut() {
                            let (h, slot, c2) = (c.host.clone(), c.result.clone(), ctx.clone());
                            std::thread::spawn(move || {
                                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(crate::admintools::check_cert(&h, 443));
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
