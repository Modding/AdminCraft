//! Recorded terminal sessions: the "Recordings" tab lists them and plays one back like a video
//! (play, pause, faster, jump to any moment). Files are asciicast v2 (`.cast`), so asciinema
//! can play them too.

use crate::i18n::{t as tr, tf};
use eframe::egui::{self, FontId, Sense, Vec2};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub enum Ev {
    Out(String),
    Resize(u16, u16),
}

#[derive(Clone, Debug)]
pub struct Cast {
    pub cols: u16,
    pub rows: u16,
    pub title: String,
    pub timestamp: u64,
    /// Time in seconds, what happened.
    pub events: Vec<(f64, Ev)>,
}

/// Reads an asciicast v2 file (header line, then `[time, "o"|"r"|"i", data]` lines).
pub fn parse_cast(text: &str) -> Result<Cast, String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: serde_json::Value = serde_json::from_str(lines.next().ok_or_else(|| tr("The recording is empty.").to_string())?).map_err(|e| e.to_string())?;
    if header["version"].as_u64() != Some(2) {
        return Err(tr("Not a recording AdminCraft can play (asciicast version 2 expected).").into());
    }
    let mut cast = Cast {
        cols: header["width"].as_u64().unwrap_or(80).clamp(10, 500) as u16,
        rows: header["height"].as_u64().unwrap_or(24).clamp(5, 300) as u16,
        title: header["title"].as_str().unwrap_or("").to_string(),
        timestamp: header["timestamp"].as_u64().unwrap_or(0),
        events: Vec::new(),
    };
    for l in lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
        let (Some(t), Some(kind), Some(data)) = (v[0].as_f64(), v[1].as_str(), v[2].as_str()) else { continue };
        match kind {
            "o" => cast.events.push((t, Ev::Out(data.to_string()))),
            "r" => {
                if let Some((c, r)) = data.split_once('x') {
                    if let (Ok(c), Ok(r)) = (c.parse::<u16>(), r.parse::<u16>()) {
                        cast.events.push((t, Ev::Resize(c.clamp(10, 500), r.clamp(5, 300))));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(cast)
}

/// Pauses longer than `max` seconds shrink to `max` (nobody wants to watch a coffee break).
pub fn compress_pauses(events: &[(f64, Ev)], max: f64) -> Vec<(f64, Ev)> {
    let mut out = Vec::with_capacity(events.len());
    let (mut last, mut shift) = (0.0, 0.0);
    for (t, e) in events {
        let gap = t - last;
        if gap > max {
            shift += gap - max;
        }
        last = *t;
        out.push(((t - shift).max(0.0), e.clone()));
    }
    out
}

pub fn recordings_dir() -> PathBuf {
    crate::model::data_dir(false).join("recordings")
}

/// Where a new recording of `name` goes.
pub fn new_recording_path(name: &str) -> PathBuf {
    let log = crate::extra::session_log_path(name);
    let file = log.file_name().map(|f| f.to_string_lossy().replace(".log", ".cast")).unwrap_or_else(|| "session.cast".into());
    recordings_dir().join(file)
}

pub struct RecFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub modified: std::time::SystemTime,
}

/// The recordings, newest first.
pub fn list() -> Vec<RecFile> {
    let mut v: Vec<RecFile> = std::fs::read_dir(recordings_dir())
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("cast")))
                .filter_map(|e| {
                    let m = e.metadata().ok()?;
                    Some(RecFile {
                        name: e.path().file_stem()?.to_string_lossy().to_string(),
                        path: e.path(),
                        size: m.len(),
                        modified: m.modified().ok()?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| b.modified.cmp(&a.modified));
    v
}

struct Player {
    path: PathBuf,
    cast: Cast,
    /// The timeline played (pauses shortened when wanted).
    events: Vec<(f64, Ev)>,
    parser: vt100::Parser<crate::terminal::TermCallbacks>,
    next: usize,
    t: f64,
    playing: bool,
}

impl Player {
    fn open(path: &Path, skip_pauses: bool) -> Result<Player, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let cast = parse_cast(&text)?;
        let events = if skip_pauses { compress_pauses(&cast.events, 2.0) } else { cast.events.clone() };
        let parser = new_parser(cast.rows, cast.cols);
        Ok(Player { path: path.to_path_buf(), cast, events, parser, next: 0, t: 0.0, playing: true })
    }

    fn duration(&self) -> f64 {
        self.events.last().map(|e| e.0).unwrap_or(0.0)
    }

    /// Plays everything up to `self.t`.
    fn advance(&mut self) {
        while let Some((t, e)) = self.events.get(self.next) {
            if *t > self.t {
                break;
            }
            match e {
                Ev::Out(s) => self.parser.process(s.as_bytes()),
                Ev::Resize(c, r) => self.parser.set_size(crate::terminal::nz(*r), crate::terminal::nz(*c)),
            }
            self.next += 1;
        }
    }

    fn seek(&mut self, t: f64) {
        if t < self.t {
            self.parser = new_parser(self.cast.rows, self.cast.cols);
            self.next = 0;
        }
        self.t = t.clamp(0.0, self.duration());
        self.advance();
    }
}

fn new_parser(rows: u16, cols: u16) -> vt100::Parser<crate::terminal::TermCallbacks> {
    vt100::Parser::new_with_callbacks(crate::terminal::nz(rows), crate::terminal::nz(cols), 0, crate::terminal::TermCallbacks::default())
}

pub struct PlaybackTab {
    files: Vec<RecFile>,
    player: Option<Player>,
    speed: f64,
    skip_pauses: bool,
    error: Option<String>,
}

impl PlaybackTab {
    pub fn new(open: Option<PathBuf>) -> PlaybackTab {
        let mut p = PlaybackTab { files: list(), player: None, speed: 1.0, skip_pauses: true, error: None };
        if let Some(path) = open {
            p.load(&path);
        }
        p
    }

    fn load(&mut self, path: &Path) {
        match Player::open(path, self.skip_pauses) {
            Ok(pl) => {
                self.player = Some(pl);
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Text of the screen shown now (for agents).
    pub fn screen_text(&self) -> String {
        self.player.as_ref().map(|p| p.parser.screen().contents()).unwrap_or_default()
    }

    pub fn title(&self) -> String {
        self.player.as_ref().map(|p| p.path.display().to_string()).unwrap_or_default()
    }
}

fn mmss(t: f64) -> String {
    let s = t.max(0.0) as u64;
    format!("{}:{:02}", s / 60, s % 60)
}

pub fn playback_ui(ui: &mut egui::Ui, p: &mut PlaybackTab, font_size: f32, dark: bool) {
    let height = ui.available_height();
    ui.horizontal_top(|ui| {
        // the list of recordings
        ui.vertical(|ui| {
            ui.set_width(240.0);
            ui.set_min_height(height);
            ui.horizontal(|ui| {
                ui.strong(tr("Recordings"));
                if ui.small_button(tr("Refresh")).clicked() {
                    p.files = list();
                }
                if ui.small_button(tr("Open folder")).clicked() {
                    let d = recordings_dir();
                    let _ = std::fs::create_dir_all(&d);
                    crate::launch::open_folder(&d);
                }
            });
            if p.files.is_empty() {
                ui.weak(tr("No recordings yet. Switch on \"Record terminal sessions for playback\" in the settings; every SSH, Telnet or shell tab is then recorded."));
            }
            let mut open: Option<PathBuf> = None;
            egui::ScrollArea::vertical().id_salt("rec_list").auto_shrink([false, false]).show(ui, |ui| {
                for f in &p.files {
                    let here = p.player.as_ref().is_some_and(|pl| pl.path == f.path);
                    let label = format!("{}\n{} KB", f.name, f.size.div_ceil(1024));
                    if ui.add(egui::Button::selectable(here, label).wrap()).clicked() {
                        open = Some(f.path.clone());
                    }
                }
            });
            if let Some(path) = open {
                p.load(&path);
            }
        });
        ui.separator();
        ui.vertical(|ui| {
            if let Some(e) = &p.error {
                ui.colored_label(egui::Color32::from_rgb(229, 115, 115), e);
            }
            let Some(pl) = p.player.as_mut() else {
                ui.weak(tr("Pick a recording on the left."));
                return;
            };
            let dur = pl.duration();
            ui.horizontal(|ui| {
                let label = if pl.playing { tr("Pause") } else { tr("Play") };
                if ui.button(label).clicked() {
                    if !pl.playing && pl.t >= dur {
                        pl.seek(0.0);
                    }
                    pl.playing = !pl.playing;
                }
                if ui.button(tr("From the start")).clicked() {
                    pl.seek(0.0);
                    pl.playing = true;
                }
                egui::ComboBox::from_id_salt("rec_speed").width(70.0).selected_text(format!("{}×", p.speed)).show_ui(ui, |ui| {
                    for s in [0.5, 1.0, 2.0, 4.0, 8.0, 16.0] {
                        ui.selectable_value(&mut p.speed, s, format!("{s}×"));
                    }
                });
                let mut t = pl.t;
                let w = (ui.available_width() - 190.0).max(120.0);
                ui.spacing_mut().slider_width = w;
                if ui.add(egui::Slider::new(&mut t, 0.0..=dur.max(0.01)).show_value(false)).changed() {
                    pl.seek(t);
                }
                ui.monospace(format!("{} / {}", mmss(pl.t), mmss(dur)));
            });
            let mut reload: Option<(PathBuf, f64)> = None;
            ui.horizontal(|ui| {
                let when = if pl.cast.timestamp > 0 { crate::extra::fmt_time(pl.cast.timestamp) } else { String::new() };
                ui.weak(tf("{0} · {1}", &[&pl.cast.title, &when]));
                if ui.checkbox(&mut p.skip_pauses, tr("Shorten pauses")).on_hover_text(tr("Waits longer than 2 seconds are cut to 2 seconds")).changed() {
                    reload = Some((pl.path.clone(), pl.t));
                }
            });
            if let Some((path, t)) = reload {
                p.load(&path);
                if let Some(pl) = p.player.as_mut() {
                    pl.seek(t.min(pl.duration()));
                }
            }
            let Some(pl) = p.player.as_mut() else { return };
            if pl.playing {
                let dt = ui.input(|i| i.stable_dt).min(0.25) as f64;
                pl.t = (pl.t + dt * p.speed).min(dur);
                pl.advance();
                if pl.t >= dur {
                    pl.playing = false;
                }
                ui.ctx().request_repaint();
            }
            // the screen, at the recorded size, scaled down when it doesn't fit
            let (rows, cols) = pl.parser.screen().size();
            let (rows, cols) = (rows.get(), cols.get());
            let avail = ui.available_size();
            let mut size = font_size;
            let (mut cw, mut ch) = (1.0, 1.0);
            for _ in 0..8 {
                let font = FontId::monospace(size);
                (cw, ch) = ui.ctx().fonts_mut(|f| (f.glyph_width(&font, 'M').max(1.0), f.row_height(&font).max(1.0)));
                if cols as f32 * cw + 8.0 <= avail.x && rows as f32 * ch + 8.0 <= avail.y || size <= 7.0 {
                    break;
                }
                size = (size * 0.88).max(7.0);
            }
            let want = Vec2::new(cols as f32 * cw + 8.0, rows as f32 * ch + 8.0);
            let (rect, _) = ui.allocate_exact_size(want.min(avail), Sense::hover());
            crate::terminal::paint_screen(ui, rect, pl.parser.screen(), rows, cols, &FontId::monospace(size), (cw, ch), dark, Some(false));
        });
    });
}
