//! A terminal tab: runs ssh / telnet / PowerShell / a shell on a pseudo terminal and draws it.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::launch::PwRule;
use eframe::egui::{self, Color32, FontId, Key, Pos2, Rect, Sense, Stroke, Vec2};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::collections::VecDeque;
use std::io::{Read, Write};

/// A line that looks like a shell waiting for input ("user@host:~$ ", "[root@db ~]# ").
pub fn is_shell_prompt(line: &str) -> bool {
    let t = line.trim_end();
    if t.chars().count() < 2 {
        return false;
    }
    let low = t.to_lowercase();
    if low.contains("password") || low.contains("passwort") || low.contains("(yes/no") {
        return false;
    }
    matches!(t.chars().last(), Some('$') | Some('#') | Some('>') | Some('%'))
}
use std::num::NonZeroU16;
use std::sync::mpsc::{Receiver, channel};

#[derive(Default)]
pub struct TermCallbacks {
    pub replies: Vec<Vec<u8>>,
    pub title: Option<String>,
    pub bell: bool,
}

impl vt100::Callbacks for TermCallbacks {
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.bell = true;
    }

    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.title = Some(String::from_utf8_lossy(title).into_owned());
    }

    fn unhandled_csi(&mut self, screen: &mut vt100::Screen, i1: Option<u8>, _i2: Option<u8>, params: &[&[u16]], c: char) {
        let first = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        match (c, i1) {
            ('n', None) if first == 6 => {
                let (r, col) = screen.cursor_position();
                self.replies.push(format!("\x1b[{};{}R", r + 1, col + 1).into_bytes());
            }
            ('n', None) if first == 5 => self.replies.push(b"\x1b[0n".to_vec()),
            ('c', None) => self.replies.push(b"\x1b[?1;2c".to_vec()),
            _ => {}
        }
    }
}

pub struct Terminal {
    parser: vt100::Parser<TermCallbacks>,
    rx: Receiver<Vec<u8>>,
    writer: Box<dyn Write + Send>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    pub exited: Option<String>,
    rows: u16,
    cols: u16,
    passwords: Vec<PwRule>,
    used: Vec<bool>,
    last_pw_prompt: Option<(u16, String)>,
    chain: VecDeque<String>,
    last_chain_prompt: Option<(u16, String)>,
    pub chain_done: usize,
    pub title: Option<String>,
    pub focus_next: bool,
    scroll_acc: f32,
    /// Session log file (text without terminal control codes).
    log: Option<std::fs::File>,
    log_state: u8,
    /// Recording for playback (asciicast v2: one JSON line per output chunk with its time).
    rec: Option<Recorder>,
}

/// Writes a session as an asciicast v2 file (`.cast`, the format asciinema plays too).
pub struct Recorder {
    file: std::fs::File,
    start: std::time::Instant,
    /// Bytes of a UTF-8 character cut at the end of the last chunk.
    carry: Vec<u8>,
}

impl Recorder {
    pub fn create(path: &std::path::Path, cols: u16, rows: u16, title: &str) -> Result<Recorder, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let header = serde_json::json!({ "version": 2, "width": cols, "height": rows, "timestamp": ts, "title": title });
        writeln!(file, "{header}").map_err(|e| e.to_string())?;
        Ok(Recorder { file, start: std::time::Instant::now(), carry: Vec::new() })
    }

    fn event(&mut self, kind: &str, data: &str) {
        let t = self.start.elapsed().as_secs_f64();
        let line = serde_json::json!([(t * 1000.0).round() / 1000.0, kind, data]);
        let _ = writeln!(self.file, "{line}");
    }

    pub fn output(&mut self, chunk: &[u8]) {
        let mut bytes = std::mem::take(&mut self.carry);
        bytes.extend_from_slice(chunk);
        let valid = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(), // cut character: keep for next time
            Err(_) => bytes.len(),
        };
        self.carry = bytes[valid..].to_vec();
        let text = String::from_utf8_lossy(&bytes[..valid]).into_owned();
        if !text.is_empty() {
            self.event("o", &text);
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.event("r", &format!("{cols}x{rows}"));
    }
}

pub(crate) fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap_or(NonZeroU16::MIN)
}

impl Terminal {
    pub fn spawn(cmd: CommandBuilder, ctx: egui::Context, passwords: Vec<PwRule>, chain: Vec<String>) -> Result<Terminal, String> {
        let rows = 30;
        let cols = 110;
        let pair = native_pty_system()
            .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| tf("Terminal could not be opened: {0}", &[&e]))?;
        let child = pair.slave.spawn_command(cmd).map_err(|e| tf("Program could not be started: {0}", &[&e]))?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 16384];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                        ctx.request_repaint();
                    }
                }
            }
        });
        Ok(Terminal {
            parser: vt100::Parser::new_with_callbacks(nz(rows), nz(cols), 5000, TermCallbacks::default()),
            rx,
            writer,
            master: pair.master,
            child,
            exited: None,
            rows,
            cols,
            used: vec![false; passwords.len()],
            passwords,
            last_pw_prompt: None,
            chain: chain.into(),
            last_chain_prompt: None,
            chain_done: 0,
            title: None,
            focus_next: true,
            scroll_acc: 0.0,
            log: None,
            log_state: 0,
            rec: None,
        })
    }

    /// Starts writing the session to `path` (appending).
    pub fn start_log(&mut self, path: &std::path::Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(|e| e.to_string())?;
        self.log = Some(f);
        Ok(())
    }

    /// Starts recording the session for playback.
    pub fn start_recording(&mut self, path: &std::path::Path, title: &str) -> Result<(), String> {
        self.rec = Some(Recorder::create(path, self.cols, self.rows, title)?);
        Ok(())
    }

    pub fn recording(&self) -> bool {
        self.rec.is_some()
    }

    /// Plain text of the output: escape sequences left out, CR LF kept as line ends.
    fn write_log(&mut self, chunk: &[u8]) {
        let Some(f) = self.log.as_mut() else { return };
        let mut out = Vec::with_capacity(chunk.len());
        for &b in chunk {
            match self.log_state {
                0 => match b {
                    0x1b => self.log_state = 1,
                    b'\r' | 0x07 | 0x08 => {}
                    _ => out.push(b),
                },
                1 => {
                    self.log_state = if b == b'[' {
                        2
                    } else if b == b']' {
                        3
                    } else {
                        0
                    }
                }
                2 => {
                    if (0x40..=0x7e).contains(&b) {
                        self.log_state = 0;
                    }
                }
                _ => {
                    if b == 0x07 || b == b'\\' {
                        self.log_state = 0;
                    }
                }
            }
        }
        let _ = f.write_all(&out);
    }

    pub fn send(&mut self, bytes: &[u8]) {
        if self.exited.is_some() {
            return;
        }
        let _ = self.writer.write_all(bytes);
        let _ = self.writer.flush();
    }

    /// Types the next password not used yet (or the target's again).
    pub fn send_password(&mut self) {
        let idx = self.used.iter().position(|u| !u).or_else(|| self.passwords.len().checked_sub(1));
        if let Some(i) = idx {
            let p = self.passwords[i].password.clone();
            self.used[i] = true;
            self.send(p.as_bytes());
            self.send(b"\r");
        }
    }

    pub fn has_password(&self) -> bool {
        !self.passwords.is_empty()
    }

    /// Types `cmd` at the next shell prompt (e.g. `sudo reboot` after logging in).
    pub fn queue_command(&mut self, cmd: String) {
        self.chain.push_back(cmd);
    }

    pub fn chain_left(&self) -> usize {
        self.chain.len()
    }

    /// Picks the password for a prompt such as "root@10.0.0.40's password:".
    fn pick_password(&self, line: &str) -> Option<usize> {
        let free = |i: &usize| !self.used[*i];
        let n = self.passwords.len();
        (0..n)
            .filter(free)
            .find(|&i| {
                let r = &self.passwords[i];
                !r.host.is_empty() && line.contains(&format!("{}@{}'", r.user.to_lowercase(), r.host.to_lowercase()))
            })
            .or_else(|| (0..n).filter(free).find(|&i| !self.passwords[i].host.is_empty() && line.contains(&self.passwords[i].host.to_lowercase())))
            .or_else(|| (0..n).find(|i| free(i)))
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
    }

    pub fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    /// Reads new output, answers terminal queries, types the stored password once when asked.
    pub fn pump(&mut self, auto_password: bool) {
        let mut got = false;
        while let Ok(chunk) = self.rx.try_recv() {
            self.parser.process(&chunk);
            self.write_log(&chunk);
            if let Some(r) = self.rec.as_mut() {
                r.output(&chunk);
            }
            got = true;
        }
        if got {
            let replies = std::mem::take(&mut self.parser.callbacks_mut().replies);
            for r in replies {
                self.send(&r);
            }
            if let Some(t) = self.parser.callbacks_mut().title.take() {
                self.title = Some(t);
            }
            let (row, line) = {
                let screen = self.parser.screen();
                let row = screen.cursor_position().0;
                let line = screen.rows(0, self.cols).nth(row as usize).unwrap_or_default();
                (row, line.trim_end().to_string())
            };
            let low = line.to_lowercase();
            let asks_pw = low.ends_with("password:")
                || low.ends_with("passwort:")
                || low.ends_with("kennwort:")
                || ((low.contains("password for") || low.contains("passwort für")) && low.ends_with(':'));
            let key = (row, line.clone());
            if asks_pw {
                if auto_password && self.last_pw_prompt.as_ref() != Some(&key) {
                    if let Some(i) = self.pick_password(&low) {
                        self.used[i] = true;
                        let p = self.passwords[i].password.clone();
                        self.send(p.as_bytes());
                        self.send(b"\r");
                    }
                    self.last_pw_prompt = Some(key);
                }
            } else if !self.chain.is_empty() && is_shell_prompt(&line) && self.last_chain_prompt.as_ref() != Some(&key) {
                if let Some(next) = self.chain.pop_front() {
                    self.send(next.as_bytes());
                    self.send(b"\r");
                    self.chain_done += 1;
                }
                self.last_chain_prompt = Some(key);
            }
        }
        if self.exited.is_none()
            && let Ok(Some(status)) = self.child.try_wait()
        {
            self.exited =
                Some(if status.success() { tr("Session ended.").to_string() } else { tf("Session ended (code {0}).", &[&(status.exit_code())]) });
        }
    }

    /// Draws the terminal; returns what was typed into it (for typing into several at once).
    pub fn ui(&mut self, ui: &mut egui::Ui, font_size: f32, dark: bool) -> Vec<u8> {
        let mut typed = Vec::new();
        let font = FontId::monospace(font_size);
        let (cw, ch) = ui.ctx().fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let cw = cw.max(1.0);
        let ch = ch.max(1.0);
        let avail = ui.available_size();
        let cols = ((avail.x - 8.0) / cw).floor().clamp(20.0, 500.0) as u16;
        let rows = ((avail.y - 8.0) / ch).floor().clamp(5.0, 300.0) as u16;
        if cols != self.cols || rows != self.rows {
            self.cols = cols;
            self.rows = rows;
            self.parser.set_size(nz(rows), nz(cols));
            let _ = self.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
            if let Some(r) = self.rec.as_mut() {
                r.resize(cols, rows);
            }
        }

        let (rect, resp) = ui.allocate_exact_size(avail, Sense::click());
        let id = resp.id;
        if resp.clicked() || self.focus_next {
            resp.request_focus();
            self.focus_next = false;
        }
        let focused = resp.has_focus();
        if focused {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true })
            });
            typed = self.handle_input(ui);
        }
        if resp.hovered() {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            if dy != 0.0 {
                self.scroll_acc += dy / ch;
                let lines = self.scroll_acc.trunc() as i64;
                if lines != 0 {
                    self.scroll_acc -= lines as f32;
                    let cur = self.parser.screen().scrollback() as i64;
                    let next = (cur + lines).max(0) as usize;
                    self.parser.screen_mut().set_scrollback(next);
                }
            }
        }
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Text);
        }

        let screen = self.parser.screen();
        let cursor = (self.exited.is_none()).then_some(focused);
        let painter = paint_screen(ui, rect, screen, rows, cols, &font, (cw, ch), dark, cursor);
        if screen.scrollback() > 0 {
            let t = tf("History: {0} lines back – press a key for current", &[&(screen.scrollback())]);
            painter.text(
                rect.right_top() + Vec2::new(-8.0, 6.0),
                egui::Align2::RIGHT_TOP,
                t,
                FontId::proportional(12.0),
                Color32::from_rgb(255, 200, 0),
            );
        }
        if focused {
            painter.rect_stroke(rect, 4.0, Stroke::new(1.0, Color32::from_rgb(33, 150, 243)), egui::StrokeKind::Inside);
        }
        typed
    }
}

/// Draws a terminal screen into `rect` (also used to play back recordings). `cursor`: None =
/// hidden, Some(true) = solid (focused), Some(false) = outline.
#[allow(clippy::too_many_arguments)]
pub fn paint_screen(
    ui: &egui::Ui,
    rect: Rect,
    screen: &vt100::Screen,
    rows: u16,
    cols: u16,
    font: &FontId,
    (cw, ch): (f32, f32),
    dark: bool,
    cursor: Option<bool>,
) -> egui::Painter {
    {
        let font = font.clone();
        let palette = Palette::new(dark);
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, palette.bg);
        let origin = rect.min + Vec2::new(4.0, 4.0);
        for r in 0..rows {
            let mut c = 0u16;
            while c < cols {
                let Some(cell) = screen.cell(r, c) else { break };
                let (fg, bg) = palette.cell_colors(cell);
                let bold = cell.bold();
                let start = c;
                let mut text = String::new();
                while c < cols {
                    let Some(cell2) = screen.cell(r, c) else { break };
                    if palette.cell_colors(cell2) != (fg, bg) || cell2.bold() != bold {
                        break;
                    }
                    if !cell2.is_wide_continuation() {
                        if cell2.has_contents() {
                            text.push_str(cell2.contents());
                        } else {
                            text.push(' ');
                        }
                    }
                    c += 1;
                }
                let x = origin.x + start as f32 * cw;
                let y = origin.y + r as f32 * ch;
                if bg != palette.bg {
                    painter.rect_filled(Rect::from_min_size(Pos2::new(x, y), Vec2::new((c - start) as f32 * cw, ch)), 0.0, bg);
                }
                if !text.trim().is_empty() {
                    let fgc = if bold { palette.brighten(fg) } else { fg };
                    painter.text(Pos2::new(x, y), egui::Align2::LEFT_TOP, text, font.clone(), fgc);
                }
            }
        }
        if let (Some(focused), false, 0) = (cursor, screen.hide_cursor(), screen.scrollback()) {
            let (cr, cc) = screen.cursor_position();
            let crect = Rect::from_min_size(Pos2::new(origin.x + cc as f32 * cw, origin.y + cr as f32 * ch), Vec2::new(cw, ch));
            if focused {
                painter.rect_filled(crect, 1.0, palette.cursor.gamma_multiply(0.7));
            } else {
                painter.rect_stroke(crect, 1.0, Stroke::new(1.0, palette.cursor), egui::StrokeKind::Inside);
            }
        }
        painter
    }
}

impl Terminal {
    fn handle_input(&mut self, ui: &mut egui::Ui) -> Vec<u8> {
        let events = ui.input(|i| i.events.clone());
        let app_cursor = self.parser.screen().application_cursor();
        let bracketed = self.parser.screen().bracketed_paste();
        let mut out: Vec<u8> = Vec::new();
        for ev in events {
            match ev {
                egui::Event::Text(t) => out.extend_from_slice(t.as_bytes()),
                egui::Event::Copy => out.push(0x03),
                egui::Event::Cut => out.push(0x18),
                egui::Event::Paste(t) => {
                    let t = t.replace("\r\n", "\r").replace('\n', "\r");
                    if bracketed {
                        out.extend_from_slice(b"\x1b[200~");
                        out.extend_from_slice(t.as_bytes());
                        out.extend_from_slice(b"\x1b[201~");
                    } else {
                        out.extend_from_slice(t.as_bytes());
                    }
                }
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    if let Some(b) = key_bytes(key, modifiers, app_cursor) {
                        out.extend_from_slice(&b);
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            self.parser.screen_mut().set_scrollback(0);
            self.send(&out);
        }
        out
    }
}

fn key_bytes(key: Key, m: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    let arrow = |c: u8| -> Vec<u8> {
        if m.ctrl {
            format!("\x1b[1;5{}", c as char).into_bytes()
        } else if app_cursor {
            vec![0x1b, b'O', c]
        } else {
            vec![0x1b, b'[', c]
        }
    };
    let s: &[u8] = match key {
        Key::Enter => b"\r",
        Key::Backspace => b"\x7f",
        Key::Tab => {
            if m.shift {
                b"\x1b[Z"
            } else {
                b"\t"
            }
        }
        Key::Escape => b"\x1b",
        Key::ArrowUp => return Some(arrow(b'A')),
        Key::ArrowDown => return Some(arrow(b'B')),
        Key::ArrowRight => return Some(arrow(b'C')),
        Key::ArrowLeft => return Some(arrow(b'D')),
        Key::Home => b"\x1b[H",
        Key::End => b"\x1b[F",
        Key::PageUp => b"\x1b[5~",
        Key::PageDown => b"\x1b[6~",
        Key::Delete => b"\x1b[3~",
        Key::Insert => b"\x1b[2~",
        Key::F1 => b"\x1bOP",
        Key::F2 => b"\x1bOQ",
        Key::F3 => b"\x1bOR",
        Key::F4 => b"\x1bOS",
        Key::F5 => b"\x1b[15~",
        Key::F6 => b"\x1b[17~",
        Key::F7 => b"\x1b[18~",
        Key::F8 => b"\x1b[19~",
        Key::F9 => b"\x1b[20~",
        Key::F10 => b"\x1b[21~",
        Key::F11 => b"\x1b[23~",
        Key::F12 => b"\x1b[24~",
        _ => {
            if m.ctrl && !m.alt {
                let name = key.name();
                if name.len() == 1 {
                    let c = name.as_bytes()[0].to_ascii_uppercase();
                    if c.is_ascii_uppercase() {
                        return Some(vec![c - b'A' + 1]);
                    }
                }
                return match key {
                    Key::OpenBracket => Some(vec![0x1b]),
                    Key::Backslash => Some(vec![0x1c]),
                    Key::CloseBracket => Some(vec![0x1d]),
                    Key::Space => Some(vec![0x00]),
                    _ => None,
                };
            }
            return None;
        }
    };
    Some(s.to_vec())
}

struct Palette {
    bg: Color32,
    fg: Color32,
    cursor: Color32,
    ansi: [Color32; 16],
}

impl Palette {
    fn new(dark: bool) -> Palette {
        let ansi = [
            Color32::from_rgb(0x1e, 0x1e, 0x1e),
            Color32::from_rgb(0xcd, 0x31, 0x31),
            Color32::from_rgb(0x0d, 0xbc, 0x79),
            Color32::from_rgb(0xe5, 0xe5, 0x10),
            Color32::from_rgb(0x24, 0x72, 0xc8),
            Color32::from_rgb(0xbc, 0x3f, 0xbc),
            Color32::from_rgb(0x11, 0xa8, 0xcd),
            Color32::from_rgb(0xcc, 0xcc, 0xcc),
            Color32::from_rgb(0x66, 0x66, 0x66),
            Color32::from_rgb(0xf1, 0x4c, 0x4c),
            Color32::from_rgb(0x23, 0xd1, 0x8b),
            Color32::from_rgb(0xf5, 0xf5, 0x43),
            Color32::from_rgb(0x3b, 0x8e, 0xea),
            Color32::from_rgb(0xd6, 0x70, 0xd6),
            Color32::from_rgb(0x29, 0xb8, 0xdb),
            Color32::from_rgb(0xff, 0xff, 0xff),
        ];
        if dark {
            Palette { bg: Color32::from_rgb(12, 14, 18), fg: Color32::from_rgb(220, 223, 228), cursor: Color32::from_rgb(120, 200, 255), ansi }
        } else {
            let mut ansi = ansi;
            ansi[7] = Color32::from_rgb(0x55, 0x55, 0x55);
            ansi[15] = Color32::from_rgb(0x22, 0x22, 0x22);
            ansi[3] = Color32::from_rgb(0x9a, 0x7b, 0x00);
            ansi[11] = Color32::from_rgb(0xa0, 0x80, 0x00);
            Palette { bg: Color32::from_rgb(250, 250, 248), fg: Color32::from_rgb(30, 30, 30), cursor: Color32::from_rgb(20, 90, 200), ansi }
        }
    }

    fn color(&self, c: vt100::Color, default: Color32) -> Color32 {
        match c {
            vt100::Color::Default => default,
            vt100::Color::Idx(i) => self.indexed(i),
            vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        }
    }

    fn indexed(&self, i: u8) -> Color32 {
        match i {
            0..=15 => self.ansi[i as usize],
            16..=231 => {
                let i = i - 16;
                let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
                Color32::from_rgb(level(i / 36), level((i / 6) % 6), level(i % 6))
            }
            _ => {
                let v = 8 + (i - 232) * 10;
                Color32::from_rgb(v, v, v)
            }
        }
    }

    fn cell_colors(&self, cell: &vt100::Cell) -> (Color32, Color32) {
        let fg = self.color(cell.fgcolor(), self.fg);
        let bg = self.color(cell.bgcolor(), self.bg);
        if cell.inverse() { (bg, fg) } else { (fg, bg) }
    }

    fn brighten(&self, c: Color32) -> Color32 {
        for i in 0..8 {
            if self.ansi[i] == c {
                return self.ansi[i + 8];
            }
        }
        c
    }
}
