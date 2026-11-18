//! A terminal tab: runs ssh / telnet / PowerShell / a shell on a pseudo terminal and draws it.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::launch::PwRule;
use eframe::egui::{self, Color32, FontId, Key, Pos2, Rect, Sense, Stroke, Vec2};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::collections::VecDeque;
use std::io::{BufWriter, Read, Write};
use std::time::{Duration, Instant};

/// Most output bytes one `pump` call feeds into the screen; the rest waits for the next frame.
const PUMP_BYTES: usize = 1024 * 1024;
/// Most time one `pump` call spends on output.
const PUMP_TIME: Duration = Duration::from_millis(8);
/// How often a running program is asked whether it ended (when no output says so).
const EXIT_CHECK: Duration = Duration::from_millis(100);
/// Session logs and recordings reach the disk about this often.
const FLUSH_EVERY: Duration = Duration::from_secs(1);

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
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};

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
    /// Output chunks with the moment the reader thread got them.
    rx: Receiver<(Instant, Vec<u8>)>,
    /// A chunk taken from `rx` that did not fit into the last `pump` any more.
    pending: Option<(Instant, Vec<u8>)>,
    /// The reader thread has ended (end of output).
    reader_done: bool,
    /// Bytes for the program, written by the writer thread in this order.
    input: Sender<Vec<u8>>,
    ctx: egui::Context,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    last_exit_check: Instant,
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
    log: Option<SessionLog>,
    /// Recording for playback (asciicast v2: one JSON line per output chunk with its time).
    rec: Option<Recorder>,
}

/// A buffered file that reaches the disk about once a second (and when dropped).
struct TimedWriter {
    w: BufWriter<std::fs::File>,
    dirty: bool,
    last_flush: Instant,
}

impl TimedWriter {
    fn new(file: std::fs::File) -> TimedWriter {
        TimedWriter { w: BufWriter::with_capacity(64 * 1024, file), dirty: false, last_flush: Instant::now() }
    }

    fn write(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() && self.w.write_all(bytes).is_ok() {
            self.dirty = true;
        }
    }

    /// Flushes when the last flush is a second ago; otherwise returns how long until it is due.
    fn tick(&mut self) -> Option<Duration> {
        if !self.dirty {
            return None;
        }
        let since = self.last_flush.elapsed();
        if since >= FLUSH_EVERY {
            let _ = self.w.flush();
            self.dirty = false;
            self.last_flush = Instant::now();
            None
        } else {
            Some(FLUSH_EVERY - since)
        }
    }
}

/// The session log: plain text, escape sequences left out.
struct SessionLog {
    out: TimedWriter,
    state: u8,
    buf: Vec<u8>,
}

/// Leaves terminal control codes out of `chunk` and appends the text to `out`. `state` carries
/// a sequence cut between two chunks (start with 0). Handles CSI (`ESC [` … final byte), escapes
/// with intermediate bytes (`ESC ( B`), and strings ended by ST or BEL: OSC (`ESC ]`), DCS
/// (`ESC P`), SOS (`ESC X`), PM (`ESC ^`) and APC (`ESC _`). CR, BEL and BS are dropped too.
pub fn strip_escapes(state: &mut u8, chunk: &[u8], out: &mut Vec<u8>) {
    // states: 0 text, 1 after ESC, 2 CSI, 3 OSC, 4 ESC intermediates, 5 DCS/SOS/PM/APC,
    // 6 ESC inside OSC, 7 ESC inside DCS/SOS/PM/APC
    for &b in chunk {
        if *state != 0 && matches!(b, 0x18 | 0x1a) {
            // CAN and SUB cancel any sequence
            *state = 0;
            continue;
        }
        *state = match *state {
            0 => match b {
                0x1b => 1,
                b'\r' | 0x07 | 0x08 => 0,
                _ => {
                    out.push(b);
                    0
                }
            },
            1 => after_esc(b),
            2 => match b {
                0x40..=0x7e => 0,
                0x1b => 1,
                _ => 2,
            },
            3 => match b {
                0x07 => 0,
                0x1b => 6,
                _ => 3,
            },
            4 => match b {
                0x20..=0x2f => 4,
                0x1b => 1,
                _ => 0,
            },
            5 => match b {
                0x1b => 7,
                _ => 5,
            },
            6 | 7 => match b {
                b'\\' => 0,
                // ESC inside a string that is not ST: the string ends, a new escape starts
                _ => after_esc(b),
            },
            _ => 0,
        };
    }
}

fn after_esc(b: u8) -> u8 {
    match b {
        b'[' => 2,
        b']' => 3,
        b'P' | b'X' | b'^' | b'_' => 5,
        0x20..=0x2f => 4,
        0x1b => 1,
        _ => 0,
    }
}

/// Writes a session as an asciicast v2 file (`.cast`, the format asciinema plays too).
pub struct Recorder {
    out: TimedWriter,
    start: Instant,
    /// Bytes of a UTF-8 character cut at the end of the last chunk.
    carry: Vec<u8>,
}

impl Recorder {
    pub fn create(path: &std::path::Path, cols: u16, rows: u16, title: &str) -> Result<Recorder, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
        let mut out = TimedWriter::new(file);
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let header = serde_json::json!({ "version": 2, "width": cols, "height": rows, "timestamp": ts, "title": title });
        writeln!(out.w, "{header}").map_err(|e| e.to_string())?;
        out.dirty = true;
        Ok(Recorder { out, start: Instant::now(), carry: Vec::new() })
    }

    fn event(&mut self, kind: &str, data: &str, at: Instant) {
        let t = at.saturating_duration_since(self.start).as_secs_f64();
        let line = serde_json::json!([(t * 1000.0).round() / 1000.0, kind, data]);
        let mut text = line.to_string();
        text.push('\n');
        self.out.write(text.as_bytes());
    }

    /// Output that arrives now (tests; the terminal passes the reader thread's time).
    #[cfg(test)]
    pub fn output(&mut self, chunk: &[u8]) {
        self.output_at(chunk, Instant::now());
    }

    /// Output that arrived at `at` (the reader thread's time, not when the screen got it).
    pub fn output_at(&mut self, chunk: &[u8], at: Instant) {
        let mut bytes = std::mem::take(&mut self.carry);
        bytes.extend_from_slice(chunk);
        let valid = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(), // cut character: keep for next time
            Err(_) => bytes.len(),
        };
        self.carry = bytes.split_off(valid.min(bytes.len()));
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !text.is_empty() {
            self.event("o", &text, at);
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.event("r", &format!("{cols}x{rows}"), Instant::now());
    }

    /// Writes buffered events when the last write to disk is a second ago; otherwise returns
    /// how long until then (None: nothing waits).
    pub fn flush_due(&mut self) -> Option<Duration> {
        self.out.tick()
    }
}

/// The host a password prompt names, with the user before it, both in lower case:
/// `root@10.0.0.4's password:`, `(root@10.0.0.4) Password:`, `Password for root@db01:`.
/// None when the prompt names no host (`Password:`, `[sudo] password for alice:`).
pub fn prompt_host(prompt: &str) -> Option<(String, String)> {
    let low = prompt.to_lowercase();
    let at = low.rfind('@')?;
    let (before, after) = low.split_at(at);
    let after = after.strip_prefix('@').unwrap_or(after);
    let host: String = after.chars().take_while(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']' | '%')).collect();
    let host = norm_host(&host);
    if host.is_empty() {
        return None;
    }
    let mut user: Vec<char> = before.chars().rev().take_while(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '\\' | '$' | '@')).collect();
    user.reverse();
    Some((user.into_iter().collect(), host))
}

/// A host for comparing: lower case, without brackets, a trailing `:` or `.`.
fn norm_host(h: &str) -> String {
    h.trim().trim_end_matches([':', '.']).trim_start_matches('[').trim_end_matches(']').to_lowercase()
}

/// Which password rule may answer `prompt`. A prompt that names a host is answered only by an
/// unused rule for exactly that host (the whole name: `10.0.0.4` is not `10.0.0.40`), the one
/// with the same user first. A prompt without a host is answered only when there is a single
/// rule. A rule is never typed twice, and nothing is typed when no rule fits.
pub fn pick_password(rules: &[PwRule], used: &[bool], prompt: &str) -> Option<usize> {
    let free = |i: usize| used.get(i).is_some_and(|u| !u);
    match prompt_host(prompt) {
        Some((user, host)) => {
            let hits: Vec<usize> = (0..rules.len())
                .filter(|&i| free(i) && rules.get(i).is_some_and(|r| !r.host.trim().is_empty() && norm_host(&r.host) == host))
                .collect();
            hits.iter()
                .copied()
                .find(|&i| !user.is_empty() && rules.get(i).is_some_and(|r| r.user.trim().to_lowercase() == user))
                .or_else(|| hits.first().copied())
        }
        None => (rules.len() == 1 && free(0)).then_some(0),
    }
}

/// What a paste sends to the program: line ends as CR, ESC removed (pasted text must not end a
/// bracketed paste early or send its own escape sequences), wrapped in the bracketed-paste
/// markers when the program asked for them.
pub fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    let t = text.replace("\r\n", "\r").replace('\n', "\r");
    let mut out = Vec::with_capacity(t.len() + 12);
    if bracketed {
        out.extend_from_slice(b"\x1b[200~");
    }
    // ESC, and its 8-bit form CSI (U+009B)
    for ch in t.chars().filter(|c| *c != '\x1b' && *c != '\u{9b}') {
        let mut b = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
    }
    if bracketed {
        out.extend_from_slice(b"\x1b[201~");
    }
    out
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
        let mut child = pair.slave.spawn_command(cmd).map_err(|e| tf("Program could not be started: {0}", &[&e]))?;
        drop(pair.slave);
        let started = (|| {
            let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
            let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;
            let (tx, rx) = channel();
            let reader_ctx = ctx.clone();
            std::thread::Builder::new()
                .name("terminal-read".into())
                .spawn(move || {
                    let mut buf = [0u8; 16384];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let chunk = buf.get(..n).unwrap_or(&buf[..]).to_vec();
                                if tx.send((Instant::now(), chunk)).is_err() {
                                    break;
                                }
                                reader_ctx.request_repaint();
                            }
                        }
                    }
                    // the end of the output: let the tab notice soon
                    reader_ctx.request_repaint();
                })
                .map_err(|e| tf("Terminal could not be opened: {0}", &[&e]))?;
            // Writes go through their own thread: a program that reads slowly (a large paste
            // into a slow session) must not stop the window.
            let (input, queue) = channel::<Vec<u8>>();
            std::thread::Builder::new()
                .name("terminal-write".into())
                .spawn(move || {
                    while let Ok(bytes) = queue.recv() {
                        if writer.write_all(&bytes).is_err() || writer.flush().is_err() {
                            break;
                        }
                    }
                })
                .map_err(|e| tf("Terminal could not be opened: {0}", &[&e]))?;
            Ok::<_, String>((rx, input))
        })();
        let (rx, input) = match started {
            Ok(v) => v,
            Err(e) => {
                let _ = child.kill();
                return Err(e);
            }
        };
        Ok(Terminal {
            parser: vt100::Parser::new_with_callbacks(nz(rows), nz(cols), 5000, TermCallbacks::default()),
            rx,
            pending: None,
            reader_done: false,
            input,
            ctx,
            master: pair.master,
            child,
            last_exit_check: Instant::now(),
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
            rec: None,
        })
    }

    /// Starts writing the session to `path` (appending).
    pub fn start_log(&mut self, path: &std::path::Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(|e| e.to_string())?;
        self.log = Some(SessionLog { out: TimedWriter::new(f), state: 0, buf: Vec::new() });
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
        let Some(log) = self.log.as_mut() else { return };
        log.buf.clear();
        strip_escapes(&mut log.state, chunk, &mut log.buf);
        log.out.write(&log.buf);
    }

    /// Queues bytes for the program (the writer thread sends them in order; never blocks).
    pub fn send(&mut self, bytes: &[u8]) {
        if self.exited.is_some() || bytes.is_empty() {
            return;
        }
        let _ = self.input.send(bytes.to_vec());
    }

    /// Types a password and Enter.
    fn type_password(&mut self, i: usize) {
        let Some(rule) = self.passwords.get(i) else { return };
        let mut b = Vec::with_capacity(rule.password.len() + 1);
        b.extend_from_slice(rule.password.as_bytes());
        b.push(b'\r');
        if let Some(u) = self.used.get_mut(i) {
            *u = true;
        }
        self.send(&b);
    }

    /// Types the next password not used yet (or the target's again); the "Send password" button.
    pub fn send_password(&mut self) {
        let idx = self.used.iter().position(|u| !u).or_else(|| self.passwords.len().checked_sub(1));
        if let Some(i) = idx {
            self.type_password(i);
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

    pub fn kill(&mut self) {
        let _ = self.child.kill();
    }

    pub fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    /// The next output chunk: the one left over from the last call, else a new one.
    fn next_chunk(&mut self) -> Option<(Instant, Vec<u8>)> {
        if let Some(c) = self.pending.take() {
            return Some(c);
        }
        match self.rx.try_recv() {
            Ok(c) => Some(c),
            Err(TryRecvError::Disconnected) => {
                self.reader_done = true;
                None
            }
            Err(TryRecvError::Empty) => None,
        }
    }

    /// Reads new output, answers terminal queries, types the stored password once when asked.
    /// Call it every frame for every terminal, shown or not: it handles at most about 1 MiB or
    /// 8 ms of output per call (and asks for another frame when more waits), and costs next to
    /// nothing when nothing arrived.
    pub fn pump(&mut self, auto_password: bool) {
        let started = Instant::now();
        let mut fed = 0usize;
        let mut got = false;
        while let Some((at, chunk)) = self.next_chunk() {
            if got && (fed + chunk.len() > PUMP_BYTES || started.elapsed() >= PUMP_TIME) {
                self.pending = Some((at, chunk));
                self.ctx.request_repaint();
                break;
            }
            fed += chunk.len();
            self.parser.process(&chunk);
            self.write_log(&chunk);
            if let Some(r) = self.rec.as_mut() {
                r.output_at(&chunk, at);
            }
            got = true;
        }
        if got {
            self.after_output(auto_password);
        }
        let due = [self.log.as_mut().and_then(|l| l.out.tick()), self.rec.as_mut().and_then(|r| r.flush_due())].into_iter().flatten().min();
        if let Some(wait) = due {
            self.ctx.request_repaint_after(wait);
        }
        if self.exited.is_none() && (self.reader_done || got || self.last_exit_check.elapsed() >= EXIT_CHECK) {
            self.last_exit_check = Instant::now();
            if let Ok(Some(status)) = self.child.try_wait() {
                self.exited =
                    Some(if status.success() { tr("Session ended.").to_string() } else { tf("Session ended (code {0}).", &[&(status.exit_code())]) });
                if let Some(l) = self.log.as_mut() {
                    let _ = l.out.w.flush();
                }
                if let Some(r) = self.rec.as_mut() {
                    let _ = r.out.w.flush();
                }
            }
        }
    }

    /// After new output: answers terminal queries, takes the title, types a password or the
    /// next chained command when the cursor line asks for it.
    fn after_output(&mut self, auto_password: bool) {
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
            let line = screen.contents_between(row, 0, row, self.cols);
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
                if let Some(i) = pick_password(&self.passwords, &self.used, &low) {
                    self.type_password(i);
                }
                self.last_pw_prompt = Some(key);
            }
        } else if !self.chain.is_empty() && is_shell_prompt(&line) && self.last_chain_prompt.as_ref() != Some(&key) {
            if let Some(next) = self.chain.pop_front() {
                let mut b = next.into_bytes();
                b.push(b'\r');
                self.send(&b);
                self.chain_done += 1;
            }
            self.last_chain_prompt = Some(key);
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
        let palette = Palette::new(dark);
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, palette.bg);
        let origin = rect.min + Vec2::new(4.0, 4.0);
        // Non-ASCII characters whose glyph is exactly one cell wide may stay inside a run; any
        // other (wide, from a fallback font, combined) is drawn alone at its own column.
        let mut odd: Vec<char> = Vec::new();
        'scan: for r in 0..rows {
            for c in 0..cols {
                let Some(cell) = screen.cell(r, c) else { break };
                if cell.is_wide() || cell.is_wide_continuation() {
                    continue;
                }
                let mut it = cell.contents().chars();
                if let (Some(ch), None) = (it.next(), it.next())
                    && !ch.is_ascii()
                    && !odd.contains(&ch)
                {
                    odd.push(ch);
                    if odd.len() >= 256 {
                        break 'scan;
                    }
                }
            }
        }
        let mut fits: Vec<char> = if odd.is_empty() {
            Vec::new()
        } else {
            ui.ctx().fonts_mut(|f| odd.into_iter().filter(|ch| (f.glyph_width(font, *ch) - cw).abs() < 0.5).collect())
        };
        fits.sort_unstable();
        for_each_run(screen, rows, cols, &|ch| fits.binary_search(&ch).is_ok(), |r, start, width, text, cell| {
            let (fg, bg) = palette.cell_colors(cell);
            let x = origin.x + start as f32 * cw;
            let y = origin.y + r as f32 * ch;
            if bg != palette.bg {
                painter.rect_filled(Rect::from_min_size(Pos2::new(x, y), Vec2::new(width as f32 * cw, ch)), 0.0, bg);
            }
            if !text.trim().is_empty() {
                let fgc = if cell.bold() { palette.brighten(fg) } else { fg };
                painter.text(Pos2::new(x, y), egui::Align2::LEFT_TOP, text, font.clone(), fgc);
            }
        });
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

/// Splits the screen into runs drawn with one text call each: `f(row, column, cells, text,
/// first cell)`. A run holds cells that look the same; a wide cell, or a character `inline`
/// refuses (not exactly one cell wide in the font), gets a run of its own, so the text after it
/// stays on the cell grid. A wide cell's run covers both of its cells.
pub(crate) fn for_each_run(
    screen: &vt100::Screen,
    rows: u16,
    cols: u16,
    inline: &dyn Fn(char) -> bool,
    mut f: impl FnMut(u16, u16, u16, &str, &vt100::Cell),
) {
    let same_look = |a: &vt100::Cell, b: &vt100::Cell| {
        a.fgcolor() == b.fgcolor() && a.bgcolor() == b.bgcolor() && a.bold() == b.bold() && a.inverse() == b.inverse()
    };
    let fits = |s: &str| {
        if s.is_ascii() {
            return true;
        }
        let mut it = s.chars();
        matches!((it.next(), it.next()), (Some(ch), None) if inline(ch))
    };
    let mut text = String::with_capacity(usize::from(cols));
    for r in 0..rows {
        let mut c = 0u16;
        while c < cols {
            let Some(first) = screen.cell(r, c) else { break };
            let start = c;
            text.clear();
            while c < cols {
                let Some(cell) = screen.cell(r, c) else { break };
                if c > start && !same_look(first, cell) {
                    break;
                }
                if cell.is_wide_continuation() {
                    // only met when its wide cell was not drawn: a blank cell of its own
                    if c == start {
                        c += 1;
                    }
                    break;
                }
                let s = cell.contents();
                let alone = cell.is_wide() || !fits(s);
                if alone && c > start {
                    break;
                }
                if s.is_empty() {
                    text.push(' ');
                } else {
                    text.push_str(s);
                }
                c += 1;
                if alone {
                    if cell.is_wide() && c < cols {
                        c += 1;
                    }
                    break;
                }
            }
            f(r, start, c - start, &text, first);
        }
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
                egui::Event::Copy => out.extend(clipboard_key_bytes(0x03, cfg!(target_os = "macos"))),
                egui::Event::Cut => out.extend(clipboard_key_bytes(0x18, cfg!(target_os = "macos"))),
                egui::Event::Paste(t) => out.extend(paste_bytes(&t, bracketed)),
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

/// What egui's "copy" / "cut" (Ctrl+C / Ctrl+X, on macOS Cmd+C / Cmd+X) sends to the program.
/// On Windows and Linux that is Ctrl+C itself, the interrupt. On macOS it is Cmd+C, which people
/// press to copy: it must not stop the running command (Ctrl+C there arrives as a normal key).
pub fn clipboard_key_bytes(control: u8, macos: bool) -> Option<u8> {
    if macos { None } else { Some(control) }
}

pub(crate) fn key_bytes(key: Key, m: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
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
