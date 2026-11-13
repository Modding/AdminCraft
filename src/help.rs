//! The user guide: `docs/help/<language>.md`, built into the program and shown in a tab with a
//! table of contents. The same files are the documentation on GitHub. A file `help-<code>.md` in
//! the language folder replaces or adds a guide for that language.
//!
//! Only the Markdown the guide uses is understood: `#`/`##`/`###` headings, paragraphs, `-` and
//! `1.` lists (with indented continuation lines), `>` tips, fenced code blocks, `|` tables,
//! `**bold**`, `*italic*` and `` `code` ``. Image lines (`![...](...)`) are left out.

use crate::i18n::t as tr;
use eframe::egui;
use egui::text::LayoutJob;
use egui::{Color32, FontId, RichText, TextFormat};

const BUILTIN: &[(&str, &str)] = &[
    ("en", include_str!("../docs/help/en.md")),
    ("de", include_str!("../docs/help/de.md")),
    ("fr", include_str!("../docs/help/fr.md")),
    ("it", include_str!("../docs/help/it.md")),
    ("uk", include_str!("../docs/help/uk.md")),
];

/// The guide's text for a language: a file in the language folder first, then the built-in one,
/// else English.
pub fn text_for(code: &str) -> String {
    let own = crate::i18n::lang_dir().join(format!("help-{code}.md"));
    if let Ok(t) = std::fs::read_to_string(own) {
        return t.trim_start_matches('\u{feff}').to_string();
    }
    BUILTIN.iter().find(|(c, _)| *c == code).unwrap_or(&BUILTIN[0]).1.to_string()
}

/// The chapters of the guide (their position; the same in every language, a test checks it).
#[allow(dead_code)] // not every chapter has a "?" pointing to it yet
#[derive(Clone, Copy, Debug)]
pub enum Topic {
    Window = 0,
    FirstConnection = 1,
    Folders = 2,
    Protocols = 3,
    Passwords = 4,
    JumpHosts = 5,
    Files = 6,
    Tools = 7,
    NetworkScan = 8,
    Sharing = 9,
    Settings = 10,
    Portable = 11,
    Languages = 12,
    Keyboard = 13,
    Agents = 14,
    Problems = 15,
}

/// How many chapters every guide has.
#[cfg(test)]
pub const TOPIC_COUNT: usize = 16;

#[derive(Clone, Debug, PartialEq)]
pub enum Block {
    Title(String),
    Section(String),
    Sub(String),
    Para(String),
    Bullet(String),
    Numbered(String, String),
    Tip(String),
    Code(String),
    Table(Vec<Vec<String>>),
}

pub fn parse(md: &str) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    let mut lines = md.lines().map(|l| l.trim_end_matches('\r')).peekable();
    let mut para = String::new();
    let flush = |para: &mut String, out: &mut Vec<Block>| {
        if !para.trim().is_empty() {
            out.push(Block::Para(para.trim().to_string()));
        }
        para.clear();
    };
    while let Some(line) = lines.next() {
        let t = line.trim();
        if t.starts_with("```") {
            flush(&mut para, &mut out);
            let mut code = Vec::new();
            for l in lines.by_ref() {
                if l.trim_start().starts_with("```") {
                    break;
                }
                code.push(l);
            }
            out.push(Block::Code(code.join("\n")));
        } else if t.is_empty() || t.starts_with("![") {
            flush(&mut para, &mut out);
        } else if let Some(h) = t.strip_prefix("### ") {
            flush(&mut para, &mut out);
            out.push(Block::Sub(h.to_string()));
        } else if let Some(h) = t.strip_prefix("## ") {
            flush(&mut para, &mut out);
            out.push(Block::Section(h.to_string()));
        } else if let Some(h) = t.strip_prefix("# ") {
            flush(&mut para, &mut out);
            out.push(Block::Title(h.to_string()));
        } else if let Some(x) = t.strip_prefix("> ").or_else(|| (t == ">").then_some("")) {
            flush(&mut para, &mut out);
            match out.last_mut() {
                Some(Block::Tip(prev)) if !x.is_empty() => {
                    prev.push(' ');
                    prev.push_str(x);
                }
                _ => out.push(Block::Tip(x.to_string())),
            }
        } else if t.starts_with('|') {
            flush(&mut para, &mut out);
            let cells: Vec<String> = t.trim_matches('|').split('|').map(|c| c.trim().to_string()).collect();
            if cells.iter().all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':')) {
                continue; // the |---|---| line under the header
            }
            match out.last_mut() {
                Some(Block::Table(rows)) => rows.push(cells),
                _ => out.push(Block::Table(vec![cells])),
            }
        } else if let Some(x) = t.strip_prefix("- ") {
            flush(&mut para, &mut out);
            out.push(Block::Bullet(x.to_string()));
        } else if let Some((n, x)) = numbered(t) {
            flush(&mut para, &mut out);
            out.push(Block::Numbered(n, x));
        } else if line.starts_with("  ") && para.is_empty() {
            // continuation of a list item
            match out.last_mut() {
                Some(Block::Bullet(s)) | Some(Block::Numbered(_, s)) => {
                    s.push(' ');
                    s.push_str(t);
                }
                _ => para.push_str(t),
            }
        } else {
            if !para.is_empty() {
                para.push(' ');
            }
            para.push_str(t);
        }
    }
    flush(&mut para, &mut out);
    out
}

fn numbered(t: &str) -> Option<(String, String)> {
    let (n, rest) = t.split_once(". ")?;
    (!n.is_empty() && n.len() <= 2 && n.chars().all(|c| c.is_ascii_digit())).then(|| (n.to_string(), rest.to_string()))
}

/// The sections (`##`) with the index of their block.
pub fn sections(blocks: &[Block]) -> Vec<(String, usize)> {
    blocks
        .iter()
        .enumerate()
        .filter_map(|(i, b)| match b {
            Block::Section(s) => Some((plain(s), i)),
            _ => None,
        })
        .collect()
}

/// Text without the Markdown marks (for the contents and the search).
pub fn plain(s: &str) -> String {
    s.replace("**", "").replace('`', "").replace('*', "")
}

fn block_text(b: &Block) -> String {
    match b {
        Block::Title(s) | Block::Section(s) | Block::Sub(s) | Block::Para(s) | Block::Bullet(s) | Block::Tip(s) | Block::Code(s) => s.clone(),
        Block::Numbered(_, s) => s.clone(),
        Block::Table(rows) => rows.iter().flatten().cloned().collect::<Vec<_>>().join(" "),
    }
}

pub struct HelpTab {
    code: String,
    blocks: Vec<Block>,
    toc: Vec<(String, usize)>,
    jump: Option<usize>,
    current: usize,
    search: String,
}

impl HelpTab {
    pub fn new() -> Self {
        let mut h = HelpTab { code: String::new(), blocks: Vec::new(), toc: Vec::new(), jump: None, current: 0, search: String::new() };
        h.load();
        h
    }

    fn load(&mut self) {
        self.code = crate::i18n::current();
        self.blocks = parse(&text_for(&self.code));
        self.toc = sections(&self.blocks);
    }

    /// Jumps to the n-th section.
    pub fn open_section(&mut self, n: usize) {
        self.jump = self.toc.get(n).map(|(_, i)| *i);
    }

    /// Which sections contain the search text (all when it is empty).
    fn matching(&self) -> Vec<bool> {
        let q = self.search.trim().to_lowercase();
        self.toc
            .iter()
            .enumerate()
            .map(|(n, (_, start))| {
                if q.is_empty() {
                    return true;
                }
                let end = self.toc.get(n + 1).map(|x| x.1).unwrap_or(self.blocks.len());
                self.blocks[*start..end].iter().any(|b| plain(&block_text(b)).to_lowercase().contains(&q))
            })
            .collect()
    }
}

/// Draws the guide: contents on the left, the text on the right.
pub fn help_ui(ui: &mut egui::Ui, h: &mut HelpTab) {
    if h.code != crate::i18n::current() {
        h.load();
    }
    let accent = Color32::from_rgb(33, 150, 243);
    let height = ui.available_height();
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(230.0);
            ui.set_min_height(height);
            ui.add(egui::TextEdit::singleline(&mut h.search).hint_text(tr("Search the guide …")).desired_width(220.0));
            ui.add_space(6.0);
            let matching = h.matching();
            egui::ScrollArea::vertical().id_salt("help_toc").auto_shrink([false, false]).show(ui, |ui| {
                for (n, (title, idx)) in h.toc.iter().enumerate() {
                    if !matching[n] {
                        continue;
                    }
                    let here = h.current == *idx;
                    let text = if here { RichText::new(title).color(accent).strong() } else { RichText::new(title) };
                    if ui.add(egui::Button::selectable(here, text).wrap()).clicked() {
                        h.jump = Some(*idx);
                    }
                }
                if !matching.iter().any(|m| *m) {
                    ui.weak(tr("Nothing found."));
                }
            });
        });
        ui.separator();
        let jump = h.jump.take();
        let mut first_visible: Option<usize> = None;
        // width of the text column: what is left of the window next to the contents (and of this
        // panel), at most a readable 860 px
        let window_left = ui.clip_rect().right().min(ui.ctx().content_rect().right()) - ui.cursor().left() - 20.0;
        let text_w = ui.available_width().min(window_left).clamp(240.0, 860.0);
        egui::ScrollArea::vertical().id_salt("help_text").auto_shrink([false, false]).show(ui, |ui| ui.vertical(|ui| {
            ui.set_width(text_w);
            let top = ui.clip_rect().top();
            let mut section = 0;
            for (i, b) in h.blocks.iter().enumerate() {
                if matches!(b, Block::Section(_)) {
                    section = i;
                }
                let r = block_ui(ui, b, accent, text_w);
                if jump == Some(i) {
                    r.scroll_to_me(Some(egui::Align::TOP));
                }
                if first_visible.is_none() && r.rect.bottom() > top + 40.0 {
                    first_visible = Some(section);
                }
            }
            ui.add_space(height * 0.5);
        }));
        if let Some(i) = jump.or(first_visible) {
            h.current = i;
        }
    });
}

fn block_ui(ui: &mut egui::Ui, b: &Block, accent: Color32, w: f32) -> egui::Response {
    match b {
        Block::Title(s) => {
            let r = ui.label(RichText::new(plain(s)).size(26.0).strong());
            ui.add_space(6.0);
            r
        }
        Block::Section(s) => {
            ui.add_space(14.0);
            let r = ui.label(RichText::new(plain(s)).size(20.0).color(accent).strong());
            ui.separator();
            r
        }
        Block::Sub(s) => {
            ui.add_space(8.0);
            ui.label(RichText::new(plain(s)).size(16.0).strong())
        }
        Block::Para(s) => {
            let r = ui.add(egui::Label::new(inline(ui, s, 14.5, w)).wrap());
            ui.add_space(6.0);
            r
        }
        Block::Bullet(s) => ui
            .horizontal_top(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("•").size(14.5).color(accent));
                ui.add(egui::Label::new(inline(ui, s, 14.5, w - 24.0)).wrap());
            })
            .response,
        Block::Numbered(n, s) => ui
            .horizontal_top(|ui| {
                ui.add_space(4.0);
                ui.label(RichText::new(format!("{n}.")).size(14.5).color(accent).strong());
                ui.add(egui::Label::new(inline(ui, s, 14.5, w - 30.0)).wrap());
            })
            .response,
        Block::Tip(s) => {
            ui.add_space(4.0);
            let r = egui::Frame::new()
                .fill(accent.gamma_multiply(0.12))
                .stroke(egui::Stroke::new(1.0, accent.gamma_multiply(0.5)))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(inline(ui, s, 14.0, w - 26.0)).wrap());
                })
                .response;
            ui.add_space(6.0);
            r
        }
        Block::Code(s) => {
            let r = egui::Frame::new()
                .fill(ui.visuals().extreme_bg_color)
                .corner_radius(6.0)
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::ScrollArea::horizontal().id_salt(s.len() ^ s.lines().count()).show(ui, |ui| {
                        ui.add(egui::Label::new(RichText::new(s).monospace().size(13.0)).extend());
                    });
                })
                .response;
            ui.add_space(6.0);
            r
        }
        Block::Table(rows) => {
            let r = egui::Grid::new(block_text(b).len())
                .striped(true)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    for (n, row) in rows.iter().enumerate() {
                        for cell in row {
                            if n == 0 {
                                ui.label(RichText::new(plain(cell)).strong().color(accent));
                            } else {
                                ui.add(egui::Label::new(inline(ui, cell, 14.0, w * 0.6)).wrap());
                            }
                        }
                        ui.end_row();
                    }
                })
                .response;
            ui.add_space(8.0);
            r
        }
    }
}

/// `**bold**`, `*italic*` and `` `code` `` inside a line.
fn inline(ui: &egui::Ui, s: &str, size: f32, max_w: f32) -> LayoutJob {
    let normal = ui.visuals().text_color();
    let strong = ui.visuals().strong_text_color();
    let code_bg = ui.visuals().extreme_bg_color;
    let mut job = LayoutJob::default();
    job.wrap.max_width = ui.available_width().min(max_w).max(120.0);
    let (mut bold, mut italic) = (false, false);
    let mut rest = s;
    let mut buf = String::new();
    let push = |job: &mut LayoutJob, text: &str, bold: bool, italic: bool| {
        if text.is_empty() {
            return;
        }
        job.append(
            text,
            0.0,
            TextFormat {
                font_id: FontId::proportional(size),
                color: if bold { strong } else { normal },
                italics: italic,
                ..Default::default()
            },
        );
    };
    while let Some(c) = rest.chars().next() {
        if rest.starts_with("**") {
            push(&mut job, &buf, bold, italic);
            buf.clear();
            bold = !bold;
            rest = &rest[2..];
        } else if c == '`' {
            push(&mut job, &buf, bold, italic);
            buf.clear();
            let after = &rest[1..];
            let end = after.find('`').unwrap_or(after.len());
            job.append(
                &after[..end],
                0.0,
                TextFormat { font_id: FontId::monospace(size - 1.0), color: strong, background: code_bg, ..Default::default() },
            );
            rest = after.get(end + 1..).unwrap_or("");
        } else if c == '*' {
            push(&mut job, &buf, bold, italic);
            buf.clear();
            italic = !italic;
            rest = &rest[1..];
        } else {
            buf.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    push(&mut job, &buf, bold, italic);
    job
}

#[cfg(test)]
pub fn builtin() -> &'static [(&'static str, &'static str)] {
    BUILTIN
}
