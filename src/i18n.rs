//! Languages. The German text in the program is the key; a language file maps it to another
//! language. English is built in; more languages are plain text files in the folder
//! "AdminCraftLang" next to the program (`xx.lang`, see LIESMICH/README there).
//!
//! File format (UTF-8):
//!   # comment
//!   @name = English
//!   @code = en
//!   Verbindungen = Connections
//!   {0} Verbindungen importiert. = {0} connections imported.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};

const BUILTIN_EN: &str = include_str!("../lang/en.lang");

static TABLE: LazyLock<RwLock<HashMap<String, &'static str>>> = LazyLock::new(|| RwLock::new(HashMap::new()));
static CURRENT: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("de".to_string()));

/// Translates a German UI text (returns it unchanged when the language has no entry).
pub fn t(s: &'static str) -> &'static str {
    match TABLE.read() {
        Ok(map) => map.get(s).copied().unwrap_or(s),
        Err(_) => s,
    }
}

/// Translates and fills {0}, {1} ... placeholders.
pub fn tf(s: &'static str, args: &[&dyn std::fmt::Display]) -> String {
    // one pass, so a value that itself contains "{1}" stays as it is
    let tpl = t(s);
    let mut out = String::with_capacity(tpl.len() + 16);
    let mut rest = tpl;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}').map(|close| (close, after[..close].parse::<usize>())) {
            Some((close, Ok(i))) if i < args.len() => {
                out.push_str(&args[i].to_string());
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn current() -> String {
    CURRENT.read().map(|c| c.clone()).unwrap_or_else(|_| "de".into())
}

#[derive(Clone, Debug)]
pub struct LangInfo {
    pub code: String,
    pub name: String,
    /// Where it comes from: "eingebaut" or the file path.
    pub source: String,
}

struct Parsed {
    name: String,
    code: String,
    map: HashMap<String, String>,
}

fn unescape(s: &str) -> String {
    s.replace("\\n", "\n")
}

fn parse(text: &str) -> Parsed {
    let mut p = Parsed { name: String::new(), code: String::new(), map: HashMap::new() };
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // " => " for texts that contain " = " themselves, else the first " = "
        let Some((k, v)) = line.split_once(" => ").or_else(|| line.split_once(" = ")) else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "@name" => p.name = v.to_string(),
            "@code" => p.code = v.to_lowercase(),
            _ if !v.is_empty() => {
                p.map.insert(unescape(k), unescape(v));
            }
            _ => {}
        }
    }
    p
}

/// "AdminCraftLang" next to the program, or in the data folder when that can't be written.
pub fn lang_dir() -> PathBuf {
    crate::programs::tools_dir().with_file_name("AdminCraftLang")
}

/// Creates the folder with the English file as a model for new languages.
pub fn ensure_lang_dir() -> PathBuf {
    let d = lang_dir();
    if std::fs::create_dir_all(&d).is_ok() {
        let model = d.join("en.lang.vorlage");
        if !model.exists() {
            let _ = std::fs::write(&model, BUILTIN_EN);
        }
        let readme = d.join("LIESMICH.txt");
        if !readme.exists() {
            let _ = std::fs::write(
                readme,
                "Sprachdateien für AdminCraft / language files for AdminCraft\r\n\r\n\
                 Neue Sprache: en.lang.vorlage kopieren, z. B. nach fr.lang, oben @name und @code ändern\r\n\
                 und jeweils den Text rechts vom \" = \" übersetzen. Links steht der deutsche Originaltext.\r\n\
                 {0}, {1} ... sind Platzhalter und müssen bleiben. AdminCraft neu starten oder in den\r\n\
                 Einstellungen die Sprache wählen.\r\n\r\n\
                 New language: copy en.lang.vorlage to e.g. fr.lang, change @name and @code at the top and\r\n\
                 translate the text right of \" = \". The left side is the German original.\r\n\
                 A file named en.lang here replaces the built-in English.\r\n",
            );
        }
    }
    d
}

fn file_langs() -> Vec<(PathBuf, Parsed)> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(lang_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x.eq_ignore_ascii_case("lang")).unwrap_or(false) {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    let mut parsed = parse(&text);
                    if parsed.code.is_empty() {
                        parsed.code = p.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
                    }
                    if parsed.name.is_empty() {
                        parsed.name = parsed.code.clone();
                    }
                    v.push((p, parsed));
                }
            }
        }
    }
    v.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    v
}

/// All languages: German (the original), English (built in) and the files in AdminCraftLang.
pub fn available() -> Vec<LangInfo> {
    let mut v = vec![
        LangInfo { code: "de".into(), name: "Deutsch".into(), source: "eingebaut".into() },
        LangInfo { code: "en".into(), name: "English".into(), source: "eingebaut".into() },
    ];
    for (path, p) in file_langs() {
        if let Some(existing) = v.iter_mut().find(|l| l.code == p.code) {
            existing.source = path.display().to_string();
        } else {
            v.push(LangInfo { code: p.code, name: p.name, source: path.display().to_string() });
        }
    }
    v
}

/// The system's language as a two-letter code ("de", "en", "fr" ...).
pub fn system_code() -> String {
    sys_locale::get_locale()
        .map(|l| l.split(['-', '_']).next().unwrap_or("en").to_lowercase())
        .unwrap_or_else(|| "en".into())
}

/// Switches the language. Empty or "auto" = the system's language (English when there is no
/// file for it).
pub fn set_language(choice: &str) {
    let langs = available();
    let mut code = if choice.is_empty() || choice == "auto" { system_code() } else { choice.to_lowercase() };
    if !langs.iter().any(|l| l.code == code) {
        code = "en".into();
    }
    let mut map: HashMap<String, &'static str> = HashMap::new();
    if code != "de" {
        let mut entries = if code == "en" { parse(BUILTIN_EN).map } else { HashMap::new() };
        if let Some((_, p)) = file_langs().into_iter().find(|(_, p)| p.code == code) {
            entries.extend(p.map);
        }
        for (k, v) in entries {
            // leaked once per language switch: the texts live as long as the program
            map.insert(k, Box::leak(v.into_boxed_str()));
        }
    }
    if let Ok(mut t) = TABLE.write() {
        *t = map;
    }
    if let Ok(mut c) = CURRENT.write() {
        *c = code;
    }
}
