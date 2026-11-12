//! Reads passwords from a KeePass / KeePassXC database (.kdbx). AdminCraft only reads it:
//! the passwords stay in KeePass, connections just name the entry to use.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::model::KeePassRef;

#[derive(Clone, Debug)]
pub struct KpEntry {
    /// "Gruppe/Untergruppe/Titel" (without the root group).
    pub path: String,
    pub title: String,
    pub user: String,
    pub password: String,
    pub url: String,
    /// otpauth:// link or base32 secret (two-factor codes), if the entry has one.
    pub otp: String,
}

#[derive(Default)]
pub struct KeePassVault {
    pub entries: Vec<KpEntry>,
    pub opened_path: String,
    pub unlocked: bool,
}

fn walk(group: keepass::db::GroupRef<'_>, prefix: &str, out: &mut Vec<KpEntry>, depth: usize) {
    if depth > 32 {
        return;
    }
    for e in group.entries() {
        let title = e.get_title().unwrap_or("").to_string();
        let path = if prefix.is_empty() { title.clone() } else { format!("{prefix}/{title}") };
        out.push(KpEntry {
            path,
            title,
            user: e.get_username().unwrap_or("").to_string(),
            password: e.get_password().unwrap_or("").to_string(),
            url: e.get_url().unwrap_or("").to_string(),
            otp: e.get("otp").or_else(|| e.get("TimeOtp-Secret-Base32")).unwrap_or("").to_string(),
        });
    }
    for g in group.groups() {
        if g.name.eq_ignore_ascii_case("Recycle Bin") || g.name.eq_ignore_ascii_case("Papierkorb") {
            continue;
        }
        let p = if prefix.is_empty() { g.name.clone() } else { format!("{prefix}/{}", g.name) };
        walk(g, &p, out, depth + 1);
    }
}

impl KeePassVault {
    pub fn open(&mut self, path: &str, password: &str, keyfile: &str) -> Result<usize, String> {
        let path = path.trim().trim_matches('"');
        if path.is_empty() {
            return Err(tr("Keine KeePass-Datei eingestellt (Einstellungen » Passwort-Tresor).").into());
        }
        let mut file = std::fs::File::open(path).map_err(|e| tf("KeePass-Datei nicht lesbar: {0}", &[&e]))?;
        let mut key = keepass::DatabaseKey::new();
        if !password.is_empty() {
            key = key.with_password(password);
        }
        let keyfile = keyfile.trim().trim_matches('"');
        if !keyfile.is_empty() {
            let mut kf = std::fs::File::open(keyfile).map_err(|e| tf("Schlüsseldatei nicht lesbar: {0}", &[&e]))?;
            key = key.with_keyfile(&mut kf).map_err(|e| tf("Schlüsseldatei: {0}", &[&e]))?;
        }
        if key.is_empty() {
            return Err(tr("Bitte Masterpasswort oder Schlüsseldatei angeben.").into());
        }
        let db = keepass::Database::open(&mut file, key).map_err(|e| {
            let t = e.to_string();
            if t.to_lowercase().contains("key") || t.to_lowercase().contains("hmac") || t.to_lowercase().contains("credential") {
                tr("Falsches Masterpasswort oder falsche Schlüsseldatei.").to_string()
            } else {
                tf("KeePass-Datei konnte nicht geöffnet werden: {0}", &[&t])
            }
        })?;
        let mut out = Vec::new();
        walk(db.root(), "", &mut out, 0);
        out.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
        self.entries = out;
        self.opened_path = path.to_string();
        self.unlocked = true;
        Ok(self.entries.len())
    }

    pub fn lock(&mut self) {
        self.entries.clear();
        self.unlocked = false;
    }

    pub fn find(&self, r: &KeePassRef) -> Option<&KpEntry> {
        match r {
            KeePassRef::Entry(name) => {
                let n = name.trim().trim_matches('/').to_lowercase();
                self.entries
                    .iter()
                    .find(|e| e.path.to_lowercase() == n)
                    .or_else(|| self.entries.iter().find(|e| e.title.to_lowercase() == n))
                    .or_else(|| self.entries.iter().find(|e| e.path.to_lowercase().ends_with(&format!("/{n}"))))
            }
            KeePassRef::Host(host) => {
                let h = host.trim().to_lowercase();
                if h.is_empty() {
                    return None;
                }
                self.entries
                    .iter()
                    .find(|e| url_host(&e.url) == h)
                    .or_else(|| self.entries.iter().find(|e| e.title.to_lowercase() == h))
                    .or_else(|| self.entries.iter().find(|e| e.title.to_lowercase().contains(&h)))
            }
        }
    }
}

/// "https://admin@10.0.0.5:8443/x" -> "10.0.0.5"
pub fn url_host(url: &str) -> String {
    let u = url.trim().to_lowercase();
    let rest = u.split_once("://").map(|(_, r)| r).unwrap_or(&u);
    let rest = rest.split('/').next().unwrap_or("");
    let rest = rest.rsplit('@').next().unwrap_or("");
    if rest.starts_with('[') {
        return rest.trim_start_matches('[').split(']').next().unwrap_or("").to_string();
    }
    rest.split(':').next().unwrap_or("").to_string()
}
