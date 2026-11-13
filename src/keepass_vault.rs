//! Reads passwords from a KeePass / KeePassXC database (.kdbx): the passwords stay in KeePass,
//! connections just name the entry to use. Writing a password into it: see `kdbx.rs`.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::model::KeePassRef;

#[derive(Clone, Debug)]
pub struct KpEntry {
    /// "Group/Subgroup/Title" (without the root group).
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
    /// Kept while unlocked, to write passwords into the database.
    pub key: Option<crate::kdbx::Key>,
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
            return Err(tr("No KeePass file set (Settings » Password vault).").into());
        }
        let mut file = std::fs::File::open(path).map_err(|e| tf("KeePass file not readable: {0}", &[&e]))?;
        let mut key = keepass::DatabaseKey::new();
        if !password.is_empty() {
            key = key.with_password(password);
        }
        let keyfile = keyfile.trim().trim_matches('"');
        if !keyfile.is_empty() {
            let mut kf = std::fs::File::open(keyfile).map_err(|e| tf("Key file not readable: {0}", &[&e]))?;
            key = key.with_keyfile(&mut kf).map_err(|e| tf("Key file: {0}", &[&e]))?;
        }
        if key.is_empty() {
            return Err(tr("Please enter the master password or a key file.").into());
        }
        let db = keepass::Database::open(&mut file, key).map_err(|e| {
            let t = e.to_string();
            if t.to_lowercase().contains("key") || t.to_lowercase().contains("hmac") || t.to_lowercase().contains("credential") {
                tr("Wrong master password or wrong key file.").to_string()
            } else {
                tf("KeePass file could not be opened: {0}", &[&t])
            }
        })?;
        let mut out = Vec::new();
        walk(db.root(), "", &mut out, 0);
        out.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
        self.entries = out;
        self.opened_path = path.to_string();
        self.unlocked = true;
        self.key = Some(crate::kdbx::Key { password: password.to_string(), keyfile: keyfile.to_string() });
        Ok(self.entries.len())
    }

    pub fn lock(&mut self) {
        self.entries.clear();
        self.key = None;
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
