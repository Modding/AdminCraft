//! KeePass as the connection list: the connections live in a KeePass / KeePassXC database
//! (.kdbx), in the group "AdminCraft". Every connection is a normal KeePass entry (title, user
//! name, password, URL such as `ssh://10.0.0.30:22`, notes), so it can be read and edited in
//! KeePass too; AdminCraft's other settings for it sit in the extra field "AdminCraft". Folders
//! are KeePass groups. Entries made in KeePass inside that group appear as connections.
//!
//! Also: writing a single password into the database (for connections that take their password
//! from KeePass).

use crate::i18n::{t as tr, tf};
use crate::model::{Entry, Protocol};
use keepass::db::fields;
use keepass::db::{EntryId, GroupId};
use std::collections::{HashMap, HashSet};

/// The group holding AdminCraft's connections.
pub const GROUP: &str = "AdminCraft";
/// The extra field with AdminCraft's own settings of a connection.
const FIELD: &str = "AdminCraft";
/// Marks AdminCraft's settings of a folder in the group's notes.
const FOLDER_MARK: &str = "\n\n[AdminCraft] ";

#[derive(Clone, Debug, Default)]
pub struct Key {
    pub password: String,
    pub keyfile: String,
}

impl Key {
    fn database_key(&self) -> Result<keepass::DatabaseKey, String> {
        let mut key = keepass::DatabaseKey::new();
        if !self.password.is_empty() {
            key = key.with_password(&self.password);
        }
        let kf = self.keyfile.trim().trim_matches('"');
        if !kf.is_empty() {
            let mut f = std::fs::File::open(kf).map_err(|e| tf("Key file not readable: {0}", &[&e]))?;
            key = key.with_keyfile(&mut f).map_err(|e| tf("Key file: {0}", &[&e]))?;
        }
        if key.is_empty() {
            return Err(tr("Please enter the master password or a key file.").into());
        }
        Ok(key)
    }
}

fn open(path: &str, key: &Key) -> Result<keepass::Database, String> {
    let path = path.trim().trim_matches('"');
    if path.is_empty() {
        return Err(tr("No KeePass file set (Settings » Password vault).").into());
    }
    let mut f = std::fs::File::open(path).map_err(|e| tf("KeePass file not readable: {0}", &[&e]))?;
    keepass::Database::open(&mut f, key.database_key()?).map_err(|e| {
        let t = e.to_string().to_lowercase();
        if t.contains("key") || t.contains("hmac") || t.contains("credential") {
            tr("Wrong master password or wrong key file.").to_string()
        } else {
            tf("KeePass file could not be opened: {0}", &[&e])
        }
    })
}

/// Writes next to the file first, so a crash never leaves half a database.
fn write(db: &keepass::Database, path: &str, key: &Key) -> Result<(), String> {
    let path = std::path::Path::new(path.trim().trim_matches('"'));
    let tmp = path.with_extension("kdbx.admincraft-tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| tf("Saving failed: {0}", &[&e]))?;
        db.save(&mut f, key.database_key()?).map_err(|e| tf("Saving failed: {0}", &[&e]))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| tf("Saving failed: {0}", &[&e]))
}

// ------------------------------------------------------------------ URL <-> connection

/// `ssh://10.0.0.30:22`, `rdp://server.corp.local:3389`, `https://10.0.0.1/`.
pub fn url_of(e: &Entry) -> String {
    match e.protocol {
        Protocol::LocalShell => String::new(),
        Protocol::Http | Protocol::Https if e.port == e.protocol.default_port() => format!("{}://{}/", e.protocol.key(), e.host),
        p => format!("{}://{}:{}", p.key(), e.host, e.port),
    }
}

/// Protocol, host and port from a URL; an unknown or missing scheme means SSH.
pub fn parse_url(url: &str) -> Option<(Protocol, String, u16)> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let proto = Protocol::ALL.iter().copied().find(|p| p.key().eq_ignore_ascii_case(scheme)).unwrap_or(match scheme.to_lowercase().as_str() {
        "ftps" => Protocol::Ftp,
        "ms-rd" | "mstsc" => Protocol::Rdp,
        "cmd" | "kdbx" => return None,
        _ => Protocol::Ssh,
    });
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = hostport.rsplit('@').next().unwrap_or("");
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, after) = v6.split_once(']').unwrap_or((v6, ""));
        (h.to_string(), after.strip_prefix(':').and_then(|p| p.parse().ok()))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h.to_string(), p.parse().ok()),
            _ => (hostport.to_string(), None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((proto, host, port.unwrap_or(proto.default_port())))
}

// ------------------------------------------------------------------ reading

/// Keeps the id AdminCraft gave an entry; a new or doubled one gets the next free id.
fn take_id(wanted: u64, next: &mut u64, used: &mut HashSet<u64>) -> u64 {
    if wanted != 0 && used.insert(wanted) {
        return wanted;
    }
    while !used.insert(*next) {
        *next += 1;
    }
    *next
}

fn walk_group(
    db: &keepass::Database,
    g: keepass::db::GroupRef<'_>,
    parent: Option<u64>,
    out: &mut Vec<Entry>,
    next: &mut u64,
    used: &mut HashSet<u64>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    for e in g.entries() {
        let stored: Option<Entry> = e.get(FIELD).and_then(|j| serde_json::from_str(j).ok());
        let mut c = stored.clone().unwrap_or_default();
        c.folder = false;
        c.id = take_id(stored.as_ref().map(|s| s.id).unwrap_or(0), next, used);
        c.parent = parent;
        c.name = e.get_title().unwrap_or("").to_string();
        c.username = e.get_username().unwrap_or("").to_string();
        c.password = e.get_password().unwrap_or("").to_string();
        c.password_enc = None;
        c.description = e.get(fields::NOTES).unwrap_or("").to_string();
        let url = e.get_url().unwrap_or("");
        match parse_url(url) {
            Some((p, h, port)) => {
                // KeePass' URL wins (it may have been edited there); keep the protocol AdminCraft
                // knows when the URL only says "ssh" for an SFTP/SCP entry.
                if stored.is_none() || p.key() != stored.as_ref().map(|s| s.protocol.key()).unwrap_or("") {
                    c.protocol = p;
                }
                c.host = h;
                c.port = port;
            }
            None if stored.is_none() => {
                c.host = c.name.clone();
                c.port = c.protocol.default_port();
            }
            None => {}
        }
        c.kp_id = e.id().to_string();
        if c.name.is_empty() {
            c.name = c.host.clone();
        }
        out.push(c);
    }
    for sub in g.groups() {
        if db.meta.recyclebin_uuid == Some(sub.id().uuid()) {
            continue;
        }
        let notes = sub.notes.clone().unwrap_or_default();
        let (desc, stored, password) = match notes.split_once(FOLDER_MARK) {
            Some((d, j)) => {
                let v: serde_json::Value = serde_json::from_str(j.trim()).unwrap_or_default();
                (d.to_string(), serde_json::from_value::<Entry>(v["settings"].clone()).ok(), v["password"].as_str().unwrap_or("").to_string())
            }
            None => (notes.clone(), None, String::new()),
        };
        let mut f = stored.clone().unwrap_or_default();
        f.folder = true;
        f.id = take_id(stored.as_ref().map(|s| s.id).unwrap_or(0), next, used);
        f.parent = parent;
        f.name = sub.name.clone();
        f.description = desc;
        f.password = password;
        f.kp_id = sub.id().to_string();
        let fid = f.id;
        out.push(f);
        walk_group(db, sub, Some(fid), out, next, used, depth + 1);
    }
}

fn find_group(db: &keepass::Database) -> Option<GroupId> {
    db.root().groups().find(|g| g.name == GROUP).map(|g| g.id())
}

/// The connections in the database's "AdminCraft" group (empty when there is none yet).
pub fn load(path: &str, key: &Key) -> Result<Vec<Entry>, String> {
    let db = open(path, key)?;
    let mut out = Vec::new();
    if let Some(gid) = find_group(&db)
        && let Some(g) = db.group(gid)
    {
        let mut used = HashSet::new();
        let mut next = 1;
        walk_group(&db, g, None, &mut out, &mut next, &mut used, 0);
    }
    Ok(out)
}

// ------------------------------------------------------------------ writing

/// What AdminCraft keeps in its extra field: everything but what KeePass shows itself.
fn extra_json(e: &Entry) -> String {
    let mut x = e.clone();
    x.password = String::new();
    x.password_enc = None;
    x.kp_id = String::new();
    serde_json::to_string(&x).unwrap_or_default()
}

fn folder_notes(f: &Entry) -> String {
    let mut x = f.clone();
    x.password_enc = None;
    x.kp_id = String::new();
    x.description = String::new();
    // a folder's password is kept with it (the whole database is encrypted)
    let json = serde_json::json!({ "settings": x, "password": f.password });
    format!("{}{FOLDER_MARK}{}", f.description, json)
}

/// Writes the whole list into the database: changed entries are updated (KeePass keeps their
/// history), new ones added, moved ones moved, deleted ones removed. Sets `kp_id` on each.
pub fn save(path: &str, key: &Key, list: &mut [Entry]) -> Result<(), String> {
    let mut db = open(path, key)?;
    let gid = match find_group(&db) {
        Some(g) => g,
        None => {
            let mut root = db.root_mut();
            let mut g = root.add_group();
            g.name = GROUP.into();
            g.notes = Some(tr("Connections of AdminCraft. Entries here open in AdminCraft; the field \"AdminCraft\" holds its settings.").into());
            g.id()
        }
    };
    // what is there now
    let mut old_entries: HashMap<String, EntryId> = HashMap::new();
    let mut old_groups: HashMap<String, GroupId> = HashMap::new();
    fn collect(db: &keepass::Database, g: GroupId, e: &mut HashMap<String, EntryId>, gs: &mut HashMap<String, GroupId>, depth: usize) {
        let Some(gr) = db.group(g) else { return };
        if depth > 32 {
            return;
        }
        for x in gr.entries() {
            e.insert(x.id().to_string(), x.id());
        }
        let subs: Vec<GroupId> = gr.groups().map(|s| s.id()).collect();
        for s in subs {
            gs.insert(s.to_string(), s);
            collect(db, s, e, gs, depth + 1);
        }
    }
    collect(&db, gid, &mut old_entries, &mut old_groups, 0);

    // folders first, parents before children
    let mut group_of: HashMap<u64, GroupId> = HashMap::new();
    let mut order: Vec<usize> = (0..list.len()).filter(|&i| list[i].folder).collect();
    let depth_of = |i: usize, list: &[Entry]| {
        let mut d = 0;
        let mut p = list[i].parent;
        while let Some(pid) = p {
            d += 1;
            p = list.iter().find(|x| x.id == pid).and_then(|x| x.parent);
            if d > 64 {
                break;
            }
        }
        d
    };
    order.sort_by_key(|&i| depth_of(i, list));
    let mut kept_groups: HashSet<GroupId> = HashSet::new();
    for i in order {
        let parent_g = list[i].parent.and_then(|p| group_of.get(&p).copied()).unwrap_or(gid);
        let existing = old_groups.get(&list[i].kp_id).copied();
        let id = match existing {
            Some(g) => {
                let now_parent = db.group(g).and_then(|x| x.parent().map(|p| p.id()));
                if let Some(mut gm) = db.group_mut(g) {
                    if now_parent != Some(parent_g) {
                        let _ = gm.track_changes().move_to(parent_g);
                    }
                    let notes = folder_notes(&list[i]);
                    if gm.name != list[i].name || gm.notes.as_deref() != Some(notes.as_str()) {
                        gm.edit_tracking(|t| {
                            let mut m = t.as_mut();
                            m.name = list[i].name.clone();
                            m.notes = Some(notes.clone());
                        });
                    }
                }
                g
            }
            None => {
                let Some(mut pg) = db.group_mut(parent_g) else { continue };
                let mut ng = pg.add_group();
                ng.name = list[i].name.clone();
                ng.notes = Some(folder_notes(&list[i]));
                ng.id()
            }
        };
        list[i].kp_id = id.to_string();
        group_of.insert(list[i].id, id);
        kept_groups.insert(id);
    }

    let mut kept_entries: HashSet<EntryId> = HashSet::new();
    for c in list.iter_mut().filter(|c| !c.folder) {
        let parent_g = c.parent.and_then(|p| group_of.get(&p).copied()).unwrap_or(gid);
        let values = [
            (fields::TITLE, c.name.clone(), false),
            (fields::USERNAME, c.username.clone(), false),
            (fields::PASSWORD, c.password.clone(), true),
            (fields::URL, url_of(c), false),
            (fields::NOTES, c.description.clone(), false),
            (FIELD, extra_json(c), false),
        ];
        let id = match old_entries.get(&c.kp_id).copied() {
            Some(id) => {
                let now_parent = db.entry(id).map(|x| x.parent().id());
                if let Some(mut em) = db.entry_mut(id) {
                    if now_parent != Some(parent_g) {
                        let _ = em.move_to(parent_g);
                    }
                    let differs = values.iter().any(|(k, v, _)| em.get(k).unwrap_or("") != v.as_str());
                    if differs {
                        em.edit_tracking(|t| {
                            for (k, v, protect) in &values {
                                if *protect {
                                    t.set_protected(*k, v.clone());
                                } else {
                                    t.set_unprotected(*k, v.clone());
                                }
                            }
                        });
                    }
                }
                id
            }
            None => {
                let Some(mut pg) = db.group_mut(parent_g) else { continue };
                let mut ne = pg.add_entry();
                for (k, v, protect) in &values {
                    if *protect {
                        ne.set_protected(*k, v.clone());
                    } else {
                        ne.set_unprotected(*k, v.clone());
                    }
                }
                ne.id()
            }
        };
        c.kp_id = id.to_string();
        kept_entries.insert(id);
    }

    // what was deleted in AdminCraft goes (KeePass records the deletion for merging)
    for (_, id) in old_entries {
        if !kept_entries.contains(&id)
            && let Some(mut em) = db.entry_mut(id)
        {
            em.track_changes().remove();
        }
    }
    for (_, g) in old_groups {
        if !kept_groups.contains(&g)
            && let Some(mut gm) = db.group_mut(g)
        {
            let _ = gm.track_changes().remove();
        }
    }
    write(&db, path, key)
}

/// Puts one password into the database (group "AdminCraft"), updating the entry with this title
/// there or making a new one. Returns the entry's path for the connection's "KeePass entry".
pub fn store_password(path: &str, key: &Key, title: &str, user: &str, password: &str, url: &str) -> Result<String, String> {
    let mut db = open(path, key)?;
    let gid = match find_group(&db) {
        Some(g) => g,
        None => {
            let mut root = db.root_mut();
            let mut g = root.add_group();
            g.name = GROUP.into();
            g.id()
        }
    };
    let existing = db.group(gid).and_then(|g| g.entries().find(|e| e.get_title() == Some(title)).map(|e| e.id()));
    match existing.and_then(|id| db.entry_mut(id)) {
        Some(mut em) => {
            em.edit_tracking(|t| {
                t.set_unprotected(fields::USERNAME, user);
                t.set_protected(fields::PASSWORD, password);
                if !url.is_empty() {
                    t.set_unprotected(fields::URL, url);
                }
            });
        }
        None => {
            let mut g = db.group_mut(gid).ok_or("group missing")?;
            let mut e = g.add_entry();
            e.set_unprotected(fields::TITLE, title);
            e.set_unprotected(fields::USERNAME, user);
            e.set_protected(fields::PASSWORD, password);
            e.set_unprotected(fields::URL, url);
        }
    }
    write(&db, path, key)?;
    Ok(format!("{GROUP}/{title}"))
}
