//! Passwords for other programs without putting them on a command line, where every program of
//! the same user could read them: the password goes into a file only the user can read, the
//! program gets the file's name (PuTTY's `-pwfile`), and the file is removed as soon as the
//! program is done.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A password file that is overwritten and removed when this value goes away.
pub struct SecretFile(PathBuf);

impl SecretFile {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        // overwrite first: on a USB stick or an old disk the bytes of a removed file stay readable
        if let Ok(len) = std::fs::metadata(&self.0).map(|m| m.len()) {
            let _ = std::fs::write(&self.0, vec![0u8; usize::try_from(len).unwrap_or(0).min(4096)]);
        }
        let _ = std::fs::remove_file(&self.0);
    }
}

fn dir() -> PathBuf {
    std::env::temp_dir().join("admincraft")
}

const PREFIX: &str = "pw-";

/// Writes `password` into a new file only this user can read.
pub fn write(password: &str) -> Result<SecretFile, String> {
    use std::io::Write;
    let dir = dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut rnd = [0u8; 12];
    getrandom::fill(&mut rnd).map_err(|e| e.to_string())?;
    let name: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("{PREFIX}{}-{name}.txt", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|e| e.to_string())?;
    // from here on the file is removed again whatever happens
    let secret = SecretFile(path);
    file.write_all(password.as_bytes()).map_err(|e| e.to_string())?;
    Ok(secret)
}

/// Whether this PuTTY program (putty, plink, psftp, pscp) knows `-pwfile` (0.77 and newer).
/// Found by looking for the option's name inside the program file, so nothing is started.
pub fn supports_pwfile(program: &Path) -> bool {
    static KNOWN: Mutex<Option<HashMap<PathBuf, bool>>> = Mutex::new(None);
    let mut known = KNOWN.lock().unwrap_or_else(|e| e.into_inner());
    let map = known.get_or_insert_with(HashMap::new);
    if let Some(&yes) = map.get(program) {
        return yes;
    }
    let yes = std::fs::read(program).map(|bytes| mentions_pwfile(&bytes)).unwrap_or(false);
    map.insert(program.to_path_buf(), yes);
    yes
}

pub fn mentions_pwfile(program_bytes: &[u8]) -> bool {
    const OPTION: &[u8] = b"-pwfile";
    program_bytes.windows(OPTION.len()).any(|w| w == OPTION)
}

/// How a PuTTY program gets the password: `-pwfile <file>` when it knows that, else the old
/// `-pw <password>` (the caller should say so). The file lives as long as the returned value.
pub fn putty_password(program: &Path, password: &str) -> Result<(Vec<String>, Option<SecretFile>), String> {
    if password.is_empty() {
        return Ok((Vec::new(), None));
    }
    if supports_pwfile(program) {
        let file = write(password)?;
        Ok((vec!["-pwfile".into(), file.path().display().to_string()], Some(file)))
    } else {
        Ok((vec!["-pw".into(), password.to_string()], None))
    }
}

fn running() -> &'static Mutex<HashMap<u32, Vec<SecretFile>>> {
    static RUNNING: std::sync::OnceLock<Mutex<HashMap<u32, Vec<SecretFile>>>> = std::sync::OnceLock::new();
    RUNNING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Keeps the files while the started program (process id `pid`) runs: PuTTY starts its jump-host
/// helper again on every reconnect, and that helper reads its password file each time.
pub fn keep_while_running(pid: u32, files: Vec<SecretFile>) {
    if !files.is_empty() {
        running().lock().unwrap_or_else(|e| e.into_inner()).entry(pid).or_default().extend(files);
    }
}

/// The program ended or its tab was closed: its password files go.
pub fn process_ended(pid: u32) {
    running().lock().unwrap_or_else(|e| e.into_inner()).remove(&pid);
}

/// AdminCraft closes: every password file goes.
pub fn remove_all() {
    running().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// At start: removes password files a crashed AdminCraft left behind (older than a day, so the
/// files of another AdminCraft that is running right now are left alone).
pub fn sweep_stale() {
    let Ok(entries) = std::fs::read_dir(dir()) else { return };
    for entry in entries.flatten() {
        let old = entry.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age.as_secs() > 86_400);
        if old && entry.file_name().to_string_lossy().starts_with(PREFIX) {
            drop(SecretFile(entry.path()));
        }
    }
}
