//! Helper programs (PuTTY, OpenSSH, RDP and VNC clients, WinSCP ...): where they are.
//!
//! Order of search: the path set in the settings, then the "AdminCraftTools" folder next to
//! AdminCraft (drop portable programs there), then the system PATH, then usual install places.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::model::Settings;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct ProgDef {
    pub key: &'static str,
    pub label: &'static str,
    pub purpose: &'static str,
    /// File names without ".exe".
    pub names: &'static [&'static str],
    /// Usual install places (absolute paths).
    pub known: &'static [&'static str],
}

#[cfg(windows)]
pub const PROGRAMS: &[ProgDef] = &[
    ProgDef { key: "ssh", label: "OpenSSH ssh", purpose: "SSH in tab, jump host", names: &["ssh"], known: &[r"C:\Windows\System32\OpenSSH\ssh.exe"] },
    ProgDef { key: "sftp", label: "OpenSSH sftp", purpose: "Files (SFTP)", names: &["sftp"], known: &[r"C:\Windows\System32\OpenSSH\sftp.exe"] },
    ProgDef { key: "scp", label: "OpenSSH scp", purpose: "Files (SCP)", names: &["scp"], known: &[r"C:\Windows\System32\OpenSSH\scp.exe"] },
    ProgDef { key: "putty", label: "PuTTY", purpose: "SSH/Telnet in tab", names: &["putty"], known: &[r"C:\Program Files\PuTTY\putty.exe", r"C:\Program Files (x86)\PuTTY\putty.exe"] },
    ProgDef { key: "plink", label: "PuTTY plink", purpose: "Jump host for PuTTY, SCP listing", names: &["plink"], known: &[r"C:\Program Files\PuTTY\plink.exe", r"C:\Program Files (x86)\PuTTY\plink.exe"] },
    ProgDef { key: "psftp", label: "PuTTY psftp", purpose: "Files (SFTP) without OpenSSH", names: &["psftp"], known: &[r"C:\Program Files\PuTTY\psftp.exe", r"C:\Program Files (x86)\PuTTY\psftp.exe"] },
    ProgDef { key: "pscp", label: "PuTTY pscp", purpose: "Files (SCP) without OpenSSH", names: &["pscp"], known: &[r"C:\Program Files\PuTTY\pscp.exe", r"C:\Program Files (x86)\PuTTY\pscp.exe"] },
    ProgDef { key: "mstsc", label: "Remote desktop (mstsc)", purpose: "RDP in tab", names: &["mstsc"], known: &[r"C:\Windows\System32\mstsc.exe"] },
    ProgDef { key: "vnc", label: "VNC viewer", purpose: "VNC in tab", names: &["vncviewer", "tvnviewer", "vncviewer64"], known: &[r"C:\Program Files\TigerVNC\vncviewer.exe", r"C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe", r"C:\Program Files\TightVNC\tvnviewer.exe", r"C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe"] },
    ProgDef { key: "telnet", label: "Telnet", purpose: "Telnet in tab", names: &["telnet"], known: &[r"C:\Windows\System32\telnet.exe"] },
    ProgDef { key: "winscp", label: "WinSCP", purpose: "Optional: open files externally", names: &["winscp"], known: &[r"C:\Program Files (x86)\WinSCP\WinSCP.exe", r"C:\Program Files\WinSCP\WinSCP.exe"] },
    ProgDef { key: "filezilla", label: "FileZilla", purpose: "Optional: open FTP externally", names: &["filezilla"], known: &[r"C:\Program Files\FileZilla FTP Client\filezilla.exe"] },
    ProgDef { key: "browser", label: "Edge / Chrome", purpose: "Web interfaces in a tab", names: &["msedge", "chrome"], known: &[r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"] },
];

#[cfg(not(windows))]
pub const PROGRAMS: &[ProgDef] = &[
    ProgDef { key: "ssh", label: "OpenSSH ssh", purpose: "SSH in tab, jump host", names: &["ssh"], known: &["/usr/bin/ssh"] },
    ProgDef { key: "sftp", label: "OpenSSH sftp", purpose: "Files (SFTP)", names: &["sftp"], known: &["/usr/bin/sftp"] },
    ProgDef { key: "scp", label: "OpenSSH scp", purpose: "Files (SCP)", names: &["scp"], known: &["/usr/bin/scp"] },
    ProgDef { key: "putty", label: "PuTTY", purpose: "SSH in its own window", names: &["putty"], known: &["/usr/bin/putty", "/opt/homebrew/bin/putty", "/usr/local/bin/putty"] },
    ProgDef { key: "plink", label: "PuTTY plink", purpose: "Jump host for PuTTY", names: &["plink"], known: &["/usr/bin/plink", "/opt/homebrew/bin/plink"] },
    ProgDef { key: "psftp", label: "PuTTY psftp", purpose: "Files (SFTP) without OpenSSH", names: &["psftp"], known: &["/usr/bin/psftp"] },
    ProgDef { key: "pscp", label: "PuTTY pscp", purpose: "Files (SCP) without OpenSSH", names: &["pscp"], known: &["/usr/bin/pscp"] },
    ProgDef { key: "rdp", label: "FreeRDP", purpose: "RDP", names: &["xfreerdp3", "xfreerdp", "wlfreerdp3", "wlfreerdp", "sdl-freerdp3", "sdl-freerdp"], known: &["/opt/homebrew/bin/xfreerdp", "/usr/local/bin/xfreerdp"] },
    ProgDef { key: "vnc", label: "VNC viewer", purpose: "VNC", names: &["vncviewer", "xtigervncviewer", "gvncviewer"], known: &["/Applications/TigerVNC Viewer.app/Contents/MacOS/TigerVNC Viewer"] },
    ProgDef { key: "telnet", label: "Telnet", purpose: "Telnet in tab", names: &["telnet"], known: &["/usr/bin/telnet", "/opt/homebrew/bin/telnet"] },
    ProgDef { key: "remmina", label: "Remmina", purpose: "RDP/VNC (Linux)", names: &["remmina"], known: &[] },
    ProgDef { key: "filezilla", label: "FileZilla", purpose: "Optional: open FTP externally", names: &["filezilla"], known: &["/Applications/FileZilla.app/Contents/MacOS/filezilla"] },
];

pub fn def(key: &str) -> Option<&'static ProgDef> {
    PROGRAMS.iter().find(|p| p.key == key)
}

/// "AdminCraftTools" next to the program (portable), or inside the data folder when the
/// program's own folder can't be written (macOS app bundle, read-only share).
pub fn tools_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let d = dir.join("AdminCraftTools");
            if d.is_dir() {
                return d;
            }
            let probe = dir.join(".admincraft-write-test");
            if std::fs::write(&probe, b"ok").is_ok() {
                let _ = std::fs::remove_file(probe);
                return d;
            }
        }
    }
    crate::model::data_dir(false).join("AdminCraftTools")
}

/// Creates the tools folder with a short note in it.
pub fn ensure_tools_dir() -> PathBuf {
    let d = tools_dir();
    if std::fs::create_dir_all(&d).is_ok() {
        let readme = d.join("README.txt");
        if !readme.exists() && !d.join("LIESMICH.txt").exists() {
            let _ = std::fs::write(
                readme,
                "Put portable programs here, AdminCraft finds them by itself:\r\n\
                 - putty.exe, plink.exe, psftp.exe, pscp.exe (PuTTY)\r\n\
                 - vncviewer.exe (TigerVNC) or tvnviewer.exe (TightVNC)\r\n\
                 - WinSCP.exe, filezilla.exe\r\n\
                 Subfolders (one level) are searched too, e.g. AdminCraftTools\\PuTTY\\putty.exe.\r\n",
            );
        }
    }
    d
}

fn exe_names(name: &str) -> Vec<String> {
    if cfg!(windows) {
        vec![format!("{name}.exe"), format!("{name}.EXE"), name.to_string()]
    } else {
        vec![name.to_string()]
    }
}

fn find_in_dir(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    for n in names {
        for f in exe_names(n) {
            let p = dir.join(&f);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    // one level of sub folders (e.g. AdminCraftTools/PuTTY/putty.exe)
    let rd = std::fs::read_dir(dir).ok()?;
    let mut subs: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect();
    subs.sort();
    for sub in subs {
        for n in names {
            for f in exe_names(n) {
                let p = sub.join(&f);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    // case-insensitive match (WinSCP.exe vs winscp)
    if cfg!(windows) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let fname = e.file_name().to_string_lossy().to_lowercase();
                if names.iter().any(|n| fname == format!("{n}.exe")) {
                    return Some(e.path());
                }
            }
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Settings,
    ToolsFolder,
    System,
    Installed,
}

impl Source {
    pub fn label(self) -> &'static str {
        tr(match self {
            Source::Settings => "own path",
            Source::ToolsFolder => "Programs folder",
            Source::System => "system",
            Source::Installed => "installed",
        })
    }
}

/// Finds a helper program by its key (see PROGRAMS).
pub fn find(key: &str, settings: &Settings) -> Option<PathBuf> {
    find_with_source(key, settings).map(|(p, _)| p)
}

pub fn find_with_source(key: &str, settings: &Settings) -> Option<(PathBuf, Source)> {
    if let Some(own) = settings.programs.get(key).map(|s| s.trim().trim_matches('"')).filter(|s| !s.is_empty()) {
        let p = PathBuf::from(own);
        if p.is_file() {
            return Some((p, Source::Settings));
        }
        if p.is_dir() {
            if let Some(d) = def(key) {
                if let Some(f) = find_in_dir(&p, d.names) {
                    return Some((f, Source::Settings));
                }
            }
        }
        if let Some(w) = crate::launch::which(own) {
            return Some((w, Source::Settings));
        }
    }
    let d = def(key)?;
    if let Some(p) = find_in_dir(&tools_dir(), d.names) {
        return Some((p, Source::ToolsFolder));
    }
    for n in d.names {
        if let Some(p) = crate::launch::which(n) {
            return Some((p, Source::System));
        }
    }
    for k in d.known {
        let p = PathBuf::from(k);
        if p.is_file() {
            return Some((p, Source::Installed));
        }
    }
    None
}

#[allow(dead_code)]
fn sh_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:@=,".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Starts a program in its own terminal window (e.g. OpenSSH "outside" AdminCraft).
pub fn spawn_in_terminal(
    program: &Path,
    args: &[String],
    title: &str,
    env: &[(String, String)],
) -> Result<String, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if let Some(wt) = crate::launch::which("wt") {
            let mut cmd = Command::new(wt);
            cmd.args(["new-tab", "--title", title, "--"]).arg(program).args(args);
            for (k, v) in env {
                cmd.env(k, v);
            }
            return cmd.spawn().map(|_| tr("Windows-Terminal").to_string()).map_err(|e| e.to_string());
        }
        let mut cmd = Command::new(program);
        cmd.args(args).creation_flags(0x0000_0010); // CREATE_NEW_CONSOLE
        for (k, v) in env {
            cmd.env(k, v);
        }
        let _ = title;
        cmd.spawn().map(|_| tr("console window").to_string()).map_err(|e| e.to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let mut line = String::new();
        for (k, v) in env {
            line.push_str(&format!("export {0}={1}; ", k, sh_quote(v)));
        }
        line.push_str(&sh_quote(&program.display().to_string()));
        for a in args {
            line.push(' ');
            line.push_str(&sh_quote(a));
        }
        let script = format!("tell application \"Terminal\" to do script \"{0}\"", line.replace('\\', "\\\\").replace('"', "\\\""));
        let _ = title;
        Command::new("osascript")
            .args(["-e", &script, "-e", "tell application \"Terminal\" to activate"])
            .spawn()
            .map(|_| tr("Terminal").to_string())
            .map_err(|e| e.to_string())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let mut line = vec![program.display().to_string()];
        line.extend(args.iter().cloned());
        let candidates: [(&str, &[&str]); 6] = [
            ("x-terminal-emulator", &["-e"]),
            ("gnome-terminal", &["--"]),
            ("konsole", &["-e"]),
            ("xfce4-terminal", &["-x"]),
            ("kitty", &[]),
            ("xterm", &["-e"]),
        ];
        for (term, pre) in candidates {
            if let Some(t) = crate::launch::which(term) {
                let mut cmd = Command::new(t);
                if term == "xterm" || term == "konsole" || term == "x-terminal-emulator" {
                    cmd.args(["-T", title]);
                }
                cmd.args(pre).args(&line);
                for (k, v) in env {
                    cmd.env(k, v);
                }
                return cmd.spawn().map(|_| term.to_string()).map_err(|e| e.to_string());
            }
        }
        let _ = sh_quote("");
        Err(tr("No terminal program found (gnome-terminal, konsole, xterm …).").into())
    }
}
