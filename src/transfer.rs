//! File transfer (upload and download) over SFTP, SCP and FTP/FTPS.
//!
//! SFTP and SCP use the system's OpenSSH programs (sftp, scp, ssh) or PuTTY's psftp/pscp/plink;
//! the password is handed to OpenSSH through AdminCraft itself acting as "askpass" helper.
//! FTP is spoken directly. Every job runs on a worker thread; the tab only shows the state.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use eframe::egui;
use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Sftp,
    Scp,
    Ftp,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Sftp => "SFTP",
            Kind::Scp => "SCP",
            Kind::Ftp => "FTP",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tool {
    OpenSsh,
    Putty,
}

#[derive(Clone, Debug, Default)]
pub struct Hop {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub password: String,
}

#[derive(Clone, Debug, Default)]
pub struct Progs {
    pub ssh: Option<PathBuf>,
    pub sftp: Option<PathBuf>,
    pub scp: Option<PathBuf>,
    pub plink: Option<PathBuf>,
    pub psftp: Option<PathBuf>,
    pub pscp: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub kind: Kind,
    pub target: Hop,
    pub key_file: String,
    /// Jump hosts, outermost first (OpenSSH -J).
    pub jumps: Vec<Hop>,
    pub tls: bool,
    /// Check the FTPS server certificate (off for self-signed devices).
    pub check_cert: bool,
    pub tool: Tool,
    pub progs: Progs,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RemoteItem {
    pub name: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub modified: String,
    pub perms: String,
}

#[derive(Clone, Debug)]
pub enum Job {
    List(String),
    Download { remote: String, is_dir: bool, local_dir: PathBuf },
    Upload { local: PathBuf, remote_dir: String },
    Mkdir(String),
    Delete { path: String, is_dir: bool },
    Rename { from: String, to: String },
}

impl Job {
    fn describe(&self) -> String {
        match self {
            Job::List(p) if p.is_empty() => tr("Connect").to_string(),
            Job::List(p) => tf("Folder {0}", &[&p]),
            Job::Download { remote, .. } => tf("Download {0}", &[&(base_name(remote))]),
            Job::Upload { local, .. } => tf("Upload {0}", &[&(local.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())]),
            Job::Mkdir(p) => tf("Create folder {0}", &[&(base_name(p))]),
            Job::Delete { path, .. } => tf("Delete {0}", &[&(base_name(path))]),
            Job::Rename { from, to } => tf("Rename {0} » {1}", &[&(base_name(from)), &(base_name(to))]),
        }
    }
}

#[derive(Default)]
pub struct Shared {
    pub cwd: String,
    pub items: Vec<RemoteItem>,
    pub busy: Option<String>,
    pub queued: usize,
    pub log: Vec<(bool, String)>,
    pub connected: bool,
    /// Set when local files changed (download finished) so the tab re-reads the folder.
    pub local_changed: bool,
}

pub struct Transfer {
    tx: Sender<Job>,
    pub shared: Arc<Mutex<Shared>>,
    pub endpoint: Endpoint,
}

impl Transfer {
    pub fn start(endpoint: Endpoint, start_path: String, ctx: egui::Context) -> Transfer {
        let (tx, rx) = channel::<Job>();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let s2 = shared.clone();
        let ep = endpoint.clone();
        std::thread::spawn(move || worker(ep, rx, s2, ctx));
        let t = Transfer { tx, shared, endpoint };
        t.send(Job::List(start_path));
        t
    }

    pub fn send(&self, job: Job) {
        self.shared.lock().unwrap().queued += 1;
        let _ = self.tx.send(job);
    }

    pub fn busy(&self) -> bool {
        let s = self.shared.lock().unwrap();
        s.busy.is_some() || s.queued > 0
    }
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        name.to_string()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

pub fn parent(dir: &str) -> String {
    let t = dir.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) => "/".into(),
        Some(i) => t[..i].to_string(),
        None => "/".into(),
    }
}

pub fn base_name(p: &str) -> String {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p).to_string()
}

fn log(shared: &Arc<Mutex<Shared>>, ok: bool, text: impl Into<String>) {
    let mut s = shared.lock().unwrap();
    s.log.push((ok, text.into()));
    if s.log.len() > 300 {
        s.log.remove(0);
    }
}

fn worker(ep: Endpoint, rx: Receiver<Job>, shared: Arc<Mutex<Shared>>, ctx: egui::Context) {
    let mut ftp: Option<FtpConn> = None;
    let mut cwd = String::new();
    while let Ok(job) = rx.recv() {
        {
            let mut s = shared.lock().unwrap();
            s.queued = s.queued.saturating_sub(1);
            s.busy = Some(job.describe());
        }
        ctx.request_repaint();
        let is_list = matches!(job, Job::List(_));
        let result = match ep.kind {
            Kind::Ftp => run_ftp(&ep, &mut ftp, &job, &mut cwd),
            Kind::Sftp => run_sftp(&ep, &job, &mut cwd),
            Kind::Scp => run_scp(&ep, &job, &mut cwd),
        };
        match result {
            Ok(Outcome::Listing(dir, items)) => {
                let mut s = shared.lock().unwrap();
                s.cwd = dir.clone();
                s.items = items;
                s.connected = true;
                cwd = dir;
            }
            Ok(Outcome::Done(msg)) => {
                log(&shared, true, msg);
                if matches!(job, Job::Download { .. }) {
                    shared.lock().unwrap().local_changed = true;
                }
            }
            Err(e) => {
                log(&shared, false, format!("{}: {e}", job.describe()));
                if is_list && !shared.lock().unwrap().connected {
                    ftp = None;
                }
            }
        }
        // after a change on the server, show the folder again
        if !is_list {
            let again = shared.lock().unwrap().queued == 0;
            if again {
                let dir = cwd.clone();
                let r = match ep.kind {
                    Kind::Ftp => run_ftp(&ep, &mut ftp, &Job::List(dir.clone()), &mut cwd),
                    Kind::Sftp => run_sftp(&ep, &Job::List(dir.clone()), &mut cwd),
                    Kind::Scp => run_scp(&ep, &Job::List(dir.clone()), &mut cwd),
                };
                if let Ok(Outcome::Listing(d, items)) = r {
                    let mut s = shared.lock().unwrap();
                    s.cwd = d.clone();
                    s.items = items;
                    cwd = d;
                }
            }
        }
        shared.lock().unwrap().busy = None;
        ctx.request_repaint();
    }
}

enum Outcome {
    Listing(String, Vec<RemoteItem>),
    Done(String),
}

// ------------------------------------------------------------------ OpenSSH / PuTTY helpers

fn no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let _ = cmd;
}

/// Environment that lets OpenSSH ask AdminCraft for passwords instead of a console.
pub fn askpass_env(hops: &[Hop]) -> Vec<(String, String)> {
    let mut v = Vec::new();
    let Ok(exe) = std::env::current_exe() else { return v };
    v.push(("SSH_ASKPASS".into(), exe.display().to_string()));
    v.push(("SSH_ASKPASS_REQUIRE".into(), "force".into()));
    if std::env::var_os("DISPLAY").is_none() {
        v.push(("DISPLAY".into(), ":0".into()));
    }
    v.push(("AC_ASKPASS".into(), "1".into()));
    v.push(("AC_ASKPASS_N".into(), hops.len().to_string()));
    for (i, h) in hops.iter().enumerate() {
        v.push((format!("AC_ASKPASS_HOST_{i}"), h.host.clone()));
        v.push((format!("AC_ASKPASS_USER_{i}"), h.user.clone()));
        v.push((format!("AC_ASKPASS_PW_{i}"), h.password.clone()));
    }
    v
}

/// The password helper itself: OpenSSH starts AdminCraft with the prompt as argument.
pub fn askpass_main(prompt: &str) -> i32 {
    let p = prompt.to_lowercase();
    if p.contains("(yes/no") || p.contains("yes/no/") {
        println!("no");
        return 0;
    }
    let n: usize = std::env::var("AC_ASKPASS_N").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let hops: Vec<(String, String, String)> = (0..n)
        .map(|i| {
            (
                std::env::var(format!("AC_ASKPASS_HOST_{i}")).unwrap_or_default().to_lowercase(),
                std::env::var(format!("AC_ASKPASS_USER_{i}")).unwrap_or_default().to_lowercase(),
                std::env::var(format!("AC_ASKPASS_PW_{i}")).unwrap_or_default(),
            )
        })
        .collect();
    let fallback = hops.last().map(|h| h.2.clone());
    // exact "user@host's password:" first, then any prompt naming the host
    let exact = hops.iter().rev().find(|(h, u, _)| !h.is_empty() && p.contains(&format!("{u}@{h}'")));
    let loose = || hops.iter().rev().find(|(h, _, _)| !h.is_empty() && p.contains(&format!("@{h}'")));
    if let Some((_, _, pw)) = exact.or_else(loose) {
        if pw.is_empty() {
            return 1;
        }
        println!("{pw}");
        return 0;
    }
    match fallback {
        Some(pw) if !pw.is_empty() => {
            println!("{pw}");
            0
        }
        _ => 1,
    }
}

fn hops_all(ep: &Endpoint) -> Vec<Hop> {
    let mut v = ep.jumps.clone();
    v.push(ep.target.clone());
    v
}

fn user_host(h: &Hop) -> String {
    if h.user.is_empty() {
        h.host.clone()
    } else {
        format!("{}@{}", h.user, h.host)
    }
}

fn jump_arg(ep: &Endpoint) -> Option<String> {
    if ep.jumps.is_empty() {
        return None;
    }
    Some(
        ep.jumps
            .iter()
            .map(|h| if h.port == 22 || h.port == 0 { user_host(h) } else { format!("{}:{}", user_host(h), h.port) })
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn openssh_opts(ep: &Endpoint) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "-o".into(),
        "BatchMode=no".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=20".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=1".into(),
    ];
    if !ep.key_file.trim().is_empty() {
        v.push("-i".into());
        v.push(ep.key_file.trim().to_string());
    }
    if let Some(j) = jump_arg(ep) {
        v.push("-J".into());
        v.push(j);
    }
    v
}

struct RunOut {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(program: &Path, args: &[String], stdin: Option<&str>, env: &[(String, String)]) -> Result<RunOut, String> {
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    for (k, v) in env {
        cmd.env(k, v);
    }
    no_window(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| tf("{0} could not be started: {1}", &[&(program.display()), &e]))?;
    if let Some(text) = stdin {
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(text.as_bytes());
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok(RunOut {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).replace('\r', ""),
        stderr: String::from_utf8_lossy(&out.stderr).replace('\r', ""),
    })
}

fn clean_error(out: &RunOut) -> String {
    let lines: Vec<&str> = out
        .stderr
        .lines()
        .chain(out.stdout.lines())
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with("sftp>") && !l.starts_with("Warning: Permanently added") && !l.starts_with("psftp>"))
        .collect();
    let text = lines.iter().rev().take(3).rev().cloned().collect::<Vec<_>>().join(" · ");
    let low = text.to_lowercase();
    if low.contains("permission denied") || low.contains("access denied") {
        tf("Login refused (check user/password). {0}", &[&text])
    } else if low.contains("host key") && low.contains("cache") {
        tf("Host key unknown: connect once with PuTTY and confirm. {0}", &[&text])
    } else if text.is_empty() {
        tr("Unknown error").into()
    } else {
        text
    }
}

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn local_q(p: &Path) -> String {
    // sftp's batch parser treats backslashes as escapes; forward slashes work on Windows too
    q(&p.display().to_string().replace('\\', "/"))
}

/// Parses one line of `ls -l` output (Unix servers and most SFTP servers).
pub fn parse_ls_line(line: &str) -> Option<RemoteItem> {
    let line = line.trim_end();
    let first = line.chars().next()?;
    if !"-dlcbps".contains(first) || line.len() < 10 {
        return None;
    }
    // split into 8 fields + the rest (name may contain spaces)
    let mut fields = Vec::new();
    let mut rest = line;
    for _ in 0..8 {
        let t = rest.trim_start();
        let end = t.find(char::is_whitespace)?;
        fields.push(&t[..end]);
        rest = &t[end..];
    }
    let mut name = rest.trim_start_matches(' ').to_string();
    if name.is_empty() {
        return None;
    }
    let is_link = first == 'l';
    if is_link {
        if let Some(i) = name.find(" -> ") {
            name.truncate(i);
        }
    }
    if name == "." || name == ".." {
        return None;
    }
    Some(RemoteItem {
        name,
        is_dir: first == 'd',
        is_link,
        size: fields[4].parse().unwrap_or(0),
        modified: format!("{} {} {}", fields[5], fields[6], fields[7]),
        perms: fields[0].to_string(),
    })
}

fn sort_items(items: &mut [RemoteItem]) {
    items.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
}

// ------------------------------------------------------------------ SFTP

fn sftp_program(ep: &Endpoint) -> Result<(PathBuf, bool), String> {
    let use_putty = ep.tool == Tool::Putty || ep.progs.sftp.is_none();
    if use_putty {
        if let Some(p) = &ep.progs.psftp {
            if !ep.jumps.is_empty() {
                return Err(tr("A jump host for file transfer needs OpenSSH (sftp).").into());
            }
            return Ok((p.clone(), true));
        }
    }
    if let Some(p) = &ep.progs.sftp {
        return Ok((p.clone(), false));
    }
    Err(tr("No SFTP program found: install the OpenSSH client or put psftp.exe into the programs folder.").into())
}

fn sftp_batch(ep: &Endpoint, script: &str) -> Result<RunOut, String> {
    let (prog, putty) = sftp_program(ep)?;
    let t = &ep.target;
    if putty {
        let file = std::env::temp_dir().join(format!("admincraft-psftp-{}.txt", std::process::id()));
        std::fs::write(&file, script).map_err(|e| e.to_string())?;
        let mut args = vec!["-batch".to_string(), "-P".into(), t.port.to_string()];
        if !t.password.is_empty() {
            args.push("-pw".into());
            args.push(t.password.clone());
        }
        if !ep.key_file.trim().is_empty() {
            args.push("-i".into());
            args.push(ep.key_file.trim().into());
        }
        args.push("-b".into());
        args.push(file.display().to_string());
        args.push(user_host(t));
        let r = run(&prog, &args, None, &[]);
        let _ = std::fs::remove_file(&file);
        r
    } else {
        let mut args = openssh_opts(ep);
        args.push("-P".into());
        args.push(t.port.to_string());
        args.push("-b".into());
        args.push("-".into());
        args.push(user_host(t));
        run(&prog, &args, Some(script), &askpass_env(&hops_all(ep)))
    }
}

fn parse_listing(out: &str) -> (Option<String>, Vec<RemoteItem>) {
    let mut cwd = None;
    let mut items = Vec::new();
    for line in out.lines() {
        let l = line.trim_end();
        if let Some(d) = l.strip_prefix("Remote working directory: ") {
            cwd = Some(d.trim().to_string());
        } else if let Some(d) = l.strip_prefix("Remote directory is ") {
            cwd = Some(d.trim().to_string());
        } else if let Some(it) = parse_ls_line(l) {
            items.push(it);
        }
    }
    sort_items(&mut items);
    (cwd, items)
}

fn sftp_list(ep: &Endpoint, path: &str) -> Result<(String, Vec<RemoteItem>), String> {
    let mut script = String::new();
    if !path.is_empty() {
        script.push_str(&format!("cd {}\n", q(path)));
    }
    script.push_str("pwd\nls -la\n");
    let out = sftp_batch(ep, &script)?;
    let (cwd, items) = parse_listing(&out.stdout);
    match cwd {
        Some(c) if out.ok || !items.is_empty() => Ok((c, items)),
        _ => Err(clean_error(&out)),
    }
}

fn sftp_walk(ep: &Endpoint, dir: &str, files: &mut Vec<String>, dirs: &mut Vec<String>, depth: usize) -> Result<(), String> {
    if depth > 12 || files.len() + dirs.len() > 5000 {
        return Err(tr("Folder too deep or too big to delete.").into());
    }
    let (_, items) = sftp_list(ep, dir)?;
    for it in items {
        let p = join(dir, &it.name);
        if it.is_dir && !it.is_link {
            sftp_walk(ep, &p, files, dirs, depth + 1)?;
        } else {
            files.push(p);
        }
    }
    dirs.push(dir.to_string());
    Ok(())
}

fn run_sftp(ep: &Endpoint, job: &Job, cwd: &mut String) -> Result<Outcome, String> {
    let done = |out: RunOut, msg: String| if out.ok { Ok(Outcome::Done(msg)) } else { Err(clean_error(&out)) };
    match job {
        Job::List(p) => {
            let (dir, items) = sftp_list(ep, p)?;
            *cwd = dir.clone();
            Ok(Outcome::Listing(dir, items))
        }
        Job::Download { remote, is_dir, local_dir } => {
            let r = if *is_dir { "-r " } else { "" };
            let script = format!("lcd {0}\nget {1}{2}\n", local_q(local_dir), r, q(remote));
            let out = sftp_batch(ep, &script)?;
            done(out, tf("Downloaded: {0} » {1}", &[&(base_name(remote)), &(local_dir.display())]))
        }
        Job::Upload { local, remote_dir } => {
            let r = if local.is_dir() { "-r " } else { "" };
            let name = local.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let mut script = format!("cd {}\n", q(remote_dir));
            if local.is_dir() {
                script.push_str(&format!("-mkdir {0}\n", q(&name)));
            }
            script.push_str(&format!("put {0}{1} {2}\n", r, local_q(local), q(&name)));
            let out = sftp_batch(ep, &script)?;
            done(out, tf("Uploaded: {0} » {1}", &[&name, &remote_dir]))
        }
        Job::Mkdir(p) => {
            let out = sftp_batch(ep, &format!("mkdir {0}\n", q(p)))?;
            done(out, tf("Folder created: {0}", &[&p]))
        }
        Job::Delete { path, is_dir } => {
            if !*is_dir {
                let out = sftp_batch(ep, &format!("rm {}\n", q(path)))?;
                return done(out, tf("Deleted: {0}", &[&path]));
            }
            let mut files = Vec::new();
            let mut dirs = Vec::new();
            sftp_walk(ep, path, &mut files, &mut dirs, 0)?;
            let mut script = String::new();
            for f in &files {
                script.push_str(&format!("rm {}\n", q(f)));
            }
            for d in &dirs {
                script.push_str(&format!("rmdir {0}\n", q(d)));
            }
            let out = sftp_batch(ep, &script)?;
            done(out, tf("Folder deleted: {0} ({1} files)", &[&path, &(files.len())]))
        }
        Job::Rename { from, to } => {
            let out = sftp_batch(ep, &format!("rename {0} {1}\n", q(from), q(to)))?;
            done(out, tf("Renamed: {0} » {1}", &[&(base_name(from)), &(base_name(to))]))
        }
    }
}

// ------------------------------------------------------------------ SCP (+ ssh commands)

fn sh(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ssh_command(ep: &Endpoint, command: &str) -> Result<RunOut, String> {
    let t = &ep.target;
    let use_putty = ep.tool == Tool::Putty || ep.progs.ssh.is_none();
    if use_putty {
        if let Some(plink) = &ep.progs.plink {
            let mut args = vec!["-batch".to_string(), "-ssh".into(), "-P".into(), t.port.to_string()];
            if !t.password.is_empty() {
                args.push("-pw".into());
                args.push(t.password.clone());
            }
            args.push(user_host(t));
            args.push(command.to_string());
            return run(plink, &args, None, &[]);
        }
    }
    let ssh = ep.progs.ssh.clone().ok_or(tr("No ssh program found (OpenSSH client or plink.exe)."))?;
    let mut args = openssh_opts(ep);
    args.push("-p".into());
    args.push(t.port.to_string());
    args.push(user_host(t));
    args.push(command.to_string());
    run(&ssh, &args, None, &askpass_env(&hops_all(ep)))
}

fn scp_copy(ep: &Endpoint, recursive: bool, from: &str, to: &str) -> Result<RunOut, String> {
    let t = &ep.target;
    let use_putty = ep.tool == Tool::Putty || ep.progs.scp.is_none();
    if use_putty {
        if let Some(pscp) = &ep.progs.pscp {
            let mut args = vec!["-batch".to_string(), "-scp".into(), "-P".into(), t.port.to_string()];
            if !t.password.is_empty() {
                args.push("-pw".into());
                args.push(t.password.clone());
            }
            if recursive {
                args.push("-r".into());
            }
            args.push(from.into());
            args.push(to.into());
            return run(pscp, &args, None, &[]);
        }
    }
    let scp = ep.progs.scp.clone().ok_or(tr("No scp program found (OpenSSH client or pscp.exe)."))?;
    let mut args = openssh_opts(ep);
    args.push("-P".into());
    args.push(t.port.to_string());
    if recursive {
        args.push("-r".into());
    }
    args.push(from.into());
    args.push(to.into());
    run(&scp, &args, None, &askpass_env(&hops_all(ep)))
}

fn remote_spec(ep: &Endpoint, path: &str) -> String {
    format!("{}:{}", user_host(&ep.target), path)
}

fn run_scp(ep: &Endpoint, job: &Job, cwd: &mut String) -> Result<Outcome, String> {
    let done = |out: RunOut, msg: String| if out.ok { Ok(Outcome::Done(msg)) } else { Err(clean_error(&out)) };
    match job {
        Job::List(p) => {
            let cd = if p.is_empty() { String::new() } else { format!("cd -- {} && ", sh(p)) };
            let out = ssh_command(ep, &format!("{0}echo \"Remote working directory: $(pwd)\" && LC_ALL=C ls -la", cd))?;
            let (dir, items) = parse_listing(&out.stdout);
            match dir {
                Some(d) if out.ok => {
                    *cwd = d.clone();
                    Ok(Outcome::Listing(d, items))
                }
                _ => Err(clean_error(&out)),
            }
        }
        Job::Download { remote, is_dir, local_dir } => {
            let out = scp_copy(ep, *is_dir, &remote_spec(ep, remote), &local_dir.display().to_string())?;
            done(out, tf("Downloaded: {0} » {1}", &[&(base_name(remote)), &(local_dir.display())]))
        }
        Job::Upload { local, remote_dir } => {
            let target = if remote_dir.ends_with('/') { remote_dir.clone() } else { format!("{remote_dir}/") };
            let out = scp_copy(ep, local.is_dir(), &local.display().to_string(), &remote_spec(ep, &target))?;
            done(out, tf("Uploaded: {0} » {1}", &[&(local.display()), &remote_dir]))
        }
        Job::Mkdir(p) => done(ssh_command(ep, &format!("mkdir -p -- {0}", sh(p)))?, tf("Folder created: {0}", &[&p])),
        Job::Delete { path, is_dir } => {
            let flag = if *is_dir { "-rf" } else { "-f" };
            done(ssh_command(ep, &format!("rm {0} -- {1}", flag, sh(path)))?, tf("Deleted: {0}", &[&path]))
        }
        Job::Rename { from, to } => done(
            ssh_command(ep, &format!("mv -- {} {}", sh(from), sh(to)))?,
            tf("Renamed: {0} » {1}", &[&(base_name(from)), &(base_name(to))]),
        ),
    }
}

// ------------------------------------------------------------------ FTP / FTPS

enum FtpConn {
    Plain(suppaftp::FtpStream),
    Tls(suppaftp::RustlsFtpStream),
}

macro_rules! with_ftp {
    ($conn:expr, $s:ident => $body:expr) => {
        match $conn {
            FtpConn::Plain($s) => $body,
            FtpConn::Tls($s) => $body,
        }
    };
}

/// Accepts any server certificate (self-signed NAS / router) – only when the person asks for it.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn tls_config(check_cert: bool) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let cfg = if check_cert {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(AnyCert(provider))).with_no_client_auth()
    };
    Ok(Arc::new(cfg))
}

fn ftp_err(e: suppaftp::FtpError) -> String {
    let t = e.to_string();
    if t.contains("530") {
        tf("Login refused (check user/password): {0}", &[&t])
    } else {
        t
    }
}

fn ftp_connect(ep: &Endpoint) -> Result<FtpConn, String> {
    let t = &ep.target;
    let addr = format!("{}:{}", t.host, if t.port == 0 { 21 } else { t.port });
    let user = if t.user.is_empty() { "anonymous".to_string() } else { t.user.clone() };
    let pass = if t.user.is_empty() && t.password.is_empty() { "admincraft@".to_string() } else { t.password.clone() };
    let mut conn = if ep.tls {
        let s = suppaftp::RustlsFtpStream::connect(&addr).map_err(ftp_err)?;
        let cfg = tls_config(ep.check_cert)?;
        let s = s.into_secure(suppaftp::RustlsConnector::from(cfg), &t.host).map_err(|e| {
            let m = ftp_err(e);
            if m.to_lowercase().contains("certificate") {
                tf("Certificate not trusted ({0}). For self-signed devices tick \"Don't check the certificate\" on the connection.", &[&m])
            } else {
                tf("TLS failed: {0}", &[&m])
            }
        })?;
        FtpConn::Tls(s)
    } else {
        FtpConn::Plain(suppaftp::FtpStream::connect(&addr).map_err(ftp_err)?)
    };
    with_ftp!(&mut conn, s => {
        s.set_passive_nat_workaround(true);
        s.login(user.as_str(), pass.as_str()).map_err(ftp_err)?;
        s.transfer_type(suppaftp::types::FileType::Binary).map_err(ftp_err)?;
    });
    Ok(conn)
}

#[allow(deprecated)]
fn ftp_list_dir(conn: &mut FtpConn, path: &str) -> Result<(String, Vec<RemoteItem>), String> {
    with_ftp!(conn, s => {
        if !path.is_empty() {
            s.cwd(path).map_err(ftp_err)?;
        }
        let dir = s.pwd().map_err(ftp_err)?;
        let lines = s.list(None).map_err(ftp_err)?;
        let mut items = Vec::new();
        for l in lines {
            if let Some(it) = parse_ls_line(&l) {
                items.push(it);
            } else if let Ok(f) = suppaftp::list::File::from_dos_line(&l) {
                if f.name() != "." && f.name() != ".." {
                    items.push(RemoteItem {
                        name: f.name().to_string(),
                        is_dir: f.is_directory(),
                        is_link: false,
                        size: f.size() as u64,
                        modified: String::new(),
                        perms: String::new(),
                    });
                }
            }
        }
        sort_items(&mut items);
        Ok((dir, items))
    })
}

fn ftp_download(conn: &mut FtpConn, remote: &str, local: &Path, is_dir: bool, depth: usize) -> Result<usize, String> {
    if !is_dir {
        let mut file = std::fs::File::create(local).map_err(|e| format!("{}: {e}", local.display()))?;
        with_ftp!(conn, s => {
            s.retr(remote, |r| std::io::copy(r, &mut file).map_err(suppaftp::FtpError::ConnectionError)).map_err(ftp_err)?;
        });
        return Ok(1);
    }
    if depth > 16 {
        return Err(tr("Folder nested too deeply.").into());
    }
    std::fs::create_dir_all(local).map_err(|e| e.to_string())?;
    let (_, items) = ftp_list_dir(conn, remote)?;
    let mut n = 0;
    for it in items {
        if it.is_link {
            continue;
        }
        n += ftp_download(conn, &join(remote, &it.name), &local.join(&it.name), it.is_dir, depth + 1)?;
    }
    Ok(n)
}

fn ftp_upload(conn: &mut FtpConn, local: &Path, remote: &str, depth: usize) -> Result<usize, String> {
    if local.is_dir() {
        if depth > 16 {
            return Err(tr("Folder nested too deeply.").into());
        }
        with_ftp!(conn, s => {
            let _ = s.mkdir(remote);
        });
        let mut n = 0;
        let rd = std::fs::read_dir(local).map_err(|e| e.to_string())?;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            n += ftp_upload(conn, &e.path(), &join(remote, &name), depth + 1)?;
        }
        return Ok(n);
    }
    let mut file = std::fs::File::open(local).map_err(|e| format!("{}: {e}", local.display()))?;
    with_ftp!(conn, s => {
        s.put_file(remote, &mut file).map_err(ftp_err)?;
    });
    Ok(1)
}

fn ftp_delete(conn: &mut FtpConn, path: &str, is_dir: bool, depth: usize) -> Result<(), String> {
    if is_dir {
        if depth > 16 {
            return Err(tr("Folder nested too deeply.").into());
        }
        let (_, items) = ftp_list_dir(conn, path)?;
        for it in items {
            ftp_delete(conn, &join(path, &it.name), it.is_dir && !it.is_link, depth + 1)?;
        }
        with_ftp!(conn, s => {
            s.cwd("/").ok();
            s.rmdir(path).map_err(ftp_err)
        })
    } else {
        with_ftp!(conn, s => s.rm(path).map_err(ftp_err))
    }
}

fn run_ftp(ep: &Endpoint, slot: &mut Option<FtpConn>, job: &Job, cwd: &mut String) -> Result<Outcome, String> {
    // reconnect when the server closed the connection
    let alive = match slot.as_mut() {
        Some(c) => with_ftp!(c, s => s.noop().is_ok()),
        None => false,
    };
    if !alive {
        *slot = Some(ftp_connect(ep)?);
    }
    let conn = slot.as_mut().unwrap();
    let result = match job {
        Job::List(p) => {
            let (dir, items) = ftp_list_dir(conn, p)?;
            *cwd = dir.clone();
            Outcome::Listing(dir, items)
        }
        Job::Download { remote, is_dir, local_dir } => {
            let n = ftp_download(conn, remote, &local_dir.join(base_name(remote)), *is_dir, 0)?;
            Outcome::Done(tf("Downloaded: {0} ({1} files) » {2}", &[&(base_name(remote)), &n, &(local_dir.display())]))
        }
        Job::Upload { local, remote_dir } => {
            let name = local.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let n = ftp_upload(conn, local, &join(remote_dir, &name), 0)?;
            Outcome::Done(tf("Uploaded: {0} ({1} files) » {2}", &[&name, &n, &remote_dir]))
        }
        Job::Mkdir(p) => {
            with_ftp!(conn, s => s.mkdir(p.as_str()).map_err(ftp_err))?;
            Outcome::Done(tf("Folder created: {0}", &[&p]))
        }
        Job::Delete { path, is_dir } => {
            ftp_delete(conn, path, *is_dir, 0)?;
            Outcome::Done(tf("Deleted: {0}", &[&path]))
        }
        Job::Rename { from, to } => {
            with_ftp!(conn, s => s.rename(from.as_str(), to.as_str()).map_err(ftp_err))?;
            Outcome::Done(tf("Renamed: {0} » {1}", &[&(base_name(from)), &(base_name(to))]))
        }
    };
    // keep the server in the folder the person looks at
    if !matches!(job, Job::List(_)) && !cwd.is_empty() {
        let c = cwd.clone();
        with_ftp!(conn, s => {
            let _ = s.cwd(c.as_str());
        });
    }
    Ok(result)
}

// ------------------------------------------------------------------ local side

#[derive(Clone, Debug)]
pub struct LocalItem {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub modified: String,
}

pub fn list_local(dir: &Path, show_hidden: bool) -> Result<Vec<LocalItem>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut v: Vec<LocalItem> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !show_hidden && name.starts_with('.') {
                return None;
            }
            let md = e.metadata().ok();
            let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = md.as_ref().map(|m| if m.is_dir() { 0 } else { m.len() }).unwrap_or(0);
            let modified = md.and_then(|m| m.modified().ok()).map(fmt_time).unwrap_or_default();
            Some(LocalItem { name, path: e.path(), is_dir, size, modified })
        })
        .collect();
    v.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(v)
}

/// Drive letters on Windows ("C:\", "D:\" ...).
pub fn drives() -> Vec<PathBuf> {
    if cfg!(windows) {
        (b'A'..=b'Z')
            .map(|c| PathBuf::from(format!("{}:\\", c as char)))
            .filter(|p| p.exists())
            .collect()
    } else {
        vec![PathBuf::from("/")]
    }
}

fn fmt_time(t: std::time::SystemTime) -> String {
    let secs = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{d:02}.{m:02}.{y} {:02}:{:02}", rem / 3600, (rem % 3600) / 60)
}

pub fn human_size(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Default local folder: Downloads, else home.
pub fn default_local_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let dl = home.join("Downloads");
    if dl.is_dir() {
        dl
    } else {
        home
    }
}

#[allow(dead_code)]
pub type JobQueue = VecDeque<Job>;

/// Self-check from the command line: `admincraft --transfer-check sftp|scp|ftp|ftps host user`
/// with the password in AC_CHECK_PW. Lists the start folder, downloads the first small file
/// into `download_dir` and prints what happened.
pub fn cli_check(kind: &str, host: &str, user: &str, download_dir: &Path) -> String {
    let settings = crate::model::Settings::default();
    let progs = Progs {
        ssh: crate::programs::find("ssh", &settings),
        sftp: crate::programs::find("sftp", &settings),
        scp: crate::programs::find("scp", &settings),
        plink: crate::programs::find("plink", &settings),
        psftp: crate::programs::find("psftp", &settings),
        pscp: crate::programs::find("pscp", &settings),
    };
    let k = match kind {
        "ftp" | "ftps" => Kind::Ftp,
        "scp" => Kind::Scp,
        _ => Kind::Sftp,
    };
    let ep = Endpoint {
        kind: k,
        target: Hop {
            user: user.into(),
            host: host.into(),
            port: if k == Kind::Ftp { 21 } else { 22 },
            password: std::env::var("AC_CHECK_PW").unwrap_or_default(),
        },
        key_file: String::new(),
        jumps: Vec::new(),
        tls: kind == "ftps",
        check_cert: true,
        tool: Tool::OpenSsh,
        progs,
    };
    let mut out = String::new();
    let mut ftp = None;
    let mut cwd = String::new();
    let mut go = |job: Job, cwd: &mut String| match k {
        Kind::Ftp => run_ftp(&ep, &mut ftp, &job, cwd),
        Kind::Sftp => run_sftp(&ep, &job, cwd),
        Kind::Scp => run_scp(&ep, &job, cwd),
    };
    match go(Job::List(String::new()), &mut cwd) {
        Ok(Outcome::Listing(dir, items)) => {
            out.push_str(&format!("LIST OK {0}: {1} entries\n", dir, items.len()));
            for it in items.iter().take(12) {
                out.push_str(&format!("  {} {} {}\n", if it.is_dir { "D" } else { "F" }, it.size, it.name));
            }
            if let Some(f) = items.iter().find(|i| !i.is_dir && !i.is_link && i.size < 200_000) {
                let _ = std::fs::create_dir_all(download_dir);
                let remote = join(&dir, &f.name);
                match go(Job::Download { remote, is_dir: false, local_dir: download_dir.to_path_buf() }, &mut cwd) {
                    Ok(Outcome::Done(m)) => {
                        let ok = download_dir.join(&f.name).is_file();
                        out.push_str(&format!("GET OK ({0}): {1}\n", ok, m));
                    }
                    Ok(_) => out.push_str("GET ?\n"),
                    Err(e) => out.push_str(&format!("GET ERROR: {0}\n", e)),
                }
            }
        }
        Ok(_) => out.push_str("LIST ?\n"),
        Err(e) => out.push_str(&format!("LIST ERROR: {0}\n", e)),
    }
    out
}
