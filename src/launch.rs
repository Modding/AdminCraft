//! Turns a connection into a terminal command (shown in a tab), an outside program (its window
//! placed in a tab where the system allows it), or a file transfer tab.

#[allow(unused_imports)]
use crate::i18n::{t as tr, tf};
use crate::model::{Entry, JumpMode, Protocol, Settings, SshClient};
use crate::programs;
use portable_pty::CommandBuilder;
use std::path::PathBuf;
use std::process::{Child, Command};

#[derive(Clone, Debug, Default)]
pub struct Creds {
    pub user: String,
    pub domain: String,
    pub password: String,
}

impl Creds {
    pub fn full_user(&self) -> String {
        if self.domain.is_empty() || self.user.contains('\\') || self.user.contains('@') {
            self.user.clone()
        } else if self.user.is_empty() {
            String::new()
        } else {
            format!("{}\\{}", self.domain, self.user)
        }
    }
}

/// One jump host in front of a connection, with its resolved login.
#[derive(Clone, Debug)]
pub struct JumpHop {
    pub entry: Entry,
    pub creds: Creds,
}

/// Which password to type when a prompt names this host ("root@10.0.0.40's password:").
#[derive(Clone, Debug)]
pub struct PwRule {
    pub host: String,
    pub user: String,
    pub password: String,
}

pub enum Launch {
    /// Runs in an AdminCraft terminal tab. Passwords are typed in when asked; `chain` commands
    /// are typed at the next shell prompts (jump host: `ssh user@next`).
    Terminal { cmd: CommandBuilder, preview: String, passwords: Vec<PwRule>, chain: Vec<String> },
    /// An outside program; `embed` = window classes to place into the tab (Windows).
    Process { child: Child, label: String, embed: Option<&'static [&'static str]> },
    /// Handed to the system (browser, macOS app); nothing to follow.
    Done(String),
    /// Opens the two-pane file transfer.
    Transfer,
}

pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into()).split(';').map(|s| s.to_lowercase()).collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let cand = dir.join(format!("{program}{ext}"));
            if cand.is_file() {
                return Some(cand);
            }
        }
        let plain = dir.join(program);
        if plain.is_file() && !cfg!(windows) {
            return Some(plain);
        }
    }
    None
}

fn first_found(names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|n| {
        let p = PathBuf::from(n);
        if p.is_absolute() { p.is_file().then_some(p) } else { which(n) }
    })
}

/// Splits a command template into words, honouring "double quotes".
pub fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn fill(template: &str, e: &Entry, c: &Creds) -> String {
    template
        .replace("{host}", e.host.trim())
        .replace("{port}", &e.port.to_string())
        .replace("{user}", &c.user)
        .replace("{domain}", &c.domain)
        .replace("{password}", &c.password)
        .replace("{name}", &e.name)
}

fn hidden(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

fn spawn(program: &PathBuf, args: &[String]) -> Result<Child, String> {
    Command::new(program).args(args).spawn().map_err(|e| tf("{0} could not be started: {1}", &[&(program.display()), &e]))
}

pub fn open_url(url: &str) -> Result<(), String> {
    let r = if cfg!(windows) {
        hidden(Command::new("rundll32").args(["url.dll,FileProtocolHandler", url])).spawn()
    } else if cfg!(target_os = "macos") {
        Command::new("open").arg(url).spawn()
    } else {
        Command::new("xdg-open").arg(url).spawn()
    };
    r.map(|_| ()).map_err(|e| tf("Could not open {0}: {1}", &[&url, &e]))
}

pub fn open_folder(path: &std::path::Path) {
    let _ = if cfg!(windows) {
        Command::new("explorer").arg(path).spawn()
    } else if cfg!(target_os = "macos") {
        Command::new("open").arg(path).spawn()
    } else {
        Command::new("xdg-open").arg(path).spawn()
    };
}

fn user_host(user: &str, host: &str) -> String {
    if user.is_empty() { host.trim().to_string() } else { format!("{}@{}", user, host.trim()) }
}

fn terminal_env(cmd: &mut CommandBuilder) {
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
}

fn effective_port(e: &Entry) -> u16 {
    if e.port == 0 { e.protocol.default_port() } else { e.port }
}

pub fn ssh_client_for(e: &Entry, settings: &Settings) -> SshClient {
    match e.ssh_client {
        SshClient::Default => match settings.default_ssh_client {
            SshClient::Default => SshClient::Builtin,
            other => other,
        },
        other => other,
    }
}

fn pw_rules(e: &Entry, c: &Creds, jumps: &[JumpHop]) -> Vec<PwRule> {
    let mut v: Vec<PwRule> = jumps
        .iter()
        .map(|j| PwRule { host: j.entry.host.trim().to_string(), user: j.creds.user.clone(), password: j.creds.password.clone() })
        .collect();
    v.push(PwRule { host: e.host.trim().to_string(), user: c.user.clone(), password: c.password.clone() });
    v.retain(|r| !r.password.is_empty());
    v
}

pub fn launch(e: &Entry, c: &Creds, settings: &Settings, jumps: &[JumpHop], tab_px: (u32, u32)) -> Result<Launch, String> {
    if e.protocol.needs_host() && e.host.trim().is_empty() {
        return Err(tr("No host entered.").into());
    }
    let single_pw = if c.password.is_empty() {
        Vec::new()
    } else {
        vec![PwRule { host: e.host.trim().to_string(), user: c.user.clone(), password: c.password.clone() }]
    };

    // An own command from the settings always wins.
    if let Some(t) = settings.templates.get(e.protocol.key()).filter(|t| !t.trim().is_empty()) {
        let words: Vec<String> = split_words(t).iter().map(|w| fill(w, e, c)).collect();
        if words.is_empty() {
            return Err(tr("Own command is empty.").into());
        }
        let preview = fill(&split_words(t).join(" "), e, &Creds { user: c.user.clone(), domain: c.domain.clone(), password: "••••".into() });
        if e.protocol.embedded() {
            let mut cmd = CommandBuilder::new(&words[0]);
            cmd.args(&words[1..]);
            terminal_env(&mut cmd);
            return Ok(Launch::Terminal { cmd, preview, passwords: single_pw, chain: Vec::new() });
        }
        let prog = PathBuf::from(&words[0]);
        let child = spawn(&prog, &words[1..])?;
        let embed: Option<&'static [&'static str]> =
            if settings.embed_windows && matches!(e.protocol, Protocol::Rdp | Protocol::Vnc | Protocol::Ssh) { Some(&[]) } else { None };
        return Ok(Launch::Process { child, label: tf("Own command: {0}", &[&preview]), embed });
    }

    let extra = split_words(&e.extra_args);
    match e.protocol {
        Protocol::Ssh => match ssh_client_for(e, settings) {
            SshClient::Putty => launch_putty(e, c, settings, jumps),
            SshClient::External => launch_ssh_external(e, c, settings, jumps),
            _ => launch_ssh_builtin(e, c, settings, jumps, &extra),
        },
        Protocol::Sftp | Protocol::Scp | Protocol::Ftp => Ok(Launch::Transfer),
        Protocol::Telnet => {
            let prog = programs::find("telnet", settings).ok_or_else(|| {
                if cfg!(windows) {
                    tr("Telnet client missing. Turn it on: Windows key » \"Turn Windows features on or off\" » Telnet Client. Or use PuTTY.")
                        .to_string()
                } else {
                    tr("Program 'telnet' not found (install package telnet / inetutils).").to_string()
                }
            })?;
            let mut cmd = CommandBuilder::new(prog);
            cmd.args(&extra);
            cmd.arg(e.host.trim());
            cmd.arg(effective_port(e).to_string());
            terminal_env(&mut cmd);
            Ok(Launch::Terminal {
                cmd,
                preview: format!("telnet {0} {1}", e.host.trim(), effective_port(e)),
                passwords: single_pw,
                chain: Vec::new(),
            })
        }
        Protocol::PowerShell => {
            let ps = if cfg!(windows) { first_found(&["pwsh", "powershell"]) } else { first_found(&["pwsh"]) }
                .ok_or(tr("PowerShell not found (install pwsh)."))?;
            let mut script = String::from("Enter-PSSession -ComputerName $env:AC_HOST");
            if e.port != 0 && e.port != 5985 {
                script.push_str(&format!(" -Port {0}", e.port));
                if e.port == 5986 {
                    script.push_str(" -UseSSL");
                }
            }
            let mut cmd = CommandBuilder::new(&ps);
            cmd.env("AC_HOST", e.host.trim());
            if !c.user.is_empty() {
                cmd.env("AC_USER", c.full_user());
                if !c.password.is_empty() {
                    cmd.env("AC_PW", &c.password);
                    script = format!(
                        "$c = New-Object System.Management.Automation.PSCredential($env:AC_USER, (ConvertTo-SecureString $env:AC_PW -AsPlainText -Force)); Remove-Item Env:AC_PW; {0} -Credential $c",
                        script
                    );
                } else {
                    script.push_str(" -Credential $env:AC_USER");
                }
            }
            cmd.args(["-NoLogo", "-NoExit", "-Command", &script]);
            let preview = format!("Enter-PSSession -ComputerName {0}", e.host.trim());
            Ok(Launch::Terminal { cmd, preview, passwords: Vec::new(), chain: Vec::new() })
        }
        Protocol::LocalShell => {
            let mut cmd = if cfg!(windows) {
                let ps = first_found(&["pwsh", "powershell"]).unwrap_or_else(|| PathBuf::from("cmd.exe"));
                let mut cmd = CommandBuilder::new(ps);
                cmd.arg("-NoLogo");
                cmd
            } else {
                let mut cmd = CommandBuilder::new_default_prog();
                terminal_env(&mut cmd);
                cmd
            };
            if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
                cmd.cwd(home);
            }
            Ok(Launch::Terminal { cmd, preview: tr("Local shell").into(), passwords: Vec::new(), chain: Vec::new() })
        }
        Protocol::Http | Protocol::Https => {
            let scheme = if e.protocol == Protocol::Http { "http" } else { "https" };
            let host = e.host.trim();
            let url = if host.contains("://") {
                host.to_string()
            } else if e.port == e.protocol.default_port() || e.port == 0 {
                format!("{scheme}://{host}")
            } else {
                format!("{scheme}://{host}:{}", e.port)
            };
            if e.web_in_tab
                && settings.embed_windows
                && cfg!(windows)
                && let Some(browser) = programs::find("browser", settings)
            {
                // own profile per connection: a new browser process whose window we can take in
                let profile = std::env::temp_dir().join("admincraft").join(format!("web-{}", e.id));
                let args = vec![
                    format!("--app={url}"),
                    format!("--user-data-dir={}", profile.display()),
                    "--no-first-run".to_string(),
                    "--no-default-browser-check".to_string(),
                    "--disable-features=Translate".to_string(),
                ];
                let child = spawn(&browser, &args)?;
                return Ok(Launch::Process { child, label: tf("Web in tab: {0}", &[&url]), embed: Some(&["Chrome_WidgetWin_1"]) });
            }
            open_url(&url)?;
            Ok(Launch::Done(tf("Browser opened: {0}", &[&url])))
        }
        Protocol::Rdp => launch_rdp(e, c, settings, tab_px),
        Protocol::Vnc => launch_vnc(e, c, settings),
        Protocol::Serial | Protocol::Raw | Protocol::Rlogin => launch_line(e, c, settings, &extra),
    }
}

/// Serial console, raw TCP and rlogin: PuTTY in the tab, else plink in a terminal tab, else
/// the usual Linux/macOS programs (picocom, screen, nc, rlogin).
fn launch_line(e: &Entry, c: &Creds, settings: &Settings, extra: &[String]) -> Result<Launch, String> {
    let host = e.host.trim().to_string();
    let baud = if e.baud == 0 { 9600 } else { e.baud };
    let mut args: Vec<String> = match e.protocol {
        Protocol::Serial => vec!["-serial".into(), host.clone(), "-sercfg".into(), format!("{baud},8,n,1,N")],
        Protocol::Raw => vec!["-raw".into(), "-P".into(), effective_port(e).to_string(), host.clone()],
        _ => {
            let mut v = vec!["-rlogin".into(), "-P".into(), effective_port(e).to_string()];
            if !c.user.is_empty() {
                v.push("-l".into());
                v.push(c.user.clone());
            }
            v.push(host.clone());
            v
        }
    };
    args.extend(extra.iter().cloned());
    if let Some(putty) = programs::find("putty", settings) {
        let child = spawn(&putty, &args)?;
        let embed: Option<&'static [&'static str]> = if settings.embed_windows { Some(&["PuTTY"]) } else { None };
        return Ok(Launch::Process { child, label: tf("PuTTY: {0}", &[&host]), embed });
    }
    let pw = if c.password.is_empty() { Vec::new() } else { vec![PwRule { host: host.clone(), user: c.user.clone(), password: c.password.clone() }] };
    if let Some(plink) = programs::find("plink", settings) {
        let mut cmd = CommandBuilder::new(&plink);
        cmd.args(&args);
        terminal_env(&mut cmd);
        return Ok(Launch::Terminal { cmd, preview: format!("plink {}", args.join(" ")), passwords: pw, chain: Vec::new() });
    }
    let (prog, a): (Option<PathBuf>, Vec<String>) = match e.protocol {
        Protocol::Serial => {
            if let Some(p) = first_found(&["picocom"]) {
                (Some(p), vec!["-b".into(), baud.to_string(), host.clone()])
            } else if let Some(p) = first_found(&["screen"]) {
                (Some(p), vec![host.clone(), baud.to_string()])
            } else if let Some(p) = first_found(&["minicom"]) {
                (Some(p), vec!["-D".into(), host.clone(), "-b".into(), baud.to_string()])
            } else {
                (None, Vec::new())
            }
        }
        Protocol::Raw => match first_found(&["nc", "ncat", "telnet"]) {
            Some(p) => (Some(p), vec![host.clone(), effective_port(e).to_string()]),
            None => (None, Vec::new()),
        },
        _ => match first_found(&["rlogin"]) {
            Some(p) => (Some(p), if c.user.is_empty() { vec![host.clone()] } else { vec!["-l".into(), c.user.clone(), host.clone()] }),
            None => (None, Vec::new()),
        },
    };
    let Some(prog) = prog else {
        return Err(tf(
            "This needs PuTTY or plink (put it into the programs folder: {0}). Linux/macOS: install picocom, screen, nc or rlogin.",
            &[&programs::tools_dir().display()],
        ));
    };
    let mut cmd = CommandBuilder::new(&prog);
    cmd.args(&a);
    terminal_env(&mut cmd);
    Ok(Launch::Terminal { cmd, preview: format!("{} {}", prog.display(), a.join(" ")), passwords: pw, chain: Vec::new() })
}

// ------------------------------------------------------------------ SSH

fn ssh_program(settings: &Settings) -> Result<PathBuf, String> {
    programs::find("ssh", settings).ok_or_else(|| {
        tr("OpenSSH (ssh) not found. Windows: Settings » System » Optional features » OpenSSH Client. Linux: package openssh-client. Or choose PuTTY as SSH program.").to_string()
    })
}

/// The `ssh` command typed on a jump host to reach the next host.
#[allow(dead_code)]
pub fn chain_command(e: &Entry, c: &Creds) -> String {
    let port = effective_port(e);
    let p = if port == 22 { String::new() } else { format!(" -p {0}", port) };
    format!("ssh -t{0} {1}", p, user_host(&c.user, &e.host))
}

fn jump_spec(jumps: &[JumpHop]) -> String {
    jumps
        .iter()
        .map(|j| {
            let port = effective_port(&j.entry);
            let uh = user_host(&j.creds.user, &j.entry.host);
            if port == 22 { uh } else { format!("{uh}:{port}") }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Chain mode: what runs on the first jump host – `ssh -t next ssh -t ... target` – so the SSH
/// key that lives on the jump host is used for the next hop (nothing is tunnelled).
pub fn chain_remote_args(e: &Entry, c: &Creds, jumps: &[JumpHop]) -> Vec<String> {
    let mut hops: Vec<(&Entry, &Creds)> = jumps.iter().skip(1).map(|j| (&j.entry, &j.creds)).collect();
    hops.push((e, c));
    let mut v = Vec::new();
    for (he, hc) in hops {
        v.push("ssh".into());
        v.push("-t".into());
        let port = effective_port(he);
        if port != 22 {
            v.push("-p".into());
            v.push(port.to_string());
        }
        v.push(user_host(&hc.user, &he.host));
    }
    v
}

fn launch_ssh_builtin(e: &Entry, c: &Creds, settings: &Settings, jumps: &[JumpHop], extra: &[String]) -> Result<Launch, String> {
    let prog = ssh_program(settings)?;
    let passwords = pw_rules(e, c, jumps);
    // Chain mode: log in to the first jump host and run `ssh -t user@target` there right away.
    let chain_mode = !jumps.is_empty() && e.jump_mode == JumpMode::Chain;
    let (first, first_creds) = if chain_mode { (&jumps[0].entry, &jumps[0].creds) } else { (e, c) };
    let remote: Vec<String> = if chain_mode { chain_remote_args(e, c, jumps) } else { Vec::new() };
    let chain: Vec<String> = Vec::new();
    let mut cmd = CommandBuilder::new(&prog);
    let mut preview = vec!["ssh".to_string()];
    if chain_mode {
        cmd.arg("-t");
        preview.push("-t".into());
    }
    let port = effective_port(first);
    if port != 22 {
        cmd.arg("-p");
        cmd.arg(port.to_string());
        preview.push(format!("-p {0}", port));
    }
    if !first.ssh_key.trim().is_empty() {
        cmd.arg("-i");
        cmd.arg(first.ssh_key.trim());
        preview.push(format!("-i {}", first.ssh_key.trim()));
    }
    if !jumps.is_empty() && e.jump_mode == JumpMode::ProxyJump {
        let spec = jump_spec(jumps);
        cmd.arg("-J");
        cmd.arg(&spec);
        preview.push(format!("-J {0}", spec));
    }
    let fextra = split_words(&first.extra_args);
    let extra_used: &[String] = if std::ptr::eq(first, e) { extra } else { &fextra };
    cmd.args(extra_used);
    preview.extend(extra_used.iter().cloned());
    let target = user_host(&first_creds.user, &first.host);
    cmd.arg(&target);
    preview.push(target);
    if !remote.is_empty() {
        cmd.args(&remote);
        preview.extend(remote.iter().cloned());
    }
    terminal_env(&mut cmd);
    Ok(Launch::Terminal { cmd, preview: preview.join(" "), passwords, chain })
}

fn launch_ssh_external(e: &Entry, c: &Creds, settings: &Settings, jumps: &[JumpHop]) -> Result<Launch, String> {
    let prog = ssh_program(settings)?;
    let mut args: Vec<String> = Vec::new();
    let chain_mode = !jumps.is_empty() && e.jump_mode == JumpMode::Chain;
    let (first, first_c) = if chain_mode { (&jumps[0].entry, &jumps[0].creds) } else { (e, c) };
    if chain_mode {
        args.push("-t".into());
    }
    let port = effective_port(first);
    if port != 22 {
        args.push("-p".into());
        args.push(port.to_string());
    }
    if !first.ssh_key.trim().is_empty() {
        args.push("-i".into());
        args.push(first.ssh_key.trim().into());
    }
    if !jumps.is_empty() && !chain_mode {
        args.push("-J".into());
        args.push(jump_spec(jumps));
    }
    args.extend(split_words(&first.extra_args));
    args.push(user_host(&first_c.user, &first.host));
    if chain_mode {
        args.extend(chain_remote_args(e, c, jumps));
    }
    let mut hops: Vec<crate::transfer::Hop> = jumps
        .iter()
        .map(|j| crate::transfer::Hop {
            user: j.creds.user.clone(),
            host: j.entry.host.trim().into(),
            port: effective_port(&j.entry),
            password: j.creds.password.clone(),
        })
        .collect();
    hops.push(crate::transfer::Hop { user: c.user.clone(), host: e.host.trim().into(), port, password: c.password.clone() });
    let env = if hops.iter().any(|h| !h.password.is_empty()) { crate::transfer::askpass_env(&hops) } else { Vec::new() };
    let how = programs::spawn_in_terminal(&prog, &args, &e.name, &env)?;
    Ok(Launch::Done(tf("OpenSSH in own window ({0}): {1}", &[&how, &(user_host(&c.user, &e.host))])))
}

fn launch_putty(e: &Entry, c: &Creds, settings: &Settings, jumps: &[JumpHop]) -> Result<Launch, String> {
    let putty = programs::find("putty", settings).ok_or_else(|| {
        tf("PuTTY not found. Put putty.exe into the programs folder ({0}) or enter its path in the settings.", &[&(programs::tools_dir().display())])
    })?;
    // Chain mode: PuTTY logs in to the first jump host and runs `ssh -t user@target` there
    // (the SSH key for the next hop stays on the jump host).
    let chain_mode = !jumps.is_empty() && e.jump_mode == JumpMode::Chain;
    let (first, first_c) = if chain_mode { (&jumps[0].entry, &jumps[0].creds) } else { (e, c) };
    let mut args = vec!["-ssh".to_string(), "-P".into(), effective_port(first).to_string()];
    if !first_c.user.is_empty() {
        args.push("-l".into());
        args.push(first_c.user.clone());
    }
    // The password goes through a file only the user can read (-pwfile), not through the
    // command line; only a PuTTY older than 0.77 still gets -pw, and the tab says so.
    let mut secrets = Vec::new();
    let mut old_putty = false;
    let (pw_args, pw_file) = crate::secretfile::putty_password(&putty, &first_c.password)?;
    old_putty |= !first_c.password.is_empty() && pw_file.is_none();
    args.extend(pw_args);
    secrets.extend(pw_file);
    if !first.ssh_key.trim().is_empty() {
        args.push("-i".into());
        args.push(first.ssh_key.trim().into());
    }
    let note = |old: bool| if old { tr(" – old PuTTY: the password is on its command line, please update PuTTY") } else { "" };
    if chain_mode {
        // the command PuTTY runs on the jump host names hosts and users: a private file that goes
        // when PuTTY ends, like the password files
        let file = crate::secretfile::write(&chain_remote_args(e, c, jumps).join(" "))?;
        args.push("-t".into());
        args.push("-m".into());
        args.push(file.path().display().to_string());
        secrets.push(file);
        args.push(first.host.trim().into());
        let child = spawn(&putty, &args)?;
        crate::secretfile::keep_while_running(child.id(), secrets);
        let embed: Option<&'static [&'static str]> = if settings.embed_windows { Some(&["PuTTY"]) } else { None };
        return Ok(Launch::Process {
            child,
            label: tf("PuTTY: {0} » {1}", &[&(user_host(&first_c.user, &first.host)), &(user_host(&c.user, &e.host))]) + note(old_putty),
            embed,
        });
    }
    match jumps.len() {
        0 => {}
        1 => {
            let plink = programs::find("plink", settings).ok_or(tr("A jump host with PuTTY needs plink.exe (put it into the programs folder)."))?;
            let j = &jumps[0];
            let mut pc = format!("\"{0}\" -batch -ssh -P {1}", plink.display(), effective_port(&j.entry));
            if !j.creds.user.is_empty() {
                pc.push_str(&format!(" -l {}", j.creds.user));
            }
            // the jump host's password: plink reads its file again on every reconnect, so the
            // file stays until PuTTY ends
            let (_, pw_file) = crate::secretfile::putty_password(&plink, &j.creds.password)?;
            match pw_file {
                Some(file) => {
                    pc.push_str(&format!(" -pwfile \"{}\"", file.path().display()));
                    secrets.push(file);
                }
                None if !j.creds.password.is_empty() => {
                    old_putty = true;
                    pc.push_str(&format!(" -pw \"{}\"", j.creds.password.replace('"', "\\\"")));
                }
                None => {}
            }
            pc.push_str(&format!(" -nc %host:%port {0}", j.entry.host.trim()));
            args.push("-proxycmd".into());
            args.push(pc);
        }
        _ => return Err(tr("PuTTY can only go through one jump host. For more: choose the built-in terminal.").into()),
    }
    args.extend(split_words(&e.extra_args));
    args.push(e.host.trim().into());
    let child = spawn(&putty, &args)?;
    crate::secretfile::keep_while_running(child.id(), secrets);
    let embed: Option<&'static [&'static str]> = if settings.embed_windows { Some(&["PuTTY"]) } else { None };
    Ok(Launch::Process { child, label: tf("PuTTY: {0}", &[&(user_host(&c.user, &e.host))]) + note(old_putty), embed })
}

// ------------------------------------------------------------------ RDP

fn rdp_file(e: &Entry, c: &Creds, size: Option<(u32, u32)>) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("admincraft");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let safe: String = e.name.chars().map(|ch| if ch.is_alphanumeric() || ch == '-' || ch == '_' { ch } else { '_' }).collect();
    let path = dir.join(format!("{}.rdp", if safe.is_empty() { "connection".into() } else { safe }));
    let o = &e.rdp;
    let mut s = String::new();
    let addr = if e.port == 3389 || e.port == 0 { e.host.trim().to_string() } else { format!("{}:{}", e.host.trim(), e.port) };
    s.push_str(&format!("full address:s:{0}\r\n", addr));
    if !c.user.is_empty() {
        s.push_str(&format!("username:s:{}\r\n", c.full_user()));
    }
    let fullscreen = o.fullscreen && size.is_none();
    s.push_str(&format!("screen mode id:i:{0}\r\n", if fullscreen { 2 } else { 1 }));
    let (w, h) = size.unwrap_or((o.width, o.height));
    if !fullscreen && w > 0 && h > 0 {
        s.push_str(&format!("desktopwidth:i:{w}\r\ndesktopheight:i:{h}\r\n"));
    }
    s.push_str(&format!("use multimon:i:{0}\r\n", (o.multimon && size.is_none()) as u8));
    s.push_str(&format!("redirectclipboard:i:{}\r\n", o.redirect_clipboard as u8));
    if o.redirect_drives {
        s.push_str("drivestoredirect:s:*\r\n");
    }
    if o.admin_session {
        s.push_str("administrative session:i:1\r\n");
    }
    s.push_str("authentication level:i:2\r\nprompt for credentials:i:0\r\nsmart sizing:i:1\r\ndynamic resolution:i:1\r\nautoreconnection enabled:i:1\r\ndisplayconnectionbar:i:0\r\n");
    std::fs::write(&path, s).map_err(|e| e.to_string())?;
    Ok(path)
}

fn launch_rdp(e: &Entry, c: &Creds, settings: &Settings, tab_px: (u32, u32)) -> Result<Launch, String> {
    let host = e.host.trim();
    if cfg!(windows) {
        let embed = settings.embed_windows && !e.rdp.fullscreen && !e.rdp.multimon;
        let size = if embed && tab_px.0 > 200 && tab_px.1 > 150 { Some((tab_px.0, tab_px.1)) } else { None };
        let file = rdp_file(e, c, size)?;
        let mut note = String::new();
        let mut forget = None;
        if e.rdp.pass_credentials && !c.user.is_empty() && !c.password.is_empty() {
            let target = format!("TERMSRV/{host}");
            // through the Windows API, so the password is on no command line; removed again
            // once Remote Desktop has read it (unless the entry was there before)
            let stored = crate::wincred::store(&target, &c.full_user(), &c.password);
            let ok = stored.is_ok();
            if stored == Ok(false) {
                forget = Some(target);
            }
            note = if ok { tr(" – login passed").into() } else { tr(" – login could not be passed").into() };
        }
        let mut args = vec![file.display().to_string()];
        if e.rdp.admin_session {
            args.push("/admin".into());
        }
        let mstsc = programs::find("mstsc", settings).unwrap_or_else(|| PathBuf::from("mstsc"));
        let child = spawn(&mstsc, &args)?;
        crate::wincred::clean_up_later(forget, vec![file]);
        let classes: Option<&'static [&'static str]> = if embed { Some(&["TscShellContainerClass"]) } else { None };
        Ok(Launch::Process { child, label: tf("Remote desktop: {0}{1}", &[&host, &note]), embed: classes })
    } else if cfg!(target_os = "macos") && programs::find("rdp", settings).is_none() {
        let file = rdp_file(e, c, None)?;
        Command::new("open").arg(&file).spawn().map_err(|err| tf("Could not open .rdp file: {0}", &[&err]))?;
        Ok(Launch::Done(tf("RDP file opened (Windows App / Microsoft Remote Desktop): {0}", &[&host])))
    } else {
        if let Some(prog) = programs::find("rdp", settings) {
            let addr = if e.port == 3389 || e.port == 0 { host.to_string() } else { format!("{host}:{}", e.port) };
            let mut args = vec![format!("/v:{addr}"), "/cert:tofu".to_string(), "/dynamic-resolution".into()];
            if !c.user.is_empty() {
                args.push(format!("/u:{}", c.user));
            }
            if !c.domain.is_empty() {
                args.push(format!("/d:{}", c.domain));
            }
            if !c.password.is_empty() && e.rdp.pass_credentials {
                args.push(format!("/p:{}", c.password));
            }
            if e.rdp.fullscreen {
                args.push("/f".into());
            } else if e.rdp.width > 0 {
                args.push(format!("/size:{}x{}", e.rdp.width, e.rdp.height));
            }
            if e.rdp.multimon {
                args.push("/multimon".into());
            }
            if e.rdp.redirect_clipboard {
                args.push("+clipboard".into());
            }
            if e.rdp.redirect_drives {
                args.push("/drive:home,~".into());
            }
            if e.rdp.admin_session {
                args.push("/admin".into());
            }
            args.extend(split_words(&e.extra_args));
            let child = spawn(&prog, &args)?;
            return Ok(Launch::Process { child, label: tf("FreeRDP: {0}", &[&host]), embed: None });
        }
        if let Some(prog) = programs::find("remmina", settings) {
            let url = if c.user.is_empty() { format!("rdp://{host}:{}", e.port) } else { format!("rdp://{}@{host}:{}", c.user, e.port) };
            let child = spawn(&prog, &["-c".into(), url])?;
            return Ok(Launch::Process { child, label: tf("Remmina: {0}", &[&host]), embed: None });
        }
        Err(tr("No RDP program found. Please install FreeRDP (xfreerdp) or Remmina.").into())
    }
}

// ------------------------------------------------------------------ VNC

fn launch_vnc(e: &Entry, c: &Creds, settings: &Settings) -> Result<Launch, String> {
    let host = e.host.trim();
    let port = if e.port == 0 { 5900 } else { e.port };
    if let Some(prog) = programs::find("vnc", settings) {
        let mut args = vec![format!("{host}::{port}")];
        args.extend(split_words(&e.extra_args));
        let child = spawn(&prog, &args)?;
        let embed: Option<&'static [&'static str]> = if settings.embed_windows { Some(&[]) } else { None };
        return Ok(Launch::Process { child, label: tf("VNC-Viewer: {0}", &[&host]), embed });
    }
    if cfg!(target_os = "macos") {
        let url = if c.user.is_empty() { format!("vnc://{host}:{port}") } else { format!("vnc://{}@{host}:{port}", c.user) };
        Command::new("open").arg(&url).spawn().map_err(|err| err.to_string())?;
        return Ok(Launch::Done(tf("Screen Sharing opened: {0}", &[&host])));
    }
    if !cfg!(windows)
        && let Some(prog) = programs::find("remmina", settings)
    {
        let child = spawn(&prog, &["-c".into(), format!("vnc://{host}:{port}")])?;
        return Ok(Launch::Process { child, label: tf("Remmina: {0}", &[&host]), embed: None });
    }
    Err(tf(
        "No VNC viewer found. Install TigerVNC/TightVNC or put vncviewer.exe into the programs folder ({0}).",
        &[&(programs::tools_dir().display())],
    ))
}

/// Which helper programs this computer has – shown on the start page.
pub fn system_check(settings: &Settings) -> Vec<(&'static str, String, bool)> {
    let mut v = Vec::new();
    for p in programs::PROGRAMS {
        let found = programs::find_with_source(p.key, settings);
        let detail = match &found {
            Some((path, src)) => format!("{} ({})", path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), src.label()),
            None => p.names.join(" / "),
        };
        v.push((p.label, detail, found.is_some()));
    }
    v.push(("PowerShell", tr("pwsh / powershell").into(), first_found(&["pwsh", "powershell"]).is_some()));
    if cfg!(target_os = "macos") {
        v.push(("RDP (Windows App)", tr(".rdp file").into(), true));
    }
    v
}

/// Shown in the settings: what each protocol starts when no own command is set.
pub fn default_hint(p: Protocol) -> &'static str {
    match p {
        Protocol::Ssh => "ssh -p {port} {user}@{host}  (or PuTTY)",
        Protocol::Sftp => "Built-in file tab (sftp / psftp)",
        Protocol::Scp => "Built-in file tab (scp / pscp)",
        Protocol::Ftp => "Built-in file tab (FTP/FTPS)",
        Protocol::Telnet => "telnet {host} {port}",
        Protocol::Rdp => {
            if cfg!(windows) {
                "mstsc in a tab (.rdp file, login via the Credential Manager)"
            } else if cfg!(target_os = "macos") {
                "open connection.rdp (Windows App)"
            } else {
                "xfreerdp /v:{host}:{port} /u:{user} /d:{domain}"
            }
        }
        Protocol::Vnc => "vncviewer {host}::{port}",
        Protocol::Serial => "putty -serial {host} -sercfg 9600,8,n,1,N",
        Protocol::Raw => "putty -raw -P {port} {host}",
        Protocol::Rlogin => "putty -rlogin -P {port} -l {user} {host}",
        Protocol::Http | Protocol::Https => "Default browser",
        Protocol::PowerShell => "pwsh/powershell Enter-PSSession",
        Protocol::LocalShell => "PowerShell / default shell",
    }
}
