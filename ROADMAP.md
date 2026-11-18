# Roadmap

## Tested

- Builds as one portable Windows executable; unit tests for encryption, master password, inheritance,
  mRemoteNG and `~/.ssh/config` import, KeePass read, jump-host commands, drag & drop, network scan
  ranges and differences, subnet math, TOTP against the RFC 6238 vectors, export/import, whole-file
  encryption, all five languages complete with their placeholders, the user guide in every language,
  update version comparison, KeePass as connection list (write, edit in KeePass, reload, delete),
  session recording and playback, SNMP/whois/HTTP parsing.
- SFTP (OpenSSH with automatic password), FTP and FTPS: listing and download against a public test server.
- By the person: mRemoteNG import with real files, jump-host chain against real servers.
- The control channel live (list tabs, open a ping, read its output, typing refused while switched off).
- Window embedding into tabs (with a Windows program), certificate check against a real HTTPS site,
  network scan on the local machine.

## Needs real-world testing

- Remote Desktop and PuTTY embedded in tabs against real servers (size, keyboard focus by click).
- SSH tunnels on real servers.
- Upload, rename, delete over SFTP/SCP/FTP on a writable server.
- Multi-input, restart/shutdown, Windows management tools, serial / raw / rlogin, web in a tab.
- Central storage on a real SMB share and WebDAV server with several users.
- KeePass as connection list with KeePassXC open at the same time; SNMP against real switches.
- Linux and macOS builds (compiled and run there).

## Linux and macOS (code review 2026-11-18)

Found by reading the code and the release files; nothing was run on a Linux or macOS machine.

Open:

1. **The Linux release needs glibc 2.43.** `ubuntu-latest` became Ubuntu 26.04; the program
   links `atan2f@GLIBC_2.43` and does not start on Ubuntu 24.04 LTS, Debian 13, Fedora 43 or
   RHEL 9/10 (`version 'GLIBC_2.43' not found`). Build the Linux release on the oldest runner
   (`ubuntu-22.04`, glibc 2.35) or with `cargo zigbuild` against an older glibc. CI change, so its
   own pull request.
2. **Try the fixes below on real machines:** OpenSSH in its own window on macOS (the Terminal
   shows only `/bin/sh …/pw-….txt`, the file is gone afterwards, the password is typed by
   AdminCraft); FreeRDP 2 (Debian 12) and 3 (`xfreerdp3`, Homebrew) with *Connect local drives*;
   PowerShell over SSH to a host with PowerShell as SSH subsystem; PuTTY with password on a
   Linux machine with two users; a network scan with names on macOS; OpenSSH in its own window
   from KDE (Konsole).

Fixed in code (tests in `src/tests.rs`, not yet tried on Linux or macOS):

- **macOS: password visible in Terminal.** OpenSSH "in its own window" sent
  `export AC_ASKPASS_PW_0='…'` to Terminal through `osascript`: shown in the window, kept in the
  shell history. Now Terminal runs a script file only the user can read, which removes itself
  (`programs::terminal_script`).
- **FreeRDP 2.** `/cert:tofu` is FreeRDP 3 syntax (FreeRDP 2: `/cert-tofu`), and Debian 12,
  Ubuntu 22.04 and Mint 21 ship FreeRDP 2 as `xfreerdp`. The version is now told from the program
  (`launch::freerdp_version`); drives go as `+home-drive` instead of `/drive:home,~`.
- **Restart / shut down ran the local `shutdown`** with Windows arguments for Remote Desktop, VNC
  and PowerShell connections on Linux and macOS. The menu now offers it there for SSH only, and
  `extra::windows_power` refuses to start outside Windows.
- **PowerShell connections** used `Enter-PSSession -ComputerName` (WSMan), which PowerShell 7 on
  Linux and macOS doesn't have; there it now goes over SSH (`-HostName`, `launch::powershell_session`).
- **Terminal: Cmd+C on macOS** was sent as Ctrl+C and stopped the running command; now nothing
  is sent (Ctrl+C still interrupts).
- **Password files in the shared `/tmp/admincraft`** (made 0755 by the first user, so a second
  user couldn't write there). Now `$XDG_RUNTIME_DIR/admincraft` or `admincraft-<uid>`, 0700,
  refused when it belongs to someone else (`secretfile::private_dir`).
- **Network scan names on macOS** came from `getent`, which macOS doesn't have; now `dscacheutil`.
- **Remmina** got `rdp://host:0` for port 0; now the default port.
- **Traceroute on Linux** falls back to `tracepath` when `traceroute` isn't installed.
- **Konsole** no longer gets `-T` (title), which it may refuse.
- **macOS release:** the README says how to allow the unsigned program (Gatekeeper). Signing and
  an Intel build: *Releases* in the work list.
- **German text in the code:** the section title "SSH / Dateien" is now translated text.

## Work list (security and Craft house rules)

Open work, most useful first. Each item is one pull request against `main`: read `AGENTS.md`
first, run `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and
`cargo test --locked` before pushing, add a test for new logic, and add every new text to all four
`lang/*.lang` files. Tick an item off here in the pull request that finishes it.

1. **No password on FreeRDP's command line.** `launch_rdp` in `src/launch.rs` passes
   `/p:<password>`; other programs of the same user can read that while FreeRDP starts.
   FreeRDP 3 can read all its arguments from standard input (`/args-from:stdin`, one argument per
   line, not combinable with other arguments) and has `/from-stdin` for credentials; whether
   FreeRDP 2 knows `/args-from` is not checked. Needs a Linux machine with FreeRDP 2 and 3 to
   try; say in the pull request what was tried. Done already: Remote Desktop on Windows
   (`src/wincred.rs`) and PuTTY, plink, psftp and pscp (`-pwfile`, `src/secretfile.rs`).
2. **Wipe the passwords of connections from memory.** Only the vault key and the key-derivation
   input are wiped (`Vault` in `src/model.rs`). `Creds.password`, `Entry.password`, the session
   passwords in `src/app.rs` and the auto-typing rules in `src/terminal.rs` are plain `String`s.
   Move them to `zeroize::Zeroizing<String>` (the crate is already a dependency); serde needs
   `zeroize`'s `serde` feature or a small wrapper. Medium; the compiler finds every place.
3. **Try the password files with a real PuTTY** (0.77 or newer, and one older): direct login,
   a jump host through plink (reconnect with *Restart session* too), and file transfer with
   psftp/pscp. The logic is covered by tests, the programs themselves were not at hand.
4. **Look at the hint in the properties panel** (password saved without a master password) in
   all five languages with `--screenshot`; it reuses existing texts and was not looked at yet.
5. **The saved WebDAV password** (`src/remote.rs`) is encrypted with a key built into the
   program, so it is only obscured. Encrypt it with the store's vault when a master password is set.
6. **Licences outside the allowlist** (`ATTRIBUTION.md`): `Zlib` and `BSL-1.0` come with egui and
   can't be swapped; ask in `storytold/craft-contrib` whether they join the allowlist.
   `CDLA-Permissive-2.0` is `webpki-roots`; it can be replaced by the system's certificate store
   (`rustls-platform-verifier` or `rustls-native-certs`) if that licence stays out.
   Add `cargo deny` with the allowlist to CI once this is settled.
7. **Contributor credits.** `contributors/people.toml` and `contributors/contributors.json` as in
   the other Craft apps, shown in *Help » About*. Add only entries their owners asked for.
8. **Split the crate.** `crates/` for model, storage, import, network tools and transfer (no
   egui), `apps/admincraft` for the window, `xtask` for `cargo xtask ci`; bring `src/app.rs`
   (about 5,000 lines) down by moving each dialog and tab into its own module. Many small pull
   requests, tests green after each. This is the precondition for the next item.
9. **Shared CI.** Replace the jobs in `ci.yml` and `release.yml` by calls to the shared gate and
   release workflows in `storytold/craft-common-actions` (they expect `cargo xtask ci`).
10. **Agents in Remote Desktop and VNC windows.** Agents can look at every tab
    (`window screenshot`) and type into terminal tabs and embedded PuTTY windows. Remote Desktop
    and VNC viewers don't take posted characters: they need real key and mouse input
    (`SendInput`, which needs the keyboard focus and so interrupts the person at the computer).
    If this is built: its own switch in the settings (it hands the whole remote desktop to the
    agent), mouse clicks at a position of the screenshot, and special keys (Ctrl+C, arrows,
    Tab) for PuTTY too. `src/embed.rs` and `src/app_control.rs`.
11. **Releases:** add an Intel macOS build; sign the Windows and macOS programs once
    certificates exist.
12. **Own browser for web interfaces** — started. Settings » *Web interfaces*: the program of any
    Chromium browser (Brave, Brave Origin, Vivaldi, Chromium, Opera) or Firefox browser (Firefox,
    LibreWolf, Waterfox, Zen …), the kind recognised from its file name or chosen, the profile (own per
    connection in the data folder, own temporary, or the browser's normal one, which can't go into a
    tab) and own arguments (`src/launch.rs` `web_args`, `src/app_web.rs`); every web interface opens
    in a tab unless switched off. The window is also found when it belongs to a process the started
    one launched (launchers, browsers that hand over), `embed::descendants`. Tried live: Edge in the
    tab. Still to do: try it with Brave Origin and a Firefox browser on Windows (window found and
    placed in the tab, focus, size, logins kept); hide the browser's own title bar inside the tab; a browser per connection instead of one for all; on Linux/macOS use the chosen
    browser too instead of the system one. A built-in webview (WebView2) is not an option: the Rust
    house rules allow no webview in native Craft apps.

Done and to be tried against real servers: the Remote Desktop login through the Credential
Manager (`src/wincred.rs`) — log in to a real host with *Pass the login automatically* and check
that the entry is gone from the Credential Manager about two minutes later.

Done and tried by the person against a real server: a Remote Desktop window that freed itself from
the tab after switching tabs (it then sat behind AdminCraft) is taken back in when its tab shows
again (`Embedded::keep_inside` in `src/embed.rs`).

## Craft principles

| Principle | Status |
|---|---|
| Open source | Yes — MIT OR Apache-2.0, everything on GitHub. |
| Native, not wrapped | Yes — pure Rust + egui, no Electron, no webview. Optional extras start the system's own programs (mstsc, PuTTY, your browser for web interfaces) and place their windows in a tab. |
| Familiar from day one | Yes — the mRemoteNG / Royal TS layout (tree, tabs, properties), right-click menus, tab drag & drop and the usual shortcuts. |
| Your files, your machine | Yes — local data next to the program; central storage (SMB/WebDAV) only when chosen. |
| Agent-ready | Yes — `admincraft cli …` (JSON), `admincraft mcp` (MCP server) and a local control channel into the open window (tabs, read, type when allowed, open tools). |
| Also in your browser | No — SSH, RDP, terminals, port scans and file transfer need direct sockets and processes, which a browser tab doesn't allow. A web build could only offer the calculators; not planned for now. |

## Ideas

- Native RDP/VNC rendering on Linux and macOS inside the tab (planned).
- Saving into KeePass in the background (big databases with strong key settings take a moment to save).
- SNMP v3 (user and encryption).
- More languages (`AdminCraftLang/xx.lang`); the French, Italian and Ukrainian texts would profit from a native speaker's review.
- Screenshots inside the user guide (in the program; on GitHub they are shown already).
