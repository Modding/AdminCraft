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

1. **Start the Linux release on Ubuntu 22.04 or Debian 12.** Built on `ubuntu-latest`
   (Ubuntu 26.04) the program linked `atan2f@GLIBC_2.43` and didn't start on Ubuntu 24.04 LTS,
   Debian 13, Fedora 43 or RHEL. Since #10 it is built in the `build-linux` job inside
   `ubuntu:22.04`; the release v0.1.0-alpha.6 needs glibc 2.35 (its "Check the glibc it needs"
   step, and `GLIBC_2.35` as the highest version in the binary). Not yet started on such a
   system.
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

## Code review 2026-11-18 (bugs and speed)

A read-through of the whole code for bugs and for work done more often than needed, without giving up
any security. Found by reading, not by running. Each item names where it is; the pull request that
fixes one marks it **fixed**. Items marked *to try* need a real program or server to confirm.

### Security

- **S1** *fixed* · Auto-typing can type the wrong host's password (`terminal.rs` `pick_password`): when no
  rule matches the prompt, any unused password is typed (a jump host asking again gets the target's
  password), and `10.0.0.4` matches a prompt for `10.0.0.40`.
- **S2** *fixed* · OpenSSH askpass (`transfer.rs` `askpass_main`): prompts like `(user@host) Password:`
  (keyboard-interactive) match no host and fall back to the target's password, which then goes to
  the jump host.
- **S3** *fixed* · KeePass lookup by host (`keepass_vault.rs`): a title that merely contains the host
  (`fw 10.0.0.10` for `10.0.0.1`) gives its password; the recycle bin is skipped by its English or
  German name only.
- **S4** *fixed* · WinSCP / FileZilla get the password inside the URL on their command line (`app.rs`
  "Open in WinSCP/FileZilla"); IPv6 hosts are not bracketed there.
- **S5** *fixed* · The psftp script file has one name per process in the shared temp folder (`transfer.rs`
  `sftp_batch`): two transfer tabs run each other's scripts; in `/tmp` another user can swap it.
- **S6** *fixed* · FTP download writes outside the target folder when the server lists names like `../x`,
  `..\x` or `C:\x` (`transfer.rs` `ftp_download`).
- **S7** *fixed* · A host or user starting with `-` becomes an option of ssh, sftp, scp, plink or PuTTY
  (`-oProxyCommand=…`); a line break in the host adds lines to the `.rdp` file (`launch.rs`,
  `transfer.rs`).
- **S8** *fixed* · `control.json` (port and token of the control channel) gets no owner-only protection on
  Windows; in a portable folder other users can read it (`control.rs`).
- **S9** *fixed* · Control channel: a thread per connection without limit, only a per-read timeout (a slow
  client holds a thread for days), `thread::spawn` can panic and stop the listener, no write timeout;
  a request that timed out still runs later; switching the channel off leaves the listener running
  (`control.rs`).
- **S10** *fixed* · Bracketed paste: pasted text containing `ESC[201~` ends the paste early and the rest runs
  as typed commands (`terminal.rs`).
- **S11** *fixed* · sftp batch quoting lets a line break through, so a file name can add an sftp command such
  as `!cmd` (a local shell) (`transfer.rs` `q`).
- **S12** *fixed* · PuTTY `-proxycmd`: `\t`, `\n`, `\x` in the plink or password-file path are PuTTY escapes
  (`C:\Users\tom\…` breaks); user and host go in unquoted (`launch.rs` `launch_putty`).
- **S13** *fixed* · Control channel / MCP: a ping, traceroute or DNS target starting with `-` becomes an option
  of the system tool (`app_control.rs` `open_tool`).
- **S14** *fixed* · Agent screenshots and temporary browser profiles go to the shared `/tmp/admincraft`
  (`app_control.rs`, `launch.rs` `web_profile_dir`).
- **S15** *fixed* · MCP `window_screenshot` reads whatever file the window's answer names, with no type or size
  check (`agent.rs`).
- **S16** *fixed* · Remote Desktop login (`wincred.rs`): an existing `TERMSRV/host` entry is overwritten and
  then kept; when AdminCraft closes within 90 s the password stays in the Credential Manager.
- **S17** *fixed* · SCP through PuTTY ignores the key file and the jump hosts (`transfer.rs`).
- **S18** *fixed* · File transfer with a PuTTY older than 0.77 falls back to `-pw` silently; the tab should
  say so as the terminal does (`transfer.rs`).
- **S19** *fixed* · A whois referral can point to any host and port (`nettools.rs`).
- **S20** *fixed* · `kdbx::Key` prints the password with `Debug` and is not wiped (`kdbx.rs`).
- **S21** *fixed* · The terminal tab's header copies entry and login (with the password) every frame (`app.rs`).

### Data loss

- **D1** *fixed* · With a master password, a reload never takes a colleague's change (the salt is emptied
  before the check), and the next save overwrites it; a change seen while locked is skipped for
  good (`model.rs` `replace_if_same_key`).
- **D2** *fixed* · WebDAV: a server copy fetched before a save is applied after it and reverts the edit;
  uploads from quick saves can arrive in the wrong order (`model.rs`).
- **D3** *fixed* · "KeePass as connection list" replaces the whole list as soon as the group "AdminCraft"
  holds any entry, e.g. one saved password (`model.rs` `use_keepass`).
- **D4** *fixed* · Duplicate and export keep `kp_id`; in KeePass mode the copy then overwrites the original's
  KeePass entry (`app.rs`, `sharing.rs`, `kdbx.rs`).
- **D5** *fixed* · Any read error counts as "no file": the sample list is saved over the real (shared) list
  (`model.rs` `Store::open`).
- **D6** *fixed* · WebDAV: the server's answer overwrites the local copy before it was checked (`model.rs`).
- **D7** *fixed* · Shared folder: every instance writes the same `.tmp` name, nothing checks for a change
  since reading, no `sync_all` before the rename (`model.rs`).
- **D8** *fixed* · Encrypted file plus KeePass list: KeePass is never unlocked after the master password, new
  entries are lost (`model.rs`).
- **D9** *fixed* · A KeePass save deletes entries in the group that were added in KeePass meanwhile
  (`kdbx.rs`).
- **D10** *fixed* · FTP download empties the local file before the transfer; an aborted one leaves a part
  file that looks complete (`transfer.rs`).
- **D11** *fixed* · Port 0 ("default") becomes 1 just by showing the entry, and is saved (`app.rs`,
  egui's `DragValue` range).
- **D12** *fixed* · Restart over SSH types `sudo reboot` into the last tab when the session could not start
  (`app.rs` power dialog).
- **D13** *fixed* · Opening or closing a folder in the tree saves the data file: with KeePass two key
  derivations on the UI thread, on shared storage a reload for every colleague (`app.rs`).
- **D14** *fixed* · Ids: `u64::MAX` overflows; an import with repeated ids gives repeated new ids
  (`model.rs`, `sharing.rs`).
- **D15** *fixed* · Import: RAW and RLOGIN become Telnet, `%h` in `~/.ssh/config` is not expanded; IPv6
  hosts in KeePass URLs lose their brackets (`import.rs`, `kdbx.rs`).
- **D16** *fixed* · Only one password question at a time: "Open all" with several "ask" connections opens
  only the last (`app.rs`).
- **D17** *fixed* · Tunnel runs are kept by position: removing a tunnel or an entry leaves ssh running unseen
  or shows the wrong state (`app.rs`).

### Crashes and hangs

- **C1** *fixed* · Playback: `clamp(0, duration)` panics when a recording has negative times
  (`playback.rs`).
- **C2** *fixed* · Deleting an entry whose parent chain loops runs forever (`model.rs` `remove`); an import
  can bring an entry that is its own parent (`sharing.rs`).
- **C3** *fixed* · Repeated ids in a data file make the tree grow exponentially (`app.rs` `tree_level`).
- **C4** *fixed* · Network scan: a thread per port per address (up to 64 × 65535); a refused thread panics
  and the scan never finishes (`netscan.rs`); other `thread::spawn` in loops (`tools.rs`).
- **C5** *fixed* · File transfer deadlocks when the sftp script is large (deleting a folder of 100+ files):
  stdin is written before stdout is read (`transfer.rs` `run`).
- **C6** *fixed* · SSH tunnels: stderr is never read while ssh runs, so after a few KB of channel errors the
  tunnel stops (`extra.rs`).
- **C7** *fixed* · Tab screenshot: `ColorImage::region` panics on a rectangle from an older frame
  (`app.rs`, `app_control.rs`).
- **C8** *fixed* · mRemoteNG import: `KdfIterations` from the file is not limited (`import.rs`).
- **C9** *fixed* · Network ranges like `255.255.255.0/24` overflow (`netscan.rs` `parse_targets`).
- **C10** *fixed* · SNMP: OID arithmetic overflows; one damaged packet from the target ends the query
  (`nettools.rs`).
- **C11** *fixed* (KeePass saves now run on a writer thread, `KdbxJob`; AdminCraft waits up to 20 s for the last one when it closes) · The UI waits for slow work: `shutdown /m`, WebDAV test and apply, writes into a terminal
  (a large paste into a slow session), KeePass saves (`app.rs`, `extra.rs`, `terminal.rs`, `model.rs`).
- **C12** *fixed* · FTP has no timeouts; closing a transfer tab doesn't cancel queued jobs (`transfer.rs`).
- **C13** *fixed* · MCP `port_scan` can block the MCP server for over an hour; the first address may be IPv6
  (`localhost` → `::1`), same in the certificate check (`agent.rs`, `admintools.rs`).
- **C14** *fixed* · Shortcuts work while the list is locked or a dialog is open (`app.rs`).

### Speed

- **P1** *fixed* · The settings page reads and parses every language file and writes a test file next to the
  program on every frame (`i18n::available`, `programs::tools_dir`).
- **P2** *fixed* · The web settings search the PATH for the browser on every frame (`app_web.rs`).
- **P3** *fixed* · Only the visible terminal tab reads its output: hidden tabs grow without limit, record
  wrong times and type no passwords; switching back can freeze the window (`app.rs`, `terminal.rs`).
- **P4** *fixed* · Drawing the tree costs O(n²) per frame (`Store::get` / `children` are linear scans), a lock
  per row, hover texts built for every row (`app.rs`, `model.rs`).
- **P5** *fixed* · The properties panel rebuilds folder, jump-host and KeePass lists every frame (`app.rs`).
- **P6** *fixed* · The search lowercases every entry every frame (`app.rs`).
- **P7** *fixed* · Ping and DNS output grows without limit and is laid out in full every frame (`tools.rs`,
  `app.rs`).
- **P8** *fixed* · The transfer tab copies the listing and log every frame; drive letters are probed every
  frame while the list is open (`app.rs`, `transfer.rs`).
- **P9** *fixed* · The network scan tab looks up local subnets and copies all hosts every frame (`extra.rs`).
- **P10** *fixed* · Four repaints a second for as long as any terminal or outside program runs (`app.rs`).
- **P11** *fixed* · Terminal drawing: wide or fallback glyphs push the rest of a run off the cell grid; a new
  string per run (`terminal.rs`).
- **P12** *fixed* · Playback reads the whole file on the UI thread, copies all events and replays from the
  start on every backward seek (`playback.rs`).
- **P13** *fixed* · Argon2 runs again on each reload of a list without master password and on every WebDAV
  request (`model.rs`, `remote.rs`).
- **P14** *fixed* · Every save encrypts every password again, so the file always changes: needless uploads
  and reloads (`model.rs`).
- **P15** *fixed* (an unchanged list is not written again; a save starts from the database read or written last, `kdbx::save_cached`, so one key derivation instead of two, unless KeePass changed the file meanwhile) · A KeePass save runs the key derivation twice on the UI thread, also when only settings
  changed (`model.rs`, `kdbx.rs`).
- **P16** *fixed* · File transfer logs in once per folder when deleting, and once more for the listing after
  each job (`transfer.rs`). Deleting a folder now lists one level of folders per login
  (`walk_levels`); with OpenSSH the folder is listed again in the job's own login (`-cd`, `-ls`);
  a download is no longer followed by a listing. psftp still lists in a login of its own (it has no
  `-` prefix). *To try* with a real server: delete a folder tree, upload, rename.
- **P17** *fixed* · Helper programs are searched again and again (6 times per transfer tab, twice per program
  on refresh) (`programs.rs`, `app.rs`).
- **P18** *fixed* · Whois text and SNMP walk rows are rebuilt every frame (`tooltabs.rs`).
- **P19** *fixed* · Monitoring copies the status map every frame (`app.rs`).
- **P20** *fixed* · Session logs and recordings write unbuffered, once per output chunk (`terminal.rs`).

### Smaller bugs

- **B1** *fixed* · A snippet sent to all "Multi" tabs uses the active tab's `{host}` / `{user}` everywhere
  (`app.rs`).
- **B2** *fixed* · DNS: a late answer overwrites a newer query's result (`app.rs`).
- **B3** *fixed* · Command runner: one child slot for all runs (the wrong process is waited for, "running"
  goes off too early); stopped or finished programs are not reaped (zombies on Linux/macOS)
  (`tools.rs`, `app.rs`, `launch.rs`, `programs.rs`).
- **B4** *fixed* · A continuous ping may keep running after AdminCraft closes (`tools.rs`). *To try.*
- **B5** *fixed* · Two close requests in one frame lose one; closing and moving a tab in the same frame can
  close the wrong one (`app_control.rs`, `app.rs`).
- **B6** *fixed* · TOTP ignores `algorithm=` and treats HOTP as TOTP: wrong codes (`admintools.rs`).
- **B7** *fixed* · The SCP listing needs an sh-like shell (`$(pwd)`, `VAR=x cmd`): csh, tcsh and fish fail
  (`transfer.rs`).
- **B8** *fixed* · psftp batch syntax: `ls -la`, `-mkdir` and `\"` quoting are OpenSSH sftp syntax
  (`transfer.rs`). Scripts now go through `transfer::Batch`: psftp gets `ls`, no `-` prefix (its
  `put -r` makes the folder) and doubled quotes. *To try with a real psftp:* listing, upload of a
  folder (new and existing), names with `"` and `\`.
- **B9** *fixed* · Listings: leading spaces of names are cut; echoed `sftp>` lines can become phantom entries
  (`transfer.rs` `parse_ls_line`).
- **B10** *fixed* · IPv6 literals are not bracketed for scp, sftp, FTP and `-J` (`transfer.rs`).
- **B11** *fixed* · Session logs keep the `B` of `ESC ( B` and DCS payloads (`terminal.rs`).
- **B12** *fixed* · Windows console output: only German letters of code page 850 are decoded (`tools.rs`).
  Now the computer's OEM code page (`winconsole::oem_code_page`) through craft-libs `craft-codepage`.
- **B13** *fixed* · "Change" / "Set" (master password) are not translated (`app.rs`).
- **B14** *fixed* · `--open connect:NAME` can pick a folder (`app.rs`).
- **B15** *fixed* · MCP `initialize` echoes any protocol version; ports are cut with `as u16`
  (`agent.rs`, `control.rs`).
- **B16** *fixed* · Window capture computes the buffer size in `i32` (`embed.rs`).

After the fixes:

- Auto-typing now answers only a prompt that names the connection's own host (S1). A connection
  whose host is an `~/.ssh/config` alias with another `HostName` gets no automatic password; the
  *Send password* button still works.
- When a colleague's change is reloaded while only folders were opened or closed here, that
  open/closed state is not kept (D13).
- On Windows the control channel's port and token moved to
  `%LOCALAPPDATA%\AdminCraft\control-<hash>.json` (S8); `admincraft cli` and `admincraft mcp` find
  it the same way.
- To try on real machines: file transfer with OpenSSH and with PuTTY (psftp, pscp, plink, jump
  host through `-proxycmd`), FTP/FTPS with a slow server, SSH tunnels with failing forwards, WebDAV
  with two computers, KeePass as connection list with an existing group, a shared folder used by
  two people at once, terminal tabs in the background (passwords, recordings), the control channel
  from an agent.

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
2. *fixed* · **Wipe the passwords of connections from memory.** `model::Secret` (a
   `Zeroizing<String>` whose `Debug` shows `<hidden>`) now holds `Entry.password`, `Creds.password`,
   `CredInfo.password`, the auto-typing rules (`PwRule`), the jump-host passwords of the file transfer
   (`Hop`), KeePass entries (password and 2FA secret), the session passwords and the password fields
   of the dialogs. Still plain for a moment where a password is handed on: the environment of a child
   (`AC_PW`, `AC_ASKPASS_PW_n`), a KeePass field being written, the export map, FreeRDP's `/p:`.
3. **Try the password files with a real PuTTY** (0.77 or newer, and one older): direct login,
   a jump host through plink (reconnect with *Restart session* too), and file transfer with
   psftp/pscp. The logic is covered by tests, the programs themselves were not at hand.
4. *fixed* · **Look at the hint in the properties panel** (password saved without a master password)
   in all five languages with `--screenshot`. Looked at: right in English, German, French and
   Italian; in Ukrainian the panel's text and fields ran under the floating scroll bar and were cut
   at the right. The panel's content now leaves room for the scroll bar.
5. *fixed* · **The saved WebDAV password** (`src/remote.rs`) was encrypted with a key built into the
   program only. With a master password it is now encrypted with the list's key (`password_sealed`):
   the server is asked once the list is unlocked, setting, changing or removing the master password
   moves it. *To try* with a real WebDAV server: start, unlock, change the master password.
6. **Licences:** `Zlib`, `BSL-1.0` and `CDLA-Permissive-2.0` joined the Craft allowlist
   (craft-contrib RFC-0027), so every licence in `ATTRIBUTION.md` is on it or offered as one choice
   of an `OR`. Still to settle with craft-contrib: three crates name a licence outside the list as
   another choice (`LGPL-2.1-or-later`, `GPL-2.0-only`, `MIT-0` in an `OR`), and the rule reads
   "every identifier". Then add `cargo deny` with the allowlist to CI (shared CI, see item 9).
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
    placed in the tab, focus, size, logins kept); hide the browser's own title bar inside the tab.
    *Done:* a chosen browser is also used on Linux and macOS and for pages that don't go into a tab
    (`launch::web_start`); a connection can name its own browser (*Web » Browser*,
    `Entry::web_browser`), which export and import leave out. A built-in webview (WebView2) is not an option: the Rust
    house rules allow no webview in native Craft apps.
13. **Shared libraries first** (house rule 16). `storytold/craft-libs` has crates for code
    AdminCraft carries itself: `craft-ber` (SNMP), `craft-codepage` (Windows console output, *done*),
    `craft-atomic` (safe file replacement), `craft-dav` (WebDAV), `craft-jsonrpc` / `craft-mcp`
    (the MCP server), `craft-i18n`, `craft-update`. Check each one's API and licence and move over
    one at a time; the UI crates need the same egui version (craft-libs v0.1.0 uses egui 0.36).

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
- SNMP v3 (user and encryption).
- More languages (`AdminCraftLang/xx.lang`); the French, Italian and Ukrainian texts would profit from a native speaker's review.
- Screenshots inside the user guide (in the program; on GitHub they are shown already).
