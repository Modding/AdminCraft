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

Done and to be tried against real servers: the Remote Desktop login through the Credential
Manager (`src/wincred.rs`) — log in to a real host with *Pass the login automatically* and check
that the entry is gone from the Credential Manager about two minutes later.

## Craft principles

| Principle | Status |
|---|---|
| Open source | Yes — MIT OR Apache-2.0, everything on GitHub. |
| Native, not wrapped | Yes — pure Rust + egui, no Electron. Optional extras start the system's own programs (mstsc, PuTTY, Edge app window for web interfaces) and place their windows in a tab. |
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
