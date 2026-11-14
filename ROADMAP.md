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

1. **Password generator must not hide a failing random source.** `random_bytes` in
   `src/admintools.rs` ignores the error of `getrandom::fill` and would then build a password from
   zero bytes. Return a `Result` and show the error instead of a password (the control channel in
   `src/control.rs` already does this for its token). Small.
2. **Say in the window that passwords without a master password are only obscured.** The status
   bar and the README say it; add a clear hint with a button to *Settings » master password* at
   the moment the first password is saved without one (`src/app.rs`, the properties panel and
   `Store::save` in `src/model.rs` show where passwords are stored). Check with
   `--screenshot`. Small.
3. **Wipe the passwords of connections from memory.** Only the vault key and the key-derivation
   input are wiped (`Vault` in `src/model.rs`). `Creds.password`, `Entry.password`, the session
   passwords in `src/app.rs` and the auto-typing rules in `src/terminal.rs` are plain `String`s.
   Move them to `zeroize::Zeroizing<String>` (the crate is already a dependency); serde needs
   `zeroize`'s `serde` feature or a small wrapper. Medium; the compiler finds every place.
4. **No passwords on command lines for PuTTY and FreeRDP.** `launch_putty` in `src/launch.rs`
   and the psftp/pscp/plink calls in `src/transfer.rs` pass `-pw <password>`; FreeRDP gets
   `/p:<password>`. Other programs of the same user can read that. Use PuTTY's `-pwfile <file>`
   (PuTTY 0.77 and newer; a file only the user can read, removed afterwards — keep `-pw` as the
   fallback for older versions and say so in the tab) and FreeRDP's `/from-stdin`. Needs a real
   PuTTY and a Linux machine with FreeRDP to try; say in the pull request what was tried.
   Remote Desktop on Windows is done (`src/wincred.rs`).
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
10. **Releases:** add an Intel macOS build; sign the Windows and macOS programs once
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
