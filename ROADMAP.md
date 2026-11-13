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

## Known limits (security and Craft house rules)

- **Passwords on command lines:** PuTTY, plink, psftp and pscp get the password with `-pw`, FreeRDP
  with `/p:`. Other programs of the same user can read it while they start. Planned: PuTTY's
  `-pwfile` (0.77 and newer) and FreeRDP's `/from-stdin`. Remote Desktop on Windows is done
  (Credential Manager API, entry removed after the start).
- **Without a master password** saved passwords are only obscured (the key is in the same file).
  Planned: say so in the window when the first password is saved, and offer the master password.
- **Passwords in memory** are wiped for the key and the key derivation; the passwords of open
  connections are not yet.
- **Licences:** `Zlib`, `BSL-1.0` and `CDLA-Permissive-2.0` crates are not on the Craft allowlist
  (see `ATTRIBUTION.md`); to be cleared with `storytold/craft-contrib`.
- **Logo:** its licence is not recorded yet (`ATTRIBUTION.md`).
- **Shared CI:** `ci.yml` and `release.yml` run their own jobs; the shared Craft gate and release
  workflows need a workspace with `cargo xtask ci`. Same step: split the one crate into
  `crates/` (model, network tools, no egui) and `apps/` and bring `src/app.rs` down to size.
- **Contributor credits** (`contributors/`, shown in *About*) are not set up yet.
- Releases are unsigned; macOS is built for Apple silicon only.

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
