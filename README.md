<p align="center">
  <img src="assets/logo-512.png" width="160" height="160" alt="AdminCraft logo: a honey badger drawn in black and white ink on a dark slate background">
</p>

<h1 align="center">AdminCraft</h1>

<p align="center">
  <b>A portable remote connection manager and admin toolbox, built in pure Rust.</b>
</p>

<p align="center">
  RDP, SSH, VNC, Telnet, PowerShell, serial consoles and file transfer in tabs, plus the everyday
  tools of a sysadmin — in one small program that runs from a USB stick on Windows, Linux and macOS.<br>
  <i>Built with CraftAnything.</i>
</p>

<p align="center">
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-147a40?style=flat-square&logo=rust&logoColor=white">
  <img alt="Runs on Windows, Linux and macOS" src="https://img.shields.io/badge/runs%20on-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-1f9d55?style=flat-square">
  <img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-147a40?style=flat-square">
  <img alt="Portable" src="https://img.shields.io/badge/portable-single%20file-1f9d55?style=flat-square">
</p>

<p align="center">
  <a href="#a-look-around">A look around</a> ·
  <a href="#features">Features</a> ·
  <a href="docs/help/en.md">User guide</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#portable-and-private">Portable and private</a> ·
  <a href="#building">Building</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="#license-and-credits">License and credits</a> ·
  <a href="docs/README.de.md">Deutsch</a>
</p>

<br>

<p align="center">
  <img src="docs/images/main.png" alt="AdminCraft main window: a connection tree with folders for data center, network and workstations on the left, the start page with quick-start cards in the middle and the properties of an RDP connection on the right" width="100%">
</p>

## A look around

<table>
<tr>
<td width="50%" valign="top"><img src="docs/images/certificate.png" alt="Certificate check of example.com: valid for 43 more days, trusted, issuer, names, validity dates and serial number" width="100%"><p align="center"><sub><b>Certificate check.</b> How long is HTTPS still valid, who issued it, is it trusted?</sub></p></td>
<td width="50%" valign="top"><img src="docs/images/subnet.png" alt="Subnet calculator for 192.168.10.77/26 showing network, mask, wildcard, broadcast, first and last address and 62 usable addresses" width="100%"><p align="center"><sub><b>Subnet calculator.</b> Network, mask, broadcast and usable range — one click to scan it.</sub></p></td>
</tr>
<tr>
<td colspan="2" valign="top"><img src="docs/images/export.png" alt="Export dialog with the choice to export without passwords, encrypted with an export password, or in plain text with a red warning that has to be confirmed" width="100%"><p align="center"><sub><b>Export for a colleague</b> — without passwords, encrypted with an export password, or (after a clear warning) in plain text.</sub></p></td>
</tr>
</table>

## Features

**Connections**
- Tree of folders and connections with search, drag & drop, duplicate, and folders that pass
  user / domain / password on to everything inside.
- **In a tab:** SSH (OpenSSH), Telnet, PowerShell Remoting, local shell, serial console, raw TCP, rlogin.
- **Window in a tab (Windows):** Remote Desktop (mstsc, automatic login), PuTTY, VNC viewers and web
  interfaces (Edge/Chrome app window) are embedded into the tab; a click gives them the keyboard.
- **Jump hosts:** log in to a jump host and continue there with `ssh user@target` (the key can live
  on the jump host), or tunnel with `ssh -J`; works in the terminal tab, with PuTTY and in an own window.
- **SSH tunnels** (port forwarding) per connection, started by hand or together with the connection.
- **Multi-input:** type into several terminal tabs at once; **saved commands** with placeholders.
- Tabs can be renamed and reordered; screenshot of the active tab to the clipboard.

**Files**
- Two-pane file transfer for **SFTP, SCP, FTP and FTPS** — upload and download (also folders),
  create, rename, delete, drag files in from the explorer. Through OpenSSH or PuTTY's psftp/pscp.

**Passwords**
- Stored encrypted with a master password (AES-256-GCM, key from Argon2), read from a **KeePass/KeePassXC** database,
  or asked every time. **2FA codes (TOTP)** from KeePass entries, password generator.
- The whole list can be encrypted with the master password and kept centrally on a
  **network share (SMB)** or a **WebDAV server** (Nextcloud, ownCloud …); changes by others are reloaded.
- **Export / import** to hand connections to a colleague — with or without passwords.
- **KeePass as the connection list:** every connection is a KeePass entry (group *AdminCraft*), editable
  in KeePass/KeePassXC too; or save single passwords into KeePass.

**Admin tools**
- **Network scanner** (in the spirit of Angry IP Scanner): ping and port checks over an IP range,
  names, MAC addresses; save a baseline and see what is **new, gone or changed** on the next scan.
- Ping / traceroute, port scan, DNS lookup (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA),
  Wake-on-LAN, subnet calculator, TLS certificate check, reachability monitoring with alerts.
- **Whois**, **HTTP header check** (redirects, security headers, cookie flags) and **SNMP query**
  (system info and interfaces of switches, printers, servers).
- **Session recording:** terminal sessions recorded with their timing and played back like a video.
- Windows management per right-click (services, event viewer, computer management, `C$`),
  restart / shut down (Windows via `shutdown /m`, Linux via `sudo reboot` over SSH).

**More**
- Import from **mRemoteNG** (`confCons.xml`) and OpenSSH (`~/.ssh/config`, including ProxyJump).
- **English, German, French, Italian and Ukrainian** built in; the system language is used by default.
  More languages as plain text files (`AdminCraftLang/xx.lang`: copy `de.lang.example` there and
  translate the right side).
- **Built-in user guide** (F1, *Help » User guide*) with contents, search and a `?` next to settings.
- **Check for updates** button in the settings (asks GitHub only when pressed).
- A settings page for the paths of helper programs, or simply drop portable programs such as
  `putty.exe` into the `AdminCraftTools` folder next to AdminCraft.

## Quick start

1. Download the archive for your system from the [releases](../../releases) (or [build it](#building))
   and unpack it.
2. Put it into any folder — a USB stick is fine — and start it.
3. Double-click an example connection, or create your own with **+ Connection**.
4. Press **F1** for the user guide.

The full guide — every feature explained step by step — is also here:
[English](docs/help/en.md) · [Deutsch](docs/help/de.md) · [Français](docs/help/fr.md) ·
[Italiano](docs/help/it.md) · [Українська](docs/help/uk.md).

Helper programs AdminCraft can use: OpenSSH (built into Windows 10/11, macOS and Linux), `mstsc`
(Windows), FreeRDP or Remmina (Linux), a VNC viewer, PuTTY. The start page shows what was found.

## Portable and private

- Everything lives next to the program: `AdminCraftData` (connections, scans, logs),
  `AdminCraftTools` (helper programs), `AdminCraftLang` (own languages). Copy the folder, done.
  If that folder can't be written (e.g. inside a macOS app bundle), `~/.admincraft` is used.
- Passwords never leave the computer unencrypted unless you explicitly export them in plain text.
- **Set a master password** (Settings) when the folder travels on a USB stick or lives on a share.
  With it, saved passwords are encrypted with AES-256-GCM. **Without it they are only obscured:**
  whoever has `connections.json` can read them. The same goes for the saved WebDAV password.
- Passwords for PuTTY, plink, psftp and pscp go through a file only you can read (`-pwfile`,
  PuTTY 0.77 and newer) that is removed afterwards, the Remote Desktop login through the Windows
  Credential Manager. Known limits, listed in the [roadmap](ROADMAP.md): FreeRDP and a PuTTY
  older than 0.77 get the password as a command-line argument, which other programs of the same
  user can see while they start.
- AdminCraft talks to nothing on the internet by itself; it only connects where you tell it to.

## Building

Rust from [rustup.rs](https://rustup.rs), then:

```sh
cargo build --release      # target/release/admincraft(.exe)
cargo test
cargo fmt --check && cargo clippy --all-targets -- -D warnings   # what CI checks
```

- **Windows:** the default MSVC toolchain works. Without Visual Studio, the
  `x86_64-pc-windows-gnullvm` toolchain with LLVM-MinGW works too (point its linker and C compiler
  at your LLVM-MinGW in your own `~/.cargo/config.toml`).
- **Linux:** `pkg-config libxkbcommon-dev libwayland-dev libx11-dev libgl1-mesa-dev` and a C compiler.
- **macOS:** the Xcode command line tools.

Command line for checks: `--screenshot <file.png>` (draws ~120 frames, saves the window, exits),
`--lang en|de|fr|it|uk`, `--data <folder>`, `--open help[:chapter]|settings|netscan:RANGE|…`.

## For agents: CLI and MCP

The same tools the window offers are available to scripts and AI agents — passwords are never returned.

```sh
admincraft cli list [filter]          # saved connections as JSON
admincraft cli scan 192.168.1.0/24    # network scan incl. new/gone/changed against the saved baseline
admincraft cli ports <host> [ports]   # TCP port scan
admincraft cli dns <name> | subnet <cidr> | cert <host> [port]
admincraft cli open <name>            # open a connection in the window
admincraft mcp                        # MCP server on stdin/stdout
```

MCP client configuration (Claude Desktop, Claude Code, Cursor …):

```json
{ "mcpServers": { "admincraft": { "command": "C:\\Tools\\AdminCraft\\AdminCraft.exe", "args": ["mcp"] } } }
```

Tools: `list_connections`, `open_connection`, `scan_network`, `port_scan`, `dns_lookup`, `subnet`,
`check_certificate`, and for the open window `window_status`, `window_list_tabs`, `window_read_tab`,
`window_type`, `window_switch_tab`, `window_close_tab`, `window_open_tool`, `window_notify`.
A fully encrypted connection list is read with the master password in `AC_MASTER`, a list kept in
KeePass with `AC_KEEPASS`.

**Control the open window** (Settings » AI agents): `admincraft cli window tabs | read [n] | type <n> <text> |
switch <n> | close <n> | tool <tool> [target]`. The window listens on 127.0.0.1 only, with a token in
the data folder; typing into terminals has to be allowed separately.

## Keyboard

`Ctrl+Tab` / `Ctrl+Shift+Tab` switch tabs, `Ctrl+Shift+W` closes, `Ctrl+Shift+N` new connection,
`Ctrl+Shift+F` search, `Ctrl+Shift+S` screenshot, `Ctrl+Shift+L` network scan, `Ctrl+,` settings,
`F1` all shortcuts (Cmd on macOS). Shift keeps the plain Ctrl keys free for programs in a terminal tab.

## Releases

Versions follow semantic versioning (`0.x.y`) like the other Craft apps. Each release
**AdminCraft vX.Y.Z** (tag `vX.Y.Z`) offers `admincraft-X.Y.Z-windows-x64-portable.zip`,
`admincraft-X.Y.Z-linux-x86_64.tar.gz`, `admincraft-X.Y.Z-macos-aarch64.tar.gz` and `SHA256SUMS.txt`.
How a release is made: [AGENTS.md](AGENTS.md#versions-and-releases).

## Roadmap

See [ROADMAP.md](ROADMAP.md) — what is tested, what still needs real-world testing, and ideas.

## License and credits

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Third-party crates and their licenses: [ATTRIBUTION.md](ATTRIBUTION.md).

AdminCraft is an independent project. mRemoteNG, PuTTY, KeePass, Angry IP Scanner and other
names are mentioned only to describe compatibility; they belong to their owners.
