# AGENTS.md — working on AdminCraft

Notes for coding agents (and humans) changing this repository.

## What it is

A portable remote connection manager and admin toolbox (Rust, eframe/egui 0.37, one binary crate).
Everything a user sees must also work from a USB stick: data, helper programs and language files
live next to the executable.

## Build, test, check

```sh
cargo build                  # debug
cargo build --release        # single portable executable
cargo test                   # unit tests in src/tests.rs (no network, no GUI)
target/debug/admincraft --screenshot shots/now.png --lang en --data shots/demo
```

`--screenshot` draws about 120 frames (longer while an embedded window or a scan is pending), saves
the window as PNG and exits; the window opens without focus. `--open settings|netscan:RANGE|cert:HOST|
subnet:CIDR|tunnels|export|transfer|shell` opens a tab at start (for checks and screenshots).
`--data <dir>` uses another data folder — use a fresh one for screenshots, so no personal
connections, hosts or paths end up in pictures or commits.

Windows without Visual Studio: `cargo.cmd` runs a local Rust + LLVM-MinGW toolchain from `.toolchain/`
(not in git). `.cargo/config.toml` points the `x86_64-pc-windows-gnullvm` linker/C compiler there.

## Layout

| File | What |
|---|---|
| `src/main.rs` | start, command-line checks (`--transfer-check`, `--netscan-check`), OpenSSH askpass helper |
| `src/app.rs` | the window: tree, tabs, properties, dialogs, settings page |
| `src/model.rs` | connections, settings, the encrypted data file (`Store`), shared/central storage |
| `src/launch.rs` | how each protocol starts (terminal tab, embedded program, transfer tab) |
| `src/embed.rs` | putting other programs' windows into tabs (Windows), focus handling, tab screenshots |
| `src/terminal.rs` | PTY terminal (vt100), password auto-typing, multi-input, session logs |
| `src/transfer.rs` | SFTP/SCP (OpenSSH, PuTTY) and FTP/FTPS (suppaftp + rustls) |
| `src/netscan.rs` | IP range scanner, saved baselines, differences |
| `src/extra.rs` | tool tabs: scanner, subnet, certificate, password generator, tunnels, Windows tools |
| `src/admintools.rs` | subnet math, TLS certificate check, passwords, TOTP |
| `src/sharing.rs` | export / import for colleagues |
| `src/remote.rs` | WebDAV storage |
| `src/keepass_vault.rs` | reading KeePass databases |
| `src/i18n.rs`, `lang/en.lang` | translations |
| `src/programs.rs` | finding helper programs (settings path, `AdminCraftTools`, PATH) |

## Versions and releases

Same scheme as the other Craft apps:

- Semantic versioning, `0.x.y` while the app is young: `x` for new features, `y` for fixes.
- The version lives only in `Cargo.toml` (`version = "…"`); the app shows it in *Help » About* and
  with `admincraft --version`.
- To release: raise the version in `Cargo.toml` (run `cargo build` so `Cargo.lock` follows), commit
  to `main`, then push `main` to the `release` branch (`git push origin main:release`).
  `.github/workflows/release.yml` builds Windows, Linux and macOS and publishes **AdminCraft vX.Y.Z**
  with the tag `vX.Y.Z`, the files `admincraft-X.Y.Z-<system>-<arch>[-portable].zip|tar.gz`,
  `SHA256SUMS.txt` and GitHub's generated release notes. A version that already has a release is refused.
- A nightly dry run builds everything from `main` without publishing; *Run workflow* can test a
  version such as `0.2.0-rc.1` (pre-release).

## Rules

- **Translations:** every user-visible text is German source text wrapped in `tr("…")` or
  `tf("… {0} …", &[&x])` (`use crate::i18n::{t as tr, tf}`). Add the English line to `lang/en.lang`
  (`German = English`; use ` => ` when the German text itself contains ` = `). A test checks the file.
- **Secrets:** never log or print passwords; plain-text passwords only leave the program through the
  export with its explicit warning. Don't commit `AdminCraftData/`, `.kdbx`, keys or screenshots
  with real hosts (see `.gitignore`).
- **Portability:** code paths for Windows, Linux and macOS; Windows-only features
  (window embedding, `shutdown /m`, mmc tools) degrade to a clear message elsewhere.
- **No new C dependencies** without need (the Windows build uses LLVM-MinGW); `ring` is the exception.
- Add a test in `src/tests.rs` for new logic that doesn't need a GUI or network.
