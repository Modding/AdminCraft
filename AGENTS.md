<!-- craft-house-rules:start core source=ce8827d4b89aa16d0236a825059b4557d29d7058 sha256=540e6cea75d12d0710c3dca89658328e81e508ecef102446ca5bb95b7c0b92bb -->
## House rules

These apply in every Craft repository. A later rule may be stricter, not weaker. The source is `standards/house-rules-core.md` in `storytold/craft-contrib`. Propose changes there, not in a copy.

1. **A person is accountable.** Whoever runs an agent answers for what it opens and for its review comments.
2. **Check, then claim.** Before writing code, read the issue comments, search pull requests for `#N` and the keywords, and check recent commits on `main`. Comment on the issue first. Release a claim you will not finish.
3. **Verify, don't guess.** Open a definition before using it. Confirm the cause in the code, even when someone names a location.
4. **Keep fixes narrow and tested.** Fix what the issue describes, where the bug is. Add a test that fails without the fix.
5. **Review the diff before opening a pull request.** Identifiers exist as used, the test fails without the fix, nothing unrelated changed, and the description is true.
6. **Look for a better pull request.** If another fixes the same thing, close yours when it is better or equal, and say why.
7. **Report only what ran.** Say what you tested and what you could not run. Without a local build or test, say so and rely on CI before marking ready.
8. **`main` changes through a pull request.** Do not push to it. Branch protection enforces this. There is no exception.
9. **Stop and ask only about** licensing outside the allowlist, publishing, releases, a new remote, secrets, spending money, destructive git, and anything else hard to undo. Otherwise keep working. `plan/` is a gitignored notebook, not rules. Without it, do not ask for it and do not stop.
10. **Keep secrets and personal details out** of the repository, logs and requests.
11. **CI stays shared.** Workflows call `storytold/craft-common-actions`. Do not change CI in a feature or fix pull request. If CI cannot cover a change, open an issue there.
12. **Guards say why.** A check that looks removable says what it prevents. Read that before changing it.
13. **Instructions must be readable by everyone.** No notes about one machine, and no links to files a reader cannot open. `craftrules` is retired. Do not link to it.
14. **Keep pull requests moving.** Concurrent pull requests are fine; unanswered actionable feedback is not. Respond in 7 days, a reminder at 14, closure eligible at 30, from when an actionable request waits on the author. Suggestions and unconfirmed bot findings do not start the clock. A fix, explanation or agreed plan resets it; unrelated activity does not. Waiting on a reviewer or maintainer pauses it and does not count against the author. A maintainer decides closure; it is never automatic. Reuse search results, do not poll, and stop at a rate limit.
15. **No agent attribution.** A pull request does not say an agent wrote it. A repository rule may not require that.
<!-- craft-house-rules:end -->
<!-- craft-house-rules:start rust source=ce8827d4b89aa16d0236a825059b4557d29d7058 sha256=642f46b4ac38cc9e4d10d1ccde19d68cb6bc03d20e4c6236a7535f3047566262 -->
## Rust Craft repositories

These apply to native Craft apps and to shared Rust libraries. Select them by repository type. A repository that merely contains some Rust does not take this block. Rules later in a repository's file may be stricter, but not weaker. The source is `standards/house-rules-rust.md` in [storytold/craft-contrib](https://github.com/storytold/craft-contrib).

1. **Never crash.** Non-test code does not panic and has no `unsafe`, except where the repository file names an exception. Return errors, treat input as hostile, and bound recursion and allocations. New production crate roots copy the `deny` attribute from an existing crate: `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::unimplemented`, `clippy::todo`, `clippy::unreachable`. Every crash fix comes with a test that panicked before the fix.
2. **Clean room.** Learn from observed behaviour and public specifications. Do not copy another product's code, assets, strings or artwork. Check a dependency's licence before adding it.
3. **Assets and fonts.** Every asset is original or suitably licensed, and is recorded in `ATTRIBUTION.md` in the same change. Font files live in [storytold/craft-fonts](https://github.com/storytold/craft-fonts), not in the app repository.
4. **Rust only for native Craft apps.** No handwritten JavaScript or TypeScript, and no Tauri, Electron or webview shell, in those apps. Shared tooling follows its documented technical scope and maintainer-approved exceptions. Craft PR Review's existing Tauri and TypeScript UI is one such exception. It does not relax this rule for native apps. Preserve any existing web build.
5. **Time goes through `chrono`.** Do not hand-roll calendar conversion. For dates beyond what `chrono` can represent, follow [standards/time.md](https://github.com/storytold/craft-contrib/blob/main/standards/time.md).
6. **Contributor credits.** Add or edit only your own person's entry in `contributors/people.toml`, and only after asking them. Never guess a name or hand-edit `contributors.json`.

## Licence allowlist

Dependencies and assets use SPDX identifiers. An expression is allowed when every identifier is in this list. A repository may name a shorter list. It may not add an identifier here by editing its own copy of these rules.

- `ISC`
- `MIT`
- `BSD-2-Clause`
- `BSD-3-Clause`
- `Apache-2.0`
- `Unicode-3.0`
- `OFL-1.1`
- `Ubuntu-font-1.0`
- `Bitstream-Vera`
- `CC0-1.0`
- `CC-BY-4.0`
- `CC-BY-SA-4.0`
- `LicenseRef-Public-Domain`

`LicenseRef-Storyteller-Trademark` is not in this list. It covers Storyteller brand marks only, where a repository already says so.
<!-- craft-house-rules:end -->

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
the window as PNG and exits; the window opens without focus. `--open help[:CHAPTER]|settings|recordings[:FILE]|whois:Q|http:URL|snmp:HOST|netscan:RANGE|cert:HOST|
subnet:CIDR|tunnels|export|transfer|shell` opens a tab at start (for checks and screenshots).
`--data <dir>` uses another data folder — use a fresh one for screenshots, so no personal
connections, hosts or paths end up in pictures or commits.

Quality gates before every commit (CI runs the same):

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Windows without Visual Studio: the `x86_64-pc-windows-gnullvm` toolchain with LLVM-MinGW works. Point
its linker and C compiler at your LLVM-MinGW in your own Cargo configuration (`~/.cargo/config.toml`
or a `.cargo/config.toml` above the checkout), not in this repository.

## Never crash

An admin tool that dies takes every open session with it. This outranks feature work.

- **No panics in non-test code:** no `unwrap()`, `expect()`, `panic!`, `unreachable!`, `todo!`,
  `unimplemented!`. `src/main.rs` denies them (`#![deny(clippy::unwrap_used, …)]`). Return
  `Result`, or fall back to a sensible value. A poisoned lock is taken over
  (`lock().unwrap_or_else(|e| e.into_inner())`), not unwrapped.
- **Input is hostile:** data files, imported files, language files, network answers (SNMP, FTP
  listings, whois, HTTP), control-channel and MCP parameters. Check lengths and indexes, cap
  allocations sized by input.
- **`unsafe` — the named exceptions.** `unsafe_code` is denied for the crate. Three modules talk
  to the Windows API, where no safe wrapper exists, and allow it for the whole file; every block
  says why it is sound:
  - `src/embed.rs` — placing other programs' windows into tabs, focus, tab screenshots;
  - `src/wincred.rs` — the Credential Manager entry for the Remote Desktop login;
  - `src/winconsole.rs` — attaching the release build to the terminal it was started from.
  New `unsafe` goes into one of these, or gets its own named module here. Nothing else.

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
| `src/agent.rs` | `admincraft cli …` (JSON) and `admincraft mcp` (MCP server over stdio); never returns passwords |
| `src/keepass_vault.rs` | reading KeePass databases (passwords per connection) |
| `src/kdbx.rs` | KeePass as the connection list (group "AdminCraft"), writing single passwords |
| `src/control.rs`, `src/app_control.rs` | control channel into the open window for agents (127.0.0.1 + token in the data folder) |
| `src/update.rs` | "Check for updates" against GitHub releases (only when pressed) |
| `src/playback.rs` | session recordings (asciicast v2) and the playback tab |
| `src/nettools.rs`, `src/tooltabs.rs` | Whois, HTTP header check, SNMP v2c (hand-written BER) and their tabs |
| `src/i18n.rs`, `lang/*.lang` | translations (English is the source text; de, fr, it, uk built in) |
| `src/help.rs`, `docs/help/*.md` | the user guide: shown in a tab (F1) and the documentation on GitHub |
| `src/programs.rs` | finding helper programs (settings path, `AdminCraftTools`, PATH) |
| `src/timefmt.rs` | dates and times as text, through `chrono` |
| `src/wincred.rs` | Windows Credential Manager entry for the Remote Desktop login (written, then removed) |
| `src/winconsole.rs` | attaches the release build to the terminal it was started from (Windows) |

## Versions and releases

Same scheme as the other Craft apps:

- Semantic versioning, `0.x.y` while the app is young: `x` for new features, `y` for fixes.
- The version lives only in `Cargo.toml` (`version = "…"`); the app shows it in *Help » About* and
  with `admincraft --version`.
- To release: raise the version in `Cargo.toml` (run `cargo build` so `Cargo.lock` follows), bring
  that to `main` through a pull request, then push `main` to the `release` branch
  (`git push origin main:release`).
  `.github/workflows/release.yml` builds Windows, Linux and macOS and publishes **AdminCraft vX.Y.Z**
  with the tag `vX.Y.Z`, the files `admincraft-X.Y.Z-<system>-<arch>[-portable].zip|tar.gz`,
  `SHA256SUMS.txt` and GitHub's generated release notes. A version that already has a release is refused.
- A nightly dry run builds everything from `main` without publishing; *Run workflow* can test a
  version such as `0.2.0-rc.1` (pre-release).

## CI workflows

- `house-rules.yml` calls the shared workflow in
  [`storytold/craft-common-actions`](https://github.com/storytold/craft-common-actions): the two
  blocks at the top of this file must match `storytold/craft-contrib`. Update them with that
  repository's `house_rules.py write`, never by hand.
- `ci.yml` and `release.yml` still run their own jobs: the shared gate and release workflows expect a
  `cargo xtask ci` workspace, which this single crate doesn't have yet. Don't add to them in a
  feature or fix pull request; moving them to the shared workflows is its own task.
- Actions are pinned to a commit; Dependabot (`.github/dependabot.yml`) raises them.

## Rules

- **Translations:** every user-visible text is English source text wrapped in `tr("…")` or
  `tf("… {0} …", &[&x])` (`use crate::i18n::{t as tr, tf}`). Only texts a person reads: program
  names, command-line arguments, environment variables, file contents and egui ids are plain
  strings and `format!` — a language file must never change what is started (a test checks this). Add a line to every built-in language file
  `lang/de.lang`, `fr.lang`, `it.lang`, `uk.lang` (`English = translation`; use ` => ` when the English
  text itself contains ` = `). No German (or other
  language) text in the code, comments included — only exception: matching the output of system tools
  (e.g. German Windows `ping`). A test checks that every language has every text and keeps its placeholders.
- **User guide:** a new feature gets a few plain sentences in `docs/help/en.md` and the same change in
  `de.md`, `fr.md`, `it.md`, `uk.md`. All guides keep the same `##` chapters in the same order
  (`help::Topic` points at them by position; a test checks the count). Images: `../images/…`.
- **Secrets:** never log or print passwords; plain-text passwords only leave the program through the
  export with its explicit warning. Don't commit `AdminCraftData/`, `.kdbx`, keys or screenshots
  with real hosts (see `.gitignore`).
- **Portability:** code paths for Windows, Linux and macOS; Windows-only features
  (window embedding, `shutdown /m`, mmc tools) degrade to a clear message elsewhere.
- **Secrets on command lines:** a password given to another program goes through a pipe, a file
  only the user can read, the environment of that one child, or an API — not through its arguments.
  Still open and listed in `ROADMAP.md`: PuTTY/plink/psftp/pscp (`-pw`) and FreeRDP (`/p:`).
- **Time goes through `chrono`** (`src/timefmt.rs`); no hand-written calendar code.
- **No new C dependencies** without need; `ring` is the exception.
- **Licences:** a new dependency must fit the allowlist above. Known exceptions already in the
  tree, to be cleared with `storytold/craft-contrib`: `Zlib`, `BSL-1.0` and `CDLA-Permissive-2.0`
  (see `ATTRIBUTION.md`).
- Add a test in `src/tests.rs` for new logic that doesn't need a GUI or network.
