# Roadmap

## Tested

- Builds as one portable Windows executable; 23 unit tests (encryption, master password, inheritance,
  mRemoteNG and `~/.ssh/config` import, KeePass read, jump-host commands, drag & drop, network scan
  ranges and differences, subnet math, TOTP against the RFC 6238 vectors, export/import, whole-file
  encryption, translations).
- SFTP (OpenSSH with automatic password), FTP and FTPS: listing and download against a public test server.
- Window embedding into tabs (with a Windows program), certificate check against a real HTTPS site,
  network scan on the local machine.

## Needs real-world testing

- Remote Desktop and PuTTY embedded in tabs against real servers (size, keyboard focus by click).
- Jump-host chain and SSH tunnels on real servers.
- Upload, rename, delete over SFTP/SCP/FTP on a writable server.
- Multi-input, restart/shutdown, Windows management tools, serial / raw / rlogin, web in a tab.
- Central storage on a real SMB share and WebDAV server with several users.
- mRemoteNG password import with real `confCons.xml` files.
- Linux and macOS builds (compiled and run there).

## Ideas

- Native RDP/VNC rendering on Linux and macOS inside the tab.
- Writing passwords back to KeePass.
- More languages (`AdminCraftLang/xx.lang`).
- Scheduled network scans with a report of changes.
