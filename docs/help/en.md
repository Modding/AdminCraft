# AdminCraft user guide

AdminCraft keeps all your servers, switches and PCs in one list and opens them with a double-click:
Remote Desktop, SSH, VNC, Telnet, PowerShell, web interfaces and file transfer, each in its own tab.
Next to that it brings the everyday tools of an administrator: ping, port scan, network scan, DNS,
subnet calculator, certificate check and more.

This guide is also inside the program: **Help » User guide** or **F1**.

## The window at a glance

![AdminCraft main window](../images/main.png)

```
+---------------------------------------------------------------------------+
| File  View  Tools  Help                                                   |
| Quick connect [SSH v] [host or IP      ] Connect | Ping  Port scan  ...   |
+-----------------+-------------------------------------+-------------------+
| Connections     |  [Home] [web01] [DC01] [Files]  <- tabs                 |
|  search ...     |                                     | Properties        |
|  > Data center  |   the open connection, a tool or    |  name, host,      |
|     DC01        |   the start page                    |  login, options   |
|     web01       |                                     |  of the selected  |
|  > Network      |                                     |  connection       |
+-----------------+-------------------------------------+-------------------+
| 16 connections · 3 folders | master password status | storage location    |
+---------------------------------------------------------------------------+
```

- **Left: the connection tree.** Folders and connections. Double-click opens, right-click shows
  everything you can do with an entry.
- **Middle: the tabs.** Every open connection or tool gets a tab. The **Home** tab shows quick-start
  cards, how many connections use which protocol, and which helper programs were found.
- **Right: properties.** Everything about the selected connection or folder. Changes are saved by
  themselves after a moment.
- **Top: quick connect.** Pick a protocol, type `host`, `user@host` or `user@host:port`, press Enter —
  for a one-off connection that you don't want to save.
- **Bottom: the status bar.** Number of connections, whether a master password protects the list,
  and where the list is stored.

> Tip: View » Show properties hides the right side when you need more room.

## Your first connection

1. Click **+ Connection** (or press **Ctrl+Shift+N**).
2. On the right, give it a **name**, choose the **protocol** (for example SSH or RDP) and type the
   **host or IP address**. The port is filled in for you.
3. Under **Login** enter the **user** and, if you like, the **password** (see *Passwords* below).
4. Double-click the connection in the tree. It opens in a new tab.

That is all. Want several similar servers? Right-click » **Copy / duplicate** and change only the host.

> Tip: The example connections in a new list show what is possible. Delete them whenever you like.

## Folders and order

- **+ Folder** creates a folder; right-click a folder for **New connection here** and **New subfolder**.
- **Drag & drop:** drag a connection onto the upper or lower half of another entry to put it before or
  after it; drop it on the middle of a folder to move it inside.
- Right-click » **Move up / Move down** does the same with the mouse menu.
- **Search** above the tree (Ctrl+Shift+F) filters by name, host and user.

**Folders pass things on.** Put user, domain and password on a folder, and every connection inside
with *Take empty fields from the folder* switched on uses them. Change the admin password once on the
folder instead of on fifty servers. The properties show in blue where a value comes from.

Right-click a folder » **Open all connections in the folder** opens them all at once.

## Protocols: what opens where

| Protocol | Opens as | Needs |
|---|---|---|
| SSH | terminal tab (or PuTTY, or its own window) | OpenSSH (built into Windows 10/11, macOS, Linux) or PuTTY |
| RDP | Remote Desktop window inside the tab (Windows) | `mstsc` (Windows), FreeRDP or Remmina (Linux), Windows App (macOS) |
| VNC | viewer window inside the tab | a VNC viewer such as TigerVNC or TightVNC |
| Telnet | terminal tab | — |
| PowerShell | terminal tab with `Enter-PSSession` | PowerShell, WinRM on the target |
| HTTP / HTTPS | browser app window inside the tab | Edge or Chrome (otherwise the normal browser) |
| SFTP / SCP / FTP / FTPS | file transfer tab | OpenSSH or PuTTY for SFTP/SCP; FTP is built in |
| Serial, raw TCP, rlogin | PuTTY in the tab or a terminal tab | PuTTY/plink (Windows); picocom, nc … elsewhere |
| Local shell | terminal tab on this computer | — |

**Windows inside tabs.** On Windows, Remote Desktop, PuTTY, VNC and web windows are placed into the
tab. Click into them to type. **As own window** detaches one again, **Focus** gives it the keyboard.
On Linux and macOS these programs run in their own windows and the tab shows their state.

**The terminal tab** understands colours and full-screen programs (top, htop, mc, vim). Its toolbar has
**Reconnect**, **Commands** (saved commands), **Copy text**, **Send password** and **Ctrl+C**.

## Passwords

For every connection you choose under **Password from**:

- **In AdminCraft (encrypted)** — stored in the list, encrypted.
- **KeePass** — read from a KeePass or KeePassXC database (entry by title or path). AdminCraft asks
  for the database password once per session (Tools » Unlock KeePass).
- **Ask every time** — nothing is stored.

**Automatic login:** for SSH and Telnet the password is typed in when the server asks for it
(Settings » *Type the stored password in the terminal automatically*). For RDP it is handed to Windows
for this one connection.

**Master password** (Settings » Storage location): without it, stored passwords are only obfuscated — anyone
with the file and AdminCraft could read them. With a master password they are properly encrypted
(AES-256-GCM, Argon2), and you can choose to **encrypt the whole list** (names and hosts too).
AdminCraft then asks for the master password at start.

> Important: there is no way back without the master password. Write it down in a safe place.

**2FA codes:** KeePass entries with a TOTP secret show the current code next to the password.
**Password generator:** Tools » Password generator, or the *Generate* button next to a password field.

### KeePass as the connection list

Already using KeePass or KeePassXC? Then keep the whole connection list in it:

1. Settings » Password vault: enter the database (`.kdbx`) and press **Unlock …**.
2. Press **Keep the connection list in KeePass**.

Every connection becomes a normal KeePass entry in the group **AdminCraft** — title, user, password,
URL (e.g. `ssh://10.0.0.30:22`) and notes; folders become KeePass groups. You can edit them in KeePass
too; AdminCraft notices and reloads. An entry you make in that group in KeePass (with a URL such as
`rdp://10.0.0.10`) shows up as a connection. At start AdminCraft asks for the KeePass master password.
**Back to AdminCraft's own list** in the same place copies the list back.

**Save password in KeePass …** (on a connection with *Password from » KeePass*): type a password once;
AdminCraft puts it into the group *AdminCraft* of your database and uses that entry from then on.

## Jump hosts

Some servers can only be reached through another server (a "jump host" or "bastion").
Under **Jump host** in the properties of the target, choose the jump connection and how to jump:

- **Continue on the jump host: "ssh user@target"** — AdminCraft logs in to the jump host and types `ssh user@target`
  there. Right when the SSH key for the target lives **on the jump host**.
- **Tunnel through the jump host (ssh -J)** — your own computer connects through the jump host; the key stays with you.

Jump hosts can be chained (a jump host may have a jump host itself). This works in the terminal tab,
with PuTTY and in an own window.

## Transferring files

Right-click an SSH connection » **Transfer files (SFTP)**, or open an SFTP/SCP/FTP connection.

```
+------------------------------+------------------------------+
| This computer                | Server                       |
|  C:\Users\me\Downloads       |  /var/www                    |
|  report.pdf        -->       |  index.html                  |
|                    <--       |  logs/                       |
+------------------------------+------------------------------+
```

- Left your computer, right the server. **Upload** and **Download** copy the selected files or folders.
- **New folder**, **Rename**, **Delete** work on either side. Files can be dragged in from the
  file manager.
- Which programs do the work is set in Settings » *File transfer with* (OpenSSH, PuTTY's psftp/pscp,
  or automatic). FTP and FTPS (TLS) are built in.

## Tools for administrators

All tools are in the **Tools** menu, the buttons at the top, and the right-click menu of a connection
(then the host is filled in already).

- **Ping / Traceroute** — is the host reachable, and which way do the packets go?
- **Port scan** — which services answer (SSH, RDP, HTTPS, SMB …)? Common ports are preset.
- **DNS lookup** — A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA records of a name.
- **Wake-on-LAN** — switches a PC on over the network; enter its MAC address in the properties.
- **Subnet calculator** — `192.168.10.77/26` gives network, mask, broadcast, first and last address.
  One click scans that range.
- **Check certificate** — how many days an HTTPS certificate is still valid, who issued it, whether it is trusted.
- **SSH tunnels** — port forwardings per connection (`local port → host:port` on the far side),
  started by hand or together with the connection.
- **Check status** (button above the tree) — tests every connection's port and colours the dots in the tree.
- **Windows tools** (right-click a Windows server) — services, event viewer, computer management,
  the `C$` share, **Restart** and **Shut down** (with confirmation). Linux servers can be restarted over SSH.
- **Multi-input** — type the same thing into several SSH tabs at once (Tools » Multi-input).
- **Saved commands** — in the terminal tab under *Commands*; placeholders `{host}` `{user}` `{name}`.
- **Whois** — who owns a domain or an IP address, with the registrar and the dates.
- **HTTP header check** — follows every redirect of a web address, shows status codes, headers and
  timings, checks the security headers (HSTS, CSP …) and the cookie flags.
- **SNMP query** — asks a switch, printer or server (SNMP v2c, community e.g. `public`) for its name,
  description, uptime, location and its interfaces with status, speed and traffic. Any OID can be walked.
- **Recordings** — plays back recorded terminal sessions (see below).

### Recording sessions

Settings » Sessions and monitoring » **Record terminal sessions for playback**: from then on every SSH,
Telnet, PowerShell and shell tab is recorded with its timing; the tab shows **• recording**.
Tools » **Recordings** lists them, newest first. **Play**, **Pause**, the speed (up to 16×) and the slider
work like a video; **Shorten pauses** skips long waits. The files (`.cast`) can also be played with
asciinema.

> Recordings contain everything the screen showed. Passwords you type are not shown by servers, so
> they are not in it — but keep the folder private anyway.

## Network scan

![Subnet calculator](../images/subnet.png)

The network scan (Ctrl+Shift+L) searches an IP range for devices, like Angry IP Scanner:

1. Enter a range: `192.168.1.0/24`, `10.0.0.1-50` or `10.0.0.250-10.0.1.5`.
2. Choose the ports to check and press **Start**.
3. Every device that answers shows its name, MAC address, response time and open ports.

**Save as comparison baseline** remembers the result. The next scan of the same range marks every device as
**new**, **gone** or **changed** (e.g. a different MAC address) — handy to spot strangers in the network.

**+ Connection** on a result creates a connection in the folder *Network scan*; choose the protocol
from the list.

## Sharing and central storage

![Export dialog](../images/export.png)

**Export for a colleague** (File » Export connections, or right-click a folder » Export folder):

- **Without passwords** — the safe default.
- **Encrypted with an export password** — tell your colleague the password by another way (phone).
- **In plain text** — only after a clear warning; anyone who gets the file can read the passwords.

**Import** with File » Import AdminCraft export. Imported entries land in their own folder.

**Central list for the team** (Settings » Storage location): keep the list on a **network share** (SMB,
e.g. `\\server\it\AdminCraft-Connections.json`) or a **WebDAV server** (Nextcloud, ownCloud, IIS).
Protect it with the master password. When a colleague changes something, AdminCraft reloads it.

**Moving from other tools:** File » Import mRemoteNG file (`confCons.xml`, with passwords) and
File » Import OpenSSH configuration (`~/.ssh/config`, including ProxyJump).

## Settings

Open with the **Settings** button, **Ctrl+,** or Tools » Settings.

- **Language** — the system language by default; switch any time.
- **Appearance** — dark or light, size of the terminal font.
- **SSH, remote desktop and files** — which client opens SSH (built-in terminal, PuTTY, own window),
  which programs transfer files, whether windows are embedded into tabs.
- **Programs** — where AdminCraft found each helper program. Give your own path, or simply drop
  portable programs into the **programs folder** (`AdminCraftTools` next to AdminCraft).
- **Storage location** — where the list lives, master password, central storage.
- **Password vault** — the KeePass database to use, or KeePass as the whole connection list.
- **Updates** — **Check for updates** asks GitHub for the newest version and offers the download page.
  AdminCraft never checks by itself.
- **AI agents** — whether AI assistants and scripts on this computer may control the open window, and
  whether they may also type into terminal tabs (off until you switch it on).
- **Sessions and monitoring** — reopen the last connections at start, text logs, recordings for
  playback, regular reachability checks.

## Portable: everything next to the program

AdminCraft is one file. Everything it keeps lives in folders next to it:

```
AdminCraft.exe
AdminCraftData\     connections, scan baselines, session logs, recordings
AdminCraftTools\    helper programs you dropped in (putty.exe, vncviewer.exe …)
AdminCraftLang\     your own language files
```

Copy the folder to a USB stick and you have your whole toolbox along. If the folder can't be written
(for example inside a macOS app), AdminCraft uses `.admincraft` in your home folder instead.

AdminCraft contacts nothing on the internet by itself — only the hosts you connect to, and GitHub
when you press *Check for updates*.

## Languages

English, German, French, Italian and Ukrainian are built in. To add a language or improve one:

1. Settings » Language » **Open language folder**.
2. Copy `de.lang.example` to e.g. `es.lang`, set `@name` and `@code` at the top.
3. Translate the text right of ` = ` on each line. The left side is the English original and stays.
   `{0}`, `{1}` are placeholders and must stay.
4. Choose the language in the settings.

A file there with the code of a built-in language (e.g. `fr.lang`) improves that language.
This user guide can be translated the same way: save it as `help-xx.md` in the language folder.

## Keyboard shortcuts

| Keys | What |
|---|---|
| Ctrl+Tab / Ctrl+Shift+Tab | next / previous tab |
| Ctrl+Shift+W | close tab |
| Ctrl+Shift+N | new connection |
| Ctrl+Shift+F | search connections |
| Ctrl+Shift+S | screenshot of the tab to the clipboard |
| Ctrl+Shift+E | export connections |
| Ctrl+Shift+L | network scan |
| Ctrl+, | settings |
| F1 | this guide |
| Double-click | open connection / rename tab |
| Middle mouse button | close tab |

The shortcuts use Shift, so programs in a terminal tab keep their own Ctrl keys. On macOS use Cmd
instead of Ctrl. Tabs can be dragged to reorder them; right-click a tab to rename it.

## For scripts and AI agents

The same tools work without the window and print JSON. Passwords are never returned.

```
admincraft cli list [filter]          saved connections
admincraft cli scan 192.168.1.0/24    network scan, compared with the saved baseline
admincraft cli ports <host> [ports]   port scan
admincraft cli dns <name>             DNS lookup
admincraft cli subnet <cidr>          subnet calculator
admincraft cli cert <host> [port]     certificate check
admincraft cli open <name>            open a connection in the window
admincraft mcp                        MCP server for AI assistants (stdin/stdout)
```

**Control the open window.** When AdminCraft is open, agents can also work with it — like a
colleague looking over your shoulder (Settings » AI agents switches it on or off):

```
admincraft cli window tabs              the open tabs
admincraft cli window read 2            what tab 2 shows (terminal screen, results)
admincraft cli window tool ping web01   open a tool tab
admincraft cli window switch 2          bring a tab to the front
admincraft cli window screenshot 2 t.png  picture of tab 2 (embedded PuTTY / Remote Desktop too)
admincraft cli window type 2 uptime     type into a terminal tab or embedded PuTTY and press Enter
```

The MCP server offers the same as `window_…` tools. Typing into terminals is only possible after you
allowed it in the settings, and every typing is shown in the window. Only programs on this computer
that can read the data folder can connect; passwords are never given out.

## Questions and problems

**"Program not found"** — Home tab, *System check*, shows which helper programs are missing. Install
them, give a path in Settings » Programs, or drop them into the programs folder and press *Search again*.

**SSH: "Remote side unexpectedly closed network connection" behind a jump host** — the key for the
target probably lives on the jump host. Choose *Continue on the jump host* as jump mode.

**The Remote Desktop window does not appear in the tab** — wait a few seconds (certificate questions
come first as their own window), then press *Reconnect*. Settings » *Embed RDP, PuTTY and VNC windows
in the tab* switches embedding off.

**AdminCraft asks for a KeePass password at start** — the connection list is kept in KeePass. Enter the
KeePass master password, or press *Without KeePass* to start with AdminCraft's own (empty) list.

**Forgot the master password** — the encrypted passwords can't be recovered. Start with an empty list
(move the file in `AdminCraftData` away) and import an export.

**Where is my data?** — File » Open data folder.
