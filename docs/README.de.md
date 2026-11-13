# AdminCraft

Portabler Verbindungs-Manager für Windows, Linux und macOS – ähnlich mRemoteNG.

**Handbuch:** [docs/help/de.md](help/de.md) – alles Schritt für Schritt erklärt (auch im Programm: F1).

## Was es kann

* Verbindungsbaum mit Ordnern, Suche, Duplizieren, Verschieben, Rechtsklick-Menü
* Benutzer / Domäne / Passwort am Ordner eintragen – Verbindungen darin erben sie
* **Terminal im Tab:** SSH (OpenSSH), Telnet, PowerShell Remoting (Enter-PSSession), lokale Shell –
  gespeicherte Passwörter werden bei der Abfrage automatisch eingegeben
* **Programmfenster im Tab (Windows):** Remotedesktop (mstsc, automatische Anmeldung),
  PuTTY und VNC-Viewer werden in den Tab eingebettet; „Als eigenes Fenster“ löst sie wieder.
  Linux/macOS: eigenes Fenster, der Tab zeigt Status und „Trennen“.
* **SSH-Programm wählbar:** eingebautes Terminal, PuTTY (im Tab) oder OpenSSH in eigenem Terminalfenster
* **Jump-Host:** am Server einen anderen SSH-Server als Sprungserver wählen –
  entweder „auf dem Jump-Host `ssh user@ziel` eintippen“ (automatisch, auch mehrstufig)
  oder Tunnel per `ssh -J`. Mit PuTTY über plink (`-proxycmd`).
* **Dateien übertragen:** zweigeteilter Tab (Dieser PC | Server) für SFTP, SCP, FTP und FTPS –
  hoch- und herunterladen (auch ganze Ordner), Ordner anlegen, umbenennen, löschen,
  Dateien aus dem Explorer ins Fenster ziehen = hochladen.
  SFTP/SCP über OpenSSH (sftp/scp) oder PuTTY (psftp/pscp), Passwort wird automatisch übergeben.
* **Passwörter:** in AdminCraft (AES-256 mit Masterpasswort; ohne Masterpasswort nur verschleiert), aus einer KeePass/KeePassXC-Datenbank
  (.kdbx, nur lesend; Eintrag per Titel/Pfad oder automatisch passend zum Host) oder jedes Mal fragen
* **Einstellungsseite (Tab):** Pfad je Programm (PuTTY, plink, psftp, pscp, mstsc, VNC, Telnet, WinSCP …),
  Standard-SSH-Programm, Einbetten an/aus, KeePass-Datei
* **Programme-Ordner** `AdminCraftTools` neben dem Programm: portable Programme (z. B. `putty.exe`)
  einfach hineinlegen – sie werden automatisch gefunden (auch eine Unterordner-Ebene)
* **Tabs:** umbenennen (Doppelklick oder Rechtsklick), verschieben (ziehen oder Rechtsklick » Nach links/rechts);
  eingebettete Fenster (PuTTY, RDP) bekommen die Tastatur einfach per Klick hinein
* **Bildschirmfoto:** Knopf oben rechts legt ein Bild des aktiven Tabs (auch RDP/PuTTY) in die Zwischenablage
* **Sprachen:** Englisch, Deutsch, Französisch, Italienisch und Ukrainisch eingebaut, Standard = Systemsprache,
  umstellbar in den Einstellungen. Weitere Sprachen als Textdatei `xx.lang` im Ordner `AdminCraftLang`
  (Vorlage `de.lang.example` liegt dort: links steht der englische Originaltext, rechts die Übersetzung)
* **Handbuch eingebaut:** F1 oder *Hilfe » Handbuch* – mit Inhaltsverzeichnis, Suche und `?`-Knöpfen in den Einstellungen
* **Netzwerk-Scanner** (wie Angry IP Scanner): IP-Bereich (`/24`, `10.0.0.1-50` …) per Ping und Port-Abfrage,
  mit Name, MAC, Antwortzeit, offenen Ports; Stand speichern und beim nächsten Scan **neu / weg / geändert** sehen;
  gefundene Geräte direkt öffnen oder als Verbindung anlegen
* **Mehrfach-Eingabe:** Tippen geht an alle Terminal-Tabs mit „Mehrfach“; **gespeicherte Befehle** (Menü „Befehle“)
* **SSH-Tunnel** (Portweiterleitungen) an der Verbindung anlegen, starten/stoppen, optional beim Verbinden mit
* **Sitzungen:** beim Start wieder öffnen, Terminal-Sitzungen als Textdatei mitschreiben;
  **Überwachung:** alle N Minuten prüfen, Meldung bei Ausfall/Wiederkehr
* **Windows-Verwaltung** per Rechtsklick (Dienste, Ereignisanzeige, Computerverwaltung, C$),
  **Neu starten / Herunterfahren** (Windows per `shutdown /m`, Linux per `sudo reboot` über SSH)
* Weitere Verbindungsarten: **Seriell** (COM/ttyUSB), **Raw TCP**, **Rlogin** (über PuTTY/plink),
  **Weboberflächen im Tab** (Edge/Chrome-Fenster, Windows)
* **Subnetz-Rechner**, **Zertifikats-Prüfer** (Ablaufdatum, Aussteller, vertrauenswürdig?),
  **Passwort-Generator**, **2FA-Codes (TOTP)** aus KeePass-Einträgen
* **Gemeinsame Verbindungsliste** im Team (Ordner auf Netzlaufwerk, Änderungen werden neu geladen)
* Werkzeuge: Ping / Dauerping, Traceroute, Port-Scan, DNS-Abfrage (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA,
  eigener DNS-Server), Wake-on-LAN, Erreichbarkeit aller Hosts
* Import: mRemoteNG (`confCons.xml`) und OpenSSH (`~/.ssh/config`, inkl. ProxyJump)
* Eigene Startbefehle pro Protokoll, Platzhalter `{host} {port} {user} {domain} {password} {name}`
* **KeePass als Verbindungsliste:** jede Verbindung ist ein KeePass-Eintrag (Gruppe *AdminCraft*), auch in
  KeePass/KeePassXC bearbeitbar; Änderungen werden neu geladen. Einzelne Passwörter direkt in KeePass speichern.
* **Whois**, **HTTP-Header-Prüfung** (Weiterleitungen, Sicherheits-Header, Cookie-Merkmale) und
  **SNMP-Abfrage** (Systeminfos und Schnittstellen von Switches, Druckern, Servern)
* **Sitzungen aufzeichnen:** Terminal-Sitzungen mit Zeitablauf aufzeichnen und wie ein Video abspielen
* **Nach Updates suchen** – Knopf in den Einstellungen (fragt GitHub nur auf Knopfdruck)
* **Handbuch** im Programm (F1) – auch hier: [Deutsch](help/de.md) · [English](help/en.md) ·
  [Français](help/fr.md) · [Italiano](help/it.md) · [Українська](help/uk.md)

## Für Skripte und KI-Agenten

    admincraft cli list | scan <bereich> | ports <host> | dns <name> | subnet <cidr> | cert <host>
    admincraft cli window tabs | read [n] | type <n> <text> | switch <n> | tool <werkzeug> [ziel]
    admincraft mcp            MCP-Server für KI-Assistenten (stdin/stdout)

`cli window …` steuert das **offene Fenster** (Einstellungen » KI-Agenten): Tabs lesen, Verbindungen und
Werkzeuge öffnen, in Terminals tippen nur wenn erlaubt. Nur Programme auf diesem Computer kommen hinein
(127.0.0.1 und ein Schlüssel im Datenordner); Passwörter werden nie herausgegeben.

## Portabel

`AdminCraftData` (Verbindungen, Scans, Protokolle, Aufzeichnungen), `AdminCraftTools` (Hilfsprogramme) und
`AdminCraftLang` (eigene Sprachen) liegen direkt neben dem Programm. Alles zusammen auf einen USB-Stick
kopieren – fertig. Ist der Programmordner schreibgeschützt (z. B. in einer macOS-App), wird `~/.admincraft`
benutzt. `--data <ordner>` wählt einen eigenen Datenordner.

## Datenschutz / was nicht ins Repository gehört

`.gitignore` hält heraus: Verbindungen und Passwörter (`AdminCraftData/`), abgelegte Programme
(`AdminCraftTools/`), eigene Sprachdateien (`AdminCraftLang/`), KeePass-Dateien, SSH-Schlüssel,
`.rdp`-Dateien, mRemoteNG-Exporte sowie Bauordner (`target/`, `dist/`).
Die Beispielverbindungen im Code sind erfunden (10.0.0.x, 203.0.113.x).

**Wie sicher sind gespeicherte Passwörter?** Mit Masterpasswort sind sie mit AES-256-GCM verschlüsselt,
der Schlüssel entsteht per Argon2 aus dem Masterpasswort. **Ohne Masterpasswort sind sie nur
verschleiert:** wer die Datei `connections.json` hat, kann sie lesen. Für einen USB-Stick oder einen
gemeinsamen Ordner also immer ein Masterpasswort setzen (Einstellungen) oder KeePass benutzen.
Das Gleiche gilt für das gespeicherte WebDAV-Passwort.

## Versionen und Releases

Versionen nach Semantic Versioning (`0.x.y`) wie bei den anderen Craft-Apps. Fertige Programme für Windows
(portabel), Linux und macOS gibt es unter [Releases](https://github.com/Modding/AdminCraft/releases) mit `SHA256SUMS.txt`. Wie ein Release
entsteht: [AGENTS.md](../AGENTS.md#versions-and-releases). Was getestet ist und was noch kommt:
[ROADMAP.md](../ROADMAP.md).

## Bauen

Mit Rust von rustup.rs auf jedem System:

    cargo build --release

Windows: mit den Visual-Studio-Build-Tools (Standard) oder ohne Visual Studio mit dem Ziel
`x86_64-pc-windows-gnullvm` und LLVM-MinGW. Linker und C-Compiler dafür trägt man in der eigenen
Cargo-Konfiguration ein (`~/.cargo/config.toml`), nicht im Repository.

Ein C-Compiler wird für die TLS-Bibliothek (FTPS) gebraucht: Linux `gcc`/`clang`,
macOS die Xcode-Kommandozeilenwerkzeuge. Linux braucht außerdem die üblichen Pakete für
Fenster-Programme (z. B. `libxkbcommon-dev libgl1-mesa-dev libx11-dev libwayland-dev`).

Das fertige Programm liegt dann in `target/release/`.

## Selbsttests

    cargo.cmd test
    AdminCraft.exe --transfer-check sftp|ftp|ftps|scp <host> <benutzer> <ordner>   (Passwort in AC_CHECK_PW)
