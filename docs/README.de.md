# AdminCraft

Portabler Verbindungs-Manager für Windows, Linux und macOS – ähnlich mRemoteNG.

## Was es kann

* Verbindungsbaum mit Ordnern, Suche, Duplizieren, Verschieben, Rechtsklick-Menü
* Benutzer / Domäne / Passwort am Ordner eintragen – Verbindungen darin erben sie
* **Terminal im Tab:** SSH (OpenSSH), Telnet, PowerShell Remoting (Enter-PSSession), lokale Shell –
  gespeicherte Passwörter werden bei der Abfrage automatisch eingegeben
* **Programmfenster im Tab (Windows):** Remotedesktop (mstsc, automatische Anmeldung per cmdkey),
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
* **Passwörter:** in AdminCraft (AES-256, optional Masterpasswort), aus einer KeePass/KeePassXC-Datenbank
  (.kdbx, nur lesend; Eintrag per Titel/Pfad oder automatisch passend zum Host) oder jedes Mal fragen
* **Einstellungsseite (Tab):** Pfad je Programm (PuTTY, plink, psftp, pscp, mstsc, VNC, Telnet, WinSCP …),
  Standard-SSH-Programm, Einbetten an/aus, KeePass-Datei
* **Programme-Ordner** `AdminCraftTools` neben dem Programm: portable Programme (z. B. `putty.exe`)
  einfach hineinlegen – sie werden automatisch gefunden (auch eine Unterordner-Ebene)
* **Tabs:** umbenennen (Doppelklick oder Rechtsklick), verschieben (ziehen oder Rechtsklick » Nach links/rechts);
  eingebettete Fenster (PuTTY, RDP) bekommen die Tastatur einfach per Klick hinein
* **Bildschirmfoto:** Knopf oben rechts legt ein Bild des aktiven Tabs (auch RDP/PuTTY) in die Zwischenablage
* **Sprachen:** Deutsch und Englisch eingebaut, Standard = Systemsprache, umstellbar in den Einstellungen.
  Weitere Sprachen als Textdatei `xx.lang` im Ordner `AdminCraftLang` (Vorlage `de.lang.example` liegt dort: links steht der englische Originaltext, rechts die Übersetzung)
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

## Portabel

`AdminCraftData` (Verbindungen) und `AdminCraftTools` (Hilfsprogramme) liegen direkt neben dem Programm.
Alles zusammen auf einen USB-Stick kopieren – fertig. Ist der Programmordner schreibgeschützt
(z. B. in einer macOS-App), wird `~/.admincraft` benutzt. `--data <ordner>` wählt einen eigenen Datenordner.

## Datenschutz / was nicht ins Repository gehört

`.gitignore` hält heraus: Verbindungen und Passwörter (`AdminCraftData/`), abgelegte Programme
(`AdminCraftTools/`), eigene Sprachdateien (`AdminCraftLang/`), KeePass-Dateien, SSH-Schlüssel,
`.rdp`-Dateien, mRemoteNG-Exporte sowie Bauordner (`target/`, `dist/`) und die lokale Werkzeugkette
(`.toolchain/`, mehrere GB). Die Beispielverbindungen im Code sind erfunden (10.0.0.x, 203.0.113.x).

Veröffentlichen:

    git init
    git add .
    git status          # prüfen: nichts aus target, .toolchain, AdminCraftData ...
    git commit -m "AdminCraft"
    git branch -M main
    git remote add origin https://github.com/<name>/AdminCraft.git
    git push -u origin main

Die fertige `AdminCraft.exe` am besten als Datei unter „Releases“ anhängen, nicht einchecken.

## Bauen

Windows mit lokaler Werkzeugkette in `.toolchain` (nicht im Repository; nur auf dem PC, auf dem
AdminCraft entstanden ist):

    cargo.cmd build --release

Nach dem Klonen auf Windows: Rust von rustup.rs installieren (mit Visual-Studio-Build-Tools) und
`cargo build --release` – die Einträge für `.toolchain` in `.cargo/config.toml` gelten nur für das
Ziel `x86_64-pc-windows-gnullvm` und stören den normalen Bau nicht.

Mit normal installiertem Rust (rustup.rs) auf jedem System:

    cargo build --release

Ein C-Compiler wird für die TLS-Bibliothek (FTPS) gebraucht: Linux `gcc`/`clang`,
macOS die Xcode-Kommandozeilenwerkzeuge. Linux braucht außerdem die üblichen Pakete für
Fenster-Programme (z. B. `libxkbcommon-dev libgl1-mesa-dev libx11-dev libwayland-dev`).

Das fertige Programm liegt dann in `target/release/`.

## Selbsttests

    cargo.cmd test
    AdminCraft.exe --transfer-check sftp|ftp|ftps|scp <host> <benutzer> <ordner>   (Passwort in AC_CHECK_PW)
