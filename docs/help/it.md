# Guida utente di AdminCraft

AdminCraft tiene tutti i tuoi server, switch e PC in un unico elenco e li apre con un doppio clic:
Desktop remoto, SSH, VNC, Telnet, PowerShell, interfacce web e trasferimento file, ognuno nella sua scheda.
In più offre gli strumenti quotidiani di un amministratore: ping, scansione porte, scansione di rete, DNS,
calcolatore subnet, verifica certificati e altro ancora.

Questa guida si trova anche nel programma: **Aiuto » Guida utente** oppure **F1**.

## La finestra in sintesi

![Finestra principale di AdminCraft](../images/main.png)

```
+---------------------------------------------------------------------------+
| File  Visualizza  Strumenti  Aiuto                                        |
| Connessione rapida [SSH v] [host o IP  ] Connetti | Ping  Scansione porte |
+-----------------+-------------------------------------+-------------------+
| Connessioni     |  [Home] [web01] [DC01] [File]  <- schede                |
|  cerca ...      |                                     | Proprietà         |
|  > Data center  |   la connessione aperta, uno        |  nome, host,      |
|     DC01        |   strumento o la pagina Home        |  accesso, opzioni |
|     web01       |                                     |  della connessione|
|  > Rete         |                                     |  selezionata      |
+-----------------+-------------------------------------+-------------------+
| 16 connessioni · 3 cartelle | stato password principale | dov'è l'elenco   |
+---------------------------------------------------------------------------+
```

- **A sinistra: l'albero delle connessioni.** Cartelle e connessioni. Il doppio clic apre, il clic destro mostra
  tutto ciò che puoi fare con una voce.
- **Al centro: le schede.** Ogni connessione o strumento aperto ha una sua scheda. La scheda **Home** mostra le
  schede di avvio rapido, quante connessioni usano ciascun protocollo e quali programmi di supporto sono stati trovati.
- **A destra: le proprietà.** Tutto sulla connessione o cartella selezionata. Le modifiche vengono salvate
  da sole dopo un attimo.
- **In alto: la connessione rapida.** Scegli un protocollo, scrivi `host`, `user@host` o `user@host:port`, premi Invio —
  per una connessione occasionale che non vuoi salvare.
- **In basso: la barra di stato.** Numero di connessioni, se una password principale protegge l'elenco
  e dove è salvato l'elenco.

> Suggerimento: Visualizza » Mostra proprietà nasconde il lato destro quando ti serve più spazio.

## La tua prima connessione

1. Fai clic su **+ Connessione** (oppure premi **Ctrl+Shift+N**).
2. A destra dai un **nome**, scegli il **protocollo** (per esempio SSH o RDP) e scrivi
   l'**host o indirizzo IP**. La porta viene compilata per te.
3. In **Accesso** inserisci l'**utente** e, se vuoi, la **password** (vedi *Password* più sotto).
4. Fai doppio clic sulla connessione nell'albero. Si apre in una nuova scheda.

Tutto qui. Vuoi più server simili? Clic destro » **Copia / duplica** e cambia solo l'host.

> Suggerimento: le connessioni di esempio in un nuovo elenco mostrano cosa è possibile. Eliminale quando vuoi.

## Cartelle e ordine

- **+ Cartella** crea una cartella; fai clic destro su una cartella per **Nuova connessione qui** e **Nuova sottocartella**.
- **Trascina e rilascia:** trascina una connessione sulla metà superiore o inferiore di un'altra voce per metterla prima o
  dopo di essa; rilasciala al centro di una cartella per spostarla dentro.
- Clic destro » **Sposta su / Sposta giù** fa lo stesso con il menu del mouse.
- **Cerca** sopra l'albero (Ctrl+Shift+F) filtra per nome, host e utente.

**Le cartelle trasmettono i valori.** Imposta utente, dominio e password su una cartella, e ogni connessione al suo interno
con *Prendi i campi vuoti dalla cartella* attivo li usa. Cambia la password di amministratore una sola volta sulla
cartella invece che su cinquanta server. Le proprietà mostrano in blu da dove viene un valore.

Clic destro su una cartella » **Apri tutte le connessioni nella cartella** le apre tutte insieme.

## Protocolli: cosa si apre dove

| Protocollo | Si apre come | Serve |
|---|---|---|
| SSH | scheda terminale (oppure PuTTY, o una finestra separata) | OpenSSH (integrato in Windows 10/11, macOS, Linux) o PuTTY |
| RDP | finestra di Desktop remoto dentro la scheda (Windows) | `mstsc` (Windows), FreeRDP o Remmina (Linux), Windows App (macOS) |
| VNC | finestra del viewer dentro la scheda | un VNC viewer come TigerVNC o TightVNC |
| Telnet | scheda terminale | — |
| PowerShell | scheda terminale con `Enter-PSSession` | PowerShell, WinRM sulla destinazione |
| HTTP / HTTPS | finestra app del browser dentro la scheda | Edge o Chrome (altrimenti il browser normale) |
| SFTP / SCP / FTP / FTPS | scheda di trasferimento file | OpenSSH o PuTTY per SFTP/SCP; FTP è integrato |
| Seriale, TCP raw, rlogin | PuTTY nella scheda o una scheda terminale | PuTTY/plink (Windows); picocom, nc … altrove |
| Shell locale | scheda terminale su questo computer | — |

**Finestre dentro le schede.** Su Windows, le finestre di Desktop remoto, PuTTY, VNC e web vengono inserite nella
scheda. Fai clic al loro interno per scrivere. **Come finestra separata** ne stacca una, **Focus** le passa la tastiera.
Su Linux e macOS questi programmi girano in finestre proprie e la scheda mostra il loro stato.

**La scheda terminale** gestisce i colori e i programmi a schermo intero (top, htop, mc, vim). La sua barra degli strumenti ha
**Riconnetti**, **Comandi** (comandi salvati), **Copia testo**, **Invia password** e **Ctrl+C**.

## Password

Per ogni connessione scegli in **Password da**:

- **In AdminCraft (crittografata)** — salvata nell'elenco, crittografata.
- **KeePass** — letta da un database KeePass o KeePassXC (voce per titolo o percorso). AdminCraft chiede
  la password del database una volta per sessione (Strumenti » Sblocca KeePass).
- **Chiedi ogni volta** — non viene salvato nulla.

**Accesso automatico:** per SSH e Telnet la password viene digitata quando il server la chiede
(Impostazioni » *Digita automaticamente la password salvata nel terminale*). Per RDP viene passata a Windows
solo per quella connessione.

**Password principale** (Impostazioni » Posizione di archiviazione): senza di essa, le password salvate sono solo offuscate — chiunque
abbia il file e AdminCraft potrebbe leggerle. Con una password principale sono crittografate davvero
(AES-256-GCM, Argon2), e puoi scegliere di **crittografare l'intero elenco** (anche nomi e host).
AdminCraft chiede poi la password principale all'avvio.

> Importante: senza la password principale non si torna indietro. Annotala in un posto sicuro.

**Codici 2FA:** le voci KeePass con un segreto TOTP mostrano il codice attuale accanto alla password.
**Generatore di password:** Strumenti » Generatore di password, oppure il pulsante *Genera* accanto a un campo password.

### KeePass come elenco delle connessioni

Usi già KeePass o KeePassXC? Allora tieni lì l'intero elenco delle connessioni:

1. Impostazioni » Cassaforte password: indica il database (`.kdbx`) e fai clic su **Sblocca …**.
2. Fai clic su **Tieni l'elenco delle connessioni in KeePass**.

Ogni connessione diventa una normale voce KeePass nel gruppo **AdminCraft** — titolo, utente, password,
URL (ad es. `ssh://10.0.0.30:22`) e note; le cartelle diventano gruppi KeePass. Puoi modificarle anche in
KeePass; AdminCraft se ne accorge e ricarica. Una voce creata in KeePass in quel gruppo (con un URL come
`rdp://10.0.0.10`) compare come connessione. All'avvio AdminCraft chiede la password principale di KeePass.
**Torna all'elenco proprio di AdminCraft** nello stesso punto ricopia l'elenco.

**Salva password in KeePass …** (su una connessione con *Password da » KeePass*): digita la password una
volta; AdminCraft la mette nel gruppo *AdminCraft* del database e da allora usa quella voce.

## Jump host

Alcuni server si raggiungono solo attraverso un altro server (un "jump host" o "bastion").
In **Jump host** nelle proprietà della destinazione, scegli la connessione di salto e il modo di saltare:

- **Prosegui sul jump host: "ssh utente@destinazione"** — AdminCraft accede al jump host e lì digita `ssh user@target`.
  Giusto quando la chiave SSH per la destinazione si trova **sul jump host**.
- **Tunnel attraverso il jump host (ssh -J)** — il tuo computer si connette attraverso il jump host; la chiave resta da te.

I jump host si possono concatenare (un jump host può avere a sua volta un jump host). Funziona nella scheda terminale,
con PuTTY e in una finestra separata.

## Trasferimento file

Clic destro su una connessione SSH » **Trasferisci file (SFTP)**, oppure apri una connessione SFTP/SCP/FTP.

```
+------------------------------+------------------------------+
| Questo computer              | Server                       |
|  C:\Users\me\Downloads       |  /var/www                    |
|  report.pdf        -->       |  index.html                  |
|                    <--       |  logs/                       |
+------------------------------+------------------------------+
```

- A sinistra il tuo computer, a destra il server. **Carica** e **Scarica** copiano i file o le cartelle selezionati.
- **Nuova cartella**, **Rinomina**, **Elimina** funzionano su entrambi i lati. Puoi trascinare i file dal
  gestore file.
- Quali programmi fanno il lavoro si imposta in Impostazioni » *Trasferimento file con* (OpenSSH, psftp/pscp di PuTTY,
  o automatico). FTP e FTPS (TLS) sono integrati.

## Strumenti per amministratori

Tutti gli strumenti sono nel menu **Strumenti**, nei pulsanti in alto e nel menu del clic destro di una connessione
(in questo caso l'host è già compilato).

- **Ping / Traceroute** — l'host è raggiungibile, e che strada fanno i pacchetti?
- **Scansione porte** — quali servizi rispondono (SSH, RDP, HTTPS, SMB …)? Le porte comuni sono preimpostate.
- **Ricerca DNS** — record A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA di un nome.
- **Wake-on-LAN** — accende un PC tramite la rete; inserisci il suo indirizzo MAC nelle proprietà.
- **Calcolatore subnet** — `192.168.10.77/26` dà rete, maschera, broadcast, primo e ultimo indirizzo.
  Un clic esegue la scansione di quell'intervallo.
- **Verifica certificato** — per quanti giorni un certificato HTTPS è ancora valido, chi lo ha rilasciato, se è attendibile.
- **Tunnel SSH** — port forwarding per connessione (`porta locale → host:porta` sul lato remoto),
  avviati a mano o insieme alla connessione.
- **Verifica stato** (pulsante sopra l'albero) — testa la porta di ogni connessione e colora i pallini nell'albero.
- **Strumenti Windows** (clic destro su un server Windows) — servizi, visualizzatore eventi, gestione computer,
  la condivisione `C$`, **Riavvia** e **Arresta** (con conferma). I server Linux si possono riavviare tramite SSH.
- **Input multiplo** — scrivi la stessa cosa in più schede SSH contemporaneamente (Strumenti » Input multiplo).
- **Comandi salvati** — nella scheda terminale sotto *Comandi*; segnaposto `{host}` `{user}` `{name}`.

- **Whois** — a chi appartiene un dominio o un indirizzo IP, con registrar e date.
- **Controllo header HTTP** — segue ogni reindirizzamento di un indirizzo web, mostra codici di stato,
  header e tempi, controlla gli header di sicurezza (HSTS, CSP …) e gli attributi dei cookie.
- **Interrogazione SNMP** — chiede a uno switch, una stampante o un server (SNMP v2c, community ad es.
  `public`) nome, descrizione, tempo di attività, posizione e le interfacce con stato, velocità e traffico.
  Si può percorrere qualsiasi OID.
- **Registrazioni** — riproduce le sessioni terminale registrate (vedi sotto).

### Registrare le sessioni

Impostazioni » Sessioni e monitoraggio » **Registra le sessioni terminale per riprodurle**: da quel momento
ogni scheda SSH, Telnet, PowerShell e shell viene registrata con i suoi tempi; la scheda mostra
**• registrazione**. Strumenti » **Registrazioni** le elenca, dalla più recente. **Riproduci**, **Pausa**,
la velocità (fino a 16×) e il cursore funzionano come in un video; **Accorcia le pause** salta le lunghe
attese. I file (`.cast`) si possono riprodurre anche con asciinema.

> Le registrazioni contengono tutto ciò che lo schermo ha mostrato. I server non mostrano le password
> digitate, quindi non ci sono — ma tieni comunque privata la cartella.

## Scansione di rete

![Calcolatore subnet](../images/subnet.png)

La scansione di rete (Ctrl+Shift+L) cerca dispositivi in un intervallo IP, come Angry IP Scanner:

1. Inserisci un intervallo: `192.168.1.0/24`, `10.0.0.1-50` o `10.0.0.250-10.0.1.5`.
2. Scegli le porte da verificare e premi **Avvia**.
3. Ogni dispositivo che risponde mostra nome, indirizzo MAC, tempo di risposta e porte aperte.

**Salva come riferimento per il confronto** memorizza il risultato. La scansione successiva dello stesso intervallo segna ogni dispositivo come
**NUOVO**, **SCOMPARSO** o **MODIFICATO** (es. un indirizzo MAC diverso) — utile per scoprire estranei nella rete.

**+ Connessione** su un risultato crea una connessione nella cartella *Scansione di rete*; scegli il protocollo
dall'elenco.

## Condivisione e archiviazione centrale

![Finestra di esportazione](../images/export.png)

**Esporta per un collega** (File » Esporta connessioni, oppure clic destro su una cartella » Esporta cartella):

- **Senza password** — la scelta sicura predefinita.
- **Crittografato con una password di esportazione** — comunica la password al collega in un altro modo (telefono).
- **In chiaro** — solo dopo un avviso chiaro; chiunque riceva il file può leggere le password.

**Importa** con File » Importa esportazione AdminCraft. Le voci importate finiscono in una cartella propria.

**Elenco centrale per il team** (Impostazioni » Posizione di archiviazione): tieni l'elenco su una **condivisione di rete** (SMB,
es. `\\server\it\AdminCraft-Connections.json`) o su un **server WebDAV** (Nextcloud, ownCloud, IIS).
Proteggilo con la password principale. Quando un collega cambia qualcosa, AdminCraft lo ricarica.

**Passare da altri strumenti:** File » Importa file mRemoteNG (`confCons.xml`, con le password) e
File » Importa configurazione OpenSSH (`~/.ssh/config`, incluso ProxyJump).

## Impostazioni

Si aprono con il pulsante **Impostazioni**, con **Ctrl+,** o con Strumenti » Impostazioni.

- **Lingua** — la lingua di sistema come predefinita; puoi cambiarla in qualsiasi momento.
- **Aspetto** — scuro o chiaro, dimensione del carattere del terminale.
- **SSH, desktop remoto e file** — quale client apre SSH (terminale integrato, PuTTY, finestra separata),
  quali programmi trasferiscono i file, se le finestre vengono incorporate nelle schede.
- **Programmi** — dove AdminCraft ha trovato ogni programma di supporto. Indica un percorso personalizzato, oppure metti semplicemente
  i programmi portatili nella **cartella programmi** (`AdminCraftTools` accanto ad AdminCraft).
- **Posizione di archiviazione** — dove si trova l'elenco, password principale, archiviazione centrale.
- **Cassaforte password** — il database KeePass da usare.

- **Aggiornamenti** — **Cerca aggiornamenti** chiede a GitHub la versione più recente e offre la pagina di
  download. AdminCraft non controlla mai da solo.
- **Agenti IA** — se assistenti IA e script su questo computer possono controllare la finestra aperta, e se
  possono anche scrivere nelle schede terminale (disattivato finché non lo attivi).
- **Sessioni e monitoraggio** — riaprire le ultime connessioni all'avvio, log di testo, registrazioni da
  riprodurre, controllo regolare della raggiungibilità.
- **Cassaforte password** — anche KeePass come intero elenco delle connessioni.

## Portatile: tutto accanto al programma

AdminCraft è un unico file. Tutto ciò che salva si trova in cartelle accanto ad esso:

```
AdminCraft.exe
AdminCraftData\     connessioni, riferimenti delle scansioni, log delle sessioni, registrazioni
AdminCraftTools\    programmi di supporto che hai aggiunto (putty.exe, vncviewer.exe …)
AdminCraftLang\     i tuoi file di lingua
```

Copia la cartella su una chiavetta USB e avrai con te tutta la tua cassetta degli attrezzi. Se nella cartella non si può scrivere
(per esempio dentro un'app macOS), AdminCraft usa invece `.admincraft` nella tua cartella home.

AdminCraft non contatta nulla su internet di sua iniziativa — solo gli host a cui ti connetti.

Unica eccezione: GitHub, quando fai clic su *Cerca aggiornamenti*.

## Lingue

Inglese, tedesco, francese, italiano e ucraino sono integrati. Per aggiungere una lingua o migliorarne una:

1. Impostazioni » Lingua » **Apri cartella lingue**.
2. Copia `de.lang.example` per es. come `es.lang`, imposta `@name` e `@code` in cima.
3. Traduci il testo a destra di ` = ` in ogni riga. Il lato sinistro è l'originale inglese e resta così.
   `{0}`, `{1}` sono segnaposto e devono restare.
4. Scegli la lingua nelle impostazioni.

Un file lì con il codice di una lingua integrata (es. `fr.lang`) migliora quella lingua.
Questa guida utente si può tradurre allo stesso modo: salvala come `help-xx.md` nella cartella lingue.

## Scorciatoie da tastiera

| Tasti | Cosa |
|---|---|
| Ctrl+Tab / Ctrl+Shift+Tab | scheda successiva / precedente |
| Ctrl+Shift+W | chiudi scheda |
| Ctrl+Shift+N | nuova connessione |
| Ctrl+Shift+F | cerca connessioni |
| Ctrl+Shift+S | screenshot della scheda negli appunti |
| Ctrl+Shift+E | esporta connessioni |
| Ctrl+Shift+L | scansione di rete |
| Ctrl+, | impostazioni |
| F1 | questa guida |
| Doppio clic | apri connessione / rinomina scheda |
| Tasto centrale del mouse | chiudi scheda |

Le scorciatoie usano Shift, così i programmi in una scheda terminale mantengono i propri tasti Ctrl. Su macOS usa Cmd
invece di Ctrl. Puoi trascinare le schede per riordinarle; fai clic destro su una scheda per rinominarla.

## Per script e agenti IA

Gli stessi strumenti funzionano senza la finestra e stampano JSON. Le password non vengono mai restituite.

```
admincraft cli list [filter]          connessioni salvate
admincraft cli scan 192.168.1.0/24    scansione di rete, confrontata con il riferimento salvato
admincraft cli ports <host> [ports]   scansione porte
admincraft cli dns <name>             ricerca DNS
admincraft cli subnet <cidr>          calcolatore subnet
admincraft cli cert <host> [port]     verifica certificato
admincraft cli open <name>            apre una connessione nella finestra
admincraft mcp                        server MCP per assistenti IA (stdin/stdout)
```

**Controllare la finestra aperta.** Quando AdminCraft è aperto, gli agenti possono anche lavorarci — come
un collega che guarda da sopra la spalla (Impostazioni » Agenti IA lo attiva o disattiva):

```
admincraft cli window tabs              le schede aperte
admincraft cli window read 2            cosa mostra la scheda 2
admincraft cli window tool ping web01   apre una scheda strumento
admincraft cli window switch 2          porta una scheda in primo piano
admincraft cli window type 2 uptime     scrive in un terminale + Invio
```

Il server MCP offre lo stesso come strumenti `window_…`. Scrivere nei terminali è possibile solo dopo averlo
consentito nelle impostazioni, e ogni digitazione viene mostrata nella finestra. Possono collegarsi solo i
programmi su questo computer che leggono la cartella dati; le password non vengono mai fornite.

## Domande e problemi

**"Programma non trovato"** — la scheda Home, *Controllo di sistema*, mostra quali programmi di supporto mancano. Installali,
indica un percorso in Impostazioni » Programmi, oppure mettili nella cartella programmi e premi *Cerca di nuovo*.

**SSH: "Remote side unexpectedly closed network connection" dietro un jump host** — probabilmente la chiave per la
destinazione si trova sul jump host. Scegli *Prosegui sul jump host* come modalità di salto.

**La finestra di Desktop remoto non compare nella scheda** — attendi qualche secondo (le richieste di certificato
compaiono prima in una finestra separata), poi premi *Riconnetti*. Impostazioni » *Incorpora le finestre RDP, PuTTY e VNC
nella scheda* disattiva l'incorporamento.

**Password principale dimenticata** — le password crittografate non si possono recuperare. Ricomincia con un elenco vuoto
(sposta altrove il file in `AdminCraftData`) e importa un'esportazione.

**Dove sono i miei dati?** — File » Apri cartella dati.

**AdminCraft chiede una password KeePass all'avvio** — l'elenco delle connessioni è in KeePass. Inserisci
la password principale di KeePass, oppure fai clic su *Senza KeePass* per partire con l'elenco proprio
(vuoto) di AdminCraft.
