# Guide d'utilisation d'AdminCraft

AdminCraft réunit tous vos serveurs, switchs et PC dans une seule liste et les ouvre d'un double-clic :
Bureau à distance, SSH, VNC, Telnet, PowerShell, interfaces web et transfert de fichiers, chacun dans son propre onglet.
En plus, il apporte les outils de tous les jours d'un administrateur : ping, scan de ports, analyse réseau, DNS,
calculateur de sous-réseau, vérification de certificat et plus encore.

Ce guide se trouve aussi dans le programme : **Aide » Guide d'utilisation** ou **F1**.

## La fenêtre en un coup d'œil

![Fenêtre principale d'AdminCraft](../images/main.png)

```
+---------------------------------------------------------------------------+
| Fichier  Affichage  Outils  Aide                                          |
| Connexion rapide [SSH v] [hôte ou IP] Connecter | Ping  Scan de ports ... |
+----------------------+------------------------------+---------------------+
| Connexions           |  [Accueil] [web01] [DC01] [Fichiers]  <- onglets   |
|  rechercher ...      |                              | Propriétés          |
|  > Centre de données |   la connexion ouverte,      |  nom, hôte,         |
|     DC01             |   un outil ou la page        |  identifiants,      |
|     web01            |   d'accueil                  |  options de la      |
|  > Réseau            |                              |  connexion choisie  |
+----------------------+------------------------------+---------------------+
| 16 connexions · 3 dossiers | état mot de passe maître | lieu de la liste  |
+---------------------------------------------------------------------------+
```

- **À gauche : l'arborescence des connexions.** Dossiers et connexions. Un double-clic ouvre, un clic droit
  affiche tout ce que vous pouvez faire avec une entrée.
- **Au milieu : les onglets.** Chaque connexion ou outil ouvert reçoit un onglet. L'onglet **Accueil** affiche des
  cartes de démarrage rapide, combien de connexions utilisent quel protocole et quels programmes d'aide ont été trouvés.
- **À droite : les propriétés.** Tout sur la connexion ou le dossier sélectionné. Les modifications sont enregistrées
  automatiquement au bout d'un instant.
- **En haut : la connexion rapide.** Choisissez un protocole, tapez `host`, `user@host` ou `user@host:port`, appuyez sur Entrée —
  pour une connexion ponctuelle que vous ne voulez pas enregistrer.
- **En bas : la barre d'état.** Nombre de connexions, si un mot de passe maître protège la liste,
  et où la liste est stockée.

> Astuce : Affichage » Afficher les propriétés masque la partie droite quand il vous faut plus de place.

## Votre première connexion

1. Cliquez sur **+ Connexion** (ou appuyez sur **Ctrl+Shift+N**).
2. À droite, donnez-lui un **nom**, choisissez le **protocole** (par exemple SSH ou RDP) et tapez
   l'**hôte ou adresse IP**. Le port est rempli pour vous.
3. Sous **Identifiants**, saisissez l'**utilisateur** et, si vous le souhaitez, le **mot de passe** (voir *Mots de passe* plus bas).
4. Double-cliquez sur la connexion dans l'arborescence. Elle s'ouvre dans un nouvel onglet.

C'est tout. Vous voulez plusieurs serveurs semblables ? Clic droit » **Copier / dupliquer** et ne changez que l'hôte.

> Astuce : les connexions d'exemple d'une nouvelle liste montrent ce qui est possible. Supprimez-les quand vous voulez.

## Dossiers et ordre

- **+ Dossier** crée un dossier ; clic droit sur un dossier pour **Nouvelle connexion ici** et **Nouveau sous-dossier**.
- **Glisser-déposer :** faites glisser une connexion sur la moitié haute ou basse d'une autre entrée pour la placer avant ou
  après elle ; déposez-la au milieu d'un dossier pour la mettre dedans.
- Clic droit » **Monter / Descendre** fait la même chose avec le menu de la souris.
- **Rechercher** au-dessus de l'arborescence (Ctrl+Shift+F) filtre par nom, hôte et utilisateur.

**Les dossiers transmettent des valeurs.** Indiquez l'utilisateur, le domaine et le mot de passe sur un dossier, et chaque connexion
qu'il contient avec *Reprendre les champs vides du dossier* activé les utilise. Changez le mot de passe admin une seule fois sur le
dossier au lieu de cinquante serveurs. Les propriétés montrent en bleu d'où vient une valeur.

Clic droit sur un dossier » **Ouvrir toutes les connexions du dossier** les ouvre toutes d'un coup.

## Protocoles : ce qui s'ouvre où

| Protocole | S'ouvre comme | Nécessite |
|---|---|---|
| SSH | onglet terminal (ou PuTTY, ou sa propre fenêtre) | OpenSSH (intégré à Windows 10/11, macOS, Linux) ou PuTTY |
| RDP | fenêtre Bureau à distance dans l'onglet (Windows) | `mstsc` (Windows), FreeRDP ou Remmina (Linux), Windows App (macOS) |
| VNC | fenêtre de la visionneuse dans l'onglet | une visionneuse VNC comme TigerVNC ou TightVNC |
| Telnet | onglet terminal | — |
| PowerShell | onglet terminal avec `Enter-PSSession` | PowerShell, WinRM sur la cible |
| HTTP / HTTPS | fenêtre d'application du navigateur dans l'onglet | Edge ou Chrome (sinon le navigateur habituel) |
| SFTP / SCP / FTP / FTPS | onglet de transfert de fichiers | OpenSSH ou PuTTY pour SFTP/SCP ; FTP est intégré |
| Série, TCP brut, rlogin | PuTTY dans l'onglet ou un onglet terminal | PuTTY/plink (Windows) ; picocom, nc … ailleurs |
| Shell local | onglet terminal sur cet ordinateur | — |

**Des fenêtres dans les onglets.** Sous Windows, les fenêtres Bureau à distance, PuTTY, VNC et web sont placées dans
l'onglet. Cliquez dedans pour taper. **Fenêtre séparée** en détache une à nouveau, **Focus** lui donne le clavier.
Sous Linux et macOS, ces programmes s'ouvrent dans leurs propres fenêtres et l'onglet affiche leur état.

**L'onglet terminal** comprend les couleurs et les programmes plein écran (top, htop, mc, vim). Sa barre d'outils propose
**Reconnecter**, **Commandes** (commandes enregistrées), **Copier le texte**, **Envoyer le mot de passe** et **Ctrl+C**.

## Mots de passe

Pour chaque connexion, vous choisissez sous **Mot de passe depuis** :

- **Dans AdminCraft (chiffré)** — enregistré dans la liste, chiffré.
- **KeePass** — lu dans une base KeePass ou KeePassXC (entrée par titre ou chemin). AdminCraft demande
  le mot de passe de la base une fois par session (Outils » Déverrouiller KeePass).
- **Demander à chaque fois** — rien n'est enregistré.

**Connexion automatique :** pour SSH et Telnet, le mot de passe est tapé quand le serveur le demande
(Paramètres » *Saisir automatiquement le mot de passe enregistré dans le terminal*). Pour RDP, il est transmis à Windows
pour cette seule connexion.

**Mot de passe maître** (Paramètres » Emplacement de stockage) : sans lui, les mots de passe enregistrés sont seulement masqués — toute personne
ayant le fichier et AdminCraft pourrait les lire. Avec un mot de passe maître, ils sont vraiment chiffrés
(AES-256-GCM, Argon2), et vous pouvez choisir de **chiffrer toute la liste** (noms et hôtes compris).
AdminCraft demande alors le mot de passe maître au démarrage.

> Important : sans le mot de passe maître, il n'y a pas de retour possible. Notez-le en lieu sûr.

**Codes 2FA :** les entrées KeePass avec un secret TOTP affichent le code actuel à côté du mot de passe.
**Générateur de mots de passe :** Outils » Générateur de mots de passe, ou le bouton *Générer* à côté d'un champ de mot de passe.

### KeePass comme liste des connexions

Vous utilisez déjà KeePass ou KeePassXC ? Alors gardez-y toute la liste des connexions :

1. Paramètres » Coffre à mots de passe : indiquez la base (`.kdbx`) et cliquez sur **Déverrouiller …**.
2. Cliquez sur **Conserver la liste des connexions dans KeePass**.

Chaque connexion devient une entrée KeePass normale dans le groupe **AdminCraft** — titre, utilisateur,
mot de passe, URL (p. ex. `ssh://10.0.0.30:22`) et notes ; les dossiers deviennent des groupes KeePass. Vous
pouvez aussi les modifier dans KeePass ; AdminCraft le remarque et recharge. Une entrée créée dans ce groupe
dans KeePass (avec une URL comme `rdp://10.0.0.10`) apparaît comme connexion. Au démarrage, AdminCraft
demande le mot de passe maître KeePass. **Revenir à la liste propre d'AdminCraft** au même endroit recopie la liste.

**Enregistrer le mot de passe dans KeePass …** (sur une connexion avec *Mot de passe depuis » KeePass*) :
saisissez le mot de passe une fois ; AdminCraft le range dans le groupe *AdminCraft* de votre base et
utilise ensuite cette entrée.

## Hôtes de rebond

Certains serveurs ne sont accessibles qu'en passant par un autre serveur (un « hôte de rebond » ou « bastion »).
Sous **Hôte de rebond** dans les propriétés de la cible, choisissez la connexion de rebond et la manière de rebondir :

- **Continuer sur l'hôte de rebond : « ssh user@cible »** — AdminCraft se connecte à l'hôte de rebond et y tape `ssh user@target`.
  Idéal quand la clé SSH de la cible se trouve **sur l'hôte de rebond**.
- **Tunnel via l'hôte de rebond (ssh -J)** — votre propre ordinateur se connecte en passant par l'hôte de rebond ; la clé reste chez vous.

Les hôtes de rebond peuvent s'enchaîner (un hôte de rebond peut lui-même avoir un hôte de rebond). Cela fonctionne dans l'onglet terminal,
avec PuTTY et dans une fenêtre séparée.

## Transférer des fichiers

Clic droit sur une connexion SSH » **Transférer des fichiers (SFTP)**, ou ouvrez une connexion SFTP/SCP/FTP.

```
+------------------------------+------------------------------+
| Cet ordinateur               | Serveur                      |
|  C:\Users\me\Downloads       |  /var/www                    |
|  report.pdf        -->       |  index.html                  |
|                    <--       |  logs/                       |
+------------------------------+------------------------------+
```

- À gauche votre ordinateur, à droite le serveur. **Envoyer** et **Télécharger** copient les fichiers ou dossiers sélectionnés.
- **Nouveau dossier**, **Renommer**, **Supprimer** fonctionnent des deux côtés. Vous pouvez glisser des fichiers depuis le
  gestionnaire de fichiers.
- Les programmes qui font le travail se règlent dans Paramètres » *Transfert de fichiers avec* (OpenSSH, psftp/pscp de PuTTY,
  ou automatique). FTP et FTPS (TLS) sont intégrés.

## Outils pour administrateurs

Tous les outils se trouvent dans le menu **Outils**, dans les boutons du haut et dans le menu du clic droit d'une connexion
(l'hôte est alors déjà rempli).

- **Ping / Traceroute** — l'hôte est-il accessible, et quel chemin prennent les paquets ?
- **Scan de ports** — quels services répondent (SSH, RDP, HTTPS, SMB …) ? Les ports courants sont présélectionnés.
- **Requête DNS** — enregistrements A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA d'un nom.
- **Wake-on-LAN** — allume un PC via le réseau ; saisissez son adresse MAC dans les propriétés.
- **Calculateur de sous-réseau** — `192.168.10.77/26` donne le réseau, le masque, le broadcast, la première et la dernière adresse.
  Un clic suffit pour scanner cette plage.
- **Vérifier un certificat** — combien de jours un certificat HTTPS reste valide, qui l'a délivré, s'il est approuvé.
- **Tunnels SSH** — redirections de ports par connexion (`local port → host:port` de l'autre côté),
  démarrées à la main ou en même temps que la connexion.
- **Vérifier l'état** (bouton au-dessus de l'arborescence) — teste le port de chaque connexion et colore les points de l'arborescence.
- **Outils Windows** (clic droit sur un serveur Windows) — services, observateur d'événements, gestion de l'ordinateur,
  le partage `C$`, **Redémarrer** et **Éteindre** (avec confirmation). Les serveurs Linux peuvent être redémarrés via SSH.
- **Saisie multiple** — tapez la même chose dans plusieurs onglets SSH à la fois (Outils » Saisie multiple).
- **Commandes enregistrées** — dans l'onglet terminal sous *Commandes* ; variables `{host}` `{user}` `{name}`.

- **Whois** — à qui appartient un domaine ou une adresse IP, avec le registraire et les dates.
- **Vérification des en-têtes HTTP** — suit chaque redirection d'une adresse web, montre codes d'état,
  en-têtes et durées, vérifie les en-têtes de sécurité (HSTS, CSP …) et les attributs des cookies.
- **Requête SNMP** — interroge un switch, une imprimante ou un serveur (SNMP v2c, communauté p. ex. `public`)
  sur son nom, sa description, sa durée de fonctionnement, son emplacement et ses interfaces avec état,
  débit et trafic. Tout OID peut être parcouru.
- **Enregistrements** — rejoue les sessions terminal enregistrées (voir ci-dessous).

### Enregistrer les sessions

Paramètres » Sessions et surveillance » **Enregistrer les sessions terminal pour les rejouer** : dès lors,
chaque onglet SSH, Telnet, PowerShell et shell est enregistré avec son minutage ; l'onglet affiche
**• enregistrement**. Outils » **Enregistrements** les liste, du plus récent au plus ancien. **Lire**,
**Pause**, la vitesse (jusqu'à 16×) et le curseur fonctionnent comme pour une vidéo ; **Raccourcir les pauses**
saute les longues attentes. Les fichiers (`.cast`) se lisent aussi avec asciinema.

> Les enregistrements contiennent tout ce que l'écran a montré. Les serveurs n'affichent pas les mots de
> passe tapés, ils n'y sont donc pas — gardez quand même le dossier privé.

## Analyse réseau

![Calculateur de sous-réseau](../images/subnet.png)

L'analyse réseau (Ctrl+Shift+L) recherche des appareils dans une plage IP, comme Angry IP Scanner :

1. Saisissez une plage : `192.168.1.0/24`, `10.0.0.1-50` ou `10.0.0.250-10.0.1.5`.
2. Choisissez les ports à vérifier et appuyez sur **Démarrer**.
3. Chaque appareil qui répond affiche son nom, son adresse MAC, son temps de réponse et ses ports ouverts.

**Enregistrer comme référence** mémorise le résultat. Le prochain scan de la même plage marque chaque appareil comme
**nouveau**, **disparu** ou **modifié** (p. ex. une autre adresse MAC) — pratique pour repérer des inconnus sur le réseau.

**+ Connexion** sur un résultat crée une connexion dans le dossier *Analyse réseau* ; choisissez le protocole
dans la liste.

## Partage et stockage centralisé

![Boîte de dialogue d'export](../images/export.png)

**Exporter pour un collègue** (Fichier » Exporter les connexions, ou clic droit sur un dossier » Exporter le dossier) :

- **Sans mots de passe** — le choix sûr par défaut.
- **Chiffré avec un mot de passe d'export** — communiquez le mot de passe à votre collègue par un autre moyen (téléphone).
- **En clair** — seulement après un avertissement clair ; toute personne qui reçoit le fichier peut lire les mots de passe.

**Importer** avec Fichier » Importer un export AdminCraft. Les entrées importées arrivent dans leur propre dossier.

**Liste centrale pour l'équipe** (Paramètres » Emplacement de stockage) : gardez la liste sur un **partage réseau** (SMB,
p. ex. `\\server\it\AdminCraft-Connections.json`) ou un **serveur WebDAV** (Nextcloud, ownCloud, IIS).
Protégez-la avec le mot de passe maître. Quand un collègue modifie quelque chose, AdminCraft la recharge.

**Venir d'autres outils :** Fichier » Importer un fichier mRemoteNG (`confCons.xml`, avec les mots de passe) et
Fichier » Importer la configuration OpenSSH (`~/.ssh/config`, ProxyJump compris).

## Paramètres

Ouvrez-les avec le bouton **Paramètres**, **Ctrl+,** ou Outils » Paramètres.

- **Langue** — la langue du système par défaut ; changez-la à tout moment.
- **Apparence** — sombre ou clair, taille de la police du terminal.
- **SSH, bureau à distance et fichiers** — quel client ouvre SSH (terminal intégré, PuTTY, fenêtre séparée),
  quels programmes transfèrent les fichiers, si les fenêtres sont intégrées dans les onglets.
- **Programmes** — où AdminCraft a trouvé chaque programme d'aide. Indiquez votre propre chemin, ou déposez simplement
  des programmes portables dans le **dossier des programmes** (`AdminCraftTools` à côté d'AdminCraft).
- **Emplacement de stockage** — où se trouve la liste, mot de passe maître, stockage centralisé.
- **Coffre à mots de passe** — la base KeePass à utiliser.

- **Mises à jour** — **Rechercher des mises à jour** demande à GitHub la dernière version et propose la page
  de téléchargement. AdminCraft ne vérifie jamais de lui-même.
- **Agents IA** — si les assistants IA et scripts de cet ordinateur peuvent piloter la fenêtre ouverte, et
  s'ils peuvent aussi taper dans les onglets terminal (désactivé tant que vous ne l'activez pas).
- **Sessions et surveillance** — rouvrir les dernières connexions au démarrage, journaux texte,
  enregistrements à rejouer, vérification régulière de l'accessibilité.
- **Coffre à mots de passe** — aussi KeePass comme liste complète des connexions.

## Portable : tout à côté du programme

AdminCraft tient en un seul fichier. Tout ce qu'il conserve se trouve dans des dossiers à côté de lui :

```
AdminCraft.exe
AdminCraftData\     connexions, références de scan, journaux de session, enregistrements
AdminCraftTools\    programmes d'aide que vous y avez déposés (putty.exe, vncviewer.exe …)
AdminCraftLang\     vos propres fichiers de langue
```

Copiez le dossier sur une clé USB et vous emportez toute votre boîte à outils. Si le dossier n'est pas accessible en écriture
(par exemple dans une app macOS), AdminCraft utilise à la place `.admincraft` dans votre dossier personnel.

AdminCraft ne contacte rien sur Internet de lui-même — seulement les hôtes auxquels vous vous connectez.

Seule exception : GitHub, quand vous cliquez sur *Rechercher des mises à jour*.

## Langues

L'anglais, l'allemand, le français, l'italien et l'ukrainien sont intégrés. Pour ajouter une langue ou en améliorer une :

1. Paramètres » Langue » **Ouvrir le dossier des langues**.
2. Copiez `de.lang.example` vers p. ex. `es.lang`, et réglez `@name` et `@code` en haut du fichier.
3. Traduisez le texte à droite de ` = ` sur chaque ligne. La partie gauche est l'original anglais et ne change pas.
   `{0}`, `{1}` sont des variables et doivent rester.
4. Choisissez la langue dans les paramètres.

Un fichier placé là avec le code d'une langue intégrée (p. ex. `fr.lang`) améliore cette langue.
Ce guide d'utilisation peut être traduit de la même façon : enregistrez-le sous `help-xx.md` dans le dossier des langues.

## Raccourcis clavier

| Touches | Action |
|---|---|
| Ctrl+Tab / Ctrl+Shift+Tab | onglet suivant / précédent |
| Ctrl+Shift+W | fermer l'onglet |
| Ctrl+Shift+N | nouvelle connexion |
| Ctrl+Shift+F | rechercher des connexions |
| Ctrl+Shift+S | capture d'écran de l'onglet dans le presse-papiers |
| Ctrl+Shift+E | exporter les connexions |
| Ctrl+Shift+L | analyse réseau |
| Ctrl+, | paramètres |
| F1 | ce guide |
| Double-clic | ouvrir la connexion / renommer l'onglet |
| Bouton du milieu de la souris | fermer l'onglet |

Les raccourcis utilisent Shift, pour que les programmes d'un onglet terminal gardent leurs propres touches Ctrl. Sous macOS, utilisez Cmd
au lieu de Ctrl. Les onglets peuvent être glissés pour changer leur ordre ; clic droit sur un onglet pour le renommer.

## Pour les scripts et les agents IA

Les mêmes outils fonctionnent sans la fenêtre et affichent du JSON. Les mots de passe ne sont jamais renvoyés.

```
admincraft cli list [filter]          connexions enregistrées
admincraft cli scan 192.168.1.0/24    analyse réseau, comparée à la référence enregistrée
admincraft cli ports <host> [ports]   scan de ports
admincraft cli dns <name>             requête DNS
admincraft cli subnet <cidr>          calculateur de sous-réseau
admincraft cli cert <host> [port]     vérification de certificat
admincraft cli open <name>            ouvrir une connexion dans la fenêtre
admincraft mcp                        serveur MCP pour assistants IA (stdin/stdout)
```

**Piloter la fenêtre ouverte.** Quand AdminCraft est ouvert, les agents peuvent aussi travailler avec —
comme un collègue qui regarde par-dessus votre épaule (Paramètres » Agents IA l'active ou le désactive) :

```
admincraft cli window tabs              les onglets ouverts
admincraft cli window read 2            ce que montre l'onglet 2
admincraft cli window tool ping web01   ouvrir un onglet d'outil
admincraft cli window switch 2          mettre un onglet au premier plan
admincraft cli window type 2 uptime     taper dans un terminal + Entrée
```

Le serveur MCP offre la même chose sous forme d'outils `window_…`. Taper dans les terminaux n'est possible
qu'après l'avoir autorisé dans les paramètres, et chaque saisie est affichée dans la fenêtre. Seuls les
programmes de cet ordinateur pouvant lire le dossier de données peuvent se connecter ; les mots de passe ne
sont jamais transmis.

## Questions et problèmes

**« Programme introuvable »** — l'onglet Accueil, *Vérification du système*, montre quels programmes d'aide manquent. Installez-les,
indiquez un chemin dans Paramètres » Programmes, ou déposez-les dans le dossier des programmes et appuyez sur *Rechercher à nouveau*.

**SSH : « Remote side unexpectedly closed network connection » derrière un hôte de rebond** — la clé de la
cible se trouve probablement sur l'hôte de rebond. Choisissez *Continuer sur l'hôte de rebond* comme mode de rebond.

**La fenêtre Bureau à distance n'apparaît pas dans l'onglet** — attendez quelques secondes (les questions de certificat
apparaissent d'abord dans leur propre fenêtre), puis appuyez sur *Reconnecter*. Paramètres » *Intégrer les fenêtres RDP, PuTTY et VNC
dans l'onglet* désactive l'intégration.

**Mot de passe maître oublié** — les mots de passe chiffrés ne peuvent pas être récupérés. Repartez d'une liste vide
(déplacez le fichier dans `AdminCraftData` ailleurs) et importez un export.

**Où sont mes données ?** — Fichier » Ouvrir le dossier de données.

**AdminCraft demande un mot de passe KeePass au démarrage** — la liste des connexions est dans KeePass.
Saisissez le mot de passe maître KeePass, ou cliquez sur *Sans KeePass* pour démarrer avec la liste propre
(vide) d'AdminCraft.
