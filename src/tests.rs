//! Quick self-tests: `cargo test`.

use crate::model::{new_salt, sample_data, Protocol, Store, Vault};
use crate::tools::{parse_mac, parse_ports};

fn temp_store(name: &str) -> Store {
    let dir = std::env::temp_dir().join(format!("admincraft-test-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let mut s = Store::open(true);
    s.read_only = false;
    s.path = dir.join("connections.json");
    s.data = sample_data();
    s.data.salt = String::new();
    s.vault = Some(Vault::derive("", &s.salt()));
    s
}

#[test]
fn vault_roundtrip() {
    let v = Vault::derive("geheim", &new_salt());
    let c = v.encrypt("P@ssw0rd äöü");
    assert_eq!(v.decrypt(&c).as_deref(), Some("P@ssw0rd äöü"));
    let other = Vault::derive("falsch", &new_salt());
    assert_eq!(other.decrypt(&c), None);
}

#[test]
fn master_password_save_and_unlock() {
    let mut s = temp_store("master");
    let id = s.data.entries.iter().find(|e| e.name.starts_with("web01")).unwrap().id;
    let i = s.index_of(id).unwrap();
    s.data.entries[i].password = "toor".into();
    s.set_master("Sicher123");
    let text = std::fs::read_to_string(&s.path).unwrap();
    assert!(!text.contains("toor"), "password must not be stored in clear text");

    // reopen from disk
    let data: crate::model::DataFile = serde_json::from_str(&text).unwrap();
    let mut s2 = temp_store("master2");
    s2.data = data;
    s2.vault = None;
    assert!(s2.locked());
    assert!(!s2.unlock("falsch"));
    assert!(s2.unlock("Sicher123"));
    assert_eq!(s2.get(id).unwrap().password, "toor");
    let _ = std::fs::remove_file(&s.path);
}

#[test]
fn credentials_inherit_from_folder() {
    let s = temp_store("inherit");
    let dc = s.data.entries.iter().find(|e| e.name.starts_with("DC01")).unwrap();
    let (u, d, _) = s.credentials(dc.id);
    assert_eq!(u, "administrator");
    assert_eq!(d, "FIRMA");
    let web = s.data.entries.iter().find(|e| e.name.starts_with("web01")).unwrap();
    let (u, d, _) = s.credentials(web.id);
    assert_eq!(u, "root");
    assert_eq!(d, "");
}

#[test]
fn remove_deletes_children() {
    let mut s = temp_store("remove");
    let before = s.data.entries.len();
    s.remove(1); // "Rechenzentrum" with 8 connections
    assert_eq!(s.data.entries.len(), before - 9);
}

#[test]
fn jump_chain_and_chain_command() {
    let s = temp_store("jump");
    let db = s.data.entries.iter().find(|e| e.name.starts_with("db01")).unwrap();
    let chain = s.jump_chain(db.id);
    assert_eq!(chain.len(), 1);
    assert_eq!(s.get(chain[0]).unwrap().name, "bastion – Jump-Host");
    let c = crate::launch::Creds { user: "root".into(), ..Default::default() };
    assert_eq!(crate::launch::chain_command(db, &c), "ssh -t root@10.0.0.40");
    let mut other = db.clone();
    other.port = 2222;
    assert_eq!(crate::launch::chain_command(&other, &c), "ssh -t -p 2222 root@10.0.0.40");
}

#[test]
fn jump_chain_runs_ssh_on_jump_host() {
    let s = temp_store("jump2");
    let db = s.data.entries.iter().find(|e| e.name.starts_with("db01")).unwrap().clone();
    let bastion = s.get(s.jump_chain(db.id)[0]).unwrap().clone();
    let jumps = vec![crate::launch::JumpHop { entry: bastion, creds: crate::launch::Creds { user: "jump".into(), ..Default::default() } }];
    let c = crate::launch::Creds { user: "root".into(), ..Default::default() };
    assert_eq!(crate::launch::chain_remote_args(&db, &c, &jumps), vec!["ssh", "-t", "root@10.0.0.40"]);
}

#[test]
fn translation_placeholders() {
    // German is the key; without a table the text comes back with the values filled in
    assert_eq!(crate::i18n::tf("{0} Verbindungen · {1} Ordner", &[&3, &"{1}"]), "3 Verbindungen · {1} Ordner");
    let en = include_str!("../lang/en.lang");
    assert!(en.contains("@code = en"));
    // every line with more than one " = " must use " => " (otherwise the key is cut)
    for l in en.lines().filter(|l| !l.starts_with('#')) {
        assert!(l.matches(" = ").count() <= 1 || l.contains(" => "), "ambiguous line: {l}");
    }
    assert!(en.lines().filter(|l| l.contains(" = ")).count() > 300);
}

#[test]
fn netscan_ranges_and_diff() {
    use crate::netscan::{diff, parse_targets, Change, ScanHost};
    use std::net::Ipv4Addr;
    assert_eq!(parse_targets("192.168.1.0/24").unwrap().len(), 254);
    assert_eq!(parse_targets("10.0.0.1-50").unwrap().len(), 50);
    assert_eq!(parse_targets("10.0.0.250-10.0.1.5").unwrap().len(), 12);
    assert_eq!(parse_targets("10.0.0.7, 10.0.0.7").unwrap(), vec![Ipv4Addr::new(10, 0, 0, 7)]);
    assert!(parse_targets("10.0.0.0/8").is_err());
    assert!(parse_targets("hallo").is_err());
    let h = |last: u8, mac: &str| ScanHost { ip: Ipv4Addr::new(10, 0, 0, last), name: String::new(), mac: mac.into(), rtt_ms: None, ports: vec![] };
    let before = vec![h(1, "AA"), h(2, "BB"), h(3, "CC")];
    let now = vec![h(1, "AA"), h(3, "DD"), h(4, "EE")];
    let d: Vec<(u8, Change)> = diff(&now, &before).iter().map(|(x, c, _)| (x.ip.octets()[3], *c)).collect();
    assert_eq!(d, vec![(1, Change::Same), (2, Change::Gone), (3, Change::Changed), (4, Change::New)]);
}

#[test]
fn subnet_calculator() {
    let s = crate::admintools::subnet("192.168.10.77/26").unwrap();
    assert_eq!(s.network.to_string(), "192.168.10.64");
    assert_eq!(s.broadcast.to_string(), "192.168.10.127");
    assert_eq!(s.first.to_string(), "192.168.10.65");
    assert_eq!(s.last.to_string(), "192.168.10.126");
    assert_eq!(s.hosts, 62);
    assert_eq!(s.mask.to_string(), "255.255.255.192");
    assert_eq!(crate::admintools::subnet("10.1.2.3 255.255.0.0").unwrap().prefix, 16);
    assert!(crate::admintools::subnet("10.1.2.3/255.0.255.0").is_err());
}

#[test]
fn totp_rfc6238_and_passwords() {
    // RFC 6238 test secret "12345678901234567890" (SHA-1)
    let key = crate::admintools::base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
    assert_eq!(key, b"12345678901234567890");
    assert_eq!(crate::admintools::totp(&key, 8, 30, 59).0, "94287082");
    assert_eq!(crate::admintools::totp(&key, 8, 30, 1111111109).0, "07081804");
    let (k, d, p) = crate::admintools::parse_otp("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30").unwrap();
    assert_eq!((k.len(), d, p), (20, 8, 30));
    let o = crate::admintools::PwOptions { length: 24, ..Default::default() };
    let pw = crate::admintools::generate_password(&o);
    assert_eq!(pw.chars().count(), 24);
    assert!(pw.chars().any(|c| c.is_ascii_digit()) && pw.chars().any(|c| c.is_ascii_uppercase()));
    assert!(!pw.contains(['0', 'O', 'l', '1', 'I']));
    assert_ne!(pw, crate::admintools::generate_password(&o));
}

#[test]
fn drag_and_drop_in_tree() {
    let mut s = temp_store("dnd");
    let web = s.data.entries.iter().find(|e| e.name.starts_with("web01 – L")).unwrap().id;
    let fs = s.data.entries.iter().find(|e| e.name.starts_with("FS01 – D")).unwrap().id;
    let dc = s.data.entries.iter().find(|e| e.name.starts_with("DC01")).unwrap().id;
    // reorder: web01 before DC01 in the same folder
    assert!(s.drop_move(web, Some(dc), false, false));
    assert_eq!(s.children(Some(1))[0], web);
    // after FS01
    assert!(s.drop_move(web, Some(fs), false, true));
    let kids = s.children(Some(1));
    assert_eq!(kids[kids.iter().position(|&k| k == fs).unwrap() + 1], web);
    // into another folder (Netzwerk, id 7)
    assert!(s.drop_move(web, Some(7), true, false));
    assert_eq!(s.get(web).unwrap().parent, Some(7));
    // a folder can't go into itself or its child
    assert!(!s.drop_move(1, Some(1), true, false));
    assert!(!s.drop_move(1, Some(dc), false, false) || s.get(1).unwrap().parent.is_none());
    assert!(!s.drop_move(1, Some(2), true, false));
    // empty space: top level, last
    assert!(s.drop_move(web, None, false, true));
    assert_eq!(s.get(web).unwrap().parent, None);
    assert_eq!(*s.children(None).last().unwrap(), web);
}

#[test]
fn scan_protocol_choices() {
    use crate::model::Protocol;
    let c = crate::netscan::protocol_candidates(&[22, 80, 443, 3389]);
    assert_eq!(c, vec![Protocol::Rdp, Protocol::Ssh, Protocol::Sftp, Protocol::Https, Protocol::Http]);
    assert!(crate::netscan::protocol_candidates(&[445]).is_empty());
}

#[test]
fn export_and_import_with_password_modes() {
    use crate::sharing::{export, merge, read, PwMode, ReadError};
    let mut s = temp_store("export");
    let web = s.data.entries.iter().find(|e| e.name.starts_with("web01 – L")).unwrap().id;
    let i = s.index_of(web).unwrap();
    s.data.entries[i].password = "geheim!".into();
    let dir = std::env::temp_dir().join(format!("admincraft-export-{}", std::process::id()));
    let f = |n: &str| dir.join(n);
    // without passwords: nothing secret in the file
    export(&s, Some(1), PwMode::Without, "", &f("none.json")).unwrap();
    let t = std::fs::read_to_string(f("none.json")).unwrap();
    assert!(!t.contains("geheim!") && t.contains("web01"));
    let (e, p) = read(&t, "").unwrap();
    assert!(p.is_empty() && e.iter().any(|x| x.id == web));
    assert!(e.iter().all(|x| x.id == 1 || s.is_descendant(x.id, 1)), "only the folder and its content");
    // plain: password readable
    export(&s, None, PwMode::Plain, "", &f("plain.json")).unwrap();
    let t = std::fs::read_to_string(f("plain.json")).unwrap();
    assert!(t.contains("geheim!"));
    // encrypted: nothing readable, needs the export password
    export(&s, None, PwMode::Encrypted, "Export-PW", &f("enc.json")).unwrap();
    let t = std::fs::read_to_string(f("enc.json")).unwrap();
    assert!(!t.contains("geheim!") && !t.contains("web01"));
    assert_eq!(read(&t, "").unwrap_err(), ReadError::NeedPassword);
    assert_eq!(read(&t, "falsch").unwrap_err(), ReadError::WrongPassword);
    let (entries, pws) = read(&t, "Export-PW").unwrap();
    // merge into another list: new ids, jump host follows, password restored
    let mut other = temp_store("import");
    let before = other.data.entries.len();
    let (fid, n) = merge(&mut other, entries.clone(), pws, "Import Test");
    assert_eq!(other.data.entries.len(), before + entries.len() + 1);
    assert!(n > 10);
    let w = other.data.entries.iter().find(|e| e.name.starts_with("web01 – L") && other.is_descendant(e.id, fid)).unwrap();
    assert_eq!(w.password, "geheim!");
    let db = other.data.entries.iter().find(|e| e.name.starts_with("db01") && other.is_descendant(e.id, fid)).unwrap();
    let jump = other.get(db.jump_host.unwrap()).unwrap();
    assert!(jump.name.starts_with("bastion") && other.is_descendant(jump.id, fid));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn whole_list_encrypted_with_master_password() {
    let mut s = temp_store("sealed");
    s.data.settings.encrypt_file = true;
    s.set_master("Team-Master");
    let text = std::fs::read_to_string(&s.path).unwrap();
    assert!(text.contains("admincraft-encrypted"));
    assert!(!text.contains("web01") && !text.contains("10.0.0.30"), "names and hosts must be encrypted too");
    // read it like a fresh start: locked until the master password is given
    let reopened = std::fs::read_to_string(&s.path).unwrap();
    assert!(reopened.contains("payload"));
    let mut s3 = temp_store("sealed-read");
    std::fs::write(&s3.path, &reopened).unwrap();
    s3.vault = None;
    assert!(s3.reload_from_disk_for_test());
    assert!(s3.locked());
    assert!(!s3.unlock("falsch"));
    assert!(s3.unlock("Team-Master"));
    assert!(s3.data.entries.iter().any(|e| e.host == "10.0.0.30"));
    assert!(s3.data.settings.encrypt_file);
    let _ = std::fs::remove_file(&s.path);
}

#[test]
fn credential_sources() {
    let mut s = temp_store("creds");
    let id = s.data.entries.iter().find(|e| e.name.starts_with("web01 – L")).unwrap().id;
    let i = s.index_of(id).unwrap();
    s.data.entries[i].password = "geheim".into();
    assert_eq!(s.credential_info(id).password, "geheim");
    s.data.entries[i].cred_source = crate::model::CredSource::KeePass;
    let info = s.credential_info(id);
    assert_eq!(info.keepass, Some(crate::model::KeePassRef::Host("10.0.0.30".into())));
    s.data.entries[i].cred_source = crate::model::CredSource::Ask;
    assert!(s.credential_info(id).ask);
}

#[test]
fn shell_prompt_detection() {
    use crate::terminal::is_shell_prompt;
    assert!(is_shell_prompt("jump@bastion:~$ "));
    assert!(is_shell_prompt("[root@db01 ~]#"));
    assert!(!is_shell_prompt("root@10.0.0.40's password:"));
    assert!(!is_shell_prompt("Are you sure you want to continue connecting (yes/no/[fingerprint])?"));
    assert!(!is_shell_prompt(""));
}

#[test]
fn ls_lines() {
    use crate::transfer::parse_ls_line;
    let d = parse_ls_line("drwxr-xr-x    2 root     root         4096 Jan  1 12:00 my folder").unwrap();
    assert!(d.is_dir);
    assert_eq!(d.name, "my folder");
    let f = parse_ls_line("-rw-r--r--    1 demo     users      379 Sep 19  2023 readme.txt").unwrap();
    assert!(!f.is_dir);
    assert_eq!(f.size, 379);
    let l = parse_ls_line("lrwxrwxrwx 1 root root 7 Jan 1 2020 bin -> usr/bin").unwrap();
    assert!(l.is_link);
    assert_eq!(l.name, "bin");
    assert!(parse_ls_line("drwxr-xr-x 2 root root 4096 Jan 1 12:00 .").is_none());
    assert!(parse_ls_line("sftp> ls -la").is_none());
    assert_eq!(crate::transfer::parent("/var/www"), "/var");
    assert_eq!(crate::transfer::parent("/var"), "/");
    assert_eq!(crate::transfer::join("/", "etc"), "/etc");
}

#[test]
fn ssh_config_import() {
    let cfg = "Host *\n  ServerAliveInterval 30\n\nHost bastion\n  HostName 203.0.113.10\n  User jump\n\nHost db\n  HostName 10.0.0.40\n  User root\n  Port 2222\n  IdentityFile ~/.ssh/id_ed25519\n  ProxyJump bastion\n";
    let v = crate::import::import_ssh_config(cfg, 50, Some(49));
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].name, "bastion");
    assert_eq!(v[1].host, "10.0.0.40");
    assert_eq!(v[1].port, 2222);
    assert_eq!(v[1].jump_host, Some(50));
    assert_eq!(v[1].ssh_key, "~/.ssh/id_ed25519");
}

#[test]
fn keepass_database_read() {
    use keepass::db::fields;
    let mut db = keepass::Database::new();
    {
        let mut root = db.root_mut();
        let mut g = root.add_group();
        g.name = "Server".into();
        let mut e = g.add_entry();
        e.set_unprotected(fields::TITLE, "web01");
        e.set_unprotected(fields::USERNAME, "root");
        e.set_protected(fields::PASSWORD, "pw-web");
        e.set_unprotected(fields::URL, "ssh://10.0.0.30");
    }
    let path = std::env::temp_dir().join(format!("admincraft-test-{}.kdbx", std::process::id()));
    {
        let mut f = std::fs::File::create(&path).unwrap();
        db.save(&mut f, keepass::DatabaseKey::new().with_password("kp-master")).unwrap();
    }
    let mut v = crate::keepass_vault::KeePassVault::default();
    assert!(v.open(path.to_str().unwrap(), "falsch", "").is_err());
    assert_eq!(v.open(path.to_str().unwrap(), "kp-master", "").unwrap(), 1);
    use crate::model::KeePassRef;
    let by_path = v.find(&KeePassRef::Entry("Server/web01".into())).unwrap();
    assert_eq!(by_path.password, "pw-web");
    assert_eq!(v.find(&KeePassRef::Entry("web01".into())).unwrap().user, "root");
    assert_eq!(v.find(&KeePassRef::Host("10.0.0.30".into())).unwrap().title, "web01");
    assert!(v.find(&KeePassRef::Host("10.9.9.9".into())).is_none());
    let _ = std::fs::remove_file(path);
}

#[test]
fn keepass_url_host() {
    assert_eq!(crate::keepass_vault::url_host("https://admin@10.0.0.5:8443/x"), "10.0.0.5");
    assert_eq!(crate::keepass_vault::url_host("ssh://web01.firma.local"), "web01.firma.local");
    assert_eq!(crate::keepass_vault::url_host("fw01"), "fw01");
}

#[test]
fn ports_and_mac() {
    assert_eq!(parse_ports("22, 80,443").unwrap(), vec![22, 80, 443]);
    assert_eq!(parse_ports("20-22").unwrap(), vec![20, 21, 22]);
    assert!(parse_ports("0").is_err());
    assert!(parse_ports("abc").is_err());
    assert_eq!(parse_mac("00-11-22-AA-bb-cc").unwrap(), [0, 0x11, 0x22, 0xAA, 0xBB, 0xCC]);
    assert!(parse_mac("00:11").is_err());
}

#[test]
fn import_mremoteng_tree() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="" ConfVersion="2.6">
  <Node Name="Server" Type="Container" Expanded="true" Username="admin" Domain="FIRMA">
    <Node Name="dc01" Type="Connection" Protocol="RDP" Hostname="10.0.0.10" Port="3389" Username="" InheritUsername="true" />
    <Node Name="linux" Type="Connection" Protocol="SSH2" Hostname="10.0.0.30" Port="2222" Username="root" />
  </Node>
  <Node Name="vnc" Type="Connection" Protocol="VNC" Hostname="pc1" Port="5900" />
</mrng:Connections>"#;
    let imp = crate::import::import_mremoteng(xml, "", 100, Some(99)).unwrap();
    assert_eq!(imp.entries.len(), 4);
    let folder = &imp.entries[0];
    assert!(folder.folder);
    assert_eq!(folder.parent, Some(99));
    let dc = &imp.entries[1];
    assert_eq!(dc.parent, Some(folder.id));
    assert_eq!(dc.protocol, Protocol::Rdp);
    assert!(dc.inherit_credentials);
    let linux = &imp.entries[2];
    assert_eq!(linux.protocol, Protocol::Ssh);
    assert_eq!(linux.port, 2222);
    let vnc = &imp.entries[3];
    assert_eq!(vnc.parent, Some(99));
    assert_eq!(vnc.protocol, Protocol::Vnc);
}

#[test]
fn split_words_quotes() {
    assert_eq!(
        crate::launch::split_words(r#"xfreerdp "/v:my host" /u:{user}"#),
        vec!["xfreerdp", "/v:my host", "/u:{user}"]
    );
}
