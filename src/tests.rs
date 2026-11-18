//! Quick self-tests: `cargo test`.

use crate::model::{Protocol, Store, Vault, new_salt, sample_data};
use crate::tools::{parse_mac, parse_ports};

fn temp_store(name: &str) -> Store {
    let dir = std::env::temp_dir().join(format!("admincraft-test-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let mut s = Store::open(true);
    s.read_only = false;
    s.path = dir.join("connections.json");
    s.data = sample_data();
    s.data.salt = String::new();
    s.vault = Vault::derive("", &s.salt()).ok();
    s
}

#[test]
fn vault_roundtrip() {
    let v = Vault::derive("secret", &new_salt()).unwrap();
    let c = v.encrypt("P@ssw0rd äöü").unwrap();
    assert_eq!(v.decrypt(&c).as_deref(), Some("P@ssw0rd äöü"));
    let other = Vault::derive("falsch", &new_salt()).unwrap();
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
    assert_eq!(d, "CORP");
    let web = s.data.entries.iter().find(|e| e.name.starts_with("web01")).unwrap();
    let (u, d, _) = s.credentials(web.id);
    assert_eq!(u, "root");
    assert_eq!(d, "");
}

#[test]
fn remove_deletes_children() {
    let mut s = temp_store("remove");
    let before = s.data.entries.len();
    s.remove(1); // "Data center" with 8 connections
    assert_eq!(s.data.entries.len(), before - 9);
}

#[test]
fn jump_chain_and_chain_command() {
    let s = temp_store("jump");
    let db = s.data.entries.iter().find(|e| e.name.starts_with("db01")).unwrap();
    let chain = s.jump_chain(db.id);
    assert_eq!(chain.len(), 1);
    assert_eq!(s.get(chain[0]).unwrap().name, "bastion – jump host");
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
    // English is the key; without a table the text comes back with the values filled in
    assert_eq!(crate::i18n::tf("{0} connections · {1} folders", &[&3, &"{1}"]), "3 connections · {1} folders");
    let de = include_str!("../lang/de.lang");
    assert!(de.contains("@code = de"));
    // every line with more than one " = " must use " => " (otherwise the key is cut)
    for l in de.lines().filter(|l| !l.starts_with('#')) {
        assert!(l.matches(" = ").count() <= 1 || l.contains(" => "), "ambiguous line: {l}");
    }
    let table = crate::i18n::german_table();
    assert!(table.len() > 600);
    assert_eq!(table.get("{0} connections · {1} folders").map(String::as_str), Some("{0} Verbindungen · {1} Ordner"));
    // every built-in language: right code, unambiguous lines, the same texts as German,
    // and every placeholder of the English text kept
    for (code, text) in crate::i18n::builtin_files() {
        assert!(text.contains(&format!("@code = {code}")), "{code}: @code");
        for l in text.lines().filter(|l| !l.starts_with('#')) {
            assert!(l.matches(" = ").count() <= 1 || l.contains(" => "), "{code}: ambiguous line: {l}");
        }
        let t = crate::i18n::table_of(text);
        for key in table.keys() {
            assert!(t.contains_key(key), "{code}: missing translation of: {key}");
        }
        for (en, tr) in &t {
            for ph in ["{0}", "{1}", "{2}", "{3}", "{host}", "{user}", "{name}", "\n"] {
                assert_eq!(en.matches(ph).count(), tr.matches(ph).count(), "{code}: placeholder {ph:?} in: {en}");
            }
        }
    }
}

#[test]
fn user_guide_in_every_language() {
    use crate::help::{Block, TOPIC_COUNT, parse, sections};
    for (code, text) in crate::help::builtin() {
        let blocks = parse(text);
        assert!(matches!(blocks.first(), Some(Block::Title(_))), "{code}: title first");
        assert_eq!(sections(&blocks).len(), TOPIC_COUNT, "{code}: same chapters as the English guide");
        assert!(blocks.iter().any(|b| matches!(b, Block::Table(r) if r.len() > 5)), "{code}: tables");
        assert!(blocks.iter().any(|b| matches!(b, Block::Code(_))), "{code}: code blocks");
    }
    let b = parse("# T\n\nOne\nline.\n\n- a\n  b\n1. x\n> tip\n| A | B |\n|---|---|\n| 1 | 2 |\n```\ncode\n```\n![x](y.png)\n");
    assert_eq!(
        b,
        vec![
            Block::Title("T".into()),
            Block::Para("One line.".into()),
            Block::Bullet("a b".into()),
            Block::Numbered("1".into(), "x".into()),
            Block::Tip("tip".into()),
            Block::Table(vec![vec!["A".into(), "B".into()], vec!["1".into(), "2".into()]]),
            Block::Code("code".into()),
        ]
    );
}

#[test]
fn netscan_ranges_and_diff() {
    use crate::netscan::{Change, ScanHost, diff, parse_targets};
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
    let pw = crate::admintools::generate_password(&o).unwrap();
    assert_eq!(pw.chars().count(), 24);
    assert!(pw.chars().any(|c| c.is_ascii_digit()) && pw.chars().any(|c| c.is_ascii_uppercase()));
    assert!(!pw.contains(['0', 'O', 'l', '1', 'I']));
    assert_ne!(pw, crate::admintools::generate_password(&o).unwrap());
}

#[test]
fn no_password_without_random_numbers() {
    use crate::admintools::{PwOptions, generate_password_with};
    let o = PwOptions::default();
    // a failing random source used to be ignored: the password was then built from zero bytes
    let failing = generate_password_with(&o, &mut |_| Err("no entropy".into()));
    assert_eq!(failing, Err("no entropy".into()));
    // a source that only ever answers with zeros gives an error too, not "AAAA…" and not a hang
    assert!(
        generate_password_with(&o, &mut |buf| {
            buf.fill(0);
            Ok(())
        })
        .is_err()
    );
    // a counting source works, and every kind of character appears
    let mut n = 0u8;
    let pw = generate_password_with(&o, &mut |buf| {
        for b in buf.iter_mut() {
            n = n.wrapping_mul(31).wrapping_add(17);
            *b = n;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(pw.chars().count(), o.length);
}

#[test]
fn drag_and_drop_in_tree() {
    let mut s = temp_store("dnd");
    let web = s.data.entries.iter().find(|e| e.name.starts_with("web01 – L")).unwrap().id;
    let fs = s.data.entries.iter().find(|e| e.name.starts_with("FS01 – f")).unwrap().id;
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
    use crate::sharing::{PwMode, ReadError, export, merge, read};
    let mut s = temp_store("export");
    let web = s.data.entries.iter().find(|e| e.name.starts_with("web01 – L")).unwrap().id;
    let i = s.index_of(web).unwrap();
    s.data.entries[i].password = "secret!".into();
    let dir = std::env::temp_dir().join(format!("admincraft-export-{}", std::process::id()));
    let f = |n: &str| dir.join(n);
    // without passwords: nothing secret in the file
    export(&s, Some(1), PwMode::Without, "", &f("none.json")).unwrap();
    let t = std::fs::read_to_string(f("none.json")).unwrap();
    assert!(!t.contains("secret!") && t.contains("web01"));
    let (e, p) = read(&t, "").unwrap();
    assert!(p.is_empty() && e.iter().any(|x| x.id == web));
    assert!(e.iter().all(|x| x.id == 1 || s.is_descendant(x.id, 1)), "only the folder and its content");
    // plain: password readable
    export(&s, None, PwMode::Plain, "", &f("plain.json")).unwrap();
    let t = std::fs::read_to_string(f("plain.json")).unwrap();
    assert!(t.contains("secret!"));
    // encrypted: nothing readable, needs the export password
    export(&s, None, PwMode::Encrypted, "Export-PW", &f("enc.json")).unwrap();
    let t = std::fs::read_to_string(f("enc.json")).unwrap();
    assert!(!t.contains("secret!") && !t.contains("web01"));
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
    assert_eq!(w.password, "secret!");
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
fn mcp_server_protocol() {
    let mut out: Vec<u8> = Vec::new();
    crate::agent::handle(
        "\u{feff}{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}",
        &mut out,
    );
    crate::agent::handle("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", &mut out);
    crate::agent::handle("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}", &mut out);
    crate::agent::handle(
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"subnet\",\"arguments\":{\"cidr\":\"10.1.2.3/24\"}}}",
        &mut out,
    );
    crate::agent::handle("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"nope\"}", &mut out);
    let lines: Vec<serde_json::Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 4, "the notification gets no answer");
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "admincraft");
    assert!(lines[1]["result"]["tools"].as_array().unwrap().len() >= 7);
    let text = lines[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("10.1.2.255") && lines[2]["result"]["isError"] == false);
    assert_eq!(lines[3]["error"]["code"], -32601);
    // never a password anywhere in the tool descriptions' promises
    assert!(lines[1].to_string().contains("Never includes passwords"));
}

#[test]
fn credential_sources() {
    let mut s = temp_store("creds");
    let id = s.data.entries.iter().find(|e| e.name.starts_with("web01 – L")).unwrap().id;
    let i = s.index_of(id).unwrap();
    s.data.entries[i].password = "secret".into();
    assert_eq!(s.credential_info(id).password, "secret");
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
    assert_eq!(crate::launch::split_words(r#"xfreerdp "/v:my host" /u:{user}"#), vec!["xfreerdp", "/v:my host", "/u:{user}"]);
}

#[test]
fn update_versions_compare() {
    use crate::update::{newest, parse_version};
    let v = |s: &str| parse_version(s).unwrap();
    assert!(v("0.1.0-alpha.2") > v("0.1.0-alpha.1"));
    assert!(v("0.1.0-alpha.10") > v("0.1.0-alpha.9"));
    assert!(v("0.1.0-beta.1") > v("0.1.0-alpha.9"));
    assert!(v("0.1.0") > v("0.1.0-rc.3"));
    assert!(v("v0.2.0") > v("0.1.9"));
    assert_eq!(v("1.2"), v("1.2.0"));
    assert!(parse_version("next").is_none());
    let json = r#"[
        {"tag_name":"v0.1.0-alpha.2","name":"AdminCraft v0.1.0-alpha.2","prerelease":true,"draft":false,"html_url":"u2","published_at":"2026-11-13T08:32:58Z"},
        {"tag_name":"v0.3.0","name":"draft","prerelease":false,"draft":true,"html_url":"d"},
        {"tag_name":"v0.1.0-alpha.1","name":"AdminCraft v0.1.0-alpha.1","prerelease":true,"draft":false,"html_url":"u1"}
    ]"#;
    let best = newest(json, true).unwrap().unwrap();
    assert_eq!((best.url.as_str(), best.published.as_str()), ("u2", "2026-11-13"));
    assert!(newest(json, false).unwrap().is_none(), "only test versions and a draft");
}

#[test]
fn keepass_as_connection_list() {
    use crate::kdbx::{self, Key};
    use keepass::db::fields;
    let path = std::env::temp_dir().join(format!("admincraft-kdbx-list-{}.kdbx", std::process::id()));
    let ps = path.to_str().unwrap().to_string();
    let key = Key { password: "kp-test".into(), keyfile: String::new() };
    {
        let db = keepass::Database::new();
        let mut f = std::fs::File::create(&path).unwrap();
        db.save(&mut f, keepass::DatabaseKey::new().with_password("kp-test")).unwrap();
    }
    let mut s = temp_store("kdbxlist");
    let web = s.data.entries.iter().position(|e| e.name.starts_with("web01 – L")).unwrap();
    s.data.entries[web].password = "secret!".into();
    let count = s.data.entries.len();
    s.data.settings.keepass_path = ps.clone();
    assert!(s.use_keepass(key.clone()).unwrap().contains(&count.to_string()));
    assert!(s.kdbx_mode());
    // the JSON file keeps the settings only
    let json = std::fs::read_to_string(&s.path).unwrap();
    assert!(!json.contains("10.0.0.30") && json.contains("keepass_db"));
    // everything is in KeePass: names, folders, passwords, URLs
    let back = kdbx::load(&ps, &key).unwrap();
    assert_eq!(back.len(), count);
    let w = back.iter().find(|e| e.name.starts_with("web01 – L")).unwrap();
    assert_eq!((w.password.as_str(), w.host.as_str(), w.protocol), ("secret!", "10.0.0.30", Protocol::Ssh));
    let dc = back.iter().find(|e| e.name.starts_with("DC01")).unwrap();
    let folder = back.iter().find(|e| Some(e.id) == dc.parent).unwrap();
    assert!(folder.folder && folder.domain == "CORP", "folder settings survive");
    // edited in KeePass: AdminCraft reloads it; an entry made there becomes a connection
    {
        let mut f = std::fs::File::open(&path).unwrap();
        let mut db = keepass::Database::open(&mut f, keepass::DatabaseKey::new().with_password("kp-test")).unwrap();
        let id = db.root().groups().find(|g| g.name == kdbx::GROUP).unwrap().id();
        let eid = {
            let g = db.group(id).unwrap();
            let x = g
                .groups()
                .flat_map(|sg| sg.entries().map(|e| (e.id(), e.get_title().unwrap_or("").to_string())).collect::<Vec<_>>())
                .find(|(_, t)| t.starts_with("web01 – L"))
                .unwrap();
            x.0
        };
        db.entry_mut(eid).unwrap().set_unprotected(fields::TITLE, "web01 – renamed in KeePass");
        let mut g = db.group_mut(id).unwrap();
        let mut ne = g.add_entry();
        ne.set_unprotected(fields::TITLE, "made in KeePass");
        ne.set_unprotected(fields::URL, "rdp://10.1.1.1");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut f = std::fs::File::create(&path).unwrap();
        db.save(&mut f, keepass::DatabaseKey::new().with_password("kp-test")).unwrap();
    }
    assert!(s.reload_if_changed());
    assert!(s.data.entries.iter().any(|e| e.name == "web01 – renamed in KeePass"));
    let made = s.data.entries.iter().find(|e| e.name == "made in KeePass").unwrap();
    assert_eq!((made.protocol, made.host.as_str(), made.port), (Protocol::Rdp, "10.1.1.1", 3389));
    // deleted in AdminCraft: gone from KeePass too
    let id = made.id;
    s.remove(id);
    s.save();
    assert_eq!(kdbx::load(&ps, &key).unwrap().len(), count);
    // locked until the KeePass password is entered
    let mut fresh = temp_store("kdbxlist2");
    fresh.data.settings = s.data.settings.clone();
    assert!(!fresh.unlock_keepass("wrong") && fresh.unlock_keepass("kp-test"));
    assert_eq!(fresh.data.entries.len(), count);
    // a single password into KeePass
    let p = kdbx::store_password(&ps, &key, "printer", "admin", "pw1", "http://10.0.1.50/").unwrap();
    assert_eq!(p, "AdminCraft/printer");
    let _ = std::fs::remove_file(path);
}

#[test]
fn keepass_urls() {
    use crate::kdbx::{parse_url, url_of};
    assert_eq!(parse_url("ssh://root@10.0.0.30:2222"), Some((Protocol::Ssh, "10.0.0.30".into(), 2222)));
    assert_eq!(parse_url("https://fw.corp.local/login"), Some((Protocol::Https, "fw.corp.local".into(), 443)));
    assert_eq!(parse_url("rdp://[fe80::1]:3390"), Some((Protocol::Rdp, "fe80::1".into(), 3390)));
    assert_eq!(parse_url("10.0.0.5"), Some((Protocol::Ssh, "10.0.0.5".into(), 22)));
    assert_eq!(parse_url(""), None);
    let e = crate::model::Entry { protocol: Protocol::Rdp, host: "dc01".into(), port: 3389, ..Default::default() };
    assert_eq!(url_of(&e), "rdp://dc01:3389");
}

#[test]
fn session_recording_and_playback() {
    use crate::playback::{Ev, compress_pauses, parse_cast};
    let path = std::env::temp_dir().join(format!("admincraft-rec-{}.cast", std::process::id()));
    {
        let mut r = crate::terminal::Recorder::create(&path, 100, 30, "web01").unwrap();
        r.output("héllo ".as_bytes());
        // a character cut between two chunks stays whole
        let bytes = "wörld\r\n".as_bytes();
        r.output(&bytes[..2]);
        r.output(&bytes[2..]);
        r.resize(120, 40);
    }
    let cast = parse_cast(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!((cast.cols, cast.rows, cast.title.as_str()), (100, 30, "web01"));
    let text: String = cast.events.iter().filter_map(|(_, e)| if let Ev::Out(s) = e { Some(s.as_str()) } else { None }).collect();
    assert_eq!(text, "héllo wörld\r\n");
    assert!(cast.events.iter().any(|(_, e)| *e == Ev::Resize(120, 40)));
    let ev = vec![(0.5, Ev::Out("a".into())), (60.5, Ev::Out("b".into())), (61.0, Ev::Out("c".into()))];
    let c: Vec<f64> = compress_pauses(&ev, 2.0).iter().map(|x| x.0).collect();
    assert_eq!(c, vec![0.5, 2.5, 3.0]);
    assert!(parse_cast("{\"version\":1}").is_err());
    let _ = std::fs::remove_file(path);
}

#[test]
fn guide_table_columns_fit() {
    let rows = vec![
        vec!["Protocol".to_string(), "Opens as".to_string(), "Needs".to_string()],
        vec!["SSH".into(), "terminal tab (or PuTTY, or its own window)".into(), "OpenSSH (built into Windows 10/11, macOS, Linux) or PuTTY".into()],
    ];
    let w = crate::help::column_widths(&rows, 800.0);
    assert_eq!(w.len(), 3);
    assert!((w.iter().sum::<f32>() - 800.0).abs() < 1.0);
    assert!(w[0] < w[1] && w[1] < w[2], "the short column stays narrow: {w:?}");
    assert!(w.iter().all(|x| *x >= 100.0), "no column too narrow to read: {w:?}");
}

#[test]
fn snmp_ber_encoding() {
    use crate::nettools::{PDU_GET, SnmpValue, decode_oid, decode_response, encode_get, encode_oid, oid_name};
    let req = encode_get("public", 1, PDU_GET, &["1.3.6.1.2.1.1.1.0"]).unwrap();
    let want = [
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01,
        0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];
    assert_eq!(req, want);
    let big = "1.3.6.1.4.1.311.21.20";
    assert_eq!(decode_oid(&encode_oid(big).unwrap()).unwrap(), big);
    assert!(encode_oid("1.x.3").is_err());
    // a hand-made GetResponse
    fn tlv(tag: u8, c: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if c.len() < 128 {
            v.push(c.len() as u8);
        } else {
            v.extend([0x82, (c.len() >> 8) as u8, c.len() as u8]);
        }
        v.extend_from_slice(c);
        v
    }
    let vb = |oid: &str, tag: u8, val: &[u8]| {
        let mut x = tlv(0x06, &encode_oid(oid).unwrap());
        x.extend(tlv(tag, val));
        tlv(0x30, &x)
    };
    let mut binds = Vec::new();
    binds.extend(vb("1.3.6.1.2.1.1.5.0", 0x04, b"router1"));
    binds.extend(vb("1.3.6.1.2.1.1.3.0", 0x43, &[0x05, 0x7e, 0x40])); // 360000 ticks = 1 h
    binds.extend(vb("1.3.6.1.2.1.2.2.1.8.3", 0x02, &[0xfb])); // -5
    binds.extend(vb("1.3.6.1.2.1.31.1.1.1.6.3", 0x46, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]));
    binds.extend(vb("1.3.6.1.2.1.1.2.0", 0x06, &encode_oid("1.3.6.1.4.1.9.1.1").unwrap()));
    binds.extend(vb("1.3.6.1.2.1.1.9.0", 0x80, &[]));
    let mut pdu = tlv(0x02, &[0x2a]);
    pdu.extend(tlv(0x02, &[0]));
    pdu.extend(tlv(0x02, &[0]));
    pdu.extend(tlv(0x30, &binds));
    let mut msg = tlv(0x02, &[1]);
    msg.extend(tlv(0x04, b"public"));
    msg.extend(tlv(0xa2, &pdu));
    let (id, err, rows) = decode_response(&tlv(0x30, &msg)).unwrap();
    assert_eq!((id, err, rows.len()), (42, 0, 6));
    assert_eq!(rows[0].1.to_string(), "router1");
    assert_eq!(rows[1].1.to_string(), "0d 01:00:00");
    assert_eq!(rows[2].1, SnmpValue::Int(-5));
    assert_eq!(rows[3].1, SnmpValue::Counter64(1 << 40));
    assert_eq!(rows[4].1, SnmpValue::Oid("1.3.6.1.4.1.9.1.1".into()));
    assert_eq!(rows[5].1, SnmpValue::NoSuchObject);
    assert!(decode_response(&[0x30, 0x05, 0x02]).is_err(), "cut answers are refused, not a panic");
    assert_eq!(oid_name("1.3.6.1.2.1.2.2.1.2.7").as_deref(), Some("ifDescr.7"));
    assert_eq!(SnmpValue::Bytes(vec![0, 0x1a, 0x2b]).to_string(), "00:1a:2b");
}

#[test]
fn whois_and_http_reading() {
    use crate::nettools::{evaluate_security, parse_cookies, parse_referral};
    assert_eq!(parse_referral("% IANA\nrefer:        whois.verisign-grs.com\n\ndomain: COM").as_deref(), Some("whois.verisign-grs.com"));
    assert_eq!(parse_referral("domain: EXAMPLE.COM\nsource: IANA"), None);
    let h = |k: &str, v: &str| (k.to_string(), v.to_string());
    let headers = vec![
        h("strict-transport-security", "max-age=63072000; includeSubDomains"),
        h("x-content-type-options", "nosniff"),
        h("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax"),
        h("set-cookie", "theme=dark"),
    ];
    let sec = evaluate_security(&headers, true);
    let hsts = sec.iter().find(|s| s.name == "Strict-Transport-Security").unwrap();
    assert!(hsts.present);
    assert!(!sec.iter().find(|s| s.name == "Content-Security-Policy").unwrap().present);
    let c = parse_cookies(&headers);
    assert_eq!(c.len(), 2);
    assert!(c[0].secure && c[0].http_only && c[0].same_site == "Lax");
    assert!(!c[1].secure && c[1].name == "theme");
}
#[test]
fn control_words_are_not_translated() {
    // A language file must never change what is started: program names and arguments are plain
    // text in the code. With German active, "open" (a status word) is translated, the command is not.
    for file in [include_str!("launch.rs"), include_str!("transfer.rs"), include_str!("tools.rs"), include_str!("programs.rs")] {
        assert!(!file.contains("Command::new(tr("), "a program name goes through the translation");
        for arg in ["tr(\"-", "tr(\"/", "tr(\"ssh\")", "tr(\"cmdkey\")"] {
            assert!(!file.contains(arg), "a command-line argument goes through the translation: {arg}");
        }
    }
}

#[cfg(windows)]
#[test]
fn rdp_login_through_the_credential_manager() {
    let target = format!("AdminCraftTest/{}", std::process::id());
    assert!(!crate::wincred::exists(&target));
    assert_eq!(crate::wincred::store(&target, "DOMAIN\\user", "pässword"), Ok(false), "new entry");
    assert!(crate::wincred::exists(&target));
    assert_eq!(crate::wincred::store(&target, "DOMAIN\\user", "other"), Ok(true), "was there before");
    assert!(crate::wincred::delete(&target));
    assert!(!crate::wincred::exists(&target));
}

#[test]
fn damaged_export_file_is_an_error_not_a_crash() {
    use crate::sharing::{PwMode, ReadError, export, read};
    // the key derivation refuses a salt shorter than 8 bytes; that used to be a panic
    assert!(Vault::derive("x", b"short").is_err());
    let s = temp_store("export-damaged");
    let dir = std::env::temp_dir().join(format!("admincraft-export-damaged-{}", std::process::id()));
    let file = dir.join("enc.json");
    export(&s, None, PwMode::Encrypted, "Export-PW", &file).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    v["salt"] = "AAAA".into();
    assert!(matches!(read(&v.to_string(), "Export-PW"), Err(ReadError::Other(_))));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn dates_through_chrono() {
    use crate::timefmt::{date, date_time, iso_minutes};
    assert_eq!(date(0), "01.01.1970");
    assert_eq!(date(951_782_400), "29.02.2000", "leap day");
    assert_eq!(date_time(1_798_761_540), "31.12.2026 23:59");
    assert_eq!(iso_minutes(1_798_761_540), "2026-12-31 23:59 UTC");
    assert_eq!(date(i64::MAX), "", "out of range is empty, not a panic");
}

#[test]
fn putty_password_goes_through_a_file() {
    use crate::secretfile::{mentions_pwfile, putty_password, write};
    assert!(mentions_pwfile(b"...\0-pw\0-pwfile\0-i\0..."), "PuTTY 0.77 and newer");
    assert!(!mentions_pwfile(b"...\0-pw\0-i\0..."), "older PuTTY");
    let dir = std::env::temp_dir().join(format!("admincraft-putty-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (new, old) = (dir.join("putty-new.exe"), dir.join("putty-old.exe"));
    std::fs::write(&new, b"MZ..-pw..-pwfile..").unwrap();
    std::fs::write(&old, b"MZ..-pw..").unwrap();
    // a new PuTTY gets the file's name, never the password
    let (args, file) = putty_password(&new, "s3cret pw").unwrap();
    let file = file.expect("a password file");
    assert_eq!(args[0], "-pwfile");
    assert!(!args.iter().any(|a| a.contains("s3cret")));
    assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "s3cret pw");
    let path = file.path().to_path_buf();
    drop(file);
    assert!(!path.exists(), "removed when the program is done");
    // an old PuTTY still works, with the password as before
    let (args, file) = putty_password(&old, "s3cret pw").unwrap();
    assert!(file.is_none());
    assert_eq!(args, vec!["-pw".to_string(), "s3cret pw".to_string()]);
    // no password: nothing at all
    assert!(putty_password(&new, "").unwrap().0.is_empty());
    // files kept for a running program go when it ends
    let kept = write("x").unwrap();
    let kept_path = kept.path().to_path_buf();
    crate::secretfile::keep_while_running(4_000_000_001, vec![kept]);
    assert!(kept_path.exists());
    crate::secretfile::process_ended(4_000_000_001);
    assert!(!kept_path.exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn agents_can_look_at_and_type_into_embedded_windows() {
    // the control channel and the MCP server both offer the picture of a tab
    assert!(crate::control::COMMANDS.iter().any(|(cmd, _)| *cmd == "screenshot"));
    let tools = crate::agent::tool_list();
    assert!(tools.iter().any(|(name, _, _)| *name == "window_screenshot"));
    let typing = tools.iter().find(|(name, _, _)| *name == "window_type").expect("window_type");
    assert!(typing.1.contains("PuTTY"), "the description says where typing works");
    // a window that is not embedded takes no typing and has no class (nothing is sent anywhere)
    let not_embedded = crate::embed::Embedded::new(0, &[]);
    assert!(!not_embedded.type_text("x"));
    assert_eq!(not_embedded.class(), "");
    // outside our own window there is nothing to take a picture of
    assert!(crate::embed::capture_window(0, crate::embed::PxRect { x: 0, y: 0, w: 10, h: 10 }).is_none());
}

#[test]
fn own_browser_for_web_interfaces() {
    use crate::launch::{browser_family, web_args, web_profile_dir};
    use crate::model::{BrowserFamily, WebProfile};
    use std::path::Path;
    let fam = |p: &str| browser_family(Path::new(p), BrowserFamily::Auto);
    assert_eq!(fam(r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"), BrowserFamily::Chromium);
    assert_eq!(fam(r"D:\Portable\LibreWolf\librewolf.exe"), BrowserFamily::Firefox);
    assert_eq!(fam("/usr/bin/firefox"), BrowserFamily::Firefox);
    assert_eq!(fam("vivaldi.exe"), BrowserFamily::Chromium);
    assert_eq!(browser_family(Path::new("mybrowser.exe"), BrowserFamily::Firefox), BrowserFamily::Firefox, "a chosen kind wins");
    let dir = Path::new("profiles").join("chromium-7");
    let c = web_args(BrowserFamily::Chromium, "https://10.0.0.1/", Some(&dir), "--incognito  --lang=de");
    assert_eq!(c[0], "--app=https://10.0.0.1/");
    assert!(c.contains(&format!("--user-data-dir={}", dir.display())));
    assert_eq!(&c[c.len() - 2..], ["--incognito", "--lang=de"]);
    let f = web_args(BrowserFamily::Firefox, "https://10.0.0.1/", Some(&dir), "");
    assert_eq!(f, vec!["-no-remote", "-profile", &dir.display().to_string(), "-new-window", "https://10.0.0.1/"]);
    let normal = web_args(BrowserFamily::Firefox, "http://x/", None, "");
    assert_eq!(normal, vec!["-new-window", "http://x/"], "the normal profile: no own process");
    assert!(web_profile_dir(BrowserFamily::Chromium, WebProfile::Normal, 3).is_none());
    let kept = web_profile_dir(BrowserFamily::Firefox, WebProfile::Kept, 3).unwrap();
    assert!(kept.ends_with(Path::new("browser").join("firefox-3")));
    assert_ne!(kept, web_profile_dir(BrowserFamily::Chromium, WebProfile::Kept, 3).unwrap(), "the two kinds never share a profile");
}

#[test]
fn embedding_finds_windows_of_child_processes() {
    use crate::embed::descendants;
    // launcher 10 starts the browser 11, which starts helpers 12 and 13; 20 is someone else's
    let pairs = [(11, 10), (12, 11), (13, 11), (20, 4), (10, 4)];
    let mut t = descendants(10, &pairs);
    t.sort_unstable();
    assert_eq!(t, vec![10, 11, 12, 13]);
    // a loop in a broken snapshot doesn't hang
    assert_eq!(descendants(1, &[(2, 1), (1, 2)]).len(), 2);
    // never more than 256
    let many: Vec<(u32, u32)> = (2..2000).map(|i| (i, 1)).collect();
    assert_eq!(descendants(1, &many).len(), 256);
}

#[test]
fn embedded_window_that_frees_itself_is_noticed() {
    use crate::embed::{child_style, embedding_broken};
    // a normal Remote Desktop window: visible, title bar, sizing border, buttons
    let framed: isize = 0x10CF_0000;
    let inside = child_style(framed);
    assert!(!embedding_broken(inside, true), "taken in: nothing to repair");
    assert!(embedding_broken(inside, false), "it left our window");
    assert!(embedding_broken(framed, true), "it put its frame back");
    assert!(embedding_broken(inside & !0x4000_0000, true), "it is no child any more");
    // a single border line is no reason to take it in again (that would flicker every frame)
    assert!(!embedding_broken(inside | 0x0080_0000, true));
}

#[test]
fn power_menu_only_where_it_can_work() {
    use crate::extra::{power_possible, windows_power};
    assert!(power_possible(Protocol::Ssh), "sudo reboot over SSH works from every system");
    for p in [Protocol::Rdp, Protocol::Vnc, Protocol::PowerShell] {
        assert_eq!(power_possible(p), cfg!(windows), "shutdown /m only exists on Windows: {p:?}");
    }
    assert!(!power_possible(Protocol::Http));
    if !cfg!(windows) {
        // outside Windows `shutdown` is the local machine's program: refused before it starts
        assert!(windows_power("192.0.2.1", true).is_err());
    }
}

#[test]
fn cmd_c_on_macos_does_not_interrupt() {
    use crate::terminal::{clipboard_key_bytes, key_bytes};
    use eframe::egui::{Key, Modifiers};
    // Windows and Linux: Ctrl+C reaches the terminal as "copy" and stays the interrupt
    assert_eq!(clipboard_key_bytes(0x03, false), Some(0x03));
    assert_eq!(clipboard_key_bytes(0x18, false), Some(0x18));
    // macOS: "copy" is Cmd+C, nothing goes to the program
    assert_eq!(clipboard_key_bytes(0x03, true), None);
    assert_eq!(clipboard_key_bytes(0x18, true), None);
    // the real Ctrl+C on macOS is a key with Ctrl held and still interrupts
    assert_eq!(key_bytes(Key::C, Modifiers::CTRL, false), Some(vec![0x03]));
    assert_eq!(key_bytes(Key::C, Modifiers::MAC_CMD, false), None);
}

#[test]
fn freerdp_2_and_3_get_their_own_options() {
    use crate::launch::{Creds, freerdp_args, freerdp_version, freerdp_version_of};
    use crate::model::Entry;
    // told by the library the program links
    assert_eq!(freerdp_version_of(b"\0libfreerdp-client2.so.2\0libwinpr2.so.2\0"), 2);
    assert_eq!(freerdp_version_of(b"\0libfreerdp-client3.so.3\0"), 3);
    assert_eq!(freerdp_version_of(b"@rpath/libfreerdp-client3.3.dylib"), 3);
    assert_eq!(freerdp_version_of(b"nothing known"), 3, "unknown: the current version");
    // a 3 in the name needs no look into the file
    assert_eq!(freerdp_version(std::path::Path::new("/nonexistent/xfreerdp3")), 3);

    let mut e = Entry { host: " rdp01 ".into(), protocol: Protocol::Rdp, port: 0, ..Default::default() };
    e.rdp.redirect_drives = true;
    let c = Creds { user: "admin".into(), domain: "CORP".into(), password: String::new() };
    let v2 = freerdp_args(&e, &c, 2);
    assert!(v2.contains(&"/cert-tofu".to_string()) && !v2.iter().any(|a| a.starts_with("/cert:")));
    let v3 = freerdp_args(&e, &c, 3);
    assert!(v3.contains(&"/cert:tofu".to_string()) && !v3.contains(&"/cert-tofu".to_string()));
    for args in [&v2, &v3] {
        assert_eq!(args[0], "/v:rdp01", "port 0 means the default port");
        assert!(args.contains(&"+home-drive".to_string()) && !args.iter().any(|a| a.contains('~')));
        assert!(args.contains(&"/u:admin".to_string()) && args.contains(&"/d:CORP".to_string()));
    }
    e.port = 3390;
    assert_eq!(freerdp_args(&e, &c, 3)[0], "/v:rdp01:3390");
}

#[test]
fn remmina_gets_the_default_rdp_port() {
    use crate::launch::{Creds, remmina_rdp_url};
    use crate::model::Entry;
    let mut e = Entry { host: "rdp01".into(), protocol: Protocol::Rdp, port: 0, ..Default::default() };
    assert_eq!(remmina_rdp_url(&e, &Creds::default()), "rdp://rdp01:3389");
    e.port = 3390;
    let c = Creds { user: "admin".into(), ..Default::default() };
    assert_eq!(remmina_rdp_url(&e, &c), "rdp://admin@rdp01:3390");
}

#[cfg(unix)]
#[test]
fn password_files_live_in_a_folder_of_this_user_only() {
    use crate::secretfile::{private_dir, write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let base = std::env::temp_dir().join(format!("admincraft-private-test-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let uid = std::fs::metadata(&base).unwrap().uid();
    // new: made with 0700
    let d = private_dir(&base.join("new"), uid).unwrap();
    assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
    // there already, ours but open for others (an older AdminCraft made it with 0755): closed
    let wide = base.join("wide");
    std::fs::create_dir(&wide).unwrap();
    std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o755)).unwrap();
    private_dir(&wide, uid).unwrap();
    assert_eq!(std::fs::metadata(&wide).unwrap().mode() & 0o777, 0o700);
    // someone else's folder is refused, and so is a link
    assert!(private_dir(&wide, uid.wrapping_add(1)).is_err());
    let link = base.join("link");
    std::os::unix::fs::symlink(&wide, &link).unwrap();
    assert!(private_dir(&link, uid).is_err());
    // the real password folder is one of these
    let f = write("x").unwrap();
    let parent = f.path().parent().unwrap().to_path_buf();
    let md = std::fs::symlink_metadata(&parent).unwrap();
    assert!(md.is_dir() && md.uid() == uid && md.mode() & 0o077 == 0, "{}", parent.display());
    assert_ne!(parent, std::env::temp_dir().join("admincraft"), "not the folder all users share");
    drop(f);
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn macos_terminal_never_sees_the_password() {
    use crate::programs::{macos_do_script, terminal_script};
    use std::path::Path;
    let env = vec![("AC_ASKPASS_PW_0".to_string(), "s3cr'et pw".to_string())];
    let args = vec!["-p".to_string(), "2222".to_string(), "root@db 01".to_string()];
    let script = terminal_script(Path::new("/usr/bin/ssh"), &args, &env);
    // the script file removes itself first, then sets the environment and starts ssh
    let lines: Vec<&str> = script.lines().collect();
    assert_eq!(lines[0], "rm -f -- \"$0\"");
    assert_eq!(lines[1], r#"export AC_ASKPASS_PW_0='s3cr'\''et pw'"#);
    assert_eq!(lines[2], "/usr/bin/ssh -p 2222 'root@db 01'");
    // what Terminal is told to type: only the script's name
    let apple = macos_do_script(Path::new("/private/var/folders/x/admincraft-501/pw-1-ab.txt"));
    assert_eq!(apple, "tell application \"Terminal\" to do script \"/bin/sh /private/var/folders/x/admincraft-501/pw-1-ab.txt\"");
    assert!(!apple.contains("s3cr"));
}

#[test]
fn powershell_goes_over_ssh_where_there_is_no_winrm() {
    use crate::launch::{Creds, powershell_session};
    use crate::model::Entry;
    let mut e = Entry { host: " win01 ".into(), protocol: Protocol::PowerShell, port: 5985, ..Default::default() };
    let c = Creds { user: "admin".into(), domain: "CORP".into(), password: "pw".into() };
    // Windows: WinRM with a credential from the environment
    let (s, env) = powershell_session(&e, &c, false);
    assert!(s.contains("-ComputerName $env:AC_HOST") && s.contains("-Credential $c"));
    assert!(env.contains(&("AC_PW".to_string(), "pw".to_string())));
    // Linux / macOS: SSH remoting; the password is typed at ssh's prompt, it is not in the environment
    let (s, env) = powershell_session(&e, &c, true);
    assert_eq!(s, "Enter-PSSession -HostName $env:AC_HOST -UserName $env:AC_USER");
    assert!(env.contains(&("AC_HOST".to_string(), "win01".to_string())));
    assert!(env.contains(&("AC_USER".to_string(), r"CORP\admin".to_string())));
    assert!(!env.iter().any(|(k, _)| k == "AC_PW"));
    e.port = 2222;
    assert!(powershell_session(&e, &c, true).0.ends_with(" -Port 2222"));
    for p in [0, 22, 5985, 5986] {
        e.port = p;
        assert!(!powershell_session(&e, &c, true).0.contains("-Port"), "port {p}");
    }
}

#[test]
fn scan_names_and_traceroute_outside_windows() {
    use crate::netscan::parse_reverse_name;
    use crate::tools::trace_cmd;
    assert_eq!(parse_reverse_name("10.0.0.5        web01.lan web01\n", false), "web01.lan");
    assert_eq!(parse_reverse_name("", false), "");
    // macOS: dscacheutil, no getent
    assert_eq!(parse_reverse_name("name: router.lan\nip_address: 192.168.1.1\n\n", true), "router.lan");
    assert_eq!(parse_reverse_name("", true), "");
    assert!(parse_reverse_name(&format!("name: {}", "a".repeat(5000)), true).len() <= 253, "bounded");
    assert_eq!(trace_cmd("h", true, false).0, "tracert");
    assert_eq!(trace_cmd("h", false, false), ("traceroute".to_string(), vec!["-n".to_string(), "h".to_string()]));
    assert_eq!(trace_cmd("h", false, true).0, "tracepath", "Linux without traceroute");
}

fn review_hop(host: &str, user: &str, password: &str) -> crate::transfer::Hop {
    crate::transfer::Hop { host: host.into(), user: user.into(), port: 22, password: password.into() }
}

fn review_endpoint(kind: crate::transfer::Kind, target: crate::transfer::Hop) -> crate::transfer::Endpoint {
    crate::transfer::Endpoint {
        kind,
        target,
        key_file: String::new(),
        jumps: Vec::new(),
        tls: false,
        check_cert: true,
        tool: crate::transfer::Tool::Putty,
        progs: crate::transfer::Progs::default(),
    }
}

#[test]
fn askpass_answers_only_the_host_the_prompt_names() {
    use crate::transfer::askpass_answer;
    let hops = vec![review_hop("bastion", "jump", "J"), review_hop("10.0.0.4", "admin", "A"), review_hop("10.0.0.40", "root", "T")];
    // keyboard-interactive prompts name the login in brackets
    assert_eq!(askpass_answer("(jump@bastion) Password: ", &hops), Some("J"));
    assert_eq!(askpass_answer("(root@10.0.0.40) Password:", &hops), Some("T"));
    assert_eq!(askpass_answer("root@10.0.0.40's password: ", &hops), Some("T"));
    // whole host names: 10.0.0.4 is not 10.0.0.40
    assert_eq!(askpass_answer("x@10.0.0.4's password: ", &hops), Some("A"));
    // with jump hosts a prompt naming no known host gets nothing (no guessing)
    assert_eq!(askpass_answer("Password: ", &hops), None);
    assert_eq!(askpass_answer("(root@other) Password: ", &hops), None);
    // a single host keeps the fallback
    let one = vec![review_hop("db", "root", "T")];
    assert_eq!(askpass_answer("Password: ", &one), Some("T"));
    let v6 = vec![review_hop("bastion", "jump", "J"), review_hop("fe80::1", "root", "V")];
    assert_eq!(askpass_answer("root@fe80::1's password: ", &v6), Some("V"));
}

#[test]
fn ftp_download_names_stay_inside_the_folder() {
    use crate::transfer::is_plain_name;
    for ok in ["file.txt", "my file", " lead", "ü.bin", ".hidden"] {
        assert!(is_plain_name(ok), "{ok}");
    }
    for bad in ["", ".", "..", "../x", "..\\x", "C:\\x", "C:x", "/etc/passwd", "a/b", "a\\b", "a\0b", "a\nb", "x:stream"] {
        assert!(!is_plain_name(bad), "{bad:?}");
    }
}

#[test]
fn ftp_download_goes_through_a_part_file() {
    use crate::transfer::write_via_part;
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("admincraft-part-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("data.bin");
    std::fs::write(&file, b"old").unwrap();
    // an aborted download leaves the old file as it was and no part file
    let r = write_via_part(&file, |f| {
        f.write_all(b"half").unwrap();
        Err("connection lost".into())
    });
    assert!(r.is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"old");
    assert!(!dir.join("data.bin.part").exists());
    // a finished one replaces it
    write_via_part(&file, |f| f.write_all(b"new").map_err(|e| e.to_string())).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"new");
    assert!(!dir.join("data.bin.part").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn host_or_user_can_not_become_an_option() {
    use crate::launch::{Creds, check_login, launch};
    use crate::model::{Entry, Settings};
    assert!(check_login("10.0.0.1", "root").is_ok());
    assert!(check_login(" fe80::1 ", "DOMAIN\\John Smith").is_ok());
    assert!(check_login("-oProxyCommand=calc", "root").is_err());
    assert!(check_login("host\r\nusername:s:x", "root").is_err());
    assert!(check_login("a b", "root").is_err());
    assert!(check_login("host", "-oProxyCommand=calc").is_err());
    assert!(check_login("host", "root\nx").is_err());
    let settings = Settings::default();
    let c = Creds { user: "root".into(), ..Default::default() };
    for (protocol, host) in [(Protocol::Ssh, "-oProxyCommand=calc"), (Protocol::Rdp, "h\r\nusername:s:evil"), (Protocol::Telnet, "-l")] {
        let e = Entry { host: host.into(), protocol, ..Default::default() };
        assert!(launch(&e, &c, &settings, &[], (0, 0)).is_err(), "{protocol:?}");
    }
    // file transfer: target and jump hosts
    let mut ep = review_endpoint(crate::transfer::Kind::Sftp, review_hop("db", "root", ""));
    assert!(crate::transfer::check_endpoint(&ep).is_ok());
    ep.jumps.push(review_hop("-oProxyCommand=x", "j", ""));
    assert!(crate::transfer::check_endpoint(&ep).is_err());
}

#[test]
fn sftp_batch_refuses_control_characters() {
    use crate::transfer::{local_q, q};
    assert_eq!(q("/srv/my \"file\"").unwrap(), r#""/srv/my \"file\"""#);
    assert!(q("x\n!rm -rf ~").is_err(), "a line break would start a new sftp command");
    assert!(q("x\ry").is_err());
    assert!(local_q(std::path::Path::new("dir\nput x")).is_err());
}

#[test]
fn putty_proxy_command_escapes_values() {
    use crate::launch::{ProxyPassword, putty_proxy_command};
    use std::path::Path;
    let pc =
        putty_proxy_command(Path::new(r"C:\Users\tom\plink.exe"), 2222, "ad min", ProxyPassword::File(Path::new(r"C:\Temp\pw-1.txt")), "jump", true);
    assert_eq!(pc, r#""C:\\Users\\tom\\plink.exe" -batch -ssh -P 2222 -l "ad min" -pwfile "C:\\Temp\\pw-1.txt" -nc %host:%port "jump""#);
    // an old plink with the password: quotes, % and a trailing backslash survive PuTTY's escapes
    let pc = putty_proxy_command(Path::new("plink"), 22, "", ProxyPassword::Plain("a\"b%c\\"), "jump", true);
    assert!(pc.contains(r#" -pw "a\\"b%%c\\\\" "#), "{pc}");
    // elsewhere /bin/sh runs it: single quotes
    let pc = putty_proxy_command(Path::new("/usr/bin/plink"), 22, "o'neil", ProxyPassword::None, "jump", false);
    assert_eq!(pc, r#"'/usr/bin/plink' -batch -ssh -P 22 -l 'o'\\''neil' -nc %host:%port 'jump'"#);
}

#[test]
fn temporary_browser_profile_in_the_private_folder() {
    use crate::launch::web_profile_dir;
    use crate::model::{BrowserFamily, WebProfile};
    let private = crate::secretfile::private_temp_dir().unwrap();
    let tmp = web_profile_dir(BrowserFamily::Chromium, WebProfile::Temporary, 5).unwrap();
    assert_eq!(tmp, private.join("web-chromium-5"));
}

#[cfg(windows)]
#[test]
fn rdp_login_leaves_an_existing_entry_and_goes_at_exit() {
    use crate::wincred::{clean_up_later, exists, forget_pending, store, user_of};
    let target = format!("AdminCraftTest/keep-{}", std::process::id());
    assert_eq!(store(&target, "first", "a"), Ok(false));
    assert_eq!(store(&target, "second", "b"), Ok(true), "there before: left alone");
    assert_eq!(user_of(&target).as_deref(), Some("first"));
    // AdminCraft closing removes what is still waiting for its removal
    clean_up_later(Some(target.clone()), Vec::new());
    forget_pending();
    assert!(!exists(&target));
}

#[test]
fn scp_through_putty_takes_the_key_and_refuses_jump_hosts() {
    use crate::transfer::{plink_args, pscp_args};
    let mut ep = review_endpoint(crate::transfer::Kind::Scp, review_hop("db", "root", ""));
    ep.key_file = " C:\\keys\\id.ppk ".into();
    let a = plink_args(&ep, Vec::new(), "pwd").unwrap();
    assert!(a.windows(2).any(|w| w == ["-i", "C:\\keys\\id.ppk"]), "{a:?}");
    let a = pscp_args(&ep, Vec::new(), false, "a", "b").unwrap();
    assert!(a.windows(2).any(|w| w == ["-i", "C:\\keys\\id.ppk"]), "{a:?}");
    ep.jumps.push(review_hop("bastion", "j", ""));
    assert!(plink_args(&ep, Vec::new(), "pwd").is_err());
    assert!(pscp_args(&ep, Vec::new(), false, "a", "b").is_err());
}

#[test]
fn transfer_tab_says_when_putty_is_old() {
    use crate::transfer::old_putty_note;
    let dir = std::env::temp_dir().join(format!("admincraft-oldputty-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (old, new) = (dir.join("pscp-old.exe"), dir.join("pscp-new.exe"));
    std::fs::write(&old, b"MZ..-pw..").unwrap();
    std::fs::write(&new, b"MZ..-pw..-pwfile..").unwrap();
    let mut ep = review_endpoint(crate::transfer::Kind::Sftp, review_hop("db", "root", "pw"));
    ep.progs.psftp = Some(old.clone());
    assert!(old_putty_note(&ep).is_some());
    ep.progs.psftp = Some(new.clone());
    assert!(old_putty_note(&ep).is_none());
    ep.kind = crate::transfer::Kind::Scp;
    ep.progs.pscp = Some(new);
    ep.progs.plink = Some(old);
    assert!(old_putty_note(&ep).is_some(), "the listing goes through the old plink");
    ep.target.password.clear();
    assert!(old_putty_note(&ep).is_none(), "no password, nothing on the command line");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn closed_transfer_tab_drops_queued_jobs() {
    use crate::transfer::{Job, next_job};
    use std::sync::atomic::{AtomicBool, Ordering};
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = AtomicBool::new(false);
    tx.send(Job::Mkdir("/a".into())).unwrap();
    tx.send(Job::Mkdir("/b".into())).unwrap();
    assert!(next_job(&rx, &cancel).is_some());
    cancel.store(true, Ordering::SeqCst);
    assert!(next_job(&rx, &cancel).is_none(), "the tab is gone: the rest is not run");
}

#[test]
fn ftp_server_that_says_nothing_times_out() {
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // accepts, then never answers
    let keep = std::thread::spawn(move || {
        if let Ok((socket, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(1));
            drop(socket);
        }
    });
    let mut target = review_hop("127.0.0.1", "u", "p");
    target.port = port;
    let ep = review_endpoint(crate::transfer::Kind::Ftp, target);
    let start = Instant::now();
    let r = crate::transfer::ftp_connect_with(&ep, Duration::from_secs(2), Duration::from_millis(300));
    assert!(r.is_err());
    assert!(start.elapsed() < Duration::from_secs(2), "the read timeout ends the wait");
    let _ = keep.join();
}

#[test]
fn listings_keep_leading_spaces_and_skip_echoed_commands() {
    use crate::transfer::{parse_ls_line, parse_scp_listing, scp_list_command};
    let f = parse_ls_line("-rw-r--r--    1 demo     users      379 Sep 19  2023   two spaces").unwrap();
    assert_eq!(f.name, "  two spaces");
    let f = parse_ls_line("-rw-r--r--+ 1 demo users 5 Jan  1 12:00 acl").unwrap();
    assert_eq!(f.name, "acl");
    assert!(parse_ls_line(r#"sftp> rm "/srv/a b c d e f g h i j""#).is_none());
    assert!(parse_ls_line(r#"psftp> rm "/srv/a b c d e f g h i j""#).is_none());
    assert!(parse_ls_line("total 12").is_none());
    // SCP listing: works without sh-only syntax; the line after the mark is the folder
    let cmd = scp_list_command("/srv/it's here");
    assert_eq!(cmd, r#"cd '/srv/it'\''s here' && echo AdminCraft-folder: && pwd && env LC_ALL=C ls -la"#);
    assert!(!cmd.contains("$(") && !cmd.contains("cd --"));
    assert!(scp_list_command("-x").starts_with("cd './-x' && "));
    assert_eq!(scp_list_command(""), "echo AdminCraft-folder: && pwd && env LC_ALL=C ls -la");
    let (dir, items) = parse_scp_listing("AdminCraft-folder:\n/srv/data\ntotal 8\n-rw-r--r-- 1 u g 5 Jan  1 12:00 a.txt\n");
    assert_eq!(dir.as_deref(), Some("/srv/data"));
    assert_eq!(items.len(), 1);
}

#[test]
fn ipv6_addresses_in_brackets_where_a_colon_follows() {
    use crate::transfer::{bracket_host, ftp_addrs, jump_arg, remote_spec};
    assert_eq!(bracket_host("::1"), "[::1]");
    assert_eq!(bracket_host("[::1]"), "[::1]");
    assert_eq!(bracket_host("db.lan"), "db.lan");
    assert_eq!(remote_spec(&review_hop("fe80::1", "root", ""), "/tmp"), "root@[fe80::1]:/tmp");
    let mut ep = review_endpoint(crate::transfer::Kind::Sftp, review_hop("db", "root", ""));
    let mut j = review_hop("2001:db8::5", "jump", "");
    j.port = 2222;
    ep.jumps = vec![j, review_hop("::2", "", "")];
    assert_eq!(jump_arg(&ep).as_deref(), Some("jump@[2001:db8::5]:2222,[::2]"));
    for h in ["::1", "[::1]"] {
        let a = ftp_addrs(h, 21).unwrap();
        assert!(a.iter().all(|a| a.is_ipv6() && a.port() == 21), "{h}");
    }
}

#[test]
fn capture_buffer_size_is_checked() {
    use crate::embed::pixel_buffer_len;
    assert_eq!(pixel_buffer_len(10, 2), Some(80));
    assert_eq!(pixel_buffer_len(16_384, 16_384), Some(16_384 * 16_384 * 4));
    assert_eq!(pixel_buffer_len(0, 5), None);
    assert_eq!(pixel_buffer_len(-3, 5), None);
    assert_eq!(pixel_buffer_len(16_385, 1), None);
    assert_eq!(pixel_buffer_len(i32::MAX, i32::MAX), None, "would overflow i32");
}

#[test]
fn tools_folder_is_worked_out_once() {
    let a = crate::programs::tools_dir();
    assert_eq!(a, crate::programs::tools_dir());
}

// ---- window: tab strip, tab contents, screenshots (code review 2026-11-18)

#[test]
fn tab_screenshot_area_is_cut_to_the_picture() {
    // C7: the area comes from an earlier frame; ColorImage::region panicked when it reached
    // past the picture or was turned around
    use crate::app::{crop_image, rgba_fits};
    use eframe::egui::{Color32, ColorImage, Pos2, Rect};
    let (w, h) = (4usize, 3usize);
    let pixels: Vec<Color32> = (0..w * h).map(|i| Color32::from_rgb(i as u8, 0, 0)).collect();
    let img = ColorImage::new([w, h], pixels);
    let red = |c: &ColorImage| c.pixels.iter().map(|p| p.r()).collect::<Vec<u8>>();
    let r = |x0: f32, y0: f32, x1: f32, y1: f32| Rect::from_min_max(Pos2::new(x0, y0), Pos2::new(x1, y1));
    // inside
    let part = crop_image(&img, r(1.0, 1.0, 3.0, 3.0), 1.0).unwrap();
    assert_eq!(part.size, [2, 2]);
    assert_eq!(red(&part), vec![5, 6, 9, 10]);
    // half outside (window got smaller): cut to the picture
    let part = crop_image(&img, r(2.0, 1.0, 40.0, 30.0), 1.0).unwrap();
    assert_eq!(part.size, [2, 2]);
    assert_eq!(red(&part), vec![6, 7, 10, 11]);
    // negative start, scaled by pixels per point
    let part = crop_image(&img, r(-5.0, -5.0, 1.0, 0.5), 2.0).unwrap();
    assert_eq!(part.size, [2, 1]);
    assert_eq!(red(&part), vec![0, 1]);
    // nothing left: None instead of a panic
    assert!(crop_image(&img, r(10.0, 10.0, 20.0, 20.0), 1.0).is_none(), "outside");
    assert!(crop_image(&img, Rect { min: Pos2::new(3.0, 2.0), max: Pos2::new(1.0, 1.0) }, 1.0).is_none(), "turned around");
    assert!(crop_image(&img, r(1.0, 1.0, 1.0, 3.0), 1.0).is_none(), "no width");
    assert!(crop_image(&img, r(f32::NAN, 0.0, f32::NAN, 2.0), 1.0).is_none(), "NaN");
    assert!(crop_image(&img, r(0.0, 0.0, 4.0, 3.0), f32::NAN).is_none(), "NaN scale");
    // a whole-window area at a large scale is the whole picture
    assert_eq!(crop_image(&img, r(0.0, 0.0, 100.0, 100.0), 3.0).unwrap().size, [4, 3]);
    // a picture whose pixels don't fit its size is not cut at all
    let mut broken = ColorImage::new([2, 2], vec![Color32::BLACK; 4]);
    broken.pixels.pop();
    assert!(crop_image(&broken, r(0.0, 0.0, 2.0, 2.0), 1.0).is_none());
    // RGBA buffers from the system capture: size and length must agree
    assert!(rgba_fits(2, 3, 24));
    assert!(!rgba_fits(2, 3, 23));
    assert!(!rgba_fits(0, 3, 0));
    assert!(!rgba_fits(usize::MAX, 2, 0), "overflow");
}

#[test]
fn close_requests_by_tab_id() {
    use crate::app::plan_closes;
    // B5: two requests in one frame (control channel and Ctrl+Shift+W) both apply
    let order = [0, 10, 11, 12, 13];
    let (remove, active) = plan_closes(&order, 4, &[11, 13]);
    assert_eq!(remove, vec![4, 2], "highest first");
    assert_eq!(active, 2, "the active tab was closed: its left neighbour (id 12, now at 2)");
    // a request made before two tabs swapped places still closes the tab it meant
    let swapped = [0, 10, 12, 11, 13];
    let (remove, active) = plan_closes(&swapped, 1, &[11]);
    assert_eq!(remove, vec![3]);
    assert_eq!(active, 1, "a tab to the left stays active");
    // the active tab right of a closed one stays the active tab
    let (_, active) = plan_closes(&order, 3, &[10]);
    assert_eq!(active, 2, "id 12 moved from 3 to 2");
    // never the start page, every tab once, unknown ids ignored
    let (remove, active) = plan_closes(&order, 0, &[0, 12, 12, 99]);
    assert_eq!(remove, vec![3]);
    assert_eq!(active, 0);
    // everything but the start page
    let (remove, active) = plan_closes(&order, 4, &[10, 11, 12, 13]);
    assert_eq!(remove, vec![4, 3, 2, 1]);
    assert_eq!(active, 0);
    assert_eq!(plan_closes(&order, 2, &[]), (vec![], 2));
}

#[test]
fn snippet_for_multi_tabs_uses_each_tabs_connection() {
    // B1: a saved command sent to all "Multi" tabs fills in each tab's own host, user and name
    use crate::app::snippet_bytes;
    use crate::launch::Creds;
    use crate::model::Entry;
    let cmd = "ping -c1 {host} # {user}@{name}";
    let a = Entry { name: "web01".into(), host: " 10.0.0.1 ".into(), ..Default::default() };
    let b = Entry { name: "db01".into(), host: "10.0.0.2".into(), ..Default::default() };
    let ca = Creds { user: "alice".into(), password: "secret-a".into(), ..Default::default() };
    let cb = Creds { user: "bob".into(), password: "secret-b".into(), ..Default::default() };
    assert_eq!(snippet_bytes(cmd, &a, &ca), b"ping -c1 10.0.0.1 # alice@web01\r".to_vec());
    assert_eq!(snippet_bytes(cmd, &b, &cb), b"ping -c1 10.0.0.2 # bob@db01\r".to_vec());
    // the password is never a placeholder
    assert!(!String::from_utf8_lossy(&snippet_bytes("{password}", &a, &ca)).contains("secret"));
}

#[test]
fn dns_late_answer_does_not_overwrite_a_newer_query() {
    // B2: every query gets its own result slot
    use crate::app::fresh_dns_slot;
    use std::sync::{Arc, Mutex};
    type Slot = Arc<Mutex<Option<Result<Vec<String>, String>>>>;
    let mut shown: Slot = Default::default();
    let first = fresh_dns_slot(&mut shown);
    let second = fresh_dns_slot(&mut shown);
    *second.lock().unwrap() = Some(Ok(vec!["2001:db8::1".into()]));
    // the first lookup answers late
    *first.lock().unwrap() = Some(Ok(vec!["192.0.2.1".into()]));
    assert_eq!(shown.lock().unwrap().clone(), Some(Ok(vec!["2001:db8::1".to_string()])));
    // a new query starts empty, even while an older lookup still runs
    let _third = fresh_dns_slot(&mut shown);
    assert!(shown.lock().unwrap().is_none());
}

#[test]
fn output_lines_and_transfer_rows() {
    // P7: the colour of a ping line; P8: which remote rows the list shows
    use crate::app::{LineTone, line_tone, visible_rows};
    assert_eq!(line_tone("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.3 ms"), LineTone::Good);
    assert_eq!(line_tone("Reply from 10.0.0.1: bytes=32 time<1ms TTL=128"), LineTone::Good);
    assert_eq!(line_tone("Antwort von 10.0.0.1: Bytes=32 Zeit<1ms TTL=128"), LineTone::Good);
    assert_eq!(line_tone("Request timed out."), LineTone::Bad);
    assert_eq!(line_tone("Destination host unreachable."), LineTone::Bad);
    assert_eq!(line_tone("Zeitüberschreitung der Anforderung."), LineTone::Bad);
    assert_eq!(line_tone("Pinging 10.0.0.1 with 32 bytes of data:"), LineTone::Normal);
    let item = |name: &str| crate::transfer::RemoteItem {
        name: name.into(),
        is_dir: false,
        is_link: false,
        size: 0,
        modified: String::new(),
        perms: String::new(),
    };
    let items = vec![item(".ssh"), item("a.txt"), item(".bashrc"), item("b")];
    assert_eq!(visible_rows(&items, false), vec![1, 3]);
    assert_eq!(visible_rows(&items, true), vec![0, 1, 2, 3]);
    assert!(visible_rows(&[], false).is_empty());
}

#[test]
fn repaint_only_as_often_as_needed() {
    // P10: no four frames a second for as long as something runs
    use crate::app::keep_alive_interval;
    use std::time::Duration;
    assert_eq!(keep_alive_interval(true, true), Some(Duration::from_millis(250)), "a window to put into its tab");
    assert_eq!(keep_alive_interval(false, true), Some(Duration::from_secs(1)));
    assert_eq!(keep_alive_interval(false, false), None);
}
