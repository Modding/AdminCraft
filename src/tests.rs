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
