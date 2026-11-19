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
fn password_goes_only_to_its_own_host() {
    use crate::launch::PwRule;
    use crate::terminal::{pick_password, prompt_host};
    let r = |h: &str, u: &str, p: &str| PwRule { host: h.into(), user: u.into(), password: p.into() };
    let rules = vec![r("10.0.0.4", "jump", "pw-jump"), r("10.0.0.40", "root", "pw-target")];
    let fresh = [false, false];
    assert_eq!(pick_password(&rules, &fresh, "root@10.0.0.40's password:"), Some(1));
    assert_eq!(pick_password(&rules, &fresh, "jump@10.0.0.4's password:"), Some(0));
    // the whole host name counts: 10.0.0.4 is not 10.0.0.40, and the other way round
    assert_eq!(pick_password(&rules[..1], &[false], "root@10.0.0.40's password:"), None);
    assert_eq!(pick_password(&rules[1..], &[false], "jump@10.0.0.4's password:"), None);
    // keyboard-interactive and "password for" forms
    assert_eq!(pick_password(&rules, &fresh, "(root@10.0.0.40) Password:"), Some(1));
    assert_eq!(pick_password(&rules, &fresh, "Password for jump@10.0.0.4:"), Some(0));
    // the jump host asking again gets nothing, not the target's password
    assert_eq!(pick_password(&rules, &[true, false], "jump@10.0.0.4's password:"), None);
    // a host without a rule gets nothing
    assert_eq!(pick_password(&rules, &fresh, "admin@10.0.0.5's password:"), None);
    // no host named: only when there is a single rule, and only once
    assert_eq!(pick_password(&rules, &fresh, "Password:"), None);
    assert_eq!(pick_password(&rules[..1], &[false], "Password:"), Some(0));
    assert_eq!(pick_password(&rules[..1], &[true], "Password:"), None);
    // same host, two users: the user decides
    let two = vec![r("db01", "app", "a"), r("DB01", "root", "b")];
    assert_eq!(pick_password(&two, &[false, false], "root@db01's password:"), Some(1));
    assert_eq!(prompt_host("root@[fe80::1]'s password:"), Some(("root".to_string(), "fe80::1".to_string())));
    assert_eq!(prompt_host("[sudo] password for alice:"), None);
}

#[test]
fn paste_cannot_end_bracketed_paste() {
    use crate::terminal::paste_bytes;
    assert_eq!(paste_bytes("ls\x1b[201~rm -rf /\n", true), b"\x1b[200~ls[201~rm -rf /\r\x1b[201~".to_vec());
    assert_eq!(paste_bytes("a\tb\r\nc\x1b", false), b"a\tb\rc".to_vec());
    assert_eq!(paste_bytes("x\u{9b}201~y", false), b"x201~y".to_vec(), "8-bit CSI too");
}

#[test]
fn session_log_leaves_out_all_escapes() {
    use crate::terminal::strip_escapes;
    let strip = |chunks: &[&[u8]]| {
        let (mut st, mut out) = (0u8, Vec::new());
        for c in chunks {
            strip_escapes(&mut st, c, &mut out);
        }
        String::from_utf8(out).unwrap()
    };
    assert_eq!(strip(&[b"\x1b(Bplain\x1b[1;31mred\x1b[0m"]), "plainred");
    assert_eq!(strip(&[b"\x1b)0\x1b#8x"]), "x");
    assert_eq!(strip(&[b"\x1bPq#0;2;0;0;0\x1b\\after"]), "after");
    assert_eq!(strip(&[b"\x1bPa\\b\x1b\\c"]), "c", "a backslash alone does not end a DCS");
    assert_eq!(strip(&[b"\x1b_Gf=100;AAAA\x1b\\x"]), "x");
    assert_eq!(strip(&[b"\x1bXsos\x1b\\1\x1b^pm\x1b\\2"]), "12");
    assert_eq!(strip(&[b"\x1b]0;title\x07t"]), "t");
    assert_eq!(strip(&[b"\x1b]0;ti", b"tle\x1b", b"\\ok\r\n"]), "ok\n");
    assert_eq!(strip(&[b"\x1b[3", b"1mz"]), "z");
}

#[test]
fn recordings_are_buffered_and_keep_arrival_time() {
    let path = std::env::temp_dir().join(format!("admincraft-recbuf-{}.cast", std::process::id()));
    {
        let mut r = crate::terminal::Recorder::create(&path, 80, 24, "t").unwrap();
        r.output(b"hello");
        // the data arrived 5 s after the start, whenever the screen gets it
        r.output_at(b"later", std::time::Instant::now() + std::time::Duration::from_secs(5));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "not written per chunk");
    }
    let cast = crate::playback::parse_cast(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(cast.events.len(), 2, "written when dropped");
    assert!(cast.events[1].0 >= 4.9, "{:?}", cast.events[1]);
    let _ = std::fs::remove_file(path);
}

#[test]
fn wide_and_odd_glyphs_stay_on_the_cell_grid() {
    use crate::terminal::{for_each_run, nz};
    let mut p = vt100::Parser::new(nz(2), nz(20), 0);
    p.process("a漢b ä\u{1F600}c".as_bytes());
    let runs = |inline: &dyn Fn(char) -> bool| {
        let mut v: Vec<(u16, u16, String)> = Vec::new();
        for_each_run(p.screen(), 1, 20, inline, |_, col, width, text, _| v.push((col, width, text.to_string())));
        v
    };
    let at = |v: &Vec<(u16, u16, String)>, s: &str| v.iter().find(|r| r.2.starts_with(s)).map(|r| (r.0, r.1));
    let v = runs(&|ch| ch == 'ä');
    assert_eq!(at(&v, "a"), Some((0, 1)));
    assert_eq!(at(&v, "漢"), Some((1, 2)));
    assert_eq!(at(&v, "b ä"), Some((3, 3)), "a one-cell glyph may stay in the run");
    assert_eq!(at(&v, "\u{1F600}"), Some((6, 2)));
    assert_eq!(at(&v, "c"), Some((8, 12)));
    // a glyph the font draws at another width is placed alone, at its column
    let v = runs(&|_| false);
    assert_eq!(at(&v, "ä"), Some((5, 1)));
    assert_eq!(at(&v, "c"), Some((8, 12)));
    assert_eq!(v.iter().map(|r| r.1).sum::<u16>(), 20, "every cell once");
}

#[test]
fn whois_referrals_stay_public() {
    use crate::nettools::referral_allowed;
    assert!(referral_allowed("whois.verisign-grs.com"));
    assert!(referral_allowed("whois.arin.net:43"));
    assert!(referral_allowed("8.8.8.8"));
    assert!(!referral_allowed("whois.example.net:4444"), "only port 43");
    for bad in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.1:43",
        "172.16.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "[::1]",
        "fe80::1",
        "[fc00::5]:43",
        "[::ffff:127.0.0.1]",
        "localhost",
    ] {
        assert!(!referral_allowed(bad), "{bad}");
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

#[test]
fn playback_survives_odd_times() {
    use crate::playback::{Player, parse_cast};
    let text = "{\"version\":2,\"width\":80,\"height\":24}\n[-5.0,\"o\",\"a\"]\n[-1.0,\"o\",\"b\"]\n[\"x\",\"o\",\"c\"]\n";
    let cast = parse_cast(text).unwrap();
    assert!(cast.events.iter().all(|(t, _)| t.is_finite() && *t >= 0.0));
    let mut p = Player::from_cast(std::path::Path::new("x.cast"), cast, false);
    assert_eq!(p.duration(), 0.0);
    for t in [3.0, -2.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0] {
        p.seek(t);
    }
    assert!(p.screen_text().starts_with("ab"));
    // times going back are kept in order
    let cast = parse_cast("{\"version\":2}\n[2.0,\"o\",\"x\"]\n[1.0,\"o\",\"y\"]\n").unwrap();
    assert_eq!(cast.events.iter().map(|e| e.0).collect::<Vec<_>>(), vec![2.0, 2.0]);
}

#[test]
fn playback_seeks_back_from_keyframes() {
    use crate::playback::{Player, parse_cast};
    let mut text = String::from("{\"version\":2,\"width\":80,\"height\":24}\n");
    for i in 0..600 {
        let chunk = format!("line {i:04} {}\r\n", "x".repeat(1000));
        text += &serde_json::json!([i as f64 * 0.1, "o", chunk]).to_string();
        text.push('\n');
    }
    let path = std::path::Path::new("k.cast");
    let mut p = Player::from_cast(path, parse_cast(&text).unwrap(), false);
    p.seek(1000.0);
    assert!(p.keyframes() > 0);
    p.seek(41.05);
    let mut fresh = Player::from_cast(path, parse_cast(&text).unwrap(), false);
    fresh.seek(41.05);
    assert_eq!(p.screen_text(), fresh.screen_text());
    assert!(p.screen_text().contains("line 0410"));
}

#[test]
fn recording_files_have_a_size_limit() {
    use crate::playback::read_cast_file;
    let path = std::env::temp_dir().join(format!("admincraft-big-{}.cast", std::process::id()));
    std::fs::write(&path, "x".repeat(2000)).unwrap();
    assert!(read_cast_file(&path, 1000).is_err());
    assert_eq!(read_cast_file(&path, 1 << 20).unwrap().len(), 2000);
    let _ = std::fs::remove_file(path);
}

#[test]
fn scan_ranges_and_threads_are_bounded() {
    use crate::netscan::{MAX_CONNECTS, parse_targets, scan_plan};
    use std::net::Ipv4Addr;
    assert_eq!(parse_targets("255.255.255.0/24").unwrap().len(), 254);
    assert_eq!(parse_targets("255.255.255.254/31").unwrap().len(), 2);
    assert_eq!(parse_targets("255.255.255.255/32").unwrap(), vec![Ipv4Addr::new(255, 255, 255, 255)]);
    assert_eq!(parse_targets("255.255.0.0/16").unwrap().len(), 65534);
    assert_eq!(parse_targets("0.0.0.0/32").unwrap().len(), 1);
    for (t, p) in [(65536, 65535), (65536, 5), (1, 1), (10, 0), (0, 0), (300, 16), (64, 3)] {
        let (w, k) = scan_plan(t, p);
        assert!(w >= 1 && k >= 1 && w * k <= MAX_CONNECTS, "{t} {p}: {w}x{k}");
    }
}

#[test]
fn snmp_numbers_and_answers_are_checked() {
    use crate::nettools::{decode_oid, encode_get, encode_oid, match_answer};
    use std::net::SocketAddr;
    assert!(encode_oid("2.18446744073709551615").is_err(), "first arcs overflow");
    assert_eq!(decode_oid(&encode_oid("2.100.3").unwrap()).unwrap(), "2.100.3");
    let mut long = vec![0xffu8; 10];
    long.push(0x7f);
    assert!(decode_oid(&long).is_err(), "arc larger than 64 bits");
    let asked: SocketAddr = "192.0.2.1:161".parse().unwrap();
    let pkt = encode_get("public", 7, 0xa2, &["1.3.6.1.2.1.1.5.0"]).unwrap();
    assert!(match_answer(asked, asked, &pkt, 7).is_some_and(|r| r.is_ok()));
    assert!(match_answer(asked, "192.0.2.1:5000".parse().unwrap(), &pkt, 7).is_none(), "another port");
    assert!(match_answer(asked, "192.0.2.9:161".parse().unwrap(), &pkt, 7).is_none(), "another sender");
    assert!(match_answer(asked, asked, &pkt, 8).is_none(), "another request");
    assert!(match_answer(asked, asked, &[0x30, 0x05, 0x02], 7).is_none(), "a damaged packet is skipped");
}

// ------------------------------------------------------------------ code review 2026-11-18: tools and control channel

/// Waits up to `secs` seconds for `f` to become true.
fn wait_for(secs: u64, f: impl Fn() -> bool) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < std::time::Duration::from_secs(secs) {
        if f() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    f()
}

#[test]
fn control_file_is_private_on_windows() {
    use crate::control::control_file_for;
    use std::path::Path;
    let local = if cfg!(windows) { Path::new(r"C:\Users\tom\AppData\Local") } else { Path::new("/home/tom/.local") };
    let data = if cfg!(windows) { Path::new(r"E:\AdminCraft\AdminCraftData") } else { Path::new("/media/usb/AdminCraftData") };
    let f = control_file_for(data, Some(local), true).unwrap();
    assert!(f.starts_with(local.join("AdminCraft")), "in the user's own folder: {}", f.display());
    assert!(!f.starts_with(data), "not in the (portable, maybe shared) data folder");
    let name = f.file_name().unwrap().to_string_lossy().to_string();
    assert!(name.starts_with("control-") && name.ends_with(".json"), "{name}");
    // client and window find the same file; another data folder gets its own
    assert_eq!(control_file_for(data, Some(local), true), Some(f.clone()));
    assert_ne!(control_file_for(&data.join("other"), Some(local), true), Some(f));
    // without a private folder: no control channel rather than a readable token
    assert_eq!(control_file_for(data, None, true), None);
    assert_eq!(control_file_for(data, Some(Path::new("relative")), true), None);
    // Linux / macOS: in the data folder, written with mode 0600
    assert_eq!(control_file_for(data, Some(local), false), Some(data.join("control.json")));
}

#[test]
fn control_request_line_has_one_deadline() {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // a client sending one byte at a time, never a line break
    let slow = std::thread::spawn(move || {
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        for _ in 0..20 {
            if c.write_all(b"x").is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    });
    let (mut s, _) = listener.accept().unwrap();
    let t0 = std::time::Instant::now();
    let r = crate::control::read_line(&mut s, t0 + std::time::Duration::from_millis(600), 1 << 20);
    assert!(r.is_err(), "the line never ended");
    assert!(t0.elapsed() < std::time::Duration::from_millis(1500), "deadline for the whole line, not per read: {:?}", t0.elapsed());
    drop(s);
    let _ = slow.join();
    // a long line without a break is refused, not collected without end
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let big = std::thread::spawn(move || {
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        let _ = c.write_all(&vec![b'a'; 10_000]);
        let _ = rx.recv();
    });
    let (mut s, _) = listener.accept().unwrap();
    assert!(crate::control::read_line(&mut s, std::time::Instant::now() + std::time::Duration::from_secs(5), 4096).is_err());
    let _ = tx.send(());
    let _ = big.join();
}

#[test]
fn control_channel_limits_connections_and_stops() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<crate::control::Request>();
    let stop = Arc::new(AtomicBool::new(false));
    let handle = crate::control::accept_loop(listener, "secret".into(), tx, Arc::new(|| {}), stop.clone()).unwrap();
    // idle clients hold every slot
    let idle: Vec<std::net::TcpStream> = (0..crate::control::MAX_CONNECTIONS).map(|_| std::net::TcpStream::connect(addr).unwrap()).collect();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut extra = std::net::TcpStream::connect(addr).unwrap();
    extra.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
    let mut b = [0u8; 16];
    match extra.read(&mut b) {
        Ok(n) => assert_eq!(n, 0, "closed right away"),
        Err(e) => assert!(!matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut), "closed right away, not kept: {e}"),
    }
    drop(idle);
    std::thread::sleep(std::time::Duration::from_millis(300));
    // a real request gets through again and carries a deadline
    let client = std::thread::spawn(move || {
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        writeln!(c, "{}", serde_json::json!({"token": "secret", "cmd": "status", "args": {}})).unwrap();
        crate::control::read_line(&mut c, std::time::Instant::now() + std::time::Duration::from_secs(10), 1 << 20).unwrap()
    });
    let req = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(req.cmd, "status");
    assert!(!req.expired());
    assert!(req.deadline <= std::time::Instant::now() + std::time::Duration::from_secs(21));
    req.reply.send(serde_json::json!({"ok": true})).unwrap();
    assert!(client.join().unwrap().contains("\"ok\":true"));
    // a request whose client was already told "no answer" is skipped by the window
    let (reply, _wait) = std::sync::mpsc::channel();
    let old = crate::control::Request {
        cmd: "close_tab".into(),
        args: serde_json::json!({}),
        reply,
        deadline: std::time::Instant::now() - std::time::Duration::from_millis(1),
    };
    assert!(old.expired());
    // switching the channel off ends the listener
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(addr);
    assert!(wait_for(5, || handle.is_finished()), "the accept loop ended");
    assert!(std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(1)).is_err(), "the port is closed");
}

#[test]
fn agent_screenshot_files_are_new_files_only() {
    let dir = std::env::temp_dir().join(format!("admincraft-shots-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let a = crate::control::new_shot_file(&dir, 2);
    let b = crate::control::new_shot_file(&dir, 2);
    assert_ne!(a, b, "every picture gets its own name");
    assert!(a.starts_with(&dir) && a.to_string_lossy().ends_with(".png"));
    let rgba = vec![255u8; 2 * 2 * 4];
    crate::control::save_png_new(&a, 2, 2, &rgba).unwrap();
    assert!(std::fs::read(&a).unwrap().starts_with(b"\x89PNG"));
    // an existing file is never replaced
    let before = std::fs::read(&a).unwrap();
    assert!(crate::control::save_png_new(&a, 1, 1, &[0, 0, 0, 0]).is_err());
    assert_eq!(std::fs::read(&a).unwrap(), before);
    // a buffer of the wrong size is an error, not a panic in the encoder
    assert!(crate::control::save_png_new(&b, 3, 3, &rgba).is_err());
    #[cfg(unix)]
    {
        // a link placed beforehand is not followed
        let target = dir.join("victim.txt");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.join("link.png");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(crate::control::save_png_new(&link, 2, 2, &rgba).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mcp_screenshot_reads_only_png_files() {
    use crate::agent::read_png;
    let dir = std::env::temp_dir().join(format!("admincraft-readpng-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0u8; 100]);
    let good = dir.join("a.png");
    std::fs::write(&good, &png).unwrap();
    let not_png_name = dir.join("a.txt");
    std::fs::write(&not_png_name, &png).unwrap();
    let not_png_data = dir.join("b.png");
    std::fs::write(&not_png_data, "secret token").unwrap();
    assert_eq!(read_png(&good.to_string_lossy(), 1 << 20), Some(png));
    assert_eq!(read_png(&not_png_name.to_string_lossy(), 1 << 20), None, "only .png names");
    assert_eq!(read_png(&not_png_data.to_string_lossy(), 1 << 20), None, "only PNG contents");
    assert_eq!(read_png(&good.to_string_lossy(), 50), None, "size cap");
    assert_eq!(read_png(&dir.to_string_lossy(), 1 << 20), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn agent_targets_are_no_tool_options() {
    use crate::tools::valid_target;
    for ok in ["web01", "10.0.0.1", "fe80::1%eth0", "host.example.com"] {
        assert!(valid_target(ok), "{ok}");
    }
    for bad in ["-t", "-n 1000 host", "host -t", "a\tb", "a\nb", "host\u{0}", ""] {
        assert!(!valid_target(bad), "{bad:?}");
    }
}

#[test]
fn port_scan_prefers_ipv4_and_has_a_time_cap() {
    use std::net::SocketAddr;
    let v6: SocketAddr = "[::1]:80".parse().unwrap();
    let v4: SocketAddr = "127.0.0.1:80".parse().unwrap();
    let v4b: SocketAddr = "10.0.0.1:80".parse().unwrap();
    assert_eq!(crate::tools::prefer_ipv4(vec![v6, v4, v4b]), vec![v4, v4b, v6]);
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let ip = std::net::IpAddr::from([127, 0, 0, 1]);
    let ports = vec![port, port.wrapping_add(1).max(1)];
    let r = crate::agent::port_scan_addr(ip, &ports, std::time::Duration::from_millis(300), std::time::Duration::from_secs(30));
    assert_eq!(r["checked"], 2);
    assert_eq!(r["complete"], true);
    assert!(r["open"].as_array().unwrap().iter().any(|o| o["port"] == port));
    // the time is up before the first port: nothing more is started
    let r = crate::agent::port_scan_addr(ip, &ports, std::time::Duration::from_millis(300), std::time::Duration::ZERO);
    assert_eq!(r["checked"], 0);
    assert_eq!(r["complete"], false);
    // no worker threads: the calling thread does the work
    let found = std::sync::Mutex::new(Vec::new());
    let n = crate::tools::scan_ports(ip, &[port], std::time::Duration::from_millis(300), 0, &|| false, &|p, ok| {
        if ok {
            found.lock().unwrap().push(p)
        }
    });
    assert_eq!(n, 1);
    assert_eq!(*found.lock().unwrap(), vec![port]);
}

#[test]
fn command_output_is_capped() {
    use crate::tools::{MAX_LINES, push_line};
    let mut lines = Vec::new();
    for i in 0..20_000 {
        push_line(&mut lines, format!("line {i}"));
        assert!(lines.len() <= MAX_LINES + 500);
    }
    assert!(lines.len() >= MAX_LINES);
    assert_eq!(lines.last().map(String::as_str), Some("line 19999"), "the newest lines stay");
}

/// A command that runs for about 30 s.
fn long_command() -> (String, Vec<String>) {
    if cfg!(windows) { ("ping".into(), vec!["-n".into(), "30".into(), "127.0.0.1".into()]) } else { ("sleep".into(), vec!["30".into()]) }
}

#[test]
fn command_runner_runs_are_separate_and_reaped() {
    let (prog, args) = long_command();
    let ctx = eframe::egui::Context::default();
    let mut runner = crate::tools::CmdRunner::default();
    runner.start(&prog, &args, ctx.clone());
    let first = runner.running.clone();
    assert!(first.load(std::sync::atomic::Ordering::SeqCst));
    // a new run stops the old one; the old one ending doesn't switch off the new one
    runner.start(&prog, &args, ctx.clone());
    assert!(wait_for(10, || !first.load(std::sync::atomic::Ordering::SeqCst)), "the first program was killed and waited for");
    assert!(runner.is_running(), "the second run is still running");
    runner.stop();
    assert!(wait_for(10, || !runner.is_running()), "stop kills, the reader thread reaps");
}

#[test]
fn command_runner_stops_when_dropped() {
    let (prog, args) = long_command();
    let mut runner = crate::tools::CmdRunner::default();
    runner.start(&prog, &args, eframe::egui::Context::default());
    let running = runner.running.clone();
    assert!(running.load(std::sync::atomic::Ordering::SeqCst));
    drop(runner);
    assert!(wait_for(10, || !running.load(std::sync::atomic::Ordering::SeqCst)), "a closed tab ends a continuous ping");
}

#[test]
fn tunnel_error_output_keeps_the_last_lines() {
    let text: String = (0..50).map(|i| if i % 7 == 0 { "\n".to_string() } else { format!("line {i}\n") }).collect();
    let tail = std::sync::Mutex::new(crate::extra::ErrTail::default());
    crate::extra::drain_stderr(std::io::Cursor::new(text.into_bytes()), &tail);
    let t = tail.lock().unwrap();
    assert!(t.done);
    assert_eq!(t.lines.len(), crate::extra::TAIL_LINES);
    assert_eq!(t.lines.back().map(String::as_str), Some("line 48"), "the last non-empty line");
    drop(t);
    // a very long line without a break doesn't grow without end
    let tail = std::sync::Mutex::new(crate::extra::ErrTail::default());
    crate::extra::drain_stderr(std::io::Cursor::new(vec![b'x'; 100_000]), &tail);
    assert!(tail.lock().unwrap().lines.iter().all(|l| l.len() <= 4096));
}

#[test]
fn scan_rows_are_built_only_when_the_scan_changes() {
    let built = std::cell::Cell::new(0);
    let mut cache = None;
    let build = || {
        built.set(built.get() + 1);
        vec![1, 2, 3]
    };
    for _ in 0..10 {
        let rows = crate::extra::cached(&mut cache, (1usize, 5usize, false, 0u64), build);
        assert_eq!(*rows, vec![1, 2, 3]);
    }
    assert_eq!(built.get(), 1, "the same scan state: no new rows per frame");
    crate::extra::cached(&mut cache, (1, 6, false, 0), build);
    crate::extra::cached(&mut cache, (1, 6, true, 0), build);
    crate::extra::cached(&mut cache, (1, 6, true, 1), build);
    assert_eq!(built.get(), 4, "progress, end and a new baseline build again");
}

#[test]
fn totp_refuses_what_it_cannot_compute() {
    use crate::admintools::parse_otp;
    let s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    assert!(parse_otp(&format!("otpauth://totp/x?secret={s}&algorithm=SHA1")).is_some());
    assert!(parse_otp(&format!("OTPAUTH://TOTP/x?secret={s}&algorithm=sha1")).is_some());
    assert!(parse_otp(&format!("otpauth://totp/x?secret={s}")).is_some());
    assert!(parse_otp(s).is_some(), "a bare key");
    assert_eq!(parse_otp(&format!("otpauth://totp/x?secret={s}&algorithm=SHA256")), None, "no wrong codes");
    assert_eq!(parse_otp(&format!("otpauth://totp/x?secret={s}&algorithm=SHA512")), None);
    assert_eq!(parse_otp(&format!("otpauth://hotp/x?secret={s}&counter=5")), None, "counter-based codes");
}

#[test]
fn mcp_initialize_answers_a_supported_version() {
    use crate::agent::{MCP_VERSIONS, mcp_version};
    assert_eq!(mcp_version(Some("2024-11-05")), "2024-11-05");
    assert_eq!(mcp_version(Some("1999-01-01")), MCP_VERSIONS[0]);
    assert_eq!(mcp_version(None), MCP_VERSIONS[0]);
    let mut out = Vec::new();
    crate::agent::handle(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"evil-9"}}"#, &mut out);
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["result"]["protocolVersion"], MCP_VERSIONS[0]);
    // ports are checked, not cut down to another port (70000 as u16 = 4464)
    let e = crate::agent::call("check_certificate", &serde_json::json!({"host": "example.invalid", "port": 70000})).unwrap_err();
    assert!(e.contains("65535"), "{e}");
    assert!(crate::agent::call("check_certificate", &serde_json::json!({"host": "example.invalid", "port": 0})).is_err());
}

// ---------------------------------------------------------------- code review 2026-11-18, app part 1

#[test]
fn file_app_url_has_no_password_and_brackets_ipv6() {
    // S4: the function has no password parameter, so nothing secret can reach the command line
    use crate::app::file_app_url;
    assert_eq!(file_app_url("sftp", "root", "10.0.0.5", 0, ""), "sftp://root@10.0.0.5");
    assert_eq!(file_app_url("sftp", "a b@c", " srv ", 2222, "/var/www"), "sftp://a%20b%40c@srv:2222/var/www");
    assert_eq!(file_app_url("ftp", "", "fe80::1", 21, ""), "ftp://[fe80::1]:21");
    assert_eq!(file_app_url("sftp", "", "fe80::1%eth0", 0, ""), "sftp://[fe80::1%25eth0]");
    assert_eq!(file_app_url("scp", "u", "[::1]", 22, ""), "scp://u@[::1]:22", "already bracketed");
}

#[test]
fn duplicate_is_not_tied_to_the_keepass_entry() {
    // D4
    let e = crate::model::Entry { id: 7, name: "web".into(), kp_id: "abc-uuid".into(), host: "h".into(), ..Default::default() };
    let copy = crate::app::duplicate_entry(&e, 8);
    assert_eq!(copy.id, 8);
    assert!(copy.kp_id.is_empty());
    assert_eq!(copy.host, "h");
    assert_eq!(copy.name, "web (copy)");
}

#[test]
fn showing_a_port_does_not_change_it() {
    // D11: port 0 (= default) and odd tunnel ports from a data file stay as they are when drawn
    let ctx = eframe::egui::Context::default();
    let (mut port, mut tport, mut tport2) = (0u16, 0u16, 65535u16);
    for _ in 0..2 {
        ctx.run_ui(Default::default(), |ui| {
            ui.add(crate::app::port_edit(&mut port));
            ui.add(crate::app::tunnel_port_edit(&mut tport));
            ui.add(crate::app::tunnel_port_edit(&mut tport2));
        })
        .drop_without_applying_deltas();
    }
    assert_eq!(port, 0);
    assert_eq!(tport, 0);
    assert_eq!(tport2, 65535);
}

#[test]
fn power_command_only_goes_to_the_new_tab() {
    // D12: tabs are (id, terminal running); the id counter was 5 before the session was started
    use crate::app::power_tab;
    assert_eq!(power_tab(5, &[(0, false), (3, true), (4, true)]), None, "no new tab: never the last old one");
    assert_eq!(power_tab(5, &[(0, false), (3, true), (5, false)]), None, "new tab, session failed");
    assert_eq!(power_tab(5, &[(0, false), (3, true), (5, true)]), Some(2));
    assert_eq!(power_tab(5, &[(0, false), (5, true), (3, true)]), Some(1), "found by id, not position");
}

#[test]
fn tunnel_runs_follow_their_tunnel() {
    // D17
    use crate::app::{TunnelSpec, tunnel_moves};
    let spec = |l: u16, h: &str, r: u16| TunnelSpec { local_port: l, remote_host: h.into(), remote_port: r };
    let a = spec(8080, "localhost", 80);
    let b = spec(8443, "10.0.0.1", 443);
    let runs = vec![((1, 0), a.clone()), ((1, 1), b.clone()), ((2, 0), a.clone())];
    // connection 1: the first tunnel was removed, b is now at 0; connection 2 is gone
    let mut moves = tunnel_moves(&runs, |id| if id == 1 { Some(vec![b.clone()]) } else { None });
    moves.sort();
    assert_eq!(moves, vec![((1, 0), None), ((1, 1), Some((1, 0))), ((2, 0), None)]);
    // unchanged list: everything stays
    let moves = tunnel_moves(&runs[..2], |_| Some(vec![a.clone(), b.clone()]));
    assert!(moves.iter().all(|(f, t)| Some(*f) == *t));
    // an edited port: the old run doesn't belong to the row any more
    let moves = tunnel_moves(&runs[..1], |_| Some(vec![spec(9090, "localhost", 80)]));
    assert_eq!(moves, vec![((1, 0), None)]);
    // two equal tunnels: each run keeps its own row
    let moves = tunnel_moves(&[((1, 0), a.clone()), ((1, 1), a.clone())], |_| Some(vec![a.clone(), a.clone()]));
    assert_eq!(moves.len(), 2);
    assert!(moves.iter().all(|(f, t)| Some(*f) == *t));
}

#[test]
fn tree_with_repeated_ids_stays_small() {
    // C3 / P4: 30 nested folders, each twice under the same id, used to draw 2^30 rows
    use crate::model::Entry;
    let mut entries = Vec::new();
    for level in 0..30u64 {
        for _ in 0..2 {
            entries.push(Entry {
                id: level + 1,
                parent: if level == 0 { None } else { Some(level) },
                folder: true,
                expanded: true,
                ..Default::default()
            });
        }
    }
    let rows = crate::app::tree_rows(&entries);
    assert_eq!(rows.len(), 30);
    assert_eq!(rows.iter().map(|r| r.1).max(), Some(29));
    // an entry that is its own parent, and a loop, are never reached from the top
    entries.push(Entry { id: 100, parent: Some(100), folder: true, ..Default::default() });
    entries.push(Entry { id: 101, parent: Some(102), folder: true, ..Default::default() });
    entries.push(Entry { id: 102, parent: Some(101), folder: true, ..Default::default() });
    assert_eq!(crate::app::tree_rows(&entries).len(), 30);
}

#[test]
fn tree_rows_keep_order_depth_and_collapsed_folders() {
    use crate::model::Entry;
    let f = |id, parent, expanded| Entry { id, parent, folder: true, expanded, ..Default::default() };
    let c = |id, parent| Entry { id, parent, ..Default::default() };
    let entries = vec![f(1, None, true), c(2, Some(1)), f(3, Some(1), false), c(4, Some(3)), c(5, None), c(6, Some(1))];
    let ids: Vec<(u64, usize)> = crate::app::tree_rows(&entries).into_iter().map(|(i, d)| (entries[i].id, d)).collect();
    assert_eq!(ids, vec![(1, 0), (2, 1), (3, 1), (6, 1), (5, 0)]);
    // depth is limited as before (32 levels below the top)
    let deep: Vec<Entry> = (0..40u64).map(|i| f(i + 1, if i == 0 { None } else { Some(i) }, true)).collect();
    assert_eq!(crate::app::tree_rows(&deep).len(), 33);
}

#[test]
fn search_finds_connections_only() {
    // P6
    use crate::model::Entry;
    let entries = vec![
        Entry { id: 1, folder: true, name: "Web".into(), ..Default::default() },
        Entry { id: 2, name: "web01".into(), ..Default::default() },
        Entry { id: 3, name: "db".into(), host: "WEB-db.lan".into(), ..Default::default() },
        Entry { id: 4, name: "x".into(), description: "nothing".into(), ..Default::default() },
    ];
    assert_eq!(crate::app::search_hits(&entries, "web"), vec![2, 3]);
    assert!(crate::app::search_hits(&entries, "zzz").is_empty());
}

#[test]
fn monitoring_reports_only_changes() {
    // P19
    use std::collections::HashMap;
    let mut prev = HashMap::new();
    let mut cur: HashMap<u64, Option<bool>> = HashMap::from([(1, Some(true)), (2, None)]);
    assert!(crate::app::status_changes(&cur, &mut prev).is_empty(), "first look: nothing to compare");
    cur.insert(1, Some(false));
    cur.insert(2, Some(true));
    assert_eq!(crate::app::status_changes(&cur, &mut prev), vec![(1, false)]);
    assert!(crate::app::status_changes(&cur, &mut prev).is_empty(), "told once");
    cur.insert(1, None); // a check running again keeps the last known state
    assert!(crate::app::status_changes(&cur, &mut prev).is_empty());
    assert_eq!(prev.get(&1), Some(&Some(false)));
}

#[test]
fn shortcuts_off_while_locked_or_in_a_dialog() {
    // C14
    use crate::app::shortcut_allowed;
    assert!(shortcut_allowed(false, false, false));
    assert!(!shortcut_allowed(true, false, false));
    assert!(!shortcut_allowed(false, true, false));
    assert!(shortcut_allowed(true, true, true), "F1 always");
}

#[test]
fn open_connect_picks_a_connection_not_a_folder() {
    // B14
    use crate::model::Entry;
    let entries = vec![
        Entry { id: 1, folder: true, name: "Servers".into(), ..Default::default() },
        Entry { id: 2, name: "web servers proxy".into(), ..Default::default() },
        Entry { id: 3, name: "servers".into(), ..Default::default() },
    ];
    assert_eq!(crate::app::find_connection(&entries, "Servers"), Some(3), "exact name first, never the folder");
    assert_eq!(crate::app::find_connection(&entries, "proxy"), Some(2));
    assert_eq!(crate::app::find_connection(&entries, ""), None);
    assert_eq!(crate::app::find_connection(&entries, "  "), None);
    assert_eq!(crate::app::find_connection(&entries[..1], "serv"), None);
}

// ------------------------------------------------------------------ code review 2026-11-18: storage

/// An empty folder of its own for one test.
fn review_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("admincraft-review-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An empty KeePass database with this password.
fn empty_kdbx(dir: &std::path::Path, password: &str) -> String {
    let path = dir.join("list.kdbx");
    let db = keepass::Database::new();
    let mut f = std::fs::File::create(&path).unwrap();
    db.save(&mut f, keepass::DatabaseKey::new().with_password(password)).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn reload_with_master_password_takes_a_colleagues_change() {
    // D1
    let dir = review_dir("d1");
    let mut a = temp_store("d1a");
    a.path = dir.join("connections.json");
    a.set_master("Team-1");
    assert!(a.last_error.is_none());
    let mut b = temp_store("d1b");
    b.path = a.path.clone();
    b.vault = None;
    assert!(b.reload_from_disk_for_test());
    assert!(b.unlock("Team-1"));
    let i = b.index_of(3).unwrap();
    b.data.entries[i].name = "changed by b".into();
    std::thread::sleep(std::time::Duration::from_millis(30));
    b.save();
    assert!(b.last_error.is_none(), "{:?}", b.last_error);
    assert!(a.reload_if_changed(), "a colleague's change arrives with a master password too");
    assert_eq!(a.get(3).unwrap().name, "changed by b");
    // seen while locked: not used up, read after unlocking
    a.vault = None;
    b.data.entries[i].name = "second change".into();
    std::thread::sleep(std::time::Duration::from_millis(30));
    b.save();
    assert!(!a.reload_if_changed());
    assert!(a.unlock("Team-1"));
    assert!(a.reload_if_changed());
    assert_eq!(a.get(3).unwrap().name, "second change");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn webdav_save_drops_an_older_server_copy() {
    // D2
    use crate::model::RemoteState;
    let dir = review_dir("d2");
    let mut s = temp_store("d2");
    s.path = dir.join("connections-webdav.json");
    // no address: the upload fails at once, without any network
    s.remote = Some(crate::remote::RemoteConfig::default());
    s.remote_state.lock().unwrap().fetched = Some("fetched before the save".into());
    s.save();
    {
        let st = s.remote_state.lock().unwrap();
        assert!(st.fetched.is_none(), "a copy fetched before the save is older than the list");
        assert_eq!(st.saves, 1);
    }
    // a poll that started before a save (or while an upload is on its way) is thrown away
    let mut st = RemoteState { saves: 1, ..Default::default() };
    st.poll_done(0, Ok(Some("old".into())));
    assert!(st.fetched.is_none());
    st.uploading = true;
    st.poll_done(1, Ok(Some("old".into())));
    assert!(st.fetched.is_none());
    st.uploading = false;
    st.poll_done(1, Ok(Some("new".into())));
    assert_eq!(st.fetched.as_deref(), Some("new"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn keepass_list_with_entries_replaces_nothing() {
    // D3
    use crate::kdbx::{self, Key};
    let dir = review_dir("d3");
    let ps = empty_kdbx(&dir, "kp-d3");
    let key = Key { password: "kp-d3".into(), keyfile: String::new() };
    kdbx::store_password(&ps, &key, "printer", "admin", "pw1", "http://10.0.1.50/").unwrap();
    let mut s = temp_store("d3");
    s.path = dir.join("connections.json");
    let count = s.data.entries.len();
    s.data.settings.keepass_path = ps.clone();
    let msg = s.use_keepass(key.clone()).unwrap();
    assert_eq!(s.data.entries.len(), count + 1, "{msg}");
    assert!(s.path.with_extension("json.before-keepass").exists(), "backup of the list as it was");
    let back = kdbx::load(&ps, &key).unwrap();
    assert_eq!(back.len(), count + 1);
    assert_eq!(back.iter().find(|e| e.name == "printer").unwrap().password, "pw1");
    assert!(back.iter().any(|e| e.name.starts_with("web01 – L")));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn copies_never_share_a_keepass_entry() {
    // D4
    use crate::kdbx::{self, Key};
    use crate::model::Entry;
    let dir = review_dir("d4");
    let ps = empty_kdbx(&dir, "kp-d4");
    let key = Key { password: "kp-d4".into(), keyfile: String::new() };
    let mut list = vec![Entry { id: 1, name: "original".into(), host: "10.0.0.1".into(), ..Default::default() }];
    kdbx::save(&ps, &key, &mut list, &Default::default()).unwrap();
    assert!(!list[0].kp_id.is_empty());
    let known = list.iter().map(|e| e.kp_id.clone()).collect();
    let copy = Entry { id: 2, name: "copy".into(), ..list[0].clone() };
    list.push(copy);
    kdbx::save(&ps, &key, &mut list, &known).unwrap();
    assert_ne!(list[0].kp_id, list[1].kp_id);
    let mut names: Vec<String> = kdbx::load(&ps, &key).unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, vec!["copy".to_string(), "original".to_string()]);
    // export and import don't carry KeePass ids
    let mut s = temp_store("d4");
    s.data.entries[0].kp_id = "some-keepass-id".into();
    let f = dir.join("export.json");
    crate::sharing::export(&s, None, crate::sharing::PwMode::Without, "", &f).unwrap();
    let (entries, pws) = crate::sharing::read(&std::fs::read_to_string(&f).unwrap(), "").unwrap();
    assert!(entries.iter().all(|e| e.kp_id.is_empty()));
    let with_id = vec![Entry { id: 1, kp_id: "x".into(), ..Default::default() }];
    let mut other = temp_store("d4b");
    let before = other.data.entries.len();
    crate::sharing::merge(&mut other, with_id, pws, "Import");
    assert!(other.data.entries[before..].iter().all(|e| e.kp_id.is_empty()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unreadable_list_is_never_replaced_by_the_sample() {
    // D5
    let dir = review_dir("d5");
    let p = dir.join("connections.json");
    let damaged = vec![0xff, 0xfe, 0x00, 0x41];
    std::fs::write(&p, &damaged).unwrap();
    let s = Store::open_at(p.clone(), None, None, false);
    assert!(s.read_only && s.last_error.is_some());
    assert_eq!(std::fs::read(&p).unwrap(), damaged);
    // really missing: the sample list is made and saved
    let q = dir.join("new.json");
    let s = Store::open_at(q.clone(), None, None, false);
    assert!(!s.read_only && q.exists() && !s.data.entries.is_empty());
    // WebDAV unreachable and no local copy: no sample that would go up over the server's list
    let r = dir.join("dav.json");
    let s = Store::open_at(r.clone(), Some(crate::remote::RemoteConfig::default()), Some(Err("offline".into())), false);
    assert!(s.read_only && !r.exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn webdav_answer_is_checked_before_it_replaces_the_local_copy() {
    // D6
    let dir = review_dir("d6");
    let p = dir.join("connections-webdav.json");
    let local = serde_json::to_string(&sample_data()).unwrap();
    std::fs::write(&p, &local).unwrap();
    let s = Store::open_at(p.clone(), Some(crate::remote::RemoteConfig::default()), Some(Ok(Some("<html>login</html>".into()))), false);
    assert!(s.read_only && s.last_error.is_some());
    assert_eq!(std::fs::read_to_string(&p).unwrap(), local);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn shared_folder_save_does_not_overwrite_a_colleague() {
    // D7
    let dir = review_dir("d7");
    let p = dir.join("connections.json");
    let mut a = temp_store("d7a");
    a.path = p.clone();
    a.save();
    assert!(a.last_error.is_none());
    let mut b = temp_store("d7b");
    b.path = p.clone();
    assert!(b.reload_from_disk_for_test());
    b.data.entries[0].name = "theirs".into();
    b.save();
    assert!(b.last_error.is_none(), "{:?}", b.last_error);
    a.data.entries[1].name = "ours".into();
    a.save();
    let disk = std::fs::read_to_string(&p).unwrap();
    assert!(disk.contains("\"theirs\"") && !disk.contains("\"ours\""), "the colleague's list stays");
    assert!(a.last_error.is_some());
    assert_eq!(a.data.entries[0].name, "theirs", "reloaded");
    let names: Vec<String> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    let side = names.iter().find(|n| n.contains("conflict-")).expect("our version is kept");
    assert!(std::fs::read_to_string(dir.join(side)).unwrap().contains("\"ours\""));
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "no temporary file left: {names:?}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sealed_list_in_keepass_asks_for_keepass_after_the_master_password() {
    // D8
    use crate::kdbx::Key;
    let dir = review_dir("d8");
    let ps = empty_kdbx(&dir, "kp-d8");
    let mut s = temp_store("d8");
    s.path = dir.join("connections.json");
    s.data.settings.keepass_path = ps;
    s.use_keepass(Key { password: "kp-d8".into(), keyfile: String::new() }).unwrap();
    let n = s.data.entries.len();
    s.data.settings.encrypt_file = true;
    s.set_master("M-d8");
    assert!(s.last_error.is_none(), "{:?}", s.last_error);
    let mut t = temp_store("d8b");
    t.path = s.path.clone();
    t.vault = None;
    assert!(t.reload_from_disk_for_test());
    assert!(t.locked());
    assert!(t.unlock("M-d8"));
    assert!(t.locked() && t.waiting_for_keepass(), "KeePass is asked for");
    assert!(t.data.entries.is_empty());
    assert!(t.unlock("kp-d8"));
    assert!(!t.locked());
    assert_eq!(t.data.entries.len(), n);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn keepass_save_keeps_entries_added_in_keepass_meanwhile() {
    // D9
    use crate::kdbx::{self, Key};
    let dir = review_dir("d9");
    let ps = empty_kdbx(&dir, "kp-d9");
    let key = Key { password: "kp-d9".into(), keyfile: String::new() };
    let mut s = temp_store("d9");
    s.path = dir.join("connections.json");
    s.data.settings.keepass_path = ps.clone();
    s.use_keepass(key.clone()).unwrap();
    let count = s.data.entries.len();
    // added in KeePass; AdminCraft saves before it reloads
    kdbx::store_password(&ps, &key, "added in KeePass", "u", "p", "ssh://10.9.9.9").unwrap();
    s.data.entries[0].name = "renamed".into();
    s.save();
    let back = kdbx::load(&ps, &key).unwrap();
    assert!(back.iter().any(|e| e.name == "added in KeePass"), "never seen, so never deleted");
    assert!(back.iter().any(|e| e.name == "renamed"));
    // deleted in AdminCraft: removed from KeePass (it was known)
    let leaf = s.data.entries.iter().find(|e| e.name.starts_with("web01 – L")).unwrap().id;
    s.remove(leaf);
    s.save();
    let back = kdbx::load(&ps, &key).unwrap();
    assert_eq!(back.len(), count);
    assert!(!back.iter().any(|e| e.name.starts_with("web01 – L")));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unchanged_keepass_list_is_not_written_again() {
    // C11 / P15
    use crate::kdbx::Key;
    let dir = review_dir("c11");
    let ps = empty_kdbx(&dir, "kp-c11");
    let mut s = temp_store("c11");
    s.path = dir.join("connections.json");
    s.data.settings.keepass_path = ps.clone();
    s.use_keepass(Key { password: "kp-c11".into(), keyfile: String::new() }).unwrap();
    let before = std::fs::read(&ps).unwrap();
    s.data.settings.dark = !s.data.settings.dark;
    s.save();
    assert_eq!(std::fs::read(&ps).unwrap(), before, "a settings change doesn't touch KeePass");
    s.data.entries[1].name = "changed".into();
    s.save();
    assert_ne!(std::fs::read(&ps).unwrap(), before);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unchanged_list_saves_byte_for_byte() {
    // P14
    let dir = review_dir("p14");
    let mut s = temp_store("p14");
    s.path = dir.join("connections.json");
    let i = s.index_of(4).unwrap();
    s.data.entries[i].password = "pw-1".into();
    s.save();
    let first = std::fs::read(&s.path).unwrap();
    s.save();
    assert_eq!(std::fs::read(&s.path).unwrap(), first);
    // a changed password is encrypted anew and opens to the new one
    let old = s.data.entries[i].password_enc.clone();
    s.data.entries[i].password = "pw-2".into();
    s.save();
    let new = s.data.entries[i].password_enc.clone().unwrap();
    assert_ne!(Some(new.clone()), old);
    assert_eq!(s.vault.as_ref().unwrap().decrypt(&new).as_deref(), Some("pw-2"));
    // the whole list sealed with the master password
    s.data.settings.encrypt_file = true;
    s.set_master("M-p14");
    let sealed = std::fs::read(&s.path).unwrap();
    s.save();
    assert_eq!(std::fs::read(&s.path).unwrap(), sealed);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn parent_loops_and_repeated_ids_cannot_hang_or_double() {
    // C2 (and repeated ids, C3/D14)
    use crate::model::{DataFile, Entry};
    let mut s = temp_store("c2");
    s.data.entries = vec![
        Entry { id: 1, parent: Some(2), folder: true, ..Default::default() },
        Entry { id: 2, parent: Some(1), folder: true, ..Default::default() },
        Entry { id: 3, parent: Some(2), ..Default::default() },
        Entry { id: 4, ..Default::default() },
    ];
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        s.remove(1);
        let _ = tx.send(s.data.entries.iter().map(|e| e.id).collect::<Vec<_>>());
    });
    let left = rx.recv_timeout(std::time::Duration::from_secs(20)).expect("remove must not loop");
    assert_eq!(left, vec![4]);
    // an import with a loop, an entry that is its own parent and a repeated id
    let mut other = temp_store("c2b");
    let before = other.data.entries.len();
    let imported = vec![
        Entry { id: 7, parent: Some(8), folder: true, name: "x".into(), ..Default::default() },
        Entry { id: 8, parent: Some(7), folder: true, name: "y".into(), ..Default::default() },
        Entry { id: 9, parent: Some(9), name: "self".into(), ..Default::default() },
        Entry { id: 7, name: "twin".into(), ..Default::default() },
    ];
    let (fid, _) = crate::sharing::merge(&mut other, imported, Default::default(), "Import");
    let new: Vec<Entry> = other.data.entries[before + 1..].to_vec();
    let ids: std::collections::HashSet<u64> = new.iter().map(|e| e.id).collect();
    assert_eq!(ids.len(), 4, "every imported entry gets its own id");
    for e in &new {
        assert_ne!(e.parent, Some(e.id));
        assert!(other.is_descendant(e.id, fid), "{} ends up in the import folder", e.name);
    }
    // a damaged data file: the twin gets a new id, the loop is broken
    let dir = review_dir("c2");
    let mut s = temp_store("c2c");
    s.path = dir.join("connections.json");
    let d = DataFile {
        entries: vec![
            Entry { id: 5, name: "a".into(), ..Default::default() },
            Entry { id: 5, name: "b".into(), ..Default::default() },
            Entry { id: 6, parent: Some(6), ..Default::default() },
        ],
        ..Default::default()
    };
    std::fs::write(&s.path, serde_json::to_string(&d).unwrap()).unwrap();
    assert!(s.reload_from_disk_for_test());
    let ids: std::collections::HashSet<u64> = s.data.entries.iter().map(|e| e.id).collect();
    assert_eq!(ids.len(), 3);
    assert_eq!(s.get(6).unwrap().parent, None);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ids_never_overflow() {
    // D14
    use crate::model::Entry;
    let mut s = temp_store("d14");
    s.data.entries.push(Entry { id: u64::MAX, ..Default::default() });
    let old: std::collections::HashSet<u64> = s.data.entries.iter().map(|e| e.id).collect();
    let a = s.next_id();
    let b = s.next_id();
    assert!(a != b && !old.contains(&a) && !old.contains(&b));
    s.data.entries.push(Entry { id: a, ..Default::default() });
    let c = s.next_id();
    assert!(c != a && c != b && !old.contains(&c));
}

#[test]
fn imports_keep_protocol_hostname_and_ipv6() {
    // D15
    use crate::kdbx::{parse_url, url_of};
    let xml = r#"<mrng:Connections Name="Connections" KdfIterations="1000" FullFileEncryption="false" Protected="">
  <Node Name="raw" Type="Connection" Protocol="RAW" Hostname="10.0.0.1" Port="5000" />
  <Node Name="rl" Type="Connection" Protocol="RLOGIN" Hostname="10.0.0.2" Port="513" />
</mrng:Connections>"#;
    let imp = crate::import::import_mremoteng(xml, "", 10, None).unwrap();
    assert_eq!(imp.entries[0].protocol, Protocol::Raw);
    assert_eq!(imp.entries[1].protocol, Protocol::Rlogin);
    let cfg = "Host web\n  HostName %h.corp.local\nHost odd\n  HostName 100%%.example\n";
    let v = crate::import::import_ssh_config(cfg, 1, None);
    assert_eq!(v[0].host, "web.corp.local");
    assert_eq!(v[1].host, "100%.example");
    let e = crate::model::Entry { protocol: Protocol::Https, host: "fe80::1".into(), port: 443, ..Default::default() };
    assert_eq!(url_of(&e), "https://[fe80::1]/");
    assert_eq!(parse_url(&url_of(&e)), Some((Protocol::Https, "fe80::1".into(), 443)));
    let e = crate::model::Entry { protocol: Protocol::Ssh, host: "2001:db8::5".into(), port: 2222, ..Default::default() };
    assert_eq!(url_of(&e), "ssh://[2001:db8::5]:2222");
    assert_eq!(parse_url(&url_of(&e)), Some((Protocol::Ssh, "2001:db8::5".into(), 2222)));
    assert_eq!(parse_url("2001:db8::5"), Some((Protocol::Ssh, "2001:db8::5".into(), 22)));
}

#[test]
fn mremoteng_kdf_iterations_are_limited() {
    // C8
    for n in ["4000000000", "0", "1000001", "lots"] {
        let xml = format!(
            r#"<mrng:Connections Name="Connections" KdfIterations="{n}" Protected=""><Node Name="a" Type="Connection" Protocol="SSH2" Hostname="h" /></mrng:Connections>"#
        );
        let err = crate::import::import_mremoteng(&xml, "", 1, None).err().unwrap_or_else(|| panic!("{n} accepted"));
        assert!(err.contains("KdfIterations"), "{err}");
    }
}

#[test]
fn keepass_host_lookup_needs_the_whole_host() {
    // S3
    use crate::model::KeePassRef;
    use keepass::db::fields;
    let mut db = keepass::Database::new();
    let bin;
    {
        let mut root = db.root_mut();
        {
            let mut g = root.add_group();
            g.name = "Trash".into();
            bin = g.id();
            let mut e = g.add_entry();
            e.set_unprotected(fields::TITLE, "deleted 10.0.0.99");
            e.set_protected(fields::PASSWORD, "old");
        }
        {
            let mut g = root.add_group();
            g.name = "Recycle Bin".into();
            let mut e = g.add_entry();
            e.set_unprotected(fields::TITLE, "kept");
        }
        {
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "fw 10.0.0.10");
            e.set_protected(fields::PASSWORD, "pw-fw");
        }
        {
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "root@10.0.0.2 shell");
        }
    }
    db.meta.recyclebin_uuid = Some(bin.uuid());
    let dir = review_dir("s3");
    let path = dir.join("s3.kdbx");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        db.save(&mut f, keepass::DatabaseKey::new().with_password("kp-s3")).unwrap();
    }
    let mut v = crate::keepass_vault::KeePassVault::default();
    v.open(path.to_str().unwrap(), "kp-s3", "").unwrap();
    assert!(v.find(&KeePassRef::Host("10.0.0.1".into())).is_none(), "10.0.0.10 is another host");
    assert_eq!(v.find(&KeePassRef::Host("10.0.0.10".into())).unwrap().password, "pw-fw");
    assert_eq!(v.find(&KeePassRef::Host("10.0.0.2".into())).unwrap().title, "root@10.0.0.2 shell");
    assert!(v.find(&KeePassRef::Host("10.0.0.99".into())).is_none(), "the recycle bin is skipped");
    assert!(v.entries.iter().any(|e| e.title == "kept"), "a group is skipped by being the bin, not by its name");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn keepass_key_never_shows_its_password() {
    // S20
    let k = crate::kdbx::Key { password: "s3cret-pw".into(), keyfile: "key.keyx".into() };
    let shown = format!("{k:?}");
    assert!(!shown.contains("s3cret-pw") && shown.contains("key.keyx"), "{shown}");
}

#[test]
fn exit_waits_for_the_last_webdav_upload_but_not_forever() {
    use std::time::{Duration, Instant};
    let s = temp_store("upload-wait");
    assert!(s.wait_for_upload(Duration::from_secs(1)), "nothing to send: no wait");
    s.remote_state.lock().unwrap().uploading = true;
    let state = s.remote_state.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        state.lock().unwrap().uploading = false;
    });
    assert!(s.wait_for_upload(Duration::from_secs(5)), "the upload finished in time");
    t.join().unwrap();
    s.remote_state.lock().unwrap().pending_upload = Some("text".into());
    let started = Instant::now();
    assert!(!s.wait_for_upload(Duration::from_millis(200)), "a stuck upload doesn't keep the program open");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn webdav_password_under_the_master_password() {
    use crate::remote::RemoteConfig;
    let master = Vault::derive("master", &new_salt()).unwrap();
    let mut c = RemoteConfig::new("https://dav.example.com/it/".into(), "admin".into());
    c.set_password("dav-secret", Some(&master));
    assert_eq!(c.password(), "dav-secret");
    let json = serde_json::to_string(&c).unwrap();
    assert!(c.password_enc.is_empty(), "nothing under the program's fixed key");
    assert!(!json.contains("dav-secret"));
    assert!(!format!("{c:?}").contains("dav-secret"), "Debug never shows it");
    // the saved settings, read at the next start: locked until the master password is given
    let mut again: RemoteConfig = serde_json::from_str(&json).unwrap();
    assert!(again.needs_unlock());
    assert_eq!(again.password(), "", "no password before the master password");
    let other = Vault::derive("other", &new_salt()).unwrap();
    assert!(!again.open_sealed(&other), "another key doesn't open it");
    assert!(again.open_sealed(&master));
    assert_eq!(again.password(), "dav-secret");
    // master password removed: back under the fixed key, opens without anything
    assert!(again.protect(None));
    let local: RemoteConfig = serde_json::from_str(&serde_json::to_string(&again).unwrap()).unwrap();
    assert!(!local.needs_unlock() && local.password_sealed.is_empty());
    assert_eq!(local.password(), "dav-secret");
    // a locked password can't be moved (it isn't known)
    let mut locked: RemoteConfig = serde_json::from_str(&json).unwrap();
    assert!(!locked.protect(None));
    assert!(locked.needs_unlock());
}
