#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod admintools;
mod agent;
mod app;
mod control;
mod embed;
mod extra;
mod help;
mod netscan;
mod nettools;
mod playback;
mod i18n;
mod import;
mod kdbx;
mod keepass_vault;
mod launch;
mod model;
mod programs;
mod remote;
mod sharing;
mod terminal;
mod tools;
mod tooltabs;
mod transfer;
mod update;
#[cfg(test)]
mod tests;

use eframe::egui;

/// The program icon / logo (honey badger, rounded square, 256 px).
pub const LOGO_PNG: &[u8] = include_bytes!("../assets/icon-256.png");

/// The release build is a window program; started from a terminal, its text output goes to
/// that terminal (unless it is already redirected, e.g. to a pipe).
fn attach_console() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{AttachConsole, GetStdHandle, ATTACH_PARENT_PROCESS, STD_OUTPUT_HANDLE};
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() || h as isize == -1 {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

fn window_icon() -> Option<egui::IconData> {
    let img = image::load_from_memory(LOGO_PNG).ok()?.to_rgba8();
    Some(egui::IconData { width: img.width(), height: img.height(), rgba: img.into_raw() })
}

fn main() -> eframe::Result<()> {
    // OpenSSH asks AdminCraft for a password (file transfer, outside terminal window).
    if std::env::var_os("AC_ASKPASS").is_some() {
        let prompt = std::env::args().nth(1).unwrap_or_default();
        std::process::exit(transfer::askpass_main(&prompt));
    }
    {
        let a: Vec<String> = std::env::args().collect();
        match a.get(1).map(String::as_str) {
            Some("cli") => {
                attach_console();
                std::process::exit(agent::cli(&a[2..]));
            }
            Some("mcp") => std::process::exit(agent::mcp_main()),
            _ => {}
        }
    }
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        attach_console();
        println!("AdminCraft {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    {
        let a: Vec<String> = std::env::args().collect();
        if a.len() >= 4 && a[1] == "--netscan-check" {
            // admincraft --netscan-check <range> <report file>: scans and writes what it found
            let report = match netscan::parse_targets(&a[2]) {
                Err(e) => format!("ERROR: {e}\n"),
                Ok(targets) => {
                    let ctx = egui::Context::default();
                    let ports = tools::parse_ports(netscan::DEFAULT_PORTS).unwrap_or_default();
                    let scan = netscan::NetScan::start(targets, ports, 700, true, ctx);
                    let t0 = std::time::Instant::now();
                    while !scan.state.lock().unwrap().finished && t0.elapsed().as_secs() < 120 {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    let st = scan.state.lock().unwrap();
                    let mut r = format!("finished={} total={} found={} secs={:.1}\n", st.finished, st.total, st.hosts.len(), st.seconds);
                    for h in &st.hosts {
                        r.push_str(&format!("{} name={} mac={} rtt={:?} ports={:?}\n", h.ip, h.name, h.mac, h.rtt_ms, h.ports));
                    }
                    r
                }
            };
            let _ = std::fs::write(&a[3], &report);
            println!("{report}");
            return Ok(());
        }
        if a.len() >= 6 && a[1] == "--transfer-check" {
            let report = transfer::cli_check(&a[2], &a[3], &a[4], std::path::Path::new(&a[5]));
            let _ = std::fs::write(std::path::Path::new(&a[5]).join("report.txt"), &report);
            println!("{report}");
            return Ok(());
        }
    }
    if std::env::var_os("ADMINCRAFT_DEBUG").is_some() {
        eprintln!("[admincraft] start");
    }
    let args: Vec<String> = std::env::args().collect();
    let screenshot = args
        .iter()
        .position(|a| a == "--screenshot")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from);

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("AdminCraft")
        .with_inner_size([1360.0, 820.0])
        .with_min_inner_size([900.0, 560.0]);
    if let Some(icon) = window_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    if screenshot.is_some() {
        viewport = viewport.with_active(false);
        #[cfg(windows)]
        {
            viewport = viewport.with_window_level(egui::WindowLevel::AlwaysOnBottom);
        }
    }

    let mut options = eframe::NativeOptions { viewport, ..Default::default() };
    #[cfg(target_os = "macos")]
    if screenshot.is_some() {
        options.event_loop_builder = Some(Box::new(|builder| {
            use winit::platform::macos::EventLoopBuilderExtMacOS;
            builder.with_activate_ignoring_other_apps(false);
        }));
    }
    #[cfg(not(target_os = "macos"))]
    let _ = &mut options;

    eframe::run_native(
        "AdminCraft",
        options,
        Box::new(move |cc| Ok(Box::new(app::AdminApp::new(cc, screenshot)))),
    )
}
