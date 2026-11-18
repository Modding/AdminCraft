//! Settings for web interfaces: which browser opens them in a tab, its profile and arguments.
//! A child module of `app`, so it can reach the window's state.

use super::*;
use crate::model::{BrowserFamily, WebProfile};

/// The key of the browser in the program list (`programs::PROGRAMS`).
const BROWSER: &str = "browser";

/// The browser as last looked for, from the window's program list.
fn browser_in(cache: &HashMap<&'static str, Option<(PathBuf, programs::Source)>>) -> Option<PathBuf> {
    cache.get(BROWSER).cloned().flatten().map(|(p, _)| p)
}

impl AdminApp {
    /// The "Web interfaces" section of the settings; true when something changed.
    pub(super) fn web_settings_ui(&mut self, ui: &mut egui::Ui) -> bool {
        let mut changed = false;
        section_help(ui, tr("Web interfaces"), crate::help::Topic::Settings, &mut self.help_request);
        ui.weak(tr("HTTP/HTTPS connections with \"Open in a tab\" start this browser in a window of its own and put it into the tab (Windows)."));
        changed |= ui
            .add_enabled(cfg!(windows), egui::Checkbox::new(&mut self.store.data.settings.web_all_in_tab, tr("Open every web interface in a tab")))
            .on_hover_text(tr("Off: only connections with \"Open in a tab\" ticked; the others open in the system's browser."))
            .changed();
        let s = &mut self.store.data.settings;
        // the browser is looked for again when its field is left, not on every frame
        let mut recheck = false;
        egui::Grid::new("web_settings").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            ui.label(tr("Browser"));
            ui.horizontal(|ui| {
                let own = s.programs.entry("browser".to_string()).or_default();
                let r = ui.add(egui::TextEdit::singleline(own).hint_text(tr("empty = Edge or Chrome")).desired_width(360.0)).on_hover_text(tr(
                    "The browser's program, e.g. brave.exe, vivaldi.exe or firefox.exe. Take the program itself, not a portable launcher.",
                ));
                changed |= r.changed();
                recheck |= r.lost_focus();
                if own.trim().is_empty() {
                    s.programs.remove("browser");
                }
            });
            ui.end_row();
            ui.label(tr("Kind"));
            ui.horizontal(|ui| {
                for (v, label) in [
                    (BrowserFamily::Auto, tr("Recognise")),
                    (BrowserFamily::Chromium, tr("Chromium-based")),
                    (BrowserFamily::Firefox, tr("Firefox-based")),
                ] {
                    changed |= ui.radio_value(&mut s.web_family, v, label).changed();
                }
            });
            ui.end_row();
            ui.label(tr("Profile"));
            ui.vertical(|ui| {
                changed |= ui
                    .radio_value(&mut s.web_profile, WebProfile::Kept, tr("Own profile per connection, kept in the data folder"))
                    .on_hover_text(tr("Logins and certificate exceptions stay and travel with AdminCraft."))
                    .changed();
                changed |= ui.radio_value(&mut s.web_profile, WebProfile::Temporary, tr("Own profile per connection, temporary")).changed();
                changed |= ui
                    .radio_value(&mut s.web_profile, WebProfile::Normal, tr("The browser's normal profile (not in the tab)"))
                    .on_hover_text(tr(
                        "Your saved passwords and extensions, but the page opens in the browser already running, so it can't be put into a tab.",
                    ))
                    .changed();
            });
            ui.end_row();
            ui.label(tr("Own arguments"));
            changed |=
                ui.add(egui::TextEdit::singleline(&mut s.web_args).hint_text(tr("optional, separated by spaces")).desired_width(360.0)).changed();
            ui.end_row();
        });
        if recheck {
            self.prog_cache.insert(BROWSER, programs::find_with_source(BROWSER, &self.store.data.settings));
        }
        // from the program list the settings page reads when it opens (and on "Search again")
        let found = browser_in(&self.prog_cache);
        match &found {
            Some(p) => {
                let family = launch::browser_family(p, self.store.data.settings.web_family);
                let kind = if family == BrowserFamily::Firefox { tr("Firefox-based") } else { tr("Chromium-based") };
                ui.weak(tf("Uses: {0} ({1})", &[&p.display(), &kind]));
                if family == BrowserFamily::Firefox {
                    ui.weak(tr("Firefox browsers show their tab and address bar in the tab; Chromium browsers open a plain window."));
                }
            }
            None => {
                ui.colored_label(WARN, tr("No browser found – web interfaces open in the system's browser."));
            }
        }
        changed
    }
}
