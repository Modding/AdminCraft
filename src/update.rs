//! "Is there a newer AdminCraft?" Asks GitHub's release list, only when the person presses the
//! button in the settings. Nothing is downloaded or installed; the download page is opened.

use crate::i18n::tf;
use std::cmp::Ordering;

pub const REPO: &str = "Modding/AdminCraft";

/// A semantic version such as `0.1.0-alpha.2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub core: [u64; 3],
    /// The part after `-` split at dots; empty for a final release.
    pub pre: Vec<String>,
}

pub fn parse_version(s: &str) -> Option<Version> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let s = s.split('+').next()?; // build metadata doesn't count
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, p.split('.').map(str::to_string).collect()),
        None => (s, Vec::new()),
    };
    let mut nums = core.split('.').map(|n| n.parse::<u64>().ok());
    let v = [nums.next()??, nums.next().unwrap_or(Some(0))?, nums.next().unwrap_or(Some(0))?];
    Some(Version { core: v, pre })
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core.cmp(&other.core).then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater, // 1.0.0 > 1.0.0-rc.1
            (false, true) => Ordering::Less,
            (false, false) => {
                for (a, b) in self.pre.iter().zip(&other.pre) {
                    let o = match (a.parse::<u64>(), b.parse::<u64>()) {
                        (Ok(x), Ok(y)) => x.cmp(&y),
                        (Ok(_), Err(_)) => Ordering::Less,
                        (Err(_), Ok(_)) => Ordering::Greater,
                        (Err(_), Err(_)) => a.cmp(b),
                    };
                    if o != Ordering::Equal {
                        return o;
                    }
                }
                self.pre.len().cmp(&other.pre.len())
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug)]
pub struct Release {
    pub version: Version,
    pub name: String,
    pub url: String,
    pub prerelease: bool,
    pub published: String,
}

/// The newest release in GitHub's answer (drafts left out, test versions only when wanted).
pub fn newest(json: &str, include_pre: bool) -> Result<Option<Release>, String> {
    let list: Vec<serde_json::Value> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut best: Option<Release> = None;
    for r in list {
        if r["draft"].as_bool().unwrap_or(false) {
            continue;
        }
        let pre = r["prerelease"].as_bool().unwrap_or(false);
        let tag = r["tag_name"].as_str().unwrap_or("").to_string();
        let Some(version) = parse_version(&tag) else { continue };
        if (pre || !version.pre.is_empty()) && !include_pre {
            continue;
        }
        if best.as_ref().is_none_or(|b| version > b.version) {
            best = Some(Release {
                version,
                name: r["name"].as_str().unwrap_or(&tag).to_string(),
                url: r["html_url"].as_str().unwrap_or("").to_string(),
                published: r["published_at"].as_str().unwrap_or("").chars().take(10).collect(),
                prerelease: pre,
            });
        }
    }
    Ok(best)
}

pub fn current() -> Version {
    parse_version(env!("CARGO_PKG_VERSION")).unwrap_or(Version { core: [0, 0, 0], pre: Vec::new() })
}

/// What the check found, in words for the settings page.
#[derive(Clone, Debug)]
pub enum Outcome {
    Newer(Release),
    UpToDate,
}

/// Asks GitHub (blocking; run it in a thread).
pub fn check(include_pre: bool) -> Result<Outcome, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases?per_page=30");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent
        .get(&url)
        .header("User-Agent", concat!("AdminCraft/", env!("CARGO_PKG_VERSION")))
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| tf("GitHub could not be reached: {0}", &[&e]))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(tf("GitHub answered with status {0}. Please try again later.", &[&status]));
    }
    let body = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
    let best = newest(&body, include_pre)?;
    Ok(match best {
        Some(r) if r.version > current() => Outcome::Newer(r),
        _ => Outcome::UpToDate,
    })
}

pub fn releases_page() -> String {
    format!("https://github.com/{REPO}/releases")
}

/// One line for the settings page.
pub fn describe(o: &Outcome) -> String {
    match o {
        Outcome::Newer(r) if r.prerelease => tf("New test version available: {0} (from {1}).", &[&r.name, &r.published]),
        Outcome::Newer(r) => tf("New version available: {0} (from {1}).", &[&r.name, &r.published]),
        Outcome::UpToDate => tf("AdminCraft {0} is the newest version.", &[&env!("CARGO_PKG_VERSION")]),
    }
}
