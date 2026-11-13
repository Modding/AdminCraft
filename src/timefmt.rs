//! Dates and times as text. All calendar conversion goes through `chrono`; times are UTC.

use chrono::{DateTime, Utc};

fn at(unix_secs: i64) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(unix_secs, 0)
}

/// `31.12.2026` — empty for a time chrono can't represent.
pub fn date(unix_secs: i64) -> String {
    at(unix_secs).map(|t| t.format("%d.%m.%Y").to_string()).unwrap_or_default()
}

/// `31.12.2026 23:59`
pub fn date_time(unix_secs: i64) -> String {
    at(unix_secs).map(|t| t.format("%d.%m.%Y %H:%M").to_string()).unwrap_or_default()
}

/// `2026-12-31 23:59 UTC`
pub fn iso_minutes(unix_secs: u64) -> String {
    i64::try_from(unix_secs).ok().and_then(at).map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default()
}

/// Seconds since 1970 of a file time; 0 for a time before that.
pub fn unix_secs(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_secs()).ok()).unwrap_or(0)
}
