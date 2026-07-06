//! Small display helpers shared across views: relative ages and short ids.

/// The current Unix time in seconds (from the browser clock).
pub fn now_unix() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// A short, human relative age for a Unix-seconds timestamp ("3m ago",
/// "2d ago"). `0` (unset) renders as a dash.
pub fn relative_age(unix_secs: u64) -> String {
    if unix_secs == 0 {
        return "—".to_string();
    }
    let now = now_unix();
    let delta = now.saturating_sub(unix_secs);
    let (value, unit) = if delta < 60 {
        (delta, "s")
    } else if delta < 3600 {
        (delta / 60, "m")
    } else if delta < 86_400 {
        (delta / 3600, "h")
    } else {
        (delta / 86_400, "d")
    };
    format!("{value}{unit} ago")
}

/// Truncate a content-hash deployment id to a readable prefix (12 chars).
pub fn short_id(id: &str) -> String {
    if id.len() <= 12 {
        id.to_string()
    } else {
        format!("{}…", &id[..12])
    }
}
