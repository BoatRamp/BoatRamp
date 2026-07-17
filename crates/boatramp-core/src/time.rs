//! The one canonical wall-clock read.
//!
//! Before this module the same `SystemTime::now() → UNIX_EPOCH` helper was
//! copy-pasted a dozen times across the native crates under four different names
//! (`now_unix`, `unix_now`, `now_secs`, `now_ms`). It lives here so a reader
//! meets it once. Wasm targets (the console, the edge Worker) do their own
//! clock read via `js_sys::Date` and never call this — `SystemTime::now()`
//! panics there — so these helpers are native-only by convention.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, saturating to `0` before 1970 (unreachable in
/// practice; keeps callers infallible).
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch, saturating to `0` before 1970.
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
