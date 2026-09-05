//! Captured guest logs: a per-site bounded ring of recent
//! stdout/stderr lines with a per-site token-bucket rate cap, so a noisy guest
//! can't flood the sink or grow memory unbounded. Implements
//! [`boatramp_handlers::LogSink`], so the engine writes captured lines here as
//! the guest emits them; the operator endpoint + `boatramp logs` read them back.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use boatramp_core::time::now_unix_ms;

use boatramp_core::logs::LogEntry;
use boatramp_handlers::{LogSink, LogStream};
use tokio::sync::broadcast;

/// Live-tail broadcast buffer: how many recent `(site, line)` events a slow SSE
/// subscriber may fall behind before it's force-skipped (then resumes).
const BROADCAST_CAP: usize = 512;

/// Recent lines retained per site.
const DEFAULT_CAPACITY: usize = 1000;
/// Default per-site capture rate (lines/sec) when the site sets no
/// `maxLogRate`.
const DEFAULT_RATE: u32 = 200;
/// Token-bucket depth as a multiple of the rate (allows a short burst).
const BURST_FACTOR: f64 = 2.0;

/// Per-site captured log state: a bounded ring + a token bucket.
struct SiteLog {
    entries: VecDeque<LogEntry>,
    rate: u32,
    tokens: f64,
    last_refill: Instant,
    /// Lines dropped by the rate cap since startup (reported to the operator).
    dropped: u64,
}

impl SiteLog {
    fn new(rate: u32) -> Self {
        Self {
            entries: VecDeque::new(),
            rate: rate.max(1),
            tokens: rate.max(1) as f64,
            last_refill: Instant::now(),
            dropped: 0,
        }
    }

    /// Refill the bucket for elapsed time and try to spend one token.
    fn take_token(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        let depth = self.rate as f64 * BURST_FACTOR;
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(depth);
        if self.tokens < 1.0 {
            self.dropped += 1;
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// The process-wide captured-log store.
pub struct LogStore {
    sites: Mutex<HashMap<String, SiteLog>>,
    capacity: usize,
    default_rate: u32,
    /// Monotonic line sequence (cursor for incremental `--follow`).
    seq: AtomicU64,
    /// Live-tail fan-out: every admitted `(site, entry)` is published here for
    /// SSE subscribers (the console's live log tail). Independent of the ring,
    /// which still backs the polling endpoint + `--follow`.
    events: broadcast::Sender<(String, LogEntry)>,
}

impl Default for LogStore {
    fn default() -> Self {
        Self {
            sites: Mutex::new(HashMap::new()),
            capacity: DEFAULT_CAPACITY,
            default_rate: DEFAULT_RATE,
            seq: AtomicU64::new(0),
            events: broadcast::channel(BROADCAST_CAP).0,
        }
    }
}

impl LogStore {
    /// Set a site's capture rate cap (lines/sec); `None` uses the server default.
    /// Called before dispatch so the cap tracks the live site config.
    pub fn configure(&self, site: &str, rate: Option<u32>) {
        let rate = rate.unwrap_or(self.default_rate).max(1);
        let mut sites = self.sites.lock().unwrap();
        sites
            .entry(site.to_string())
            .or_insert_with(|| SiteLog::new(rate))
            .rate = rate;
    }

    /// The most recent `limit` lines for `site` with `seq > after` (pass
    /// `after = 0` for "from the start of the ring"), optionally filtered to one
    /// stream, plus the total dropped-by-rate-cap count.
    pub fn tail(
        &self,
        site: &str,
        limit: usize,
        after: u64,
        stream: Option<LogStream>,
    ) -> (Vec<LogEntry>, u64) {
        let sites = self.sites.lock().unwrap();
        let Some(site) = sites.get(site) else {
            return (Vec::new(), 0);
        };
        let want = stream.map(LogStream::as_str);
        let filtered: Vec<LogEntry> = site
            .entries
            .iter()
            .filter(|entry| entry.seq > after && want.is_none_or(|s| entry.stream == s))
            .cloned()
            .collect();
        let start = filtered.len().saturating_sub(limit);
        (filtered[start..].to_vec(), site.dropped)
    }

    /// Subscribe to the live `(site, line)` feed for an SSE tail. Each admitted
    /// line (post rate-cap) is delivered; a slow subscriber that falls more than
    /// [`BROADCAST_CAP`] behind skips the gap (`Lagged`) and resumes.
    pub fn subscribe(&self) -> broadcast::Receiver<(String, LogEntry)> {
        self.events.subscribe()
    }
}

impl LogSink for LogStore {
    fn append(&self, scope: &str, stream: LogStream, line: &str) {
        self.append_tagged(scope, None, stream, line);
    }

    fn append_tagged(&self, scope: &str, request_id: Option<&str>, stream: LogStream, line: &str) {
        // Mirror every captured line into the structured server log (`serve.log`) under the
        // `boatramp::guest` target, so an operator tailing `serve.log` sees guest output too —
        // not only the per-site log store / SSE tail. Gated by the tracing level (off at the
        // default `info`, on at `debug`), so it never floods production; it fires before the
        // rate cap so `serve.log` is the full firehose while the API-served ring stays bounded.
        // The `request_id` matches the `boatramp::access` line, so the two correlate.
        tracing::debug!(target: "boatramp::guest", site = scope, request_id, stream = stream.as_str(), "{line}");
        let mut sites = self.sites.lock().unwrap();
        let site = sites
            .entry(scope.to_string())
            .or_insert_with(|| SiteLog::new(self.default_rate));
        if !site.take_token() {
            return; // rate-capped: dropped (counted)
        }
        let entry = LogEntry {
            // 1-based, so the `after = 0` sentinel ("from the start") includes
            // the very first line.
            seq: self.seq.fetch_add(1, Ordering::Relaxed) + 1,
            ts_ms: now_unix_ms(),
            stream: stream.as_str().to_string(),
            line: line.to_string(),
            request_id: request_id.map(str::to_string),
        };
        // Fan out to live SSE tails (best-effort; no subscribers → ignored).
        let _ = self.events.send((scope.to_string(), entry.clone()));
        site.entries.push_back(entry);
        while site.entries.len() > self.capacity {
            site.entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(capacity: usize, default_rate: u32) -> LogStore {
        LogStore {
            sites: Mutex::new(HashMap::new()),
            capacity,
            default_rate,
            seq: AtomicU64::new(0),
            events: broadcast::channel(BROADCAST_CAP).0,
        }
    }

    #[tokio::test]
    async fn subscribe_receives_admitted_lines_for_its_site() {
        let store = store_with(100, 1_000_000);
        let mut rx = store.subscribe();
        store.append("blog", LogStream::Stdout, "hello");
        store.append("other", LogStream::Stdout, "ignored-by-filter");
        let (site, entry) = rx.recv().await.unwrap();
        assert_eq!(site, "blog");
        assert_eq!(entry.line, "hello");
        // The second event is delivered too (the SSE handler filters by site).
        let (site2, _) = rx.recv().await.unwrap();
        assert_eq!(site2, "other");
    }

    #[test]
    fn function_and_site_scopes_are_independent_in_the_shared_store() {
        // One store serves both sites and functions, keyed by scope — the exact scope
        // strings the writer (function_runtime `project.qualified("fn/<name>")`) and the
        // reader (`operator_function_logs`) both compute. A function tail must return
        // only that function's lines, never a site's; and two tenants' same-named
        // functions must not share a namespace.
        let store = store_with(100, 1_000_000);
        store.append("console", LogStream::Stdout, "site line"); // a site
        store.append("fn/identity", LogStream::Stdout, "default fn line"); // default-project fn
        store.append("acme/fn/identity", LogStream::Stdout, "acme fn line"); // tenant fn

        let fn_default = store.tail("fn/identity", 100, 0, None).0;
        assert_eq!(fn_default.len(), 1);
        assert_eq!(fn_default[0].line, "default fn line");

        let fn_acme = store.tail("acme/fn/identity", 100, 0, None).0;
        assert_eq!(fn_acme.len(), 1);
        assert_eq!(fn_acme[0].line, "acme fn line");

        // The site tail is unchanged and never leaks a function's lines.
        let site = store.tail("console", 100, 0, None).0;
        assert_eq!(site.len(), 1);
        assert_eq!(site[0].line, "site line");
    }

    #[test]
    fn ring_keeps_most_recent_within_capacity() {
        let store = store_with(3, 1_000_000); // effectively uncapped rate
        for i in 0..5 {
            store.append("blog", LogStream::Stdout, &format!("line {i}"));
        }
        let (entries, dropped) = store.tail("blog", 10, 0, None);
        assert_eq!(dropped, 0);
        let lines: Vec<_> = entries.iter().map(|e| e.line.as_str()).collect();
        assert_eq!(lines, ["line 2", "line 3", "line 4"]); // oldest evicted
    }

    #[test]
    fn rate_cap_drops_and_counts_excess() {
        // Rate 5/sec, burst depth 10: a tight burst of 100 admits ~10, drops the
        // rest (no wall-clock elapses between calls in the test).
        let store = store_with(1000, 5);
        store.configure("blog", Some(5));
        for i in 0..100 {
            store.append("blog", LogStream::Stderr, &format!("{i}"));
        }
        let (entries, dropped) = store.tail("blog", 1000, 0, None);
        assert!(entries.len() <= 10, "burst exceeded bucket depth");
        assert!(!entries.is_empty(), "some lines should be admitted");
        assert_eq!(entries.len() as u64 + dropped, 100);
    }

    #[test]
    fn stream_filter_selects_one_stream() {
        let store = LogStore::default();
        store.append("blog", LogStream::Stdout, "out");
        store.append("blog", LogStream::Stderr, "err");
        let (only_err, _) = store.tail("blog", 10, 0, Some(LogStream::Stderr));
        assert_eq!(only_err.len(), 1);
        assert_eq!(only_err[0].line, "err");
    }

    #[test]
    fn after_cursor_returns_only_newer_lines() {
        let store = store_with(100, 1_000_000);
        store.append("blog", LogStream::Stdout, "a");
        store.append("blog", LogStream::Stdout, "b");
        let (first, _) = store.tail("blog", 100, 0, None);
        let cursor = first.last().unwrap().seq;
        store.append("blog", LogStream::Stdout, "c");
        let (newer, _) = store.tail("blog", 100, cursor, None);
        let lines: Vec<_> = newer.iter().map(|e| e.line.as_str()).collect();
        assert_eq!(lines, ["c"]);
    }
}
