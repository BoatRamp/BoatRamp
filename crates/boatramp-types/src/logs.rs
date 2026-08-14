//! Wire DTOs for the captured-guest-logs endpoint: one bounded ring of recent
//! stdout/stderr lines plus the per-site rate-cap drop count. The server
//! captures and serializes these; the operator endpoint and the console tail
//! read them back.

use serde::{Deserialize, Serialize};

/// One captured guest log line, as the logs endpoint returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Process-global monotonic sequence (a stable cursor for `--follow`).
    pub seq: u64,
    /// Capture time (Unix milliseconds).
    pub ts_ms: u64,
    /// Which stream it came from (`stdout` / `stderr`).
    pub stream: String,
    /// The line text (newline stripped).
    pub line: String,
    /// The id of the request that produced this line, when the platform assigned one
    /// (the same id the `boatramp::access` line carries), so a captured line is
    /// correlatable with its request. Absent for lines with no request context (e.g. a
    /// background consumer). Omitted from the wire when absent — backward-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// The logs endpoint response: recent captured lines + the rate-cap drop count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogsResponse {
    /// The captured lines (most recent `limit`, with `seq > after`).
    pub entries: Vec<LogEntry>,
    /// Lines dropped server-side by the per-site rate cap.
    pub dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shape_is_stable() {
        // The exact keys the server emits and the CLI/console read; pinned so
        // moving the DTO here can never silently rename a field.
        let entry = LogEntry {
            seq: 7,
            ts_ms: 1_700_000_000_000,
            stream: "stdout".into(),
            line: "hello".into(),
            request_id: None,
        };
        // `request_id: None` is omitted, so the wire shape is unchanged.
        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            serde_json::json!({
                "seq": 7,
                "ts_ms": 1_700_000_000_000_u64,
                "stream": "stdout",
                "line": "hello",
            })
        );
        // A present request id is emitted for correlation with the access line.
        let tagged = LogEntry {
            request_id: Some("r-42".into()),
            ..entry.clone()
        };
        assert_eq!(
            serde_json::to_value(&tagged).unwrap()["request_id"],
            serde_json::json!("r-42")
        );
        let resp = LogsResponse {
            entries: vec![entry.clone()],
            dropped: 3,
        };
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            serde_json::json!({ "entries": [serde_json::to_value(&entry).unwrap()], "dropped": 3 })
        );
        // Readers that drop `ts_ms` still round-trip since the server always emits it.
        let back: LogEntry = serde_json::from_value(serde_json::to_value(&entry).unwrap()).unwrap();
        assert_eq!(back, entry);
    }
}
