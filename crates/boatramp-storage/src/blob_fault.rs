//! Blob-READ fault classification + structured logging, shared by the HTTP object-store backends
//! (`s3`, `gcs`, `azure`).
//!
//! Before this, a `get`/`get_range`/`head` fault collapsed into one opaque `StorageError::Backend`
//! string with NO HTTP status / error code / request-id in the logs — so a 403 (under-scoped
//! credential), a 416, a throttle/5xx, or a transport fault were indistinguishable from a genuine
//! 404, which cost a multi-hour misdiagnosis (construens `boatramp-blob-read-error-granularity`). Now
//! each backend extracts `(status, code, request_id)` from its SDK error and routes through
//! [`read_fault`], which classifies the outcome, emits ONE structured log line per failed read (key +
//! op + status + code + request-id + latency), and returns a `StorageError` carrying the detail.
//!
//! Custody: the log + the error carry ONLY key / op / status / code / request-id / latency and a
//! short operator-level backend `reason` — NEVER the object bytes (the body stream is only read after
//! a successful `get`) and NEVER a credential (SDK error display redacts secrets; the guest-facing
//! layer further collapses this to a coarse, non-leaking reason).

use boatramp_core::StorageError;

/// The concrete outcome of a failed blob read, distinguished so an operator (and a potential
/// retry/alert caller) never conflates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobFaultKind {
    /// 404 / `NoSuchKey` — the object really is absent.
    NotFound,
    /// 403 `AccessDenied` — under-scoped credential (the incident: this masqueraded as a 404).
    AccessDenied,
    /// 416 `InvalidRange`.
    InvalidRange,
    /// 503 `SlowDown` / 429 — throttled; a retry may succeed.
    Throttle,
    /// Other 5xx — server-side fault.
    ServerError,
    /// No HTTP response reached us — dispatch / timeout / TLS / connection fault.
    Transport,
    /// Anything else (an unexpected 4xx, etc.).
    Other,
}

/// Classify a read fault from its HTTP `status` (absent ⇒ no response reached us) and the backend
/// error `code`. PURE (no I/O) so it is exhaustively unit-tested without constructing an SDK error —
/// the distinctness of these classes is the load-bearing invariant the incident turned on.
pub(crate) fn classify(status: Option<u16>, code: Option<&str>) -> BlobFaultKind {
    // MUTATION SEAM (gate `flatten_403`): collapse AccessDenied → NotFound, reproducing the EXACT
    // incident (a 403 under-scoped credential indistinguishable from a 404). Compiled out of shipped
    // builds; the classifier distinctness gate then goes RED.
    if fault_mutation().as_deref() == Some("flatten_403") && matches!(code, Some("AccessDenied")) {
        return BlobFaultKind::NotFound;
    }
    match (status, code) {
        (_, Some("NoSuchKey" | "NoSuchBucket")) | (Some(404), _) => BlobFaultKind::NotFound,
        (_, Some("AccessDenied" | "Forbidden")) | (Some(403), _) => BlobFaultKind::AccessDenied,
        (_, Some("InvalidRange" | "InvalidArgument")) | (Some(416), _) => {
            BlobFaultKind::InvalidRange
        }
        (_, Some("SlowDown" | "TooManyRequests")) | (Some(429 | 503), _) => BlobFaultKind::Throttle,
        (Some(s), _) if (500..=599).contains(&s) => BlobFaultKind::ServerError,
        (None, _) => BlobFaultKind::Transport,
        _ => BlobFaultKind::Other,
    }
}

/// The operator log level for a read fault, by `kind` and `op`. The host's default filter is
/// `boatramp=info`, so INFO reaches an operator and DEBUG does not — the levels are chosen against
/// that line:
/// - a **content-read miss** (`get`/`get_range` 404) is the incident shape — an unexpected absence on
///   an object a sibling lane reads — so it is INFO, surfaced with its request-id so an operator can
///   correlate it against the successful lane;
/// - a **HEAD 404** is a routine existence-probe miss (`head` is used across the codebase as
///   `is_ok()`), kept at DEBUG so those do not flood the log;
/// - every **abnormal fault** (403/416/throttle/5xx/transport), on any op, is the surprising,
///   actionable case → WARN.
///
/// Pure (no I/O) so the operator-visibility contract is unit-tested directly, without a subscriber.
fn fault_log_level(kind: BlobFaultKind, op: &str) -> tracing::Level {
    match kind {
        BlobFaultKind::NotFound if op == "head" => tracing::Level::DEBUG,
        BlobFaultKind::NotFound => tracing::Level::INFO,
        _ => tracing::Level::WARN,
    }
}

/// Classify, LOG one structured line, and return the `StorageError` for a failed blob read. `ms` is
/// the measured op latency. A genuine `NotFound` returns the unchanged [`StorageError::NotFound`]
/// variant; every other fault returns the structured [`StorageError::BackendRead`]. The one log line
/// carries key/op/status/code/request-id/latency at the level [`fault_log_level`] picks for the
/// `(kind, op)` pair (the `get`/`get_range` content miss — the incident — is operator-visible at
/// INFO). `reason` is short operator-level backend text.
pub(crate) fn read_fault(
    op: &str,
    key: &str,
    ms: u128,
    status: Option<u16>,
    code: Option<&str>,
    request_id: Option<&str>,
    reason: String,
) -> StorageError {
    let kind = classify(status, code);
    // Unwrap to grep-friendly scalars (status=0 ⇒ no response = transport fault; "-" ⇒ absent).
    let status_f = status.unwrap_or(0);
    let code_f = code.unwrap_or("-");
    let reqid_f = request_id.unwrap_or("-");
    let msg = if matches!(kind, BlobFaultKind::NotFound) {
        "blob read: object not found"
    } else {
        "blob read backend fault"
    };
    // ONE structured line per failed read, at the level chosen for (kind, op). `tracing::event!`
    // needs a CONST level, so dispatch to the static macro for the level `fault_log_level` picked;
    // the local macro keeps the field set single-source across the three arms.
    macro_rules! emit {
        ($level:ident) => {
            tracing::$level!(
                op,
                key,
                status = status_f,
                code = code_f,
                request_id = reqid_f,
                ms,
                kind = ?kind,
                "{msg}"
            )
        };
    }
    match fault_log_level(kind, op) {
        tracing::Level::DEBUG => emit!(debug),
        tracing::Level::INFO => emit!(info),
        _ => emit!(warn),
    }
    if matches!(kind, BlobFaultKind::NotFound) {
        return StorageError::NotFound(key.to_string());
    }
    StorageError::BackendRead {
        reason,
        status,
        code: code.map(str::to_string),
        request_id: request_id.map(str::to_string),
    }
}

/// The active blob-fault mutation (anti-hollow gate), or `None`. Present ONLY under `cfg(test)` or the
/// `blob-fault-gate-mutation` feature; a shipped build has neither, so [`classify`] is unconditional
/// and this is a dead `None`.
#[cfg(any(test, feature = "blob-fault-gate-mutation"))]
fn fault_mutation() -> Option<String> {
    std::env::var("BOATRAMP_BLOBFAULT_MUTATION").ok()
}
#[cfg(not(any(test, feature = "blob-fault-gate-mutation")))]
#[inline]
fn fault_mutation() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GATE — the read-fault classifier maps each S3-compatible outcome to a DISTINCT kind, so a 403 /
    /// 416 / throttle / 5xx / transport fault is never conflated with a genuine 404 (the incident).
    /// Mutation-verified: `BOATRAMP_BLOBFAULT_MUTATION=flatten_403` collapses AccessDenied→NotFound,
    /// turning the 403≠404 assertion RED. Marker `BLOB READ FAULT CLASS OK`.
    #[test]
    fn classifier_distinguishes_every_read_outcome() {
        use BlobFaultKind::*;
        // by status
        assert_eq!(classify(Some(404), None), NotFound);
        assert_eq!(classify(Some(403), None), AccessDenied);
        assert_eq!(classify(Some(416), None), InvalidRange);
        assert_eq!(classify(Some(503), None), Throttle);
        assert_eq!(classify(Some(429), None), Throttle);
        assert_eq!(classify(Some(500), None), ServerError);
        assert_eq!(classify(Some(502), None), ServerError);
        assert_eq!(classify(None, None), Transport); // no response = dispatch/timeout/TLS
        // by code (status may be carried differently by a backend)
        assert_eq!(classify(None, Some("NoSuchKey")), NotFound);
        assert_eq!(classify(None, Some("AccessDenied")), AccessDenied);
        assert_eq!(classify(None, Some("SlowDown")), Throttle);
        assert_eq!(classify(None, Some("InvalidRange")), InvalidRange);
        // THE incident: a 403 must NOT read as a 404.
        assert_ne!(classify(Some(403), Some("AccessDenied")), NotFound);
        // All six fault kinds are mutually distinct.
        let kinds = [
            classify(Some(404), None),
            classify(Some(403), None),
            classify(Some(416), None),
            classify(Some(503), None),
            classify(Some(500), None),
            classify(None, None),
        ];
        for i in 0..kinds.len() {
            for j in (i + 1)..kinds.len() {
                assert_ne!(
                    kinds[i], kinds[j],
                    "fault kinds {i} and {j} must be distinct"
                );
            }
        }
        println!("BLOB READ FAULT CLASS OK");
    }

    /// OBSERVABILITY — the read fault's operator log level is chosen so the incident shape (a
    /// `get`/`get_range` content miss) is visible at the `boatramp=info` default, while routine HEAD
    /// existence-probe misses stay quiet and every abnormal fault is actionable. Locks the contract
    /// construens' Ask 1 verification turns on (a failed consumer `get` 404 must reach the operator).
    #[test]
    fn read_fault_level_surfaces_the_content_miss_but_not_head_probes() {
        use tracing::Level;
        // The incident: a get/get_range 404 is operator-visible (INFO ≥ the `info` default).
        assert_eq!(fault_log_level(BlobFaultKind::NotFound, "get"), Level::INFO);
        assert_eq!(
            fault_log_level(BlobFaultKind::NotFound, "get_range"),
            Level::INFO
        );
        // A HEAD miss is a routine existence probe — kept below the default (DEBUG).
        assert_eq!(
            fault_log_level(BlobFaultKind::NotFound, "head"),
            Level::DEBUG
        );
        // Every abnormal fault is actionable at WARN regardless of op.
        for op in ["get", "get_range", "head"] {
            for kind in [
                BlobFaultKind::AccessDenied,
                BlobFaultKind::InvalidRange,
                BlobFaultKind::Throttle,
                BlobFaultKind::ServerError,
                BlobFaultKind::Transport,
                BlobFaultKind::Other,
            ] {
                assert_eq!(fault_log_level(kind, op), Level::WARN);
            }
        }
    }

    /// CUSTODY — the structured error carries ONLY status/code/request-id + a short reason; it never
    /// embeds the object value or a credential. (The log takes the same fields.)
    #[test]
    fn read_fault_error_carries_no_value_or_credential() {
        let err = read_fault(
            "get",
            "hblob/proj/site/assets-ten_1/abc",
            12,
            Some(403),
            Some("AccessDenied"),
            Some("req-123"),
            "access denied".to_string(),
        );
        let s = format!("{err:?}") + &err.to_string();
        assert!(!s.contains("SECRETBYTES"), "no object bytes in the error");
        assert!(
            !s.to_lowercase().contains("aws_secret"),
            "no credential in the error"
        );
        assert!(matches!(
            err,
            StorageError::BackendRead {
                status: Some(403),
                ..
            }
        ));
    }
}
