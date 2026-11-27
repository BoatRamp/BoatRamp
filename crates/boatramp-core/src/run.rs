//! The **run** primitive (PLAN-run-streaming P1) — shared types, the typed event envelope, the
//! tenancy-fenced keyspace, and the durable per-run state record.
//!
//! A **run** is a correlation-scoped, DURABLE, resumable event stream built ON the v0.74
//! consumer-delivery core (the durable claim/lease/ack/retained-log model behind
//! [`Messaging::claim_grouped`](crate::messaging::Messaging::claim_grouped)) — NOT the lossy
//! `Messaging::subscribe` fan-out. This module holds the pieces that are shared between the run
//! ENGINE (`boatramp_server::run_stream`, which drives the durable core) and the guest-facing
//! `boatramp:handlers/run` binding; the engine lives a layer up, next to the other durable-delivery
//! surfaces, so it can reuse the same claim pump.
//!
//! # The run is its OWN durable grouped topic — the keyspace extension (the key review point)
//! The finest grain the durable core offered was `(topic, group)`. A run EXTENDS that to a per-run
//! correlation scope by being its **own durable topic**, under a reserved, tenancy-fenced namespace
//! that is **structurally unreachable by any guest messaging producer**:
//!
//! ```text
//!   run_topic = "{project}/.boatramp-run/{scope}/{run_id}"
//! ```
//!
//! - `{project}` is the project-qualified root (the same root [`bus_namespace`] builds on).
//! - `.boatramp-run` is a RESERVED path segment. A guest's `wasi:messaging` producer can name only
//!   `{project}/bus/…` (`bus:<topic>`) or its component-private `{project}/{site}/…` namespace; a
//!   site/project name is a strict slug that can NEVER begin with `.` (see
//!   [`validate_resource_name`](crate::project::validate_resource_name)), and `.boatramp*` is itself
//!   a reserved object-key segment (see [`validate_object_key`](crate::project::validate_object_key)).
//!   So no guest producer — and no authenticated external bus consumer, which screens the topic with
//!   `validate_object_key` AND is rooted at `{project}/bus/` — can ever address a run topic.
//! - `{scope}` fences the run to its creator's **tenant** (see [`run_scope_segment`]): a run created
//!   by tenant A is keyed under A's scope, so a `run_id` presented by tenant B composes to a DIFFERENT
//!   key (B's scope) that does not exist — cross-tenant reach is structurally impossible, and the
//!   `run_id` is a 128-bit-random, unguessable token on top.
//!
//! Emitting an event = publishing the serialized [`RunEnvelope`] to the run topic (retained in the
//! durable grouped log, because a retention group is registered at create); attaching = draining that
//! retained log as a consumer group in `seq` order, resumable after a cursor with no loss. All the
//! durability (lease / ack / retained log / at-least-once) is inherited from the unchanged
//! `claim_grouped` core — this module adds only the correlation scope, the envelope, and the
//! per-run state.

use serde::{Deserialize, Serialize};

use crate::time::now_unix_ms;

/// The reserved namespace segment a run topic is rooted under, immediately below the project root.
/// A guest producer can never name it (a site/project slug cannot begin with `.`, and `.boatramp*`
/// is a reserved object-key segment), so the whole run keyspace is unreachable from the data plane.
pub const RUN_NAMESPACE: &str = ".boatramp-run";

/// The durable **retention** consumer group seeded at run-create. Registering it makes every emit
/// land in the retained grouped log (not the delete-on-ack work-queue), and because it is NEVER
/// advanced after seeding, its retention low-water pins the whole event log for the run's life — so
/// any (re)attach replays from the start with no loss. A single clean group segment (never `/`).
pub const RUN_RETENTION_GROUP: &str = "ret";

/// Upper bound on a single run event payload (bounds host memory + the envelope size). The payload is
/// opaque JSON bytes supplied by the guest; a larger one is refused at emit ([`RunError::Invalid`]).
pub const RUN_PAYLOAD_MAX: usize = 1024 * 1024;

/// The tenancy **scope segment** of a run topic, composed by the HOST from THIS invocation's resolved
/// own-tenant (never guest-supplied). A resolved tenant `t` maps to `t_{t}`; an unresolved tenant (a
/// single-tenant / unscoped invocation) maps to the fixed sentinel `u`. The `t_` prefix is
/// host-added, so a tenanted scope is always `t_…` and the untenanted scope is exactly `u` — the two
/// spaces are disjoint, and two distinct tenants map to distinct scopes, so a run is reachable ONLY by
/// its own tenant (a different resolved tenant composes a different key).
#[must_use]
pub fn run_scope_segment(resolved_tenant: Option<&str>) -> String {
    match resolved_tenant {
        Some(tenant) => format!("t_{tenant}"),
        None => "u".to_string(),
    }
}

/// The durable topic for a run — tenancy-fenced and structurally unreachable by any guest producer
/// (see the module docs). `project` is the bare project name (`ProjectRef::as_str`); the topic is
/// `{project}/.boatramp-run/{scope}/{run_id}`, a SIBLING of the `{project}/bus/…` namespace
/// (`ProjectRef::qualified` is uniformly `{project}/{base}`), so a run is confined to its project
/// exactly like the project bus. `scope` comes from [`run_scope_segment`]; `run_id` is a server-minted
/// token ([`mint_run_id`]).
#[must_use]
pub fn run_topic(project: &str, scope: &str, run_id: &str) -> String {
    format!("{project}/{RUN_NAMESPACE}/{scope}/{run_id}")
}

/// KV key for a run's durable [`RunState`] record (the source of truth for status + the `seq`
/// allocator). Keyed by the full run topic, so it shares the run's tenancy fence.
#[must_use]
pub fn run_state_key(run_topic: &str) -> String {
    format!("runstate/{run_topic}")
}

/// The kind of a run event. `progress` is the only NON-terminal kind; `result`, `error`, `end`, and
/// `cancelled` each conclude the run (and end the attach stream). `cancelled` is a DISTINCT terminal
/// outcome from `error`/`end` (a deliberate stop, not a failure or a clean finish).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunEventKind {
    /// An intermediate progress event (0 or more per run).
    Progress,
    /// The run's success result payload — terminal.
    Result,
    /// The run failed — terminal.
    Error,
    /// The run finished cleanly with no distinct result payload — terminal.
    End,
    /// The run was cancelled (drop-cancel or explicit) — terminal, distinct from `error`/`end`.
    Cancelled,
}

impl RunEventKind {
    /// Whether this kind CONCLUDES the run (everything but [`Progress`](Self::Progress)).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Progress)
    }

    /// The [`RunStatus`] a terminal kind drives the run to (`Progress` has no terminal status).
    #[must_use]
    pub fn terminal_status(self) -> Option<RunStatus> {
        match self {
            Self::Progress => None,
            Self::Result | Self::End => Some(RunStatus::Ended),
            Self::Error => Some(RunStatus::Errored),
            Self::Cancelled => Some(RunStatus::Cancelled),
        }
    }
}

/// A run's lifecycle status, held in its [`RunState`] record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    /// The run is open — emits are accepted.
    Active,
    /// The run ended cleanly (a `result`/`end` event was emitted).
    Ended,
    /// The run ended with an `error` event.
    Errored,
    /// The run was cancelled (a `cancelled` event was emitted).
    Cancelled,
}

/// One typed run event as it rides the durable log (the serialized message payload). `payload` is
/// opaque JSON bytes — the guest's own event — and `seq` is the monotonic, per-run durable resume
/// cursor the attacher reports back to resume losslessly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunEnvelope {
    /// The run this event belongs to.
    pub run_id: String,
    /// Monotonic per-run sequence — the durable resume cursor (strictly increasing across a run).
    pub seq: u64,
    /// The event kind.
    pub kind: RunEventKind,
    /// Emit time, unix milliseconds.
    pub timestamp_ms: u64,
    /// The opaque event payload (JSON bytes; the guest's event body).
    pub payload: Vec<u8>,
}

/// A run's durable state record — the source of truth for its status and `seq` allocator. One compact
/// KV value per run, CAS-updated so the `seq` reservation and the terminal transition are atomic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunState {
    /// Pinned schema discriminant (`v1`), like every boatramp schema record.
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// Lifecycle status.
    pub status: RunStatus,
    /// The NEXT `seq` to hand out (the monotonic allocator; starts at 0).
    pub next_seq: u64,
    /// The `seq` of the terminal event, once one has been emitted (so an attach whose `after-seq`
    /// already covers the terminal can end immediately instead of parking forever).
    #[serde(default)]
    pub terminal_seq: Option<u64>,
    /// Whether DROP-CANCEL is armed: if every attacher drops before a terminal event, the run is
    /// cancelled (so a long-lived emitter stops). On by default (the plan's default); the creator may
    /// turn it off (e.g. a fire-and-forget run with no watcher).
    pub drop_cancel: bool,
}

impl RunState {
    /// A freshly-created, active run with the `seq` allocator at 0.
    #[must_use]
    pub fn new(drop_cancel: bool) -> Self {
        Self {
            version: crate::schema_version(),
            status: RunStatus::Active,
            next_seq: 0,
            terminal_seq: None,
            drop_cancel,
        }
    }
}

/// Why a run operation failed (the host-internal error; the guest-facing `run-error` is mapped from
/// it a layer up). The `access-denied` posture/grant deny is decided by the binding, never here.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// No such run under THIS invocation's tenant/project — a wrong-tenant `run_id`, one that was
    /// never created, or a fabricated id. The cross-tenant refusal surfaces here (the key does not
    /// exist under the caller's scope).
    #[error("run not found")]
    NotFound,
    /// The run has already ENDED (a `result`/`end`/`error` terminal event was emitted) — a further
    /// emit is refused. A long-lived emitter treats this as "stop".
    #[error("run has already ended")]
    Terminal,
    /// The run was CANCELLED — a further emit is refused. THE STOP SIGNAL a long-lived emitter
    /// observes to genuinely stop (don't keep burning compute).
    #[error("run was cancelled")]
    Cancelled,
    /// The request was malformed (an invalid `run_id`, an over-cap payload). Carries a reason.
    #[error("invalid run request: {0}")]
    Invalid(String),
    /// A backend (messaging / KV) fault. Carries a sanitized reason.
    #[error("run backend error: {0}")]
    Backend(String),
}

/// Mint a new, unguessable run id: `{unix-millis:013}-{128-bit-random:hex}`. Time-sortable (so run
/// topics group by age for a future sweep) with a 128-bit random suffix, so a run id is both unique
/// and unforgeable (a second fence on top of the per-tenant scope). A single clean path segment.
#[must_use]
pub fn mint_run_id() -> String {
    let mut bytes = [0u8; 16];
    // getrandom is the same CSPRNG the auth/token paths use; a failure here is unrecoverable
    // (no entropy source), so panic rather than mint a predictable id.
    getrandom::getrandom(&mut bytes).expect("getrandom for run id");
    let mut hex = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    format!("{:013}-{hex}", now_unix_ms())
}

/// Validate a guest-presented `run_id` as a single clean key segment before it is ever composed into
/// a run topic: non-empty, bounded, and free of a path separator / `*` / control bytes (so it can
/// never reshape the key or escape the run namespace). A server-minted id always passes; a
/// fabricated/garbage id is refused loudly here.
pub fn validate_run_id(run_id: &str) -> Result<(), RunError> {
    if run_id.is_empty() {
        return Err(RunError::Invalid("run id must not be empty".into()));
    }
    if run_id.len() > 128 {
        return Err(RunError::Invalid("run id must not exceed 128 bytes".into()));
    }
    for c in run_id.chars() {
        match c {
            '/' | '\\' => {
                return Err(RunError::Invalid(
                    "run id must not contain a path separator".into(),
                ));
            }
            '*' => return Err(RunError::Invalid("run id must not contain '*'".into())),
            c if c.is_control() => {
                return Err(RunError::Invalid(
                    "run id must not contain control characters".into(),
                ));
            }
            _ => {}
        }
    }
    if run_id == "." || run_id == ".." {
        return Err(RunError::Invalid("run id must not be '.' or '..'".into()));
    }
    Ok(())
}

/// Serialize a [`RunEnvelope`] for the durable log. Infallible in practice (plain data), mapped to a
/// [`RunError::Backend`] on the impossible serializer failure.
pub fn encode_envelope(env: &RunEnvelope) -> Result<Vec<u8>, RunError> {
    serde_json::to_vec(env).map_err(|e| RunError::Backend(format!("envelope encode: {e}")))
}

/// Decode a [`RunEnvelope`] off the durable log. A malformed record (never written by this host) is a
/// [`RunError::Backend`].
pub fn decode_envelope(bytes: &[u8]) -> Result<RunEnvelope, RunError> {
    serde_json::from_slice(bytes).map_err(|e| RunError::Backend(format!("envelope decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_topic_is_rooted_under_the_reserved_namespace() {
        let topic = run_topic("acme", &run_scope_segment(Some("firm-a@x.com")), "123-ab");
        assert_eq!(topic, "acme/.boatramp-run/t_firm-a@x.com/123-ab");
        // The second segment is the reserved `.boatramp*` namespace a guest producer can never name
        // (a site/project slug cannot begin with '.', and `.boatramp*` is a reserved object-key seg).
        assert_eq!(topic.split('/').nth(1), Some(RUN_NAMESPACE));
    }

    #[test]
    fn tenant_scopes_are_disjoint_and_fence_cross_tenant() {
        let a = run_topic("acme", &run_scope_segment(Some("a")), "RID");
        let b = run_topic("acme", &run_scope_segment(Some("b")), "RID");
        // The SAME run id under two tenants composes two DIFFERENT keys — tenant B cannot reach A's run.
        assert_ne!(a, b);
        // A tenanted scope is always `t_…`; the untenanted sentinel is exactly `u` — disjoint spaces,
        // so a tenant literally named `u` still never collides with the untenanted scope.
        let tenanted_u = run_topic("acme", &run_scope_segment(Some("u")), "RID");
        let untenanted = run_topic("acme", &run_scope_segment(None), "RID");
        assert_ne!(tenanted_u, untenanted);
        assert_eq!(untenanted, "acme/.boatramp-run/u/RID");
        assert_eq!(tenanted_u, "acme/.boatramp-run/t_u/RID");
    }

    #[test]
    fn terminal_classification() {
        assert!(!RunEventKind::Progress.is_terminal());
        for k in [
            RunEventKind::Result,
            RunEventKind::Error,
            RunEventKind::End,
            RunEventKind::Cancelled,
        ] {
            assert!(k.is_terminal());
            assert!(k.terminal_status().is_some());
        }
        assert_eq!(
            RunEventKind::Cancelled.terminal_status(),
            Some(RunStatus::Cancelled)
        );
        assert_eq!(
            RunEventKind::Error.terminal_status(),
            Some(RunStatus::Errored)
        );
        assert_eq!(
            RunEventKind::Result.terminal_status(),
            Some(RunStatus::Ended)
        );
    }

    #[test]
    fn envelope_round_trips() {
        let env = RunEnvelope {
            run_id: "r1".into(),
            seq: 7,
            kind: RunEventKind::Progress,
            timestamp_ms: 12345,
            payload: b"{\"stage\":\"ocr\"}".to_vec(),
        };
        let bytes = encode_envelope(&env).unwrap();
        assert_eq!(decode_envelope(&bytes).unwrap(), env);
    }

    #[test]
    fn minted_ids_are_unique_well_formed_and_validate() {
        let a = mint_run_id();
        let b = mint_run_id();
        assert_ne!(a, b, "128-bit random suffix must make ids unique");
        validate_run_id(&a).unwrap();
        // The minted id is a clean single segment.
        assert!(!a.contains('/'));
    }

    #[test]
    fn validate_run_id_rejects_traversal_and_shaping() {
        for bad in ["", "a/b", "a\\b", "with*star", ".", "..", "ctrl\u{0}byte"] {
            assert!(validate_run_id(bad).is_err(), "must reject {bad:?}");
        }
        validate_run_id("1700000000000-0123456789abcdef0123456789abcdef").unwrap();
    }
}
