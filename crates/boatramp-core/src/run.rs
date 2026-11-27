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
//! - `.boatramp-run` is a RESERVED path segment, immediately below the project root and a SIBLING of
//!   the `{project}/bus/…` and component-private `{project}/{site}/…` namespaces a guest can reach.
//!   The guest-unreachability guarantee on the `wasi:messaging` PUBLISH path is the **host-rooting
//!   prefix + opaque-key** invariant — NOT an object-key check. The host prepends a host-chosen root
//!   to every guest topic (`{project}/bus/` for a `bus:<topic>`, else the component-private
//!   `{project}/{site}/`) and the guest's string rides only as an opaque SUFFIX (see
//!   `MessagingBinding::namespace` in `boatramp-handlers`). The guest controls neither the leading
//!   project segment nor the root segment after it (always `bus` or a `{site}` slug — a strict slug
//!   that can NEVER begin with `.`, see
//!   [`validate_resource_name`](crate::project::validate_resource_name)), so a guest topic composes
//!   to `{project}/bus/<anything>` or `{project}/{site}/<anything>` and can never reach the sibling
//!   `{project}/.boatramp-run/…`. (The `.boatramp*` object-key reservation —
//!   [`validate_object_key`](crate::project::validate_object_key) — is a SEPARATE backstop on the
//!   authenticated EXTERNAL bus-consumer path, which screens the topic AND is rooted at
//!   `{project}/bus/`. The guest publish path does NOT call it, so this fence must not rely on it —
//!   a future refactor of the reserved-key check must not weaken the run keyspace.)
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
//!
//! # Single-emitter model (one run ⇔ one task)
//! A run is **single-emitter** by design: exactly one task emits to a given run over its lifetime.
//! An attach delivers that run's events in `seq` order and ENDS on the FIRST terminal event. The `seq`
//! allocator ([`RunState::next_seq`], a CAS) keeps every reserved `seq` unique and monotonic even
//! under concurrent emitters, but two tasks emitting to the SAME run is NOT a supported pattern: their
//! events can interleave in an order neither intends, and whichever emits a terminal first concludes
//! the run and ends every attach (the other emitter then observes the stop). A fan-in of several
//! producers belongs on its own `bus:` topic with a consumer that drives one run. (P2's run-scoped
//! token is minted for one run ⇒ one emitting task, reinforcing this model at the external door.)

use serde::{Deserialize, Serialize};

use crate::time::now_unix_ms;

/// The reserved namespace segment a run topic is rooted under, immediately below the project root —
/// a SIBLING of the `{project}/bus/…` and `{project}/{site}/…` namespaces. A guest `wasi:messaging`
/// producer can never address it: the host roots every guest topic under a host-chosen prefix
/// (`{project}/bus/` or the component-private `{project}/{site}/`) with the guest string as an opaque
/// suffix, so a guest topic can never reach this sibling root (the host-rooting-prefix invariant — NOT
/// an object-key check, which the guest publish path does not run). So the whole run keyspace is
/// unreachable from the data plane.
pub const RUN_NAMESPACE: &str = ".boatramp-run";

/// The durable **retention** consumer group seeded at run-create. Registering it makes every emit
/// land in the retained grouped log (not the delete-on-ack work-queue), and because it is NEVER
/// advanced after seeding, its retention low-water pins the whole event log for the run's life — so
/// any (re)attach replays from the start with no loss. A single clean group segment (never `/`).
pub const RUN_RETENTION_GROUP: &str = "ret";

/// Upper bound on a single run event payload (bounds host memory + the envelope size). The payload is
/// opaque JSON bytes supplied by the guest; a larger one is refused at emit ([`RunError::Invalid`]).
pub const RUN_PAYLOAD_MAX: usize = 1024 * 1024;

/// Per-run cap on the number of NON-terminal (`progress`) events a run may emit (P1 Security #3a).
///
/// The [`RUN_PAYLOAD_MAX`] cap is PER-EVENT, so without a per-run ceiling a granted emitter could grow
/// a run's retained log without bound (in P1 the retained log is pinned by the never-advanced
/// retention group and has no TTL — the terminal+idle sweep is the deferred P2 enable-gate). This caps
/// the retained log at `RUN_MAX_EVENTS` progress events + at most one terminal event, so a run's log is
/// bounded by `RUN_MAX_EVENTS * RUN_PAYLOAD_MAX`. The engine enforces it at the `seq` allocator: a
/// `progress` emit at/over the cap fails closed ([`RunError::Invalid`]); a TERMINAL emit (`result` /
/// `error` / `end` / `cancelled`) is ALWAYS admitted so a capped run can still conclude or be
/// cancelled. The default is generous for any legitimate run (≈ a full day of once-a-second progress)
/// and is a safety ceiling against a misbehaving granted emitter, not a tuning knob (the capability is
/// posture-OFF by default; P1 adds no operator override).
pub const RUN_MAX_EVENTS: u64 = 100_000;

/// The tenancy **scope segment** of a run topic, composed by the HOST from THIS invocation's resolved
/// own-tenant (never guest-supplied). A resolved tenant `t` maps to `t_{t}`; an unresolved tenant (a
/// single-tenant / unscoped invocation) maps to the fixed sentinel `u`. The `t_` prefix is
/// host-added, so a tenanted scope is always `t_…` and the untenanted scope is exactly `u` — the two
/// spaces are disjoint, and two distinct tenants map to distinct scopes, so a run is reachable ONLY by
/// its own tenant (a different resolved tenant composes a different key).
///
/// This is a pure composer: it does NOT screen the tenant. Callers that take an untrusted/host-resolved
/// tenant go through [`run_grant_scope`], which screens the tenant as a clean key segment and
/// fail-closes an untenanted run under a multi-tenant posture.
#[must_use]
pub fn run_scope_segment(resolved_tenant: Option<&str>) -> String {
    match resolved_tenant {
        Some(tenant) => format!("t_{tenant}"),
        None => "u".to_string(),
    }
}

/// Decide a run grant's scope segment, fail-closed (P1 Security #2 + #5). Returns `Some(scope)` to
/// BUILD the run engine for this invocation, or `None` to REFUSE the grant entirely (the host then
/// does not bake a run binding, so every run op fails `access-denied`).
///
/// - **#5 def-in-depth — screen the resolved tenant.** The resolved own-tenant is screened as a clean
///   key segment ([`validate_key_segment`](crate::project::validate_key_segment), the same check the
///   blob container path runs) before it is ever composed into `t_{tenant}`. An unscreenable tenant
///   (one that could reshape the key — a path separator, `*`, control/whitespace) is treated as
///   NO-resolved-tenant, fail-closed.
/// - **#2 fail-close an untenanted run under a multi-tenant posture.** When the node is multi-tenant
///   (`multi_tenant`) and no own-tenant resolved (anonymous, a capability FUNNEL — a `TargetTenant`
///   with no own `Tenant` → `None` —, cron/system, empty-tenant, or an unscreenable tenant from the
///   step above), the run would otherwise collapse into the SHARED per-project `u` scope — a
///   cross-tenant reach (two distinct funnels would both land in `u`). It is REFUSED. This mirrors the
///   tenant-secrets hard-fail-on-no-resolved-tenant precedent and the blob multi-tenant deny-default.
/// - **Single-tenant / dev** (`!multi_tenant`) keeps the `u` scope for an untenanted run — one tenant,
///   so `u` is safe.
#[must_use]
pub fn run_grant_scope(multi_tenant: bool, resolved_tenant: Option<&str>) -> Option<String> {
    // #5: screen the resolved tenant as a clean key segment; an unscreenable one ⇒ no-resolved-tenant.
    let screened =
        resolved_tenant.filter(|t| crate::project::validate_key_segment("tenant", t).is_ok());
    // #2: under a multi-tenant posture an untenanted run would share the per-project `u` scope → deny.
    if multi_tenant && screened.is_none() {
        return None;
    }
    Some(run_scope_segment(screened))
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
    fn run_grant_scope_fail_closes_untenanted_under_multi_tenant() {
        // #2: under a multi-tenant posture, a None resolved tenant (anonymous, capability-funnel,
        // cron/system, empty-tenant) is REFUSED — no scope, so the host builds no run engine.
        assert_eq!(run_grant_scope(true, None), None);
        // A properly tenanted run under multi-tenant gets its own disjoint `t_…` scope.
        assert_eq!(
            run_grant_scope(true, Some("firm-a")).as_deref(),
            Some("t_firm-a")
        );
        // Single-tenant / dev keeps `u` for an untenanted run — one tenant, so `u` is safe.
        assert_eq!(run_grant_scope(false, None).as_deref(), Some("u"));
        assert_eq!(run_grant_scope(false, Some("x")).as_deref(), Some("t_x"));
    }

    #[test]
    fn run_grant_scope_screens_the_resolved_tenant() {
        // #5 def-in-depth: a tenant that could reshape the key (path separator / `*` / control /
        // whitespace / `.`/`..`) is unscreenable ⇒ treated as no-resolved-tenant, fail-closed.
        for dirty in ["a/b", "a\\b", "with*star", "sp ace", ".", "..", "ctl\u{0}x"] {
            // Under multi-tenant an unscreenable tenant is REFUSED (it cannot be safely scoped, and it
            // must not collapse into the shared `u` space).
            assert_eq!(
                run_grant_scope(true, Some(dirty)),
                None,
                "dirty tenant {dirty:?} must be refused under multi-tenant"
            );
            // Under single-tenant it degrades to the safe `u` sentinel rather than `t_<garbage>` (the
            // garbage never reaches the key), matching the blob container-screen behavior.
            assert_eq!(
                run_grant_scope(false, Some(dirty)).as_deref(),
                Some("u"),
                "dirty tenant {dirty:?} must not shape a key under single-tenant"
            );
        }
        // A real-world tenant slug (`@`/`.`/`-` are allowed) screens cleanly to its own scope.
        assert_eq!(
            run_grant_scope(true, Some("firm-a@x.com")).as_deref(),
            Some("t_firm-a@x.com")
        );
    }

    #[test]
    fn two_distinct_funnels_cannot_share_a_run_under_multi_tenant() {
        // The hazard the #2 fix closes: two DIFFERENT end-tenants funnelled through a capability that
        // resolves NO own-tenant both compose the SAME untenanted scope (`u`) — a shared space.
        assert_eq!(run_scope_segment(None), run_scope_segment(None));
        assert_eq!(run_scope_segment(None), "u");
        // With the fix, under a multi-tenant posture neither funnel is granted a run at all, so the
        // shared `u` space is never reachable — the collision is structurally impossible.
        assert_eq!(run_grant_scope(true, None), None);
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
