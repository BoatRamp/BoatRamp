//! Request/response shapes that the server defines inline (not in
//! `boatramp-types`). Kept minimal and matched field-for-field to
//! `crates/boatramp-server/src/lib.rs` so the wire format stays in lock-step.
//!
//! Everything with a `boatramp-types` model (SiteConfig, DeploymentList,
//! CertStatus, GcReport, ScrubReport, DomainVerification, …) is used directly
//! from there — these are only the handful the server keeps private.

use serde::{Deserialize, Serialize};

/// Body of `PUT /api/sites/:site/aliases/:name` — point the alias at a
/// deployment id (server: `SetAliasRequest`).
#[derive(Debug, Clone, Serialize)]
pub struct SetAliasRequest {
    /// The deployment id (full content hash) the alias should resolve to.
    pub id: String,
}

/// Result of `POST /api/sites/:site/domains/:host/verification/check`: the
/// challenge plus whether it passed / was attached. The shared
/// `boatramp_types::domain_verify::CheckResult`.
pub use boatramp_types::domain_verify::CheckResult;

/// Body of `POST /api/tokens` — mint a token (server: `CreateTokenRequest`).
#[derive(Debug, Clone, Serialize)]
pub struct CreateTokenRequest {
    /// A human label for the token.
    pub label: String,
    /// Role specs (`<role>` or `<role>:<site>`), e.g. `admin`, `publisher:blog`.
    pub roles: Vec<String>,
    /// Optional TTL in seconds (omitted ⇒ no expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

/// Response of `POST /api/tokens` — the minted token (shown once) and its
/// revocation id (server: `CreateTokenResponse`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CreateTokenResponse {
    /// The freshly-minted token (never stored server-side).
    pub token: String,
    /// The authority revocation id (the `revoke` argument).
    pub id: String,
}

/// One record from `GET /api/tokens` — issued-token metadata, never the token
/// itself. This is the shared `boatramp_types::authz::TokenMeta`.
pub use boatramp_types::authz::{GrantedRole, TokenMeta};

/// Response of `GET /api/auth/whoami` — the signed-in principal's own roles
/// (server: `WhoAmI`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WhoAmI {
    /// Whether control-plane auth is enabled on the server.
    pub auth_enabled: bool,
    /// The roles the current token grants.
    #[serde(default)]
    pub roles: Vec<GrantedRole>,
}

/// Body of `POST /api/cache/invalidate` — keys to drop (empty = flush all)
/// (server: `InvalidateRequest`).
#[derive(Debug, Clone, Serialize)]
pub struct InvalidateRequest {
    /// Cache keys to invalidate; an empty list flushes the whole cache.
    pub keys: Vec<String>,
}

/// The captured guest log line and the logs endpoint response, shared with the
/// server and CLI (`boatramp_types::logs`).
pub use boatramp_types::logs::{LogEntry, LogsResponse};

/// One entry from `GET /api/functions` (server:
/// `boatramp_core::function::FunctionSummary`). Only the fields the console renders are
/// modeled; serde ignores the rest. A **top-level** function has a bare `name` (its
/// invoke + logs path segment); a site-derived one is `"<site>/<fn>"` (its output is the
/// site's), so the console lists only the top-level ones.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FunctionSummary {
    /// The function name — the `{name}` in `/api/functions/{name}/…` for a top-level one.
    pub name: String,
    /// The guest runtime (e.g. `wasm`), for display.
    #[serde(default)]
    pub runtime: String,
}

// ---- Node monitoring (the Monitoring page) --------------------------------
//
// These node-global `System·Read` payloads are defined server-side (NOT in
// `boatramp-types`): `NodeVersion` in boatramp-server, `InstanceStatsSnapshot`
// in boatramp-handlers; the CLI consumes them as untyped JSON. Mirrored here
// field-for-field (serde-tolerant) so the Monitoring page can render them typed.

/// `GET /api/version` — the running node's boatramp version (server: `NodeVersion`,
/// shaped as an object so it can grow build metadata without breaking clients).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NodeVersion {
    /// The workspace version every crate shares, e.g. `"0.15.0"`.
    pub version: String,
}

/// `GET /api/instance-stats` — node-wide wasm instance lifecycle + memory
/// (server: `boatramp_handlers::instance_stats::InstanceStatsSnapshot`; feature
/// `handlers`, so a `404` means the server was built without it).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct InstanceStatsSnapshot {
    /// Process memory (RSS vs the per-instance ceiling).
    pub memory: ProcessMemory,
    /// The synchronous request/proxy serve lane.
    pub request: LaneStats,
    /// The async queue-consumer lane.
    pub consumer: LaneStats,
    /// The session (handler-session) lane.
    pub session: LaneStats,
}

/// Process-level memory in [`InstanceStatsSnapshot`].
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ProcessMemory {
    /// Resident set size in bytes; `None` off Linux (dev macOS) rather than fabricated.
    #[serde(default)]
    pub rss_bytes: Option<u64>,
    /// The configured per-instance memory ceiling in bytes (`u64::MAX` ⇒ uncapped).
    #[serde(default)]
    pub per_instance_limit_bytes: u64,
}

/// Per-lane instance lifecycle counters in [`InstanceStatsSnapshot`].
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct LaneStats {
    /// Warm instances cached right now.
    #[serde(default)]
    pub warm_now: u64,
    /// The warm-cache capacity (`[handlers] instance_cache_size`).
    #[serde(default)]
    pub warm_capacity: u64,
    /// The component hashes currently warm.
    #[serde(default)]
    pub warm_components: Vec<String>,
    /// Instances serving a request right now.
    #[serde(default)]
    pub in_flight: u64,
    /// The per-lane concurrency ceiling.
    #[serde(default)]
    pub lane_ceiling: u64,
    /// Warm cache hits (served without a fetch/compile).
    #[serde(default)]
    pub warm_hits: u64,
    /// Cold misses (a compile was required).
    #[serde(default)]
    pub cold_misses: u64,
    /// Evictions from the warm cache.
    #[serde(default)]
    pub evictions: u64,
    /// Total instantiations.
    #[serde(default)]
    pub instantiations: u64,
    /// Mean instantiate time in microseconds.
    #[serde(default)]
    pub instantiate_us_avg: u64,
    /// Max instantiate time in microseconds.
    #[serde(default)]
    pub instantiate_us_max: u64,
    /// Mean cold-compile time in milliseconds.
    #[serde(default)]
    pub compile_ms_avg: u64,
    /// Max cold-compile time in milliseconds.
    #[serde(default)]
    pub compile_ms_max: u64,
}

/// `GET /api/blob-status` — whether a read-fallback secondary is attached (the
/// node is mid blob-migration) (server: a free-form object with this one field).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct BlobStatus {
    /// `true` while a `[serve.blob_fallback]` secondary is attached for reads.
    #[serde(default)]
    pub blob_fallback_active: bool,
}

/// `GET /api/kv-status` — the control-plane KV health. The body is polymorphic
/// (SlateDB vs backend-aware, clean vs degraded/recovered), so only the
/// back-compat top-level `state` is typed; the rest is kept as raw detail.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KvStatus {
    /// `ok` | `degraded` | `recovered` | `recovered_lossless` (top-level, back-compat).
    pub state: String,
    /// Everything else the body carries (frontier/loss-window/durability/backend/…).
    #[serde(flatten)]
    pub detail: serde_json::Map<String, serde_json::Value>,
}

// ---- Node ops (the Maintenance page's node-ops sections) ------------------

/// One row of `GET /api/cluster/members` (server inline `MeshMember`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MeshMember {
    /// The Raft node id.
    pub node: u64,
    /// Whether the member is a voter (vs a learner).
    #[serde(default)]
    pub voter: bool,
    /// Whether the member has caught up to the log.
    #[serde(default)]
    pub caught_up: bool,
    /// Whether the member is the current leader.
    #[serde(default)]
    pub leader: bool,
    /// The member's advertised mesh address (absent for some members).
    #[serde(default)]
    pub addr: Option<String>,
}

/// Response of `POST /api/cluster/join-token` (server inline `CreateJoinTokenResponse`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct JoinToken {
    /// The single-use join token (base64url) — shown ONCE, never stored.
    pub token: String,
    /// When the token expires (unix seconds).
    pub expires_at: u64,
}

/// Response of `GET /api/daemon/config` — the stored dynamic daemon config plus
/// its generation (sha256-hex, `null` when none stored). The config body is
/// kept as raw JSON for a read-only pretty view (editing comes in a later stage).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DaemonConfigResponse {
    /// The stored config's generation hash, or `null` when the file baseline is in effect.
    #[serde(default)]
    pub generation: Option<String>,
    /// The effective `DaemonConfig` as JSON (rendered pretty, read-only this stage).
    pub config: serde_json::Value,
}

// ---- Projects (the multi-project selector) --------------------------------

/// One entry from `GET /api/projects` (server `boatramp_core::project::Project`).
/// Only the fields the selector renders are modeled; serde ignores the rest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ProjectSummary {
    /// The project slug — the `{proj}` segment in `/api/projects/{proj}/…`.
    pub name: String,
    /// Display metadata (optional free-text name / description).
    #[serde(default)]
    pub meta: ProjectMeta,
}

/// The `meta` block of a [`ProjectSummary`].
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ProjectMeta {
    /// A human display name (falls back to the slug when empty).
    #[serde(default)]
    pub display: String,
    /// Free-text description.
    #[serde(default)]
    pub description: String,
}
