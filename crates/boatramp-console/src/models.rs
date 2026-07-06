//! Request/response shapes that the server defines inline (not in
//! `boatramp-types`). Kept minimal and matched field-for-field to
//! `crates/boatramp-server/src/lib.rs` so the wire format stays in lock-step.
//!
//! Everything with a `boatramp-types` model (SiteConfig, DeploymentList,
//! CertStatus, GcReport, ScrubReport, DomainVerification, …) is used directly
//! from there — these are only the handful the server keeps private.

use boatramp_types::domain_verify::DomainVerification;
use serde::{Deserialize, Serialize};

/// Body of `PUT /api/sites/:site/aliases/:name` — point the alias at a
/// deployment id (server: `SetAliasRequest`).
#[derive(Debug, Clone, Serialize)]
pub struct SetAliasRequest {
    /// The deployment id (full content hash) the alias should resolve to.
    pub id: String,
}

/// Result of `POST /api/sites/:site/domains/:host/verification/check`
/// (server: `CheckResult`). The challenge plus whether it passed / was attached.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    /// The challenge after the check (its `verified` flag reflects the outcome).
    pub verification: DomainVerification,
    /// Whether ownership was proven this round.
    pub passed: bool,
    /// Whether the host was attached to the site's config (only on `passed`).
    pub attached: bool,
    /// A human-readable note on failure (what was expected / why it failed).
    #[serde(default)]
    pub detail: Option<String>,
}

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

/// One captured guest log line from `GET /api/sites/:site/_boatramp/logs`
/// (a subset of the server's `logs::LogEntry`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    /// Monotonic sequence number (poll with `?after=<seq>` for new lines).
    pub seq: u64,
    /// Which stream — `stdout` or `stderr`.
    pub stream: String,
    /// The captured line.
    pub line: String,
}

/// The logs endpoint response (server: `LogsResponse`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct LogsResponse {
    /// The captured lines (most recent `limit`, with `seq > after`).
    pub entries: Vec<LogEntry>,
    /// Lines dropped server-side by the per-site rate cap.
    pub dropped: u64,
}
