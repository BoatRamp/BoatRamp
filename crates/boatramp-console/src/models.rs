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
