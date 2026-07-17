//! Control-plane **authorization** vocabulary and RBAC policy.
//!
//! This is the wasm-clean, pure core of authorization: the `action × resource`
//! right vocabulary, the request → required-[`Right`] mapping (the analogue of
//! the old `required_scope`), the RBAC [`AuthzPolicy`] (roles → right
//! templates) with its built-in default, and the pure [`RightSet::allows`]
//! decision. The COSE/Cedar engine (`boatramp_core::cose` + `::cedar`) reuses these types
//! and mirrors [`RightSet::allows`]; keeping the semantics
//! here means the server, CLI, and tests can't drift from the token format.
//!
//! No IO, no async, no authz-engine dependency — so it compiles to the edge target
//! and is exhaustively unit-testable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a principal may *do* to a resource. [`Action::Admin`] is the superuser
/// action: holding it on a resource satisfies any other action there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Read/list (GET endpoints).
    Read,
    /// Mutate configuration (site config, aliases, domain verification, cache).
    Write,
    /// Ship content: create + activate deployments, upload blobs.
    Deploy,
    /// Full control of the resource (implies read/write/deploy).
    Admin,
}

/// A class of control-plane resource a [`Right`] governs. Only [`Resource::Site`]
/// is target-scoped (the target is a site name); the rest are global.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Resource {
    /// A single site (`target` = site name): deployments, config, aliases, …
    Site,
    /// Content-addressed blob uploads (`PUT /api/blobs/<hash>`).
    Blobs,
    /// API token management (`/api/tokens`).
    Tokens,
    /// TLS certificate status (`/api/certs`).
    Certs,
    /// Cache invalidation (`/api/cache/invalidate`).
    Cache,
    /// Node/system operations: metrics, prune, scrub, site listing.
    System,
}

impl Resource {
    /// Every resource variant — used to expand the `admin` role to "all rights".
    pub const ALL: [Resource; 6] = [
        Resource::Site,
        Resource::Blobs,
        Resource::Tokens,
        Resource::Certs,
        Resource::Cache,
        Resource::System,
    ];

    /// The serde term for this resource (matches `rename_all`).
    pub fn as_str(self) -> &'static str {
        match self {
            Resource::Site => "site",
            Resource::Blobs => "blobs",
            Resource::Tokens => "tokens",
            Resource::Certs => "certs",
            Resource::Cache => "cache",
            Resource::System => "system",
        }
    }
}

impl Action {
    /// The serde term for this action (matches `rename_all`).
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Deploy => "deploy",
            Action::Admin => "admin",
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single grant or requirement: an `action` on a `resource`, optionally scoped
/// to a `target` (a site name for [`Resource::Site`]). A `target` of `None` on a
/// *granted* right is a wildcard ("all targets"); a required right for a site
/// always carries `Some(site)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Right {
    /// The resource class this right governs.
    pub resource: Resource,
    /// The site name for [`Resource::Site`]; `None` (wildcard/global) otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The permitted action.
    pub action: Action,
}

impl Right {
    /// Construct a right.
    pub fn new(resource: Resource, target: Option<String>, action: Action) -> Self {
        Self {
            resource,
            target,
            action,
        }
    }

    /// The target term: the site name, or `*` for a wildcard/global right.
    pub fn target_term(&self) -> &str {
        self.target.as_deref().unwrap_or("*")
    }

    /// Whether holding `self` (a *granted* right) satisfies a `required` right:
    /// same resource, the granted action matches or is [`Action::Admin`], and the
    /// granted target is a wildcard (`None`/`*`) or equals the required target.
    pub fn satisfies(&self, required: &Right) -> bool {
        self.resource == required.resource
            && (self.action == required.action || self.action == Action::Admin)
            && target_matches(self.target.as_deref(), required.target.as_deref())
    }

    /// Map an HTTP `method` + request `path` to the single right it requires, or
    /// `None` for endpoints not gated by a right (the OIDC→token exchange).
    ///
    /// This is the authoritative request→right table. Unknown
    /// `/api/sites/<s>/…` subpaths fall through to the most restrictive
    /// `system · admin` so a narrow token can never reach an unmapped action.
    pub fn required(method: &str, path: &str) -> Option<Right> {
        let m = method.to_ascii_uppercase();
        let get = m == "GET";

        // Self-service endpoints gated only by holding *some* valid token, not a
        // right: the OIDC→token exchange (carries an IdP JWT) and `whoami`
        // (a principal reading its own identity). The handlers verify the token.
        if path == "/api/auth/exchange" || path == "/api/auth/whoami" {
            return None;
        }

        // Mesh join: the joiner presents a single-use *join
        // token* (verified by the handler), not an admin bearer — so this exact
        // path is unauthenticated at the RBAC layer. Note the `==`: the sibling
        // `/api/cluster/join-token` (minting) stays admin-scoped via the default.
        if path == "/api/cluster/join" {
            return None;
        }

        // First-token bootstrap: the caller presents a single-use, operator-set
        // *bootstrap secret* (verified by the handler), not an admin bearer — so
        // this exact path is unauthenticated at the RBAC layer. Note the `==`: the
        // sibling `/api/tokens` (minting) stays admin-scoped via the default below.
        if path == "/api/tokens/bootstrap" {
            return None;
        }

        // Content blobs are content-addressed (not site-specific); uploading is
        // a deploy-grade action.
        if path.starts_with("/api/blobs/") {
            return Some(Right::new(Resource::Blobs, None, Action::Deploy));
        }

        // Attaching a host **without** an ownership proof (`domain add
        // --unverified`) is an admin-only override: it asserts ownership of an
        // arbitrary hostname, so a site-scoped publisher must never reach it
        // (that would let them claim someone else's domain). Gate it at
        // `system·admin` explicitly, above the per-site branch that would
        // otherwise map it to the site-write right.
        if m == "POST" && path.contains("/domains/") && path.ends_with("/attach-unverified") {
            return Some(Right::new(Resource::System, None, Action::Admin));
        }

        // Per-site endpoints: `/api/sites/<site>/<sub...>`.
        if let Some(rest) = path.strip_prefix("/api/sites/") {
            let mut segs = rest.split('/');
            let site = segs.next().unwrap_or("");
            if site.is_empty() {
                // `/api/sites/` (trailing slash) — listing.
                return Some(Right::new(Resource::System, None, Action::Read));
            }
            let target = Some(site.to_string());
            let sub: Vec<&str> = segs.filter(|s| !s.is_empty()).collect();
            let action = site_subpath_action(&m, get, &sub);
            return Some(match action {
                Some(a) => Right::new(Resource::Site, target, a),
                // Unknown subpath — deny-safe.
                None => Right::new(Resource::System, None, Action::Admin),
            });
        }

        // Exact, non-site endpoints.
        let right = match path {
            "/api/sites" => Right::new(Resource::System, None, Action::Read),
            // Functions (FA-1/FA-2): read the function view with `system·read` (like
            // `/api/sites`); mutating a top-level function (deploy a version, alias,
            // rollback, delete) requires `system·admin`. (A per-owner `function`
            // resource with finer invoke/deploy rights lands in FA-4.)
            p if p == "/api/functions" || p.starts_with("/api/functions/") => {
                let action = if get { Action::Read } else { Action::Admin };
                Right::new(Resource::System, None, action)
            }
            // Workflows (FA-6): read the definitions/runs with `system·read`;
            // defining a workflow, starting a run, or deleting requires
            // `system·admin`. Same shape as `/api/functions`.
            p if p == "/api/workflows" || p.starts_with("/api/workflows/") => {
                let action = if get { Action::Read } else { Action::Admin };
                Right::new(Resource::System, None, action)
            }
            "/api/blobs" => Right::new(Resource::Blobs, None, Action::Deploy),
            "/api/certs" => Right::new(Resource::Certs, None, Action::Read),
            "/api/cache/invalidate" => Right::new(Resource::Cache, None, Action::Write),
            "/api/metrics" => Right::new(Resource::System, None, Action::Read),
            "/api/prune" | "/api/scrub" => Right::new(Resource::System, None, Action::Admin),
            p if p == "/api/tokens" || p.starts_with("/api/tokens/") => {
                Right::new(Resource::Tokens, None, Action::Admin)
            }
            p if p == "/api/authz/policy" || p.starts_with("/api/authz/") => {
                Right::new(Resource::System, None, Action::Admin)
            }
            // Any other `/api/*` path: deny-safe (must hold system·admin).
            _ => Right::new(Resource::System, None, Action::Admin),
        };
        Some(right)
    }
}

/// The action a per-site subpath requires, or `None` if the subpath is unknown.
fn site_subpath_action(method: &str, get: bool, sub: &[&str]) -> Option<Action> {
    match sub.first().copied() {
        // `deployments`, `deployments/<id>`, `deployments/<id>/activate`.
        Some("deployments") => {
            let activate = sub.last() == Some(&"activate");
            if activate || method == "POST" {
                Some(Action::Deploy) // activate, or create a deployment
            } else if get {
                Some(Action::Read)
            } else {
                None
            }
        }
        Some("current") if get => Some(Action::Read),
        Some("config") => {
            if get {
                Some(Action::Read)
            } else if method == "PUT" {
                Some(Action::Write)
            } else {
                None
            }
        }
        // `domains/<host>/verification[/check]`, `domain-verifications`.
        Some("domains") => {
            let check = sub.last() == Some(&"check"); // a status check (POST, but read-grade)
            if get || check {
                Some(Action::Read)
            } else if method == "POST" || method == "DELETE" {
                Some(Action::Write)
            } else {
                None
            }
        }
        Some("domain-verifications") if get => Some(Action::Read),
        Some("aliases") => {
            if get {
                Some(Action::Read)
            } else if method == "PUT" || method == "DELETE" {
                Some(Action::Write)
            } else {
                None
            }
        }
        // `_boatramp/handlers`, `_boatramp/logs` (per-site observability, read);
        // `_boatramp/dlq` purge/redrive is a destructive site-scoped write.
        Some("_boatramp") => {
            if get {
                Some(Action::Read)
            } else if method == "POST" && sub.get(1) == Some(&"dlq") {
                Some(Action::Write)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Whether a granted target (wildcard `None`/`*`, or a specific site) covers a
/// required target.
fn target_matches(granted: Option<&str>, required: Option<&str>) -> bool {
    match granted {
        None | Some("*") => true,
        Some(g) => required == Some(g),
    }
}

/// A set of granted [`Right`]s with the pure authorization decision. This is the
/// pure-Rust reference decision: the differential oracle the Cedar authorizer is
/// tested against, and used by issuance code that needs to reason about a role's
/// effective rights.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RightSet {
    rights: Vec<Right>,
}

impl RightSet {
    /// An empty set (grants nothing).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a right (de-duplicated).
    pub fn insert(&mut self, right: Right) {
        if !self.rights.contains(&right) {
            self.rights.push(right);
        }
    }

    /// Whether any held right satisfies `required`.
    pub fn allows(&self, required: &Right) -> bool {
        self.rights.iter().any(|g| g.satisfies(required))
    }

    /// Whether the set grants nothing.
    pub fn is_empty(&self) -> bool {
        self.rights.is_empty()
    }

    /// The held rights.
    pub fn rights(&self) -> &[Right] {
        &self.rights
    }
}

impl FromIterator<Right> for RightSet {
    fn from_iter<I: IntoIterator<Item = Right>>(iter: I) -> Self {
        let mut set = RightSet::new();
        for r in iter {
            set.insert(r);
        }
        set
    }
}

/// A role granted to a principal: a role `name` from the [`AuthzPolicy`], plus an
/// optional `target` (a site name) for target-scoped roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantedRole {
    /// The role name (a key in [`AuthzPolicy::roles`]).
    pub name: String,
    /// The site this instance is scoped to, for target-scoped roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl GrantedRole {
    /// A global role (no target).
    pub fn global(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            target: None,
        }
    }

    /// A target-scoped role (e.g. `publisher` on a site).
    pub fn scoped(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            target: Some(target.into()),
        }
    }

    /// Parse a role spec: `"<role>"` (global) or `"<role>:<target>"`
    /// (target-scoped). Used by the CLI `--role`, the API token-create body, and
    /// the OIDC claim→roles mapping, so they agree on the format.
    pub fn parse(spec: &str) -> Self {
        match spec.split_once(':') {
            Some((name, target)) if !target.trim().is_empty() => {
                GrantedRole::scoped(name.trim(), target.trim())
            }
            _ => GrantedRole::global(spec.trim()),
        }
    }
}

/// How a [`RightTemplate`] derives its target when expanding a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    /// Wildcard/global: the expanded right has `target = None`.
    AnyTarget,
    /// Bind to the granted role instance's target (target-scoped roles).
    RoleTarget,
}

/// One right a role grants, before binding to a concrete target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RightTemplate {
    /// The resource the right governs.
    pub resource: Resource,
    /// The action granted.
    pub action: Action,
    /// How the target is derived when the role is expanded.
    pub scope: TargetScope,
}

impl RightTemplate {
    /// A global right template (`AnyTarget`).
    pub fn any(resource: Resource, action: Action) -> Self {
        Self {
            resource,
            action,
            scope: TargetScope::AnyTarget,
        }
    }

    /// A target-scoped right template (`RoleTarget`).
    pub fn scoped(resource: Resource, action: Action) -> Self {
        Self {
            resource,
            action,
            scope: TargetScope::RoleTarget,
        }
    }
}

/// The RBAC policy: roles → the rights they grant. Stored at KV `authz/policy`
/// (schema v1); when absent the server uses [`AuthzPolicy::default_policy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthzPolicy {
    /// Pinned schema discriminant (`v1`).
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// Role name → the right templates it grants.
    pub roles: BTreeMap<String, Vec<RightTemplate>>,
}

impl Default for AuthzPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

impl AuthzPolicy {
    /// The built-in default policy: `admin`, `publisher`,
    /// `deployer`, `viewer`, `operator`.
    pub fn default_policy() -> Self {
        let mut roles: BTreeMap<String, Vec<RightTemplate>> = BTreeMap::new();

        // admin — every (resource, action). Expanded as one Admin right per
        // resource with a wildcard target.
        roles.insert(
            "admin".to_string(),
            Resource::ALL
                .iter()
                .map(|&r| RightTemplate::any(r, Action::Admin))
                .collect(),
        );

        // publisher (site) — full control of its site + blob uploads.
        roles.insert(
            "publisher".to_string(),
            vec![
                RightTemplate::scoped(Resource::Site, Action::Read),
                RightTemplate::scoped(Resource::Site, Action::Write),
                RightTemplate::scoped(Resource::Site, Action::Deploy),
                RightTemplate::any(Resource::Blobs, Action::Deploy),
            ],
        );

        // deployer (site) — ship + read, but not edit config.
        roles.insert(
            "deployer".to_string(),
            vec![
                RightTemplate::scoped(Resource::Site, Action::Read),
                RightTemplate::scoped(Resource::Site, Action::Deploy),
                RightTemplate::any(Resource::Blobs, Action::Deploy),
            ],
        );

        // viewer (site) — read-only on its site.
        roles.insert(
            "viewer".to_string(),
            vec![RightTemplate::scoped(Resource::Site, Action::Read)],
        );

        // operator — node-level read + cache control, no site access.
        roles.insert(
            "operator".to_string(),
            vec![
                RightTemplate::any(Resource::System, Action::Read),
                RightTemplate::any(Resource::Certs, Action::Read),
                RightTemplate::any(Resource::Cache, Action::Write),
            ],
        );

        Self {
            version: crate::SCHEMA_VERSION,
            roles,
        }
    }

    /// Whether `role` is target-scoped (any of its templates binds the target).
    pub fn role_takes_target(&self, role: &str) -> bool {
        self.roles
            .get(role)
            .is_some_and(|ts| ts.iter().any(|t| t.scope == TargetScope::RoleTarget))
    }

    /// Expand a principal's granted roles into the concrete [`RightSet`] they
    /// confer under this policy. A target-scoped template on a role granted
    /// without a target contributes nothing (defensive). This is the pure RBAC
    /// expansion the Cedar authorizer reproduces as a policy set.
    pub fn rights_for(&self, roles: &[GrantedRole]) -> RightSet {
        let mut set = RightSet::new();
        for granted in roles {
            let Some(templates) = self.roles.get(&granted.name) else {
                continue;
            };
            for t in templates {
                let target = match t.scope {
                    TargetScope::AnyTarget => None,
                    TargetScope::RoleTarget => match &granted.target {
                        Some(x) => Some(x.clone()),
                        None => continue,
                    },
                };
                set.insert(Right::new(t.resource, target, t.action));
            }
        }
        set
    }
}

/// KV key for the RBAC policy document (`authz/policy`); absent ⇒ the built-in
/// [`AuthzPolicy::default_policy`].
pub const POLICY_KEY: &str = "authz/policy";

/// KV key prefix for revocation markers — presence of `authz/revoked/<id>`
/// means the token with authority revocation id `<id>` (and its attenuations)
/// is revoked.
pub const REVOKED_PREFIX: &str = "authz/revoked/";

/// KV key prefix for issued-token metadata (`authz/tokens/<id>`). The token
/// itself is never stored — only this metadata, for `token ls`.
pub const TOKEN_META_PREFIX: &str = "authz/tokens/";

/// The revocation-marker key for an authority revocation id.
pub fn revoked_key(revocation_id: &str) -> String {
    format!("{REVOKED_PREFIX}{revocation_id}")
}

/// KV key prefix for extra trusted **root anchors** added by `auth rotate-root`
/// (`auth/root/{alg:hex}`). Each is a `TokenPublicKey` trusted alongside the
/// configured primary root during a make-before-break root rotation.
pub const ROOT_ANCHOR_PREFIX: &str = "auth/root/";

/// The root-anchor key trusting `pubkey` (an `alg:hex`-encoded `TokenPublicKey`).
pub fn root_anchor_key(pubkey: &str) -> String {
    format!("{ROOT_ANCHOR_PREFIX}{pubkey}")
}

/// The metadata key for an issued token (keyed by its authority revocation id).
pub fn token_meta_key(id: &str) -> String {
    format!("{TOKEN_META_PREFIX}{id}")
}

/// The single-use marker key for a redeemed first-token bootstrap secret
/// (keyed by the secret's SHA-256 hex).
pub fn bootstrap_key(secret_hash: &str) -> String {
    format!("authz/bootstrap/{secret_hash}")
}

/// Metadata for an issued token (`authz/tokens/<id>`). The token itself is
/// shown once at creation and never stored; this is what `token ls` reports and
/// what `token rm` needs to find the revocation id. Schema v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMeta {
    /// Pinned schema discriminant (`v1`).
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// Human label for the token.
    pub label: String,
    /// The roles the token grants.
    pub roles: Vec<GrantedRole>,
    /// Unix timestamp (seconds) of creation.
    pub created_at: u64,
    /// Unix timestamp (seconds) of expiry, if the token carries a TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// The authority revocation id (hex) — also the `authz/tokens/<id>` key and
    /// the argument to `token rm`.
    pub revocation_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_satisfies_every_action_on_its_resource() {
        let admin_site = Right::new(Resource::Site, None, Action::Admin);
        for action in [Action::Read, Action::Write, Action::Deploy, Action::Admin] {
            let required = Right::new(Resource::Site, Some("blog".into()), action);
            assert!(
                admin_site.satisfies(&required),
                "admin must satisfy {action:?}"
            );
        }
        // …but not a different resource.
        assert!(!admin_site.satisfies(&Right::new(Resource::Tokens, None, Action::Read)));
    }

    #[test]
    fn target_scoping_is_exact_unless_wildcard() {
        let blog = Right::new(Resource::Site, Some("blog".into()), Action::Write);
        assert!(blog.satisfies(&Right::new(
            Resource::Site,
            Some("blog".into()),
            Action::Write
        )));
        assert!(!blog.satisfies(&Right::new(
            Resource::Site,
            Some("api".into()),
            Action::Write
        )));
        // A wildcard grant covers any site.
        let any = Right::new(Resource::Site, None, Action::Write);
        assert!(any.satisfies(&Right::new(
            Resource::Site,
            Some("api".into()),
            Action::Write
        )));
    }

    #[test]
    fn distinct_actions_do_not_imply_each_other() {
        let write = Right::new(Resource::Site, Some("blog".into()), Action::Write);
        let deploy_req = Right::new(Resource::Site, Some("blog".into()), Action::Deploy);
        assert!(
            !write.satisfies(&deploy_req),
            "write must not imply deploy (only admin does)"
        );
    }

    /// Every row of the request→right table.
    #[test]
    fn required_right_table() {
        let cases: &[(&str, &str, Option<Right>)] = &[
            ("POST", "/api/auth/exchange", None),
            ("GET", "/api/auth/whoami", None),
            // Minting a mesh join token is admin-scoped (deny-safe default for
            // `/api/cluster/*`) — an operator issues it.
            (
                "POST",
                "/api/cluster/join-token",
                Some(Right::new(Resource::System, None, Action::Admin)),
            ),
            // Presenting a join token to join is gated by the token itself, not
            // an admin bearer (the handler verifies it) — exact-path `None`.
            ("POST", "/api/cluster/join", None),
            // Rotating this node's mesh key is an operator action → admin-scoped.
            (
                "POST",
                "/api/cluster/rotate-key",
                Some(Right::new(Resource::System, None, Action::Admin)),
            ),
            // Revoking a node from the mesh is an operator action → admin-scoped.
            (
                "POST",
                "/api/cluster/revoke",
                Some(Right::new(Resource::System, None, Action::Admin)),
            ),
            (
                "PUT",
                "/api/blobs/abc123",
                Some(Right::new(Resource::Blobs, None, Action::Deploy)),
            ),
            (
                "GET",
                "/api/sites",
                Some(Right::new(Resource::System, None, Action::Read)),
            ),
            (
                "POST",
                "/api/sites/blog/deployments",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Deploy,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/deployments",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/deployments/d1",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "POST",
                "/api/sites/blog/deployments/d1/activate",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Deploy,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/current",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/config",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "PUT",
                "/api/sites/blog/config",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Write,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/domains/x.example.com/verification",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "POST",
                "/api/sites/blog/domains/x.example.com/verification",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Write,
                )),
            ),
            (
                "DELETE",
                "/api/sites/blog/domains/x.example.com/verification",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Write,
                )),
            ),
            (
                "POST",
                "/api/sites/blog/domains/x.example.com/verification/check",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/domain-verifications",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "PUT",
                "/api/sites/blog/aliases/www",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Write,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/aliases",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "GET",
                "/api/sites/blog/_boatramp/handlers",
                Some(Right::new(
                    Resource::Site,
                    Some("blog".into()),
                    Action::Read,
                )),
            ),
            (
                "POST",
                "/api/tokens",
                Some(Right::new(Resource::Tokens, None, Action::Admin)),
            ),
            (
                "DELETE",
                "/api/tokens/t1",
                Some(Right::new(Resource::Tokens, None, Action::Admin)),
            ),
            (
                "GET",
                "/api/prune",
                Some(Right::new(Resource::System, None, Action::Admin)),
            ),
            (
                "POST",
                "/api/scrub",
                Some(Right::new(Resource::System, None, Action::Admin)),
            ),
            (
                "GET",
                "/api/certs",
                Some(Right::new(Resource::Certs, None, Action::Read)),
            ),
            (
                "POST",
                "/api/cache/invalidate",
                Some(Right::new(Resource::Cache, None, Action::Write)),
            ),
            (
                "GET",
                "/api/metrics",
                Some(Right::new(Resource::System, None, Action::Read)),
            ),
        ];
        for (method, path, expected) in cases {
            assert_eq!(
                &Right::required(method, path),
                expected,
                "required({method}, {path})"
            );
        }
    }

    #[test]
    fn unknown_site_subpath_is_deny_safe() {
        // An unmapped subpath must require system·admin, not the site's action.
        assert_eq!(
            Right::required("PATCH", "/api/sites/blog/frobnicate"),
            Some(Right::new(Resource::System, None, Action::Admin))
        );
    }

    #[test]
    fn attach_unverified_is_admin_only() {
        // Attaching a host without a proof (`domain add --unverified`) must need
        // system·admin — a site-write right must NOT satisfy it, so a scoped
        // publisher can't claim an arbitrary host.
        let required = Right::required(
            "POST",
            "/api/sites/blog/domains/evil.example.com/attach-unverified",
        )
        .expect("route is gated");
        assert_eq!(required, Right::new(Resource::System, None, Action::Admin));
        // A publisher's site-write right does not satisfy the admin gate.
        let site_write = Right::new(Resource::Site, Some("blog".into()), Action::Write);
        assert!(!site_write.satisfies(&required));
        // A system-admin right does.
        assert!(Right::new(Resource::System, None, Action::Admin).satisfies(&required));
    }

    #[test]
    fn default_policy_publisher_can_deploy_and_write_its_site_only() {
        let policy = AuthzPolicy::default_policy();
        let rights = policy.rights_for(&[GrantedRole::scoped("publisher", "blog")]);
        // Can read/write/deploy blog + upload blobs…
        assert!(rights.allows(&Right::new(
            Resource::Site,
            Some("blog".into()),
            Action::Deploy
        )));
        assert!(rights.allows(&Right::new(
            Resource::Site,
            Some("blog".into()),
            Action::Write
        )));
        assert!(rights.allows(&Right::new(Resource::Blobs, None, Action::Deploy)));
        // …but not another site, nor token management.
        assert!(!rights.allows(&Right::new(
            Resource::Site,
            Some("api".into()),
            Action::Read
        )));
        assert!(!rights.allows(&Right::new(Resource::Tokens, None, Action::Admin)));
    }

    #[test]
    fn default_policy_deployer_cannot_edit_config() {
        let policy = AuthzPolicy::default_policy();
        let rights = policy.rights_for(&[GrantedRole::scoped("deployer", "blog")]);
        assert!(rights.allows(&Right::new(
            Resource::Site,
            Some("blog".into()),
            Action::Deploy
        )));
        assert!(rights.allows(&Right::new(
            Resource::Site,
            Some("blog".into()),
            Action::Read
        )));
        assert!(
            !rights.allows(&Right::new(
                Resource::Site,
                Some("blog".into()),
                Action::Write
            )),
            "deployer must not edit config"
        );
    }

    #[test]
    fn default_policy_admin_can_do_anything() {
        let policy = AuthzPolicy::default_policy();
        let rights = policy.rights_for(&[GrantedRole::global("admin")]);
        for resource in Resource::ALL {
            for action in [Action::Read, Action::Write, Action::Deploy, Action::Admin] {
                let target = matches!(resource, Resource::Site).then(|| "any".to_string());
                assert!(
                    rights.allows(&Right::new(resource, target, action)),
                    "admin must allow {resource:?}·{action:?}"
                );
            }
        }
    }

    #[test]
    fn site_role_without_target_grants_nothing_site_scoped() {
        let policy = AuthzPolicy::default_policy();
        // `publisher` granted globally (no target) — the site templates are
        // RoleTarget, so they contribute nothing; only the AnyTarget blobs right.
        let rights = policy.rights_for(&[GrantedRole::global("publisher")]);
        assert!(rights.allows(&Right::new(Resource::Blobs, None, Action::Deploy)));
        assert!(!rights.allows(&Right::new(
            Resource::Site,
            Some("blog".into()),
            Action::Read
        )));
    }

    #[test]
    fn role_takes_target_classifies_roles() {
        let policy = AuthzPolicy::default_policy();
        assert!(policy.role_takes_target("publisher"));
        assert!(policy.role_takes_target("viewer"));
        assert!(!policy.role_takes_target("admin"));
        assert!(!policy.role_takes_target("operator"));
    }

    #[test]
    fn policy_round_trips_through_json() {
        let policy = AuthzPolicy::default_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let back: AuthzPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
        assert_eq!(back.version, crate::SCHEMA_VERSION);
    }

    #[test]
    fn unknown_role_is_ignored() {
        let policy = AuthzPolicy::default_policy();
        let rights = policy.rights_for(&[GrantedRole::global("nonesuch")]);
        assert!(rights.is_empty());
    }
}
