//! Per-tenant wasm-runtime routing, keying + link-wiring (privsep Phase 4 — WS-B; design
//! `PLAN-privsep-phase1.md` §Phase-4). **SECURITY-CRITICAL — this is the per-tenant isolation
//! boundary: the #1 leak surface (tenant keying, Security artifact #1) and the unforgeable
//! backend-call identity (Security artifact #2).**
//!
//! Phase 4 instantiates the guest JIT (`exec.wasmtime`) as a per-tenant TEMPLATE
//! ([`boatramp_core::privsep::InstanceLifecycle::PerTenantTemplate`], WS-A): one isolated
//! runtime per active tenant (boundary = **project**), so a wasmtime escape lands in a SINGLE
//! tenant's runtime and nothing else. This module is the FRONTEND side of that boundary — it
//! answers two questions, fail-closed:
//!
//! 1. **Which tenant's instance does this request go to?** (artifact #1). The frontend resolves
//!    the project STRUCTURALLY from the routed `Host` header (the SAME Stage-0 resolution the
//!    monolith does in `serve_pipeline::serve_by_host_inner` → [`DeployStore::resolve_site_by_host`],
//!    *before any guest byte*), derives a [`TenantScope`] fail-closed, and routes to that project's
//!    per-tenant instance via a [`PerTenantInstanceRegistry`]. An unresolved / absent host REFUSES —
//!    never a wildcard, never a default/fallback tenant. The tenant is **never** taken from a
//!    guest-supplied field; the routing API has no parameter for one.
//! 2. **What tenant identity do that instance's calls OUT to a shared backend carry?** (artifact #2).
//!    The per-tenant instance's identity is [`WiredTenantIdentity`]: read SOLELY from the
//!    root/compute-plane-wired [`PRIVSEP_TENANT_SCOPE_ENV`] and RE-VALIDATED with
//!    [`TenantScope::from_env_value`] — never from a guest-supplied tenant. A guest has nowhere to
//!    name a tenant (mirrors `privsep_authority::AuthorityContext`, which carries only a signed token
//!    and no caller-asserted id). The shared backend scopes by that unforgeable link identity;
//!    [`scope_backend_call`] refuses a guest that tries to name a FOREIGN tenant.
//!
//! **Seams to WS-C (the real compute plane — NOT built here).** [`PerTenantInstanceRegistry`] is the
//! trait WS-C implements over the live compute plane (spawn / wake / scale-to-zero); WS-B routes
//! against it and ships only an in-process [`MockRegistry`] for tests. An absent instance
//! ([`PerTenantInstanceRegistry::resolve`] → `None`) is a well-defined [`RouteOutcome::NotReady`] —
//! WS-B surfaces it; it never wakes/spawns and never falls back to another tenant. The relay REUSES
//! the existing `local` feature-link transport ([`crate::privsep_link::LinkEndpoint`]'s
//! `SCM_RIGHTS` client-fd pass) via [`LinkEndpointRelay`]; the frontend accept-loop that drives it
//! per connection (and parses the `Host` to route on) is WS-C's integration with the live per-tenant
//! instances. Nothing here is Linux-gated: the routing / keying / identity core is pure and
//! host-testable, and the fd relay runs its round-trip test on any Unix host.

use std::sync::Arc;

use boatramp_core::deploy::DeployStore;
use boatramp_core::privsep::{PRIVSEP_TENANT_SCOPE_ENV, TenantScope, TenantScopeError};

/// A raw accepted-client-connection fd number to splice to a per-tenant instance (a Unix fd;
/// privsep is Unix/Linux-only live). Kept a plain integer so the routing core compiles on every
/// target — the actual `SCM_RIGHTS` pass is the `cfg(unix)` [`LinkEndpointRelay`].
pub type ClientConnFd = std::os::raw::c_int;

// =============================================================================
// The per-tenant instance link + the relay seam (deliverable 1 + 3)
// =============================================================================

/// The transport to ONE tenant's per-tenant instance — the relay half of a [`TenantInstanceLink`].
/// The live implementation is [`LinkEndpointRelay`] (the root/compute-plane-wired `local`
/// socketpair, reusing [`crate::privsep_link::LinkEndpoint::send_client_conn`]); tests use
/// [`MockRelay`]. The received client fd confers **NO authority** (design F5): the backend serves it
/// as opaque client bytes and takes its tenant identity from its OWN wired env, never from the wire.
pub trait PerTenantRelay: Send + Sync + std::fmt::Debug {
    /// An opaque identity for the per-tenant instance behind this link — for routing assertions +
    /// logs (e.g. the instance's process label / scope). NOT an authority token.
    fn instance_id(&self) -> &str;

    /// Relay one accepted CLIENT connection (by raw fd) + its parsed request `head` to the per-tenant
    /// instance over the wired local link (frontend→backend, unidirectional; the response streams
    /// back over the client socket the backend now holds). The `head` is frontend-set (NOT
    /// guest-set) and carries the non-authoritative routing marker ([`routing_head`]); the backend's
    /// authority is always its env-wired identity. Fail-closed on a transport error.
    fn relay_client(&self, client_fd: ClientConnFd, head: &[u8]) -> std::io::Result<()>;
}

/// A routed handle to one tenant's per-tenant `exec.wasmtime` instance (deliverable 1). Carries the
/// UNFORGEABLE [`TenantScope`] the instance is keyed for (the project), plus the [`PerTenantRelay`]
/// to splice a request over. WS-C's registry builds these over the live compute plane; the mock
/// builds them over an in-process recorder.
#[derive(Clone, Debug)]
pub struct TenantInstanceLink {
    scope: TenantScope,
    relay: Arc<dyn PerTenantRelay>,
}

impl TenantInstanceLink {
    /// Wire a link for `scope` over `relay`.
    pub fn new(scope: TenantScope, relay: Arc<dyn PerTenantRelay>) -> Self {
        Self { scope, relay }
    }

    /// The tenant scope (project) this link routes to. Always a valid single-project slug — never a
    /// wildcard / default (enforced by [`TenantScope::resolve`] at routing time).
    pub fn scope(&self) -> &TenantScope {
        &self.scope
    }

    /// The opaque per-tenant instance identity behind this link (for assertions + logs).
    pub fn instance_id(&self) -> &str {
        self.relay.instance_id()
    }

    /// Relay one accepted client connection + its head to the per-tenant instance (delegates to the
    /// wired [`PerTenantRelay`]).
    pub fn relay_client(&self, client_fd: ClientConnFd, head: &[u8]) -> std::io::Result<()> {
        self.relay.relay_client(client_fd, head)
    }
}

/// The seam WS-C implements: given a resolved [`TenantScope`] (a project), return the link/handle to
/// that tenant's per-tenant `exec.wasmtime` instance. WS-B routes against this trait; the real
/// compute-plane-backed implementation (spawn / wake / scale-to-zero / pooled-per-tenant) is WS-C.
///
/// The "instance absent" behavior is a seam to WS-C: [`resolve`](Self::resolve) returns `None` when
/// no instance is currently instantiated for `scope`, which WS-B surfaces as
/// [`RouteOutcome::NotReady`] — a well-defined "not-ready/wake" outcome. WS-B NEVER wakes/spawns here
/// and NEVER falls back to another tenant.
pub trait PerTenantInstanceRegistry: Send + Sync {
    /// The live per-tenant instance link for `scope`, or `None` when none is instantiated (the WS-C
    /// wake seam). The returned link's [`scope`](TenantInstanceLink::scope) MUST equal `scope`.
    fn resolve(&self, scope: &TenantScope) -> Option<TenantInstanceLink>;
}

// =============================================================================
// Frontend → per-tenant routing (deliverable 2 — Security artifact #1)
// =============================================================================

/// The result of routing a request to a per-tenant instance.
#[derive(Debug)]
pub enum RouteOutcome {
    /// Routed: the host resolved to a valid tenant scope AND the registry has a live instance for it.
    Routed(TenantInstanceLink),
    /// The host resolved to a valid tenant [`TenantScope`], but no instance is instantiated for it
    /// yet — the WS-C wake / scale-from-zero seam. WS-B surfaces this; it does NOT wake and does NOT
    /// route the request anywhere else (never a fallback tenant). The scope is carried so WS-C can
    /// instantiate exactly that tenant's instance.
    NotReady(TenantScope),
}

/// Why per-tenant routing REFUSED — every arm is fail-closed (no wildcard, no default/fallback
/// tenant; design §Phase-4 / Security artifact #1, the #1 leak surface). Carries only non-secret
/// reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteRefusal {
    /// The routed `Host` matched no verified virtualhost ([`DeployStore::resolve_site_by_host`] →
    /// `None`), or carried no host at all. Fail-closed: a request with no resolved tenant is REFUSED —
    /// it is never served by a wildcard, a default site, or any fallback tenant (unlike the monolith
    /// serve path, which may fall back to `default_site`; per-tenant routing deliberately does not).
    UnresolvedHost,
    /// The host resolved to a project, but that project is not a valid single tenant scope (empty,
    /// a wildcard, or a non-slug value). Fail-closed via [`TenantScope::resolve`].
    BadScope(TenantScopeError),
    /// [`DeployStore::resolve_site_by_host`] itself errored (a store/IO failure). Fail-closed: a
    /// resolution that could not complete is refused, never guessed. Carries a non-secret message.
    Resolve(String),
    /// The [`PerTenantInstanceRegistry`] returned a link keyed to a DIFFERENT scope than the one
    /// requested (a WS-C mis-keying bug at the #1 tenant-keying boundary). Fail-closed, RELEASE-active:
    /// routing a request to an instance keyed for another tenant would cross tenants (the #1 leak
    /// surface), so a mismatch REFUSES rather than routes — it is never guessed or coerced. Carries
    /// only the non-secret project slugs (what was requested vs. what the registry returned).
    RegistryScopeMismatch {
        /// The project slug WS-B resolved from the host and asked the registry for (authoritative).
        requested: String,
        /// The project slug of the link the registry actually returned (the mis-key).
        returned: String,
    },
}

impl std::fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnresolvedHost => f.write_str(
                "per-tenant routing refused: the routed host resolved to no verified tenant \
                 (refusing fail-closed — never a wildcard, a default site, or a fallback tenant)",
            ),
            Self::BadScope(e) => write!(f, "per-tenant routing refused: {e}"),
            Self::Resolve(e) => write!(
                f,
                "per-tenant routing refused: host→project resolution failed ({e}) — refusing \
                 fail-closed rather than guessing a tenant"
            ),
            Self::RegistryScopeMismatch {
                requested,
                returned,
            } => write!(
                f,
                "per-tenant routing refused: the registry returned a link keyed for project \
                 {returned:?} but the request resolved to {requested:?} — refusing fail-closed \
                 rather than routing a request to another tenant's instance (the resolved scope is \
                 authoritative; a mismatch is a registry/keying bug)"
            ),
        }
    }
}

impl std::error::Error for RouteRefusal {}

/// Route a request to its per-tenant instance from the STRUCTURALLY-resolved project (the PURE,
/// fail-closed core of artifact #1; host-testable). `resolved_project` is the project
/// [`DeployStore::resolve_site_by_host`] returned for the routed `Host` header — Stage 0, before any
/// guest byte — and is `None` when the host matched no verified virtualhost. **It is NEVER a
/// guest-supplied value**: this function has no parameter by which a guest could name a tenant, so a
/// spoofed `X-Tenant` header / body field can never change the routed instance.
///
/// Fail-closed, in order:
/// - `None` (unresolved/absent host) ⇒ [`RouteRefusal::UnresolvedHost`] — never a fallback tenant;
/// - a non-slug / wildcard / empty project ⇒ [`RouteRefusal::BadScope`] (via [`TenantScope::resolve`]);
/// - resolved + a live instance ⇒ [`RouteOutcome::Routed`];
/// - resolved + no instance ⇒ [`RouteOutcome::NotReady`] (the WS-C wake seam).
pub fn route_resolved_host(
    resolved_project: Option<&str>,
    registry: &dyn PerTenantInstanceRegistry,
) -> Result<RouteOutcome, RouteRefusal> {
    // Fail-closed: a host that resolved to no verified tenant is refused — NOT served by a wildcard,
    // a default site, or any fallback tenant (artifact #1, the #1 leak surface).
    let project = resolved_project.ok_or(RouteRefusal::UnresolvedHost)?;
    // Fail-closed: re-run the WS-A validator so a wildcard / path-traversal / over-length project can
    // never become a tenant key (the same rule the data plane keys tenant namespaces by).
    let scope = TenantScope::resolve(project).map_err(RouteRefusal::BadScope)?;
    match registry.resolve(&scope) {
        Some(link) => {
            // The registry must key the link by the SAME scope WS-B resolved — the resolved scope is
            // authoritative. A mismatch is a WS-C mis-keying bug at the #1 tenant-keying boundary;
            // routing a request to a link keyed for another tenant would cross tenants. Refuse
            // fail-closed, RELEASE-active (not a `debug_assert`, which is compiled out in release and
            // would silently mis-route there), and panic-free — BEFORE building the routing head /
            // returning the route.
            if link.scope() != &scope {
                return Err(RouteRefusal::RegistryScopeMismatch {
                    requested: scope.project().to_string(),
                    returned: link.scope().project().to_string(),
                });
            }
            Ok(RouteOutcome::Routed(link))
        }
        None => Ok(RouteOutcome::NotReady(scope)),
    }
}

/// Route a request to its per-tenant instance from the routed `Host` header (the async wrapper
/// mirroring `serve_pipeline::serve_by_host_inner`'s Stage-0 structural resolution). Resolves the
/// project via [`DeployStore::resolve_site_by_host`] — the SAME source of truth the monolith uses,
/// keyed off the structurally-routed host, before any guest byte — then delegates to the pure
/// [`route_resolved_host`]. The tenant is taken ONLY from this host resolution, never from a
/// guest-supplied field.
pub async fn route_by_host(
    deploy: &DeployStore,
    host: &str,
    registry: &dyn PerTenantInstanceRegistry,
) -> Result<RouteOutcome, RouteRefusal> {
    let owner = deploy
        .resolve_site_by_host(host)
        .await
        .map_err(|e| RouteRefusal::Resolve(e.to_string()))?;
    route_resolved_host(owner.as_ref().map(|o| o.project.as_str()), registry)
}

/// The non-authoritative routing marker the frontend sets in the relay `head` for an accepted
/// connection: the routed project id, UTF-8. It lets the backend CROSS-CHECK that the frontend
/// spliced it the right tenant's connection ([`WiredTenantIdentity::matches_routed`]) as
/// defence-in-depth — but it is NEVER the backend's authority (that is always the env-wired
/// [`WiredTenantIdentity`], artifact #2). WS-C/WS-E extend this head with the full typed request.
pub fn routing_head(scope: &TenantScope) -> Vec<u8> {
    scope.project().as_bytes().to_vec()
}

// =============================================================================
// Unforgeable backend-call tenant identity (deliverable 4 — Security artifact #2)
// =============================================================================

/// Why a per-tenant instance could not establish its [`WiredTenantIdentity`] — fail-closed in every
/// arm (an instance that cannot prove its own tenant must not serve).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WiredTenantIdentityError {
    /// [`PRIVSEP_TENANT_SCOPE_ENV`] is absent — the instance was not wired a tenant scope. Fail-closed:
    /// a per-tenant instance with no wired scope has no identity to stamp backend calls with and must
    /// not serve (it would otherwise reach the shared backend unscoped).
    Unwired,
    /// [`PRIVSEP_TENANT_SCOPE_ENV`] held a value that failed re-validation ([`TenantScope::from_env_value`]):
    /// a tampered / truncated / wildcard / malformed scope is refused exactly as a bad host resolution
    /// would be, rather than trusted because it arrived in the environment.
    Invalid(TenantScopeError),
    /// The env var could not be read as UTF-8 (a corrupt environment). Fail-closed.
    Unreadable,
}

impl std::fmt::Display for WiredTenantIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unwired => write!(
                f,
                "per-tenant instance has no wired tenant scope ({PRIVSEP_TENANT_SCOPE_ENV} is \
                 absent) — refusing fail-closed (an instance with no identity cannot scope a \
                 backend call)"
            ),
            Self::Invalid(e) => write!(
                f,
                "per-tenant instance's wired tenant scope failed re-validation: {e}"
            ),
            Self::Unreadable => write!(
                f,
                "per-tenant instance's wired tenant scope ({PRIVSEP_TENANT_SCOPE_ENV}) is not valid \
                 UTF-8 — refusing fail-closed"
            ),
        }
    }
}

impl std::error::Error for WiredTenantIdentityError {}

/// The UNFORGEABLE per-tenant identity of a per-tenant `exec.wasmtime` instance (Security artifact #2).
/// It is derived SOLELY from the root/compute-plane-wired [`PRIVSEP_TENANT_SCOPE_ENV`] and
/// RE-VALIDATED with [`TenantScope::from_env_value`] — the same fail-closed rule a host resolution
/// goes through — so a tampered/forged env value is refused rather than trusted. The instance stamps
/// every call OUT to a shared backend with THIS scope; a guest running in the instance has **nowhere
/// to name a tenant** (there is no tenant field it can set), exactly as a relayed
/// `privsep_authority::AuthorityContext` carries only a signed token and no caller-asserted id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiredTenantIdentity {
    scope: TenantScope,
}

impl WiredTenantIdentity {
    /// Re-derive the identity from an explicit [`PRIVSEP_TENANT_SCOPE_ENV`] value, re-validating
    /// fail-closed (the pure, host-testable form of [`from_env`](Self::from_env)). Used by the live
    /// instance with the value read from the environment, and by tests directly.
    pub fn from_env_value(value: &str) -> Result<Self, WiredTenantIdentityError> {
        let scope =
            TenantScope::from_env_value(value).map_err(WiredTenantIdentityError::Invalid)?;
        Ok(Self { scope })
    }

    /// Read + re-validate the identity from the process environment ([`PRIVSEP_TENANT_SCOPE_ENV`]).
    /// Fail-closed: an absent var is [`WiredTenantIdentityError::Unwired`]; a non-UTF-8 var is
    /// [`WiredTenantIdentityError::Unreadable`]; an invalid value is
    /// [`WiredTenantIdentityError::Invalid`]. The live per-tenant instance calls this once at boot,
    /// before serving, so an instance with no valid wired tenant never reaches the shared backend.
    pub fn from_env() -> Result<Self, WiredTenantIdentityError> {
        match std::env::var(PRIVSEP_TENANT_SCOPE_ENV) {
            Ok(v) => Self::from_env_value(&v),
            Err(std::env::VarError::NotPresent) => Err(WiredTenantIdentityError::Unwired),
            Err(std::env::VarError::NotUnicode(_)) => Err(WiredTenantIdentityError::Unreadable),
        }
    }

    /// The unforgeable tenant scope (project) this instance is wired for.
    pub fn scope(&self) -> &TenantScope {
        &self.scope
    }

    /// The backend keyspace prefix (`project/<id>/…`) every backend call this instance makes is
    /// scoped to. The identity grants no authority — it only narrows the backend namespace.
    pub fn resource_prefix(&self) -> String {
        self.scope.resource_prefix()
    }

    /// Whether the frontend's routing marker ([`routing_head`]) matches this instance's wired
    /// identity — a defence-in-depth consistency check (did the frontend splice us the right
    /// tenant's connection?). The wired identity remains authoritative either way; a mismatch is a
    /// routing bug to refuse loudly, NOT a path by which the head overrides the env.
    pub fn matches_routed(&self, head: &[u8]) -> bool {
        head == self.scope.project().as_bytes()
    }
}

/// A guest tried to name a tenant OTHER than its instance's wired identity on a backend call —
/// refused fail-closed (Security artifact #2: a guest cannot name another tenant). Carries only the
/// non-secret project slugs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignTenantRefusal {
    /// The instance's own unforgeable wired tenant (the only one it may scope to).
    pub wired: String,
    /// The foreign tenant the guest attempted to name.
    pub attempted: String,
}

impl std::fmt::Display for ForeignTenantRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend call refused: a guest in tenant {:?} attempted to name tenant {:?} — a guest \
             cannot name another tenant; backend calls are scoped by the unforgeable wired identity",
            self.wired, self.attempted
        )
    }
}

impl std::error::Error for ForeignTenantRefusal {}

/// Scope a backend call by the instance's UNFORGEABLE wired identity, refusing any guest attempt to
/// name a FOREIGN tenant (Security artifact #2). The returned [`TenantScope`] — the one the shared
/// backend keys by — is ALWAYS the wired identity, NEVER a guest-supplied value:
/// - `guest_supplied_tenant = None` ⇒ the guest named no tenant (the normal shape — a guest has no
///   tenant field): scope to the wired identity;
/// - `Some(t)` where `t` is the instance's own wired project ⇒ a redundant self-reference: allowed,
///   scoped to the wired identity;
/// - `Some(t)` naming a DIFFERENT project ⇒ [`ForeignTenantRefusal`], fail-closed.
///
/// So even an allowed guest assertion never *selects* the tenant — it is only checked against the
/// wired identity. The shared backend never reads a tenant off the guest.
pub fn scope_backend_call(
    wired: &WiredTenantIdentity,
    guest_supplied_tenant: Option<&str>,
) -> Result<TenantScope, ForeignTenantRefusal> {
    match guest_supplied_tenant {
        None => Ok(wired.scope().clone()),
        Some(t) if t == wired.scope().project() => Ok(wired.scope().clone()),
        Some(t) => Err(ForeignTenantRefusal {
            wired: wired.scope().project().to_string(),
            attempted: t.to_string(),
        }),
    }
}

// =============================================================================
// The real `local`-link relay (deliverable 3) — reuses privsep_link's SCM_RIGHTS pass
// =============================================================================

/// The LIVE [`PerTenantRelay`] over a root/compute-plane-wired `local` feature-link
/// ([`crate::privsep_link::LinkEndpoint`]). It REUSES the existing serving-splice transport
/// (`send_client_conn` = a `SCM_RIGHTS` client-fd pass + a length-delimited head) unchanged,
/// parameterized with the per-tenant instance's identity + scope — it does NOT reinvent the
/// transport. WS-C builds one of these per per-tenant instance from the link fd the root/compute
/// plane wired, and registers it in its [`PerTenantInstanceRegistry`].
#[cfg(unix)]
#[derive(Debug)]
pub struct LinkEndpointRelay {
    instance_id: String,
    link: Arc<crate::privsep_link::LinkEndpoint>,
}

#[cfg(unix)]
impl LinkEndpointRelay {
    /// Wire a relay to the per-tenant instance `instance_id` over `link` (its root-wired socketpair
    /// end to that instance).
    pub fn new(
        instance_id: impl Into<String>,
        link: Arc<crate::privsep_link::LinkEndpoint>,
    ) -> Self {
        Self {
            instance_id: instance_id.into(),
            link,
        }
    }
}

#[cfg(unix)]
impl PerTenantRelay for LinkEndpointRelay {
    fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn relay_client(&self, client_fd: ClientConnFd, head: &[u8]) -> std::io::Result<()> {
        use std::os::fd::BorrowedFd;
        // SAFETY: `client_fd` is a live accepted-connection fd the FRONTEND owns for the duration of
        // this call (it drops its copy only after the SCM_RIGHTS pass duplicates it to the backend).
        // We only borrow it to hand to `send_client_conn`; we never take ownership or close it.
        let client = unsafe { BorrowedFd::borrow_raw(client_fd) };
        self.link.send_client_conn(client, head)
    }
}

// =============================================================================
// In-process mock (tests + a WS-C reference shape)
// =============================================================================

/// An in-process [`PerTenantRelay`] for tests: records every relayed `(client_fd, head)` so a test
/// can assert WHICH instance a connection was spliced to and that the routing head carried the
/// scope. No real fd passing — the fd number is recorded verbatim.
#[derive(Debug)]
pub struct MockRelay {
    instance_id: String,
    relayed: std::sync::Mutex<Vec<(ClientConnFd, Vec<u8>)>>,
}

impl MockRelay {
    /// A mock relay to a per-tenant instance identified by `instance_id`.
    pub fn new(instance_id: impl Into<String>) -> Self {
        Self {
            instance_id: instance_id.into(),
            relayed: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Every `(client_fd, head)` relayed through this mock, in order.
    pub fn relayed(&self) -> Vec<(ClientConnFd, Vec<u8>)> {
        self.relayed.lock().unwrap().clone()
    }
}

impl PerTenantRelay for MockRelay {
    fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn relay_client(&self, client_fd: ClientConnFd, head: &[u8]) -> std::io::Result<()> {
        self.relayed
            .lock()
            .unwrap()
            .push((client_fd, head.to_vec()));
        Ok(())
    }
}

/// An in-process [`PerTenantInstanceRegistry`] for tests: a fixed map of project → per-tenant
/// instance (its [`MockRelay`]). A project with no entry resolves to `None`
/// ([`RouteOutcome::NotReady`], the WS-C wake seam). Each entry's link is keyed by the project's own
/// [`TenantScope`], so a lookup for a DIFFERENT project never returns another tenant's link.
#[derive(Debug, Default)]
pub struct MockRegistry {
    instances: std::collections::BTreeMap<String, Arc<MockRelay>>,
}

impl MockRegistry {
    /// An empty registry (every scope resolves to `None`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a live per-tenant instance for `project` (the instance id defaults to
    /// `instance:<project>`). Panics if `project` is not a valid tenant slug — a test fixture must
    /// use real project slugs.
    pub fn with_instance(mut self, project: &str) -> Self {
        assert!(
            TenantScope::resolve(project).is_ok(),
            "MockRegistry fixture project {project:?} is not a valid tenant slug"
        );
        self.instances.insert(
            project.to_string(),
            Arc::new(MockRelay::new(format!("instance:{project}"))),
        );
        self
    }

    /// The recorded [`MockRelay`] for `project`, if an instance is registered (to inspect what was
    /// relayed to that tenant's instance).
    pub fn relay_for(&self, project: &str) -> Option<Arc<MockRelay>> {
        self.instances.get(project).cloned()
    }
}

impl PerTenantInstanceRegistry for MockRegistry {
    fn resolve(&self, scope: &TenantScope) -> Option<TenantInstanceLink> {
        let relay = self.instances.get(scope.project())?.clone();
        Some(TenantInstanceLink::new(scope.clone(), relay))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- deliverable 2 / artifact #1: frontend → per-tenant routing ----

    #[test]
    fn resolved_host_routes_to_its_own_tenant_instance() {
        let registry = MockRegistry::new()
            .with_instance("shop-alpha")
            .with_instance("shop-beta");

        match route_resolved_host(Some("shop-alpha"), &registry).unwrap() {
            RouteOutcome::Routed(link) => {
                assert_eq!(link.scope().project(), "shop-alpha");
                assert_eq!(link.instance_id(), "instance:shop-alpha");
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    #[test]
    fn a_different_host_routes_to_a_different_instance() {
        let registry = MockRegistry::new()
            .with_instance("shop-alpha")
            .with_instance("shop-beta");

        let a = match route_resolved_host(Some("shop-alpha"), &registry).unwrap() {
            RouteOutcome::Routed(l) => l.instance_id().to_string(),
            other => panic!("expected Routed, got {other:?}"),
        };
        let b = match route_resolved_host(Some("shop-beta"), &registry).unwrap() {
            RouteOutcome::Routed(l) => l.instance_id().to_string(),
            other => panic!("expected Routed, got {other:?}"),
        };
        assert_ne!(
            a, b,
            "two different tenants must route to two different instances"
        );
        assert_eq!(a, "instance:shop-alpha");
        assert_eq!(b, "instance:shop-beta");
    }

    #[test]
    fn a_spoofed_guest_tenant_never_changes_the_routed_instance() {
        // Artifact #1: the tenant is taken ONLY from the structurally-resolved host. There is no
        // parameter by which a guest could name a tenant, so a spoofed value is structurally
        // unreachable. We model a request whose host resolves to `shop-alpha` while the guest ALSO
        // asserts `shop-beta` in some body/header field, and show the route is unchanged.
        let registry = MockRegistry::new()
            .with_instance("shop-alpha")
            .with_instance("shop-beta");

        // The structurally-resolved host (the ONLY routing input).
        let host_resolved_project = Some("shop-alpha");
        // A guest-supplied tenant claim — deliberately NOT passed to the router (it has no such arg).
        let _spoofed_guest_claim = "shop-beta";

        match route_resolved_host(host_resolved_project, &registry).unwrap() {
            RouteOutcome::Routed(link) => {
                assert_eq!(
                    link.scope().project(),
                    "shop-alpha",
                    "routing must follow the host, never the guest-supplied tenant"
                );
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    // ---- fail-closed routing ----

    #[test]
    fn an_unresolved_host_refuses_with_no_fallback_tenant() {
        let registry = MockRegistry::new().with_instance("shop-alpha");
        // `None` = resolve_site_by_host found no verified virtualhost.
        let refusal = route_resolved_host(None, &registry).unwrap_err();
        assert_eq!(refusal, RouteRefusal::UnresolvedHost);
    }

    #[test]
    fn an_empty_host_refuses() {
        let registry = MockRegistry::new().with_instance("shop-alpha");
        let refusal = route_resolved_host(Some(""), &registry).unwrap_err();
        assert!(matches!(
            refusal,
            RouteRefusal::BadScope(TenantScopeError::Unresolved)
        ));
    }

    #[test]
    fn a_wildcard_host_refuses_never_selecting_every_tenant() {
        let registry = MockRegistry::new().with_instance("shop-alpha");
        let refusal = route_resolved_host(Some("*"), &registry).unwrap_err();
        assert!(matches!(
            refusal,
            RouteRefusal::BadScope(TenantScopeError::Wildcard { .. })
        ));
    }

    #[test]
    fn a_path_traversal_project_refuses() {
        let registry = MockRegistry::new().with_instance("shop-alpha");
        let refusal = route_resolved_host(Some("../victim"), &registry).unwrap_err();
        assert!(matches!(
            refusal,
            RouteRefusal::BadScope(TenantScopeError::Malformed { .. })
        ));
    }

    #[test]
    fn a_resolved_host_with_no_instance_is_not_ready_not_a_fallback() {
        // `shop-gamma` is a valid tenant, but the registry has no live instance for it.
        let registry = MockRegistry::new().with_instance("shop-alpha");
        match route_resolved_host(Some("shop-gamma"), &registry).unwrap() {
            RouteOutcome::NotReady(scope) => assert_eq!(scope.project(), "shop-gamma"),
            other => panic!("expected NotReady (the WS-C wake seam), got {other:?}"),
        }
    }

    /// A deliberately BROKEN registry (a WS-C mis-keying bug model): it IGNORES the requested scope
    /// and always returns a link keyed to a FIXED project — so a lookup for one tenant hands back
    /// another tenant's link. Used only by the LOW-1 scope↔link consistency test.
    #[derive(Debug)]
    struct MiskeyedRegistry {
        returned_project: String,
    }

    impl PerTenantInstanceRegistry for MiskeyedRegistry {
        fn resolve(&self, _requested: &TenantScope) -> Option<TenantInstanceLink> {
            let returned =
                TenantScope::resolve(&self.returned_project).expect("valid fixture slug");
            Some(TenantInstanceLink::new(
                returned,
                Arc::new(MockRelay::new("instance:wrong-tenant")),
            ))
        }
    }

    #[test]
    fn a_registry_returning_a_mis_keyed_link_refuses_release_active_not_a_route() {
        // LOW-1: at the #1 tenant-keying boundary, a registry that hands back a link keyed for a
        // DIFFERENT scope than requested must be REFUSED fail-closed (RELEASE-active, panic-free) —
        // not routed, not silently mis-routed. (The old `debug_assert_eq!` was compiled out in release
        // and would silently return the wrong tenant's link there.) This test runs under normal,
        // release-semantics expectations: it asserts a refusal value, not a panic.
        let registry = MiskeyedRegistry {
            returned_project: "shop-beta".to_string(),
        };
        let refusal = route_resolved_host(Some("shop-alpha"), &registry).unwrap_err();
        assert!(
            matches!(
                &refusal,
                RouteRefusal::RegistryScopeMismatch { requested, returned }
                    if requested == "shop-alpha" && returned == "shop-beta"
            ),
            "expected a RegistryScopeMismatch refusal (not a route, no panic), got {refusal:?}"
        );
    }

    // ---- deliverable 4 / artifact #2: unforgeable backend-call tenant identity ----

    #[test]
    fn wired_identity_re_validates_the_env_scope() {
        let id = WiredTenantIdentity::from_env_value("shop-alpha").unwrap();
        assert_eq!(id.scope().project(), "shop-alpha");
        assert_eq!(id.resource_prefix(), "project/shop-alpha/");
    }

    #[test]
    fn a_tampered_wired_scope_is_refused_not_trusted() {
        // A tampered/forged env value is refused by re-validation rather than trusted because it
        // arrived in the environment (artifact #2).
        for bad in ["", "*", "../victim", "a/b", "shop alpha"] {
            let err = WiredTenantIdentity::from_env_value(bad).unwrap_err();
            assert!(
                matches!(err, WiredTenantIdentityError::Invalid(_)),
                "expected Invalid for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn a_backend_call_carries_the_wired_identity_when_the_guest_names_nothing() {
        let wired = WiredTenantIdentity::from_env_value("shop-alpha").unwrap();
        // The normal shape: a guest has no tenant field, so None.
        let scope = scope_backend_call(&wired, None).unwrap();
        assert_eq!(scope.project(), "shop-alpha");
    }

    #[test]
    fn a_guest_naming_its_own_tenant_is_allowed_but_still_scopes_to_the_wired_identity() {
        let wired = WiredTenantIdentity::from_env_value("shop-alpha").unwrap();
        let scope = scope_backend_call(&wired, Some("shop-alpha")).unwrap();
        assert_eq!(scope.project(), "shop-alpha");
    }

    #[test]
    fn a_guest_naming_a_foreign_tenant_is_refused() {
        // Artifact #2: a guest cannot name another tenant.
        let wired = WiredTenantIdentity::from_env_value("shop-alpha").unwrap();
        let err = scope_backend_call(&wired, Some("shop-beta")).unwrap_err();
        assert_eq!(err.wired, "shop-alpha");
        assert_eq!(err.attempted, "shop-beta");
    }

    #[test]
    fn the_routing_head_is_a_consistency_marker_not_an_authority() {
        let wired = WiredTenantIdentity::from_env_value("shop-alpha").unwrap();
        let own = TenantScope::resolve("shop-alpha").unwrap();
        let foreign = TenantScope::resolve("shop-beta").unwrap();
        assert!(wired.matches_routed(&routing_head(&own)));
        assert!(!wired.matches_routed(&routing_head(&foreign)));
    }

    // ---- deliverable 3: the real local-link relay (reuses privsep_link's SCM_RIGHTS pass) ----

    #[cfg(unix)]
    #[test]
    fn link_endpoint_relay_round_trips_a_client_fd_with_the_scope_head() {
        use crate::privsep_link::LinkEndpoint;
        use std::os::fd::AsRawFd;

        // The root-wired per-tenant link: `front` is the frontend end, `back` the backend end.
        let (front, back) = LinkEndpoint::socketpair().expect("socketpair");
        let registry = MockRegistryWired::wire("shop-alpha", Arc::new(front));

        // A real accepted "client" connection to splice (a second socketpair end stands in).
        let (client_a, client_b) = LinkEndpoint::socketpair().expect("client socketpair");

        // Route `shop-alpha` → the wired link, then relay the client fd with the routing head,
        // exactly as the frontend would.
        let outcome = route_resolved_host(Some("shop-alpha"), &registry).unwrap();
        let link = match outcome {
            RouteOutcome::Routed(l) => l,
            other => panic!("expected Routed, got {other:?}"),
        };
        assert_eq!(link.instance_id(), "instance:shop-alpha");
        let head = routing_head(link.scope());
        link.relay_client(client_a.as_raw_fd(), &head)
            .expect("relay the client fd over the real local link");
        drop(client_a); // SCM_RIGHTS duplicated it to the backend end.

        // The backend receives the passed client fd + the scope head over the real link.
        let (recv_fd, recv_head) = back.recv_client_conn().expect("recv the client fd");
        assert_eq!(recv_head, b"shop-alpha", "the scope rode in the relay head");
        // The received fd is a live, distinct client socket fd (SCM_RIGHTS duplicated it).
        assert!(recv_fd.as_raw_fd() >= 0);
        drop(recv_fd);
        drop(client_b);
        drop(back);
    }

    /// A tiny `cfg(unix)` registry wiring a single real [`LinkEndpointRelay`] — used only by the
    /// round-trip relay test to prove routing hands back the live link.
    #[cfg(unix)]
    #[derive(Debug)]
    struct MockRegistryWired {
        project: String,
        relay: Arc<LinkEndpointRelay>,
    }

    #[cfg(unix)]
    impl MockRegistryWired {
        fn wire(project: &str, link: Arc<crate::privsep_link::LinkEndpoint>) -> Self {
            Self {
                project: project.to_string(),
                relay: Arc::new(LinkEndpointRelay::new(format!("instance:{project}"), link)),
            }
        }
    }

    #[cfg(unix)]
    impl PerTenantInstanceRegistry for MockRegistryWired {
        fn resolve(&self, scope: &TenantScope) -> Option<TenantInstanceLink> {
            if scope.project() == self.project {
                Some(TenantInstanceLink::new(scope.clone(), self.relay.clone()))
            } else {
                None
            }
        }
    }
}
