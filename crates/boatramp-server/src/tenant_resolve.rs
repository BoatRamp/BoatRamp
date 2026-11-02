//! Server-side resolution of a function/site's declared [`Tenancy`] into the host-applied
//! [`HostTenancy`] the `sql`/`orm` bindings enforce (Stage 0).
//!
//! Crate layering: the JWT/JWKS verifier lives here in `boatramp-server` (it pulls
//! `jsonwebtoken`/`reqwest`), so we resolve the tenant **value** here and hand the binding a
//! ready [`HostTenancy`] — the binding never learns how the value was sourced. The verifier is
//! reused from the GraphQL data connector ([`crate::graphql_data::token`]).
//!
//! Two things are enforced here, above the compiler:
//! - **Dimension 0** — a sql/orm importer with an *undeclared* tenancy is **refused** under a
//!   posture that `require_tenancy_declaration` (multi-tenant), so running plain is always a
//!   reviewed decision.
//! - **The cross-tenant ceiling** — an `all` grant is **capped to `own`** unless the posture
//!   `allow_cross_tenant_db`, so a misconfigured or compromised tenant can't read the fleet even
//!   if its config asks to.

use boatramp_core::config::HandlerGraphqlTokenClaims;
use boatramp_core::tenancy::{AccessMode, PrincipalKind, Tenancy, TenantSource};
use boatramp_handlers::HostTenancy;

/// Everything needed to resolve the tenant value for one invocation. Each caller fills what its
/// trigger has: an HTTP request has a `bearer` and a `domain_context`; a background consumer/cron
/// has neither (so an "own" source fails closed).
#[derive(Default, Clone, Copy)]
pub(crate) struct TenantSourceInputs<'a> {
    /// The request's verified-app bearer (for [`TenantSource::Token`]).
    pub bearer: Option<&'a str>,
    /// The routed domain's context tag (for [`TenantSource::Domain`]).
    pub domain_context: Option<&'a str>,
    /// The JWKS/issuer config used to verify the bearer (reused from the GDC's `claims_from_token`).
    /// Absent ⇒ the token source can't verify, so it resolves to no value (fail-closed).
    pub token_cfg: Option<&'a HandlerGraphqlTokenClaims>,
    /// The host-issued anonymous **session cookie** value (R3), if the request carried one. Verified
    /// (signature + expiry) against [`session_anchor`](Self::session_anchor) to populate the
    /// [`ScopeAxis::Session`](boatramp_core::tenancy::ScopeAxis) fact — independent of the tenant
    /// source. Absent / unverifiable ⇒ no session fact (the disjunct then has only the tenant arm).
    pub session_cookie: Option<&'a str>,
    /// The fleet public key that verifies a session cookie (the issuing [`Signer`]'s public half).
    /// `None` ⇒ session cookies can't be verified here, so no session fact is resolved.
    pub session_anchor: Option<&'a boatramp_core::cose::TokenPublicKey>,
    /// The host-minted **durable signed-context** envelope (R1) carried on a durable message the
    /// async lane is draining (for [`TenantSource::SignedContext`]). Verified (signature + expiry +
    /// `br_kind == "context"`) against [`context_anchor`](Self::context_anchor); a forged/absent
    /// envelope resolves no value, so an "own" op on the async lane fails closed. The producer's
    /// tenant is stamped host-side at publish — the guest never names it.
    pub signed_context: Option<&'a str>,
    /// The fleet public key that verifies a signed-context envelope (the issuing [`Signer`]'s
    /// public half — the same key that mints/verifies session cookies). `None` ⇒ signed contexts
    /// can't be verified here, so the `SignedContext` source resolves no value (fail-closed).
    pub context_anchor: Option<&'a boatramp_core::cose::TokenPublicKey>,
    /// Injectable source for the `token_cfg.jwks_env` host-env lookup (the JWKS the `Token` source
    /// verifies against). Production passes the runtime's `inner.env_source()` (⇒ the real process
    /// env); a test passes a `MapEnv` so the JWKS is injected without mutating the process
    /// environment. `None` ⇒ the real process env ([`SystemEnv`](boatramp_core::env::SystemEnv)) —
    /// the default for a lane that carries no token (async/background), where it is never read.
    pub env_source: Option<&'a dyn boatramp_core::env::EnvSource>,
    /// Inputs for the [`TenantSource::SealedState`] source (the pre-auth SSO callback): the request
    /// param lookup, the host `[secrets]` key envelope that unseals the state token, the
    /// host-resolved project+site (bound into the seal at mint, re-checked here), and the real-tenant
    /// registry. `None` on any lane with no request params / no host envelope (async/background) ⇒
    /// the `sealed-state` source resolves no value (fail-closed). Bundled so the whole capability is
    /// present-or-absent atomically.
    pub sealed_state: Option<SealedStateInputs<'a>>,
    /// Inputs for the [`TenantSource::PreAuthRequest`] source (construens #2 — the pre-auth SSO
    /// login-start firm selection): the request param/path lookup, the (optionally buffered) request
    /// body for the `body` location, the routed-host context for the `host` location, the
    /// host-resolved project, and the configured-firm registry. `None` on any lane with no request
    /// surface (async/background) ⇒ the `pre_auth_request` source resolves no value (fail-closed).
    pub preauth: Option<PreAuthInputs<'a>>,
}

/// A buffered request body for the [`TenantSource::PreAuthRequest`] `body` location (construens #2).
/// The serving path buffers it (up to the selector's size cap) and snapshots the `Content-Type`
/// ONLY for a route that declared a `body`-location pre-auth source, so the body parse never touches
/// the per-tenant serving hot path. Borrowed by [`PreAuthInputs`].
pub(crate) struct PreAuthBody {
    /// The request `Content-Type` header value (for content-type dispatch), or `None`.
    pub content_type: Option<String>,
    /// The buffered body bytes (already capped at the serving buffer; re-checked at parse).
    pub bytes: Vec<u8>,
}

/// Everything the [`TenantSource::PreAuthRequest`] source needs at the (pre-auth) login-start.
/// `params`/`body`/`registry` are host-held references; `domain_context` is the routed-host context
/// tag (for the `host` location); `project` is THIS request's host-resolved project (passed to the
/// registry's configured-firm check). A trait-object registry so the resolver is unit-testable with
/// an in-memory set.
#[derive(Clone, Copy)]
pub(crate) struct PreAuthInputs<'a> {
    /// The request's query + path lookup (the `query`/`path` locations).
    pub params: &'a dyn RequestParams,
    /// The buffered request body (the `body` location); `None` when the route declared no body
    /// source (so the body was never buffered — the hot-path guarantee).
    pub body: Option<&'a PreAuthBody>,
    /// The routed-host context tag (the `host` location — the strongest signal, host-stamped at
    /// routing). `None` ⇒ the `host` location fails closed.
    pub domain_context: Option<&'a str>,
    /// This request's host-resolved project (passed to the configured-firm registry).
    pub project: &'a str,
    /// The configured-firm registry: a firm selector resolves ONLY to a provisioned/configured firm
    /// in the project (reuses the same [`TenantExists`] provisioning signal the `sealed-state`
    /// source's defense-in-depth check uses). An unknown/unconfigured selector fails closed.
    pub registry: &'a dyn TenantExists,
}

/// A request's parameter lookup surface for the `sealed-state` source — query params + headers. The
/// serving path implements it over the live HTTP request; a background/async lane has no such params
/// and passes no [`SealedStateInputs`] at all (the source then fails closed). A trait so the resolver
/// is unit-testable with an in-memory map.
pub(crate) trait RequestParams: Send + Sync {
    /// The first value of query parameter `name` (already percent-decoded), or `None`.
    fn query(&self, name: &str) -> Option<String>;
    /// The value of request header `name` (case-insensitive), or `None`.
    fn header(&self, name: &str) -> Option<String>;
    /// The request **path** (without the query string), e.g. `/sso/start/ten_X`. Used by the
    /// `pre_auth_request` source's `path` extraction (construens #2). Defaults to `None` for a lane /
    /// test double that carries no path (the path extraction then fails closed).
    fn path(&self) -> Option<String> {
        None
    }
}

/// A [`RequestParams`] over a live HTTP request's query string + headers — the serving-path impl the
/// site-handler dispatch builds (an owned snapshot, so it borrows nothing from the request past the
/// call). A header is read case-insensitively via `axum::http::HeaderMap`; a query parameter is split
/// out of the stored query string and percent-decoded by [`decode_query_value`] (no extra dep — a
/// URL-safe-base64 sealed token needs no decoding, but a correct decoder keeps the source general).
pub(crate) struct HttpStateParams {
    /// The raw query string (without the leading `?`), or `None`.
    pub query: Option<String>,
    /// A snapshot of the request headers.
    pub headers: axum::http::HeaderMap,
    /// The request path (without the query string), for the `pre_auth_request` `path` extraction.
    pub path: Option<String>,
}

impl RequestParams for HttpStateParams {
    fn query(&self, name: &str) -> Option<String> {
        let q = self.query.as_deref()?;
        // First matching key wins (standard for a single-valued param like OIDC `state`).
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if decode_query_value(k) == name {
                return Some(decode_query_value(v));
            }
        }
        None
    }
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
    fn path(&self) -> Option<String> {
        self.path.clone()
    }
}

/// `application/x-www-form-urlencoded` value decode: `+` → space, `%XX` → byte, everything else
/// verbatim. A malformed `%XX` is left literal (lossless, never a panic).
fn decode_query_value(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Bridge the per-tenant secret store's provisioning signal into the [`TenantExists`] check: a tenant
/// is real iff it holds at least one sealed secret name in its index. A backend error fails closed
/// (`false`) — a source that cannot confirm the tenant resolves nothing.
#[async_trait::async_trait]
impl TenantExists for boatramp_core::secret_store::TenantSecretStore {
    async fn exists(&self, project: &str, tenant: &str) -> bool {
        self.tenant_exists(boatramp_core::project::ProjectRef::new(project), tenant)
            .await
            .unwrap_or(false)
    }
}

/// Whether `tenant` is a real/provisioned tenant in `project` — the defense-in-depth check the
/// `sealed-state` source applies to an unsealed tenant BEFORE resolving it. The AEAD seal already
/// proves the tenant came from a host mint, but a decommissioned / never-provisioned tenant must
/// still fail closed. The server wires this to the per-tenant secret store's index
/// ([`TenantSecretStore::tenant_exists`](boatramp_core::secret_store::TenantSecretStore::tenant_exists));
/// a test injects a set.
#[async_trait::async_trait]
pub(crate) trait TenantExists: Send + Sync {
    /// `true` iff `tenant` is provisioned in `project`. Must fail closed (`false`) on any backend
    /// error — a source that cannot confirm the tenant is real resolves nothing.
    async fn exists(&self, project: &str, tenant: &str) -> bool;
}

/// Everything the [`TenantSource::SealedState`] source needs at the (pre-auth) callback. The
/// `env`/`registry`/`params` are host-held references; `project`/`site` are THIS request's
/// host-resolved scope (the values the seal was bound to at mint, re-checked by
/// [`boatramp_core::sealed_state::unseal_state`]).
#[derive(Clone, Copy)]
pub(crate) struct SealedStateInputs<'a> {
    /// Where the token rides (query/header), looked up by the config-named param.
    pub params: &'a dyn RequestParams,
    /// The host `[secrets]` key envelope (the SAME AEAD the per-tenant secret store seals with).
    pub env: &'a dyn boatramp_core::envelope::KeyEnvelope,
    /// This request's host-resolved project (re-checked against the seal's bound project).
    pub project: &'a str,
    /// This request's host-resolved site (re-checked against the seal's bound site).
    pub site: &'a str,
    /// The real-tenant registry (defense in depth).
    pub registry: &'a dyn TenantExists,
}

/// The posture knobs that bound tenancy (read from the runtime's resolved [`SecurityPosture`]).
#[derive(Clone, Copy)]
pub(crate) struct TenantPosture {
    /// Refuse an undeclared sql/orm importer (multi-tenant).
    pub require_declaration: bool,
    /// Permit an `all` grant to actually cross tenants; else it's capped to `own`.
    pub allow_cross_tenant: bool,
}

/// Refusal to activate a guest because its tenancy declaration is missing where the posture
/// requires one (Dimension 0). Surfaces as a "bindings refused" activation failure.
#[derive(Debug, Clone)]
pub(crate) struct TenancyUndeclared;

impl std::fmt::Display for TenancyUndeclared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "tenancy: this function imports sql/orm or wasi:blobstore but declares no tenancy \
             decision; the multi-tenant posture requires an explicit `tenancy` (disabled or scoped)",
        )
    }
}
impl std::error::Error for TenancyUndeclared {}

/// Resolve the effective [`Tenancy`] `decision` into a [`HostTenancy`] (or `None` = plain
/// queries). `imports_tenant_scoped_data` is whether the guest imports a tenant-scoped DATA
/// capability — `sql`/`orm` OR `wasi:blobstore` (which carries per-tenant blob assets, Security
/// HIGH-1) — only then does the Dimension-0 declaration requirement bite. Async because the token
/// source verifies a JWT.
pub(crate) async fn resolve_host_tenancy(
    decision: Option<&Tenancy>,
    imports_tenant_scoped_data: bool,
    posture: TenantPosture,
    inputs: TenantSourceInputs<'_>,
) -> Result<Option<HostTenancy>, TenancyUndeclared> {
    match decision {
        // Undeclared: refuse a tenant-scoped-data-importing guest under the strict posture; else plain.
        None => {
            if imports_tenant_scoped_data && posture.require_declaration {
                Err(TenancyUndeclared)
            } else {
                Ok(None)
            }
        }
        // Deliberately no in-site tenancy — plain queries.
        Some(Tenancy::Disabled) => Ok(None),
        Some(Tenancy::Scoped {
            column,
            sources,
            read,
            write,
            // #503: this route's per-route write-global allowlist — the plain-`Unscoped` table names
            // it may write unstamped. Threaded onto the `HostTenancy` (below) so BOTH the ORM
            // `write_target` and the raw-SQL surface consult it. The runtime resolve-gate is primary;
            // apply-time validation (422) is defense-in-depth.
            unscoped_writes,
            // v0.12.x soft `domain` source: what this route does when it resolves NO principal — `Deny`
            // (today) or `Pass` (null-principal handler invocation; reads → zero rows, writes → denied).
            // Threaded onto the `HostTenancy` below so the confiner relaxes the READ deny into the
            // `1 = 0` empty-set confinement; it never relaxes a write.
            on_unresolved,
            // `exceed_site_ceiling` (task #470) is deliberately NOT read here: the token relaxes only
            // the `narrows_within` shape check at bind, never the runtime resolver. `cap()` below
            // stays the SOLE authority over whether an `all` grant actually crosses tenants (key 3).
            ..
        }) => {
            // Resolve the own-tenant axis first. It may be the typed `System` class (PLAN-system-
            // principal), which SHORT-CIRCUITS: a system principal has no tenant and no session fact,
            // so `coerce_system` empties the facts and forces both axes to `Null` (base/`IS NULL`),
            // independent of the route's declared `read`/`write` — a route whose own grant is `own`
            // still yields the base-partition-only system principal, and the tenant GUC stays unset.
            match resolve_from_sources(sources, &inputs).await {
                Some(ResolvedPrincipal::System) => Ok(Some(
                    HostTenancy::from_facts(
                        column.clone(),
                        Vec::new(),
                        AccessMode::Null,
                        AccessMode::Null,
                    )
                    // #503 write-global allowlist still applies (a system principal may legitimately
                    // write base rows of a write-global table); pass-through is a no-op (a system
                    // principal always resolves, so the null-principal READ relaxation never fires).
                    .with_unscoped_writes(unscoped_writes.iter().cloned())
                    .with_unresolved_pass(on_unresolved.is_pass())
                    // The class marker — the WHOLE point: drives `app.principal_kind='system'` + the
                    // guest `current-principal` system shape. Applied last (it also re-clamps modes).
                    .coerce_system(),
                )),
                // construens #2 — a SEAL-ONLY pre-auth firm (login-start). The firm is carried as the
                // `HostTenancy` seal-only subject, NOT a `ScopeAxis::Tenant` data fact, so it reaches
                // ONLY the `sealed-state:mint` binding. The data axes are FORCED to `None` (every
                // scoped read/write denied) regardless of the route's declared `read`/`write`, so a
                // login-start has NO data access at all (the firm's rows are unreachable, and
                // `resolved_tenant_string(facts)` is `None` ⇒ `tenant-secrets`/blob are
                // `no-resolved-tenant`) — the confinement is structural (no `Tenant` fact + `None`
                // grants), not a bolt-on guard. A session cookie (if the login-start carried a valid
                // one) still resolves its anonymous `Session` fact independently (never the firm). The
                // firm becomes a DATA tenant only later, at `/callback`, once `sealed-state` unseals it
                // (and the external auth has run).
                Some(ResolvedPrincipal::PreAuthSeal(firm)) => {
                    let mut facts = Vec::new();
                    if let Some(value) = resolve_session_fact(&inputs) {
                        facts.push(boatramp_handlers::ScopeFact {
                            axis: boatramp_core::tenancy::ScopeAxis::Session,
                            value,
                        });
                    }
                    Ok(Some(
                        HostTenancy::from_facts(
                            column.clone(),
                            facts,
                            // No data access at /start: force both axes to `None` (deny every scoped
                            // op), independent of the declared modes — airtight even if a pre-auth
                            // route wrongly declares `read: all`.
                            AccessMode::None,
                            AccessMode::None,
                        )
                        .with_preauth_seal_subject(Some(firm)),
                    ))
                }
                // A concrete tenant value (or none) + the anonymous session fact (R3, from a verified
                // cookie) — each axis resolved independently, tagged, carried as the principal's fact
                // set. Either may be absent (a purely anonymous request has only a session fact; a
                // plain token request has only a tenant fact).
                resolved => {
                    let mut facts = Vec::new();
                    if let Some(ResolvedPrincipal::Tenant(value)) = resolved {
                        facts.push(boatramp_handlers::ScopeFact {
                            axis: boatramp_core::tenancy::ScopeAxis::Tenant,
                            value,
                        });
                    }
                    if let Some(value) = resolve_session_fact(&inputs) {
                        facts.push(boatramp_handlers::ScopeFact {
                            axis: boatramp_core::tenancy::ScopeAxis::Session,
                            value,
                        });
                    }
                    let read = cap(*read, posture.allow_cross_tenant);
                    let write = normalize_write(cap(*write, posture.allow_cross_tenant));
                    Ok(Some(
                        HostTenancy::from_facts(column.clone(), facts, read, write)
                            // #503: carry the per-route write-global allowlist (empty for most routes).
                            .with_unscoped_writes(unscoped_writes.iter().cloned())
                            // v0.12.x: opt into the null-principal READ pass-through (zero rows) when
                            // declared; `Deny` (the default) leaves the fail-closed deny unchanged.
                            .with_unresolved_pass(on_unresolved.is_pass()),
                    ))
                }
            }
        }
        // R4/D8: a `target` route is bound by the serving path ([`build_bindings`] in
        // handler_dispatch), which has the routed domain + the project schema to resolve `B` and
        // build the confined target scope (`HostTenancy::target`). This OWN-axis resolver never
        // produces a target scope, so reaching here for a `Target` decision means the serving path
        // did not bind it for this trigger — fail closed (refuse) rather than run own/unscoped.
        Some(Tenancy::Target { .. }) => Err(TenancyUndeclared),
    }
}

/// A resolved target source (R4/D8 5c): the target tenant `B` + the effective write-allowlist for
/// this invocation. `write` is the route's grant for the `domain`/`capability` (authenticated)
/// sources, but is forced **empty (read-only, G1)** for the `handle` source — a public handle may
/// only ever read.
pub(crate) struct ResolvedTarget {
    pub value: String,
    pub write: Vec<String>,
    /// The opaque, app-authored context carried by a verified **capability** (its `br_app` claim) —
    /// handed back to the resolver for its own within-tenant filter (e.g. a per-client `sub`), never
    /// interpreted by the host. Empty for the anonymous `domain`/`handle` sources (which carry no
    /// app-context). (PLAN-delegable-capabilities Stage D.)
    pub context: std::collections::BTreeMap<String, String>,
}

/// Resolve the target tenant `B` from the first applicable [`TargetSource`] in `via`
/// (first-resolves-wins, R4/D8 5c). Returns `None` when no listed source resolves (the route then
/// fails closed — never own/plain).
///
/// - **Domain**: the routed domain's host-stamped context tag (unforgeable — set at routing, never a
///   client header). Honors the route's `write` grant.
/// - **Capability**: the request bearer, verified as a [`KIND_CAPABILITY`](boatramp_core::cose::KIND_CAPABILITY)
///   envelope against the fleet key, bound to this project as audience and to this route's `public`
///   subset. A wrong-audience / wrong-subset / forged / expired capability does not resolve (fail
///   closed → next source). Honors the route's `write` grant.
/// - **Handle** (G1–G4): a PUBLIC slug (`handle_slug`, guest-named), resolved against the operator's
///   [`handles`](boatramp_core::tenancy::TenancySchema::handles) registry (deny-by-default: an
///   unlisted slug does not resolve, G4), and ONLY when the route's `public` subset is
///   [`world_public`](boatramp_core::tenancy::PublicSubset::world_public) (G2/G3). Always
///   **read-only** — the effective write-allowlist is forced empty (G1) regardless of the route's
///   `write` grant. So a public handle can only ever read `B`'s world-public rows.
#[allow(clippy::too_many_arguments)] // a source resolver: each arg is a distinct verified input.
pub(crate) fn resolve_target_via(
    via: &[boatramp_core::tenancy::TargetSource],
    route_public: &str,
    route_write: &[String],
    schema: &boatramp_core::tenancy::TenancySchema,
    domain_context: Option<&str>,
    capability: Option<&str>,
    capability_anchor: Option<&boatramp_core::cose::TokenPublicKey>,
    handle_slug: Option<&str>,
    audience: &str,
    now_unix: u64,
) -> Option<ResolvedTarget> {
    use boatramp_core::tenancy::TargetSource;
    for source in via {
        match source {
            TargetSource::Domain => {
                if let Some(ctx) = domain_context.filter(|c| !c.is_empty()) {
                    return Some(ResolvedTarget {
                        value: ctx.to_string(),
                        write: route_write.to_vec(),
                        context: std::collections::BTreeMap::new(),
                    });
                }
            }
            TargetSource::Capability => {
                if let (Some(token), Some(anchor)) = (capability, capability_anchor)
                    && let Ok(grant) =
                        boatramp_core::cose::verify_capability(token, anchor, now_unix, audience)
                {
                    // The capability must grant EXACTLY this route's public subset (a capability
                    // for another subset can't be redeemed here).
                    if grant.public == route_public {
                        return Some(ResolvedTarget {
                            value: grant.tenant,
                            write: route_write.to_vec(),
                            // Hand the capability's opaque app-context back to the resolver
                            // (Stage D) — the host never interprets it.
                            context: grant.context,
                        });
                    }
                }
            }
            TargetSource::Handle => {
                // G2/G3: a handle resolves ONLY when the route's subset is world_public (the
                // deny-by-default host flag), folded into the chain via `.filter`. G4: only a slug
                // the operator listed resolves; an unlisted slug does not (no existence oracle — the
                // route refuses identically whether the slug is absent or the subset isn't
                // world-public). G1: read-only (the write-allowlist is forced empty).
                if let Some(ctx) = handle_slug
                    .filter(|s| !s.is_empty())
                    .filter(|_| schema.subset_is_world_public(route_public))
                    .and_then(|slug| schema.resolve_handle(slug))
                {
                    return Some(ResolvedTarget {
                        value: ctx.to_string(),
                        write: Vec::new(), // G1: a handle is always read-only.
                        context: std::collections::BTreeMap::new(),
                    });
                }
            }
            // A future source this build doesn't understand does not resolve here (fail-closed).
            _ => {}
        }
    }
    None
}

/// Resolve tenancy for an **in-project invoke** (a function/handler calling a sibling): the tenant
/// **value** is inherited from the caller (host-carried, not from the guest's invoke request), and
/// the callee applies its OWN declared column + modes. Same Dimension-0 refusal + posture cap as
/// [`resolve_host_tenancy`]; the only difference is the value comes from the caller, not a source.
pub(crate) fn resolve_inherited_tenancy(
    decision: Option<&Tenancy>,
    imports_tenant_scoped_data: bool,
    posture: TenantPosture,
    inherited: Vec<boatramp_handlers::ScopeFact>,
) -> Result<Option<HostTenancy>, TenancyUndeclared> {
    match decision {
        None => {
            if imports_tenant_scoped_data && posture.require_declaration {
                Err(TenancyUndeclared)
            } else {
                Ok(None)
            }
        }
        Some(Tenancy::Disabled) => Ok(None),
        Some(Tenancy::Scoped {
            column,
            read,
            write,
            // #503: the callee's OWN per-route write-global allowlist applies on the invoke path too.
            unscoped_writes,
            // v0.12.x: the callee's OWN unresolved-request policy applies on the invoke path too — an
            // inherited empty principal yields zero rows (not a deny) iff the callee declared `Pass`.
            on_unresolved,
            ..
        }) => {
            let read = cap(*read, posture.allow_cross_tenant);
            let write = normalize_write(cap(*write, posture.allow_cross_tenant));
            // The callee applies its OWN column + posture-capped modes to the caller's inherited
            // **principal** (axis-tagged facts), so an inherited `TargetTenant`/`Session` fact keeps
            // its axis rather than collapsing into an `own` `Tenant` value.
            Ok(Some(
                HostTenancy::from_facts(column.clone(), inherited, read, write)
                    .with_unscoped_writes(unscoped_writes.iter().cloned())
                    .with_unresolved_pass(on_unresolved.is_pass()),
            ))
        }
        // A `target` route resolves `B` from its own trigger (the routed domain), not from an
        // inherited invoke principal — so a target decision reached over the invoke path is refused
        // (fail closed) rather than wrongly binding the caller's inherited facts as a target scope.
        Some(Tenancy::Target { .. }) => Err(TenancyUndeclared),
    }
}

/// Cap a cross-tenant `all` grant to `own` unless the posture permits crossing tenants.
fn cap(mode: AccessMode, allow_cross_tenant: bool) -> AccessMode {
    if mode == AccessMode::All && !allow_cross_tenant {
        AccessMode::Own
    } else {
        mode
    }
}

/// Normalize the **write** axis: `own+null` degrades to `own`. Widening a *read* to the shared
/// NULL baseline is a sensible pattern, but *writing/deleting* the baseline is a cross-tenant blast
/// (every tenant reads those rows), so `own+null` never grants baseline writes — a write reaches
/// only the resolved tenant. (`null` stays: it's an explicit, deny-by-default "write the shared
/// baseline" grant; `all` is posture-gated above.)
fn normalize_write(mode: AccessMode) -> AccessMode {
    if mode == AccessMode::OwnOrNull {
        AccessMode::Own
    } else {
        mode
    }
}

/// Resolve the "own" tenant value from the **priority-ordered** source list (`PLAN-tenancy-principal`
/// R1): the first source whose current-trigger input is present wins, so one component can serve a
/// token-auth'd request, a storefront domain, and an async job by declaring `[token, domain,
/// signed_context]`. `None` if none apply (anonymous / not-yet-wired source) — the binding then
/// fails an "own" op closed rather than running unscoped.
/// The resolved principal for one invocation's own-tenant axis: either a concrete host-verified
/// tenant **value**, or the typed **System** class (PLAN-system-principal). The class is carried as a
/// distinct variant — NEVER a sentinel `SqlValue` — so a system principal can never collide with, or
/// be forged by, a tenant key. `None` from the resolver means "no principal resolved" (the scoped op
/// then fails closed), exactly as before.
pub(crate) enum ResolvedPrincipal {
    /// A concrete, host-verified own-tenant value (a token claim, a routed domain, a signed context).
    Tenant(boatramp_core::sql::SqlValue),
    /// The node-wide **system** principal (no tenant), conferred ONLY by a verified system source
    /// (P1: a `system_when` operator opt-in on an exactly-named first-party issuer).
    System,
    /// A **pre-auth seal-only firm** (construens #2 — [`TenantSource::PreAuthRequest`]): the firm
    /// resolved host-side from an UNSCOPED login-start request, validated against the configured-firm
    /// registry. It is NOT a data tenant — [`resolve_host_tenancy`] carries it as the
    /// [`HostTenancy`]'s seal-only subject (no `ScopeAxis::Tenant` fact), so it reaches ONLY the
    /// `sealed-state:mint` binding and grants no RLS/`tenant-secrets` access at `/start`.
    PreAuthSeal(String),
}

async fn resolve_from_sources(
    sources: &[TenantSource],
    inputs: &TenantSourceInputs<'_>,
) -> Option<ResolvedPrincipal> {
    // Runtime backstop (Security Finding A): a route that namespaces one token source but also carries
    // an un-namespaced tenant-producing source (a plain token, a domain, a signed context) shares one
    // flat key space — an attacker-influenceable un-namespaced value could equal a `namespace:span`
    // key. Refuse to resolve ANY principal for such a mixed route (fail closed), so the mix is unsafe
    // even if apply-time admission was bypassed (a direct control-plane API deploy, or a serving
    // surface whose apply path does not validate the source list). This covers every surface uniformly
    // (function, site, per-route) because they all resolve here.
    if boatramp_core::claim_extract::sources_mix_is_forbidden(sources) {
        tracing::warn!(
            tenant_source = "token",
            outcome = "forbidden_source_mix",
            counter = "transform_denied",
            "tenant claim transform: a namespaced token source is mixed with an un-namespaced \
             tenant source on this route; refusing to resolve a principal (fail closed)"
        );
        return None;
    }
    // construens #2 sole-source backstop: a `pre_auth_request` source confers a SEAL-ONLY firm, not a
    // data tenant key. It must be the SOLE source — mixing it with any other tenant-producing source
    // would let a login-start route also resolve a real data tenant, blurring the seal-only boundary.
    // Refuse to resolve ANY principal for such a mix (fail closed), covering a control-plane deploy
    // that bypassed the apply-time `validate_sources` check.
    if boatramp_core::claim_extract::preauth_source_misplaced(sources) {
        tracing::warn!(
            tenant_source = "pre_auth_request",
            outcome = "preauth_source_mix",
            counter = "preauth_denied",
            "pre_auth_request is not the sole source on this route; refusing to resolve a principal \
             (fail closed)"
        );
        return None;
    }
    // System-principal mix backstop (PLAN-system-principal S0): a `system_when` token source confers a
    // typed CLASS, not a tenant key. It must be the SOLE source — mixing it with any other
    // tenant-producing source (a `domain`, a second token, a `signed_context`, even a trailing `none`)
    // would let a non-system request silently resolve a tenant under a source list whose purpose is to
    // gate system, blurring the class boundary. Refuse to resolve ANY principal for such a mix (fail
    // closed), covering a control-plane deploy that bypassed the apply-time check.
    if inputs.token_cfg.is_some_and(|c| c.system_when.is_some())
        && !matches!(sources, [TenantSource::Token { .. }])
    {
        tracing::warn!(
            tenant_source = "token",
            outcome = "system_when_source_mix",
            counter = "transform_denied",
            "system_when is set but the source list is not a single `token` source; refusing to \
             resolve a principal (fail closed)"
        );
        return None;
    }
    for source in sources {
        if let Some(p) = resolve_value(source, inputs).await {
            return Some(p);
        }
    }
    None
}

/// Resolve the anonymous-**session** fact (R3) from a host-issued session cookie: verify its COSE
/// signature + expiry against the fleet anchor and return the bound `sid` as the session value.
/// `None` when no cookie / no anchor / an invalid or expired cookie — the request then simply
/// carries no session fact (a client-forged `sid` never verifies, so it can't manufacture one).
/// Per-fact lifetime is enforced here: an expired cookie drops out, and (with a still-live tenant
/// fact) the request falls back to the tenant arm.
fn resolve_session_fact(inputs: &TenantSourceInputs<'_>) -> Option<boatramp_core::sql::SqlValue> {
    let cookie = inputs.session_cookie?;
    let anchor = inputs.session_anchor?;
    let sid = boatramp_core::cose::verify_session(cookie, anchor, boatramp_core::time::now_unix())
        .ok()?;
    Some(boatramp_core::sql::SqlValue::Text(sid))
}

/// Re-check (at resolution) that a `system_when.issuer` is an EXACT trusted issuer — the single
/// `issuer`, or a member of `issuer_trust.allow`. NEVER a `suffix`-matched or discovered issuer. This
/// is the S0 runtime backstop dual of the apply-time check ([`HandlerGraphqlTokenClaims::validate`]),
/// so a control-plane deploy that bypassed apply still cannot confer the node-wide system class via a
/// family-trusted issuer.
#[cfg(feature = "oidc")]
fn system_when_issuer_is_exact_trusted(cfg: &HandlerGraphqlTokenClaims, issuer: &str) -> bool {
    // MUTATION SEAM (gate `skip_exact_issuer`): the S0 backstop always passes, so a `suffix`-trusted
    // (not exactly-listed) issuer can mint the node-wide system principal. Compiled out of shipped
    // builds; the gate then goes RED (a non-exact system issuer must fail the whole source closed).
    if sysprincipal_mutation().as_deref() == Some("skip_exact_issuer") {
        return true;
    }
    if !cfg.issuer.is_empty() && cfg.issuer == issuer {
        return true;
    }
    cfg.issuer_trust
        .as_ref()
        .is_some_and(|t| t.allow.iter().any(|a| a == issuer))
}

/// The active system-principal anti-hollow mutation (`BOATRAMP_SYSPRINCIPAL_MUTATION`), or `None`.
/// Present ONLY under `cfg(test)` or the `system-principal-gate-mutation` feature; a shipped build has
/// neither, so the S0 exact-issuer backstop is unconditional and this is a dead `None`.
#[cfg(all(
    feature = "oidc",
    any(test, feature = "system-principal-gate-mutation")
))]
fn sysprincipal_mutation() -> Option<String> {
    std::env::var("BOATRAMP_SYSPRINCIPAL_MUTATION").ok()
}
#[cfg(all(
    feature = "oidc",
    not(any(test, feature = "system-principal-gate-mutation"))
))]
#[inline]
fn sysprincipal_mutation() -> Option<String> {
    None
}

/// Resolve the principal from a single verified source — a tenant value or the typed `System` class.
/// `None` for anonymous / not-yet-wired sources (the caller [`resolve_from_sources`] then tries the
/// next, else fails closed).
async fn resolve_value(
    source: &TenantSource,
    inputs: &TenantSourceInputs<'_>,
) -> Option<ResolvedPrincipal> {
    match source {
        TenantSource::Token {
            claim,
            extract,
            namespace,
        } => {
            // The verifier lives behind `oidc` (it pulls `jsonwebtoken`). Without that feature the
            // token source can't verify, so it sources no value (fail-closed) — mirroring the GDC.
            #[cfg(feature = "oidc")]
            {
                let (cfg, bearer) = (inputs.token_cfg?, inputs.bearer?);
                static SYSTEM: boatramp_core::env::SystemEnv = boatramp_core::env::SystemEnv;
                let env_source = inputs
                    .env_source
                    .unwrap_or(&SYSTEM as &dyn boatramp_core::env::EnvSource);
                let claims =
                    crate::graphql_data::token::verified_claims(cfg, bearer, env_source).await?;

                // P1 — system-principal mapping (PLAN-system-principal), operator opt-in,
                // deny-by-default. A verified token whose `iss` is EXACTLY the operator-named system
                // issuer AND whose gating claim equals the configured value resolves the typed
                // `System` class (no tenant) — retiring the old `tid="platform"` sentinel.
                if let Some(sw) = &cfg.system_when {
                    // Runtime S0 backstop: the system issuer must be EXACT-trusted (single `issuer`
                    // or an `issuer_trust.allow` member), never `suffix`-matched/discovered. A tainted
                    // (non-exact) system_when fails the WHOLE source closed — it never silently
                    // degrades to a tenant, because the source's intent is compromised.
                    if !system_when_issuer_is_exact_trusted(cfg, &sw.issuer) {
                        tracing::warn!(
                            tenant_source = "token",
                            outcome = "system_when_issuer_not_exact",
                            counter = "transform_denied",
                            "system_when.issuer is not an exact trusted issuer (misconfig bypassed \
                             apply); refusing any principal (fail closed)"
                        );
                        return None;
                    }
                    // The verified `iss` (re-pinned into the signature check by the verifier) must
                    // EXACTLY equal the named system issuer — so one trusted issuer among several in
                    // `allow` does NOT confer system; only the operator's chosen one does. The gating
                    // claim must be a string equal to the configured value.
                    let iss_ok =
                        claims.get("iss").and_then(|v| v.as_str()) == Some(sw.issuer.as_str());
                    let claim_ok =
                        claims.get(&sw.claim).and_then(|v| v.as_str()) == Some(sw.equals.as_str());
                    if iss_ok && claim_ok {
                        return Some(ResolvedPrincipal::System);
                    }
                    // A non-system token on a dual-use source (regular user, or a token missing the
                    // gating claim) falls through to the normal tenant extraction below.
                }

                // No transform declared ⇒ today's verbatim behavior, byte-identical.
                if extract.is_none() && namespace.is_none() {
                    return claims
                        .get(claim)
                        .and_then(scalar_to_sql)
                        .map(ResolvedPrincipal::Tenant);
                }

                // Transform active: derive the key from the *verified* claim, deny-by-default. The
                // guest-facing outcome is uniform (no principal → the scoped op fails closed); the
                // host logs the precise reason so a misconfiguration is a grep, not a mystery. The
                // claim NAME (a config field) is safe to log; the claim VALUE is not logged.
                use boatramp_core::claim_extract::{DeriveOutcome, derive_tenant};
                let Some(value) = claims.get(claim) else {
                    tracing::warn!(
                        tenant_source = "token",
                        outcome = "claim_absent",
                        counter = "transform_denied",
                        claim = %claim,
                        "tenant claim transform: named claim is absent from the verified token"
                    );
                    return None;
                };
                match derive_tenant(extract.as_ref(), namespace.as_deref(), value) {
                    DeriveOutcome::Resolved(key) => Some(ResolvedPrincipal::Tenant(
                        boatramp_core::sql::SqlValue::Text(key),
                    )),
                    DeriveOutcome::ClaimNonString => {
                        tracing::warn!(
                            tenant_source = "token",
                            outcome = "claim_not_string",
                            counter = "transform_denied",
                            claim = %claim,
                            "tenant claim transform: claim is present but not a JSON string"
                        );
                        None
                    }
                    DeriveOutcome::NoMatch { empty_capture } => {
                        tracing::warn!(
                            tenant_source = "token",
                            outcome = "extract_no_match",
                            counter = "transform_denied",
                            claim = %claim,
                            empty_capture,
                            "tenant claim transform: extraction did not match the claim value"
                        );
                        None
                    }
                    DeriveOutcome::KeyRejected(reason) => {
                        tracing::warn!(
                            tenant_source = "token",
                            outcome = "derived_key_rejected",
                            counter = "transform_denied",
                            claim = %claim,
                            reason = %reason,
                            "tenant claim transform: derived key failed the key-safety screen"
                        );
                        None
                    }
                }
            }
            #[cfg(not(feature = "oidc"))]
            {
                // Without `oidc` the token source can't verify — reference the token-only fields so
                // they aren't flagged dead in a handlers-without-oidc build (the domain/none
                // sources don't use them).
                let _ = (
                    claim,
                    extract,
                    namespace,
                    inputs.bearer,
                    inputs.token_cfg,
                    inputs.domain_context,
                    inputs.env_source,
                );
                None
            }
        }
        TenantSource::Domain => inputs
            .domain_context
            .filter(|c| !c.is_empty())
            .map(|c| ResolvedPrincipal::Tenant(boatramp_core::sql::SqlValue::Text(c.to_string()))),
        // The async lane's durable signed-context (R1): verify the host-minted envelope carried on
        // the drained message against the fleet anchor and return the producer's stamped tenant. A
        // forged/altered/expired envelope (or no envelope / no anchor) resolves no value — the
        // consumer's "own" op then fails closed rather than running unscoped. The guest never names
        // the tenant; only a host signature over the producer's principal verifies here. A *system*
        // signed-context (a cron / `System·Admin`-deploy producer seal carrying a positive signed
        // `br_scope_kind=system` and NO `br_ctx`) resolves to the typed `System` class — so a consumer
        // declaring `sources: [signed_context]` draining a system producer's message acts as the system
        // principal (base/`IS NULL`), NOT a dead-letter on a missing tenant (PLAN-system-principal P3).
        // The class is read from the SIGNED marker via the full verifier — never inferred from a missing
        // tenant (a stripped/forged envelope fails the signature check, so it resolves nothing).
        TenantSource::SignedContext => {
            let (env, anchor) = (inputs.signed_context?, inputs.context_anchor?);
            let v = boatramp_core::cose::verify_context_full(
                env,
                anchor,
                boatramp_core::time::now_unix(),
            )
            .ok()?;
            match v.kind {
                PrincipalKind::System => Some(ResolvedPrincipal::System),
                PrincipalKind::Tenant => v
                    .tenant
                    .map(|t| ResolvedPrincipal::Tenant(boatramp_core::sql::SqlValue::Text(t))),
            }
        }
        // The pre-auth SSO callback's sealed `state`: verify + decrypt the named request param with
        // the host `[secrets]` key envelope and extract the HOST-SEALED tenant (bound at login-start
        // to the minting guest's OWN resolved tenant — the guest never names it). The tenant comes
        // ONLY from the crypto seal, NEVER parsed from request text. A tampered / forged / expired /
        // wrong-(project,site) / missing token resolves NO value — the scoped op then fails closed,
        // never a fallback/default/first tenant. As a final belt, the unsealed tenant is validated to
        // be a REAL provisioned tenant in the project. No `sealed_state` substrate on this lane (an
        // async/background drain, or no `[secrets]` envelope wired) ⇒ fail closed.
        TenantSource::SealedState { param } => {
            use boatramp_core::tenancy::ParamKind;
            let ss = inputs.sealed_state.as_ref()?;
            let token = match param.kind {
                ParamKind::Query => ss.params.query(&param.name),
                ParamKind::Header => ss.params.header(&param.name),
            }?;
            let claims = match boatramp_core::sealed_state::unseal_state(
                ss.env,
                &token,
                boatramp_core::time::now_unix(),
                ss.project,
                ss.site,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    // Uniform guest-facing outcome (no tenant → fail closed); the host logs the
                    // precise reason so a misconfig/attack is a grep. Never logs the token or tenant.
                    tracing::warn!(
                        tenant_source = "sealed_state",
                        outcome = %e,
                        counter = "sealed_state_denied",
                        "sealed-state: unseal refused (fail closed)"
                    );
                    return None;
                }
            };
            // Defense in depth: the host-sealed tenant must be a REAL tenant in the project. A seal
            // for a decommissioned / never-provisioned tenant (or a key-unsafe value) fails closed.
            if !ss.registry.exists(ss.project, &claims.tenant).await {
                tracing::warn!(
                    tenant_source = "sealed_state",
                    outcome = "unknown_tenant",
                    counter = "sealed_state_denied",
                    "sealed-state: unsealed tenant is not a provisioned tenant (fail closed)"
                );
                return None;
            }
            Some(ResolvedPrincipal::Tenant(
                boatramp_core::sql::SqlValue::Text(claims.tenant),
            ))
        }
        // construens #2 — the pre-auth SSO login-start firm selection. Extract the firm selector from
        // the configured location (host/query/path/body), screen it for key-safety (malformed /
        // wildcard ⇒ fail closed), and resolve ONLY to a CONFIGURED/provisioned firm in the project
        // (the registry — the same provisioning signal the sealed-state source uses). The result is a
        // SEAL-ONLY firm (`PreAuthSeal`), NOT a data tenant: `resolve_host_tenancy` carries it as the
        // `HostTenancy` seal-only subject (no `ScopeAxis::Tenant` fact), so it reaches ONLY the
        // `sealed-state:mint` binding — NO RLS / `tenant-secrets` access at `/start`. The guest-facing
        // outcome is UNIFORM across every failure (no existence oracle); the host logs the precise
        // reason. The request-carried firm is safe BECAUSE the auth (the external IdP / firm
        // credentials + the callback's sealed-firm validation) is the real gate — this only selects
        // WHICH configured firm to seal. No pre-auth substrate on this lane (async/background drain,
        // or no request surface) ⇒ fail closed.
        TenantSource::PreAuthRequest { selector } => {
            let pre = inputs.preauth.as_ref()?;
            // Extract the raw request-carried selector from the configured location. Missing ⇒ None.
            let Some(selected) = extract_preauth_selector(selector, pre) else {
                tracing::warn!(
                    tenant_source = "pre_auth_request",
                    outcome = "selector_absent",
                    counter = "preauth_denied",
                    location = ?selector.location,
                    "pre_auth_request: no firm selector present in the configured location (fail closed)"
                );
                return None;
            };
            // Key-safety screen (defense in depth over the registry): empty / wildcard (`*`) /
            // traversal / whitespace / control / over-long ⇒ fail closed BEFORE the registry call.
            if let Err(e) =
                boatramp_core::project::validate_key_segment("pre_auth_firm", selected.trim())
            {
                tracing::warn!(
                    tenant_source = "pre_auth_request",
                    outcome = "selector_malformed",
                    counter = "preauth_denied",
                    reason = %e,
                    "pre_auth_request: firm selector failed the key-safety screen (fail closed)"
                );
                return None;
            }
            let firm = selected.trim();
            // Configured-firm registry: resolve ONLY to a provisioned/configured firm in the project.
            // Uniform fail-closed outcome — an unknown firm is indistinguishable from any other
            // failure at the guest; the host logs the (non-value) reason. NO fallback / default.
            if !pre.registry.exists(pre.project, firm).await {
                tracing::warn!(
                    tenant_source = "pre_auth_request",
                    outcome = "unknown_or_unconfigured_firm",
                    counter = "preauth_denied",
                    "pre_auth_request: selected firm is not a configured/provisioned tenant (fail closed)"
                );
                return None;
            }
            Some(ResolvedPrincipal::PreAuthSeal(firm.to_string()))
        }
        // Truly anonymous — no "own" tenant.
        TenantSource::None => None,
    }
}

/// Extract the raw, request-carried firm **selector** string for a [`TenantSource::PreAuthRequest`]
/// from its configured [`location`](boatramp_core::tenancy::PreAuthLocation) (construens #2) — BEFORE
/// any key-safety screen or registry check (both applied by the caller). `None` when the selector is
/// absent from the configured location (fail closed). This is the ONLY place a pre-auth firm is read
/// from request text, and it never touches the per-tenant serving hot path (the `body` surface is
/// buffered by the serving path ONLY for a route that declared a `body` source).
fn extract_preauth_selector(
    selector: &boatramp_core::tenancy::PreAuthSelector,
    pre: &PreAuthInputs<'_>,
) -> Option<String> {
    use boatramp_core::tenancy::PreAuthLocation;
    match selector.location {
        // The routed-host context tag — the strongest signal (host-stamped at routing, never a client
        // header). Reuses the `domain` source's resolved context; `name` is ignored.
        PreAuthLocation::Host => pre
            .domain_context
            .filter(|c| !c.is_empty())
            .map(str::to_owned),
        // The already-parsed query string (`?<name>=<firm>`).
        PreAuthLocation::Query => pre.params.query(&selector.name).filter(|v| !v.is_empty()),
        // The already-parsed path: the firm segment is the one IMMEDIATELY FOLLOWING a literal
        // segment equal to `name` (e.g. `name: "start"` → `/sso/start/<firm>`), so the position is
        // unambiguous and label-anchored (never "guess the Nth segment"). Absent label ⇒ None.
        PreAuthLocation::Path => {
            let path = pre.params.path()?;
            let mut segs = path.split('/').filter(|s| !s.is_empty());
            while let Some(seg) = segs.next() {
                if seg == selector.name {
                    return segs.next().filter(|v| !v.is_empty()).map(str::to_owned);
                }
            }
            None
        }
        // The buffered request body (the AWS-IAM-style credentials-against-the-firm POST). Content-
        // type dispatch (form-urlencoded + JSON), size cap, malformed ⇒ None. Buffered by the serving
        // path ONLY for a route that declared a `body` source (the hot-path guarantee).
        PreAuthLocation::Body => {
            let body = pre.body?;
            extract_preauth_body_field(selector, body)
        }
    }
}

/// Parse a buffered request body for the `body`-location firm field (construens #2): dispatch on the
/// `Content-Type` (`application/x-www-form-urlencoded` or `application/json`), enforce the selector's
/// body-size cap, and extract the string field named `selector.name`. Any mismatch — an over-cap
/// body, an unaccepted/unknown content-type, malformed form/JSON, a missing or non-string field —
/// yields `None` (fail closed). A nested/array/number JSON value for the field is rejected (a firm
/// selector is always a top-level string).
fn extract_preauth_body_field(
    selector: &boatramp_core::tenancy::PreAuthSelector,
    body: &PreAuthBody,
) -> Option<String> {
    // Size cap (re-checked here even though the serving buffer already capped it — defense in depth,
    // and the unit tests exercise it directly).
    if body.bytes.len() > selector.effective_body_cap() {
        return None;
    }
    // The request's MEDIA TYPE: the `Content-Type` header with any parameters (`; charset=utf-8`)
    // dropped, then trimmed and lowercased. Matching is a proper media-type EQUALITY test — never a
    // substring test, which would let a crafted header like `application/json-evil` or
    // `text/x-application/json` smuggle past the allowlist and pick a parser it was never granted.
    let media_type = body
        .content_type
        .as_deref()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    // Is this request's media type accepted? The configured allowlist (each entry matched for EQUALITY
    // against the request media type, case-insensitively), or — when the operator configured none —
    // any media type (the two understood parsers then self-select on the actual media type below). A
    // media type matching no configured entry fails closed (never parsed).
    let accepted = selector.content_types.is_empty()
        || selector
            .content_types
            .iter()
            .any(|c| !c.is_empty() && c.trim().eq_ignore_ascii_case(&media_type));
    // Dispatch the parser on the ACTUAL media type (only among the understood types); an accepted but
    // unrecognized media type still fails closed (never guess a parser).
    let accepts = |expected: &str| accepted && media_type == expected;
    if accepts("application/x-www-form-urlencoded") {
        // Reuse the form-urlencoded value decoder (first matching key wins).
        let text = std::str::from_utf8(&body.bytes).ok()?;
        for pair in text.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if decode_query_value(k) == selector.name {
                let decoded = decode_query_value(v);
                return (!decoded.is_empty()).then_some(decoded);
            }
        }
        None
    } else if accepts("application/json") {
        let json: serde_json::Value = serde_json::from_slice(&body.bytes).ok()?;
        match json.get(&selector.name) {
            // A firm selector is always a top-level JSON string; a non-string (number/array/object/
            // bool/null) is rejected (fail closed) rather than coerced.
            Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    } else {
        // An unaccepted / unrecognized content-type: fail closed (never guess a parser).
        None
    }
}

/// Convert a verified JSON claim scalar into a bound SQL value. Non-scalars (arrays/objects/null)
/// are rejected — a tenant id is always a scalar. Only reached from the `oidc` token branch (the
/// request-path `token` source + the async-lane `present-token` producer stamp, Gap 3).
#[cfg(feature = "oidc")]
pub(crate) fn scalar_to_sql(v: &serde_json::Value) -> Option<boatramp_core::sql::SqlValue> {
    use boatramp_core::sql::SqlValue;
    match v {
        serde_json::Value::String(s) => Some(SqlValue::Text(s.clone())),
        serde_json::Value::Bool(b) => Some(SqlValue::Boolean(*b)),
        serde_json::Value::Number(n) if n.is_i64() => Some(SqlValue::Integer(n.as_i64().unwrap())),
        // A non-integer number is unusual for a tenant id; bind it as text to avoid float keys.
        serde_json::Value::Number(n) => Some(SqlValue::Text(n.to_string())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::sql::SqlValue;
    use boatramp_core::tenancy::OnUnresolved;

    fn posture(require: bool, cross: bool) -> TenantPosture {
        TenantPosture {
            require_declaration: require,
            allow_cross_tenant: cross,
        }
    }

    // ---- P1: login-token → system principal (PLAN-system-principal), end-to-end resolution ----

    #[cfg(feature = "oidc")]
    const P1_ISS: &str = "https://admin.acme.example";

    #[cfg(feature = "oidc")]
    fn p1_b64url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Sign a JWT by hand with Ed25519; the production verifier checks it via the JWKS.
    #[cfg(feature = "oidc")]
    fn p1_token(key: &ed25519_dalek::SigningKey, kid: &str, claims: serde_json::Value) -> String {
        use ed25519_dalek::Signer;
        let header = p1_b64url(
            serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid })
                .to_string()
                .as_bytes(),
        );
        let payload = p1_b64url(claims.to_string().as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", p1_b64url(&sig.to_bytes()))
    }

    #[cfg(feature = "oidc")]
    fn p1_jwks(key: &ed25519_dalek::SigningKey, kid: &str) -> String {
        serde_json::json!({ "keys": [ {
            "kty": "OKP", "crv": "Ed25519", "kid": kid,
            "x": p1_b64url(key.verifying_key().as_bytes()),
        } ] })
        .to_string()
    }

    /// A dual-use console handler: one `token` source whose `token_claims.system_when` maps a verified
    /// `role=super_admin` token FROM THE EXACT admin issuer to the system principal; every other
    /// verified token resolves its own `tid` tenant.
    #[cfg(feature = "oidc")]
    fn p1_decision(sources: Vec<TenantSource>) -> Tenancy {
        Tenancy::Scoped {
            column: "tenant_id".into(),
            sources,
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        }
    }

    #[cfg(feature = "oidc")]
    fn p1_token_source() -> TenantSource {
        TenantSource::Token {
            claim: "tid".into(),
            extract: None,
            namespace: None,
        }
    }

    #[cfg(feature = "oidc")]
    fn p1_cfg(system_issuer: &str) -> HandlerGraphqlTokenClaims {
        HandlerGraphqlTokenClaims {
            issuer: P1_ISS.into(),
            jwks_env: Some("ADMIN_JWKS".into()),
            system_when: Some(boatramp_core::config::SystemWhen {
                issuer: system_issuer.into(),
                claim: "role".into(),
                equals: "super_admin".into(),
            }),
            ..Default::default()
        }
    }

    /// A verified `role=super_admin` token from the EXACTLY-named admin issuer resolves the typed
    /// SYSTEM class: no tenant fact, no own-value, and (the G2 no-leak property) NO tenant RLS GUC.
    #[cfg(feature = "oidc")]
    #[tokio::test]
    async fn p1_system_token_from_exact_issuer_resolves_the_system_class() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let env = boatramp_core::env::MapEnv::new().with("ADMIN_JWKS", p1_jwks(&key, "a1"));
        let cfg = p1_cfg(P1_ISS);
        let token = p1_token(
            &key,
            "a1",
            serde_json::json!({ "iss": P1_ISS, "exp": 9_999_999_999i64, "role": "super_admin", "tid": "ignored" }),
        );
        let decision = p1_decision(vec![p1_token_source()]);
        let inputs = TenantSourceInputs {
            bearer: Some(&token),
            token_cfg: Some(&cfg),
            env_source: Some(&env),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            ht.is_system(),
            "an exact-issuer super_admin token confers the system class"
        );
        assert!(
            ht.facts().is_empty(),
            "a system principal carries NO tenant/session fact"
        );
        assert!(
            ht.value().is_none(),
            "a system principal has no own-tenant value (tid ignored)"
        );
        assert!(
            ht.rls_tenant_value().is_none(),
            "G2: a system principal sets NO tenant GUC — it can never read a tenant's rows"
        );
    }

    /// The SAME dual-use handler: a regular user's token (no `role=super_admin`) still resolves its
    /// OWN `tid` tenant — the system mapping only fires for the gating claim, never by mere presence.
    #[cfg(feature = "oidc")]
    #[tokio::test]
    async fn p1_non_system_token_on_dual_use_source_still_resolves_its_tenant() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let env = boatramp_core::env::MapEnv::new().with("ADMIN_JWKS", p1_jwks(&key, "a1"));
        let cfg = p1_cfg(P1_ISS);
        let token = p1_token(
            &key,
            "a1",
            serde_json::json!({ "iss": P1_ISS, "exp": 9_999_999_999i64, "role": "member", "tid": "acme" }),
        );
        let inputs = TenantSourceInputs {
            bearer: Some(&token),
            token_cfg: Some(&cfg),
            env_source: Some(&env),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(
            Some(&p1_decision(vec![p1_token_source()])),
            true,
            posture(true, false),
            inputs,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!ht.is_system(), "a non-super_admin token is NOT system");
        assert_eq!(
            ht.value(),
            Some(&SqlValue::Text("acme".into())),
            "the regular user resolves its own tenant"
        );
    }

    /// Runtime S0 backstop: a `system_when` whose issuer is NOT an exact trusted issuer (here only a
    /// `suffix` covers it) must fail the WHOLE source closed — even a correctly-signed super_admin
    /// token from that issuer resolves NO principal (never system, never a tenant).
    #[cfg(feature = "oidc")]
    #[tokio::test]
    async fn p1_system_when_with_a_non_exact_issuer_fails_closed() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let env = boatramp_core::env::MapEnv::new().with("ADMIN_JWKS", p1_jwks(&key, "a1"));
        // Single-issuer `issuer` is P1_ISS, but system_when names a DIFFERENT issuer (not exact-trusted).
        let cfg = p1_cfg("https://evil.my.salesforce.com");
        let token = p1_token(
            &key,
            "a1",
            serde_json::json!({ "iss": P1_ISS, "exp": 9_999_999_999i64, "role": "super_admin", "tid": "acme" }),
        );
        let inputs = TenantSourceInputs {
            bearer: Some(&token),
            token_cfg: Some(&cfg),
            env_source: Some(&env),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(
            Some(&p1_decision(vec![p1_token_source()])),
            true,
            posture(true, false),
            inputs,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            !ht.is_system(),
            "a non-exact system issuer never confers system"
        );
        assert!(
            ht.value().is_none() && ht.facts().is_empty(),
            "the tainted source resolves NO principal — never degrading to a tenant (fail closed)"
        );
        // CI anti-hollow marker (grepped by the mutation gate): reached ONLY when a non-exact system
        // issuer was refused. `BOATRAMP_SYSPRINCIPAL_MUTATION=skip_exact_issuer` makes the backstop pass
        // → this token confers system → `!ht.is_system()` goes RED before this line.
        println!("SYSTEM PRINCIPAL EXACT-ISSUER OK");
    }

    /// Mix backstop: a `system_when` token source mixed with ANY other tenant-producing source
    /// resolves no principal (fail closed), covering a control-plane deploy that bypassed apply.
    #[cfg(feature = "oidc")]
    #[tokio::test]
    async fn p1_system_when_mixed_with_another_source_fails_closed() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let env = boatramp_core::env::MapEnv::new().with("ADMIN_JWKS", p1_jwks(&key, "a1"));
        let cfg = p1_cfg(P1_ISS);
        let token = p1_token(
            &key,
            "a1",
            serde_json::json!({ "iss": P1_ISS, "exp": 9_999_999_999i64, "role": "super_admin" }),
        );
        // sources = [token(system_when), domain] — forbidden mix.
        let inputs = TenantSourceInputs {
            bearer: Some(&token),
            token_cfg: Some(&cfg),
            env_source: Some(&env),
            domain_context: Some("acme"),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(
            Some(&p1_decision(vec![p1_token_source(), TenantSource::Domain])),
            true,
            posture(true, false),
            inputs,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!ht.is_system(), "a mixed source never confers system");
        assert!(
            ht.value().is_none() && ht.facts().is_empty(),
            "a system_when source mixed with another source resolves NO principal (fail closed)"
        );
    }

    /// A valid host-issued session cookie resolves the `Session` axis fact (R3), carried alongside a
    /// tenant fact in the principal; a forged/absent cookie resolves none.
    #[tokio::test]
    async fn a_valid_session_cookie_resolves_the_session_fact() {
        use boatramp_core::cose::{LocalSigner, Signer, TokenAlg, mint_session};
        use boatramp_handlers::ScopeFact;

        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        let cookie = mint_session("sid-xyz", 3600, boatramp_core::time::now_unix(), &signer)
            .await
            .unwrap();

        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        // A request carrying BOTH a routed domain (⇒ a tenant fact) and a valid session cookie
        // (⇒ a session fact): the resolved principal holds both, axis-tagged.
        let inputs = TenantSourceInputs {
            domain_context: Some("acme"),
            session_cookie: Some(&cookie),
            session_anchor: Some(&anchor),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        let facts: Vec<&ScopeFact> = ht.facts().iter().collect();
        assert!(
            facts
                .iter()
                .any(|f| f.axis == boatramp_core::tenancy::ScopeAxis::Tenant
                    && f.value == SqlValue::Text("acme".into())),
            "the domain source resolved the tenant fact"
        );
        assert!(
            facts
                .iter()
                .any(|f| f.axis == boatramp_core::tenancy::ScopeAxis::Session
                    && f.value == SqlValue::Text("sid-xyz".into())),
            "the valid cookie resolved the session fact"
        );

        // A forged cookie (signed by a stranger, not the fleet anchor) resolves NO session fact.
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        let forged = mint_session("sid-EVIL", 3600, boatramp_core::time::now_unix(), &stranger)
            .await
            .unwrap();
        let inputs = TenantSourceInputs {
            domain_context: Some("acme"),
            session_cookie: Some(&forged),
            session_anchor: Some(&anchor),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !ht.facts()
                .iter()
                .any(|f| f.axis == boatramp_core::tenancy::ScopeAxis::Session),
            "a cookie not signed by the fleet anchor resolves no session fact"
        );
    }

    /// A consumer declaring `sources: [signed_context]` resolves its own-tenant from a host-minted
    /// durable envelope (R1) — the async-lane keystone. A forged (stranger-signed) or absent
    /// envelope resolves NO tenant fact, so the consumer's "own" op fails closed rather than
    /// running unscoped. The guest never names the tenant; only a fleet signature verifies here.
    #[tokio::test]
    async fn a_valid_signed_context_resolves_the_own_tenant_on_the_async_lane() {
        use boatramp_core::cose::{LocalSigner, Signer, TokenAlg, mint_context};
        use boatramp_core::tenancy::ScopeAxis;

        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        let envelope = mint_context("acme", None, 3600, boatramp_core::time::now_unix(), &signer)
            .await
            .unwrap();

        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::SignedContext],
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        // The drained message carried a valid envelope + the fleet anchor ⇒ the producer's stamped
        // tenant resolves as the consumer's own `Tenant` fact.
        let inputs = TenantSourceInputs {
            signed_context: Some(&envelope),
            context_anchor: Some(&anchor),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            ht.facts()
                .iter()
                .any(|f| f.axis == ScopeAxis::Tenant && f.value == SqlValue::Text("acme".into())),
            "a valid signed context resolves the producer's tenant as the consumer's own fact"
        );

        // A forged envelope (signed by a stranger) resolves NO tenant fact — fail closed.
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        let forged = mint_context(
            "evil",
            None,
            3600,
            boatramp_core::time::now_unix(),
            &stranger,
        )
        .await
        .unwrap();
        let inputs = TenantSourceInputs {
            signed_context: Some(&forged),
            context_anchor: Some(&anchor),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !ht.facts().iter().any(|f| f.axis == ScopeAxis::Tenant),
            "an envelope not signed by the fleet anchor resolves no own tenant"
        );

        // No envelope at all (a plain background drain) resolves no tenant fact either.
        let inputs = TenantSourceInputs {
            context_anchor: Some(&anchor),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !ht.facts().iter().any(|f| f.axis == ScopeAxis::Tenant),
            "no envelope ⇒ no own tenant (the async lane fails an own op closed)"
        );
    }

    /// PLAN-system-principal P3: a consumer declaring `sources: [signed_context]` draining a SYSTEM
    /// producer seal (a `run_as: deployer` cron / `System·Admin`-deploy seal — positive signed
    /// `br_scope_kind=system`, no tenant) resolves the typed SYSTEM class (base/`IS NULL`, no tenant
    /// GUC), NOT a dead-letter on a missing tenant. The class rides the SIGNED marker — a forged
    /// envelope fails the signature check and resolves nothing.
    #[tokio::test]
    async fn a_system_signed_context_resolves_the_system_class_on_the_async_lane() {
        use boatramp_core::cose::{LocalSigner, Signer, TokenAlg, mint_system_context};

        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        let envelope = mint_system_context(None, 3600, boatramp_core::time::now_unix(), &signer)
            .await
            .unwrap();

        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::SignedContext],
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let inputs = TenantSourceInputs {
            signed_context: Some(&envelope),
            context_anchor: Some(&anchor),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            ht.is_system(),
            "a system producer seal resolves the consumer as the system class"
        );
        assert!(
            ht.facts().is_empty(),
            "a system principal carries no tenant fact"
        );
        assert!(
            ht.rls_tenant_value().is_none(),
            "G2: a system consumer sets NO tenant GUC — it cannot read a tenant's rows"
        );

        // A system seal signed by a stranger (not the fleet anchor) resolves NOTHING — the class is
        // never granted by a forged marker.
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        let forged = mint_system_context(None, 3600, boatramp_core::time::now_unix(), &stranger)
            .await
            .unwrap();
        let inputs = TenantSourceInputs {
            signed_context: Some(&forged),
            context_anchor: Some(&anchor),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !ht.is_system() && ht.facts().is_empty(),
            "a forged system seal confers neither the system class nor a tenant (fail closed)"
        );
    }

    #[test]
    fn inherited_invoke_uses_the_caller_value_with_the_callee_grant() {
        // A sibling invoked with `read: own_or_null, write: all` inherits the caller's tenant
        // VALUE but applies its OWN modes (write `all` capped to own under the strict posture,
        // own+null-write degraded to own).
        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::None], // irrelevant on the invoke path — the value is inherited
            read: AccessMode::OwnOrNull,
            write: AccessMode::All,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let ht = resolve_inherited_tenancy(
            Some(&decision),
            true,
            posture(true, false),
            vec![boatramp_handlers::ScopeFact {
                axis: boatramp_core::tenancy::ScopeAxis::Tenant,
                value: SqlValue::Text("caller-tenant".into()),
            }],
        )
        .unwrap()
        .unwrap();
        let read = ht
            .orm_scope(boatramp_handlers::TenantAxis::Read)
            .unwrap()
            .unwrap();
        assert_eq!(read.value, Some(SqlValue::Text("caller-tenant".into())));
        assert_eq!(read.mode, boatramp_core::orm::ScopeMode::OwnOrNull);
        // write: all capped to own (posture closed) → a concrete predicate, bound to the caller's value.
        let write = ht
            .orm_scope(boatramp_handlers::TenantAxis::Write)
            .unwrap()
            .unwrap();
        assert_eq!(write.mode, boatramp_core::orm::ScopeMode::Own);
        // A sibling with no inherited principal (empty fact set) + an own grant fails closed.
        let ht = resolve_inherited_tenancy(Some(&decision), true, posture(true, false), Vec::new())
            .unwrap()
            .unwrap();
        assert!(ht.orm_scope(boatramp_handlers::TenantAxis::Read).is_err());
    }

    #[tokio::test]
    async fn undeclared_db_importer_is_refused_only_under_the_strict_posture() {
        // Strict posture + imports db + undeclared ⇒ refused.
        assert!(
            resolve_host_tenancy(
                None,
                true,
                posture(true, false),
                TenantSourceInputs::default()
            )
            .await
            .is_err()
        );
        // Same, but doesn't import db ⇒ fine (plain).
        assert!(matches!(
            resolve_host_tenancy(
                None,
                false,
                posture(true, false),
                TenantSourceInputs::default()
            )
            .await,
            Ok(None)
        ));
        // Relaxed posture ⇒ undeclared is fine (plain).
        assert!(matches!(
            resolve_host_tenancy(
                None,
                true,
                posture(false, true),
                TenantSourceInputs::default()
            )
            .await,
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn disabled_is_plain() {
        let out = resolve_host_tenancy(
            Some(&Tenancy::Disabled),
            true,
            posture(true, false),
            TenantSourceInputs::default(),
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn domain_source_binds_the_context_tag() {
        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let inputs = TenantSourceInputs {
            domain_context: Some("acme-store"),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        // The resolved value scopes reads to the domain's tenant.
        let scope = ht
            .orm_scope(boatramp_handlers::TenantAxis::Read)
            .unwrap()
            .unwrap();
        assert_eq!(scope.value, Some(SqlValue::Text("acme-store".into())));
    }

    #[tokio::test]
    async fn via_resolves_first_applicable_source() {
        use boatramp_core::cose::{LocalSigner, Signer, TokenAlg, mint_capability};
        use boatramp_core::tenancy::{
            PublicCmp, PublicLiteral, PublicPredicate, PublicSubset, PublicTerm, TargetSource,
            TenancySchema,
        };
        let now = 1000;
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        let write = vec!["title".to_string()];

        // A schema with a WORLD-PUBLIC `products` subset and a NON-world-public `reviews` subset,
        // plus a handle registry mapping slug `acme` -> tenant_B.
        let mk = |world_public: bool| PublicSubset {
            predicate: PublicPredicate {
                terms: vec![PublicTerm::Cmp {
                    column: "published".into(),
                    op: PublicCmp::Eq,
                    value: PublicLiteral::Bool(true),
                }],
            },
            world_public,
            listable: world_public,
        };
        let mut schema = TenancySchema::default();
        schema.public_subsets.insert("products".into(), mk(true));
        schema.public_subsets.insert("reviews".into(), mk(false));
        schema.handles.insert("acme".into(), "tenant_B".into());

        // A capability granting tenant_B's `products` subset, redeemable at project `shop`.
        let cap = mint_capability(
            "tenant_B",
            "shop",
            "products",
            &Default::default(),
            300,
            now,
            &signer,
        )
        .await
        .unwrap();

        let call = |via: &[TargetSource],
                    public: &str,
                    dom: Option<&str>,
                    capa: Option<&str>,
                    hnd: Option<&str>,
                    aud: &str| {
            resolve_target_via(
                via,
                public,
                &write,
                &schema,
                dom,
                capa,
                Some(&anchor),
                hnd,
                aud,
                now,
            )
        };

        // via = [domain, capability]: domain wins first (honors the write grant).
        let r = call(
            &[TargetSource::Domain, TargetSource::Capability],
            "products",
            Some("acme-store"),
            Some(cap.as_str()),
            None,
            "shop",
        )
        .unwrap();
        assert_eq!(r.value, "acme-store");
        assert_eq!(r.write, write);

        // Capability (no domain present): resolves B + honors the write grant.
        let r = call(
            &[TargetSource::Capability],
            "products",
            None,
            Some(cap.as_str()),
            None,
            "shop",
        )
        .unwrap();
        assert_eq!(r.value, "tenant_B");
        assert_eq!(r.write, write);

        // Capability wrong audience / wrong subset / an app bearer ⇒ no resolution.
        assert!(
            call(
                &[TargetSource::Capability],
                "products",
                None,
                Some(cap.as_str()),
                None,
                "other"
            )
            .is_none()
        );
        assert!(
            call(
                &[TargetSource::Capability],
                "reviews",
                None,
                Some(cap.as_str()),
                None,
                "shop"
            )
            .is_none()
        );
        assert!(
            call(
                &[TargetSource::Capability],
                "products",
                None,
                Some("not-a-capability"),
                None,
                "shop"
            )
            .is_none()
        );

        // Handle (G1-G4): a listed slug on a WORLD-PUBLIC subset resolves B, READ-ONLY (write empty).
        let r = call(
            &[TargetSource::Handle],
            "products",
            None,
            None,
            Some("acme"),
            "shop",
        )
        .unwrap();
        assert_eq!(r.value, "tenant_B");
        assert!(
            r.write.is_empty(),
            "G1: a handle source is always read-only"
        );

        // G4: an UNLISTED slug does not resolve (indistinguishable from absent).
        assert!(
            call(
                &[TargetSource::Handle],
                "products",
                None,
                None,
                Some("ghost"),
                "shop"
            )
            .is_none()
        );
        // G2/G3: a listed slug on a NON-world-public subset does not resolve.
        assert!(
            call(
                &[TargetSource::Handle],
                "reviews",
                None,
                None,
                Some("acme"),
                "shop"
            )
            .is_none()
        );
        // No slug named ⇒ no handle resolution.
        assert!(
            call(
                &[TargetSource::Handle],
                "products",
                None,
                None,
                None,
                "shop"
            )
            .is_none()
        );
        // No via source at all ⇒ None (the route then fails closed).
        assert!(
            call(
                &[],
                "products",
                Some("acme-store"),
                Some(cap.as_str()),
                Some("acme"),
                "shop"
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn all_is_capped_to_own_unless_the_posture_opens_it() {
        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::All,
            write: AccessMode::All,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let inputs = TenantSourceInputs {
            domain_context: Some("acme"),
            ..Default::default()
        };
        // Ceiling closed: `all` capped to `own` ⇒ the read carries a tenant predicate.
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            ht.orm_scope(boatramp_handlers::TenantAxis::Read)
                .unwrap()
                .is_some()
        );
        // Ceiling open: `all` stands ⇒ no scope (unscoped, cross-tenant).
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, true), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(
            ht.orm_scope(boatramp_handlers::TenantAxis::Read)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn own_plus_null_write_degrades_to_own_never_the_shared_baseline() {
        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::OwnOrNull,
            write: AccessMode::OwnOrNull,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let inputs = TenantSourceInputs {
            domain_context: Some("acme"),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, false), inputs)
            .await
            .unwrap()
            .unwrap();
        // Read keeps own+null; write is degraded to own (no baseline mutation).
        let read = ht
            .orm_scope(boatramp_handlers::TenantAxis::Read)
            .unwrap()
            .unwrap();
        let write = ht
            .orm_scope(boatramp_handlers::TenantAxis::Write)
            .unwrap()
            .unwrap();
        assert_eq!(read.mode, boatramp_core::orm::ScopeMode::OwnOrNull);
        assert_eq!(write.mode, boatramp_core::orm::ScopeMode::Own);
    }

    #[tokio::test]
    async fn own_source_without_inputs_resolves_to_no_value_then_fails_closed() {
        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        // No domain context supplied ⇒ no value; the binding will deny an own op.
        let ht = resolve_host_tenancy(
            Some(&decision),
            true,
            posture(true, false),
            TenantSourceInputs::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(ht.orm_scope(boatramp_handlers::TenantAxis::Read).is_err());
    }

    #[tokio::test]
    async fn on_unresolved_pass_binds_a_null_scoped_read_but_still_denies_writes_and_unaffected_when_resolved()
     {
        use boatramp_handlers::TenantAxis;
        // A `domain`-source storefront route: read:own / write:none, opted into `on_unresolved: pass`.
        let pass_route = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::Own,
            write: AccessMode::None,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Pass,
        };
        // UNRESOLVED host (no domain context): the route is NOT pre-handler-denied — `orm_scope(Read)`
        // yields a scope (the handler would be invoked) carrying a NULL principal + the pass flag, so
        // the injector confines to zero rows rather than refusing. The WRITE axis stays denied.
        let ht = resolve_host_tenancy(
            Some(&pass_route),
            true,
            posture(true, false),
            TenantSourceInputs::default(),
        )
        .await
        .unwrap()
        .unwrap();
        let read = ht
            .orm_scope(TenantAxis::Read)
            .expect("pass + unresolved must NOT pre-handler-deny the read")
            .expect("a scope (not `all`) is produced");
        assert_eq!(read.value, None, "null principal");
        assert!(
            read.pass_unresolved,
            "the read scope carries the zero-rows pass flag"
        );
        // The write axis is denied (write:none ⇒ NoAccess) — the pass-through never opens a write.
        assert!(
            ht.orm_scope(TenantAxis::Write).is_err(),
            "writes stay denied"
        );

        // The SAME route WITHOUT the opt-in (default Deny) still fails the read closed (today's behavior).
        let deny_route = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::Own,
            write: AccessMode::Own, // an own write, so the read denial isn't masked by a `none` write
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let ht_deny = resolve_host_tenancy(
            Some(&deny_route),
            true,
            posture(true, false),
            TenantSourceInputs::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(
                ht_deny.orm_scope(TenantAxis::Read),
                Err(boatramp_handlers::TenantDenied::NoSource)
            ),
            "default (no opt-in) null-principal read must DENY"
        );

        // A RESOLVED host is UNAFFECTED: the pass route with a routed domain context stamps that
        // tenant and the flag is inert (a real value is bound, read:own enforced downstream).
        let ht_resolved = resolve_host_tenancy(
            Some(&pass_route),
            true,
            posture(true, false),
            TenantSourceInputs {
                domain_context: Some("tenant_A"),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        let read = ht_resolved.orm_scope(TenantAxis::Read).unwrap().unwrap();
        assert_eq!(
            read.value,
            Some(SqlValue::Text("tenant_A".into())),
            "a resolved host stamps its own tenant (pass flag inert when a principal is present)"
        );
    }

    /// **Live** proof (R4/D8) that a **plain-wasm** target route confines BOTH its `orm` and its
    /// raw-`sql` reads to tenant `B`'s PUBLIC subset on a REAL libsql engine — the non-federated
    /// analog of the GDC target live gate. Drives `HostTenancy::target` through `orm_scope`
    /// (force_scope → compile → run) AND `rewrite_target_read` (AST rewrite → run) against a shared
    /// `products` table holding tenant A's row + tenant B's public / draft / soft-deleted rows,
    /// asserting each path returns ONLY B's published, non-deleted row — the raw-SQL path proven over
    /// a join, a subquery, and an OR-escape (the multi-table / escape cases the old single-table
    /// `{scope}` marker could not confine). `#[ignore]`d as a heavy libsql battery (former static-musl bug now fixed)
    /// reason as the ORM batteries; the `test-target-plain-wasm` CI job runs it unignored on the host
    /// toolchain and greps the marker.
    #[tokio::test]
    #[ignore = "heavy libsql battery; run via the test-target-plain-wasm CI job on the static-musl target (libsql 0.10.0 fixes the former static-musl connection double-free)"]
    async fn plain_wasm_target_confines_orm_and_raw_sql_to_b_public_on_a_real_engine() {
        use boatramp_core::orm::{
            CmpOp, Expr, Func, Join, JoinKind, Predicate, Select, SelectItem,
        };
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_core::tenancy::{
            AccessMode, PublicCmp, PublicLiteral, PublicPredicate, PublicSubset, PublicTerm,
            TableScope, TenancySchema,
        };
        use boatramp_handlers::{HostTenancy, TenantAxis};
        use std::collections::BTreeMap;

        let dir =
            std::env::temp_dir().join(format!("boatramp-target-plainwasm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&dir);
        let db = backends.database("default", "shop", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE products (id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT, \
                 published INTEGER, deleted_at TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, name, published, deleted) in [
                ("b1", "tenant_B", "B public", 1i64, None),
                ("b2", "tenant_B", "B draft", 0, None),
                ("b3", "tenant_B", "B removed", 1, Some("2020-01-01")),
                ("a1", "tenant_A", "A public", 1, None),
            ] {
                tx.execute(
                    "INSERT INTO products (id, tenant_id, name, published, deleted_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Text(name.into()),
                        SqlValue::Integer(published),
                        deleted.map_or(SqlValue::Null, |d: &str| SqlValue::Text(d.into())),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        // Project schema: `products` is a Tenant table with a public subset (published=1 AND
        // deleted_at IS NULL). Build the plain-wasm target principal for tenant B.
        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("products".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        schema.public_subsets.insert(
            "products".into(),
            PublicSubset {
                predicate: PublicPredicate {
                    terms: vec![
                        PublicTerm::Cmp {
                            column: "published".into(),
                            op: PublicCmp::Eq,
                            value: PublicLiteral::Int(1),
                        },
                        PublicTerm::Null {
                            column: "deleted_at".into(),
                            negated: false,
                        },
                    ],
                },
                world_public: true,
                listable: true,
            },
        );
        let ht = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &schema,
            "products",
            &[],
            true,
        );

        // (1) The `orm` path: force the target scope onto a Select, compile, run.
        let mut q = Select {
            columns: vec![SelectItem {
                expr: Expr::col("name"),
                alias: None,
            }],
            ..Select::from("products")
        };
        q.force_scope(&ht.orm_scope(TenantAxis::Read).unwrap().unwrap())
            .unwrap();
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let orm_rows = run_text_rows(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            orm_rows,
            vec!["B public".to_string()],
            "orm target read returns ONLY B's published, non-deleted row: {sql}"
        );
        tx.commit().await.unwrap();

        // (2) The raw-SQL path: the guest writes PLAIN SQL and the host AST-rewrites it, confining
        // every table reference to `tenant = B AND <public>`. Run each rewritten statement on the
        // real engine and assert it returns ONLY B's published, non-deleted row — INCLUDING the two
        // cases the old single-table `{scope}` marker could NOT confine (M1 multi-table, M2
        // OR-escape). B + the public literals are injected as literals, so no params are bound.
        for (label, guest_sql) in [
            // Plain single-table read.
            ("plain", "SELECT name FROM products"),
            // M2: a top-level OR that tried to widen to every row — parenthesised, cannot escape.
            (
                "or-escape",
                "SELECT name FROM products WHERE 1 = 1 OR published = 0",
            ),
            // M1: a self-join — BOTH references must be confined, not just one marker position.
            (
                "self-join",
                "SELECT p.name FROM products p JOIN products q ON q.id = p.id",
            ),
            // A subquery source — the inner ref must be confined too.
            (
                "subquery",
                "SELECT name FROM products WHERE id IN (SELECT id FROM products)",
            ),
        ] {
            let rewritten = ht
                .rewrite_target_read(guest_sql, Dialect::Sqlite)
                .unwrap_or_else(|e| panic!("{label}: rewrite refused: {}", e.reason()));
            let mut tx = db.begin().await.unwrap();
            let raw_rows = run_text_rows(tx.as_mut(), &rewritten, &[]).await;
            assert_eq!(
                raw_rows,
                vec!["B public".to_string()],
                "raw-SQL target read [{label}] returns ONLY B's published, non-deleted row: {rewritten}"
            );
            tx.commit().await.unwrap();
        }

        // A target read that touches an UNDECLARED table (no public subset) is refused before the
        // engine — deny-by-default, proven live.
        assert!(
            ht.rewrite_target_read("SELECT name FROM orders", Dialect::Sqlite)
                .is_err(),
            "a target read of an undeclared table must be refused"
        );
        // The Critical review finding: a self-named CTE must be refused (never a pass-through) — it
        // would otherwise read tenant A's private rows raw.
        assert!(
            ht.rewrite_target_read(
                "WITH products AS (SELECT * FROM products WHERE tenant_id = 'tenant_A') \
                 SELECT name FROM products",
                Dialect::Sqlite,
            )
            .is_err(),
            "a self-named CTE must be refused, not passed through unconfined"
        );

        // v0.4.13: a LEFT JOIN confines the joined table in its OWN `ON`, not the top-level WHERE —
        // else the LEFT JOIN collapses to an INNER JOIN and a routed tenant with no matching joined
        // row is dropped (its `COALESCE(joined, driving)` fallback never fires). Prove on the real
        // engine that (a) a no-config tenant B still gets its OWN driving-row fallback, and (b)
        // tenant A's joined row never leaks — on BOTH the orm and raw-sql target paths.
        {
            {
                let mut tx = db.begin().await.unwrap();
                tx.execute(
                    "CREATE TABLE config (tenant_id TEXT, theme TEXT, published INTEGER)",
                    &[],
                )
                .await
                .unwrap();
                // Only tenant A has a config row; tenant B has NONE (the no-config fallback case).
                tx.execute(
                    "INSERT INTO config (tenant_id, theme, published) VALUES ('tenant_A', 'A-theme', 1)",
                    &[],
                )
                .await
                .unwrap();
                tx.commit().await.unwrap();
            }
            let mut schema2 = schema.clone();
            schema2.tables.insert("config".into(), TableScope::Tenant);
            schema2.public_subsets.insert(
                "config".into(),
                PublicSubset {
                    predicate: PublicPredicate {
                        terms: vec![PublicTerm::Cmp {
                            column: "published".into(),
                            op: PublicCmp::Eq,
                            value: PublicLiteral::Int(1),
                        }],
                    },
                    world_public: true,
                    listable: true,
                },
            );
            let ht2 = HostTenancy::target(
                SqlValue::Text("tenant_B".into()),
                AccessMode::Own,
                &schema2,
                "products",
                &[],
                true,
            );
            // orm: products p LEFT JOIN config c ON c.tenant_id = p.tenant_id, SELECT
            // COALESCE(c.theme, p.name) — B has no config, so it must fall back to B's own p.name.
            let mut q = Select {
                table: "products".into(),
                table_alias: Some("p".into()),
                columns: vec![SelectItem {
                    expr: Expr::Func(
                        Func::Coalesce,
                        vec![Expr::col("c.theme"), Expr::col("p.name")],
                    ),
                    alias: None,
                }],
                joins: vec![Join {
                    kind: JoinKind::Left,
                    table: "config".into(),
                    alias: Some("c".into()),
                    on: Predicate::Cmp {
                        left: Expr::col("c.tenant_id"),
                        op: CmpOp::Eq,
                        right: Expr::col("p.tenant_id"),
                    },
                }],
                ..Select::from("products")
            };
            q.force_scope(&ht2.orm_scope(TenantAxis::Read).unwrap().unwrap())
                .unwrap();
            let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
            let mut tx = db.begin().await.unwrap();
            let orm_rows = run_text_rows(tx.as_mut(), &sql, &params).await;
            tx.commit().await.unwrap();
            assert_eq!(
                orm_rows,
                vec!["B public".to_string()],
                "orm LEFT JOIN: no-config tenant B falls back to its own driving row, never A's theme: {sql}"
            );
            // raw-SQL: the same shape, AST-rewritten (joined table confined in the ON).
            let rw = ht2
                .rewrite_target_read(
                    "SELECT COALESCE(c.theme, p.name) FROM products p \
                     LEFT JOIN config c ON c.tenant_id = p.tenant_id",
                    Dialect::Sqlite,
                )
                .unwrap();
            let mut tx = db.begin().await.unwrap();
            let raw_rows = run_text_rows(tx.as_mut(), &rw, &[]).await;
            tx.commit().await.unwrap();
            assert_eq!(
                raw_rows,
                vec!["B public".to_string()],
                "raw-sql LEFT JOIN: no-config tenant B falls back to its own driving row, never A's theme: {rw}"
            );
        }

        println!(
            "PLAIN-WASM TARGET ISOLATION OK: a target route's orm AND raw-sql reads each return only \
             tenant B's published+non-deleted rows (never tenant A's, never B's draft/removed) on a \
             real libsql engine — the raw-SQL path is AST-rewritten so multi-table joins, subqueries, \
             and OR-escapes are all confined, and an undeclared table is refused; a LEFT JOIN confines \
             the joined table in its own ON so a no-config tenant falls back to its own row via \
             COALESCE (never another tenant's, never a dropped row)"
        );
    }

    /// **Live** proof (v0.4.16) that a per-table **`TenantOrBase`** scope folds a table's shared
    /// `tenant IS NULL` base into reads on BOTH the own and target axes, on a REAL libsql engine,
    /// WITHOUT widening a sibling plain-tenant table: an own read as A returns A's rows ⊕ the base
    /// (never B's); a target read for B returns B's public rows ⊕ the base (never A's, never B's
    /// non-public draft); a write stamps the resolved tenant (never a NULL base row). orm + raw-SQL.
    /// `#[ignore]`d (heavy libsql battery; former static-musl concurrency bug now fixed); the `test-target-plain-wasm` CI job runs it +
    /// greps the marker.
    #[tokio::test]
    #[ignore = "heavy libsql battery; run via the test-target-plain-wasm CI job on the static-musl target (libsql 0.10.0 fixes the former static-musl connection double-free)"]
    async fn plain_wasm_target_or_base_folds_shared_base_on_own_and_target_on_a_real_engine() {
        use boatramp_core::orm::{Expr, ScopeMode, Select, SelectItem, TableKeys};
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_core::tenancy::{
            AccessMode, PublicCmp, PublicLiteral, PublicPredicate, PublicSubset, PublicTerm,
            TableScope, TenancySchema,
        };
        use boatramp_handlers::{HostTenancy, TenantAxis};
        use std::collections::BTreeMap;

        let dir =
            std::env::temp_dir().join(format!("boatramp-target-orbase-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&dir);
        let db = backends.database("default", "shop", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE pack (id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT, published INTEGER)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, name, published) in [
                ("base1", None, "base pack", 1i64), // shared base (tenant_id NULL)
                ("a1", Some("tenant_A"), "A pack", 1),
                ("b1", Some("tenant_B"), "B pack", 1),
                ("b2", Some("tenant_B"), "B draft", 0), // B's non-public row (target subset excludes)
            ] {
                tx.execute(
                    "INSERT INTO pack (id, tenant_id, name, published) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        SqlValue::Text(id.into()),
                        tenant.map_or(SqlValue::Null, |t| SqlValue::Text(t.into())),
                        SqlValue::Text(name.into()),
                        SqlValue::Integer(published),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }
        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("pack".into(), TableScope::TenantOrBase)]),
            ..Default::default()
        };
        schema.public_subsets.insert(
            "pack".into(),
            PublicSubset {
                predicate: PublicPredicate {
                    terms: vec![PublicTerm::Cmp {
                        column: "published".into(),
                        op: PublicCmp::Eq,
                        value: PublicLiteral::Int(1),
                    }],
                },
                world_public: true,
                listable: true,
            },
        );

        let name_q = || Select {
            columns: vec![SelectItem {
                expr: Expr::col("name"),
                alias: None,
            }],
            ..Select::from("pack")
        };
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };

        // (1) OWN axis as tenant A: (tenant = A OR tenant IS NULL) — A's rows ⊕ the shared base,
        // never B's. (No public subset on the own axis.)
        let own_a = boatramp_core::orm::Scope {
            column: "tenant_id".into(),
            value: Some(SqlValue::Text("tenant_A".into())),
            session: None,
            mode: ScopeMode::Own,
            keys: TableKeys::PerTable(schema.table_key_map()),
            unscoped_writes: std::collections::BTreeSet::new(),
            pass_unresolved: false,
        };
        let mut q = name_q();
        q.force_scope(&own_a).unwrap();
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let rows = run_text_rows(tx.as_mut(), &sql, &params).await;
        tx.commit().await.unwrap();
        assert_eq!(
            sorted(rows),
            vec!["A pack".to_string(), "base pack".to_string()],
            "own read as A = A's rows ⊕ shared base, never B's: {sql}"
        );

        // (2) TARGET axis for tenant B (domain source, require_public): (tenant = B OR tenant IS NULL)
        // AND published = 1 — B's PUBLIC row ⊕ the public base, never A's, never B's draft.
        let ht = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &schema,
            "pack",
            &[],
            true,
        );
        let mut tq = name_q();
        tq.force_scope(&ht.orm_scope(TenantAxis::Read).unwrap().unwrap())
            .unwrap();
        let (tsql, tparams) = tq.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let trows = run_text_rows(tx.as_mut(), &tsql, &tparams).await;
        tx.commit().await.unwrap();
        assert_eq!(
            sorted(trows),
            vec!["B pack".to_string(), "base pack".to_string()],
            "target orm read for B = B's public rows ⊕ public base, never A, never B's draft: {tsql}"
        );

        // (3) raw-SQL target read (AST-rewritten): identical confinement.
        let rewritten = ht
            .rewrite_target_read("SELECT name FROM pack", Dialect::Sqlite)
            .unwrap();
        assert!(
            rewritten.contains("pack.tenant_id = 'tenant_B' OR pack.tenant_id IS NULL"),
            "raw-sql folds the base under a plain target read: {rewritten}"
        );
        let mut tx = db.begin().await.unwrap();
        let rrows = run_text_rows(tx.as_mut(), &rewritten, &[]).await;
        tx.commit().await.unwrap();
        assert_eq!(
            sorted(rrows),
            vec!["B pack".to_string(), "base pack".to_string()],
            "raw-sql target read for B = B's public rows ⊕ public base: {rewritten}"
        );

        // (4) WRITE (own axis as A) stamps tenant = A, never a NULL base row.
        let mut ins = boatramp_core::orm::Insert {
            table: "pack".into(),
            rows: vec![boatramp_core::orm::RowValues {
                cells: vec![
                    boatramp_core::orm::Assignment {
                        column: "id".into(),
                        value: Expr::val(SqlValue::Text("a_new".into())),
                    },
                    boatramp_core::orm::Assignment {
                        column: "name".into(),
                        value: Expr::val(SqlValue::Text("A wrote".into())),
                    },
                ],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        ins.force_scope(Some(&own_a), Some(&own_a)).unwrap();
        let (isql, iparams) = ins.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&isql, &iparams).await.unwrap();
        tx.commit().await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let stamped = tx
            .query("SELECT tenant_id FROM pack WHERE id = 'a_new'", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            stamped.rows[0][0],
            SqlValue::Text("tenant_A".into()),
            "an own write to a base-inclusive table stamps tenant = A, never a NULL base row"
        );

        println!(
            "PLAIN-WASM TENANT-OR-BASE OK: a per-table TenantOrBase scope folds a table's shared \
             tenant-NULL base into reads on both the own axis (A ⊕ base, never B) and the target axis \
             (B's public rows ⊕ public base, never A, never B's draft), orm AND raw-sql, while a \
             write stamps the resolved tenant (never a NULL base row), on a real libsql engine"
        );
    }

    /// **Live** proof (R4/D8, Stage 5b) that a **plain-wasm** target route's WRITES land ONLY in
    /// tenant `B`'s PUBLIC subset on a REAL libsql engine: an INSERT force-stamps `tenant = B` + the
    /// visibility columns (so the row is B's and public) and takes only the SET-allowlisted column
    /// from the guest; an UPDATE is confined to `tenant = B AND <public>` and may set only the
    /// allowlisted column; a DELETE, a set of the tenant/visibility column, and a read-only-route
    /// write are all refused. `#[ignore]`d (heavy libsql battery; former static-musl concurrency bug now fixed); the `test-target-plain-wasm`
    /// CI job runs it unignored and greps the marker.
    #[tokio::test]
    #[ignore = "heavy libsql battery; run via the test-target-plain-wasm CI job on the static-musl target (libsql 0.10.0 fixes the former static-musl connection double-free)"]
    async fn plain_wasm_target_writes_confine_to_b_public_subset_on_a_real_engine() {
        use boatramp_core::orm::{Assignment, CmpOp, Delete, Expr, Insert, Predicate, RowValues};
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_core::tenancy::{
            AccessMode, PublicCmp, PublicLiteral, PublicPredicate, PublicSubset, PublicTerm,
            TableScope, TenancySchema,
        };
        use boatramp_handlers::{HostTenancy, TenantAxis};
        use std::collections::BTreeMap;

        let dir = std::env::temp_dir().join(format!(
            "boatramp-target-plainwasm-write-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&dir);
        let db = backends.database("default", "shop", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE products (id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT, \
                 published INTEGER, deleted_at TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, name, published, deleted) in [
                ("b1", "tenant_B", "B public", 1i64, None),
                ("b2", "tenant_B", "B draft", 0, None),
                ("a1", "tenant_A", "A public", 1, None),
            ] {
                tx.execute(
                    "INSERT INTO products (id, tenant_id, name, published, deleted_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Text(name.into()),
                        SqlValue::Integer(published),
                        deleted.map_or(SqlValue::Null, |d: &str| SqlValue::Text(d.into())),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("products".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        schema.public_subsets.insert(
            "products".into(),
            PublicSubset {
                predicate: PublicPredicate {
                    terms: vec![
                        PublicTerm::Cmp {
                            column: "published".into(),
                            op: PublicCmp::Eq,
                            value: PublicLiteral::Int(1),
                        },
                        PublicTerm::Null {
                            column: "deleted_at".into(),
                            negated: false,
                        },
                    ],
                },
                world_public: true,
                listable: true,
            },
        );
        // A write-granted target principal: the guest may set ONLY `name`.
        let ht = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &schema,
            "products",
            &["name".to_string()],
            true,
        );
        let write = ht.orm_scope(TenantAxis::Write).unwrap().unwrap();
        let read = ht.orm_scope(TenantAxis::Read).unwrap().unwrap();

        // (1) INSERT: the guest sets only `name`; the host force-stamps tenant=B + published=1 +
        // deleted_at=NULL, so the row lands in B's public subset.
        let mut ins = Insert {
            table: "products".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "id".into(),
                        value: Expr::val(SqlValue::Text("new1".into())),
                    },
                    Assignment {
                        column: "name".into(),
                        value: Expr::val(SqlValue::Text("guest wrote".into())),
                    },
                ],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        // `id` is not in the allowlist → the INSERT must be refused (the guest may set only `name`).
        assert!(
            ins.force_scope(Some(&write), Some(&read)).is_err(),
            "a target INSERT setting a non-allowlisted column (id) must be refused"
        );
        // With only `name`, it is accepted and confined.
        let mut ins = Insert {
            table: "products".into(),
            rows: vec![RowValues {
                cells: vec![Assignment {
                    column: "name".into(),
                    value: Expr::val(SqlValue::Text("guest wrote".into())),
                }],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        ins.force_scope(Some(&write), Some(&read)).unwrap();
        let (sql, params) = ins.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        tx.commit().await.unwrap();
        // Read the inserted row back (as the operator, unscoped) — it must be B's + public.
        let mut tx = db.begin().await.unwrap();
        let rows = tx
            .query(
                "SELECT tenant_id, published, deleted_at FROM products WHERE name = 'guest wrote'",
                &[],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(rows.rows.len(), 1, "exactly one inserted row");
        let row = &rows.rows[0];
        assert_eq!(
            row[0],
            SqlValue::Text("tenant_B".into()),
            "tenant forced to B"
        );
        assert!(
            matches!(row[1], SqlValue::Integer(1)),
            "published forced to 1 (public)"
        );
        assert_eq!(row[2], SqlValue::Null, "deleted_at forced NULL (public)");

        // (2) UPDATE confined to B's public rows. Targeting b2 (B's DRAFT, non-public) changes
        // nothing; targeting a1 (tenant A) changes nothing; targeting b1 (B public) renames it.
        for (id, expected) in [("b2", 0u64), ("a1", 0), ("b1", 1)] {
            let mut upd = boatramp_core::orm::Update {
                table: "products".into(),
                set: vec![Assignment {
                    column: "name".into(),
                    value: Expr::val(SqlValue::Text("RENAMED".into())),
                }],
                filter: Predicate::Cmp {
                    left: Expr::col("id"),
                    op: CmpOp::Eq,
                    right: Expr::val(SqlValue::Text(id.into())),
                },
                scope: None,
                returning: vec![],
            };
            upd.force_scope(&write).unwrap();
            let (sql, params) = upd.compile(Dialect::Sqlite).unwrap();
            let mut tx = db.begin().await.unwrap();
            let n = tx.execute(&sql, &params).await.unwrap();
            tx.commit().await.unwrap();
            assert_eq!(
                n, expected,
                "UPDATE of {id}: expected {expected} rows affected (confined to B's public subset)"
            );
        }
        // Confirm only b1 was renamed; b2/a1 kept their names.
        let mut tx = db.begin().await.unwrap();
        let names = run_text_rows(
            tx.as_mut(),
            "SELECT name FROM products WHERE id IN ('b1','b2','a1') ORDER BY id",
            &[],
        )
        .await;
        tx.commit().await.unwrap();
        assert_eq!(
            names,
            vec![
                "A public".to_string(),
                "B draft".to_string(),
                "RENAMED".to_string()
            ],
            "only B's public row (b1) was renamed; B's draft + tenant A untouched"
        );

        // (3) A target UPDATE that tries to flip visibility (set published) is refused.
        let mut flip = boatramp_core::orm::Update {
            table: "products".into(),
            set: vec![Assignment {
                column: "published".into(),
                value: Expr::val(SqlValue::Integer(0)),
            }],
            filter: Predicate::Cmp {
                left: Expr::col("id"),
                op: CmpOp::Eq,
                right: Expr::val(SqlValue::Text("b1".into())),
            },
            scope: None,
            returning: vec![],
        };
        assert!(
            flip.force_scope(&write).is_err(),
            "a target UPDATE may not set a visibility column (published)"
        );

        // (4) A target DELETE is always refused.
        let mut del = Delete {
            table: "products".into(),
            filter: Predicate::Cmp {
                left: Expr::col("id"),
                op: CmpOp::Eq,
                right: Expr::val(SqlValue::Text("b1".into())),
            },
            scope: None,
            returning: vec![],
        };
        assert!(
            del.force_scope(&write).is_err(),
            "a target DELETE is refused"
        );

        // (5) A read-only target route (no write grant) cannot write at all.
        let ro = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &schema,
            "products",
            &[],
            true,
        );
        assert!(
            ro.orm_scope(TenantAxis::Write).is_err(),
            "a read-only target route denies the write axis outright"
        );

        // (6) v0.4.15 — a CAPABILITY-axis `ON CONFLICT … DO UPDATE` upsert (own↔target parity, the
        // embedSubmitSurvey latest-wins pattern). The conflict key is tenant-scoped
        // `(tenant_id, project_id, client_id)`; the DO UPDATE is guarded to `tenant = B`. A first
        // submit inserts (stamped B), a second upserts the same (B,key) row (latest wins), and a
        // pre-seeded tenant-A row sharing the natural key is neither updated nor duplicated.
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE client_survey (tenant_id TEXT, project_id TEXT, client_id TEXT, \
                 score INTEGER, PRIMARY KEY (tenant_id, project_id, client_id))",
                &[],
            )
            .await
            .unwrap();
            // tenant A already rated (proj1, cli_a) = 1 — must never be touched by B's capability upsert.
            tx.execute(
                "INSERT INTO client_survey (tenant_id, project_id, client_id, score) \
                 VALUES ('tenant_A','proj1','cli_a',1)",
                &[],
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let survey_schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("client_survey".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        // Capability axis: require_public = false (no visibility subset); the guest may set the
        // natural-key cells + score.
        let ht_cap = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &survey_schema,
            "survey",
            &[
                "project_id".to_string(),
                "client_id".to_string(),
                "score".to_string(),
            ],
            false,
        );
        let write_cap = ht_cap.orm_scope(TenantAxis::Write).unwrap().unwrap();
        let read_cap = ht_cap.orm_scope(TenantAxis::Read).unwrap().unwrap();
        let submit = |score: i64| {
            let mut ins = Insert {
                table: "client_survey".into(),
                rows: vec![RowValues {
                    cells: vec![
                        Assignment {
                            column: "project_id".into(),
                            value: Expr::val(SqlValue::Text("proj1".into())),
                        },
                        Assignment {
                            column: "client_id".into(),
                            value: Expr::val(SqlValue::Text("cli_a".into())),
                        },
                        Assignment {
                            column: "score".into(),
                            value: Expr::val(SqlValue::Integer(score)),
                        },
                    ],
                }],
                conflict: Some(boatramp_core::orm::OnConflict {
                    conflict_columns: vec![
                        "tenant_id".into(),
                        "project_id".into(),
                        "client_id".into(),
                    ],
                    update: vec![Assignment {
                        column: "score".into(),
                        value: Expr::col("excluded.score"),
                    }],
                }),
                scope: None,
                returning: vec![],
                from_select: None,
            };
            ins.force_scope(Some(&write_cap), Some(&read_cap)).unwrap();
            ins.compile(Dialect::Sqlite).unwrap()
        };
        for score in [5i64, 9] {
            let (sql, params) = submit(score);
            assert!(
                sql.contains("client_survey.tenant_id ="),
                "DO UPDATE guarded to tenant = B: {sql}"
            );
            let mut tx = db.begin().await.unwrap();
            tx.execute(&sql, &params).await.unwrap();
            tx.commit().await.unwrap();
        }
        let mut tx = db.begin().await.unwrap();
        let survey = tx
            .query(
                "SELECT tenant_id, score FROM client_survey ORDER BY tenant_id",
                &[],
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        // Exactly two rows: tenant A's untouched (score 1) and tenant B's latest-wins (score 9).
        assert_eq!(
            survey.rows.len(),
            2,
            "no cross-tenant row created: {survey:?}"
        );
        assert_eq!(
            survey.rows[0],
            vec![SqlValue::Text("tenant_A".into()), SqlValue::Integer(1)],
            "tenant A's survey untouched by B's capability upsert"
        );
        assert_eq!(
            survey.rows[1],
            vec![SqlValue::Text("tenant_B".into()), SqlValue::Integer(9)],
            "tenant B's survey upserted latest-wins (5 -> 9) on the (B,key) row"
        );

        println!(
            "PLAIN-WASM TARGET WRITE ISOLATION OK: a target route's orm writes land only in tenant \
             B's public subset (INSERT force-stamps tenant=B + visibility; UPDATE confined to B's \
             public rows, only the allowlisted column settable), a DELETE / visibility-flip / \
             read-only write are all refused, AND a capability-axis ON CONFLICT DO UPDATE upsert is \
             latest-wins on the (B,key) row with tenant A untouched/unduplicated, on a real libsql engine"
        );
    }

    /// **Live** proof (R4/D8, Stage 5d) that `attach_reference` derives the child's tenant from a
    /// parent reachable under the caller's confined scope on a REAL libsql engine: a reference to B's
    /// PUBLIC parent row inserts a child row stamped tenant=B (+ the child's visibility forced); a
    /// reference to B's DRAFT (non-public) parent or to tenant A's parent is a fail-closed NO-OP (0
    /// rows), so the derived tenant can never be one the caller couldn't already reach. `#[ignore]`d
    /// (heavy libsql battery; former static-musl concurrency bug now fixed); the `test-target-plain-wasm` CI job runs it + greps the marker.
    #[tokio::test]
    #[ignore = "heavy libsql battery; run via the test-target-plain-wasm CI job on the static-musl target (libsql 0.10.0 fixes the former static-musl connection double-free)"]
    async fn plain_wasm_target_attach_reference_derives_tenant_from_a_reachable_parent_on_a_real_engine()
     {
        use boatramp_core::orm::{Assignment, AttachReference, Expr, compile_attach_reference};
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_core::tenancy::{
            AccessMode, PublicCmp, PublicLiteral, PublicPredicate, PublicSubset, PublicTerm,
            TableScope, TenancySchema,
        };
        use boatramp_handlers::{HostTenancy, TenantAxis};
        use std::collections::BTreeMap;

        let dir =
            std::env::temp_dir().join(format!("boatramp-target-attachref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&dir);
        let db = backends.database("default", "shop", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE products (id TEXT PRIMARY KEY, tenant_id TEXT, published INTEGER)",
                &[],
            )
            .await
            .unwrap();
            tx.execute(
                "CREATE TABLE favorites (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, \
                 product_id TEXT, note TEXT, visible INTEGER)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, published) in [
                ("b_pub", "tenant_B", 1i64),
                ("b_draft", "tenant_B", 0),
                ("a_pub", "tenant_A", 1),
            ] {
                tx.execute(
                    "INSERT INTO products (id, tenant_id, published) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Integer(published),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        // Schema: products public = published=1; favorites public = visible=1. Write-granted target
        // scope for B, `note` settable on favorites.
        let world = |col: &str, v: i64| PublicSubset {
            predicate: PublicPredicate {
                terms: vec![PublicTerm::Cmp {
                    column: col.into(),
                    op: PublicCmp::Eq,
                    value: PublicLiteral::Int(v),
                }],
            },
            world_public: true,
            listable: true,
        };
        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([
                ("products".into(), TableScope::Tenant),
                ("favorites".into(), TableScope::Tenant),
            ]),
            ..Default::default()
        };
        schema
            .public_subsets
            .insert("products".into(), world("published", 1));
        schema
            .public_subsets
            .insert("favorites".into(), world("visible", 1));
        let ht = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &schema,
            "products",
            &["note".to_string(), "product_id".to_string()],
            true,
        );
        let write = ht.orm_scope(TenantAxis::Write).unwrap().unwrap();

        let attach = |product: &str| AttachReference {
            child: "favorites".into(),
            parent: "products".into(),
            ref_column: "id".into(),
            ref_value: SqlValue::Text(product.into()),
            set: vec![
                Assignment {
                    column: "product_id".into(),
                    value: Expr::val(SqlValue::Text(product.into())),
                },
                Assignment {
                    column: "note".into(),
                    value: Expr::val(SqlValue::Text("fav".into())),
                },
            ],
        };
        // Reference each product; only B's PUBLIC product is reachable → 1 insert; the draft + tenant
        // A are no-ops (0 rows).
        for (product, expected) in [("b_pub", 1u64), ("b_draft", 0), ("a_pub", 0)] {
            let (sql, params) =
                compile_attach_reference(&write, &attach(product), Dialect::Sqlite).unwrap();
            let mut tx = db.begin().await.unwrap();
            let n = tx.execute(&sql, &params).await.unwrap();
            tx.commit().await.unwrap();
            assert_eq!(
                n, expected,
                "attach_reference to {product}: expected {expected} inserts (reachable-parent gate)"
            );
        }
        // The one inserted favorite is stamped tenant=B and visible=1 (forced public), referencing the
        // public product — never tenant A, never the draft.
        let mut tx = db.begin().await.unwrap();
        let rows = tx
            .query("SELECT tenant_id, product_id, visible FROM favorites", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            rows.rows.len(),
            1,
            "exactly one favorite inserted (only b_pub reachable)"
        );
        let row = &rows.rows[0];
        assert_eq!(
            row[0],
            SqlValue::Text("tenant_B".into()),
            "derived tenant = B (the parent's)"
        );
        assert_eq!(
            row[1],
            SqlValue::Text("b_pub".into()),
            "references B's public product"
        );
        assert!(
            matches!(row[2], SqlValue::Integer(1)),
            "child visibility forced public"
        );

        println!(
            "PLAIN-WASM TARGET ATTACH-REFERENCE ISOLATION OK: attach_reference stamped the child's \
             tenant from B's reachable public parent (never tenant A, never B's draft) and was a \
             fail-closed no-op for every unreachable parent, on a real libsql engine"
        );
    }

    /// **Live** proof (R4/D8 5c ruling A) that a **`via: [capability]`-only** target field with NO
    /// declared public subset confines to `tenant = B` alone — the capability is the authorization —
    /// on a REAL libsql engine: both the `orm` and the raw-`sql` (AST-rewritten) reads return ALL of
    /// tenant B's rows (across clients — the per-client filter is the app's, in-guest) and NEVER
    /// tenant A's. Proves the exemption does not widen past the one tenant `B`. `#[ignore]`d
    /// (heavy libsql battery; former static-musl concurrency bug now fixed); the `test-target-plain-wasm` CI job runs it + greps the marker.
    #[tokio::test]
    #[ignore = "heavy libsql battery; run via the test-target-plain-wasm CI job on the static-musl target (libsql 0.10.0 fixes the former static-musl connection double-free)"]
    async fn plain_wasm_target_capability_confines_to_tenant_b_without_a_subset_on_a_real_engine() {
        use boatramp_core::orm::{CmpOp, Expr, Predicate, Select, SelectItem};
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_core::tenancy::{
            AccessMode, PublicPredicate, PublicSubset, PublicTerm, TableScope, TenancySchema,
        };
        use boatramp_handlers::{HostTenancy, TenantAxis};
        use std::collections::BTreeMap;

        let dir =
            std::env::temp_dir().join(format!("boatramp-target-capability-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&dir);
        let db = backends.database("default", "shop", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE invoices (id TEXT PRIMARY KEY, tenant_id TEXT, client_id TEXT, amount INTEGER)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, client, amount) in [
                ("b1", "tenant_B", "cli_1", 10i64),
                ("b2", "tenant_B", "cli_2", 20), // a DIFFERENT client within B (per-client is in-guest)
                ("a1", "tenant_A", "cli_9", 99),
            ] {
                tx.execute(
                    "INSERT INTO invoices (id, tenant_id, client_id, amount) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Text(client.into()),
                        SqlValue::Integer(amount),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        // `invoices` is a Tenant table with NO declared public subset. A capability-only field
        // (require_public = false) confines it to `tenant = B` alone.
        let schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("invoices".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        let ht = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &schema,
            "client-invoices", // a scope LABEL (matched against the capability's grant); not a subset
            &[],
            false, // capability-only: no visibility subset required
        );

        // (1) orm: SELECT id FROM invoices → confined to tenant = B (both of B's clients; never A).
        let mut q = Select {
            columns: vec![SelectItem {
                expr: Expr::col("id"),
                alias: None,
            }],
            ..Select::from("invoices")
        };
        q.force_scope(&ht.orm_scope(TenantAxis::Read).unwrap().unwrap())
            .unwrap();
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let orm_rows = run_text_rows(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            orm_rows,
            vec!["b1".to_string(), "b2".to_string()],
            "capability orm read = ALL of tenant B (across clients), never A: {sql}"
        );
        tx.commit().await.unwrap();
        assert!(
            !sql.contains("published") && !sql.contains("client_id"),
            "no visibility/per-client predicate injected — confinement is tenant-only: {sql}"
        );

        // (2) raw SQL (AST-rewritten) → tenant = B, no visibility predicate.
        let rewritten = ht
            .rewrite_target_read("SELECT id FROM invoices", Dialect::Sqlite)
            .unwrap();
        assert!(
            rewritten.contains("invoices.tenant_id = 'tenant_B'")
                && !rewritten.contains("published"),
            "raw-sql capability read confines tenant-only: {rewritten}"
        );
        let mut tx = db.begin().await.unwrap();
        let raw_rows = run_text_rows(tx.as_mut(), &rewritten, &[]).await;
        assert_eq!(
            raw_rows,
            vec!["b1".to_string(), "b2".to_string()],
            "raw-sql capability read = tenant B only: {rewritten}"
        );
        tx.commit().await.unwrap();

        // (3) v0.4.14 — ruling A COMPLETE: a table that DECLARES a public subset for the anonymous
        // funnel must NOT have it applied on the capability axis. `documents` declares
        // `client_id IS NULL` (the unclaimed-storefront funnel reveal). A capability read that adds
        // its OWN within-tenant `client_id = 'cli_1'` filter must return cli_1's CLAIMED docs — NOT
        // the empty set the old `client_id = 'cli_1' AND client_id IS NULL` collision produced — and
        // still never tenant A's row (even one sharing the same client_id).
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE documents (id TEXT PRIMARY KEY, tenant_id TEXT, client_id TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, client) in [
                ("d_b1", "tenant_B", Some("cli_1")),
                ("d_b2", "tenant_B", Some("cli_2")), // another client within B
                ("d_bpub", "tenant_B", None),        // an unclaimed (funnel-public) row
                ("d_a1", "tenant_A", Some("cli_1")), // tenant A, SAME client label — must never leak
            ] {
                tx.execute(
                    "INSERT INTO documents (id, tenant_id, client_id) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        client.map_or(SqlValue::Null, |c| SqlValue::Text(c.into())),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }
        let mut schema_docs = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("documents".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        schema_docs.public_subsets.insert(
            "documents".into(),
            PublicSubset {
                // The funnel subset: unclaimed rows are the anonymous-public ones.
                predicate: PublicPredicate {
                    terms: vec![PublicTerm::Null {
                        column: "client_id".into(),
                        negated: false,
                    }],
                },
                world_public: true,
                listable: true,
            },
        );
        // Capability axis (require_public = false) even though a subset is DECLARED.
        let ht_docs = HostTenancy::target(
            SqlValue::Text("tenant_B".into()),
            AccessMode::Own,
            &schema_docs,
            "client-documents", // scope label matched to the capability grant
            &[],
            false,
        );

        // orm: the resolver's OWN in-guest filter `client_id = 'cli_1'`.
        let mut qd = Select {
            columns: vec![SelectItem {
                expr: Expr::col("id"),
                alias: None,
            }],
            filter: Some(Predicate::Cmp {
                left: Expr::col("client_id"),
                op: CmpOp::Eq,
                right: Expr::Value(SqlValue::Text("cli_1".into())),
            }),
            ..Select::from("documents")
        };
        qd.force_scope(&ht_docs.orm_scope(TenantAxis::Read).unwrap().unwrap())
            .unwrap();
        let (sqld, paramsd) = qd.compile(Dialect::Sqlite).unwrap();
        assert!(
            !sqld.contains("IS NULL"),
            "the declared `client_id IS NULL` subset must NOT be applied on the capability axis: {sqld}"
        );
        let mut tx = db.begin().await.unwrap();
        let doc_rows = run_text_rows(tx.as_mut(), &sqld, &paramsd).await;
        assert_eq!(
            doc_rows,
            vec!["d_b1".to_string()],
            "capability orm read returns cli_1's CLAIMED doc (declared subset NOT AND-ed on), never \
             cli_2/unclaimed, never tenant A: {sqld}"
        );
        tx.commit().await.unwrap();

        // raw sql: same — the guest's `client_id = 'cli_1'` survives, the funnel subset is dropped.
        let rewritten_docs = ht_docs
            .rewrite_target_read(
                "SELECT id FROM documents WHERE client_id = 'cli_1'",
                Dialect::Sqlite,
            )
            .unwrap();
        assert!(
            rewritten_docs.contains("documents.tenant_id = 'tenant_B'")
                && rewritten_docs.contains("client_id = 'cli_1'")
                && !rewritten_docs.contains("IS NULL"),
            "raw-sql capability read keeps tenant=B + the guest filter, drops the funnel subset: {rewritten_docs}"
        );
        let mut tx = db.begin().await.unwrap();
        let raw_doc_rows = run_text_rows(tx.as_mut(), &rewritten_docs, &[]).await;
        assert_eq!(
            raw_doc_rows,
            vec!["d_b1".to_string()],
            "raw-sql capability read of a declared-subset table = cli_1's claimed doc only: {rewritten_docs}"
        );
        tx.commit().await.unwrap();

        println!(
            "PLAIN-WASM CAPABILITY TARGET ISOLATION OK: a via:[capability]-only field confines its \
             orm AND raw-sql reads to tenant B alone — with NO declared subset (all of B's rows) AND \
             with a DECLARED funnel subset that is dropped so the resolver's own client_id filter \
             returns the claimed rows (never the empty set, never tenant A), on a real libsql engine"
        );
    }

    /// **Live** proof (Stages B→C→D, PLAN-delegable-capabilities) that the delegable-capability
    /// round-trip works end to end on a real libsql engine: a capability carrying an opaque app-context
    /// (`sub`) is redeemed on a `via:[capability]` route → the host confines the read to `tenant = B`
    /// AND surfaces `sub` back to the guest via `HostTenancy::target_context` (never the tenant `B`
    /// itself) → the guest's own in-guest `client_id = sub` filter narrows within B, and crucially
    /// never reaches tenant A's row that happens to share the same `client_id`. Plus the negative
    /// control: the same capability is INERT at another project (no cross-project redeem). `#[ignore]`d
    /// (heavy libsql battery; former static-musl concurrency bug now fixed); the `test-target-plain-wasm` CI job runs it + greps the marker.
    #[tokio::test]
    #[ignore = "heavy libsql battery; run via the test-target-plain-wasm CI job on the static-musl target (libsql 0.10.0 fixes the former static-musl connection double-free)"]
    async fn plain_wasm_target_capability_context_roundtrips_sub_on_a_real_engine() {
        use boatramp_core::cose::{LocalSigner, Signer, TokenAlg, mint_capability};
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_core::tenancy::{AccessMode, TableScope, TargetSource, TenancySchema};
        use boatramp_handlers::HostTenancy;
        use std::collections::BTreeMap;

        // Real engine: tenant B has two clients (cli_1, cli_2); tenant A is a DIFFERENT tenant whose
        // row shares client_id cli_1 — the host `tenant = B` floor must exclude it regardless.
        let dir =
            std::env::temp_dir().join(format!("boatramp-target-capctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&dir);
        let db = backends.database("default", "shop", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE invoices (id TEXT PRIMARY KEY, tenant_id TEXT, client_id TEXT, amount INTEGER)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, client, amount) in [
                ("b1", "tenant_B", "cli_1", 10i64),
                ("b2", "tenant_B", "cli_2", 20),
                ("a1", "tenant_A", "cli_1", 99), // SAME client_id, different tenant — must never leak
            ] {
                tx.execute(
                    "INSERT INTO invoices (id, tenant_id, client_id, amount) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Text(client.into()),
                        SqlValue::Integer(amount),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        // MINT (Stage C outcome): a capability for tenant B, redeemable at project `shop`, carrying the
        // opaque per-client context sub=cli_1. `shop` is the audience the mint binding host-forces.
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        let app_context = BTreeMap::from([("sub".to_string(), "cli_1".to_string())]);
        let cap = mint_capability(
            "tenant_B",
            "shop",
            "client-invoices",
            &app_context,
            300,
            1000,
            &signer,
        )
        .await
        .unwrap();

        // `invoices` is a Tenant table with no declared public subset (a capability-only field).
        let schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("invoices".into(), TableScope::Tenant)]),
            ..Default::default()
        };

        // REDEEM (Stage B verify + resolve): the capability resolves tenant B AND surfaces the context.
        let rt = resolve_target_via(
            &[TargetSource::Capability],
            "client-invoices", // route public label, matched against the capability's grant
            &[],               // read-only route
            &schema,
            None,
            Some(cap.as_str()),
            Some(&anchor),
            None,
            "shop",
            1000,
        )
        .expect("the capability resolves at its own project");
        assert_eq!(rt.value, "tenant_B", "redeem resolves tenant B");
        assert_eq!(
            rt.context.get("sub").map(String::as_str),
            Some("cli_1"),
            "the opaque sub is surfaced from the verified capability"
        );

        // Negative control: the SAME capability is inert at a DIFFERENT project (no cross-project redeem).
        assert!(
            resolve_target_via(
                &[TargetSource::Capability],
                "client-invoices",
                &[],
                &schema,
                None,
                Some(cap.as_str()),
                Some(&anchor),
                None,
                "other-project",
                1000,
            )
            .is_none(),
            "a capability minted for `shop` must not resolve at `other-project`"
        );

        // Build the target principal + carry the app-context (Stage D), exactly as dispatch does.
        let ht = HostTenancy::target(
            SqlValue::Text(rt.value.clone()),
            AccessMode::Own,
            &schema,
            "client-invoices",
            &rt.write,
            false, // capability-only: no visibility subset
        )
        .with_target_context(rt.context.clone());

        // READ-BACK (Stage D): the guest reads sub; the host-forced tenant B is NEVER exposed.
        let ctx = ht.target_context();
        assert_eq!(ctx.get("sub").map(String::as_str), Some("cli_1"));
        assert!(
            !ctx.values().any(|v| v == "tenant_B") && !ctx.contains_key("tenant_id"),
            "the read-back exposes ONLY the app-context, never the host-forced tenant B: {ctx:?}"
        );

        // (1) Host confinement: an unfiltered read returns ALL of tenant B (both clients), never A.
        let unfiltered = ht
            .rewrite_target_read("SELECT id FROM invoices", Dialect::Sqlite)
            .unwrap();
        let mut tx = db.begin().await.unwrap();
        assert_eq!(
            run_text_rows(tx.as_mut(), &unfiltered, &[]).await,
            vec!["b1".to_string(), "b2".to_string()],
            "host confines to tenant B across clients: {unfiltered}"
        );
        tx.commit().await.unwrap();

        // (2) The guest applies its OWN per-client filter using the read-back sub → only cli_1's row
        // within B (b1). The host `tenant = B` floor still excludes tenant A's a1 despite the SAME
        // client_id — proving the two-layer isolation (host tenancy + in-guest authz) composes.
        let sub = ctx.get("sub").unwrap();
        let filtered = ht
            .rewrite_target_read(
                &format!("SELECT id FROM invoices WHERE client_id = '{sub}'"),
                Dialect::Sqlite,
            )
            .unwrap();
        assert!(
            filtered.contains("invoices.tenant_id = 'tenant_B'") && filtered.contains("client_id"),
            "both the host tenant floor and the guest client filter are present: {filtered}"
        );
        let mut tx = db.begin().await.unwrap();
        assert_eq!(
            run_text_rows(tx.as_mut(), &filtered, &[]).await,
            vec!["b1".to_string()],
            "the in-guest sub filter narrows to cli_1 WITHIN B (b1), never tenant A's a1: {filtered}"
        );
        tx.commit().await.unwrap();

        println!(
            "PLAIN-WASM CAPABILITY CONTEXT ROUNDTRIP OK: a capability carrying an opaque sub redeems to \
             tenant B (inert cross-project), surfaces sub via target-context (never leaking B), the host \
             confines the read to tenant B, and the guest's in-guest client_id = sub filter narrows to \
             the one client within B (never tenant A's same-client_id row), on a real libsql engine"
        );
    }

    /// **CI-hard live gate: the #470 three-key ceiling-exception truth table, end-to-end on a real
    /// engine.** A site pinned to an `own` ceiling; a route may EXCEED it to `all` only when BOTH
    /// deployer keys are present at bind (site `allow_ceiling_exceptions` + route
    /// `exceed_site_ceiling`) AND the operator posture permits cross-tenant. Drives the REAL bind
    /// admission (`narrows_within_authorized`, mirroring `handler_dispatch`), the REAL resolve+clamp
    /// (`resolve_host_tenancy` + `cap`), and the REAL ORM scope against a libsql engine holding
    /// tenant A + B rows — so every corner is OBSERVED in SQL, not just asserted on a predicate.
    /// `#[ignore]`d locally (the former static-musl libsql concurrency bug, now fixed); the `test-target-plain-wasm` CI job
    /// runs it unignored on the static-musl target and greps `TENANCY OVERRIDE THREE-KEY OK`.
    #[tokio::test]
    #[ignore = "heavy libsql battery; run via the test-target-plain-wasm CI job on the static-musl target (libsql 0.10.0 fixes the former static-musl connection double-free)"]
    async fn ceiling_exception_three_key_truth_table_on_a_real_engine() {
        use boatramp_core::orm::{Expr, Select, SelectItem};
        use boatramp_core::sql::{Dialect, SqlBackends, SqlValue};
        use boatramp_handlers::TenantAxis;

        let dir = std::env::temp_dir().join(format!("boatramp-threekey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backends = boatramp_storage::LibsqlSqlBackends::local(&dir);
        let db = backends.database("default", "svc", "").await.unwrap();
        {
            let mut tx = db.begin().await.unwrap();
            tx.execute(
                "CREATE TABLE docs (id TEXT PRIMARY KEY, tenant_id TEXT, name TEXT)",
                &[],
            )
            .await
            .unwrap();
            for (id, tenant, name) in [
                ("a1", "tenant_A", "A one"),
                ("b1", "tenant_B", "B one"),
                ("b2", "tenant_B", "B two"),
            ] {
                tx.execute(
                    "INSERT INTO docs (id, tenant_id, name) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(id.into()),
                        SqlValue::Text(tenant.into()),
                        SqlValue::Text(name.into()),
                    ],
                )
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        // The route's "own" tenant resolves to B (via the routed-domain context), so an `own` scope
        // returns only B's rows and an `all` scope (posture permitting) returns every tenant's.
        let scoped = |read: AccessMode, write: AccessMode, token: bool| Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read,
            write,
            exceed_site_ceiling: token,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let ceiling = scoped(AccessMode::Own, AccessMode::Own, false); // an `own` site ceiling.
        let route_all_token = scoped(AccessMode::All, AccessMode::All, true);
        let route_all_notoken = scoped(AccessMode::All, AccessMode::All, false);
        let route_own = scoped(AccessMode::Own, AccessMode::Own, false);

        // The REAL bind admission (exactly what `handler_dispatch` checks).
        let admit = |route: &Tenancy, site_allows: bool| {
            route.narrows_within_authorized(&ceiling, site_allows)
        };

        // Resolve the route through the REAL resolver+clamp, apply the REAL ORM read scope, and
        // observe which tenants' rows come back from the engine.
        let observe = |route: &Tenancy, cross: bool| {
            let route = route.clone();
            let db = &db;
            async move {
                let inputs = TenantSourceInputs {
                    domain_context: Some("tenant_B"),
                    ..Default::default()
                };
                let ht = resolve_host_tenancy(Some(&route), true, posture(false, cross), inputs)
                    .await
                    .unwrap()
                    .unwrap();
                let mut q = Select {
                    columns: vec![SelectItem {
                        expr: Expr::col("name"),
                        alias: None,
                    }],
                    ..Select::from("docs")
                };
                // `all` (posture permitting) ⇒ no scope ⇒ unconfined ⇒ cross-tenant; else confine.
                if let Some(scope) = ht.orm_scope(TenantAxis::Read).unwrap() {
                    q.force_scope(&scope).unwrap();
                }
                let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
                let mut tx = db.begin().await.unwrap();
                let rows = run_text_rows(tx.as_mut(), &sql, &params).await;
                tx.commit().await.unwrap();
                rows
            }
        };

        // ── Corner 1: ALL THREE keys on → the route genuinely crosses tenants (the only GREEN corner).
        assert!(
            admit(&route_all_token, true),
            "corner 1: both deployer keys admit the widen at bind"
        );
        assert_eq!(
            observe(&route_all_token, true).await,
            vec![
                "A one".to_string(),
                "B one".to_string(),
                "B two".to_string()
            ],
            "corner 1: with the posture ON, the authorized `all` route reads EVERY tenant's rows"
        );

        // ── Corner 2: keys present but the operator posture is OFF → clamped to `own` at runtime.
        assert!(
            admit(&route_all_token, true),
            "corner 2: bind admission does not depend on the posture"
        );
        assert_eq!(
            observe(&route_all_token, false).await,
            vec!["B one".to_string(), "B two".to_string()],
            "corner 2: the posture (key 3) clamps `all`→`own` — the route sees ONLY its own tenant B"
        );

        // ── Corner 3: route token present, but the SITE does not permit exceptions → refused at bind.
        assert!(
            !admit(&route_all_token, false),
            "corner 3: without the site key (allow_ceiling_exceptions) the widen fails closed"
        );

        // ── Corner 4: site permits exceptions, but the route carries NO token + wants `all` → refused.
        assert!(
            !admit(&route_all_notoken, true),
            "corner 4: without the route token a bare `all` widen fails closed even on a permitting site"
        );

        // ── Corner 5: no bleed — a tokened route A does not widen a sibling route B. Route B, an
        // honest `own` narrowing, is admitted and observably stays on its own tenant EVEN WHILE the
        // sibling A is cross-tenant; and a sibling that wants `all` without its own token is refused.
        assert!(
            admit(&route_own, true),
            "corner 5: the `own` sibling is admitted (a narrowing)"
        );
        assert_eq!(
            observe(&route_own, true).await,
            vec!["B one".to_string(), "B two".to_string()],
            "corner 5: the sibling `own` route sees only tenant B — the tokened route's `all` did not bleed"
        );
        assert!(
            !admit(&route_all_notoken, true),
            "corner 5: a sibling wanting `all` needs its OWN token — A's token does not carry over"
        );

        // ── Corner 6: a tokened widen on a plain HTTP route does NOT widen the /graphql gateway. The
        // gateway is its own HandlerConfig; a gateway decision wanting `all` with no token of its own
        // is refused, regardless of a sibling route holding the token.
        let gateway_all_notoken = scoped(AccessMode::All, AccessMode::All, false);
        assert!(
            !admit(&gateway_all_notoken, true),
            "corner 6: the /graphql gateway needs its OWN exceed_site_ceiling — a sibling's does not widen it"
        );

        println!(
            "TENANCY OVERRIDE THREE-KEY OK: an `own`-ceilinged site admits a route's `all` widen ONLY \
             with BOTH deployer keys, and it crosses tenants ONLY when the operator posture also \
             permits it (else clamped to own); every missing-key corner + the sibling/gateway no-bleed \
             corners fail closed — all observed end-to-end on a real libsql engine"
        );
    }

    /// Run a compiled `(sql, params)` returning the single text column, sorted.
    async fn run_text_rows(
        tx: &mut dyn boatramp_core::sql::SqlTransaction,
        sql: &str,
        params: &[boatramp_core::sql::SqlValue],
    ) -> Vec<String> {
        let rows = tx.query(sql, params).await.expect("query runs");
        let mut out: Vec<String> = rows
            .rows
            .into_iter()
            .flatten()
            .filter_map(|v| match v {
                boatramp_core::sql::SqlValue::Text(s) => Some(s),
                _ => None,
            })
            .collect();
        out.sort();
        out
    }
}

/// The ≥2-tenant **tenancy isolation gate** for the `sealed-state` source (PLAN-sealed-state-source).
/// Drives the REAL path end to end — mint via [`boatramp_core::sealed_state::seal_state`], resolve via
/// [`resolve_host_tenancy`] over a `SealedState` source — under the REAL `LocalKek` AES-256-GCM
/// envelope (the same AEAD the per-tenant secret store uses), proving: a state minted for X resolves
/// to X; a state minted for X can NEVER be turned into a resolution of Y; a tampered / forged /
/// expired / wrong-(project,site) / unprovisioned / missing state resolves to NONE (fail-closed); and
/// that the binding + expiry checks are MUTATION-SENSITIVE (neutering either turns the gate RED).
#[cfg(test)]
mod sealed_state_gate {
    use super::{
        RequestParams, SealedStateInputs, TenantExists, TenantPosture, TenantSourceInputs,
        resolve_host_tenancy,
    };
    use crate::envelope::LocalKek;
    use boatramp_core::sealed_state::{mint_claims, seal_state};
    use boatramp_core::sql::SqlValue;
    use boatramp_core::tenancy::{
        AccessMode, OnUnresolved, ParamKind, ScopeAxis, StateParam, Tenancy, TenantSource,
    };

    const PROJECT: &str = "acme";
    const SITE: &str = "console";

    // The binding/expiry-sensitive tests are grouped `#[serial(sealed_state_env)]` so the
    // process-global `BOATRAMP_SEALEDSTATE_MUTATION` (set only by the two mutation tests) can never
    // bleed into a concurrent negative assertion.

    struct MapParams {
        state: Option<String>,
    }
    impl RequestParams for MapParams {
        fn query(&self, name: &str) -> Option<String> {
            (name == "state").then(|| self.state.clone()).flatten()
        }
        fn header(&self, _name: &str) -> Option<String> {
            None
        }
    }

    struct Provisioned(Vec<String>);
    #[async_trait::async_trait]
    impl TenantExists for Provisioned {
        async fn exists(&self, _project: &str, tenant: &str) -> bool {
            self.0.iter().any(|t| t == tenant)
        }
    }

    fn kek() -> LocalKek {
        LocalKek::from_bytes([7u8; 32])
    }

    fn decision() -> Tenancy {
        Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::SealedState {
                param: StateParam {
                    kind: ParamKind::Query,
                    name: "state".into(),
                },
            }],
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        }
    }

    /// Mint a state token for `tenant`, bound to (`project`, `site`), via the REAL AEAD seal.
    async fn mint(
        env: &LocalKek,
        tenant: &str,
        project: &str,
        site: &str,
        iat: u64,
        ttl: u64,
    ) -> String {
        let claims = mint_claims(
            project,
            site,
            tenant,
            Some("pkce".into()),
            Some("n".into()),
            ttl,
            iat,
        );
        seal_state(env, &claims).await.unwrap()
    }

    /// Resolve `token` at (`project`, `site`) with `provisioned` tenants, returning the resolved
    /// own-tenant value (the `ScopeAxis::Tenant` fact), or `None` when nothing resolved (fail-closed).
    async fn resolve(
        env: &LocalKek,
        token: Option<&str>,
        project: &str,
        site: &str,
        provisioned: &[&str],
    ) -> Option<String> {
        let params = MapParams {
            state: token.map(str::to_owned),
        };
        let registry = Provisioned(provisioned.iter().copied().map(String::from).collect());
        let inputs = TenantSourceInputs {
            sealed_state: Some(SealedStateInputs {
                params: &params,
                env,
                project,
                site,
                registry: &registry,
            }),
            ..Default::default()
        };
        let posture = TenantPosture {
            require_declaration: true,
            allow_cross_tenant: false,
        };
        let ht = resolve_host_tenancy(Some(&decision()), true, posture, inputs)
            .await
            .unwrap()
            .unwrap();
        ht.facts()
            .iter()
            .find(|f| f.axis == ScopeAxis::Tenant)
            .map(|f| match &f.value {
                SqlValue::Text(s) => s.clone(),
                other => panic!("tenant fact must be text, got {other:?}"),
            })
    }

    #[tokio::test]
    async fn a_state_minted_for_x_resolves_to_x_and_for_y_to_y() {
        let env = kek();
        let now = boatramp_core::time::now_unix();
        let x = mint(&env, "firm-x", PROJECT, SITE, now, 300).await;
        let y = mint(&env, "firm-y", PROJECT, SITE, now, 300).await;
        assert_eq!(
            resolve(&env, Some(&x), PROJECT, SITE, &["firm-x", "firm-y"]).await,
            Some("firm-x".to_string()),
            "X's sealed state resolves X"
        );
        assert_eq!(
            resolve(&env, Some(&y), PROJECT, SITE, &["firm-x", "firm-y"]).await,
            Some("firm-y".to_string()),
            "Y's sealed state resolves Y (distinct) — the tenant rides the seal, not request text"
        );
    }

    #[serial_test::serial(sealed_state_env)]
    #[tokio::test]
    async fn x_state_at_another_site_or_project_resolves_to_none() {
        // THE cross-tenant/cross-surface isolation: a seal minted for site X can NEVER resolve at a
        // different (project, site) — so one firm's login can't be replayed into another site's
        // tenancy, even though the KEK is node-wide. Serialized (binding-sensitive).
        let env = kek();
        let now = boatramp_core::time::now_unix();
        let x = mint(&env, "firm-x", PROJECT, SITE, now, 300).await;
        assert_eq!(
            resolve(&env, Some(&x), PROJECT, "other-site", &["firm-x"]).await,
            None,
            "a seal bound to site `console` must not resolve at site `other-site`"
        );
        assert_eq!(
            resolve(&env, Some(&x), "other-proj", SITE, &["firm-x"]).await,
            None,
            "a seal bound to project `acme` must not resolve at project `other-proj`"
        );
    }

    #[tokio::test]
    async fn a_tampered_or_forged_or_missing_state_resolves_to_none() {
        let env = kek();
        let now = boatramp_core::time::now_unix();
        let x = mint(&env, "firm-x", PROJECT, SITE, now, 300).await;

        // Tampered: flip a byte in the middle of the token.
        let mut b = x.clone().into_bytes();
        let mid = b.len() / 2;
        b[mid] = if b[mid] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(b).unwrap();
        assert_eq!(
            resolve(&env, Some(&tampered), PROJECT, SITE, &["firm-x"]).await,
            None,
            "a tampered state fails the AEAD tag → no tenant"
        );

        // Forged: minted under a DIFFERENT (attacker) key, resolved under the host key.
        let attacker = LocalKek::from_bytes([9u8; 32]);
        let forged = mint(&attacker, "firm-x", PROJECT, SITE, now, 300).await;
        assert_eq!(
            resolve(&env, Some(&forged), PROJECT, SITE, &["firm-x"]).await,
            None,
            "a state sealed under a foreign key does not open under the host key → no tenant"
        );

        // Missing: no `state` param on the request at all.
        assert_eq!(
            resolve(&env, None, PROJECT, SITE, &["firm-x"]).await,
            None,
            "no state param → no tenant (never a fallback/default/first tenant)"
        );

        // Garbage that is not even base64url for the token.
        assert_eq!(
            resolve(
                &env,
                Some("!!! not-a-token !!!"),
                PROJECT,
                SITE,
                &["firm-x"]
            )
            .await,
            None,
            "an unparseable state → no tenant"
        );
    }

    #[tokio::test]
    async fn an_unprovisioned_tenant_resolves_to_none() {
        // The seal is authentic, but the tenant is not a REAL tenant in the project (registry says
        // no) → fail closed (defense in depth over the seal's authenticity).
        let env = kek();
        let now = boatramp_core::time::now_unix();
        let x = mint(&env, "firm-x", PROJECT, SITE, now, 300).await;
        assert_eq!(
            resolve(&env, Some(&x), PROJECT, SITE, &["firm-y"]).await,
            None,
            "a validly-sealed but unprovisioned tenant must not resolve"
        );
        // And with the empty registry nothing resolves either.
        assert_eq!(resolve(&env, Some(&x), PROJECT, SITE, &[]).await, None);
    }

    #[serial_test::serial(sealed_state_env)]
    #[tokio::test]
    async fn an_expired_state_resolves_to_none() {
        let env = kek();
        // iat 1000s ago, ttl 300 ⇒ expired 700s ago.
        let now = boatramp_core::time::now_unix();
        let x = mint(&env, "firm-x", PROJECT, SITE, now - 1000, 300).await;
        assert_eq!(
            resolve(&env, Some(&x), PROJECT, SITE, &["firm-x"]).await,
            None,
            "an expired state must not resolve"
        );
    }

    // ---- mutation-sensitivity: neutering a fail-closed check turns the gate RED ----
    // Gated behind `sealed-state-gate-mutation` (which enables `boatramp-core/sealed-state-gate-
    // mutation`), because the core seam `sealed_state::mutation_skips` is active only under core's own
    // `cfg(test)` OR that feature — and core compiles as a plain DEPENDENCY here (no `cfg(test)`). A
    // dedicated CI lane runs `cargo test -p boatramp-server --features sealed-state-gate-mutation` to
    // drive these, exactly like the `boatramp-storage` tenancy gate lanes. The core unit tests in
    // `sealed_state.rs` prove the SAME two seams under core's native `cfg(test)`.

    #[cfg(feature = "sealed-state-gate-mutation")]
    #[serial_test::serial(sealed_state_env)]
    #[tokio::test]
    async fn mutation_skip_binding_opens_a_cross_site_resolution() {
        let env = kek();
        let now = boatramp_core::time::now_unix();
        let x = mint(&env, "firm-x", PROJECT, SITE, now, 300).await;
        // Baseline: cross-site is None.
        assert_eq!(
            resolve(&env, Some(&x), PROJECT, "other-site", &["firm-x"]).await,
            None
        );
        // Armed: neuter the per-(project,site) binding → the cross-site seal now resolves (RED).
        // SAFETY: test-only env var; serialized by the `sealed_state_env` group; cleared below.
        unsafe { std::env::set_var("BOATRAMP_SEALEDSTATE_MUTATION", "skip_binding") };
        let leaked = resolve(&env, Some(&x), PROJECT, "other-site", &["firm-x"]).await;
        // SAFETY: test-only env var; serialized by the group.
        unsafe { std::env::remove_var("BOATRAMP_SEALEDSTATE_MUTATION") };
        assert_eq!(
            leaked,
            Some("firm-x".to_string()),
            "neutering the binding check must let a cross-site seal resolve — the gate is live"
        );
    }

    #[cfg(feature = "sealed-state-gate-mutation")]
    #[serial_test::serial(sealed_state_env)]
    #[tokio::test]
    async fn mutation_skip_exp_opens_an_expired_resolution() {
        let env = kek();
        let now = boatramp_core::time::now_unix();
        let x = mint(&env, "firm-x", PROJECT, SITE, now - 1000, 300).await;
        assert_eq!(
            resolve(&env, Some(&x), PROJECT, SITE, &["firm-x"]).await,
            None
        );
        // SAFETY: test-only env var; serialized by the `sealed_state_env` group; cleared below.
        unsafe { std::env::set_var("BOATRAMP_SEALEDSTATE_MUTATION", "skip_exp") };
        let stale = resolve(&env, Some(&x), PROJECT, SITE, &["firm-x"]).await;
        // SAFETY: test-only env var; serialized by the group.
        unsafe { std::env::remove_var("BOATRAMP_SEALEDSTATE_MUTATION") };
        assert_eq!(
            stale,
            Some("firm-x".to_string()),
            "neutering the expiry check must let an expired seal resolve — the gate is live"
        );
    }
}

/// Unit tests for the construens #2 **`pre_auth_request`** source (the pre-auth SSO login-start firm
/// selection): each extraction location (host/query/path/body), the fail-closed cases (unknown /
/// missing / malformed / wildcard / unconfigured firm, body size-cap / malformed / unaccepted
/// content-type), the sole-source backstop, and the **seal-only confinement** (the resolved firm is
/// NEVER a data `Tenant` fact — no RLS / `tenant-secrets` access at `/start`).
#[cfg(test)]
mod preauth_source {
    use super::{
        PreAuthBody, PreAuthInputs, RequestParams, TenantExists, TenantPosture, TenantSourceInputs,
        resolve_host_tenancy,
    };
    use boatramp_core::sql::SqlValue;
    use boatramp_core::tenancy::{
        AccessMode, OnUnresolved, PreAuthLocation, PreAuthSelector, ScopeAxis, Tenancy,
        TenantSource,
    };
    use boatramp_handlers::TenantAxis as Axis;

    /// A request param/path surface for the query/path locations.
    #[derive(Default)]
    struct Req {
        query: Vec<(String, String)>,
        path: Option<String>,
    }
    impl RequestParams for Req {
        fn query(&self, name: &str) -> Option<String> {
            self.query
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
        fn header(&self, _name: &str) -> Option<String> {
            None
        }
        fn path(&self) -> Option<String> {
            self.path.clone()
        }
    }

    /// The configured-firm registry (a firm is configured iff listed).
    struct Configured(Vec<String>);
    #[async_trait::async_trait]
    impl TenantExists for Configured {
        async fn exists(&self, _project: &str, tenant: &str) -> bool {
            self.0.iter().any(|t| t == tenant)
        }
    }

    fn selector(location: PreAuthLocation, name: &str) -> PreAuthSelector {
        PreAuthSelector {
            location,
            name: name.into(),
            content_types: Vec::new(),
            max_body_bytes: None,
        }
    }

    fn decision(sources: Vec<TenantSource>) -> Tenancy {
        Tenancy::Scoped {
            column: "tenant_id".into(),
            sources,
            // Even an `own` grant yields NO data access on a pre-auth resolution (forced to `None`).
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        }
    }

    fn posture() -> TenantPosture {
        TenantPosture {
            require_declaration: true,
            allow_cross_tenant: false,
        }
    }

    /// Resolve a `pre_auth_request` decision and return the resolved `HostTenancy`.
    async fn resolve(
        selector: PreAuthSelector,
        req: &Req,
        body: Option<&PreAuthBody>,
        domain_context: Option<&str>,
        configured: &[&str],
    ) -> boatramp_handlers::HostTenancy {
        let registry = Configured(configured.iter().copied().map(String::from).collect());
        let inputs = TenantSourceInputs {
            preauth: Some(PreAuthInputs {
                params: req,
                body,
                domain_context,
                project: "acme",
                registry: &registry,
            }),
            ..Default::default()
        };
        resolve_host_tenancy(
            Some(&decision(vec![TenantSource::PreAuthRequest { selector }])),
            true,
            posture(),
            inputs,
        )
        .await
        .unwrap()
        .unwrap()
    }

    /// The load-bearing SEAL-ONLY assertion: the firm is the seal-only subject, NOT a data `Tenant`
    /// fact — every scoped read/write is denied (no RLS access) and there is no own-tenant value for a
    /// `tenant-secrets`/blob binding to key on.
    fn assert_seal_only(ht: &boatramp_handlers::HostTenancy, firm: &str) {
        assert_eq!(
            ht.preauth_seal_subject(),
            Some(firm),
            "the firm is carried as the seal-only subject (the only consumer is sealed-state:mint)"
        );
        assert!(
            !ht.facts().iter().any(|f| f.axis == ScopeAxis::Tenant),
            "a pre-auth firm must NOT be a data Tenant fact (no RLS data access at /start)"
        );
        assert_eq!(
            ht.value(),
            None,
            "no own-tenant value — a tenant-secrets/blob binding keys on None => no-resolved-tenant"
        );
        assert!(
            ht.orm_scope(Axis::Read).is_err(),
            "every scoped READ is denied at /start (no data access)"
        );
        assert!(
            ht.orm_scope(Axis::Write).is_err(),
            "every scoped WRITE is denied at /start (no data access)"
        );
    }

    #[tokio::test]
    async fn query_location_resolves_a_configured_firm_seal_only() {
        let req = Req {
            query: vec![("tenant".into(), "ten_x".into())],
            ..Default::default()
        };
        let ht = resolve(
            selector(PreAuthLocation::Query, "tenant"),
            &req,
            None,
            None,
            &["ten_x"],
        )
        .await;
        assert_seal_only(&ht, "ten_x");
    }

    /// Multi-firm POSITIVE-DISCRIMINATION gate (the standing "tenancy gate needs a multi-tenant
    /// fixture" rule). With TWO configured firms, `/sso/start?tenant=<firm>` must resolve the seal-only
    /// subject to EXACTLY the requested firm and never the OTHER configured firm — a single-firm
    /// fixture is blind to a lookup that returns the first/any configured firm instead of echoing the
    /// request-selected one. Guards against a future "lookup-returns-value" refactor.
    #[tokio::test]
    async fn two_configured_firms_resolve_exactly_the_requested_one() {
        // firm-x requested; BOTH firm-x and firm-y configured => the seal subject is EXACTLY firm-x.
        let req_x = Req {
            query: vec![("tenant".into(), "firm-x".into())],
            ..Default::default()
        };
        let ht_x = resolve(
            selector(PreAuthLocation::Query, "tenant"),
            &req_x,
            None,
            None,
            &["firm-x", "firm-y"],
        )
        .await;
        assert_eq!(
            ht_x.preauth_seal_subject(),
            Some("firm-x"),
            "the requested firm-x is the resolved seal subject"
        );
        assert_ne!(
            ht_x.preauth_seal_subject(),
            Some("firm-y"),
            "and NEVER the other configured firm (firm-y)"
        );

        // firm-y requested; the SAME two firms configured => the seal subject is EXACTLY firm-y.
        let req_y = Req {
            query: vec![("tenant".into(), "firm-y".into())],
            ..Default::default()
        };
        let ht_y = resolve(
            selector(PreAuthLocation::Query, "tenant"),
            &req_y,
            None,
            None,
            &["firm-x", "firm-y"],
        )
        .await;
        assert_eq!(
            ht_y.preauth_seal_subject(),
            Some("firm-y"),
            "the requested firm-y is the resolved seal subject"
        );
        assert_ne!(
            ht_y.preauth_seal_subject(),
            Some("firm-x"),
            "and NEVER the other configured firm (firm-x)"
        );
    }

    #[tokio::test]
    async fn host_location_reuses_the_routed_host_context() {
        let req = Req::default();
        let ht = resolve(
            selector(PreAuthLocation::Host, "ignored"),
            &req,
            None,
            Some("ten_host"),
            &["ten_host"],
        )
        .await;
        assert_seal_only(&ht, "ten_host");
    }

    #[tokio::test]
    async fn path_location_extracts_the_segment_after_the_label() {
        let req = Req {
            path: Some("/sso/start/ten_path/extra".into()),
            ..Default::default()
        };
        let ht = resolve(
            selector(PreAuthLocation::Path, "start"),
            &req,
            None,
            None,
            &["ten_path"],
        )
        .await;
        assert_seal_only(&ht, "ten_path");
    }

    #[tokio::test]
    async fn body_location_form_urlencoded_and_json() {
        // form-urlencoded
        let body = PreAuthBody {
            content_type: Some("application/x-www-form-urlencoded".into()),
            bytes: b"account=ten_body&password=secret".to_vec(),
        };
        let ht = resolve(
            selector(PreAuthLocation::Body, "account"),
            &Req::default(),
            Some(&body),
            None,
            &["ten_body"],
        )
        .await;
        assert_seal_only(&ht, "ten_body");

        // JSON
        let body = PreAuthBody {
            content_type: Some("application/json".into()),
            bytes: br#"{"account":"ten_json","password":"secret"}"#.to_vec(),
        };
        let ht = resolve(
            selector(PreAuthLocation::Body, "account"),
            &Req::default(),
            Some(&body),
            None,
            &["ten_json"],
        )
        .await;
        assert_seal_only(&ht, "ten_json");
    }

    /// Every fail-closed case resolves NO principal (uniform outcome) — the `HostTenancy` carries no
    /// Tenant fact AND no seal-only subject, so the mint later fails `no-resolved-tenant`.
    async fn resolves_nothing(
        selector: PreAuthSelector,
        req: &Req,
        body: Option<&PreAuthBody>,
        domain_context: Option<&str>,
        configured: &[&str],
    ) {
        let ht = resolve(selector, req, body, domain_context, configured).await;
        assert_eq!(
            ht.preauth_seal_subject(),
            None,
            "a failed pre-auth resolution carries NO seal subject (the mint fails closed)"
        );
        assert!(
            !ht.facts().iter().any(|f| f.axis == ScopeAxis::Tenant),
            "and never a data Tenant fact"
        );
    }

    #[tokio::test]
    async fn fail_closed_unknown_missing_malformed_wildcard_unconfigured() {
        // Unknown / unconfigured firm (registry says no).
        let req = Req {
            query: vec![("tenant".into(), "ten_x".into())],
            ..Default::default()
        };
        resolves_nothing(
            selector(PreAuthLocation::Query, "tenant"),
            &req,
            None,
            None,
            &["ten_y"],
        )
        .await;

        // Missing selector (param absent).
        resolves_nothing(
            selector(PreAuthLocation::Query, "tenant"),
            &Req::default(),
            None,
            None,
            &["ten_x"],
        )
        .await;

        // Wildcard — even if a firm literally named "*" were provisioned, the key-safety screen
        // rejects `*` BEFORE the registry call (no wildcard fan-out).
        let req = Req {
            query: vec![("tenant".into(), "*".into())],
            ..Default::default()
        };
        resolves_nothing(
            selector(PreAuthLocation::Query, "tenant"),
            &req,
            None,
            None,
            &["*"],
        )
        .await;

        // Malformed (path traversal) — rejected by the key-safety screen.
        let req = Req {
            query: vec![("tenant".into(), "../etc".into())],
            ..Default::default()
        };
        resolves_nothing(
            selector(PreAuthLocation::Query, "tenant"),
            &req,
            None,
            None,
            &["../etc"],
        )
        .await;

        // host location with no routed host context => nothing.
        resolves_nothing(
            selector(PreAuthLocation::Host, "x"),
            &Req::default(),
            None,
            None,
            &["ten_x"],
        )
        .await;
    }

    #[tokio::test]
    async fn body_fail_closed_cases() {
        let sel = selector(PreAuthLocation::Body, "account");

        // Over the size cap => fail closed.
        let mut sel_capped = sel.clone();
        sel_capped.max_body_bytes = Some(8);
        let body = PreAuthBody {
            content_type: Some("application/json".into()),
            bytes: br#"{"account":"ten_body"}"#.to_vec(),
        };
        resolves_nothing(
            sel_capped,
            &Req::default(),
            Some(&body),
            None,
            &["ten_body"],
        )
        .await;

        // Malformed JSON => fail closed.
        let body = PreAuthBody {
            content_type: Some("application/json".into()),
            bytes: b"{not json".to_vec(),
        };
        resolves_nothing(
            sel.clone(),
            &Req::default(),
            Some(&body),
            None,
            &["ten_body"],
        )
        .await;

        // Unaccepted content-type (never guess a parser) => fail closed.
        let body = PreAuthBody {
            content_type: Some("text/plain".into()),
            bytes: b"account=ten_body".to_vec(),
        };
        resolves_nothing(
            sel.clone(),
            &Req::default(),
            Some(&body),
            None,
            &["ten_body"],
        )
        .await;

        // A non-string JSON field (a number) is rejected (a firm selector is always a string).
        let body = PreAuthBody {
            content_type: Some("application/json".into()),
            bytes: br#"{"account":12345}"#.to_vec(),
        };
        resolves_nothing(sel.clone(), &Req::default(), Some(&body), None, &["12345"]).await;

        // No body buffered at all (the route declared a body source but the serving path passed None,
        // e.g. an over-cap read reconstructed an empty body) => fail closed.
        resolves_nothing(sel, &Req::default(), None, None, &["ten_body"]).await;
    }

    /// The sole-source backstop: a `pre_auth_request` mixed with ANY other tenant-producing source
    /// resolves NO principal (fail closed) — covering a control-plane deploy that bypassed the
    /// apply-time `validate_sources` check.
    #[tokio::test]
    async fn preauth_mixed_with_another_source_fails_closed() {
        let registry = Configured(vec!["ten_x".into()]);
        let req = Req {
            query: vec![("tenant".into(), "ten_x".into())],
            ..Default::default()
        };
        let inputs = TenantSourceInputs {
            preauth: Some(PreAuthInputs {
                params: &req,
                body: None,
                domain_context: Some("ten_x"),
                project: "acme",
                registry: &registry,
            }),
            domain_context: Some("ten_x"),
            ..Default::default()
        };
        let ht = resolve_host_tenancy(
            Some(&decision(vec![
                TenantSource::PreAuthRequest {
                    selector: selector(PreAuthLocation::Query, "tenant"),
                },
                TenantSource::Domain,
            ])),
            true,
            posture(),
            inputs,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            ht.preauth_seal_subject(),
            None,
            "a mixed pre_auth_request route resolves no seal subject (sole-source backstop)"
        );
        assert_eq!(
            ht.value(),
            None,
            "and never silently resolves the mixed Domain source as a data tenant"
        );
        // Belt: the domain source would otherwise have resolved `ten_x` as a Tenant fact.
        assert!(
            !ht.facts()
                .iter()
                .any(|f| f.value == SqlValue::Text("ten_x".into())),
            "the mix resolves NO principal at all (fail closed)"
        );
    }
}

/// The construens #2 **`pre_auth_request` e2e tenancy gate** — the real-path, reproduces-the-failing-
/// shape gate (non-negotiable per our lessons). Drives the FULL construens RP flow through the REAL
/// Stage-0 [`resolve_host_tenancy`]:
///
/// 1. **WIRED arm**: `/sso/start?tenant=firm-x` with `sources: [pre_auth_request(query,"tenant")]` =>
///    the firm becomes the HOST-RESOLVED *seal-only* subject (NO data `Tenant` fact) => the existing
///    mint (`boatramp_core::sealed_state::seal_state`, driven with the SAME `resolved_tenant` the
///    `build_bindings` mint call site derives) seals it => `/sso/callback?state=<token>` with
///    `sources: [sealed_state(query,"state")]` UNSEALS and recovers `firm-x`.
/// 2. **INERT arm** (reproduces today's failure): an UNSCOPED `/sso/start` (no `pre_auth_request`
///    source) resolves NO tenant and NO seal subject => the mint's `resolved_tenant` is `None` => the
///    mint FAILS CLOSED (`no-resolved-tenant`) => no sealed firm => the callback recovers nothing.
///
/// Neutering the START-side resolution (removing the seal subject) turns the WIRED arm into the INERT
/// shape — proving the new source is what makes the firm host-resolved.
#[cfg(test)]
mod preauth_gate {
    use super::{
        PreAuthInputs, RequestParams, SealedStateInputs, TenantExists, TenantPosture,
        TenantSourceInputs, resolve_host_tenancy,
    };
    use crate::envelope::LocalKek;
    use boatramp_core::sealed_state::{mint_claims, seal_state};
    use boatramp_core::sql::SqlValue;
    use boatramp_core::tenancy::{
        AccessMode, OnUnresolved, ParamKind, PreAuthLocation, PreAuthSelector, ScopeAxis,
        StateParam, Tenancy, TenantSource,
    };
    use boatramp_handlers::HostTenancy;

    const PROJECT: &str = "acme";
    const SITE: &str = "console";

    struct Req {
        query: Vec<(String, String)>,
    }
    impl RequestParams for Req {
        fn query(&self, name: &str) -> Option<String> {
            self.query
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
        fn header(&self, _name: &str) -> Option<String> {
            None
        }
    }

    struct Configured(Vec<String>);
    #[async_trait::async_trait]
    impl TenantExists for Configured {
        async fn exists(&self, _project: &str, tenant: &str) -> bool {
            self.0.iter().any(|t| t == tenant)
        }
    }

    fn kek() -> LocalKek {
        LocalKek::from_bytes([42u8; 32])
    }

    fn posture() -> TenantPosture {
        TenantPosture {
            require_declaration: true,
            allow_cross_tenant: false,
        }
    }

    fn start_decision(sources: Vec<TenantSource>) -> Tenancy {
        Tenancy::Scoped {
            column: "tenant_id".into(),
            sources,
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        }
    }

    /// The EXACT value the `build_bindings` mint call site derives for the sealed-state mint's
    /// `resolved_tenant`: the own-`Tenant` fact (if any), else the seal-only pre-auth subject. `None`
    /// => the mint fails closed (`no-resolved-tenant`), exactly as `SealedStateMintBinding::mint` does.
    fn mint_tenant(ht: &HostTenancy) -> Option<String> {
        ht.facts()
            .iter()
            .find(|f| f.axis == ScopeAxis::Tenant)
            .and_then(|f| match &f.value {
                SqlValue::Text(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            })
            .or_else(|| ht.preauth_seal_subject().map(str::to_owned))
    }

    /// The START leg: resolve `/sso/start` through the REAL Stage-0 resolver and return the resolved
    /// `HostTenancy` (whose seal-only subject the mint consumes).
    async fn resolve_start(start: &Tenancy, req: &Req, configured: &[&str]) -> HostTenancy {
        let registry = Configured(configured.iter().copied().map(String::from).collect());
        let inputs = TenantSourceInputs {
            preauth: Some(PreAuthInputs {
                params: req,
                body: None,
                domain_context: None,
                project: PROJECT,
                registry: &registry,
            }),
            ..Default::default()
        };
        resolve_host_tenancy(Some(start), true, posture(), inputs)
            .await
            .unwrap()
            .unwrap()
    }

    /// The CALLBACK leg: resolve `/sso/callback?state=<token>` through the REAL Stage-0 resolver over
    /// a `sealed_state` source and return the recovered own-tenant (or `None`, fail-closed).
    async fn resolve_callback(env: &LocalKek, token: Option<&str>) -> Option<String> {
        struct State(Option<String>);
        impl RequestParams for State {
            fn query(&self, name: &str) -> Option<String> {
                (name == "state").then(|| self.0.clone()).flatten()
            }
            fn header(&self, _n: &str) -> Option<String> {
                None
            }
        }
        let params = State(token.map(str::to_owned));
        let registry = Configured(vec!["firm-x".into()]);
        let inputs = TenantSourceInputs {
            sealed_state: Some(SealedStateInputs {
                params: &params,
                env,
                project: PROJECT,
                site: SITE,
                registry: &registry,
            }),
            ..Default::default()
        };
        let callback = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::SealedState {
                param: StateParam {
                    kind: ParamKind::Query,
                    name: "state".into(),
                },
            }],
            read: AccessMode::Own,
            write: AccessMode::Own,
            exceed_site_ceiling: false,
            unscoped_writes: Vec::new(),
            on_unresolved: OnUnresolved::Deny,
        };
        let ht = resolve_host_tenancy(Some(&callback), true, posture(), inputs)
            .await
            .unwrap()
            .unwrap();
        ht.facts()
            .iter()
            .find(|f| f.axis == ScopeAxis::Tenant)
            .map(|f| match &f.value {
                SqlValue::Text(s) => s.clone(),
                other => panic!("tenant fact must be text, got {other:?}"),
            })
    }

    async fn seal_firm(env: &LocalKek, firm: &str) -> String {
        let now = boatramp_core::time::now_unix();
        let claims = mint_claims(
            PROJECT,
            SITE,
            firm,
            Some("pkce".into()),
            Some("n".into()),
            300,
            now,
        );
        seal_state(env, &claims).await.unwrap()
    }

    #[tokio::test]
    async fn preauth_start_to_callback_roundtrips_and_an_unscoped_start_fails_closed() {
        let env = kek();

        // ---- INERT arm (today's failing shape): an UNSCOPED /sso/start resolves no tenant. ----
        // A plain login-start declaring NO pre_auth_request source (a bare `[None]` source list):
        // nothing resolves, so there is NO own tenant and NO seal subject => the mint's resolved_tenant
        // is None => the mint FAILS CLOSED (no token is produced) => the callback recovers nothing.
        let inert = resolve_start(
            &start_decision(vec![TenantSource::None]),
            &Req {
                query: vec![("tenant".into(), "firm-x".into())],
            },
            &["firm-x"],
        )
        .await;
        assert_eq!(
            mint_tenant(&inert),
            None,
            "an unscoped start resolves NO tenant -> the mint fails closed (no sealed firm)"
        );
        // With no token minted, the callback has nothing to unseal.
        assert_eq!(
            resolve_callback(&env, None).await,
            None,
            "no sealed firm -> the callback recovers nothing (today's failing shape)"
        );

        // ---- WIRED arm: /sso/start?tenant=firm-x with the pre_auth_request source. ----
        let start = resolve_start(
            &start_decision(vec![TenantSource::PreAuthRequest {
                selector: PreAuthSelector {
                    location: PreAuthLocation::Query,
                    name: "tenant".into(),
                    content_types: Vec::new(),
                    max_body_bytes: None,
                },
            }]),
            &Req {
                query: vec![("tenant".into(), "firm-x".into())],
            },
            &["firm-x"],
        )
        .await;
        // SEAL-ONLY confinement: the firm is the seal subject, NOT a data Tenant fact => NO data access
        // at /start (every scoped op denied, and no own-tenant value for tenant-secrets/blob to key on).
        assert_eq!(start.preauth_seal_subject(), Some("firm-x"));
        assert!(
            !start.facts().iter().any(|f| f.axis == ScopeAxis::Tenant),
            "SEAL-ONLY: the pre-auth firm is never a data tenant fact (no RLS at /start)"
        );
        assert!(
            start
                .orm_scope(boatramp_handlers::TenantAxis::Read)
                .is_err()
                && start
                    .orm_scope(boatramp_handlers::TenantAxis::Write)
                    .is_err(),
            "SEAL-ONLY: every scoped read/write is denied at /start (no tenant-secrets / RLS access)"
        );
        // The firm is now HOST-RESOLVED, so the existing mint seals it.
        let firm = mint_tenant(&start).expect("the pre-auth firm is the mint's resolved tenant");
        assert_eq!(firm, "firm-x");
        let token = seal_firm(&env, &firm).await;
        // The callback UNSEALS and recovers the firm as a real (data) tenant.
        assert_eq!(
            resolve_callback(&env, Some(&token)).await,
            Some("firm-x".to_string()),
            "WIRED: the sealed firm is recovered at /sso/callback"
        );

        // A seal minted for firm-x can never be turned into a resolution of firm-y (the sealed-state
        // isolation still holds end to end): a tampered token recovers nothing.
        let mut b = token.into_bytes();
        let mid = b.len() / 2;
        b[mid] = if b[mid] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(b).unwrap();
        assert_eq!(
            resolve_callback(&env, Some(&tampered)).await,
            None,
            "a tampered sealed state recovers nothing (fail closed)"
        );

        // The anti-silent-skip marker — printed ONLY after BOTH the INERT (fails closed) and WIRED
        // (seal-only start -> mint -> callback recovers firm) arms pass. The CI gate greps this.
        println!(
            "PRE-AUTH TENANT SOURCE OK: unscoped start fails closed; wired start resolves firm-x \
             SEAL-ONLY (no data tenant), mint seals it, /callback recovers firm-x"
        );
    }
}
