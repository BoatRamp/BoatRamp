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
use boatramp_core::tenancy::{AccessMode, Tenancy, TenantSource};
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
            "tenancy: this function imports sql/orm but declares no tenancy decision; the \
             multi-tenant posture requires an explicit `tenancy` (disabled or scoped)",
        )
    }
}
impl std::error::Error for TenancyUndeclared {}

/// Resolve the effective [`Tenancy`] `decision` into a [`HostTenancy`] (or `None` = plain
/// queries). `imports_db` is whether the guest imports `sql`/`orm` at all (only then does the
/// Dimension-0 requirement bite). Async because the token source verifies a JWT.
pub(crate) async fn resolve_host_tenancy(
    decision: Option<&Tenancy>,
    imports_db: bool,
    posture: TenantPosture,
    inputs: TenantSourceInputs<'_>,
) -> Result<Option<HostTenancy>, TenancyUndeclared> {
    match decision {
        // Undeclared: refuse a db-importing guest under the strict posture; otherwise run plain.
        None => {
            if imports_db && posture.require_declaration {
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
        }) => {
            // The own-tenant fact (from the trigger's first applicable source) + the anonymous
            // session fact (R3, from a verified cookie) — each axis resolved independently, tagged,
            // and carried as the principal's fact set. Either may be absent (a purely anonymous
            // request has only a session fact; a plain token request has only a tenant fact).
            let mut facts = Vec::new();
            if let Some(value) = resolve_from_sources(sources, &inputs).await {
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
            Ok(Some(HostTenancy::from_facts(
                column.clone(),
                facts,
                read,
                write,
            )))
        }
        // R4/D8: a `target` route is bound by the serving path ([`build_bindings`] in
        // handler_dispatch), which has the routed domain + the project schema to resolve `B` and
        // build the confined target scope (`HostTenancy::target`). This OWN-axis resolver never
        // produces a target scope, so reaching here for a `Target` decision means the serving path
        // did not bind it for this trigger — fail closed (refuse) rather than run own/unscoped.
        Some(Tenancy::Target { .. }) => Err(TenancyUndeclared),
    }
}

/// Resolve tenancy for an **in-project invoke** (a function/handler calling a sibling): the tenant
/// **value** is inherited from the caller (host-carried, not from the guest's invoke request), and
/// the callee applies its OWN declared column + modes. Same Dimension-0 refusal + posture cap as
/// [`resolve_host_tenancy`]; the only difference is the value comes from the caller, not a source.
pub(crate) fn resolve_inherited_tenancy(
    decision: Option<&Tenancy>,
    imports_db: bool,
    posture: TenantPosture,
    inherited: Vec<boatramp_handlers::ScopeFact>,
) -> Result<Option<HostTenancy>, TenancyUndeclared> {
    match decision {
        None => {
            if imports_db && posture.require_declaration {
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
            ..
        }) => {
            let read = cap(*read, posture.allow_cross_tenant);
            let write = normalize_write(cap(*write, posture.allow_cross_tenant));
            // The callee applies its OWN column + posture-capped modes to the caller's inherited
            // **principal** (axis-tagged facts), so an inherited `TargetTenant`/`Session` fact keeps
            // its axis rather than collapsing into an `own` `Tenant` value.
            Ok(Some(HostTenancy::from_facts(
                column.clone(),
                inherited,
                read,
                write,
            )))
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
async fn resolve_from_sources(
    sources: &[TenantSource],
    inputs: &TenantSourceInputs<'_>,
) -> Option<boatramp_core::sql::SqlValue> {
    for source in sources {
        if let Some(value) = resolve_value(source, inputs).await {
            return Some(value);
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

/// Resolve the tenant value from a single verified source. `None` for anonymous / not-yet-wired
/// sources — the caller ([`resolve_from_sources`]) then tries the next, else fails closed.
async fn resolve_value(
    source: &TenantSource,
    inputs: &TenantSourceInputs<'_>,
) -> Option<boatramp_core::sql::SqlValue> {
    match source {
        TenantSource::Token { claim } => {
            // The verifier lives behind `oidc` (it pulls `jsonwebtoken`). Without that feature the
            // token source can't verify, so it sources no value (fail-closed) — mirroring the GDC.
            #[cfg(feature = "oidc")]
            {
                let (cfg, bearer) = (inputs.token_cfg?, inputs.bearer?);
                let claims = crate::graphql_data::token::verified_claims(cfg, bearer).await?;
                claims.get(claim).and_then(scalar_to_sql)
            }
            #[cfg(not(feature = "oidc"))]
            {
                // Without `oidc` the token source can't verify — reference the token-only fields so
                // they aren't flagged dead in a handlers-without-oidc build (the domain/none
                // sources don't use them).
                let _ = (
                    claim,
                    inputs.bearer,
                    inputs.token_cfg,
                    inputs.domain_context,
                );
                None
            }
        }
        TenantSource::Domain => inputs
            .domain_context
            .filter(|c| !c.is_empty())
            .map(|c| boatramp_core::sql::SqlValue::Text(c.to_string())),
        // The async lane's durable signed-context (R1): verify the host-minted envelope carried on
        // the drained message against the fleet anchor and return the producer's stamped tenant. A
        // forged/altered/expired envelope (or no envelope / no anchor) resolves no value — the
        // consumer's "own" op then fails closed rather than running unscoped. The guest never names
        // the tenant; only a host signature over the producer's principal verifies here.
        TenantSource::SignedContext => {
            let (env, anchor) = (inputs.signed_context?, inputs.context_anchor?);
            let tenant =
                boatramp_core::cose::verify_context(env, anchor, boatramp_core::time::now_unix())
                    .ok()?;
            Some(boatramp_core::sql::SqlValue::Text(tenant))
        }
        // Truly anonymous — no "own" tenant.
        TenantSource::None => None,
    }
}

/// Convert a verified JSON claim scalar into a bound SQL value. Non-scalars (arrays/objects/null)
/// are rejected — a tenant id is always a scalar. Only reached from the `oidc` token branch.
#[cfg(feature = "oidc")]
fn scalar_to_sql(v: &serde_json::Value) -> Option<boatramp_core::sql::SqlValue> {
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

    fn posture(require: bool, cross: bool) -> TenantPosture {
        TenantPosture {
            require_declaration: require,
            allow_cross_tenant: cross,
        }
    }

    /// A valid host-issued session cookie resolves the `Session` axis fact (R3), carried alongside a
    /// tenant fact in the principal; a forged/absent cookie resolves none.
    #[tokio::test]
    async fn a_valid_session_cookie_resolves_the_session_fact() {
        use boatramp_core::cose::{mint_session, LocalSigner, Signer, TokenAlg};
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
        use boatramp_core::cose::{mint_context, LocalSigner, Signer, TokenAlg};
        use boatramp_core::tenancy::ScopeAxis;

        let signer = LocalSigner::generate(TokenAlg::Es256);
        let anchor = signer.public_key();
        let envelope = mint_context("acme", 3600, boatramp_core::time::now_unix(), &signer)
            .await
            .unwrap();

        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::SignedContext],
            read: AccessMode::Own,
            write: AccessMode::Own,
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
        let forged = mint_context("evil", 3600, boatramp_core::time::now_unix(), &stranger)
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
        assert!(resolve_host_tenancy(
            None,
            true,
            posture(true, false),
            TenantSourceInputs::default()
        )
        .await
        .is_err());
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
    async fn all_is_capped_to_own_unless_the_posture_opens_it() {
        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::All,
            write: AccessMode::All,
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
        assert!(ht
            .orm_scope(boatramp_handlers::TenantAxis::Read)
            .unwrap()
            .is_some());
        // Ceiling open: `all` stands ⇒ no scope (unscoped, cross-tenant).
        let ht = resolve_host_tenancy(Some(&decision), true, posture(true, true), inputs)
            .await
            .unwrap()
            .unwrap();
        assert!(ht
            .orm_scope(boatramp_handlers::TenantAxis::Read)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn own_plus_null_write_degrades_to_own_never_the_shared_baseline() {
        let decision = Tenancy::Scoped {
            column: "tenant_id".into(),
            sources: vec![TenantSource::Domain],
            read: AccessMode::OwnOrNull,
            write: AccessMode::OwnOrNull,
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

    /// **Live** proof (R4/D8) that a **plain-wasm** target route confines BOTH its `orm` and its
    /// raw-`sql` reads to tenant `B`'s PUBLIC subset on a REAL libsql engine — the non-federated
    /// analog of the GDC target live gate. Drives `HostTenancy::target` through `orm_scope`
    /// (force_scope → compile → run) AND `rewrite_target_read` (AST rewrite → run) against a shared
    /// `products` table holding tenant A's row + tenant B's public / draft / soft-deleted rows,
    /// asserting each path returns ONLY B's published, non-deleted row — the raw-SQL path proven over
    /// a join, a subquery, and an OR-escape (the multi-table / escape cases the old single-table
    /// `{scope}` marker could not confine). `#[ignore]`d for the same libsql static-musl segfault
    /// reason as the ORM batteries; the `test-target-plain-wasm` CI job runs it unignored on the host
    /// toolchain and greps the marker.
    #[tokio::test]
    #[ignore = "run via the test-target-plain-wasm CI job on the host toolchain (static-musl libsql segfault)"]
    async fn plain_wasm_target_confines_orm_and_raw_sql_to_b_public_on_a_real_engine() {
        use boatramp_core::orm::{Expr, Select, SelectItem};
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

        println!(
            "PLAIN-WASM TARGET ISOLATION OK: a target route's orm AND raw-sql reads each return only \
             tenant B's published+non-deleted rows (never tenant A's, never B's draft/removed) on a \
             real libsql engine — the raw-SQL path is AST-rewritten so multi-table joins, subqueries, \
             and OR-escapes are all confined, and an undeclared table is refused"
        );
    }

    /// **Live** proof (R4/D8, Stage 5b) that a **plain-wasm** target route's WRITES land ONLY in
    /// tenant `B`'s PUBLIC subset on a REAL libsql engine: an INSERT force-stamps `tenant = B` + the
    /// visibility columns (so the row is B's and public) and takes only the SET-allowlisted column
    /// from the guest; an UPDATE is confined to `tenant = B AND <public>` and may set only the
    /// allowlisted column; a DELETE, a set of the tenant/visibility column, and a read-only-route
    /// write are all refused. `#[ignore]`d (static-musl libsql segfault); the `test-target-plain-wasm`
    /// CI job runs it unignored and greps the marker.
    #[tokio::test]
    #[ignore = "run via the test-target-plain-wasm CI job on the host toolchain (static-musl libsql segfault)"]
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
        );
        assert!(
            ro.orm_scope(TenantAxis::Write).is_err(),
            "a read-only target route denies the write axis outright"
        );

        println!(
            "PLAIN-WASM TARGET WRITE ISOLATION OK: a target route's orm writes land only in tenant \
             B's public subset (INSERT force-stamps tenant=B + visibility; UPDATE confined to B's \
             public rows, only the allowlisted column settable), and a DELETE / visibility-flip / \
             read-only write are all refused, on a real libsql engine"
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
