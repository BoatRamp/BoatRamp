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
            let value = resolve_from_sources(sources, &inputs).await;
            let read = cap(*read, posture.allow_cross_tenant);
            let write = normalize_write(cap(*write, posture.allow_cross_tenant));
            Ok(Some(HostTenancy::new(column.clone(), value, read, write)))
        }
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
        // Reserved: async worker signed-context isn't wired yet, so it resolves to no value —
        // an "own" op then fails closed rather than running unscoped.
        TenantSource::SignedContext => None,
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
        assert_eq!(read.value, SqlValue::Text("caller-tenant".into()));
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
        assert_eq!(scope.value, SqlValue::Text("acme-store".into()));
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
}
