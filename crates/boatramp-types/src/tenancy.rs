//! In-site tenancy configuration — the declared side of the tenant-isolation model.
//!
//! An app **opts into** in-site sub-tenancy per function/site by declaring a [`Tenancy::Scoped`]
//! block: a tenant column + a host-verified [`TenantSource`] + per-axis [`AccessMode`] grants.
//! A config with **no** [`Tenancy`] block means *undeclared*; [`Tenancy::Disabled`] means
//! *deliberately no in-site tenancy* — plain queries, where the project=database boundary is the
//! entire isolation. The distinction matters only under the `multi-tenant` operator posture,
//! which **requires** an explicit decision (`disabled` or `scoped`) so running plain is a
//! reviewed choice, never an accidental omission; `single-tenant`/`dev` treat *undeclared* as
//! `disabled` silently.
//!
//! This module carries only the wasm-clean *declaration*. Resolving the tenant **value** from the
//! source and building the injected row scope happens above (host-side), where `SqlValue` lives.

use serde::{Deserialize, Serialize};

/// How the host resolves an app's in-site "own" tenant for a request. Every source is
/// **host-verified** and bound once per invocation; a guest never supplies the tenant value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TenantSource {
    /// The verified JWT claim named `claim` (default `tid`), via the same JWKS/issuer machinery
    /// the GraphQL data connector uses. Authenticated console/portal paths.
    Token {
        #[serde(default = "default_tid_claim")]
        claim: String,
    },
    /// Derived from the already-verified request domain via its per-domain context tag
    /// ([`crate::project::DomainOwner`]'s context). Storefront / public-render paths — no
    /// app-side `Host`→slug lookup.
    Domain,
    /// A host-verifiable signed context token carried on a job/message (async workers).
    /// **Reserved**: declared for completeness; resolution is not yet wired, so a function that
    /// requires "own" via this source fails closed until it lands (never runs unscoped).
    SignedContext,
    /// Truly anonymous / non-token auth (funnel reads, HMAC webhooks): there is no "own" tenant,
    /// so only the `null`/`all` access modes are meaningful (an "own" mode fails closed).
    None,
}

fn default_tid_claim() -> String {
    "tid".to_string()
}

impl Default for TenantSource {
    fn default() -> Self {
        TenantSource::None
    }
}

/// Which tenant-set one axis (read or write) of a function may reach. **Default-deny** on
/// cross-tenant: only [`AccessMode::All`] crosses tenants, and it needs the operator posture
/// ceiling to permit it. Distinguishes every case: own, own+null, null-only, all, and no access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// No access at all on this axis (deny).
    None,
    /// The shared baseline only (`<column> IS NULL`).
    Null,
    /// The resolved tenant only.
    Own,
    /// The resolved tenant plus the shared baseline.
    OwnOrNull,
    /// Cross-tenant — all rows. Gated by the operator posture ceiling.
    All,
}

impl AccessMode {
    /// Whether this mode crosses tenants (so it needs the operator ceiling to be permitted).
    pub fn is_cross_tenant(self) -> bool {
        matches!(self, AccessMode::All)
    }
    /// Whether this mode needs a resolved "own" tenant value (so an unresolvable source ⇒ deny).
    pub fn needs_own_value(self) -> bool {
        matches!(self, AccessMode::Own | AccessMode::OwnOrNull)
    }
}

fn default_own() -> AccessMode {
    AccessMode::Own
}

/// A function/site's in-site tenancy decision. Its **presence** (`Some`) is the explicit
/// "I decided about tenancy" signal the `multi-tenant` posture requires; absence (`None`) means
/// *undeclared*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Tenancy {
    /// Deliberately no in-site tenancy — plain queries (the project=database boundary is the whole
    /// isolation). The explicit "single-tenant / no tenancy" declaration.
    Disabled,
    /// In-site sub-tenancy on `column`, resolving "own" from `source`, at the per-axis grants.
    Scoped {
        /// The tenant column the host scopes on (e.g. `tenant_id`). Validated as a SQL identifier
        /// when the scope is applied.
        column: String,
        /// How the host resolves "own".
        #[serde(default)]
        source: TenantSource,
        /// Which tenant-set reads may reach (default [`AccessMode::Own`]).
        #[serde(default = "default_own")]
        read: AccessMode,
        /// Which tenant-set writes may reach (default [`AccessMode::Own`]).
        #[serde(default = "default_own")]
        write: AccessMode,
    },
}

impl Tenancy {
    /// Whether this decision enables in-site row scoping (`Scoped`), vs. plain queries.
    pub fn is_scoped(&self) -> bool {
        matches!(self, Tenancy::Scoped { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_defaults_are_own_own_none_source() {
        // Only `column` is required; source defaults to None, both axes to Own.
        let t: Tenancy = serde_json::from_str(r#"{"mode":"scoped","column":"tenant_id"}"#).unwrap();
        assert_eq!(
            t,
            Tenancy::Scoped {
                column: "tenant_id".into(),
                source: TenantSource::None,
                read: AccessMode::Own,
                write: AccessMode::Own,
            }
        );
        assert!(t.is_scoped());
    }

    #[test]
    fn disabled_is_an_explicit_decision() {
        let t: Tenancy = serde_json::from_str(r#"{"mode":"disabled"}"#).unwrap();
        assert_eq!(t, Tenancy::Disabled);
        assert!(!t.is_scoped());
    }

    #[test]
    fn token_source_defaults_the_claim_to_tid() {
        let t: Tenancy = serde_json::from_str(
            r#"{"mode":"scoped","column":"tenant_id","source":{"kind":"token"},"read":"own_or_null","write":"own"}"#,
        )
        .unwrap();
        let Tenancy::Scoped { source, read, .. } = t else {
            panic!("scoped")
        };
        assert_eq!(
            source,
            TenantSource::Token {
                claim: "tid".into()
            }
        );
        assert_eq!(read, AccessMode::OwnOrNull);
    }

    #[test]
    fn access_mode_cross_tenant_and_own_value_flags() {
        assert!(AccessMode::All.is_cross_tenant());
        assert!(!AccessMode::Own.is_cross_tenant());
        assert!(AccessMode::Own.needs_own_value());
        assert!(AccessMode::OwnOrNull.needs_own_value());
        assert!(!AccessMode::Null.needs_own_value());
        assert!(!AccessMode::All.needs_own_value());
        assert!(!AccessMode::None.needs_own_value());
    }

    #[test]
    fn roundtrips_through_json() {
        let t = Tenancy::Scoped {
            column: "org_id".into(),
            source: TenantSource::Domain,
            read: AccessMode::OwnOrNull,
            write: AccessMode::Own,
        };
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(t, serde_json::from_str::<Tenancy>(&s).unwrap());
    }
}
