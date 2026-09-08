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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How the host resolves an app's in-site "own" tenant for a request. Every source is
/// **host-verified** and bound once per invocation; a guest never supplies the tenant value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[derive(Default)]
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
    #[default]
    None,
}

fn default_tid_claim() -> String {
    "tid".to_string()
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
        matches!(self, Self::All)
    }
    /// Whether this mode needs a resolved "own" tenant value (so an unresolvable source ⇒ deny).
    pub fn needs_own_value(self) -> bool {
        matches!(self, Self::Own | Self::OwnOrNull)
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
        matches!(self, Self::Scoped { .. })
    }
}

/// How the host scopes one table under a project's [`TenancySchema`] (`PLAN-tenancy-principal`,
/// Decision A / D2 / D3). A table's scope is a fact of the **data model**, declared per project (the
/// guiding principle — the app configures its own concepts — not baked into a component). New
/// variants (the R3 session disjunct, the R4 target public-subset) land in later stages; the enum is
/// `#[non_exhaustive]` so adding them is not a breaking change for downstream crates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TableScope {
    /// Scope on the schema's [`default_tenant_key`](TenancySchema::default_tenant_key) = the resolved
    /// tenant (the common case).
    Tenant,
    /// The identity table (`tenant`/`org`/`account`), keyed by its own PK: scope on `key` = the
    /// resolved tenant instead of the default column (R2). `key` MUST be unique — a non-unique key
    /// would match other tenants' rows — validated at schema load.
    TenantKeyed { key: String },
    /// Global reference/enum data (`countries`): reads are unscoped (reachable even by a
    /// principal-less request — fail-closed is per table-scope, not per invocation); writes are
    /// deny-by-default (a shared-data write is a cross-tenant blast). Host-declared, never
    /// guest-inferred (a guest can't mark a sensitive table global).
    Unscoped,
}

/// The effective, host-resolved scope for one table (from [`TenancySchema::resolve`]) — the input
/// the ORM scope-injector needs per table reference. `None` from `resolve` means **refused**
/// (undeclared — deny-by-default); this enum is only the *declared* outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedScope {
    /// Scope this table on `column` = the resolved tenant (the injector picks the mode/value).
    Column(String),
    /// No tenant predicate — a globally-readable `Unscoped` table.
    Unscoped,
}

/// A project's tenant-isolation **schema map** — the host-held facts the scope-injector keys off
/// (`PLAN-tenancy-principal`, D2). Per-project, not per-component: a table's tenant key is a fact of
/// the data model. **Absent** (no project schema at all) ⇒ the legacy behavior (every table scopes
/// on the component's `Tenancy::Scoped.column`, byte-identical to pre-schema). **Present** ⇒ the
/// `tables` map is authoritative and **exhaustive**: a scoped component touching a table with no
/// entry is *refused* (deny-by-default, D3 — "no key" and "forgot the key" are indistinguishable, so
/// the safe collapse is deny; `Unscoped` is the explicit, reviewed "this table is global").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TenancySchema {
    /// The tenant column for a [`TableScope::Tenant`] table (e.g. `tenant_id`).
    pub default_tenant_key: String,
    /// Per-table scope facts. Authoritative + exhaustive when a schema is present (an absent table
    /// is refused, not defaulted — see the type doc).
    pub tables: BTreeMap<String, TableScope>,
}

impl Default for TenancySchema {
    fn default() -> Self {
        Self {
            default_tenant_key: "tenant_id".to_string(),
            tables: BTreeMap::new(),
        }
    }
}

impl TenancySchema {
    /// Resolve how to scope `table`. `None` ⇒ **refused** (the table is undeclared under a present
    /// schema — deny-by-default; the injector fails the query closed). `Some(ResolvedScope::Column)`
    /// ⇒ scope on that column; `Some(ResolvedScope::Unscoped)` ⇒ no tenant predicate (global read).
    pub fn resolve(&self, table: &str) -> Option<ResolvedScope> {
        match self.tables.get(table)? {
            TableScope::Tenant => Some(ResolvedScope::Column(self.default_tenant_key.clone())),
            TableScope::TenantKeyed { key } => Some(ResolvedScope::Column(key.clone())),
            TableScope::Unscoped => Some(ResolvedScope::Unscoped),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_resolves_per_table_key_and_denies_undeclared() {
        // A present schema is authoritative + exhaustive: Tenant → default key, TenantKeyed → its
        // own key (R2 identity table), Unscoped → global, and an ABSENT table is refused (D3).
        let schema: TenancySchema = serde_json::from_str(
            r#"{"default_tenant_key":"tenant_id","tables":{
                 "orders":{"kind":"tenant"},
                 "tenant":{"kind":"tenant_keyed","key":"id"},
                 "countries":{"kind":"unscoped"}}}"#,
        )
        .unwrap();
        assert_eq!(
            schema.resolve("orders"),
            Some(ResolvedScope::Column("tenant_id".into()))
        );
        assert_eq!(
            schema.resolve("tenant"),
            Some(ResolvedScope::Column("id".into())) // scoped on its PK, not tenant_id
        );
        assert_eq!(schema.resolve("countries"), Some(ResolvedScope::Unscoped));
        assert_eq!(schema.resolve("secrets_table"), None); // undeclared → deny-by-default
    }

    #[test]
    fn schema_default_is_tenant_id_no_tables() {
        let s = TenancySchema::default();
        assert_eq!(s.default_tenant_key, "tenant_id");
        assert!(s.tables.is_empty());
        // With no declared tables, even the default column resolves nothing (present-but-empty
        // schema refuses everything — a project adopting a schema declares its tables exhaustively).
        assert_eq!(s.resolve("orders"), None);
    }

    #[test]
    fn table_scope_roundtrips_through_json() {
        for ts in [
            TableScope::Tenant,
            TableScope::TenantKeyed { key: "id".into() },
            TableScope::Unscoped,
        ] {
            let j = serde_json::to_string(&ts).unwrap();
            assert_eq!(ts, serde_json::from_str::<TableScope>(&j).unwrap());
        }
    }

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
