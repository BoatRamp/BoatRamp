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

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
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

/// The default source list when a `Scoped` block omits it: truly anonymous (`[None]`) — an "own"
/// grant then fails closed until a source is declared.
fn default_sources() -> Vec<TenantSource> {
    vec![TenantSource::None]
}

/// Deserialize the [`Tenancy::Scoped`] `sources` list, accepting BOTH the Stage-2 list form
/// (`sources: [ (kind: token), (kind: domain) ]` — priority-ordered per-trigger sources) AND — for
/// backward compatibility with the pre-Stage-2 singular `source:` field (v0.4.0) — a single source
/// written as one map (`source: (kind: token)`), which becomes a one-element list. Uses
/// `deserialize_any` (the wire format is self-describing) so a seq → many and a map → the singleton,
/// **without** an `untagged` enum (which RON — the manifest format — handles poorly). A pre-Stage-2
/// config therefore keeps resolving exactly as before.
fn de_sources<'de, D>(deserializer: D) -> Result<Vec<TenantSource>, D::Error>
where
    D: Deserializer<'de>,
{
    struct SourcesVisitor;
    impl<'de> Visitor<'de> for SourcesVisitor {
        type Value = Vec<TenantSource>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a TenantSource map or a list of TenantSource maps")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<TenantSource>()? {
                out.push(s);
            }
            Ok(out)
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            // A single source written as a struct-map (the legacy `source:` singular).
            let s = TenantSource::deserialize(de::value::MapAccessDeserializer::new(map))?;
            Ok(vec![s])
        }
    }
    deserializer.deserialize_any(SourcesVisitor)
}

/// Which **axis** a resolved tenant fact belongs to (`PLAN-tenancy-principal` D1). The host-resolved
/// principal is a small *set* of facts, each tagged with its axis, so an inherited/carried principal
/// preserves which axis a value belongs to (e.g. an inherited `TargetTenant` fact keeps its
/// public-subset confinement, never collapsing into an `own` `Tenant` fact).
///
/// **CLOSED enum — the line.** Only these three axes exist, ever: `Tenant` (the caller's own tenant,
/// Stage 2), `Session` (an anonymous-identity disjunct, Stage 3), `TargetTenant` (one *other*
/// tenant's public subset, Stage 5). A fourth axis is a design smell — extend a table's scope class
/// or a fact's lifetime instead. `#[non_exhaustive]` only so the later stages can land their variants
/// without a breaking change for downstream crates; it is not an invitation to add a fourth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScopeAxis {
    /// The caller's own tenant — resolved per trigger from a [`TenantSource`] (Stage 2).
    Tenant,
    /// An anonymous returning-visitor identity, a disjunct of `Tenant` (Stage 3).
    Session,
    /// One *other* tenant, read-only, confined to a host-declared public subset (Stage 5).
    TargetTenant,
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
    /// In-site sub-tenancy on `column`, resolving "own" from the first applicable `sources` entry,
    /// at the per-axis grants.
    Scoped {
        /// The tenant column the host scopes on (e.g. `tenant_id`). Validated as a SQL identifier
        /// when the scope is applied.
        column: String,
        /// The host-verified sources the "own" tenant may resolve from, in **priority order** — the
        /// host picks the first whose current-trigger input is present (a `token` on an authenticated
        /// HTTP request, the routed `domain` on a storefront, a `signed_context` on an async job), so
        /// one component can serve multiple trigger kinds (`PLAN-tenancy-principal` R1). Accepts the
        /// pre-Stage-2 singular `source:` map too (back-compat, [`de_sources`]). Default `[None]`
        /// (anonymous — an "own" grant fails closed).
        #[serde(
            default = "default_sources",
            alias = "source",
            deserialize_with = "de_sources"
        )]
        sources: Vec<TenantSource>,
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
    /// An **anonymous-first** table (R3): rows are owned EITHER by a resolved tenant
    /// (`default_tenant_key = <Tenant fact>`) OR by an anonymous session
    /// ([`session_key`](TenancySchema::session_key)` = <Session fact>`, on `default_tenant_key IS
    /// NULL` rows). A read lowers to the disjunction `Or([tenant_key = T, session_key = S])` over
    /// whichever axis facts the request carries; the disjoint columns confine a cheap anon session
    /// to `tenant IS NULL` rows structurally (never tenant-owned rows). Requires the schema to set
    /// `session_key`; a `TenantOrSession` table with no `session_key` is refused (deny-by-default).
    TenantOrSession,
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
    /// The R3 anonymous-first disjunction: a read is `Or([tenant = <Tenant fact>, session =
    /// <Session fact>])` over whichever axis facts are present; a write stamps the actor's own axis
    /// (`tenant` if authenticated, else `session`, with the other column left `NULL`).
    TenantOrSession {
        /// The tenant column (`default_tenant_key`).
        tenant: String,
        /// The anonymous-session column (`session_key`).
        session: String,
    },
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
    /// The anonymous-session column for [`TableScope::TenantOrSession`] tables (e.g. `session_id`),
    /// present iff the project uses the R3 session axis. A `TenantOrSession` table with no
    /// `session_key` is refused (the disjunct is unrepresentable — deny-by-default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// Per-table scope facts. Authoritative + exhaustive when a schema is present (an absent table
    /// is refused, not defaulted — see the type doc).
    pub tables: BTreeMap<String, TableScope>,
}

impl Default for TenancySchema {
    fn default() -> Self {
        Self {
            default_tenant_key: "tenant_id".to_string(),
            session_key: None,
            tables: BTreeMap::new(),
        }
    }
}

impl TenancySchema {
    /// A **deny-all** schema: present (so it is authoritative, not legacy `Uniform`) with **no**
    /// declared tables, so every table is undeclared and every guest ORM query is refused
    /// deny-by-default. The host binds this as the fail-closed posture when a project's stored
    /// schema is present but cannot be read/parsed — never a silent downgrade to `Uniform`.
    pub fn deny_all() -> Self {
        Self {
            default_tenant_key: "tenant_id".to_string(),
            session_key: None,
            tables: BTreeMap::new(),
        }
    }

    /// Resolve how to scope `table`. `None` ⇒ **refused** (undeclared under a present schema —
    /// deny-by-default; the injector fails the query closed; ALSO returned for a `TenantOrSession`
    /// table when the schema declares no `session_key`, so the unrepresentable disjunct fails
    /// closed). `Some(Column)` ⇒ scope on that column; `Some(Unscoped)` ⇒ global read; `Some(
    /// TenantOrSession)` ⇒ the R3 disjunction.
    pub fn resolve(&self, table: &str) -> Option<ResolvedScope> {
        match self.tables.get(table)? {
            TableScope::Tenant => Some(ResolvedScope::Column(self.default_tenant_key.clone())),
            TableScope::TenantKeyed { key } => Some(ResolvedScope::Column(key.clone())),
            TableScope::Unscoped => Some(ResolvedScope::Unscoped),
            TableScope::TenantOrSession => Some(ResolvedScope::TenantOrSession {
                tenant: self.default_tenant_key.clone(),
                session: self.session_key.clone()?,
            }),
        }
    }

    /// The `table → `[`ResolvedScope`] map the host threads into the ORM scope injector (wrapped as
    /// `boatramp_core::orm::TableKeys::PerTable` one layer up — that type lives in the crate that owns
    /// the injector, which depends on this one). The [`TableScope`] match is exhaustive **here**, in
    /// its defining crate, so adding a variant is a compile error to classify rather than a silent
    /// miss. A `TenantOrSession` table with no `session_key` is **omitted** — an absent entry is
    /// refused (deny-by-default), never a silent single-axis scope. An empty schema yields an empty
    /// map.
    pub fn table_key_map(&self) -> BTreeMap<String, ResolvedScope> {
        self.tables
            .iter()
            .filter_map(|(table, scope)| {
                let resolved = match scope {
                    TableScope::Tenant => ResolvedScope::Column(self.default_tenant_key.clone()),
                    TableScope::TenantKeyed { key } => ResolvedScope::Column(key.clone()),
                    TableScope::Unscoped => ResolvedScope::Unscoped,
                    TableScope::TenantOrSession => ResolvedScope::TenantOrSession {
                        tenant: self.default_tenant_key.clone(),
                        session: self.session_key.clone()?, // no session_key ⇒ omit ⇒ deny
                    },
                };
                Some((table.clone(), resolved))
            })
            .collect()
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
            TableScope::TenantOrSession,
        ] {
            let j = serde_json::to_string(&ts).unwrap();
            assert_eq!(ts, serde_json::from_str::<TableScope>(&j).unwrap());
        }
    }

    #[test]
    fn tenant_or_session_needs_a_session_key_else_denies() {
        // With a session_key, a TenantOrSession table resolves to the R3 disjunct on both columns.
        let s = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            session_key: Some("session_id".into()),
            tables: BTreeMap::from([("carts".into(), TableScope::TenantOrSession)]),
        };
        assert_eq!(
            s.resolve("carts"),
            Some(ResolvedScope::TenantOrSession {
                tenant: "tenant_id".into(),
                session: "session_id".into(),
            })
        );

        // WITHOUT a session_key the disjunct is unrepresentable ⇒ fail closed: `resolve` refuses,
        // and `table_key_map` OMITS it (an absent entry is deny-by-default at the injector), never a
        // silent single-axis scope.
        let s = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            session_key: None,
            tables: BTreeMap::from([("carts".into(), TableScope::TenantOrSession)]),
        };
        assert_eq!(s.resolve("carts"), None);
        assert!(
            !s.table_key_map().contains_key("carts"),
            "a TenantOrSession table without a session_key must be omitted (denied), not scoped"
        );
    }

    #[test]
    fn scoped_defaults_are_own_own_none_source() {
        // Only `column` is required; sources default to [None], both axes to Own.
        let t: Tenancy = serde_json::from_str(r#"{"mode":"scoped","column":"tenant_id"}"#).unwrap();
        assert_eq!(
            t,
            Tenancy::Scoped {
                column: "tenant_id".into(),
                sources: vec![TenantSource::None],
                read: AccessMode::Own,
                write: AccessMode::Own,
            }
        );
        assert!(t.is_scoped());
    }

    #[test]
    fn sources_accept_both_the_legacy_singular_and_the_stage2_list() {
        // Back-compat: the pre-Stage-2 singular `source:` map still parses (→ a one-element list),
        // so a v0.4.0 tenancy config resolves exactly as before.
        let legacy: Tenancy = serde_json::from_str(
            r#"{"mode":"scoped","column":"tenant_id","source":{"kind":"domain"}}"#,
        )
        .unwrap();
        let Tenancy::Scoped { sources, .. } = &legacy else {
            panic!("scoped")
        };
        assert_eq!(sources, &vec![TenantSource::Domain]);

        // Stage 2: a priority-ordered list of per-trigger sources.
        let listed: Tenancy = serde_json::from_str(
            r#"{"mode":"scoped","column":"tenant_id","sources":[{"kind":"token"},{"kind":"domain"}]}"#,
        )
        .unwrap();
        let Tenancy::Scoped { sources, .. } = &listed else {
            panic!("scoped")
        };
        assert_eq!(
            sources,
            &vec![
                TenantSource::Token {
                    claim: "tid".into()
                },
                TenantSource::Domain
            ]
        );
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
        let Tenancy::Scoped { sources, read, .. } = t else {
            panic!("scoped")
        };
        assert_eq!(
            sources,
            vec![TenantSource::Token {
                claim: "tid".into()
            }]
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
            sources: vec![TenantSource::Domain],
            read: AccessMode::OwnOrNull,
            write: AccessMode::Own,
        };
        let s = serde_json::to_string(&t).unwrap();
        assert_eq!(t, serde_json::from_str::<Tenancy>(&s).unwrap());
    }
}
