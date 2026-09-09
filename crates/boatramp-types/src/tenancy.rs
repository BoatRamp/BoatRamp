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

use std::collections::{BTreeMap, BTreeSet};

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

/// A **closed** set of the host-verified/host-resolved sources for the *target* axis (R4/D8) — a
/// SECOND tenant `B` (≠ the caller's own tenant `A`), used only to read `B`'s deliberately-published
/// PUBLIC subset. Deliberately **distinct** from [`TenantSource`] so `Handle` (a public slug) is
/// *unrepresentable* on the own/session/private axes at the type level — a guest can never name its
/// OWN tenant, only a public target, and only within the guardrails (G1–G6). `via` is a
/// priority-ordered list of these, homogeneous in tier by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TargetSource {
    /// The terminating request domain, host-verified (same-origin, write-capable) — a world-public
    /// funnel served on the tenant's own host. Tier-2 (published storefront/directory).
    Domain,
    /// A public **slug/handle** passed from a third-party origin (embed / aggregator / preview):
    /// **READ-ONLY (G1)** and admissible **only** on a `world_public` subset (G2). It names public
    /// data, so it grants nothing an anonymous GET of that data wouldn't. Never on a write field.
    Handle,
    /// A host-verified **capability token** carrying the target facts (`tid`, `sub`): the token is
    /// the *authorization* (tier-3 embed/handoff, NOT world-public), so it is never mixed with
    /// `Handle` and can back a target write.
    Capability,
}

/// The tenancy **class** a root Query/Mutation field (or a plain-wasm route) runs under (R4/D8),
/// composed from the trusted SDL `@tenant` directive at publish and gated by the operator's
/// [`TenancySchema::target_eligible_fields`]. Looked up by the host planner and bound **before the
/// guest runs** — there is no request-time parameter expressing own-vs-target, so a guest can never
/// select or detect which scope it got (picking the wrong scope is *unrepresentable*). Absent ⇒
/// `Own` (byte-identical to pre-Stage-5).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(tag = "scope", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TenancyClass {
    /// The caller's OWN resolved tenant/session (today's behavior).
    #[default]
    Own,
    /// A SECOND tenant `B`'s PUBLIC subset. `via` is the prioritized target-source list
    /// (first-resolves-wins); `public` NAMES the host-held public subset to confine to; `write` is
    /// the (deny-by-default, empty ⇒ read-only) SET-allowlist of columns a target write may set.
    Target {
        via: Vec<TargetSource>,
        public: String,
        #[serde(default)]
        write: Vec<String>,
    },
}

impl TenancyClass {
    /// Whether this class reads/writes another tenant (target axis) vs. the caller's own.
    pub fn is_target(&self) -> bool {
        matches!(self, Self::Target { .. })
    }
}

/// One host-held visibility term of a [`PublicPredicate`] — `column <op> literal` or a null test.
/// Never a DSL, never guest-authored or claim-bound: a fixed shape over a literal only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublicTerm {
    /// `column <op> <value>` (e.g. `published = true`).
    Cmp {
        column: String,
        op: PublicCmp,
        value: PublicLiteral,
    },
    /// `column IS [NOT] NULL` (e.g. `deleted_at IS NULL`).
    Null { column: String, negated: bool },
}

/// The comparison operators a [`PublicTerm`] may use (a closed set — visibility predicates only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicCmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A literal a [`PublicTerm`] compares against. Types-local (this crate is `SqlValue`-free —
/// boatramp-core lowers it to a bound `SqlValue` at injection, so the literal is always a parameter,
/// never interpolated text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicLiteral {
    Bool(bool),
    Int(i64),
    Text(String),
}

/// A host-held definition of a table's PUBLIC rows (R4/D8): a **closed conjunction** of visibility
/// terms (`published = true AND deleted_at IS NULL`). A target READ conjoins it (never sees a
/// non-public row of `B`); a target WRITE filters on it (a non-public row is a fail-closed no-op).
/// Host-held per table — never a guest-authored DSL — so a guest can never widen its own visibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PublicPredicate {
    /// The conjoined terms (AND). Empty is legal but meaningless (matches every row) — the schema
    /// loader should reject an empty public predicate on a `world_public` subset.
    pub terms: Vec<PublicTerm>,
}

/// A named PUBLIC subset (R4/D8): a table's [`PublicPredicate`] plus the two **separate**,
/// deny-by-default, operator-held flags that gate the least-trusted target sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PublicSubset {
    /// The visibility predicate confining a target read/write to public rows.
    pub predicate: PublicPredicate,
    /// **G2** — is this subset readable by an anonymous `Handle` (public slug) at all? A SEPARATE,
    /// explicit flag, NOT "has a public subset" (every target field has one, incl. tier-3 capability
    /// data). `false` (default) ⇒ `handle` is refused on this subset at composition, regardless of a
    /// field's declared `via` list — so a tier-2 handle can never reach tier-3 data.
    pub world_public: bool,
    /// Whether this table's tenants are discoverable by a `handle` lookup (`SELECT tenant WHERE slug
    /// = ? AND listable = true`). Directory-scraping of listable tenants is confidentiality-neutral
    /// (that is what listable means) but rate-limited (G5). `false` (default) ⇒ no handle resolves.
    pub listable: bool,
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
    /// **Target** (R4/D8): this route/handler reads (and, with a `write` grant, writes) a SECOND
    /// tenant `B`'s PUBLIC subset (never the caller's own). The non-federated (plain-wasm) analog of
    /// a GraphQL `@tenant(scope: target)` field: the host resolves `B` from the first applicable
    /// [`via`](Self::Target::via) source (5a: the routed domain) and binds a target scope BEFORE the
    /// guest runs — confining every `orm` access to `tenant = B AND <public subset>` (deny-by-default
    /// on an undeclared subset), and AST-rewriting every raw-`sql` READ the same way. A distinct
    /// variant from [`Scoped`](Self::Scoped) so a route can't be both own and target (a misdeclaration
    /// is unrepresentable). Gated by the operator's [`TenancySchema::target_eligible_fields`].
    Target {
        /// The prioritized target-source list (first-resolves-wins). 5a resolves only `domain`.
        via: Vec<TargetSource>,
        /// Names the host-held public subset (a table in [`TenancySchema::public_subsets`]) this
        /// route's raw-`sql`/`orm` accesses confine to; the `orm` path confines every accessed table
        /// on its own declared subset.
        public: String,
        /// **Target WRITE grant (5b), deny-by-default.** The SET-allowlist of columns a target write
        /// (INSERT / UPDATE, via the typed `orm` only) may set. **Empty ⇒ read-only** (today's
        /// behavior). Non-empty ⇒ the guest may INSERT/UPDATE rows in `B`'s public subset, setting
        /// ONLY these columns — the host force-stamps `tenant = B` and the public-visibility columns,
        /// confines an UPDATE's `WHERE` to `tenant = B AND <public>`, and refuses a DELETE, a raw-SQL
        /// write, or any attempt to set the tenant/visibility columns (so a target write can never
        /// change ownership or flip a row's visibility). The tenant/public columns MUST NOT appear in
        /// this list.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        write: Vec<String>,
    },
}

impl Tenancy {
    /// Whether this decision enables in-site row scoping (own [`Scoped`](Self::Scoped) or
    /// [`Target`](Self::Target)), vs. plain queries ([`Disabled`](Self::Disabled)).
    pub fn is_scoped(&self) -> bool {
        matches!(self, Self::Scoped { .. } | Self::Target { .. })
    }

    /// Whether this decision reads/writes a SECOND tenant (the target axis) rather than the caller's
    /// own — the plain-wasm analog of a `@tenant(scope: target)` field.
    pub fn is_target(&self) -> bool {
        matches!(self, Self::Target { .. })
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
    ///
    /// The confinement rests on the invariant **a session-owned row has `default_tenant_key IS
    /// NULL`** — the host write path enforces it (an anon write stamps only `session_key`, leaving
    /// the tenant key NULL; `promote` is the sole cross-partition move, guarded by `tenant_key IS
    /// NULL`). An app should add a DB `CHECK (<tenant_key> IS NULL OR <session_key> IS NULL)` as
    /// belt-and-suspenders: a raw-SQL migration or an `all`-grant write that set BOTH columns on one
    /// row would let a session reader match a row a tenant also owns.
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
    /// **R4 target axis — the operator's host-held allowlist ceiling.** The set of root
    /// Query/Mutation field names (and plain-wasm route ids) that may carry `@tenant(scope: target)`
    /// at all. Composition **refuses** a `target` field absent from this set — the app declares
    /// intent in its SDL, but the operator gates which fields may cross to another tenant. Empty ⇒
    /// no field may be target (deny-by-default).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub target_eligible_fields: BTreeSet<String>,
    /// **R4 target axis — per-table PUBLIC subset definitions.** Keyed by table name: the host-held
    /// visibility predicate + the deny-by-default `world_public`/`listable` flags a target read/write
    /// confines to. A `target` field over a table with **no** entry here is refused at composition
    /// (mandatory — deny-by-default); the ORM join composition refuses a joined table with no entry
    /// under a target read (the strict analog of the missing-tenant-column fail-close).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub public_subsets: BTreeMap<String, PublicSubset>,
    /// **R4 target axis — the operator-curated `handle` registry (5c).** Maps a PUBLIC handle/slug →
    /// the target tenant's context tag `B` (the same opaque value a routed domain resolves to). A
    /// [`TargetSource::Handle`] resolves `B` ONLY for a slug listed here (deny-by-default: an unlisted
    /// slug is indistinguishable from an absent one — no existence oracle, G4), and ONLY when the
    /// route's `public` subset is [`world_public`](PublicSubset::world_public) (G2/G3). The handle
    /// source is always READ-ONLY (G1). Empty ⇒ no slug is handle-addressable. This is the opt-in
    /// allowlist that keeps handle addressing from reaching an arbitrary tenant — only tenants the
    /// operator deliberately publishes a handle for are reachable.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub handles: BTreeMap<String, String>,
}

impl Default for TenancySchema {
    fn default() -> Self {
        Self {
            default_tenant_key: "tenant_id".to_string(),
            session_key: None,
            tables: BTreeMap::new(),
            target_eligible_fields: BTreeSet::new(),
            public_subsets: BTreeMap::new(),
            handles: BTreeMap::new(),
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
            // A deny-all posture must also refuse every target field + declare no public subset, so
            // the target axis fails closed exactly like the own axis when a schema can't be read.
            target_eligible_fields: BTreeSet::new(),
            public_subsets: BTreeMap::new(),
            // No handle resolves under deny-all (an unreadable schema exposes no public handle).
            handles: BTreeMap::new(),
        }
    }

    /// Whether a root field / route `field` is operator-permitted to carry `@tenant(scope: target)`
    /// (the host-held allowlist ceiling). Composition refuses a `target` field for which this is
    /// `false`, so the app's SDL intent can never exceed the operator's grant.
    pub fn target_field_eligible(&self, field: &str) -> bool {
        self.target_eligible_fields.contains(field)
    }

    /// Whether the named public `subset` is flagged [`world_public`](PublicSubset::world_public) —
    /// the deny-by-default host flag that admits the anonymous `handle` source (G2/G3). A subset that
    /// declares a public predicate but is NOT `world_public` is target-readable via
    /// domain/capability, but NEVER via a handle.
    pub fn subset_is_world_public(&self, subset: &str) -> bool {
        self.public_subsets
            .get(subset)
            .is_some_and(|s| s.world_public)
    }

    /// Resolve a PUBLIC `handle`/slug to its target tenant's context tag `B` (5c), or `None` for an
    /// unlisted slug (deny-by-default — an unlisted slug is indistinguishable from an absent one, G4).
    /// Only slugs the operator deliberately published in [`handles`](Self::handles) resolve.
    pub fn resolve_handle(&self, slug: &str) -> Option<&str> {
        self.handles.get(slug).map(String::as_str)
    }

    /// The host-held PUBLIC subset for `table` (its visibility predicate + `world_public`/`listable`
    /// flags), or `None` when the table declares none — a target read/write over which is refused
    /// (deny-by-default), including a joined ref with no declared subset.
    pub fn public_subset(&self, table: &str) -> Option<&PublicSubset> {
        self.public_subsets.get(table)
    }

    /// Validate the schema before it is stored — the safety checks the target-read confinement
    /// assumes. Returns a human-readable reason on the first violation.
    ///
    /// **An empty public predicate is refused (R4/D8).** A [`PublicSubset`] with no terms would
    /// match **every** row (`tenant = B` with no visibility restriction), silently defeating the
    /// target-read confinement and exposing a tenant's PRIVATE rows — so a subset that declares a
    /// public surface must actually restrict it. Callers reject a schema that fails this rather than
    /// store a match-all subset (the write path is the single choke point where this can be caught).
    pub fn validate(&self) -> Result<(), String> {
        for (table, subset) in &self.public_subsets {
            if subset.predicate.terms.is_empty() {
                return Err(format!(
                    "public subset for table `{table}` has an empty predicate (would match every \
                     row, defeating the target-read confinement) — declare at least one visibility \
                     term (e.g. `published = true`)"
                ));
            }
        }
        Ok(())
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
            ..Default::default()
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
            ..Default::default()
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

    #[test]
    fn tenancy_class_default_is_own_and_target_flag() {
        assert_eq!(TenancyClass::default(), TenancyClass::Own);
        assert!(!TenancyClass::Own.is_target());
        let tgt = TenancyClass::Target {
            via: vec![TargetSource::Domain, TargetSource::Handle],
            public: "storefront".into(),
            write: vec![],
        };
        assert!(tgt.is_target());
        // Round-trips (the class rides on the composed supergraph).
        assert_eq!(
            tgt,
            serde_json::from_str(&serde_json::to_string(&tgt).unwrap()).unwrap()
        );
    }

    #[test]
    fn target_schema_facts_roundtrip_and_gate_deny_by_default() {
        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("products".into(), TableScope::Tenant)]),
            ..Default::default()
        };
        schema
            .target_eligible_fields
            .insert("publicProducts".into());
        schema.public_subsets.insert(
            "products".into(),
            PublicSubset {
                predicate: PublicPredicate {
                    terms: vec![
                        PublicTerm::Cmp {
                            column: "published".into(),
                            op: PublicCmp::Eq,
                            value: PublicLiteral::Bool(true),
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

        // The operator allowlist gates which fields may be target (deny-by-default).
        assert!(schema.target_field_eligible("publicProducts"));
        assert!(!schema.target_field_eligible("secretOrders"));
        // A declared public subset resolves; an undeclared table is None (⇒ refused downstream).
        assert!(schema.public_subset("products").unwrap().world_public);
        assert!(schema.public_subset("orders").is_none());

        // The whole schema round-trips (it is stored/loaded as the project config).
        let s = serde_json::to_string(&schema).unwrap();
        assert_eq!(schema, serde_json::from_str::<TenancySchema>(&s).unwrap());
    }

    #[test]
    fn validate_rejects_an_empty_public_predicate() {
        let mut schema = TenancySchema::default();
        // A public subset with at least one visibility term is valid.
        schema.public_subsets.insert(
            "products".into(),
            PublicSubset {
                predicate: PublicPredicate {
                    terms: vec![PublicTerm::Cmp {
                        column: "published".into(),
                        op: PublicCmp::Eq,
                        value: PublicLiteral::Bool(true),
                    }],
                },
                world_public: true,
                listable: true,
            },
        );
        assert!(schema.validate().is_ok());
        // An EMPTY predicate would match every row (`tenant = B` with no visibility restriction),
        // defeating the target-read confinement — refused at the write path.
        schema.public_subsets.insert(
            "orders".into(),
            PublicSubset {
                predicate: PublicPredicate { terms: vec![] },
                world_public: true,
                listable: false,
            },
        );
        let err = schema.validate().unwrap_err();
        assert!(
            err.contains("orders") && err.contains("empty predicate"),
            "got: {err}"
        );
    }

    #[test]
    fn a_pre_stage5_schema_deserializes_with_empty_target_facts() {
        // A schema stored by a pre-Stage-5 binary has no target fields; `#[serde(default)]` must
        // fill them empty (no target eligibility, no public subsets) — a clean fail-closed default,
        // never a parse error under `deny_unknown_fields`.
        let legacy = r#"{"default_tenant_key":"tenant_id","tables":{"notes":{"kind":"tenant"}}}"#;
        let schema: TenancySchema = serde_json::from_str(legacy).unwrap();
        assert!(schema.target_eligible_fields.is_empty());
        assert!(schema.public_subsets.is_empty());
        assert!(!schema.target_field_eligible("anything"));
    }
}
