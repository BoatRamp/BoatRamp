//! Host-resolved in-site tenancy for one guest invocation — the **applied** side of the
//! tenant-isolation model (the declared side is [`boatramp_core::tenancy`]).
//!
//! The server resolves the tenant *value* from the verified source and the (posture-capped)
//! per-axis access modes, then hands the binding a [`HostTenancy`]. The binding **forces** it
//! onto every ORM query node ([`orm::Select::force_scope`] et al.) and **fills** the raw-SQL
//! [`SCOPE_MARKER`] — the guest can neither see nor set it. Absent a `HostTenancy` ⇒ plain queries
//! (no scoping; the project=database boundary is the whole isolation).
//!
//! Applying to **both** surfaces is the load-bearing invariant: scoping only the ORM would let a
//! guest that also imports raw `sql` read/write across tenants and bypass the whole model.

use boatramp_core::orm::{Scope, ScopeMode, TableKeys};
use boatramp_core::sql::SqlValue;
use boatramp_core::tenancy::{AccessMode, ScopeAxis, TenancySchema};

/// One host-resolved, host-verified tenant fact, tagged with the [`ScopeAxis`] it belongs to
/// (`PLAN-tenancy-principal` D1). The principal is a small *set* of these, borne statelessly. In
/// Stage 2 only the [`ScopeAxis::Tenant`] fact is ever populated (the caller's own tenant); the
/// `Session` and `TargetTenant` facts land in later stages. Keeping the set axis-tagged now is the
/// keystone: an inherited/carried principal preserves which axis a value belongs to.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeFact {
    /// Which axis this fact scopes.
    pub axis: ScopeAxis,
    /// The host-resolved value (never guest-supplied).
    pub value: SqlValue,
}

/// The reserved token a scoped-tenancy guest places in a raw-SQL statement to mark **where** the
/// host injects the tenant predicate (the host, not the guest, decides *what* it is). A scoped
/// statement without it is refused (fail-closed); an unscoped statement never needs it.
pub const SCOPE_MARKER: &str = "{scope}";

/// Which axis of a function's grant an operation exercises. Reads (`SELECT`) use the read grant;
/// writes (`INSERT`/`UPDATE`/`DELETE`) use the write grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    Read,
    Write,
}

/// Why a scoped operation is refused **before** it reaches the backend (always fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantDenied {
    /// The axis grants no access at all ([`AccessMode::None`]).
    NoAccess,
    /// The mode needs a resolved "own" tenant, but the source produced none (anonymous request,
    /// or a source not yet wired) — so the query is refused rather than run unscoped.
    NoSource,
    /// The configured tenant column is not a valid SQL identifier (operator/app misconfig).
    BadColumn,
}

impl TenantDenied {
    /// A short, guest-safe reason string (no tenant values leaked).
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoAccess => "tenancy: this function is not granted access on this axis",
            Self::NoSource => "tenancy: no verified tenant source for this request",
            Self::BadColumn => "tenancy: misconfigured tenant column",
        }
    }
}

/// The host-resolved tenancy for one invocation. Built server-side: `value` is the tenant resolved
/// from the verified source (`None` for anonymous / null-only), and `read`/`write` are the access
/// modes **already capped by the operator posture** (so an `all` here is a deliberately-permitted
/// cross-tenant grant, never an un-vetted one). Shared by the `sql` and `orm` bindings.
#[derive(Debug, Clone)]
pub struct HostTenancy {
    column: String,
    /// The resolved **principal**: an axis-tagged fact set (`PLAN-tenancy-principal` D1). Stage 2
    /// only ever holds a single [`ScopeAxis::Tenant`] fact (or none, for anonymous / null-only); the
    /// `Session` (Stage 3) and `TargetTenant` (Stage 5) facts join it later. Carried statelessly.
    facts: Vec<ScopeFact>,
    read: AccessMode,
    write: AccessMode,
    /// Per-table tenant-key resolution from the project [`TenancySchema`](boatramp_core::tenancy::TenancySchema)
    /// (Stage 1 / R2). `Uniform` (no project schema) ⇒ every table scopes on `column`; `PerTable`
    /// ⇒ the identity table on its own PK, `Unscoped` tables skipped, undeclared tables refused.
    keys: boatramp_core::orm::TableKeys,
    /// The public-subset terms the **raw-SQL `{scope}` marker** conjoins under a TARGET read (R4/D8)
    /// — the single-table (`Tenancy::Target.public`-named) analog of the `orm` path's per-table
    /// `PerTableTarget` confinement. Empty for an own scope (the marker then injects only the tenant
    /// predicate). Populated by [`target`](Self::target) from the named subset; unqualified columns
    /// (raw SQL is single-table at the marker).
    target_public: Vec<boatramp_core::orm::PublicTermSql>,
}

impl HostTenancy {
    /// Build a resolved tenancy. `column` is the default tenant column; `value` the resolved tenant
    /// (if any); `read`/`write` the posture-capped access modes. Per-table keys default to
    /// `Uniform` (legacy single-column); attach a project schema with [`with_schema`](Self::with_schema).
    pub fn new(
        column: impl Into<String>,
        value: Option<SqlValue>,
        read: AccessMode,
        write: AccessMode,
    ) -> Self {
        // A resolved own-tenant value becomes the single `Tenant` fact; anonymous / null-only
        // resolves to an empty fact set. The fact-set shape is the Stage-2 keystone.
        let facts = value
            .map(|value| ScopeFact {
                axis: ScopeAxis::Tenant,
                value,
            })
            .into_iter()
            .collect();
        Self::from_facts(column, facts, read, write)
    }

    /// Build a resolved tenancy directly from an axis-tagged fact set — the constructor the edge
    /// **carry** uses (invoke / session re-entry), so an inherited principal preserves each fact's
    /// axis. Per-table keys default to `Uniform`; attach a project schema with
    /// [`with_schema`](Self::with_schema).
    pub fn from_facts(
        column: impl Into<String>,
        facts: Vec<ScopeFact>,
        read: AccessMode,
        write: AccessMode,
    ) -> Self {
        Self {
            column: column.into(),
            facts,
            read,
            write,
            keys: boatramp_core::orm::TableKeys::Uniform,
            // Own/session principals carry no target marker terms; only `target()` populates them.
            target_public: Vec::new(),
        }
    }

    /// Build the **target-read** tenancy for a host-resolved target tenant `B` (R4/D8): a principal
    /// carrying a single [`ScopeAxis::TargetTenant`] fact (never an own/session fact — own and target
    /// never co-occur), read-only (`write = None`; target writes are a later grant), with the
    /// project schema's per-table keys **and** per-table public subsets baked into a
    /// [`TableKeys::PerTableTarget`]. Its [`orm_scope`](Self::orm_scope)`(Read)` then yields a scope
    /// that confines every accessed table to `tenant = B AND <that table's public subset>` and
    /// refuses any table with no declared public subset (deny-by-default). `B` is host-derived at the
    /// edge (terminating domain / verified capability claim / handle lookup), NEVER guest input.
    /// `public` NAMES the subset (a table in [`TenancySchema::public_subsets`]) the raw-SQL `{scope}`
    /// marker confines to (single-table); the `orm` path independently confines EVERY accessed table
    /// on its own declared subset via [`TableKeys::PerTableTarget`]. The marker's tenant column is
    /// that named table's key (from the schema); `B` is host-derived, never guest input.
    pub fn target(
        target_value: SqlValue,
        read: AccessMode,
        schema: &TenancySchema,
        public: &str,
    ) -> Self {
        // The orm path: confine every accessed table on its own declared public subset.
        let per_table = schema
            .public_subsets
            .iter()
            .map(|(table, subset)| {
                (
                    table.clone(),
                    boatramp_core::orm::lower_public_terms(&subset.predicate),
                )
            })
            .collect();
        // The raw-SQL marker path (single-table): the named subset's tenant column + public terms.
        // A `public` that names no tenant-scoped table with a subset leaves the marker terms empty
        // and the column at the default key — the marker then still binds `tenant = B`, and any
        // unconfined raw-SQL read is the operator's misdeclaration (documented), never a silent
        // widening on the orm path (which is per-table deny-by-default regardless).
        let column = match schema.resolve(public) {
            Some(boatramp_core::tenancy::ResolvedScope::Column(c)) => c,
            _ => schema.default_tenant_key.clone(),
        };
        let target_public = schema
            .public_subset(public)
            .map(|s| boatramp_core::orm::lower_public_terms(&s.predicate))
            .unwrap_or_default();
        Self {
            column,
            facts: vec![ScopeFact {
                axis: ScopeAxis::TargetTenant,
                value: target_value,
            }],
            read,
            // Target writes need their own grant + confinement (a later stage); a target-read
            // principal is read-only, so the write axis is denied outright here.
            write: AccessMode::None,
            keys: TableKeys::PerTableTarget {
                keys: schema.table_key_map(),
                public: per_table,
            },
            target_public,
        }
    }

    /// The resolved principal's fact set (axis-tagged). The host **carries** this down an in-project
    /// invoke / session re-entry so an inherited principal keeps each fact's axis.
    pub fn facts(&self) -> &[ScopeFact] {
        &self.facts
    }

    /// The resolved own-[`ScopeAxis::Tenant`] value, if any — the value the `Own`/`OwnOrNull` scope
    /// modes bind.
    fn tenant_value(&self) -> Option<&SqlValue> {
        self.fact(ScopeAxis::Tenant)
    }

    /// The resolved anonymous-[`ScopeAxis::Session`] value, if any (R3) — the `session_key` arm of a
    /// `TenantOrSession` table's disjunct.
    fn session_value(&self) -> Option<&SqlValue> {
        self.fact(ScopeAxis::Session)
    }

    /// The resolved value on `axis`, if the principal carries a fact for it.
    fn fact(&self, axis: ScopeAxis) -> Option<&SqlValue> {
        self.facts.iter().find(|f| f.axis == axis).map(|f| &f.value)
    }

    /// Attach the project's per-table tenancy map (R2), so each table scopes on its own key (the
    /// identity table on its PK, `Unscoped` tables skipped, undeclared tables refused).
    ///
    /// A **present** schema (`Some`) is authoritative — it becomes `PerTable` **even when empty**, so
    /// an empty (or [`deny_all`](boatramp_core::tenancy::TenancySchema::deny_all)) schema refuses
    /// every table rather than silently reverting to single-column scoping. Only an **absent** schema
    /// (`None` — the project declared none) keeps the legacy `Uniform` behavior. This is the
    /// fail-closed contract the bind path relies on: a project that has adopted a schema can never be
    /// downgraded to `Uniform` by an empty map. Chained by the host at bind time.
    #[must_use]
    pub fn with_schema(mut self, schema: Option<&boatramp_core::tenancy::TenancySchema>) -> Self {
        if let Some(s) = schema {
            self.keys = boatramp_core::orm::TableKeys::PerTable(s.table_key_map());
        }
        self
    }

    /// The resolved own-tenant value, if any (the [`ScopeAxis::Tenant`] fact). Used by the host to
    /// **propagate** the caller's tenant down an in-project invoke chain (host-carried — never read
    /// from a guest-supplied invoke request), so an invoked sibling inherits the caller's tenant
    /// identity while applying its own grant. (Prefer [`facts`](Self::facts) for the full principal.)
    pub fn value(&self) -> Option<&SqlValue> {
        self.tenant_value()
    }

    fn mode(&self, axis: Axis) -> AccessMode {
        match axis {
            Axis::Read => self.read,
            Axis::Write => self.write,
        }
    }

    fn valid_column(&self) -> bool {
        is_ident(&self.column)
    }

    /// The core ORM [`Scope`] to force onto a query for `axis`, or a [`TenantDenied`]
    /// (fail-closed). `Ok(None)` means *no scope* — cross-tenant [`AccessMode::All`], which runs
    /// unscoped by design (its grant was posture-vetted upstream).
    pub fn orm_scope(&self, axis: Axis) -> Result<Option<Scope>, TenantDenied> {
        if !self.valid_column() {
            return Err(TenantDenied::BadColumn);
        }
        let mode = match self.mode(axis) {
            AccessMode::None => return Err(TenantDenied::NoAccess),
            AccessMode::All => return Ok(None),
            AccessMode::Null => ScopeMode::NullOnly,
            AccessMode::Own => ScopeMode::Own,
            AccessMode::OwnOrNull => ScopeMode::OwnOrNull,
        };
        // Under a TARGET scope the bound value is the resolved `TargetTenant` fact `B` (own and
        // target never co-occur, so there is no own fact to confuse it with); otherwise it is the
        // own `Tenant` fact. The `session` arm is own-axis only (a target read carries no session).
        let is_target = matches!(self.keys, TableKeys::PerTableTarget { .. });
        let bound = if is_target {
            self.fact(ScopeAxis::TargetTenant).cloned()
        } else {
            self.tenant_value().cloned()
        };
        let session = if is_target {
            None
        } else {
            self.session_value().cloned()
        };
        // `own`/`own+null` need SOME principal. Fail closed early only when the mode needs a value
        // AND neither the bound (tenant/target) nor a session fact is present (a fully anonymous
        // request). The finer, per-table decision is the injector's: a plain tenant table with only
        // a session fact still denies there ([`OrmError::TenancyNoPrincipal`]), while a
        // `TenantOrSession` table uses the session arm. `NullOnly` needs no value (it emits `IS NULL`).
        if matches!(mode, ScopeMode::Own | ScopeMode::OwnOrNull)
            && bound.is_none()
            && session.is_none()
        {
            return Err(TenantDenied::NoSource);
        }
        Ok(Some(Scope {
            column: self.column.clone(),
            // The resolved bound value (own `Tenant`, or `TargetTenant` `B` under a target scope;
            // `None` for a purely anonymous actor) + the session fact (R3, own-axis only). The
            // per-table key map (R2/R3/R4), resolved at bind time; `Uniform` when the project
            // declared no schema (byte-identical to the pre-schema behavior).
            value: bound,
            session,
            mode,
            keys: self.keys.clone(),
        }))
    }

    /// Whether raw SQL on `axis` must carry the [`SCOPE_MARKER`]. True whenever the axis actually
    /// restricts rows (null/own/own+null); false for cross-tenant `all` (nothing to inject) — a
    /// `None`-grant axis "requires" it moot-ly since it's denied outright.
    pub fn requires_marker(&self, axis: Axis) -> bool {
        !matches!(self.mode(axis), AccessMode::All)
    }

    /// Fill the raw-SQL [`SCOPE_MARKER`] for `axis`, given the guest's current positional-param
    /// count. Returns the predicate SQL to substitute for the marker plus the values to **append**
    /// to the params, in placeholder order (the predicate references them as `?<param_count+1>`,
    /// `?<param_count+2>`, …). `all` yields a tautology (`1 = 1`) and no values.
    ///
    /// Under a **target** read (R4/D8) the predicate is `<col> = ?N AND <public subset>` — the
    /// tenant `B` bound at `?N`, then the named public subset's terms (comparison literals bound in
    /// order; a null test binds nothing) — the single-table analog of the `orm` path's per-table
    /// confinement, so a target raw-SQL read reaches only B's public rows.
    pub fn sql_marker(
        &self,
        axis: Axis,
        param_count: usize,
    ) -> Result<(String, Vec<SqlValue>), TenantDenied> {
        use boatramp_core::orm::{PublicTermSql, TableKeys};
        if !self.valid_column() {
            return Err(TenantDenied::BadColumn);
        }
        let col = &self.column;
        let is_target = matches!(self.keys, TableKeys::PerTableTarget { .. });
        match self.mode(axis) {
            AccessMode::None => Err(TenantDenied::NoAccess),
            AccessMode::All => Ok(("1 = 1".to_string(), Vec::new())),
            AccessMode::Null => Ok((format!("{col} IS NULL"), Vec::new())),
            AccessMode::Own => {
                // The bound value is the target `B` under a target read, else the own tenant.
                let v = if is_target {
                    self.fact(ScopeAxis::TargetTenant)
                } else {
                    self.tenant_value()
                }
                .cloned()
                .ok_or(TenantDenied::NoSource)?;
                let mut next = param_count + 1;
                let mut sql = format!("{col} = ?{next}");
                let mut values = vec![v];
                if is_target {
                    // Conjoin the named public subset (single-table, unqualified columns) so a target
                    // raw-SQL read is confined to `tenant = B AND <public>`, never all of B's rows.
                    for term in &self.target_public {
                        match term {
                            PublicTermSql::Cmp { column, op, value } => {
                                next += 1;
                                sql.push_str(&format!(" AND {column} {} ?{next}", op.symbol()));
                                values.push(value.clone());
                            }
                            PublicTermSql::Null { column, negated } => {
                                let not = if *negated { "NOT " } else { "" };
                                sql.push_str(&format!(" AND {column} IS {not}NULL"));
                            }
                        }
                    }
                }
                Ok((sql, values))
            }
            AccessMode::OwnOrNull => {
                // `own+null` is an OWN-axis mode (a target read is exact `= B`, never `OR NULL`).
                let v = self.tenant_value().cloned().ok_or(TenantDenied::NoSource)?;
                Ok((
                    format!("({col} = ?{} OR {col} IS NULL)", param_count + 1),
                    vec![v],
                ))
            }
        }
    }
}

/// A conservative SQL-identifier check for the tenant column (host/operator-set, still validated):
/// non-empty, ASCII alphanumeric or `_`, not starting with a digit.
fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> SqlValue {
        SqlValue::Text(s.to_string())
    }

    #[test]
    fn a_resolved_value_becomes_a_single_tenant_fact() {
        // The keystone: `new(Some(v))` yields a one-fact `Tenant` principal; `value()`/the scope
        // read it back. Anonymous (`None`) is an empty fact set.
        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("acme")),
            AccessMode::Own,
            AccessMode::Own,
        );
        assert_eq!(ht.facts().len(), 1);
        assert_eq!(ht.facts()[0].axis, ScopeAxis::Tenant);
        assert_eq!(ht.facts()[0].value, t("acme"));
        assert_eq!(ht.value(), Some(&t("acme")));

        let anon = HostTenancy::new("tenant_id", None, AccessMode::Null, AccessMode::Null);
        assert!(anon.facts().is_empty());
        assert_eq!(anon.value(), None);

        // `from_facts` is the carry constructor — it round-trips the axis-tagged set.
        let carried = HostTenancy::from_facts(
            "tenant_id",
            vec![ScopeFact {
                axis: ScopeAxis::Tenant,
                value: t("globex"),
            }],
            AccessMode::Own,
            AccessMode::Own,
        );
        assert_eq!(carried.value(), Some(&t("globex")));
        assert_eq!(
            carried.orm_scope(Axis::Read).unwrap().unwrap().value,
            Some(t("globex"))
        );
    }

    #[test]
    fn orm_scope_maps_each_mode() {
        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::Own,
            AccessMode::Own,
        );
        let s = ht.orm_scope(Axis::Read).unwrap().unwrap();
        assert_eq!(s.column, "tenant_id");
        assert_eq!(s.value, Some(t("ten_1")));
        assert_eq!(s.mode, ScopeMode::Own);

        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::OwnOrNull,
            AccessMode::All,
        );
        assert_eq!(
            ht.orm_scope(Axis::Read).unwrap().unwrap().mode,
            ScopeMode::OwnOrNull
        );
        // `all` on the write axis → no scope (unscoped by design).
        assert_eq!(ht.orm_scope(Axis::Write).unwrap(), None);
    }

    #[test]
    fn with_schema_puts_per_table_keys_on_the_scope() {
        use boatramp_core::orm::TableKeys;
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        let mut schema = TenancySchema::default();
        schema.tables.insert("orders".into(), TableScope::Tenant);
        schema.tables.insert(
            "tenant".into(),
            TableScope::TenantKeyed { key: "id".into() },
        );
        schema
            .tables
            .insert("countries".into(), TableScope::Unscoped);
        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("acme")),
            AccessMode::Own,
            AccessMode::Own,
        )
        .with_schema(Some(&schema));
        let scope = ht.orm_scope(Axis::Read).unwrap().unwrap();
        match &scope.keys {
            TableKeys::PerTable(m) => {
                use boatramp_core::tenancy::ResolvedScope;
                assert_eq!(
                    m.get("orders"),
                    Some(&ResolvedScope::Column("tenant_id".to_string()))
                );
                // identity table on its own PK:
                assert_eq!(
                    m.get("tenant"),
                    Some(&ResolvedScope::Column("id".to_string()))
                );
                assert_eq!(m.get("countries"), Some(&ResolvedScope::Unscoped)); // unscoped
                assert_eq!(m.get("secrets"), None); // undeclared → refused at injection
            }
            other => panic!("expected PerTable, got {other:?}"),
        }
        // No project schema (absent) ⇒ Uniform (legacy single-column).
        let ht2 = HostTenancy::new(
            "tenant_id",
            Some(t("acme")),
            AccessMode::Own,
            AccessMode::Own,
        );
        assert!(matches!(
            ht2.orm_scope(Axis::Read).unwrap().unwrap().keys,
            TableKeys::Uniform
        ));
        // A PRESENT but empty (deny-all) schema is authoritative ⇒ PerTable(empty), NOT Uniform, so
        // every table is undeclared and refused. This is the fail-closed posture the bind path binds
        // when the stored schema can't be read — an empty map must never downgrade to Uniform.
        let ht3 = HostTenancy::new(
            "tenant_id",
            Some(t("acme")),
            AccessMode::Own,
            AccessMode::Own,
        )
        .with_schema(Some(&TenancySchema::deny_all()));
        match ht3.orm_scope(Axis::Read).unwrap().unwrap().keys {
            TableKeys::PerTable(m) => assert!(m.is_empty(), "deny-all is an empty PerTable map"),
            other => panic!("deny-all must be PerTable(empty), got {other:?}"),
        }
    }

    #[test]
    fn own_without_a_value_fails_closed() {
        let ht = HostTenancy::new("tenant_id", None, AccessMode::Own, AccessMode::None);
        assert_eq!(ht.orm_scope(Axis::Read), Err(TenantDenied::NoSource));
        // A None-grant axis denies outright.
        assert_eq!(ht.orm_scope(Axis::Write), Err(TenantDenied::NoAccess));
    }

    #[test]
    fn null_only_needs_no_value() {
        let ht = HostTenancy::new("tenant_id", None, AccessMode::Null, AccessMode::Null);
        let s = ht.orm_scope(Axis::Read).unwrap().unwrap();
        assert_eq!(s.mode, ScopeMode::NullOnly);
        // No tenant fact resolved ⇒ `value` is `None`; the injector emits `IS NULL` for NullOnly
        // regardless of the value, so null-only genuinely needs no resolved principal.
        assert_eq!(s.value, None);
    }

    #[test]
    fn sql_marker_references_appended_param() {
        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::Own,
            AccessMode::Own,
        );
        // Two guest params already ⇒ the injected predicate binds ?3.
        let (pred, val) = ht.sql_marker(Axis::Read, 2).unwrap();
        assert_eq!(pred, "tenant_id = ?3");
        assert_eq!(val, vec![t("ten_1")]);

        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::OwnOrNull,
            AccessMode::Own,
        );
        let (pred, _) = ht.sql_marker(Axis::Read, 0).unwrap();
        assert_eq!(pred, "(tenant_id = ?1 OR tenant_id IS NULL)");
    }

    #[test]
    fn sql_marker_all_is_a_tautology_and_null_binds_nothing() {
        let ht = HostTenancy::new("tenant_id", None, AccessMode::All, AccessMode::Null);
        assert_eq!(
            ht.sql_marker(Axis::Read, 3).unwrap(),
            ("1 = 1".to_string(), Vec::new())
        );
        assert!(!ht.requires_marker(Axis::Read));
        assert_eq!(
            ht.sql_marker(Axis::Write, 3).unwrap(),
            ("tenant_id IS NULL".to_string(), Vec::new())
        );
        assert!(ht.requires_marker(Axis::Write));
    }

    #[test]
    fn a_bad_column_is_refused() {
        let ht = HostTenancy::new(
            "tenant_id; DROP",
            Some(t("x")),
            AccessMode::Own,
            AccessMode::Own,
        );
        assert_eq!(ht.orm_scope(Axis::Read), Err(TenantDenied::BadColumn));
        assert_eq!(ht.sql_marker(Axis::Read, 0), Err(TenantDenied::BadColumn));
    }

    #[test]
    fn target_builds_a_read_only_public_confined_scope() {
        use boatramp_core::tenancy::{
            PublicCmp, PublicLiteral, PublicPredicate, PublicSubset, PublicTerm, TableScope,
        };
        use std::collections::BTreeMap;

        let mut schema = TenancySchema {
            default_tenant_key: "tenant_id".into(),
            tables: BTreeMap::from([("products".into(), TableScope::Tenant)]),
            ..Default::default()
        };
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

        let ht = HostTenancy::target(t("tenant_B"), AccessMode::Own, &schema, "products");
        let scope = ht.orm_scope(Axis::Read).unwrap().unwrap();
        // Bound to B (the TargetTenant fact), own-mode, and carrying the PerTableTarget keys+public.
        assert_eq!(scope.value, Some(t("tenant_B")));
        assert_eq!(scope.session, None);
        assert_eq!(scope.mode, ScopeMode::Own);
        match &scope.keys {
            TableKeys::PerTableTarget { keys, public } => {
                assert!(keys.contains_key("products"));
                assert!(
                    public.contains_key("products"),
                    "public subset lowered per table"
                );
            }
            other => panic!("target scope must be PerTableTarget, got {other:?}"),
        }
        // A target-read principal is READ-ONLY: the write axis is denied outright (target writes are
        // a separate, later grant).
        assert_eq!(ht.orm_scope(Axis::Write), Err(TenantDenied::NoAccess));

        // The raw-SQL `{scope}` marker also confines to `tenant = B AND <public subset>` (single
        // table), so a target raw-SQL read reaches only B's public rows — B + the public literal
        // bound as params (never interpolated).
        let (pred, values) = ht.sql_marker(Axis::Read, 0).unwrap();
        assert_eq!(pred, "tenant_id = ?1 AND published = ?2");
        assert_eq!(values, vec![t("tenant_B"), SqlValue::Boolean(true)]);
    }
}
