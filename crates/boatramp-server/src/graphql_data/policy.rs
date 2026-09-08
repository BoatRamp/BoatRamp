//! The data connector's exposure + access policy — backend-agnostic and **deny-by-default**.
//!
//! A database-derived GraphQL API must never leak by default, so nothing is exposed unless
//! the policy names it: a table absent here is neither in the generated SDL nor queryable,
//! and a column absent from its table's allow-set is invisible. A table may carry a
//! **row-level predicate** that is conjoined onto every access, its placeholders bound from the
//! request's verified **claims** — the tenant-isolation seam. Resolution is **fail-closed**:
//! a predicate that references a claim the request doesn't carry is an error, never silently
//! dropped (which would widen access).
//!
//! The same policy object governs SQL access here and (in a later landing) which wasm
//! delegation targets a field may invoke, so there is no cross-backend authorization seam.

use super::schema::{Column, DbSchema, Table};
use boatramp_core::sql::SqlValue;
use std::collections::{BTreeMap, BTreeSet};

/// The request's verified identity claims, which a row predicate binds against (e.g. a
/// `tenant` claim → `tenant_id = {claim:tenant}`). Populated by the serving layer from the
/// caller's token; a bare map here so the policy stays pure and testable.
#[derive(Debug, Clone, Default)]
pub(crate) struct Claims(BTreeMap<String, SqlValue>);

impl Claims {
    pub(crate) fn new(map: BTreeMap<String, SqlValue>) -> Self {
        Self(map)
    }

    pub(crate) fn get(&self, name: &str) -> Option<&SqlValue> {
        self.0.get(name)
    }
}

/// A row predicate's right-hand value: bound from a request claim, or a fixed literal.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RowValue {
    /// Bind the value of the named request claim (fail-closed if absent).
    Claim(String),
    /// A fixed value.
    Literal(SqlValue),
}

/// A row-predicate comparison. Kept minimal (equality) — the tenant-isolation case — and
/// extensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowOp {
    Eq,
}

/// One term of a row predicate: `<column> <op> <value>`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RowTerm {
    pub column: String,
    pub op: RowOp,
    pub value: RowValue,
}

/// A table's row-level predicate: a conjunction of terms applied to every access.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RowPredicate {
    pub terms: Vec<RowTerm>,
}

/// The policy for one exposed table.
#[derive(Debug, Clone, Default)]
pub(crate) struct TablePolicy {
    /// The readable columns (an allow-list). A column not here is invisible.
    pub columns: BTreeSet<String>,
    /// An optional row filter conjoined onto every access to this table.
    pub rows: Option<RowPredicate>,
    /// Delegated fields: `field → wasm function`. Also the invoke allowlist — only these
    /// fields delegate, only to these functions.
    pub resolvers: BTreeMap<String, String>,
}

impl TablePolicy {
    /// A table policy exposing exactly `columns`, with no row predicate.
    pub(crate) fn columns<I, S>(columns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            columns: columns.into_iter().map(Into::into).collect(),
            rows: None,
            resolvers: BTreeMap::new(),
        }
    }

    /// Add a row predicate.
    pub(crate) fn with_rows(mut self, rows: RowPredicate) -> Self {
        self.rows = Some(rows);
        self
    }

    /// Add a delegated field → function mapping.
    pub(crate) fn with_resolver(
        mut self,
        field: impl Into<String>,
        function: impl Into<String>,
    ) -> Self {
        self.resolvers.insert(field.into(), function.into());
        self
    }
}

/// Why resolving a policy against a request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PolicyError {
    /// A row predicate references a claim the request doesn't carry — deny (never widen).
    #[error("access requires the `{0}` claim, which the request does not carry")]
    MissingClaim(String),
    /// A **target read** (R4/D8) touched a table with no declared public subset — deny-by-default
    /// (the strict analog of an undeclared tenant key). A target scope may only read rows that
    /// satisfy each accessed table's host-held public predicate, so a table (root or any
    /// joined/subquery ref) that declares none is refused before any SQL is emitted.
    #[error("table `{0}` has no declared public subset for a target read (deny-by-default)")]
    TargetSubsetUndeclared(String),
}

/// One table's confinement under a **target read**: the tenant column to bind to the target tenant
/// `B`, plus the host-held public-subset terms (literals) to conjoin. Sourced from the project
/// `TenancySchema` by the host (never from the GDC's own claim-bound config, which is the OWN path).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TargetTable {
    /// The table's tenant key column (from the project schema's per-table keys).
    pub tenant_column: String,
    /// The table's host-held public-subset terms (all literal values — never claim-bound).
    pub public: Vec<ResolvedTerm>,
}

/// A host-resolved **target-tenant read scope** (R4/D8): read another tenant `B`'s PUBLIC subset.
/// `B` is host-derived at the edge (terminating domain / verified capability / handle lookup), NEVER
/// guest input. `tables` maps each table permitted under this scope to its confinement; a table
/// **absent** from the map is refused (deny-by-default), so a target read can never reach `B`'s
/// PRIVATE rows through an un-confined table (root, join, or subquery).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TargetScope {
    /// The resolved target tenant `B` — bound as a literal on every table's tenant column.
    pub tenant_value: SqlValue,
    /// Per-table confinement; deny-by-default for a table not present.
    pub tables: BTreeMap<String, TargetTable>,
}

/// One resolved row-predicate term: a column compared to a concrete bound value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResolvedTerm {
    pub column: String,
    pub op: RowOp,
    pub value: SqlValue,
}

/// A table's row predicate resolved against the request claims — ready to lower to a
/// parameterized `WHERE`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResolvedFilter {
    pub terms: Vec<ResolvedTerm>,
}

/// The connector's whole exposure + access policy: a per-table allow-map. Deny-by-default —
/// an empty policy exposes nothing (fail-closed).
#[derive(Debug, Clone, Default)]
pub(crate) struct DataPolicy {
    tables: BTreeMap<String, TablePolicy>,
}

impl DataPolicy {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add a table's policy (builder).
    pub(crate) fn with_table(mut self, name: impl Into<String>, policy: TablePolicy) -> Self {
        self.tables.insert(name.into(), policy);
        self
    }

    pub(crate) fn table(&self, name: &str) -> Option<&TablePolicy> {
        self.tables.get(name)
    }

    /// Whether `table` is exposed at all.
    pub(crate) fn is_table_exposed(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }

    /// Whether `column` of `table` is readable.
    pub(crate) fn is_column_exposed(&self, table: &str, column: &str) -> bool {
        self.tables
            .get(table)
            .is_some_and(|t| t.columns.contains(column))
    }

    /// The wasm function a delegated `field` of `table` resolves to, if any.
    pub(crate) fn delegated(&self, table: &str, field: &str) -> Option<&str> {
        self.tables
            .get(table)
            .and_then(|t| t.resolvers.get(field))
            .map(String::as_str)
    }

    /// A schema projected to only what the policy exposes: exposed tables, exposed columns,
    /// and foreign keys whose local columns are all exposed. A table's primary key is kept
    /// only if every key column is exposed (else no `_by_pk`/`@key` is generated for it).
    pub(crate) fn project_schema(&self, schema: &DbSchema) -> DbSchema {
        let tables = schema
            .tables
            .iter()
            .filter_map(|t| self.project_table(t))
            .collect();
        DbSchema { tables }
    }

    fn project_table(&self, table: &Table) -> Option<Table> {
        let policy = self.tables.get(&table.name)?;
        let columns: Vec<Column> = table
            .columns
            .iter()
            .filter(|c| policy.columns.contains(&c.name))
            .cloned()
            .collect();
        if columns.is_empty() {
            return None; // a table with no exposed columns is not a usable type
        }
        let exposed = |name: &String| policy.columns.contains(name);
        let primary_key = if !table.primary_key.is_empty() && table.primary_key.iter().all(exposed)
        {
            table.primary_key.clone()
        } else {
            Vec::new()
        };
        let foreign_keys = table
            .foreign_keys
            .iter()
            .filter(|fk| fk.columns.iter().all(exposed))
            .cloned()
            .collect();
        Some(Table {
            name: table.name.clone(),
            columns,
            primary_key,
            foreign_keys,
        })
    }

    /// Resolve `table`'s row predicate against `claims` into concrete terms ready to lower
    /// to SQL. `Ok(None)` when the table has no predicate. **Fail-closed:** a term binding a
    /// claim the request doesn't carry is a [`PolicyError::MissingClaim`], never dropped.
    pub(crate) fn row_filter(
        &self,
        table: &str,
        claims: &Claims,
    ) -> Result<Option<ResolvedFilter>, PolicyError> {
        let Some(predicate) = self.tables.get(table).and_then(|t| t.rows.as_ref()) else {
            return Ok(None);
        };
        let mut terms = Vec::with_capacity(predicate.terms.len());
        for term in &predicate.terms {
            let value = match &term.value {
                RowValue::Literal(v) => v.clone(),
                RowValue::Claim(name) => claims
                    .get(name)
                    .cloned()
                    .ok_or_else(|| PolicyError::MissingClaim(name.clone()))?,
            };
            terms.push(ResolvedTerm {
                column: term.column.clone(),
                op: term.op,
                value,
            });
        }
        Ok(Some(ResolvedFilter { terms }))
    }

    /// Resolve `table`'s row filter under an optional **target scope** (R4/D8).
    ///
    /// - `target = None` ⇒ identical to [`row_filter`](Self::row_filter) (the OWN path: the table's
    ///   claim-bound predicate).
    /// - `target = Some(ts)` ⇒ the OWN claim-bound predicate is **replaced** by `tenant_column = B`
    ///   (the host-resolved target tenant, a literal — never the caller's own claim) conjoined with
    ///   the table's host-held public-subset terms. A table **not** present in `ts.tables` is refused
    ///   ([`PolicyError::TargetSubsetUndeclared`], deny-by-default) — the confinement that stops a
    ///   target read from reaching `B`'s private rows through any table (root/join/subquery).
    ///
    /// Applied at every per-table injection seam, so the confinement composes at every depth.
    pub(crate) fn row_filter_with_target(
        &self,
        table: &str,
        claims: &Claims,
        target: Option<&TargetScope>,
    ) -> Result<Option<ResolvedFilter>, PolicyError> {
        let Some(ts) = target else {
            return self.row_filter(table, claims);
        };
        let confine = ts
            .tables
            .get(table)
            .ok_or_else(|| PolicyError::TargetSubsetUndeclared(table.to_string()))?;
        // `tenant_column = B` (literal), then every public-subset term (also literals). The own
        // claim-bound predicate is deliberately NOT consulted here — a target read is confined by
        // the host-resolved B + the public subset, not by the caller's own claim.
        let mut terms = Vec::with_capacity(1 + confine.public.len());
        terms.push(ResolvedTerm {
            column: confine.tenant_column.clone(),
            op: RowOp::Eq,
            value: ts.tenant_value.clone(),
        });
        terms.extend(confine.public.iter().cloned());
        Ok(Some(ResolvedFilter { terms }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::schema::{Column, DbSchema, ForeignKey, ScalarType, Table};
    use super::*;

    fn schema() -> DbSchema {
        DbSchema {
            tables: vec![
                Table {
                    name: "users".into(),
                    columns: vec![
                        Column {
                            name: "id".into(),
                            ty: ScalarType::Id,
                            nullable: false,
                        },
                        Column {
                            name: "name".into(),
                            ty: ScalarType::String,
                            nullable: true,
                        },
                        Column {
                            name: "tenant_id".into(),
                            ty: ScalarType::String,
                            nullable: false,
                        },
                        Column {
                            name: "secret".into(),
                            ty: ScalarType::String,
                            nullable: true,
                        },
                    ],
                    primary_key: vec!["id".into()],
                    foreign_keys: vec![],
                },
                Table {
                    name: "audit".into(),
                    columns: vec![Column {
                        name: "id".into(),
                        ty: ScalarType::Id,
                        nullable: false,
                    }],
                    primary_key: vec!["id".into()],
                    foreign_keys: vec![ForeignKey {
                        columns: vec!["id".into()],
                        ref_table: "users".into(),
                        ref_columns: vec!["id".into()],
                    }],
                },
            ],
        }
    }

    /// A policy exposing `users`(id,name) with a tenant row filter — `secret` and the whole
    /// `audit` table stay unexposed.
    fn policy() -> DataPolicy {
        DataPolicy::new().with_table(
            "users",
            TablePolicy::columns(["id", "name"]).with_rows(RowPredicate {
                terms: vec![RowTerm {
                    column: "tenant_id".into(),
                    op: RowOp::Eq,
                    value: RowValue::Claim("tenant".into()),
                }],
            }),
        )
    }

    #[test]
    fn deny_by_default_hides_unlisted_tables_and_columns() {
        let p = policy();
        assert!(p.is_table_exposed("users"));
        assert!(!p.is_table_exposed("audit"));
        assert!(p.is_column_exposed("users", "name"));
        assert!(!p.is_column_exposed("users", "secret"));
        assert!(!p.is_column_exposed("audit", "id"));
    }

    #[test]
    fn project_schema_drops_unexposed_tables_and_columns() {
        let projected = policy().project_schema(&schema());
        assert_eq!(projected.tables.len(), 1);
        let users = projected.table("users").unwrap();
        let cols: Vec<&str> = users.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(cols, vec!["id", "name"]); // secret + tenant_id dropped
        assert_eq!(users.primary_key, vec!["id".to_string()]);
    }

    #[test]
    fn row_filter_binds_a_claim() {
        let claims = Claims::new(BTreeMap::from([(
            "tenant".to_string(),
            SqlValue::Text("acme".into()),
        )]));
        let filter = policy().row_filter("users", &claims).unwrap().unwrap();
        assert_eq!(
            filter.terms,
            vec![ResolvedTerm {
                column: "tenant_id".into(),
                op: RowOp::Eq,
                value: SqlValue::Text("acme".into()),
            }]
        );
    }

    #[test]
    fn row_filter_is_fail_closed_on_a_missing_claim() {
        // No `tenant` claim ⇒ deny, never return all rows.
        let err = policy()
            .row_filter("users", &Claims::default())
            .unwrap_err();
        assert_eq!(err, PolicyError::MissingClaim("tenant".into()));
    }

    #[test]
    fn a_table_with_no_predicate_resolves_to_no_filter() {
        let p = DataPolicy::new().with_table("users", TablePolicy::columns(["id"]));
        assert_eq!(p.row_filter("users", &Claims::default()).unwrap(), None);
    }

    #[test]
    fn target_scope_binds_b_and_public_and_denies_undeclared() {
        // A target read of tenant `B`: the OWN claim-bound filter is REPLACED by `tenant_id = B`
        // (a host literal) conjoined with the host-held public subset — no `tenant` claim consulted.
        let target = TargetScope {
            tenant_value: SqlValue::Text("tenant_B".into()),
            tables: BTreeMap::from([(
                "users".to_string(),
                TargetTable {
                    tenant_column: "tenant_id".into(),
                    public: vec![ResolvedTerm {
                        column: "published".into(),
                        op: RowOp::Eq,
                        value: SqlValue::Boolean(true),
                    }],
                },
            )]),
        };
        // No `tenant` claim at all — a target read does not need one (B is host-resolved).
        let filter = policy()
            .row_filter_with_target("users", &Claims::default(), Some(&target))
            .unwrap()
            .unwrap();
        assert_eq!(
            filter.terms,
            vec![
                ResolvedTerm {
                    column: "tenant_id".into(),
                    op: RowOp::Eq,
                    value: SqlValue::Text("tenant_B".into()),
                },
                ResolvedTerm {
                    column: "published".into(),
                    op: RowOp::Eq,
                    value: SqlValue::Boolean(true),
                },
            ]
        );

        // Deny-by-default: a table with no target confinement is refused (never an un-confined read).
        let err = policy()
            .row_filter_with_target("audit", &Claims::default(), Some(&target))
            .unwrap_err();
        assert_eq!(err, PolicyError::TargetSubsetUndeclared("audit".into()));

        // target = None ⇒ the own path is unchanged (claim-bound), byte-identical to before.
        let claims = Claims::new(BTreeMap::from([(
            "tenant".to_string(),
            SqlValue::Text("acme".into()),
        )]));
        assert_eq!(
            policy()
                .row_filter_with_target("users", &claims, None)
                .unwrap(),
            policy().row_filter("users", &claims).unwrap(),
        );
    }
}
