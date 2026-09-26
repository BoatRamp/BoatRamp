//! Host-side parse-and-rewrite confinement of a guest's **raw-SQL target read** (R4/D8).
//!
//! The `orm` binding confines a target read (reading ANOTHER tenant `B`'s PUBLIC subset) per table
//! via [`TableKeys::PerTableTarget`](crate::orm::TableKeys::PerTableTarget): every accessed table is
//! rewritten to `tenant = B AND <that table's public predicate>`, and a table with no declared
//! public subset is refused (deny-by-default). Raw SQL had only the guest-cooperative `{scope}`
//! marker — a single, single-table, guest-placed injection point that a guest could **reposition**
//! (leaving joined tables unconfined) or **`OR`-escape** (`WHERE {scope} OR 1=1`). That is
//! structurally unfixable with a text marker.
//!
//! This module closes it by doing to raw SQL what the ORM does to typed queries: it **parses** the
//! guest statement into an AST and **injects** the same per-table confinement onto EVERY table
//! reference — the root `FROM`, every `JOIN`, every subquery, CTE, and set-operation arm — at the
//! AST level, where the guest cannot move or escape it. The guest's own `WHERE` is parenthesised
//! before the confinement is `AND`-ed on, so a top-level `OR` in the guest predicate can never widen
//! past the tenant/public gate.
//!
//! ## Why this is safe (the completeness argument)
//!
//! A single missed table reference is a cross-tenant leak, so completeness cannot rest on a
//! hand-rolled belief that every AST position has been enumerated. Instead:
//!
//! 1. The traversal is sqlparser's derived [`VisitMut`](sqlparser::ast::VisitMut) walk, which is
//!    maintained by sqlparser to cover the WHOLE grammar. Every `Query` node in the tree — including
//!    those buried in `IN (SELECT …)`, `EXISTS (…)`, scalar subqueries, derived tables, and
//!    `UNION`/`INTERSECT`/`EXCEPT` arms — receives a [`pre_visit_query`](Rewriter::pre_visit_query),
//!    where its own `SELECT`s are confined.
//! 2. Every table reference lives in a `SELECT`'s `FROM` (directly or under a `NESTED JOIN`), and
//!    every `SELECT` is confined by exactly one enclosing query's visit — so every base table is
//!    reached exactly once. With `WITH`/CTEs refused up front, a bare `FROM foo` is ALWAYS a base
//!    table (derived tables are a distinct AST node, subqueries are their own `Query`), so there is
//!    no name-shadowing case in which a reference could be mistaken for a non-table and skipped.
//! 3. Anything the confinement cannot reason about — a table-valued function, `UNNEST`, `PIVOT`, a
//!    schema-qualified name, a CTE, a write smuggled into a read position, an exotic table source —
//!    is **refused** (fail-closed), never silently passed. A second
//!    [`pre_visit_table_factor`](Rewriter::pre_visit_table_factor) guard rejects any un-confinable
//!    table source anywhere in the tree as belt-and-suspenders.
//!
//! The injected `B` and public-subset literals are host-held (from the routing context + the
//! operator's schema), never guest input, and are rendered through sqlparser's own escaping
//! ([`Value::SingleQuotedString`](sqlparser::ast::Value) doubles quotes) — so they are safe as
//! literals and, unlike bound parameters, do not disturb the guest's own positional placeholders
//! (which matters for the positional-parameter dialects).

use std::collections::BTreeMap;
use std::ops::ControlFlow;

use sqlparser::ast::{
    BinaryOperator, Expr, Ident, JoinConstraint, JoinOperator, Query, Select, SetExpr, Statement,
    TableFactor, Value, VisitMut, VisitorMut,
};
use sqlparser::dialect::{Dialect as SpDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;

use crate::orm::{CmpOp, PublicTermSql};
use crate::sql::{Dialect, SqlValue};
use crate::tenancy::ResolvedScope;

/// Why a raw-SQL target read is **refused** before it reaches the backend (always fail-closed — a
/// target read that cannot be provably confined does not run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetRewriteError {
    /// The statement did not parse under the backend's dialect.
    Parse(String),
    /// Not a single read-only query: multiple statements, or a top-level statement that is not a
    /// `SELECT` / `VALUES` / set-operation (a write or DDL). Target reads are read-only.
    NotReadOnly,
    /// A write was smuggled into a read position (a `SELECT … INTO`, a `TABLE t` shorthand, or an
    /// `INSERT`/`UPDATE` inside a CTE / set-op arm).
    WriteInReadPosition,
    /// A table source the confinement cannot reason about (a table-valued function, `UNNEST`,
    /// `PIVOT`/`UNPIVOT`, `JSON_TABLE`, `MATCH_RECOGNIZE`, …) — refused rather than left unconfined.
    UnsupportedTableSource(String),
    /// A schema-/database-qualified table name (`schema.table`). A target read must use bare table
    /// identifiers so the per-table key/public lookup is unambiguous (a qualified name could point
    /// at a different physical table than the schema entry it would be confined by).
    QualifiedTableName(String),
    /// A table accessed under a target read declares no PUBLIC subset (deny-by-default — the strict
    /// analog of the ORM's `PublicSubsetUndeclared`).
    PublicSubsetUndeclared(String),
    /// A table accessed under a target read has no declared tenant key in the schema
    /// (deny-by-default — the analog of `TenancyUndeclared`).
    TenancyUndeclared(String),
    /// The tenant `B` value, or a public-subset literal, cannot be rendered as a safe SQL literal
    /// (a blob / JSON / null / non-finite float where a scalar was required).
    UnsupportedLiteral,
    /// A tenant/public column in the schema is not a valid SQL identifier (operator misconfig).
    BadColumn(String),
    /// A declared subset lowered to no confinement at all (empty predicate on an unscoped table) —
    /// would match every row; refused. (The schema validator rejects empty predicates up front;
    /// this is the injector-level backstop.)
    EmptyConfinement(String),
    /// A target read was attempted with no resolved target tenant `B` (the principal carried no
    /// `TargetTenant` fact). Unreachable by construction — a target principal always resolves `B` —
    /// but refused fail-closed rather than run unconfined.
    MissingTarget,
    /// A join the target-read confinement cannot soundly place: a RIGHT/FULL OUTER join (the driving
    /// side is nullable), a semi/anti/apply/asof join, or a LEFT OUTER join with a `USING`/`NATURAL`/
    /// no constraint (no `ON` to inject the confinement into). Refused fail-closed — the ORM target
    /// path is INNER + LEFT-`ON` only, and the same read is expressible as a `LEFT … ON` join.
    UnsupportedJoin(String),
    /// The statement used a `WITH` (CTE). CTEs are refused in a raw-SQL target read (deny-by-default,
    /// matching the ORM target path, which does not support CTEs): a non-recursive CTE's body may
    /// reference the base table under the CTE's own name, and a recursive CTE references itself, so a
    /// name-based "is this a CTE reference?" test cannot soundly distinguish a base-table read from a
    /// CTE reference — the safe collapse is to refuse. The same read is expressible with a derived
    /// table / subquery, which IS confined.
    CteNotAllowed,
}

impl TargetRewriteError {
    /// A short, guest-safe reason (no tenant values leaked).
    pub fn reason(&self) -> String {
        match self {
            Self::Parse(m) => format!("tenancy(target): raw SQL did not parse: {m}"),
            Self::NotReadOnly => {
                "tenancy(target): a target read must be a single read-only SELECT".into()
            }
            Self::WriteInReadPosition => {
                "tenancy(target): a write is not allowed in a target read".into()
            }
            Self::UnsupportedTableSource(s) => {
                format!("tenancy(target): unsupported table source in a target read: {s}")
            }
            Self::QualifiedTableName(t) => format!(
                "tenancy(target): schema-qualified table name `{t}` is not allowed in a target \
                 read (use a bare table name)"
            ),
            Self::PublicSubsetUndeclared(t) => format!(
                "tenancy(target): table `{t}` declares no public subset (a target read may only \
                 reach tables with a declared public subset)"
            ),
            Self::TenancyUndeclared(t) => {
                format!("tenancy(target): table `{t}` is not declared in the tenancy schema")
            }
            Self::UnsupportedLiteral => {
                "tenancy(target): a confinement literal cannot be safely rendered".into()
            }
            Self::BadColumn(c) => format!("tenancy(target): misconfigured column `{c}`"),
            Self::EmptyConfinement(t) => {
                format!("tenancy(target): table `{t}` lowered to an empty confinement")
            }
            Self::MissingTarget => {
                "tenancy(target): no resolved target tenant for this request".into()
            }
            Self::CteNotAllowed => {
                "tenancy(target): a WITH/CTE is not allowed in a target read (use a subquery or \
                 derived table)"
                    .into()
            }
            Self::UnsupportedJoin(k) => format!(
                "tenancy(target): a {k} join is not allowed in a target read (use an INNER join or a \
                 LEFT … ON join)"
            ),
        }
    }
}

/// Rewrite a guest's **raw-SQL target read** so every table reference is confined to
/// `tenant = <tenant_value> AND <that table's public subset>` (R4/D8). `keys` and `public` are the
/// project schema's per-table tenant-key map and per-table lowered public-subset terms (exactly the
/// two maps a [`TableKeys::PerTableTarget`](crate::orm::TableKeys::PerTableTarget) carries);
/// `tenant_value` is the host-resolved target tenant `B` (NEVER guest input); `dialect` selects the
/// parser. Returns the rewritten SQL text (the guest's own positional params are untouched — `B`
/// and the public literals are injected as escaped literals), or a [`TargetRewriteError`]
/// (fail-closed — the read does not run).
#[allow(clippy::too_many_arguments)] // a confinement rewriter: each arg is a distinct host input.
pub fn rewrite_target_select(
    statement: &str,
    tenant_value: &SqlValue,
    keys: &BTreeMap<String, ResolvedScope>,
    public: &BTreeMap<String, Vec<PublicTermSql>>,
    require_public: bool,
    // `target_or_null` (v0.4.8): when `true`, a plain tenant (`Column`) table's confinement is
    // `(col = B OR col IS NULL)` — B's rows ⊕ the shared `NULL`-tenant base rows — instead of
    // `col = B`. Read-only; ONLY plain `Column` tables (never `TenantOrSession`/`Unscoped`).
    null_base: bool,
    dialect: Dialect,
) -> Result<String, TargetRewriteError> {
    let sp: Box<dyn SpDialect> = match dialect {
        Dialect::Sqlite => Box::new(SQLiteDialect {}),
        Dialect::Postgres => Box::new(PostgreSqlDialect {}),
        Dialect::Mysql => Box::new(MySqlDialect {}),
    };
    let mut statements =
        Parser::parse_sql(&*sp, statement).map_err(|e| TargetRewriteError::Parse(e.to_string()))?;
    // Exactly one, read-only, top-level query. A write/DDL, or a multi-statement batch, is refused
    // here (belt-and-suspenders with the write-axis grant, which is `None` under a target read).
    if statements.len() != 1 {
        return Err(TargetRewriteError::NotReadOnly);
    }
    match &statements[0] {
        Statement::Query(_) => {}
        _ => return Err(TargetRewriteError::NotReadOnly),
    }
    // Pre-render B once (fail-closed on a value we cannot render safely as a literal).
    let bound = value_expr(tenant_value)?;
    let mut rewriter = Rewriter {
        keys,
        public,
        require_public,
        bound,
        null_base,
    };
    if let ControlFlow::Break(err) = statements[0].visit(&mut rewriter) {
        return Err(err);
    }
    Ok(statements[0].to_string())
}

/// Best-effort extraction of the single tenant value a **raw-SQL `all` write** declares, so the host
/// can set the RLS tenant GUC to it (v0.4.20 — the raw-path analog of
/// [`Insert::uniform_scope_value`](crate::orm::Insert::uniform_scope_value) /
/// [`Update::pinned_scope_value`](crate::orm::Update::pinned_scope_value)). Parses `statement` and:
/// - **INSERT** → the uniform literal value of column `col` across all `VALUES` rows (`None` if `col`
///   is missing, a non-literal, rows disagree, an `INSERT … SELECT`, or not a single INSERT);
/// - **UPDATE** → the literal the WHERE pins `col` to at top level or within `AND`s (`None` for an
///   `OR`/`IN`/range/unpinned filter, or contradictory pins);
/// - anything else → `None`.
///
/// `col_for_table` maps the statement's target table to the tenant/scope column an RLS policy keys
/// on (the caller resolves it from the project schema — the identity table on its own PK, a data
/// table on `tenant_id`, an `Unscoped`/undeclared table to `None`). Returning `None` there ⇒ no GUC.
///
/// `None` fails **closed**: the GUC isn't re-set, so it keeps the prior per-transaction value (or
/// stays unset if none) — either way the DB's RLS (`WITH CHECK`/`USING`) can only *over*-restrict the
/// write, never widen it. The DB is the final arbiter, so a conservative (over-`None`) extractor is
/// safe — it can only make a legitimate write fail, never permit a cross-tenant one. Guest input never
/// reaches a predicate or the GUC name; only the *value* the write already carries sets the GUC.
/// The **target table** of a raw-SQL WRITE (`INSERT INTO t` / `UPDATE t` / `DELETE FROM t`),
/// lowercased-last-segment (`schema.t` → `t`), or `None` for a read / a non-single statement / an
/// unparsable / exotic-source write (#503). Used to resolve the write's declared scope on the
/// raw-SQL surface so the write-global / `unscoped_writes` exemption AGREES with the ORM
/// `write_target` (cross-surface parity). `None` fails **closed**: an unresolvable write table is
/// NOT treated as global, so the required-`{scope}`-marker rule still applies (deny-by-default) — a
/// conservative extractor can only keep a legitimate write marker-required, never exempt an
/// un-global one.
pub fn extract_raw_write_table(statement: &str, dialect: Dialect) -> Option<String> {
    use sqlparser::ast::{Statement, TableFactor};
    // The guest `sql` contract is numbered `?N` placeholders on EVERY backend — the storage layer
    // translates them to `$N` (Postgres) LATER, after this host tenancy layer runs. sqlparser's
    // Postgres dialect rejects `?N`, so parse the requested dialect first and FALL BACK to the
    // SQLite dialect (which tolerates `?N`) purely to recover the write's table name — the table of
    // an INSERT/UPDATE/DELETE is dialect-agnostic, so the fallback cannot mis-identify it. Without
    // this, a Postgres write-global write would fail to parse here (`None`) and be wrongly refused,
    // breaking the cross-surface parity on Postgres. (`extract_raw_write_scope_value` keeps the
    // old-dialect-only parse: `None` there merely leaves an RLS GUC unset, which fails safe.)
    let parse = |d: Dialect| -> Option<Vec<Statement>> {
        let sp: Box<dyn SpDialect> = match d {
            Dialect::Sqlite => Box::new(SQLiteDialect {}),
            Dialect::Postgres => Box::new(PostgreSqlDialect {}),
            Dialect::Mysql => Box::new(MySqlDialect {}),
        };
        Parser::parse_sql(&*sp, statement).ok()
    };
    let stmts = parse(dialect).or_else(|| {
        if dialect == Dialect::Sqlite {
            None
        } else {
            parse(Dialect::Sqlite)
        }
    })?;
    if stmts.len() != 1 {
        return None;
    }
    let table_of = |name: &sqlparser::ast::ObjectName| -> Option<String> {
        name.0.last().map(|i| i.value.clone())
    };
    match &stmts[0] {
        Statement::Insert(ins) => table_of(&ins.table_name),
        Statement::Update { table, .. } => match &table.relation {
            TableFactor::Table { name, .. } => table_of(name),
            _ => None,
        },
        Statement::Delete(del) => {
            // A DELETE names its table(s) either in `FROM` or (MySQL multi-table) `tables`.
            let from = match &del.from {
                sqlparser::ast::FromTable::WithFromKeyword(t)
                | sqlparser::ast::FromTable::WithoutKeyword(t) => t,
            };
            // A single-table DELETE only (multi-table / joined DELETE is not a global write — fail
            // closed to marker-required).
            if from.len() != 1 || !from[0].joins.is_empty() {
                return None;
            }
            match &from[0].relation {
                TableFactor::Table { name, .. } => table_of(name),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn extract_raw_write_scope_value(
    statement: &str,
    dialect: Dialect,
    col_for_table: impl Fn(&str) -> Option<String>,
) -> Option<SqlValue> {
    use sqlparser::ast::{BinaryOperator, Expr as E, SetExpr, Statement, TableFactor, Value as V};

    fn lit(v: &V) -> Option<SqlValue> {
        match v {
            V::SingleQuotedString(s) | V::DoubleQuotedString(s) => Some(SqlValue::Text(s.clone())),
            V::Number(n, _) => Some(
                n.parse::<i64>()
                    .map(SqlValue::Integer)
                    .unwrap_or_else(|_| SqlValue::Text(n.clone())),
            ),
            V::Boolean(b) => Some(SqlValue::Boolean(*b)),
            _ => None,
        }
    }
    fn col_name(e: &E) -> Option<String> {
        match e {
            E::Identifier(id) => Some(id.value.clone()),
            E::CompoundIdentifier(ids) => ids.last().map(|i| i.value.clone()),
            _ => None,
        }
    }
    // The literal `col = <lit>` pinned by a WHERE `Expr` at top level or within `AND`s.
    fn pinned(e: &E, col: &str) -> Option<SqlValue> {
        match e {
            E::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                if col_name(left).is_some_and(|c| c.eq_ignore_ascii_case(col))
                    && let E::Value(v) = right.as_ref()
                {
                    return lit(v);
                }
                if col_name(right).is_some_and(|c| c.eq_ignore_ascii_case(col))
                    && let E::Value(v) = left.as_ref()
                {
                    return lit(v);
                }
                None
            }
            E::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => match (pinned(left, col), pinned(right, col)) {
                (Some(a), Some(b)) if a == b => Some(a),
                (Some(a), None) | (None, Some(a)) => Some(a),
                _ => None, // both sides pin different tenants (contradiction) → fail closed
            },
            E::Nested(inner) => pinned(inner, col),
            _ => None,
        }
    }

    let sp: Box<dyn SpDialect> = match dialect {
        Dialect::Sqlite => Box::new(SQLiteDialect {}),
        Dialect::Postgres => Box::new(PostgreSqlDialect {}),
        Dialect::Mysql => Box::new(MySqlDialect {}),
    };
    let stmts = Parser::parse_sql(&*sp, statement).ok()?;
    if stmts.len() != 1 {
        return None;
    }
    // The last identifier of an `ObjectName` (`schema.table` → `table`), lowercased for lookup.
    let table_of = |name: &sqlparser::ast::ObjectName| -> Option<String> {
        name.0.last().map(|i| i.value.clone())
    };
    match &stmts[0] {
        Statement::Insert(ins) => {
            let col = col_for_table(&table_of(&ins.table_name)?)?;
            let idx = ins
                .columns
                .iter()
                .position(|c| c.value.eq_ignore_ascii_case(&col))?;
            let rows = match ins.source.as_ref()?.body.as_ref() {
                SetExpr::Values(vals) => &vals.rows,
                _ => return None, // INSERT … SELECT (or other) — no literal row values
            };
            if rows.is_empty() {
                return None;
            }
            let mut found: Option<SqlValue> = None;
            for row in rows {
                let v = match row.get(idx)? {
                    E::Value(v) => lit(v)?,
                    _ => return None,
                };
                match &found {
                    None => found = Some(v),
                    Some(prev) if *prev == v => {}
                    Some(_) => return None,
                }
            }
            found
        }
        Statement::Update {
            table,
            selection: Some(where_),
            ..
        } => {
            let name = match &table.relation {
                TableFactor::Table { name, .. } => name,
                _ => return None,
            };
            let col = col_for_table(&table_of(name)?)?;
            pinned(where_, &col)
        }
        _ => None,
    }
}

/// The mutating visitor that injects the per-table confinement. `WITH`/CTEs are refused up front
/// (see [`TargetRewriteError::CteNotAllowed`]), so — because derived tables are `TableFactor::Derived`
/// and subqueries are their own `Query` nodes — a `TableFactor::Table` bare name is ALWAYS a base
/// table (never a CTE reference). That removes the need to track a CTE-name scope, and with it the
/// scope foot-gun class entirely: every base table is unconditionally confined.
struct Rewriter<'a> {
    keys: &'a BTreeMap<String, ResolvedScope>,
    public: &'a BTreeMap<String, Vec<PublicTermSql>>,
    /// Whether a per-table public subset is mandatory (R4/D8 5c ruling A): `true` for domain/handle
    /// (an undeclared subset ⇒ refuse); `false` for a `capability`-only field (an undeclared subset ⇒
    /// confine to `tenant = B` alone — the capability is the authorization).
    require_public: bool,
    /// The host-resolved target tenant `B`, pre-rendered as a literal expression.
    bound: Expr,
    /// `target_or_null` (v0.4.8): widen a plain `Column` table's tenant confinement from `col = B`
    /// to `(col = B OR col IS NULL)` — B ⊕ the shared `NULL`-tenant base rows.
    null_base: bool,
}

impl VisitorMut for Rewriter<'_> {
    type Break = TargetRewriteError;

    fn pre_visit_query(&mut self, query: &mut Query) -> ControlFlow<Self::Break> {
        // Refuse any CTE (deny-by-default): a non-recursive CTE body may reference the base table
        // under the CTE's own name, and a recursive CTE references itself, so a name-based test
        // cannot soundly tell a base-table read from a CTE reference. The same read is expressible
        // with a derived table / subquery, which is confined.
        if query.with.is_some() {
            return ControlFlow::Break(TargetRewriteError::CteNotAllowed);
        }
        // Confine every SELECT directly in this query's body (through set-operation arms). Nested
        // queries (derived tables, expression subqueries, `SetExpr::Query`) are separate `Query`
        // nodes and receive their own `pre_visit_query`.
        if let Err(e) = self.confine_body(&mut query.body) {
            return ControlFlow::Break(e);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(
        &mut self,
        table_factor: &mut TableFactor,
    ) -> ControlFlow<Self::Break> {
        // Belt-and-suspenders: refuse any un-confinable table source ANYWHERE in the tree, resting on
        // sqlparser's exhaustive traversal rather than on the confinement walk reaching every FROM.
        // (Recognised sources — a bare base table, a derived subquery, a nested join — pass; the
        // confinement itself is applied per-SELECT in `confine_body`.)
        match table_factor {
            TableFactor::Table { args: Some(_), .. } => ControlFlow::Break(
                TargetRewriteError::UnsupportedTableSource("table-valued function".into()),
            ),
            TableFactor::Table { name, .. } if name.0.len() != 1 => ControlFlow::Break(
                TargetRewriteError::QualifiedTableName(object_name_string(name)),
            ),
            TableFactor::Table { .. }
            | TableFactor::Derived { .. }
            | TableFactor::NestedJoin { .. } => ControlFlow::Continue(()),
            other => ControlFlow::Break(TargetRewriteError::UnsupportedTableSource(
                table_factor_kind(other).into(),
            )),
        }
    }
}

impl Rewriter<'_> {
    /// Confine every `SELECT` reachable in this `SetExpr` at THIS query level (through set-operation
    /// arms), refusing writes smuggled into a read position. Nested `Query` nodes are left to their
    /// own `pre_visit_query`.
    fn confine_body(&self, body: &mut SetExpr) -> Result<(), TargetRewriteError> {
        match body {
            SetExpr::Select(select) => self.confine_select(select),
            SetExpr::SetOperation { left, right, .. } => {
                self.confine_body(left)?;
                self.confine_body(right)
            }
            // A nested parenthesised query / constant rows: handled by the query's own visit (a
            // subquery inside a VALUES row is itself a `Query` node and is confined there).
            SetExpr::Query(_) | SetExpr::Values(_) => Ok(()),
            // Writes are never a target read.
            SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Table(_) => {
                Err(TargetRewriteError::WriteInReadPosition)
            }
        }
    }

    /// Conjoin `tenant = B AND <public>` for each base table in this `SELECT` onto the RIGHT
    /// position: the driving relation and every INNER/CROSS-joined table go onto the top-level
    /// `WHERE` (the guest's own `WHERE` parenthesised first, so a top-level `OR` cannot widen past
    /// the gate — closes M2); a **LEFT-OUTER**-joined table's confinement goes onto that join's own
    /// `ON` (its guest `ON` parenthesised first). Confining a LEFT-joined table in the top-level
    /// `WHERE` would collapse the LEFT JOIN to an INNER JOIN — dropping the driving row when there is
    /// no match — so a routed tenant with no matching joined row would vanish and a SELECT-list
    /// `COALESCE(joined.col, driving.col)` fallback would never fire. In the `ON`, an unmatched /
    /// other-tenant row instead becomes `NULL` (never a cross-tenant bleed — the tenant/public gate
    /// is AND-ed into the join condition), and the fallback correctly resolves to the (confined)
    /// driving value. CTE references and derived tables are skipped (confined at their own level).
    /// RIGHT/FULL OUTER, semi/anti/apply/asof joins, and a LEFT OUTER with a `USING`/`NATURAL`/no
    /// constraint are refused fail-closed: the ORM target path is INNER + LEFT-`ON` only, and the
    /// same read is expressible as a `LEFT … ON` join.
    fn confine_select(&self, select: &mut Select) -> Result<(), TargetRewriteError> {
        // `SELECT … INTO t` materialises a table — a write in a read position.
        if select.into.is_some() {
            return Err(TargetRewriteError::WriteInReadPosition);
        }
        // Confinement destined for the top-level `WHERE`: the non-nullable positions — the driving
        // relation and every INNER/CROSS join. A LEFT-OUTER join injects into its own `ON` below.
        let mut where_conf: Option<Expr> = None;
        for twj in &mut select.from {
            self.accumulate_relation(&twj.relation, &mut where_conf)?;
            for join in &mut twj.joins {
                match &mut join.join_operator {
                    JoinOperator::Inner(_) | JoinOperator::CrossJoin => {
                        self.accumulate_relation(&join.relation, &mut where_conf)?;
                    }
                    JoinOperator::LeftOuter(JoinConstraint::On(on)) => {
                        let mut on_conf: Option<Expr> = None;
                        self.accumulate_relation(&join.relation, &mut on_conf)?;
                        if let Some(conf) = on_conf {
                            // `(<guest ON>) AND <confinement>` — the same OR-escape closure as the
                            // WHERE path, in the join's own ON so LEFT-JOIN semantics are preserved.
                            let existing = on.clone();
                            *on = and(Expr::Nested(Box::new(existing)), conf);
                        }
                    }
                    other => {
                        return Err(TargetRewriteError::UnsupportedJoin(
                            join_operator_kind(other).into(),
                        ));
                    }
                }
            }
        }
        let Some(confinement) = where_conf else {
            // No base table needed a WHERE predicate (all confinement landed in LEFT-join ONs, or a
            // capability field's global reference tables) — nothing to add here.
            return Ok(());
        };
        select.selection = Some(match select.selection.take() {
            // Parenthesise the guest's predicate: `(<guest WHERE>) AND <confinement>` — a top-level
            // OR in the guest predicate can never escape the tenant/public gate (closes M2).
            Some(existing) => and(Expr::Nested(Box::new(existing)), confinement),
            None => confinement,
        });
        Ok(())
    }

    /// Accumulate (via `AND`) the confinement predicate for every base table in a `FROM` factor —
    /// its own table, plus, for a `NESTED JOIN`, each nested relation — into `acc`. Derived tables
    /// and CTE references are skipped (confined at their own query level). A table-valued function,
    /// a schema-qualified name, or any un-confinable source is refused fail-closed. (A base table
    /// that needs no predicate — a `capability` field's global `Unscoped` reference table — adds
    /// nothing; the confined tables still gate the row set.)
    fn accumulate_relation(
        &self,
        factor: &TableFactor,
        acc: &mut Option<Expr>,
    ) -> Result<(), TargetRewriteError> {
        match factor {
            TableFactor::Table { args: Some(_), .. } => Err(
                TargetRewriteError::UnsupportedTableSource("table-valued function".into()),
            ),
            TableFactor::Table { name, alias, .. } => {
                if name.0.len() != 1 {
                    return Err(TargetRewriteError::QualifiedTableName(object_name_string(
                        name,
                    )));
                }
                // With CTEs refused, a bare `TableFactor::Table` is unconditionally a base table.
                let base = name.0[0].value.clone();
                // The qualifier columns will be referenced by: the alias if present, else the
                // table's own identifier (cloned to preserve any quoting).
                let qualifier = alias
                    .as_ref()
                    .map(|a| a.name.clone())
                    .unwrap_or_else(|| name.0[0].clone());
                if let Some(pred) = self.table_confinement(&base, &qualifier)? {
                    *acc = Some(match acc.take() {
                        Some(a) => and(a, pred),
                        None => pred,
                    });
                }
                Ok(())
            }
            // A derived table is a nested `Query` — confined by its own `pre_visit_query`; its alias
            // is a logical name, not a base table.
            TableFactor::Derived { .. } => Ok(()),
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => {
                self.accumulate_relation(&table_with_joins.relation, acc)?;
                for join in &table_with_joins.joins {
                    self.accumulate_relation(&join.relation, acc)?;
                }
                Ok(())
            }
            other => Err(TargetRewriteError::UnsupportedTableSource(
                table_factor_kind(other).into(),
            )),
        }
    }

    /// The confinement predicate for one base table: `qualifier.tenant = B` (unless the table is
    /// `Unscoped`) `AND` the table's public-subset terms (each qualified). `Ok(None)` when the table
    /// needs no predicate at all (a `capability`-only field's global/`Unscoped` reference table).
    /// Deny-by-default: a table with no declared tenant key is refused; under `require_public`
    /// (domain/handle) a table with no declared public subset is refused.
    fn table_confinement(
        &self,
        table: &str,
        qualifier: &Ident,
    ) -> Result<Option<Expr>, TargetRewriteError> {
        // The public terms. Ruling A (v0.4.4), made COMPLETE: under a `capability`-only field
        // (`!require_public`) the visibility subset is INERT — confine to `tenant = B` alone
        // (applied below) and apply NO per-table subset, not even a DECLARED one. A subset authored
        // for the anonymous domain/handle funnel (e.g. `client_id IS NULL`) must not narrow a
        // capability read: it collides with the resolver's own in-guest per-`sub` filter and would
        // empty the result. The host-verified, project-audience-bound capability + that in-guest
        // filter is the authorization. Under `require_public` (domain/handle — the visibility
        // predicate is the only guard for an anonymous actor; and any `target_or_null`, whose shared
        // NULL-base arm v0.4.8 forces the subset even under a capability) a declared subset is
        // applied and an undeclared one is refused (deny-by-default).
        let empty: Vec<PublicTermSql> = Vec::new();
        let terms = if !self.require_public {
            &empty
        } else {
            match self.public.get(table) {
                Some(t) => t,
                None => {
                    return Err(TargetRewriteError::PublicSubsetUndeclared(
                        table.to_string(),
                    ));
                }
            }
        };
        let resolved = self
            .keys
            .get(table)
            .ok_or_else(|| TargetRewriteError::TenancyUndeclared(table.to_string()))?;

        let mut parts: Vec<Expr> = Vec::new();
        match resolved {
            ResolvedScope::Column(col) => {
                check_ident(col)?;
                let eq = binop(
                    col_expr(qualifier, col),
                    BinaryOperator::Eq,
                    self.bound.clone(),
                );
                // `target_or_null`: `(col = B OR col IS NULL)` — B's rows ⊕ the shared base. ONLY on
                // a plain `Column` (tenant) table; the `TenantOrSession` arm below never ORs in NULL
                // (its NULL partition is session rows, not shared base — that would leak).
                parts.push(if self.null_base {
                    Expr::Nested(Box::new(or(
                        eq,
                        Expr::IsNull(Box::new(col_expr(qualifier, col))),
                    )))
                } else {
                    eq
                });
            }
            // A base-inclusive table folds its shared `tenant IS NULL` base into EVERY target read:
            // `(col = B OR col IS NULL)`, regardless of the field's `null_base` — the per-table analog
            // of `target_or_null`. The per-tenant (non-NULL) rows keep the `tenant = B` boundary; only
            // the NULL rows are shared. (The public subset below still applies on the target axis.)
            ResolvedScope::TenantOrBase { tenant } => {
                check_ident(tenant)?;
                let eq = binop(
                    col_expr(qualifier, tenant),
                    BinaryOperator::Eq,
                    self.bound.clone(),
                );
                parts.push(Expr::Nested(Box::new(or(
                    eq,
                    Expr::IsNull(Box::new(col_expr(qualifier, tenant))),
                ))));
            }
            // A globally-readable table carries no tenant predicate — only its public subset (which
            // must still be declared and non-empty, exactly as the ORM target path requires). A
            // write-global table (#503 `SharedWritable`) is READ-identical here (G2): a target READ
            // of it carries no tenant predicate either. (A target WRITE never reaches the rewriter —
            // raw-SQL target writes are refused, and the write-global write arm is `!is_target`.)
            ResolvedScope::Unscoped | ResolvedScope::SharedWritable => {}
            // Under a target read the principal carries only the `TargetTenant` fact `B` (no session
            // fact), so the R3 disjunct collapses to the single tenant arm `tenant = B`.
            ResolvedScope::TenantOrSession { tenant, .. } => {
                check_ident(tenant)?;
                parts.push(binop(
                    col_expr(qualifier, tenant),
                    BinaryOperator::Eq,
                    self.bound.clone(),
                ));
            }
        }
        for term in terms {
            match term {
                PublicTermSql::Cmp { column, op, value } => {
                    check_ident(column)?;
                    parts.push(binop(
                        col_expr(qualifier, column),
                        cmp_operator(*op),
                        value_expr(value)?,
                    ));
                }
                PublicTermSql::Null { column, negated } => {
                    check_ident(column)?;
                    let e = Box::new(col_expr(qualifier, column));
                    parts.push(if *negated {
                        Expr::IsNotNull(e)
                    } else {
                        Expr::IsNull(e)
                    });
                }
            }
        }
        // AND all parts. Empty ⇒ no confinement for this table: an `Unscoped` global reference table
        // under a `capability`-only field (no tenant column, no declared subset) — read globally,
        // exactly as the own/GDC paths treat `Unscoped`. Under `require_public` this is unreachable
        // (a Column table always adds `tenant = B`; an `Unscoped`/undeclared-subset table was already
        // refused), so a domain/handle read can never end up unconfined.
        let mut it = parts.into_iter();
        let Some(first) = it.next() else {
            return Ok(None);
        };
        Ok(Some(it.fold(first, and)))
    }
}

/// `<qualifier>.<column>` as a compound identifier (the qualifier `Ident` is cloned as-is to
/// preserve any quoting of the table name/alias).
fn col_expr(qualifier: &Ident, column: &str) -> Expr {
    Expr::CompoundIdentifier(vec![qualifier.clone(), Ident::new(column)])
}

fn binop(left: Expr, op: BinaryOperator, right: Expr) -> Expr {
    Expr::BinaryOp {
        left: Box::new(left),
        op,
        right: Box::new(right),
    }
}

/// `left AND right`.
fn and(left: Expr, right: Expr) -> Expr {
    binop(left, BinaryOperator::And, right)
}

/// `left OR right` — the `target_or_null` tenant disjunct (`col = B OR col IS NULL`).
fn or(left: Expr, right: Expr) -> Expr {
    binop(left, BinaryOperator::Or, right)
}

fn cmp_operator(op: CmpOp) -> BinaryOperator {
    match op {
        CmpOp::Eq => BinaryOperator::Eq,
        CmpOp::Ne => BinaryOperator::NotEq,
        CmpOp::Lt => BinaryOperator::Lt,
        CmpOp::Le => BinaryOperator::LtEq,
        CmpOp::Gt => BinaryOperator::Gt,
        CmpOp::Ge => BinaryOperator::GtEq,
    }
}

/// Render a host-held [`SqlValue`] as a safe SQL literal expression. Text is single-quoted through
/// sqlparser's escaping (doubles embedded quotes); numbers/booleans are rendered verbatim. A blob,
/// JSON, NULL, or non-finite float — none of which a tenant value or a lowered public literal is —
/// is refused (fail-closed) rather than rendered ambiguously.
fn value_expr(value: &SqlValue) -> Result<Expr, TargetRewriteError> {
    Ok(Expr::Value(match value {
        SqlValue::Text(s) => Value::SingleQuotedString(s.clone()),
        SqlValue::Integer(i) => Value::Number(i.to_string(), false),
        SqlValue::Boolean(b) => Value::Boolean(*b),
        SqlValue::Real(f) if f.is_finite() => Value::Number(f.to_string(), false),
        SqlValue::Real(_) | SqlValue::Null | SqlValue::Blob(_) | SqlValue::Json(_) => {
            return Err(TargetRewriteError::UnsupportedLiteral);
        }
    }))
}

/// A conservative SQL-identifier check (matches the tenant-column check on the applied side):
/// non-empty, ASCII alphanumeric or `_`, not starting with a digit.
fn check_ident(s: &str) -> Result<(), TargetRewriteError> {
    let mut chars = s.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(TargetRewriteError::BadColumn(s.to_string()))
    }
}

/// A dotted rendering of a (rejected) qualified table name, for the error message only.
fn object_name_string(name: &sqlparser::ast::ObjectName) -> String {
    name.0
        .iter()
        .map(|i| i.value.clone())
        .collect::<Vec<_>>()
        .join(".")
}

/// A short label for a rejected exotic table factor (error message only).
fn table_factor_kind(factor: &TableFactor) -> &'static str {
    match factor {
        TableFactor::Table { .. } => "table",
        TableFactor::Derived { .. } => "derived subquery",
        TableFactor::TableFunction { .. } => "table function",
        TableFactor::Function { .. } => "function",
        TableFactor::UNNEST { .. } => "UNNEST",
        TableFactor::JsonTable { .. } => "JSON_TABLE",
        TableFactor::OpenJsonTable { .. } => "OPENJSON",
        TableFactor::NestedJoin { .. } => "nested join",
        TableFactor::Pivot { .. } => "PIVOT",
        TableFactor::Unpivot { .. } => "UNPIVOT",
        TableFactor::MatchRecognize { .. } => "MATCH_RECOGNIZE",
    }
}

/// A short, guest-safe name for a join operator the target-read confinement refuses (used only in
/// the `UnsupportedJoin` error). INNER + `CROSS` + LEFT-`ON` are handled and never reach here.
fn join_operator_kind(op: &JoinOperator) -> &'static str {
    match op {
        JoinOperator::RightOuter(_) => "RIGHT OUTER",
        JoinOperator::FullOuter(_) => "FULL OUTER",
        JoinOperator::LeftOuter(_) => "LEFT OUTER (USING/NATURAL)",
        JoinOperator::Semi(_) | JoinOperator::LeftSemi(_) | JoinOperator::RightSemi(_) => "SEMI",
        JoinOperator::Anti(_) | JoinOperator::LeftAnti(_) | JoinOperator::RightAnti(_) => "ANTI",
        JoinOperator::CrossApply | JoinOperator::OuterApply => "APPLY",
        JoinOperator::AsOf { .. } => "ASOF",
        // INNER + CROSS are handled; LEFT-`ON` is handled. Anything else is an unsupported outer join.
        JoinOperator::Inner(_) | JoinOperator::CrossJoin => "unsupported",
    }
}

#[cfg(test)]
mod raw_write_scope_value_tests {
    use super::*;

    // Resolve the tenant column: `tenant`'s identity PK is `id`, everything else `tenant_id`;
    // an `unscoped` table has none.
    fn col_for(t: &str) -> Option<String> {
        match t {
            "tenant" => Some("id".into()),
            "unscoped" => None,
            _ => Some("tenant_id".into()),
        }
    }
    fn extract(sql: &str) -> Option<SqlValue> {
        extract_raw_write_scope_value(sql, Dialect::Postgres, col_for)
    }
    fn text(s: &str) -> SqlValue {
        SqlValue::Text(s.to_string())
    }

    #[test]
    fn extract_raw_write_table_finds_the_write_target_on_every_dialect() {
        // #503: the write-table extractor recovers the INSERT/UPDATE/DELETE target on all dialects,
        // INCLUDING with `?N` placeholders under the Postgres dialect (which sqlparser's PG parser
        // rejects natively — the SQLite fallback recovers the table name). Reads / multi-table /
        // exotic sources → None (fail-closed → the write stays marker-required).
        for d in [Dialect::Sqlite, Dialect::Postgres, Dialect::Mysql] {
            assert_eq!(
                extract_raw_write_table("INSERT INTO oauth_state (state) VALUES (?1)", d),
                Some("oauth_state".into()),
                "INSERT on {d:?}"
            );
            assert_eq!(
                extract_raw_write_table("UPDATE app.orders SET status = ?1 WHERE id = ?2", d),
                Some("orders".into()),
                "UPDATE (schema-qualified) on {d:?}"
            );
            assert_eq!(
                extract_raw_write_table("DELETE FROM sessions WHERE id = ?1", d),
                Some("sessions".into()),
                "DELETE on {d:?}"
            );
            // A read is not a write target.
            assert_eq!(
                extract_raw_write_table("SELECT * FROM orders WHERE id = ?1", d),
                None,
                "SELECT on {d:?}"
            );
            // Unparsable → None (fail-closed).
            assert_eq!(extract_raw_write_table("NOT SQL AT ALL", d), None);
        }
    }

    #[test]
    fn insert_and_update_extract_a_single_declared_tenant_else_none() {
        // INSERT single row → the row's tenant.
        assert_eq!(
            extract("INSERT INTO audit_event (tenant_id, kind) VALUES ('A','x')"),
            Some(text("A"))
        );
        // A TenantKeyed identity table resolves its PK column.
        assert_eq!(
            extract("INSERT INTO tenant (id, name) VALUES ('A','Acme')"),
            Some(text("A"))
        );
        // Multi-row agreeing → the shared value; disagreeing → None.
        assert_eq!(
            extract("INSERT INTO audit_event (tenant_id, kind) VALUES ('A','x'),('A','y')"),
            Some(text("A"))
        );
        assert_eq!(
            extract("INSERT INTO audit_event (tenant_id, kind) VALUES ('A','x'),('B','y')"),
            None
        );
        // UPDATE pinned by the WHERE → the tenant; unpinned / OR → None.
        assert_eq!(
            extract("UPDATE audit_event SET kind='x' WHERE tenant_id = 'A'"),
            Some(text("A"))
        );
        assert_eq!(
            extract("UPDATE audit_event SET kind='x' WHERE tenant_id='A' AND kind='k'"),
            Some(text("A"))
        );
        assert_eq!(
            extract("UPDATE audit_event SET kind='x' WHERE tenant_id='A' OR tenant_id='B'"),
            None
        );
        assert_eq!(
            extract("UPDATE audit_event SET kind='x' WHERE kind='k'"),
            None
        );
        // No per-tenant column (unscoped table) → None.
        assert_eq!(
            extract("INSERT INTO unscoped (tenant_id) VALUES ('A')"),
            None
        );
        // INSERT … SELECT, a read, or garbage → None (fail-closed).
        assert_eq!(
            extract("INSERT INTO audit_event (tenant_id) SELECT tenant_id FROM other"),
            None
        );
        assert_eq!(extract("SELECT 1"), None);
        assert_eq!(extract("not sql at all ;;"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> BTreeMap<String, ResolvedScope> {
        BTreeMap::from([
            (
                "products".to_string(),
                ResolvedScope::Column("tenant_id".to_string()),
            ),
            (
                "reviews".to_string(),
                ResolvedScope::Column("tenant_id".to_string()),
            ),
            ("countries".to_string(), ResolvedScope::Unscoped),
        ])
    }

    fn public() -> BTreeMap<String, Vec<PublicTermSql>> {
        BTreeMap::from([
            (
                "products".to_string(),
                vec![PublicTermSql::Cmp {
                    column: "published".to_string(),
                    op: CmpOp::Eq,
                    value: SqlValue::Boolean(true),
                }],
            ),
            (
                "reviews".to_string(),
                vec![PublicTermSql::Cmp {
                    column: "visible".to_string(),
                    op: CmpOp::Eq,
                    value: SqlValue::Boolean(true),
                }],
            ),
        ])
    }

    fn b() -> SqlValue {
        SqlValue::Text("tenant_B".to_string())
    }

    fn rewrite(sql: &str) -> Result<String, TargetRewriteError> {
        // Default helper tests the anonymous (domain/handle) path: public subset mandatory.
        rewrite_target_select(sql, &b(), &keys(), &public(), true, false, Dialect::Sqlite)
    }

    /// Rewrite under a `capability`-only field (`require_public = false`): a table with no declared
    /// public subset confines to `tenant = B` alone.
    fn rewrite_cap(sql: &str) -> Result<String, TargetRewriteError> {
        rewrite_target_select(sql, &b(), &keys(), &public(), false, false, Dialect::Sqlite)
    }

    /// Rewrite under `target_or_null` (`null_base = true`): a plain tenant table's confinement widens
    /// to `(col = B OR col IS NULL)` — B's rows ⊕ the shared base — still AND the public subset.
    fn rewrite_null_base(sql: &str) -> Result<String, TargetRewriteError> {
        rewrite_target_select(sql, &b(), &keys(), &public(), true, true, Dialect::Sqlite)
    }

    #[test]
    fn target_or_null_widens_a_tenant_table_to_include_the_null_base() {
        // The base⊕B read: B's rows OR the shared `NULL`-tenant base rows, still confined to the
        // public subset. The OR is parenthesized so the AND-ed public term can't rebind it.
        let out = rewrite_null_base("SELECT id FROM products").unwrap();
        assert_eq!(
            out,
            "SELECT id FROM products WHERE (products.tenant_id = 'tenant_B' OR products.tenant_id IS NULL) AND products.published = true"
        );
        // `target` (null_base = false) still reads B alone — no base leak into the non-null-base case.
        assert_eq!(
            rewrite("SELECT id FROM products").unwrap(),
            "SELECT id FROM products WHERE products.tenant_id = 'tenant_B' AND products.published = true"
        );
    }

    #[test]
    fn tenant_or_base_table_folds_the_null_base_under_a_plain_target_read() {
        // v0.4.16: a PER-TABLE base-inclusive `pack` folds `(tenant = B OR tenant IS NULL)` even under
        // a plain `target` field (null_base = false) — B's packs ⊕ the shared base — while a plain
        // `products` table in the SAME read stays `tenant = B` alone. No field-level widening.
        let keys = BTreeMap::from([
            (
                "pack".to_string(),
                ResolvedScope::TenantOrBase {
                    tenant: "tenant_id".to_string(),
                },
            ),
            (
                "products".to_string(),
                ResolvedScope::Column("tenant_id".to_string()),
            ),
        ]);
        let public = BTreeMap::from([
            (
                "pack".to_string(),
                vec![PublicTermSql::Cmp {
                    column: "published".to_string(),
                    op: CmpOp::Eq,
                    value: SqlValue::Boolean(true),
                }],
            ),
            (
                "products".to_string(),
                vec![PublicTermSql::Cmp {
                    column: "published".to_string(),
                    op: CmpOp::Eq,
                    value: SqlValue::Boolean(true),
                }],
            ),
        ]);
        // Plain `target` read (require_public = true, null_base = false) over a join of both tables.
        let out = rewrite_target_select(
            "SELECT p.id FROM pack p JOIN products x ON x.id = p.product_id",
            &b(),
            &keys,
            &public,
            true,
            false,
            Dialect::Sqlite,
        )
        .unwrap();
        // `pack` (base-inclusive): (p.tenant_id = B OR p.tenant_id IS NULL) AND p.published.
        assert!(
            out.contains(
                "(p.tenant_id = 'tenant_B' OR p.tenant_id IS NULL) AND p.published = true"
            ),
            "base-inclusive pack folds the NULL base: {out}"
        );
        // `products` (plain tenant): x.tenant_id = B alone — no base fold on the sibling table.
        assert!(
            out.contains("x.tenant_id = 'tenant_B' AND x.published = true")
                && !out.contains("x.tenant_id IS NULL"),
            "the plain tenant table stays tenant-only (per-table, not per-field): {out}"
        );
    }

    #[test]
    fn simple_select_is_confined() {
        let out = rewrite("SELECT id FROM products").unwrap();
        assert_eq!(
            out,
            "SELECT id FROM products WHERE products.tenant_id = 'tenant_B' AND products.published = true"
        );
    }

    #[test]
    fn capability_confines_tenant_only_when_no_subset_but_domain_handle_refuses() {
        use std::collections::BTreeMap;
        // `orders` is a plain tenant table with NO declared public subset.
        let keys = BTreeMap::from([(
            "orders".to_string(),
            ResolvedScope::Column("tenant_id".to_string()),
        )]);
        let public = BTreeMap::new();
        // capability-only (require_public = false): confine to `tenant = B` alone (no visibility
        // predicate) — the capability is the authorization; per-client stays in-guest.
        let out = rewrite_target_select(
            "SELECT id FROM orders WHERE total > 10",
            &b(),
            &keys,
            &public,
            false,
            false,
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "SELECT id FROM orders WHERE (total > 10) AND orders.tenant_id = 'tenant_B'"
        );
        // domain/handle (require_public = true): the SAME table is refused — an anonymous actor needs
        // the visibility predicate as its only guard.
        let err = rewrite_target_select(
            "SELECT id FROM orders",
            &b(),
            &keys,
            &public,
            true,
            false,
            Dialect::Sqlite,
        )
        .unwrap_err();
        assert!(
            matches!(err, TargetRewriteError::PublicSubsetUndeclared(ref t) if t == "orders"),
            "{err:?}"
        );
        // Ruling A COMPLETE: a table that DOES declare a subset is confined to `tenant = B` ALONE
        // under a capability — the declared subset (authored for the anonymous funnel) is NOT applied.
        let out = rewrite_cap("SELECT id FROM products").unwrap();
        assert_eq!(
            out,
            "SELECT id FROM products WHERE products.tenant_id = 'tenant_B'"
        );
        assert!(
            !out.contains("published"),
            "declared subset must be inert on the capability axis: {out}"
        );
    }

    #[test]
    fn capability_drops_declared_subset_so_a_resolver_filter_on_that_column_survives() {
        // The construens embed bug: `products` declares `published = true` for the anonymous funnel,
        // but a capability read filters on that same column for its own within-tenant purpose. The
        // declared subset must NOT be AND-ed on (it would collide), and the guest's own predicate is
        // preserved verbatim inside its parenthesised group — confined only by `tenant = B`.
        let out = rewrite_cap("SELECT id FROM products WHERE published = false").unwrap();
        assert_eq!(
            out,
            "SELECT id FROM products WHERE (published = false) AND products.tenant_id = 'tenant_B'"
        );
        // Every joined table that declares a subset is ALSO confined to `tenant = B` alone (the
        // reviews subset `visible = true` is not applied), so a capability read across a join is not
        // silently emptied by a funnel subset on the joined table.
        let out = rewrite_cap("SELECT p.id FROM products p JOIN reviews r ON r.product_id = p.id")
            .unwrap();
        assert!(out.contains("p.tenant_id = 'tenant_B'"), "{out}");
        assert!(out.contains("r.tenant_id = 'tenant_B'"), "{out}");
        assert!(
            !out.contains("published") && !out.contains("visible"),
            "no declared subset on either table under a capability: {out}"
        );
    }

    #[test]
    fn existing_where_is_parenthesised_so_a_top_level_or_cannot_escape() {
        // The classic M2 escape: `WHERE 1=1 OR <anything>`. The guest predicate is parenthesised and
        // the confinement AND-ed on, so it can never widen past `tenant = B AND published`.
        let out = rewrite("SELECT id FROM products WHERE price < 10 OR 1 = 1").unwrap();
        assert_eq!(
            out,
            "SELECT id FROM products WHERE (price < 10 OR 1 = 1) AND products.tenant_id = 'tenant_B' AND products.published = true"
        );
    }

    #[test]
    fn every_join_is_confined() {
        let out = rewrite(
            "SELECT p.id FROM products p JOIN reviews r ON r.product_id = p.id WHERE p.price < 10",
        )
        .unwrap();
        // BOTH the aliased root and the aliased join are confined on their own alias.
        assert!(
            out.contains("p.tenant_id = 'tenant_B' AND p.published = true"),
            "{out}"
        );
        assert!(
            out.contains("r.tenant_id = 'tenant_B' AND r.visible = true"),
            "{out}"
        );
    }

    #[test]
    fn left_join_confines_the_joined_table_in_its_own_on_not_the_where() {
        // A LEFT JOIN's joined table is confined in its OWN `ON` (so an unmatched / other-tenant row
        // becomes NULL, never dropping the driving row or bleeding) — the driving table stays in the
        // WHERE. Confining the joined table in the WHERE would collapse the LEFT JOIN to an INNER
        // JOIN (dropping a no-config driving row so a SELECT-list COALESCE fallback never fires).
        let out = rewrite(
            "SELECT p.id, COALESCE(r.body, p.fallback) FROM products p \
             LEFT JOIN reviews r ON r.product_id = p.id",
        )
        .unwrap();
        // The joined `reviews` confinement is in the ON (parenthesising the guest ON), AND-ed on:
        assert!(
            out.contains(
                "LEFT JOIN reviews AS r ON (r.product_id = p.id) AND r.tenant_id = 'tenant_B' AND r.visible = true"
            ),
            "joined table confined in the ON: {out}"
        );
        // ...the driving `products` is in the WHERE, and `reviews` is NOT confined in the WHERE.
        assert!(
            out.contains("WHERE p.tenant_id = 'tenant_B' AND p.published = true"),
            "driving table confined in the WHERE: {out}"
        );
        assert!(
            !out.contains("WHERE p.tenant_id = 'tenant_B' AND p.published = true AND r."),
            "the LEFT-joined table must NOT be in the WHERE (would collapse to INNER): {out}"
        );
    }

    #[test]
    fn a_left_join_with_a_top_level_or_in_its_on_cannot_escape_the_gate() {
        // The guest's ON is parenthesised before the confinement is AND-ed, so a top-level OR in it
        // can never widen past `tenant = B AND <public>` (the join-ON analog of the M2 WHERE closure).
        let out = rewrite(
            "SELECT p.id FROM products p LEFT JOIN reviews r ON r.product_id = p.id OR 1 = 1",
        )
        .unwrap();
        assert!(
            out.contains(
                "ON (r.product_id = p.id OR 1 = 1) AND r.tenant_id = 'tenant_B' AND r.visible = true"
            ),
            "the guest ON's top-level OR is parenthesised inside the gate: {out}"
        );
    }

    #[test]
    fn a_right_or_full_outer_join_is_refused() {
        // RIGHT/FULL OUTER (nullable driving side) can't be soundly confined in the WHERE or a single
        // join ON — refused fail-closed (the same read is a LEFT … ON join).
        for sql in [
            "SELECT p.id FROM products p RIGHT JOIN reviews r ON r.product_id = p.id",
            "SELECT p.id FROM products p FULL OUTER JOIN reviews r ON r.product_id = p.id",
        ] {
            assert!(
                matches!(
                    rewrite(sql).unwrap_err(),
                    TargetRewriteError::UnsupportedJoin(_)
                ),
                "must refuse: {sql}"
            );
        }
    }

    #[test]
    fn subquery_in_where_is_confined() {
        let out = rewrite(
            "SELECT id FROM products WHERE id IN (SELECT product_id FROM reviews WHERE visible = true)",
        )
        .unwrap();
        // The outer products ref is confined...
        assert!(out.contains("products.tenant_id = 'tenant_B'"), "{out}");
        // ...and the inner reviews subquery is independently confined.
        assert!(
            out.contains("reviews.tenant_id = 'tenant_B' AND reviews.visible = true"),
            "{out}"
        );
    }

    #[test]
    fn any_cte_is_refused() {
        // CTEs are refused deny-by-default (a self-named CTE is a scope-shadowing leak vector; the
        // same read is expressible with a subquery/derived table, which is confined).
        assert_eq!(
            rewrite("WITH live AS (SELECT id FROM products) SELECT * FROM live WHERE id > 0")
                .unwrap_err(),
            TargetRewriteError::CteNotAllowed
        );
    }

    /// Regression for the Critical review finding: a self-named CTE must NOT pass through unconfined.
    /// These exact statements previously leaked another tenant's private rows (the outer ref and the
    /// CTE body's own base ref were both skipped by the over-approximating scope). They must now be
    /// refused, never rewritten to a pass-through.
    #[test]
    fn self_named_cte_bypass_is_refused() {
        for hostile in [
            "WITH products AS (SELECT * FROM products WHERE tenant_id = 'tenant_A' AND published = false) SELECT * FROM products",
            "WITH reviews AS (SELECT * FROM reviews) SELECT id FROM products",
            "WITH secrets AS (SELECT * FROM secrets) SELECT * FROM secrets",
            "WITH RECURSIVE products AS (SELECT * FROM products) SELECT * FROM products",
        ] {
            assert_eq!(
                rewrite(hostile).unwrap_err(),
                TargetRewriteError::CteNotAllowed,
                "must refuse (never pass through unconfined): {hostile}"
            );
        }
    }

    #[test]
    fn set_operation_arms_are_each_confined() {
        let out = rewrite("SELECT id FROM products UNION SELECT id FROM reviews").unwrap();
        assert!(
            out.contains("FROM products WHERE products.tenant_id = 'tenant_B'"),
            "{out}"
        );
        assert!(
            out.contains("FROM reviews WHERE reviews.tenant_id = 'tenant_B'"),
            "{out}"
        );
    }

    #[test]
    fn unscoped_table_needs_a_public_subset_and_is_refused_without_one() {
        // `countries` is Unscoped but declares no public subset → deny-by-default.
        let err = rewrite("SELECT * FROM countries").unwrap_err();
        assert_eq!(
            err,
            TargetRewriteError::PublicSubsetUndeclared("countries".to_string())
        );
    }

    #[test]
    fn undeclared_table_is_refused() {
        let err = rewrite("SELECT * FROM secrets").unwrap_err();
        assert_eq!(
            err,
            TargetRewriteError::PublicSubsetUndeclared("secrets".to_string())
        );
    }

    #[test]
    fn a_write_is_refused() {
        assert_eq!(
            rewrite("DELETE FROM products WHERE id = 1").unwrap_err(),
            TargetRewriteError::NotReadOnly
        );
        assert_eq!(
            rewrite("UPDATE products SET published = false").unwrap_err(),
            TargetRewriteError::NotReadOnly
        );
        assert_eq!(
            rewrite("INSERT INTO products (id) VALUES (1)").unwrap_err(),
            TargetRewriteError::NotReadOnly
        );
    }

    #[test]
    fn multiple_statements_are_refused() {
        assert_eq!(
            rewrite("SELECT id FROM products; SELECT id FROM reviews").unwrap_err(),
            TargetRewriteError::NotReadOnly
        );
    }

    #[test]
    fn select_into_is_refused_as_a_write() {
        // `SELECT … INTO t` materialises a table — a write smuggled into a read.
        let err = rewrite("SELECT id INTO stash FROM products").unwrap_err();
        assert_eq!(err, TargetRewriteError::WriteInReadPosition);
    }

    #[test]
    fn schema_qualified_table_name_is_refused() {
        let err = rewrite("SELECT id FROM public.products").unwrap_err();
        assert_eq!(
            err,
            TargetRewriteError::QualifiedTableName("public.products".to_string())
        );
    }

    #[test]
    fn table_valued_function_is_refused() {
        // A TVF is not a confinable base table.
        let err = rewrite_target_select(
            "SELECT * FROM generate_series(1, 10)",
            &b(),
            &keys(),
            &public(),
            true,
            false,
            Dialect::Postgres,
        )
        .unwrap_err();
        assert!(
            matches!(err, TargetRewriteError::UnsupportedTableSource(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_text_tenant_value_with_a_quote_is_escaped_not_injected() {
        // A hostile-looking B is host-derived and can't actually occur, but prove the literal is
        // escaped (doubled quote) rather than breaking out of the string.
        let out = rewrite_target_select(
            "SELECT id FROM products",
            &SqlValue::Text("x' OR '1'='1".to_string()),
            &keys(),
            &public(),
            true,
            false,
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(
            out.contains("products.tenant_id = 'x'' OR ''1''=''1'"),
            "{out}"
        );
    }

    #[test]
    fn nested_join_inner_tables_are_confined() {
        let out =
            rewrite("SELECT * FROM (products p JOIN reviews r ON r.product_id = p.id)").unwrap();
        assert!(out.contains("p.tenant_id = 'tenant_B'"), "{out}");
        assert!(out.contains("r.tenant_id = 'tenant_B'"), "{out}");
    }

    #[test]
    fn derived_table_subquery_is_confined() {
        let out = rewrite("SELECT * FROM (SELECT id FROM products) AS live WHERE id > 0").unwrap();
        // The derived subquery confines `products`, and `live` is not a base table.
        assert!(
            out.contains("FROM products WHERE products.tenant_id = 'tenant_B'"),
            "{out}"
        );
        assert!(!out.contains("live.tenant_id"), "{out}");
    }

    #[test]
    fn correlated_exists_subquery_is_confined() {
        let out = rewrite(
            "SELECT id FROM products WHERE EXISTS (SELECT 1 FROM reviews WHERE reviews.product_id = products.id)",
        )
        .unwrap();
        assert!(out.contains("products.tenant_id = 'tenant_B'"), "{out}");
        assert!(out.contains("reviews.tenant_id = 'tenant_B'"), "{out}");
    }
}
