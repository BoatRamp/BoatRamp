//! Host-side parse-and-rewrite confinement of a guest's **raw SQL** — the **target read** (R4/D8)
//! AND the caller's **own/session read + write** (the P0 marker-escape fix).
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
//! guest statement into an AST and **injects** the per-table confinement onto EVERY table
//! reference — the root `FROM`, every `JOIN`, every subquery, CTE, and set-operation arm — at the
//! AST level, where the guest cannot move or escape it. The guest's own `WHERE` is parenthesised
//! before the confinement is `AND`-ed on, so a top-level `OR` in the guest predicate can never widen
//! past the tenant/public gate.
//!
//! ## Own/session confinement (the P0 fix)
//!
//! The same `VisitMut` walk is **generalized** over a [`Confiner`] — a per-table predicate builder —
//! so it confines the caller's OWN/SESSION axes too, not only the target axis. [`rewrite_own_read`]
//! reuses the read walk with an [`OwnConfiner`] that mirrors [`orm::Scope::read_pred`]: a plain
//! tenant table → `tenant_col = <own>`; a `TenantOrSession` table → `(tenant = T OR session = S)`;
//! a `TenantOrBase` table → `(tenant = <own> OR tenant IS NULL)`; an `Unscoped` table → no predicate
//! (global read). [`rewrite_own_write`] structurally injects the write confinement, mirroring
//! [`orm::Scope::write_target`] / `force_scope`: an UPDATE/DELETE gets `tenant_col = <own>` AND-ed
//! onto its parenthesised guest `WHERE`, an UPDATE cannot re-tenant (a guest `SET tenant_col = …` is
//! forced back to `<own>`), an INSERT force-stamps the tenant column in VALUES (a guest-supplied
//! tenant is overridden) and scopes any `INSERT … SELECT` source through the read walk. An
//! `Unscoped` (global) write stays refused (deny-by-default — global writes are ORM-only on this
//! base). Because the confinement is host-injected structurally, the `{scope}` marker is no longer
//! required and, if present, is neutralised (`1 = 1`) — a guest can neither move nor `OR`-escape it.
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
    Assignment, AssignmentTarget, BinaryOperator, Delete, Expr, FromTable, Ident, Insert,
    JoinConstraint, JoinOperator, ObjectName, Query, Select, SelectItem, SetExpr, Statement,
    TableFactor, Value, VisitMut, VisitorMut,
};
use sqlparser::dialect::{Dialect as SpDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;

use crate::orm::{CmpOp, PublicTermSql, ScopeMode};
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
    /// An own/session raw-SQL **write** needed a resolved principal (an own-tenant value, or — for a
    /// `TenantOrSession` table — at least one of the tenant/session facts) but the request carried
    /// none. Fail closed: the write is refused rather than run unscoped (the write-path analog of the
    /// ORM's [`OrmError::TenancyNoPrincipal`](crate::orm::OrmError::TenancyNoPrincipal)).
    NoPrincipal,
    /// A guest raw-SQL **write** targeted a table declared `Unscoped` (global reference data). Reads
    /// of an `Unscoped` table are global by design, but writes are deny-by-default (a shared-data
    /// write is a cross-tenant blast) — global writes are ORM-only on this base. The raw-SQL analog
    /// of [`OrmError::UnscopedWrite`](crate::orm::OrmError::UnscopedWrite).
    UnscopedWrite(String),
    /// A raw-SQL write used a top-level statement the own/session confinement does not structurally
    /// support (a DDL, a `MERGE`, a bare `TABLE t`, a set-operation, a `WITH`-led write, …). Refused
    /// fail-closed rather than run without a provable per-table tenant bound.
    UnsupportedWrite(String),
    /// A raw-SQL write's target relation was not a single bare base table (a joined/aliased/qualified
    /// UPDATE target, a multi-table DELETE, a `USING`/`FROM` join). Refused fail-closed: the tenant
    /// bound must attach to exactly one unambiguous base table.
    BadWriteTarget(String),
    /// A raw-SQL `INSERT` gave the forced tenant column a value the confinement cannot prove is the
    /// caller's own tenant, or in a shape it cannot force (an `INSERT … DEFAULT VALUES`, a row-arity
    /// mismatch). The tenant column is force-stamped, so a guest-supplied value is normally
    /// overridden; this is the fail-closed backstop for a shape where the stamp cannot be placed.
    UnsupportedInsert(String),
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
                "tenancy: a WITH/CTE is not allowed in a confined raw-SQL statement (use a subquery \
                 or derived table)"
                    .into()
            }
            Self::UnsupportedJoin(k) => format!(
                "tenancy(target): a {k} join is not allowed in a target read (use an INNER join or a \
                 LEFT … ON join)"
            ),
            Self::NoPrincipal => {
                "tenancy: no resolved principal for a scoped raw-SQL write (deny-by-default)".into()
            }
            Self::UnscopedWrite(t) => format!(
                "tenancy: table `{t}` is Unscoped (global reference); raw-SQL guest writes are \
                 refused (deny-by-default)"
            ),
            Self::UnsupportedWrite(k) => {
                format!("tenancy: unsupported raw-SQL write shape ({k}); refused")
            }
            Self::BadWriteTarget(t) => format!(
                "tenancy: a raw-SQL write must target a single bare base table (got `{t}`)"
            ),
            Self::UnsupportedInsert(k) => {
                format!("tenancy: unsupported raw-SQL INSERT shape ({k}); refused")
            }
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
    let confiner = TargetConfiner {
        keys,
        public,
        require_public,
        bound,
        null_base,
    };
    let mut rewriter = Rewriter {
        confiner: &confiner,
    };
    if let ControlFlow::Break(err) = statements[0].visit(&mut rewriter) {
        return Err(err);
    }
    Ok(statements[0].to_string())
}

// ---- own/session read + write (the P0 marker-escape fix) -------------------

/// Per-table tenant-key resolution for a raw-SQL own confinement — the applied side of
/// [`orm::TableKeys`](crate::orm::TableKeys)'s own/session cases (the target case is
/// [`rewrite_target_select`]). `Uniform` (no project schema) scopes EVERY table on one column,
/// byte-identical to the pre-schema single-column raw-SQL marker; `PerTable` is the project schema's
/// authoritative map (the identity table on its PK, `Unscoped` tables skipped, undeclared tables
/// refused — deny-by-default).
pub enum OwnKeys<'a> {
    /// Every table scopes on this one tenant column (legacy `Uniform`).
    Uniform(String),
    /// The project schema's per-table map (authoritative + exhaustive; an absent table is refused).
    PerTable(&'a BTreeMap<String, ResolvedScope>),
}

impl OwnKeys<'_> {
    /// Resolve `table`'s scope: `Uniform` → `Column(col)` for every table; `PerTable` → the map entry
    /// (deny-by-default — an absent table is [`TenancyUndeclared`](TargetRewriteError::TenancyUndeclared)).
    fn resolve(&self, table: &str) -> Result<ResolvedScope, TargetRewriteError> {
        match self {
            OwnKeys::Uniform(col) => Ok(ResolvedScope::Column(col.clone())),
            OwnKeys::PerTable(m) => m
                .get(table)
                .cloned()
                .ok_or_else(|| TargetRewriteError::TenancyUndeclared(table.to_string())),
        }
    }
}

/// The resolved own/session facts a raw-SQL own confinement injects (the applied side of the
/// principal, mirroring [`orm::Scope`](crate::orm::Scope)'s `value`/`session`/`keys`). Built by the
/// host from the verified principal + the project schema — NEVER guest input. `own` is the resolved
/// own-tenant value (`None` for a purely anonymous, session-only actor); `session` the resolved
/// anonymous-session value (R3); `keys` the per-table tenant-key resolution.
pub struct OwnScope<'a> {
    /// The resolved own-tenant value, or `None` for an anonymous (session-only) actor.
    pub own: Option<&'a SqlValue>,
    /// The resolved anonymous-session value (R3), or `None`.
    pub session: Option<&'a SqlValue>,
    /// The field-level tenant-axis restriction (mirrors [`orm::ScopeMode`](crate::orm::ScopeMode)):
    /// `Own` → `col = <own>`; `OwnOrNull` → `(col = <own> OR col IS NULL)`; `NullOnly` → `col IS
    /// NULL` (baseline only). `All` is never routed here (a cross-tenant grant is unconfined). A
    /// per-table `TenantOrSession` overrides to its R3 disjunct; `TenantOrBase` always folds the NULL
    /// base — exactly as `orm::Scope::read_pred`.
    pub mode: ScopeMode,
    /// Per-table tenant-key resolution (legacy single-column `Uniform`, or the project schema's map).
    pub keys: OwnKeys<'a>,
}

/// Rewrite a guest's **raw-SQL own/session READ** so every table reference is confined to the
/// caller's own/session partition (the P0 fix). Reuses the exact same completeness-argued `VisitMut`
/// walk as the target-read path ([`rewrite_target_select`]), with a per-table predicate that mirrors
/// [`orm::Scope::read_pred`](crate::orm::Scope): `Column`/`TenantKeyed` → `col = <own>`;
/// `TenantOrSession` → `(tenant = T OR session = S)`; `TenantOrBase` → `(tenant = <own> OR tenant IS
/// NULL)`; `Unscoped` → no predicate (global read). `SharedWritable` is not a variant on this base
/// (arrives when #503 rebases — see [`OwnConfiner::table_read_pred`] for the extension point).
/// Fail-closed: unparseable, a write in read position, an undeclared table, or an own read with no
/// principal → refused (never the old escapable marker). `dialect` selects the parser.
pub fn rewrite_own_read(
    statement: &str,
    scope: &OwnScope<'_>,
    dialect: Dialect,
) -> Result<String, TargetRewriteError> {
    let mut statements = parse_one(statement, dialect)?;
    match &statements[0] {
        Statement::Query(_) => {}
        _ => return Err(TargetRewriteError::NotReadOnly),
    }
    let confiner = OwnConfiner { scope };
    let mut rewriter = Rewriter {
        confiner: &confiner,
    };
    if let ControlFlow::Break(err) = statements[0].visit(&mut rewriter) {
        return Err(err);
    }
    Ok(statements[0].to_string())
}

/// Rewrite a guest's **raw-SQL own/session WRITE** (UPDATE / DELETE / INSERT) so the write is
/// structurally confined to the caller's own/session partition (the P0 fix), mirroring
/// [`orm::Scope::force_scope`](crate::orm::Scope)/`write_target`:
/// - **UPDATE**: the guest `WHERE` is parenthesised and `tenant_col = <own>` (or the session-axis
///   value) is `AND`-ed on; any guest `SET tenant_col = …` is dropped and re-forced to `<own>` so the
///   write can never re-tenant a row. A subquery in a `SET` value or the `WHERE` is confined through
///   the read walk.
/// - **DELETE**: the guest `WHERE` is parenthesised and the tenant bound `AND`-ed on.
/// - **INSERT**: the tenant column is force-stamped in every `VALUES` row (a guest-supplied tenant is
///   overridden); an `INSERT … SELECT` source is confined through the read walk and its projected
///   tenant column host-forced.
///
/// A plain `Unscoped` (global) write is refused (deny-by-default). Fail-closed: unparseable, a
/// no-principal own write, an undeclared table, a multi-table / qualified write target, or an
/// unsupported write shape → refused. `dialect` selects the parser.
pub fn rewrite_own_write(
    statement: &str,
    scope: &OwnScope<'_>,
    dialect: Dialect,
) -> Result<String, TargetRewriteError> {
    let mut statements = parse_one(statement, dialect)?;
    // A CTE-led write hides the write target under a `WITH`; refuse it (the read walk already refuses
    // CTEs, and a raw-SQL own write must attach the bound to one bare base table).
    let stmt = &mut statements[0];
    match stmt {
        Statement::Update { .. } => confine_own_update(stmt, scope)?,
        Statement::Delete(_) => confine_own_delete(stmt, scope)?,
        Statement::Insert(_) => confine_own_insert(stmt, scope, dialect)?,
        Statement::Query(_) => return Err(TargetRewriteError::NotReadOnly),
        other => {
            return Err(TargetRewriteError::UnsupportedWrite(
                statement_kind(other).into(),
            ));
        }
    }
    // Fail-closed backstop (the write-path analog of the read walk's `pre_visit_table_factor` +
    // CTE-refusal), resting on sqlparser's exhaustive VisitMut rather than on the per-statement
    // confiner having reached every position. After the confinement above, walk the WHOLE confined
    // statement and refuse any un-confinable table source (a TVF, a schema-qualified name, an exotic
    // source) or a CTE ANYWHERE — including one carried by a future sqlparser field the per-statement
    // confiner does not yet destructure. A recognised bare base table / derived subquery / nested
    // join passes (its read-position subqueries were confined above); an unrecognised source is
    // refused, never silently passed.
    let mut detector = WriteBackstop;
    if let ControlFlow::Break(err) = stmt.visit(&mut detector) {
        return Err(err);
    }
    Ok(statements[0].to_string())
}

/// The fail-closed backstop visitor over a confined write. Mirrors the read walk's
/// [`Rewriter::pre_visit_table_factor`] + CTE refusal exactly, rested on sqlparser's exhaustive
/// traversal: it visits EVERY `Query` and `TableFactor` reachable in the confined statement and
/// refuses any un-confinable table source or CTE anywhere — so a read position the per-statement
/// confiner did not reach (including a future sqlparser field) carrying an exotic / CTE source is
/// caught here, never left unconfined. (A plain confined base table passes: its per-table tenant
/// predicate was injected by the confiner / the read walk above.)
struct WriteBackstop;

impl VisitorMut for WriteBackstop {
    type Break = TargetRewriteError;

    fn pre_visit_query(&mut self, query: &mut Query) -> ControlFlow<Self::Break> {
        // A CTE hides a base table under its own name (unresolvable to a confinement) — refuse it
        // anywhere in the confined statement, exactly as the read walk does.
        if query.with.is_some() {
            return ControlFlow::Break(TargetRewriteError::CteNotAllowed);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(
        &mut self,
        table_factor: &mut TableFactor,
    ) -> ControlFlow<Self::Break> {
        // Belt-and-suspenders identical to the read walk: refuse any un-confinable table source
        // ANYWHERE in the confined write (a TVF, a schema-qualified name, an exotic source). The
        // write-target base table and ordinary derived/nested joins pass.
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

/// Parse exactly one statement under `dialect` (multi-statement / empty batches refused).
fn parse_one(statement: &str, dialect: Dialect) -> Result<Vec<Statement>, TargetRewriteError> {
    let sp: Box<dyn SpDialect> = match dialect {
        Dialect::Sqlite => Box::new(SQLiteDialect {}),
        Dialect::Postgres => Box::new(PostgreSqlDialect {}),
        Dialect::Mysql => Box::new(MySqlDialect {}),
    };
    let statements =
        Parser::parse_sql(&*sp, statement).map_err(|e| TargetRewriteError::Parse(e.to_string()))?;
    if statements.len() != 1 {
        return Err(TargetRewriteError::NotReadOnly);
    }
    Ok(statements)
}

/// The `(column, value)` an own/session WRITE stamps/bounds for `table`, mirroring
/// [`orm::Scope::write_target`](crate::orm::Scope): a plain tenant / `TenantKeyed` / `TenantOrBase`
/// table binds `col = <own>`; a `TenantOrSession` table binds the single axis the actor holds
/// (`tenant = T` authenticated, else `session = S`); an `Unscoped` table is refused (global writes
/// are ORM-only). Fail-closed: an undeclared table, an `Unscoped` table, or a scoped write with no
/// principal are refused before any SQL is emitted.
fn write_target(
    scope: &OwnScope<'_>,
    table: &str,
) -> Result<(String, SqlValue), TargetRewriteError> {
    let resolved = scope.keys.resolve(table)?;
    // The tenant-axis stamp value for the field mode (mirrors `orm::Scope::write_target`):
    // `Own`/`OwnOrNull` → the resolved own tenant; `NullOnly` → the shared baseline (`NULL`); `All`
    // never reaches here. Fail-closed when an own stamp is required but no principal is present.
    let stamp = || -> Result<SqlValue, TargetRewriteError> {
        match scope.mode {
            ScopeMode::NullOnly => Ok(SqlValue::Null),
            ScopeMode::Own | ScopeMode::OwnOrNull => {
                scope.own.cloned().ok_or(TargetRewriteError::NoPrincipal)
            }
            ScopeMode::All => Err(TargetRewriteError::NoPrincipal),
        }
    };
    match &resolved {
        // A plain tenant `Column` and a base-inclusive `TenantOrBase` both stamp per the field mode
        // (own/own+null → the resolved tenant; null → the shared baseline). A guest write can never
        // create/update a NULL-base row under an own grant — exactly as the ORM.
        ResolvedScope::Column(col) => {
            check_ident(col)?;
            Ok((col.clone(), stamp()?))
        }
        ResolvedScope::TenantOrBase { tenant } => {
            check_ident(tenant)?;
            Ok((tenant.clone(), stamp()?))
        }
        // Prefer the tenant axis when authenticated; else the session axis for an anon write.
        ResolvedScope::TenantOrSession { tenant, session } => {
            check_ident(tenant)?;
            check_ident(session)?;
            if let Some(v) = scope.own {
                Ok((tenant.clone(), v.clone()))
            } else if let Some(s) = scope.session {
                Ok((session.clone(), s.clone()))
            } else {
                Err(TargetRewriteError::NoPrincipal)
            }
        }
        ResolvedScope::Unscoped => Err(TargetRewriteError::UnscopedWrite(table.to_string())),
    }
}

/// The single-table write bound as an `Expr` for a `WHERE`/`ON`: `col = <value>`, or `col IS NULL`
/// for the explicit `NullOnly` baseline grant (a NULL stamp value ⇒ `IS NULL`, exactly as the ORM's
/// `single_scope_pred`; own/session values are never NULL, so this is unambiguous).
fn write_bound_expr(scope: &OwnScope<'_>, table: &str) -> Result<Expr, TargetRewriteError> {
    let (col, value) = write_target(scope, table)?;
    Ok(if matches!(value, SqlValue::Null) {
        Expr::IsNull(Box::new(Expr::Identifier(Ident::new(col))))
    } else {
        binop(
            Expr::Identifier(Ident::new(col)),
            BinaryOperator::Eq,
            value_expr(&value)?,
        )
    })
}

/// Confine any `Query` subquery embedded in a write's SET value / WHERE / RETURNING through the SAME
/// read walk, so a subquery source can never read cross-tenant (the write-path twin of the ORM's
/// `inject_scope_expr`). Applied to the whole expression tree; nested `Query` nodes each receive the
/// read confinement.
fn confine_subqueries_in_expr(
    scope: &OwnScope<'_>,
    expr: &mut Expr,
) -> Result<(), TargetRewriteError> {
    let confiner = OwnConfiner { scope };
    let mut rewriter = Rewriter {
        confiner: &confiner,
    };
    if let ControlFlow::Break(err) = expr.visit(&mut rewriter) {
        return Err(err);
    }
    Ok(())
}

/// Confine every read-position sub-expression carried by a write's `RETURNING` clause through the
/// SAME read walk — a `RETURNING (SELECT … FROM other)` scalar subquery, an aggregate over a joined
/// table, etc. — so a `RETURNING` item can never read cross-tenant (the C1 fix). A `Wildcard` /
/// `QualifiedWildcard` item carries no expression (it projects the write target's own — already
/// confined — columns) and needs no walk. Applied to each item in place.
fn confine_returning_items(
    scope: &OwnScope<'_>,
    returning: &mut [SelectItem],
) -> Result<(), TargetRewriteError> {
    for item in returning.iter_mut() {
        match item {
            SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => {
                confine_subqueries_in_expr(scope, e)?;
            }
            // A bare / qualified `*` projects the (already-confined) write-target columns — no
            // embedded read position.
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => {}
        }
    }
    Ok(())
}

/// Confine an own/session `UPDATE`: parenthesise the guest `WHERE` and `AND` the tenant bound onto
/// the target table; force any guest `SET tenant_col = …` back to `<own>` (an UPDATE can never
/// re-tenant a row); confine any subquery in the SET values / WHERE / RETURNING through the read
/// walk. The target must be a single bare base table (a joined/qualified/`FROM`-bearing UPDATE is
/// refused).
fn confine_own_update(
    stmt: &mut Statement,
    scope: &OwnScope<'_>,
) -> Result<(), TargetRewriteError> {
    let Statement::Update {
        table,
        assignments,
        from,
        selection,
        returning,
        // `or` is a SQLite conflict-resolution keyword (`UPDATE OR REPLACE …`) — a modifier, not a
        // read position; it carries no sub-expression and cannot widen the tenant bound.
        or: _,
    } = stmt
    else {
        unreachable!("confine_own_update called on a non-UPDATE");
    };
    // A `FROM`-bearing UPDATE (Postgres `UPDATE … FROM other`) reads a second relation that the
    // single-table bound cannot confine — refuse fail-closed.
    if from.is_some() {
        return Err(TargetRewriteError::UnsupportedWrite("UPDATE … FROM".into()));
    }
    if !table.joins.is_empty() {
        return Err(TargetRewriteError::BadWriteTarget(
            "joined UPDATE target".into(),
        ));
    }
    let (base, _alias) = bare_table_ref(&table.relation)?;
    let (tenant_col, own_val) = write_target(scope, &base)?;
    // Prevent re-tenanting: if the guest SETs the tenant column, force that assignment back to
    // `<own>` (drop it, re-append the host value below); a tuple-target assignment touching the
    // tenant column is refused fail-closed (its RHS shape is not a single value we can host-force).
    // `same_col` matches a re-spelled / qualified tenant column too. If the guest did NOT touch the
    // tenant column, no SET is added — the WHERE bound already confines the UPDATE to own rows, so a
    // spurious `tenant_col = <own>` SET is unnecessary (and would be a no-op on those rows anyway).
    let guest_set_tenant = assignments
        .iter()
        .any(|a| assignment_touches(&a.target, &tenant_col));
    for a in assignments.iter() {
        if assignment_touches(&a.target, &tenant_col) && !is_column_target(&a.target) {
            return Err(TargetRewriteError::UnsupportedWrite(
                "tuple SET touching the tenant column".into(),
            ));
        }
    }
    assignments.retain(|a| !assignment_touches(&a.target, &tenant_col));
    // Confine subqueries in the surviving guest SET values BEFORE re-appending the forced stamp.
    for a in assignments.iter_mut() {
        confine_subqueries_in_expr(scope, &mut a.value)?;
    }
    if guest_set_tenant {
        assignments.push(Assignment {
            target: AssignmentTarget::ColumnName(ObjectName(vec![Ident::new(tenant_col)])),
            value: value_expr(&own_val)?,
        });
    }
    // Confine subqueries in the guest WHERE, then parenthesise it and AND the tenant bound on.
    if let Some(w) = selection.as_mut() {
        confine_subqueries_in_expr(scope, w)?;
    }
    let bound = write_bound_expr(scope, &base)?;
    *selection = Some(match selection.take() {
        Some(existing) => and(Expr::Nested(Box::new(existing)), bound),
        None => bound,
    });
    // Confine any subquery in a RETURNING item (C1): `UPDATE … RETURNING (SELECT … FROM other)` must
    // not read cross-tenant.
    if let Some(items) = returning.as_mut() {
        confine_returning_items(scope, items)?;
    }
    Ok(())
}

/// Confine an own/session `DELETE`: parenthesise the guest `WHERE` and `AND` the tenant bound on;
/// confine any subquery in a RETURNING item through the read walk. The target must be a single bare
/// base table (a multi-table DELETE / `USING` join is refused), and a MySQL `ORDER BY`/`LIMIT` on the
/// DELETE is refused (its sub-expressions are read positions the single-table bound does not reach —
/// and an ordered/limited confined single-table delete is expressible via the `orm` surface).
fn confine_own_delete(
    stmt: &mut Statement,
    scope: &OwnScope<'_>,
) -> Result<(), TargetRewriteError> {
    let Statement::Delete(del) = stmt else {
        unreachable!("confine_own_delete called on a non-DELETE");
    };
    let Delete {
        tables,
        from,
        using,
        selection,
        returning,
        order_by,
        limit,
    } = del;
    if !tables.is_empty() || using.is_some() {
        return Err(TargetRewriteError::UnsupportedWrite(
            "multi-table / USING DELETE".into(),
        ));
    }
    // C3: a MySQL `DELETE … ORDER BY … LIMIT …` carries read-position sub-expressions (the ORDER BY
    // keys, the LIMIT expr) the single-table tenant bound does not reach — refuse fail-closed rather
    // than emit an under-confined delete. A confined single-table ordered/limited delete is
    // expressible via the typed `orm` surface.
    if !order_by.is_empty() || limit.is_some() {
        return Err(TargetRewriteError::UnsupportedWrite(
            "DELETE with ORDER BY / LIMIT".into(),
        ));
    }
    let relations = match from {
        FromTable::WithFromKeyword(v) | FromTable::WithoutKeyword(v) => v,
    };
    if relations.len() != 1 || !relations[0].joins.is_empty() {
        return Err(TargetRewriteError::BadWriteTarget(
            "joined / multi-relation DELETE target".into(),
        ));
    }
    let (base, _alias) = bare_table_ref(&relations[0].relation)?;
    if let Some(w) = selection.as_mut() {
        confine_subqueries_in_expr(scope, w)?;
    }
    let bound = write_bound_expr(scope, &base)?;
    *selection = Some(match selection.take() {
        Some(existing) => and(Expr::Nested(Box::new(existing)), bound),
        None => bound,
    });
    // Confine any subquery in a RETURNING item (C1): `DELETE … RETURNING (SELECT … FROM other)` must
    // not read cross-tenant.
    if let Some(items) = returning.as_mut() {
        confine_returning_items(scope, items)?;
    }
    Ok(())
}

/// Confine an own/session `INSERT`: force-stamp the tenant column in every `VALUES` row (a
/// guest-supplied tenant is overridden) and confine any subquery embedded in a VALUES cell / a
/// RETURNING item through the read walk, or, for an `INSERT … SELECT`, confine the source through the
/// read walk and host-force the projected tenant column. Refuses:
/// - an upsert `ON CONFLICT DO UPDATE` (its DO-UPDATE arm would need the same re-tenant guard as an
///   UPDATE — deny-by-default on the raw path; use the typed `orm` surface);
/// - a MySQL `REPLACE INTO` (its implicit DELETE on a PK/unique collision carries no tenant predicate
///   and could delete a victim's row — route it to the `orm` surface, matching the ON CONFLICT
///   rationale);
/// - an INSERT with no explicit column list (a positional INSERT — the host cannot locate the tenant
///   column positionally to override a guest-supplied value; only an incidental arity mismatch would
///   error, which is not fail-closed), or a column list naming the tenant column more than once;
/// - a `DEFAULT VALUES` / partitioned insert, and an `Unscoped` target.
fn confine_own_insert(
    stmt: &mut Statement,
    scope: &OwnScope<'_>,
    dialect: Dialect,
) -> Result<(), TargetRewriteError> {
    let Statement::Insert(ins) = stmt else {
        unreachable!("confine_own_insert called on a non-INSERT");
    };
    // Up-front refusals read `ins` directly (before the field reborrows below) so the
    // `SetExpr::Select` arm can re-pass `ins` to `confine_insert_select`, and so the RETURNING clause
    // can be reborrowed (`ins.returning`) after the body match.
    // MEDIUM: a `REPLACE` insert performs an implicit DELETE on a PK/unique collision with NO tenant
    // predicate — it could delete a victim tenant's row. Both spellings carry this risk: MySQL
    // `REPLACE INTO …` (`replace_into = true`) and SQLite `INSERT OR REPLACE …`
    // (`or = Some(Replace)`). Refuse both (route to the `orm` surface), matching the ON CONFLICT
    // refusal rationale.
    if ins.replace_into || matches!(ins.or, Some(sqlparser::ast::SqliteOnConflict::Replace)) {
        return Err(TargetRewriteError::UnsupportedInsert(
            "REPLACE / INSERT OR REPLACE (implicit delete has no tenant predicate; use the orm \
             surface)"
                .into(),
        ));
    }
    if ins.on.is_some() {
        return Err(TargetRewriteError::UnsupportedInsert(
            "ON CONFLICT / ON DUPLICATE upsert (use the orm surface)".into(),
        ));
    }
    if ins.partitioned.is_some() || !ins.after_columns.is_empty() {
        return Err(TargetRewriteError::UnsupportedInsert(
            "partitioned INSERT".into(),
        ));
    }
    if ins.table_name.0.len() != 1 {
        return Err(TargetRewriteError::BadWriteTarget(object_name_string(
            &ins.table_name,
        )));
    }
    let base = ins.table_name.0[0].value.clone();
    // Resolve+validate the write target (deny-by-default: undeclared / Unscoped / no-principal).
    let (tenant_col, own_val) = write_target(scope, &base)?;
    // Now reborrow the mutable fields the body rewrite needs. The remaining `Insert` fields are
    // non-read-position modifiers (`or`/`ignore`/`priority`/`insert_alias`/`into`/`overwrite`/`table`
    // and the already-checked `replace_into`/`on`/`partitioned`/`after_columns`/`table_name`): none
    // carries a sub-expression that could read cross-tenant or widen the tenant stamp.
    let Insert {
        table_alias,
        columns,
        source,
        ..
    } = &mut *ins;
    let _ = table_alias;
    let Some(query) = source.as_deref_mut() else {
        return Err(TargetRewriteError::UnsupportedInsert(
            "INSERT without VALUES/SELECT (e.g. DEFAULT VALUES)".into(),
        ));
    };
    // HIGH: a positional INSERT with no explicit column list can't be tenant-stamped — the host
    // cannot locate the tenant column by position, so it could not override a guest-supplied tenant
    // value (appending a column would only ever produce an arity mismatch, not a fail-closed
    // override). Refuse. Likewise refuse a column list that names the tenant column more than once
    // (the single-position override below would leave a second guest-controlled tenant cell).
    if columns.is_empty() {
        return Err(TargetRewriteError::UnsupportedInsert(
            "INSERT without an explicit column list".into(),
        ));
    }
    if columns
        .iter()
        .filter(|c| same_col(&c.value, &tenant_col))
        .count()
        > 1
    {
        return Err(TargetRewriteError::UnsupportedInsert(
            "duplicate tenant column in the INSERT column list".into(),
        ));
    }
    let confine_result = match query.body.as_mut() {
        // INSERT … VALUES: confine any subquery in a guest VALUES cell (C2 — a
        // `VALUES ('x', (SELECT … FROM other))` cell must not exfiltrate cross-tenant), then
        // force-stamp the tenant column into every row. If the guest already named the tenant column,
        // override that cell in place (a guest-supplied tenant is discarded); otherwise append the
        // column + a stamped cell to every row.
        SetExpr::Values(values) => {
            for row in &mut values.rows {
                for cell in row.iter_mut() {
                    confine_subqueries_in_expr(scope, cell)?;
                }
            }
            let col_pos = columns.iter().position(|c| same_col(&c.value, &tenant_col));
            let stamp = stamp_value_expr(&own_val)?;
            match col_pos {
                Some(i) => {
                    for row in &mut values.rows {
                        if row.len() != columns.len() {
                            return Err(TargetRewriteError::UnsupportedInsert(
                                "VALUES row arity mismatch".into(),
                            ));
                        }
                        row[i] = stamp.clone();
                    }
                }
                None => {
                    columns.push(Ident::new(tenant_col));
                    for row in &mut values.rows {
                        row.push(stamp.clone());
                    }
                }
            }
            Ok(())
        }
        // INSERT … SELECT: read-confine the source (so the selected rows stay own-scoped), then
        // host-force the projected tenant column. A guest that named the tenant column in the INSERT
        // column list is refused (the host stamps it — a guest-named tenant on an `INSERT … SELECT`
        // can't be safely overridden without projection surgery across arbitrary SELECT/UNION
        // shapes). The confined source is wrapped in a derived table so the host appends `<own>` as
        // the trailing tenant column: `SELECT __src.*, <own> FROM (<confined source>) AS __src`.
        SetExpr::Select(_) | SetExpr::Query(_) | SetExpr::SetOperation { .. } => {
            confine_insert_select(ins, &tenant_col, &own_val, scope, dialect)
        }
        SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Table(_) => Err(
            TargetRewriteError::UnsupportedInsert("write in the INSERT source position".into()),
        ),
    };
    confine_result?;
    // Confine any subquery in a RETURNING item (C1): `INSERT … RETURNING (SELECT … FROM other)` must
    // not read cross-tenant. Reborrowed here (after the body match releases `ins`).
    if let Some(items) = ins.returning.as_mut() {
        confine_returning_items(scope, items)?;
    }
    Ok(())
}

/// Confine an `INSERT … SELECT`: read-confine the source in place (every source table gets the
/// own/session read predicate via the shared walk), refuse a guest-named tenant column, then wrap the
/// confined source so the host appends `<own>` as the trailing tenant column. `INSERT INTO t (…,
/// tenant_col) SELECT __bramp_src.*, <own> FROM (<confined source>) AS __bramp_src`.
fn confine_insert_select(
    ins: &mut Insert,
    tenant_col: &str,
    own_val: &SqlValue,
    scope: &OwnScope<'_>,
    dialect: Dialect,
) -> Result<(), TargetRewriteError> {
    if ins.columns.iter().any(|c| same_col(&c.value, tenant_col)) {
        return Err(TargetRewriteError::UnsupportedInsert(
            "INSERT … SELECT may not name the tenant column (the host stamps it)".into(),
        ));
    }
    // Read-confine the SELECT source in place (each source table gets the own/session read predicate;
    // undeclared / no-principal source tables fail closed here).
    let source = ins
        .source
        .as_deref_mut()
        .expect("caller verified a source exists");
    let confiner = OwnConfiner { scope };
    let mut rewriter = Rewriter {
        confiner: &confiner,
    };
    if let ControlFlow::Break(err) = source.visit(&mut rewriter) {
        return Err(err);
    }
    // Wrap the confined source in a derived table and append the host-forced tenant literal as a
    // trailing column, so a guest can neither project another tenant's id nor omit the stamp. Build
    // it by rendering the confined source back to SQL and re-parsing the wrapper (one extra parse per
    // INSERT … SELECT — a rare shape — keeping the AST construction dialect-faithful).
    let src_sql = source.to_string();
    let stamped = render_literal(own_val)?;
    let wrapper = format!("SELECT __bramp_src.*, {stamped} FROM ({src_sql}) AS __bramp_src");
    let mut wrapper_stmts = parse_one(&wrapper, dialect)?;
    let Statement::Query(q) = wrapper_stmts.remove(0) else {
        return Err(TargetRewriteError::UnsupportedInsert(
            "INSERT … SELECT wrapper".into(),
        ));
    };
    ins.columns.push(Ident::new(tenant_col.to_string()));
    ins.source = Some(q);
    Ok(())
}

/// The bare base-table name (+ optional alias) a write targets, or a [`TargetRewriteError`] if the
/// relation is not a single unqualified base table (a subquery, TVF, qualified name, join, …).
fn bare_table_ref(factor: &TableFactor) -> Result<(String, Option<Ident>), TargetRewriteError> {
    match factor {
        TableFactor::Table { args: Some(_), .. } => Err(TargetRewriteError::BadWriteTarget(
            "table-valued function".into(),
        )),
        TableFactor::Table { name, alias, .. } => {
            if name.0.len() != 1 {
                return Err(TargetRewriteError::BadWriteTarget(object_name_string(name)));
            }
            Ok((
                name.0[0].value.clone(),
                alias.as_ref().map(|a| a.name.clone()),
            ))
        }
        other => Err(TargetRewriteError::BadWriteTarget(
            table_factor_kind(other).to_string(),
        )),
    }
}

/// Whether an assignment target names (or includes, for a tuple) the column `col` (case-insensitive,
/// qualifier-insensitive — a guest can't dodge it by re-spelling `TENANT_ID` / `t.tenant_id`).
fn assignment_touches(target: &AssignmentTarget, col: &str) -> bool {
    let names = |name: &ObjectName| name.0.last().is_some_and(|i| same_col(&i.value, col));
    match target {
        AssignmentTarget::ColumnName(name) => names(name),
        AssignmentTarget::Tuple(cols) => cols.iter().any(names),
    }
}

/// Whether an assignment target is a single column (vs. a tuple `(a, b) = …`).
fn is_column_target(target: &AssignmentTarget) -> bool {
    matches!(target, AssignmentTarget::ColumnName(_))
}

/// A short label for a rejected top-level write statement (error message only).
fn statement_kind(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Insert(_) => "INSERT",
        Statement::Update { .. } => "UPDATE",
        Statement::Delete(_) => "DELETE",
        Statement::Query(_) => "SELECT",
        Statement::Merge { .. } => "MERGE",
        _ => "non-DML statement",
    }
}

/// Case-insensitive, qualifier-insensitive column-name equality (mirrors `orm::same_col`): a guest
/// can't dodge the tenant-column guards by re-spelling (`TENANT_ID`, `t.tenant_id`).
fn same_col(a: &str, b: &str) -> bool {
    let base = |s: &str| s.rsplit('.').next().unwrap_or(s).to_ascii_lowercase();
    base(a) == base(b)
}

/// Render the resolved own value as a literal expression, or fail closed if the actor holds none
/// (`NoPrincipal`) — the read-path analog of `orm::Scope::tenant_pred`'s no-principal refusal.
fn own_value_expr(own: Option<&SqlValue>) -> Result<Expr, TargetRewriteError> {
    match own {
        Some(v) => value_expr(v),
        None => Err(TargetRewriteError::NoPrincipal),
    }
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

/// Builds the per-table READ confinement predicate for one axis (target vs. own/session). The
/// completeness-argued [`Rewriter`] walk is generic over this trait so BOTH the target-read path
/// ([`TargetConfiner`]) and the own/session path ([`OwnConfiner`]) share one walk (and one
/// completeness proof) — only the per-table predicate differs. A `None` means "this table needs no
/// predicate" (a global `Unscoped` reference table); an `Err` fails the whole rewrite closed.
trait Confiner {
    /// The confinement predicate for one base table, qualified by `qualifier` (its alias, else its
    /// own identifier). `Ok(None)` ⇒ no predicate for this table (a global reference table).
    fn table_read_pred(
        &self,
        table: &str,
        qualifier: &Ident,
    ) -> Result<Option<Expr>, TargetRewriteError>;
}

/// The **target-read** confiner (R4/D8): confines each table to `tenant = B AND <public subset>`,
/// deny-by-default. This is the byte-for-byte original target-path logic, unchanged — extracted into
/// a [`Confiner`] so the [`Rewriter`] walk can be shared with the own/session path without weakening
/// it.
struct TargetConfiner<'a> {
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

/// The **own/session** confiner (the P0 fix): confines each table to the caller's own/session
/// partition, mirroring [`orm::Scope::read_pred`](crate::orm::Scope). No public subset (own reads see
/// their own private rows); a global `Unscoped` table adds no predicate.
struct OwnConfiner<'a> {
    scope: &'a OwnScope<'a>,
}

impl Confiner for OwnConfiner<'_> {
    /// The own/session read predicate for one base table, mirroring
    /// [`orm::Scope::read_pred`](crate::orm::Scope) exactly:
    /// - `Column(col)` (a plain tenant / `TenantKeyed` identity table) → `col = <own>` (fail-closed
    ///   [`NoPrincipal`](TargetRewriteError::NoPrincipal) if the actor holds no own value);
    /// - `TenantOrSession { tenant, session }` → the R3 disjunct over whichever axis facts are held
    ///   (`tenant = T` and/or `session = S`); neither ⇒ deny;
    /// - `TenantOrBase { tenant }` → `(tenant = <own> OR tenant IS NULL)` — own rows ⊕ the shared
    ///   `NULL`-tenant base;
    /// - `Unscoped` → `None` (a globally-readable table adds no predicate).
    ///
    /// **Extension point for #503:** when `SharedWritable` (read-none / write-allowed-if-global)
    /// lands as a `ResolvedScope` variant, add its READ arm here (likely `Some(1 = 0)` or a refusal,
    /// per #503's design) — this is the single per-table read decision the whole walk funnels through.
    fn table_read_pred(
        &self,
        table: &str,
        qualifier: &Ident,
    ) -> Result<Option<Expr>, TargetRewriteError> {
        let resolved = self.scope.keys.resolve(table)?;
        match &resolved {
            // A plain tenant `Column` honors the field-level mode, exactly as `orm::Scope::tenant_pred`:
            // `Own` → `col = <own>`; `OwnOrNull` → `(col = <own> OR col IS NULL)`; `NullOnly` → `col
            // IS NULL` (no own value needed). `All` never reaches here (routed to the unscoped path).
            ResolvedScope::Column(col) => {
                check_ident(col)?;
                let is_null = || Expr::IsNull(Box::new(col_expr(qualifier, col)));
                Ok(Some(match self.scope.mode {
                    ScopeMode::NullOnly => is_null(),
                    ScopeMode::Own => binop(
                        col_expr(qualifier, col),
                        BinaryOperator::Eq,
                        own_value_expr(self.scope.own)?,
                    ),
                    ScopeMode::OwnOrNull => {
                        let eq = binop(
                            col_expr(qualifier, col),
                            BinaryOperator::Eq,
                            own_value_expr(self.scope.own)?,
                        );
                        Expr::Nested(Box::new(or(eq, is_null())))
                    }
                    // `All` is unconfined — never routed to the own confiner (a cross-tenant grant
                    // skips the rewrite). Refuse fail-closed rather than emit an unbounded read.
                    ScopeMode::All => return Err(TargetRewriteError::NoPrincipal),
                }))
            }
            ResolvedScope::TenantOrBase { tenant } => {
                check_ident(tenant)?;
                let own = own_value_expr(self.scope.own)?;
                let eq = binop(col_expr(qualifier, tenant), BinaryOperator::Eq, own);
                Ok(Some(Expr::Nested(Box::new(or(
                    eq,
                    Expr::IsNull(Box::new(col_expr(qualifier, tenant))),
                )))))
            }
            ResolvedScope::TenantOrSession { tenant, session } => {
                check_ident(tenant)?;
                check_ident(session)?;
                // The R3 disjunct over whichever axis facts the request carries (own and/or session)
                // — over the two DISJOINT columns. No fact at all ⇒ deny (fail-closed), exactly as
                // `orm::Scope::disjunct_pred`.
                let mut arms: Vec<Expr> = Vec::new();
                if let Some(v) = self.scope.own {
                    arms.push(binop(
                        col_expr(qualifier, tenant),
                        BinaryOperator::Eq,
                        value_expr(v)?,
                    ));
                }
                if let Some(s) = self.scope.session {
                    arms.push(binop(
                        col_expr(qualifier, session),
                        BinaryOperator::Eq,
                        value_expr(s)?,
                    ));
                }
                let mut it = arms.into_iter();
                let Some(first) = it.next() else {
                    return Err(TargetRewriteError::NoPrincipal);
                };
                Ok(Some(match it.next() {
                    Some(second) => Expr::Nested(Box::new(or(first, second))),
                    None => first,
                }))
            }
            ResolvedScope::Unscoped => Ok(None),
        }
    }
}

/// The mutating visitor that injects the per-table READ confinement produced by a [`Confiner`].
/// `WITH`/CTEs are refused up front (see [`TargetRewriteError::CteNotAllowed`]), so — because derived
/// tables are `TableFactor::Derived` and subqueries are their own `Query` nodes — a
/// `TableFactor::Table` bare name is ALWAYS a base table (never a CTE reference). That removes the
/// need to track a CTE-name scope, and with it the scope foot-gun class entirely: every base table is
/// unconditionally confined.
struct Rewriter<'a, C: Confiner> {
    confiner: &'a C,
}

impl<C: Confiner> VisitorMut for Rewriter<'_, C> {
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

impl<C: Confiner> Rewriter<'_, C> {
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
                if let Some(pred) = self.confiner.table_read_pred(&base, &qualifier)? {
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
}

impl Confiner for TargetConfiner<'_> {
    /// The confinement predicate for one base table: `qualifier.tenant = B` (unless the table is
    /// `Unscoped`) `AND` the table's public-subset terms (each qualified). `Ok(None)` when the table
    /// needs no predicate at all (a `capability`-only field's global/`Unscoped` reference table).
    /// Deny-by-default: a table with no declared tenant key is refused; under `require_public`
    /// (domain/handle) a table with no declared public subset is refused.
    fn table_read_pred(
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
            // must still be declared and non-empty, exactly as the ORM target path requires).
            ResolvedScope::Unscoped => {}
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

/// Render a host-held tenant **stamp** value as a literal expression: like [`value_expr`], but a
/// `SqlValue::Null` (the explicit `NullOnly` baseline stamp) renders as the SQL `NULL` literal rather
/// than being refused (a stamp legitimately writes the shared baseline; a *read/where* NULL is
/// `IS NULL`, handled separately).
fn stamp_value_expr(value: &SqlValue) -> Result<Expr, TargetRewriteError> {
    if matches!(value, SqlValue::Null) {
        Ok(Expr::Value(Value::Null))
    } else {
        value_expr(value)
    }
}

/// Render a host-held tenant stamp as a safe SQL literal **string** — the text form of
/// [`stamp_value_expr`], for the one place an own INSERT … SELECT wrapper is built from text (a rare
/// shape). Uses sqlparser's own `Display` so text is escaped identically (quotes doubled).
fn render_literal(value: &SqlValue) -> Result<String, TargetRewriteError> {
    Ok(stamp_value_expr(value)?.to_string())
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

#[cfg(test)]
mod own_confinement_tests {
    //! Unit proofs for the P0 own/session raw-SQL confinement: the AST rewrite injects the tenant
    //! bound structurally (read AND write) so a guest can neither move nor `OR`-escape it, mirroring
    //! `orm::Scope::read_pred`/`write_target`. Behavioral (live) proof is in the storage batteries;
    //! these lock the exact rewrite shape + the fail-closed paths.
    use super::*;

    fn t(s: &str) -> SqlValue {
        SqlValue::Text(s.into())
    }

    fn keys() -> BTreeMap<String, ResolvedScope> {
        BTreeMap::from([
            (
                "orders".to_string(),
                ResolvedScope::Column("tenant_id".to_string()),
            ),
            (
                "lines".to_string(),
                ResolvedScope::Column("tenant_id".to_string()),
            ),
            ("countries".to_string(), ResolvedScope::Unscoped),
            (
                "notes".to_string(),
                ResolvedScope::TenantOrSession {
                    tenant: "tenant_id".to_string(),
                    session: "session_id".to_string(),
                },
            ),
            (
                "packs".to_string(),
                ResolvedScope::TenantOrBase {
                    tenant: "tenant_id".to_string(),
                },
            ),
        ])
    }

    fn own_scope<'a>(
        own: Option<&'a SqlValue>,
        session: Option<&'a SqlValue>,
        keys: &'a BTreeMap<String, ResolvedScope>,
    ) -> OwnScope<'a> {
        OwnScope {
            own,
            session,
            mode: ScopeMode::Own,
            keys: OwnKeys::PerTable(keys),
        }
    }

    // ---- READ -------------------------------------------------------------

    #[test]
    fn read_or_escape_is_neutralized() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        let out = rewrite_own_read(
            "SELECT * FROM orders WHERE 1 = 1 OR 1 = 1",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        // The guest predicate is parenthesised and the bound AND-ed on — a top-level OR can't widen.
        assert_eq!(
            out,
            "SELECT * FROM orders WHERE (1 = 1 OR 1 = 1) AND orders.tenant_id = 'A'"
        );
    }

    #[test]
    fn read_confines_joins_and_subqueries() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        let out = rewrite_own_read(
            "SELECT o.id FROM orders o JOIN lines l ON l.order_id = o.id \
             WHERE o.id IN (SELECT order_id FROM lines)",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(out.contains("o.tenant_id = 'A'"), "{out}");
        assert!(out.contains("l.tenant_id = 'A'"), "{out}");
        // the subquery `lines` is independently confined
        assert!(
            out.matches("tenant_id = 'A'").count() >= 3,
            "root + join + subquery all confined: {out}"
        );
    }

    #[test]
    fn read_tenant_or_session_is_the_disjunct() {
        let k = keys();
        let a = t("A");
        let s = t("sess1");
        // both facts → (tenant = A OR session = sess1)
        let out = rewrite_own_read(
            "SELECT * FROM notes",
            &own_scope(Some(&a), Some(&s), &k),
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "SELECT * FROM notes WHERE (notes.tenant_id = 'A' OR notes.session_id = 'sess1')"
        );
        // session-only (anonymous) → session arm alone
        let out = rewrite_own_read(
            "SELECT * FROM notes",
            &own_scope(None, Some(&s), &k),
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(out, "SELECT * FROM notes WHERE notes.session_id = 'sess1'");
    }

    #[test]
    fn read_tenant_or_base_folds_the_null_base() {
        let k = keys();
        let a = t("A");
        let out = rewrite_own_read(
            "SELECT * FROM packs",
            &own_scope(Some(&a), None, &k),
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "SELECT * FROM packs WHERE (packs.tenant_id = 'A' OR packs.tenant_id IS NULL)"
        );
    }

    #[test]
    fn read_and_write_honor_own_or_null_and_null_only_modes() {
        let k = keys();
        let a = t("A");
        // OwnOrNull READ → (col = A OR col IS NULL).
        let out = rewrite_own_read(
            "SELECT * FROM orders",
            &OwnScope {
                own: Some(&a),
                session: None,
                mode: ScopeMode::OwnOrNull,
                keys: OwnKeys::PerTable(&k),
            },
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "SELECT * FROM orders WHERE (orders.tenant_id = 'A' OR orders.tenant_id IS NULL)"
        );
        // NullOnly READ → col IS NULL (no own value needed).
        let out = rewrite_own_read(
            "SELECT * FROM orders",
            &OwnScope {
                own: None,
                session: None,
                mode: ScopeMode::NullOnly,
                keys: OwnKeys::PerTable(&k),
            },
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(out, "SELECT * FROM orders WHERE orders.tenant_id IS NULL");
        // NullOnly WRITE → the DELETE bound is `tenant_id IS NULL` (baseline-only write).
        let out = rewrite_own_write(
            "DELETE FROM orders WHERE id = 1",
            &OwnScope {
                own: None,
                session: None,
                mode: ScopeMode::NullOnly,
                keys: OwnKeys::PerTable(&k),
            },
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "DELETE FROM orders WHERE (id = 1) AND tenant_id IS NULL"
        );
    }

    #[test]
    fn read_unscoped_adds_no_predicate() {
        let k = keys();
        let a = t("A");
        let out = rewrite_own_read(
            "SELECT * FROM countries",
            &own_scope(Some(&a), None, &k),
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(out, "SELECT * FROM countries");
    }

    #[test]
    fn read_fails_closed_on_undeclared_no_principal_and_unparseable() {
        let k = keys();
        let a = t("A");
        // undeclared table
        assert!(matches!(
            rewrite_own_read("SELECT * FROM secrets", &own_scope(Some(&a), None, &k), Dialect::Sqlite)
                .unwrap_err(),
            TargetRewriteError::TenancyUndeclared(t) if t == "secrets"
        ));
        // own read with no principal (plain tenant table)
        assert!(matches!(
            rewrite_own_read(
                "SELECT * FROM orders",
                &own_scope(None, None, &k),
                Dialect::Sqlite
            )
            .unwrap_err(),
            TargetRewriteError::NoPrincipal
        ));
        // unparseable
        assert!(matches!(
            rewrite_own_read(
                "NOT SQL ;;",
                &own_scope(Some(&a), None, &k),
                Dialect::Sqlite
            )
            .unwrap_err(),
            TargetRewriteError::Parse(_)
        ));
        // a write in a read position
        assert!(matches!(
            rewrite_own_read(
                "DELETE FROM orders",
                &own_scope(Some(&a), None, &k),
                Dialect::Sqlite
            )
            .unwrap_err(),
            TargetRewriteError::NotReadOnly
        ));
    }

    // ---- WRITE ------------------------------------------------------------

    #[test]
    fn update_or_escape_is_neutralized_and_bound() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        let out = rewrite_own_write(
            "UPDATE orders SET status = 'void' WHERE 1 = 1 OR 1 = 1",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "UPDATE orders SET status = 'void' WHERE (1 = 1 OR 1 = 1) AND tenant_id = 'A'"
        );
    }

    #[test]
    fn update_cannot_retenant() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // A guest SET of the tenant column is dropped and re-forced to A.
        let out = rewrite_own_write(
            "UPDATE orders SET tenant_id = 'B', status = 'x' WHERE id = 1",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(
            !out.contains("tenant_id = 'B'"),
            "must not re-tenant: {out}"
        );
        assert!(out.contains("tenant_id = 'A'"), "forced to own: {out}");
        assert!(out.contains("status = 'x'"), "keeps other sets: {out}");
        assert!(
            out.contains("WHERE (id = 1) AND tenant_id = 'A'"),
            "where bound: {out}"
        );
    }

    #[test]
    fn delete_or_escape_is_neutralized_and_bound() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        let out = rewrite_own_write(
            "DELETE FROM orders WHERE id = 1 OR ('a' = 'a')",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "DELETE FROM orders WHERE (id = 1 OR ('a' = 'a')) AND tenant_id = 'A'"
        );
    }

    #[test]
    fn insert_force_stamps_the_tenant_column() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // Guest supplies a victim tenant — it must be overridden to A in place.
        let out = rewrite_own_write(
            "INSERT INTO orders (tenant_id, status) VALUES ('B', 'new')",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(!out.contains("'B'"), "guest tenant overridden: {out}");
        assert!(out.contains("VALUES ('A', 'new')"), "stamped A: {out}");
        // Guest omits the tenant column — it is appended + stamped on every row.
        let out = rewrite_own_write(
            "INSERT INTO orders (status) VALUES ('x'), ('y')",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(
            out.contains("(status, tenant_id)") && out.contains("('x', 'A'), ('y', 'A')"),
            "appended + stamped every row: {out}"
        );
    }

    #[test]
    fn insert_select_source_is_read_confined_and_stamped() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        let out = rewrite_own_write(
            "INSERT INTO orders (status) SELECT status FROM lines WHERE detail = 'x'",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        // The source `lines` is read-confined to A, and the wrapper appends the host tenant literal.
        assert!(
            out.contains("lines.tenant_id = 'A'"),
            "source confined: {out}"
        );
        assert!(
            out.contains("(status, tenant_id)"),
            "tenant column added: {out}"
        );
        assert!(out.contains("'A'"), "host stamp present: {out}");
    }

    #[test]
    fn insert_select_naming_the_tenant_column_is_refused() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        assert!(matches!(
            rewrite_own_write(
                "INSERT INTO orders (tenant_id, status) SELECT tenant_id, status FROM lines",
                &scope,
                Dialect::Sqlite,
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedInsert(_)
        ));
    }

    #[test]
    fn write_tenant_or_session_binds_the_held_axis() {
        let k = keys();
        let a = t("A");
        let s = t("sess1");
        // authenticated → tenant axis
        let out = rewrite_own_write(
            "UPDATE notes SET body = 'x' WHERE id = 1",
            &own_scope(Some(&a), Some(&s), &k),
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(out.contains("WHERE (id = 1) AND tenant_id = 'A'"), "{out}");
        // anonymous → session axis
        let out = rewrite_own_write(
            "UPDATE notes SET body = 'x' WHERE id = 1",
            &own_scope(None, Some(&s), &k),
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(
            out.contains("WHERE (id = 1) AND session_id = 'sess1'"),
            "{out}"
        );
    }

    #[test]
    fn write_fails_closed() {
        let k = keys();
        let a = t("A");
        // Unscoped write refused (global writes are ORM-only).
        assert!(matches!(
            rewrite_own_write("DELETE FROM countries WHERE id = 1", &own_scope(Some(&a), None, &k), Dialect::Sqlite)
                .unwrap_err(),
            TargetRewriteError::UnscopedWrite(t) if t == "countries"
        ));
        // No-principal own write refused.
        assert!(matches!(
            rewrite_own_write(
                "UPDATE orders SET status = 'x' WHERE id = 1",
                &own_scope(None, None, &k),
                Dialect::Sqlite
            )
            .unwrap_err(),
            TargetRewriteError::NoPrincipal
        ));
        // Undeclared table refused.
        assert!(matches!(
            rewrite_own_write("DELETE FROM secrets WHERE id = 1", &own_scope(Some(&a), None, &k), Dialect::Sqlite)
                .unwrap_err(),
            TargetRewriteError::TenancyUndeclared(t) if t == "secrets"
        ));
        // Joined UPDATE target refused.
        assert!(matches!(
            rewrite_own_write(
                "UPDATE orders SET status = 'x' FROM lines WHERE orders.id = lines.order_id",
                &own_scope(Some(&a), None, &k),
                Dialect::Postgres
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedWrite(_)
        ));
        // Unparseable refused.
        assert!(matches!(
            rewrite_own_write(
                "NOT SQL ;;",
                &own_scope(Some(&a), None, &k),
                Dialect::Sqlite
            )
            .unwrap_err(),
            TargetRewriteError::Parse(_)
        ));
        // A CTE-led / multi-statement write refused.
        assert!(matches!(
            rewrite_own_write(
                "DELETE FROM orders WHERE id=1; DELETE FROM lines WHERE id=1",
                &own_scope(Some(&a), None, &k),
                Dialect::Sqlite
            )
            .unwrap_err(),
            TargetRewriteError::NotReadOnly
        ));
        // An ON CONFLICT upsert refused (use the orm surface).
        assert!(matches!(
            rewrite_own_write("INSERT INTO orders (id, status) VALUES (1,'x') ON CONFLICT (id) DO UPDATE SET status='y'", &own_scope(Some(&a), None, &k), Dialect::Sqlite)
                .unwrap_err(),
            TargetRewriteError::UnsupportedInsert(_)
        ));
    }

    #[test]
    fn uniform_keys_scope_every_table_on_one_column() {
        // Legacy `Uniform` (no project schema): every table scopes on the single column, matching
        // the pre-schema raw-SQL marker behavior — but now unescapable (AST-injected).
        let a = t("A");
        let scope = OwnScope {
            own: Some(&a),
            session: None,
            mode: ScopeMode::Own,
            keys: OwnKeys::Uniform("tenant_id".to_string()),
        };
        let out = rewrite_own_read(
            "SELECT * FROM anything WHERE 1=1 OR 1=1",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "SELECT * FROM anything WHERE (1 = 1 OR 1 = 1) AND anything.tenant_id = 'A'"
        );
        let out = rewrite_own_write(
            "UPDATE whatever SET x=1 WHERE 1=1 OR 1=1",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert_eq!(
            out,
            "UPDATE whatever SET x = 1 WHERE (1 = 1 OR 1 = 1) AND tenant_id = 'A'"
        );
    }

    #[test]
    fn insert_tenant_value_is_escaped_not_injected() {
        let k = keys();
        let hostile = t("x' OR '1'='1");
        let scope = own_scope(Some(&hostile), None, &k);
        let out = rewrite_own_write(
            "INSERT INTO orders (status) VALUES ('x')",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        // The host value is a host-derived literal; prove it is escaped (doubled quotes), not broken out.
        assert!(out.contains("'x'' OR ''1''=''1'"), "{out}");
    }

    // ---- the 5 Security-review findings (C1 RETURNING, C2 VALUES cell subquery, C3 DELETE
    //      ORDER BY/LIMIT, HIGH INSERT no/dup collist, MEDIUM REPLACE INTO) ------------------------

    #[test]
    fn c1_returning_subqueries_are_confined_in_all_three_write_confiners() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // UPDATE … RETURNING (SELECT … FROM lines): the RETURNING subquery is read-confined to A.
        let out = rewrite_own_write(
            "UPDATE orders SET status = 'x' WHERE id = 1 \
             RETURNING (SELECT count(*) FROM lines) AS c",
            &scope,
            Dialect::Postgres,
        )
        .unwrap();
        assert!(
            out.contains("lines.tenant_id = 'A'"),
            "UPDATE RETURNING: {out}"
        );
        // DELETE … RETURNING (SELECT … FROM lines).
        let out = rewrite_own_write(
            "DELETE FROM orders WHERE id = 'oA' RETURNING (SELECT count(*) FROM lines)",
            &scope,
            Dialect::Postgres,
        )
        .unwrap();
        assert!(
            out.contains("lines.tenant_id = 'A'"),
            "DELETE RETURNING: {out}"
        );
        // INSERT … RETURNING (SELECT … FROM lines).
        let out = rewrite_own_write(
            "INSERT INTO orders (status) VALUES ('x') \
             RETURNING (SELECT count(*) FROM lines)",
            &scope,
            Dialect::Postgres,
        )
        .unwrap();
        assert!(
            out.contains("lines.tenant_id = 'A'"),
            "INSERT RETURNING: {out}"
        );
    }

    #[test]
    fn c2_insert_values_cell_subqueries_are_confined() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // A subquery in a VALUES cell must be read-confined so it can't exfiltrate another tenant's
        // data into the caller's own row.
        let out = rewrite_own_write(
            "INSERT INTO orders (id, status) VALUES ('x', (SELECT detail FROM lines LIMIT 1))",
            &scope,
            Dialect::Sqlite,
        )
        .unwrap();
        assert!(
            out.contains("lines.tenant_id = 'A'"),
            "VALUES cell subquery: {out}"
        );
    }

    #[test]
    fn c3_delete_with_order_by_or_limit_is_refused() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // A MySQL `DELETE … ORDER BY … LIMIT …` carries read-position sub-expressions the single-table
        // bound does not reach — refuse fail-closed.
        assert!(matches!(
            rewrite_own_write(
                "DELETE FROM orders WHERE id = 1 ORDER BY status LIMIT 1",
                &scope,
                Dialect::Mysql,
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedWrite(_)
        ));
        assert!(matches!(
            rewrite_own_write(
                "DELETE FROM orders WHERE id = 1 LIMIT 1",
                &scope,
                Dialect::Mysql,
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedWrite(_)
        ));
    }

    #[test]
    fn high_insert_without_column_list_is_refused() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // A positional INSERT (no column list) can't be tenant-stamped — the host can't locate the
        // tenant column positionally to override a guest-supplied value. Refuse.
        assert!(matches!(
            rewrite_own_write(
                "INSERT INTO orders VALUES ('x', 'B', 'new')",
                &scope,
                Dialect::Sqlite,
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedInsert(_)
        ));
        // Same for a positional INSERT … SELECT (the host can't align a positional projection either).
        assert!(matches!(
            rewrite_own_write(
                "INSERT INTO orders SELECT * FROM lines",
                &scope,
                Dialect::Sqlite,
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedInsert(_)
        ));
    }

    #[test]
    fn high_insert_with_duplicate_tenant_column_is_refused() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // A column list naming the tenant column twice would leave a second guest-controlled tenant
        // cell after the single-position override. Refuse.
        assert!(matches!(
            rewrite_own_write(
                "INSERT INTO orders (tenant_id, tenant_id, status) VALUES ('B', 'B', 'x')",
                &scope,
                Dialect::Sqlite,
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedInsert(_)
        ));
    }

    #[test]
    fn medium_replace_into_is_refused() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // MySQL `REPLACE INTO` performs an implicit DELETE on a PK/unique collision with NO tenant
        // predicate — it could delete a victim tenant's row. Refuse (route to the orm surface).
        assert!(matches!(
            rewrite_own_write(
                "REPLACE INTO orders (id, status) VALUES ('oB', 'x')",
                &scope,
                Dialect::Mysql,
            )
            .unwrap_err(),
            TargetRewriteError::UnsupportedInsert(_)
        ));
    }

    #[test]
    fn write_backstop_refuses_a_tvf_or_qualified_source_smuggled_into_a_read_position() {
        let k = keys();
        let a = t("A");
        let scope = own_scope(Some(&a), None, &k);
        // A schema-qualified table name in a WHERE subquery is refused by the read walk / backstop.
        assert!(
            rewrite_own_write(
                "UPDATE orders SET status = 'x' WHERE id IN (SELECT order_id FROM other.lines)",
                &scope,
                Dialect::Postgres,
            )
            .is_err()
        );
    }
}
