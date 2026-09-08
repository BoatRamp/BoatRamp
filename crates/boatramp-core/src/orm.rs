//! A typed query AST and an injection-safe SQL compiler — the backing for the `orm`
//! handler binding (`boatramp:handlers/orm`).
//!
//! The compiler turns a typed [`Select`] / [`Insert`] / [`Update`] into a `?N`-placeholder
//! SQL string plus its bound [`SqlValue`] parameters, in order. It is **pure** (no I/O, no
//! wasm/wit deps) so it is fully unit-testable; the binding runs the result through the same
//! [`crate::sql::SqlTransaction`] the raw `sql-query` binding uses, which rewrites `?N` to the
//! engine's native dialect. That shares one execution + dialect substrate across bindings.
//!
//! # Expressiveness
//! [`Expr`] is a recursive scalar expression (column, bound value, aggregate, arithmetic,
//! a small allow-listed [`Func`] set, JSON key-path extraction, Postgres-only `pgvector`
//! distance, and a narrow correlated roll-up — a filtered aggregate over one named table) and
//! [`Predicate`] is a recursive boolean tree (`AND`/`OR`/`NOT` +
//! comparisons/`BETWEEN`/`IN`/`LIKE`/`IS NULL`). Selects add joins, `GROUP BY`/`HAVING`,
//! aliases, ordering and pagination; inserts/updates add `RETURNING`. General scalar
//! subqueries (beyond the correlated roll-up), CTEs and window functions are deliberately out
//! of scope — they go through the raw `sql-query` escape hatch.
//!
//! # Safety
//! - **Every value binds as a parameter** (`?N`); no value is ever formatted into the SQL.
//! - **Identifiers are validated** (`[A-Za-z_][A-Za-z0-9_]*`, optionally `table.column`) and
//!   emitted unquoted — an identifier that isn't a plain name is rejected, so a column/table
//!   name can't smuggle SQL. Function names come from the closed [`Func`] enum (never a
//!   free string), so they can't inject either.
//! - **UPDATE requires a filter** — an unbounded update is refused.
//!
//! # Isolation
//! The project/database boundary is the caller's (the binding opens a per-project database).
//! An optional per-query [`Scope`] (`column = value`) is the *in-site* row-tenancy seam: on a
//! read/update it is conjoined into the `WHERE`; on an insert it is forced into every row. It is
//! guest-declared here (the shim's `Scoped` model); a host-enforced-from-claims variant is a
//! later enhancement (see plans/PLAN-orm-wit.md §4).

use crate::sql::{Dialect, SqlValue};

// ---- expressions -----------------------------------------------------------

/// An aggregate function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agg {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

impl Agg {
    fn keyword(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Sum => "sum",
            Self::Avg => "avg",
            Self::Min => "min",
            Self::Max => "max",
        }
    }
}

/// An arithmetic operator (rendered parenthesized, so precedence is explicit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

impl BinOp {
    fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
        }
    }
}

/// An allow-listed, dialect-portable scalar function. A closed enum (not a free string) so a
/// function name can never inject and only portable functions are reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    Lower,
    Upper,
    Length,
    Trim,
    Abs,
    Round,
    Coalesce,
    /// `CURRENT_TIMESTAMP` (ANSI); takes no arguments.
    Now,
}

impl Func {
    /// The rendered SQL name, and the accepted argument arity as an inclusive `(min, max)`
    /// where `max == None` means variadic.
    fn spec(self) -> (&'static str, usize, Option<usize>) {
        match self {
            Self::Lower => ("lower", 1, Some(1)),
            Self::Upper => ("upper", 1, Some(1)),
            Self::Length => ("length", 1, Some(1)),
            Self::Trim => ("trim", 1, Some(1)),
            Self::Abs => ("abs", 1, Some(1)),
            Self::Round => ("round", 1, Some(2)),
            Self::Coalesce => ("coalesce", 2, None),
            Self::Now => ("current_timestamp", 0, Some(0)),
        }
    }
}

/// A `pgvector` distance metric. A closed enum, so the rendered operator is a compiler
/// constant (never a guest string) and can't inject. Postgres-only (see [`Expr::Distance`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    /// Cosine distance (`<=>`).
    Cosine,
    /// Euclidean / L2 distance (`<->`).
    L2,
}

impl Metric {
    fn operator(self) -> &'static str {
        match self {
            Self::Cosine => "<=>",
            Self::L2 => "<->",
        }
    }
}

/// The argument of a correlated roll-up ([`Expr::RelatedAggregate`]): `*` (only valid for
/// `count`) or a single validated column. Deliberately not a full [`Expr`] — a correlated
/// aggregate takes a column or `*`, nothing free-form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelArg {
    /// `count(*)`.
    Star,
    /// `agg(<column>)`.
    Column(String),
}

/// A scalar expression: the leaf/branch type used in select lists, comparisons, `SET`,
/// `GROUP BY`, `ORDER BY` and join conditions.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// A column reference (`col` or `table.col`), validated + emitted unquoted.
    Column(String),
    /// A literal value — bound as a `?N` parameter, never formatted in.
    Value(SqlValue),
    /// `*`, valid only as the argument of `count(*)`.
    Star,
    /// An aggregate over an inner expression (use [`Expr::Star`] for `count(*)`).
    Aggregate(Agg, Box<Self>),
    /// A parenthesized binary arithmetic expression.
    Binary(BinOp, Box<Self>, Box<Self>),
    /// An allow-listed function call.
    Func(Func, Vec<Self>),
    /// Extract a text value from a JSON column by a key path (e.g. `["a", "b"]` ⇒ `$.a.b`).
    /// Rendered per-dialect (SQLite/MySQL `json_extract`, Postgres `#>>`); each key is
    /// validated as an identifier so the built path can't inject.
    JsonExtract(Box<Self>, Vec<String>),
    /// A `pgvector` distance between two vector expressions, rendered `(left <op> right)`.
    /// **Postgres-only** — SQLite/MySQL have no vector type, so it fails closed
    /// ([`OrmError::BadExpr`]); there is no correct portable fallback. Usable in a select
    /// list and in `ORDER BY` (nearest-neighbour search).
    Distance {
        left: Box<Self>,
        right: Box<Self>,
        metric: Metric,
    },
    /// A vector literal — a bracketed float list (`[0.1, 0.2, …]`) bound as a `?N` parameter
    /// and rendered `?N::vector`. The components are validated as finite numbers; the value
    /// binds (never formatted in), so it can't inject. **Postgres-only.**
    VectorLiteral(String),
    /// A filtered aggregate over a *named* related table, rendered as a scalar subquery
    /// `(SELECT agg(arg) FROM table WHERE <filter>)` — a correlated roll-up. The correlation
    /// to the outer row lives in `filter` (e.g. `child.fk = parent.pk`); unlike a
    /// `LEFT JOIN … GROUP BY` rewrite it never fans out, so several counts per row are just
    /// several select-list entries. Everything reachable is closed/validated: a closed [`Agg`],
    /// a [`RelArg`] column-or-`*`, an identifier-checked `table`, and a bound-parameter
    /// predicate — no arbitrary nested `FROM`, which keeps it mechanically scopable. This is
    /// the *only* subquery form; general scalar subqueries are deliberately not supported.
    RelatedAggregate {
        agg: Agg,
        arg: RelArg,
        table: String,
        filter: Box<Predicate>,
    },
    /// A `CASE WHEN <pred> THEN <expr> … [ELSE <expr>] END` (parenthesized). Each branch's
    /// condition reuses the predicate compiler (bound params). A boolean/comparison `ORDER BY`
    /// term is expressed portably as `ORDER BY CASE WHEN <cond> THEN 0 ELSE 1 END`.
    Case {
        branches: Vec<(Predicate, Self)>,
        otherwise: Option<Box<Self>>,
    },
    /// Extract a JSON value by a **dynamic/bound key**: `(base ->> key)` (key is an expression,
    /// e.g. a bound param — `labels ->> ?`). Postgres + SQLite; MySQL fails closed (its `->>`
    /// needs a `$.path`). Distinct from [`Expr::JsonExtract`], which takes a static key path.
    JsonExtractDyn(Box<Self>, Box<Self>),
    /// jsonb concat/merge `(left || right)` — **Postgres-only** (elsewhere `||` is string concat,
    /// so it fails closed). Used for `col = col || ?::jsonb` merge updates.
    JsonConcat(Box<Self>, Box<Self>),
    /// A **scalar subquery over a named table**: `(SELECT <column> FROM <table> WHERE <filter>)`.
    /// The narrow non-aggregate sibling of [`Expr::RelatedAggregate`] (single named table + a
    /// bound-parameter predicate — mechanically scopable, no arbitrary nested FROM). Used as the
    /// RHS of a comparison, e.g. `id = (SELECT head_version FROM pack WHERE …)`.
    RelatedScalar {
        column: String,
        table: String,
        filter: Box<Predicate>,
    },
    /// A host-resolved **"is this row the caller's own tenant?"** marker — a `0`/`1`-valued
    /// expression the guest builds *without naming the tenant column* (which is host-injected and
    /// hidden). During [`Select::force_scope`] it is lowered, using the same resolved scope the
    /// tenant predicate uses, to `CASE WHEN (<col> IS NOT NULL AND <col> = <own>) THEN 1 ELSE 0 END`
    /// — `1` for the tenant's own rows, `0` for the shared (`NULL`) baseline (or another tenant
    /// under a cross-tenant `all` read). Its purpose is the base-vs-override read: sort the tenant's
    /// override ahead of the shared base (`ORDER BY is_own DESC`) or select/filter on own-ness,
    /// without a raw `ORDER BY (tenant_id IS NOT NULL)`. **Fails closed:** if no own-tenant scope is
    /// applied (an unscoped/`disabled` function), it is never lowered and rendering it is an error.
    IsOwn,
}

impl Expr {
    /// Convenience: a column reference.
    pub fn col(name: impl Into<String>) -> Self {
        Self::Column(name.into())
    }
    /// Convenience: a bound literal.
    pub fn val(v: impl Into<SqlValue>) -> Self {
        Self::Value(v.into())
    }
}

// ---- predicates ------------------------------------------------------------

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "<>",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }
}

/// A recursive boolean predicate tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    /// `AND` of all children (an empty list is the always-true identity `1 = 1`).
    And(Vec<Self>),
    /// `OR` of all children (an empty list is the always-false identity `1 = 0`).
    Or(Vec<Self>),
    /// Negation.
    Not(Box<Self>),
    /// `<left> <op> <right>`.
    Cmp { left: Expr, op: CmpOp, right: Expr },
    /// `<expr> [NOT] BETWEEN <low> AND <high>`.
    Between {
        expr: Expr,
        low: Expr,
        high: Expr,
        negated: bool,
    },
    /// `<expr> [NOT] IN (<values>)`. Empty `values` is the corresponding identity
    /// (`1 = 0` for `IN ()`, `1 = 1` for `NOT IN ()`).
    In {
        expr: Expr,
        values: Vec<Expr>,
        negated: bool,
    },
    /// `<expr> [NOT] LIKE <pattern>`; `insensitive` renders the portable
    /// `lower(<expr>) LIKE lower(<pattern>)` (no dialect-specific `ILIKE`).
    Like {
        expr: Expr,
        pattern: String,
        insensitive: bool,
        negated: bool,
    },
    /// `<expr> IS [NOT] NULL`.
    Null { expr: Expr, negated: bool },
    /// `<expr> [NOT] IN (SELECT <column> FROM <table> WHERE <filter>)` — a narrow single-named-
    /// table IN-subquery (the sibling of [`Expr::RelatedScalar`]; same safe-by-construction shape).
    InSubquery {
        expr: Expr,
        column: String,
        table: String,
        filter: Box<Self>,
        negated: bool,
    },
}

/// Build an `AND` of the given predicates.
pub fn all(preds: impl IntoIterator<Item = Predicate>) -> Predicate {
    Predicate::And(preds.into_iter().collect())
}
/// Build an `OR` of the given predicates.
pub fn any(preds: impl IntoIterator<Item = Predicate>) -> Predicate {
    Predicate::Or(preds.into_iter().collect())
}

// ---- select / insert / update ---------------------------------------------

/// The kind of join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    Left,
}

/// A join: `<kind> JOIN <table>[ AS <alias>] ON <on>`.
#[derive(Debug, Clone, PartialEq)]
pub struct Join {
    pub kind: JoinKind,
    pub table: String,
    pub alias: Option<String>,
    pub on: Predicate,
}

/// A sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

/// An `ORDER BY` term over an expression.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderBy {
    pub expr: Expr,
    pub dir: Direction,
}

/// A `SELECT`-list entry: an expression with an optional `AS <alias>`.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectItem {
    pub expr: Expr,
    pub alias: Option<String>,
}

/// How a tenant [`Scope`] restricts rows for one operation. The host resolves this from the
/// per-function/site `db.read`/`db.write` grant (read modes on `SELECT`, write modes on
/// `INSERT`/`UPDATE`/`DELETE`); a guest never chooses it. `None`-grant (deny) is handled above
/// the compiler — a compiled query always carries a concrete mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeMode {
    /// `column = value` — the resolved tenant only.
    #[default]
    Own,
    /// `(column = value OR column IS NULL)` — the resolved tenant plus the shared/`NULL` baseline.
    OwnOrNull,
    /// `column IS NULL` — the shared/`NULL` baseline only (no tenant rows).
    NullOnly,
    /// No tenant predicate — cross-tenant. Only reachable with an explicit `all` grant under the
    /// operator posture ceiling (both enforced host-side, above this compiler).
    All,
}

/// Per-table tenant-key resolution for a [`Scope`] (Stage 1, PLAN-tenancy-principal D2/D3). Legacy /
/// no project schema ⇒ [`Uniform`](TableKeys::Uniform): every table scopes on [`Scope::column`].
/// A present project schema ⇒ [`PerTable`](TableKeys::PerTable): the authoritative map, `table →
/// Some(column)` to scope that table on `column` (`TenantKeyed` identity tables use their own PK),
/// `table → None` for an `Unscoped` global table (no predicate); a table **absent** from the map is
/// refused ([`OrmError::TenancyUndeclared`], deny-by-default).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TableKeys {
    #[default]
    Uniform,
    PerTable(std::collections::BTreeMap<String, Option<String>>),
}

/// A host-resolved in-site row-tenancy scope. The `value` is the resolved tenant (from the
/// verified source); `mode` decides how it restricts the operation; `keys` resolves the tenant
/// **column per table** (the project schema — R2/D2). Injected by the host on **every** query node
/// (top-level, `UNION` branch, `INSERT … SELECT` source), never guest-set.
#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    pub column: String,
    pub value: SqlValue,
    pub mode: ScopeMode,
    /// Per-table key resolution; [`TableKeys::Uniform`] (the default) preserves the pre-schema
    /// single-column behavior (every table scopes on `column`).
    pub keys: TableKeys,
}

impl Scope {
    /// The tenant column to scope `table` on: `Ok(Some(col))` ⇒ scope on `col`; `Ok(None)` ⇒ the
    /// table is `Unscoped` (no predicate); `Err(TenancyUndeclared)` ⇒ undeclared under a present
    /// schema (deny-by-default). Legacy `Uniform` keys always yield `Some(self.column)`.
    fn column_for<'a>(&'a self, table: &str) -> Result<Option<&'a str>, OrmError> {
        match &self.keys {
            TableKeys::Uniform => Ok(Some(self.column.as_str())),
            TableKeys::PerTable(m) => match m.get(table) {
                Some(Some(col)) => Ok(Some(col.as_str())),
                Some(None) => Ok(None),
                None => Err(OrmError::TenancyUndeclared(table.to_string())),
            },
        }
    }

    /// The scope as a `WHERE`/`HAVING` predicate on `column` for the resolved mode (unqualified), or
    /// `None` for [`ScopeMode::All`] (cross-tenant — no tenant predicate). The single-table SELECT +
    /// the write paths use this with the scope's own `column` (per-table resolution matters only
    /// across joins, handled in `scope_where_pred`).
    fn as_predicate(&self) -> Option<Predicate> {
        self.predicate_on(&self.column, None)
    }

    /// The per-mode predicate on `column`, optionally qualified `<qualifier>.column` — so it binds to
    /// a specific table in a multi-table (join) or subquery context, never accidentally to an
    /// outer/other table with the same column name (a scoping leak). `column` is the per-table
    /// resolved key (see [`Scope::column_for`]).
    fn predicate_on(&self, column: &str, qualifier: Option<&str>) -> Option<Predicate> {
        let col = || {
            Expr::Column(match qualifier {
                Some(q) => format!("{q}.{column}"),
                None => column.to_string(),
            })
        };
        let eq = || Predicate::Cmp {
            left: col(),
            op: CmpOp::Eq,
            right: Expr::Value(self.value.clone()),
        };
        let is_null = || Predicate::Null {
            expr: col(),
            negated: false,
        };
        match self.mode {
            ScopeMode::Own => Some(eq()),
            ScopeMode::OwnOrNull => Some(Predicate::Or(vec![eq(), is_null()])),
            ScopeMode::NullOnly => Some(is_null()),
            ScopeMode::All => None,
        }
    }

    /// The value the scope stamps into a scoped `INSERT`'s tenant column for this mode, or `None`
    /// when the mode forces no column (`all` — the guest supplies the value; a cross-tenant write).
    /// `own`/`own+null` stamp the resolved tenant; `null` stamps `NULL` (the shared baseline).
    fn stamp_value(&self) -> Option<SqlValue> {
        match self.mode {
            ScopeMode::Own | ScopeMode::OwnOrNull => Some(self.value.clone()),
            ScopeMode::NullOnly => Some(SqlValue::Null),
            ScopeMode::All => None,
        }
    }
}

/// A `SELECT`.
#[derive(Debug, Clone, PartialEq)]
pub struct Select {
    pub table: String,
    pub table_alias: Option<String>,
    /// Empty ⇒ `SELECT *`.
    pub columns: Vec<SelectItem>,
    pub joins: Vec<Join>,
    pub filter: Option<Predicate>,
    pub scope: Option<Scope>,
    pub group_by: Vec<Expr>,
    pub having: Option<Predicate>,
    pub distinct: bool,
    /// `DISTINCT ON (<exprs>)` — **Postgres-only** (fails closed elsewhere). Non-empty takes
    /// precedence over `distinct`; empty ⇒ inactive.
    pub distinct_on: Vec<Expr>,
    pub order: Vec<OrderBy>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    /// `UNION [ALL] <query>` — one level (the branch's own `union` is not rendered). Each side
    /// carries its own scope/filter, so both stay tenant-isolated.
    pub union: Option<Box<Union>>,
}

/// A `UNION [ALL]` branch of a [`Select`].
#[derive(Debug, Clone, PartialEq)]
pub struct Union {
    pub all: bool,
    pub query: Select,
}

/// A `column = <expr>` assignment (an INSERT cell or an UPDATE SET).
#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub column: String,
    pub value: Expr,
}

/// One row's cells for an INSERT.
#[derive(Debug, Clone, PartialEq)]
pub struct RowValues {
    pub cells: Vec<Assignment>,
}

/// An `ON CONFLICT (<columns>) DO UPDATE SET <update>` (empty `update` ⇒ `DO NOTHING`).
#[derive(Debug, Clone, PartialEq)]
pub struct OnConflict {
    pub conflict_columns: Vec<String>,
    pub update: Vec<Assignment>,
}

/// An `INSERT` (single- or multi-row), optionally an upsert, optionally `RETURNING`.
#[derive(Debug, Clone, PartialEq)]
pub struct Insert {
    pub table: String,
    pub rows: Vec<RowValues>,
    pub conflict: Option<OnConflict>,
    /// Forces `column = value` into every inserted row (adds or overrides).
    pub scope: Option<Scope>,
    /// `RETURNING <items>` (empty ⇒ none). Not supported by every engine (e.g. MySQL).
    pub returning: Vec<SelectItem>,
    /// `INSERT INTO t (<columns>) <select>` — when set, rows come from a SELECT (`rows` ignored).
    /// Under a scoped write, [`Insert::force_scope`] read-scopes the source **and** host-forces the
    /// target tenant column (dropping any guest projection of it), so the written tenant can't be
    /// forged; without a scope (or `all`) the columns/projection are taken verbatim.
    pub from_select: Option<(Vec<String>, Box<Select>)>,
}

/// An `UPDATE`; `filter` is required (an unbounded update is refused).
#[derive(Debug, Clone, PartialEq)]
pub struct Update {
    pub table: String,
    pub set: Vec<Assignment>,
    pub filter: Predicate,
    pub scope: Option<Scope>,
    pub returning: Vec<SelectItem>,
}

/// A `DELETE`; `filter` is required (an unbounded delete is refused, mirroring [`Update`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Delete {
    pub table: String,
    pub filter: Predicate,
    pub scope: Option<Scope>,
    pub returning: Vec<SelectItem>,
}

impl Select {
    /// Force a host-resolved `scope` onto this `SELECT` **and every nested read node** — its
    /// `UNION` branch — so a tenant scope reaches every row source (a union branch left unscoped
    /// would leak across tenants). Overwrites any pre-existing scope. This is the host's tenant
    /// injection point for reads; the guest never sets a scope of its own.
    pub fn force_scope(&mut self, scope: &Scope) {
        self.scope = Some(scope.clone());
        self.inject_subquery_scope(scope);
        if let Some(u) = self.union.as_mut() {
            u.query.force_scope(scope);
        }
    }
}

impl Insert {
    /// Force the host-resolved tenant scope. `write` stamps the tenant column on a
    /// `VALUES`-based insert (per [`ScopeMode`]); for an `INSERT … SELECT`, the `read` scope is
    /// forced onto the source query (and its nested unions) so the selected rows stay
    /// tenant-isolated, **and** the target tenant column is host-forced too — any guest-supplied
    /// tenant column + its projection is dropped and re-appended bound to the resolved value, so a
    /// guest can't project another tenant's id into the write (a cross-tenant write forgery).
    /// `None` for an axis (cross-tenant `all`) clears that scope — the operation runs unscoped on
    /// that axis, by design (an `all` write's `stamp_value()` is `None`, so nothing is forced).
    pub fn force_scope(&mut self, write: Option<&Scope>, read: Option<&Scope>) {
        self.scope = write.cloned();
        // A subquery embedded in a row cell, an upsert `SET` expr, or a `RETURNING` item is a READ
        // of another table — scope it to that table so it can't read cross-tenant.
        if let Some(r) = read {
            for row in &mut self.rows {
                for cell in &mut row.cells {
                    inject_scope_expr(r, &mut cell.value);
                }
            }
            if let Some(c) = self.conflict.as_mut() {
                for a in &mut c.update {
                    inject_scope_expr(r, &mut a.value);
                }
            }
            for it in &mut self.returning {
                inject_scope_expr(r, &mut it.expr);
            }
        }
        if let Some((cols, src)) = self.from_select.as_mut() {
            match read {
                Some(r) => src.force_scope(r),
                None => src.scope = None,
            }
            // A scoped write owns the tenant column written — never trust the guest's target
            // projection. Drop any guest-supplied tenant column (+ its aligned projection, in the
            // source and every union branch) and re-append it bound to the host value.
            if let Some(v) = write.and_then(Scope::stamp_value) {
                let column = write.expect("stamp implies write").column.clone();
                if let Some(i) = cols.iter().position(|c| same_col(c, &column)) {
                    cols.remove(i);
                    drop_projection_at(src, i);
                }
                cols.push(column);
                push_projection(
                    src,
                    SelectItem {
                        expr: Expr::Value(v),
                        alias: None,
                    },
                );
            }
        }
    }
}

/// Remove the projection at index `i` from a `SELECT` and every one-level `UNION` branch, keeping
/// the branches' column counts aligned (used by [`Insert::force_scope`]).
fn drop_projection_at(s: &mut Select, i: usize) {
    if i < s.columns.len() {
        s.columns.remove(i);
    }
    if let Some(u) = s.union.as_mut() {
        drop_projection_at(&mut u.query, i);
    }
}

/// Append `item` to a `SELECT`'s projection and every one-level `UNION` branch (so both sides of
/// a union source stamp the same host tenant value).
fn push_projection(s: &mut Select, item: SelectItem) {
    s.columns.push(item.clone());
    if let Some(u) = s.union.as_mut() {
        push_projection(&mut u.query, item);
    }
}

/// Conjoin `add` (if any) as the FIRST conjunct of `filter` (`filter := add AND filter`). A
/// no-op empty-`AND` existing filter is replaced outright, so the scope doesn't trail a spurious
/// `AND 1 = 1`.
fn conjoin_front(filter: &mut Predicate, add: Option<Predicate>) {
    let Some(a) = add else { return };
    if matches!(filter, Predicate::And(v) if v.is_empty()) {
        *filter = a;
    } else {
        let existing = std::mem::replace(filter, Predicate::And(Vec::new()));
        *filter = Predicate::And(vec![a, existing]);
    }
}

/// Lower an [`Expr::IsOwn`] marker to a concrete `0`/`1` rank using the resolved `scope` — the
/// same host-resolved tenant `value` the scope predicate uses. `CASE WHEN (<col> IS NOT NULL AND
/// <col> = <own>) THEN 1 ELSE 0 END`: `1` for the caller's own rows, `0` for the shared `NULL`
/// baseline (and for other tenants under a cross-tenant `all` read). The `IS NOT NULL` guard keeps
/// it a proper boolean (never `NULL`) so `ORDER BY … DESC` is portable (own sorts first) across
/// every dialect. The column is unqualified — the base-vs-override read this serves is single-table.
fn own_rank_expr(scope: &Scope) -> Expr {
    let col = || Expr::Column(scope.column.clone());
    let own = Predicate::And(vec![
        Predicate::Null {
            expr: col(),
            negated: true,
        },
        Predicate::Cmp {
            left: col(),
            op: CmpOp::Eq,
            right: Expr::Value(scope.value.clone()),
        },
    ]);
    Expr::Case {
        branches: vec![(own, Expr::Value(SqlValue::Integer(1)))],
        otherwise: Some(Box::new(Expr::Value(SqlValue::Integer(0)))),
    }
}

/// Walk an expression and inject the tenant scope into every **narrow subquery**'s inner filter,
/// qualified to that subquery's own table (`<subtable>.col`), so a subquery can't read another
/// tenant's rows. Recurses into a subquery's filter first (nested subqueries scope their own
/// tables). The correctness twin of [`Select::scope_where_pred`] for the subquery surface. Also
/// lowers any [`Expr::IsOwn`] marker here (where the resolved `scope` is in hand) — so an
/// unlowered `IsOwn` reaching the renderer means no scope was applied, and it fails closed.
fn inject_scope_expr(scope: &Scope, e: &mut Expr) {
    match e {
        Expr::IsOwn => *e = own_rank_expr(scope),
        Expr::RelatedAggregate { table, filter, .. }
        | Expr::RelatedScalar { table, filter, .. } => {
            inject_scope_pred(scope, filter);
            conjoin_front(filter, scope.predicate_on(&scope.column, Some(table)));
        }
        Expr::Aggregate(_, inner) | Expr::JsonExtract(inner, _) => inject_scope_expr(scope, inner),
        Expr::Binary(_, l, r) | Expr::JsonExtractDyn(l, r) | Expr::JsonConcat(l, r) => {
            inject_scope_expr(scope, l);
            inject_scope_expr(scope, r);
        }
        Expr::Distance { left, right, .. } => {
            inject_scope_expr(scope, left);
            inject_scope_expr(scope, right);
        }
        Expr::Func(_, args) => args.iter_mut().for_each(|a| inject_scope_expr(scope, a)),
        Expr::Case {
            branches,
            otherwise,
        } => {
            for (when, then) in branches {
                inject_scope_pred(scope, when);
                inject_scope_expr(scope, then);
            }
            if let Some(e) = otherwise {
                inject_scope_expr(scope, e);
            }
        }
        Expr::Column(_) | Expr::Value(_) | Expr::Star | Expr::VectorLiteral(_) => {}
    }
}

/// Walk a predicate and inject the tenant scope into every narrow subquery (see
/// [`inject_scope_expr`]).
fn inject_scope_pred(scope: &Scope, p: &mut Predicate) {
    match p {
        Predicate::InSubquery {
            expr,
            table,
            filter,
            ..
        } => {
            inject_scope_expr(scope, expr);
            inject_scope_pred(scope, filter);
            conjoin_front(filter, scope.predicate_on(&scope.column, Some(table)));
        }
        Predicate::And(v) | Predicate::Or(v) => {
            v.iter_mut().for_each(|c| inject_scope_pred(scope, c));
        }
        Predicate::Not(inner) => inject_scope_pred(scope, inner),
        Predicate::Cmp { left, right, .. } => {
            inject_scope_expr(scope, left);
            inject_scope_expr(scope, right);
        }
        Predicate::Between {
            expr, low, high, ..
        } => {
            inject_scope_expr(scope, expr);
            inject_scope_expr(scope, low);
            inject_scope_expr(scope, high);
        }
        Predicate::In { expr, values, .. } => {
            inject_scope_expr(scope, expr);
            values.iter_mut().for_each(|v| inject_scope_expr(scope, v));
        }
        Predicate::Like { expr, .. } | Predicate::Null { expr, .. } => {
            inject_scope_expr(scope, expr);
        }
    }
}

impl Select {
    /// Inject the tenant scope into every narrow subquery this SELECT embeds — across ALL of its
    /// expr/pred-bearing fields (projection, `DISTINCT ON`, filter, having, group-by, order, and
    /// join `ON`s) — so a subquery's own table is scoped, not just the outer FROM. Called by
    /// [`Select::force_scope`] after setting the scope. Must stay exhaustive over the Expr/Predicate
    /// fields: a missed field is a cross-tenant subquery leak.
    fn inject_subquery_scope(&mut self, scope: &Scope) {
        for it in &mut self.columns {
            inject_scope_expr(scope, &mut it.expr);
        }
        for e in &mut self.distinct_on {
            inject_scope_expr(scope, e);
        }
        if let Some(f) = self.filter.as_mut() {
            inject_scope_pred(scope, f);
        }
        if let Some(h) = self.having.as_mut() {
            inject_scope_pred(scope, h);
        }
        for e in &mut self.group_by {
            inject_scope_expr(scope, e);
        }
        for o in &mut self.order {
            inject_scope_expr(scope, &mut o.expr);
        }
        for j in &mut self.joins {
            inject_scope_pred(scope, &mut j.on);
        }
    }
}

impl Update {
    /// Force a host-resolved write `scope` (conjoined into `WHERE`), also scoping any subquery in
    /// the `SET` exprs, filter, and `RETURNING` items. Overwrites any prior scope.
    pub fn force_scope(&mut self, scope: &Scope) {
        self.scope = Some(scope.clone());
        for a in &mut self.set {
            inject_scope_expr(scope, &mut a.value);
        }
        inject_scope_pred(scope, &mut self.filter);
        for it in &mut self.returning {
            inject_scope_expr(scope, &mut it.expr);
        }
    }
}

impl Delete {
    /// Force a host-resolved write `scope` (conjoined into `WHERE`), also scoping any subquery in
    /// the filter and `RETURNING` items. Overwrites any prior scope.
    pub fn force_scope(&mut self, scope: &Scope) {
        self.scope = Some(scope.clone());
        inject_scope_pred(scope, &mut self.filter);
        for it in &mut self.returning {
            inject_scope_expr(scope, &mut it.expr);
        }
    }
}

/// Why compilation failed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum OrmError {
    /// An identifier was not a plain `[A-Za-z_][A-Za-z0-9_]*` (optionally `table.column`) name.
    #[error("invalid identifier: {0:?}")]
    InvalidIdentifier(String),
    /// The query was structurally empty (no rows to insert, no columns to set, …).
    #[error("empty query: {0}")]
    Empty(&'static str),
    /// A function was called with the wrong number of arguments, or `*` was used outside
    /// `count(*)`.
    #[error("bad expression: {0}")]
    BadExpr(&'static str),
    /// A scoped query touched a table with **no** entry in the project's [`TenancySchema`]
    /// (deny-by-default, PLAN-tenancy-principal D3): "no key" and "forgot the key" are
    /// indistinguishable, so the safe collapse is to refuse rather than run it unscoped or wrongly
    /// scoped. `Unscoped` is the explicit, reviewed "this table is global"; an absent table is a
    /// misconfiguration the host surfaces (the binding names the component + marker site).
    #[error("tenancy: table {0:?} has no declared scope (deny-by-default)")]
    TenancyUndeclared(String),
}

/// The compiled statement: `?N` SQL plus its bound parameters, in placeholder order.
pub type Compiled = (String, Vec<SqlValue>);

/// Validate a plain identifier or a `table.column` qualified one. Emitted unquoted, so this
/// is the *only* thing standing between a caller-supplied name and the SQL text.
fn ident(name: &str) -> Result<&str, OrmError> {
    let ok = |s: &str| {
        let mut cs = s.chars();
        matches!(cs.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
            && s.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    };
    let valid = match name.split_once('.') {
        Some((t, c)) => !t.is_empty() && !c.is_empty() && ok(t) && ok(c),
        None => ok(name),
    };
    if valid {
        Ok(name)
    } else {
        Err(OrmError::InvalidIdentifier(name.to_string()))
    }
}

/// Whether two identifiers name the **same column** the way the engines resolve unquoted names:
/// ASCII-case-insensitively, ignoring a leading `table.` qualifier. Used by the tenant-scope
/// guards so a guest can't dodge them by re-spelling the tenant column (`TENANT_ID`, `t.tenant_id`)
/// — the DB would still resolve it to the tenant column, but a naive `==` would miss it.
fn same_col(a: &str, b: &str) -> bool {
    let base = |s: &str| s.rsplit('.').next().unwrap_or(s).to_ascii_lowercase();
    base(a) == base(b)
}

/// Accumulates the parameter list and mints `?N` placeholders in order.
#[derive(Default)]
struct Params(Vec<SqlValue>);

impl Params {
    fn bind(&mut self, v: SqlValue) -> String {
        self.0.push(v);
        format!("?{}", self.0.len())
    }
}

/// Render a scalar expression, binding any literals.
fn render_expr(e: &Expr, params: &mut Params, dialect: Dialect) -> Result<String, OrmError> {
    Ok(match e {
        Expr::Column(name) => ident(name)?.to_string(),
        Expr::Value(v) => params.bind(v.clone()),
        Expr::Star => {
            return Err(OrmError::BadExpr(
                "`*` is only valid as the count(*) argument",
            ))
        }
        Expr::Aggregate(agg, inner) => {
            let arg = match inner.as_ref() {
                Expr::Star if *agg == Agg::Count => "*".to_string(),
                Expr::Star => return Err(OrmError::BadExpr("`*` is only valid as count(*)")),
                other => render_expr(other, params, dialect)?,
            };
            format!("{}({arg})", agg.keyword())
        }
        Expr::Binary(op, l, r) => {
            format!(
                "({} {} {})",
                render_expr(l, params, dialect)?,
                op.symbol(),
                render_expr(r, params, dialect)?
            )
        }
        Expr::Func(f, args) => {
            let (name, min, max) = f.spec();
            if args.len() < min || max.is_some_and(|m| args.len() > m) {
                return Err(OrmError::BadExpr("function called with the wrong arity"));
            }
            if args.is_empty() {
                // Nullary (`current_timestamp`) renders without parentheses (ANSI form).
                name.to_string()
            } else {
                let rendered: Result<Vec<String>, _> = args
                    .iter()
                    .map(|a| render_expr(a, params, dialect))
                    .collect();
                format!("{name}({})", rendered?.join(", "))
            }
        }
        Expr::JsonExtract(inner, path) => {
            if path.is_empty() {
                return Err(OrmError::BadExpr("json extract needs at least one key"));
            }
            // Each key is validated as an identifier — the built path can't inject.
            for k in path {
                ident(k)?;
            }
            let base = render_expr(inner, params, dialect)?;
            match dialect {
                // Postgres: `(base) #>> '{a,b}'` — keys validated, safe to inline (there is
                // no portable way to bind a `text[]` path here).
                Dialect::Postgres => format!("({base}) #>> '{{{}}}'", path.join(",")),
                // SQLite/MySQL: `json_extract(base, ?N)` with the `$.a.b` path bound.
                Dialect::Sqlite | Dialect::Mysql => {
                    let p = params.bind(SqlValue::Text(format!("$.{}", path.join("."))));
                    format!("json_extract({base}, {p})")
                }
            }
        }
        Expr::Distance {
            left,
            right,
            metric,
        } => {
            if dialect != Dialect::Postgres {
                return Err(OrmError::BadExpr("vector distance is Postgres-only"));
            }
            format!(
                "({} {} {})",
                render_expr(left, params, dialect)?,
                metric.operator(),
                render_expr(right, params, dialect)?,
            )
        }
        Expr::VectorLiteral(v) => {
            if dialect != Dialect::Postgres {
                return Err(OrmError::BadExpr("vector literals are Postgres-only"));
            }
            let p = params.bind(SqlValue::Text(vector_literal(v)?));
            // The `::vector` cast rides through the `?N` placeholder normaliser unchanged.
            format!("{p}::vector")
        }
        Expr::RelatedAggregate {
            agg,
            arg,
            table,
            filter,
        } => {
            let arg_sql = match arg {
                RelArg::Star if *agg == Agg::Count => "*".to_string(),
                RelArg::Star => return Err(OrmError::BadExpr("`*` is only valid as count(*)")),
                RelArg::Column(c) => ident(c)?.to_string(),
            };
            let table_sql = ident(table)?;
            // The correlated filter reuses the ordinary predicate compiler (bound params); the
            // WHERE clause delimits it, so it renders unparenthesised (`nested = false`).
            let where_sql = render_pred(filter, params, false, dialect)?;
            format!(
                "(SELECT {}({arg_sql}) FROM {table_sql} WHERE {where_sql})",
                agg.keyword()
            )
        }
        Expr::RelatedScalar {
            column,
            table,
            filter,
        } => {
            let col_sql = ident(column)?;
            let table_sql = ident(table)?;
            let where_sql = render_pred(filter, params, false, dialect)?;
            format!("(SELECT {col_sql} FROM {table_sql} WHERE {where_sql})")
        }
        Expr::JsonExtractDyn(base, key) => {
            if matches!(dialect, Dialect::Mysql) {
                return Err(OrmError::BadExpr(
                    "dynamic-key json extract (->> <bound>) is not supported on MySQL",
                ));
            }
            format!(
                "({} ->> {})",
                render_expr(base, params, dialect)?,
                render_expr(key, params, dialect)?,
            )
        }
        Expr::JsonConcat(left, right) => {
            if dialect != Dialect::Postgres {
                return Err(OrmError::BadExpr("json concat (||) is Postgres-only"));
            }
            format!(
                "({} || {})",
                render_expr(left, params, dialect)?,
                render_expr(right, params, dialect)?,
            )
        }
        Expr::Case {
            branches,
            otherwise,
        } => {
            if branches.is_empty() {
                return Err(OrmError::BadExpr("CASE has no WHEN branches"));
            }
            let mut s = String::from("CASE");
            for (when, then) in branches {
                // Params bind in textual order: each WHEN before its THEN, branches in order,
                // ELSE last — matching how `render_pred`/`render_expr` push placeholders.
                let w = render_pred(when, params, false, dialect)?;
                let t = render_expr(then, params, dialect)?;
                s.push_str(&format!(" WHEN {w} THEN {t}"));
            }
            if let Some(e) = otherwise {
                let e = render_expr(e, params, dialect)?;
                s.push_str(&format!(" ELSE {e}"));
            }
            s.push_str(" END");
            format!("({s})")
        }
        // Reaching here means the marker was never lowered — i.e. no own-tenant scope was applied
        // to this query (an unscoped / `disabled` / cross-tenant-`all`-without-value function). Fail
        // closed rather than emit an unscoped ranking.
        Expr::IsOwn => {
            return Err(OrmError::BadExpr(
                "is_own()/own_first() requires an own-tenant (own or own+null) read scope",
            ))
        }
    })
}

/// Validate a `pgvector` literal — a bracketed, comma-separated list of finite numbers
/// (`[0.1, 0.2]`) — returning it whitespace-normalised. The result binds as a parameter, so
/// this is a data-quality gate (a clear early error over a Postgres runtime failure), not an
/// injection defence.
fn vector_literal(s: &str) -> Result<String, OrmError> {
    let inner = s
        .trim()
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .ok_or(OrmError::BadExpr(
            "vector literal must be a bracketed list like [0.1, 0.2]",
        ))?;
    if inner.trim().is_empty() {
        return Err(OrmError::BadExpr(
            "vector literal must have at least one component",
        ));
    }
    let mut parts = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        let f: f64 = p
            .parse()
            .map_err(|_| OrmError::BadExpr("vector literal component is not a number"))?;
        if !f.is_finite() {
            return Err(OrmError::BadExpr("vector literal component must be finite"));
        }
        parts.push(p);
    }
    Ok(format!("[{}]", parts.join(",")))
}

/// Render a predicate; `nested` parenthesizes a compound (`AND`/`OR`) so precedence is explicit.
fn render_pred(
    p: &Predicate,
    params: &mut Params,
    nested: bool,
    dialect: Dialect,
) -> Result<String, OrmError> {
    let compound = |body: String| {
        if nested {
            format!("({body})")
        } else {
            body
        }
    };
    Ok(match p {
        Predicate::And(ps) => {
            if ps.is_empty() {
                "1 = 1".to_string()
            } else {
                let parts: Result<Vec<String>, _> = ps
                    .iter()
                    .map(|c| render_pred(c, params, true, dialect))
                    .collect();
                compound(parts?.join(" AND "))
            }
        }
        Predicate::Or(ps) => {
            if ps.is_empty() {
                "1 = 0".to_string()
            } else {
                let parts: Result<Vec<String>, _> = ps
                    .iter()
                    .map(|c| render_pred(c, params, true, dialect))
                    .collect();
                compound(parts?.join(" OR "))
            }
        }
        Predicate::Not(inner) => format!("NOT {}", render_pred(inner, params, true, dialect)?),
        Predicate::Cmp { left, op, right } => format!(
            "{} {} {}",
            render_expr(left, params, dialect)?,
            op.symbol(),
            render_expr(right, params, dialect)?
        ),
        Predicate::Between {
            expr,
            low,
            high,
            negated,
        } => format!(
            "{} {}BETWEEN {} AND {}",
            render_expr(expr, params, dialect)?,
            if *negated { "NOT " } else { "" },
            render_expr(low, params, dialect)?,
            render_expr(high, params, dialect)?
        ),
        Predicate::In {
            expr,
            values,
            negated,
        } => {
            if values.is_empty() {
                // `IN ()` is a syntax error; render the matching identity.
                if *negated { "1 = 1" } else { "1 = 0" }.to_string()
            } else {
                let lhs = render_expr(expr, params, dialect)?;
                let ph: Result<Vec<String>, _> = values
                    .iter()
                    .map(|v| render_expr(v, params, dialect))
                    .collect();
                format!(
                    "{lhs} {}IN ({})",
                    if *negated { "NOT " } else { "" },
                    ph?.join(", ")
                )
            }
        }
        Predicate::Like {
            expr,
            pattern,
            insensitive,
            negated,
        } => {
            let neg = if *negated { "NOT " } else { "" };
            let lhs = render_expr(expr, params, dialect)?;
            let pat = params.bind(SqlValue::Text(pattern.clone()));
            if *insensitive {
                // Portable case-insensitive LIKE (no dialect-specific ILIKE).
                format!("lower({lhs}) {neg}LIKE lower({pat})")
            } else {
                format!("{lhs} {neg}LIKE {pat}")
            }
        }
        Predicate::Null { expr, negated } => format!(
            "{} IS {}NULL",
            render_expr(expr, params, dialect)?,
            if *negated { "NOT " } else { "" }
        ),
        Predicate::InSubquery {
            expr,
            column,
            table,
            filter,
            negated,
        } => {
            let lhs = render_expr(expr, params, dialect)?;
            let col_sql = ident(column)?;
            let table_sql = ident(table)?;
            let where_sql = render_pred(filter, params, false, dialect)?;
            let not = if *negated { "NOT " } else { "" };
            format!("{lhs} {not}IN (SELECT {col_sql} FROM {table_sql} WHERE {where_sql})")
        }
    })
}

/// Render the `WHERE` body from a pre-built scope predicate + optional filter (scope conjoined
/// first). The scope predicate is built by the caller — single-table for UPDATE/DELETE
/// ([`single_scope_pred`]), multi-table-qualified for a SELECT with joins
/// ([`Select::scope_where_pred`]).
fn render_where(
    scope_pred: Option<Predicate>,
    filter: Option<&Predicate>,
    params: &mut Params,
    dialect: Dialect,
) -> Result<Option<String>, OrmError> {
    // An empty `AND` filter is a no-op (always true) — drop it so it never adds a spurious
    // `AND 1 = 1`. (An empty `OR` means "match nothing" and is kept.)
    let filter = filter.filter(|f| !matches!(f, Predicate::And(v) if v.is_empty()));
    // A lone clause renders directly (no wrapping `AND`, so a top-level `AND`/`OR` filter
    // isn't spuriously parenthesized); scope + filter conjoin as `scope AND (filter)`.
    let combined = match (scope_pred, filter) {
        (None, None) => return Ok(None),
        (Some(s), None) => s,
        (None, Some(f)) => f.clone(),
        (Some(s), Some(f)) => Predicate::And(vec![s, f.clone()]),
    };
    Ok(Some(render_pred(&combined, params, false, dialect)?))
}

/// The single-table scope predicate for an UPDATE/DELETE (validates the column, unqualified).
fn single_scope_pred(scope: Option<&Scope>) -> Result<Option<Predicate>, OrmError> {
    match scope {
        Some(s) => {
            ident(&s.column)?;
            Ok(s.as_predicate())
        }
        None => Ok(None),
    }
}

/// Render a select list (empty ⇒ `*`).
fn render_select_items(
    items: &[SelectItem],
    params: &mut Params,
    dialect: Dialect,
) -> Result<String, OrmError> {
    if items.is_empty() {
        return Ok("*".to_string());
    }
    let parts: Result<Vec<String>, _> = items
        .iter()
        .map(|it| {
            let e = render_expr(&it.expr, params, dialect)?;
            Ok::<String, OrmError>(match &it.alias {
                Some(a) => format!("{e} AS {}", ident(a)?),
                None => e,
            })
        })
        .collect();
    Ok(parts?.join(", "))
}

/// Render a `RETURNING` clause, if any.
fn render_returning(
    items: &[SelectItem],
    params: &mut Params,
    dialect: Dialect,
) -> Result<String, OrmError> {
    if items.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!(
            " RETURNING {}",
            render_select_items(items, params, dialect)?
        ))
    }
}

impl Select {
    /// A `SELECT * FROM <table>` to refine with the public fields.
    pub fn from(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            table_alias: None,
            columns: Vec::new(),
            joins: Vec::new(),
            filter: None,
            scope: None,
            group_by: Vec::new(),
            having: None,
            distinct: false,
            distinct_on: Vec::new(),
            order: Vec::new(),
            limit: None,
            offset: None,
            union: None,
        }
    }

    /// Compile to `?N` SQL + bound parameters for the given dialect. A `UNION` branch renders
    /// after the body, sharing the placeholder sequence (so binds stay in textual order).
    pub fn compile(&self, dialect: Dialect) -> Result<Compiled, OrmError> {
        let mut params = Params::default();
        let sql = self.render_into(&mut params, dialect)?;
        Ok((sql, params.0))
    }

    /// The scope predicate to conjoin into this SELECT's `WHERE`. With **no joins** it's the
    /// single-table (unqualified) predicate. With joins, the per-mode predicate is applied to
    /// **every** table reference — the FROM table plus each join, qualified by its alias-or-name —
    /// so a guest can't read a joined table's cross-tenant rows through the projection (a
    /// join to a table lacking the tenant column then fails closed at the DB, not leaks).
    /// `all`/no-scope ⇒ `None`.
    fn scope_where_pred(&self) -> Result<Option<Predicate>, OrmError> {
        let Some(scope) = &self.scope else {
            return Ok(None);
        };
        if self.joins.is_empty() {
            // Single table: resolve its per-table key (deny-by-default if undeclared; skip if
            // Unscoped), and emit the unqualified predicate on it.
            let Some(col) = scope.column_for(&self.table)? else {
                return Ok(None); // Unscoped table — no tenant predicate
            };
            ident(col)?;
            return Ok(scope.predicate_on(col, None));
        }
        // Joined: each table reference is scoped on its OWN resolved key, qualified by alias-or-name,
        // so a guest can't read a joined table's cross-tenant rows through the projection. A ref
        // whose table is undeclared fails closed (deny-by-default); an `Unscoped` ref adds no
        // predicate (it is global by declaration).
        let refs: Vec<(&str, &str)> = std::iter::once((
            self.table.as_str(),
            self.table_alias.as_deref().unwrap_or(&self.table),
        ))
        .chain(
            self.joins
                .iter()
                .map(|j| (j.table.as_str(), j.alias.as_deref().unwrap_or(&j.table))),
        )
        .collect();
        let mut parts: Vec<Predicate> = Vec::with_capacity(refs.len());
        for (table, qual) in refs {
            ident(qual)?;
            let Some(col) = scope.column_for(table)? else {
                continue; // Unscoped ref
            };
            ident(col)?;
            if let Some(p) = scope.predicate_on(col, Some(qual)) {
                parts.push(p);
            }
        }
        Ok((!parts.is_empty()).then_some(Predicate::And(parts)))
    }

    /// Render the full SELECT (body + any UNION branch) into the shared `params`. Reused by
    /// `INSERT … SELECT` so a source select shares the outer placeholder sequence. Module-private
    /// because `Params` is (Insert::compile, same module, is the other caller).
    fn render_into(&self, params: &mut Params, dialect: Dialect) -> Result<String, OrmError> {
        let mut sql = self.render_body(params, dialect)?;
        if let Some(u) = &self.union {
            let kw = if u.all { "UNION ALL" } else { "UNION" };
            let branch = u.query.render_body(params, dialect)?;
            sql.push_str(&format!(" {kw} {branch}"));
        }
        Ok(sql)
    }

    /// Render one SELECT body (no UNION) into the shared `params`.
    fn render_body(&self, params: &mut Params, dialect: Dialect) -> Result<String, OrmError> {
        let table = ident(&self.table)?;

        // The DISTINCT clause renders before the select list so any bound params order correctly.
        let distinct = if !self.distinct_on.is_empty() {
            if dialect != Dialect::Postgres {
                return Err(OrmError::BadExpr("DISTINCT ON is Postgres-only"));
            }
            let cols = self
                .distinct_on
                .iter()
                .map(|e| render_expr(e, &mut *params, dialect))
                .collect::<Result<Vec<_>, _>>()?;
            format!("DISTINCT ON ({}) ", cols.join(", "))
        } else if self.distinct {
            "DISTINCT ".to_string()
        } else {
            String::new()
        };
        let select_list = render_select_items(&self.columns, &mut *params, dialect)?;
        let mut sql = format!("SELECT {distinct}{select_list} FROM {table}");
        if let Some(a) = &self.table_alias {
            sql.push_str(&format!(" AS {}", ident(a)?));
        }

        for j in &self.joins {
            let jt = ident(&j.table)?;
            let kw = match j.kind {
                JoinKind::Inner => "JOIN",
                JoinKind::Left => "LEFT JOIN",
            };
            sql.push_str(&format!(" {kw} {jt}"));
            if let Some(a) = &j.alias {
                sql.push_str(&format!(" AS {}", ident(a)?));
            }
            sql.push_str(&format!(
                " ON {}",
                render_pred(&j.on, &mut *params, false, dialect)?
            ));
        }

        if let Some(w) = render_where(
            self.scope_where_pred()?,
            self.filter.as_ref(),
            &mut *params,
            dialect,
        )? {
            sql.push_str(&format!(" WHERE {w}"));
        }

        if !self.group_by.is_empty() {
            let terms: Result<Vec<String>, _> = self
                .group_by
                .iter()
                .map(|e| render_expr(e, &mut *params, dialect))
                .collect();
            sql.push_str(&format!(" GROUP BY {}", terms?.join(", ")));
        }

        if let Some(h) = &self.having {
            sql.push_str(&format!(
                " HAVING {}",
                render_pred(h, &mut *params, false, dialect)?
            ));
        }

        if !self.order.is_empty() {
            let terms: Result<Vec<String>, _> = self
                .order
                .iter()
                .map(|o| {
                    let e = render_expr(&o.expr, &mut *params, dialect)?;
                    let d = match o.dir {
                        Direction::Asc => "ASC",
                        Direction::Desc => "DESC",
                    };
                    Ok::<String, OrmError>(format!("{e} {d}"))
                })
                .collect();
            sql.push_str(&format!(" ORDER BY {}", terms?.join(", ")));
        }

        if let Some(n) = self.limit {
            sql.push_str(&format!(" LIMIT {n}"));
        }
        if let Some(n) = self.offset {
            sql.push_str(&format!(" OFFSET {n}"));
        }

        Ok(sql)
    }
}

impl Insert {
    /// Compile to `?N` SQL + bound parameters for the given dialect.
    pub fn compile(&self, dialect: Dialect) -> Result<Compiled, OrmError> {
        let table = ident(&self.table)?;
        let mut params = Params::default();

        // INSERT … SELECT: rows come from a source query sharing the placeholder sequence.
        if let Some((cols, select)) = &self.from_select {
            let col_sql = cols
                .iter()
                .map(|c| ident(c).map(str::to_string))
                .collect::<Result<Vec<_>, _>>()?;
            if col_sql.is_empty() {
                return Err(OrmError::Empty("insert-select has no columns"));
            }
            let select_sql = select.render_into(&mut params, dialect)?;
            let mut sql = format!("INSERT INTO {table} ({}) {select_sql}", col_sql.join(", "));
            sql.push_str(&render_conflict(
                self.conflict.as_ref(),
                self.scope.as_ref(),
                &mut params,
                dialect,
            )?);
            sql.push_str(&render_returning(&self.returning, &mut params, dialect)?);
            return Ok((sql, params.0));
        }

        if self.rows.is_empty() {
            return Err(OrmError::Empty("insert has no rows"));
        }

        // Column set: from the first row (+ the scope column if forced), in a stable order.
        // Every row is coerced to exactly these columns; the scope value overrides.
        let mut columns: Vec<String> = Vec::new();
        for a in &self.rows[0].cells {
            let c = ident(&a.column)?.to_string();
            if !columns.contains(&c) {
                columns.push(c);
            }
        }
        // A scope with a stampable value (own/own+null → the tenant, null → NULL) forces its
        // column into every row. `all` mode stamps nothing (the guest supplies the value —
        // a cross-tenant write), so it behaves like no scope here. The column match is
        // case/qualifier-insensitive (`same_col`) so a guest can't smuggle its own value into the
        // tenant column by re-spelling it (`TENANT_ID`, `t.tenant_id`).
        let stamp = self
            .scope
            .as_ref()
            .and_then(|s| s.stamp_value().map(|v| (s.column.as_str(), v)));
        if let Some((column, _)) = &stamp {
            let c = ident(column)?.to_string();
            if !columns.iter().any(|existing| same_col(existing, &c)) {
                columns.push(c);
            }
        }
        if columns.is_empty() {
            return Err(OrmError::Empty("insert row has no columns"));
        }

        let mut value_groups: Vec<String> = Vec::new();
        for row in &self.rows {
            let mut ph: Vec<String> = Vec::with_capacity(columns.len());
            for col in &columns {
                // The scope forces its column to the resolved stamp; otherwise take the row's
                // cell expr, else NULL.
                if let Some((column, value)) = &stamp {
                    if same_col(column, col) {
                        ph.push(params.bind(value.clone()));
                        continue;
                    }
                }
                match row.cells.iter().find(|a| same_col(&a.column, col)) {
                    Some(a) => ph.push(render_expr(&a.value, &mut params, dialect)?),
                    None => ph.push(params.bind(SqlValue::Null)),
                }
            }
            value_groups.push(format!("({})", ph.join(", ")));
        }

        let mut sql = format!(
            "INSERT INTO {table} ({}) VALUES {}",
            columns.join(", "),
            value_groups.join(", ")
        );

        sql.push_str(&render_conflict(
            self.conflict.as_ref(),
            self.scope.as_ref(),
            &mut params,
            dialect,
        )?);
        sql.push_str(&render_returning(&self.returning, &mut params, dialect)?);
        Ok((sql, params.0))
    }
}

/// Render an `ON CONFLICT (...) DO NOTHING|UPDATE SET ...` clause (empty when `None`). The
/// DO UPDATE assignments bind params, so it takes the shared [`Params`].
///
/// Under a tenant scope with a stampable value (own/null — `all` bounds nothing), the DO UPDATE is
/// **bounded to the tenant's own rows** so a guest upsert can't overwrite another tenant's row via
/// a conflict on a non-tenant-partitioned key, and any assignment targeting the scope column is
/// **dropped** so the tenant of an existing row is never reassigned. MySQL's `ON DUPLICATE KEY
/// UPDATE` can't carry that bound, so a scoped upsert on MySQL is refused (fail-closed).
fn render_conflict(
    conflict: Option<&OnConflict>,
    scope: Option<&Scope>,
    params: &mut Params,
    dialect: Dialect,
) -> Result<String, OrmError> {
    let Some(oc) = conflict else {
        return Ok(String::new());
    };
    let conflict_cols = oc
        .conflict_columns
        .iter()
        .map(|c| ident(c).map(str::to_string))
        .collect::<Result<Vec<_>, _>>()?;
    // The scope that must bound the upsert (own/null → a predicate; all/none contributes nothing).
    let guard = scope.filter(|s| s.stamp_value().is_some());
    let do_nothing = || format!(" ON CONFLICT ({}) DO NOTHING", conflict_cols.join(", "));
    if oc.update.is_empty() {
        return Ok(do_nothing());
    }
    if guard.is_some() && matches!(dialect, Dialect::Mysql) {
        return Err(OrmError::BadExpr(
            "a tenant-scoped upsert (ON CONFLICT DO UPDATE) is unsupported on MySQL \
             (ON DUPLICATE KEY UPDATE cannot be bounded to the tenant's rows)",
        ));
    }
    // Drop any assignment to the scope column: a guest upsert never reassigns an existing row's
    // tenant. If that leaves nothing to update, degrade to DO NOTHING.
    let sets = oc
        .update
        .iter()
        .filter(|a| guard.is_none_or(|s| !same_col(&a.column, &s.column)))
        .map(|a| {
            let c = ident(&a.column)?;
            Ok::<String, OrmError>(format!("{c} = {}", render_expr(&a.value, params, dialect)?))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if sets.is_empty() {
        return Ok(do_nothing());
    }
    let mut clause = format!(
        " ON CONFLICT ({}) DO UPDATE SET {}",
        conflict_cols.join(", "),
        sets.join(", ")
    );
    if let Some(s) = guard {
        // Bound the DO UPDATE to the tenant's own rows (Postgres/SQLite support a trailing WHERE).
        let pred = s
            .as_predicate()
            .expect("a stampable scope always has a predicate");
        clause.push_str(&format!(
            " WHERE {}",
            render_pred(&pred, params, false, dialect)?
        ));
    }
    Ok(clause)
}

impl Update {
    /// Compile to `?N` SQL + bound parameters for the given dialect. An empty `filter` is
    /// refused (no unbounded update).
    pub fn compile(&self, dialect: Dialect) -> Result<Compiled, OrmError> {
        if self.set.is_empty() {
            return Err(OrmError::Empty("update has no assignments"));
        }
        // Guard against an effectively-unbounded update: an empty `AND`/`OR` filter renders to
        // a tautology, so with no tenant scope it would touch every row. Refuse it. (A scope
        // keeps the update bounded, so an empty filter + scope is allowed.)
        let empty_filter =
            matches!(&self.filter, Predicate::And(v) | Predicate::Or(v) if v.is_empty());
        if empty_filter && self.scope.is_none() {
            return Err(OrmError::Empty(
                "update has an empty filter (unbounded update refused)",
            ));
        }
        let table = ident(&self.table)?;
        let mut params = Params::default();

        // A scoped write never reassigns the tenant column: drop any `SET <scope column> = …`
        // (case/qualifier-insensitively) so a guest can't donate its own rows into another
        // tenant's partition (mirrors the ON CONFLICT DO UPDATE guard). The WHERE still bounds the
        // update to own rows; this bounds what it may *change*.
        let scope_col = self
            .scope
            .as_ref()
            .filter(|s| s.stamp_value().is_some())
            .map(|s| s.column.clone());
        // SET binds before WHERE so placeholder order matches the parameter order.
        let sets: Result<Vec<String>, _> = self
            .set
            .iter()
            .filter(|a| {
                scope_col
                    .as_deref()
                    .is_none_or(|col| !same_col(&a.column, col))
            })
            .map(|a| {
                let c = ident(&a.column)?;
                Ok::<String, OrmError>(format!(
                    "{c} = {}",
                    render_expr(&a.value, &mut params, dialect)?
                ))
            })
            .collect();
        let sets = sets?;
        if sets.is_empty() {
            return Err(OrmError::Empty(
                "update has no assignments left after dropping the tenant column",
            ));
        }
        let set_sql = sets.join(", ");

        let where_sql = render_where(
            single_scope_pred(self.scope.as_ref())?,
            Some(&self.filter),
            &mut params,
            dialect,
        )?
        .ok_or(OrmError::Empty(
            "update has an empty filter (unbounded update refused)",
        ))?;

        let mut sql = format!("UPDATE {table} SET {set_sql} WHERE {where_sql}");
        sql.push_str(&render_returning(&self.returning, &mut params, dialect)?);
        Ok((sql, params.0))
    }
}

impl Delete {
    /// Compile to `?N` SQL + bound parameters. An empty `filter` with no scope is refused
    /// (no unbounded delete), exactly as [`Update::compile`]. A scope keeps it bounded, so an
    /// empty filter + scope is allowed.
    pub fn compile(&self, dialect: Dialect) -> Result<Compiled, OrmError> {
        let empty_filter =
            matches!(&self.filter, Predicate::And(v) | Predicate::Or(v) if v.is_empty());
        if empty_filter && self.scope.is_none() {
            return Err(OrmError::Empty(
                "delete has an empty filter (unbounded delete refused)",
            ));
        }
        let table = ident(&self.table)?;
        let mut params = Params::default();
        let where_sql = render_where(
            single_scope_pred(self.scope.as_ref())?,
            Some(&self.filter),
            &mut params,
            dialect,
        )?
        .ok_or(OrmError::Empty(
            "delete has an empty filter (unbounded delete refused)",
        ))?;
        let mut sql = format!("DELETE FROM {table} WHERE {where_sql}");
        sql.push_str(&render_returning(&self.returning, &mut params, dialect)?);
        Ok((sql, params.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> SqlValue {
        SqlValue::Text(s.to_string())
    }
    fn cmp(col: &str, op: CmpOp, v: SqlValue) -> Predicate {
        Predicate::Cmp {
            left: Expr::Column(col.into()),
            op,
            right: Expr::Value(v),
        }
    }
    fn item(e: Expr) -> SelectItem {
        SelectItem {
            expr: e,
            alias: None,
        }
    }

    #[test]
    fn select_basic_where_order_limit() {
        let q = Select {
            columns: vec![item(Expr::col("id")), item(Expr::col("state"))],
            filter: Some(cmp("project_id", CmpOp::Eq, t("prj_1"))),
            order: vec![OrderBy {
                expr: Expr::col("created_at"),
                dir: Direction::Desc,
            }],
            limit: Some(10),
            ..Select::from("work_order")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT id, state FROM work_order WHERE project_id = ?1 ORDER BY created_at DESC LIMIT 10"
        );
        assert_eq!(params, vec![t("prj_1")]);
    }

    #[test]
    fn scope_is_anded_and_bound_first() {
        let q = Select {
            filter: Some(cmp("kind", CmpOp::Eq, t("supplier"))),
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode: ScopeMode::Own,
                keys: TableKeys::Uniform,
            }),
            ..Select::from("party")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM party WHERE tenant_id = ?1 AND kind = ?2"
        );
        assert_eq!(params, vec![t("ten_1"), t("supplier")]);
    }

    #[test]
    fn per_table_keys_scope_each_ref_on_its_own_column() {
        use std::collections::BTreeMap;
        // A settings-page read: storefront_config (Tenant -> tenant_id) LEFT JOIN the identity table
        // `tenant` (TenantKeyed -> its own PK `id`). The host injects the RIGHT column per ref (R2).
        let q = Select {
            table_alias: Some("sc".into()),
            joins: vec![Join {
                kind: JoinKind::Left,
                table: "tenant".into(),
                alias: Some("t".into()),
                on: Predicate::Cmp {
                    left: Expr::col("sc.tenant_id"),
                    op: CmpOp::Eq,
                    right: Expr::col("t.id"),
                },
            }],
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("acme"),
                mode: ScopeMode::Own,
                keys: TableKeys::PerTable(BTreeMap::from([
                    (
                        "storefront_config".to_string(),
                        Some("tenant_id".to_string()),
                    ),
                    ("tenant".to_string(), Some("id".to_string())),
                ])),
            }),
            ..Select::from("storefront_config")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("sc.tenant_id = ?"),
            "base scoped on tenant_id: {sql}"
        );
        assert!(
            sql.contains("t.id = ?"),
            "identity table scoped on its own PK: {sql}"
        );
        assert_eq!(params, vec![t("acme"), t("acme")]);

        // An `Unscoped` join (reference data) adds NO tenant predicate; the base still scopes.
        let mut q2 = Select {
            table_alias: Some("sc".into()),
            joins: vec![Join {
                kind: JoinKind::Left,
                table: "countries".into(),
                alias: Some("c".into()),
                on: Predicate::Cmp {
                    left: Expr::col("sc.country"),
                    op: CmpOp::Eq,
                    right: Expr::col("c.code"),
                },
            }],
            ..Select::from("storefront_config")
        };
        q2.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("acme"),
            mode: ScopeMode::Own,
            keys: TableKeys::PerTable(BTreeMap::from([
                (
                    "storefront_config".to_string(),
                    Some("tenant_id".to_string()),
                ),
                ("countries".to_string(), None),
            ])),
        });
        let (sql2, params2) = q2.compile(Dialect::Sqlite).unwrap();
        assert!(sql2.contains("sc.tenant_id = ?"), "sql2: {sql2}");
        // The `Unscoped` join binds NO tenant value — the sole bind is the base's own tenant — which
        // proves `countries` contributed no scope predicate (a substring check on the alias would
        // false-match `sc.tenant_id`).
        assert_eq!(
            params2,
            vec![t("acme")],
            "unscoped join adds no tenant predicate: {sql2}"
        );

        // An UNDECLARED table under a present schema is refused (deny-by-default, D3).
        let mut q3 = Select::from("secret_table");
        q3.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("acme"),
            mode: ScopeMode::Own,
            keys: TableKeys::PerTable(BTreeMap::from([(
                "orders".to_string(),
                Some("tenant_id".to_string()),
            )])),
        });
        assert!(matches!(
            q3.compile(Dialect::Sqlite),
            Err(OrmError::TenancyUndeclared(tbl)) if tbl == "secret_table"
        ));
    }

    #[test]
    fn is_own_lowers_to_a_case_rank_and_orders_own_first() {
        // The base-vs-override read: `own+null` + `ORDER BY is_own DESC LIMIT 1` — the tenant's
        // override (own) sorts ahead of the shared base (NULL), without the guest naming tenant_id.
        let mut q = Select {
            columns: vec![item(Expr::col("body"))],
            filter: Some(cmp("key_name", CmpOp::Eq, t("k"))),
            order: vec![OrderBy {
                expr: Expr::IsOwn,
                dir: Direction::Desc,
            }],
            limit: Some(1),
            ..Select::from("knowledge_entry")
        };
        q.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("acme"),
            mode: ScopeMode::OwnOrNull,
            keys: TableKeys::Uniform,
        });
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT body FROM knowledge_entry WHERE (tenant_id = ?1 OR tenant_id IS NULL) \
             AND key_name = ?2 ORDER BY (CASE WHEN tenant_id IS NOT NULL AND tenant_id = ?3 \
             THEN ?4 ELSE ?5 END) DESC LIMIT 1"
        );
        // Scope value (own+null), filter, then the is_own rank (own value + 1/0), in textual order.
        assert_eq!(
            params,
            vec![
                t("acme"),
                t("k"),
                t("acme"),
                SqlValue::Integer(1),
                SqlValue::Integer(0)
            ]
        );
    }

    #[test]
    fn is_own_in_select_under_all_uses_the_resolved_own_value() {
        // Under a cross-tenant `all` read is_own means "MY own" (col = <own>), not "any non-base".
        let mut q = Select {
            columns: vec![item(Expr::IsOwn)],
            ..Select::from("t")
        };
        q.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("acme"),
            mode: ScopeMode::All,
            keys: TableKeys::Uniform,
        });
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT (CASE WHEN tenant_id IS NOT NULL AND tenant_id = ?1 THEN ?2 ELSE ?3 END) FROM t"
        );
        assert_eq!(
            params,
            vec![t("acme"), SqlValue::Integer(1), SqlValue::Integer(0)]
        );
    }

    #[test]
    fn is_own_without_a_scope_is_rejected() {
        // No force_scope ⇒ the marker is never lowered ⇒ fail closed at compile (never an unscoped
        // ranking that could leak whether other tenants exist).
        let q = Select {
            order: vec![OrderBy {
                expr: Expr::IsOwn,
                dir: Direction::Desc,
            }],
            ..Select::from("t")
        };
        let err = q.compile(Dialect::Sqlite).unwrap_err();
        assert!(
            matches!(err, OrmError::BadExpr(m) if m.contains("is_own")),
            "expected a fail-closed is_own error, got {err:?}"
        );
    }

    #[test]
    fn is_own_in_a_filter_does_not_subtract_the_scope_predicate() {
        // Using is_own() as a label in WHERE (`WHERE is_own() = 1`, "only my overrides") must keep
        // the independent host tenant predicate — the label can never remove a scope conjunct.
        let mut q = Select {
            filter: Some(Predicate::Cmp {
                left: Expr::IsOwn,
                op: CmpOp::Eq,
                right: Expr::Value(SqlValue::Integer(1)),
            }),
            ..Select::from("notes")
        };
        q.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("acme"),
            mode: ScopeMode::OwnOrNull,
            keys: TableKeys::Uniform,
        });
        let (sql, _) = q.compile(Dialect::Sqlite).unwrap();
        // The host scope predicate is conjoined in FRONT, independent of the is_own label.
        assert!(
            sql.contains("(tenant_id = ?1 OR tenant_id IS NULL) AND"),
            "scope predicate must survive the is_own filter: {sql}"
        );
        assert!(
            sql.contains("CASE WHEN tenant_id IS NOT NULL AND tenant_id = ?2 THEN"),
            "is_own lowered to the own-rank CASE: {sql}"
        );
    }

    fn scoped_select(mode: ScopeMode) -> Select {
        Select {
            filter: Some(cmp("kind", CmpOp::Eq, t("supplier"))),
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode,
                keys: TableKeys::Uniform,
            }),
            ..Select::from("party")
        }
    }

    #[test]
    fn scope_mode_own_or_null_admits_the_shared_baseline() {
        let (sql, params) = scoped_select(ScopeMode::OwnOrNull)
            .compile(Dialect::Sqlite)
            .unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM party WHERE (tenant_id = ?1 OR tenant_id IS NULL) AND kind = ?2"
        );
        assert_eq!(params, vec![t("ten_1"), t("supplier")]);
    }

    #[test]
    fn scope_mode_null_only_sees_only_the_baseline() {
        let (sql, params) = scoped_select(ScopeMode::NullOnly)
            .compile(Dialect::Sqlite)
            .unwrap();
        // The resolved tenant value is not bound at all — NULL-only never references it.
        assert_eq!(
            sql,
            "SELECT * FROM party WHERE tenant_id IS NULL AND kind = ?1"
        );
        assert_eq!(params, vec![t("supplier")]);
    }

    #[test]
    fn scope_mode_all_injects_no_tenant_predicate() {
        let (sql, params) = scoped_select(ScopeMode::All)
            .compile(Dialect::Sqlite)
            .unwrap();
        // `all` (cross-tenant) renders exactly as if unscoped — only the guest filter remains.
        assert_eq!(sql, "SELECT * FROM party WHERE kind = ?1");
        assert_eq!(params, vec![t("supplier")]);
    }

    #[test]
    fn force_scope_reaches_every_union_branch() {
        // A union whose branches start unscoped: force_scope must scope BOTH sides, or the
        // branch would leak across tenants.
        let branch = Select::from("archived_party");
        let mut q = Select {
            union: Some(Box::new(Union {
                all: false,
                query: branch,
            })),
            ..Select::from("party")
        };
        q.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("ten_1"),
            mode: ScopeMode::Own,
            keys: TableKeys::Uniform,
        });
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM party WHERE tenant_id = ?1 UNION SELECT * FROM archived_party WHERE tenant_id = ?2"
        );
        assert_eq!(params, vec![t("ten_1"), t("ten_1")]);
    }

    #[test]
    fn scoped_select_scopes_every_joined_table() {
        // A guest joins a victim table hoping to read its cross-tenant rows via the projection.
        // force_scope must scope the FROM table AND every joined table (qualified by alias/name).
        let mut q = Select {
            table: "orders".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("v.secret"))],
            joins: vec![Join {
                kind: JoinKind::Left,
                table: "victim".into(),
                alias: Some("v".into()),
                on: Predicate::Cmp {
                    left: Expr::col("v.order_id"),
                    op: CmpOp::Eq,
                    right: Expr::col("o.id"),
                },
            }],
            ..Select::from("orders")
        };
        q.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("ten_1"),
            mode: ScopeMode::Own,
            keys: TableKeys::Uniform,
        });
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT v.secret FROM orders AS o LEFT JOIN victim AS v ON v.order_id = o.id \
             WHERE o.tenant_id = ?1 AND v.tenant_id = ?2"
        );
        assert_eq!(params, vec![t("ten_1"), t("ten_1")]);
    }

    #[test]
    fn scoped_returning_and_distinct_on_subqueries_are_scoped() {
        let sub = || Expr::RelatedScalar {
            column: "balance".into(),
            table: "victim".into(),
            filter: Box::new(Predicate::And(Vec::new())),
        };
        let scope = Scope {
            column: "tenant_id".into(),
            value: t("ten_1"),
            mode: ScopeMode::Own,
            keys: TableKeys::Uniform,
        };
        // DELETE … RETURNING (subquery) — the RETURNING read must be scoped to victim.
        let mut del = Delete {
            table: "orders".into(),
            filter: cmp("id", CmpOp::Eq, t("o_1")),
            scope: None,
            returning: vec![item(sub())],
        };
        del.force_scope(&scope);
        let (sql, _) = del.compile(Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("RETURNING (SELECT balance FROM victim WHERE victim.tenant_id = ?"),
            "RETURNING subquery unscoped: {sql}"
        );
        // SELECT DISTINCT ON ((subquery)) — the DISTINCT ON read must be scoped too (PG).
        let mut sel = Select {
            columns: vec![item(Expr::col("id"))],
            distinct_on: vec![sub()],
            ..Select::from("orders")
        };
        sel.force_scope(&scope);
        // The compiler emits portable `?N` placeholders (the backend rewrites to `$N` on PG).
        let (sql, _) = sel.compile(Dialect::Postgres).unwrap();
        assert!(
            sql.contains("DISTINCT ON ((SELECT balance FROM victim WHERE victim.tenant_id = ?"),
            "DISTINCT ON subquery unscoped: {sql}"
        );
    }

    #[test]
    fn scoped_select_scopes_a_subquerys_inner_table() {
        // A guest embeds a scalar subquery over another table; force_scope must scope the
        // subquery's OWN table so it can't read cross-tenant.
        let mut q = Select {
            columns: vec![item(Expr::RelatedScalar {
                column: "balance".into(),
                table: "victim".into(),
                filter: Box::new(Predicate::And(Vec::new())), // guest filter: none
            })],
            ..Select::from("orders")
        };
        q.force_scope(&Scope {
            column: "tenant_id".into(),
            value: t("ten_1"),
            mode: ScopeMode::Own,
            keys: TableKeys::Uniform,
        });
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        // The subquery's WHERE is scoped to victim.tenant_id; the outer to orders (single table).
        assert_eq!(
            sql,
            "SELECT (SELECT balance FROM victim WHERE victim.tenant_id = ?1) \
             FROM orders WHERE tenant_id = ?2"
        );
        assert_eq!(params, vec![t("ten_1"), t("ten_1")]);
    }

    #[test]
    fn insert_select_cannot_forge_the_target_tenant() {
        // A guest projects a chosen tenant id into the target `tenant_id` column. force_scope must
        // drop that projection and re-bind the host-resolved own value — no cross-tenant forgery.
        let source = Select {
            columns: vec![
                item(Expr::val(t("VICTIM"))), // guest-chosen tenant id
                item(Expr::col("total")),
            ],
            ..Select::from("orders")
        };
        let mut ins = Insert {
            table: "orders".into(),
            rows: vec![],
            conflict: None,
            scope: None,
            returning: vec![],
            // `TENANT_ID` (case variant) must still be recognized as the tenant column + dropped.
            from_select: Some((vec!["TENANT_ID".into(), "total".into()], Box::new(source))),
        };
        let own = Scope {
            column: "tenant_id".into(),
            value: t("OWN"),
            mode: ScopeMode::Own,
            keys: TableKeys::Uniform,
        };
        ins.force_scope(Some(&own), Some(&own));
        let (sql, params) = ins.compile(Dialect::Sqlite).unwrap();
        // The tenant column is re-appended last, bound to OWN; the source is read-scoped to OWN.
        assert_eq!(
            sql,
            "INSERT INTO orders (total, tenant_id) SELECT total, ?1 FROM orders WHERE tenant_id = ?2"
        );
        assert_eq!(params, vec![t("OWN"), t("OWN")]);
        assert!(
            !params.contains(&t("VICTIM")),
            "the forged tenant never binds"
        );
    }

    #[test]
    fn scoped_update_cannot_reassign_the_tenant() {
        // A guest tries to donate its own rows to another tenant: SET tenant_id = VICTIM. The
        // scope guard drops that assignment (case-insensitively) while the WHERE stays own-bound.
        let q = Update {
            table: "orders".into(),
            set: vec![
                Assignment {
                    column: "TENANT_ID".into(),
                    value: Expr::val(t("VICTIM")),
                },
                Assignment {
                    column: "status".into(),
                    value: Expr::val(t("paid")),
                },
            ],
            filter: cmp("id", CmpOp::Eq, t("o_1")),
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("OWN"),
                mode: ScopeMode::Own,
                keys: TableKeys::Uniform,
            }),
            returning: vec![],
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "UPDATE orders SET status = ?1 WHERE tenant_id = ?2 AND id = ?3"
        );
        assert_eq!(params, vec![t("paid"), t("OWN"), t("o_1")]);
        assert!(!params.contains(&t("VICTIM")));
    }

    #[test]
    fn scoped_upsert_drops_tenant_reassignment_and_bounds_the_do_update() {
        // A guest upsert tries to (a) reassign tenant_id to VICTIM on conflict and (b) overwrite
        // another tenant's row via a conflict on a non-tenant key. The scope guard must drop the
        // tenant reassignment and bound the DO UPDATE to own rows.
        let mut ins = Insert {
            table: "orders".into(),
            rows: vec![RowValues {
                cells: vec![Assignment {
                    column: "id".into(),
                    value: Expr::val(t("k")),
                }],
            }],
            conflict: Some(OnConflict {
                conflict_columns: vec!["id".into()],
                update: vec![
                    // Case/qualifier-respelled to dodge the drop — must still be caught.
                    Assignment {
                        column: "TENANT_ID".into(),
                        value: Expr::val(t("VICTIM")),
                    },
                    Assignment {
                        column: "total".into(),
                        value: Expr::val(SqlValue::Integer(999)),
                    },
                ],
            }),
            scope: None,
            returning: vec![],
            from_select: None,
        };
        let own = Scope {
            column: "tenant_id".into(),
            value: t("OWN"),
            mode: ScopeMode::Own,
            keys: TableKeys::Uniform,
        };
        ins.force_scope(Some(&own), Some(&own));
        let (sql, params) = ins.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "INSERT INTO orders (id, tenant_id) VALUES (?1, ?2) \
             ON CONFLICT (id) DO UPDATE SET total = ?3 WHERE tenant_id = ?4"
        );
        // The inserted row stamps OWN; the DO UPDATE is bounded to OWN; VICTIM never binds.
        assert_eq!(
            params,
            vec![t("k"), t("OWN"), SqlValue::Integer(999), t("OWN")]
        );
        assert!(!params.contains(&t("VICTIM")));
        // The same scoped upsert is refused on MySQL (no bounded DO UPDATE).
        assert!(matches!(
            ins.compile(Dialect::Mysql),
            Err(OrmError::BadExpr(_))
        ));
    }

    #[test]
    fn insert_null_mode_stamps_null_all_mode_stamps_nothing() {
        let base = |mode| Insert {
            table: "audit_event".into(),
            rows: vec![RowValues {
                cells: vec![Assignment {
                    column: "detail".into(),
                    value: Expr::val(t("x")),
                }],
            }],
            conflict: None,
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode,
                keys: TableKeys::Uniform,
            }),
            returning: vec![],
            from_select: None,
        };
        // null-only write stamps NULL into the tenant column.
        let (sql, params) = base(ScopeMode::NullOnly).compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "INSERT INTO audit_event (detail, tenant_id) VALUES (?1, ?2)"
        );
        assert_eq!(params, vec![t("x"), SqlValue::Null]);
        // all-mode write forces no tenant column — the guest's columns stand verbatim.
        let (sql, params) = base(ScopeMode::All).compile(Dialect::Sqlite).unwrap();
        assert_eq!(sql, "INSERT INTO audit_event (detail) VALUES (?1)");
        assert_eq!(params, vec![t("x")]);
    }

    #[test]
    fn nested_and_or_not_is_parenthesized() {
        // scope AND (state IN (..) AND (priority >= ? OR escalated = ?) AND NOT archived)
        let q = Select {
            filter: Some(all([
                Predicate::In {
                    expr: Expr::col("state"),
                    values: vec![Expr::val(t("po_linked")), Expr::val(t("awarded"))],
                    negated: false,
                },
                any([
                    cmp("priority", CmpOp::Ge, SqlValue::Integer(3)),
                    cmp("escalated", CmpOp::Eq, SqlValue::Boolean(true)),
                ]),
                Predicate::Not(Box::new(cmp(
                    "archived",
                    CmpOp::Eq,
                    SqlValue::Boolean(true),
                ))),
            ])),
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode: ScopeMode::Own,
                keys: TableKeys::Uniform,
            }),
            ..Select::from("order_to_network")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM order_to_network WHERE tenant_id = ?1 AND (state IN (?2, ?3) AND (priority >= ?4 OR escalated = ?5) AND NOT archived = ?6)"
        );
        assert_eq!(
            params,
            vec![
                t("ten_1"),
                t("po_linked"),
                t("awarded"),
                SqlValue::Integer(3),
                SqlValue::Boolean(true),
                SqlValue::Boolean(true)
            ]
        );
    }

    #[test]
    fn group_by_having_with_aggregate_and_alias() {
        let q = Select {
            columns: vec![
                item(Expr::col("network_id")),
                SelectItem {
                    expr: Expr::Aggregate(Agg::Sum, Box::new(Expr::col("committed_minor"))),
                    alias: Some("total".into()),
                },
            ],
            group_by: vec![Expr::col("network_id")],
            having: Some(Predicate::Cmp {
                left: Expr::Aggregate(Agg::Sum, Box::new(Expr::col("committed_minor"))),
                op: CmpOp::Gt,
                right: Expr::val(SqlValue::Integer(1000)),
            }),
            order: vec![OrderBy {
                expr: Expr::col("total"),
                dir: Direction::Desc,
            }],
            ..Select::from("order_to_network")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT network_id, sum(committed_minor) AS total FROM order_to_network GROUP BY network_id HAVING sum(committed_minor) > ?1 ORDER BY total DESC"
        );
        assert_eq!(params, vec![SqlValue::Integer(1000)]);
    }

    #[test]
    fn join_with_alias_and_column_ref_condition() {
        let q = Select {
            columns: vec![item(Expr::Aggregate(Agg::Count, Box::new(Expr::Star)))],
            joins: vec![Join {
                kind: JoinKind::Inner,
                table: "element".into(),
                alias: Some("e".into()),
                on: Predicate::Cmp {
                    left: Expr::col("order_to_network.element_id"),
                    op: CmpOp::Eq,
                    right: Expr::col("e.id"),
                },
            }],
            filter: Some(cmp("order_id", CmpOp::Eq, SqlValue::Integer(7))),
            ..Select::from("order_to_network")
        };
        let (sql, _) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT count(*) FROM order_to_network JOIN element AS e ON order_to_network.element_id = e.id WHERE order_id = ?1"
        );
    }

    #[test]
    fn between_like_insensitive_and_notin() {
        let q = Select {
            filter: Some(all([
                Predicate::Between {
                    expr: Expr::col("amount"),
                    low: Expr::val(SqlValue::Integer(10)),
                    high: Expr::val(SqlValue::Integer(20)),
                    negated: false,
                },
                Predicate::Like {
                    expr: Expr::col("name"),
                    pattern: "ac%".into(),
                    insensitive: true,
                    negated: false,
                },
                Predicate::In {
                    expr: Expr::col("state"),
                    values: vec![Expr::val(t("void"))],
                    negated: true,
                },
            ])),
            ..Select::from("invoice")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM invoice WHERE amount BETWEEN ?1 AND ?2 AND lower(name) LIKE lower(?3) AND state NOT IN (?4)"
        );
        assert_eq!(
            params,
            vec![
                SqlValue::Integer(10),
                SqlValue::Integer(20),
                t("ac%"),
                t("void")
            ]
        );
    }

    #[test]
    fn arithmetic_and_functions_in_select_and_set() {
        let q = Select {
            columns: vec![
                SelectItem {
                    expr: Expr::Func(Func::Lower, vec![Expr::col("email")]),
                    alias: Some("email_lc".into()),
                },
                item(Expr::Binary(
                    BinOp::Mul,
                    Box::new(Expr::col("qty")),
                    Box::new(Expr::val(SqlValue::Integer(2))),
                )),
                item(Expr::Func(
                    Func::Coalesce,
                    vec![Expr::col("nickname"), Expr::val(t("n/a"))],
                )),
            ],
            ..Select::from("account")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT lower(email) AS email_lc, (qty * ?1), coalesce(nickname, ?2) FROM account"
        );
        assert_eq!(params, vec![SqlValue::Integer(2), t("n/a")]);
    }

    #[test]
    fn empty_in_and_not_in_are_identities() {
        let matches_none = Select {
            filter: Some(Predicate::In {
                expr: Expr::col("x"),
                values: vec![],
                negated: false,
            }),
            ..Select::from("t")
        };
        assert_eq!(
            matches_none.compile(Dialect::Sqlite).unwrap().0,
            "SELECT * FROM t WHERE 1 = 0"
        );
        let matches_all = Select {
            filter: Some(Predicate::In {
                expr: Expr::col("x"),
                values: vec![],
                negated: true,
            }),
            ..Select::from("t")
        };
        assert_eq!(
            matches_all.compile(Dialect::Sqlite).unwrap().0,
            "SELECT * FROM t WHERE 1 = 1"
        );
    }

    #[test]
    fn insert_with_scope_and_returning() {
        let q = Insert {
            table: "work_area".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "id".into(),
                        value: Expr::val(t("wa_1")),
                    },
                    Assignment {
                        column: "project_id".into(),
                        value: Expr::val(t("prj_1")),
                    },
                ],
            }],
            conflict: None,
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode: ScopeMode::Own,
                keys: TableKeys::Uniform,
            }),
            returning: vec![item(Expr::col("id"))],
            from_select: None,
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "INSERT INTO work_area (id, project_id, tenant_id) VALUES (?1, ?2, ?3) RETURNING id"
        );
        assert_eq!(params, vec![t("wa_1"), t("prj_1"), t("ten_1")]);
    }

    #[test]
    fn upsert_do_update_and_do_nothing() {
        let base = |update: Vec<Assignment>| Insert {
            table: "country_pack".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "country".into(),
                        value: Expr::val(t("US")),
                    },
                    Assignment {
                        column: "currency".into(),
                        value: Expr::val(t("USD")),
                    },
                ],
            }],
            conflict: Some(OnConflict {
                conflict_columns: vec!["tenant_id".into(), "country".into()],
                update,
            }),
            scope: None,
            returning: vec![],
            from_select: None,
        };
        let (sql_do, _) = base(vec![Assignment {
            column: "currency".into(),
            value: Expr::val(t("USD")),
        }])
        .compile(Dialect::Sqlite)
        .unwrap();
        assert_eq!(
            sql_do,
            "INSERT INTO country_pack (country, currency) VALUES (?1, ?2) ON CONFLICT (tenant_id, country) DO UPDATE SET currency = ?3"
        );
        let (sql_nothing, _) = base(vec![]).compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql_nothing,
            "INSERT INTO country_pack (country, currency) VALUES (?1, ?2) ON CONFLICT (tenant_id, country) DO NOTHING"
        );
    }

    #[test]
    fn update_binds_set_before_where_and_supports_expr_set() {
        let q = Update {
            table: "counter".into(),
            set: vec![Assignment {
                column: "hits".into(),
                value: Expr::Binary(
                    BinOp::Add,
                    Box::new(Expr::col("hits")),
                    Box::new(Expr::val(SqlValue::Integer(1))),
                ),
            }],
            filter: cmp("id", CmpOp::Eq, t("c_1")),
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode: ScopeMode::Own,
                keys: TableKeys::Uniform,
            }),
            returning: vec![],
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "UPDATE counter SET hits = (hits + ?1) WHERE tenant_id = ?2 AND id = ?3"
        );
        assert_eq!(params, vec![SqlValue::Integer(1), t("ten_1"), t("c_1")]);
    }

    #[test]
    fn identifier_injection_is_rejected() {
        let q = Select {
            columns: vec![item(Expr::col("id; DROP TABLE users"))],
            ..Select::from("t")
        };
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn qualified_identifier_allowed() {
        let q = Select {
            columns: vec![item(Expr::col("t.id"))],
            ..Select::from("t")
        };
        assert_eq!(q.compile(Dialect::Sqlite).unwrap().0, "SELECT t.id FROM t");
    }

    #[test]
    fn function_arity_is_checked() {
        let q = Select {
            columns: vec![item(Expr::Func(Func::Lower, vec![]))],
            ..Select::from("t")
        };
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::BadExpr(_))
        ));
    }

    #[test]
    fn update_with_empty_all_filter_is_refused() {
        let q = Update {
            table: "t".into(),
            set: vec![Assignment {
                column: "x".into(),
                value: Expr::val(SqlValue::Integer(1)),
            }],
            filter: Predicate::And(vec![]),
            scope: None,
            returning: vec![],
        };
        // An empty filter with no scope is an effectively-unbounded update → refused.
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::Empty(_))
        ));
    }

    #[test]
    fn empty_filter_with_scope_is_allowed() {
        // A scope keeps it bounded, so an empty filter + scope compiles.
        let q = Update {
            table: "t".into(),
            set: vec![Assignment {
                column: "x".into(),
                value: Expr::val(SqlValue::Integer(1)),
            }],
            filter: Predicate::And(vec![]),
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode: ScopeMode::Own,
                keys: TableKeys::Uniform,
            }),
            returning: vec![],
        };
        assert_eq!(
            q.compile(Dialect::Sqlite).unwrap().0,
            "UPDATE t SET x = ?1 WHERE tenant_id = ?2"
        );
    }

    #[test]
    fn delete_by_predicate_compiles() {
        let q = Delete {
            table: "payment".into(),
            filter: cmp("id", CmpOp::Eq, t("pay_1")),
            scope: None,
            returning: vec![],
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(sql, "DELETE FROM payment WHERE id = ?1");
        assert_eq!(params, vec![t("pay_1")]);
    }

    #[test]
    fn delete_returning_renders() {
        // The one DELETE … RETURNING shape (consume-and-read a pending signup). `?N` is emitted
        // for every dialect — the backend rewrites to the engine's native placeholder.
        let q = Delete {
            table: "pending_signup".into(),
            filter: cmp("slug", CmpOp::Eq, t("acme")),
            scope: None,
            returning: vec![item(Expr::col("name")), item(Expr::col("password_hash"))],
        };
        assert_eq!(
            q.compile(Dialect::Postgres).unwrap().0,
            "DELETE FROM pending_signup WHERE slug = ?1 RETURNING name, password_hash"
        );
    }

    #[test]
    fn delete_with_empty_filter_is_refused() {
        // Empty filter, no scope → effectively-unbounded delete → refused (mirrors UPDATE).
        let q = Delete {
            table: "t".into(),
            filter: Predicate::And(vec![]),
            scope: None,
            returning: vec![],
        };
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::Empty(_))
        ));
    }

    #[test]
    fn delete_empty_filter_with_scope_is_allowed() {
        // A scope keeps it bounded, so an empty filter + scope compiles (bulk clear within tenant).
        let q = Delete {
            table: "t".into(),
            filter: Predicate::And(vec![]),
            scope: Some(Scope {
                column: "tenant_id".into(),
                value: t("ten_1"),
                mode: ScopeMode::Own,
                keys: TableKeys::Uniform,
            }),
            returning: vec![],
        };
        assert_eq!(
            q.compile(Dialect::Sqlite).unwrap().0,
            "DELETE FROM t WHERE tenant_id = ?1"
        );
    }

    #[test]
    fn delete_rejects_identifier_injection_in_table() {
        let q = Delete {
            table: "t; DROP TABLE users".into(),
            filter: cmp("id", CmpOp::Eq, t("x")),
            scope: None,
            returning: vec![],
        };
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn case_expression_renders_with_bound_params() {
        // CASE WHEN state = ? THEN 1 ELSE 0 END as a select item; params bind in textual order.
        let q = Select {
            columns: vec![item(Expr::Case {
                branches: vec![(
                    cmp("state", CmpOp::Eq, t("open")),
                    Expr::val(SqlValue::Integer(1)),
                )],
                otherwise: Some(Box::new(Expr::val(SqlValue::Integer(0)))),
            })],
            ..Select::from("t")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT (CASE WHEN state = ?1 THEN ?2 ELSE ?3 END) FROM t"
        );
        assert_eq!(
            params,
            vec![t("open"), SqlValue::Integer(1), SqlValue::Integer(0)]
        );
    }

    #[test]
    fn distinct_on_renders_on_postgres_and_fails_closed_elsewhere() {
        let q = Select {
            distinct_on: vec![Expr::col("key")],
            columns: vec![item(Expr::col("key")), item(Expr::col("val"))],
            ..Select::from("consent_state")
        };
        assert_eq!(
            q.compile(Dialect::Postgres).unwrap().0,
            "SELECT DISTINCT ON (key) key, val FROM consent_state"
        );
        // No portable rewrite on SQLite/MySQL — fail closed.
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::BadExpr(_))
        ));
    }

    #[test]
    fn empty_case_is_rejected() {
        let q = Select {
            columns: vec![item(Expr::Case {
                branches: vec![],
                otherwise: None,
            })],
            ..Select::from("t")
        };
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::BadExpr(_))
        ));
    }

    #[test]
    fn json_extract_dyn_binds_the_key() {
        // labels ->> ?  (bound key). Postgres + SQLite render `->>`; MySQL fails closed.
        let q = Select {
            columns: vec![item(Expr::JsonExtractDyn(
                Box::new(Expr::col("labels")),
                Box::new(Expr::val(t("en"))),
            ))],
            ..Select::from("vocabulary_term")
        };
        for d in [Dialect::Postgres, Dialect::Sqlite] {
            assert_eq!(
                q.compile(d).unwrap().0,
                "SELECT (labels ->> ?1) FROM vocabulary_term"
            );
        }
        assert!(matches!(
            q.compile(Dialect::Mysql),
            Err(OrmError::BadExpr(_))
        ));
    }

    #[test]
    fn json_concat_merge_is_postgres_only() {
        // UPDATE request SET brief_state = brief_state || ?::jsonb WHERE id = ?
        let q = Update {
            table: "request".into(),
            set: vec![Assignment {
                column: "brief_state".into(),
                value: Expr::JsonConcat(
                    Box::new(Expr::col("brief_state")),
                    Box::new(Expr::val(SqlValue::Json("{\"a\":1}".into()))),
                ),
            }],
            filter: cmp("id", CmpOp::Eq, t("req_1")),
            scope: None,
            returning: vec![],
        };
        assert_eq!(
            q.compile(Dialect::Postgres).unwrap().0,
            "UPDATE request SET brief_state = (brief_state || ?1) WHERE id = ?2"
        );
        assert!(matches!(
            q.compile(Dialect::Sqlite),
            Err(OrmError::BadExpr(_))
        ));
    }

    #[test]
    fn union_renders_both_bodies_with_shared_params() {
        // slug-reservation check across two tables; the branches share the ?N sequence.
        let q = Select {
            columns: vec![item(Expr::col("slug"))],
            filter: Some(cmp("slug", CmpOp::Eq, t("acme"))),
            union: Some(Box::new(Union {
                all: false,
                query: Select {
                    columns: vec![item(Expr::col("slug"))],
                    filter: Some(cmp("slug", CmpOp::Eq, t("acme"))),
                    ..Select::from("reserved_slug")
                },
            })),
            ..Select::from("pending_signup")
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT slug FROM pending_signup WHERE slug = ?1 \
             UNION SELECT slug FROM reserved_slug WHERE slug = ?2"
        );
        assert_eq!(params, vec![t("acme"), t("acme")]);
    }

    #[test]
    fn insert_from_select_shares_params_and_carries_no_auto_scope() {
        // INSERT INTO ref (a, b) SELECT x, y FROM src WHERE id = ? (attach_reference shape).
        let q = Insert {
            table: "portfolio_ref".into(),
            rows: vec![],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: Some((
                vec!["a".into(), "b".into()],
                Box::new(Select {
                    columns: vec![item(Expr::col("x")), item(Expr::col("y"))],
                    filter: Some(cmp("id", CmpOp::Eq, t("pi_1"))),
                    ..Select::from("portfolio_item")
                }),
            )),
        };
        let (sql, params) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "INSERT INTO portfolio_ref (a, b) SELECT x, y FROM portfolio_item WHERE id = ?1"
        );
        assert_eq!(params, vec![t("pi_1")]);
    }

    #[test]
    fn related_scalar_and_in_subquery_render() {
        // id = (SELECT head_version FROM pack WHERE id = ?1)
        let q = Select {
            columns: vec![item(Expr::col("id"))],
            filter: Some(Predicate::Cmp {
                left: Expr::col("id"),
                op: CmpOp::Eq,
                right: Expr::RelatedScalar {
                    column: "head_version".into(),
                    table: "pack".into(),
                    filter: Box::new(cmp("id", CmpOp::Eq, t("pk_1"))),
                },
            }),
            ..Select::from("pack_version")
        };
        assert_eq!(
            q.compile(Dialect::Sqlite).unwrap().0,
            "SELECT id FROM pack_version WHERE id = (SELECT head_version FROM pack WHERE id = ?1)"
        );

        // doc_id IN (SELECT id FROM document WHERE tenant_id = ?1)
        let q2 = Select {
            columns: vec![item(Expr::col("x"))],
            filter: Some(Predicate::InSubquery {
                expr: Expr::col("doc_id"),
                column: "id".into(),
                table: "document".into(),
                filter: Box::new(cmp("tenant_id", CmpOp::Eq, t("ten_1"))),
                negated: false,
            }),
            ..Select::from("access")
        };
        assert_eq!(
            q2.compile(Dialect::Sqlite).unwrap().0,
            "SELECT x FROM access WHERE doc_id IN (SELECT id FROM document WHERE tenant_id = ?1)"
        );
    }

    #[test]
    fn now_renders_without_parens() {
        let q = Select {
            columns: vec![item(Expr::Func(Func::Now, vec![]))],
            ..Select::from("t")
        };
        assert_eq!(
            q.compile(Dialect::Sqlite).unwrap().0,
            "SELECT current_timestamp FROM t"
        );
    }

    fn json_query() -> Select {
        Select {
            columns: vec![item(Expr::JsonExtract(
                Box::new(Expr::col("metadata")),
                vec!["status".into()],
            ))],
            filter: Some(Predicate::Cmp {
                left: Expr::JsonExtract(
                    Box::new(Expr::col("metadata")),
                    vec!["a".into(), "b".into()],
                ),
                op: CmpOp::Eq,
                right: Expr::val(t("x")),
            }),
            ..Select::from("doc")
        }
    }

    #[test]
    fn json_extract_sqlite_and_mysql_bind_the_path() {
        for d in [Dialect::Sqlite, Dialect::Mysql] {
            let (sql, params) = json_query().compile(d).unwrap();
            assert_eq!(
                sql,
                "SELECT json_extract(metadata, ?1) FROM doc WHERE json_extract(metadata, ?2) = ?3"
            );
            assert_eq!(params, vec![t("$.status"), t("$.a.b"), t("x")]);
        }
    }

    #[test]
    fn json_extract_postgres_inlines_the_validated_path() {
        let (sql, params) = json_query().compile(Dialect::Postgres).unwrap();
        assert_eq!(
            sql,
            "SELECT (metadata) #>> '{status}' FROM doc WHERE (metadata) #>> '{a,b}' = ?1"
        );
        assert_eq!(params, vec![t("x")]);
    }

    #[test]
    fn json_extract_key_injection_is_rejected() {
        let q = Select {
            columns: vec![item(Expr::JsonExtract(
                Box::new(Expr::col("m")),
                vec!["a'); DROP TABLE t--".into()],
            ))],
            ..Select::from("doc")
        };
        assert!(matches!(
            q.compile(Dialect::Postgres),
            Err(OrmError::InvalidIdentifier(_))
        ));
    }

    // ---- pgvector distance (Postgres-only) -----------------------------------

    fn knn_query() -> Select {
        // Nearest-neighbour: `ORDER BY embedding <=> [q] LIMIT k`.
        Select {
            columns: vec![item(Expr::col("id"))],
            order: vec![OrderBy {
                expr: Expr::Distance {
                    left: Box::new(Expr::col("embedding")),
                    right: Box::new(Expr::VectorLiteral("[0.1, 0.2, 0.3]".into())),
                    metric: Metric::Cosine,
                },
                dir: Direction::Asc,
            }],
            limit: Some(5),
            ..Select::from("doc")
        }
    }

    #[test]
    fn distance_orders_by_cosine_nearest_neighbour_on_postgres() {
        let (sql, params) = knn_query().compile(Dialect::Postgres).unwrap();
        assert_eq!(
            sql,
            "SELECT id FROM doc ORDER BY (embedding <=> ?1::vector) ASC LIMIT 5"
        );
        // The literal binds as a parameter (whitespace-normalised), never formatted in.
        assert_eq!(params, vec![t("[0.1,0.2,0.3]")]);
    }

    #[test]
    fn distance_l2_in_select_list_on_postgres() {
        let q = Select {
            columns: vec![
                item(Expr::col("id")),
                SelectItem {
                    expr: Expr::Distance {
                        left: Box::new(Expr::col("embedding")),
                        right: Box::new(Expr::VectorLiteral("[-1, 2e0, 3.5]".into())),
                        metric: Metric::L2,
                    },
                    alias: Some("dist".into()),
                },
            ],
            ..Select::from("doc")
        };
        let (sql, params) = q.compile(Dialect::Postgres).unwrap();
        assert_eq!(
            sql,
            "SELECT id, (embedding <-> ?1::vector) AS dist FROM doc"
        );
        assert_eq!(params, vec![t("[-1,2e0,3.5]")]);
    }

    #[test]
    fn distance_fails_closed_off_postgres() {
        for d in [Dialect::Sqlite, Dialect::Mysql] {
            assert!(
                matches!(knn_query().compile(d), Err(OrmError::BadExpr(_))),
                "vector distance must be rejected on {d:?}"
            );
        }
    }

    #[test]
    fn vector_literal_fails_closed_off_postgres() {
        for d in [Dialect::Sqlite, Dialect::Mysql] {
            let q = Select {
                columns: vec![item(Expr::VectorLiteral("[1, 2]".into()))],
                ..Select::from("doc")
            };
            assert!(
                matches!(q.compile(d), Err(OrmError::BadExpr(_))),
                "vector literal must be rejected on {d:?}"
            );
        }
    }

    #[test]
    fn malformed_vector_literal_is_rejected() {
        // No brackets, non-numeric, empty, unclosed, empty component, and non-finite
        // (`inf`/`NaN` parse as floats but must be refused).
        for bad in [
            "1,2",
            "[a, b]",
            "[]",
            "[1, 2",
            "[1,,2]",
            "[Infinity]",
            "[1, NaN]",
        ] {
            let q = Select {
                columns: vec![item(Expr::VectorLiteral(bad.to_string()))],
                ..Select::from("doc")
            };
            assert!(
                matches!(q.compile(Dialect::Postgres), Err(OrmError::BadExpr(_))),
                "expected {bad:?} to be rejected"
            );
        }
    }

    // ---- correlated roll-ups (related-aggregate) -----------------------------

    /// `agg(arg) FROM table WHERE child.fk = parent.pk [AND extra]` — the correlation is a
    /// column-to-column comparison in the subquery's filter.
    fn related(agg: Agg, arg: RelArg, table: &str, filter: Predicate) -> Expr {
        Expr::RelatedAggregate {
            agg,
            arg,
            table: table.into(),
            filter: Box::new(filter),
        }
    }
    fn correlate(fk: &str, pk: &str) -> Predicate {
        Predicate::Cmp {
            left: Expr::col(fk),
            op: CmpOp::Eq,
            right: Expr::col(pk),
        }
    }

    #[test]
    fn related_aggregate_single_correlated_count() {
        // construens subgraph-chain:701 — count of child rows per parent, no fan-out.
        let q = Select {
            columns: vec![
                item(Expr::col("id")),
                SelectItem {
                    expr: related(
                        Agg::Count,
                        RelArg::Star,
                        "element",
                        correlate("element.order_id", "work_order.id"),
                    ),
                    alias: Some("element_count".into()),
                },
            ],
            ..Select::from("work_order")
        };
        let (sql, params) = q.compile(Dialect::Postgres).unwrap();
        assert_eq!(
            sql,
            "SELECT id, (SELECT count(*) FROM element WHERE element.order_id = work_order.id) AS element_count FROM work_order"
        );
        assert!(params.is_empty());
    }

    #[test]
    fn related_aggregate_two_counts_bind_distinct_params_and_dont_fan_out() {
        // Two correlated counts in one SELECT — each its own subquery (no join, no fan-out),
        // and their bound filters take distinct `?N` in left-to-right order.
        let with_status = |child: &str, fk: &str, status: &str| {
            related(
                Agg::Count,
                RelArg::Star,
                child,
                Predicate::And(vec![
                    correlate(fk, "party.id"),
                    Predicate::Cmp {
                        left: Expr::col("status"),
                        op: CmpOp::Eq,
                        right: Expr::val(t(status)),
                    },
                ]),
            )
        };
        let q = Select {
            columns: vec![
                item(with_status("party_role", "party_role.party_id", "active")),
                item(with_status(
                    "party_qualification",
                    "party_qualification.party_id",
                    "valid",
                )),
            ],
            ..Select::from("party")
        };
        let (sql, params) = q.compile(Dialect::Postgres).unwrap();
        assert_eq!(
            sql,
            "SELECT \
             (SELECT count(*) FROM party_role WHERE party_role.party_id = party.id AND status = ?1), \
             (SELECT count(*) FROM party_qualification WHERE party_qualification.party_id = party.id AND status = ?2) \
             FROM party"
        );
        assert_eq!(params, vec![t("active"), t("valid")]);
    }

    #[test]
    fn related_aggregate_with_temporal_or_filter() {
        // construens subgraph-chain:731 — correlated count with a temporal `valid_to` filter.
        let q = Select {
            columns: vec![SelectItem {
                expr: related(
                    Agg::Count,
                    RelArg::Star,
                    "party_qualification",
                    Predicate::And(vec![
                        correlate("party_qualification.party_id", "party.id"),
                        Predicate::Or(vec![
                            Predicate::Null {
                                expr: Expr::col("valid_to"),
                                negated: false,
                            },
                            Predicate::Cmp {
                                left: Expr::col("valid_to"),
                                op: CmpOp::Gt,
                                right: Expr::val(t("2026-01-01")),
                            },
                        ]),
                    ]),
                ),
                alias: Some("active_quals".into()),
            }],
            ..Select::from("party")
        };
        let (sql, params) = q.compile(Dialect::Postgres).unwrap();
        assert_eq!(
            sql,
            "SELECT (SELECT count(*) FROM party_qualification WHERE party_qualification.party_id = party.id AND (valid_to IS NULL OR valid_to > ?1)) AS active_quals FROM party"
        );
        assert_eq!(params, vec![t("2026-01-01")]);
    }

    #[test]
    fn related_aggregate_max_over_a_column_is_portable() {
        // A correlated MAX over a column (construens subgraph-chain:1932 shape) — an ordinary
        // subquery, portable across engines (not Postgres-specific like vector distance).
        let q = Select {
            columns: vec![SelectItem {
                expr: related(
                    Agg::Max,
                    RelArg::Column("total_minor".into()),
                    "line_item",
                    correlate("line_item.order_id", "order_summary.id"),
                ),
                alias: Some("max_total".into()),
            }],
            ..Select::from("order_summary")
        };
        let (sql, _) = q.compile(Dialect::Sqlite).unwrap();
        assert_eq!(
            sql,
            "SELECT (SELECT max(total_minor) FROM line_item WHERE line_item.order_id = order_summary.id) AS max_total FROM order_summary"
        );
    }

    #[test]
    fn related_aggregate_star_is_count_only() {
        let q = Select {
            columns: vec![item(related(
                Agg::Sum,
                RelArg::Star,
                "t",
                correlate("t.fk", "p.id"),
            ))],
            ..Select::from("p")
        };
        assert!(matches!(
            q.compile(Dialect::Postgres),
            Err(OrmError::BadExpr(_))
        ));
    }

    #[test]
    fn related_aggregate_table_injection_is_rejected() {
        let q = Select {
            columns: vec![item(related(
                Agg::Count,
                RelArg::Star,
                "element; DROP TABLE users",
                correlate("element.order_id", "p.id"),
            ))],
            ..Select::from("p")
        };
        assert!(matches!(
            q.compile(Dialect::Postgres),
            Err(OrmError::InvalidIdentifier(_))
        ));
    }
}
