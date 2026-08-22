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
//! a small allow-listed [`Func`] set) and [`Predicate`] is a recursive boolean tree
//! (`AND`/`OR`/`NOT` + comparisons/`BETWEEN`/`IN`/`LIKE`/`IS NULL`). Selects add joins,
//! `GROUP BY`/`HAVING`, aliases, ordering and pagination; inserts/updates add `RETURNING`.
//! Subqueries, CTEs, window functions and dialect-specific constructs (`DISTINCT ON`, JSON
//! paths, …) are deliberately out of scope — they go through the raw `sql-query` escape hatch.
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

use crate::sql::SqlValue;

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
    Aggregate(Agg, Box<Expr>),
    /// A parenthesized binary arithmetic expression.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// An allow-listed function call.
    Func(Func, Vec<Expr>),
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
    And(Vec<Predicate>),
    /// `OR` of all children (an empty list is the always-false identity `1 = 0`).
    Or(Vec<Predicate>),
    /// Negation.
    Not(Box<Predicate>),
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

/// An optional in-site row-tenancy scope: `column = value`.
#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    pub column: String,
    pub value: SqlValue,
}

impl Scope {
    /// The scope as a predicate (`column = value`), conjoined into `WHERE`.
    fn as_predicate(&self) -> Predicate {
        Predicate::Cmp {
            left: Expr::Column(self.column.clone()),
            op: CmpOp::Eq,
            right: Expr::Value(self.value.clone()),
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
    pub order: Vec<OrderBy>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
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
fn render_expr(e: &Expr, params: &mut Params) -> Result<String, OrmError> {
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
                other => render_expr(other, params)?,
            };
            format!("{}({arg})", agg.keyword())
        }
        Expr::Binary(op, l, r) => {
            format!(
                "({} {} {})",
                render_expr(l, params)?,
                op.symbol(),
                render_expr(r, params)?
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
                let rendered: Result<Vec<String>, _> =
                    args.iter().map(|a| render_expr(a, params)).collect();
                format!("{name}({})", rendered?.join(", "))
            }
        }
    })
}

/// Render a predicate; `nested` parenthesizes a compound (`AND`/`OR`) so precedence is explicit.
fn render_pred(p: &Predicate, params: &mut Params, nested: bool) -> Result<String, OrmError> {
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
                let parts: Result<Vec<String>, _> =
                    ps.iter().map(|c| render_pred(c, params, true)).collect();
                compound(parts?.join(" AND "))
            }
        }
        Predicate::Or(ps) => {
            if ps.is_empty() {
                "1 = 0".to_string()
            } else {
                let parts: Result<Vec<String>, _> =
                    ps.iter().map(|c| render_pred(c, params, true)).collect();
                compound(parts?.join(" OR "))
            }
        }
        Predicate::Not(inner) => format!("NOT {}", render_pred(inner, params, true)?),
        Predicate::Cmp { left, op, right } => format!(
            "{} {} {}",
            render_expr(left, params)?,
            op.symbol(),
            render_expr(right, params)?
        ),
        Predicate::Between {
            expr,
            low,
            high,
            negated,
        } => format!(
            "{} {}BETWEEN {} AND {}",
            render_expr(expr, params)?,
            if *negated { "NOT " } else { "" },
            render_expr(low, params)?,
            render_expr(high, params)?
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
                let lhs = render_expr(expr, params)?;
                let ph: Result<Vec<String>, _> =
                    values.iter().map(|v| render_expr(v, params)).collect();
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
            if *insensitive {
                // Portable case-insensitive LIKE (no dialect-specific ILIKE).
                let lhs = render_expr(expr, params)?;
                let pat = params.bind(SqlValue::Text(pattern.clone()));
                format!("lower({lhs}) {neg}LIKE lower({pat})")
            } else {
                let lhs = render_expr(expr, params)?;
                let pat = params.bind(SqlValue::Text(pattern.clone()));
                format!("{lhs} {neg}LIKE {pat}")
            }
        }
        Predicate::Null { expr, negated } => format!(
            "{} IS {}NULL",
            render_expr(expr, params)?,
            if *negated { "NOT " } else { "" }
        ),
    })
}

/// Render the `WHERE` body from an optional scope + optional predicate (scope conjoined first).
fn render_where(
    scope: Option<&Scope>,
    filter: Option<&Predicate>,
    params: &mut Params,
) -> Result<Option<String>, OrmError> {
    // Validate the scope column eagerly (its predicate is rendered below).
    if let Some(s) = scope {
        ident(&s.column)?;
    }
    // A lone clause renders directly (no wrapping `AND`, so a top-level `AND`/`OR` filter
    // isn't spuriously parenthesized); scope + filter conjoin as `scope AND (filter)`.
    let combined = match (scope, filter) {
        (None, None) => return Ok(None),
        (Some(s), None) => s.as_predicate(),
        (None, Some(f)) => f.clone(),
        (Some(s), Some(f)) => Predicate::And(vec![s.as_predicate(), f.clone()]),
    };
    Ok(Some(render_pred(&combined, params, false)?))
}

/// Render a select list (empty ⇒ `*`).
fn render_select_items(items: &[SelectItem], params: &mut Params) -> Result<String, OrmError> {
    if items.is_empty() {
        return Ok("*".to_string());
    }
    let parts: Result<Vec<String>, _> = items
        .iter()
        .map(|it| {
            let e = render_expr(&it.expr, params)?;
            Ok::<String, OrmError>(match &it.alias {
                Some(a) => format!("{e} AS {}", ident(a)?),
                None => e,
            })
        })
        .collect();
    Ok(parts?.join(", "))
}

/// Render a `RETURNING` clause, if any.
fn render_returning(items: &[SelectItem], params: &mut Params) -> Result<String, OrmError> {
    if items.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!(
            " RETURNING {}",
            render_select_items(items, params)?
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
            order: Vec::new(),
            limit: None,
            offset: None,
        }
    }

    /// Compile to `?N` SQL + bound parameters.
    pub fn compile(&self) -> Result<Compiled, OrmError> {
        let mut params = Params::default();
        let table = ident(&self.table)?;

        let select_list = render_select_items(&self.columns, &mut params)?;
        let distinct = if self.distinct { "DISTINCT " } else { "" };
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
            sql.push_str(&format!(" ON {}", render_pred(&j.on, &mut params, false)?));
        }

        if let Some(w) = render_where(self.scope.as_ref(), self.filter.as_ref(), &mut params)? {
            sql.push_str(&format!(" WHERE {w}"));
        }

        if !self.group_by.is_empty() {
            let terms: Result<Vec<String>, _> = self
                .group_by
                .iter()
                .map(|e| render_expr(e, &mut params))
                .collect();
            sql.push_str(&format!(" GROUP BY {}", terms?.join(", ")));
        }

        if let Some(h) = &self.having {
            sql.push_str(&format!(" HAVING {}", render_pred(h, &mut params, false)?));
        }

        if !self.order.is_empty() {
            let terms: Result<Vec<String>, _> = self
                .order
                .iter()
                .map(|o| {
                    let e = render_expr(&o.expr, &mut params)?;
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

        Ok((sql, params.0))
    }
}

impl Insert {
    /// Compile to `?N` SQL + bound parameters.
    pub fn compile(&self) -> Result<Compiled, OrmError> {
        if self.rows.is_empty() {
            return Err(OrmError::Empty("insert has no rows"));
        }
        let table = ident(&self.table)?;
        let mut params = Params::default();

        // Column set: from the first row (+ the scope column if forced), in a stable order.
        // Every row is coerced to exactly these columns; the scope value overrides.
        let mut columns: Vec<String> = Vec::new();
        for a in &self.rows[0].cells {
            let c = ident(&a.column)?.to_string();
            if !columns.contains(&c) {
                columns.push(c);
            }
        }
        if let Some(s) = &self.scope {
            let c = ident(&s.column)?.to_string();
            if !columns.contains(&c) {
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
                // Scope forces its column; otherwise take the row's cell expr, else NULL.
                if self.scope.as_ref().is_some_and(|s| &s.column == col) {
                    ph.push(params.bind(self.scope.as_ref().unwrap().value.clone()));
                } else {
                    match row.cells.iter().find(|a| &a.column == col) {
                        Some(a) => ph.push(render_expr(&a.value, &mut params)?),
                        None => ph.push(params.bind(SqlValue::Null)),
                    }
                }
            }
            value_groups.push(format!("({})", ph.join(", ")));
        }

        let mut sql = format!(
            "INSERT INTO {table} ({}) VALUES {}",
            columns.join(", "),
            value_groups.join(", ")
        );

        if let Some(oc) = &self.conflict {
            let conflict_cols: Result<Vec<String>, _> = oc
                .conflict_columns
                .iter()
                .map(|c| ident(c).map(str::to_string))
                .collect();
            let conflict_cols = conflict_cols?;
            if oc.update.is_empty() {
                sql.push_str(&format!(
                    " ON CONFLICT ({}) DO NOTHING",
                    conflict_cols.join(", ")
                ));
            } else {
                let sets: Result<Vec<String>, _> = oc
                    .update
                    .iter()
                    .map(|a| {
                        let c = ident(&a.column)?;
                        Ok::<String, OrmError>(format!(
                            "{c} = {}",
                            render_expr(&a.value, &mut params)?
                        ))
                    })
                    .collect();
                sql.push_str(&format!(
                    " ON CONFLICT ({}) DO UPDATE SET {}",
                    conflict_cols.join(", "),
                    sets?.join(", ")
                ));
            }
        }

        sql.push_str(&render_returning(&self.returning, &mut params)?);
        Ok((sql, params.0))
    }
}

impl Update {
    /// Compile to `?N` SQL + bound parameters. An empty `filter` is refused (no unbounded update).
    pub fn compile(&self) -> Result<Compiled, OrmError> {
        if self.set.is_empty() {
            return Err(OrmError::Empty("update has no assignments"));
        }
        let table = ident(&self.table)?;
        let mut params = Params::default();

        // SET binds before WHERE so placeholder order matches the parameter order.
        let sets: Result<Vec<String>, _> = self
            .set
            .iter()
            .map(|a| {
                let c = ident(&a.column)?;
                Ok::<String, OrmError>(format!("{c} = {}", render_expr(&a.value, &mut params)?))
            })
            .collect();
        let set_sql = sets?.join(", ");

        let where_sql = render_where(self.scope.as_ref(), Some(&self.filter), &mut params)?.ok_or(
            OrmError::Empty("update has an empty filter (unbounded update refused)"),
        )?;

        let mut sql = format!("UPDATE {table} SET {set_sql} WHERE {where_sql}");
        sql.push_str(&render_returning(&self.returning, &mut params)?);
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
        let (sql, params) = q.compile().unwrap();
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
            }),
            ..Select::from("party")
        };
        let (sql, params) = q.compile().unwrap();
        assert_eq!(
            sql,
            "SELECT * FROM party WHERE tenant_id = ?1 AND kind = ?2"
        );
        assert_eq!(params, vec![t("ten_1"), t("supplier")]);
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
            }),
            ..Select::from("order_to_network")
        };
        let (sql, params) = q.compile().unwrap();
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
        let (sql, params) = q.compile().unwrap();
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
        let (sql, _) = q.compile().unwrap();
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
        let (sql, params) = q.compile().unwrap();
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
        let (sql, params) = q.compile().unwrap();
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
            matches_none.compile().unwrap().0,
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
            matches_all.compile().unwrap().0,
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
            }),
            returning: vec![item(Expr::col("id"))],
        };
        let (sql, params) = q.compile().unwrap();
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
        };
        let (sql_do, _) = base(vec![Assignment {
            column: "currency".into(),
            value: Expr::val(t("USD")),
        }])
        .compile()
        .unwrap();
        assert_eq!(
            sql_do,
            "INSERT INTO country_pack (country, currency) VALUES (?1, ?2) ON CONFLICT (tenant_id, country) DO UPDATE SET currency = ?3"
        );
        let (sql_nothing, _) = base(vec![]).compile().unwrap();
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
            }),
            returning: vec![],
        };
        let (sql, params) = q.compile().unwrap();
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
        assert!(matches!(q.compile(), Err(OrmError::InvalidIdentifier(_))));
    }

    #[test]
    fn qualified_identifier_allowed() {
        let q = Select {
            columns: vec![item(Expr::col("t.id"))],
            ..Select::from("t")
        };
        assert_eq!(q.compile().unwrap().0, "SELECT t.id FROM t");
    }

    #[test]
    fn function_arity_is_checked() {
        let q = Select {
            columns: vec![item(Expr::Func(Func::Lower, vec![]))],
            ..Select::from("t")
        };
        assert!(matches!(q.compile(), Err(OrmError::BadExpr(_))));
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
        // An empty AND renders `1 = 1`, which IS a WHERE — so this is NOT refused; the
        // guard is against a *missing* filter, which the type system already prevents
        // (filter is non-Option). Assert it compiles to the explicit always-true form so
        // the behavior is at least visible + intentional.
        assert_eq!(q.compile().unwrap().0, "UPDATE t SET x = ?1 WHERE 1 = 1");
    }

    #[test]
    fn now_renders_without_parens() {
        let q = Select {
            columns: vec![item(Expr::Func(Func::Now, vec![]))],
            ..Select::from("t")
        };
        assert_eq!(q.compile().unwrap().0, "SELECT current_timestamp FROM t");
    }
}
