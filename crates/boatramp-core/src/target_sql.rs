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
//!    those buried in `IN (SELECT …)`, `EXISTS (…)`, scalar subqueries, derived tables, CTE bodies,
//!    and `UNION`/`INTERSECT`/`EXCEPT` arms — receives a [`pre_visit_query`](Rewriter::pre_visit_query),
//!    where its own `SELECT`s are confined.
//! 2. Every table reference lives in a `SELECT`'s `FROM` (directly or under a `NESTED JOIN`), and
//!    every `SELECT` is confined by exactly one enclosing query's visit — so every base table is
//!    reached exactly once.
//! 3. Anything the confinement cannot reason about — a table-valued function, `UNNEST`, `PIVOT`, a
//!    schema-qualified name, a write smuggled into a CTE, an exotic table source — is **refused**
//!    (fail-closed), never silently passed. A second [`pre_visit_table_factor`](Rewriter::pre_visit_table_factor)
//!    guard rejects any un-confinable table source anywhere in the tree as belt-and-suspenders.
//!
//! The injected `B` and public-subset literals are host-held (from the routing context + the
//! operator's schema), never guest input, and are rendered through sqlparser's own escaping
//! ([`Value::SingleQuotedString`](sqlparser::ast::Value) doubles quotes) — so they are safe as
//! literals and, unlike bound parameters, do not disturb the guest's own positional placeholders
//! (which matters for the positional-parameter dialects).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use sqlparser::ast::{
    BinaryOperator, Expr, Ident, Query, Select, SetExpr, Statement, TableFactor, TableWithJoins,
    Value, VisitMut, VisitorMut,
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
pub fn rewrite_target_select(
    statement: &str,
    tenant_value: &SqlValue,
    keys: &BTreeMap<String, ResolvedScope>,
    public: &BTreeMap<String, Vec<PublicTermSql>>,
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
        bound,
        scope: Vec::new(),
    };
    if let ControlFlow::Break(err) = statements[0].visit(&mut rewriter) {
        return Err(err);
    }
    Ok(statements[0].to_string())
}

/// The mutating visitor that injects the per-table confinement. `scope` is a stack of CTE-name
/// frames (one per enclosing query that has a `WITH`); a `FROM` reference to a name visible on the
/// stack is a CTE reference (its body is confined at its own level), not a base table.
struct Rewriter<'a> {
    keys: &'a BTreeMap<String, ResolvedScope>,
    public: &'a BTreeMap<String, Vec<PublicTermSql>>,
    /// The host-resolved target tenant `B`, pre-rendered as a literal expression.
    bound: Expr,
    scope: Vec<BTreeSet<String>>,
}

impl VisitorMut for Rewriter<'_> {
    type Break = TargetRewriteError;

    fn pre_visit_query(&mut self, query: &mut Query) -> ControlFlow<Self::Break> {
        // Bring this query's CTE names into scope *before* confining its body (a body SELECT may
        // reference a sibling CTE; over-approximating the scope matches SQL's own name shadowing —
        // a bare name that matches a visible CTE resolves to the CTE, whose body is confined).
        if let Some(with) = &query.with {
            let frame = with
                .cte_tables
                .iter()
                .map(|c| c.alias.name.value.clone())
                .collect();
            self.scope.push(frame);
        }
        // Confine every SELECT directly in this query's body (through set-operation arms). Nested
        // queries (derived tables, expression subqueries, CTE bodies, `SetExpr::Query`) are separate
        // `Query` nodes and receive their own `pre_visit_query`.
        if let Err(e) = self.confine_body(&mut query.body) {
            return ControlFlow::Break(e);
        }
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, query: &mut Query) -> ControlFlow<Self::Break> {
        if query.with.is_some() {
            self.scope.pop();
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
    /// Whether `name` is a CTE name visible in the current scope (so a `FROM` reference to it is a
    /// CTE reference, not a base table).
    fn cte_in_scope(&self, name: &str) -> bool {
        self.scope.iter().any(|frame| frame.contains(name))
    }

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

    /// Conjoin `tenant = B AND <public>` for each base table in this `SELECT`'s `FROM` onto its
    /// `WHERE` (the guest's own `WHERE` parenthesised first, so a top-level `OR` cannot widen past
    /// the gate). CTE references and derived tables are skipped (confined at their own level).
    fn confine_select(&self, select: &mut Select) -> Result<(), TargetRewriteError> {
        // `SELECT … INTO t` materialises a table — a write in a read position.
        if select.into.is_some() {
            return Err(TargetRewriteError::WriteInReadPosition);
        }
        let mut bases: Vec<(Ident, String)> = Vec::new();
        for twj in &select.from {
            self.collect_bases(twj, &mut bases)?;
        }
        if bases.is_empty() {
            // No base table (e.g. `SELECT 1`, or a FROM of only CTE refs / derived tables) — nothing
            // to confine at this level.
            return Ok(());
        }
        let mut confinement: Option<Expr> = None;
        for (qualifier, table) in &bases {
            let pred = self.table_confinement(table, qualifier)?;
            confinement = Some(match confinement.take() {
                Some(acc) => and(acc, pred),
                None => pred,
            });
        }
        let confinement = confinement.expect("bases is non-empty");
        select.selection = Some(match select.selection.take() {
            // Parenthesise the guest's predicate: `(<guest WHERE>) AND <confinement>` — a top-level
            // OR in the guest predicate can never escape the tenant/public gate (closes M2).
            Some(existing) => and(Expr::Nested(Box::new(existing)), confinement),
            None => confinement,
        });
        Ok(())
    }

    /// Collect the base tables of a `FROM` entry (its relation + each join's relation), recursing
    /// through nested joins. Derived tables and CTE references are skipped.
    fn collect_bases(
        &self,
        twj: &TableWithJoins,
        out: &mut Vec<(Ident, String)>,
    ) -> Result<(), TargetRewriteError> {
        self.collect_factor(&twj.relation, out)?;
        for join in &twj.joins {
            self.collect_factor(&join.relation, out)?;
        }
        Ok(())
    }

    fn collect_factor(
        &self,
        factor: &TableFactor,
        out: &mut Vec<(Ident, String)>,
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
                let base = name.0[0].value.clone();
                if self.cte_in_scope(&base) {
                    // A reference to a CTE defined in an enclosing scope — its body is confined at
                    // its own level; do not treat it as a base table.
                    return Ok(());
                }
                // The qualifier columns will be referenced by: the alias if present, else the
                // table's own identifier (cloned to preserve any quoting).
                let qualifier = alias
                    .as_ref()
                    .map(|a| a.name.clone())
                    .unwrap_or_else(|| name.0[0].clone());
                out.push((qualifier, base));
                Ok(())
            }
            // A derived table is a nested `Query` — confined by its own `pre_visit_query`; its alias
            // is a logical name, not a base table.
            TableFactor::Derived { .. } => Ok(()),
            TableFactor::NestedJoin {
                table_with_joins, ..
            } => self.collect_bases(table_with_joins, out),
            other => Err(TargetRewriteError::UnsupportedTableSource(
                table_factor_kind(other).into(),
            )),
        }
    }

    /// The confinement predicate for one base table: `qualifier.tenant = B` (unless the table is
    /// `Unscoped`) `AND` the table's public-subset terms (each qualified). Deny-by-default: a table
    /// with no declared public subset, or no declared tenant key, is refused.
    fn table_confinement(
        &self,
        table: &str,
        qualifier: &Ident,
    ) -> Result<Expr, TargetRewriteError> {
        // Deny-by-default: a target read may only reach a table with a declared public subset.
        let terms = self
            .public
            .get(table)
            .ok_or_else(|| TargetRewriteError::PublicSubsetUndeclared(table.to_string()))?;
        let resolved = self
            .keys
            .get(table)
            .ok_or_else(|| TargetRewriteError::TenancyUndeclared(table.to_string()))?;

        let mut parts: Vec<Expr> = Vec::new();
        match resolved {
            ResolvedScope::Column(col) => {
                check_ident(col)?;
                parts.push(binop(
                    col_expr(qualifier, col),
                    BinaryOperator::Eq,
                    self.bound.clone(),
                ));
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
        // AND all parts. Empty only if the table is `Unscoped` with no public terms — which the
        // schema validator rejects (an empty public predicate matches every row); refuse defensively.
        let mut it = parts.into_iter();
        let Some(first) = it.next() else {
            return Err(TargetRewriteError::EmptyConfinement(table.to_string()));
        };
        Ok(it.fold(first, and))
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
            return Err(TargetRewriteError::UnsupportedLiteral)
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
        rewrite_target_select(sql, &b(), &keys(), &public(), Dialect::Sqlite)
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
    fn cte_body_is_confined_and_cte_reference_is_not_a_base_table() {
        let out = rewrite("WITH live AS (SELECT id FROM products) SELECT * FROM live WHERE id > 0")
            .unwrap();
        // The CTE body confines `products`...
        assert!(
            out.contains("FROM products WHERE products.tenant_id = 'tenant_B'"),
            "{out}"
        );
        // ...and `FROM live` (the CTE name) is NOT treated as a base table (no `live.tenant_id`).
        assert!(!out.contains("live.tenant_id"), "{out}");
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
