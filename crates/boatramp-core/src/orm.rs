//! A typed query AST and an injection-safe SQL compiler — the backing for the `orm`
//! handler binding (`boatramp:handlers/orm`).
//!
//! The compiler turns a typed [`Select`] / [`Insert`] / [`Update`] into a `?N`-placeholder
//! SQL string plus its bound [`SqlValue`] parameters, in order. It is **pure** (no I/O, no
//! wasm/wit deps) so it is fully unit-testable; the binding runs the result through the same
//! [`crate::sql::SqlTransaction`] the raw `sql-query` binding uses, which rewrites `?N` to the
//! engine's native dialect. That shares one execution + dialect substrate across bindings.
//!
//! # Safety
//! - **Every value binds as a parameter** (`?N`); no value is ever formatted into the SQL.
//! - **Identifiers are validated** (`[A-Za-z_][A-Za-z0-9_]*`, optionally `table.column`) and
//!   emitted unquoted — an identifier that isn't a plain name is rejected, so a column/table
//!   name can't smuggle SQL. (Unquoted keeps the output dialect-portable; the trade-off is
//!   that a column literally named after a reserved word must use the raw `sql-query` escape
//!   hatch.)
//! - **UPDATE requires a filter** — an unbounded update is refused.
//!
//! # Isolation
//! The project/database boundary is the caller's (the binding opens a per-project database).
//! An optional per-query [`Scope`] (`column = value`) is the *in-site* row-tenancy seam: on a
//! read/update it is ANDed into the `WHERE`; on an insert it is forced into every row. It is
//! guest-declared here (the shim's `Scoped` model); a host-enforced-from-claims variant is a
//! later enhancement (see plans/PLAN-orm-wit.md §4).

use crate::sql::SqlValue;

/// A comparison of a column against a bound value, or a null/list test.
#[derive(Debug, Clone, PartialEq)]
pub enum Compare {
    Eq(SqlValue),
    Ne(SqlValue),
    Lt(SqlValue),
    Le(SqlValue),
    Gt(SqlValue),
    Ge(SqlValue),
    /// SQL `LIKE` — the pattern binds as a parameter.
    Like(String),
    /// `IN (…)` — each value binds as a parameter. An empty list matches nothing.
    InList(Vec<SqlValue>),
    IsNull,
    IsNotNull,
}

/// A predicate on one column.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnPredicate {
    pub column: String,
    pub test: Compare,
}

/// A boolean combination of column predicates. Flat AND/OR covers every observed query;
/// nested trees are deferred to the raw escape hatch.
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    /// `AND` of all.
    All(Vec<ColumnPredicate>),
    /// `OR` of any.
    Any(Vec<ColumnPredicate>),
}

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

/// A `SELECT`-list entry.
#[derive(Debug, Clone, PartialEq)]
pub enum Projection {
    /// A plain column.
    Column(String),
    /// An aggregate over a column; use column `"*"` for `count(*)`.
    Aggregate(Agg, String),
}

/// The kind of join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    Left,
}

/// A join: `<kind> JOIN <table> ON <left_column> = <table>.<right_column>`.
#[derive(Debug, Clone, PartialEq)]
pub struct Join {
    pub kind: JoinKind,
    pub table: String,
    pub left_column: String,
    pub right_column: String,
}

/// A sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

/// An `ORDER BY` term.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderBy {
    pub column: String,
    pub dir: Direction,
}

/// An optional in-site row-tenancy scope: `column = value`.
#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    pub column: String,
    pub value: SqlValue,
}

/// A `SELECT`.
#[derive(Debug, Clone, PartialEq)]
pub struct Select {
    pub table: String,
    /// Empty ⇒ `SELECT *`.
    pub columns: Vec<Projection>,
    pub joins: Vec<Join>,
    pub filter: Option<Predicate>,
    pub scope: Option<Scope>,
    pub distinct: bool,
    pub order: Vec<OrderBy>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// A `column = value` assignment (an INSERT cell or an UPDATE SET).
#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub column: String,
    pub value: SqlValue,
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

/// An `INSERT` (single- or multi-row), optionally an upsert.
#[derive(Debug, Clone, PartialEq)]
pub struct Insert {
    pub table: String,
    pub rows: Vec<RowValues>,
    pub conflict: Option<OnConflict>,
    /// Forces `column = value` into every inserted row (adds or overrides).
    pub scope: Option<Scope>,
}

/// An `UPDATE`; `filter` is required (an unbounded update is refused).
#[derive(Debug, Clone, PartialEq)]
pub struct Update {
    pub table: String,
    pub set: Vec<Assignment>,
    pub filter: Predicate,
    pub scope: Option<Scope>,
}

/// Why compilation failed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum OrmError {
    /// An identifier was not a plain `[A-Za-z_][A-Za-z0-9_]*` (optionally `table.column`) name.
    #[error("invalid identifier: {0:?}")]
    InvalidIdentifier(String),
    /// The query was structurally empty (no rows to insert, no columns to set).
    #[error("empty query: {0}")]
    Empty(&'static str),
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

/// `count(*)` is the one place `*` is allowed as a "column".
fn agg_arg(col: &str) -> Result<String, OrmError> {
    if col == "*" {
        Ok("*".to_string())
    } else {
        Ok(ident(col)?.to_string())
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

/// Render one column predicate to SQL, binding any values.
fn render_predicate(p: &ColumnPredicate, params: &mut Params) -> Result<String, OrmError> {
    let col = ident(&p.column)?;
    Ok(match &p.test {
        Compare::Eq(v) => format!("{col} = {}", params.bind(v.clone())),
        Compare::Ne(v) => format!("{col} <> {}", params.bind(v.clone())),
        Compare::Lt(v) => format!("{col} < {}", params.bind(v.clone())),
        Compare::Le(v) => format!("{col} <= {}", params.bind(v.clone())),
        Compare::Gt(v) => format!("{col} > {}", params.bind(v.clone())),
        Compare::Ge(v) => format!("{col} >= {}", params.bind(v.clone())),
        Compare::Like(pat) => format!("{col} LIKE {}", params.bind(SqlValue::Text(pat.clone()))),
        Compare::InList(vs) => {
            if vs.is_empty() {
                // `IN ()` is a syntax error; an empty set matches nothing.
                "1 = 0".to_string()
            } else {
                let ph: Vec<String> = vs.iter().map(|v| params.bind(v.clone())).collect();
                format!("{col} IN ({})", ph.join(", "))
            }
        }
        Compare::IsNull => format!("{col} IS NULL"),
        Compare::IsNotNull => format!("{col} IS NOT NULL"),
    })
}

/// Render the `WHERE` body from an optional scope + optional predicate. Returns `None` when
/// there is nothing to constrain.
fn render_where(
    scope: Option<&Scope>,
    filter: Option<&Predicate>,
    params: &mut Params,
) -> Result<Option<String>, OrmError> {
    let mut clauses: Vec<String> = Vec::new();
    if let Some(s) = scope {
        let col = ident(&s.column)?;
        clauses.push(format!("{col} = {}", params.bind(s.value.clone())));
    }
    if let Some(pred) = filter {
        let (items, joiner) = match pred {
            Predicate::All(v) => (v, " AND "),
            Predicate::Any(v) => (v, " OR "),
        };
        if !items.is_empty() {
            let rendered: Result<Vec<String>, _> =
                items.iter().map(|p| render_predicate(p, params)).collect();
            let body = rendered?.join(joiner);
            // Parenthesize an OR group so a scope AND (a OR b) binds correctly.
            clauses.push(if matches!(pred, Predicate::Any(_)) && scope.is_some() {
                format!("({body})")
            } else {
                body
            });
        }
    }
    if clauses.is_empty() {
        Ok(None)
    } else {
        Ok(Some(clauses.join(" AND ")))
    }
}

impl Select {
    /// Compile to `?N` SQL + bound parameters.
    pub fn compile(&self) -> Result<Compiled, OrmError> {
        let mut params = Params::default();
        let table = ident(&self.table)?;

        let select_list = if self.columns.is_empty() {
            "*".to_string()
        } else {
            let cols: Result<Vec<String>, _> = self
                .columns
                .iter()
                .map(|c| match c {
                    Projection::Column(name) => ident(name).map(str::to_string),
                    Projection::Aggregate(agg, col) => {
                        Ok(format!("{}({})", agg.keyword(), agg_arg(col)?))
                    }
                })
                .collect();
            cols?.join(", ")
        };

        let distinct = if self.distinct { "DISTINCT " } else { "" };
        let mut sql = format!("SELECT {distinct}{select_list} FROM {table}");

        for j in &self.joins {
            let jt = ident(&j.table)?;
            let lc = ident(&j.left_column)?;
            let rc = ident(&j.right_column)?;
            let kw = match j.kind {
                JoinKind::Inner => "JOIN",
                JoinKind::Left => "LEFT JOIN",
            };
            sql.push_str(&format!(" {kw} {jt} ON {lc} = {jt}.{rc}"));
        }

        if let Some(w) = render_where(self.scope.as_ref(), self.filter.as_ref(), &mut params)? {
            sql.push_str(&format!(" WHERE {w}"));
        }

        if !self.order.is_empty() {
            let terms: Result<Vec<String>, _> = self
                .order
                .iter()
                .map(|o| {
                    let c = ident(&o.column)?;
                    let d = match o.dir {
                        Direction::Asc => "ASC",
                        Direction::Desc => "DESC",
                    };
                    Ok::<String, OrmError>(format!("{c} {d}"))
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
                // Scope forces its column; otherwise take the row's cell, else NULL.
                let v = if self.scope.as_ref().is_some_and(|s| &s.column == col) {
                    self.scope.as_ref().unwrap().value.clone()
                } else {
                    row.cells
                        .iter()
                        .find(|a| &a.column == col)
                        .map(|a| a.value.clone())
                        .unwrap_or(SqlValue::Null)
                };
                ph.push(params.bind(v));
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
                // `DO UPDATE SET col = ?N` — the new value binds as a parameter. (We bind the
                // provided value rather than `EXCLUDED.col`; the guest passes what it wants.)
                let sets: Result<Vec<String>, _> = oc
                    .update
                    .iter()
                    .map(|a| {
                        let c = ident(&a.column)?;
                        Ok::<String, OrmError>(format!("{c} = {}", params.bind(a.value.clone())))
                    })
                    .collect();
                sql.push_str(&format!(
                    " ON CONFLICT ({}) DO UPDATE SET {}",
                    conflict_cols.join(", "),
                    sets?.join(", ")
                ));
            }
        }

        Ok((sql, params.0))
    }
}

impl Update {
    /// Compile to `?N` SQL + bound parameters. A filter is required.
    pub fn compile(&self) -> Result<Compiled, OrmError> {
        if self.set.is_empty() {
            return Err(OrmError::Empty("update sets no columns"));
        }
        let table = ident(&self.table)?;
        let mut params = Params::default();

        let sets: Result<Vec<String>, _> = self
            .set
            .iter()
            .map(|a| {
                let c = ident(&a.column)?;
                Ok::<String, OrmError>(format!("{c} = {}", params.bind(a.value.clone())))
            })
            .collect();

        let where_body = render_where(self.scope.as_ref(), Some(&self.filter), &mut params)?
            .ok_or(OrmError::Empty("update has an empty filter (unbounded update refused)"))?;

        let sql = format!(
            "UPDATE {table} SET {} WHERE {where_body}",
            sets?.join(", ")
        );
        Ok((sql, params.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> SqlValue {
        SqlValue::Text(s.to_string())
    }

    #[test]
    fn select_basic_where_order_limit() {
        let q = Select {
            table: "work_order".into(),
            columns: vec![Projection::Column("id".into()), Projection::Column("state".into())],
            joins: vec![],
            filter: Some(Predicate::All(vec![ColumnPredicate {
                column: "project_id".into(),
                test: Compare::Eq(t("prj_1")),
            }])),
            scope: None,
            distinct: false,
            order: vec![OrderBy { column: "created_at".into(), dir: Direction::Desc }],
            limit: Some(10),
            offset: None,
        };
        let (sql, params) = q.compile().unwrap();
        assert_eq!(
            sql,
            "SELECT id, state FROM work_order WHERE project_id = ?1 ORDER BY created_at DESC LIMIT 10"
        );
        assert_eq!(params, vec![t("prj_1")]);
    }

    #[test]
    fn select_scope_is_anded_and_bound() {
        let q = Select {
            table: "party".into(),
            columns: vec![],
            joins: vec![],
            filter: Some(Predicate::All(vec![ColumnPredicate {
                column: "kind".into(),
                test: Compare::Eq(t("supplier")),
            }])),
            scope: Some(Scope { column: "tenant_id".into(), value: t("ten_1") }),
            distinct: false,
            order: vec![],
            limit: None,
            offset: None,
        };
        let (sql, params) = q.compile().unwrap();
        // Scope binds first (?1), then the filter (?2).
        assert_eq!(sql, "SELECT * FROM party WHERE tenant_id = ?1 AND kind = ?2");
        assert_eq!(params, vec![t("ten_1"), t("supplier")]);
    }

    #[test]
    fn select_join_and_aggregate() {
        let q = Select {
            table: "order_to_network".into(),
            columns: vec![Projection::Aggregate(Agg::Sum, "committed_minor".into())],
            joins: vec![Join {
                kind: JoinKind::Inner,
                table: "element".into(),
                left_column: "element_id".into(),
                right_column: "id".into(),
            }],
            filter: Some(Predicate::All(vec![ColumnPredicate {
                column: "order_id".into(),
                test: Compare::Eq(SqlValue::Integer(7)),
            }])),
            scope: None,
            distinct: false,
            order: vec![],
            limit: None,
            offset: None,
        };
        let (sql, _) = q.compile().unwrap();
        assert_eq!(
            sql,
            "SELECT sum(committed_minor) FROM order_to_network JOIN element ON element_id = element.id WHERE order_id = ?1"
        );
    }

    #[test]
    fn select_in_list_and_count_star() {
        let q = Select {
            table: "order_to_network".into(),
            columns: vec![Projection::Aggregate(Agg::Count, "*".into())],
            joins: vec![],
            filter: Some(Predicate::All(vec![ColumnPredicate {
                column: "state".into(),
                test: Compare::InList(vec![t("po_linked"), t("awarded")]),
            }])),
            scope: None,
            distinct: false,
            order: vec![],
            limit: None,
            offset: None,
        };
        let (sql, params) = q.compile().unwrap();
        assert_eq!(
            sql,
            "SELECT count(*) FROM order_to_network WHERE state IN (?1, ?2)"
        );
        assert_eq!(params, vec![t("po_linked"), t("awarded")]);
    }

    #[test]
    fn empty_in_list_matches_nothing() {
        let q = Select {
            table: "t".into(),
            columns: vec![],
            joins: vec![],
            filter: Some(Predicate::All(vec![ColumnPredicate {
                column: "state".into(),
                test: Compare::InList(vec![]),
            }])),
            scope: None,
            distinct: false,
            order: vec![],
            limit: None,
            offset: None,
        };
        let (sql, params) = q.compile().unwrap();
        assert_eq!(sql, "SELECT * FROM t WHERE 1 = 0");
        assert!(params.is_empty());
    }

    #[test]
    fn insert_with_scope_forced() {
        let q = Insert {
            table: "work_area".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment { column: "id".into(), value: t("wa_1") },
                    Assignment { column: "project_id".into(), value: t("prj_1") },
                ],
            }],
            conflict: None,
            scope: Some(Scope { column: "tenant_id".into(), value: t("ten_1") }),
        };
        let (sql, params) = q.compile().unwrap();
        assert_eq!(
            sql,
            "INSERT INTO work_area (id, project_id, tenant_id) VALUES (?1, ?2, ?3)"
        );
        assert_eq!(params, vec![t("wa_1"), t("prj_1"), t("ten_1")]);
    }

    #[test]
    fn upsert_do_update_and_do_nothing() {
        let base = |update: Vec<Assignment>| Insert {
            table: "country_pack".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment { column: "country".into(), value: t("US") },
                    Assignment { column: "currency".into(), value: t("USD") },
                ],
            }],
            conflict: Some(OnConflict {
                conflict_columns: vec!["tenant_id".into(), "country".into()],
                update,
            }),
            scope: None,
        };
        let (sql_do, _) = base(vec![Assignment { column: "currency".into(), value: t("USD") }])
            .compile()
            .unwrap();
        assert_eq!(
            sql_do,
            "INSERT INTO country_pack (country, currency) VALUES (?1, ?2) ON CONFLICT (tenant_id, country) DO UPDATE SET currency = ?3"
        );
        let (sql_nothing, _) = base(vec![]).compile().unwrap();
        assert!(sql_nothing.ends_with("ON CONFLICT (tenant_id, country) DO NOTHING"));
    }

    #[test]
    fn update_requires_filter_and_binds_set_before_where() {
        let q = Update {
            table: "supplier_invoice".into(),
            set: vec![Assignment { column: "payment_gate".into(), value: t("paid") }],
            filter: Predicate::All(vec![ColumnPredicate {
                column: "id".into(),
                test: Compare::Eq(t("inv_1")),
            }]),
            scope: Some(Scope { column: "tenant_id".into(), value: t("ten_1") }),
        };
        let (sql, params) = q.compile().unwrap();
        // SET binds ?1; then scope ?2; then filter ?3.
        assert_eq!(
            sql,
            "UPDATE supplier_invoice SET payment_gate = ?1 WHERE tenant_id = ?2 AND id = ?3"
        );
        assert_eq!(params, vec![t("paid"), t("ten_1"), t("inv_1")]);
    }

    #[test]
    fn update_with_empty_all_filter_is_refused() {
        let q = Update {
            table: "t".into(),
            set: vec![Assignment { column: "x".into(), value: SqlValue::Integer(1) }],
            filter: Predicate::All(vec![]),
            scope: None,
        };
        assert!(matches!(q.compile(), Err(OrmError::Empty(_))));
    }

    #[test]
    fn identifier_injection_is_rejected() {
        let q = Select {
            table: "t; DROP TABLE users".into(),
            columns: vec![],
            joins: vec![],
            filter: None,
            scope: None,
            distinct: false,
            order: vec![],
            limit: None,
            offset: None,
        };
        assert!(matches!(q.compile(), Err(OrmError::InvalidIdentifier(_))));

        let bad_col = Select {
            table: "t".into(),
            columns: vec![Projection::Column("id) FROM t; --".into())],
            joins: vec![],
            filter: None,
            scope: None,
            distinct: false,
            order: vec![],
            limit: None,
            offset: None,
        };
        assert!(matches!(bad_col.compile(), Err(OrmError::InvalidIdentifier(_))));
    }

    #[test]
    fn qualified_identifier_allowed() {
        assert_eq!(ident("element.id").unwrap(), "element.id");
        assert!(ident("a.b.c").is_err());
        assert!(ident("").is_err());
        assert!(ident("1col").is_err());
    }
}
