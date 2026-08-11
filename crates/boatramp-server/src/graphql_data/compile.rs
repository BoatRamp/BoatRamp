//! The query compiler: a GraphQL read operation → one parameterized SQL `SELECT` per root
//! field.
//!
//! This is where the connector stays a *compiler*, not an engine. Each root field lowers to
//! a single `SELECT` whose values are **always bound parameters** (injection-safe) and whose
//! identifiers come **only** from the introspected + policy-exposed schema (never request
//! text). A relationship field (from a foreign key) lowers to a correlated JSON subquery, so
//! one statement still returns the whole tree — no N+1. Anything the compiler cannot lower —
//! an unexposed table/column, an unknown operator, a relationship nested beyond one level, a
//! mutation/subscription — is a [`CompileError`], never a partial or guessed result. The
//! policy's row filter is combined into every access (the root and every relationship
//! subquery), so tenant isolation is enforced at compile time, at every depth.

use super::dialect::{sql_string_literal, Dialect};
use super::policy::{Claims, DataPolicy, PolicyError, RowOp};
use super::schema::{DbSchema, RelKind, Relationship, Table};
use boatramp_core::sql::SqlValue;
use graphql_parser::query::{Definition, Field, OperationDefinition, Selection, Value};

/// How one output field of a row is produced.
#[derive(Debug, PartialEq)]
pub(crate) enum OutSource {
    /// The value at this index of the `SELECT` column list (and the returned row).
    Column(usize),
    /// A relationship: the value at this index is JSON text to parse into a nested
    /// object/array.
    Json(usize),
    /// A constant `__typename` (the object type name).
    Typename(String),
}

/// One field of the GraphQL object built per row: its response key + where the value comes
/// from.
#[derive(Debug, PartialEq)]
pub(crate) struct OutField {
    pub key: String,
    pub source: OutSource,
}

/// One root field lowered to SQL.
#[derive(Debug, PartialEq)]
pub(crate) struct RootQuery {
    /// The response key (alias or field name) this root field is returned under.
    pub response_key: String,
    /// The parameterized SQL `SELECT`.
    pub sql: String,
    /// The bound parameters, in placeholder order.
    pub params: Vec<SqlValue>,
    /// `true` for a `_by_pk` field (return the first row or null); `false` for a list.
    pub single: bool,
    /// How to shape each returned row into the GraphQL object.
    pub projection: Vec<OutField>,
}

/// A whole operation lowered to one SQL statement per root field.
#[derive(Debug, PartialEq)]
pub(crate) struct PlannedSql {
    pub roots: Vec<RootQuery>,
}

/// Why compilation failed. Every variant is a hard rejection — the connector never runs a
/// partial or guessed query.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CompileError {
    #[error("invalid GraphQL query: {0}")]
    Parse(String),
    #[error("no operation to execute")]
    NoOperation,
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("unknown or unexposed field `{0}`")]
    UnknownField(String),
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

/// Compile `query` (with its `variables`) against `schema` under `policy` + `claims`,
/// targeting `dialect`.
pub(crate) fn compile(
    query: &str,
    variables: &serde_json::Value,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    dialect: &dyn Dialect,
) -> Result<PlannedSql, CompileError> {
    let doc = graphql_parser::query::parse_query::<String>(query)
        .map_err(|e| CompileError::Parse(e.to_string()))?;
    let op = doc
        .definitions
        .iter()
        .find_map(|d| match d {
            Definition::Operation(op) => Some(op),
            _ => None,
        })
        .ok_or(CompileError::NoOperation)?;
    let selection = match op {
        OperationDefinition::Query(q) => &q.selection_set,
        OperationDefinition::SelectionSet(ss) => ss,
        OperationDefinition::Mutation(_) => {
            return Err(CompileError::Unsupported("mutations".into()))
        }
        OperationDefinition::Subscription(_) => {
            return Err(CompileError::Unsupported("subscriptions".into()))
        }
    };

    let mut roots = Vec::new();
    for item in &selection.items {
        let Selection::Field(field) = item else {
            return Err(CompileError::Unsupported("fragments at the root".into()));
        };
        roots.push(compile_root(
            field, variables, schema, policy, claims, dialect,
        )?);
    }
    Ok(PlannedSql { roots })
}

/// Per-root compilation state: the parameter + subquery-alias accumulators and the request
/// context.
struct Cx<'a> {
    dialect: &'a dyn Dialect,
    variables: &'a serde_json::Value,
    params: Vec<SqlValue>,
    alias_seq: usize,
}

impl Cx<'_> {
    /// Bind `value` as the next parameter and return its placeholder.
    fn bind(&mut self, value: SqlValue) -> String {
        self.params.push(value);
        self.dialect.placeholder(self.params.len())
    }

    /// A fresh subquery table alias (`t1`, `t2`, …); distinct from any root table name.
    fn next_alias(&mut self) -> String {
        let alias = format!("t{}", self.alias_seq);
        self.alias_seq += 1;
        alias
    }
}

fn compile_root(
    field: &Field<'_, String>,
    variables: &serde_json::Value,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    dialect: &dyn Dialect,
) -> Result<RootQuery, CompileError> {
    let response_key = field.alias.clone().unwrap_or_else(|| field.name.clone());
    let (table_name, single) = match field.name.strip_suffix("_by_pk") {
        Some(t) => (t, true),
        None => (field.name.as_str(), false),
    };

    if !policy.is_table_exposed(table_name) {
        return Err(CompileError::UnknownField(field.name.clone()));
    }
    let table = schema
        .table(table_name)
        .ok_or_else(|| CompileError::UnknownField(field.name.clone()))?;

    let mut cx = Cx {
        dialect,
        variables,
        params: Vec::new(),
        alias_seq: 1,
    };
    // The root table is referenced by its (quoted) name; subqueries correlate to it.
    let qualifier = dialect.quote_ident(table_name);

    // Projection (columns, relationship subqueries, __typename). Built first, so its
    // subquery parameters number before the WHERE's.
    let (select_exprs, projection) = compile_selection(
        &field.selection_set.items,
        table,
        &qualifier,
        schema,
        policy,
        claims,
        &mut cx,
    )?;

    // WHERE = the policy row filter, plus the `_by_pk` key equality or the list `where` arg.
    let mut clauses: Vec<String> = Vec::new();
    if let Some(filter) = policy.row_filter(table_name, claims)? {
        for term in filter.terms {
            let op = match term.op {
                RowOp::Eq => "=",
            };
            let col = format!("{qualifier}.{}", dialect.quote_ident(&term.column));
            let ph = cx.bind(term.value);
            clauses.push(format!("{col} {op} {ph}"));
        }
    }
    if single {
        if table.primary_key.is_empty() {
            return Err(CompileError::UnknownField(field.name.clone()));
        }
        for pk in &table.primary_key {
            let arg = field
                .arguments
                .iter()
                .find(|(name, _)| name == pk)
                .ok_or_else(|| CompileError::UnknownField(format!("{table_name}_by_pk.{pk}")))?;
            let value = resolve_value(&arg.1, variables)?;
            let col = format!("{qualifier}.{}", dialect.quote_ident(pk));
            let ph = cx.bind(value);
            clauses.push(format!("{col} = {ph}"));
        }
    } else if let Some((_, where_arg)) = field.arguments.iter().find(|(n, _)| n == "where") {
        if let Some(expr) = compile_bool_exp(where_arg, table, &qualifier, policy, &mut cx)? {
            clauses.push(expr);
        }
    }

    let select_list = if select_exprs.is_empty() {
        "1".to_string()
    } else {
        select_exprs.join(", ")
    };
    let mut sql = format!(
        "SELECT {select_list} FROM {}",
        dialect.quote_ident(table_name)
    );
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    if !single {
        if let Some(order) = order_by_clause(field, table, &qualifier, policy, dialect)? {
            sql.push_str(" ORDER BY ");
            sql.push_str(&order);
        }
        if let Some((_, limit)) = field.arguments.iter().find(|(n, _)| n == "limit") {
            let ph = cx.bind(resolve_value(limit, variables)?);
            sql.push_str(&format!(" LIMIT {ph}"));
        }
        if let Some((_, offset)) = field.arguments.iter().find(|(n, _)| n == "offset") {
            let ph = cx.bind(resolve_value(offset, variables)?);
            sql.push_str(&format!(" OFFSET {ph}"));
        }
    }

    Ok(RootQuery {
        response_key,
        sql,
        params: cx.params,
        single,
        projection,
    })
}

/// Compile a selection set on `table` (referenced by `qualifier`) into the `SELECT`
/// expression list and the output projection. A scalar field is a qualified column; a
/// relationship field is a correlated JSON subquery; `__typename` is a constant.
fn compile_selection(
    items: &[Selection<'_, String>],
    table: &Table,
    qualifier: &str,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    cx: &mut Cx<'_>,
) -> Result<(Vec<String>, Vec<OutField>), CompileError> {
    let relationships = schema.relationships(&table.name);
    let mut exprs = Vec::new();
    let mut projection = Vec::new();
    for sel in items {
        let Selection::Field(f) = sel else {
            return Err(CompileError::Unsupported("fragments in a selection".into()));
        };
        let key = f.alias.clone().unwrap_or_else(|| f.name.clone());
        if f.name == "__typename" {
            projection.push(OutField {
                key,
                source: OutSource::Typename(table.name.clone()),
            });
            continue;
        }
        if let Some(rel) = relationships.iter().find(|r| r.field == f.name) {
            if f.selection_set.items.is_empty() {
                return Err(CompileError::UnknownField(format!(
                    "{}.{}",
                    table.name, f.name
                )));
            }
            let subquery = relationship_subquery(rel, f, qualifier, schema, policy, claims, cx)?;
            let idx = exprs.len();
            exprs.push(subquery);
            projection.push(OutField {
                key,
                source: OutSource::Json(idx),
            });
            continue;
        }
        // A scalar column.
        if !f.selection_set.items.is_empty()
            || table.column(&f.name).is_none()
            || !policy.is_column_exposed(&table.name, &f.name)
        {
            return Err(CompileError::UnknownField(format!(
                "{}.{}",
                table.name, f.name
            )));
        }
        let idx = exprs.len();
        exprs.push(format!("{qualifier}.{}", cx.dialect.quote_ident(&f.name)));
        projection.push(OutField {
            key,
            source: OutSource::Column(idx),
        });
    }
    Ok((exprs, projection))
}

/// Lower a relationship field to a correlated JSON subquery selecting the target's scalar
/// fields, joined to the outer row and filtered by the target's row policy. The target
/// selection must be scalar-only — a relationship nested beyond one level is rejected.
fn relationship_subquery(
    rel: &Relationship,
    field: &Field<'_, String>,
    outer_qualifier: &str,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    cx: &mut Cx<'_>,
) -> Result<String, CompileError> {
    if !policy.is_table_exposed(&rel.target_table) {
        return Err(CompileError::UnknownField(rel.field.clone()));
    }
    let target = schema
        .table(&rel.target_table)
        .ok_or_else(|| CompileError::UnknownField(rel.field.clone()))?;
    let alias = cx.next_alias();
    let qalias = cx.dialect.quote_ident(&alias);

    // The per-row JSON object: scalar fields + __typename only.
    let mut pairs: Vec<(String, String)> = Vec::new();
    for sel in &field.selection_set.items {
        let Selection::Field(sf) = sel else {
            return Err(CompileError::Unsupported("fragments in a selection".into()));
        };
        let key = sf.alias.clone().unwrap_or_else(|| sf.name.clone());
        if sf.name == "__typename" {
            pairs.push((key, sql_string_literal(&rel.target_table)));
            continue;
        }
        if !sf.selection_set.items.is_empty() {
            return Err(CompileError::Unsupported(
                "a relationship nested beyond one level".into(),
            ));
        }
        if target.column(&sf.name).is_none()
            || !policy.is_column_exposed(&rel.target_table, &sf.name)
        {
            return Err(CompileError::UnknownField(format!(
                "{}.{}",
                rel.target_table, sf.name
            )));
        }
        pairs.push((
            key,
            format!("{qalias}.{}", cx.dialect.quote_ident(&sf.name)),
        ));
    }
    let object = cx.dialect.json_object(&pairs);

    // Join to the outer row, plus the target's own row filter (isolation at every depth).
    let mut clauses = Vec::new();
    for (local, remote) in rel.local_columns.iter().zip(&rel.target_columns) {
        clauses.push(format!(
            "{qalias}.{} = {outer_qualifier}.{}",
            cx.dialect.quote_ident(remote),
            cx.dialect.quote_ident(local)
        ));
    }
    if let Some(filter) = policy.row_filter(&rel.target_table, claims)? {
        for term in filter.terms {
            let col = format!("{qalias}.{}", cx.dialect.quote_ident(&term.column));
            let ph = cx.bind(term.value);
            clauses.push(format!("{col} = {ph}"));
        }
    }
    let where_sql = clauses.join(" AND ");
    let from = cx.dialect.quote_ident(&rel.target_table);
    let body = match rel.kind {
        RelKind::ToOne => format!("SELECT {object} FROM {from} AS {qalias} WHERE {where_sql}"),
        RelKind::ToMany => {
            let agg = cx.dialect.json_array_agg(&object);
            format!("SELECT {agg} FROM {from} AS {qalias} WHERE {where_sql}")
        }
    };
    Ok(format!("({body})"))
}

/// Compile a `<table>_bool_exp` value into a SQL boolean expression (or `None` if empty).
fn compile_bool_exp(
    value: &Value<'_, String>,
    table: &Table,
    qualifier: &str,
    policy: &DataPolicy,
    cx: &mut Cx<'_>,
) -> Result<Option<String>, CompileError> {
    let Value::Object(obj) = value else {
        return Err(CompileError::Unsupported("non-object `where`".into()));
    };
    let mut clauses = Vec::new();
    for (key, val) in obj {
        match key.as_str() {
            "_and" => clauses.push(compile_junction(
                val, table, qualifier, policy, cx, " AND ",
            )?),
            "_or" => clauses.push(compile_junction(val, table, qualifier, policy, cx, " OR ")?),
            "_not" => {
                let inner =
                    compile_bool_exp(val, table, qualifier, policy, cx)?.unwrap_or_default();
                clauses.push(format!("NOT ({inner})"));
            }
            column => {
                if table.column(column).is_none() || !policy.is_column_exposed(&table.name, column)
                {
                    return Err(CompileError::UnknownField(format!(
                        "{}.{column}",
                        table.name
                    )));
                }
                clauses.push(compile_comparison(qualifier, column, val, cx)?);
            }
        }
    }
    Ok(if clauses.is_empty() {
        None
    } else {
        Some(clauses.join(" AND "))
    })
}

/// Compile an `_and`/`_or` list of bool-exps, joined by `sep`.
fn compile_junction(
    value: &Value<'_, String>,
    table: &Table,
    qualifier: &str,
    policy: &DataPolicy,
    cx: &mut Cx<'_>,
    sep: &str,
) -> Result<String, CompileError> {
    let Value::List(items) = value else {
        return Err(CompileError::Unsupported("_and/_or expects a list".into()));
    };
    let parts: Vec<String> = items
        .iter()
        .map(|v| compile_bool_exp(v, table, qualifier, policy, cx).map(Option::unwrap_or_default))
        .collect::<Result<_, _>>()?;
    Ok(format!("({})", parts.join(sep)))
}

/// Compile a `<Scalar>_comparison_exp` for `qualifier.column` (already exposure-checked).
fn compile_comparison(
    qualifier: &str,
    column: &str,
    value: &Value<'_, String>,
    cx: &mut Cx<'_>,
) -> Result<String, CompileError> {
    let Value::Object(ops) = value else {
        return Err(CompileError::Unsupported(
            "a comparison must be an object".into(),
        ));
    };
    let col = format!("{qualifier}.{}", cx.dialect.quote_ident(column));
    let mut parts = Vec::new();
    for (op, operand) in ops {
        let clause = match op.as_str() {
            "_eq" => format!("{col} = {}", cx.bind(resolve_value(operand, cx.variables)?)),
            "_neq" => format!(
                "{col} <> {}",
                cx.bind(resolve_value(operand, cx.variables)?)
            ),
            "_gt" => format!("{col} > {}", cx.bind(resolve_value(operand, cx.variables)?)),
            "_gte" => format!(
                "{col} >= {}",
                cx.bind(resolve_value(operand, cx.variables)?)
            ),
            "_lt" => format!("{col} < {}", cx.bind(resolve_value(operand, cx.variables)?)),
            "_lte" => format!(
                "{col} <= {}",
                cx.bind(resolve_value(operand, cx.variables)?)
            ),
            "_like" => format!(
                "{col} LIKE {}",
                cx.bind(resolve_value(operand, cx.variables)?)
            ),
            "_in" => {
                let items = resolve_list(operand, cx.variables)?;
                if items.is_empty() {
                    "0 = 1".to_string() // IN () is false
                } else {
                    let phs: Vec<String> = items.into_iter().map(|v| cx.bind(v)).collect();
                    format!("{col} IN ({})", phs.join(", "))
                }
            }
            "_is_null" => match resolve_value(operand, cx.variables)? {
                SqlValue::Boolean(true) => format!("{col} IS NULL"),
                SqlValue::Boolean(false) => format!("{col} IS NOT NULL"),
                _ => {
                    return Err(CompileError::Unsupported(
                        "_is_null expects a boolean".into(),
                    ))
                }
            },
            other => return Err(CompileError::Unsupported(format!("operator `{other}`"))),
        };
        parts.push(clause);
    }
    Ok(if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        format!("({})", parts.join(" AND "))
    })
}

/// The `ORDER BY` clause from the `order_by` argument (a list of `{col: asc|desc}`).
fn order_by_clause(
    field: &Field<'_, String>,
    table: &Table,
    qualifier: &str,
    policy: &DataPolicy,
    dialect: &dyn Dialect,
) -> Result<Option<String>, CompileError> {
    let Some((_, arg)) = field.arguments.iter().find(|(n, _)| n == "order_by") else {
        return Ok(None);
    };
    let entries: Vec<&Value<'_, String>> = match arg {
        Value::List(items) => items.iter().collect(),
        obj @ Value::Object(_) => vec![obj],
        _ => {
            return Err(CompileError::Unsupported(
                "order_by expects object(s)".into(),
            ))
        }
    };
    let mut terms = Vec::new();
    for entry in entries {
        let Value::Object(obj) = entry else {
            return Err(CompileError::Unsupported(
                "order_by entry must be an object".into(),
            ));
        };
        for (column, dir) in obj {
            if table.column(column).is_none() || !policy.is_column_exposed(&table.name, column) {
                return Err(CompileError::UnknownField(format!(
                    "{}.{column}",
                    table.name
                )));
            }
            let direction = match dir {
                Value::Enum(e) if e == "asc" => "ASC",
                Value::Enum(e) if e == "desc" => "DESC",
                Value::String(s) if s == "asc" => "ASC",
                Value::String(s) if s == "desc" => "DESC",
                _ => return Err(CompileError::Unsupported("order_by direction".into())),
            };
            terms.push(format!(
                "{qualifier}.{} {direction}",
                dialect.quote_ident(column)
            ));
        }
    }
    Ok(if terms.is_empty() {
        None
    } else {
        Some(terms.join(", "))
    })
}

/// Resolve a GraphQL value (resolving a variable reference) to a single SQL value.
fn resolve_value(
    value: &Value<'_, String>,
    variables: &serde_json::Value,
) -> Result<SqlValue, CompileError> {
    match value {
        Value::Variable(name) => json_to_sql(
            variables
                .get(name.as_str())
                .unwrap_or(&serde_json::Value::Null),
        ),
        Value::Int(n) => n
            .as_i64()
            .map(SqlValue::Integer)
            .ok_or_else(|| CompileError::Unsupported("integer out of range".into())),
        Value::Float(f) => Ok(SqlValue::Real(*f)),
        Value::String(s) => Ok(SqlValue::Text(s.clone())),
        Value::Boolean(b) => Ok(SqlValue::Boolean(*b)),
        Value::Null => Ok(SqlValue::Null),
        Value::Enum(e) => Ok(SqlValue::Text(e.clone())),
        Value::List(_) | Value::Object(_) => Err(CompileError::Unsupported(
            "a scalar value was expected".into(),
        )),
    }
}

/// Resolve a value expected to be a list (an inline list, or a variable holding a JSON
/// array) into SQL values.
fn resolve_list(
    value: &Value<'_, String>,
    variables: &serde_json::Value,
) -> Result<Vec<SqlValue>, CompileError> {
    match value {
        Value::List(items) => items.iter().map(|v| resolve_value(v, variables)).collect(),
        Value::Variable(name) => match variables.get(name.as_str()) {
            Some(serde_json::Value::Array(items)) => items.iter().map(json_to_sql).collect(),
            _ => Err(CompileError::Unsupported("_in expects a list".into())),
        },
        _ => Err(CompileError::Unsupported("_in expects a list".into())),
    }
}

/// Map a JSON scalar (a resolved variable) to a SQL value.
fn json_to_sql(value: &serde_json::Value) -> Result<SqlValue, CompileError> {
    Ok(match value {
        serde_json::Value::Null => SqlValue::Null,
        serde_json::Value::Bool(b) => SqlValue::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqlValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                SqlValue::Real(f)
            } else {
                return Err(CompileError::Unsupported("numeric out of range".into()));
            }
        }
        serde_json::Value::String(s) => SqlValue::Text(s.clone()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            return Err(CompileError::Unsupported(
                "a scalar variable was expected".into(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::policy::{DataPolicy, RowPredicate, RowTerm, RowValue, TablePolicy};
    use super::super::schema::{Column, DbSchema, ForeignKey, ScalarType, Table};
    use super::*;
    use std::collections::BTreeMap;

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
                            name: "age".into(),
                            ty: ScalarType::Int,
                            nullable: true,
                        },
                        Column {
                            name: "tenant_id".into(),
                            ty: ScalarType::String,
                            nullable: false,
                        },
                    ],
                    primary_key: vec!["id".into()],
                    foreign_keys: vec![],
                },
                Table {
                    name: "posts".into(),
                    columns: vec![
                        Column {
                            name: "id".into(),
                            ty: ScalarType::Id,
                            nullable: false,
                        },
                        Column {
                            name: "author_id".into(),
                            ty: ScalarType::Id,
                            nullable: false,
                        },
                    ],
                    primary_key: vec!["id".into()],
                    foreign_keys: vec![ForeignKey {
                        columns: vec!["author_id".into()],
                        ref_table: "users".into(),
                        ref_columns: vec!["id".into()],
                    }],
                },
            ],
        }
    }

    fn open_policy() -> DataPolicy {
        DataPolicy::new()
            .with_table("users", TablePolicy::columns(["id", "name", "age"]))
            .with_table("posts", TablePolicy::columns(["id", "author_id"]))
    }

    fn compile_one(
        query: &str,
        policy: &DataPolicy,
        claims: &Claims,
    ) -> Result<RootQuery, CompileError> {
        let vars = serde_json::json!({});
        let mut planned = compile(
            query,
            &vars,
            &schema(),
            policy,
            claims,
            &super::super::dialect::Sqlite,
        )?;
        Ok(planned.roots.remove(0))
    }

    #[test]
    fn a_list_selects_qualified_columns() {
        let root =
            compile_one("{ users { id name } }", &open_policy(), &Claims::default()).unwrap();
        assert_eq!(
            root.sql,
            r#"SELECT "users"."id", "users"."name" FROM "users""#
        );
        assert!(!root.single);
    }

    #[test]
    fn by_pk_binds_the_key_as_a_parameter() {
        let root = compile_one(
            r#"{ users_by_pk(id: "7") { name } }"#,
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert_eq!(
            root.sql,
            r#"SELECT "users"."name" FROM "users" WHERE "users"."id" = ?1"#
        );
        assert_eq!(root.params, vec![SqlValue::Text("7".into())]);
        assert!(root.single);
    }

    #[test]
    fn where_operators_are_parameterized_never_inlined() {
        let root = compile_one(
            r#"{ users(where: { age: { _gte: 18 }, name: { _like: "a%" } }) { id } }"#,
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert_eq!(
            root.sql,
            r#"SELECT "users"."id" FROM "users" WHERE "users"."age" >= ?1 AND "users"."name" LIKE ?2"#
        );
        assert_eq!(
            root.params,
            vec![SqlValue::Integer(18), SqlValue::Text("a%".into())]
        );
    }

    #[test]
    fn in_and_junctions_compile() {
        let root = compile_one(
            r#"{ users(where: { _or: [ { id: { _in: ["1","2"] } }, { age: { _lt: 5 } } ] }) { id } }"#,
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert_eq!(
            root.sql,
            r#"SELECT "users"."id" FROM "users" WHERE ("users"."id" IN (?1, ?2) OR "users"."age" < ?3)"#
        );
        assert_eq!(root.params.len(), 3);
    }

    #[test]
    fn order_limit_offset_compile() {
        let root = compile_one(
            "{ users(order_by: { age: desc }, limit: 10, offset: 5) { id } }",
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert_eq!(
            root.sql,
            r#"SELECT "users"."id" FROM "users" ORDER BY "users"."age" DESC LIMIT ?1 OFFSET ?2"#
        );
        assert_eq!(
            root.params,
            vec![SqlValue::Integer(10), SqlValue::Integer(5)]
        );
    }

    #[test]
    fn the_policy_row_filter_is_combined_into_where() {
        let policy = DataPolicy::new().with_table(
            "users",
            TablePolicy::columns(["id", "name"]).with_rows(RowPredicate {
                terms: vec![RowTerm {
                    column: "tenant_id".into(),
                    op: RowOp::Eq,
                    value: RowValue::Claim("tenant".into()),
                }],
            }),
        );
        let claims = Claims::new(BTreeMap::from([(
            "tenant".to_string(),
            SqlValue::Text("acme".into()),
        )]));
        let root = compile_one(
            r#"{ users(where: { name: { _eq: "x" } }) { id } }"#,
            &policy,
            &claims,
        )
        .unwrap();
        assert_eq!(
            root.sql,
            r#"SELECT "users"."id" FROM "users" WHERE "users"."tenant_id" = ?1 AND "users"."name" = ?2"#
        );
        assert_eq!(
            root.params,
            vec![SqlValue::Text("acme".into()), SqlValue::Text("x".into())]
        );
    }

    #[test]
    fn a_to_many_relationship_becomes_a_correlated_json_subquery() {
        // users → posts (posts.author_id references users.id).
        let root = compile_one(
            "{ users { name posts { id } } }",
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert!(
            root.sql.contains(
                r#"(SELECT json_group_array(json_object('id', "t1"."id")) FROM "posts" AS "t1" WHERE "t1"."author_id" = "users"."id")"#
            ),
            "sql: {}",
            root.sql
        );
        // The `posts` field is a JSON-sourced projection.
        assert!(root
            .projection
            .iter()
            .any(|f| f.key == "posts" && matches!(f.source, OutSource::Json(_))));
    }

    #[test]
    fn a_to_one_relationship_becomes_a_correlated_json_subquery() {
        // posts → author (follow posts.author_id to users). The FK column `author_id`
        // strips to the field name `author`.
        let root = compile_one(
            "{ posts { id author { name } } }",
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert!(
            root.sql.contains(
                r#"(SELECT json_object('name', "t1"."name") FROM "users" AS "t1" WHERE "t1"."id" = "posts"."author_id")"#
            ),
            "sql: {}",
            root.sql
        );
    }

    #[test]
    fn a_relationship_nested_beyond_one_level_is_rejected() {
        let err = compile_one(
            "{ users { posts { author { name } } } }",
            &open_policy(),
            &Claims::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::Unsupported(m) if m.contains("nested")));
    }

    #[test]
    fn an_unexposed_column_is_rejected() {
        let err = compile_one(
            "{ users { tenant_id } }",
            &open_policy(),
            &Claims::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::UnknownField(f) if f == "users.tenant_id"));
    }

    #[test]
    fn an_unexposed_table_is_rejected() {
        let err =
            compile_one("{ secrets { id } }", &open_policy(), &Claims::default()).unwrap_err();
        assert!(matches!(err, CompileError::UnknownField(_)));
    }

    #[test]
    fn a_variable_where_value_is_resolved() {
        let vars = serde_json::json!({ "min": 21 });
        let mut planned = compile(
            "query($min: Int) { users(where: { age: { _gte: $min } }) { id } }",
            &vars,
            &schema(),
            &open_policy(),
            &Claims::default(),
            &super::super::dialect::Sqlite,
        )
        .unwrap();
        let root = planned.roots.remove(0);
        assert_eq!(root.params, vec![SqlValue::Integer(21)]);
    }

    #[test]
    fn mutations_are_not_compiled_here() {
        let vars = serde_json::json!({});
        let err = compile(
            "mutation { insert_users(name: \"x\") { id } }",
            &vars,
            &schema(),
            &open_policy(),
            &Claims::default(),
            &super::super::dialect::Sqlite,
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::Unsupported(m) if m.contains("mutation")));
    }
}
