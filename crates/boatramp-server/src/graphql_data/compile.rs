//! The query compiler: a GraphQL read operation → one parameterized SQL `SELECT` per root
//! field.
//!
//! This is where the connector stays a *compiler*, not an engine. Each root field lowers to
//! a single `SELECT` whose values are **always bound parameters** (injection-safe) and whose
//! identifiers come **only** from the introspected + policy-exposed schema (never request
//! text). Anything the compiler cannot lower — an unexposed table/column, an unknown
//! operator, a relationship field (a later landing), a mutation/subscription — is a
//! [`CompileError`], never a partial or guessed result. The policy's row filter is combined
//! into every `WHERE`, so tenant isolation is enforced at compile time.

use super::dialect::Dialect;
use super::policy::{Claims, DataPolicy, PolicyError, RowOp};
use super::schema::{DbSchema, Table};
use boatramp_core::sql::SqlValue;
use graphql_parser::query::{Definition, Field, OperationDefinition, Selection, Value};

/// How one output field of a row is produced.
#[derive(Debug, PartialEq)]
pub(crate) enum OutSource {
    /// The value at this index of the `SELECT` column list (and the returned row).
    Column(usize),
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

/// Compile `query` (with its `variables`) against `schema` (already policy-projected is
/// fine, but exposure is re-checked here) under `policy` + `claims`, targeting `dialect`.
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

/// Per-root compilation state: the parameter accumulator and the request context.
struct Cx<'a> {
    dialect: &'a dyn Dialect,
    variables: &'a serde_json::Value,
    params: Vec<SqlValue>,
}

impl Cx<'_> {
    /// Bind `value` as the next parameter and return its placeholder.
    fn bind(&mut self, value: SqlValue) -> String {
        self.params.push(value);
        self.dialect.placeholder(self.params.len())
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

    // The table must exist and be exposed.
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
    };

    // Projection (the selected columns / __typename).
    let (projection, select_columns) = build_projection(field, table, table_name, policy)?;

    // WHERE = the policy row filter, plus either the `_by_pk` key equality or the list
    // `where` argument.
    let mut clauses: Vec<String> = Vec::new();
    if let Some(filter) = policy.row_filter(table_name, claims)? {
        for term in filter.terms {
            let op = match term.op {
                RowOp::Eq => "=",
            };
            let ph = cx.bind(term.value);
            clauses.push(format!("{} {op} {ph}", dialect.quote_ident(&term.column)));
        }
    }
    if single {
        // A `_by_pk` field: each primary-key column is a required argument.
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
            let ph = cx.bind(value);
            clauses.push(format!("{} = {ph}", dialect.quote_ident(pk)));
        }
    } else if let Some((_, where_arg)) = field.arguments.iter().find(|(n, _)| n == "where") {
        if let Some(expr) = compile_bool_exp(where_arg, table, policy, &mut cx)? {
            clauses.push(expr);
        }
    }

    // Assemble the statement.
    let select_list = if select_columns.is_empty() {
        "1".to_string()
    } else {
        select_columns
            .iter()
            .map(|c| dialect.quote_ident(c))
            .collect::<Vec<_>>()
            .join(", ")
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
        if let Some(order) = order_by_clause(field, table, policy, dialect)? {
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

/// Build the output projection + the ordered list of DB columns to `SELECT`.
fn build_projection(
    field: &Field<'_, String>,
    table: &Table,
    table_name: &str,
    policy: &DataPolicy,
) -> Result<(Vec<OutField>, Vec<String>), CompileError> {
    let mut projection = Vec::new();
    let mut select_columns = Vec::new();
    for sel in &field.selection_set.items {
        let Selection::Field(f) = sel else {
            return Err(CompileError::Unsupported("fragments in a selection".into()));
        };
        let key = f.alias.clone().unwrap_or_else(|| f.name.clone());
        if f.name == "__typename" {
            projection.push(OutField {
                key,
                source: OutSource::Typename(table_name.to_string()),
            });
            continue;
        }
        if !f.selection_set.items.is_empty() {
            // A nested selection is a relationship — a later landing.
            return Err(CompileError::Unsupported(format!(
                "relationship field `{}`",
                f.name
            )));
        }
        if table.column(&f.name).is_none() || !policy.is_column_exposed(table_name, &f.name) {
            return Err(CompileError::UnknownField(format!(
                "{table_name}.{}",
                f.name
            )));
        }
        let idx = select_columns.len();
        select_columns.push(f.name.clone());
        projection.push(OutField {
            key,
            source: OutSource::Column(idx),
        });
    }
    Ok((projection, select_columns))
}

/// Compile a `<table>_bool_exp` value into a SQL boolean expression (or `None` if empty).
fn compile_bool_exp(
    value: &Value<'_, String>,
    table: &Table,
    policy: &DataPolicy,
    cx: &mut Cx<'_>,
) -> Result<Option<String>, CompileError> {
    let Value::Object(obj) = value else {
        // A variable holding the whole `where` is not supported; require an inline object.
        return Err(CompileError::Unsupported("non-object `where`".into()));
    };
    let mut clauses = Vec::new();
    for (key, val) in obj {
        match key.as_str() {
            "_and" => clauses.push(compile_junction(val, table, policy, cx, " AND ")?),
            "_or" => clauses.push(compile_junction(val, table, policy, cx, " OR ")?),
            "_not" => {
                let inner = compile_bool_exp(val, table, policy, cx)?.unwrap_or_default();
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
                clauses.push(compile_comparison(column, val, cx)?);
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
    policy: &DataPolicy,
    cx: &mut Cx<'_>,
    sep: &str,
) -> Result<String, CompileError> {
    let Value::List(items) = value else {
        return Err(CompileError::Unsupported("_and/_or expects a list".into()));
    };
    let parts: Vec<String> = items
        .iter()
        .map(|v| compile_bool_exp(v, table, policy, cx).map(Option::unwrap_or_default))
        .collect::<Result<_, _>>()?;
    Ok(format!("({})", parts.join(sep)))
}

/// Compile a `<Scalar>_comparison_exp` for `column` (already exposure-checked).
fn compile_comparison(
    column: &str,
    value: &Value<'_, String>,
    cx: &mut Cx<'_>,
) -> Result<String, CompileError> {
    let Value::Object(ops) = value else {
        return Err(CompileError::Unsupported(
            "a comparison must be an object".into(),
        ));
    };
    let col = cx.dialect.quote_ident(column);
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
    policy: &DataPolicy,
    dialect: &dyn Dialect,
) -> Result<Option<String>, CompileError> {
    let Some((_, arg)) = field.arguments.iter().find(|(n, _)| n == "order_by") else {
        return Ok(None);
    };
    // Accept a single object or a list of them.
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
            terms.push(format!("{} {direction}", dialect.quote_ident(column)));
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
    use super::super::schema::{Column, DbSchema, ScalarType, Table};
    use super::*;
    use std::collections::BTreeMap;

    fn schema() -> DbSchema {
        DbSchema {
            tables: vec![Table {
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
            }],
        }
    }

    fn open_policy() -> DataPolicy {
        DataPolicy::new().with_table("users", TablePolicy::columns(["id", "name", "age"]))
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
    fn a_list_selects_exposed_columns() {
        let root =
            compile_one("{ users { id name } }", &open_policy(), &Claims::default()).unwrap();
        assert_eq!(root.sql, r#"SELECT "id", "name" FROM "users""#);
        assert!(!root.single);
        assert_eq!(root.projection.len(), 2);
    }

    #[test]
    fn by_pk_binds_the_key_as_a_parameter() {
        let root = compile_one(
            r#"{ users_by_pk(id: "7") { name } }"#,
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert_eq!(root.sql, r#"SELECT "name" FROM "users" WHERE "id" = ?"#);
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
        // Keys sort (BTreeMap): age before name.
        assert_eq!(
            root.sql,
            r#"SELECT "id" FROM "users" WHERE "age" >= ? AND "name" LIKE ?"#
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
            r#"SELECT "id" FROM "users" WHERE ("id" IN (?, ?) OR "age" < ?)"#
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
            r#"SELECT "id" FROM "users" ORDER BY "age" DESC LIMIT ? OFFSET ?"#
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
            r#"SELECT "id" FROM "users" WHERE "tenant_id" = ? AND "name" = ?"#
        );
        assert_eq!(
            root.params,
            vec![SqlValue::Text("acme".into()), SqlValue::Text("x".into())]
        );
    }

    #[test]
    fn an_unexposed_column_is_rejected() {
        // `tenant_id` exists but is not exposed by open_policy.
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
    fn a_relationship_field_is_unsupported_for_now() {
        // A nested selection (posts) is a relationship — not yet lowered.
        let err = compile_one(
            "{ users { id posts { id } } }",
            &open_policy(),
            &Claims::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::Unsupported(m) if m.contains("relationship")));
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
