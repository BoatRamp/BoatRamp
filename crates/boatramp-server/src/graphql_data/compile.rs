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
use async_graphql_parser::types::{
    DocumentOperations, ExecutableDocument, Field, OperationDefinition, OperationType, Selection,
};
use async_graphql_parser::Positioned;
use async_graphql_value::Value;
use boatramp_core::sql::SqlValue;
use std::collections::BTreeMap;

/// The operation to compile: the sole operation, or the first of a multi-operation document
/// (the data connector compiles one operation). An anonymous `{ … }` shorthand parses as a
/// single query operation.
fn first_operation(doc: &ExecutableDocument) -> Option<&OperationDefinition> {
    match &doc.operations {
        DocumentOperations::Single(op) => Some(&op.node),
        DocumentOperations::Multiple(map) => map.values().next().map(|op| &op.node),
    }
}

/// The response key a field projects under: its alias, else its name.
fn field_response_key(field: &Field) -> String {
    field
        .alias
        .as_ref()
        .map(|a| a.node.to_string())
        .unwrap_or_else(|| field.name.node.to_string())
}

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

/// A field of the root type resolved by a **wasm function** (a local `_entities` fetch),
/// batched over the returned rows and joined by key.
#[derive(Debug, PartialEq)]
pub(crate) struct Delegation {
    /// The response key (alias) to fill on each row object.
    pub response_key: String,
    /// The entity field the function resolves (the key into its `_entities` result).
    pub field: String,
    /// The wasm function to invoke.
    pub function: String,
    /// The GraphQL type name (for the `... on Type` in the `_entities` query).
    pub type_name: String,
    /// The entity key: each key column's name + its index in the `SELECT`/row (so the
    /// runner can build one representation per row).
    pub key: Vec<(String, usize)>,
    /// The `_entities` query text to send the function.
    pub entities_query: String,
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
    /// Fields resolved after the query by a wasm function (batched), if any.
    pub delegations: Vec<Delegation>,
}

/// A whole operation lowered to one SQL statement per root field.
#[derive(Debug, PartialEq)]
pub(crate) struct PlannedSql {
    pub roots: Vec<RootQuery>,
}

/// A compiled selection set: the `SELECT` expressions, the output projection, and any
/// delegated fields.
type CompiledSelection = (Vec<String>, Vec<OutField>, Vec<Delegation>);

/// One write (`INSERT`/`UPDATE`/`DELETE`) a mutation lowers to.
#[derive(Debug, PartialEq)]
pub(crate) struct WriteStatement {
    /// The response key the write's result (`{ affected_rows }`) is returned under.
    pub response_key: String,
    /// The parameterized write SQL.
    pub sql: String,
    /// The bound parameters, in placeholder order.
    pub params: Vec<SqlValue>,
}

/// A mutation operation lowered to a sequence of writes (run in one transaction).
#[derive(Debug, PartialEq)]
pub(crate) struct MutationPlan {
    pub statements: Vec<WriteStatement>,
}

/// A federation `_entities` fetch lowered to a single keyed `SELECT`. The runner joins the
/// returned rows back to the representations by key, in representation order (the `_entities`
/// contract), so a SQL source is a full federation entity resolver.
#[derive(Debug, PartialEq)]
pub(crate) struct EntitiesPlan {
    pub sql: String,
    pub params: Vec<SqlValue>,
    /// How to shape each returned row.
    pub projection: Vec<OutField>,
    /// Delegated fields within the entity selection (filled by the runner).
    pub delegations: Vec<Delegation>,
    /// The `SELECT`/row indices of the key columns (to match a row back to a representation).
    pub key_indices: Vec<usize>,
    /// The key tuple per representation, in request order (the output order).
    pub representation_keys: Vec<Vec<SqlValue>>,
}

/// Whether `query` is a federation `_entities` fetch (a root `_entities` field).
pub(crate) fn is_entities_query(query: &str) -> bool {
    let Ok(doc) = async_graphql_parser::parse_query(query) else {
        return false;
    };
    let Some(op) = first_operation(&doc) else {
        return false;
    };
    op.ty == OperationType::Query
        && op
            .selection_set
            .node
            .items
            .iter()
            .any(|s| matches!(&s.node, Selection::Field(f) if f.node.name.node == "_entities"))
}

/// Compile a federation `_entities` fetch into one keyed `SELECT`. The `... on <Type>`
/// selection names the entity table; each representation supplies the key. The row filter
/// still applies, so a subgraph only resolves entities it's allowed to see.
pub(crate) fn compile_entities(
    query: &str,
    variables: &serde_json::Value,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    dialect: &dyn Dialect,
) -> Result<EntitiesPlan, CompileError> {
    let doc =
        async_graphql_parser::parse_query(query).map_err(|e| CompileError::Parse(e.to_string()))?;
    let op = first_operation(&doc).ok_or(CompileError::NoOperation)?;
    if op.ty != OperationType::Query {
        return Err(CompileError::Unsupported(
            "`_entities` must be a query".into(),
        ));
    }
    let entities = op
        .selection_set
        .node
        .items
        .iter()
        .find_map(|s| match &s.node {
            Selection::Field(f) if f.node.name.node == "_entities" => Some(&f.node),
            _ => None,
        })
        .ok_or_else(|| CompileError::Unsupported("expected an `_entities` query".into()))?;
    // The `... on <Type> { … }` inline fragment names the entity type + its selection.
    let (type_name, inner) = entities
        .selection_set
        .node
        .items
        .iter()
        .find_map(|s| match &s.node {
            Selection::InlineFragment(frag) => frag.node.type_condition.as_ref().map(|tc| {
                (
                    tc.node.on.node.to_string(),
                    &frag.node.selection_set.node.items,
                )
            }),
            _ => None,
        })
        .ok_or_else(|| {
            CompileError::Unsupported("`_entities` needs an `... on Type` selection".into())
        })?;

    if !policy.is_table_exposed(&type_name) {
        return Err(CompileError::UnknownField(type_name));
    }
    let table = schema
        .table(&type_name)
        .ok_or_else(|| CompileError::UnknownField(type_name.clone()))?;
    if table.primary_key.is_empty() {
        return Err(CompileError::Unsupported(format!(
            "entity `{type_name}` has no primary key to resolve by"
        )));
    }

    // One key tuple per representation, in order.
    let reps = variables
        .get("representations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut representation_keys = Vec::with_capacity(reps.len());
    for rep in &reps {
        let mut key = Vec::with_capacity(table.primary_key.len());
        for pk in &table.primary_key {
            key.push(json_to_sql(
                rep.get(pk).unwrap_or(&serde_json::Value::Null),
            )?);
        }
        representation_keys.push(key);
    }

    let mut cx = Cx {
        dialect,
        variables,
        params: Vec::new(),
        alias_seq: 1,
    };
    let qualifier = dialect.quote_ident(&type_name);
    let (mut exprs, projection, delegations) =
        compile_selection(inner, table, &qualifier, schema, policy, claims, &mut cx)?;
    // Ensure the key columns are selected, so a row can be matched to its representation.
    let mut key_indices = Vec::with_capacity(table.primary_key.len());
    for pk in &table.primary_key {
        let expr = format!("{qualifier}.{}", dialect.quote_ident(pk));
        let idx = exprs.iter().position(|e| *e == expr).unwrap_or_else(|| {
            exprs.push(expr);
            exprs.len() - 1
        });
        key_indices.push(idx);
    }

    // WHERE: the key set + the row filter.
    let mut clauses = Vec::new();
    if !representation_keys.is_empty() {
        if table.primary_key.len() == 1 {
            let col = qualify(&qualifier, &table.primary_key[0], dialect);
            let phs: Vec<String> = representation_keys
                .iter()
                .map(|k| cx.bind(k[0].clone()))
                .collect();
            clauses.push(format!("{col} IN ({})", phs.join(", ")));
        } else {
            let cols = table
                .primary_key
                .iter()
                .map(|pk| qualify(&qualifier, pk, dialect))
                .collect::<Vec<_>>()
                .join(", ");
            let tuples: Vec<String> = representation_keys
                .iter()
                .map(|k| {
                    let phs = k
                        .iter()
                        .map(|v| cx.bind(v.clone()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("({phs})")
                })
                .collect();
            clauses.push(format!("({cols}) IN ({})", tuples.join(", ")));
        }
    }
    if let Some(filter) = policy.row_filter(&type_name, claims)? {
        for term in filter.terms {
            let col = qualify(&qualifier, &term.column, dialect);
            let ph = cx.bind(term.value);
            clauses.push(format!("{col} = {ph}"));
        }
    }

    let select_list = if exprs.is_empty() {
        "1".to_string()
    } else {
        exprs.join(", ")
    };
    let mut sql = format!("SELECT {select_list} FROM {qualifier}");
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    Ok(EntitiesPlan {
        sql,
        params: cx.params,
        projection,
        delegations,
        key_indices,
        representation_keys,
    })
}

/// Whether `query`'s operation is a mutation (so the caller runs it on a write transaction
/// and only if the site opted into mutations).
pub(crate) fn is_mutation(query: &str) -> bool {
    async_graphql_parser::parse_query(query)
        .ok()
        .and_then(|doc| first_operation(&doc).map(|op| op.ty == OperationType::Mutation))
        .unwrap_or(false)
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
    let doc =
        async_graphql_parser::parse_query(query).map_err(|e| CompileError::Parse(e.to_string()))?;
    let op = first_operation(&doc).ok_or(CompileError::NoOperation)?;
    match op.ty {
        OperationType::Query => {}
        OperationType::Mutation => return Err(CompileError::Unsupported("mutations".into())),
        OperationType::Subscription => {
            return Err(CompileError::Unsupported("subscriptions".into()))
        }
    }

    let mut roots = Vec::new();
    for item in &op.selection_set.node.items {
        let Selection::Field(field) = &item.node else {
            return Err(CompileError::Unsupported("fragments at the root".into()));
        };
        roots.push(compile_root(
            &field.node,
            variables,
            schema,
            policy,
            claims,
            dialect,
        )?);
    }
    Ok(PlannedSql { roots })
}

/// Compile a **mutation** operation into a sequence of writes. Each root field is
/// `insert_<t>` / `update_<t>` / `delete_<t>` on an exposed table. Writable columns are the
/// exposed columns; the row filter is forced onto inserts (so a new row belongs to the
/// tenant) and combined into every update/delete `WHERE` (so a tenant can only change its own
/// rows). An unbounded update/delete is refused. Values are always bound parameters.
pub(crate) fn compile_mutation(
    query: &str,
    variables: &serde_json::Value,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    dialect: &dyn Dialect,
) -> Result<MutationPlan, CompileError> {
    let doc =
        async_graphql_parser::parse_query(query).map_err(|e| CompileError::Parse(e.to_string()))?;
    let op = first_operation(&doc).ok_or(CompileError::NoOperation)?;
    if op.ty != OperationType::Mutation {
        return Err(CompileError::Unsupported("expected a mutation".into()));
    }
    let mut statements = Vec::new();
    for sel in &op.selection_set.node.items {
        let Selection::Field(field) = &sel.node else {
            return Err(CompileError::Unsupported("fragments in a mutation".into()));
        };
        statements.push(compile_write(
            &field.node,
            variables,
            schema,
            policy,
            claims,
            dialect,
        )?);
    }
    Ok(MutationPlan { statements })
}

/// The three write shapes.
enum WriteKind {
    Insert,
    Update,
    Delete,
}

fn compile_write(
    field: &Field,
    variables: &serde_json::Value,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    dialect: &dyn Dialect,
) -> Result<WriteStatement, CompileError> {
    let response_key = field_response_key(field);
    let field_name = field.name.node.as_str();
    let (table_name, kind) = if let Some(t) = field_name.strip_prefix("insert_") {
        (t, WriteKind::Insert)
    } else if let Some(t) = field_name.strip_prefix("update_") {
        (t, WriteKind::Update)
    } else if let Some(t) = field_name.strip_prefix("delete_") {
        (t, WriteKind::Delete)
    } else {
        return Err(CompileError::UnknownField(field_name.to_string()));
    };
    if !policy.is_table_exposed(table_name) {
        return Err(CompileError::UnknownField(field_name.to_string()));
    }
    let table = schema
        .table(table_name)
        .ok_or_else(|| CompileError::UnknownField(field_name.to_string()))?;

    let mut cx = Cx {
        dialect,
        variables,
        params: Vec::new(),
        alias_seq: 1,
    };
    let sql = match kind {
        WriteKind::Insert => compile_insert(field, table, policy, claims, &mut cx)?,
        WriteKind::Update => compile_update(field, table, policy, claims, &mut cx)?,
        WriteKind::Delete => compile_delete(field, table, policy, claims, &mut cx)?,
    };
    Ok(WriteStatement {
        response_key,
        sql,
        params: cx.params,
    })
}

/// `INSERT INTO <t> (…) VALUES (…)` from an `object` argument, with the row filter forced.
fn compile_insert(
    field: &Field,
    table: &Table,
    policy: &DataPolicy,
    claims: &Claims,
    cx: &mut Cx<'_>,
) -> Result<String, CompileError> {
    let Some((_, arg)) = field.arguments.iter().find(|(n, _)| n.node == "object") else {
        return Err(CompileError::Unsupported(
            "insert requires an `object` argument".into(),
        ));
    };
    let Value::Object(map) = &arg.node else {
        return Err(CompileError::Unsupported(
            "insert requires an `object` argument".into(),
        ));
    };
    let mut columns: Vec<String> = Vec::new();
    let mut values: Vec<SqlValue> = Vec::new();
    for (col, val) in map {
        let col = col.as_str();
        if table.column(col).is_none() || !policy.is_column_exposed(&table.name, col) {
            return Err(CompileError::UnknownField(format!("{}.{col}", table.name)));
        }
        columns.push(col.to_string());
        values.push(resolve_value(val, cx.variables)?);
    }
    // A new row must belong to the tenant: force the row-filter columns to the claim values.
    if let Some(filter) = policy.row_filter(&table.name, claims)? {
        for term in filter.terms {
            match columns.iter().position(|c| *c == term.column) {
                Some(pos) => values[pos] = term.value,
                None => {
                    columns.push(term.column);
                    values.push(term.value);
                }
            }
        }
    }
    if columns.is_empty() {
        return Err(CompileError::Unsupported("insert sets no columns".into()));
    }
    let col_list = columns
        .iter()
        .map(|c| cx.dialect.quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = values
        .into_iter()
        .map(|v| cx.bind(v))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        "INSERT INTO {} ({col_list}) VALUES ({placeholders})",
        cx.dialect.quote_ident(&table.name)
    ))
}

/// `UPDATE <t> SET … WHERE …` from `_set` + `where`; refuses an unbounded update.
fn compile_update(
    field: &Field,
    table: &Table,
    policy: &DataPolicy,
    claims: &Claims,
    cx: &mut Cx<'_>,
) -> Result<String, CompileError> {
    let Some((_, arg)) = field.arguments.iter().find(|(n, _)| n.node == "_set") else {
        return Err(CompileError::Unsupported(
            "update requires a `_set` argument".into(),
        ));
    };
    let Value::Object(map) = &arg.node else {
        return Err(CompileError::Unsupported(
            "update requires a `_set` argument".into(),
        ));
    };
    if map.is_empty() {
        return Err(CompileError::Unsupported("`_set` sets no columns".into()));
    }
    let mut assignments = Vec::new();
    for (col, val) in map {
        let col = col.as_str();
        if table.column(col).is_none() || !policy.is_column_exposed(&table.name, col) {
            return Err(CompileError::UnknownField(format!("{}.{col}", table.name)));
        }
        let value = resolve_value(val, cx.variables)?;
        let ph = cx.bind(value);
        assignments.push(format!("{} = {ph}", cx.dialect.quote_ident(col)));
    }
    let Some(where_sql) = compile_write_where(field, table, policy, claims, cx)? else {
        return Err(CompileError::Unsupported(
            "update requires a `where` (or a row filter) — an unbounded update is refused".into(),
        ));
    };
    Ok(format!(
        "UPDATE {} SET {} WHERE {where_sql}",
        cx.dialect.quote_ident(&table.name),
        assignments.join(", ")
    ))
}

/// `DELETE FROM <t> WHERE …`; refuses an unbounded delete.
fn compile_delete(
    field: &Field,
    table: &Table,
    policy: &DataPolicy,
    claims: &Claims,
    cx: &mut Cx<'_>,
) -> Result<String, CompileError> {
    let Some(where_sql) = compile_write_where(field, table, policy, claims, cx)? else {
        return Err(CompileError::Unsupported(
            "delete requires a `where` (or a row filter) — an unbounded delete is refused".into(),
        ));
    };
    Ok(format!(
        "DELETE FROM {} WHERE {where_sql}",
        cx.dialect.quote_ident(&table.name)
    ))
}

/// The write `WHERE`: the client `where` argument combined with the table's row filter
/// (unqualified columns — a single-table statement). `None` when both are absent.
fn compile_write_where(
    field: &Field,
    table: &Table,
    policy: &DataPolicy,
    claims: &Claims,
    cx: &mut Cx<'_>,
) -> Result<Option<String>, CompileError> {
    let mut clauses = Vec::new();
    if let Some((_, where_arg)) = field.arguments.iter().find(|(n, _)| n.node == "where") {
        if let Some(expr) = compile_bool_exp(&where_arg.node, table, "", policy, cx)? {
            clauses.push(expr);
        }
    }
    if let Some(filter) = policy.row_filter(&table.name, claims)? {
        for term in filter.terms {
            let col = cx.dialect.quote_ident(&term.column);
            let ph = cx.bind(term.value);
            clauses.push(format!("{col} = {ph}"));
        }
    }
    Ok(if clauses.is_empty() {
        None
    } else {
        Some(clauses.join(" AND "))
    })
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
    field: &Field,
    variables: &serde_json::Value,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    dialect: &dyn Dialect,
) -> Result<RootQuery, CompileError> {
    let response_key = field_response_key(field);
    let field_name = field.name.node.as_str();
    let (table_name, single) = match field_name.strip_suffix("_by_pk") {
        Some(t) => (t, true),
        None => (field_name, false),
    };

    if !policy.is_table_exposed(table_name) {
        return Err(CompileError::UnknownField(field_name.to_string()));
    }
    let table = schema
        .table(table_name)
        .ok_or_else(|| CompileError::UnknownField(field_name.to_string()))?;

    let mut cx = Cx {
        dialect,
        variables,
        params: Vec::new(),
        alias_seq: 1,
    };
    // The root table is referenced by its (quoted) name; subqueries correlate to it.
    let qualifier = dialect.quote_ident(table_name);

    // Projection (columns, relationship subqueries, __typename) + delegated fields. Built
    // first, so its subquery parameters number before the WHERE's.
    let (select_exprs, projection, delegations) = compile_selection(
        &field.selection_set.node.items,
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
            return Err(CompileError::UnknownField(field_name.to_string()));
        }
        for pk in &table.primary_key {
            let arg = field
                .arguments
                .iter()
                .find(|(name, _)| name.node.as_str() == pk)
                .ok_or_else(|| CompileError::UnknownField(format!("{table_name}_by_pk.{pk}")))?;
            let value = resolve_value(&arg.1.node, variables)?;
            let col = format!("{qualifier}.{}", dialect.quote_ident(pk));
            let ph = cx.bind(value);
            clauses.push(format!("{col} = {ph}"));
        }
    } else if let Some((_, where_arg)) = field.arguments.iter().find(|(n, _)| n.node == "where") {
        if let Some(expr) = compile_bool_exp(&where_arg.node, table, &qualifier, policy, &mut cx)? {
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
        if let Some((_, limit)) = field.arguments.iter().find(|(n, _)| n.node == "limit") {
            let ph = cx.bind(resolve_value(&limit.node, variables)?);
            sql.push_str(&format!(" LIMIT {ph}"));
        }
        if let Some((_, offset)) = field.arguments.iter().find(|(n, _)| n.node == "offset") {
            let ph = cx.bind(resolve_value(&offset.node, variables)?);
            sql.push_str(&format!(" OFFSET {ph}"));
        }
    }

    Ok(RootQuery {
        response_key,
        sql,
        params: cx.params,
        single,
        projection,
        delegations,
    })
}

/// Compile a selection set on `table` (referenced by `qualifier`) into the `SELECT`
/// expression list, the output projection, and any delegated fields. A scalar field is a
/// qualified column; a relationship field is a correlated JSON subquery; a delegated field
/// is resolved by a wasm function after the query; `__typename` is a constant.
fn compile_selection(
    items: &[Positioned<Selection>],
    table: &Table,
    qualifier: &str,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    cx: &mut Cx<'_>,
) -> Result<CompiledSelection, CompileError> {
    let relationships = schema.relationships(&table.name);
    let mut exprs = Vec::new();
    let mut projection = Vec::new();
    let mut delegations = Vec::new();
    // Columns already in `exprs`, so a delegation can reuse a selected key column.
    let mut column_index: BTreeMap<String, usize> = BTreeMap::new();
    for sel in items {
        let Selection::Field(f) = &sel.node else {
            return Err(CompileError::Unsupported("fragments in a selection".into()));
        };
        let f = &f.node;
        let f_name = f.name.node.as_str();
        let key = field_response_key(f);
        if f_name == "__typename" {
            projection.push(OutField {
                key,
                source: OutSource::Typename(table.name.clone()),
            });
            continue;
        }
        if let Some(rel) = relationships.iter().find(|r| r.field == f_name) {
            if f.selection_set.node.items.is_empty() {
                return Err(CompileError::UnknownField(format!(
                    "{}.{f_name}",
                    table.name
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
        // A field resolved by a wasm function (the config allowlist), not a column.
        if let Some(function) = policy.delegated(&table.name, f_name) {
            delegations.push(compile_delegation(
                f,
                function,
                table,
                qualifier,
                &mut exprs,
                &mut column_index,
                cx,
            )?);
            continue;
        }
        // A scalar column.
        if !f.selection_set.node.items.is_empty()
            || table.column(f_name).is_none()
            || !policy.is_column_exposed(&table.name, f_name)
        {
            return Err(CompileError::UnknownField(format!(
                "{}.{f_name}",
                table.name
            )));
        }
        let idx = ensure_column(f_name, qualifier, &mut exprs, &mut column_index, cx);
        projection.push(OutField {
            key,
            source: OutSource::Column(idx),
        });
    }
    Ok((exprs, projection, delegations))
}

/// Ensure `column` is selected (reusing an existing select expression), returning its index.
fn ensure_column(
    column: &str,
    qualifier: &str,
    exprs: &mut Vec<String>,
    column_index: &mut BTreeMap<String, usize>,
    cx: &Cx<'_>,
) -> usize {
    if let Some(idx) = column_index.get(column) {
        return *idx;
    }
    let idx = exprs.len();
    exprs.push(format!("{qualifier}.{}", cx.dialect.quote_ident(column)));
    column_index.insert(column.to_string(), idx);
    idx
}

/// Plan a delegated field: ensure the entity key columns are selected (so the runner can
/// build one representation per row), and build the `_entities` query the function receives.
fn compile_delegation(
    field: &Field,
    function: &str,
    table: &Table,
    qualifier: &str,
    exprs: &mut Vec<String>,
    column_index: &mut BTreeMap<String, usize>,
    cx: &Cx<'_>,
) -> Result<Delegation, CompileError> {
    let field_name = field.name.node.as_str();
    if field.selection_set.node.items.is_empty() {
        return Err(CompileError::UnknownField(format!(
            "{}.{field_name}",
            table.name
        )));
    }
    if table.primary_key.is_empty() {
        return Err(CompileError::Unsupported(format!(
            "delegated field `{}.{field_name}` needs a primary key to join on",
            table.name
        )));
    }
    let key = table
        .primary_key
        .iter()
        .map(|pk| {
            (
                pk.clone(),
                ensure_column(pk, qualifier, exprs, column_index, cx),
            )
        })
        .collect();
    let inner = serialize_field(field);
    let entities_query = format!(
        "query($representations:[_Any!]!){{ _entities(representations:$representations){{ ... on {} {{ {inner} }} }} }}",
        table.name
    );
    Ok(Delegation {
        response_key: field_response_key(field),
        field: field_name.to_string(),
        function: function.to_string(),
        type_name: table.name.clone(),
        key,
        entities_query,
    })
}

/// Serialize a field (name + nested selection) back to GraphQL text, for the delegated
/// `_entities` query. Only fields are emitted (fragments are not delegated).
fn serialize_field(field: &Field) -> String {
    let mut out = field.name.node.to_string();
    if !field.selection_set.node.items.is_empty() {
        out.push_str(" { ");
        for sel in &field.selection_set.node.items {
            if let Selection::Field(f) = &sel.node {
                out.push_str(&serialize_field(&f.node));
                out.push(' ');
            }
        }
        out.push('}');
    }
    out
}

/// Lower a relationship field to a correlated JSON subquery selecting the target's scalar
/// fields, joined to the outer row and filtered by the target's row policy. The target
/// selection must be scalar-only — a relationship nested beyond one level is rejected.
fn relationship_subquery(
    rel: &Relationship,
    field: &Field,
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
    for sel in &field.selection_set.node.items {
        let Selection::Field(sf) = &sel.node else {
            return Err(CompileError::Unsupported("fragments in a selection".into()));
        };
        let sf = &sf.node;
        let sf_name = sf.name.node.as_str();
        let key = field_response_key(sf);
        if sf_name == "__typename" {
            pairs.push((key, sql_string_literal(&rel.target_table)));
            continue;
        }
        if !sf.selection_set.node.items.is_empty() {
            return Err(CompileError::Unsupported(
                "a relationship nested beyond one level".into(),
            ));
        }
        if target.column(sf_name).is_none() || !policy.is_column_exposed(&rel.target_table, sf_name)
        {
            return Err(CompileError::UnknownField(format!(
                "{}.{sf_name}",
                rel.target_table
            )));
        }
        pairs.push((key, format!("{qalias}.{}", cx.dialect.quote_ident(sf_name))));
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
    value: &Value,
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
    value: &Value,
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

/// A column reference: `qualifier."column"`, or bare `"column"` when `qualifier` is empty
/// (mutations address a single table, so their `WHERE`/`SET` columns are unqualified).
fn qualify(qualifier: &str, column: &str, dialect: &dyn Dialect) -> String {
    if qualifier.is_empty() {
        dialect.quote_ident(column)
    } else {
        format!("{qualifier}.{}", dialect.quote_ident(column))
    }
}

/// Compile a `<Scalar>_comparison_exp` for `qualifier.column` (already exposure-checked).
fn compile_comparison(
    qualifier: &str,
    column: &str,
    value: &Value,
    cx: &mut Cx<'_>,
) -> Result<String, CompileError> {
    let Value::Object(ops) = value else {
        return Err(CompileError::Unsupported(
            "a comparison must be an object".into(),
        ));
    };
    let col = qualify(qualifier, column, cx.dialect);
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
    field: &Field,
    table: &Table,
    qualifier: &str,
    policy: &DataPolicy,
    dialect: &dyn Dialect,
) -> Result<Option<String>, CompileError> {
    let Some((_, arg)) = field.arguments.iter().find(|(n, _)| n.node == "order_by") else {
        return Ok(None);
    };
    let entries: Vec<&Value> = match &arg.node {
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
            let column = column.as_str();
            if table.column(column).is_none() || !policy.is_column_exposed(&table.name, column) {
                return Err(CompileError::UnknownField(format!(
                    "{}.{column}",
                    table.name
                )));
            }
            let direction = match dir {
                Value::Enum(e) if e.as_str() == "asc" => "ASC",
                Value::Enum(e) if e.as_str() == "desc" => "DESC",
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
fn resolve_value(value: &Value, variables: &serde_json::Value) -> Result<SqlValue, CompileError> {
    match value {
        Value::Variable(name) => json_to_sql(
            variables
                .get(name.as_str())
                .unwrap_or(&serde_json::Value::Null),
        ),
        // async-graphql-value unifies integers and floats under one `Number`.
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(SqlValue::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(SqlValue::Real(f))
            } else {
                Err(CompileError::Unsupported("numeric out of range".into()))
            }
        }
        Value::String(s) => Ok(SqlValue::Text(s.clone())),
        Value::Boolean(b) => Ok(SqlValue::Boolean(*b)),
        Value::Null => Ok(SqlValue::Null),
        Value::Enum(e) => Ok(SqlValue::Text(e.as_str().to_string())),
        Value::List(_) | Value::Object(_) | Value::Binary(_) => Err(CompileError::Unsupported(
            "a scalar value was expected".into(),
        )),
    }
}

/// Resolve a value expected to be a list (an inline list, or a variable holding a JSON
/// array) into SQL values.
fn resolve_list(
    value: &Value,
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
        // Exact full SQL: the correlated JSON subquery is embedded inline in the SELECT
        // list of the root query (pins the whole shape, not just the subquery fragment).
        assert_eq!(
            root.sql,
            r#"SELECT "users"."name", (SELECT json_group_array(json_object('id', "t1"."id")) FROM "posts" AS "t1" WHERE "t1"."author_id" = "users"."id") FROM "users""#
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
        // Exact full SQL: a to-one relationship is a single-object correlated subquery.
        assert_eq!(
            root.sql,
            r#"SELECT "posts"."id", (SELECT json_object('name', "t1"."name") FROM "users" AS "t1" WHERE "t1"."id" = "posts"."author_id") FROM "posts""#
        );
    }

    #[test]
    fn a_delegated_field_becomes_a_batched_entities_fetch() {
        let policy = DataPolicy::new().with_table(
            "users",
            TablePolicy::columns(["id", "name"]).with_resolver("reviews", "reviews"),
        );
        let root = compile_one(
            "{ users { name reviews { body } } }",
            &policy,
            &Claims::default(),
        )
        .unwrap();
        assert_eq!(root.delegations.len(), 1);
        let d = &root.delegations[0];
        assert_eq!(d.function, "reviews");
        assert_eq!(d.field, "reviews");
        assert_eq!(d.type_name, "users");
        // Exact delegated `_entities` query dispatched to the subgraph function.
        assert_eq!(
            d.entities_query,
            "query($representations:[_Any!]!){ _entities(representations:$representations){ ... on users { reviews { body } } } }"
        );
        // Exact root SQL: the key column `id` is appended to the SELECT so the runner can
        // build entity representations, even though the client didn't select it; `reviews`
        // is delegated, not SQL-projected.
        assert_eq!(
            root.sql,
            r#"SELECT "users"."name", "users"."id" FROM "users""#
        );
        assert!(!root.projection.iter().any(|f| f.key == "reviews"));
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
    fn mutations_are_not_compiled_by_the_query_path() {
        let vars = serde_json::json!({});
        let err = compile(
            "mutation { insert_users(object: {}) { affected_rows } }",
            &vars,
            &schema(),
            &open_policy(),
            &Claims::default(),
            &super::super::dialect::Sqlite,
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::Unsupported(m) if m.contains("mutation")));
    }

    fn mutate(
        query: &str,
        policy: &DataPolicy,
        claims: &Claims,
    ) -> Result<WriteStatement, CompileError> {
        let vars = serde_json::json!({});
        let mut plan = compile_mutation(
            query,
            &vars,
            &schema(),
            policy,
            claims,
            &super::super::dialect::Sqlite,
        )?;
        Ok(plan.statements.remove(0))
    }

    #[test]
    fn entities_compiles_to_a_keyed_select_ordered_by_representation() {
        let policy = open_policy();
        let vars = serde_json::json!({ "representations": [
            { "__typename": "users", "id": "2" },
            { "__typename": "users", "id": "1" },
        ] });
        let plan = compile_entities(
            "query($representations:[_Any!]!){ _entities(representations:$representations){ ... on users { name } } }",
            &vars,
            &schema(),
            &policy,
            &Claims::default(),
            &super::super::dialect::Sqlite,
        )
        .unwrap();
        // Exact full SQL: only `name` was asked, but the key column `id` is selected (for
        // the runner to join representations back) and filtered by the keyed `IN` list.
        assert_eq!(
            plan.sql,
            r#"SELECT "users"."name", "users"."id" FROM "users" WHERE "users"."id" IN (?1, ?2)"#
        );
        assert_eq!(
            plan.params,
            vec![SqlValue::Text("2".into()), SqlValue::Text("1".into())]
        );
        // Representation order is preserved (2 before 1) for the runner to join back by.
        assert_eq!(
            plan.representation_keys,
            vec![
                vec![SqlValue::Text("2".into())],
                vec![SqlValue::Text("1".into())]
            ]
        );
        assert!(is_entities_query(
            "{ _entities(representations: []) { __typename } }"
        ));
        assert!(!is_entities_query("{ users { id } }"));
    }

    #[test]
    fn is_mutation_distinguishes_operations() {
        assert!(is_mutation(
            "mutation { insert_users(object: {}) { affected_rows } }"
        ));
        assert!(!is_mutation("{ users { id } }"));
        assert!(!is_mutation("query Q { users { id } }"));
    }

    #[test]
    fn insert_compiles_to_a_parameterized_insert() {
        let stmt = mutate(
            r#"mutation { insert_users(object: {id: "1", name: "Alice"}) { affected_rows } }"#,
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        // BTreeMap sorts the object keys: id before name.
        assert_eq!(
            stmt.sql,
            r#"INSERT INTO "users" ("id", "name") VALUES (?1, ?2)"#
        );
        assert_eq!(
            stmt.params,
            vec![SqlValue::Text("1".into()), SqlValue::Text("Alice".into())]
        );
    }

    #[test]
    fn insert_forces_the_row_filter_column_to_the_claim() {
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
        let claims = BTreeMap::from([("tenant".to_string(), SqlValue::Text("acme".into()))]);
        let stmt = mutate(
            r#"mutation { insert_users(object: {id: "1", name: "Alice"}) { affected_rows } }"#,
            &policy,
            &Claims::new(claims),
        )
        .unwrap();
        assert_eq!(
            stmt.sql,
            r#"INSERT INTO "users" ("id", "name", "tenant_id") VALUES (?1, ?2, ?3)"#
        );
        assert_eq!(stmt.params[2], SqlValue::Text("acme".into()));
    }

    #[test]
    fn update_combines_set_where_and_row_filter() {
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
        let claims = BTreeMap::from([("tenant".to_string(), SqlValue::Text("acme".into()))]);
        let stmt = mutate(
            r#"mutation { update_users(where: {id: {_eq: "1"}}, _set: {name: "Bob"}) { affected_rows } }"#,
            &policy,
            &Claims::new(claims),
        )
        .unwrap();
        // SET binds first, then the WHERE (client predicate, then the forced tenant filter).
        assert_eq!(
            stmt.sql,
            r#"UPDATE "users" SET "name" = ?1 WHERE "id" = ?2 AND "tenant_id" = ?3"#
        );
    }

    #[test]
    fn an_unbounded_delete_is_refused() {
        let err = mutate(
            "mutation { delete_users { affected_rows } }",
            &open_policy(),
            &Claims::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::Unsupported(m) if m.contains("where")));
    }

    #[test]
    fn an_unexposed_insert_column_is_rejected() {
        let err = mutate(
            r#"mutation { insert_users(object: {tenant_id: "x"}) { affected_rows } }"#,
            &open_policy(),
            &Claims::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::UnknownField(f) if f == "users.tenant_id"));
    }

    #[test]
    fn a_bounded_delete_compiles_to_a_parameterized_delete() {
        let stmt = mutate(
            r#"mutation { delete_users(where: {id: {_eq: "9"}}) { affected_rows } }"#,
            &open_policy(),
            &Claims::default(),
        )
        .unwrap();
        assert_eq!(stmt.sql, r#"DELETE FROM "users" WHERE "id" = ?1"#);
        assert_eq!(stmt.params, vec![SqlValue::Text("9".into())]);
    }
}
