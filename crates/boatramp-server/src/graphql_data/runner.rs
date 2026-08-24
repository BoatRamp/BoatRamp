//! Executing a compiled query against a SQL backend and shaping the rows into GraphQL JSON.
//!
//! This runs the [`compile`](super::compile) output: for each root field, run its one
//! parameterized `SELECT` on a **read-only** transaction and turn the returned rows into the
//! GraphQL response object. A compile or SQL error becomes a GraphQL error envelope — never a
//! partial result. The connector remains a translator: the database executes, this maps
//! rows to JSON.

use super::compile::{compile, Delegation, OutField, OutSource};
use super::dialect::Dialect;
use super::policy::{Claims, DataPolicy};
use super::schema::DbSchema;
use boatramp_core::sql::{SqlBackend, SqlRows, SqlValue};
use boatramp_handlers::{InvokeRequest, Invoker};
use serde_json::{json, Map, Value};

/// Execute `query` (with its `variables`) against `backend`, returning a GraphQL response
/// (`{"data": …}` on success, `{"errors": …}` on a compile or SQL failure). `invoker`
/// resolves delegated fields (a wasm function per the policy); a query that delegates
/// without one configured is an error. `bearer` is the caller's verified token, forwarded to
/// a delegated function so its own per-field authorization sees the same principal.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute(
    backend: &dyn SqlBackend,
    dialect: &dyn Dialect,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    query: &str,
    variables: &Value,
    invoker: Option<&dyn Invoker>,
    bearer: Option<&str>,
    depth: u32,
) -> Value {
    let planned = match compile(query, variables, schema, policy, claims, dialect) {
        Ok(planned) => planned,
        Err(err) => return errors(&err.to_string()),
    };
    let mut tx = match backend.begin_read_only().await {
        Ok(tx) => tx,
        Err(err) => return errors(&format!("database unavailable: {err}")),
    };
    let mut data = Map::new();
    for root in &planned.roots {
        let rows = match tx.query(&root.sql, &root.params).await {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return errors(&format!("query failed: {err}"));
            }
        };
        let mut objects = shape_objects(&root.projection, &rows);
        for delegation in &root.delegations {
            if let Err(message) =
                apply_delegation(&mut objects, &rows, delegation, invoker, bearer, depth).await
            {
                let _ = tx.rollback().await;
                return errors(&message);
            }
        }
        let value = if root.single {
            objects.into_iter().next().unwrap_or(Value::Null)
        } else {
            Value::Array(objects)
        };
        data.insert(root.response_key.clone(), value);
    }
    let _ = tx.rollback().await; // read-only: nothing to commit
    json!({ "data": data })
}

/// Execute a **mutation**: compile it to writes and run them in one transaction (commit on
/// success, roll back on any failure). Each write returns `{ affected_rows }` under its
/// response key. `{"errors": …}` on a compile or SQL failure — never a partial write.
pub(crate) async fn execute_mutation(
    backend: &dyn SqlBackend,
    dialect: &dyn Dialect,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    query: &str,
    variables: &Value,
) -> Value {
    use super::compile::compile_mutation;
    let plan = match compile_mutation(query, variables, schema, policy, claims, dialect) {
        Ok(plan) => plan,
        Err(err) => return errors(&err.to_string()),
    };
    let mut tx = match backend.begin().await {
        Ok(tx) => tx,
        Err(err) => return errors(&format!("database unavailable: {err}")),
    };
    let mut data = Map::new();
    for statement in &plan.statements {
        match tx.execute(&statement.sql, &statement.params).await {
            Ok(affected) => {
                data.insert(
                    statement.response_key.clone(),
                    json!({ "affected_rows": affected }),
                );
            }
            Err(err) => {
                let _ = tx.rollback().await;
                return errors(&format!("mutation failed: {err}"));
            }
        }
    }
    if let Err(err) = tx.commit().await {
        return errors(&format!("commit failed: {err}"));
    }
    json!({ "data": data })
}

/// Resolve a federation `_entities` fetch against `backend`: run the keyed `SELECT`, shape
/// the rows, and join them back to the representations **by key, in representation order**
/// (nulls for keys with no matching row). Returns `{"data": {"_entities": […]}}`. This makes
/// a SQL source a full federation entity resolver, not only a root owner.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_entities(
    backend: &dyn SqlBackend,
    dialect: &dyn Dialect,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    query: &str,
    variables: &Value,
    invoker: Option<&dyn Invoker>,
    bearer: Option<&str>,
    depth: u32,
) -> Value {
    use super::compile::compile_entities;
    let plan = match compile_entities(query, variables, schema, policy, claims, dialect) {
        Ok(plan) => plan,
        Err(err) => return errors(&err.to_string()),
    };
    if plan.representation_keys.is_empty() {
        return json!({ "data": { "_entities": [] } });
    }
    let mut tx = match backend.begin_read_only().await {
        Ok(tx) => tx,
        Err(err) => return errors(&format!("database unavailable: {err}")),
    };
    let rows = match tx.query(&plan.sql, &plan.params).await {
        Ok(rows) => rows,
        Err(err) => {
            let _ = tx.rollback().await;
            return errors(&format!("query failed: {err}"));
        }
    };
    let _ = tx.rollback().await;

    let mut objects = shape_objects(&plan.projection, &rows);
    for delegation in &plan.delegations {
        if let Err(message) =
            apply_delegation(&mut objects, &rows, delegation, invoker, bearer, depth).await
        {
            return errors(&message);
        }
    }
    // Index the resolved rows by their key tuple (as canonical JSON), then emit one entity per
    // representation, preserving order.
    let mut by_key: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for (row, object) in rows.rows.iter().zip(objects) {
        let key: Vec<Value> = plan
            .key_indices
            .iter()
            .map(|i| row.get(*i).map_or(Value::Null, sql_to_json))
            .collect();
        by_key.insert(Value::Array(key).to_string(), object);
    }
    let entities: Vec<Value> = plan
        .representation_keys
        .iter()
        .map(|k| {
            let key: Vec<Value> = k.iter().map(sql_to_json).collect();
            by_key
                .get(&Value::Array(key).to_string())
                .cloned()
                .unwrap_or(Value::Null)
        })
        .collect();
    json!({ "data": { "_entities": entities } })
}

/// Shape each returned row into its base GraphQL object (columns, relationships,
/// `__typename`); delegated fields are filled afterward.
fn shape_objects(projection: &[OutField], rows: &SqlRows) -> Vec<Value> {
    rows.rows
        .iter()
        .map(|row| {
            let mut obj = Map::new();
            for field in projection {
                let value = match &field.source {
                    OutSource::Column(idx) => row.get(*idx).map_or(Value::Null, sql_to_json),
                    OutSource::Json(idx) => row.get(*idx).map_or(Value::Null, json_cell),
                    OutSource::Typename(name) => json!(name),
                };
                obj.insert(field.key.clone(), value);
            }
            Value::Object(obj)
        })
        .collect()
}

/// Fill a delegated field on every row object by a **single** batched invoke to its function
/// (a local `_entities` fetch): build one representation per row from its key, send them, and
/// join the returned entities back by position. No N+1 — one invoke for the whole result set.
async fn apply_delegation(
    objects: &mut [Value],
    rows: &SqlRows,
    delegation: &Delegation,
    invoker: Option<&dyn Invoker>,
    bearer: Option<&str>,
    depth: u32,
) -> Result<(), String> {
    let Some(invoker) = invoker else {
        return Err(format!(
            "field `{}` needs a resolver function, but this server has no invoker configured",
            delegation.response_key
        ));
    };
    // One representation per row: `{ __typename, <key…> }`.
    let representations: Vec<Value> = rows
        .rows
        .iter()
        .map(|row| {
            let mut repr = Map::new();
            repr.insert("__typename".to_string(), json!(delegation.type_name));
            for (name, idx) in &delegation.key {
                repr.insert(name.clone(), row.get(*idx).map_or(Value::Null, sql_to_json));
            }
            Value::Object(repr)
        })
        .collect();

    let body = json!({
        "query": delegation.entities_query,
        "variables": { "representations": representations },
    })
    .to_string()
    .into_bytes();
    // Forward the caller's verified identity so a delegated function that authorizes per field
    // sees the same principal — the same identity propagation the federation gateway does for a
    // function subgraph. `bearer` is the raw token (the scheme was stripped at intake), so
    // re-add it; the callee re-verifies, so this is propagation, not delegation.
    let mut headers = vec![("content-type".to_string(), b"application/json".to_vec())];
    if let Some(token) = bearer {
        headers.push((
            "authorization".to_string(),
            format!("Bearer {token}").into_bytes(),
        ));
    }
    let request = InvokeRequest {
        method: "POST".to_string(),
        path: "/".to_string(),
        headers,
        body,
    };
    let response = invoker
        .invoke(&delegation.function, request, depth)
        .await
        .map_err(|_| {
            format!(
                "resolver function `{}` for `{}` is unavailable",
                delegation.function, delegation.response_key
            )
        })?;
    let parsed: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    let entities = parsed
        .pointer("/data/_entities")
        .or_else(|| parsed.pointer("/_entities"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Join by position (the `_entities` contract preserves representation order).
    for (object, entity) in objects.iter_mut().zip(entities.iter()) {
        let value = entity
            .get(&delegation.field)
            .cloned()
            .unwrap_or(Value::Null);
        if let Value::Object(map) = object {
            map.insert(delegation.response_key.clone(), value);
        }
    }
    Ok(())
}

/// Map a SQL cell to JSON. A blob becomes a base64 string (GraphQL has no bytes scalar).
fn sql_to_json(value: &SqlValue) -> Value {
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Boolean(b) => json!(b),
        SqlValue::Integer(i) => json!(i),
        SqlValue::Real(f) => json!(f),
        SqlValue::Text(s) => json!(s),
        // A JSON cell surfaces as its parsed value (real nested JSON), falling back to the
        // raw text if it somehow doesn't parse.
        SqlValue::Json(s) => serde_json::from_str(s).unwrap_or_else(|_| json!(s)),
        SqlValue::Blob(bytes) => {
            use base64::Engine;
            json!(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
    }
}

/// Parse a relationship cell (JSON text from a subquery) into its nested value: an object
/// for a to-one, an array for a to-many, or null when the to-one had no match.
fn json_cell(value: &SqlValue) -> Value {
    match value {
        SqlValue::Text(text) => serde_json::from_str(text).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}

/// A GraphQL error envelope.
fn errors(message: &str) -> Value {
    json!({ "errors": [ { "message": message } ] })
}

#[cfg(test)]
mod tests {
    use super::super::policy::{DataPolicy, TablePolicy};
    use super::super::schema::{Column, DbSchema, ScalarType, Table};
    use super::*;
    use async_trait::async_trait;
    use boatramp_core::sql::{SqlError, SqlTransaction};

    /// A fake backend returning a fixed result set for any query — enough to exercise
    /// shaping + response assembly without a real database.
    struct FakeBackend(SqlRows);

    #[async_trait]
    impl SqlBackend for FakeBackend {
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            Ok(Box::new(FakeTx(self.0.clone())))
        }
    }

    struct FakeTx(SqlRows);

    #[async_trait]
    impl SqlTransaction for FakeTx {
        async fn query(&mut self, _sql: &str, _params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            Ok(self.0.clone())
        }
        async fn execute(&mut self, _sql: &str, _params: &[SqlValue]) -> Result<u64, SqlError> {
            Ok(0)
        }
        async fn commit(self: Box<Self>) -> Result<(), SqlError> {
            Ok(())
        }
        async fn rollback(self: Box<Self>) -> Result<(), SqlError> {
            Ok(())
        }
    }

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
                ],
                primary_key: vec!["id".into()],
                foreign_keys: vec![],
            }],
        }
    }

    fn policy() -> DataPolicy {
        DataPolicy::new().with_table("users", TablePolicy::columns(["id", "name"]))
    }

    #[tokio::test]
    async fn a_list_query_shapes_rows_into_a_json_array() {
        let rows = SqlRows {
            columns: vec!["id".into(), "name".into()],
            rows: vec![
                vec![SqlValue::Text("1".into()), SqlValue::Text("Alice".into())],
                vec![SqlValue::Text("2".into()), SqlValue::Null],
            ],
        };
        let backend = FakeBackend(rows);
        let out = execute(
            &backend,
            &super::super::dialect::Sqlite,
            &schema(),
            &policy(),
            &Claims::default(),
            "{ users { id name } }",
            &json!({}),
            None,
            None,
            0,
        )
        .await;
        assert_eq!(out["data"]["users"][0]["name"], json!("Alice"));
        assert_eq!(out["data"]["users"][1]["name"], Value::Null);
        assert_eq!(out["data"]["users"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn entities_are_joined_by_key_in_representation_order() {
        // The keyed SELECT compiles to `SELECT "users"."name", "users"."id" …`, so the row
        // is [name, id]; the fake returns Alice(1) and Bob(2) in that order.
        let backend = FakeBackend(SqlRows {
            columns: vec!["name".into(), "id".into()],
            rows: vec![
                vec![SqlValue::Text("Alice".into()), SqlValue::Text("1".into())],
                vec![SqlValue::Text("Bob".into()), SqlValue::Text("2".into())],
            ],
        });
        // Representations are in the order 2 then 1 — the output must follow.
        let variables = json!({ "representations": [
            { "__typename": "users", "id": "2" },
            { "__typename": "users", "id": "1" },
        ] });
        let out = execute_entities(
            &backend,
            &super::super::dialect::Sqlite,
            &schema(),
            &policy(),
            &Claims::default(),
            "query($representations:[_Any!]!){ _entities(representations:$representations){ ... on users { name } } }",
            &variables,
            None,
            None,
            0,
        )
        .await;
        let entities = out["data"]["_entities"]
            .as_array()
            .expect("_entities array");
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0]["name"], json!("Bob")); // representation id 2 → Bob
        assert_eq!(entities[1]["name"], json!("Alice")); // representation id 1 → Alice
    }

    #[tokio::test]
    async fn a_by_pk_query_returns_the_first_object_or_null() {
        let backend = FakeBackend(SqlRows {
            columns: vec!["name".into()],
            rows: vec![vec![SqlValue::Text("Alice".into())]],
        });
        let out = execute(
            &backend,
            &super::super::dialect::Sqlite,
            &schema(),
            &policy(),
            &Claims::default(),
            r#"{ users_by_pk(id: "1") { name } }"#,
            &json!({}),
            None,
            None,
            0,
        )
        .await;
        assert_eq!(out["data"]["users_by_pk"]["name"], json!("Alice"));
        assert!(out["data"]["users_by_pk"].is_object());
    }

    #[tokio::test]
    async fn a_compile_error_is_a_graphql_error_envelope() {
        let backend = FakeBackend(SqlRows::default());
        let out = execute(
            &backend,
            &super::super::dialect::Sqlite,
            &schema(),
            &policy(),
            &Claims::default(),
            "{ users { secret } }", // unexposed column
            &json!({}),
            None,
            None,
            0,
        )
        .await;
        assert!(out["data"].is_null());
        assert!(out["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("secret"));
    }

    /// An invoker that reflects the `Authorization` header it received into the resolved
    /// entity field — so a test can prove a delegated field forwards the caller's identity
    /// (and sends none when the caller is anonymous), like the federation gateway does.
    struct AuthEchoInvoker;

    #[async_trait]
    impl Invoker for AuthEchoInvoker {
        async fn invoke(
            &self,
            _target: &str,
            request: boatramp_handlers::InvokeRequest,
            _depth: u32,
        ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
            let authz = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_else(|| "anonymous".to_string());
            let body = json!({ "data": { "_entities": [ { "reviews": authz } ] } });
            Ok(boatramp_handlers::InvokeResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&body).unwrap(),
            })
        }
    }

    #[tokio::test]
    async fn a_delegated_field_forwards_the_callers_bearer() {
        let rows = SqlRows {
            columns: vec!["id".into()],
            rows: vec![vec![SqlValue::Text("1".into())]],
        };
        let delegation = Delegation {
            response_key: "reviews".into(),
            field: "reviews".into(),
            function: "reviews".into(),
            type_name: "User".into(),
            key: vec![("id".into(), 0)],
            entities_query:
                "query($r:[_Any!]!){ _entities(representations:$r){ ... on User { reviews } } }"
                    .into(),
        };
        let invoker = AuthEchoInvoker;

        // A verified caller's identity rides the delegated invoke as `Bearer <token>`.
        let mut objects = vec![json!({ "id": "1" })];
        apply_delegation(
            &mut objects,
            &rows,
            &delegation,
            Some(&invoker as &dyn Invoker),
            Some("t-acme"),
            0,
        )
        .await
        .unwrap();
        assert_eq!(objects[0]["reviews"], json!("Bearer t-acme"));

        // An anonymous connector query forwards no bearer — so a delegated function that
        // authorizes per field sees an anonymous caller, exactly as it would at the gateway.
        let mut objects = vec![json!({ "id": "1" })];
        apply_delegation(
            &mut objects,
            &rows,
            &delegation,
            Some(&invoker as &dyn Invoker),
            None,
            0,
        )
        .await
        .unwrap();
        assert_eq!(objects[0]["reviews"], json!("anonymous"));
    }
}
