//! Executing a compiled query against a SQL backend and shaping the rows into GraphQL JSON.
//!
//! This runs the [`compile`](super::compile) output: for each root field, run its one
//! parameterized `SELECT` on a **read-only** transaction and turn the returned rows into the
//! GraphQL response object. A compile or SQL error becomes a GraphQL error envelope — never a
//! partial result. The connector remains a translator: the database executes, this maps
//! rows to JSON.

use super::compile::{compile, OutSource, RootQuery};
use super::dialect::Dialect;
use super::policy::{Claims, DataPolicy};
use super::schema::DbSchema;
use boatramp_core::sql::{SqlBackend, SqlRows, SqlValue};
use serde_json::{json, Map, Value};

/// Execute `query` (with its `variables`) against `backend`, returning a GraphQL response
/// (`{"data": …}` on success, `{"errors": …}` on a compile or SQL failure).
pub(crate) async fn execute(
    backend: &dyn SqlBackend,
    dialect: &dyn Dialect,
    schema: &DbSchema,
    policy: &DataPolicy,
    claims: &Claims,
    query: &str,
    variables: &Value,
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
        match tx.query(&root.sql, &root.params).await {
            Ok(rows) => {
                data.insert(root.response_key.clone(), shape_rows(root, &rows));
            }
            Err(err) => {
                let _ = tx.rollback().await;
                return errors(&format!("query failed: {err}"));
            }
        }
    }
    let _ = tx.rollback().await; // read-only: nothing to commit
    json!({ "data": data })
}

/// Shape a root field's returned rows into its GraphQL value: an array for a list field, the
/// first object (or null) for a `_by_pk` field.
fn shape_rows(root: &RootQuery, rows: &SqlRows) -> Value {
    let objects: Vec<Value> = rows
        .rows
        .iter()
        .map(|row| {
            let mut obj = Map::new();
            for field in &root.projection {
                let value = match &field.source {
                    OutSource::Column(idx) => row.get(*idx).map_or(Value::Null, sql_to_json),
                    OutSource::Json(idx) => row.get(*idx).map_or(Value::Null, json_cell),
                    OutSource::Typename(name) => json!(name),
                };
                obj.insert(field.key.clone(), value);
            }
            Value::Object(obj)
        })
        .collect();
    if root.single {
        objects.into_iter().next().unwrap_or(Value::Null)
    } else {
        Value::Array(objects)
    }
}

/// Map a SQL cell to JSON. A blob becomes a base64 string (GraphQL has no bytes scalar).
fn sql_to_json(value: &SqlValue) -> Value {
    match value {
        SqlValue::Null => Value::Null,
        SqlValue::Boolean(b) => json!(b),
        SqlValue::Integer(i) => json!(i),
        SqlValue::Real(f) => json!(f),
        SqlValue::Text(s) => json!(s),
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
        )
        .await;
        assert_eq!(out["data"]["users"][0]["name"], json!("Alice"));
        assert_eq!(out["data"]["users"][1]["name"], Value::Null);
        assert_eq!(out["data"]["users"].as_array().unwrap().len(), 2);
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
        )
        .await;
        assert!(out["data"].is_null());
        assert!(out["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("secret"));
    }
}
