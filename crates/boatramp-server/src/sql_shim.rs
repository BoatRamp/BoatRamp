//! The compute **sql-shim** (PLAN-compute-bindings, Phase 0).
//!
//! An opaque compute workload (container / micro-VM) cannot import the WASI `sql`
//! host interface a handler uses. This shim gives it the *same* per-tenant-scoped
//! [`SqlBackend`] over a wire protocol: a single per-node HTTP endpoint speaking
//! libsql's **hrana-over-HTTP `/v2/pipeline`** JSON, so an off-the-shelf libsql
//! client in the guest connects with zero boatramp-specific code.
//!
//! ## Isolation
//!
//! Requests authenticate with `Authorization: Bearer <token>`; the token maps to an
//! `Arc<dyn SqlBackend>` **already resolved for exactly one `project/site`** (via the
//! same `SqlBackends::database` call a handler makes). The wire protocol has no
//! "open database" verb — a request can only run statements against the backend its
//! token was registered with — so a workload is structurally incapable of naming
//! another tenant's data, exactly like the WASI handler. The token is boatramp-minted
//! and instance-scoped; the operator's DB credentials never enter the guest.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use boatramp_core::sql::{SqlBackend, SqlValue};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// The shim's token → resolved backend registry, shared with the HTTP handler.
#[derive(Clone, Default)]
pub struct SqlShim {
    registry: Arc<RwLock<HashMap<String, Arc<dyn SqlBackend>>>>,
}

impl SqlShim {
    /// A fresh, empty shim.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a bearer `token` for an already-resolved, tenant-scoped `backend`.
    /// Idempotent: re-registering the same token replaces the mapping.
    pub async fn register(&self, token: String, backend: Arc<dyn SqlBackend>) {
        self.registry.write().await.insert(token, backend);
    }

    /// Drop a token when its workload replica is torn down.
    pub async fn deregister(&self, token: &str) {
        self.registry.write().await.remove(token);
    }

    async fn lookup(&self, token: &str) -> Option<Arc<dyn SqlBackend>> {
        self.registry.read().await.get(token).cloned()
    }

    /// The axum router: `POST /v2/pipeline` (+ `/v3/pipeline`), the hrana-over-HTTP
    /// endpoint. Mount it on a listener bound to the guest-reachable gateway.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/v2/pipeline", post(pipeline))
            .route("/v3/pipeline", post(pipeline))
            .with_state(self.clone())
    }
}

/// Extract the `Authorization: Bearer <token>` value.
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.trim().to_string())
}

// ---- hrana wire types (the `/v2/pipeline` subset) ---------------------------

#[derive(Deserialize)]
struct PipelineReq {
    #[serde(default)]
    requests: Vec<StreamRequest>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StreamRequest {
    Execute {
        stmt: Stmt,
    },
    Close,
    /// Any other hrana request type (`batch`, `store_sql`, …) — unsupported in the
    /// stateless subset; answered with an error result, not a hard failure.
    #[serde(other)]
    Unsupported,
}

#[derive(Deserialize)]
struct Stmt {
    sql: Option<String>,
    #[serde(default)]
    args: Vec<Value>,
    #[serde(default)]
    want_rows: bool,
}

#[derive(Serialize)]
struct PipelineResp {
    baton: Option<String>,
    base_url: Option<String>,
    results: Vec<StreamResult>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StreamResult {
    Ok { response: HranaResponse },
    Error { error: HranaError },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HranaResponse {
    Execute { result: StmtResult },
    Close,
}

#[derive(Serialize)]
struct StmtResult {
    cols: Vec<Col>,
    rows: Vec<Vec<Value>>,
    affected_row_count: u64,
    last_insert_rowid: Option<String>,
}

#[derive(Serialize)]
struct Col {
    name: Option<String>,
    decltype: Option<String>,
}

#[derive(Serialize)]
struct HranaError {
    message: String,
}

/// A hrana value. Integers are strings (JSON can't hold a full i64 exactly);
/// booleans are folded to `0`/`1` (SQLite-family), matching the WASI binding.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Value {
    Null,
    Integer { value: String },
    Float { value: f64 },
    Text { value: String },
    Blob { base64: String },
}

impl Value {
    fn from_sql(v: &SqlValue) -> Self {
        match v {
            SqlValue::Null => Self::Null,
            SqlValue::Boolean(b) => Self::Integer {
                value: (i64::from(*b)).to_string(),
            },
            SqlValue::Integer(i) => Self::Integer {
                value: i.to_string(),
            },
            SqlValue::Real(f) => Self::Float { value: *f },
            SqlValue::Text(s) => Self::Text { value: s.clone() },
            SqlValue::Blob(b) => Self::Blob {
                base64: base64::engine::general_purpose::STANDARD.encode(b),
            },
        }
    }

    fn to_sql(&self) -> Result<SqlValue, String> {
        Ok(match self {
            Self::Null => SqlValue::Null,
            Self::Integer { value } => SqlValue::Integer(
                value
                    .parse()
                    .map_err(|_| "invalid integer arg".to_string())?,
            ),
            Self::Float { value } => SqlValue::Real(*value),
            Self::Text { value } => SqlValue::Text(value.clone()),
            Self::Blob { base64 } => SqlValue::Blob(
                base64::engine::general_purpose::STANDARD
                    .decode(base64)
                    .map_err(|_| "invalid base64 blob arg".to_string())?,
            ),
        })
    }
}

/// `POST /v{2,3}/pipeline`: authenticate the bearer token to a resolved backend,
/// then run each request against it. A statement error is a per-result error, not a
/// transport failure (matching hrana). An unknown/missing token is `401`.
async fn pipeline(
    State(shim): State<SqlShim>,
    headers: HeaderMap,
    Json(req): Json<PipelineReq>,
) -> Response {
    let Some(token) = bearer(&headers) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token\n").into_response();
    };
    let Some(backend) = shim.lookup(&token).await else {
        return (StatusCode::UNAUTHORIZED, "unknown token\n").into_response();
    };

    let mut results = Vec::with_capacity(req.requests.len());
    for request in req.requests {
        let result = match request {
            StreamRequest::Close => StreamResult::Ok {
                response: HranaResponse::Close,
            },
            StreamRequest::Unsupported => StreamResult::Error {
                error: HranaError {
                    message: "unsupported request type in the stateless pipeline".to_string(),
                },
            },
            StreamRequest::Execute { stmt } => match run_stmt(backend.as_ref(), stmt).await {
                Ok(result) => StreamResult::Ok {
                    response: HranaResponse::Execute { result },
                },
                Err(message) => StreamResult::Error {
                    error: HranaError { message },
                },
            },
        };
        results.push(result);
    }

    Json(PipelineResp {
        baton: None,
        base_url: None,
        results,
    })
    .into_response()
}

/// Run one statement in its own implicit transaction. `want_rows` routes to the
/// backend's `query` (return rows) or `execute` (return the affected count) — the
/// two `SqlTransaction` methods.
async fn run_stmt(backend: &dyn SqlBackend, stmt: Stmt) -> Result<StmtResult, String> {
    let sql = stmt.sql.ok_or_else(|| "statement has no sql".to_string())?;
    let params: Vec<SqlValue> = stmt
        .args
        .iter()
        .map(Value::to_sql)
        .collect::<Result<_, _>>()?;

    let mut tx = backend.begin().await.map_err(|e| e.to_string())?;
    if stmt.want_rows {
        let rows = tx.query(&sql, &params).await.map_err(|e| e.to_string());
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => return Err(e),
        };
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(StmtResult {
            cols: rows
                .columns
                .iter()
                .map(|c| Col {
                    name: Some(c.clone()),
                    decltype: None,
                })
                .collect(),
            rows: rows
                .rows
                .iter()
                .map(|row| row.iter().map(Value::from_sql).collect())
                .collect(),
            affected_row_count: 0,
            last_insert_rowid: None,
        })
    } else {
        let affected = match tx.execute(&sql, &params).await.map_err(|e| e.to_string()) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(StmtResult {
            cols: vec![],
            rows: vec![],
            affected_row_count: affected,
            last_insert_rowid: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use boatramp_core::sql::{SqlError, SqlRows, SqlTransaction};
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    /// The statements (sql + decoded params) a fake backend observed.
    type Seen = Arc<Mutex<Vec<(String, Vec<SqlValue>)>>>;

    /// An in-memory backend: `execute` records the (sql, params) it saw and returns a
    /// fixed affected count; `query` returns a fixed 1x1 row. Enough to prove the wire
    /// mapping without a real database.
    #[derive(Default)]
    struct FakeBackend {
        seen: Seen,
    }
    struct FakeTx {
        seen: Seen,
    }

    #[async_trait]
    impl SqlBackend for FakeBackend {
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            Ok(Box::new(FakeTx {
                seen: self.seen.clone(),
            }))
        }
    }

    #[async_trait]
    impl SqlTransaction for FakeTx {
        async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError> {
            self.seen
                .lock()
                .unwrap()
                .push((sql.to_string(), params.to_vec()));
            Ok(SqlRows {
                columns: vec!["n".to_string()],
                rows: vec![vec![SqlValue::Integer(42)]],
            })
        }
        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            self.seen
                .lock()
                .unwrap()
                .push((sql.to_string(), params.to_vec()));
            Ok(7)
        }
        async fn commit(self: Box<Self>) -> Result<(), SqlError> {
            Ok(())
        }
        async fn rollback(self: Box<Self>) -> Result<(), SqlError> {
            Ok(())
        }
    }

    async fn post(
        shim: &SqlShim,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v2/pipeline")
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let req = builder.body(Body::from(body.to_string())).unwrap();
        let resp = shim.router().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn unknown_or_missing_token_is_unauthorized() {
        let shim = SqlShim::new();
        let body = serde_json::json!({ "requests": [{ "type": "close" }] });
        assert_eq!(
            post(&shim, None, body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(&shim, Some("nope"), body).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_registered_token_runs_a_query_and_maps_values() {
        let shim = SqlShim::new();
        let backend = Arc::new(FakeBackend::default());
        shim.register("tok".to_string(), backend.clone()).await;

        // want_rows: true → query → the fake's 1x1 row comes back hrana-encoded.
        let body = serde_json::json!({
            "requests": [
                { "type": "execute", "stmt": {
                    "sql": "SELECT n WHERE x = ?",
                    "args": [{ "type": "text", "value": "hi" }],
                    "want_rows": true }},
                { "type": "close" }
            ]
        });
        let (status, json) = post(&shim, Some("tok"), body).await;
        assert_eq!(status, StatusCode::OK);
        let result = &json["results"][0]["response"]["result"];
        assert_eq!(result["cols"][0]["name"], "n");
        assert_eq!(result["rows"][0][0]["type"], "integer");
        assert_eq!(result["rows"][0][0]["value"], "42");
        assert_eq!(json["results"][1]["type"], "ok"); // close

        // The bound backend saw the statement + the decoded arg.
        let seen = backend.seen.lock().unwrap();
        assert_eq!(seen[0].0, "SELECT n WHERE x = ?");
        assert_eq!(seen[0].1, vec![SqlValue::Text("hi".to_string())]);
    }

    #[tokio::test]
    async fn want_rows_false_routes_to_execute_and_returns_affected() {
        let shim = SqlShim::new();
        shim.register("tok".to_string(), Arc::new(FakeBackend::default()))
            .await;
        let body = serde_json::json!({
            "requests": [
                { "type": "execute", "stmt": { "sql": "INSERT INTO t VALUES (1)", "want_rows": false }}
            ]
        });
        let (status, json) = post(&shim, Some("tok"), body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["results"][0]["response"]["result"]["affected_row_count"],
            7
        );
    }

    #[tokio::test]
    async fn deregister_revokes_access() {
        let shim = SqlShim::new();
        shim.register("tok".to_string(), Arc::new(FakeBackend::default()))
            .await;
        shim.deregister("tok").await;
        let body = serde_json::json!({ "requests": [{ "type": "close" }] });
        assert_eq!(
            post(&shim, Some("tok"), body).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
}
