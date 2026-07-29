//! The in-`serve` HTTP MCP endpoint (`/mcp`).
//!
//! Mounts rmcp's streamable-http tower service behind a valid-token gate, backed by
//! a [`LocalControlPlane`] that dispatches each tool's request IN-PROCESS through
//! this node's own `/api/*` router, carrying the caller's forwarded bearer. So
//! authorization re-runs through the one real authz path with the caller's own
//! authority — nothing is minted (works on verify-only nodes), and there is no
//! network hop. A `cnf`/DPoP token can't be re-proven on the synthetic request, so
//! `/mcp` is a plain-bearer surface (a `cnf` token's tool calls fail the PoP check).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use boatramp_mcp::{Backend, BoatrampMcp, ControlPlane, SingleBackend};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use tower::ServiceExt;

use crate::auth::Auth;

/// The largest control-plane response we buffer from an in-process call (the API
/// returns small JSON; this is a generous ceiling).
const MAX_BODY: usize = 16 * 1024 * 1024;

/// A control plane that dispatches in-process to this node's own `/api/*` router,
/// authorizing each call with the caller's forwarded bearer.
struct LocalControlPlane {
    router: Router,
}

#[async_trait::async_trait]
impl ControlPlane for LocalControlPlane {
    fn name(&self) -> &str {
        "local"
    }

    fn base_url(&self) -> &str {
        "in-process"
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> boatramp_mcp::Result<serde_json::Value> {
        let mut builder = axum::http::Request::builder()
            .method(method.as_str())
            .uri(path)
            .header(header::ACCEPT, "application/json");
        // Forward the caller's bearer so the synthetic request re-authorizes as them.
        if let Some(bearer) = boatramp_mcp::caller_bearer() {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let bytes = match body {
            Some(v) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                serde_json::to_vec(v)?
            }
            None => Vec::new(),
        };
        let request = builder
            .body(Body::from(bytes))
            .map_err(|e| boatramp_mcp::Error::Invalid(e.to_string()))?;
        // In-memory dispatch through the real router (no socket); it is Infallible.
        let resp = self
            .router
            .clone()
            .oneshot(request)
            .await
            .map_err(|e| boatramp_mcp::Error::Invalid(e.to_string()))?;
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), MAX_BODY)
            .await
            .map_err(|e| boatramp_mcp::Error::Invalid(e.to_string()))?;
        let text = String::from_utf8_lossy(&body).into_owned();
        if !status.is_success() {
            return Err(boatramp_mcp::Error::Api {
                status: status.as_u16(),
                message: if text.is_empty() {
                    status.canonical_reason().unwrap_or("error").to_string()
                } else {
                    text
                },
            });
        }
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)))
    }
}

/// Build the `/mcp` router: rmcp's streamable-http service over this node's own
/// control plane, gated on a valid token. `api_router` is the fully built,
/// auth-layered `/api/*` router the tools dispatch into.
pub(crate) fn mcp_router(api_router: Router, auth: Auth) -> Router {
    let local = LocalControlPlane { router: api_router };
    let backend: Arc<dyn Backend> = Arc::new(SingleBackend::new(Arc::new(local)));
    let mcp = BoatrampMcp::new(backend);
    let service = StreamableHttpService::new(
        move || Ok(mcp.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    Router::new()
        .route_service("/mcp", service)
        .route_layer(axum::middleware::from_fn_with_state(
            auth,
            require_valid_token,
        ))
}

/// Channel gate for `/mcp`: require a present, cryptographically VALID bearer (not
/// a specific right — each tool is separately authorized by the forwarded bearer
/// against `/api/*`, so a scoped token opens the channel and is bounded per call).
async fn require_valid_token(State(auth): State<Auth>, request: Request, next: Next) -> Response {
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    match bearer {
        Some(b) if auth.verify_bearer(&b).await => next.run(request).await,
        Some(_) => (StatusCode::UNAUTHORIZED, "invalid bearer token\n").into_response(),
        None => (StatusCode::UNAUTHORIZED, "missing bearer token\n").into_response(),
    }
}
