//! The **dedicated S3 listener** wiring (PLAN §Endpoint topology — Architect HIGH-4).
//!
//! The local S3 face is served on its OWN listener/port, with its OWN axum [`Router`] — it is NOT the
//! control-plane router, does NOT mount `/api`, and does NOT fall back to `serve_by_host`. Its only
//! auth is SigV4 (verified inside [`super::face`]), so it sits entirely OUTSIDE `require_auth`. This
//! clean boundary is proved by [`s3_router`] having a single catch-all fallback and no other routes
//! (asserted in the tests).
//!
//! [`serve_s3`] / [`serve_s3_listener`] mirror the existing [`serve_plaintext`](crate::serve_plaintext)
//! accept loop (own `TcpListener`, per-connection spawn, bounded drain). [`s3_face_enable_guard`]
//! runs M1's fail-closed multi-node secret check before a caller enables the face.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::any;

use super::config::{Deployment, S3IngressState};
use super::credential::{CredentialError, multi_node_secret_ok};
use super::face::{self, S3Request};

/// Percent-decode a raw query string into `(name, value)` pairs, decoding each key + value ONCE (the
/// SigV4 presigned path re-encodes them). Shared by the face + router. A param with no `=` gets an
/// empty value. Empty query ⇒ no params.
pub fn decoded_query_params(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (
                super::keypath::percent_decode_once(k),
                super::keypath::percent_decode_once(v),
            ),
            None => (super::keypath::percent_decode_once(pair), String::new()),
        })
        .collect()
}

/// **Fail-closed enable guard** (M1 credential model / CRITICAL-1). A caller MUST call this before
/// enabling the local S3 face: it refuses a multi-node deployment that has no explicitly configured,
/// cluster-uniform ingress secret (so credentials remain verifiable on every node). Single-node may
/// auto-generate. Wraps M1's [`multi_node_secret_ok`] with the live deployment flag.
pub fn s3_face_enable_guard(
    deployment: Deployment,
    explicit_secret_configured: bool,
) -> Result<(), CredentialError> {
    multi_node_secret_ok(deployment.is_multi_node(), explicit_secret_configured)
}

/// Build the dedicated S3-face [`Router`]. It has exactly ONE route: a catch-all fallback that
/// reconstructs the raw request + delegates to [`face::handle`]. No `/api`, no `serve_by_host`, no
/// auth middleware — the SigV4 verification inside the handler is the sole auth surface.
pub fn s3_router(state: Arc<S3IngressState>) -> Router {
    Router::new().fallback(any(dispatch)).with_state(state)
}

/// The single dispatch handler: capture the RAW path/query/headers + streaming body, then hand to the
/// engine. Reads `request.uri()` directly (NOT an axum `Path` extractor) so the object key keeps its
/// wire percent-encoding, which SigV4 signs over.
async fn dispatch(State(state): State<Arc<S3IngressState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let uri_path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let method = parts.method.as_str().to_ascii_uppercase();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
        })
        .collect();
    let req = S3Request {
        method,
        uri_path,
        query,
        headers,
        body: Body::new(body),
    };
    face::handle(&state, req, boatramp_core::time::now_unix() as i64).await
}

/// Serve the S3 face on `addr` through the plaintext accept loop (mirrors
/// [`serve_plaintext`](crate::serve_plaintext)). For a browser/UGC deployment the face is normally
/// fronted by the same TLS terminator as the site; a dedicated TLS listener can use
/// [`serve_s3_tls`](serve_s3_tls) instead.
pub async fn serve_s3<S>(
    addr: SocketAddr,
    state: Arc<S3IngressState>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    crate::serve_plaintext(addr, s3_router(state), shutdown).await
}

/// [`serve_s3`] on an already-bound listener (an ephemeral `:0` bind, tests, socket inheritance).
pub async fn serve_s3_listener<S>(
    listener: tokio::net::TcpListener,
    state: Arc<S3IngressState>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    crate::serve_plaintext_listener(listener, s3_router(state), shutdown).await
}

/// Serve the S3 face over TLS on `addr` (dedicated HTTPS listener), mirroring
/// [`serve_tls`](crate::serve_tls).
pub async fn serve_s3_tls<S>(
    addr: SocketAddr,
    tls: crate::ReloadableTls,
    state: Arc<S3IngressState>,
    shutdown: S,
) -> std::io::Result<()>
where
    S: Future<Output = ()> + Send,
{
    crate::serve_tls(addr, tls, s3_router(state), shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_query_params_once() {
        let p = decoded_query_params("partNumber=3&uploadId=ab%2Fcd&flag");
        assert_eq!(p[0], ("partNumber".to_string(), "3".to_string()));
        assert_eq!(p[1], ("uploadId".to_string(), "ab/cd".to_string()));
        assert_eq!(p[2], ("flag".to_string(), String::new()));
        assert!(decoded_query_params("").is_empty());
    }

    #[test]
    fn enable_guard_is_fail_closed_on_multi_node_without_secret() {
        // Single node may auto-generate; multi-node without an explicit secret is refused.
        assert!(s3_face_enable_guard(Deployment::SingleNode, false).is_ok());
        assert!(s3_face_enable_guard(Deployment::MultiNode, true).is_ok());
        assert!(matches!(
            s3_face_enable_guard(Deployment::MultiNode, false),
            Err(CredentialError::MultiNodeSecretRequired)
        ));
    }

    /// LISTENER ISOLATION (Architect HIGH-4): prove the S3 router never reaches the control-plane
    /// router or `serve_by_host`. It is built from ONLY `s3_router` (no `/api` nest, no
    /// `serve_by_host` fallback, no `require_auth` layer) — so a control-plane path like `/api/sites`
    /// is dispatched by the S3 engine (which rejects it as an unauthenticated S3 request), NOT routed
    /// to a control-plane handler. We assert the router responds via the S3 engine for an `/api/...`
    /// path: with no credentials it yields the uniform 403 (or a 405 for a non-S3 method), never a
    /// control-plane response.
    #[tokio::test]
    async fn s3_router_never_reaches_control_plane() {
        use crate::s3_ingress::test_support::MapStorage;
        use axum::body::to_bytes;
        use boatramp_core::cose::{LocalSigner, Signer as _, TokenAlg};
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::MemoryKv;
        use tower::ServiceExt as _; // oneshot

        let pk = LocalSigner::generate(TokenAlg::Es256).public_key();
        let secret = super::super::credential::S3IngressSecret::generate().unwrap();
        let deploy = DeployStore::new(Arc::new(MapStorage::default()), Arc::new(MemoryKv::new()));
        let guard = Arc::new(crate::limits::UploadGuard::new(Default::default()));
        let state = Arc::new(S3IngressState::new(pk, secret, deploy, guard));
        let router = s3_router(state);

        // A control-plane-shaped GET with no S3 credentials. The S3 engine runs its SigV4 auth path
        // first — with no credential it returns the uniform S3 `AccessDenied` 403. It is NEVER handled
        // by a control-plane handler (there is no `/api` route + no `serve_by_host` fallback on this
        // router), so it can never yield a control-plane "list sites" body.
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/sites")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("<Code>AccessDenied</Code>"),
            "S3 engine (not a control-plane handler) produced the response, got: {text}"
        );

        // And an OPTIONS preflight to the same control-plane path (answered pre-auth) never routes to
        // a control-plane handler either: with no configured CORS it is a bare 403, no CORS headers.
        let opt = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/sites")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(opt.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(
            opt.headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "a disallowed origin must never be echoed"
        );

        // A credential-less PUT to a control-plane-shaped path is a uniform 403 (auth refusal), again
        // proving the S3 auth path — not a control-plane route — is in force.
        let resp2 = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/deployments/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), axum::http::StatusCode::FORBIDDEN);
        let body2 = to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body2).contains("<Code>AccessDenied</Code>"));
    }
}
