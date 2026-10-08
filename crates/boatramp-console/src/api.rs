//! The control-plane API client.
//!
//! One thin gloo-net wrapper that injects `Authorization: Bearer <token>` into
//! every request and deserializes responses into `boatramp-types` (so the wire
//! format can't drift from the server). This *is* the whole auth surface — there
//! is no server-side framework half.
//!
//! Errors carry the HTTP status so a caller (the 401 interceptor) can clear the
//! token and route to login; a `403` is surfaced as a scope error (the token is
//! valid but lacks the required `*`/`site:<name>` scope).

use gloo_net::http::{RequestBuilder, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// An API call failure, with enough detail for the UI and the 401 interceptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The request was rejected with `401 Unauthorized` — the token is missing,
    /// invalid, or expired. The auth layer clears the token and routes to login.
    Unauthorized,
    /// `403 Forbidden` — the token is valid but lacks the scope this resource
    /// needs (`*` admin, or `site:<name>`).
    Forbidden,
    /// Any other non-2xx status, with the server's text body (trimmed).
    Status { code: u16, body: String },
    /// The request never completed (network/CORS) or the body failed to decode.
    Transport(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized => f.write_str("unauthorized — sign in again"),
            ApiError::Forbidden => f.write_str("forbidden — your token lacks the required scope"),
            ApiError::Status { code, body } if body.is_empty() => write!(f, "HTTP {code}"),
            ApiError::Status { code, body } => write!(f, "HTTP {code}: {body}"),
            ApiError::Transport(msg) => write!(f, "request failed: {msg}"),
        }
    }
}

impl ApiError {
    /// Whether this error means the session is dead and the UI should re-auth.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, ApiError::Unauthorized)
    }

    /// Whether this is a `404` — used by the observability views to detect a
    /// server built without the `handlers` feature (the metrics / logs / stats
    /// endpoints only exist there) and show a friendly note instead of an error.
    pub fn is_not_found(&self) -> bool {
        matches!(self, ApiError::Status { code: 404, .. })
    }
}

/// A `Result` over [`ApiError`].
pub type ApiResult<T> = Result<T, ApiError>;

/// The project-scoped API path prefixes: when a non-`default` project is active,
/// a request to one of these is rewritten from its bare global form
/// `/api/<family>/…` to the project-qualified form `/api/projects/<proj>/<family>/…`
/// (which the server's `project_scope` layer maps back). Node-global paths
/// (`/api/metrics`, `/api/instance-stats`, `/api/tokens`, `/api/projects` itself,
/// the node-ops endpoints, …) are NOT listed, so they are never rewritten. This
/// list grows as each console stage adds a project-scoped family.
const PROJECT_FAMILIES: &[&str] = &["/api/sites", "/api/functions", "/api/tenancy"];

/// The control-plane API client. Holds the base URL, an optional bearer token,
/// and the active project (whose non-`default` value scopes the family paths);
/// cheap to clone.
#[derive(Clone, PartialEq)]
pub struct ApiClient {
    /// Base URL of the control-plane server, without a trailing slash. Empty for
    /// the same-origin dogfood deploy (requests are then origin-relative).
    base: String,
    /// The bearer token, if signed in.
    token: Option<String>,
    /// The active project; `"default"` (or empty) uses the bare global paths.
    project: String,
}

impl ApiClient {
    /// A client against `base` (trailing slash trimmed; empty = same-origin)
    /// with an optional bearer `token`, scoped to the `default` project.
    pub fn new(base: impl Into<String>, token: Option<String>) -> Self {
        let base = base.into();
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            project: "default".to_string(),
        }
    }

    /// Scope this client to `project` (builder). The `default` project keeps the
    /// bare global paths; any other project qualifies the [`PROJECT_FAMILIES`].
    #[must_use]
    pub fn with_project(mut self, project: impl Into<String>) -> Self {
        self.project = project.into();
        self
    }

    /// Rewrite a request `path` to the project-qualified form when a non-`default`
    /// project is active and `path` is a project-scoped family; otherwise return
    /// it unchanged. `/api/sites/x` → `/api/projects/<proj>/sites/x`.
    fn project_scoped<'a>(&self, path: &'a str) -> std::borrow::Cow<'a, str> {
        if self.project.is_empty() || self.project == "default" {
            return path.into();
        }
        for fam in PROJECT_FAMILIES {
            if let Some(rest) = path.strip_prefix(fam) {
                if rest.is_empty() || rest.starts_with('/') {
                    // Drop the leading "/api", keep "/sites/x", requalify.
                    let after_api = &path[4..];
                    return format!("/api/projects/{}{after_api}", self.project).into();
                }
            }
        }
        path.into()
    }

    /// Build a full URL for `path` (which must start with `/`), applying the
    /// active-project rewrite.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, self.project_scoped(path))
    }

    /// The same project-rewritten absolute URL, for callers that issue a raw
    /// `fetch` outside this client (the SSE log tail, which can't use the typed
    /// methods because `EventSource` can't carry the Bearer). Keeps the log
    /// stream on the same project as every other call.
    #[must_use]
    pub fn abs_url(&self, path: &str) -> String {
        self.url(path)
    }

    /// Attach the bearer header (if any) to a request builder.
    fn authed(&self, req: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(token) => req.header("Authorization", &format!("Bearer {token}")),
            None => req,
        }
    }

    /// `GET path`, deserializing the JSON body into `T`.
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> ApiResult<T> {
        let req = self.authed(RequestBuilder::new(&self.url(path)));
        let resp = send(req).await?;
        decode_json(resp).await
    }

    /// `GET path`, returning the raw text body (e.g. the Prometheus exporter at
    /// `/api/metrics`, which is `text/plain`, not JSON).
    pub async fn get_text(&self, path: &str) -> ApiResult<String> {
        let req = self.authed(RequestBuilder::new(&self.url(path)));
        let resp = send(req).await?;
        resp.text()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))
    }

    /// `PUT path` with a JSON `body`, expecting a 2xx with no body (204).
    pub async fn put_json<B: Serialize>(&self, path: &str, body: &B) -> ApiResult<()> {
        let req = self
            .authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::PUT))
            .json(body)
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        check(req.send().await)?;
        Ok(())
    }

    /// `POST path` with a JSON `body`, deserializing the JSON response into `T`.
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> ApiResult<T> {
        let req = self
            .authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::POST))
            .json(body)
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        let resp = check(req.send().await)?;
        decode_json(resp).await
    }

    /// `POST path` with a JSON `body`, expecting a 2xx with no body (204).
    pub async fn post_no_content_json<B: Serialize>(&self, path: &str, body: &B) -> ApiResult<()> {
        let req = self
            .authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::POST))
            .json(body)
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        check(req.send().await)?;
        Ok(())
    }

    /// `POST path` with no body, deserializing the JSON response into `T`.
    pub async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> ApiResult<T> {
        let req =
            self.authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::POST));
        let resp = send(req).await?;
        decode_json(resp).await
    }

    /// `POST path` with no body, expecting a 2xx with no body (204).
    pub async fn post_no_content(&self, path: &str) -> ApiResult<()> {
        let req =
            self.authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::POST));
        send(req).await?;
        Ok(())
    }

    /// `DELETE path`, expecting a 2xx with no body (204).
    pub async fn delete(&self, path: &str) -> ApiResult<()> {
        let req = self
            .authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::DELETE));
        send(req).await?;
        Ok(())
    }

    /// `POST path` with no body, returning the response as text (the control-plane
    /// KV checkpoint at `/api/kv-checkpoint`, which replies `text/plain`).
    pub async fn post_text(&self, path: &str) -> ApiResult<String> {
        let req =
            self.authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::POST));
        let resp = send(req).await?;
        resp.text()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))
    }

    /// `GET path`, returning the raw response bytes (the control-plane KV export
    /// at `/api/kv-export`, which is an `application/octet-stream` binary dump).
    pub async fn get_bytes(&self, path: &str) -> ApiResult<Vec<u8>> {
        let req = self.authed(RequestBuilder::new(&self.url(path)));
        let resp = send(req).await?;
        resp.binary()
            .await
            .map_err(|err| ApiError::Transport(err.to_string()))
    }

    /// `POST path` with a raw `bytes` body under `content_type`, deserializing
    /// the JSON response into `T` (the control-plane KV import at
    /// `/api/kv-import`, which takes an `application/octet-stream` dump).
    pub async fn post_bytes_json<T: DeserializeOwned>(
        &self,
        path: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> ApiResult<T> {
        let body = js_sys::Uint8Array::from(bytes.as_slice());
        let req = self
            .authed(RequestBuilder::new(&self.url(path)).method(gloo_net::http::Method::POST))
            .header("Content-Type", content_type)
            .body(body)
            .map_err(|err| ApiError::Transport(err.to_string()))?;
        let resp = check(req.send().await)?;
        decode_json(resp).await
    }
}

/// Send a builder (a request with no JSON body) and map the status.
async fn send(req: RequestBuilder) -> ApiResult<Response> {
    check(req.send().await)
}

/// Map a gloo-net send result to a checked [`Response`] or [`ApiError`].
fn check(result: Result<Response, gloo_net::Error>) -> ApiResult<Response> {
    let resp = result.map_err(|err| ApiError::Transport(err.to_string()))?;
    let status = resp.status();
    if (200..300).contains(&status) {
        return Ok(resp);
    }
    Err(match status {
        401 => ApiError::Unauthorized,
        403 => ApiError::Forbidden,
        // The body is left for the (rare) caller that wants it; for the common
        // path we record the status only, since reading the body is async.
        code => ApiError::Status {
            code,
            body: resp.status_text(),
        },
    })
}

/// Decode a checked response's JSON body into `T`.
async fn decode_json<T: DeserializeOwned>(resp: Response) -> ApiResult<T> {
    resp.json::<T>()
        .await
        .map_err(|err| ApiError::Transport(err.to_string()))
}
