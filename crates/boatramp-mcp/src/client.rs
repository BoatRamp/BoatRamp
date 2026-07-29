//! The control-plane the MCP tools call. [`ControlPlane`] is the trait the tools
//! use (a small JSON `get`/`post`/`put`/`delete` surface); it has two impls:
//!  - [`HttpControlPlane`] — a real HTTP client to a remote instance, with the
//!    same auth the `boatramp` CLI uses (bearer token, optional per-request
//!    DPoP/PoP proof for `cnf` tokens, optional RFC 7250 raw-public-key pinning).
//!    This backs the stdio transport (which can drive many named instances).
//!  - a `LocalControlPlane` (in `boatramp-server`) that dispatches in-process to
//!    the serving node's own router with the caller's forwarded bearer. This backs
//!    the in-`serve` HTTP `/mcp` endpoint.

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::cose::{self, LocalSigner, PopClaims};
use boatramp_core::time::now_unix;

use crate::config::{resolve_secret, InstanceConfig};
use crate::error::{Error, Result};

tokio::task_local! {
    /// The caller's forwarded bearer for the current HTTP `/mcp` tool dispatch. The
    /// manual `call_tool` sets it (from the request's `Authorization` header) around
    /// the tool's execution; a `LocalControlPlane` reads it to authorize its
    /// in-process call with the caller's own authority. Absent on the stdio
    /// transport (where each `HttpControlPlane` carries its own token).
    pub static CALLER_BEARER: Option<String>;
}

/// Read the caller's forwarded bearer for the current tool dispatch, if any.
pub fn caller_bearer() -> Option<String> {
    CALLER_BEARER.try_with(Clone::clone).ok().flatten()
}

/// A control-plane the MCP tools issue requests against. Implementors carry their
/// own authentication; the tools only build `(method, path, body)`.
#[async_trait::async_trait]
pub trait ControlPlane: Send + Sync {
    /// Send a request to `path` (a leading-slash control-plane path) with an
    /// optional JSON body, returning the parsed JSON response. A non-2xx status is
    /// an [`Error::Api`] carrying the body; an empty 2xx body yields `null`.
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value>;

    /// This instance's display name.
    fn name(&self) -> &str;

    /// This instance's base URL.
    fn base_url(&self) -> &str;

    /// `GET path` → JSON.
    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        self.call(reqwest::Method::GET, path, None).await
    }
    /// `POST path` with an optional JSON body → JSON.
    async fn post(
        &self,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.call(reqwest::Method::POST, path, body).await
    }
    /// `PUT path` with a JSON body → JSON.
    async fn put(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        self.call(reqwest::Method::PUT, path, Some(body)).await
    }
    /// `DELETE path` → JSON.
    async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        self.call(reqwest::Method::DELETE, path, None).await
    }
}

/// An HTTP control-plane connection: an authenticated `reqwest` client bound to one
/// instance's base URL. Cloneable and cheap (an `Arc` inside `reqwest::Client`).
#[derive(Clone)]
pub struct HttpControlPlane {
    inner: reqwest::Client,
    pop: Option<Arc<PopSigner>>,
    base: String,
    name: String,
}

impl HttpControlPlane {
    /// Build a connection from an [`InstanceConfig`], resolving its token/holder
    /// secret specs. Fails if a named secret can't be resolved or TLS pinning is
    /// misconfigured.
    pub fn from_instance(inst: &InstanceConfig) -> Result<Self> {
        let token = resolve_secret(&inst.token)?;
        let holder = match &inst.holder_key {
            Some(spec) => resolve_secret(spec)?,
            None => None,
        };
        let mut builder = reqwest::Client::builder();
        if let Some(token) = &token {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(reqwest::header::AUTHORIZATION, value);
                builder = builder.default_headers(headers);
            }
        }
        if inst.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(hex) = inst.server_pubkey.as_deref() {
            // Pin the single logical control-plane peer (id 0) to its raw public key.
            if let Ok(spki) = boatramp_rpktls::parse_public_key(hex.trim()) {
                let trust = boatramp_rpktls::TrustSet::from_map(BTreeMap::from([(0u64, spki)]));
                if let Ok(config) = boatramp_rpktls::client_config_server_auth(trust, 0) {
                    builder = builder.use_preconfigured_tls(config);
                }
            } else {
                return Err(Error::Config(format!(
                    "instance '{}': malformed server_pubkey",
                    inst.name
                )));
            }
        }
        let inner = builder.build()?;
        // PoP signing turns on only with both a token and a parseable holder key.
        let pop =
            match (&token, &holder) {
                (Some(token), Some(holder)) => LocalSigner::from_private_hex(holder.trim())
                    .ok()
                    .map(|holder| {
                        Arc::new(PopSigner {
                            holder,
                            token: token.clone(),
                            origin: inst.server.trim_end_matches('/').to_string(),
                        })
                    }),
                _ => None,
            };
        Ok(Self {
            inner,
            pop,
            base: inst.server.trim_end_matches('/').to_string(),
            name: inst.name.clone(),
        })
    }
}

#[async_trait::async_trait]
impl ControlPlane for HttpControlPlane {
    fn name(&self) -> &str {
        &self.name
    }

    fn base_url(&self) -> &str {
        &self.base
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.inner.request(method, url);
        if let Some(body) = body {
            req = req.json(body);
        }
        let mut request = req.build()?;
        if let Some(pop) = &self.pop {
            pop.sign(&mut request).await;
        }
        let resp = self.inner.execute(request).await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(Error::Api {
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
        // Prefer structured JSON, but fall back to a string for text/plain bodies.
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)))
    }
}

/// Holds a token's holder (`cnf`) private key + the bound origin, signing a fresh
/// [`PopClaims`] proof per request into the `Boatramp-PoP` header — mirroring the
/// CLI's `PopSigner` so the server's DPoP check is satisfied identically.
struct PopSigner {
    holder: LocalSigner,
    token: String,
    origin: String,
}

impl PopSigner {
    /// Attach a per-request PoP proof (best-effort: a signing failure sends the
    /// request unsigned, which the server then rejects — never a silent bypass).
    async fn sign(&self, request: &mut reqwest::Request) {
        let bh = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .filter(|b| !b.is_empty() && b.len() <= cose::POP_MAX_BODY_HASH_BYTES)
            .map(cose::pop_sha256_hex);
        let claims = PopClaims {
            htm: request.method().as_str().to_string(),
            htp: cose::canon_pop_path(request.url().path()),
            aud: self.origin.clone(),
            ath: cose::pop_sha256_hex(self.token.as_bytes()),
            bh,
        };
        let Ok(proof) = cose::mint_pop(&claims, &self.holder, now_unix()).await else {
            return;
        };
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&proof) {
            request.headers_mut().insert(
                reqwest::header::HeaderName::from_static("boatramp-pop"),
                value,
            );
        }
    }
}
