//! The compute **blob-shim** (PLAN-compute-bindings) — the blob analogue of the
//! [`sql_shim`](crate::sql_shim), symmetric with it end to end.
//!
//! An opaque compute workload (container / micro-VM) cannot import the WASI
//! `wasi:blobstore` host interface a handler uses. This shim gives it the *same*
//! per-site-scoped [`Storage`] namespace over a plain HTTP wire: a single per-node
//! endpoint exposing `PUT`/`GET`/`HEAD`/`DELETE` on `{BLOB_URL}/{container}/{key}`,
//! so an off-the-shelf HTTP client in the guest reads/writes exactly the objects a
//! `wasi:blobstore` handler for the same `(project, site)` sees — objects under
//! `hblob/{project-qualified-site}/{container}/{key}`, the SAME `Storage` backend
//! (`BlobBackends::backend(project)`) the host binding resolves. A handler and a
//! native worker therefore share ONE blob namespace.
//!
//! ## Isolation (mirrors the sql-shim's token→resolved-backend model)
//!
//! Requests authenticate with `Authorization: Bearer <token>`; the token maps to a
//! [`BlobScope`] **already resolved for exactly one `project/site`** (the same
//! `BlobBackends::backend` call + `hblob/{qualified-site}/` prefix a handler gets).
//! The SITE is carried by the TOKEN's stored `site_prefix`, NEVER by a
//! client-supplied or guessable field, so a workload is structurally incapable of
//! naming another tenant's site — exactly like the WASI handler. A
//! `--bind blob:<name>` token is additionally bound to one container (cross-container
//! rejected); a bare `--bind blob` token is site-wide but still confined to the
//! site, and every object key is screened ([`validate_object_key`]) so a
//! path-traversal key can never escape the container prefix. The token is
//! boatramp-minted (HMAC over the per-node secret), instance-scoped, and rotatable
//! (a fresh per-node secret on restart re-derives it); the operator's storage
//! credentials never enter the guest.
//!
//! ## Network posture (listener bind)
//!
//! The listener binds the **host the operator names in `compute.blob_shim_url`** — the compute
//! bridge-gateway IP / loopback that makes it reachable from the guests — via
//! [`crate::shim_bind_addr`], NEVER all interfaces on its own. This is a token-gated DATA plane
//! over the whole `hblob/{site}/` namespace whose per-replica token is injected into an
//! often-untrusted guest env, so it MUST NOT be reachable off-node: operators point
//! `blob_shim_url` at the bridge gateway (or loopback), never a public address. (An explicit
//! `0.0.0.0` in the URL is honored as the operator's own choice.)
//!
//! ## Known limitation (accepted — Security review Finding 8)
//!
//! The site identity is `ProjectRef::qualified(project, workload)`: the `default` project is
//! UNQUALIFIED (`hblob/{workload}/`) while a named project is prefixed (`hblob/{project}/{site}/`).
//! A `default`-project workload NAMED like a real project (e.g. workload `acme/api` is impossible —
//! names carry no `/` — but a workload `acme` under `default` yields `hblob/acme/…`, colliding with
//! project `acme`'s prefix) therefore shares that project's `hblob/` subtree. This is an INHERITED
//! property of the node-wide `hblob/` tenancy scheme (the SAME collision a `wasi:blobstore` handler
//! has), not introduced here; the shim faithfully reuses `qualified` rather than inventing a parallel
//! layout. The proper fix lives in the tenancy scheme (`ProjectRef::qualified`) and is owned
//! separately — a conscious acceptance for this change.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use boatramp_core::blob_backends::BlobBackends;
use boatramp_core::compute::{BindingKind, ComputeBinding, ComputeBindingResolver};
use boatramp_core::project::{ProjectRef, validate_key_segment, validate_object_key};
use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use futures::StreamExt as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// Default per-object PUT ceiling (5 GiB — S3's single-`PutObject` limit) when the operator sets no
/// `compute.blob_shim_max_object_bytes`. Bounds a single write so a compromised/buggy guest cannot
/// exhaust node/bucket storage with one unbounded PUT. `0` (operator-configured) = unlimited.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// A token-resolved blob capability: the site's [`Storage`] backend, the key prefix the
/// token is confined to (`hblob/{project-qualified-site}/` — host-stamped, never
/// client-supplied), and the one container it may touch when the binding named one.
#[derive(Clone)]
struct BlobScope {
    storage: Arc<dyn Storage>,
    /// `hblob/{project-qualified-site}/` — the EXACT per-site prefix a `wasi:blobstore`
    /// handler for this `(project, site)` is confined to (see `with_blobstore`).
    site_prefix: String,
    /// The one container a `--bind blob:<name>` token is bound to, or `None` for a
    /// site-wide `--bind blob` token (which may name any container WITHIN the site).
    container: Option<String>,
}

/// The shim's token → resolved [`BlobScope`] registry, shared with the HTTP handlers.
///
/// The registry is keyed on `SHA-256(salt ∥ token)`, never the raw bearer token, so token
/// ADMISSION (the `HashMap` key compare) is timing-safe: a probe can at most learn a prefix of a
/// preimage-resistant hash of a 256-bit secret token, never the token itself (LOW hardening,
/// Security review — defense-in-depth atop the already-unguessable HMAC token).
#[derive(Clone)]
pub struct BlobShim {
    registry: Arc<RwLock<HashMap<[u8; 32], BlobScope>>>,
    salt: [u8; 32],
    /// Per-object PUT ceiling in bytes (`0` = unlimited); a larger write is refused `413`.
    max_object_bytes: u64,
}

impl Default for BlobShim {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobShim {
    /// A fresh, empty shim with a per-instance random admission salt and the default per-object
    /// PUT ceiling ([`DEFAULT_MAX_OBJECT_BYTES`]).
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        // A failed RNG only weakens the (defense-in-depth) salt to zero — admission stays timing-safe
        // because the key is still a preimage-resistant hash of a 256-bit secret token.
        let _ = getrandom::getrandom(&mut salt);
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            salt,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        }
    }

    /// Set the per-object PUT ceiling (`0` = unlimited). Builder used by [`spawn_blob_shim`].
    pub fn with_max_object_bytes(mut self, max_object_bytes: u64) -> Self {
        self.max_object_bytes = max_object_bytes;
        self
    }

    /// The registry key for a bearer `token`: `SHA-256(salt ∥ token)`.
    fn key(&self, token: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(token.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Register a bearer `token` for an already-resolved, site-scoped `scope`.
    /// Idempotent: re-registering the same token replaces the mapping.
    async fn register(&self, token: &str, scope: BlobScope) {
        let key = self.key(token);
        self.registry.write().await.insert(key, scope);
    }

    /// Drop a token when its workload replica is torn down.
    async fn deregister(&self, token: &str) {
        let key = self.key(token);
        self.registry.write().await.remove(&key);
    }

    /// Resolve a presented bearer `token` to its [`BlobScope`], or `None` for a missing
    /// or unknown/mismatched token (fail-closed authentication — anti-hollow gate case
    /// iii). The `admit_unmatched` mutation seam admits a missing/unknown token to SOME
    /// registered scope — exactly the breach the gate must catch; it is compiled out of
    /// every shipped build.
    async fn authenticate(&self, token: Option<&str>) -> Option<BlobScope> {
        let reg = self.registry.read().await;
        if let Some(t) = token
            && let Some(scope) = reg.get(&self.key(t)).cloned()
        {
            return Some(scope);
        }
        if blob_mutation().as_deref() == Some("admit_unmatched") {
            return reg.values().next().cloned();
        }
        None
    }

    /// The axum router: `{PUT,GET,HEAD,DELETE} /{container}/{*key}`. Mount it on a
    /// node-internal listener (see [`spawn_blob_shim`]).
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/{container}/{*key}",
                get(get_object)
                    .put(put_object)
                    .head(head_object)
                    .delete(delete_object),
            )
            .with_state(self.clone())
    }
}

/// Resolves a workload's `blob` [`ComputeBinding`]s to a shim endpoint + credential
/// injected into the guest env. Holds the same [`BlobBackends`] provider the
/// `wasi:blobstore` host binding uses, the shim registry, the guest-reachable shim base
/// URL, and a per-node secret used to derive a token that is **deterministic**
/// (recomputable at release / re-register without persisting it) yet **unguessable**
/// (keyed by the secret). The direct analogue of [`crate::sql_shim::SqlShimResolver`].
pub struct BlobShimResolver {
    provider: Arc<dyn BlobBackends>,
    shim: BlobShim,
    base_url: String,
    secret: [u8; 32],
}

impl BlobShimResolver {
    /// `base_url` is the shim URL reachable from the guest; `secret` is a per-node random
    /// used only to key the token derivation.
    pub fn new(
        provider: Arc<dyn BlobBackends>,
        shim: BlobShim,
        base_url: String,
        secret: [u8; 32],
    ) -> Self {
        Self {
            provider,
            shim,
            base_url,
            secret,
        }
    }

    /// A deterministic, unguessable bearer token for one `(project, workload, replica,
    /// binding)` — `HMAC-SHA256(secret, project ∥ workload ∥ name ∥ replica ∥ kind)`.
    /// Identical derivation to the sql-shim's, so a blob and a sql binding on the same
    /// replica mint DISTINCT tokens (the `kind` byte differs).
    fn token(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        binding: &ComputeBinding,
    ) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("hmac accepts any key len");
        for part in [
            project.as_bytes(),
            workload.as_bytes(),
            binding.name.as_bytes(),
        ] {
            mac.update(part);
            mac.update(&[0]);
        }
        mac.update(&replica.to_le_bytes());
        // A STABLE discriminant byte — never `format!("{:?}", kind)`, which would silently rotate
        // every live token if the enum were reordered/renamed.
        mac.update(&[binding.kind.stable_tag()]);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// The [`BlobScope`] for a `blob` binding on this `(project, workload)`: the SAME
    /// backend + `hblob/{qualified-site}/` prefix the `wasi:blobstore` host binding
    /// resolves, with the workload name standing in as the site identity (exactly as the
    /// sql-shim treats the workload name as its site). A `--bind blob:<name>` additionally
    /// binds the one named container; an invalid container name fails closed (`None`
    /// returned ⇒ the binding is skipped). Pure given the provider, so the convention is
    /// unit-testable.
    fn scope(&self, project: &str, workload: &str, binding: &ComputeBinding) -> Option<BlobScope> {
        // The container, when named (`--bind blob:<name>`), must be a safe single segment —
        // reject traversal/separators at resolve time (fail closed), mirroring the host
        // binding's `validate_key_segment("container", …)` choke point.
        let container = if binding.name.is_empty() {
            None
        } else {
            if validate_key_segment("container", &binding.name).is_err() {
                tracing::warn!(
                    %project, %workload, name = %binding.name,
                    "blob binding: invalid container name; binding skipped"
                );
                return None;
            }
            Some(binding.name.clone())
        };
        // The per-project blob backend the `wasi:blobstore` binding build reads
        // (`inner.blob_backends`); an unconfigured project resolves the global default.
        let storage = self.provider.backend(ProjectRef::new(project));
        // `hblob/{qualified-site}/` — `hblob/{project}/{site}/` for EVERY project including the
        // reserved `default` (`hblob/default/{site}/`, v0.31.0 Finding 8; ProjectRef::qualified),
        // matching the host binding's `format!("hblob/{site}/")` where `site` is
        // `project.qualified(site)`.
        let qualified_site = ProjectRef::new(project).qualified(workload);
        Some(BlobScope {
            storage,
            site_prefix: format!("hblob/{qualified_site}/"),
            container,
        })
    }
}

#[async_trait::async_trait]
impl ComputeBindingResolver for BlobShimResolver {
    async fn resolve(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) -> Vec<(String, String)> {
        let mut env = Vec::new();
        for binding in bindings {
            if binding.kind != BindingKind::Blob {
                continue;
            }
            let Some(scope) = self.scope(project, workload, binding) else {
                continue;
            };
            let token = self.token(project, workload, replica, binding);
            self.shim.register(&token, scope).await;
            let url_env = binding.url_env();
            env.push((url_env.clone(), self.base_url.clone()));
            env.push((format!("{url_env}_AUTH_TOKEN"), token));
        }
        env
    }

    async fn release(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) {
        for binding in bindings {
            if binding.kind == BindingKind::Blob {
                self.shim
                    .deregister(&self.token(project, workload, replica, binding))
                    .await;
            }
        }
    }
}

/// Activate the compute blob-shim: bind its listener and build the resolver to hand the
/// compute reconcile. `shim_url` is the guest-reachable base URL (e.g.
/// `http://10.0.0.1:8082`, or the docker bridge gateway); the shim binds the **host:port the
/// URL names** — the compute bridge-gateway IP / loopback the operator configured — NOT all
/// interfaces (see [`crate::shim_bind_addr`] for the security rationale). `max_object_bytes`
/// caps a single PUT (`None` ⇒ [`DEFAULT_MAX_OBJECT_BYTES`]; `Some(0)` ⇒ unlimited). Returns
/// `None` — the feature stays off — when there is no blob provider, no `shim_url`, or the
/// host:port does not resolve / bind. The direct analogue of [`crate::sql_shim::spawn_sql_shim`].
pub async fn spawn_blob_shim(
    blob: Option<Arc<dyn BlobBackends>>,
    shim_url: Option<String>,
    max_object_bytes: Option<u64>,
) -> Option<Arc<dyn ComputeBindingResolver>> {
    let blob = blob?;
    let base_url = shim_url?;
    let Some(bind) = crate::shim_bind_addr(&base_url) else {
        tracing::warn!(%base_url, "compute.blob_shim_url has no resolvable host:port; blob bindings disabled");
        return None;
    };
    let mut secret = [0u8; 32];
    if getrandom::getrandom(&mut secret).is_err() {
        tracing::error!("getrandom failed; blob bindings disabled");
        return None;
    }
    let shim =
        BlobShim::new().with_max_object_bytes(max_object_bytes.unwrap_or(DEFAULT_MAX_OBJECT_BYTES));
    let router = shim.router();
    match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => {
            // TCP_NODELAY: the shim serves small control responses (PUT/HEAD/DELETE) to the
            // guest's `blob` binding over keep-alive; Nagle would add a ~40 ms delayed-ACK
            // stall to each. Mirrors the sql-shim. See `disable_nagle`.
            use axum::serve::ListenerExt;
            let listener = listener.tap_io(crate::disable_nagle);
            tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, router).await {
                    tracing::error!(error = %err, "compute blob-shim listener exited");
                }
            });
            tracing::info!(%bind, %base_url, "compute blob-shim listening");
        }
        Err(err) => {
            tracing::warn!(%bind, error = %err, "compute blob-shim bind failed; blob bindings disabled");
            return None;
        }
    }
    Some(Arc::new(BlobShimResolver::new(
        blob, shim, base_url, secret,
    )))
}

// ---- the enforced authorization + key-composition decision -------------------

/// A fail-closed refusal from [`authorize`]. Distinct, greppable categories — never
/// collapsed — each mapped to a status by [`IntoResponse`].
#[derive(Debug)]
enum Denied {
    /// Missing or unknown/mismatched bearer token (gate case iii) → 401.
    Unauthenticated,
    /// A container-bound token named a DIFFERENT container (gate case i) → 403.
    CrossContainer,
    /// The request container is not a safe single path segment → 400.
    BadContainer(String),
    /// The object key escapes its container prefix (`..`/absolute/reserved/…, gate case
    /// ii) → 400.
    BadKey(String),
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "missing or unknown bearer token\n",
            )
                .into_response(),
            Self::CrossContainer => (
                StatusCode::FORBIDDEN,
                "container not permitted by this token's scope\n",
            )
                .into_response(),
            Self::BadContainer(e) => {
                (StatusCode::BAD_REQUEST, format!("invalid container: {e}\n")).into_response()
            }
            Self::BadKey(e) => (
                StatusCode::BAD_REQUEST,
                format!("invalid object key: {e}\n"),
            )
                .into_response(),
        }
    }
}

/// **THE single enforced authorization + key-composition decision** (mirrors the
/// sql-shim's token→backend confinement and the egress gate's `tcp_connect_decision`):
/// every HTTP method handler resolves its target through here, so the TESTED code is the
/// ENFORCED code. Given the token-resolved `scope` (`None` ⇒ the bearer was
/// missing/unknown) and the client-supplied `container` + object `key`, return the
/// backend plus the FINAL storage key `hblob/{project-qualified-site}/{container}/{key}`,
/// or a fail-closed [`Denied`].
///
/// The SITE is taken ONLY from `scope.site_prefix` (token-bound), never from any client
/// field, so **cross-site is structurally impossible**. The three anti-hollow mutation
/// seams (test / `compute-blob-shim-gate-mutation` only, compiled out of ships) each
/// neuter ONE enforced check so the CI gate proves it load-bearing: `allow_cross_container`
/// drops the container bind (i), `allow_traversal` drops the key screen (ii), and
/// `admit_unmatched` (in [`BlobShim::authenticate`]) admits an unmatched token (iii).
fn authorize(
    scope: Option<&BlobScope>,
    container: &str,
    key: &str,
) -> Result<(Arc<dyn Storage>, String), Denied> {
    // (iii) authentication: no resolved scope ⇒ fail closed.
    let scope = scope.ok_or(Denied::Unauthenticated)?;
    // (i) cross-container: a container-bound token admits ONLY its container. The site is
    // already fixed by `scope.site_prefix`, so this is the only client-named dimension.
    if let Some(bound) = scope.container.as_deref() {
        let permitted =
            bound == container || blob_mutation().as_deref() == Some("allow_cross_container");
        if !permitted {
            return Err(Denied::CrossContainer);
        }
    }
    // The container must be a single safe segment (defense-in-depth; blocks a `..`/`/`
    // container even for a site-wide token). `..` is already inert on `fs` (`resolve`
    // rejects) and literal on cloud backends; this is the belt, not the load-bearing fix.
    validate_key_segment("container", container)
        .map_err(|e| Denied::BadContainer(e.to_string()))?;
    // (ii) traversal: screen the object key (rejects `..`/absolute/doubled-`/`/`\`/`*`/
    // control bytes + the reserved `.boatramp*` namespace) — the SAME screen the host
    // binding's `checked_object_key` runs.
    if blob_mutation().as_deref() != Some("allow_traversal") {
        validate_object_key(key).map_err(|e| Denied::BadKey(e.to_string()))?;
    }
    // Compose under the TOKEN's site prefix: `hblob/{qualified-site}/{container}/{key}` —
    // the EXACT key a `wasi:blobstore` handler for this site reads/writes.
    Ok((
        scope.storage.clone(),
        format!("{}{container}/{key}", scope.site_prefix),
    ))
}

/// Extract the `Authorization: Bearer <token>` value.
fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.trim().to_string())
}

/// Authenticate the request's bearer token and authorize `(container, key)` to a
/// confined storage key. The common prelude of every method handler.
async fn resolve_target(
    shim: &BlobShim,
    headers: &HeaderMap,
    container: &str,
    key: &str,
) -> Result<(Arc<dyn Storage>, String), Response> {
    let token = bearer(headers);
    let scope = shim.authenticate(token.as_deref()).await;
    authorize(scope.as_ref(), container, key).map_err(axum::response::IntoResponse::into_response)
}

/// Map a storage fault to a client status, logging a genuine backend fault with its real
/// cause (op + key) for the operator while giving the guest a coarse, non-leaking reason
/// — exactly the discipline the host binding's `blob_err` enforces (a raw object-store
/// error can carry signing/endpoint/credential metadata, so it reaches ONLY the log).
fn storage_fault(op: &str, key: &str, err: StorageError) -> Response {
    match err {
        StorageError::NotFound(_) => (StatusCode::NOT_FOUND, "object not found\n").into_response(),
        StorageError::InvalidKey(e) => {
            (StatusCode::BAD_REQUEST, format!("invalid key: {e}\n")).into_response()
        }
        StorageError::Unsupported(_) => {
            (StatusCode::NOT_IMPLEMENTED, "unsupported\n").into_response()
        }
        other => {
            tracing::warn!(op, key, error = %other, "compute blob-shim backend fault");
            (StatusCode::BAD_GATEWAY, "blob backend unavailable\n").into_response()
        }
    }
}

/// A `Range: bytes=…` request, parsed to the one form the backend's `get_range` takes.
enum RangeSpec {
    /// `bytes=start-end` (inclusive).
    FromTo(u64, u64),
    /// `bytes=start-` (start to end).
    From(u64),
    /// `bytes=-suffix` (the final `suffix` bytes).
    Suffix(u64),
}

/// Parse a single-range `Range: bytes=…` header; multi-ranges and malformed values yield
/// `None` (the handler then serves the whole object).
fn parse_range(value: &str) -> Option<RangeSpec> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // single range only
    }
    let (start, end) = spec.split_once('-')?;
    match (start.trim(), end.trim()) {
        ("", "") => None,
        ("", suffix) => Some(RangeSpec::Suffix(suffix.parse().ok()?)),
        (start, "") => Some(RangeSpec::From(start.parse().ok()?)),
        (start, end) => {
            let (s, e): (u64, u64) = (start.parse().ok()?, end.parse().ok()?);
            (s <= e).then_some(RangeSpec::FromTo(s, e))
        }
    }
}

/// `GET /{container}/{*key}`: read the object, honoring a single-range `Range:` and
/// streaming the (possibly large) body chunk by chunk.
async fn get_object(
    State(shim): State<BlobShim>,
    headers: HeaderMap,
    Path((container, key)): Path<(String, String)>,
) -> Response {
    let (storage, skey) = match resolve_target(&shim, &headers, &container, &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range);

    // Resolve the (offset, len) and the response status. A suffix range needs the size,
    // so `HEAD` it first; the other forms go straight to the backend.
    let (offset, len, ranged) = match range {
        None => (0, None, false),
        Some(RangeSpec::From(s)) => (s, None, true),
        Some(RangeSpec::FromTo(s, e)) => (s, Some(e.saturating_sub(s).saturating_add(1)), true),
        Some(RangeSpec::Suffix(n)) => {
            let size = match storage.head(&skey).await {
                Ok(meta) => meta.size.unwrap_or(0),
                Err(err) => return storage_fault("head", &skey, err),
            };
            (size.saturating_sub(n), None, true)
        }
    };

    let object = if ranged || offset != 0 {
        storage.get_range(&skey, offset, len).await
    } else {
        storage.get(&skey).await
    };
    let object = match object {
        Ok(o) => o,
        Err(err) => return storage_fault("get", &skey, err),
    };

    let mut builder = Response::builder().status(if ranged {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    });
    if let Some(ct) = &object.meta.content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    builder = builder.header(header::ACCEPT_RANGES, "bytes");
    if let Some(size) = object.meta.size {
        builder = builder.header(header::CONTENT_LENGTH, size);
        if ranged {
            let last = offset.saturating_add(size).saturating_sub(1);
            builder = builder.header(header::CONTENT_RANGE, format!("bytes {offset}-{last}/*"));
        }
    }
    builder
        .body(Body::from_stream(object.body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `PUT /{container}/{*key}`: stream the request body into the object, returning the
/// object key on success.
async fn put_object(
    State(shim): State<BlobShim>,
    headers: HeaderMap,
    Path((container, key)): Path<(String, String)>,
    body: Body,
) -> Response {
    let (storage, skey) = match resolve_target(&shim, &headers, &container, &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Per-object size cap (`0` = unlimited): bound a single write so a compromised/buggy guest
    // cannot exhaust node/bucket storage with one unbounded PUT (storage-exhaustion DoS).
    let cap = shim.max_object_bytes;
    // Fast path: an honest `Content-Length` over the cap is refused BEFORE reading the body.
    if cap != 0
        && let Some(len) = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        && len > cap
    {
        return oversize(cap);
    }
    // Streaming enforcement for a chunked / Content-Length-lying client: count bytes as they
    // arrive and abort the stream once the cap is crossed (the object is never fully buffered).
    let over = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let over_writer = over.clone();
    let mut seen: u64 = 0;
    let stream: ByteStream = body
        .into_data_stream()
        .map(move |chunk| {
            let bytes = chunk.map_err(|e| StorageError::backend(e.to_string()))?;
            if cap != 0 {
                seen = seen.saturating_add(bytes.len() as u64);
                if seen > cap {
                    over_writer.store(true, std::sync::atomic::Ordering::Relaxed);
                    return Err(StorageError::backend(
                        "object exceeds the per-object size cap",
                    ));
                }
            }
            Ok(bytes)
        })
        .boxed();
    match storage.put(&skey, stream, PutMeta { content_type }).await {
        Ok(_) => (StatusCode::OK, key).into_response(),
        // A put failure caused by the cap guard is a 413, not a backend fault.
        Err(_) if over.load(std::sync::atomic::Ordering::Relaxed) => oversize(cap),
        Err(err) => storage_fault("put", &skey, err),
    }
}

/// The `413 Payload Too Large` refusal for an over-cap PUT.
fn oversize(cap: u64) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("object exceeds the {cap}-byte per-object limit\n"),
    )
        .into_response()
}

/// `HEAD /{container}/{*key}`: existence + size, no body.
async fn head_object(
    State(shim): State<BlobShim>,
    headers: HeaderMap,
    Path((container, key)): Path<(String, String)>,
) -> Response {
    let (storage, skey) = match resolve_target(&shim, &headers, &container, &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match storage.head(&skey).await {
        Ok(meta) => {
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::ACCEPT_RANGES, "bytes");
            if let Some(size) = meta.size {
                builder = builder.header(header::CONTENT_LENGTH, size);
            }
            if let Some(ct) = &meta.content_type {
                builder = builder.header(header::CONTENT_TYPE, ct);
            }
            builder
                .body(Body::empty())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(err) => storage_fault("head", &skey, err),
    }
}

/// `DELETE /{container}/{*key}`: remove the object (deleting a missing object is not an
/// error, matching [`Storage::delete`]).
async fn delete_object(
    State(shim): State<BlobShim>,
    headers: HeaderMap,
    Path((container, key)): Path<(String, String)>,
) -> Response {
    let (storage, skey) = match resolve_target(&shim, &headers, &container, &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match storage.delete(&skey).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => storage_fault("delete", &skey, err),
    }
}

/// The active compute-blob-shim gate mutation (PLAN-compute-bindings anti-hollow gate), or
/// `None`. Present ONLY under `cfg(test)` (the in-crate gate) or the
/// `compute-blob-shim-gate-mutation` feature; a shipped build has neither, so
/// [`authorize`] / [`BlobShim::authenticate`] evaluate every check unconditionally and
/// this is a dead `None`. Each recognized value neuters ONE check so the CI gate can prove
/// it goes RED: `allow_cross_container` (bypass the container bind), `allow_traversal`
/// (skip the object-key screen), `admit_unmatched` (admit a missing/unknown token). NOT a
/// backdoor — it only reads a test env var.
#[cfg(any(test, feature = "compute-blob-shim-gate-mutation"))]
fn blob_mutation() -> Option<String> {
    std::env::var("BOATRAMP_COMPUTEBLOB_MUTATION").ok()
}
#[cfg(not(any(test, feature = "compute-blob-shim-gate-mutation")))]
#[inline]
fn blob_mutation() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use boatramp_core::blob_backends::GlobalBlobBackend;
    use boatramp_core::{GetObject, ListPage, ObjectMeta};
    use bytes::Bytes;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    /// A minimal in-memory [`Storage`] for exercising the shim end to end.
    #[derive(Default, Clone)]
    struct MemStorage {
        map: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }

    fn meta(key: &str, len: usize) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: Some(len as u64),
            content_type: None,
            etag: None,
        }
    }

    fn once_stream(bytes: Bytes) -> ByteStream {
        futures::stream::once(async move { Ok::<_, StorageError>(bytes) }).boxed()
    }

    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(GetObject {
                meta: meta(key, data.len()),
                body: once_stream(Bytes::from(data)),
            })
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let start = (offset as usize).min(data.len());
            let end = match len {
                Some(l) => (start + l as usize).min(data.len()),
                None => data.len(),
            };
            let slice = data[start..end].to_vec();
            Ok(GetObject {
                meta: meta(key, slice.len()),
                body: once_stream(Bytes::from(slice)),
            })
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            let m = meta(key, buf.len());
            self.map.lock().unwrap().insert(key.to_string(), buf);
            Ok(m)
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let map = self.map.lock().unwrap();
            let data = map
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(meta(key, data.len()))
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| meta(k, v.len()))
                .collect())
        }
        async fn list_page(
            &self,
            prefix: &str,
            _after: Option<&str>,
            _limit: u32,
        ) -> Result<ListPage, StorageError> {
            Ok(ListPage {
                metas: self.list(prefix).await?,
                cursor: None,
            })
        }
    }

    /// Drive one request through the real router (the enforced HTTP path).
    async fn request(
        shim: &BlobShim,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &[u8],
    ) -> (StatusCode, Vec<u8>) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let req = builder.body(Body::from(body.to_vec())).unwrap();
        let resp = shim.router().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec();
        (status, bytes)
    }

    fn resolver(shim: &BlobShim, storage: Arc<dyn Storage>) -> BlobShimResolver {
        BlobShimResolver::new(
            Arc::new(GlobalBlobBackend::new(storage)),
            shim.clone(),
            "http://10.0.0.1:8082".to_string(),
            [9u8; 32],
        )
    }

    fn blob_binding(name: &str) -> ComputeBinding {
        ComputeBinding {
            kind: BindingKind::Blob,
            name: name.to_string(),
            url_env: None,
        }
    }

    #[tokio::test]
    async fn resolver_injects_url_and_token_and_release_revokes() {
        let shim = BlobShim::new();
        let storage = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage);
        let bindings = vec![blob_binding("assets")];

        let env = resolver.resolve("default", "api", 0, &bindings).await;
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("BOATRAMP_BLOB_URL").as_deref(),
            Some("http://10.0.0.1:8082")
        );
        let token = get("BOATRAMP_BLOB_URL_AUTH_TOKEN").expect("token env injected");

        // Deterministic: resolving again mints the identical env (recomputable without persistence).
        assert_eq!(resolver.resolve("default", "api", 0, &bindings).await, env);

        // The token now authorizes a PUT to its bound container …
        let (status, _) = request(&shim, "PUT", "/assets/cat.jpg", Some(&token), b"hi").await;
        assert_eq!(status, StatusCode::OK);
        // … and release revokes it.
        resolver.release("default", "api", 0, &bindings).await;
        let (status, _) = request(&shim, "PUT", "/assets/cat.jpg", Some(&token), b"hi").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn named_project_qualifies_the_site_prefix() {
        // A non-default project qualifies the site: `hblob/{project}/{workload}/…`.
        let shim = BlobShim::new();
        let storage = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage.clone());
        let bindings = vec![blob_binding("assets")];
        let env = resolver.resolve("acme", "api", 0, &bindings).await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let (status, _) = request(&shim, "PUT", "/assets/x.bin", Some(&token), b"z").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            storage
                .map
                .lock()
                .unwrap()
                .contains_key("hblob/acme/api/assets/x.bin"),
            "a named project lands objects under hblob/{{project}}/{{site}}/…"
        );
    }

    #[tokio::test]
    async fn get_honors_range_and_streams() {
        let shim = BlobShim::new();
        let storage = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage);
        let env = resolver
            .resolve("default", "api", 0, &[blob_binding("")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        request(&shim, "PUT", "/docs/a.txt", Some(&token), b"0123456789").await;

        // Whole object.
        let (status, body) = request(&shim, "GET", "/docs/a.txt", Some(&token), b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"0123456789");

        // Ranged.
        let req = Request::builder()
            .method("GET")
            .uri("/docs/a.txt")
            .header("authorization", format!("Bearer {token}"))
            .header("range", "bytes=2-4")
            .body(Body::empty())
            .unwrap();
        let resp = shim.router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert_eq!(&body[..], b"234");
    }

    /// Security HIGH: the shim binds the HOST the `blob_shim_url` names (bridge-gateway IP /
    /// loopback), NEVER widening to all interfaces on its own.
    #[test]
    fn bind_addr_honors_configured_host_never_all_interfaces() {
        // A literal IP binds that exact IP, not 0.0.0.0.
        let a = crate::shim_bind_addr("http://127.0.0.1:8082/").expect("ip:port");
        assert_eq!(a.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_eq!(a.port(), 8082);
        assert!(!a.ip().is_unspecified(), "must not widen to all interfaces");
        // No scheme + a bare host:port still parses.
        assert_eq!(crate::shim_bind_addr("10.0.0.1:9000").unwrap().port(), 9000);
        // An explicit 0.0.0.0 is the operator's OWN choice — honored as-is.
        assert!(
            crate::shim_bind_addr("http://0.0.0.0:8082")
                .unwrap()
                .ip()
                .is_unspecified()
        );
        // No resolvable host:port ⇒ None (fail closed; never a silent all-interfaces fallback).
        assert!(crate::shim_bind_addr("http://").is_none());
    }

    /// Security LOW: a PUT above the per-object cap is refused `413` and nothing is stored;
    /// an at/under-cap PUT succeeds.
    #[tokio::test]
    async fn put_rejects_oversize_object_with_413() {
        let shim = BlobShim::new().with_max_object_bytes(4);
        let storage = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage.clone());
        let env = resolver
            .resolve("default", "api", 0, &[blob_binding("")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        // 10 bytes > 4-byte cap → 413 (caught by the streaming guard), nothing stored.
        let (status, _) = request(&shim, "PUT", "/docs/big.bin", Some(&token), b"0123456789").await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            !storage
                .map
                .lock()
                .unwrap()
                // Project default ⇒ the two-segment qualified site `default/api`
                // (v0.31.0 Finding 8): the real storage key an over-cap write would
                // have landed at, so the negative assertion still bites.
                .contains_key("hblob/default/api/docs/big.bin"),
            "an over-cap object must not be persisted"
        );
        // At/under the cap → OK.
        let (status, _) = request(&shim, "PUT", "/docs/ok.bin", Some(&token), b"1234").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// **CI mutation gate** (PLAN-compute-bindings anti-hollow, marker `COMPUTE BLOB-SHIM
    /// SCOPED OK`). Drives the ENFORCED [`authorize`] / [`BlobShim::authenticate`] decision
    /// across the three security dimensions + proves the SHARED-NAMESPACE property, and
    /// prints the marker so the merge gate can assert it RAN. MUTATION-VERIFIED: the SAME
    /// test re-run under each `BOATRAMP_COMPUTEBLOB_MUTATION` neuters ONE check and MUST
    /// FAIL — `allow_cross_container` (i: a token scoped to one site/container reaches a
    /// different container), `allow_traversal` (ii: a `../` key escapes the prefix),
    /// `admit_unmatched` (iii: an unauthenticated/mismatched token is admitted).
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn compute_blob_shim_scoped_gate() {
        let shim = BlobShim::new();
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage.clone());

        // Site "api", container-bound to "assets" (`--bind blob:assets`); project default,
        // so the qualified site is the two-segment `default/api` (v0.31.0 Finding 8) → prefix
        // `hblob/default/api/`.
        let env = resolver
            .resolve("default", "api", 0, &[blob_binding("assets")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let scope = shim
            .authenticate(Some(&token))
            .await
            .expect("scope registered");

        // ---- (i) cross-container / cross-site confinement -----------------------------
        // The token is bound to `assets`; a different container is refused …
        assert!(
            matches!(
                authorize(Some(&scope), "secrets", "k"),
                Err(Denied::CrossContainer)
            ),
            "a container-bound token must refuse a DIFFERENT container"
        );
        // … while its own container composes the EXACT site-scoped key, and the composed
        // key ALWAYS begins with the token's own (never client-named) site prefix — so
        // cross-SITE is structurally impossible.
        let (_, key) = authorize(Some(&scope), "assets", "k").expect("own container admitted");
        assert_eq!(key, "hblob/default/api/assets/k");
        assert!(key.starts_with(&scope.site_prefix));

        // ---- (ii) path-traversal confinement ------------------------------------------
        for bad in ["../escape", "a/../../b", "/abs", ".boatramp-container"] {
            assert!(
                matches!(
                    authorize(Some(&scope), "assets", bad),
                    Err(Denied::BadKey(_))
                ),
                "a traversal/reserved key must be refused: {bad:?}"
            );
        }

        // ---- (iii) authentication ------------------------------------------------------
        assert!(
            shim.authenticate(None).await.is_none(),
            "a missing bearer token must not authenticate"
        );
        assert!(
            shim.authenticate(Some("not-a-real-token")).await.is_none(),
            "an unknown/mismatched bearer token must not authenticate"
        );

        // ---- SHARED-NAMESPACE positive proof ------------------------------------------
        // An object written via the shim PUT is readable at the IDENTICAL
        // `hblob/{site}/{container}/{key}` the real `wasi:blobstore` host binding composes
        // — proven by reading it back THROUGH that binding's actual read path.
        let (status, _) = request(
            &shim,
            "PUT",
            "/assets/shared.bin",
            Some(&token),
            b"from-shim",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let via_guest = boatramp_handlers::read_object_through_guest_binding(
            storage.clone(),
            // The shim composes the two-segment default scope `hblob/default/api/…` (Finding 8), so
            // the guest read-through must name the qualified site `default/api`.
            "default/api",
            "assets",
            "shared.bin",
        )
        .await
        .expect("guest wasi:blobstore read-through of the shim's write");
        assert_eq!(
            via_guest, b"from-shim",
            "the shim PUT is guest-readable at the same key"
        );

        // And the reverse: an object a `wasi:blobstore` handler wrote (landed at the SAME
        // key) is served by the shim GET.
        storage
            .put(
                "hblob/default/api/assets/from-guest.bin",
                once_stream(Bytes::from_static(b"from-guest")),
                PutMeta::default(),
            )
            .await
            .unwrap();
        let (status, body) =
            request(&shim, "GET", "/assets/from-guest.bin", Some(&token), b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body, b"from-guest",
            "the shim reads what the guest binding wrote"
        );

        println!("COMPUTE BLOB-SHIM SCOPED OK");
    }
}
