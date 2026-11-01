//! The compute **kv-shim** (PLAN-compute-bindings) — the key/value analogue of the
//! [`sql_shim`](crate::sql_shim) / [`blob_shim`](crate::blob_shim), symmetric with them end to end.
//!
//! An opaque compute workload (container / micro-VM) cannot import the WASI `wasi:keyvalue` host
//! interface a handler uses. This shim gives it the *same* per-site-scoped [`KvStore`] namespace over
//! a plain HTTP wire: a single per-node endpoint exposing `GET`/`PUT`/`DELETE` on `{KV_URL}/{*key}`
//! (the handler's DEFAULT/unnamed bucket) and on `{KV_URL}/b/{bucket}/{*key}` (a NAMED bucket), so an
//! off-the-shelf HTTP client in the guest reads/writes exactly the keys a `wasi:keyvalue` handler for
//! the same `(project, site)` sees — under `hkv/{project-qualified-site}/{key}` (default bucket) or
//! `hkv/{project-qualified-site}/{bucket}/{key}` (named), the SAME [`KvStore`] (the node's one
//! control-plane store, `inner.kv`) the host binding reads/writes. A handler and a native worker
//! therefore share ONE key/value namespace.
//!
//! ## Why two routes, not blob's single `{container}` segment
//!
//! `wasi:keyvalue`'s `store.open("")` is the handler's DEFAULT bucket and composes NO extra path
//! segment (`hkv/{site}/{key}`); `wasi:blobstore` has no such default — every blob object lives in
//! SOME named container, so the blob-shim's single `{container}/{*key}` route always has one. Reusing
//! that shape for kv would force every default-bucket key one segment deeper than the handler's
//! (`hkv/{site}/default/{key}` ≠ `hkv/{site}/{key}`), breaking the shared-namespace guarantee for the
//! common (unnamed) case. So the kv-shim routes the default bucket through the bare `{*key}` path and
//! reserves `/b/{bucket}/{*key}` for an explicitly named one.
//!
//! ## Isolation (mirrors the sql/blob-shim's token→resolved-scope model)
//!
//! Requests authenticate with `Authorization: Bearer <token>`; the token maps to a [`KvScope`]
//! **already resolved for exactly one `project/site`** (the same `inner.kv` store + `hkv/{qualified-
//! site}/` prefix a handler gets). The SITE is carried by the TOKEN's stored `site_prefix`, NEVER by a
//! client-supplied or guessable field, so a workload is structurally incapable of naming another
//! tenant's site — exactly like the WASI handler. A `--bind kv:<name>` token is additionally bound to
//! one bucket (a request naming a DIFFERENT bucket is rejected); a bare `--bind kv` token is site-wide
//! (any bucket — including the default — is reachable). Unlike the blob-shim's object keys (which
//! address a real filesystem/object-store key hierarchy and so need a `..`-escape screen), a
//! [`KvStore`] key is an OPAQUE flat string with no path semantics: `hkv/{site}/{bucket}/{key}`
//! composed as one literal string can never "escape" its site/bucket prefix regardless of what
//! characters `key` contains, so there is no analogous traversal screen here — the control-plane
//! store (SlateDB / SQL / in-memory) never interprets `/` in a key as a path separator. The token is
//! boatramp-minted (HMAC over the per-node secret), instance-scoped, and rotatable (a fresh per-node
//! secret on restart re-derives it); no long-lived credential ever enters the guest.
//!
//! ## Network posture (listener bind)
//!
//! The listener binds the **host the operator names in `compute.kv_shim_url`** — the compute
//! bridge-gateway IP / loopback that makes it reachable from the guests — via [`crate::shim_bind_addr`],
//! NEVER all interfaces on its own. This is a token-gated DATA plane over the whole `hkv/{site}/`
//! namespace (the SAME control-plane store every site's metadata and every OTHER handler's keyvalue
//! data lives in) whose per-replica token is injected into an often-untrusted guest env, so it MUST NOT
//! be reachable off-node: operators point `kv_shim_url` at the bridge gateway (or loopback), never a
//! public address. (An explicit `0.0.0.0` in the URL is honored as the operator's own choice.)
//!
//! ## Shared data-plane keying (the `default`-project collision is CLOSED, not inherited)
//!
//! Like the blob/sql-shims, this shim treats the compute WORKLOAD's name as the site identity:
//! `qualified_site = ProjectRef::new(project).qualified(workload)`. [`ProjectRef::qualified`] is
//! unconditionally two-segment (`{project}/{base}`) for EVERY project INCLUDING the reserved
//! `default` (`default/{base}`) — the pre-`v0.31.0` bare-default branch (`qualified(DEFAULT, x) ==
//! x`) is gone — and project creation separately refuses the name `default` (both Finding 8 fixes;
//! see `ProjectRef::qualified`'s own `qualified_is_two_segment_for_every_project_including_default`
//! test and the `DEFAULT-SCOPE DISJOINTNESS`/`RESERVATION` CI gates). So a `default`-project
//! workload can never alias a named project's `hkv/` subtree: `default.qualified("acme")` is
//! `"default/acme"`, never bare `"acme"`, and is prefix-disjoint from the real project `acme`'s own
//! `"acme/…"` scope. The one sharing this composition DOES imply — by design, not a flaw — is that
//! a compute workload and a `wasi:keyvalue` handler SITE that happen to share the same name under
//! the same project see the IDENTICAL `hkv/{project}/{name}/` subtree; that is the shared-namespace
//! property this shim exists to provide.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use boatramp_core::compute::{BindingKind, ComputeBinding, ComputeBindingResolver};
use boatramp_core::kv::{KvError, KvStore};
use boatramp_core::project::{ProjectRef, validate_key_segment};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// Default per-value PUT ceiling (1 MiB — [`KvStore`] is documented for "small values") when the
/// operator sets no `compute.kv_shim_max_value_bytes`. Bounds a single write so a compromised/buggy
/// guest cannot exhaust the control-plane store with one unbounded PUT. `0` (operator-configured) =
/// unlimited.
pub const DEFAULT_MAX_VALUE_BYTES: u64 = 1024 * 1024;

/// A token-resolved kv capability: the node's [`KvStore`], the key prefix the token is confined to
/// (`hkv/{project-qualified-site}/` — host-stamped, never client-supplied), and the one bucket it may
/// touch when the binding named one.
#[derive(Clone)]
struct KvScope {
    store: Arc<dyn KvStore>,
    /// `hkv/{project-qualified-site}/` — the EXACT per-site prefix a `wasi:keyvalue` handler for this
    /// `(project, site)` is confined to (see `Bindings::with_keyvalue`).
    site_prefix: String,
    /// The one bucket a `--bind kv:<name>` token is bound to, or `None` for a site-wide `--bind kv`
    /// token (which may address any bucket, or none, WITHIN the site).
    bucket: Option<String>,
}

/// The shim's token → resolved [`KvScope`] registry, shared with the HTTP handlers.
///
/// The registry is keyed on `SHA-256(salt ∥ token)`, never the raw bearer token, so token ADMISSION
/// (the `HashMap` key compare) is timing-safe — see [`crate::blob_shim::BlobShim`] for the identical
/// rationale.
#[derive(Clone)]
pub struct KvShim {
    registry: Arc<RwLock<HashMap<[u8; 32], KvScope>>>,
    salt: [u8; 32],
    /// Per-value PUT ceiling in bytes (`0` = unlimited); a larger write is refused `413`.
    max_value_bytes: u64,
}

impl Default for KvShim {
    fn default() -> Self {
        Self::new()
    }
}

impl KvShim {
    /// A fresh, empty shim with a per-instance random admission salt and the default per-value PUT
    /// ceiling ([`DEFAULT_MAX_VALUE_BYTES`]).
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        // A failed RNG only weakens the (defense-in-depth) salt to zero — admission stays timing-safe
        // because the key is still a preimage-resistant hash of a 256-bit secret token.
        let _ = getrandom::getrandom(&mut salt);
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            salt,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }

    /// Set the per-value PUT ceiling (`0` = unlimited). Builder used by [`spawn_kv_shim`].
    pub fn with_max_value_bytes(mut self, max_value_bytes: u64) -> Self {
        self.max_value_bytes = max_value_bytes;
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
    async fn register(&self, token: &str, scope: KvScope) {
        let key = self.key(token);
        self.registry.write().await.insert(key, scope);
    }

    /// Drop a token when its workload replica is torn down.
    async fn deregister(&self, token: &str) {
        let key = self.key(token);
        self.registry.write().await.remove(&key);
    }

    /// Resolve a presented bearer `token` to its [`KvScope`], or `None` for a missing or
    /// unknown/mismatched token (fail-closed authentication — anti-hollow gate case ii). The
    /// `admit_unmatched` mutation seam admits a missing/unknown token to SOME registered scope —
    /// exactly the breach the gate must catch; it is compiled out of every shipped build.
    async fn authenticate(&self, token: Option<&str>) -> Option<KvScope> {
        let reg = self.registry.read().await;
        if let Some(t) = token
            && let Some(scope) = reg.get(&self.key(t)).cloned()
        {
            return Some(scope);
        }
        if kv_mutation().as_deref() == Some("admit_unmatched") {
            return reg.values().next().cloned();
        }
        None
    }

    /// The axum router: the default-bucket `{GET,PUT,DELETE} /{*key}` plus the named-bucket
    /// `{GET,PUT,DELETE} /b/{bucket}/{*key}`. Mount it on a node-internal listener (see
    /// [`spawn_kv_shim`]).
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/b/{bucket}/{*key}",
                get(get_named).put(put_named).delete(delete_named),
            )
            .route(
                "/{*key}",
                get(get_default).put(put_default).delete(delete_default),
            )
            .with_state(self.clone())
    }
}

/// Resolves a workload's `kv` [`ComputeBinding`]s to a shim endpoint + credential injected into the
/// guest env. Holds the node's single [`KvStore`] — unlike the sql/blob shims, kv has no PER-PROJECT
/// backend to look up; every site shares the SAME control-plane store, namespaced by key prefix — the
/// shim registry, the guest-reachable shim base URL, and a per-node secret used to derive a token that
/// is **deterministic** (recomputable at release / re-register without persisting it) yet
/// **unguessable** (keyed by the secret). The direct analogue of
/// [`crate::blob_shim::BlobShimResolver`].
pub struct KvShimResolver {
    store: Arc<dyn KvStore>,
    shim: KvShim,
    base_url: String,
    secret: [u8; 32],
}

impl KvShimResolver {
    /// `base_url` is the shim URL reachable from the guest; `secret` is a per-node random used only
    /// to key the token derivation.
    pub fn new(store: Arc<dyn KvStore>, shim: KvShim, base_url: String, secret: [u8; 32]) -> Self {
        Self {
            store,
            shim,
            base_url,
            secret,
        }
    }

    /// A deterministic, unguessable bearer token for one `(project, workload, replica, binding)` —
    /// `HMAC-SHA256(secret, project ∥ workload ∥ name ∥ replica ∥ kind)`. Identical derivation to the
    /// sql/blob-shims', so a kv binding on the same replica mints a DISTINCT token from a
    /// sql/blob/messaging one (the `kind` byte differs).
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

    /// The [`KvScope`] for a `kv` binding on this `(project, workload)`: the SAME store +
    /// `hkv/{qualified-site}/` prefix the `wasi:keyvalue` host binding resolves, with the workload
    /// name standing in as the site identity (exactly as the sql/blob-shims treat the workload name
    /// as their site). A `--bind kv:<name>` additionally binds the one named bucket; an invalid
    /// bucket name fails closed (`None` returned ⇒ the binding is skipped). Pure given the provider,
    /// so the convention is unit-testable.
    fn scope(&self, project: &str, workload: &str, binding: &ComputeBinding) -> Option<KvScope> {
        // The bucket, when named (`--bind kv:<name>`), must be a safe single segment — reject
        // separators/control chars at resolve time (fail closed), mirroring the blob-shim's
        // `validate_key_segment("container", …)` choke point.
        let bucket = if binding.name.is_empty() {
            None
        } else {
            if validate_key_segment("bucket", &binding.name).is_err() {
                tracing::warn!(
                    %project, %workload, name = %binding.name,
                    "kv binding: invalid bucket name; binding skipped"
                );
                return None;
            }
            Some(binding.name.clone())
        };
        let qualified_site = ProjectRef::new(project).qualified(workload);
        Some(KvScope {
            store: self.store.clone(),
            site_prefix: format!("hkv/{qualified_site}/"),
            bucket,
        })
    }
}

#[async_trait::async_trait]
impl ComputeBindingResolver for KvShimResolver {
    async fn resolve(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) -> Vec<(String, String)> {
        let mut env = Vec::new();
        for binding in bindings {
            if binding.kind != BindingKind::Kv {
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
            if binding.kind == BindingKind::Kv {
                self.shim
                    .deregister(&self.token(project, workload, replica, binding))
                    .await;
            }
        }
    }
}

/// Activate the compute kv-shim: bind its listener and build the resolver to hand the compute
/// reconcile. `shim_url` is the guest-reachable base URL (e.g. `http://10.0.0.1:8084`, or the docker
/// bridge gateway); the shim binds the **host:port the URL names** — the compute bridge-gateway IP /
/// loopback the operator configured — NOT all interfaces (see [`crate::shim_bind_addr`]).
/// `max_value_bytes` caps a single PUT (`None` ⇒ [`DEFAULT_MAX_VALUE_BYTES`]; `Some(0)` ⇒ unlimited).
/// Returns `None` — the feature stays off — when there is no kv store, no `shim_url`, or the host:port
/// does not resolve / bind. The direct analogue of [`crate::blob_shim::spawn_blob_shim`].
pub async fn spawn_kv_shim(
    kv: Option<Arc<dyn KvStore>>,
    shim_url: Option<String>,
    max_value_bytes: Option<u64>,
) -> Option<Arc<dyn ComputeBindingResolver>> {
    let kv = kv?;
    let base_url = shim_url?;
    let Some(bind) = crate::shim_bind_addr(&base_url) else {
        tracing::warn!(%base_url, "compute.kv_shim_url has no resolvable host:port; kv bindings disabled");
        return None;
    };
    let mut secret = [0u8; 32];
    if getrandom::getrandom(&mut secret).is_err() {
        tracing::error!("getrandom failed; kv bindings disabled");
        return None;
    }
    let shim =
        KvShim::new().with_max_value_bytes(max_value_bytes.unwrap_or(DEFAULT_MAX_VALUE_BYTES));
    let router = shim.router();
    match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => {
            // TCP_NODELAY: the shim serves small control responses (GET/PUT/DELETE) to the guest's
            // `kv` binding over keep-alive; Nagle would add a ~40 ms delayed-ACK stall to each.
            // Mirrors the sql/blob-shims. See `disable_nagle`.
            use axum::serve::ListenerExt;
            let listener = listener.tap_io(crate::disable_nagle);
            tokio::spawn(async move {
                if let Err(err) = axum::serve(listener, router).await {
                    tracing::error!(error = %err, "compute kv-shim listener exited");
                }
            });
            tracing::info!(%bind, %base_url, "compute kv-shim listening");
        }
        Err(err) => {
            tracing::warn!(%bind, error = %err, "compute kv-shim bind failed; kv bindings disabled");
            return None;
        }
    }
    Some(Arc::new(KvShimResolver::new(kv, shim, base_url, secret)))
}

// ---- the enforced authorization + key-composition decision -------------------

/// A fail-closed refusal from [`authorize`]. Distinct, greppable categories — never collapsed —
/// each mapped to a status by [`IntoResponse`].
#[derive(Debug)]
enum Denied {
    /// Missing or unknown/mismatched bearer token (gate case ii) → 401.
    Unauthenticated,
    /// A bucket-bound token named a DIFFERENT bucket (gate case i) → 403.
    CrossBucket,
    /// The requested bucket is not a safe single path segment → 400.
    BadBucket(String),
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "missing or unknown bearer token\n",
            )
                .into_response(),
            Self::CrossBucket => (
                StatusCode::FORBIDDEN,
                "bucket not permitted by this token's scope\n",
            )
                .into_response(),
            Self::BadBucket(e) => {
                (StatusCode::BAD_REQUEST, format!("invalid bucket: {e}\n")).into_response()
            }
        }
    }
}

/// **THE single enforced authorization + key-composition decision** (mirrors the blob-shim's
/// `authorize` / the egress gate's `tcp_connect_decision`): every HTTP method handler resolves its
/// target through here, so the TESTED code is the ENFORCED code. Given the token-resolved `scope`
/// (`None` ⇒ the bearer was missing/unknown) and the client-named `requested` bucket (`None` for the
/// bare default-bucket route, `Some(name)` for `/b/{name}/…`), return the backend plus the FINAL
/// storage key — `hkv/{project-qualified-site}/{key}` for the default bucket, or
/// `hkv/{project-qualified-site}/{bucket}/{key}` for a named one — or a fail-closed [`Denied`].
///
/// The SITE is taken ONLY from `scope.site_prefix` (token-bound), never from any client field, so
/// **cross-site is structurally impossible**. A bucket-bound token's bare route resolves to ITS OWN
/// bucket (so a `--bind kv:<name>` token needs no `/b/` path at all to reach its bucket); a site-wide
/// token's bare route resolves to the TRUE default (unnamed) bucket, matching the handler's
/// `store.open("")`. The two anti-hollow mutation seams (test / `compute-kv-shim-gate-mutation` only,
/// compiled out of ships) each neuter ONE enforced check so the CI gate can prove it load-bearing:
/// `allow_cross_bucket` drops the bucket bind (i), and `admit_unmatched` (in
/// [`KvShim::authenticate`]) admits an unmatched token (ii).
fn authorize(
    scope: Option<&KvScope>,
    requested: Option<&str>,
    key: &str,
) -> Result<(Arc<dyn KvStore>, String), Denied> {
    // (ii) authentication: no resolved scope ⇒ fail closed.
    let scope = scope.ok_or(Denied::Unauthenticated)?;
    // (i) cross-bucket: a bucket-bound token admits ONLY its own bucket. The site is already fixed
    // by `scope.site_prefix`, so this is the only client-named dimension.
    if let Some(bound) = scope.bucket.as_deref()
        && let Some(r) = requested
    {
        let permitted = r == bound || kv_mutation().as_deref() == Some("allow_cross_bucket");
        if !permitted {
            return Err(Denied::CrossBucket);
        }
    }
    // The effective bucket: the client-requested one when present, else the token's own bound
    // bucket (the bare-route shorthand), else the TRUE default (unnamed) bucket.
    let bucket = requested.or(scope.bucket.as_deref());
    // The bucket must be a single safe segment (defense-in-depth; mirrors the blob-shim's belt —
    // there is no traversal risk on a flat KV store, but a malformed bucket name is still rejected).
    if let Some(b) = bucket {
        validate_key_segment("bucket", b).map_err(|e| Denied::BadBucket(e.to_string()))?;
    }
    // Compose under the TOKEN's site prefix: `hkv/{qualified-site}/{key}` for the default bucket, or
    // `hkv/{qualified-site}/{bucket}/{key}` for a named one — the EXACT key a `wasi:keyvalue` handler
    // for this site reads/writes.
    let full_key = match bucket {
        Some(b) => format!("{}{b}/{key}", scope.site_prefix),
        None => format!("{}{key}", scope.site_prefix),
    };
    Ok((scope.store.clone(), full_key))
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

/// Authenticate the request's bearer token and authorize the `(bucket, key)` pair to a confined
/// storage key. The common prelude of every method handler.
async fn resolve_target(
    shim: &KvShim,
    headers: &HeaderMap,
    requested: Option<&str>,
    key: &str,
) -> Result<(Arc<dyn KvStore>, String), Response> {
    let token = bearer(headers);
    let scope = shim.authenticate(token.as_deref()).await;
    authorize(scope.as_ref(), requested, key).map_err(IntoResponse::into_response)
}

/// Map a [`KvError`] to a client status, logging a genuine backend fault for the operator while
/// giving the guest a coarse, non-leaking reason.
fn kv_fault(op: &str, key: &str, err: KvError) -> Response {
    tracing::warn!(op, key, error = %err, "compute kv-shim backend fault");
    (StatusCode::BAD_GATEWAY, "kv backend unavailable\n").into_response()
}

/// The `413 Payload Too Large` refusal for an over-cap PUT.
fn oversize(cap: u64) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("value exceeds the {cap}-byte per-value limit\n"),
    )
        .into_response()
}

// ---- method handlers (two routes each; shared body) --------------------------

async fn get_default(
    State(shim): State<KvShim>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    get_value(shim, headers, None, key).await
}

async fn get_named(
    State(shim): State<KvShim>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    get_value(shim, headers, Some(bucket), key).await
}

/// `GET`: read the value for `key` (in `bucket`, or the default when `None`).
async fn get_value(
    shim: KvShim,
    headers: HeaderMap,
    bucket: Option<String>,
    key: String,
) -> Response {
    let (store, skey) = match resolve_target(&shim, &headers, bucket.as_deref(), &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match store.get(&skey).await {
        Ok(Some(value)) => (StatusCode::OK, value).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "key not found\n").into_response(),
        Err(err) => kv_fault("get", &skey, err),
    }
}

async fn put_default(
    State(shim): State<KvShim>,
    headers: HeaderMap,
    Path(key): Path<String>,
    body: Body,
) -> Response {
    put_value(shim, headers, None, key, body).await
}

async fn put_named(
    State(shim): State<KvShim>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
    body: Body,
) -> Response {
    put_value(shim, headers, Some(bucket), key, body).await
}

/// `PUT`: set `key` (in `bucket`, or the default when `None`) to the request body, bounded by the
/// per-value cap.
async fn put_value(
    shim: KvShim,
    headers: HeaderMap,
    bucket: Option<String>,
    key: String,
    body: Body,
) -> Response {
    let (store, skey) = match resolve_target(&shim, &headers, bucket.as_deref(), &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cap = shim.max_value_bytes;
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
    // `to_bytes` enforces the cap while draining a chunked / Content-Length-lying client too — the
    // body is never buffered past `limit`.
    let limit = if cap == 0 { usize::MAX } else { cap as usize };
    let bytes = match to_bytes(body, limit).await {
        Ok(b) => b,
        Err(_) => return oversize(cap),
    };
    match store.put(&skey, bytes.to_vec()).await {
        Ok(()) => (StatusCode::OK, key).into_response(),
        Err(err) => kv_fault("put", &skey, err),
    }
}

async fn delete_default(
    State(shim): State<KvShim>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    delete_value(shim, headers, None, key).await
}

async fn delete_named(
    State(shim): State<KvShim>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    delete_value(shim, headers, Some(bucket), key).await
}

/// `DELETE`: remove `key` (in `bucket`, or the default when `None`); deleting a missing key is not
/// an error, matching [`KvStore::delete`].
async fn delete_value(
    shim: KvShim,
    headers: HeaderMap,
    bucket: Option<String>,
    key: String,
) -> Response {
    let (store, skey) = match resolve_target(&shim, &headers, bucket.as_deref(), &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match store.delete(&skey).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => kv_fault("delete", &skey, err),
    }
}

/// The active compute-kv-shim gate mutation (PLAN-compute-bindings anti-hollow gate), or `None`.
/// Present ONLY under `cfg(test)` (the in-crate gate) or the `compute-kv-shim-gate-mutation` feature;
/// a shipped build has neither, so [`authorize`] / [`KvShim::authenticate`] evaluate every check
/// unconditionally and this is a dead `None`. Each recognized value neuters ONE check so the CI gate
/// can prove it goes RED: `allow_cross_bucket` (bypass the bucket bind), `admit_unmatched` (admit a
/// missing/unknown token). NOT a backdoor — it only reads a test env var.
#[cfg(any(test, feature = "compute-kv-shim-gate-mutation"))]
fn kv_mutation() -> Option<String> {
    std::env::var("BOATRAMP_COMPUTEKV_MUTATION").ok()
}
#[cfg(not(any(test, feature = "compute-kv-shim-gate-mutation")))]
#[inline]
fn kv_mutation() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes as body_to_bytes;
    use axum::http::Request;
    use boatramp_core::kv::MemoryKv;
    use tower::ServiceExt as _;

    fn resolver(shim: &KvShim, store: Arc<dyn KvStore>) -> KvShimResolver {
        KvShimResolver::new(
            store,
            shim.clone(),
            "http://10.0.0.1:8084".to_string(),
            [9u8; 32],
        )
    }

    fn kv_binding(name: &str) -> ComputeBinding {
        ComputeBinding {
            kind: BindingKind::Kv,
            name: name.to_string(),
            url_env: None,
        }
    }

    /// Drive one request through the real router (the enforced HTTP path).
    async fn request(
        shim: &KvShim,
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
        let bytes = body_to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    }

    #[tokio::test]
    async fn resolver_injects_url_and_token_and_release_revokes() {
        let shim = KvShim::new();
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let resolver = resolver(&shim, store);
        let bindings = vec![kv_binding("cache")];

        let env = resolver.resolve("default", "api", 0, &bindings).await;
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("BOATRAMP_KV_URL").as_deref(),
            Some("http://10.0.0.1:8084")
        );
        let token = get("BOATRAMP_KV_URL_AUTH_TOKEN").expect("token env injected");

        // Deterministic: resolving again mints the identical env (recomputable without persistence).
        assert_eq!(resolver.resolve("default", "api", 0, &bindings).await, env);

        // The token now authorizes a PUT to its bound bucket via the bare route (no `/b/` needed) …
        let (status, _) = request(&shim, "PUT", "/greeting", Some(&token), b"hi").await;
        assert_eq!(status, StatusCode::OK);
        // … and release revokes it.
        resolver.release("default", "api", 0, &bindings).await;
        let (status, _) = request(&shim, "PUT", "/greeting", Some(&token), b"hi").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn named_project_qualifies_the_site_prefix() {
        // A non-default project qualifies the site: `hkv/{project}/{workload}/…`.
        let shim = KvShim::new();
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let resolver = resolver(&shim, store.clone());
        let bindings = vec![kv_binding("cache")];
        let env = resolver.resolve("acme", "api", 0, &bindings).await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_KV_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let (status, _) = request(&shim, "PUT", "/x", Some(&token), b"z").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            store.get("hkv/acme/api/cache/x").await.unwrap(),
            Some(b"z".to_vec()),
            "a named project lands keys under hkv/{{project}}/{{site}}/{{bucket}}/…"
        );
    }

    #[tokio::test]
    async fn site_wide_token_reaches_the_true_default_bucket_and_any_named_one() {
        // A bare `--bind kv` (empty name) is site-wide: the bare route reaches the handler's TRUE
        // default bucket (no extra segment), and the named route reaches any bucket the client names.
        let shim = KvShim::new();
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let resolver = resolver(&shim, store.clone());
        let env = resolver
            .resolve("default", "api", 0, &[kv_binding("")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_KV_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();

        // Default bucket: no `{bucket}` segment in the composed key.
        let (status, _) = request(&shim, "PUT", "/greeting", Some(&token), b"hi").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            store.get("hkv/default/api/greeting").await.unwrap(),
            Some(b"hi".to_vec())
        );

        // Any named bucket is also reachable.
        let (status, _) = request(&shim, "PUT", "/b/cache/k", Some(&token), b"v").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            store.get("hkv/default/api/cache/k").await.unwrap(),
            Some(b"v".to_vec())
        );
    }

    #[tokio::test]
    async fn get_and_delete_round_trip() {
        let shim = KvShim::new();
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let resolver = resolver(&shim, store);
        let env = resolver
            .resolve("default", "api", 0, &[kv_binding("docs")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_KV_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();

        request(&shim, "PUT", "/a.txt", Some(&token), b"0123456789").await;
        let (status, body) = request(&shim, "GET", "/a.txt", Some(&token), b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"0123456789");

        // A missing key is a 404, not a backend fault.
        let (status, _) = request(&shim, "GET", "/missing.txt", Some(&token), b"").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Delete then re-read confirms removal; deleting again is still a success (idempotent).
        let (status, _) = request(&shim, "DELETE", "/a.txt", Some(&token), b"").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = request(&shim, "GET", "/a.txt", Some(&token), b"").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = request(&shim, "DELETE", "/a.txt", Some(&token), b"").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    /// Security LOW: a PUT above the per-value cap is refused `413` and nothing is stored; an
    /// at/under-cap PUT succeeds.
    #[tokio::test]
    async fn put_rejects_oversize_value_with_413() {
        let shim = KvShim::new().with_max_value_bytes(4);
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let resolver = resolver(&shim, store.clone());
        let env = resolver
            .resolve("default", "api", 0, &[kv_binding("")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_KV_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        // 10 bytes > 4-byte cap → 413, nothing stored.
        let (status, _) = request(&shim, "PUT", "/big", Some(&token), b"0123456789").await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(store.get("hkv/default/api/big").await.unwrap().is_none());
        // At/under the cap → OK.
        let (status, _) = request(&shim, "PUT", "/ok", Some(&token), b"1234").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Security HIGH: the shim binds the HOST the `kv_shim_url` names (bridge-gateway IP / loopback),
    /// NEVER widening to all interfaces on its own. Shares the helper every compute shim tests.
    #[test]
    fn bind_addr_honors_configured_host_never_all_interfaces() {
        let a = crate::shim_bind_addr("http://127.0.0.1:8084/").expect("ip:port");
        assert_eq!(a.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_eq!(a.port(), 8084);
        assert!(!a.ip().is_unspecified(), "must not widen to all interfaces");
        assert_eq!(crate::shim_bind_addr("10.0.0.1:9000").unwrap().port(), 9000);
        assert!(
            crate::shim_bind_addr("http://0.0.0.0:8084")
                .unwrap()
                .ip()
                .is_unspecified()
        );
        assert!(crate::shim_bind_addr("http://").is_none());
    }

    /// **CI mutation gate** (PLAN-compute-bindings anti-hollow, marker `COMPUTE KV-SHIM SCOPED OK`).
    /// Drives the ENFORCED [`authorize`] / [`KvShim::authenticate`] decision across the two security
    /// dimensions + proves the SHARED-NAMESPACE property (through the REAL guest `wasi:keyvalue`
    /// read-path, not just a string-equality check on the raw store), and prints the marker so the
    /// merge gate can assert it RAN. MUTATION-VERIFIED: the SAME test re-run under each
    /// `BOATRAMP_COMPUTEKV_MUTATION` neuters ONE check and MUST FAIL — `allow_cross_bucket` (i: a
    /// token scoped to one bucket reaches a different bucket), `admit_unmatched` (ii: an
    /// unauthenticated/mismatched token is admitted).
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn compute_kv_shim_scoped_gate() {
        let shim = KvShim::new();
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let resolver = resolver(&shim, store.clone());

        // Bucket-bound to "cache" (`--bind kv:cache`); project default, so the qualified site is
        // the two-segment `default/api` → prefix `hkv/default/api/`.
        let env = resolver
            .resolve("default", "api", 0, &[kv_binding("cache")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_KV_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let scope = shim
            .authenticate(Some(&token))
            .await
            .expect("scope registered");

        // ---- (i) cross-bucket / cross-site confinement --------------------------------
        assert!(
            matches!(
                authorize(Some(&scope), Some("secrets"), "k"),
                Err(Denied::CrossBucket)
            ),
            "a bucket-bound token must refuse a DIFFERENT bucket"
        );
        // … while its own bucket (named explicitly, or via the bare-route shorthand) composes the
        // EXACT site-scoped key, and the composed key ALWAYS begins with the token's own (never
        // client-named) site prefix — so cross-SITE is structurally impossible.
        let (_, key) = authorize(Some(&scope), Some("cache"), "k").expect("own bucket admitted");
        assert_eq!(key, "hkv/default/api/cache/k");
        let (_, key_bare) = authorize(Some(&scope), None, "k").expect("bare route ⇒ own bucket");
        assert_eq!(key_bare, key);
        assert!(key.starts_with(&scope.site_prefix));

        // ---- (ii) authentication -------------------------------------------------------
        assert!(
            shim.authenticate(None).await.is_none(),
            "a missing bearer token must not authenticate"
        );
        assert!(
            shim.authenticate(Some("not-a-real-token")).await.is_none(),
            "an unknown/mismatched bearer token must not authenticate"
        );

        // ---- SHARED-NAMESPACE positive proof -------------------------------------------
        // A value written via the shim PUT is readable through the REAL guest `wasi:keyvalue`
        // read-path (`store.get`) — the same `Bucket::key` composition a handler's import uses.
        let (status, _) = request(
            &shim,
            "PUT",
            "/b/cache/shared.txt",
            Some(&token),
            b"from-shim",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let via_guest = boatramp_handlers::read_value_through_guest_binding(
            store.clone(),
            // The shim composes the two-segment default scope `hkv/default/api/…`, so the guest
            // read-through must name the qualified site `default/api`.
            "default/api",
            "cache",
            "shared.txt",
        )
        .await
        .expect("guest wasi:keyvalue read-through of the shim's write");
        assert_eq!(
            via_guest,
            Some(b"from-shim".to_vec()),
            "the shim PUT is guest-readable at the same key"
        );

        // And the reverse: a value a `wasi:keyvalue` handler wrote (landed at the SAME key) is
        // served by the shim GET.
        store
            .put(
                "hkv/default/api/cache/from-guest.txt",
                b"from-guest".to_vec(),
            )
            .await
            .unwrap();
        let (status, body) =
            request(&shim, "GET", "/b/cache/from-guest.txt", Some(&token), b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body, b"from-guest",
            "the shim reads what the guest binding wrote"
        );

        println!("COMPUTE KV-SHIM SCOPED OK");
    }
}
