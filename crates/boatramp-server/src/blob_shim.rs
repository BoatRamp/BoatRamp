//! The compute **blob-shim** (PLAN-compute-bindings) — the blob analogue of the
//! [`sql_shim`](crate::sql_shim), symmetric with it end to end.
//!
//! An opaque compute workload (container / micro-VM) cannot import the WASI
//! `wasi:blobstore` host interface a handler uses. This shim gives it an equivalent
//! [`Storage`] namespace over a plain HTTP wire: a single per-node endpoint exposing
//! `PUT`/`GET`/`HEAD`/`DELETE` on `{BLOB_URL}/{container}/{key}` plus a `LIST`
//! (`GET {BLOB_URL}/{container}` with an optional `?prefix=`/`?after=`/`?limit=`), so an
//! off-the-shelf HTTP client in the guest reads/writes/enumerates objects on the SAME `Storage`
//! backend (`BlobBackends::backend(project)`) a `wasi:blobstore` handler resolves.
//!
//! ## Namespace (which blob tape a `blob` binding reaches)
//!
//! A `--bind blob` resolves to ONE confined `hblob/…` prefix, chosen by the binding's
//! [`site`](ComputeBinding::site):
//!
//! * **No `site` (the default)** → the workload's PRIVATE **reserved compute namespace**
//!   `hblob/{project}/_compute/{workload}/{container}/`. The `_compute` segment is RESERVED:
//!   a site name can never be `_compute` (`is_valid_resource_slug` rejects a leading `_`), so this
//!   namespace is **disjoint from every site's blob tape** — a compute workload can never silently
//!   collide with a same-named site. This is the v0.73.0 convention-drop: before it, a bare `blob`
//!   binding resolved under the WORKLOAD NAME as the site segment (`hblob/{project}/{workload}/…`),
//!   so a workload NAMED after a site implicitly shared that site's tape — an undiscoverable,
//!   error-prone coupling, now gone.
//!
//! * **Explicit `site: "blog"`** → that SITE's tape `hblob/{project}/{site}/{container}/`, the
//!   EXACT objects a `wasi:blobstore` handler for `(project, site)` sees, so a worker and a handler
//!   deliberately share ONE blob namespace. The `{project}` is ALWAYS the WORKLOAD's own (from its
//!   key), NEVER the binding, so a share can never cross tenants; the server additionally gates it
//!   at set time (the named site must EXIST in the workload's project, and the caller must hold that
//!   site's blob-write right — see `admin_api::put_compute`). `scope` fails CLOSED on a malformed
//!   site name (binding skipped).
//!
//! ## Isolation (mirrors the sql-shim's token→resolved-backend model)
//!
//! Requests authenticate with `Authorization: Bearer <token>`; the token maps to a
//! [`BlobScope`] **already resolved to exactly one confined `hblob/…` prefix** (the private
//! reserved compute namespace, or — for an explicit-`site` binding — that site's tape, resolved
//! through the same `BlobBackends::backend` call a handler gets). The prefix is carried by the
//! TOKEN's stored `site_prefix`, NEVER by a client-supplied or guessable field, so a workload is
//! structurally incapable of naming another namespace — exactly like the WASI handler. A
//! `--bind blob:<name>` token is additionally bound to one container (cross-container
//! rejected); a bare `--bind blob` token is namespace-wide but still confined to its one
//! prefix, and every object key is screened ([`validate_object_key`]) so a
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
//! ## Tenancy of the resolved prefix
//!
//! Both namespace shapes are rooted at `hblob/{project}/…` where `{project}` is taken ONLY from the
//! WORKLOAD's key (the control-plane `project/<proj>/compute/<name>` path), never from the binding —
//! so a `blob` binding can NEVER resolve into another project's `hblob/` subtree. For the reserved
//! default the next segment is the literal `_compute`, which `is_valid_resource_slug` rejects as a
//! site name, so the compute keyspace is provably disjoint from every site tape (the flat `hblob/`
//! keyspace has no in-key kind marker — the reserved `_compute` segment is the load-bearing safety).
//! For an explicit `site` the next segment is that site, validated to a well-formed slug in
//! [`BlobShimResolver::scope`] (a malformed one fails CLOSED → the binding is skipped), and gated to
//! a REAL same-project site + the caller's site blob-write right at set time (`put_compute`).

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use boatramp_core::blob_backends::BlobBackends;
use boatramp_core::compute::{
    BindingKind, ComputeBinding, ComputeBindingResolver, SurfaceContribution,
};
use boatramp_core::project::{
    ProjectRef, validate_key_segment, validate_object_key, validate_resource_name,
};
use boatramp_core::{ByteStream, ObjectMeta, PutMeta, Storage, StorageError};
use futures::StreamExt as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// Default per-object PUT ceiling (5 GiB — S3's single-`PutObject` limit) when the operator sets no
/// `compute.blob_shim_max_object_bytes`. Bounds a single write so a compromised/buggy guest cannot
/// exhaust node/bucket storage with one unbounded PUT. `0` (operator-configured) = unlimited.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// The LIST page ceiling: a `GET /{container}` returns at most this many keys per request (the
/// guest resumes with the opaque `?after=` cursor), clamping a guest-supplied `?limit=` to
/// `[1, MAX_LIST_PAGE]`. Matches the `wasi:blobstore` `blob-list` host binding's own page ceiling,
/// so the shim and a handler bound the keyspace identically.
const MAX_LIST_PAGE: u32 = 1000;

/// The reserved key namespace a LIST must never surface — the container marker
/// (`.boatramp-container`) and host-internal multipart staging (`.boatramp-uploads/…`). A guest can
/// never WRITE one ([`validate_object_key`] rejects it), but the host writes the marker, so the
/// listing hides ANY key whose path touches it. Mirrors the host `blob-list` binding's reserve.
const RESERVED_PREFIX: &str = ".boatramp";

/// The RESERVED site-identity segment for a compute workload's PRIVATE blob namespace
/// (`hblob/{project}/_compute/{workload}/…`), used when a `blob` binding sets no explicit
/// [`site`](ComputeBinding::site). It is deliberately NOT a valid resource slug
/// (`boatramp_core::project::is_valid_resource_slug` rejects the leading `_`), so NO site can ever
/// be named `_compute` — the compute keyspace is therefore provably disjoint from every site's
/// `hblob/{project}/{site}/` tape. This is the load-bearing safety of the v0.73.0 convention-drop
/// (the flat `hblob/` keyspace carries no in-key kind marker, so the reserved segment IS the
/// marker). A unit test (`default_namespace_segment_is_never_a_valid_site`) pins the invariant.
const COMPUTE_RESERVED_SEGMENT: &str = "_compute";

/// The container MARKER object name. A boatramp "container" is a key prefix PLUS this marker object,
/// so a `wasi:blobstore` handler's `get-container`/`container-exists` only admits a container whose
/// marker is present. A shim PUT therefore ENSURES this marker (see [`put_object`]), making a
/// worker-written container first-class for a guest handler. Kept byte-for-byte IDENTICAL to
/// `boatramp_handlers`' own `MARKER`; it is duplicated (not imported) because `boatramp-handlers` is
/// an OPTIONAL dependency while this module compiles unconditionally — the `compute_blob_shim_scoped_gate`
/// asserts the two strings match under `--features handlers`, so a drift is caught, never silent.
const CONTAINER_MARKER: &str = ".boatramp-container";

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

    /// The axum router: `{PUT,GET,HEAD,DELETE} /{container}/{*key}` on individual objects, plus
    /// `GET /{container}` (no key segment) to LIST the keys under the token's container. The two
    /// routes never collide: the object routes require a container AND a key segment, while the
    /// single-segment LIST route has no key (and an object key is never empty). Mount it on a
    /// node-internal listener (see [`spawn_blob_shim`]).
    pub fn router(&self) -> Router {
        Router::new()
            .route("/{container}", get(list_objects))
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
    /// The optional **direct-S3 STS minter** (PLAN-compute-managed-resources Phase 3) + its
    /// lease TTL (seconds). `Some` ⇒ a `--bind blob:<container>` ALSO gets short-lived
    /// `TempCredentials` so an off-the-shelf S3 client talks DIRECTLY to R2/Tigris (`AWS_*` env
    /// plus `{{blob.*}}` STS vars), KEEPING the HMAC shim as the full-R/W fallback. `None` (always,
    /// in a build without `blob-upload`, or on a backend with no real STS) ⇒ the HMAC shim only.
    /// Feature-gated because `boatramp_handlers` (the `BlobUploadMinter` seam) is an optional dep.
    #[cfg(feature = "blob-upload")]
    blob_minter: Option<(
        Arc<dyn boatramp_handlers::BlobUploadMinter>,
        u64,
        Option<u64>,
    )>,
}

/// The direct-S3 STS minter slot [`spawn_blob_shim`] takes:
/// `Some((minter, max_ttl_secs, max_bytes_ceiling))` wires direct-to-R2/Tigris
/// `TempCredentials`; `None` (and the always-`()` variant without the `blob-upload` feature) ⇒
/// the HMAC shim only. `max_bytes_ceiling` is the operator per-object size ceiling (the SAME
/// one the guest mint path clamps to). Keeps the node's call site feature-independent.
#[cfg(feature = "blob-upload")]
pub type BlobMintSlot = Option<(
    Arc<dyn boatramp_handlers::BlobUploadMinter>,
    u64,
    Option<u64>,
)>;
/// See the feature-on variant: without `blob-upload` there is no minter type, so the slot is unit.
#[cfg(not(feature = "blob-upload"))]
pub type BlobMintSlot = ();

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
            #[cfg(feature = "blob-upload")]
            blob_minter: None,
        }
    }

    /// Attach the direct-S3 STS minter + its lease TTL + the operator per-object size ceiling.
    /// Builder used by [`spawn_blob_shim`].
    #[cfg(feature = "blob-upload")]
    pub fn with_blob_minter(
        mut self,
        minter: Option<Arc<dyn boatramp_handlers::BlobUploadMinter>>,
        max_ttl_secs: u64,
        max_bytes_ceiling: Option<u64>,
    ) -> Self {
        self.blob_minter = minter.map(|m| (m, max_ttl_secs, max_bytes_ceiling));
        self
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

    /// The [`BlobScope`] for a `blob` binding on this `(project, workload)` — the ONE confined
    /// `hblob/…` prefix the token is bound to, chosen by the binding's
    /// [`site`](ComputeBinding::site):
    ///
    /// * **No `site`** → the workload's PRIVATE reserved namespace
    ///   `hblob/{project}/_compute/{workload}/` ([`COMPUTE_RESERVED_SEGMENT`]) — disjoint from every
    ///   site tape (a site can never be named `_compute`). This DROPS the pre-v0.73.0 name-match
    ///   convention: a workload named like a site no longer shares that site's tape by default.
    /// * **Explicit `site`** → that site's tape `hblob/{project}/{site}/`, the SAME prefix a
    ///   `wasi:blobstore` host binding for `(project, site)` resolves — so the share is exact. The
    ///   site name is re-validated here as a well-formed slug; a malformed one fails CLOSED (`None`
    ///   ⇒ the binding is skipped), defense-in-depth behind the set-time existence/authz gate.
    ///
    /// The `{project}` is ALWAYS the WORKLOAD's own (the `project` argument, from the workload's
    /// key), NEVER the binding, so a resolved prefix can never cross tenants. A `--bind blob:<name>`
    /// additionally binds the one named container; an invalid container name fails closed. Pure
    /// given the provider, so the namespace scheme is unit-testable.
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
        // (`inner.blob_backends`); an unconfigured project resolves the global default. The project
        // is the WORKLOAD's own — the structural tenant boundary (never the binding).
        let proj = ProjectRef::new(project);
        let storage = self.provider.backend(proj);
        // Resolve the one confined `hblob/{project}/…/` prefix. BOTH shapes root at the workload's
        // own project via `ProjectRef::qualified`, so neither can reach another tenant's subtree.
        let qualified = match binding.site.as_deref() {
            // Explicit site-share → `hblob/{project}/{site}/`, byte-identical to the host binding's
            // `(project, site)` prefix. Fail CLOSED on a malformed site name (defense-in-depth
            // behind the set-time existence + authz gate; the project is still the workload's own,
            // so even a slipped-through bad site can only ever name WITHIN this tenant).
            Some(site) => {
                if validate_resource_name("site", site).is_err() {
                    tracing::warn!(
                        %project, %workload, site = %site,
                        "blob binding: invalid site name; binding skipped (fail closed)"
                    );
                    return None;
                }
                proj.qualified(site)
            }
            // No explicit site → the RESERVED compute namespace `hblob/{project}/_compute/{workload}/`
            // (the `_compute` segment can never be a site, so this is disjoint from every site tape).
            None => format!("{}/{workload}", proj.qualified(COMPUTE_RESERVED_SEGMENT)),
        };
        Some(BlobScope {
            storage,
            site_prefix: format!("hblob/{qualified}/"),
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

    async fn contribute(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        _env: &std::collections::BTreeMap<String, String>,
    ) -> SurfaceContribution {
        // PLAN-compute-managed-resources Phase 3: contribute the `{{blob.*}}` namespace. TWO layers:
        //   (1) the HMAC shim (always) — `{{blob.url}}`/`{{blob.token}}` + the back-compat
        //       `BOATRAMP_BLOB_URL`(+`_AUTH_TOKEN`) defaults — the registry-backed bearer `resolve`
        //       mints, revoked-on-stop via `release`; the full R/W namespace.
        //   (2) direct-S3 STS (a `--bind blob:<container>` + a wired minter) — real
        //       `TempCredentials` an off-the-shelf S3 client uses to talk DIRECTLY to R2/Tigris,
        //       surfaced as `{{blob.endpoint/region/bucket/access_key/secret/session_token/prefix}}`
        //       + `AWS_*` defaults. STS creds are stateless-verifiable (cannot be actively revoked),
        //       so they LET-EXPIRE at the lease TTL; the HMAC token is the revoke-on-stop fallback.
        let mut out = SurfaceContribution::default();
        let blob_bindings: Vec<&ComputeBinding> = bindings
            .iter()
            .filter(|b| b.kind == BindingKind::Blob)
            .collect();
        let single = blob_bindings.len() == 1;
        for binding in blob_bindings {
            let Some(scope) = self.scope(project, workload, binding) else {
                continue;
            };
            let token = self.token(project, workload, replica, binding);
            self.shim.register(&token, scope).await;
            let url_env = binding.url_env();
            out.defaults.push((url_env.clone(), self.base_url.clone()));
            out.defaults
                .push((format!("{url_env}_AUTH_TOKEN"), token.clone()));
            if binding.name.is_empty() || single {
                out.vars
                    .insert("blob.url".to_string(), self.base_url.clone());
                out.vars.insert("blob.token".to_string(), token.clone());
            }
            if !binding.name.is_empty() {
                out.vars
                    .insert(format!("blob.{}.url", binding.name), self.base_url.clone());
                out.vars
                    .insert(format!("blob.{}.token", binding.name), token.clone());
            }
            #[cfg(feature = "blob-upload")]
            self.contribute_blob_sts(project, workload, binding, single, &mut out)
                .await;
        }
        out
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

#[cfg(feature = "blob-upload")]
impl BlobShimResolver {
    /// Mint direct-S3 `TempCredentials` for a `--bind blob:<container>` and contribute the
    /// `{{blob.*}}` STS vars + `AWS_*` default env, so an off-the-shelf S3 client talks DIRECTLY
    /// to R2/Tigris. A bare `--bind blob` (no container) stays HMAC-only; so does any backend with
    /// no real STS minter wired, a mint failure, or a presigned-only return — all FALL BACK to the
    /// HMAC shim (never panic). NEVER logs the minted secret / session token (a `TempCredentials`
    /// is read field-by-field into the var/default maps, never `{:?}`-printed).
    async fn contribute_blob_sts(
        &self,
        project: &str,
        workload: &str,
        binding: &ComputeBinding,
        single: bool,
        out: &mut SurfaceContribution,
    ) {
        use boatramp_handlers::{
            MintScope, MintedCredentials, TempCredentials, UploadConstraints, UploadPerm,
            UploadTarget, screen_upload_target,
        };
        let Some((minter, max_ttl_secs, max_bytes_ceiling)) = &self.blob_minter else {
            return;
        };
        // Posture-off kill switch: a `0` TTL ceiling disables direct-S3 minting entirely — mirror
        // the guest mint path's guard (bindings/blob_upload.rs) so this path fails closed to the
        // HMAC shim regardless of the upstream `set_blob_upload_minting` 0-ceiling drop, rather than
        // relying on that invariant (LOW-1, security review).
        if *max_ttl_secs == 0 {
            return;
        }
        // Direct-S3 needs a concrete container to scope the credential to; a bare `--bind blob`
        // (no container) stays HMAC-only.
        if binding.name.is_empty() {
            return;
        }
        let target = UploadTarget::Prefix(String::new()); // the whole container (no sub-prefix)
        // Defense-in-depth: screen the container/target the SAME way the guest/operator mint path
        // does, even though `scope` already validated the container name. A refusal ⇒ HMAC-only.
        if let Err(e) = screen_upload_target(&binding.name, &target) {
            tracing::warn!(
                %project, %workload, container = %binding.name, error = ?e,
                "blob binding: direct-S3 scope screen refused; falling back to the HMAC shim"
            );
            return;
        }
        let scope = MintScope {
            project: project.to_string(),
            // The SITE is host-forced to the workload name — the SAME per-site identity the shim's
            // `hblob/{qualified-site}/` prefix + a `wasi:blobstore` handler use (never guest-named).
            site: workload.to_string(),
            container: binding.name.clone(),
            target,
            // Direct-S3 is WRITE-scoped (PUT + multipart); the HMAC shim covers reads (GET).
            perms: vec![UploadPerm::Put, UploadPerm::Multipart],
            // Clamp per-object size to the operator ceiling (the SAME ceiling the guest mint
            // path applies) so a compromised/greedy replica cannot write unbounded objects on
            // the direct-S3 path. `None` ⇒ no operator ceiling configured (unbounded, as before).
            constraints: UploadConstraints {
                max_bytes: *max_bytes_ceiling,
                ..UploadConstraints::default()
            },
            // Leased to the replica by a generous wall-clock TTL (the operator ceiling): off-the-
            // shelf apps read creds once at startup, so a short TTL would break them. A relaunch
            // mints fresh creds; the creds LET-EXPIRE on stop — an STS lease CANNOT be actively
            // revoked, so the operator `max_ttl_secs` ceiling IS the containment window: keep it
            // short. (revoke-on-stop cuts the HMAC token + the dynamic DB role, not this lease.)
            ttl_secs: *max_ttl_secs,
        };
        let creds: TempCredentials = match minter.mint(&scope).await {
            Ok(MintedCredentials::TempCredentials(t)) => t,
            Ok(MintedCredentials::PresignedPut(_)) => {
                tracing::warn!(
                    %project, %workload, container = %binding.name,
                    "blob binding: minter returned a presigned PUT (not temp credentials); \
                     direct-S3 env not injected (the HMAC shim still works)"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    %project, %workload, container = %binding.name, error = %e,
                    "blob binding: direct-S3 credential mint failed; falling back to the HMAC shim"
                );
                return;
            }
        };
        // STS template vars (bare + named mirror the HMAC convention). The `prefix` is empty — the
        // credential is scoped to the whole container (the `bucket`).
        let mut put_vars = |ns: &str| {
            out.vars
                .insert(format!("{ns}.endpoint"), creds.endpoint.clone());
            out.vars
                .insert(format!("{ns}.region"), creds.region.clone());
            out.vars
                .insert(format!("{ns}.bucket"), creds.bucket.clone());
            out.vars
                .insert(format!("{ns}.access_key"), creds.access_key_id.clone());
            out.vars
                .insert(format!("{ns}.secret"), creds.secret.clone());
            out.vars
                .insert(format!("{ns}.session_token"), creds.session_token.clone());
            out.vars.insert(format!("{ns}.prefix"), String::new());
        };
        if single {
            put_vars("blob");
        }
        put_vars(&format!("blob.{}", binding.name));
        // The `AWS_*` convention defaults so a stock S3 client Just Works — only for the SINGLE
        // blob binding (multiple would make the unqualified `AWS_*` ambiguous; the operator then
        // templates the named `{{blob.<container>.*}}` vars into whatever env each client reads).
        if single {
            out.defaults
                .push(("AWS_ENDPOINT_URL".to_string(), creds.endpoint.clone()));
            out.defaults
                .push(("AWS_ACCESS_KEY_ID".to_string(), creds.access_key_id.clone()));
            out.defaults
                .push(("AWS_SECRET_ACCESS_KEY".to_string(), creds.secret.clone()));
            out.defaults
                .push(("AWS_SESSION_TOKEN".to_string(), creds.session_token.clone()));
            out.defaults
                .push(("AWS_REGION".to_string(), creds.region.clone()));
            out.defaults
                .push(("BOATRAMP_BLOB_BUCKET".to_string(), creds.bucket.clone()));
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
    mint_slot: BlobMintSlot,
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
    let resolver = BlobShimResolver::new(blob, shim, base_url, secret);
    // Attach the direct-S3 STS minter (PLAN-compute-managed-resources Phase 3), when wired. Without
    // the `blob-upload` feature `mint_slot` is `()` and there is no minter to attach.
    #[cfg(feature = "blob-upload")]
    let resolver = {
        let (minter, max_ttl_secs, max_bytes_ceiling) = match mint_slot {
            Some((m, ttl, ceil)) => (Some(m), ttl, ceil),
            None => (None, 0, None),
        };
        resolver.with_blob_minter(minter, max_ttl_secs, max_bytes_ceiling)
    };
    #[cfg(not(feature = "blob-upload"))]
    let _ = mint_slot;
    Some(Arc::new(resolver))
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
    /// A guest-supplied LIST prefix is not container-relative (`..`/absolute/reserved/…) → 400.
    BadPrefix(String),
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
            Self::BadPrefix(e) => (
                StatusCode::BAD_REQUEST,
                format!("invalid list prefix: {e}\n"),
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
/// backend plus TWO keys composed under that one confined `hblob/{project-qualified-site}/
/// {container}/` prefix — the FINAL object key `…/{container}/{key}` the op acts on, and the
/// container MARKER key `…/{container}/.boatramp-container` a PUT ensures (GET/HEAD/DELETE ignore
/// it) — or a fail-closed [`Denied`].
///
/// The SITE is taken ONLY from `scope.site_prefix` (token-bound), never from any client
/// field, so **cross-site is structurally impossible**; the MARKER key, sharing the same
/// confined prefix, is equally un-escapable. The three anti-hollow mutation seams HERE (test /
/// `compute-blob-shim-gate-mutation` only, compiled out of ships) each neuter ONE enforced check
/// so the CI gate proves it load-bearing: `allow_cross_container` drops the container bind (i),
/// `allow_traversal` drops the key screen (ii), and `admit_unmatched` (in
/// [`BlobShim::authenticate`]) admits an unmatched token (iii). A fourth seam, `skip_marker`, lives
/// on the PUT path ([`put_object`]) and neuters the marker-ensure (iv).
fn authorize(
    scope: Option<&BlobScope>,
    container: &str,
    key: &str,
) -> Result<(Arc<dyn Storage>, String, String), Denied> {
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
    // Compose under the TOKEN's site prefix: the EXACT `hblob/{qualified-site}/{container}/`
    // keyspace a `wasi:blobstore` handler for this site reads/writes. Both the object key and the
    // container MARKER key are composed from this ONE confined prefix — `scope.site_prefix` is
    // token-bound (never a client field) and `container` is bound (i) + validated above — so the
    // marker a PUT ensures can NEVER land outside the token's own site/container (a bare `--bind
    // blob` token stays within its `site_prefix`; a `--bind blob:<container>` token stays in its
    // one container). Returned together so a later composition cannot drift from the enforced one.
    let container_prefix = format!("{}{container}/", scope.site_prefix);
    Ok((
        scope.storage.clone(),
        format!("{container_prefix}{key}"),
        format!("{container_prefix}{CONTAINER_MARKER}"),
    ))
}

/// The LIST analogue of [`authorize`] — the single enforced decision behind `GET /{container}`.
/// Given the token-resolved `scope` and the client-supplied `container` + optional container-relative
/// `prefix`, return the backend, the JOINED storage prefix to list under
/// (`hblob/{project-qualified-site}/{container}/{prefix}`), and the bare
/// `hblob/{project-qualified-site}/{container}/` prefix results are relativized against, or a
/// fail-closed [`Denied`].
///
/// Same fail-closed model as [`authorize`]: the SITE comes ONLY from `scope.site_prefix`
/// (token-bound, never a client field), so a listing can only ever narrow WITHIN the token's own
/// site, and a container-bound token admits ONLY its container — **cross-site and cross-container are
/// structurally impossible**. It shares [`authorize`]'s `allow_cross_container` mutation seam (i) and
/// `allow_traversal` seam (ii, here neutering the defense-in-depth prefix screen so the gate proves
/// the structural join-under-prefix confinement still contains an escaping prefix).
fn authorize_list(
    scope: Option<&BlobScope>,
    container: &str,
    prefix: &str,
) -> Result<(Arc<dyn Storage>, String, String), Denied> {
    // (iii) authentication: no resolved scope ⇒ fail closed.
    let scope = scope.ok_or(Denied::Unauthenticated)?;
    // (i) cross-container: a container-bound token lists ONLY its own container.
    if let Some(bound) = scope.container.as_deref() {
        let permitted =
            bound == container || blob_mutation().as_deref() == Some("allow_cross_container");
        if !permitted {
            return Err(Denied::CrossContainer);
        }
    }
    // The container must be a single safe segment (defense-in-depth, as in `authorize`).
    validate_key_segment("container", container)
        .map_err(|e| Denied::BadContainer(e.to_string()))?;
    // (ii) screen the guest LIST prefix. The LOAD-BEARING confinement is structural — the join UNDER
    // the container prefix below + the strip back in `confine_list_names` — so this screen is
    // defense-in-depth and a clean guest error; `allow_traversal` neuters it so the gate proves the
    // structural confinement alone still contains an escaping prefix.
    if blob_mutation().as_deref() != Some("allow_traversal") {
        screen_list_prefix(prefix).map_err(Denied::BadPrefix)?;
    }
    // Compose under the TOKEN's site+container prefix: list under
    // `hblob/{qualified-site}/{container}/{prefix}`, relativize against
    // `hblob/{qualified-site}/{container}/`.
    let container_prefix = format!("{}{container}/", scope.site_prefix);
    let joined = join_list_prefix(&container_prefix, prefix);
    Ok((scope.storage.clone(), joined, container_prefix))
}

/// Join a screened guest list `prefix` UNDER the host-computed `container_prefix`
/// (`hblob/{site}/{container}/`), so the storage prefix ALWAYS starts with the container prefix and
/// the listing can only ever narrow WITHIN the guest's own container — one half of the structural
/// confinement (the other is [`confine_list_names`]). The direct analogue of the host `blob-list`
/// binding's `join_list_prefix`, kept a pure split so the anti-hollow gate can mutate it directly.
fn join_list_prefix(container_prefix: &str, guest_prefix: &str) -> String {
    // MUTATION SEAM (gate `escape_prefix`): use the guest prefix RAW, so the listing escapes the
    // container (another site's keyspace). Compiled out of shipped builds; the confinement gate then
    // goes RED. Parity with the host `blob-list` binding's same-named seam.
    if blob_mutation().as_deref() == Some("escape_prefix") {
        return guest_prefix.to_string();
    }
    format!("{container_prefix}{guest_prefix}")
}

/// Screen a guest-supplied LIST `prefix` (mirrors the host `blob-list` binding's `screen_list_prefix`):
/// empty is fine (the whole container); otherwise reject a leading `/` (absolute-looking), a `..` path
/// segment, the reserved `.boatramp*` namespace, backslashes, globs, and control bytes. Defense-in-depth
/// only — [`authorize_list`]'s join-under-prefix + [`confine_list_names`]'s strip are the structural
/// confinement, so an escaping prefix that slipped the screen would simply match nothing.
fn screen_list_prefix(prefix: &str) -> Result<(), String> {
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.starts_with('/') {
        return Err("must be container-relative (no leading '/')".to_string());
    }
    if prefix.contains('\0')
        || prefix.contains('\\')
        || prefix.contains('*')
        || prefix.chars().any(char::is_control)
    {
        return Err("contains a control, backslash, or glob character".to_string());
    }
    if prefix.split('/').any(|seg| seg == "..") {
        return Err("'..' path segment".to_string());
    }
    if prefix.starts_with(RESERVED_PREFIX) {
        return Err("reserved namespace".to_string());
    }
    Ok(())
}

/// Whether a container-relative `name` touches the reserved [`RESERVED_PREFIX`] namespace in ANY path
/// segment — the container marker / host staging, never a guest object — so a LIST must drop it.
/// Mirrors the host `blob-list` binding's `is_reserved_name`.
fn is_reserved_name(name: &str) -> bool {
    name.split('/').any(|seg| {
        seg.get(..RESERVED_PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(RESERVED_PREFIX))
    })
}

/// Relativize + confine a raw backend listing page to the guest's container view: STRIP
/// `container_prefix` off each key (→ container-relative, e.g. `sub/c.txt`) and DROP the reserved
/// `.boatramp*` namespace; a key not under `container_prefix` is dropped entirely (the structural
/// guarantee a raw internal / foreign key can never reach the guest). The direct analogue of the host
/// `blob-list` binding's `confine_list_names`. MUTATION SEAMS (test / gate only, compiled out of
/// ships, parity with that host binding): `list_no_strip` returns the raw internal key (leaks the
/// `hblob/…` prefix AND fails to drop a foreign key), and `show_marker` leaks the reserved `.boatramp*`
/// namespace (the container marker + host staging) — each turns the relevant gate assertion RED.
fn confine_list_names(container_prefix: &str, metas: Vec<ObjectMeta>) -> Vec<String> {
    let strip = blob_mutation().as_deref() != Some("list_no_strip");
    let hide_reserved = blob_mutation().as_deref() != Some("show_marker");
    metas
        .into_iter()
        .filter_map(|meta| {
            let name = if strip {
                meta.key.strip_prefix(container_prefix)?.to_string()
            } else {
                meta.key
            };
            (!(hide_reserved && is_reserved_name(&name))).then_some(name)
        })
        .collect()
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

/// Authenticate the request's bearer token and authorize `(container, key)` to a confined
/// storage key. The common prelude of every method handler. Returns `(storage, object_key,
/// marker_key)` — the object key the op acts on, plus the container MARKER key the PUT path
/// ensures (both composed under the token's own confined prefix by [`authorize`]); GET/HEAD/DELETE
/// ignore the marker key.
async fn resolve_target(
    shim: &BlobShim,
    headers: &HeaderMap,
    container: &str,
    key: &str,
) -> Result<(Arc<dyn Storage>, String, String), Response> {
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
    let (storage, skey, _) = match resolve_target(&shim, &headers, &container, &key).await {
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

/// Ensure the container MARKER exists at `marker_key` (idempotent). A boatramp "container" is a key
/// prefix PLUS this marker object, so a `wasi:blobstore` handler's `get-container`/`container-exists`
/// only admits a container whose marker is present; a shim PUT ensures it so a worker-written
/// container is first-class. Probes first so an existing container's marker (and the creation time it
/// records) is never clobbered and an honest PUT skips a redundant write — `NotFound` means "write
/// it", any other backend error propagates. The marker BODY matches what `wasi:blobstore`
/// `create-container` writes — the container's creation time (unix seconds, decimal) — so a
/// worker-created container's `container.info().created-at` reads a real timestamp. `marker_key` is
/// ALREADY composed + confined by [`authorize`]; this function never composes a storage key.
async fn ensure_container_marker(
    storage: &dyn Storage,
    marker_key: &str,
) -> Result<(), StorageError> {
    match storage.head(marker_key).await {
        Ok(_) => Ok(()),
        Err(StorageError::NotFound(_)) => {
            let body = boatramp_core::time::now_unix().to_string();
            let stream: ByteStream =
                futures::stream::once(
                    async move { Ok::<_, StorageError>(bytes::Bytes::from(body)) },
                )
                .boxed();
            storage
                .put(marker_key, stream, PutMeta::default())
                .await
                .map(|_| ())
        }
        Err(err) => Err(err),
    }
}

/// `PUT /{container}/{*key}`: stream the request body into the object, returning the
/// object key on success.
async fn put_object(
    State(shim): State<BlobShim>,
    headers: HeaderMap,
    Path((container, key)): Path<(String, String)>,
    body: Body,
) -> Response {
    let (storage, skey, marker_key) = match resolve_target(&shim, &headers, &container, &key).await
    {
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
    // Ensure the container MARKER exists so a worker-written container is first-class for a guest
    // `wasi:blobstore` handler (whose `get-container` probes the marker). The marker key is composed
    // from the SAME token-confined prefix as the object (see `authorize`), so it can never escape the
    // token's own site/container. Done AFTER the up-front honest-`Content-Length` cap check (so a PUT
    // rejected 413 on declared size leaves NO empty container behind) but BEFORE the object write (so
    // the container is defined whenever the object lands). A dishonest Content-Length that only trips
    // the streaming cap below can still leave the marker — an accepted edge (same keyspace; the worker
    // could create the container anyway), not worth complicating the path. Idempotent (probe-then-
    // write) so an existing container's marker/creation-time is never clobbered and honest PUTs avoid
    // a redundant write. A genuine backend fault surfaces. The `skip_marker` mutation seam (test /
    // `compute-blob-shim-gate-mutation` only; a dead `None` in ships) neuters this ensure so the CI
    // gate proves it load-bearing (a guest `get-container` then fails with `no such container`).
    if blob_mutation().as_deref() != Some("skip_marker")
        && let Err(err) = ensure_container_marker(&*storage, &marker_key).await
    {
        return storage_fault("put", &marker_key, err);
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
    let (storage, skey, _) = match resolve_target(&shim, &headers, &container, &key).await {
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
    let (storage, skey, _) = match resolve_target(&shim, &headers, &container, &key).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match storage.delete(&skey).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => storage_fault("delete", &skey, err),
    }
}

/// Query parameters for the LIST endpoint (`GET /{container}`): an optional container-relative
/// `prefix` filter, an opaque `after` cursor (a prior response's `cursor`, to resume), and a
/// `limit` (clamped to `[1, MAX_LIST_PAGE]`; absent ⇒ a full [`MAX_LIST_PAGE`] page).
#[derive(Deserialize, Default)]
struct ListQuery {
    prefix: Option<String>,
    after: Option<String>,
    limit: Option<u32>,
}

/// The LIST response body: the container-relative object `keys` for this page, plus an OPAQUE
/// `cursor` — `null` once the listing is exhausted, otherwise passed back as `?after=` for the next
/// page. The keys are exactly the names a `wasi:blobstore` `blob-list` handler for the same container
/// returns (container-relative, reserved namespace hidden).
#[derive(Serialize)]
struct ListResponse {
    keys: Vec<String>,
    cursor: Option<String>,
}

/// `GET /{container}[?prefix=&after=&limit=]`: list the object keys under the token's container,
/// optionally narrowed by a container-relative `prefix`, returned container-relative and bounded to
/// one [`MAX_LIST_PAGE`] page (resume with the response `cursor` as `?after=`). The blob analogue of
/// the `wasi:blobstore` `blob-list` host binding — authed by the SAME bearer and confined to the
/// token's site+container, so a token can only ever enumerate WITHIN its own namespace.
async fn list_objects(
    State(shim): State<BlobShim>,
    headers: HeaderMap,
    Path(container): Path<String>,
    Query(q): Query<ListQuery>,
) -> Response {
    let prefix = q.prefix.unwrap_or_default();
    let token = bearer(&headers);
    let scope = shim.authenticate(token.as_deref()).await;
    let (storage, joined, container_prefix) =
        match authorize_list(scope.as_ref(), &container, &prefix) {
            Ok(v) => v,
            Err(denied) => return denied.into_response(),
        };
    let limit = q.limit.unwrap_or(MAX_LIST_PAGE).clamp(1, MAX_LIST_PAGE);
    match storage.list_page(&joined, q.after.as_deref(), limit).await {
        Ok(page) => {
            let keys = confine_list_names(&container_prefix, page.metas);
            Json(ListResponse {
                keys,
                cursor: page.cursor,
            })
            .into_response()
        }
        Err(err) => storage_fault("list", &joined, err),
    }
}

/// The active compute-blob-shim gate mutation (PLAN-compute-bindings anti-hollow gate), or
/// `None`. Present ONLY under `cfg(test)` (the in-crate gate) or the
/// `compute-blob-shim-gate-mutation` feature; a shipped build has neither, so
/// [`authorize`] / [`BlobShim::authenticate`] evaluate every check unconditionally and
/// this is a dead `None`. Each recognized value neuters ONE check so the CI gate can prove
/// it goes RED: `allow_cross_container` (bypass the container bind — GET/PUT/… and LIST),
/// `allow_traversal` (skip the object-key screen, and the LIST prefix screen),
/// `admit_unmatched` (admit a missing/unknown token), `list_no_strip` (LIST returns the raw
/// internal `hblob/{site}/{container}/…` key instead of the container-relative name), `escape_prefix`
/// (LIST joins the guest prefix RAW so it escapes the container), `show_marker` (LIST leaks the
/// reserved `.boatramp*` namespace), `skip_marker` (skip a PUT's container-marker ensure, so a
/// worker-written container is not openable by a guest `get-container`). NOT a backdoor — it only
/// reads a test env var.
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
        /// The `limit` the most recent `list_page` received — lets a test assert the LIST handler's
        /// MAX_LIST_PAGE clamp (`[1, MAX_LIST_PAGE]`) without depending on backend key ordering.
        last_limit: Arc<std::sync::atomic::AtomicU32>,
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
            limit: u32,
        ) -> Result<ListPage, StorageError> {
            self.last_limit
                .store(limit, std::sync::atomic::Ordering::SeqCst);
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

    /// Drive a LIST (`GET /{container}[?…]`) through the real router and parse the JSON body into
    /// `(status, keys, cursor)`. A non-200 yields empty keys (the caller asserts the status).
    async fn list_keys(
        shim: &BlobShim,
        path: &str,
        token: Option<&str>,
    ) -> (StatusCode, Vec<String>, Option<String>) {
        let (status, body) = request(shim, "GET", path, token, b"").await;
        if status != StatusCode::OK {
            return (status, Vec::new(), None);
        }
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        let keys = v["keys"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let cursor = v["cursor"].as_str().map(str::to_string);
        (status, keys, cursor)
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
        ComputeBinding::new(BindingKind::Blob).with_name(name)
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

    /// PLAN-compute-managed-resources Phase 3: with NO minter wired, `contribute` is HMAC-only —
    /// `{{blob.url}}`/`{{blob.token}}` + the back-compat defaults, NO `AWS_*`/STS vars — and the
    /// token is revoked on stop (registry-backed).
    #[tokio::test]
    async fn contribute_without_minter_is_hmac_only_and_revoked_on_stop() {
        let shim = BlobShim::new();
        let storage = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage);
        let bindings = vec![blob_binding("assets")];

        let c = resolver
            .contribute(
                "acme",
                "api",
                0,
                &bindings,
                &std::collections::BTreeMap::new(),
            )
            .await;
        assert_eq!(
            c.vars.get("blob.url").map(String::as_str),
            Some("http://10.0.0.1:8082")
        );
        let token = c.vars.get("blob.token").expect("blob.token var").clone();
        assert_eq!(c.vars.get("blob.assets.token"), Some(&token));
        // No direct-S3 creds without a minter.
        assert!(!c.vars.contains_key("blob.endpoint"));
        assert!(c.defaults.iter().all(|(k, _)| k != "AWS_ACCESS_KEY_ID"));
        // Revoke-on-stop: the HMAC token the var carries is invalidated by release.
        let (status, _) = request(&shim, "PUT", "/assets/x", Some(&token), b"z").await;
        assert_eq!(status, StatusCode::OK);
        resolver.release("acme", "api", 0, &bindings).await;
        let (status, _) = request(&shim, "PUT", "/assets/x", Some(&token), b"z").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn default_namespace_is_reserved_under_the_project() {
        // A `blob` binding with NO explicit site lands in the workload's PRIVATE reserved compute
        // namespace `hblob/{project}/_compute/{workload}/…` — NOT the same-named site's tape. The
        // project segment is the workload's own (here the NAMED project `acme`).
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
                .contains_key("hblob/acme/_compute/api/assets/x.bin"),
            "a no-site binding lands under the reserved hblob/{{project}}/_compute/{{workload}}/…"
        );
    }

    #[test]
    fn default_namespace_segment_is_never_a_valid_site() {
        // The load-bearing safety of the convention-drop: the reserved `_compute` segment can NEVER
        // be a site name (a site must be a valid resource slug, which rejects a leading `_`), so the
        // compute keyspace `hblob/{project}/_compute/…` is provably disjoint from every site tape.
        assert!(
            !boatramp_core::project::is_valid_resource_slug(COMPUTE_RESERVED_SEGMENT),
            "the reserved compute segment must be unusable as a site name"
        );
    }

    #[tokio::test]
    async fn default_namespace_drops_the_name_match_convention() {
        // A compute workload NAMED EXACTLY like a site (`api`) with a DEFAULT `blob` binding (no
        // explicit site) NO LONGER shares that site's blob tape — it resolves to the disjoint
        // reserved namespace `hblob/default/_compute/api/`. Opting in with `.with_site("api")` IS
        // how a worker reaches the site's tape now.
        let shim = BlobShim::new();
        // Concrete handle so the test can introspect the backing map directly.
        let storage = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage.clone());

        // What a `wasi:blobstore` handler for site `default/api` wrote (its real tape).
        storage
            .put(
                "hblob/default/api/assets/site-owned.bin",
                once_stream(Bytes::from_static(b"site-owned")),
                PutMeta::default(),
            )
            .await
            .unwrap();

        // The compute workload `api` with a DEFAULT (no-site) binding.
        let env = resolver
            .resolve("default", "api", 0, &[blob_binding("assets")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let scope = shim.authenticate(Some(&token)).await.unwrap();
        assert_eq!(
            scope.site_prefix, "hblob/default/_compute/api/",
            "a no-site binding resolves to the reserved compute namespace, NOT the site's tape"
        );

        // The site's object is INVISIBLE to the default-namespace binding (disjoint keyspaces) …
        let (status, _) = request(&shim, "GET", "/assets/site-owned.bin", Some(&token), b"").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a name-matching workload no longer reads the same-named site's tape by default"
        );
        // … and the worker's own write lands under `_compute`, never under the site's tape.
        let (status, _) =
            request(&shim, "PUT", "/assets/worker-owned.bin", Some(&token), b"w").await;
        assert_eq!(status, StatusCode::OK);
        let map = storage.map.lock().unwrap();
        assert!(
            map.contains_key("hblob/default/_compute/api/assets/worker-owned.bin"),
            "the worker's write lands in the reserved compute namespace"
        );
        assert!(
            !map.contains_key("hblob/default/api/assets/worker-owned.bin"),
            "the worker's write must NOT leak into the same-named site's tape"
        );
    }

    #[tokio::test]
    async fn explicit_site_shares_that_sites_tape() {
        // The opt-in: a workload (NOT named `api`) with `.with_site("api")` reaches site `api`'s
        // tape — reading a handler-written object and landing its own writes there, the exact
        // `hblob/{project}/{site}/` namespace a `wasi:blobstore` handler for `(default, api)` sees.
        let shim = BlobShim::new();
        // Concrete handle so the test can introspect the backing map directly.
        let storage = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage.clone());
        storage
            .put(
                "hblob/default/api/assets/site-owned.bin",
                once_stream(Bytes::from_static(b"site-owned")),
                PutMeta::default(),
            )
            .await
            .unwrap();
        let env = resolver
            .resolve(
                "default",
                "worker",
                0,
                &[blob_binding("assets").with_site("api")],
            )
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let scope = shim.authenticate(Some(&token)).await.unwrap();
        assert_eq!(scope.site_prefix, "hblob/default/api/");
        // Reads the site's object …
        let (status, body) =
            request(&shim, "GET", "/assets/site-owned.bin", Some(&token), b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"site-owned");
        // … and its writes land on the site's tape.
        let (status, _) =
            request(&shim, "PUT", "/assets/from-worker.bin", Some(&token), b"w").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            storage
                .map
                .lock()
                .unwrap()
                .contains_key("hblob/default/api/assets/from-worker.bin"),
            "an explicit-site worker's write lands on the site's tape"
        );
    }

    #[tokio::test]
    async fn scope_fails_closed_on_a_malformed_explicit_site() {
        // Defense-in-depth behind the set-time gate: `scope` skips a binding whose explicit site is
        // not a well-formed slug (traversal / reserved `_compute` / empty), so even a hand-crafted
        // spec that slipped a bad site past set time injects NO env rather than resolving somewhere.
        let shim = BlobShim::new();
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage);
        for bad in ["../escape", "_compute", "a/b", ""] {
            let env = resolver
                .resolve(
                    "default",
                    "worker",
                    0,
                    &[blob_binding("assets").with_site(bad)],
                )
                .await;
            assert!(
                env.is_empty(),
                "a malformed explicit site {bad:?} must fail closed (no env injected)"
            );
        }
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
    /// across the three security dimensions + proves the SHARED-NAMESPACE property (including
    /// that a shim PUT makes the container FIRST-CLASS — its MARKER ensured — so a guest
    /// `get-container` → `has-object` → `get-data` reads a worker-written object), and prints
    /// the marker so the merge gate can assert it RAN. MUTATION-VERIFIED: the SAME test re-run
    /// under each `BOATRAMP_COMPUTEBLOB_MUTATION` neuters ONE check and MUST FAIL —
    /// `allow_cross_container` (i: a token scoped to one site/container reaches a different
    /// container), `allow_traversal` (ii: a `../` key escapes the prefix), `admit_unmatched`
    /// (iii: an unauthenticated/mismatched token is admitted), `skip_marker` (iv: a PUT does
    /// not ensure the container marker, so the worker-written container is not guest-openable).
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn compute_blob_shim_scoped_gate() {
        let shim = BlobShim::new();
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage.clone());

        // A workload `worker` that EXPLICITLY shares site `api`'s blob tape
        // (`--bind blob:assets@api`), container-bound to `assets`; project default, so the
        // explicit-site prefix is the two-segment `hblob/default/api/` — the SAME tape a
        // `wasi:blobstore` handler for `(default, api)` sees, even though the workload is NOT named
        // `api`. This exercises the explicit-site shared-namespace path end to end.
        let env = resolver
            .resolve(
                "default",
                "worker",
                0,
                &[blob_binding("assets").with_site("api")],
            )
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
        let (_, key, marker_key) =
            authorize(Some(&scope), "assets", "k").expect("own container admitted");
        assert_eq!(key, "hblob/default/api/assets/k");
        assert!(key.starts_with(&scope.site_prefix));
        // The container MARKER a PUT ensures is composed from the SAME confined prefix as the object
        // key — token-bound `site_prefix` + the bound/validated container — so it can never escape
        // the token's own site/container.
        assert_eq!(marker_key, "hblob/default/api/assets/.boatramp-container");
        assert!(marker_key.starts_with(&scope.site_prefix));
        assert_eq!(
            marker_key,
            format!("{}assets/{CONTAINER_MARKER}", scope.site_prefix)
        );

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

        // ---- CONTAINER MARKER: a worker-written container is FIRST-CLASS for a guest handler ----
        // The shim's own MARKER string must stay byte-identical to the one `boatramp-handlers`
        // actually probes (it is an OPTIONAL dep, so the shim carries its own copy) — a drift would
        // silently break `get-container` for every worker-written container.
        assert_eq!(
            CONTAINER_MARKER,
            boatramp_handlers::CONTAINER_MARKER,
            "the shim's container-marker string drifted from boatramp-handlers' authoritative one"
        );

        // A real shim PUT, then the FULL guest `wasi:blobstore` handoff that REQUIRES the marker:
        // `get-container(container)` (marker probe) → `has-object(key)` → `get-data(key)`. Without
        // the shim's marker-ensure this fails with `no such container` — the bug this fix closes, and
        // the MUTATION that turns this gate RED (revert the marker-ensure ⇒ `get-container` errors).
        let (status, _) = request(
            &shim,
            "PUT",
            "/assets/job-42.bin",
            Some(&token),
            b"artifact-bytes",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let via_container = boatramp_handlers::read_object_through_guest_container(
            storage.clone(),
            "default/api",
            "assets",
            "job-42.bin",
        )
        .await
        .expect(
            "guest get-container → has-object → get-data of a shim-written object \
             (the shim PUT must ensure the container marker)",
        );
        assert_eq!(
            via_container, b"artifact-bytes",
            "the worker-written object reads back through the full guest container handoff"
        );

        // The marker landed at EXACTLY the token-confined key, and its BODY matches what
        // `create-container` writes — the container's creation time (decimal unix seconds) — so a
        // worker-created container reports a real `created-at` to a guest handler.
        let marker = storage
            .get("hblob/default/api/assets/.boatramp-container")
            .await
            .expect("container marker written under the token's own site/container prefix");
        let mut marker_body = marker.body;
        let mut marker_bytes = Vec::new();
        while let Some(chunk) = marker_body.next().await {
            marker_bytes.extend_from_slice(&chunk.unwrap());
        }
        let created_at: u64 = String::from_utf8_lossy(&marker_bytes)
            .parse()
            .expect("marker body is a decimal unix-seconds creation time (create-container shape)");
        assert!(created_at > 0, "the marker records a real creation time");

        // Marker CONFINEMENT: a cross-container PUT is refused AND writes NO marker — the marker-ensure
        // runs only AFTER `authorize` admits the container, so the fix never creates a marker for an
        // unauthorized container, and the ONLY marker in the store is the token's own.
        let (status, _) = request(&shim, "PUT", "/secrets/x", Some(&token), b"nope").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let mut markers: Vec<String> = storage
            .list("hblob/")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .filter(|k| k.ends_with(CONTAINER_MARKER))
            .collect();
        markers.sort();
        assert_eq!(
            markers,
            vec!["hblob/default/api/assets/.boatramp-container".to_string()],
            "a marker exists ONLY under the token's own site/container (no cross-container leak)"
        );

        // Marker ORDERING: a PUT rejected 413 up front on an honest over-cap `Content-Length` leaves
        // NO marker — the marker-ensure runs only AFTER that fast-path check, so an oversized PUT does
        // not create an empty container. (A small-cap shim + fresh store so the marker cannot pre-exist.)
        let capped = BlobShim::new().with_max_object_bytes(4);
        let cap_store: Arc<dyn Storage> = Arc::new(MemStorage::default());
        // Build the resolver inline (the `resolver` helper is shadowed by the local above).
        let cap_resolver = BlobShimResolver::new(
            Arc::new(GlobalBlobBackend::new(cap_store.clone())),
            capped.clone(),
            "http://10.0.0.1:8082".to_string(),
            [9u8; 32],
        );
        let cap_env = cap_resolver
            .resolve(
                "default",
                "worker",
                0,
                &[blob_binding("assets").with_site("api")],
            )
            .await;
        let cap_token = cap_env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let oversize_put = Request::builder()
            .method("PUT")
            .uri("/assets/too-big.bin")
            .header("authorization", format!("Bearer {cap_token}"))
            .header("content-length", "999")
            .body(Body::from(Vec::new()))
            .unwrap();
        let resp = capped.router().oneshot(oversize_put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            cap_store
                .head("hblob/default/api/assets/.boatramp-container")
                .await
                .is_err(),
            "a PUT rejected 413 up front on Content-Length must leave no container marker"
        );

        println!("COMPUTE BLOB-SHIM SCOPED OK");
    }

    /// **CI mutation gate** (PLAN-compute-bindings anti-hollow, marker `COMPUTE BLOB-SHIM LIST
    /// SCOPED OK`). Drives the ENFORCED LIST decision (`authorize_list` + `confine_list_names` +
    /// `BlobShim::authenticate`) through the REAL `GET /{container}` route, and proves the positive
    /// behavior (keys returned container-relative; the reserved namespace + a foreign site + another
    /// container never surface; a `prefix` filter narrows). MUTATION-VERIFIED: the SAME test re-run
    /// under each `BOATRAMP_COMPUTEBLOB_MUTATION` neuters ONE check and MUST FAIL —
    /// `allow_cross_container` (an `assets`-bound token LISTs a DIFFERENT container),
    /// `allow_traversal` (a `../` list prefix escapes the container), `admit_unmatched` (an
    /// unauthenticated LIST is admitted), `list_no_strip` (the raw internal key leaks instead of the
    /// container-relative name), `escape_prefix` (the guest list prefix joins RAW so the `prefix=sub/`
    /// narrowing matches nothing — the join confinement is load-bearing), `show_marker` (the reserved
    /// `.boatramp*` marker surfaces). A pass-under-mutation (a hollow gate) fails the merge.
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn compute_blob_shim_list_scoped_gate() {
        let shim = BlobShim::new();
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let resolver = resolver(&shim, storage.clone());

        // Workload `worker`, container `assets`, EXPLICITLY sharing site `api` (`blob:assets@api`),
        // project default ⇒ prefix hblob/default/api/ (the site's tape, not the workload's name).
        let env = resolver
            .resolve(
                "default",
                "worker",
                0,
                &[blob_binding("assets").with_site("api")],
            )
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();

        // Seed three objects (one nested) under the token's container via the shim PUT.
        for (p, b) in [
            ("/assets/a.txt", &b"1"[..]),
            ("/assets/b.txt", b"2"),
            ("/assets/sub/c.txt", b"3"),
        ] {
            let (s, _) = request(&shim, "PUT", p, Some(&token), b).await;
            assert_eq!(s, StatusCode::OK);
        }
        // And, straight into the backend: the host-written reserved marker, a DIFFERENT container in
        // the SAME site, and a DIFFERENT site's object — none may ever surface to the assets token.
        for k in [
            "hblob/default/api/assets/.boatramp-container",
            "hblob/default/api/secrets/s.txt",
            "hblob/default/other/assets/foreign.txt",
        ] {
            storage
                .put(k, once_stream(Bytes::from_static(b"x")), PutMeta::default())
                .await
                .unwrap();
        }

        // ---- positive: LIST returns the container-relative keys ---------------------------------
        let (status, keys, _) = list_keys(&shim, "/assets", Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        for want in ["a.txt", "b.txt", "sub/c.txt"] {
            assert!(
                keys.iter().any(|k| k == want),
                "LIST must return {want:?}; got {keys:?}"
            );
        }
        // Relativized — the raw internal `hblob/…` key is never leaked (bites `list_no_strip`).
        assert!(
            keys.iter().all(|k| !k.starts_with("hblob/")),
            "keys must be container-relative, not raw internal keys: {keys:?}"
        );
        // The reserved marker, another container, and a foreign site are all absent (structural
        // site/container confinement + reserved-namespace hiding).
        assert!(
            keys.iter().all(|k| !k.starts_with(".boatramp")),
            "the reserved namespace must be hidden: {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.contains("foreign")),
            "another site's keys must never surface: {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.contains("secrets") || k == "s.txt"),
            "another container's keys must never surface: {keys:?}"
        );

        // ---- prefix filter narrows --------------------------------------------------------------
        let (status, keys, _) = list_keys(&shim, "/assets?prefix=sub/", Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            keys,
            vec!["sub/c.txt".to_string()],
            "a prefix filter must narrow to the sub/ subtree"
        );

        // ---- (i) cross-container: the assets-bound token must NOT list another container --------
        let (status, _) = request(&shim, "GET", "/secrets", Some(&token), b"").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a container-bound token must refuse to LIST a different container"
        );

        // ---- (ii) a traversal list prefix is refused (the structural confinement's belt) --------
        let (status, _) =
            request(&shim, "GET", "/assets?prefix=../escape", Some(&token), b"").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a '..' list prefix must be refused"
        );

        // ---- (iii) an unauthenticated LIST is refused -------------------------------------------
        let (status, _) = request(&shim, "GET", "/assets", None, b"").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an unauthenticated LIST must be refused"
        );

        println!("COMPUTE BLOB-SHIM LIST SCOPED OK");
    }

    /// The native blob-shim LIST clamps a guest-supplied `?limit=` to `[1, MAX_LIST_PAGE]` before it
    /// reaches the backend (parity with the `wasi:blobstore` `blob-list` host binding's page ceiling):
    /// an over-large limit is capped at `MAX_LIST_PAGE`, a zero one floored at `1`, and an absent one
    /// defaults to the ceiling — so a guest can neither demand an unbounded page nor a zero-size one.
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn compute_blob_shim_list_clamps_the_page_limit() {
        let shim = BlobShim::new();
        let mem = MemStorage::default();
        // Keep a typed handle (shared via the inner `Arc`s) so the test can read back the `limit` the
        // handler actually passed the backend, while the router still sees it as a `dyn Storage`.
        let storage: Arc<dyn Storage> = Arc::new(mem.clone());
        let resolver = resolver(&shim, storage.clone());
        let env = resolver
            .resolve("default", "api", 0, &[blob_binding("assets")])
            .await;
        let token = env
            .iter()
            .find(|(k, _)| k == "BOATRAMP_BLOB_URL_AUTH_TOKEN")
            .map(|(_, v)| v.clone())
            .unwrap();
        let (s, _) = request(&shim, "PUT", "/assets/a.txt", Some(&token), b"1").await;
        assert_eq!(s, StatusCode::OK);

        let seen = || mem.last_limit.load(std::sync::atomic::Ordering::SeqCst);

        // An over-large guest limit is capped at MAX_LIST_PAGE.
        let (status, _, _) = list_keys(&shim, "/assets?limit=99999", Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen(),
            MAX_LIST_PAGE,
            "an over-large ?limit must clamp to MAX_LIST_PAGE"
        );

        // A zero limit is floored at 1 (never a zero-size page).
        let (status, _, _) = list_keys(&shim, "/assets?limit=0", Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen(), 1, "a ?limit=0 must floor to 1");

        // An absent limit defaults to the MAX_LIST_PAGE ceiling.
        let (status, _, _) = list_keys(&shim, "/assets", Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            seen(),
            MAX_LIST_PAGE,
            "an absent ?limit must default to MAX_LIST_PAGE"
        );
    }

    /// A fake [`BlobUploadMinter`] returning fixed `TempCredentials` (bucket = the requested
    /// container), so the direct-S3 wiring is unit-testable without a live S3/STS endpoint.
    #[cfg(feature = "blob-upload")]
    struct FakeBlobMinter;
    #[cfg(feature = "blob-upload")]
    #[async_trait::async_trait]
    impl boatramp_handlers::BlobUploadMinter for FakeBlobMinter {
        async fn mint(
            &self,
            scope: &boatramp_handlers::MintScope,
        ) -> Result<boatramp_handlers::MintedCredentials, String> {
            Ok(boatramp_handlers::MintedCredentials::TempCredentials(
                boatramp_handlers::TempCredentials {
                    access_key_id: "AKIAFAKE".to_string(),
                    secret: "sekret".to_string(),
                    session_token: "sess-tok".to_string(),
                    endpoint: "https://r2.example.com".to_string(),
                    region: "auto".to_string(),
                    bucket: scope.container.clone(),
                    force_path_style: true,
                    expires_at: 9_999_999_999,
                    expires_in_secs: scope.ttl_secs,
                    enforced: Vec::new(),
                    advisory: Vec::new(),
                },
            ))
        }
    }

    #[cfg(feature = "blob-upload")]
    fn resolver_with_minter(shim: &BlobShim, storage: Arc<dyn Storage>) -> BlobShimResolver {
        BlobShimResolver::new(
            Arc::new(GlobalBlobBackend::new(storage)),
            shim.clone(),
            "http://10.0.0.1:8082".to_string(),
            [9u8; 32],
        )
        .with_blob_minter(Some(Arc::new(FakeBlobMinter)), 3600, Some(8 * 1024 * 1024))
    }

    /// Phase 3: a `--bind blob:<container>` with a wired minter ALSO gets direct-S3 `TempCredentials`
    /// — `{{blob.*}}` STS vars + the `AWS_*` convention defaults — WHILE keeping the HMAC shim env.
    #[cfg(feature = "blob-upload")]
    #[tokio::test]
    async fn contribute_mints_direct_s3_temp_credentials_for_a_named_container() {
        let shim = BlobShim::new();
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let resolver = resolver_with_minter(&shim, storage);
        let c = resolver
            .contribute(
                "acme",
                "api",
                0,
                &[blob_binding("assets")],
                &BTreeMap::new(),
            )
            .await;
        // STS template vars (bare + named).
        assert_eq!(
            c.vars.get("blob.endpoint").map(String::as_str),
            Some("https://r2.example.com")
        );
        assert_eq!(c.vars.get("blob.region").map(String::as_str), Some("auto"));
        assert_eq!(
            c.vars.get("blob.bucket").map(String::as_str),
            Some("assets")
        );
        assert_eq!(
            c.vars.get("blob.access_key").map(String::as_str),
            Some("AKIAFAKE")
        );
        assert_eq!(
            c.vars.get("blob.secret").map(String::as_str),
            Some("sekret")
        );
        assert_eq!(
            c.vars.get("blob.session_token").map(String::as_str),
            Some("sess-tok")
        );
        assert_eq!(c.vars.get("blob.prefix").map(String::as_str), Some(""));
        assert_eq!(
            c.vars.get("blob.assets.access_key").map(String::as_str),
            Some("AKIAFAKE")
        );
        // AWS_* convention defaults (single binding) so a stock S3 client Just Works.
        let def = |k: &str| {
            c.defaults
                .iter()
                .find(|(kk, _)| kk == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(def("AWS_ENDPOINT_URL"), Some("https://r2.example.com"));
        assert_eq!(def("AWS_ACCESS_KEY_ID"), Some("AKIAFAKE"));
        assert_eq!(def("AWS_SECRET_ACCESS_KEY"), Some("sekret"));
        assert_eq!(def("AWS_SESSION_TOKEN"), Some("sess-tok"));
        assert_eq!(def("AWS_REGION"), Some("auto"));
        assert_eq!(def("BOATRAMP_BLOB_BUCKET"), Some("assets"));
        // The HMAC shim env is STILL present (back-compat full R/W).
        assert!(def("BOATRAMP_BLOB_URL").is_some());
        assert!(c.vars.contains_key("blob.token"));
    }

    /// **Live gate** (PLAN-compute-managed-resources Phase 3, marker `PHASE3 BLOB STS DIRECT-R2 OK`).
    /// Proves a boatramp-minted blob credential uploads DIRECTLY to R2/Tigris — no shim hop. Set
    /// `BOATRAMP_PHASE3_S3_PUT_URL` to a presigned PUT URL derived from a real workload's injected
    /// direct-S3 creds, e.g. deploy a workload with `--bind blob:<container>`, read its injected
    /// `AWS_ENDPOINT_URL`/`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`/`AWS_REGION`,
    /// then `aws --endpoint-url "$AWS_ENDPOINT_URL" s3 presign "s3://$BUCKET/phase3-probe"`. The gate
    /// does a REAL `PUT` to that URL and asserts success. `#[ignore]` (needs live R2/Tigris); run on
    /// the Linux box. Do NOT run in CI's default lane.
    #[tokio::test]
    #[ignore = "live: set BOATRAMP_PHASE3_S3_PUT_URL to a presigned PUT derived from a workload's injected AWS_* creds; proves direct-to-R2 upload"]
    async fn blob_sts_direct_r2_live() {
        let Ok(put_url) = std::env::var("BOATRAMP_PHASE3_S3_PUT_URL") else {
            panic!(
                "set BOATRAMP_PHASE3_S3_PUT_URL to a presigned PUT URL from a workload's injected \
                 AWS_* creds to run this live gate"
            );
        };
        let resp = reqwest::Client::new()
            .put(&put_url)
            .body(b"phase3-direct-r2".to_vec())
            .send()
            .await
            .expect("PUT to R2/Tigris with the minted credential");
        assert!(
            resp.status().is_success(),
            "direct-to-R2 upload with the boatramp-minted credential must succeed; got {}",
            resp.status()
        );
        println!("PHASE3 BLOB STS DIRECT-R2 OK");
    }

    /// A BARE `--bind blob` (no container) can't scope an STS credential, so even WITH a minter it
    /// falls back to the HMAC shim only — never a panic, never a blank credential.
    #[cfg(feature = "blob-upload")]
    #[tokio::test]
    async fn contribute_bare_blob_binding_falls_back_to_hmac_even_with_a_minter() {
        let shim = BlobShim::new();
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let resolver = resolver_with_minter(&shim, storage);
        let c = resolver
            .contribute("acme", "api", 0, &[blob_binding("")], &BTreeMap::new())
            .await;
        assert!(
            !c.vars.contains_key("blob.endpoint"),
            "no STS for a bare binding"
        );
        assert!(c.defaults.iter().all(|(k, _)| k != "AWS_ACCESS_KEY_ID"));
        assert!(c.vars.contains_key("blob.url"), "HMAC var still present");
    }
}
