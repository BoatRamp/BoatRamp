//! Content-addressed deployments with atomic activation.
//!
//! A **deployment** is an immutable [`Manifest`] mapping site paths to content
//! hashes. File contents ("blobs") are stored once, keyed by their SHA-256, in
//! a [`Storage`] backend; the manifest and the per-site "current" pointer live
//! in a [`KvStore`].
//!
//! Publishing is therefore:
//! 1. upload any blobs the server is missing (dedup is automatic — identical
//!    bytes share a key),
//! 2. store the manifest, and
//! 3. atomically point the site at it.
//!
//! Because the pointer write is a single atomic KV operation, a reader always
//! sees either the previous deployment or the new one in full — never a
//! half-published mix. Rollback is just pointing the site at an older manifest.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use sha2::{Digest, Sha256};

use crate::config::SiteConfig;
use crate::domain_verify::{DomainVerification, VerificationMethod};
use crate::error::DeployError;
use crate::kv::{KvStore, WriteOp};
use crate::{ByteStream, GetObject, PutMeta, Storage, StorageError};

// The per-file descriptor, its precompressed variants, the immutable
// content-addressed `Manifest`, and `sha256_hex` are wasm-clean wire types in
// `boatramp-types` (so the edge Worker + web console share one definition);
// re-exported so `boatramp_core::deploy::{FileEntry, Variant, Manifest,
// sha256_hex}` are unchanged. `Manifest`'s methods now return `ConfigError`,
// which converts to `DeployError` via the existing `From` at `?` sites.
pub use boatramp_types::file::{FileEntry, Variant};
pub use boatramp_types::manifest::{sha256_hex, Manifest};

// The deployment **wire structs** — provenance metadata, activation history,
// and the GC/scrub reports — are pure serde wire types in `boatramp-types` (so
// the server, CLI, and web console share one definition); re-exported so
// `boatramp_core::deploy::{DeployMeta, …, ScrubReport}` are unchanged. The
// `DeployStore` plumbing below that produces them stays here.
pub use boatramp_types::deploy::{
    BlobMismatch, BlobReadError, DeployMeta, DeployMetaInput, DeploymentList, GcReport,
    HistoryEntry, ScrubReport,
};

/// Tuning for a garbage-collection pass: a safety grace window plus a retention
/// policy. The defaults are conservative — no retention pressure (all history is
/// kept) and no grace window — so callers opt into pruning aggressiveness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcOptions {
    /// Never collect a manifest first-seen within this many seconds, even if it
    /// is unreferenced. This protects an in-flight deploy whose blobs/manifest
    /// are uploaded but not yet activated (so not yet reachable from history).
    pub grace_secs: u64,
    /// Keep at most this many most-recent history entries per site as
    /// retention-protected (beyond `current` and aliases, which are always
    /// kept). `None` keeps the entire history.
    pub keep_last: Option<usize>,
    /// Also keep any history entry activated within this many seconds, even
    /// beyond `keep_last`. `None` applies no age-based retention.
    pub keep_age_secs: Option<u64>,
}

/// Most recent activations retained per site.
const MAX_HISTORY: usize = 100;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Canonicalize a routing host: trimmed, no trailing dot, lower-cased. Host names
/// are case-insensitive and a trailing dot is a legal FQDN form, so the routing
/// index — and the host-uniqueness guard that protects it — must key on one
/// canonical form. Otherwise a case- or dot-variant (`Example.com`, `example.com.`)
/// would write a *second* `domain/<host>` entry and slip past the hijack guard,
/// then route real traffic when a client sends that exact `Host`.
fn canon_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `key` is a sharded blob key (`ab/<64 hex>`). Used so GC never
/// touches objects it did not write, even in a shared bucket.
fn is_blob_key(key: &str) -> bool {
    match key.split_once('/') {
        Some((shard, hash)) => {
            shard.len() == 2
                && hash.len() == 64
                && shard.bytes().all(|b| b.is_ascii_hexdigit())
                && hash.bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Ties a blob [`Storage`] to a metadata [`KvStore`] to provide
/// content-addressed deployments and atomic activation.
#[derive(Clone)]
pub struct DeployStore {
    storage: Arc<dyn Storage>,
    kv: Arc<dyn KvStore>,
    /// Serializes host-claim read-modify-writes on the domain routing index
    /// (`set_site_config` / `attach_verified_domain`), so a `domain/<host>`
    /// mapping can't be checked-then-overwritten across an `await` and one site
    /// can't race in to hijack another's domain. Process-local: airtight on a
    /// single node; a Raft cluster needs the same as a consensus-level
    /// conditional (noted on [`set_site_config`](Self::set_site_config)).
    domain_claim_lock: Arc<futures::lock::Mutex<()>>,
}

impl DeployStore {
    /// Build a deploy store over a blob `storage` and a metadata `kv`.
    pub fn new(storage: Arc<dyn Storage>, kv: Arc<dyn KvStore>) -> Self {
        Self {
            storage,
            kv,
            domain_claim_lock: Arc::new(futures::lock::Mutex::new(())),
        }
    }

    /// Readiness probe: confirm the metadata backend is reachable with a cheap
    /// read (a missing key is fine — it still proves the backend answered). The
    /// blob backend is exercised per-request rather than probed here.
    pub async fn ready(&self) -> Result<(), DeployError> {
        self.kv.get("__readyz_probe__").await?;
        Ok(())
    }

    fn manifest_key(id: &str) -> String {
        format!("manifests/{id}")
    }

    fn meta_key(id: &str) -> String {
        format!("meta/{id}")
    }

    fn current_key(site: &str) -> String {
        format!("current/{site}")
    }

    fn alias_key(site: &str, name: &str) -> String {
        format!("alias/{site}/{name}")
    }

    fn alias_prefix(site: &str) -> String {
        format!("alias/{site}/")
    }

    /// Sharded blob key, e.g. `ab/abcdef...`, to avoid one huge directory.
    fn blob_key(hash: &str) -> String {
        if hash.len() >= 2 {
            format!("{}/{}", &hash[..2], hash)
        } else {
            hash.to_string()
        }
    }

    /// Store a manifest (idempotent) and return its deployment id.
    pub async fn put_manifest(&self, manifest: &Manifest) -> Result<String, DeployError> {
        self.put_manifest_with(manifest, DeployMetaInput::default())
            .await
    }

    /// Store a manifest (idempotent) and record/refresh its [`DeployMeta`].
    ///
    /// `created_at` is set on first store and preserved across re-deploys of the
    /// same content (so the GC grace window measures true age); sizes are
    /// recomputed from the manifest, and the client-supplied provenance fields
    /// are merged in (a later deploy of identical content can update its source/
    /// message without resetting `created_at`).
    pub async fn put_manifest_with(
        &self,
        manifest: &Manifest,
        input: DeployMetaInput,
    ) -> Result<String, DeployError> {
        let id = manifest.id()?;

        // Compute the metadata first (it merges with any prior record), then
        // commit the manifest and its metadata together: one durable flush,
        // and a reader never sees the manifest without its companion meta.
        let existing = self.get_meta(&id).await?;
        let created_at = existing
            .as_ref()
            .map(|m| m.created_at)
            .unwrap_or_else(unix_now);
        let meta = DeployMeta {
            version: crate::SCHEMA_VERSION,
            created_at,
            file_count: manifest.files.len() as u64,
            total_size: manifest.files.values().map(|entry| entry.size).sum(),
            source: input
                .source
                .or_else(|| existing.as_ref().and_then(|m| m.source.clone())),
            branch: input
                .branch
                .or_else(|| existing.as_ref().and_then(|m| m.branch.clone())),
            author: input
                .author
                .or_else(|| existing.as_ref().and_then(|m| m.author.clone())),
            message: input
                .message
                .or_else(|| existing.as_ref().and_then(|m| m.message.clone())),
        };
        self.kv
            .write_batch(vec![
                WriteOp::Put(Self::manifest_key(&id), manifest.to_bytes()?),
                WriteOp::Put(Self::meta_key(&id), serde_json::to_vec(&meta)?),
            ])
            .await?;
        Ok(id)
    }

    /// Fetch a deployment's [`DeployMeta`], if recorded.
    pub async fn get_meta(&self, id: &str) -> Result<Option<DeployMeta>, DeployError> {
        match self.kv.get(&Self::meta_key(id)).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Fetch a manifest by deployment id.
    pub async fn get_manifest(&self, id: &str) -> Result<Option<Manifest>, DeployError> {
        match self.kv.get(&Self::manifest_key(id)).await? {
            Some(bytes) => Ok(Some(Manifest::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Resolve a deployment-id **prefix** to the one full id it uniquely names
    /// (an exact id resolves to itself). Used for the wildcard preview host form
    /// `<id>.deploy.<host>`, where the id rides as a DNS label — capped at 63
    /// chars, shorter than a full 64-hex content hash — so operators use a
    /// prefix. Returns `None` if nothing matches; `Err(Ambiguous)` if the prefix
    /// is not unique (the caller should treat that as not-found).
    pub async fn resolve_manifest_id(&self, prefix: &str) -> Result<Option<String>, DeployError> {
        // Exact hit first (the common case; avoids a scan).
        if self.kv.get(&Self::manifest_key(prefix)).await?.is_some() {
            return Ok(Some(prefix.to_string()));
        }
        let key_prefix = Self::manifest_key(prefix);
        let strip = "manifests/".len();
        let keys = self.kv.list_prefix(&key_prefix).await?;
        let mut ids = keys.iter().map(|key| &key[strip..]);
        match (ids.next(), ids.next()) {
            (Some(only), None) => Ok(Some(only.to_string())),
            (Some(_), Some(_)) => Err(DeployError::Ambiguous(prefix.to_string())),
            _ => Ok(None),
        }
    }

    /// Whether a blob with `hash` is already stored.
    pub async fn has_blob(&self, hash: &str) -> Result<bool, DeployError> {
        match self.storage.head(&Self::blob_key(hash)).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound(_)) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    /// The blob hashes from `manifest` that the store is missing.
    pub async fn missing_blobs(&self, manifest: &Manifest) -> Result<Vec<String>, DeployError> {
        let mut missing = Vec::new();
        for hash in manifest.blob_hashes() {
            if !self.has_blob(&hash).await? {
                missing.push(hash);
            }
        }
        Ok(missing)
    }

    /// Stream a blob into storage, verifying it hashes to `hash`.
    ///
    /// The bytes are hashed as they pass through to the backend (never fully
    /// buffered). A mismatch deletes the partial blob and errors.
    pub async fn put_blob(&self, hash: &str, body: ByteStream) -> Result<(), DeployError> {
        let hasher = Arc::new(Mutex::new(Sha256::new()));
        let tap = hasher.clone();
        let verified: ByteStream = body
            .map(move |chunk| {
                if let Ok(bytes) = &chunk {
                    tap.lock().unwrap().update(bytes);
                }
                chunk
            })
            .boxed();

        let key = Self::blob_key(hash);
        self.storage.put(&key, verified, PutMeta::default()).await?;

        let actual = hex::encode(hasher.lock().unwrap().clone().finalize());
        if actual != hash {
            let _ = self.storage.delete(&key).await;
            return Err(DeployError::HashMismatch {
                expected: hash.to_string(),
                actual,
            });
        }
        Ok(())
    }

    /// Open a blob for streaming reads.
    pub async fn open_blob(&self, hash: &str) -> Result<GetObject, DeployError> {
        Ok(self.storage.get(&Self::blob_key(hash)).await?)
    }

    /// Open a byte range of a blob for streaming reads (HTTP `Range`).
    pub async fn open_blob_range(
        &self,
        hash: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, DeployError> {
        Ok(self
            .storage
            .get_range(&Self::blob_key(hash), offset, len)
            .await?)
    }

    /// The **mutable pointer** for a site: `site/<site>` → the content hash of
    /// its current `SiteConfig`. Tiny; the only key that changes on a config
    /// edit, so it's the only thing the shared-mode invalidation feed must carry.
    fn site_pointer_key(site: &str) -> String {
        format!("site/{site}")
    }

    /// The **immutable, content-addressed** config body:
    /// `siteconfig/<hash>` → the `SiteConfig` JSON. Keyed by its own hash, so it
    /// never changes under a key and is safe to cache forever; identical configs
    /// across sites dedup to one blob.
    fn site_config_blob_key(hash: &str) -> String {
        format!("siteconfig/{hash}")
    }

    fn domain_key(host: &str) -> String {
        format!("domain/{}", canon_host(host))
    }

    fn wildcard_key(suffix: &str) -> String {
        format!("wildcard/{}", canon_host(suffix))
    }

    fn domain_verification_key(site: &str, host: &str) -> String {
        format!(
            "domainverify/{site}/{}",
            crate::domain_verify::normalize_host(host)
        )
    }

    /// Index key mapping an **HTTP challenge** `(host, token)` → its site, so the
    /// unauthenticated self-serve edge route is an O(1) lookup rather than an O(N)
    /// scan of every site's challenges (a flood-amplification vector). The token
    /// is a 128-bit random, so carrying it in the key is safe.
    fn http_challenge_index_key(host: &str, token: &str) -> String {
        format!(
            "httpchallenge/{}/{token}",
            crate::domain_verify::normalize_host(host)
        )
    }

    /// A site's [`SiteConfig`], if it has been set. Reads the `site/<site>`
    /// pointer, then the immutable `siteconfig/<hash>` body it names.
    pub async fn get_site_config(&self, site: &str) -> Result<Option<SiteConfig>, DeployError> {
        let Some(hash) = self.kv.get(&Self::site_pointer_key(site)).await? else {
            return Ok(None);
        };
        let hash = String::from_utf8_lossy(&hash).into_owned();
        match self.kv.get(&Self::site_config_blob_key(&hash)).await? {
            Some(bytes) => Ok(Some(SiteConfig::from_json(&bytes)?)),
            // A dangling pointer (body GC'd out from under it) reads as unset.
            None => Ok(None),
        }
    }

    /// Store a site's [`SiteConfig`] and rebuild its host → site index entries
    /// (so `resolve_site_by_host` can route by `Host`).
    ///
    /// Content-addressed: the config body is written
    /// once under `siteconfig/<hash>` (immutable, dedup'd) and the mutable
    /// `site/<site>` pointer is flipped to it. Only the tiny pointer changes, so
    /// the shared-mode invalidation surface is the pointer, not the body. The
    /// whole change (drop old index, write body, flip pointer, write new index)
    /// commits as one atomic batch.
    ///
    /// **Host uniqueness (hijack guard):** a host — or wildcard suffix — already
    /// mapped to a *different* site is refused with [`DeployError::Conflict`]
    /// rather than silently overwritten. Without this, any site-writer could
    /// point another site's live domain at their own site (last-writer-wins
    /// takeover). The read-check and the write are serialized by a process-local
    /// lock so they can't be interleaved across an `await`. This is airtight on a
    /// single node; a Raft cluster holds it per node, and a cross-node claim race
    /// would additionally need a consensus-level conditional apply — a documented
    /// follow-up, not reachable in the dominant single-node topology.
    pub async fn set_site_config(
        &self,
        site: &str,
        config: &SiteConfig,
    ) -> Result<(), DeployError> {
        let _claim = self.domain_claim_lock.lock().await;
        self.set_site_config_locked(site, config).await
    }

    /// [`set_site_config`](Self::set_site_config) assuming the domain-claim lock
    /// is **already held** — so [`attach_verified_domain`](Self::attach_verified_domain)
    /// can extend a config under the same lock without re-entering it (the lock
    /// is not reentrant).
    async fn set_site_config_locked(
        &self,
        site: &str,
        config: &SiteConfig,
    ) -> Result<(), DeployError> {
        // Refuse any host/wildcard already claimed by another site before writing
        // anything (the hijack guard). A host this site already owns, or one that
        // is unclaimed, passes.
        for host in config.domains.exact_hosts() {
            self.ensure_host_claimable(&Self::domain_key(host), host, site)
                .await?;
        }
        for wildcard in &config.domains.wildcards {
            if let Some(suffix) = wildcard.strip_prefix("*.") {
                self.ensure_host_claimable(&Self::wildcard_key(suffix), wildcard, site)
                    .await?;
            }
        }

        let body = config.to_json()?;
        let hash = sha256_hex(&body);

        let mut ops = Vec::new();
        if let Some(old) = self.get_site_config(site).await? {
            for host in old.domains.exact_hosts() {
                ops.push(WriteOp::Delete(Self::domain_key(host)));
            }
            for wildcard in &old.domains.wildcards {
                if let Some(suffix) = wildcard.strip_prefix("*.") {
                    ops.push(WriteOp::Delete(Self::wildcard_key(suffix)));
                }
            }
        }

        // Immutable body (idempotent put) + the mutable pointer flip.
        ops.push(WriteOp::Put(Self::site_config_blob_key(&hash), body));
        ops.push(WriteOp::Put(
            Self::site_pointer_key(site),
            hash.into_bytes(),
        ));

        let site_bytes = site.as_bytes().to_vec();
        for host in config.domains.exact_hosts() {
            ops.push(WriteOp::Put(Self::domain_key(host), site_bytes.clone()));
        }
        for wildcard in &config.domains.wildcards {
            if let Some(suffix) = wildcard.strip_prefix("*.") {
                ops.push(WriteOp::Put(Self::wildcard_key(suffix), site_bytes.clone()));
            }
        }
        self.kv.write_batch(ops).await?;
        Ok(())
    }

    /// Error with [`DeployError::Conflict`] if index `key` (a `domain/<host>` or
    /// `wildcard/<suffix>` entry) is already held by a site other than `site`.
    /// `label` is the host as written, for the message. Must be called with the
    /// domain-claim lock held.
    async fn ensure_host_claimable(
        &self,
        key: &str,
        label: &str,
        site: &str,
    ) -> Result<(), DeployError> {
        if let Some(bytes) = self.kv.get(key).await? {
            let owner = String::from_utf8_lossy(&bytes);
            if owner != site {
                return Err(DeployError::Conflict(format!(
                    "{label} is already attached to site `{owner}`"
                )));
            }
        }
        Ok(())
    }

    /// Resolve a request `Host` to a site: exact match first, then wildcard
    /// suffixes from most specific to least (so `*.example.com` matches
    /// `a.b.example.com`).
    pub async fn resolve_site_by_host(&self, host: &str) -> Result<Option<String>, DeployError> {
        // Canonicalize once so the `Host` a client sends matches the canonical
        // key written by `set_site_config` regardless of case / trailing dot.
        let host = canon_host(host);
        let host = host.as_str();
        if let Some(bytes) = self.kv.get(&Self::domain_key(host)).await? {
            return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
        }
        let mut rest = host;
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(bytes) = self.kv.get(&Self::wildcard_key(parent)).await? {
                return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
            }
            rest = parent;
        }
        Ok(None)
    }

    /// Every known site name, sorted and de-duplicated. A site is "known" if it
    /// has a current deployment (`current/<site>`), a config (`site/<site>`), or
    /// activation history (`history/<site>`) — so a configured-but-not-yet-
    /// deployed site (or vice versa) still appears. Backs `GET /api/sites`.
    /// (Broader than [`list_sites`](Self::list_sites), which is just the
    /// currently-deployed sites the scheduler runs.)
    pub async fn all_sites(&self) -> Result<Vec<String>, DeployError> {
        let mut sites = BTreeSet::new();
        for prefix in ["current/", "site/", "history/"] {
            for key in self.kv.list_prefix(prefix).await? {
                if let Some(name) = key.strip_prefix(prefix) {
                    if !name.is_empty() {
                        sites.insert(name.to_string());
                    }
                }
            }
        }
        Ok(sites.into_iter().collect())
    }

    // ---- Top-level functions (PLAN-faas FA-2) --------------------------------
    // Independently-versioned functions stored as one JSON record per name under
    // `functions/<name>`, referencing content-addressed component blobs. Reuses the
    // blob store + KV; the deploy/alias immutability model applies (a version id is
    // its component's content hash).

    /// Store a top-level function's record (its versions, active, aliases).
    pub async fn put_function(&self, f: &crate::function::Function) -> Result<(), DeployError> {
        let bytes = serde_json::to_vec(f).map_err(|e| DeployError::Serde(e.to_string()))?;
        self.kv
            .put(&crate::function::keys::meta(&f.name), bytes)
            .await?;
        Ok(())
    }

    /// Load a stored function record, if any.
    pub async fn get_function(
        &self,
        name: &str,
    ) -> Result<Option<crate::function::Function>, DeployError> {
        match self.kv.get(&crate::function::keys::meta(name)).await? {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| DeployError::Serde(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// List all stored (top-level) functions.
    ///
    /// Only the `functions/<name>` *meta* keys are function records; the
    /// `functions/<name>/{versions,alias,triggers,invocations,idem}/…` sub-keys
    /// are skipped by requiring the suffix to hold no further `/`.
    pub async fn list_stored_functions(
        &self,
    ) -> Result<Vec<crate::function::Function>, DeployError> {
        let mut out = Vec::new();
        for key in self.kv.list_prefix("functions/").await? {
            if key["functions/".len()..].contains('/') {
                continue;
            }
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(f) = serde_json::from_slice(&bytes) {
                    out.push(f);
                }
            }
        }
        Ok(out)
    }

    /// Delete a stored function. Returns whether it existed. The component blobs
    /// are content-addressed + shared, so they are left to `prune`.
    pub async fn delete_function(&self, name: &str) -> Result<bool, DeployError> {
        let key = crate::function::keys::meta(name);
        let existed = self.kv.get(&key).await?.is_some();
        self.kv.delete(&key).await?;
        Ok(existed)
    }

    // ---- function invocations (FA-3) ---------------------------------------

    /// Persist (create or update) an invocation record.
    pub async fn put_invocation(
        &self,
        inv: &crate::function::Invocation,
    ) -> Result<(), DeployError> {
        let bytes = serde_json::to_vec(inv).map_err(|e| DeployError::Serde(e.to_string()))?;
        self.kv
            .put(
                &crate::function::keys::invocation(&inv.function, &inv.id),
                bytes,
            )
            .await?;
        Ok(())
    }

    /// Load one invocation record, if any.
    pub async fn get_invocation(
        &self,
        function: &str,
        id: &str,
    ) -> Result<Option<crate::function::Invocation>, DeployError> {
        match self
            .kv
            .get(&crate::function::keys::invocation(function, id))
            .await?
        {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(|e| DeployError::Serde(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// List a function's invocation records (queue scan / poll listing).
    pub async fn list_invocations(
        &self,
        function: &str,
    ) -> Result<Vec<crate::function::Invocation>, DeployError> {
        let prefix = crate::function::keys::invocations_prefix(function);
        let mut out = Vec::new();
        for key in self.kv.list_prefix(&prefix).await? {
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(inv) = serde_json::from_slice(&bytes) {
                    out.push(inv);
                }
            }
        }
        Ok(out)
    }

    /// Bind an idempotency key to an invocation id (the dedup pointer). The value
    /// is the raw invocation id.
    pub async fn put_idempotency(
        &self,
        function: &str,
        key: &str,
        invocation_id: &str,
    ) -> Result<(), DeployError> {
        self.kv
            .put(
                &crate::function::keys::idempotency(function, key),
                invocation_id.as_bytes().to_vec(),
            )
            .await?;
        Ok(())
    }

    /// Resolve an idempotency key to its invocation id, if one was recorded.
    pub async fn get_idempotency(
        &self,
        function: &str,
        key: &str,
    ) -> Result<Option<String>, DeployError> {
        match self
            .kv
            .get(&crate::function::keys::idempotency(function, key))
            .await?
        {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    /// The ownership-verification challenge for `(site, host)`, if one exists.
    pub async fn get_domain_verification(
        &self,
        site: &str,
        host: &str,
    ) -> Result<Option<DomainVerification>, DeployError> {
        match self
            .kv
            .get(&Self::domain_verification_key(site, host))
            .await?
        {
            Some(bytes) => Ok(Some(DomainVerification::from_json(&bytes)?)),
            None => Ok(None),
        }
    }

    /// All ownership challenges for `site` (pending and verified), by host.
    pub async fn list_domain_verifications(
        &self,
        site: &str,
    ) -> Result<Vec<DomainVerification>, DeployError> {
        let prefix = format!("domainverify/{site}/");
        let mut out = Vec::new();
        for key in self.kv.list_prefix(&prefix).await? {
            if let Some(bytes) = self.kv.get(&key).await? {
                out.push(DomainVerification::from_json(&bytes)?);
            }
        }
        out.sort_by(|a, b| a.host.cmp(&b.host));
        Ok(out)
    }

    /// Find a **pending HTTP** ownership challenge matching `(host, token)`
    /// across every site — the lookup behind the self-serve edge route
    /// `/.well-known/boatramp-domain-verification/<token>`. Matches on the
    /// normalized host, the HTTP method, an exact token match, and a non-expired
    /// challenge (`now_unix` gates the TTL), so a host pointed at this server can
    /// prove ownership before it is attached and deployed — closing the
    /// verify-before-attach chicken-and-egg. Returns the challenge so the caller
    /// can echo its token back.
    pub async fn find_pending_http_challenge(
        &self,
        host: &str,
        token: &str,
        now_unix: u64,
    ) -> Result<Option<DomainVerification>, DeployError> {
        let host = crate::domain_verify::normalize_host(host);
        // O(1): the `(host, token)` index names the owning site directly. Then
        // load and **fully re-validate** the challenge — so a stale index entry
        // (left by a method change / new token) can never serve the wrong thing.
        let Some(site_bytes) = self
            .kv
            .get(&Self::http_challenge_index_key(&host, token))
            .await?
        else {
            return Ok(None);
        };
        let site = String::from_utf8_lossy(&site_bytes).into_owned();
        let Some(v) = self.get_domain_verification(&site, &host).await? else {
            return Ok(None);
        };
        if v.method == VerificationMethod::Http
            && v.host == host
            && v.matches(token)
            && !v.is_expired(now_unix)
        {
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    async fn put_domain_verification(
        &self,
        site: &str,
        verification: &DomainVerification,
    ) -> Result<(), DeployError> {
        let mut ops = vec![WriteOp::Put(
            Self::domain_verification_key(site, &verification.host),
            verification.to_json()?,
        )];
        // Maintain the self-serve `(host, token)` index for HTTP challenges. A
        // stale entry left by a later method/token change is harmless — the
        // lookup re-validates the loaded challenge — so no delete-on-replace is
        // needed here.
        if verification.method == VerificationMethod::Http {
            ops.push(WriteOp::Put(
                Self::http_challenge_index_key(&verification.host, &verification.token),
                site.as_bytes().to_vec(),
            ));
        }
        self.kv.write_batch(ops).await?;
        Ok(())
    }

    // ---- managed-DNS ledger (records boatramp pointed at the server) ----------

    /// The managed-DNS ledger for `(site, host)`, if boatramp has pointed it.
    pub async fn get_managed_dns(
        &self,
        site: &str,
        host: &str,
    ) -> Result<Option<crate::dns_managed::ManagedDns>, DeployError> {
        match self
            .kv
            .get(&crate::dns_managed::dnsmanaged_key(site, host))
            .await?
        {
            Some(bytes) => Ok(Some(crate::dns_managed::ManagedDns::from_json(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Record (create/replace) the managed-DNS ledger entry for a host.
    pub async fn set_managed_dns(
        &self,
        site: &str,
        ledger: &crate::dns_managed::ManagedDns,
    ) -> Result<(), DeployError> {
        self.kv
            .put(
                &crate::dns_managed::dnsmanaged_key(site, &ledger.host),
                ledger.to_json()?,
            )
            .await?;
        Ok(())
    }

    /// Drop a host's managed-DNS ledger entry (after its records are retracted).
    pub async fn remove_managed_dns(&self, site: &str, host: &str) -> Result<(), DeployError> {
        self.kv
            .delete(&crate::dns_managed::dnsmanaged_key(site, host))
            .await?;
        Ok(())
    }

    /// All managed-DNS ledger entries for `site` (the reconcile sweep reads these
    /// to retract records whose host is no longer attached).
    pub async fn list_managed_dns(
        &self,
        site: &str,
    ) -> Result<Vec<crate::dns_managed::ManagedDns>, DeployError> {
        let prefix = crate::dns_managed::dnsmanaged_site_prefix(site);
        let mut out = Vec::new();
        for key in self.kv.list_prefix(&prefix).await? {
            if let Some(bytes) = self.kv.get(&key).await? {
                out.push(crate::dns_managed::ManagedDns::from_json(&bytes)?);
            }
        }
        out.sort_by(|a, b| a.host.cmp(&b.host));
        Ok(out)
    }

    /// Start (or restart) an ownership challenge for `(site, host)`.
    ///
    /// Returns the existing challenge if one is already pending under the same
    /// method (so re-running `domain add` shows the same token instead of
    /// invalidating an in-progress setup); otherwise mints a fresh one. A
    /// challenge that's already `verified` is returned untouched.
    pub async fn start_domain_verification(
        &self,
        site: &str,
        host: &str,
        method: VerificationMethod,
        now_unix: u64,
    ) -> Result<DomainVerification, DeployError> {
        if let Some(existing) = self.get_domain_verification(site, host).await? {
            if existing.verified || existing.method == method {
                return Ok(existing);
            }
        }
        let verification = DomainVerification::new(host, method, now_unix);
        self.put_domain_verification(site, &verification).await?;
        Ok(verification)
    }

    /// Whether `(site, host)` has a confirmed ownership challenge.
    pub async fn is_domain_verified(&self, site: &str, host: &str) -> Result<bool, DeployError> {
        Ok(self
            .get_domain_verification(site, host)
            .await?
            .is_some_and(|v| v.verified))
    }

    /// Mark `(site, host)`'s challenge verified and persist it. Errors if no
    /// challenge has been started.
    pub async fn mark_domain_verified(
        &self,
        site: &str,
        host: &str,
    ) -> Result<DomainVerification, DeployError> {
        let mut verification =
            self.get_domain_verification(site, host)
                .await?
                .ok_or_else(|| {
                    DeployError::NotFound(format!("no verification challenge for {host}"))
                })?;
        verification.verified = true;
        self.put_domain_verification(site, &verification).await?;
        Ok(verification)
    }

    /// Drop the verification record for `(site, host)` (when detaching a host).
    /// Returns whether one existed.
    pub async fn remove_domain_verification(
        &self,
        site: &str,
        host: &str,
    ) -> Result<bool, DeployError> {
        let Some(v) = self.get_domain_verification(site, host).await? else {
            return Ok(false);
        };
        let mut ops = vec![WriteOp::Delete(Self::domain_verification_key(site, host))];
        if v.method == VerificationMethod::Http {
            ops.push(WriteOp::Delete(Self::http_challenge_index_key(
                &v.host, &v.token,
            )));
        }
        self.kv.write_batch(ops).await?;
        Ok(true)
    }

    /// Attach a verified `host` to the site's [`SiteConfig`] so it routes by
    /// `Host` and becomes eligible for ACME. The host's *kind* is inferred:
    /// a `*.`-prefixed host is a wildcard; otherwise it becomes the primary if
    /// the site has none, else an alias.
    ///
    /// Refuses an unverified host — this is the server-enforced gate that keeps
    /// unowned domains out of routing and out of cert issuance. (The wildcard /
    /// primary base name is verified; see [`normalize_host`].)
    ///
    /// [`normalize_host`]: crate::domain_verify::normalize_host
    pub async fn attach_verified_domain(
        &self,
        site: &str,
        host: &str,
    ) -> Result<SiteConfig, DeployError> {
        if !self.is_domain_verified(site, host).await? {
            return Err(DeployError::NotFound(format!(
                "{host} is not verified for {site}; run domain verification first"
            )));
        }
        // A wildcard needs the stronger DNS proof — an HTTP token at the base host
        // proves control of one name, not the whole subtree (ACME requires DNS-01
        // for a wildcard cert for the same reason).
        if host.trim_start().starts_with("*.")
            && self
                .get_domain_verification(site, host)
                .await?
                .map(|v| v.method)
                != Some(VerificationMethod::Dns)
        {
            return Err(DeployError::Conflict(format!(
                "wildcard {host} must be verified via DNS \
                 (an HTTP token proves only the base host, not the subtree)"
            )));
        }
        // Hold the claim lock across the whole read-modify-write so a concurrent
        // attach (to this site or another) can't interleave between our read and
        // the index write. `set_site_config_locked` runs under the same lock.
        let _claim = self.domain_claim_lock.lock().await;
        let mut config = self.get_site_config(site).await?.unwrap_or_default();
        let domains = &mut config.domains;
        if let Some(suffix) = host.strip_prefix("*.") {
            let wildcard = format!("*.{}", suffix.trim_end_matches('.').to_ascii_lowercase());
            if !domains.wildcards.contains(&wildcard) {
                domains.wildcards.push(wildcard);
            }
        } else {
            let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if domains.primary.is_none() {
                domains.primary = Some(host);
            } else if domains.primary.as_deref() != Some(host.as_str())
                && !domains.aliases.contains(&host)
            {
                domains.aliases.push(host);
            }
        }
        self.set_site_config_locked(site, &config).await?;
        Ok(config)
    }

    /// Point a named alias (`staging`, `preview-pr-42`, …) at a deployment id.
    ///
    /// Like [`activate`](Self::activate), this refuses a deployment whose blobs
    /// are not all present, so an alias never resolves to an incomplete deploy.
    /// Aliased deployments are retention-protected from garbage collection.
    pub async fn set_alias(&self, site: &str, name: &str, id: &str) -> Result<(), DeployError> {
        let manifest = self
            .get_manifest(id)
            .await?
            .ok_or_else(|| DeployError::NotFound(format!("deployment {id}")))?;
        let missing = self.missing_blobs(&manifest).await?;
        if !missing.is_empty() {
            return Err(DeployError::Incomplete(missing));
        }
        self.kv
            .put(&Self::alias_key(site, name), id.as_bytes().to_vec())
            .await?;
        Ok(())
    }

    /// Resolve a named alias to its deployment id, if set.
    pub async fn get_alias(&self, site: &str, name: &str) -> Result<Option<String>, DeployError> {
        match self.kv.get(&Self::alias_key(site, name)).await? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    /// Remove a named alias; returns whether one existed.
    pub async fn remove_alias(&self, site: &str, name: &str) -> Result<bool, DeployError> {
        let key = Self::alias_key(site, name);
        let existed = self.kv.get(&key).await?.is_some();
        if existed {
            self.kv.delete(&key).await?;
        }
        Ok(existed)
    }

    /// All of a site's named aliases as `name → deployment id`, sorted by name.
    pub async fn list_aliases(&self, site: &str) -> Result<BTreeMap<String, String>, DeployError> {
        let prefix = Self::alias_prefix(site);
        let mut out = BTreeMap::new();
        for key in self.kv.list_prefix(&prefix).await? {
            if let Some(bytes) = self.kv.get(&key).await? {
                let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
                out.insert(name, String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        Ok(out)
    }

    /// Store metadata for an issued token (`authz/tokens/<id>`). The
    /// token itself is never stored — only this record, for `token ls`.
    /// Minting needs the root private key, so it happens in the
    /// caller (the API route / CLI), which then records the metadata here.
    pub async fn put_token_meta(&self, meta: &crate::authz::TokenMeta) -> Result<(), DeployError> {
        self.kv
            .put(
                &crate::authz::token_meta_key(&meta.revocation_id),
                serde_json::to_vec(meta)?,
            )
            .await?;
        Ok(())
    }

    /// List metadata for all issued, non-revoked tokens.
    pub async fn list_token_meta(&self) -> Result<Vec<crate::authz::TokenMeta>, DeployError> {
        let mut out = Vec::new();
        for key in self.kv.list_prefix(crate::authz::TOKEN_META_PREFIX).await? {
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(meta) = serde_json::from_slice::<crate::authz::TokenMeta>(&bytes) {
                    out.push(meta);
                }
            }
        }
        Ok(out)
    }

    /// Revoke an issued token by its revocation id (or a unique id prefix):
    /// write the `authz/revoked/<id>` marker and drop its metadata. Returns
    /// whether a matching token was found. The marker makes every node deny the
    /// token (and its attenuations) on the next request.
    pub async fn revoke_token(&self, id_or_prefix: &str) -> Result<bool, DeployError> {
        let ids: Vec<String> = self
            .list_token_meta()
            .await?
            .into_iter()
            .map(|m| m.revocation_id)
            .collect();
        let matches: Vec<&String> = ids
            .iter()
            .filter(|id| id.starts_with(id_or_prefix))
            .collect();
        if let [id] = matches.as_slice() {
            self.kv
                .put(&crate::authz::revoked_key(id), Vec::new())
                .await?;
            self.kv.delete(&crate::authz::token_meta_key(id)).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Whether a first-token bootstrap secret (identified by its SHA-256 hex) has
    /// already been redeemed. The marker persists, so a spent secret stays spent
    /// across restarts; rotating the secret yields a fresh hash that re-enables
    /// bootstrap (the recovery path).
    pub async fn bootstrap_consumed(&self, secret_hash: &str) -> Result<bool, DeployError> {
        Ok(self
            .kv
            .get(&crate::authz::bootstrap_key(secret_hash))
            .await?
            .is_some())
    }

    /// Mark a bootstrap secret (by SHA-256 hex) consumed — single-use.
    pub async fn mark_bootstrap_consumed(&self, secret_hash: &str) -> Result<(), DeployError> {
        self.kv
            .put(&crate::authz::bootstrap_key(secret_hash), Vec::new())
            .await?;
        Ok(())
    }

    /// Read the stored RBAC `AuthzPolicy` (`authz/policy`), or `None` when the
    /// built-in default is in effect.
    pub async fn get_authz_policy(&self) -> Result<Option<crate::authz::AuthzPolicy>, DeployError> {
        match self.kv.get(crate::authz::POLICY_KEY).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Store the RBAC `AuthzPolicy`. The caller validates it first (the server
    /// route compiles it before storing); a write rides the existing cache
    /// invalidation so every node picks it up.
    pub async fn set_authz_policy(
        &self,
        policy: &crate::authz::AuthzPolicy,
    ) -> Result<(), DeployError> {
        self.kv
            .put(crate::authz::POLICY_KEY, serde_json::to_vec(policy)?)
            .await?;
        Ok(())
    }

    /// Trust an additional **root anchor** (`auth rotate-root`): a `TokenPublicKey`
    /// (`alg:hex`) accepted alongside the configured primary root, for a
    /// make-before-break rotation. Replicated to every node through the control
    /// plane, so no per-node edit is needed.
    pub async fn add_root_anchor(&self, pubkey: &str) -> Result<(), DeployError> {
        self.kv
            .put(&crate::authz::root_anchor_key(pubkey), Vec::new())
            .await?;
        Ok(())
    }

    /// Retire a previously-added root anchor (the old key, after propagation).
    pub async fn remove_root_anchor(&self, pubkey: &str) -> Result<(), DeployError> {
        self.kv
            .delete(&crate::authz::root_anchor_key(pubkey))
            .await?;
        Ok(())
    }

    /// The currently-trusted extra root anchors (the `alg:hex` public keys).
    pub async fn list_root_anchors(&self) -> Result<Vec<String>, DeployError> {
        Ok(self
            .kv
            .list_prefix(crate::authz::ROOT_ANCHOR_PREFIX)
            .await?
            .iter()
            .filter_map(|k| {
                k.strip_prefix(crate::authz::ROOT_ANCHOR_PREFIX)
                    .map(String::from)
            })
            .collect())
    }

    // ---- Dynamic daemon config --------------------------------------------

    /// The `daemon/current` pointer key → the active generation hash.
    const DAEMON_CURRENT_KEY: &'static str = "daemon/current";
    /// The `daemon/history` key → JSON array of prior generation hashes (rollback).
    const DAEMON_HISTORY_KEY: &'static str = "daemon/history";
    /// How many prior generations the rollback ring retains.
    const DAEMON_HISTORY_MAX: usize = 20;

    /// The immutable, content-addressed body: `daemonconfig/<hash>` → the
    /// [`DaemonConfig`](crate::daemon_config::DaemonConfig) JSON.
    fn daemon_config_blob_key(hash: &str) -> String {
        format!("daemonconfig/{hash}")
    }

    /// The active daemon-config **generation** (the `daemon/current` hash), if any.
    /// This is the value nodes report so an operator can confirm convergence.
    pub async fn daemon_config_generation(&self) -> Result<Option<String>, DeployError> {
        Ok(self
            .kv
            .get(Self::DAEMON_CURRENT_KEY)
            .await?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }

    /// The active dynamic daemon config, if any (`None` = none set ⇒ the server
    /// runs on the pure file baseline).
    pub async fn get_daemon_config(
        &self,
    ) -> Result<Option<crate::daemon_config::DaemonConfig>, DeployError> {
        let Some(hash) = self.daemon_config_generation().await? else {
            return Ok(None);
        };
        match self.kv.get(&Self::daemon_config_blob_key(&hash)).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            // Dangling pointer (body GC'd) reads as unset → baseline.
            None => Ok(None),
        }
    }

    /// The rollback history (oldest → newest prior generation hashes; excludes the
    /// current generation).
    pub async fn daemon_config_history(&self) -> Result<Vec<String>, DeployError> {
        match self.kv.get(Self::DAEMON_HISTORY_KEY).await? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    /// Store a new daemon config: write the content-addressed body, push the
    /// current generation onto the bounded history, and flip the `daemon/current`
    /// pointer — all as one atomic batch. **The caller validates first** (the
    /// server route runs [`DaemonConfig::validate`](crate::daemon_config::DaemonConfig::validate)
    /// before this). Returns the new generation hash.
    pub async fn set_daemon_config(
        &self,
        config: &crate::daemon_config::DaemonConfig,
    ) -> Result<String, DeployError> {
        let body = serde_json::to_vec(config)?;
        let hash = sha256_hex(&body);
        let mut history = self.daemon_config_history().await?;
        if let Some(current) = self.daemon_config_generation().await? {
            if current != hash {
                history.push(current);
                if history.len() > Self::DAEMON_HISTORY_MAX {
                    let overflow = history.len() - Self::DAEMON_HISTORY_MAX;
                    history.drain(0..overflow);
                }
            }
        }
        let ops = vec![
            WriteOp::Put(Self::daemon_config_blob_key(&hash), body),
            WriteOp::Put(
                Self::DAEMON_HISTORY_KEY.to_string(),
                serde_json::to_vec(&history)?,
            ),
            WriteOp::Put(
                Self::DAEMON_CURRENT_KEY.to_string(),
                hash.clone().into_bytes(),
            ),
        ];
        self.kv.write_batch(ops).await?;
        Ok(hash)
    }

    /// Roll back to the previous generation: pop the history and flip the pointer,
    /// atomically. Returns the hash rolled back to, or `None` if there is no
    /// history. Reverting past the last dynamic config falls back to the file
    /// baseline (which already booted successfully — the known-good floor).
    pub async fn rollback_daemon_config(&self) -> Result<Option<String>, DeployError> {
        let mut history = self.daemon_config_history().await?;
        let Some(prev) = history.pop() else {
            return Ok(None);
        };
        let ops = vec![
            WriteOp::Put(
                Self::DAEMON_HISTORY_KEY.to_string(),
                serde_json::to_vec(&history)?,
            ),
            WriteOp::Put(
                Self::DAEMON_CURRENT_KEY.to_string(),
                prev.clone().into_bytes(),
            ),
        ];
        self.kv.write_batch(ops).await?;
        Ok(Some(prev))
    }

    // ---- Compute workloads ------------------------------------------------

    /// Store an immutable, content-addressed [`ComputeSpec`](crate::compute::ComputeSpec)
    /// at `computever/<hash>` (idempotent), returning its hash.
    pub async fn put_compute_spec(
        &self,
        spec: &crate::compute::ComputeSpec,
    ) -> Result<String, DeployError> {
        let id = spec.id();
        self.kv
            .put(&crate::compute::spec_key(&id), serde_json::to_vec(spec)?)
            .await?;
        Ok(id)
    }

    /// Read a compute spec by its content hash.
    pub async fn get_compute_spec(
        &self,
        hash: &str,
    ) -> Result<Option<crate::compute::ComputeSpec>, DeployError> {
        match self.kv.get(&crate::compute::spec_key(hash)).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Set (replacing) a workload's desired state at `compute/<name>`. Activation
    /// is this pointer write — atomic, like a deployment's `current`.
    pub async fn set_compute_workload(
        &self,
        workload: &crate::compute::ComputeWorkload,
    ) -> Result<(), DeployError> {
        self.kv
            .put(
                &crate::compute::workload_key(&workload.name),
                serde_json::to_vec(workload)?,
            )
            .await?;
        Ok(())
    }

    /// Read a workload's desired state.
    pub async fn get_compute_workload(
        &self,
        name: &str,
    ) -> Result<Option<crate::compute::ComputeWorkload>, DeployError> {
        match self.kv.get(&crate::compute::workload_key(name)).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// List all compute workloads' desired state.
    pub async fn list_compute_workloads(
        &self,
    ) -> Result<Vec<crate::compute::ComputeWorkload>, DeployError> {
        let mut out = Vec::new();
        for key in self.kv.list_prefix(crate::compute::WORKLOAD_PREFIX).await? {
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(w) = serde_json::from_slice::<crate::compute::ComputeWorkload>(&bytes) {
                    out.push(w);
                }
            }
        }
        Ok(out)
    }

    /// Remove a workload's desired state (the executor then stops its replicas).
    /// Returns whether one existed.
    pub async fn delete_compute_workload(&self, name: &str) -> Result<bool, DeployError> {
        let key = crate::compute::workload_key(name);
        let existed = self.kv.get(&key).await?.is_some();
        if existed {
            self.kv.delete(&key).await?;
        }
        Ok(existed)
    }

    /// Persist a replica's observed state at `compute_state/<workload>/<replica>`
    /// (the reconcile loop's record + the gateway's upstream source).
    pub async fn set_replica_state(
        &self,
        state: &crate::compute::ObservedInstance,
    ) -> Result<(), DeployError> {
        self.kv
            .put(
                &crate::compute::replica_state_key(&state.handle.workload, state.handle.replica),
                serde_json::to_vec(state)?,
            )
            .await?;
        Ok(())
    }

    /// List a workload's observed replica states.
    pub async fn list_replica_states(
        &self,
        workload: &str,
    ) -> Result<Vec<crate::compute::ObservedInstance>, DeployError> {
        let mut out = Vec::new();
        for key in self
            .kv
            .list_prefix(&crate::compute::replica_state_prefix(workload))
            .await?
        {
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(state) =
                    serde_json::from_slice::<crate::compute::ObservedInstance>(&bytes)
                {
                    out.push(state);
                }
            }
        }
        Ok(out)
    }

    /// List **all** observed replica states across workloads (the gateway's
    /// dynamic-pool source).
    pub async fn list_all_replica_states(
        &self,
    ) -> Result<Vec<crate::compute::ObservedInstance>, DeployError> {
        let mut out = Vec::new();
        for key in self
            .kv
            .list_prefix(crate::compute::REPLICA_STATE_PREFIX)
            .await?
        {
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(state) =
                    serde_json::from_slice::<crate::compute::ObservedInstance>(&bytes)
                {
                    out.push(state);
                }
            }
        }
        Ok(out)
    }

    /// Remove a replica's observed state.
    pub async fn delete_replica_state(
        &self,
        workload: &str,
        replica: u32,
    ) -> Result<(), DeployError> {
        self.kv
            .delete(&crate::compute::replica_state_key(workload, replica))
            .await?;
        Ok(())
    }

    /// Atomically point `site` at deployment `id`.
    ///
    /// Refuses to activate a deployment whose blobs are not all present.
    pub async fn activate(&self, site: &str, id: &str) -> Result<(), DeployError> {
        let manifest = self
            .get_manifest(id)
            .await?
            .ok_or_else(|| DeployError::NotFound(format!("deployment {id}")))?;
        let missing = self.missing_blobs(&manifest).await?;
        if !missing.is_empty() {
            return Err(DeployError::Incomplete(missing));
        }

        // The atomic switch: a single KV write, so readers see the old or new
        // deployment in full, never a partial state.
        self.kv
            .put(&Self::current_key(site), id.as_bytes().to_vec())
            .await?;

        // Record the activation. Best-effort: `current` above is the source of
        // truth, so a history-write failure must not fail an activation that
        // already took effect.
        let _ = self.record_history(site, id).await;
        Ok(())
    }

    fn history_key(site: &str) -> String {
        format!("history/{site}")
    }

    /// Prepend `id` to `site`'s activation history, de-duplicating by id and
    /// keeping at most [`MAX_HISTORY`] entries.
    async fn record_history(&self, site: &str, id: &str) -> Result<(), DeployError> {
        let mut history = self.history(site).await.unwrap_or_default();
        history.retain(|entry| entry.id != id);
        history.insert(
            0,
            HistoryEntry {
                id: id.to_string(),
                at: unix_now(),
                meta: None,
            },
        );
        history.truncate(MAX_HISTORY);
        self.kv
            .put(&Self::history_key(site), serde_json::to_vec(&history)?)
            .await?;
        Ok(())
    }

    /// A site's activation history, most recent first.
    pub async fn history(&self, site: &str) -> Result<Vec<HistoryEntry>, DeployError> {
        match self.kv.get(&Self::history_key(site)).await? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    /// A site's current deployment plus its activation history, each history
    /// entry joined with its [`DeployMeta`] provenance (when recorded).
    pub async fn deployments(&self, site: &str) -> Result<DeploymentList, DeployError> {
        let mut deployments = self.history(site).await?;
        for entry in &mut deployments {
            entry.meta = self.get_meta(&entry.id).await?;
        }
        Ok(DeploymentList {
            current: self.current_id(site).await?,
            deployments,
        })
    }

    /// Deployment ids that must survive garbage collection: every `current`
    /// pointer, every named alias, and the history entries the retention policy
    /// in `opts` keeps (most-recent `keep_last` and/or anything within
    /// `keep_age_secs`; with neither set, the entire history).
    async fn live_deployment_ids(&self, opts: &GcOptions) -> Result<BTreeSet<String>, DeployError> {
        let mut ids = BTreeSet::new();
        let now = unix_now();
        for key in self.kv.list_prefix("history/").await? {
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(history) = serde_json::from_slice::<Vec<HistoryEntry>>(&bytes) {
                    for (idx, entry) in history.iter().enumerate() {
                        let within_count = opts.keep_last.is_none_or(|n| idx < n);
                        let within_age = opts
                            .keep_age_secs
                            .is_some_and(|age| now.saturating_sub(entry.at) <= age);
                        if within_count || within_age {
                            ids.insert(entry.id.clone());
                        }
                    }
                }
            }
        }
        // `current` pointers and named aliases are always live.
        for prefix in ["current/", "alias/"] {
            for key in self.kv.list_prefix(prefix).await? {
                if let Some(bytes) = self.kv.get(&key).await? {
                    ids.insert(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
        }
        Ok(ids)
    }

    /// Whether `id`'s manifest was first seen within the grace window — i.e. it
    /// may be an in-flight (uploaded-but-not-yet-activated) deploy that is not
    /// yet reachable. Manifests with no recorded `created_at` (pre-dating the
    /// metadata feature) are not grace-protected.
    async fn within_grace(
        &self,
        id: &str,
        now: u64,
        opts: &GcOptions,
    ) -> Result<bool, DeployError> {
        if opts.grace_secs == 0 {
            return Ok(false);
        }
        match self.get_meta(id).await? {
            Some(meta) => Ok(now.saturating_sub(meta.created_at) < opts.grace_secs),
            None => Ok(false),
        }
    }

    /// Garbage-collect deployments unreachable from any site's `current`
    /// pointer, alias, or retained history, and the blobs no surviving
    /// deployment references.
    ///
    /// Equivalent to [`collect_garbage_with`](Self::collect_garbage_with) with
    /// default options (keep all history, no grace window).
    pub async fn collect_garbage(&self, prune: bool) -> Result<GcReport, DeployError> {
        self.collect_garbage_with(prune, GcOptions::default()).await
    }

    /// Garbage-collect under an explicit retention policy and grace window.
    ///
    /// A manifest survives if it is reachable (see
    /// [`live_deployment_ids`](Self::live_deployment_ids)) **or** was first seen
    /// within `opts.grace_secs` — the latter protects an in-flight deploy whose
    /// manifest is stored and blobs are uploading but which is not yet
    /// activated. A blob survives if any surviving manifest references it.
    ///
    /// With `prune == false` nothing is deleted; the [`GcReport`] describes what
    /// *would* be removed.
    pub async fn collect_garbage_with(
        &self,
        prune: bool,
        opts: GcOptions,
    ) -> Result<GcReport, DeployError> {
        let live_ids = self.live_deployment_ids(&opts).await?;
        let now = unix_now();

        let manifest_keys = self.kv.list_prefix("manifests/").await?;
        let manifests_total = manifest_keys.len();
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        let mut orphan_manifests: Vec<String> = Vec::new();
        for key in &manifest_keys {
            let id = key.strip_prefix("manifests/").unwrap_or(key);
            let protected = live_ids.contains(id) || self.within_grace(id, now, &opts).await?;
            if protected {
                if let Some(bytes) = self.kv.get(key).await? {
                    if let Ok(manifest) = Manifest::from_bytes(&bytes) {
                        referenced.extend(manifest.blob_hashes());
                    }
                }
            } else {
                orphan_manifests.push(key.clone());
            }
        }

        let blobs = self.storage.list("").await?;
        let blobs_total = blobs.len();
        let mut blobs_removed = 0;
        let mut bytes_reclaimed = 0;
        for meta in &blobs {
            if !is_blob_key(&meta.key) {
                continue;
            }
            let hash = meta.key.rsplit('/').next().unwrap_or(&meta.key);
            if !referenced.contains(hash) {
                blobs_removed += 1;
                bytes_reclaimed += meta.size.unwrap_or(0);
                if prune {
                    self.storage.delete(&meta.key).await?;
                }
            }
        }

        // Orphaned content-addressed config bodies: a `siteconfig/<hash>` no
        // longer pointed to by any `site/<site>` (left behind by a config edit;
        // dedup means a body shared by several sites stays while any references
        // it). Tiny KV entries, cleaned under `prune` (not counted in the
        // blob/manifest totals, which are deploy-content concepts).
        if prune {
            let mut referenced_configs: BTreeSet<String> = BTreeSet::new();
            for pointer in self.kv.list_prefix("site/").await? {
                if let Some(bytes) = self.kv.get(&pointer).await? {
                    referenced_configs.insert(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
            for key in self.kv.list_prefix("siteconfig/").await? {
                let hash = key.strip_prefix("siteconfig/").unwrap_or(&key);
                if !referenced_configs.contains(hash) {
                    self.kv.delete(&key).await?;
                }
            }
        }

        let manifests_removed = orphan_manifests.len();
        if prune {
            for key in &orphan_manifests {
                self.kv.delete(key).await?;
                // Drop the companion metadata record alongside the manifest.
                if let Some(id) = key.strip_prefix("manifests/") {
                    let _ = self.kv.delete(&Self::meta_key(id)).await;
                }
            }
        }

        Ok(GcReport {
            manifests_total,
            manifests_removed,
            blobs_total,
            blobs_removed,
            bytes_reclaimed,
        })
    }

    /// Verify every stored blob still hashes to its key — an integrity scrub
    /// that detects bit-rot or tampering. Each blob is streamed
    /// through a hasher (never fully buffered); read-only (never deletes). The
    /// serving path can't reject a corrupt blob without buffering, so this
    /// verification is performed offline.
    pub async fn scrub_blobs(&self) -> Result<ScrubReport, DeployError> {
        let blobs = self.storage.list("").await?;
        let mut report = ScrubReport::default();
        for meta in &blobs {
            if !is_blob_key(&meta.key) {
                continue;
            }
            report.checked += 1;
            let expected = meta
                .key
                .rsplit('/')
                .next()
                .unwrap_or(meta.key.as_str())
                .to_string();
            match self.hash_stored_object(&meta.key).await {
                Ok(actual) if actual == expected => {}
                Ok(actual) => report.mismatched.push(BlobMismatch {
                    key: meta.key.clone(),
                    expected,
                    actual,
                }),
                Err(err) => report.errors.push(BlobReadError {
                    key: meta.key.clone(),
                    error: err.to_string(),
                }),
            }
        }
        Ok(report)
    }

    /// Drop these keys from the control-plane KV's local cache (shared-mode
    /// **push** invalidation). A Cloudflare DO /
    /// Queue (or any pusher) calls this — via the `/api/cache/invalidate`
    /// endpoint — when a peer changed those keys, for real-time invalidation
    /// without waiting on the poll interval. A no-op on an uncached/Raft store.
    pub fn invalidate_cache_keys(&self, keys: &[String]) {
        self.kv.invalidate_keys(keys);
    }

    /// Drop the entire control-plane KV cache (the coarse fallback / `SIGHUP`
    /// equivalent over HTTP).
    pub fn invalidate_cache(&self) {
        self.kv.invalidate_cache();
    }

    /// The key-free status (domain + expiry) of every cluster-managed cert in
    /// the control plane (`cert/<domain>`). Empty when certs
    /// live in a file cache instead (single-node `acme`). Never returns key
    /// material. Sorted by domain.
    pub async fn cert_status(&self) -> Result<Vec<crate::cert::CertStatus>, DeployError> {
        let mut out = Vec::new();
        for key in self.kv.list_prefix("cert/").await? {
            let domain = key.strip_prefix("cert/").unwrap_or(&key).to_string();
            if let Some(bytes) = self.kv.get(&key).await? {
                if let Ok(cert) = serde_json::from_slice::<crate::cert::StoredCert>(&bytes) {
                    out.push(crate::cert::CertStatus {
                        domain,
                        not_after_unix: cert.not_after_unix,
                    });
                }
            }
        }
        out.sort_by(|a, b| a.domain.cmp(&b.domain));
        Ok(out)
    }

    /// Stream a stored object through a SHA-256 hasher and return the hex digest.
    async fn hash_stored_object(&self, key: &str) -> Result<String, DeployError> {
        let mut body = self.storage.get(key).await?.body;
        let mut hasher = Sha256::new();
        while let Some(chunk) = body.next().await {
            hasher.update(&chunk?);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Every site that has a current deployment (i.e. a `current/<site>`
    /// pointer). Used by the background scheduler to find which sites' consumers
    /// and crons to run.
    pub async fn list_sites(&self) -> Result<Vec<String>, DeployError> {
        let prefix = "current/";
        let keys = self.kv.list_prefix(prefix).await?;
        Ok(keys
            .into_iter()
            .filter_map(|k| k.strip_prefix(prefix).map(str::to_string))
            .collect())
    }

    /// Delete a site and its routing/config state (the Kubernetes operator's
    /// `Site` finalizer). Removes the config pointer, the current-deployment
    /// pointer, activation history, aliases, the domain-routing entries the site
    /// owns (so its hosts free up), and any pending domain verifications. The
    /// content-addressed deployment manifests + blobs are shared and left to
    /// `prune`. Idempotent (deleting an absent site is a no-op).
    pub async fn delete_site(&self, site: &str) -> Result<(), DeployError> {
        use crate::kv::WriteOp;
        // Hold the domain-claim lock so a concurrent attach can't race the routing
        // deletes and leave a dangling `domain/*` → deleted-site entry.
        let _claim = self.domain_claim_lock.lock().await;
        let mut batch = vec![
            WriteOp::Delete(Self::site_pointer_key(site)),
            WriteOp::Delete(Self::current_key(site)),
            WriteOp::Delete(Self::history_key(site)),
        ];
        if let Some(config) = self.get_site_config(site).await? {
            for host in config.domains.exact_hosts() {
                batch.push(WriteOp::Delete(Self::domain_key(host)));
            }
            for wildcard in &config.domains.wildcards {
                if let Some(suffix) = wildcard.strip_prefix("*.") {
                    batch.push(WriteOp::Delete(Self::wildcard_key(suffix)));
                }
            }
        }
        for key in self.kv.list_prefix(&Self::alias_prefix(site)).await? {
            batch.push(WriteOp::Delete(key));
        }
        for key in self
            .kv
            .list_prefix(&format!("domainverify/{site}/"))
            .await?
        {
            batch.push(WriteOp::Delete(key));
        }
        self.kv.write_batch(batch).await?;
        Ok(())
    }

    /// The deployment id currently serving `site`, if any.
    pub async fn current_id(&self, site: &str) -> Result<Option<String>, DeployError> {
        match self.kv.get(&Self::current_key(site)).await? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            None => Ok(None),
        }
    }

    /// The manifest currently serving `site`, if any.
    pub async fn current_manifest(&self, site: &str) -> Result<Option<Manifest>, DeployError> {
        match self.current_id(site).await? {
            Some(id) => self.get_manifest(&id).await,
            None => Ok(None),
        }
    }

    /// Resolve a request `path` against `site`'s current deployment.
    ///
    /// Applies a directory-index fallback: an empty/trailing-slash path, or a
    /// path with no matching file, falls back to `<path>/index.html`.
    pub async fn resolve(&self, site: &str, path: &str) -> Result<Option<FileEntry>, DeployError> {
        let Some(manifest) = self.current_manifest(site).await? else {
            return Ok(None);
        };
        Ok(lookup(&manifest, path))
    }
}

/// Look up `path` in `manifest`, applying the directory-index fallback.
fn lookup(manifest: &Manifest, path: &str) -> Option<FileEntry> {
    let trimmed = path.trim_start_matches('/');
    if let Some(entry) = manifest.files.get(trimmed) {
        return Some(entry.clone());
    }
    let index = if trimmed.is_empty() {
        "index.html".to_string()
    } else {
        format!("{}/index.html", trimmed.trim_end_matches('/'))
    };
    manifest.files.get(&index).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeployConfig;
    use crate::ObjectMeta;

    fn entry(hash: &str) -> FileEntry {
        FileEntry {
            hash: hash.to_string(),
            size: 0,
            content_type: None,
            variants: BTreeMap::new(),
        }
    }

    #[test]
    fn manifest_id_is_deterministic() {
        let mut a = Manifest::default();
        a.files.insert("index.html".into(), entry("aa"));
        a.files.insert("style.css".into(), entry("bb"));

        let mut b = Manifest::default();
        // Insertion order differs; id must not.
        b.files.insert("style.css".into(), entry("bb"));
        b.files.insert("index.html".into(), entry("aa"));

        assert_eq!(a.id().unwrap(), b.id().unwrap());
    }

    #[test]
    fn manifest_carries_schema_version_and_reads_legacy() {
        // New manifests are stamped with the current version.
        let manifest = Manifest::default();
        assert_eq!(manifest.version, crate::SCHEMA_VERSION);
        assert!(manifest.to_bytes().unwrap().starts_with(b"{\"version\":1"));

        // A version-less document (pre-field) still reads as v1.
        let legacy = br#"{"files":{},"config":{}}"#;
        assert_eq!(Manifest::from_bytes(legacy).unwrap().version, 1);
    }

    #[test]
    fn directory_index_fallback() {
        let mut m = Manifest::default();
        m.files.insert("index.html".into(), entry("root"));
        m.files.insert("blog/index.html".into(), entry("blog"));

        assert_eq!(lookup(&m, "").unwrap().hash, "root");
        assert_eq!(lookup(&m, "/").unwrap().hash, "root");
        assert_eq!(lookup(&m, "blog").unwrap().hash, "blog");
        assert_eq!(lookup(&m, "blog/").unwrap().hash, "blog");
        assert!(lookup(&m, "missing.html").is_none());
    }

    /// A do-nothing blob backend, so we can exercise the KV-only site-config and
    /// host-routing logic without a real `Storage`.
    struct NullStorage;

    #[async_trait::async_trait]
    impl Storage for NullStorage {
        async fn get(&self, _: &str) -> Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            Err(StorageError::unsupported("null"))
        }
        async fn head(&self, _: &str) -> Result<ObjectMeta, StorageError> {
            Err(StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn function_storage_versioning_alias_rollback() {
        use crate::function::{Function, FunctionConfig, Lifecycle, Owner};
        use crate::kv::MemoryKv;

        let store = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        assert!(store.list_stored_functions().await.unwrap().is_empty());

        let mut f = Function::new(
            "resize",
            Owner::Project("acme".into()),
            "hashA",
            FunctionConfig::default(),
            Lifecycle::Independent,
            1,
        );
        store.put_function(&f).await.unwrap();
        assert_eq!(
            store.get_function("resize").await.unwrap().unwrap().active,
            "hashA"
        );
        assert_eq!(store.list_stored_functions().await.unwrap().len(), 1);

        // A new version + an alias, persisted and read back.
        f.upsert_version("hashB", Lifecycle::Independent, 2);
        f.set_alias("prod", "hashA").unwrap();
        store.put_function(&f).await.unwrap();
        let got = store.get_function("resize").await.unwrap().unwrap();
        assert_eq!(got.active, "hashB");
        assert_eq!(got.aliases.get("prod").map(String::as_str), Some("hashA"));

        // Delete is idempotent + reports prior existence.
        assert!(store.delete_function("resize").await.unwrap());
        assert!(store.get_function("resize").await.unwrap().is_none());
        assert!(!store.delete_function("resize").await.unwrap());
    }

    #[tokio::test]
    async fn function_invocation_and_idempotency_storage() {
        use crate::function::{
            Function, FunctionConfig, Invocation, InvocationResult, InvocationStatus, InvokeMode,
            Lifecycle, Owner,
        };
        use crate::kv::MemoryKv;

        let store = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        // A function whose invocation sub-keys must NOT leak into the function list.
        let f = Function::new(
            "greeter",
            Owner::Project("acme".into()),
            "hashA",
            FunctionConfig::default(),
            Lifecycle::Independent,
            1,
        );
        store.put_function(&f).await.unwrap();

        let mut inv = Invocation {
            id: "inv-1".into(),
            function: "greeter".into(),
            version: "hashA".into(),
            mode: InvokeMode::Async,
            status: InvocationStatus::Queued,
            idempotency_key: Some("key-1".into()),
            attempts: 0,
            request_b64: None,
            request_content_type: None,
            result: None,
            created: 10,
            updated: 10,
        };
        store.put_invocation(&inv).await.unwrap();
        store
            .put_idempotency("greeter", "key-1", "inv-1")
            .await
            .unwrap();

        // Read back, resolve the idempotency pointer, and list.
        assert_eq!(
            store
                .get_invocation("greeter", "inv-1")
                .await
                .unwrap()
                .unwrap()
                .status,
            InvocationStatus::Queued
        );
        assert_eq!(
            store.get_idempotency("greeter", "key-1").await.unwrap(),
            Some("inv-1".to_string())
        );
        assert_eq!(store.list_invocations("greeter").await.unwrap().len(), 1);
        // The invocation + idempotency sub-keys must not be mistaken for functions.
        assert_eq!(store.list_stored_functions().await.unwrap().len(), 1);

        // Transition to a terminal, captured result.
        inv.status = InvocationStatus::Succeeded;
        inv.attempts = 1;
        inv.result = Some(InvocationResult {
            status: 200,
            content_type: Some("text/plain".into()),
            body_b64: "aGVsbG8=".into(),
        });
        inv.updated = 20;
        store.put_invocation(&inv).await.unwrap();
        let got = store
            .get_invocation("greeter", "inv-1")
            .await
            .unwrap()
            .unwrap();
        assert!(got.is_terminal());
        assert_eq!(got.result.unwrap().status, 200);

        // An unrecorded key resolves to nothing.
        assert!(store
            .get_idempotency("greeter", "absent")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn managed_dns_ledger_round_trip_and_retract() {
        use crate::dns_managed::{ManagedDns, ManagedRecord};
        use crate::kv::MemoryKv;

        let store = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        assert!(store
            .get_managed_dns("blog", "www.example.com")
            .await
            .unwrap()
            .is_none());

        let ledger = ManagedDns::new(
            "www.example.com",
            "cloudflare",
            vec![ManagedRecord {
                kind: "A".into(),
                name: "www.example.com".into(),
                value: "203.0.113.7".into(),
                ttl: 300,
            }],
            10,
        );
        store.set_managed_dns("blog", &ledger).await.unwrap();
        // Lookup normalizes the host, so a differently-cased/dotted query hits it.
        assert_eq!(
            store
                .get_managed_dns("blog", "WWW.example.com.")
                .await
                .unwrap(),
            Some(ledger.clone())
        );
        assert_eq!(store.list_managed_dns("blog").await.unwrap(), vec![ledger]);

        store
            .remove_managed_dns("blog", "www.example.com")
            .await
            .unwrap();
        assert!(store.list_managed_dns("blog").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn site_config_round_trip_and_host_routing() {
        use crate::config::{DomainConfig, SiteConfig};
        use crate::kv::MemoryKv;

        let store = DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()));
        let config = SiteConfig {
            domains: DomainConfig {
                primary: Some("example.com".into()),
                aliases: vec!["www.example.com".into()],
                wildcards: vec!["*.example.com".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        store.set_site_config("blog", &config).await.unwrap();

        let resolved = |host: &'static str| {
            let store = store.clone();
            async move { store.resolve_site_by_host(host).await.unwrap() }
        };
        assert_eq!(resolved("example.com").await.as_deref(), Some("blog")); // exact primary
        assert_eq!(resolved("www.example.com").await.as_deref(), Some("blog")); // exact alias
        assert_eq!(resolved("api.example.com").await.as_deref(), Some("blog")); // wildcard
        assert_eq!(resolved("a.b.example.com").await.as_deref(), Some("blog")); // wildcard, deep
        assert_eq!(resolved("other.com").await, None);

        // Clearing the domains drops the index entries.
        store
            .set_site_config("blog", &SiteConfig::default())
            .await
            .unwrap();
        assert_eq!(resolved("example.com").await, None);
    }

    #[tokio::test]
    async fn site_config_is_content_addressed_and_dedups() {
        use crate::config::SiteConfig;
        use crate::kv::MemoryKv;

        let kv = Arc::new(MemoryKv::new());
        let store = DeployStore::new(Arc::new(NullStorage), kv.clone());

        // Distinguish the sites by a *non-domain* field: two sites can't share a
        // domain (the host-uniqueness guard refuses it), but they can share an
        // identical body — which is what this test is about.
        let mut cfg = SiteConfig::default();
        cfg.security.https_redirect = true;
        // Two different sites with identical config dedup to one body blob.
        store.set_site_config("s1", &cfg).await.unwrap();
        let mut cfg2 = cfg.clone();
        cfg2.security.https_redirect = false;
        store.set_site_config("s2", &cfg2).await.unwrap();
        store.set_site_config("s3", &cfg).await.unwrap(); // identical to s1

        // Pointers exist for each site; bodies are deduped (s1 == s3 → one blob).
        let bodies = kv.list_prefix("siteconfig/").await.unwrap();
        assert_eq!(bodies.len(), 2, "s1/s3 share a body; s2 distinct");
        let pointers = kv.list_prefix("site/").await.unwrap();
        assert_eq!(pointers.len(), 3);

        // Round-trips.
        assert!(
            store
                .get_site_config("s1")
                .await
                .unwrap()
                .unwrap()
                .security
                .https_redirect
        );
        assert_eq!(store.get_site_config("missing").await.unwrap(), None);

        // Editing s1 flips its pointer and orphans its old body; GC reclaims it
        // (s3 still references it, so it survives until s3 changes too).
        let mut edited = cfg.clone();
        edited.security.frame_options = Some("DENY".into());
        store.set_site_config("s1", &edited).await.unwrap();
        store.collect_garbage(true).await.unwrap();
        // s1's old body is still referenced by s3 → not collected.
        assert_eq!(kv.list_prefix("siteconfig/").await.unwrap().len(), 3);
        // Now change s3 too; the old shared body becomes orphaned and is GC'd.
        store.set_site_config("s3", &edited).await.unwrap();
        store.collect_garbage(true).await.unwrap();
        let remaining = kv.list_prefix("siteconfig/").await.unwrap();
        assert_eq!(remaining.len(), 2, "orphaned shared body reclaimed");
        // Everything still reads correctly after GC.
        assert!(
            store
                .get_site_config("s1")
                .await
                .unwrap()
                .unwrap()
                .security
                .https_redirect
        );
        assert!(
            !store
                .get_site_config("s2")
                .await
                .unwrap()
                .unwrap()
                .security
                .https_redirect
        );
    }

    #[tokio::test]
    async fn cert_status_lists_domains_and_expiry_without_keys() {
        use crate::cert::StoredCert;
        use crate::kv::MemoryKv;

        let kv = Arc::new(MemoryKv::new());
        let store = DeployStore::new(Arc::new(NullStorage), kv.clone());
        // Two stored certs (as the cluster cert store writes them) + an unrelated key.
        for (domain, not_after) in [("b.example.com", 2000u64), ("a.example.com", 1000u64)] {
            let cert = StoredCert::new("CHAINPEM", "KEYPEM", not_after);
            kv.put(
                &crate::cert::cert_key(domain),
                serde_json::to_vec(&cert).unwrap(),
            )
            .await
            .unwrap();
        }
        kv.put("site/x/config", b"{}".to_vec()).await.unwrap();

        let status = store.cert_status().await.unwrap();
        assert_eq!(status.len(), 2);
        // Sorted by domain; carries expiry, never key material.
        assert_eq!(status[0].domain, "a.example.com");
        assert_eq!(status[0].not_after_unix, 1000);
        assert_eq!(status[1].domain, "b.example.com");
    }

    #[tokio::test]
    async fn domain_verification_gates_attachment() {
        use crate::domain_verify::VerificationMethod;

        let store = store();

        // Start a challenge; re-starting under the same method is idempotent.
        let v1 = store
            .start_domain_verification("blog", "example.com", VerificationMethod::Dns, 100)
            .await
            .unwrap();
        let v2 = store
            .start_domain_verification("blog", "example.com", VerificationMethod::Dns, 200)
            .await
            .unwrap();
        assert_eq!(v1.token, v2.token, "same method → same pending token");
        assert!(!store
            .is_domain_verified("blog", "example.com")
            .await
            .unwrap());

        // Unverified hosts cannot be attached — the gate.
        assert!(store
            .attach_verified_domain("blog", "example.com")
            .await
            .is_err());

        // Verify, then attach: the host enters routing as the primary.
        store
            .mark_domain_verified("blog", "example.com")
            .await
            .unwrap();
        assert!(store
            .is_domain_verified("blog", "example.com")
            .await
            .unwrap());
        store
            .attach_verified_domain("blog", "example.com")
            .await
            .unwrap();
        assert_eq!(
            store
                .resolve_site_by_host("example.com")
                .await
                .unwrap()
                .as_deref(),
            Some("blog")
        );
        // A second verified host becomes an alias, not the primary.
        store
            .start_domain_verification("blog", "www.example.com", VerificationMethod::Http, 300)
            .await
            .unwrap();
        store
            .mark_domain_verified("blog", "www.example.com")
            .await
            .unwrap();
        let config = store
            .attach_verified_domain("blog", "www.example.com")
            .await
            .unwrap();
        assert_eq!(config.domains.primary.as_deref(), Some("example.com"));
        assert_eq!(config.domains.aliases, vec!["www.example.com".to_string()]);

        // A wildcard is verified at its base name and attached as a wildcard.
        store
            .start_domain_verification("blog", "*.example.com", VerificationMethod::Dns, 400)
            .await
            .unwrap();
        // The challenge keys on the base host, so the wildcard shares it.
        assert!(store
            .is_domain_verified("blog", "*.example.com")
            .await
            .unwrap());
        let config = store
            .attach_verified_domain("blog", "*.example.com")
            .await
            .unwrap();
        assert_eq!(config.domains.wildcards, vec!["*.example.com".to_string()]);

        // Listing surfaces every challenge; removing drops the record.
        assert_eq!(
            store.list_domain_verifications("blog").await.unwrap().len(),
            2
        );
        assert!(store
            .remove_domain_verification("blog", "example.com")
            .await
            .unwrap());
        assert!(!store
            .is_domain_verified("blog", "example.com")
            .await
            .unwrap());
    }

    /// The host-uniqueness hijack guard: a host already routed to one site cannot
    /// be claimed by another — neither via `attach_verified_domain` nor via a
    /// direct `set_site_config` — so a site-writer can't steal another's domain.
    #[tokio::test]
    async fn host_cannot_be_hijacked_across_sites() {
        use crate::config::{DomainConfig, SiteConfig};
        use crate::domain_verify::VerificationMethod;

        let store = store();

        // Site `a` legitimately verifies + attaches `shared.example`.
        store
            .start_domain_verification("a", "shared.example", VerificationMethod::Http, 100)
            .await
            .unwrap();
        store
            .mark_domain_verified("a", "shared.example")
            .await
            .unwrap();
        store
            .attach_verified_domain("a", "shared.example")
            .await
            .unwrap();
        assert_eq!(
            store
                .resolve_site_by_host("shared.example")
                .await
                .unwrap()
                .as_deref(),
            Some("a")
        );

        // Site `b` verifies the same host (imagine control briefly changed hands,
        // or a stale challenge) and tries to attach — it must be refused, not
        // silently steal the live mapping.
        store
            .start_domain_verification("b", "shared.example", VerificationMethod::Http, 200)
            .await
            .unwrap();
        store
            .mark_domain_verified("b", "shared.example")
            .await
            .unwrap();
        let err = store
            .attach_verified_domain("b", "shared.example")
            .await
            .expect_err("second site must not hijack an attached host");
        assert!(matches!(err, DeployError::Conflict(_)), "got {err:?}");

        // The direct config path is guarded too (this is what a raw
        // `PUT /config` with a stolen domain would hit).
        let stolen = SiteConfig {
            domains: DomainConfig {
                primary: Some("shared.example".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = store
            .set_site_config("b", &stolen)
            .await
            .expect_err("set_site_config must refuse another site's host");
        assert!(matches!(err, DeployError::Conflict(_)), "got {err:?}");

        // The original owner is untouched.
        assert_eq!(
            store
                .resolve_site_by_host("shared.example")
                .await
                .unwrap()
                .as_deref(),
            Some("a")
        );

        // Re-writing the *same* site's own config (no owner change) is fine — the
        // guard only fires across sites.
        let readd = SiteConfig {
            domains: DomainConfig {
                primary: Some("shared.example".into()),
                aliases: vec!["www.shared.example".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        store.set_site_config("a", &readd).await.unwrap();
        assert_eq!(
            store
                .resolve_site_by_host("www.shared.example")
                .await
                .unwrap()
                .as_deref(),
            Some("a")
        );
    }

    /// The hijack guard folds case + trailing dot: a variant-cased or
    /// dot-suffixed host can't write a second routing key past the guard, and
    /// routing resolves any casing to the one owner.
    #[tokio::test]
    async fn host_uniqueness_is_case_and_dot_insensitive() {
        use crate::config::{DomainConfig, SiteConfig};
        use crate::domain_verify::VerificationMethod;

        let store = store();
        // Site `a` legitimately attaches `example.com`.
        store
            .start_domain_verification("a", "example.com", VerificationMethod::Http, 100)
            .await
            .unwrap();
        store
            .mark_domain_verified("a", "example.com")
            .await
            .unwrap();
        store
            .attach_verified_domain("a", "example.com")
            .await
            .unwrap();

        // Site `b` tries to claim case / trailing-dot variants of the same host.
        for variant in ["Example.COM", "example.com.", "EXAMPLE.com."] {
            let cfg = SiteConfig {
                domains: DomainConfig {
                    primary: Some(variant.into()),
                    ..Default::default()
                },
                ..Default::default()
            };
            let err = store
                .set_site_config("b", &cfg)
                .await
                .expect_err("variant claim must be refused");
            assert!(
                matches!(err, DeployError::Conflict(_)),
                "variant {variant:?} must Conflict, got {err:?}"
            );
        }

        // Routing folds case + trailing dot to the one owner.
        for h in ["example.com", "Example.com", "EXAMPLE.COM", "example.com."] {
            assert_eq!(
                store.resolve_site_by_host(h).await.unwrap().as_deref(),
                Some("a"),
                "host {h:?} must resolve to site a"
            );
        }
    }

    /// The self-serve edge lookup: a pending HTTP challenge is found by
    /// (host, token), and only then — not for the wrong token/host, a DNS
    /// challenge, or an expired one.
    #[tokio::test]
    async fn self_serve_challenge_lookup_matches_pending_http_only() {
        use crate::domain_verify::{VerificationMethod, CHALLENGE_TTL_SECS};

        let store = store();
        let v = store
            .start_domain_verification("docs", "docs.example", VerificationMethod::Http, 1_000)
            .await
            .unwrap();

        // Exact (host, token) within the TTL → found.
        let found = store
            .find_pending_http_challenge("docs.example", &v.token, 1_000)
            .await
            .unwrap();
        assert_eq!(
            found.as_ref().map(|f| f.token.clone()),
            Some(v.token.clone())
        );
        // A trailing dot / uppercase host still normalizes to a match.
        assert!(store
            .find_pending_http_challenge("Docs.Example.", &v.token, 1_000)
            .await
            .unwrap()
            .is_some());

        // Wrong token, wrong host → no match (never leaks another host's token).
        assert!(store
            .find_pending_http_challenge("docs.example", "not-the-token", 1_000)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .find_pending_http_challenge("other.example", &v.token, 1_000)
            .await
            .unwrap()
            .is_none());

        // Past the TTL → refused (a stale token can't be redeemed forever).
        assert!(store
            .find_pending_http_challenge("docs.example", &v.token, 1_000 + CHALLENGE_TTL_SECS + 1)
            .await
            .unwrap()
            .is_none());

        // A DNS-method challenge is never served over the HTTP edge route.
        let dv = store
            .start_domain_verification("dns-site", "dns.example", VerificationMethod::Dns, 1_000)
            .await
            .unwrap();
        assert!(store
            .find_pending_http_challenge("dns.example", &dv.token, 1_000)
            .await
            .unwrap()
            .is_none());
    }

    /// A wildcard can only be attached with DNS proof; an HTTP token at the base
    /// host is refused. And a stale HTTP self-serve index entry (left by a later
    /// method change) never serves the wrong challenge — the lookup re-validates.
    #[tokio::test]
    async fn wildcard_requires_dns_and_stale_index_is_safe() {
        use crate::domain_verify::VerificationMethod;

        let store = store();

        // HTTP-verify the base host, then try to attach the wildcard → refused.
        let http = store
            .start_domain_verification("s", "*.example.com", VerificationMethod::Http, 100)
            .await
            .unwrap();
        store
            .mark_domain_verified("s", "*.example.com")
            .await
            .unwrap();
        let err = store
            .attach_verified_domain("s", "*.example.com")
            .await
            .expect_err("wildcard with only HTTP proof must be refused");
        assert!(matches!(err, DeployError::Conflict(_)), "got {err:?}");

        // Drop it and re-verify via DNS → the wildcard now attaches. This replaces
        // the record (the old HTTP token's self-serve index entry is dropped on
        // remove), and re-proves via DNS.
        store
            .remove_domain_verification("s", "*.example.com")
            .await
            .unwrap();
        // The removed HTTP token is no longer self-servable.
        assert!(store
            .find_pending_http_challenge("example.com", &http.token, 100)
            .await
            .unwrap()
            .is_none());
        store
            .start_domain_verification("s", "*.example.com", VerificationMethod::Dns, 200)
            .await
            .unwrap();
        store
            .mark_domain_verified("s", "*.example.com")
            .await
            .unwrap();
        let cfg = store
            .attach_verified_domain("s", "*.example.com")
            .await
            .unwrap();
        assert_eq!(cfg.domains.wildcards, vec!["*.example.com".to_string()]);

        // Stale-index safety: an HTTP challenge whose record is later switched to
        // DNS (without removal) leaves a dangling token index; the lookup loads
        // the current (DNS) record and refuses to serve the old HTTP token.
        let h2 = store
            .start_domain_verification("s2", "host.example", VerificationMethod::Http, 300)
            .await
            .unwrap();
        assert!(store
            .find_pending_http_challenge("host.example", &h2.token, 300)
            .await
            .unwrap()
            .is_some());
        store
            .start_domain_verification("s2", "host.example", VerificationMethod::Dns, 300)
            .await
            .unwrap();
        assert!(
            store
                .find_pending_http_challenge("host.example", &h2.token, 300)
                .await
                .unwrap()
                .is_none(),
            "a stale HTTP index must not serve a token whose record is now DNS"
        );
    }

    fn store() -> DeployStore {
        use crate::kv::MemoryKv;
        DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()))
    }

    #[tokio::test]
    async fn daemon_config_store_round_trips_and_rolls_back() {
        use crate::daemon_config::DaemonConfig;
        let s = store();
        // None set → baseline.
        assert!(s.get_daemon_config().await.unwrap().is_none());
        assert!(s.daemon_config_generation().await.unwrap().is_none());

        // Set gen 1.
        let g1cfg = DaemonConfig {
            default_site: Some("one".into()),
            ..Default::default()
        };
        let g1 = s.set_daemon_config(&g1cfg).await.unwrap();
        assert_eq!(
            s.daemon_config_generation().await.unwrap().as_deref(),
            Some(g1.as_str())
        );
        assert_eq!(s.get_daemon_config().await.unwrap().unwrap(), g1cfg);
        assert!(s.daemon_config_history().await.unwrap().is_empty());

        // Set gen 2 → gen 1 goes to history.
        let g2cfg = DaemonConfig {
            default_site: Some("two".into()),
            ..Default::default()
        };
        let g2 = s.set_daemon_config(&g2cfg).await.unwrap();
        assert_ne!(g1, g2);
        assert_eq!(s.daemon_config_history().await.unwrap(), vec![g1.clone()]);

        // Rollback → back to gen 1.
        let rolled = s.rollback_daemon_config().await.unwrap();
        assert_eq!(rolled.as_deref(), Some(g1.as_str()));
        assert_eq!(
            s.daemon_config_generation().await.unwrap().as_deref(),
            Some(g1.as_str())
        );
        assert_eq!(s.get_daemon_config().await.unwrap().unwrap(), g1cfg);
        // No further history → rollback is a no-op signal.
        assert!(s.rollback_daemon_config().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn compute_store_round_trips() {
        use crate::compute::{ComputeSpec, ComputeWorkload, PlacementConstraints, RestartPolicy};
        let s = store();
        let spec = ComputeSpec {
            version: crate::SCHEMA_VERSION,
            rootfs: "r".repeat(64),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: 256,
            entrypoint: vec!["/app".into()],
            env: Default::default(),
            port: 8080,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![],
            isolation: Default::default(),
            prefer_backend: None,
        };
        // Content-addressed spec: storing returns the hash; re-reads match.
        let hash = s.put_compute_spec(&spec).await.unwrap();
        assert_eq!(hash, spec.id());
        assert_eq!(s.get_compute_spec(&hash).await.unwrap(), Some(spec));
        assert!(s.get_compute_spec("deadbeef").await.unwrap().is_none());

        // Workload desired state: set / get / list / delete.
        let workload = ComputeWorkload {
            version: crate::SCHEMA_VERSION,
            name: "api".into(),
            active: hash.clone(),
            replicas: 3,
            placement: PlacementConstraints::default(),
        };
        s.set_compute_workload(&workload).await.unwrap();
        assert_eq!(s.get_compute_workload("api").await.unwrap(), Some(workload));
        assert_eq!(s.list_compute_workloads().await.unwrap().len(), 1);
        assert!(s.delete_compute_workload("api").await.unwrap());
        assert!(!s.delete_compute_workload("api").await.unwrap());
        assert!(s.list_compute_workloads().await.unwrap().is_empty());
    }

    /// A distinct, blob-free manifest (distinguished only by its config), so it
    /// activates without a real blob backend.
    fn empty_manifest(clean_urls: bool) -> Manifest {
        Manifest {
            config: DeployConfig {
                clean_urls,
                ..DeployConfig::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn deploy_meta_records_sizes_and_merges_provenance() {
        let store = store();
        let mut manifest = Manifest::default();
        manifest.files.insert("index.html".into(), {
            let mut e = entry("aa");
            e.size = 10;
            e
        });
        manifest.files.insert("app.js".into(), {
            let mut e = entry("bb");
            e.size = 32;
            e
        });

        // First store carries provenance.
        let id = store
            .put_manifest_with(
                &manifest,
                DeployMetaInput {
                    source: Some("abc123".into()),
                    message: Some("first".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let meta = store.get_meta(&id).await.unwrap().unwrap();
        assert_eq!(meta.file_count, 2);
        assert_eq!(meta.total_size, 42);
        assert_eq!(meta.source.as_deref(), Some("abc123"));
        let created = meta.created_at;

        // Re-store with empty input preserves created_at and prior provenance.
        store
            .put_manifest_with(&manifest, DeployMetaInput::default())
            .await
            .unwrap();
        let meta = store.get_meta(&id).await.unwrap().unwrap();
        assert_eq!(meta.created_at, created);
        assert_eq!(meta.source.as_deref(), Some("abc123"));
        assert_eq!(meta.message.as_deref(), Some("first"));
    }

    #[tokio::test]
    async fn aliases_round_trip_and_guard_completeness() {
        let store = store();
        let manifest = empty_manifest(false);
        let id = store.put_manifest(&manifest).await.unwrap();

        // Unknown deployment cannot be aliased.
        assert!(matches!(
            store.set_alias("blog", "staging", "deadbeef").await,
            Err(DeployError::NotFound(_))
        ));

        store.set_alias("blog", "staging", &id).await.unwrap();
        assert_eq!(
            store.get_alias("blog", "staging").await.unwrap(),
            Some(id.clone())
        );
        let aliases = store.list_aliases("blog").await.unwrap();
        assert_eq!(aliases.get("staging"), Some(&id));

        assert!(store.remove_alias("blog", "staging").await.unwrap());
        assert!(!store.remove_alias("blog", "staging").await.unwrap());
        assert_eq!(store.get_alias("blog", "staging").await.unwrap(), None);
    }

    #[tokio::test]
    async fn retention_keep_last_collects_older_history() {
        let store = store();
        // Three distinct deployments, activated oldest→newest.
        let m1 = empty_manifest(false);
        let m2 = empty_manifest(true);
        let mut m3 = empty_manifest(true);
        m3.config.trailing_slash = crate::config::TrailingSlash::Always;
        let id1 = store.put_manifest(&m1).await.unwrap();
        let id2 = store.put_manifest(&m2).await.unwrap();
        let id3 = store.put_manifest(&m3).await.unwrap();
        store.activate("blog", &id1).await.unwrap();
        store.activate("blog", &id2).await.unwrap();
        store.activate("blog", &id3).await.unwrap();

        // Default: full history kept, nothing collectable.
        let report = store.collect_garbage(false).await.unwrap();
        assert_eq!(report.manifests_removed, 0);

        // keep_last = 1 keeps only the most recent (== current id3); id1 and id2
        // become orphans. An alias to id1 rescues it.
        store.set_alias("blog", "pinned", &id1).await.unwrap();
        let report = store
            .collect_garbage_with(
                false,
                GcOptions {
                    keep_last: Some(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(report.manifests_removed, 1); // only id2 (id1 aliased, id3 current)
    }

    #[tokio::test]
    async fn grace_window_protects_in_flight_manifest() {
        let store = store();
        // An uploaded-but-never-activated manifest: an orphan.
        let id = store.put_manifest(&empty_manifest(false)).await.unwrap();
        assert!(store.get_manifest(&id).await.unwrap().is_some());

        // With a grace window it is protected (treated as in-flight)...
        let report = store
            .collect_garbage_with(
                false,
                GcOptions {
                    grace_secs: 3600,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(report.manifests_removed, 0);

        // ...without one, it is collectable.
        let report = store.collect_garbage(false).await.unwrap();
        assert_eq!(report.manifests_removed, 1);
    }

    #[tokio::test]
    async fn resolve_manifest_id_exact_prefix_and_missing() {
        let store = store();
        let id = store.put_manifest(&empty_manifest(true)).await.unwrap();

        // Exact id resolves to itself.
        assert_eq!(
            store.resolve_manifest_id(&id).await.unwrap().as_deref(),
            Some(id.as_str())
        );
        // A unique prefix (the DNS-label use case) resolves to the full id.
        assert_eq!(
            store
                .resolve_manifest_id(&id[..16])
                .await
                .unwrap()
                .as_deref(),
            Some(id.as_str())
        );
        // An unknown prefix resolves to nothing.
        assert!(store
            .resolve_manifest_id("ffffffffffffffff")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn delete_site_removes_config_routing_and_aliases() {
        let store = store();
        let mut cfg = SiteConfig::default();
        cfg.domains.primary = Some("blog.example".into());
        cfg.domains.wildcards = vec!["*.preview.blog.example".into()];
        store.set_site_config("blog", &cfg).await.unwrap();
        // A real deployment so the alias points at something valid.
        let id = store.put_manifest(&empty_manifest(true)).await.unwrap();
        store.set_alias("blog", "stable", &id).await.unwrap();

        // Present: config stored + its hosts route to it.
        assert!(store.get_site_config("blog").await.unwrap().is_some());
        assert_eq!(
            store
                .resolve_site_by_host("blog.example")
                .await
                .unwrap()
                .as_deref(),
            Some("blog")
        );

        store.delete_site("blog").await.unwrap();

        // Gone: config pointer, domain routing (host freed), aliases.
        assert!(store.get_site_config("blog").await.unwrap().is_none());
        assert!(store
            .resolve_site_by_host("blog.example")
            .await
            .unwrap()
            .is_none());
        assert!(store.list_aliases("blog").await.unwrap().is_empty());

        // Idempotent — deleting an absent site is a no-op.
        store.delete_site("blog").await.unwrap();
    }
}
