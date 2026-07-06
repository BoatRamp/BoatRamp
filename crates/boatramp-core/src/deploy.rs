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
}

impl DeployStore {
    /// Build a deploy store over a blob `storage` and a metadata `kv`.
    pub fn new(storage: Arc<dyn Storage>, kv: Arc<dyn KvStore>) -> Self {
        Self { storage, kv }
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
        format!("domain/{host}")
    }

    fn wildcard_key(suffix: &str) -> String {
        format!("wildcard/{suffix}")
    }

    fn domain_verification_key(site: &str, host: &str) -> String {
        format!(
            "domainverify/{site}/{}",
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
    pub async fn set_site_config(
        &self,
        site: &str,
        config: &SiteConfig,
    ) -> Result<(), DeployError> {
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

    /// Resolve a request `Host` to a site: exact match first, then wildcard
    /// suffixes from most specific to least (so `*.example.com` matches
    /// `a.b.example.com`).
    pub async fn resolve_site_by_host(&self, host: &str) -> Result<Option<String>, DeployError> {
        let host = host.trim();
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

    async fn put_domain_verification(
        &self,
        site: &str,
        verification: &DomainVerification,
    ) -> Result<(), DeployError> {
        self.kv
            .put(
                &Self::domain_verification_key(site, &verification.host),
                verification.to_json()?,
            )
            .await?;
        Ok(())
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
        let key = Self::domain_verification_key(site, host);
        let existed = self.kv.get(&key).await?.is_some();
        if existed {
            self.kv.delete(&key).await?;
        }
        Ok(existed)
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
        self.set_site_config(site, &config).await?;
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
        use crate::config::{DomainConfig, SiteConfig};
        use crate::kv::MemoryKv;

        let kv = Arc::new(MemoryKv::new());
        let store = DeployStore::new(Arc::new(NullStorage), kv.clone());

        let cfg = SiteConfig {
            domains: DomainConfig {
                primary: Some("a.example".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        // Two different sites with identical config dedup to one body blob.
        store.set_site_config("s1", &cfg).await.unwrap();
        let mut cfg2 = cfg.clone();
        cfg2.domains.primary = Some("b.example".into());
        store.set_site_config("s2", &cfg2).await.unwrap();
        store.set_site_config("s3", &cfg).await.unwrap(); // identical to s1

        // Pointers exist for each site; bodies are deduped (s1 == s3 → one blob).
        let bodies = kv.list_prefix("siteconfig/").await.unwrap();
        assert_eq!(bodies.len(), 2, "s1/s3 share a body; s2 distinct");
        let pointers = kv.list_prefix("site/").await.unwrap();
        assert_eq!(pointers.len(), 3);

        // Round-trips.
        assert_eq!(
            store
                .get_site_config("s1")
                .await
                .unwrap()
                .unwrap()
                .domains
                .primary
                .as_deref(),
            Some("a.example")
        );
        assert_eq!(store.get_site_config("missing").await.unwrap(), None);

        // Editing s1 flips its pointer and orphans its old body; GC reclaims it
        // (s3 still references it, so it survives until s3 changes too).
        let mut edited = cfg.clone();
        edited.security.https_redirect = true;
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
        assert_eq!(
            store
                .get_site_config("s2")
                .await
                .unwrap()
                .unwrap()
                .domains
                .primary
                .as_deref(),
            Some("b.example")
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

    fn store() -> DeployStore {
        use crate::kv::MemoryKv;
        DeployStore::new(Arc::new(NullStorage), Arc::new(MemoryKv::new()))
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
}
