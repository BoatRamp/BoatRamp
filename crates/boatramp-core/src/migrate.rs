//! Online, resumable migration of a pre-0.2.0 (**layout 1**) control-plane store to
//! the project-scoped **layout 2** (`project/<proj>/…`) introduced by the first-class
//! Project campaign. The store is the small metadata KV — pointers, configs,
//! function/compute/workflow records, the domain-routing index — **not** the
//! content-addressed blob storage, which never moves (a content hash is stable
//! across layouts), so the blast radius is bounded.
//!
//! ## What moves
//!
//! Every mutable, per-name record re-keys by a **uniform prefix prepend**: the old
//! key *is* the suffix under `project/<default>/`, so `current/blog` becomes
//! `project/default/current/blog`, `functions/x/versions/y` becomes
//! `project/default/functions/x/versions/y`, and so on across the twelve
//! [`MUTABLE_FAMILIES`]. The three [`DOMAIN_FAMILIES`] (`domain/`, `wildcard/`,
//! `httpchallenge/`) keep their **global** key and get a **value rewrite**: the old
//! bare-site string becomes a `{project, site}` [`DomainOwner`] JSON. Content-
//! addressed bodies and control-plane singletons ([`GLOBAL_FAMILIES`], plus blob
//! keys) are left untouched.
//!
//! ## Safety
//!
//! - **Copy-before-delete.** Each datum is written to its new key and read back to
//!   verify *before* the old key is deleted, so every datum always exists under at
//!   least one key — a crash at any point leaves a recoverable store.
//! - **Resumable + idempotent.** A [`SchemaVersion`] marker at [`SCHEMA_KEY`] records
//!   which families are done; re-running resumes at the first unfinished family and
//!   completes to convergence. A finished migration is a no-op.
//! - **Tolerant readers.** [`DomainOwner::from_bytes`] reads all three value forms
//!   (object / JSON string / raw legacy bytes), so a reader is correct at every point
//!   during the value rewrite.
//! - **Staging.** With [`MigrateOptions::finalize`] `false` the copy + verify + value
//!   rewrite run and the marker flips to `2-dual` — the store now serves entirely off
//!   the new keys while the old keys linger for rollback; a later `finalize` run
//!   deletes them and flips to layout 2. `finalize` `true` (the default) does both in
//!   one pass. [`MigrateOptions::dry_run`] scans and reports without writing anything.
//!
//! ## Cluster
//!
//! The migration runs through the same [`KvStore`] a node serves from; in a Raft
//! cluster that is the replicated store, so a single leader-run migration replicates
//! for free. A follower must **not** race its own copy — it blocks on the marker (see
//! the serve-startup guard) until the leader's migration has replicated.

use serde::{Deserialize, Serialize};

use crate::kv::{KvStore, WriteOp};
use crate::project::{
    self, owner_kind, DomainOwner, Project, ProjectConfig, ProjectMeta, DEFAULT_PROJECT,
};
use crate::time::now_unix;

/// The global marker key recording the store's on-disk layout + migration progress.
pub const SCHEMA_KEY: &str = "schema/version";

/// A pre-migration snapshot of the full key list, written before any change so an
/// operator can diff/audit what existed at layout 1.
pub const PREMIGRATION_INDEX_KEY: &str = "schema/premigration-index";

/// Layout **1**: the pre-0.2.0, flat, un-scoped keyspace.
pub const LAYOUT_LEGACY: u32 = 1;
/// Layout **2**: the project-scoped keyspace.
pub const LAYOUT_PROJECT: u32 = 2;

/// The mutable per-name families, each re-keyed by prepending `project/<default>/`.
/// Order is irrelevant to correctness (families are independent) but fixed for a
/// legible, resumable progress record.
pub const MUTABLE_FAMILIES: &[&str] = &[
    "current/",
    "site/",
    "history/",
    "alias/",
    "domainverify/",
    "dnsmanaged/",
    "functions/",
    "metering/",
    "blobnotify/",
    "workflows/",
    "compute/",
    "compute_state/",
];

/// The domain-routing families: the **key stays global**, the **value** is rewritten
/// from a bare site name to a `{project, site}` [`DomainOwner`].
pub const DOMAIN_FAMILIES: &[&str] = &["domain/", "wildcard/", "httpchallenge/"];

/// Families that are **never** migrated: content-addressed bodies (dedup-shared,
/// stable across layouts) and control-plane singletons. Listed for documentation and
/// the migration's own guard against clobbering them. (Blob bodies live under a
/// two-hex-char shard prefix in the *blob* store, a different backend entirely.)
pub const GLOBAL_FAMILIES: &[&str] = &[
    "manifests/",
    "meta/",
    "siteconfig/",
    "computever/",
    "daemonconfig/",
    "authz/",
    "daemon/",
    "cert/",
    // The 0.2.0 namespaces themselves — already layout 2, must not be re-migrated.
    "project/",
    "projectmeta/",
    "projectver/",
    "project-history/",
    "owner/",
    "schema/",
];

/// The persisted layout marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SchemaVersion {
    /// On-disk layout: [`LAYOUT_LEGACY`] or [`LAYOUT_PROJECT`].
    pub layout: u32,
    /// `true` while transitional (`2-dual`): copy + verify + value-rewrite are done
    /// and reads serve off the new keys, but the old keys have not yet been deleted.
    pub dual: bool,
    /// Unix time the (copy phase of the) migration completed; `0` if never run.
    pub migrated_at: u64,
    /// The mutable families whose copy (and, unless `dual`, delete) has completed —
    /// the resumability cursor.
    pub families_done: Vec<String>,
}

impl Default for SchemaVersion {
    fn default() -> Self {
        // The absence of a marker means layout 1 (pre-0.2.0), so the default a serde
        // `default` fills in is the legacy layout.
        Self {
            layout: LAYOUT_LEGACY,
            dual: false,
            migrated_at: 0,
            families_done: Vec::new(),
        }
    }
}

impl SchemaVersion {
    /// A finalized layout-2 marker (migration fully complete, old keys gone).
    pub fn finalized() -> Self {
        Self {
            layout: LAYOUT_PROJECT,
            dual: false,
            migrated_at: now_unix(),
            families_done: MUTABLE_FAMILIES.iter().map(ToString::to_string).collect(),
        }
    }

    /// Whether the store is fully migrated (layout 2, not dual) — nothing to do.
    pub fn is_complete(&self) -> bool {
        self.layout >= LAYOUT_PROJECT && !self.dual
    }
}

/// How a store needs to be treated on startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Empty / never written, or already fully migrated — serve as-is.
    Ready,
    /// Layout 1 data present and unmigrated — refuse to serve until migrated.
    NeedsMigration,
    /// Copy done, old keys still present (`2-dual`) — serve OK; a `finalize` pass is
    /// the only remaining work.
    Dual,
}

/// Options controlling a migration pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateOptions {
    /// Scan and report what *would* change, writing nothing.
    pub dry_run: bool,
    /// Delete the old keys after copy + verify (a one-shot migration). With `false`
    /// the pass stops at `2-dual` (copy + verify + value-rewrite only), leaving the
    /// old keys for a soak/rollback window; a later `finalize` deletes them.
    pub finalize: bool,
}

impl MigrateOptions {
    /// The default one-shot migration: copy, verify, value-rewrite, delete old keys.
    pub fn one_shot() -> Self {
        Self {
            dry_run: false,
            finalize: true,
        }
    }
}

/// A per-family tally of what a migration pass moved (or, on a dry run, would move).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Keys re-keyed per mutable family (`old prefix` → count).
    pub rekeyed: Vec<(String, usize)>,
    /// Domain-index values rewritten per family.
    pub values_rewritten: Vec<(String, usize)>,
    /// Owner reverse-index entries written.
    pub owner_entries: usize,
    /// Whether the pass created the `default` project pointer.
    pub created_default_project: bool,
    /// The store was already fully migrated — the pass was a no-op.
    pub already_migrated: bool,
    /// The resulting layout after this pass (`1`, `2-dual`, or `2`).
    pub dual: bool,
}

impl MigrationReport {
    /// Total keys re-keyed across all mutable families.
    pub fn total_rekeyed(&self) -> usize {
        self.rekeyed.iter().map(|(_, n)| n).sum()
    }
}

/// A migration failure.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// The underlying KV store failed.
    #[error(transparent)]
    Kv(#[from] crate::error::KvError),
    /// A copied datum failed read-back verification — the migration aborts rather
    /// than risk deleting the source of a datum that did not land.
    #[error("verification failed for migrated key {0}")]
    Verify(String),
    /// (De)serializing the marker / default project failed.
    #[error("migration serde error: {0}")]
    Serde(String),
}

/// Read the layout marker (defaulting to the legacy layout when absent).
pub async fn read_marker(kv: &dyn KvStore) -> Result<SchemaVersion, MigrateError> {
    match kv.get(SCHEMA_KEY).await? {
        Some(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| MigrateError::Serde(e.to_string()))
        }
        None => Ok(SchemaVersion::default()),
    }
}

/// Classify a store for the serve-startup guard: is it ready to serve, does it hold
/// unmigrated layout-1 data, or is it in the `2-dual` soak window?
pub async fn status(kv: &dyn KvStore) -> Result<Status, MigrateError> {
    let marker = read_marker(kv).await?;
    if marker.is_complete() {
        return Ok(Status::Ready);
    }
    if marker.dual {
        return Ok(Status::Dual);
    }
    // No/legacy marker: layout 1 *only if* any layout-1 datum actually exists. A
    // fresh store (new binary, never written) has none, so it needs no migration —
    // new writes already land in layout 2.
    if has_legacy_data(kv).await? {
        Ok(Status::NeedsMigration)
    } else {
        Ok(Status::Ready)
    }
}

/// Whether any layout-1 key exists (any mutable or domain family with ≥1 key).
async fn has_legacy_data(kv: &dyn KvStore) -> Result<bool, MigrateError> {
    for family in MUTABLE_FAMILIES.iter().chain(DOMAIN_FAMILIES) {
        if !kv.list_prefix(family).await?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Migrate `kv` from layout 1 to layout 2, resumable + idempotent.
///
/// Copies each mutable family to its `project/<default>/…` key (copy → verify →
/// delete-old, the last only when `finalize`), rewrites the domain-index values,
/// creates the `default` project pointer, and builds the `owner/*` reverse index.
/// Returns a per-family report. Safe to call on an already-migrated store (no-op) and
/// safe to re-run after an interruption (resumes from the marker).
pub async fn migrate(
    kv: &dyn KvStore,
    opts: MigrateOptions,
) -> Result<MigrationReport, MigrateError> {
    let mut report = MigrationReport::default();
    let mut marker = read_marker(kv).await?;

    if marker.is_complete() {
        report.already_migrated = true;
        return Ok(report);
    }

    // A dry run reports the full pending set without persisting anything.
    if opts.dry_run {
        for family in MUTABLE_FAMILIES {
            let n = kv.list_prefix(family).await?.len();
            if n > 0 {
                report.rekeyed.push((family.to_string(), n));
            }
        }
        for family in DOMAIN_FAMILIES {
            let n = count_values_needing_rewrite(kv, family).await?;
            if n > 0 {
                report.values_rewritten.push((family.to_string(), n));
            }
        }
        report.created_default_project = kv
            .get(&project::pointer_key(DEFAULT_PROJECT))
            .await?
            .is_none();
        report.dual = !opts.finalize;
        return Ok(report);
    }

    // Snapshot the pre-migration key list once, for audit/rollback (best-effort:
    // only on the first pass, never overwriting an existing snapshot).
    if kv.get(PREMIGRATION_INDEX_KEY).await?.is_none() {
        write_premigration_index(kv).await?;
    }

    // Copy phase (resumable): copy + verify each family, **never** deleting here, so
    // the `families_done` cursor tracks copy completion independently of the (finalize-
    // gated) delete below. A crash re-runs only the interrupted family.
    for family in MUTABLE_FAMILIES {
        if marker.families_done.iter().any(|f| f == family) {
            continue;
        }
        let moved = copy_family(kv, family).await?;
        if moved > 0 {
            report.rekeyed.push((family.to_string(), moved));
        }
        marker.families_done.push(family.to_string());
        marker.migrated_at = now_unix();
        persist_marker(kv, &marker).await?;
    }

    // Rewrite the domain-routing index values (idempotent — an already-rewritten
    // value round-trips through `DomainOwner`).
    for family in DOMAIN_FAMILIES {
        let n = rewrite_domain_values(kv, family).await?;
        if n > 0 {
            report.values_rewritten.push((family.to_string(), n));
        }
    }

    // Create the `default` project pointer + body (idempotent) and build the reverse
    // ownership index over the now-migrated resources.
    report.created_default_project = ensure_default_project(kv).await?;
    report.owner_entries = build_owner_index(kv).await?;

    // Delete phase (finalize only): now that every datum is safely copied + verified,
    // drop the old keys. Idempotent — a key already gone (or never present) is a
    // no-op — so this correctly finalizes a store staged by an earlier `dual` pass.
    if opts.finalize {
        for family in MUTABLE_FAMILIES {
            delete_old_family(kv, family).await?;
        }
    }

    // Flip the marker: `2-dual` if we left the old keys, layout 2 if we deleted them.
    marker.layout = LAYOUT_PROJECT;
    marker.dual = !opts.finalize;
    marker.migrated_at = now_unix();
    persist_marker(kv, &marker).await?;
    report.dual = marker.dual;
    Ok(report)
}

/// Delete the old keys left behind by a staged (`2-dual`) migration, flipping the
/// marker to a finalized layout 2. A no-op on a store that is already finalized or
/// was never migrated.
pub async fn finalize(kv: &dyn KvStore) -> Result<MigrationReport, MigrateError> {
    let mut report = MigrationReport::default();
    let marker = read_marker(kv).await?;
    if marker.is_complete() {
        report.already_migrated = true;
        return Ok(report);
    }
    // Deleting the old keys is exactly a `finalize` migrate pass; copy + verify of an
    // already-copied family is idempotent, then the old keys go.
    migrate(kv, MigrateOptions::one_shot()).await
}

/// Copy one mutable family to its `project/<default>/…` keys: copy → read-back
/// verify, **without** deleting the source (that is the finalize-gated delete phase).
/// Returns the number of keys copied.
async fn copy_family(kv: &dyn KvStore, family: &str) -> Result<usize, MigrateError> {
    let mut moved = 0;
    for old_key in kv.list_prefix(family).await? {
        let new_key = format!("project/{DEFAULT_PROJECT}/{old_key}");
        let Some(value) = kv.get(&old_key).await? else {
            continue; // vanished between listing and read — nothing to move
        };
        kv.put(&new_key, value.clone()).await?;
        if kv.get(&new_key).await?.as_deref() != Some(value.as_slice()) {
            return Err(MigrateError::Verify(new_key));
        }
        moved += 1;
    }
    Ok(moved)
}

/// Delete the old keys of one mutable family whose `project/<default>/…` counterpart
/// is present and byte-identical — the finalize half of copy-verify-delete. Idempotent
/// (a missing old key is skipped). Refuses to delete an old key whose new key is
/// absent or mismatched, so a partially-copied family never loses data.
async fn delete_old_family(kv: &dyn KvStore, family: &str) -> Result<(), MigrateError> {
    for old_key in kv.list_prefix(family).await? {
        let new_key = format!("project/{DEFAULT_PROJECT}/{old_key}");
        let old = kv.get(&old_key).await?;
        let new = kv.get(&new_key).await?;
        match (old, new) {
            (Some(o), Some(n)) if o == n => kv.delete(&old_key).await?,
            (Some(_), _) => return Err(MigrateError::Verify(new_key)),
            (None, _) => {}
        }
    }
    Ok(())
}

/// Rewrite the values of one domain-routing family to the `{project, site}` form.
/// Idempotent: an already-object value round-trips unchanged.
async fn rewrite_domain_values(kv: &dyn KvStore, family: &str) -> Result<usize, MigrateError> {
    let mut rewritten = 0;
    for key in kv.list_prefix(family).await? {
        let Some(value) = kv.get(&key).await? else {
            continue;
        };
        let owner = DomainOwner::from_bytes(&value);
        let canonical = owner.to_bytes();
        if canonical != value {
            kv.put(&key, canonical).await?;
            rewritten += 1;
        }
    }
    Ok(rewritten)
}

/// Count how many values in a domain family are not yet in the canonical object form
/// (for the dry-run report).
async fn count_values_needing_rewrite(
    kv: &dyn KvStore,
    family: &str,
) -> Result<usize, MigrateError> {
    let mut n = 0;
    for key in kv.list_prefix(family).await? {
        if let Some(value) = kv.get(&key).await? {
            if DomainOwner::from_bytes(&value).to_bytes() != value {
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Create the `default` project pointer + content-addressed body if absent. Returns
/// whether it was created.
async fn ensure_default_project(kv: &dyn KvStore) -> Result<bool, MigrateError> {
    let pointer = project::pointer_key(DEFAULT_PROJECT);
    if kv.get(&pointer).await?.is_some() {
        return Ok(false);
    }
    let default = Project {
        version: crate::SCHEMA_VERSION,
        name: DEFAULT_PROJECT.to_string(),
        created_at: now_unix(),
        meta: ProjectMeta::default(),
        config: ProjectConfig::default(),
        secrets_ref: None,
    };
    let hash = default.id();
    let body = serde_json::to_vec(&default).map_err(|e| MigrateError::Serde(e.to_string()))?;
    kv.write_batch(vec![
        WriteOp::Put(project::spec_key(&hash), body),
        WriteOp::Put(pointer, hash.into_bytes()),
    ])
    .await?;
    Ok(true)
}

/// Build (or refresh) the `owner/<kind>/<name>` → project reverse index over the
/// migrated site / function / compute records. Idempotent. Returns the entry count.
async fn build_owner_index(kv: &dyn KvStore) -> Result<usize, MigrateError> {
    let mut ops = Vec::new();
    // Sites: the site-config pointer `project/default/site/<site>`.
    let site_prefix = format!("project/{DEFAULT_PROJECT}/site/");
    for key in kv.list_prefix(&site_prefix).await? {
        if let Some(site) = key.strip_prefix(&site_prefix) {
            if !site.is_empty() {
                ops.push(WriteOp::Put(
                    project::owner_key(owner_kind::SITE, site),
                    DEFAULT_PROJECT.as_bytes().to_vec(),
                ));
            }
        }
    }
    // Functions: the meta key `project/default/functions/<name>` (no further `/`).
    let fn_prefix = format!("project/{DEFAULT_PROJECT}/functions/");
    for key in kv.list_prefix(&fn_prefix).await? {
        if let Some(rest) = key.strip_prefix(&fn_prefix) {
            if !rest.is_empty() && !rest.contains('/') {
                ops.push(WriteOp::Put(
                    project::owner_key(owner_kind::FUNCTION, rest),
                    DEFAULT_PROJECT.as_bytes().to_vec(),
                ));
            }
        }
    }
    // Compute workloads: `project/default/compute/<name>`.
    let compute_prefix = format!("project/{DEFAULT_PROJECT}/compute/");
    for key in kv.list_prefix(&compute_prefix).await? {
        if let Some(name) = key.strip_prefix(&compute_prefix) {
            if !name.is_empty() {
                ops.push(WriteOp::Put(
                    project::owner_key(owner_kind::COMPUTE, name),
                    DEFAULT_PROJECT.as_bytes().to_vec(),
                ));
            }
        }
    }
    let count = ops.len();
    if !ops.is_empty() {
        kv.write_batch(ops).await?;
    }
    Ok(count)
}

/// Persist the layout marker.
async fn persist_marker(kv: &dyn KvStore, marker: &SchemaVersion) -> Result<(), MigrateError> {
    let bytes = serde_json::to_vec(marker).map_err(|e| MigrateError::Serde(e.to_string()))?;
    kv.put(SCHEMA_KEY, bytes).await?;
    Ok(())
}

/// Write the pre-migration key snapshot (a newline-joined list of every key, for
/// audit/rollback). Best-effort; never blocks the migration.
async fn write_premigration_index(kv: &dyn KvStore) -> Result<(), MigrateError> {
    let mut keys = Vec::new();
    for family in MUTABLE_FAMILIES.iter().chain(DOMAIN_FAMILIES) {
        keys.extend(kv.list_prefix(family).await?);
    }
    keys.sort();
    kv.put(PREMIGRATION_INDEX_KEY, keys.join("\n").into_bytes())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryKv;

    /// Seed a synthetic layout-1 store: sites, functions, compute, aliases, domain
    /// index (raw bare-site values), and a content-addressed body that must NOT move.
    async fn seed_legacy(kv: &MemoryKv) {
        // Mutable families (bare, un-scoped keys).
        kv.put("current/blog", b"dep-1".to_vec()).await.unwrap();
        kv.put("site/blog", b"cfghash".to_vec()).await.unwrap();
        kv.put("history/blog", b"[]".to_vec()).await.unwrap();
        kv.put("alias/blog/staging", b"dep-1".to_vec())
            .await
            .unwrap();
        kv.put("domainverify/blog/www.example", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("dnsmanaged/blog/www.example", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("functions/resize", b"{}".to_vec()).await.unwrap();
        kv.put("functions/resize/versions/v1", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("metering/resize", b"{}".to_vec()).await.unwrap();
        kv.put("blobnotify/resize/uploads", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("workflows/etl", b"{}".to_vec()).await.unwrap();
        kv.put("compute/api", b"{}".to_vec()).await.unwrap();
        kv.put("compute_state/api/0", b"{}".to_vec()).await.unwrap();
        // Domain index: legacy RAW bare-site values (not JSON).
        kv.put("domain/www.example", b"blog".to_vec())
            .await
            .unwrap();
        kv.put("wildcard/preview.example", b"blog".to_vec())
            .await
            .unwrap();
        kv.put("httpchallenge/www.example/tok", b"blog".to_vec())
            .await
            .unwrap();
        // Content-addressed body + a singleton — must be left untouched.
        kv.put("siteconfig/cfghash", b"the-config".to_vec())
            .await
            .unwrap();
        kv.put("manifests/dep-1", b"the-manifest".to_vec())
            .await
            .unwrap();
        kv.put("authz/tokens/t1", b"tok".to_vec()).await.unwrap();
    }

    #[tokio::test]
    async fn status_detects_legacy_fresh_and_migrated() {
        let fresh = MemoryKv::new();
        assert_eq!(
            status(&fresh).await.unwrap(),
            Status::Ready,
            "empty store is ready"
        );

        let legacy = MemoryKv::new();
        seed_legacy(&legacy).await;
        assert_eq!(status(&legacy).await.unwrap(), Status::NeedsMigration);

        migrate(&legacy, MigrateOptions::one_shot()).await.unwrap();
        assert_eq!(
            status(&legacy).await.unwrap(),
            Status::Ready,
            "migrated store is ready"
        );
    }

    #[tokio::test]
    async fn migrate_rekeys_mutable_families_and_rewrites_domain_values() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;
        let report = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();

        // Mutable keys re-keyed under project/default/, old keys gone.
        assert_eq!(
            kv.get("project/default/current/blog")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"dep-1"[..])
        );
        assert_eq!(
            kv.get("project/default/functions/resize/versions/v1")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"{}"[..])
        );
        assert_eq!(
            kv.get("project/default/compute_state/api/0")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"{}"[..])
        );
        assert!(
            kv.get("current/blog").await.unwrap().is_none(),
            "old key deleted after finalize"
        );
        assert!(kv.get("compute/api").await.unwrap().is_none());

        // Domain values rewritten to the {project, site} object; keys unchanged.
        let dv = kv.get("domain/www.example").await.unwrap().unwrap();
        assert_eq!(
            DomainOwner::from_bytes(&dv),
            DomainOwner::new("default", "blog")
        );
        assert!(String::from_utf8_lossy(&dv).contains("\"project\":\"default\""));
        assert_eq!(
            DomainOwner::from_bytes(
                &kv.get("httpchallenge/www.example/tok")
                    .await
                    .unwrap()
                    .unwrap()
            ),
            DomainOwner::new("default", "blog")
        );

        // Content-addressed body + singleton untouched.
        assert_eq!(
            kv.get("siteconfig/cfghash").await.unwrap().as_deref(),
            Some(&b"the-config"[..])
        );
        assert_eq!(
            kv.get("manifests/dep-1").await.unwrap().as_deref(),
            Some(&b"the-manifest"[..])
        );
        assert_eq!(
            kv.get("authz/tokens/t1").await.unwrap().as_deref(),
            Some(&b"tok"[..])
        );

        // The default project pointer + body + owner reverse index exist.
        assert!(kv.get("projectmeta/default").await.unwrap().is_some());
        assert!(report.created_default_project);
        assert_eq!(
            kv.get("owner/site/blog").await.unwrap().as_deref(),
            Some(&b"default"[..])
        );
        assert_eq!(
            kv.get("owner/function/resize").await.unwrap().as_deref(),
            Some(&b"default"[..])
        );
        assert_eq!(
            kv.get("owner/compute/api").await.unwrap().as_deref(),
            Some(&b"default"[..])
        );
        // The function's per-version sub-key is not mistaken for a function owner.
        assert!(kv
            .get("owner/function/resize/versions/v1")
            .await
            .unwrap()
            .is_none());

        // Marker finalized.
        assert!(read_marker(&kv).await.unwrap().is_complete());
        assert!(!report.already_migrated);
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;
        let first = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(first.total_rekeyed() > 0);

        // A full re-run is a no-op (already complete), and the store is byte-identical.
        let before: Vec<String> = kv.list_prefix("project/").await.unwrap();
        let second = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(second.already_migrated);
        assert_eq!(second.total_rekeyed(), 0);
        assert_eq!(kv.list_prefix("project/").await.unwrap(), before);
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;
        let report = migrate(
            &kv,
            MigrateOptions {
                dry_run: true,
                finalize: true,
            },
        )
        .await
        .unwrap();

        assert!(
            report.total_rekeyed() > 0,
            "dry run reports the pending work"
        );
        assert!(report.created_default_project);
        // ...but nothing changed on disk.
        assert!(kv
            .get("project/default/current/blog")
            .await
            .unwrap()
            .is_none());
        assert!(kv.get("current/blog").await.unwrap().is_some());
        assert!(kv.get("projectmeta/default").await.unwrap().is_none());
        assert_eq!(status(&kv).await.unwrap(), Status::NeedsMigration);
    }

    #[tokio::test]
    async fn dual_stage_then_finalize() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;

        // Stage: copy + verify + value-rewrite, but keep the old keys.
        let staged = migrate(
            &kv,
            MigrateOptions {
                dry_run: false,
                finalize: false,
            },
        )
        .await
        .unwrap();
        assert!(staged.dual);
        assert_eq!(status(&kv).await.unwrap(), Status::Dual);
        // New keys serve; old keys linger for rollback.
        assert!(kv
            .get("project/default/current/blog")
            .await
            .unwrap()
            .is_some());
        assert!(
            kv.get("current/blog").await.unwrap().is_some(),
            "old key kept during dual soak"
        );

        // Finalize: old keys removed, marker completes.
        let done = finalize(&kv).await.unwrap();
        assert!(!done.dual);
        assert!(kv.get("current/blog").await.unwrap().is_none());
        assert_eq!(status(&kv).await.unwrap(), Status::Ready);
    }

    #[tokio::test]
    async fn resumes_after_a_crash_mid_migration() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;

        // Simulate a crash after only the first two families copied + recorded: copy
        // `current/` and `site/` by hand, write a partial marker, leave the rest.
        for old in ["current/blog", "site/blog"] {
            let v = kv.get(old).await.unwrap().unwrap();
            kv.put(&format!("project/default/{old}"), v).await.unwrap();
            kv.delete(old).await.unwrap();
        }
        let partial = SchemaVersion {
            layout: LAYOUT_LEGACY,
            dual: false,
            migrated_at: 1,
            families_done: vec!["current/".to_string(), "site/".to_string()],
        };
        persist_marker(&kv, &partial).await.unwrap();

        // Re-running resumes and converges: every family ends up migrated exactly once.
        migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(read_marker(&kv).await.unwrap().is_complete());
        assert_eq!(
            kv.get("project/default/compute/api")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"{}"[..])
        );
        assert_eq!(
            kv.get("project/default/current/blog")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"dep-1"[..])
        );
        assert!(kv.get("compute/api").await.unwrap().is_none());
        // No accidental double-nesting from re-processing the already-done families.
        assert!(kv
            .get("project/default/project/default/current/blog")
            .await
            .unwrap()
            .is_none());
    }
}
