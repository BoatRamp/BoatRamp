//! The operator-facing **project export/import** capability — the native env-clone
//! surface. A node that runs a project's managed databases + blobs
//! implements it; the admin API (`POST /api/project-export` / `/api/project-import`,
//! `System·Admin`) and the `boatramp project export|import` CLI client consume it,
//! mirroring the [`OperatorSql`](crate::sql::OperatorSql) /
//! [`ComputeExec`](crate::compute::ComputeExec) capability-trait pattern (a core trait,
//! node-implemented, server-consumed via an axum `Extension`).
//!
//! The methods **stream** the bundle through an [`AsyncWrite`] / [`AsyncRead`] (format
//! v2), so neither the exporting node nor the importing node ever stages the WHOLE
//! bundle to disk: `export` writes the `BRPROJ` tar straight into `sink` (the handler
//! wires that to the HTTP response body), producing + freeing each member just-in-time so
//! the transient on-disk footprint is bounded to the LARGEST SINGLE MEMBER, never the
//! whole bundle (the env-clone disk-fill fix); `import` reads the bundle straight from
//! `src` (the handler wires that to the request body) in a single forward pass, restoring
//! each member as it streams. The `futures::io` traits (not `tokio::io`) are used so the
//! trait stays usable from this crate's wasm32 build, which has no tokio. The bundle
//! format itself (the `BRPROJ` tar + MANIFEST, both v1 read-compat and the v2 streamable
//! writer) lives in `boatramp-node`.

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::project::ProjectRef;

/// The control-plane KV key PREFIXES a project **exclusively owns** — the structural allowlist
/// the project export is scoped to (the C1 cross-tenant-isolation invariant). A single-project
/// bundle carries ONLY keys under these prefixes, plus the site-config bodies the project's own
/// sites reference (`siteconfig/<hash>`, content-addressed — resolved by the driver from the
/// project's `site/` pointers, since a config blob is keyed by its own hash, not by project).
///
/// **Nothing from the global / shared keyspace rides along.** Another project's
/// `project/<other>/…`, EVERY project's TLS private keys (`cert/<domain>`), the global
/// routing-ownership records (`domain/<host>`, `wildcard/<suffix>`), the node's `daemonconfig/…`,
/// and the `_cp/*` / `_inval/*` coordination feeds are ALL excluded — fail-closed: a key under
/// none of these prefixes is never exported. Routing + TLS are deliberately kept OUT of a
/// portable bundle: a TLS private key never leaves the node, and the target re-establishes
/// routing and re-issues certs (ACME) under its OWN identity on import. This is both the simplest
/// auditable answer to "a single-project export must carry zero other-project material" and the
/// strictest custody posture for the global crown jewels.
///
/// The shapes mirror the canonical `deploy::keys` builders (and `managed_sql`'s
/// `managed-sql-cred/<project>/<workload>`); each prefix ends in `/` so a sibling project can
/// never be over-captured (`project/foo/` is not a prefix of `project/foobar/…`).
pub fn project_owned_prefixes(project: ProjectRef<'_>) -> Vec<String> {
    vec![
        format!("project/{project}/"),
        crate::deploy::keys::graphql_registry_prefix(project), // graphql/<p>/
        crate::deploy::keys::graphql_safelist_prefix(project), // hapq/<p>/
        format!("managed-sql-cred/{project}/"),
    ]
}

/// Whether `key` is owned by `project` under the [`project_owned_prefixes`] structural allowlist.
/// (Does NOT cover the referenced `siteconfig/<hash>` bodies — those are content-addressed and
/// resolved separately by the driver from the project's `site/` pointers.)
#[must_use]
pub fn project_owns_key(key: &str, project: ProjectRef<'_>) -> bool {
    project_owned_prefixes(project)
        .iter()
        .any(|p| key.starts_with(p.as_str()))
}

/// The control-plane KV prefixes holding a project's KEK-**sealed** / environment-coupled
/// material — the keyspace a `--identity fresh` import DROPS after the restore (it was sealed
/// under the SOURCE KEK and can never unseal under the target's own key, so dropping it makes
/// "zero source-sealed artifacts" a POSITIVE absence rather than present-but-inert). The SINGLE
/// source of truth, built from the canonical `deploy::keys` builders:
///   - `project/<p>/secret/`              operator / app env secrets
///   - `project/<p>/tenant-secret/`       ALL per-tenant secrets
///   - `project/<p>/tenant-secret-index/` the per-tenant name index
///   - `project/<p>/email/`               SMTP profiles (sealed password)   ← was missing (H1)
///   - `managed-sql-cred/<p>/`            managed-DB credentials             ← was missing (H1)
///
/// Prefixes are keyed on the TARGET project; the driver re-qualifies an imported slice to the
/// target BEFORE the drop, so a project-rename import drops the right keys. (TLS keys and routing
/// — `cert/`, `domain/`, `wildcard/` — are never exported at all, so there is nothing to drop
/// there; see [`project_owned_prefixes`].) The project-wide `tenant-secret/` prefix is composed
/// here deliberately (no guest-facing builder — a `list` is always tenant-scoped to avoid a
/// cross-tenant name oracle); this is an admin-only teardown scan, not a guest enumeration.
pub fn sealed_secret_prefixes(project: ProjectRef<'_>) -> Vec<String> {
    vec![
        crate::deploy::keys::secret_prefix(project),
        format!("project/{project}/tenant-secret/"),
        format!("project/{project}/tenant-secret-index/"),
        crate::deploy::keys::email_profile_prefix(project),
        format!("managed-sql-cred/{project}/"),
    ]
}

/// Scope a whole-store KV scan down to the keys a single `project` owns — the C1 cross-tenant
/// isolation filter applied to the exported control-plane slice. Keeps ONLY [`project_owns_key`]
/// matches plus the content-addressed site-config bodies (`siteconfig/<hash>`) this project's own
/// `site/` pointers reference (a pointer `project/<p>/site/<site>` stores the raw UTF-8 hash of
/// its current `SiteConfig`, whose body lives at the GLOBAL `siteconfig/<hash>`; including only the
/// referenced hashes keeps the restore faithful — sites would otherwise dangle — without pulling
/// any OTHER project's config body). Every other key is dropped (fail-closed), so a single-project
/// bundle can physically carry no other tenant's `project/…`, no TLS key (`cert/…`), no routing
/// record (`domain/…`, `wildcard/…`) and no node `daemonconfig/…`. `entries` is a full
/// [`crate::kv_dump::scan_dumpable`] result (the reserved `_cp/*` / `_inval/*` feeds already
/// removed).
#[must_use]
pub fn scope_entries_to_project(
    entries: Vec<crate::kv::KvDumpEntry>,
    project: ProjectRef<'_>,
) -> Vec<crate::kv::KvDumpEntry> {
    let site_pointer_prefix = format!("project/{project}/site/");
    let mut referenced_siteconfig: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for e in &entries {
        if e.key.starts_with(&site_pointer_prefix)
            && let Ok(hash) = std::str::from_utf8(&e.value)
        {
            let hash = hash.trim();
            if !hash.is_empty() {
                referenced_siteconfig.insert(crate::deploy::keys::site_config_blob(hash));
            }
        }
    }
    entries
        .into_iter()
        .filter(|e| project_owns_key(&e.key, project) || referenced_siteconfig.contains(&e.key))
        .collect()
}

/// Re-qualify a project-scoped KV slice's keys from the SOURCE project to the TARGET, so an import
/// under a different name lands every owned control-plane key in the target's scope — matching the
/// blob and libsql re-qualification the driver already does. Rewrites the leading project segment
/// of the owned prefixes (`project/<s>/…`, `graphql/<s>/…`, `hapq/<s>/…`, `managed-sql-cred/<s>/…`);
/// the content-addressed `siteconfig/<hash>` bodies are identity-free and kept verbatim (the
/// re-keyed site pointer still references the same hash). A no-op when `source == target` (the
/// common same-name cross-environment move). Rename is best-effort key-PATH re-qualification — like
/// blobs/libsql it does not rewrite project references embedded inside opaque config bodies.
pub fn rekey_entries_to_target(entries: &mut [crate::kv::KvDumpEntry], source: &str, target: &str) {
    if source == target {
        return;
    }
    for e in entries {
        e.key = rekey_owned_key(&e.key, source, target);
    }
}

/// Rewrite the SOURCE project segment of one owned KV key to the TARGET (see
/// [`rekey_entries_to_target`]); any non-owned key (e.g. the content-addressed `siteconfig/<hash>`)
/// is returned unchanged.
#[must_use]
pub fn rekey_owned_key(key: &str, source: &str, target: &str) -> String {
    for head in ["project/", "graphql/", "hapq/", "managed-sql-cred/"] {
        let src_pref = format!("{head}{source}/");
        if let Some(rest) = key.strip_prefix(&src_pref) {
            return format!("{head}{target}/{rest}");
        }
    }
    key.to_string()
}

/// Import-side SYMMETRIC, FAIL-CLOSED tenancy enforcement on the control-plane KV slice — the
/// mirror of the export-side [`scope_entries_to_project`], applied AFTER the slice has been
/// re-keyed to the TARGET project ([`rekey_entries_to_target`]) and BEFORE it is written.
///
/// A bundle crosses a TRUST boundary and its KV slice carries only a plaintext integrity SHA
/// (integrity, **not** authenticity), so a crafted/tampered slice must never be trusted to
/// write OUTSIDE the target's own scope. The export side filters; without this the import side
/// would fail-OPEN — [`rekey_owned_key`] only rewrites keys under the SOURCE's owned prefixes,
/// so any other key (`project/<other-tenant>/…`, a global `cert/`/`domain/`/`wildcard/`, a node
/// `daemonconfig/`, a reserved `_cp/`/`_inval/`, an unreferenced `siteconfig/…`) would pass
/// through unchanged and be written node-wide — a cross-tenant KV overwrite / routing hijack /
/// cert replacement / siteconfig poisoning.
///
/// Every entry MUST therefore be EITHER:
///   - under the TARGET's owned prefixes ([`project_owns_key`]); OR
///   - a content-addressed `siteconfig/<hash>` body that is BOTH (a) referenced by one of the
///     target's own just-imported `project/<target>/site/` pointers in this slice, AND (b)
///     content-verified — `key == siteconfig/<sha256(body)>` — so an attacker cannot plant a
///     mismatched body at a victim's hash.
///
/// Any other entry ABORTS the import LOUD, returning a message naming the offending key
/// (fail-closed, matching the blob re-key's refuse stance). A legitimate clone's own re-keyed
/// slice is entirely target-owned (plus its own content-correct site configs), so it passes.
pub fn enforce_target_scoped_kv(
    entries: &[crate::kv::KvDumpEntry],
    target: ProjectRef<'_>,
) -> Result<(), String> {
    // Site-config hashes legitimately referenced by the TARGET's own site pointers in this slice.
    let site_pointer_prefix = format!("project/{target}/site/");
    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for e in entries {
        if e.key.starts_with(&site_pointer_prefix)
            && let Ok(hash) = std::str::from_utf8(&e.value)
        {
            let hash = hash.trim();
            if !hash.is_empty() {
                referenced.insert(crate::deploy::keys::site_config_blob(hash));
            }
        }
    }
    for e in entries {
        if project_owns_key(&e.key, target) {
            continue;
        }
        if referenced.contains(&e.key) {
            // Content-address check: the body MUST hash to the key's embedded hash.
            let computed =
                crate::deploy::keys::site_config_blob(&hex::encode(Sha256::digest(&e.value)));
            if computed == e.key {
                continue;
            }
            return Err(format!(
                "control-plane KV import refused: site-config body for {:?} does not match its \
                 content-address (expected key {computed:?}) — refusing a poisoned siteconfig",
                e.key
            ));
        }
        return Err(format!(
            "control-plane KV import refused: entry {:?} is outside the target project {target}'s \
             owned scope after re-key — a bundle must not carry another tenant's or a global \
             (routing / TLS / daemon) control-plane key",
            e.key
        ));
    }
    Ok(())
}

/// Flags for an export. `Debug` is implemented by hand to **redact** the transport key so
/// it can never reach a log line.
#[derive(Clone, Default)]
pub struct ExportOptions {
    /// App-data-only bundle (pg/mysql rows + libsql + blobs); EXCLUDES the control-plane KV
    /// slice and identity. Mutually exclusive with `include_identity`.
    pub data_only: bool,
    /// Also stage the identity transport container (the project KEK, passphrase-wrapped) so
    /// an `--identity adopt` recovery can unseal the KV slice's sealed secrets. Requires
    /// `transport_key` and a local KEK envelope (refused for Vault / none). Default OFF —
    /// the safe, identity-free bundle.
    pub include_identity: bool,
    /// The operator transport passphrase wrapping the identity container, resolved by the
    /// caller from `--transport-key-file` / env / prompt. Required iff `include_identity`.
    /// Secret — never logged (see the hand-written `Debug`).
    pub transport_key: Option<Vec<u8>>,
    /// When set, produce an INCREMENTAL / DELTA bundle chaining onto a prior base (the
    /// `--mode differential|incremental` + base-reference surface). `None` ⇒ an ordinary full
    /// bundle. A delta is only meaningful for the resumable member-object target (the base must be
    /// re-readable), so it is honoured by `export_resumable` / `import_resumable`, not the
    /// forward-only streaming `export`.
    pub delta: Option<crate::project_delta::DeltaRequest>,
}

impl std::fmt::Debug for ExportOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportOptions")
            .field("data_only", &self.data_only)
            .field("include_identity", &self.include_identity)
            .field(
                "transport_key",
                &self.transport_key.as_ref().map(|_| "<redacted>"),
            )
            .field("delta", &self.delta)
            .finish()
    }
}

/// The identity decision for an import (Ask-2 / Ask-4 c/d). The CLI/API surface
/// requires the operator to choose explicitly; the in-core default is the SAFE `Fresh`.
#[derive(Clone, Default)]
pub enum IdentityChoice {
    /// A DIFFERENT environment: the target keeps/mints its own KEK and the source-sealed
    /// secrets are dropped (they would never unseal under the target's key). The safe
    /// default.
    #[default]
    Fresh,
    /// Backup/recovery of the SAME environment: install the source KEK — opened from the
    /// bundle's transport-wrapped identity member with `transport_key` — BEFORE the restore,
    /// so the KV slice's sealed secrets unseal and existing tokens stay valid.
    Adopt {
        /// The operator transport passphrase that opens the identity container. Secret —
        /// never logged (see the hand-written `Debug`).
        transport_key: Vec<u8>,
    },
}

impl std::fmt::Debug for IdentityChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fresh => f.write_str("Fresh"),
            Self::Adopt { .. } => f.write_str("Adopt { transport_key: <redacted> }"),
        }
    }
}

/// Flags for an import. `Debug` is hand-written so the adopt transport key cannot leak.
#[derive(Clone, Default)]
pub struct ImportOptions {
    /// Execute the import (default `false` ⇒ a dry-run plan, no mutation).
    pub apply: bool,
    /// Overlay a non-empty control-plane KV destination (the `kv_dump` commingle
    /// override). Default `false` ⇒ refuse a non-pristine KV dest.
    pub force: bool,
    /// Proceed despite a Postgres schema-ledger fingerprint mismatch between the bundle
    /// and the target (a `--data-only` restore into a schema-skewed target). Default
    /// `false` ⇒ REFUSE on skew.
    pub allow_schema_skew: bool,
    /// Replace an EXISTING target project (one that already holds data under its own owned
    /// KV prefixes or blob scope). Default `false` ⇒ REFUSE such a target, so a clone into a
    /// FRESH target is the safe default and overwriting a populated project is opt-in. Note
    /// this is distinct from `force`, which overlays a non-pristine KV destination store-wide;
    /// `overwrite` is scoped to the TARGET PROJECT's own data.
    pub overwrite: bool,
    /// Adopt the source identity (recovery) or mint fresh (a different environment).
    pub identity: IdentityChoice,
    /// Clone-robustness (PLAN-clone-robustness #1): ENUMERATE every member whose streamed bytes
    /// disagree with its declared size/SHA-256 in ONE pass and fail at the end (reporting each
    /// path + class), instead of aborting at the first — so an operator can assess the scope of a
    /// stale/truncated source population. Applies no mismatched member (an assessment, never a
    /// mutation); pairs with a dry-run / clone-verify. Default `false`.
    pub enumerate_mismatches: bool,
    /// Clone-robustness (PLAN-clone-robustness #2): WARN + CONTINUE past a member whose streamed
    /// bytes disagree with its declared size/SHA-256 instead of hard-failing — the target
    /// re-derives a skipped derivative on access. DEFAULT-scoped to re-generable `der/` derivatives
    /// (a baseline/primary/non-blob mismatch STILL hard-fails); broaden with
    /// [`skip_any_blob_mismatch`](Self::skip_any_blob_mismatch). Default `false`.
    pub skip_member_mismatch: bool,
    /// Clone-robustness: broaden [`skip_member_mismatch`](Self::skip_member_mismatch) beyond
    /// re-generable `der/` derivatives to ANY blob member (baselines + primaries too) — the louder,
    /// explicit opt-in. NEVER tolerates a non-blob (DB/KV/identity) member even so. Ignored unless
    /// `skip_member_mismatch` is set. Default `false`.
    pub skip_any_blob_mismatch: bool,
}

impl std::fmt::Debug for ImportOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportOptions")
            .field("apply", &self.apply)
            .field("force", &self.force)
            .field("allow_schema_skew", &self.allow_schema_skew)
            .field("overwrite", &self.overwrite)
            .field("identity", &self.identity)
            .field("enumerate_mismatches", &self.enumerate_mismatches)
            .field("skip_member_mismatch", &self.skip_member_mismatch)
            .field("skip_any_blob_mismatch", &self.skip_any_blob_mismatch)
            .finish()
    }
}

/// The outcome of an export or import — a legible summary for the operator / API JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportReport {
    /// Whether this was a dry-run (no mutation).
    pub dry_run: bool,
    /// Postgres databases processed.
    pub pg_databases: usize,
    /// libsql databases processed.
    pub libsql_databases: usize,
    /// Control-plane KV records written (import) / exported (export).
    pub kv_records: usize,
    /// Control-plane KV records byte-verified after an applied import.
    pub kv_verified: usize,
    /// Blob objects copied.
    pub blobs: u64,
    /// Database names whose source schema-ledger fingerprint differed from the target's
    /// (populated on an import; a REFUSAL unless `allow_schema_skew`).
    pub schema_skew: Vec<String>,
    /// Free-form notes (deferred/skipped members, warnings).
    pub notes: Vec<String>,
}

/// Why a project export/import failed.
#[derive(Debug, thiserror::Error)]
pub enum ProjectExportError {
    /// The node has no managed-DB/compute context to export or import (no sql bindings /
    /// no compute backend) — the capability is not available here.
    #[error("project export/import is not available on this node: {0}")]
    Unavailable(String),
    /// A Postgres schema-ledger fingerprint mismatch was detected and `allow_schema_skew`
    /// was not set — refused so a `--data-only` restore cannot land data into a target
    /// whose migrated schema differs from what the data expects.
    #[error(
        "schema skew: the target's migrated schema differs from the source bundle for {0:?}; \
         re-run with --allow-schema-skew only if you intend to load the data anyway"
    )]
    SchemaSkew(Vec<String>),
    /// The control-plane KV import refused a non-pristine destination without `force`
    /// (the commingle guard).
    #[error("{0}")]
    Commingle(String),
    /// Any other failure (a backend error, an engine dump/restore failure, a bundle error).
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Streaming project CLONE (PLAN-project-clone, increment 1) — the manifest-first,
// target-driven handshake layered ON TOP of the existing streaming export/import.
//
// A clone is `import <target> --clone-from <source>`: the TARGET pulls from the SOURCE
// and restores each format-v2/v3 member as it streams in (O(largest member), nothing
// staged full-size). Resumable from day one via a cheap MANIFEST ([`CloneManifest`]): the
// source lists its blob objects (SHAs/refs, NO full materialization — a LIST, not a read);
// the target diffs that against its OWN content-addressed store ([`CloneSkip`]) and the
// source then streams ONLY the members the target is missing. Blobs flow bucket→bucket; the
// restore reuses the existing inc2 atomic shadow-restore + target-scope enforcement, so a
// clone is NEVER trusted to write outside the target's own project scope.
// ---------------------------------------------------------------------------

/// One blob object the SOURCE holds, as listed in the cheap clone [`CloneManifest`]. Carries
/// the bundle member PATH (`blobs/hblob/{source}/…` — re-keyed to the target's own scope on
/// restore, exactly like the streaming export) plus a cheap CONTENT identity for the per-SHA
/// presence skip: the backend `etag` when the store supplies one (real S3/GCS — the content
/// hash, free from a LIST), else the declared `size`. Produced from a prefix LIST — never a
/// body read — so the manifest stays O(object-count), never O(bytes), even at 33 GB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneBlobRef {
    /// The bundle member path (`blobs/hblob/{source}/{site}/{container}/{key}`).
    pub member_path: String,
    /// The object's byte length when known (the fallback content identity on a backend with
    /// no etag, e.g. the local fs store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The backend entity tag when available (the strong content identity — a content hash on
    /// S3/GCS). `None` ⇒ fall back to `size` for the presence skip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

/// The cheap clone MANIFEST the SOURCE produces for the manifest-first handshake — a LIST of
/// the project's blob objects (for the target's per-SHA diff) plus the non-blob member paths
/// (DB/KV/identity) the target will always pull. NO full materialization: blobs come from a
/// prefix list, the non-blob members from a light enumeration (no engine version-detection /
/// dump). The target diffs [`blobs`](Self::blobs) against its own content-addressed store and
/// asks the source to stream only the missing members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneManifest {
    /// The project the manifest was produced for (the clone SOURCE). The target cross-checks
    /// this against the operator-requested source before trusting any member path.
    pub source_project: String,
    /// Whether the clone stream will be a `--data-only` bundle (no control-plane KV/identity).
    pub data_only: bool,
    /// Every blob object the source holds under the project's own `hblob/{source}/` scope — the
    /// set the target diffs against its own store. Scoped STRUCTURALLY by the project prefix, so
    /// no other tenant's object can appear here.
    pub blobs: Vec<CloneBlobRef>,
    /// The non-blob member paths (pg/mysql/libsql/kv/identity) the clone stream carries — always
    /// pulled (small relative to blobs; the manifest-diff is a blob optimization only).
    /// Informational for the operator/logs; the target does not gate on it.
    #[serde(default)]
    pub non_blob_members: Vec<String>,
}

/// The TARGET's diff result: the set of SOURCE blob member paths the target ALREADY holds
/// (content-matched in its own scope) and so the source must OMIT from the clone stream (the
/// per-SHA / content-presence skip). Everything the target is missing streams. On a resume the
/// target re-diffs, so a re-run transfers only the remainder — O(remaining), not an O(largest
/// member) re-stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneSkip {
    /// SOURCE blob member paths (`blobs/hblob/{source}/…`) the source should NOT stream — the
    /// target already holds a content-matched object at the re-keyed target key.
    pub skip_member_paths: std::collections::BTreeSet<String>,
}

/// The CHEAP PLAN a dry-run clone returns (the DEFAULT, non-`apply` posture): the outcome of the
/// manifest-first handshake WITHOUT opening the source stream or restoring anything. Built from the
/// source [`CloneManifest`] and the target's own [`CloneSkip`] diff — the same diff + scope logic a
/// real clone runs, just stopped before the stream — so a `~18k`-blob / `~33 GB` env-clone answers
/// in the time of a manifest fetch + a (bound-parallelized) HEAD diff rather than ~39 min of
/// silence. `apply` then restores exactly this plan's `blobs_to_transfer` + `non_blob_members`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClonePlan {
    /// The project on the SOURCE node the plan was built for.
    pub source_project: String,
    /// The TARGET project the clone would restore into (this node).
    pub target_project: String,
    /// Whether the clone stream would be `--data-only` (no control-plane KV / identity).
    pub data_only: bool,
    /// Blob objects the source holds under its own scope (the manifest's blob count).
    pub blobs_total: usize,
    /// Blobs the target ALREADY holds content-matched in its own scope (the diff skip set) — these
    /// would NOT be transferred (the resume / per-SHA skip).
    pub blobs_present: usize,
    /// Blobs the target is MISSING and would pull (`blobs_total - blobs_present`).
    pub blobs_to_transfer: usize,
    /// Approximate bytes to transfer: the sum of the KNOWN sizes among the to-transfer blobs. A
    /// backend with no per-object size (fallback) contributes nothing, so this is a LOWER BOUND
    /// unless [`bytes_exact`](Self::bytes_exact) is set.
    pub bytes_to_transfer: u64,
    /// `true` iff EVERY to-transfer blob carried a known size (so [`bytes_to_transfer`] is exact,
    /// not a lower bound).
    pub bytes_exact: bool,
    /// The non-blob member paths (managed-DB dumps, the KV slice, identity) the clone stream would
    /// always carry — informational; the manifest diff is a blob optimization only.
    pub non_blob_members: Vec<String>,
}

impl ClonePlan {
    /// Build the plan from the source manifest + the target's diff skip set, for the target
    /// project. PURE — no I/O, no scope decisions of its own: it reports what the SAME diff +
    /// scope logic (`clone_blobs_present`) already decided. A blob is counted "present" iff its
    /// source member path is in `skip.skip_member_paths` (exactly the set the source will omit).
    pub fn from_manifest_and_skip(
        manifest: &CloneManifest,
        skip: &CloneSkip,
        target_project: &str,
    ) -> Self {
        let mut blobs_present = 0usize;
        let mut blobs_to_transfer = 0usize;
        let mut bytes_to_transfer = 0u64;
        let mut bytes_exact = true;
        for b in &manifest.blobs {
            if skip.skip_member_paths.contains(&b.member_path) {
                blobs_present += 1;
            } else {
                blobs_to_transfer += 1;
                match b.size {
                    Some(s) => bytes_to_transfer = bytes_to_transfer.saturating_add(s),
                    None => bytes_exact = false,
                }
            }
        }
        Self {
            source_project: manifest.source_project.clone(),
            target_project: target_project.to_string(),
            data_only: manifest.data_only,
            blobs_total: manifest.blobs.len(),
            blobs_present,
            blobs_to_transfer,
            bytes_to_transfer,
            bytes_exact,
            non_blob_members: manifest.non_blob_members.clone(),
        }
    }
}

/// One line of the NDJSON progress stream a clone `--apply` (or `--clone-verify`) returns, so a
/// long clone is never zero-output: the orchestrator sends the [`Plan`](Self::Plan) up front, then
/// periodic [`Progress`](Self::Progress) as bytes flow, and finally exactly one terminal
/// [`Report`](Self::Report) (success) or [`Error`](Self::Error). The dry-run (plan-only) path
/// returns a bare [`ClonePlan`] instead — not this envelope. Internally tagged on `event` so each
/// line is a self-describing JSON object the CLI can dispatch on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CloneEvent {
    /// The plan, emitted first (even on `--apply`), so the operator sees the shape before bytes move.
    Plan(ClonePlan),
    /// Periodic transfer progress: bytes pulled from the source so far and elapsed wall-clock.
    Progress {
        bytes_transferred: u64,
        elapsed_secs: u64,
    },
    /// The terminal success event: the final import/restore report.
    Report(ImportReport),
    /// The terminal failure event: the restore failed AFTER the stream opened (an already-`200`
    /// response can no longer change status, so the failure rides in-band — mirroring the streamed
    /// export's own after-first-byte failure mode).
    Error { message: String },
}

/// The project export/import capability (see the module docs).
#[async_trait]
pub trait ProjectExport: Send + Sync {
    /// Stream a `project` export bundle (`BRPROJ`, format v2) into `sink`. The caller (the
    /// API handler) wires `sink` to the HTTP response body, so the bundle is produced and
    /// sent member-by-member with a transient on-disk staging bounded to the largest single
    /// member — never the whole bundle. `opts` selects data-only vs full and whether to
    /// include the identity transport container. Because the bytes stream as they are
    /// produced, a failure AFTER the first bytes cannot change an already-sent HTTP status;
    /// the bundle's per-member size + SHA-256 make a truncated/partial bundle fail LOUD on
    /// import instead.
    async fn export(
        &self,
        project: &str,
        opts: &ExportOptions,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<(), ProjectExportError>;

    /// Import a bundle streamed from `src` into `project`, in a single forward pass (reads
    /// both the v2 streamable format and legacy v1 bundles — the reader dispatches on the
    /// manifest version). Each member is restored as it streams, with a transient on-disk
    /// staging bounded to the largest single member. Dry-run (plan only) unless `opts.apply`.
    /// Returns a summary report.
    async fn import(
        &self,
        project: &str,
        src: &mut (dyn AsyncRead + Send + Unpin),
        opts: ImportOptions,
    ) -> Result<ImportReport, ProjectExportError>;

    /// Resumable export of `project` into a member-object directory named by the operator
    /// relative to the node's configured resumable base (NOT a client path — the directory
    /// is node-local, which is what lets an interrupted export resume instead of restart).
    /// `dir_name` is a single relative name under that base; the impl confines it and
    /// REFUSES when no base is configured or the name escapes the base (fail-closed). On
    /// re-run it skips members already written + SHA-valid. Unlike [`export`], this does not
    /// stream to a sink — it writes the dir and returns on completion. Default impl refuses
    /// (a node without the resumable capability).
    async fn export_resumable(
        &self,
        _project: &str,
        _opts: &ExportOptions,
        _dir_name: &str,
    ) -> Result<(), ProjectExportError> {
        Err(ProjectExportError::Other(
            "resumable export is not available on this node".into(),
        ))
    }

    /// Import a resumable member-object directory (the output of [`export_resumable`]) named
    /// by the operator relative to the node's configured resumable base. Confined + refused
    /// identically to [`export_resumable`]. Restores members in the MANIFEST's authoritative
    /// order. Default impl refuses.
    async fn import_resumable(
        &self,
        _project: &str,
        _dir_name: &str,
        _opts: ImportOptions,
    ) -> Result<ImportReport, ProjectExportError> {
        Err(ProjectExportError::Other(
            "resumable import is not available on this node".into(),
        ))
    }

    /// CLONE SOURCE — produce the cheap [`CloneManifest`] (blob LIST + non-blob member paths, no
    /// full materialization) the target diffs for the manifest-first handshake. `opts.data_only`
    /// selects whether the eventual clone stream carries the control-plane KV slice. Default impl
    /// refuses (a node without the clone capability).
    async fn clone_manifest(
        &self,
        _project: &str,
        _opts: &ExportOptions,
    ) -> Result<CloneManifest, ProjectExportError> {
        Err(ProjectExportError::Other(
            "project clone is not available on this node".into(),
        ))
    }

    /// CLONE TARGET — diff the source's listed `blobs` against THIS node's own content-addressed
    /// store, returning the [`CloneSkip`] set of source member paths the target already holds (so
    /// the source omits them from the stream — the per-SHA presence skip / resume). Each ref is
    /// re-keyed to the target's OWN scope (`source_project` → this project) before the presence
    /// check, and a ref outside `hblob/{source_project}/` is REFUSED fail-closed — the target never
    /// reads or writes outside its own scope. Default impl refuses.
    async fn clone_blobs_present(
        &self,
        _project: &str,
        _source_project: &str,
        _blobs: &[CloneBlobRef],
    ) -> Result<CloneSkip, ProjectExportError> {
        Err(ProjectExportError::Other(
            "project clone is not available on this node".into(),
        ))
    }

    /// CLONE SOURCE — stream a format-v2/v3 bundle of exactly the members the target is missing:
    /// the ordinary streaming [`export`](Self::export) with the `skip`ped blob members OMITTED
    /// from both the MANIFEST and the stream (so the target restores it through the SAME inc2
    /// atomic reader, unchanged). Only blob members may be skipped; any other skip entry is
    /// ignored. Default impl refuses.
    async fn export_clone(
        &self,
        _project: &str,
        _opts: &ExportOptions,
        _skip: &CloneSkip,
        _sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<(), ProjectExportError> {
        Err(ProjectExportError::Other(
            "project clone is not available on this node".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::KvDumpEntry;

    fn e(key: &str, value: &[u8]) -> KvDumpEntry {
        KvDumpEntry {
            key: key.to_string(),
            value: value.to_vec(),
            version: 1,
        }
    }

    /// GATE (C1 cross-tenant isolation): a single-project export's KV slice carries ZERO other
    /// tenant's material and NO global TLS/routing/daemon keys. Two projects (`acme`, `globex`)
    /// plus the global crown-jewel keyspaces share one store; scoping to `acme` keeps exactly
    /// acme's owned keyspace + the site-config body acme references, and drops everything else.
    #[test]
    fn scope_excludes_other_tenants_and_global_crown_jewels() {
        let all = vec![
            // --- acme's OWNED keyspace (must survive) ---
            e("project/acme/secret/api-key", b"sealed"),
            e("project/acme/tenant-secret/t1/token", b"sealed-t"),
            e("project/acme/tenant-secret-index/t1", b"idx"),
            e("project/acme/email/smtp", b"sealed-pw"),
            e("project/acme/config/tenancy", b"{}"),
            e("project/acme/site/web", b"HASHACME"), // pointer → siteconfig/HASHACME
            e("graphql/acme/subgraph/users", b"sdl"),
            e("hapq/acme/abc123", b"op"),
            e("managed-sql-cred/acme/pg", b"sealed-cred"),
            e("siteconfig/HASHACME", b"{...acme config...}"), // referenced by acme → survive
            // --- OTHER tenant's material (every one MUST be excluded) ---
            e("project/globex/secret/other", b"globex-sealed"),
            e("project/globex/email/smtp", b"globex-pw"),
            e("managed-sql-cred/globex/pg", b"globex-cred"),
            e("graphql/globex/subgraph/x", b"globex-sdl"),
            e("hapq/globex/zzz", b"globex-op"),
            e("siteconfig/HASHGLOBEX", b"{...globex config...}"), // NOT referenced by acme
            // sibling-prefix over-capture guard: `acmecorp` is NOT `acme`.
            e("project/acmecorp/secret/s", b"neighbour-sealed"),
            // --- global crown jewels / node state (MUST be excluded) ---
            e("cert/acme.example.com", b"TLS-PRIVATE-KEY-acme"),
            e("cert/globex.example.com", b"TLS-PRIVATE-KEY-globex"),
            e("domain/acme.example.com", br#"{"project":"acme"}"#),
            e("wildcard/.acme.dev", br#"{"project":"acme"}"#),
            e("daemonconfig/deadbeef", b"node-config"),
        ];

        let kept: std::collections::BTreeSet<String> =
            scope_entries_to_project(all, ProjectRef::new("acme"))
                .into_iter()
                .map(|x| x.key)
                .collect();

        let expected: std::collections::BTreeSet<String> = [
            "project/acme/secret/api-key",
            "project/acme/tenant-secret/t1/token",
            "project/acme/tenant-secret-index/t1",
            "project/acme/email/smtp",
            "project/acme/config/tenancy",
            "project/acme/site/web",
            "graphql/acme/subgraph/users",
            "hapq/acme/abc123",
            "managed-sql-cred/acme/pg",
            "siteconfig/HASHACME",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            kept, expected,
            "exactly acme's keyspace + its referenced site config"
        );

        // The load-bearing security assertions, stated independently of the exact set:
        assert!(
            !kept.iter().any(|k| k.contains("globex")),
            "NO other-tenant (globex) key may appear in acme's export"
        );
        assert!(
            !kept.iter().any(|k| k.starts_with("cert/")),
            "NO TLS private key (any project) travels in a portable bundle"
        );
        assert!(
            !kept
                .iter()
                .any(|k| k.starts_with("domain/") || k.starts_with("wildcard/")),
            "NO global routing-ownership record travels"
        );
        assert!(
            !kept.iter().any(|k| k.starts_with("daemonconfig/")),
            "NO node daemon config travels with a project"
        );
        assert!(
            !kept.contains("project/acmecorp/secret/s"),
            "a sibling project sharing a name PREFIX is not over-captured"
        );
        assert!(
            !kept.contains("siteconfig/HASHGLOBEX"),
            "only the site-config bodies THIS project references are carried"
        );
    }

    /// GATE (H1): `--identity fresh` drops the COMPLETE sealed / environment-coupled keyspace —
    /// including the previously-missed `email/` and `managed-sql-cred/` families.
    #[test]
    fn sealed_prefixes_cover_the_complete_coupled_keyspace() {
        let p = sealed_secret_prefixes(ProjectRef::new("acme"));
        for want in [
            "project/acme/secret/",
            "project/acme/tenant-secret/",
            "project/acme/tenant-secret-index/",
            "project/acme/email/",
            "managed-sql-cred/acme/",
        ] {
            assert!(
                p.iter().any(|x| x == want),
                "fresh-drop set must include {want:?}"
            );
        }
    }

    /// The import re-key rewrites ONLY the owned project segment, leaving content-addressed
    /// bodies untouched and never over-rewriting a sibling-prefix project.
    #[test]
    fn rekey_rewrites_owned_segment_only() {
        let rk = |k: &str| rekey_owned_key(k, "acme", "beta");
        assert_eq!(rk("project/acme/secret/x"), "project/beta/secret/x");
        assert_eq!(rk("graphql/acme/subgraph/u"), "graphql/beta/subgraph/u");
        assert_eq!(rk("hapq/acme/h"), "hapq/beta/h");
        assert_eq!(rk("managed-sql-cred/acme/pg"), "managed-sql-cred/beta/pg");
        // Content-addressed body — identity-free, untouched.
        assert_eq!(rk("siteconfig/HASH"), "siteconfig/HASH");
        // Sibling-prefix project is NOT rewritten.
        assert_eq!(rk("project/acmecorp/secret/x"), "project/acmecorp/secret/x");
        // source == target is a no-op over a whole slice.
        let mut slice = vec![e("project/acme/secret/x", b"v")];
        rekey_entries_to_target(&mut slice, "acme", "acme");
        assert_eq!(slice[0].key, "project/acme/secret/x");
        rekey_entries_to_target(&mut slice, "acme", "beta");
        assert_eq!(slice[0].key, "project/beta/secret/x");
    }

    /// GATE (HIGH-1 import-direction, symmetric fail-closed): after re-key, the import-side
    /// [`enforce_target_scoped_kv`] ACCEPTS a slice that is entirely target-owned plus a
    /// referenced, content-correct `siteconfig/<hash>`, and REFUSES any foreign-tenant / global
    /// / reserved / unreferenced / poisoned key. The mutation that drops this refuse (skipping
    /// the import-side filter) is exactly the fail-OPEN cross-tenant-overwrite bug it guards.
    #[test]
    fn import_enforce_accepts_target_scope_and_refuses_foreign_or_poisoned() {
        let target = ProjectRef::new("acme");
        let site_body = b"{\"acme\":\"site\"}";
        let site_hash = hex::encode(Sha256::digest(site_body));
        let site_key = crate::deploy::keys::site_config_blob(&site_hash);

        // A fully legitimate re-keyed slice: owned keys + the site pointer + its content-correct
        // body — ACCEPTED.
        let ok = vec![
            e("project/acme/config/tenancy", b"{}"),
            e("project/acme/secret/api-key", b"sealed"),
            e("graphql/acme/subgraph/u", b"sdl"),
            e("hapq/acme/op", b"op"),
            e("managed-sql-cred/acme/pg", b"cred"),
            e("project/acme/site/web", site_hash.as_bytes()),
            e(&site_key, site_body),
        ];
        assert!(
            enforce_target_scoped_kv(&ok, target).is_ok(),
            "a fully target-owned + content-correct slice must be accepted"
        );

        // Each of these, mixed into an otherwise-legit slice, must ABORT the import.
        for (what, bad) in [
            ("another tenant", e("project/globex/secret/x", b"foreign")),
            (
                "a sibling-prefix project",
                e("project/acmecorp/secret/x", b"neighbour"),
            ),
            ("a global TLS key", e("cert/acme.example.com", b"TLS")),
            (
                "a global routing record",
                e("domain/acme.example.com", b"{}"),
            ),
            ("a wildcard routing record", e("wildcard/.acme.dev", b"{}")),
            ("a node daemon config", e("daemonconfig/deadbeef", b"cfg")),
            ("a reserved coordination key", e("_cp/leader", b"node-1")),
            (
                "an unreferenced siteconfig",
                e("siteconfig/orphanhash", b"body"),
            ),
        ] {
            let mut slice = vec![e("project/acme/config/tenancy", b"{}"), bad];
            assert!(
                enforce_target_scoped_kv(&slice, target).is_err(),
                "import must refuse {what}"
            );
            slice.clear();
        }

        // A POISONED siteconfig: referenced by the target's pointer but body != content-address.
        let poisoned = vec![
            e("project/acme/site/web", b"deadbeef"),
            e("siteconfig/deadbeef", b"not-the-preimage"),
        ];
        assert!(
            enforce_target_scoped_kv(&poisoned, target).is_err(),
            "import must refuse a siteconfig whose body does not hash to its key"
        );
    }

    fn bref(path: &str, size: Option<u64>) -> CloneBlobRef {
        CloneBlobRef {
            member_path: path.to_string(),
            size,
            etag: None,
        }
    }

    /// The cheap plan reports exactly the diff's decision: present blobs come from the skip set,
    /// the rest transfer, and the to-transfer bytes sum the KNOWN sizes. The plan is a pure
    /// projection of `(manifest, skip)` — it makes NO scope decision of its own.
    #[test]
    fn clone_plan_counts_match_the_diff_skip_set() {
        let manifest = CloneManifest {
            source_project: "acme".into(),
            data_only: false,
            blobs: vec![
                bref("blobs/hblob/acme/web/c/a", Some(100)),
                bref("blobs/hblob/acme/web/c/b", Some(250)),
                bref("blobs/hblob/acme/web/c/c", Some(50)),
            ],
            non_blob_members: vec!["sql/app.pgc".into(), "kv/control-plane.jsonl".into()],
        };
        // The target already holds `a` (present ⇒ skip); `b` and `c` must transfer.
        let mut skip = CloneSkip::default();
        skip.skip_member_paths
            .insert("blobs/hblob/acme/web/c/a".into());

        let plan = ClonePlan::from_manifest_and_skip(&manifest, &skip, "acme-staging");
        assert_eq!(plan.source_project, "acme");
        assert_eq!(plan.target_project, "acme-staging");
        assert_eq!(plan.blobs_total, 3);
        assert_eq!(plan.blobs_present, 1);
        assert_eq!(plan.blobs_to_transfer, 2);
        assert_eq!(plan.bytes_to_transfer, 300); // 250 + 50, NOT the skipped `a`'s 100
        assert!(plan.bytes_exact, "every to-transfer blob had a known size");
        assert_eq!(plan.non_blob_members.len(), 2);
    }

    /// A to-transfer blob with NO known size (a fallback backend) makes `bytes_to_transfer` a
    /// lower bound and clears `bytes_exact`, so the operator is not misled into thinking a
    /// partial byte total is the whole transfer.
    #[test]
    fn clone_plan_bytes_are_a_lower_bound_when_a_size_is_unknown() {
        let manifest = CloneManifest {
            source_project: "acme".into(),
            data_only: false,
            blobs: vec![
                bref("blobs/hblob/acme/web/c/a", Some(100)),
                bref("blobs/hblob/acme/web/c/b", None),
            ],
            non_blob_members: vec![],
        };
        let plan = ClonePlan::from_manifest_and_skip(&manifest, &CloneSkip::default(), "acme");
        assert_eq!(plan.blobs_to_transfer, 2);
        assert_eq!(
            plan.bytes_to_transfer, 100,
            "only the known size contributes"
        );
        assert!(
            !plan.bytes_exact,
            "an unknown size makes the total a lower bound"
        );
    }

    /// The NDJSON event envelope round-trips through serde internally-tagged on `event`, so the
    /// orchestrator's lines decode on the CLI (plan / progress / terminal report).
    #[test]
    fn clone_event_ndjson_round_trips() {
        let plan = ClonePlan {
            source_project: "acme".into(),
            target_project: "acme".into(),
            blobs_total: 2,
            blobs_to_transfer: 2,
            ..Default::default()
        };
        for ev in [
            CloneEvent::Plan(plan),
            CloneEvent::Progress {
                bytes_transferred: 4096,
                elapsed_secs: 3,
            },
            CloneEvent::Report(ImportReport {
                blobs: 2,
                ..Default::default()
            }),
            CloneEvent::Error {
                message: "boom".into(),
            },
        ] {
            let line = serde_json::to_string(&ev).unwrap();
            let back: CloneEvent = serde_json::from_str(&line).unwrap();
            // The tag is present and the payload survives a round-trip.
            assert!(line.contains("\"event\""), "tagged line: {line}");
            match (ev, back) {
                (CloneEvent::Plan(a), CloneEvent::Plan(b)) => assert_eq!(a, b),
                (
                    CloneEvent::Progress {
                        bytes_transferred, ..
                    },
                    CloneEvent::Progress {
                        bytes_transferred: b,
                        ..
                    },
                ) => assert_eq!(bytes_transferred, b),
                (CloneEvent::Report(a), CloneEvent::Report(b)) => assert_eq!(a.blobs, b.blobs),
                (CloneEvent::Error { message }, CloneEvent::Error { message: b }) => {
                    assert_eq!(message, b);
                }
                _ => panic!("event variant changed across the round-trip"),
            }
        }
    }
}
