//! Deployment **wire structs**: the serde models the server writes, the CLI
//! reads, and the web console renders — provenance metadata ([`DeployMeta`]),
//! activation history ([`HistoryEntry`]/[`DeploymentList`]), and the
//! garbage-collection / integrity-scrub reports ([`GcReport`]/[`ScrubReport`]).
//!
//! These are pure serde (no IO/KV/Storage), so they live in `boatramp-types`
//! (one canonical definition, wasm-clean) and `boatramp-core::deploy`
//! re-exports them. The `DeployStore` plumbing that produces them stays in core.

use serde::{Deserialize, Serialize};

/// Metadata about a deployment, captured at publish time and kept alongside the
/// (content-addressed, immutable) manifest. It is stored separately from the
/// manifest precisely *because* it is mutable provenance — putting it inside the
/// manifest would change the content id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployMeta {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`].
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// Unix timestamp (seconds) when this manifest was *first* stored. The GC
    /// grace window keys off this, so it is never overwritten on re-deploy.
    pub created_at: u64,
    /// Number of files in the deployment.
    pub file_count: u64,
    /// Total bytes across all files.
    pub total_size: u64,
    /// Source revision (e.g. a git commit SHA), if the client supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Source branch, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Deploy author, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Free-form deploy message, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Client-supplied provenance for a deployment (the mutable subset of
/// [`DeployMeta`]; sizes and `created_at` are filled in server-side).
#[derive(Debug, Clone, Default)]
pub struct DeployMetaInput {
    /// Source revision (git SHA).
    pub source: Option<String>,
    /// Source branch.
    pub branch: Option<String>,
    /// Deploy author.
    pub author: Option<String>,
    /// Deploy message.
    pub message: Option<String>,
}

/// An entry in a site's activation history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Deployment id that was activated.
    pub id: String,
    /// Unix timestamp (seconds) of the activation.
    pub at: u64,
    /// Provenance for this deployment, joined in when the list is read (never
    /// persisted in the history record itself — see `DeployStore::deployments`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<DeployMeta>,
}

/// A site's current deployment plus its activation history.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentList {
    /// The currently-active deployment id, if any.
    pub current: Option<String>,
    /// Activation history, most recent first.
    pub deployments: Vec<HistoryEntry>,
}

/// What a garbage-collection pass found (or removed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcReport {
    /// Total deploy manifests present.
    pub manifests_total: usize,
    /// Orphan manifests removed (or removable, in a dry run).
    pub manifests_removed: usize,
    /// Total blobs present.
    pub blobs_total: usize,
    /// Unreferenced blobs removed (or removable, in a dry run).
    pub blobs_removed: usize,
    /// Bytes reclaimed (or reclaimable) from removed blobs.
    pub bytes_reclaimed: u64,
}

/// One blob whose content no longer hashes to its key (a scrub finding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMismatch {
    /// The storage key (`blobs/<shard>/<hash>`).
    pub key: String,
    /// The hash the key claims the bytes have.
    pub expected: String,
    /// The hash actually computed from the stored bytes.
    pub actual: String,
}

/// One blob that could not be read during a scrub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobReadError {
    /// The storage key.
    pub key: String,
    /// Why the read failed.
    pub error: String,
}

/// What a blob integrity scrub found. Read-only — a scrub never
/// deletes; it reports so an operator can re-deploy or restore the affected
/// content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubReport {
    /// Blobs checked.
    pub checked: usize,
    /// Blobs whose content no longer matches their key (corruption/tampering).
    pub mismatched: Vec<BlobMismatch>,
    /// Blobs that could not be read.
    pub errors: Vec<BlobReadError>,
}

impl ScrubReport {
    /// Whether the scrub found no corruption and no read errors.
    pub fn is_clean(&self) -> bool {
        self.mismatched.is_empty() && self.errors.is_empty()
    }
}
