//! The operator-facing **project export/import** capability — the native env-clone
//! surface (construens). A node that runs a project's managed databases + blobs
//! implements it; the admin API (`POST /api/project-export` / `/api/project-import`,
//! `System·Admin`) and the `boatramp project export|import` CLI client consume it,
//! mirroring the [`OperatorSql`](crate::sql::OperatorSql) /
//! [`ComputeExec`](crate::compute::ComputeExec) capability-trait pattern (a core trait,
//! node-implemented, server-consumed via an axum `Extension`).
//!
//! The methods are **file-based** to stay object-safe and to keep the multi-gigabyte
//! bundle off the heap: `export` writes a bundle file and returns its path (the handler
//! streams it out then deletes it); `import` reads a bundle file (the handler streams
//! the request body to a temp file first). The bundle format itself (the `BRPROJ` tar +
//! MANIFEST) lives in `boatramp-node`.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Serialize;

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
            .finish()
    }
}

/// Flags for an import.
#[derive(Debug, Clone, Copy, Default)]
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
}

/// The outcome of an export or import — a legible summary for the operator / API JSON.
#[derive(Debug, Clone, Default, Serialize)]
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

/// The project export/import capability (see the module docs).
#[async_trait]
pub trait ProjectExport: Send + Sync {
    /// Export `project` to a freshly-written bundle file, returning its path. The caller
    /// (the API handler) streams the file to the response, then deletes it. `opts` selects
    /// data-only vs full and whether to include the identity transport container.
    async fn export(
        &self,
        project: &str,
        opts: &ExportOptions,
    ) -> Result<PathBuf, ProjectExportError>;

    /// Import the bundle at `bundle` into `project`. Dry-run (plan only) unless
    /// `opts.apply`. Returns a summary report.
    async fn import(
        &self,
        project: &str,
        bundle: &Path,
        opts: ImportOptions,
    ) -> Result<ImportReport, ProjectExportError>;

    /// A node-private directory the API handler should stage an INCOMING import bundle
    /// into (a bundle carries a full DB dump — it must never sit in world-readable
    /// `/tmp`). The node implementation returns its own data-dir work area; the default
    /// is the system temp dir (used only by a stub with no node context).
    fn staging_root(&self) -> PathBuf {
        std::env::temp_dir()
    }
}
