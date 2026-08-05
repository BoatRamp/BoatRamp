//! Backend-selection enums for a node's blob + KV stores (node-library N2b).
//!
//! These are the domain types the store-construction assembly dispatches on. They
//! live here (not the binary) so the assembly can move into the library; the
//! `clap::ValueEnum` derive is behind the optional `clap` feature so the CLI
//! binary uses them directly in its args, while a non-CLI embedder never pulls
//! clap. (`build_kv`/`build_blobs` join this module as they migrate off the
//! binary's `ServeArgs`.)

/// Blob (file-content) backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum BlobBackend {
    /// Local filesystem (`<data-dir>/blobs`).
    Fs,
    /// S3-compatible object store (requires `--features s3`).
    S3,
    /// Google Cloud Storage (requires `--features gcs`).
    Gcs,
    /// Azure Blob Storage (requires `--features azure`).
    Azure,
}

/// Metadata (manifest + pointer) backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum KvBackend {
    /// Transactional LSM over object storage; durable local default
    /// (`<data-dir>/kv-slate`). Requires `--features slatedb` (on by default).
    Slatedb,
    /// In-memory (ephemeral; lost on restart).
    Memory,
    /// Cloudflare KV over REST (requires `--features cloudflare-kv`).
    Cloudflare,
}
