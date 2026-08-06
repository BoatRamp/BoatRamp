//! Backend-selection enums for a node's blob + KV stores (node-library N2b).
//!
//! These are the domain types the store-construction assembly dispatches on. They
//! live here (not the binary) so the assembly can move into the library; the
//! `clap::ValueEnum` derive is behind the optional `clap` feature so the CLI
//! binary uses them directly in its args, while a non-CLI embedder never pulls
//! clap. (`build_kv`/`build_blobs` join this module as they migrate off the
//! binary's `ServeArgs`.)

use std::path::Path;
use std::sync::Arc;

use boatramp_core::kv::{KvStore, MemoryKv};

use crate::error::Result;

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

/// Flush interval for the control-plane SlateDB store: tiny, so a control-plane
/// write is durable almost immediately (correctness over throughput).
pub const CONTROL_PLANE_FLUSH: std::time::Duration = std::time::Duration::from_millis(5);

/// Build the metadata KV store for the selected [`KvBackend`].
pub async fn build_kv(kv: KvBackend, data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    match kv {
        KvBackend::Slatedb => build_slatedb_kv(data_dir).await,
        KvBackend::Memory => Ok(Arc::new(MemoryKv::new())),
        KvBackend::Cloudflare => build_cloudflare_kv(),
    }
}

#[cfg(feature = "slatedb")]
async fn build_slatedb_kv(data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    Ok(Arc::new(
        boatramp_storage::SlateKv::open_local_with_flush(
            data_dir.join("kv-slate"),
            CONTROL_PLANE_FLUSH,
        )
        .await?,
    ))
}

#[cfg(not(feature = "slatedb"))]
async fn build_slatedb_kv(_data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    Err(crate::error::Error::NoSlatedbSupport)
}

#[cfg(feature = "cloudflare-kv")]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Ok(Arc::new(boatramp_storage::CloudflareKv::from_env()?))
}

#[cfg(not(feature = "cloudflare-kv"))]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Err(crate::error::Error::NoCloudflareKvSupport)
}
