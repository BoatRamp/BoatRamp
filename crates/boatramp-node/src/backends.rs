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

/// Where the SlateDB control-plane store lives when it runs on an S3-compatible
/// object store (Cloudflare R2) instead of local disk — the durable, remote-state
/// deployment. Credentials come from the ambient AWS environment
/// (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), matching the S3 blob backend.
#[derive(Debug, Clone)]
pub struct SlateKvS3 {
    /// The bucket the store lives in (shared with S3 blobs, under `prefix`).
    pub bucket: String,
    /// Custom endpoint (R2: `https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: Option<String>,
    /// Region (R2 uses `auto`).
    pub region: Option<String>,
    /// Use path-style addressing (R2 accepts it).
    pub path_style: bool,
    /// Key prefix within the bucket (keeps the LSM files apart from the blobs).
    pub prefix: String,
}

/// Build the metadata KV store for the selected [`KvBackend`]. When `slate_s3` is
/// set (and the backend is SlateDB), the store runs on R2/S3 (durable across a
/// scale-to-zero container stop) rather than the local `data_dir`.
pub async fn build_kv(
    kv: KvBackend,
    data_dir: &Path,
    slate_s3: Option<&SlateKvS3>,
) -> Result<Arc<dyn KvStore>> {
    match kv {
        KvBackend::Slatedb => build_slatedb_kv(data_dir, slate_s3).await,
        KvBackend::Memory => Ok(Arc::new(MemoryKv::new())),
        KvBackend::Cloudflare => build_cloudflare_kv(),
    }
}

#[cfg(feature = "slatedb")]
async fn build_slatedb_kv(
    data_dir: &Path,
    slate_s3: Option<&SlateKvS3>,
) -> Result<Arc<dyn KvStore>> {
    match slate_s3 {
        Some(s3) => Ok(Arc::new(
            boatramp_storage::SlateKv::open_s3_with_flush(
                &boatramp_storage::S3StoreConfig {
                    bucket: s3.bucket.clone(),
                    endpoint: s3.endpoint.clone(),
                    region: s3.region.clone(),
                    path_style: s3.path_style,
                },
                &s3.prefix,
                CONTROL_PLANE_FLUSH,
            )
            .await?,
        )),
        None => Ok(Arc::new(
            boatramp_storage::SlateKv::open_local_with_flush(
                data_dir.join("kv-slate"),
                CONTROL_PLANE_FLUSH,
            )
            .await?,
        )),
    }
}

#[cfg(not(feature = "slatedb"))]
async fn build_slatedb_kv(
    _data_dir: &Path,
    _slate_s3: Option<&SlateKvS3>,
) -> Result<Arc<dyn KvStore>> {
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
