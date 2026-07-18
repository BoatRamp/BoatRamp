//! Blob/KV backend construction for `boatramp serve`: build the configured
//! object store (fs/S3/GCS/Azure, with optional blob-change notification
//! provisioning) and KV store (SlateDB/memory/Cloudflare) from the CLI args. Each
//! cloud backend is feature-gated; a disabled one returns an explanatory error
//! rather than a misleading no-op.

use std::path::Path;
use std::sync::Arc;

use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::Storage;
use boatramp_storage::FsStorage;

use super::{BlobBackend, Error, KvBackend, Result, ServeArgs};

/// The blob backend plus, on a cloud object store with notification provisioning
/// configured, its blob-change [`WatchProvider`](boatramp_core::blob_provision::WatchProvider)
/// and operator tier (FA-5b2). The provider/tier are consumed only by the handler
/// runtime, so they are dead code in a `--no-default-features` (no `handlers`)
/// build.
pub(super) struct BuiltBlobs {
    pub(super) storage: Arc<dyn Storage>,
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub(super) watch_provider: Option<Arc<dyn boatramp_core::blob_provision::WatchProvider>>,
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub(super) provision_tier: boatramp_core::blob_notify::ProvisionTier,
}

pub(super) async fn build_blobs(
    args: &ServeArgs,
    data_dir: &Path,
    notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    match args.blobs {
        BlobBackend::Fs => Ok(BuiltBlobs {
            storage: Arc::new(FsStorage::new(data_dir.join("blobs"))),
            watch_provider: None,
            provision_tier: boatramp_core::blob_notify::ProvisionTier::default(),
        }),
        BlobBackend::S3 => build_s3(args, notify_tier, notify_account).await,
        BlobBackend::Gcs => build_gcs(args, notify_tier, notify_account).await,
        BlobBackend::Azure => build_azure(args, notify_tier, notify_account).await,
    }
}

// Azure storage + optional blob-change notification (Event Grid → Storage Queue,
// FA-5b2). When a notify tier is configured the backend is consumer-wired and
// paired with the AzureWatchProvider (the Event Grid subscription is an operator
// step — see the provider recipe).
#[cfg(feature = "azure")]
async fn build_azure(
    args: &ServeArgs,
    notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    _notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    let (Some(account), Some(container)) =
        (args.azure_account.clone(), args.azure_container.clone())
    else {
        return Err(Error::AzureConfigRequired);
    };
    let opts = boatramp_storage::AzureOptions {
        account,
        container,
        access_key: args.azure_access_key.clone(),
        emulator: args.azure_emulator,
    };
    match notify_tier {
        Some(tier) => {
            let (storage, provider) = boatramp_storage::AzureStorage::connect_with_notify(opts)
                .map_err(|err| Error::AzureConnect(err.to_string()))?;
            Ok(BuiltBlobs {
                storage: Arc::new(storage),
                watch_provider: Some(Arc::new(provider)),
                provision_tier: tier,
            })
        }
        None => {
            let storage = boatramp_storage::AzureStorage::connect(opts)
                .map_err(|err| Error::AzureConnect(err.to_string()))?;
            Ok(BuiltBlobs {
                storage: Arc::new(storage),
                watch_provider: None,
                provision_tier: boatramp_core::blob_notify::ProvisionTier::default(),
            })
        }
    }
}

#[cfg(not(feature = "azure"))]
async fn build_azure(
    _args: &ServeArgs,
    _notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    _notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    Err(Error::NoAzureSupport)
}

// GCS storage + optional blob-change notification (GCS→Pub/Sub, FA-5b2). When a
// notify tier is configured the backend is consumer-wired and paired with the
// GcsWatchProvider; `blob_notify_account_id` is read as the GCP project id.
#[cfg(feature = "gcs")]
async fn build_gcs(
    args: &ServeArgs,
    notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    let bucket = args.gcs_bucket.clone().ok_or(Error::GcsBucketRequired)?;
    let opts = boatramp_storage::GcsOptions {
        bucket,
        endpoint: args.gcs_endpoint.clone(),
        anonymous: args.gcs_anonymous,
    };
    match notify_tier {
        Some(tier) => {
            let project = notify_account.unwrap_or_default();
            let (storage, provider) =
                boatramp_storage::GcsStorage::connect_with_notify(opts, project)
                    .await
                    .map_err(|err| Error::GcsConnect(err.to_string()))?;
            Ok(BuiltBlobs {
                storage: Arc::new(storage),
                watch_provider: Some(Arc::new(provider)),
                provision_tier: tier,
            })
        }
        None => {
            let storage = boatramp_storage::GcsStorage::connect(opts)
                .await
                .map_err(|err| Error::GcsConnect(err.to_string()))?;
            Ok(BuiltBlobs {
                storage: Arc::new(storage),
                watch_provider: None,
                provision_tier: boatramp_core::blob_notify::ProvisionTier::default(),
            })
        }
    }
}

#[cfg(not(feature = "gcs"))]
async fn build_gcs(
    _args: &ServeArgs,
    _notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    _notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    Err(Error::NoGcsSupport)
}

#[cfg(feature = "s3")]
async fn build_s3(
    args: &ServeArgs,
    notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    let bucket = args.s3_bucket.clone().ok_or(Error::S3BucketRequired)?;
    let opts = boatramp_storage::S3Options {
        bucket,
        endpoint: args.s3_endpoint.clone(),
        region: args.s3_region.clone(),
        force_path_style: args.s3_path_style,
    };
    match notify_tier {
        // Blob-change notification provisioning is enabled: build the
        // consumer-wired storage + the S3→SQS provider from one AWS config.
        Some(tier) => {
            let account = notify_account.unwrap_or_default();
            let (storage, provider) =
                boatramp_storage::S3Storage::connect_with_notify(opts, account).await;
            Ok(BuiltBlobs {
                storage: Arc::new(storage),
                watch_provider: Some(Arc::new(provider)),
                provision_tier: tier,
            })
        }
        // No provisioning configured: a plain S3 backend (blob triggers refuse).
        None => Ok(BuiltBlobs {
            storage: Arc::new(boatramp_storage::S3Storage::connect(opts).await),
            watch_provider: None,
            provision_tier: boatramp_core::blob_notify::ProvisionTier::default(),
        }),
    }
}

#[cfg(not(feature = "s3"))]
async fn build_s3(
    _args: &ServeArgs,
    _notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    _notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    Err(Error::NoS3Support)
}

pub(super) async fn build_kv(args: &ServeArgs, data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    match args.kv {
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
            super::CONTROL_PLANE_FLUSH,
        )
        .await?,
    ))
}

#[cfg(not(feature = "slatedb"))]
async fn build_slatedb_kv(_data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    Err(Error::NoSlatedbSupport)
}

#[cfg(feature = "cloudflare-kv")]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Ok(Arc::new(boatramp_storage::CloudflareKv::from_env()?))
}

#[cfg(not(feature = "cloudflare-kv"))]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Err(Error::NoCloudflareKvSupport)
}
