//! Blob (object-store) backend construction: build the configured object store
//! (fs/S3/GCS/Azure, with optional blob-change notification provisioning) from a
//! resolved [`BlobArgs`]. Each cloud backend is feature-gated; a disabled one
//! returns an explanatory error rather than a misleading no-op. Moved out of the
//! binary (node-library N2b.2c); the binary populates `BlobArgs` from its CLI
//! `ServeArgs`.

use std::path::Path;
use std::sync::Arc;

use boatramp_core::Storage;

use crate::backends::BlobBackend;
use crate::error::{Error, Result};

#[cfg(feature = "fs")]
use boatramp_storage::FsStorage;

/// The resolved blob-backend selection — the binary populates this from its CLI
/// `ServeArgs` (the credential/endpoint flags), keeping clap out of the library.
#[derive(Debug, Clone)]
pub struct BlobArgs {
    pub blobs: BlobBackend,
    pub s3_bucket: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_region: Option<String>,
    pub s3_path_style: bool,
    pub gcs_bucket: Option<String>,
    pub gcs_endpoint: Option<String>,
    pub gcs_anonymous: bool,
    pub azure_account: Option<String>,
    pub azure_container: Option<String>,
    pub azure_access_key: Option<String>,
    pub azure_emulator: bool,
}

/// The blob backend plus, on a cloud object store with notification provisioning
/// configured, its blob-change [`WatchProvider`](boatramp_core::blob_provision::WatchProvider)
/// and operator tier (FA-5b2). The provider/tier are consumed only by the handler
/// runtime, so they are dead code in a `--no-default-features` (no `handlers`) build.
pub struct BuiltBlobs {
    pub storage: Arc<dyn Storage>,
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub watch_provider: Option<Arc<dyn boatramp_core::blob_provision::WatchProvider>>,
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub provision_tier: boatramp_core::blob_notify::ProvisionTier,
}

/// Build the object store for the selected [`BlobBackend`]. `data_dir` is used
/// only by the `fs` backend (unused when `fs` is off).
#[cfg_attr(not(feature = "fs"), allow(unused_variables))]
pub async fn build_blobs(
    args: &BlobArgs,
    data_dir: &Path,
    notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    match args.blobs {
        #[cfg(feature = "fs")]
        BlobBackend::Fs => Ok(BuiltBlobs {
            storage: Arc::new(FsStorage::new(data_dir.join("blobs"))),
            watch_provider: None,
            provision_tier: boatramp_core::blob_notify::ProvisionTier::default(),
        }),
        #[cfg(not(feature = "fs"))]
        BlobBackend::Fs => Err(Error::NoFsSupport),
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
    args: &BlobArgs,
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
    _args: &BlobArgs,
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
    args: &BlobArgs,
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
    _args: &BlobArgs,
    _notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    _notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    Err(Error::NoGcsSupport)
}

#[cfg(feature = "s3")]
async fn build_s3(
    args: &BlobArgs,
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
    _args: &BlobArgs,
    _notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    _notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    Err(Error::NoS3Support)
}
