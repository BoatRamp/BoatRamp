//! Blob (object-store) backend construction: build the configured object store
//! (fs/S3/GCS/Azure, with optional blob-change notification provisioning) from a
//! resolved [`BlobArgs`]. Each cloud backend is feature-gated; a disabled one
//! returns an explanatory error rather than a misleading no-op. Moved out of the
//! binary (node-library N2b.2c); the binary populates `BlobArgs` from its CLI
//! `ServeArgs`.

use std::path::Path;
use std::sync::Arc;
#[cfg(feature = "fallback")]
use std::time::Duration;

use boatramp_core::Storage;

use crate::backends::BlobBackend;
use crate::error::{Error, Result};

#[cfg(feature = "fs")]
use boatramp_storage::FsStorage;

/// The boatramp read-fallback allowlist predicate (blob-backend migration Part 2): a primary miss
/// falls through to the read-only secondary ONLY for a boatramp-OWNED key —
/// - a content-addressed deploy blob (`{2hex}/{64hex}`, via [`boatramp_core::deploy::is_blob_key`]),
/// - a guest object (`hblob/…`),
/// - a messaging object (`mqgp/…`).
///
/// Any OTHER key (e.g. a stray `config/…` that should never live in the blob store — the mutable
/// control-plane records are in the KV, not `Storage`) is primary-only, so it can NEVER silently
/// resurrect off a secondary during a transition (Security Finding F4/G5-cp, defense-in-depth). The
/// predicate is supplied to the generic [`FallbackStorage`](boatramp_storage::FallbackStorage), which
/// hardcodes no app prefixes.
#[cfg(feature = "fallback")]
pub fn blob_fallback_when() -> boatramp_storage::FallbackWhen {
    Arc::new(|k: &str| {
        boatramp_core::deploy::is_blob_key(k) || k.starts_with("hblob/") || k.starts_with("mqgp/")
    })
}

/// The resolved blob-backend selection — the binary populates this from its CLI
/// `ServeArgs` (the credential/endpoint flags), keeping clap out of the library.
///
/// `s3_credential` (#505) is the optional node-level **sealed base S3 credential** the operator
/// resolved from the `[secrets]` store; when present it is injected into the S3 client's SDK config
/// instead of the ambient env chain. It is a redacted [`SealedS3Credential`], so `BlobArgs` can keep its
/// derived `Debug` without leaking the secret.
#[derive(Debug, Clone)]
pub struct BlobArgs {
    pub blobs: BlobBackend,
    pub s3_bucket: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_region: Option<String>,
    pub s3_path_style: bool,
    /// The node-level sealed base S3 credential (#505). `None` ⇒ the ambient AWS env chain (unchanged).
    pub s3_credential: Option<crate::s3_credential::SealedS3Credential>,
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

/// Build the PRIMARY blob backend (with its notify provisioning) and, when `fallback` is supplied,
/// build a read-only SECONDARY and wrap the pair in a [`FallbackStorage`](boatramp_storage::FallbackStorage)
/// — the zero-downtime backend switch (blob-backend migration Part 2).
///
/// The secondary is built via the SAME [`build_blobs`] path but with **NO watcher provisioning**
/// (`notify_tier: None`, `notify_account: None`) — a read-only drain source never watches — and its
/// `watch_provider`/`provision_tier` are discarded. The returned [`BuiltBlobs`] keeps the PRIMARY's
/// `watch_provider`/`provision_tier` (watching is the primary's capability). The secondary is NEVER
/// handed to the blob-upload/STS minter (that path takes the primary `BlobArgs` only).
///
/// CRITICAL ordering: if a read-through cache is ever wrapped around the result, it must wrap the
/// OUTSIDE — `cache(fallback(primary, secondary))` — so the cache's `allows_prune` delegates through
/// the fallback's `false`. `FallbackStorage` is therefore the INNERMOST composite here; the returned
/// `storage` is the fallback (or the bare primary when no fallback is configured).
#[cfg(feature = "fallback")]
pub async fn build_blobs_with_fallback(
    args: &BlobArgs,
    fallback: Option<(&BlobArgs, Duration)>,
    data_dir: &Path,
    notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    notify_account: Option<String>,
) -> Result<BuiltBlobs> {
    // The PRIMARY carries its notify provisioning (watching stays a primary capability).
    let primary = build_blobs(args, data_dir, notify_tier, notify_account).await?;
    let Some((secondary_args, timeout)) = fallback else {
        return Ok(primary);
    };
    // The read-only SECONDARY: same build path, NO watcher provisioning; discard its
    // watch_provider/provision_tier (a drain source never watches).
    let secondary = build_blobs(secondary_args, data_dir, None, None).await?;
    let composite: Arc<dyn Storage> = Arc::new(boatramp_storage::FallbackStorage::new(
        primary.storage,
        secondary.storage,
        blob_fallback_when(),
        timeout,
    ));
    Ok(BuiltBlobs {
        storage: composite,
        // Keep the PRIMARY's watcher/tier — watching is the primary's capability.
        watch_provider: primary.watch_provider,
        provision_tier: primary.provision_tier,
    })
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
        // #505: when the operator configured a node-level sealed base credential, inject it so the S3
        // client signs with the sealed key rather than the ambient `AWS_ACCESS_KEY_ID`/`_SECRET`.
        credential: args.s3_credential.as_ref().map(|c| c.as_pair()),
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
