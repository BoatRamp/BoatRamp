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
/// - a messaging PAYLOAD — both the work-queue payload (`mqp/…`) and the grouped/retained payload
///   (`mqgp/…`).
///
/// Any OTHER key (e.g. a stray `config/…` that should never live in the blob store — the mutable
/// control-plane records are in the KV, not `Storage`) is primary-only, so it can NEVER silently
/// resurrect off a secondary during a transition (Security Finding F4/G5-cp, defense-in-depth). The
/// predicate is supplied to the generic [`FallbackStorage`](boatramp_storage::FallbackStorage), which
/// hardcodes no app prefixes.
///
/// v0.31.0: `mqp/` was added alongside `mqgp/` so that, during the default-scope re-home soak
/// (Finding 8), a work-queue payload re-homed from `mqp/{topic}/…` to `mqp/default/{topic}/…` is
/// fallback-eligible too — without it a default-scoped work-queue payload would 404 on the new
/// spelling during a concurrent backend switch.
#[cfg(feature = "fallback")]
pub fn blob_fallback_when() -> boatramp_storage::FallbackWhen {
    Arc::new(|k: &str| {
        boatramp_core::deploy::is_blob_key(k)
            || k.starts_with("hblob/")
            || k.starts_with("mqp/")
            || k.starts_with("mqgp/")
    })
}

/// The guest-blob data families whose keys the default-scope re-home (v0.31.0 Finding 8) re-homes:
/// the guest object store and both messaging payload stores. `hkv/` + the `mq*/` INDICES live in the
/// KV, not `Storage`, so they migrate via `boatramp migrate`, not here.
#[cfg(feature = "fallback")]
pub const DEFAULT_SCOPE_BLOB_FAMILIES: &[&str] = &["hblob/", "mqp/", "mqgp/"];

/// Timeout bounding each translated secondary read in the default-scope blob fallback (a wedged
/// backend degrades a translated miss to `NotFound`, never a serve-path hang). Matches the default
/// used by the backend-switch fallback.
#[cfg(feature = "fallback")]
const DEFAULT_SCOPE_FALLBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The **new→old** translator for the default-scope blob fallback: for a post-flip key
/// `{family}default/{rest}` under a known data family, name the pre-flip bare key `{family}{rest}` to
/// fall back to. Purely syntactic (no project set needed): only a `…/default/…` key is translatable,
/// so a named project's `{family}{project}/…` key never falls back and no cross-scope resurrection is
/// possible.
#[cfg(feature = "fallback")]
pub fn default_scope_to_old() -> boatramp_storage::KeyTranslate {
    Arc::new(|k: &str| {
        for fam in DEFAULT_SCOPE_BLOB_FAMILIES {
            if let Some(rest) = k.strip_prefix(fam) {
                let suffix = rest.strip_prefix("default/")?;
                return Some(format!("{fam}{suffix}"));
            }
        }
        None
    })
}

/// The **old→new** translator (project-aware) for the default-scope blob fallback's `list` union and
/// the [`blob_rehome`](boatramp_storage::blob_rehome) drain/retire: for a bare default-scoped key
/// `{family}{base}/…` (whose scope segment is NOT a known project), name the re-homed
/// `{family}default/{base}/…`. A named project's key and an already-`default/` key both yield `None`.
#[cfg(feature = "fallback")]
pub fn default_scope_to_new(
    projects: std::sync::Arc<std::collections::HashSet<String>>,
) -> boatramp_storage::KeyTranslate {
    Arc::new(move |k: &str| {
        for fam in DEFAULT_SCOPE_BLOB_FAMILIES {
            if let Some(rest) = k.strip_prefix(fam) {
                let first = rest.split('/').next().unwrap_or("");
                if first.is_empty()
                    || first == boatramp_core::project::DEFAULT_PROJECT
                    || projects.contains(first)
                {
                    return None;
                }
                return Some(format!(
                    "{fam}{}/{rest}",
                    boatramp_core::project::DEFAULT_PROJECT
                ));
            }
        }
        None
    })
}

/// A [`BlobBackends`](boatramp_core::blob_backends::BlobBackends) decorator that wraps each resolved
/// backend in a [`TranslatingFallbackStorage`](boatramp_storage::TranslatingFallbackStorage) — the
/// serve-path half of the default-scope blob re-home (Finding 8). Enabled ONLY while the store is in
/// the default-scope migration's `dual` soak (see [`default_scope_blob_fallback`]); removed (by
/// restarting after `boatramp migrate --finalize` + a verified blob retire) once the soak ends.
#[cfg(feature = "fallback")]
pub struct DefaultScopeFallbackBackends {
    inner: Arc<dyn boatramp_core::blob_backends::BlobBackends>,
    to_old: boatramp_storage::KeyTranslate,
    to_new: boatramp_storage::KeyTranslate,
}

#[cfg(feature = "fallback")]
impl boatramp_core::blob_backends::BlobBackends for DefaultScopeFallbackBackends {
    fn backend(&self, project: boatramp_core::project::ProjectRef<'_>) -> Arc<dyn Storage> {
        Arc::new(boatramp_storage::TranslatingFallbackStorage::new(
            self.inner.backend(project),
            self.to_old.clone(),
            self.to_new.clone(),
            DEFAULT_SCOPE_FALLBACK_TIMEOUT,
        ))
    }
    fn default_backend(&self) -> Arc<dyn Storage> {
        Arc::new(boatramp_storage::TranslatingFallbackStorage::new(
            self.inner.default_backend(),
            self.to_old.clone(),
            self.to_new.clone(),
            DEFAULT_SCOPE_FALLBACK_TIMEOUT,
        ))
    }
}

/// If the control-plane store `kv` is in the **default-scope migration's `dual` soak** (its forward
/// re-key has run but the destructive finalize is deferred), wrap `inner` so every `wasi:blobstore`
/// backend serves a not-yet-drained bare `hblob/{site}/…`/`mqp/…`/`mqgp/…` object at the new
/// `…/default/…` spelling the post-flip runtime composes — the zero-downtime blob transition. Returns
/// `None` (the inner resolver unchanged) when the store is not in that soak, so a fully-migrated or
/// pre-migration node is byte-for-byte unchanged. The named-project set (for the `list`-union / drain
/// translator) is read once here from `projectmeta/`.
#[cfg(feature = "fallback")]
pub async fn default_scope_blob_fallback(
    kv: &dyn boatramp_core::kv::KvStore,
    inner: Arc<dyn boatramp_core::blob_backends::BlobBackends>,
) -> Arc<dyn boatramp_core::blob_backends::BlobBackends> {
    let in_soak = boatramp_core::migrate::read_state(kv)
        .await
        .map(|s| {
            s.unfinalized
                .contains(&boatramp_core::migrate::DEFAULT_SCOPE_REHOME_VERSION)
        })
        .unwrap_or(false);
    if !in_soak {
        return inner;
    }
    // The named projects (for the project-aware old→new translator). Read once at wiring.
    let mut projects = std::collections::HashSet::new();
    if let Ok(keys) = kv.list_prefix(boatramp_core::project::POINTER_PREFIX).await {
        for key in keys {
            if let Some(name) = key.strip_prefix(boatramp_core::project::POINTER_PREFIX)
                && !name.is_empty()
                && !name.contains('/')
            {
                projects.insert(name.to_string());
            }
        }
    }
    tracing::warn!(
        "default-scope blob read-fallback ACTIVE (migration {} in dual soak): serving bare \
         default-scoped blobs at their new default/ spelling. Run the blob re-home drain, then \
         `boatramp migrate --finalize` + retire the old blobs, and restart to disable it.",
        boatramp_core::migrate::DEFAULT_SCOPE_REHOME_VERSION
    );
    Arc::new(DefaultScopeFallbackBackends {
        inner,
        to_old: default_scope_to_old(),
        to_new: default_scope_to_new(std::sync::Arc::new(projects)),
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
