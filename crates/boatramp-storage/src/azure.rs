//! Azure Blob Storage [`Storage`] backend (compile with `--features azure`).
//!
//! Native `azure-sdk-for-rust` **1.x GA** (`azure_storage_blob`), the single Azure
//! SDK generation the workspace is on. Reads stream the download body directly;
//! writes stream as a sequence of **staged blocks** committed with one block-list
//! call (the Azure equivalent of S3's multipart), so a whole object is never held in
//! memory. Azure separates object data from metadata, so `get` resolves metadata with
//! a `get_properties` (head) before opening the data stream.
//!
//! The 1.x SDK is AAD/`TokenCredential`-first and dropped native shared-key auth, so
//! operator-supplied account-key + Azurite-emulator auth is preserved by injecting a
//! hand-rolled [`SharedKeyAuthorizationPolicy`](crate::azure_shared_key) into the
//! client's `per_try_policies` (see [`AzureStorage::connect`]).

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::{Bytes, BytesMut};
use futures::{StreamExt, TryStreamExt};

use azure_core_v1::Bytes as AzBytes;
use azure_core_v1::error::ErrorKind;
use azure_core_v1::http::{ClientOptions, RequestContent, StatusCode, Url};
use azure_storage_blob::models::{
    BlobClientDeleteOptions, BlobClientDownloadOptions, BlobClientGetPropertiesResultHeaders,
    BlobContainerClientListBlobsOptions, BlockBlobClientCommitBlockListOptions,
    BlockBlobClientStageBlockOptions, BlockLookupList, HttpRange,
};
use azure_storage_blob::{
    BlobClient, BlobContainerClient, BlobServiceClient, BlobServiceClientOptions,
};

use crate::azure_shared_key::{SharedKeyAuthorizationPolicy, SharedKeyResource};

/// Size of each staged block. Azure block blobs are assembled from blocks; 8 MiB
/// keeps the block count low while bounding the in-memory buffer to one block.
const BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// The Azurite emulator well-known account name + key (public dev credentials) and the
/// default local blob/queue endpoints.
const AZURITE_ACCOUNT: &str = "devstoreaccount1";
const AZURITE_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const AZURITE_BLOB_ENDPOINT: &str = "http://127.0.0.1:10000/devstoreaccount1";
const AZURITE_QUEUE_ENDPOINT: &str = "http://127.0.0.1:10001/devstoreaccount1";

/// Stores objects in an Azure Blob Storage container, streaming reads and writes.
///
/// The 1.x SDK clients are not `Clone`, so the container + queue clients are held
/// behind [`Arc`](std::sync::Arc) to keep `AzureStorage` cheaply cloneable (the 0.21
/// clients were `Clone`; this preserves that at the boundary).
#[derive(Clone)]
pub struct AzureStorage {
    container: std::sync::Arc<BlobContainerClient>,
    /// The container name (the 1.x `BlobContainerClient` does not expose its own name).
    container_name: String,
    /// Optional Storage Queue client for the blob-change **consumer** (S4/FA-5b2).
    /// When set, [`supports_watch`](Storage::supports_watch) is `true` and
    /// [`watch`](Storage::watch) polls the queue provisioned for the prefix.
    queues: Option<crate::azure_notify::QueueService>,
}

/// Connection options for [`AzureStorage::connect`].
#[derive(Debug, Clone, Default)]
pub struct AzureOptions {
    /// Storage account name.
    pub account: String,
    /// Container to store blobs in.
    pub container: String,
    /// The account access key (shared-key auth). Required unless `emulator`.
    pub access_key: Option<String>,
    /// Use the Azurite emulator (well-known dev credentials + local endpoint).
    pub emulator: bool,
}

impl AzureOptions {
    /// The blob service URL for this account (or the Azurite emulator endpoint).
    fn blob_service_url(&self) -> String {
        if self.emulator {
            AZURITE_BLOB_ENDPOINT.to_string()
        } else {
            format!("https://{}.blob.core.windows.net", self.account)
        }
    }

    /// The queue service URL for this account (or the Azurite emulator endpoint).
    pub(crate) fn queue_service_url_pub(&self) -> String {
        if self.emulator {
            AZURITE_QUEUE_ENDPOINT.to_string()
        } else {
            format!("https://{}.queue.core.windows.net", self.account)
        }
    }

    /// The `(account, key)` shared-key credential pair for the queue service (same
    /// account credentials as blob).
    pub(crate) fn queue_shared_key(&self) -> Result<(String, String), StorageError> {
        self.shared_key()
    }

    /// The `(account, key)` shared-key credential pair for signing, resolving the
    /// Azurite well-known credentials in emulator mode.
    fn shared_key(&self) -> Result<(String, String), StorageError> {
        if self.emulator {
            Ok((AZURITE_ACCOUNT.to_string(), AZURITE_KEY.to_string()))
        } else {
            let key = self.access_key.clone().ok_or_else(|| {
                StorageError::backend("Azure access key required (set --azure-access-key)")
            })?;
            Ok((self.account.clone(), key))
        }
    }
}

impl AzureStorage {
    /// Build a backend from an existing container client + its container name.
    pub fn new(container: BlobContainerClient, container_name: impl Into<String>) -> Self {
        Self {
            container: std::sync::Arc::new(container),
            container_name: container_name.into(),
            queues: None,
        }
    }

    /// Build a backend from [`AzureOptions`]. Uses shared-key auth from `access_key`
    /// (or the Azurite emulator credentials when `emulator` is set) by injecting a
    /// [`SharedKeyAuthorizationPolicy`] into the client's per-try policies.
    pub fn connect(opts: AzureOptions) -> Result<Self, StorageError> {
        let service = build_blob_service(&opts)?;
        let container = service.blob_container_client(&opts.container);
        Ok(Self::new(container, opts.container))
    }

    /// Attach a Storage Queue service client so this backend can **consume**
    /// blob-change notifications (S4/FA-5b2).
    pub fn with_queue_notify(mut self, queues: crate::azure_notify::QueueService) -> Self {
        self.queues = Some(queues);
        self
    }

    /// Build a notify-enabled Azure backend + its blob-change
    /// [`AzureWatchProvider`](crate::azure_notify::AzureWatchProvider) (FA-5b2
    /// Azure), sharing the account's shared-key auth. The storage consumes the
    /// provisioned Storage Queue; the provider creates/retracts it (the Event Grid
    /// subscription is an operator step — see the provider recipe).
    pub fn connect_with_notify(
        opts: AzureOptions,
    ) -> Result<(Self, crate::azure_notify::AzureWatchProvider), StorageError> {
        let storage = Self::connect(opts.clone())?;
        let queues = crate::azure_notify::build_queue_service(&opts)?;
        let provider = crate::azure_notify::AzureWatchProvider::new(
            queues.clone(),
            opts.account,
            opts.container,
        );
        Ok((storage.with_queue_notify(queues), provider))
    }

    /// The container this backend targets.
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    /// The underlying container client.
    pub fn container(&self) -> &BlobContainerClient {
        &self.container
    }

    fn blob_client(&self, key: &str) -> BlobClient {
        self.container.blob_client(key)
    }

    /// Open the object's data stream for `key`, optionally over `range`, boxing the
    /// download body into boatramp's [`ByteStream`].
    async fn download(
        &self,
        key: &str,
        range: Option<HttpRange>,
    ) -> Result<ByteStream, StorageError> {
        let options = BlobClientDownloadOptions {
            range,
            ..Default::default()
        };
        let result = self
            .blob_client(key)
            .download(Some(options))
            .await
            .map_err(|err| az_err(err, key))?;
        // `body` is a `Stream<Item = azure_core::Result<Bytes>>`; adapt its error type
        // and box it behind the unchanged `ByteStream` boundary.
        let stream = result
            .body
            .map_err(|err| StorageError::backend(err.to_string()))
            .boxed();
        Ok(stream)
    }
}

#[async_trait]
impl Storage for AzureStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        // Resolve metadata first (Azure serves data + properties separately), so a
        // missing blob is a clean `NotFound` before the data stream opens.
        let meta = self.head(key).await?;
        let body = self.download(key, None).await?;
        Ok(GetObject { meta, body })
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        let meta = self.head(key).await?;
        // Azure `HttpRange` is `[start, start+len)`; an open-ended range reads to EOF.
        let range = match len {
            Some(n) if n > 0 => HttpRange::from(offset..offset + n),
            _ => HttpRange::from(offset..),
        };
        let body = self.download(key, Some(range)).await?;
        Ok(GetObject { meta, body })
    }

    async fn put(
        &self,
        key: &str,
        mut body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        let blob_client = self.blob_client(key);
        let block_blob = blob_client.block_blob_client();
        let mut buf = BytesMut::with_capacity(BLOCK_SIZE);
        // Block ids (raw bytes; the SDK base64-encodes them in the block-list XML).
        let mut block_ids: Vec<Vec<u8>> = Vec::new();
        let mut total: u64 = 0;

        while let Some(chunk) = body.try_next().await? {
            total += chunk.len() as u64;
            buf.extend_from_slice(&chunk);
            while buf.len() >= BLOCK_SIZE {
                let block = buf.split_to(BLOCK_SIZE).freeze();
                stage_block(&block_blob, block_ids.len(), block, &mut block_ids).await?;
            }
        }
        // Commit the remainder as the final block (a block blob needs at least one
        // block; a 0-byte object stages one empty block).
        let block = buf.freeze();
        stage_block(&block_blob, block_ids.len(), block, &mut block_ids).await?;

        let block_list = BlockLookupList {
            latest: Some(block_ids),
            ..Default::default()
        };
        let content: RequestContent<BlockLookupList, _> = block_list
            .try_into()
            .map_err(|err: azure_core_v1::Error| StorageError::backend(err.to_string()))?;
        let options = BlockBlobClientCommitBlockListOptions {
            // Content-type is signed onto the committed blob (not a builder in 1.x).
            blob_content_type: meta.content_type.clone(),
            ..Default::default()
        };
        block_blob
            .commit_block_list(content, Some(options))
            .await
            .map_err(|err| StorageError::backend(err.to_string()))?;

        Ok(ObjectMeta {
            key: key.to_string(),
            size: Some(total),
            content_type: meta.content_type,
            etag: None,
        })
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        let response = self
            .blob_client(key)
            .get_properties(None)
            .await
            .map_err(|err| az_err(err, key))?;
        // Read content-length/content-type/etag off the typed response headers (1.x has
        // no nested `Blob.properties` struct — the properties are HTTP headers).
        let size = response.content_length().map_err(|err| az_err(err, key))?;
        let content_type = response.content_type().map_err(|err| az_err(err, key))?;
        let etag = response
            .etag()
            .map_err(|err| az_err(err, key))?
            .map(|e| e.to_string());
        Ok(ObjectMeta {
            key: key.to_string(),
            size,
            content_type,
            etag,
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match self
            .blob_client(key)
            .delete(None::<BlobClientDeleteOptions>)
            .await
        {
            Ok(_) => Ok(()),
            // Deleting a missing blob is not an error (unlike Azure's own 404).
            Err(err) if is_not_found(&err) => Ok(()),
            Err(err) => Err(StorageError::backend(err.to_string())),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = Vec::new();
        let options = BlobContainerClientListBlobsOptions {
            prefix: Some(prefix.to_string()),
            ..Default::default()
        };
        let mut pages = self
            .container
            .list_blobs(Some(options))
            .map_err(|err| StorageError::backend(err.to_string()))?
            .into_pages();
        while let Some(page) = pages
            .try_next()
            .await
            .map_err(|err| StorageError::backend(err.to_string()))?
        {
            let model = page
                .into_model()
                .map_err(|err| StorageError::backend(err.to_string()))?;
            for item in model.blob_items {
                let Some(name) = item.name else { continue };
                let props = item.properties.unwrap_or_default();
                out.push(ObjectMeta {
                    key: name,
                    size: props.content_length,
                    content_type: props.content_type,
                    etag: props.etag.map(|e| e.to_string()),
                });
            }
        }
        Ok(out)
    }

    /// Azure can watch once the Storage Queue notification consumer is wired (the
    /// pipeline is provisioned per-prefix by
    /// [`AzureWatchProvider`](crate::azure_notify::AzureWatchProvider) at trigger
    /// add).
    fn supports_watch(&self) -> bool {
        self.queues.is_some()
    }

    async fn watch(
        &self,
        prefix: &str,
    ) -> Result<Option<boatramp_core::ChangeStream>, StorageError> {
        let Some(queues) = self.queues.clone() else {
            return Ok(None);
        };
        // The queue name is derived deterministically from the prefix — provider and
        // consumer agree without a lookup table.
        let queue = queues
            .queue_client(&crate::azure_notify::queue_name(prefix))
            .map_err(|err| StorageError::backend(err.to_string()))?;
        Ok(Some(crate::azure_notify::azure_watch_stream(
            queue,
            prefix.to_string(),
        )))
    }
}

/// Stage one block of a streamed upload, appending its raw block id to `block_ids`.
async fn stage_block(
    block_blob: &azure_storage_blob::BlockBlobClient,
    index: usize,
    data: Bytes,
    block_ids: &mut Vec<Vec<u8>>,
) -> Result<(), StorageError> {
    // Block ids must be equal-length across a blob; a zero-padded counter is.
    let id = format!("br-block-{index:08}").into_bytes();
    let len = data.len() as u64;
    // Use the `From<Bytes>` trait via fully-qualified syntax (the inherent
    // `RequestContent::from(Vec<u8>)` would otherwise shadow it) so the block body
    // streams as `Bytes` without a copy. `data` is already `azure_core::Bytes`.
    let content =
        <RequestContent<AzBytes, azure_core_v1::http::NoFormat> as From<AzBytes>>::from(data);
    block_blob
        .stage_block(&id, len, content, None::<BlockBlobClientStageBlockOptions>)
        .await
        .map_err(|err| StorageError::backend(err.to_string()))?;
    block_ids.push(id);
    Ok(())
}

/// Build a 1.x [`BlobServiceClient`] for `opts`, injecting the Shared Key signing
/// policy (account-key / Azurite auth) as a per-try policy.
fn build_blob_service(opts: &AzureOptions) -> Result<BlobServiceClient, StorageError> {
    let (account, key) = opts.shared_key()?;
    let url = Url::parse(&opts.blob_service_url())
        .map_err(|e| StorageError::backend(format!("invalid Azure blob service URL: {e}")))?;
    let policy = std::sync::Arc::new(SharedKeyAuthorizationPolicy::new(
        account,
        key,
        SharedKeyResource::Blob,
    ));
    let options = BlobServiceClientOptions {
        client_options: ClientOptions {
            per_try_policies: vec![policy],
            ..Default::default()
        },
        ..Default::default()
    };
    // No AAD credential — the Shared Key policy authorizes the request.
    BlobServiceClient::new(url, None, Some(options))
        .map_err(|e| StorageError::backend(format!("Azure BlobServiceClient: {e}")))
}

/// Whether an Azure error is a 404 (blob/container not found).
fn is_not_found(err: &azure_core_v1::Error) -> bool {
    matches!(err.kind(), ErrorKind::HttpResponse { status, .. } if *status == StatusCode::NotFound)
}

/// Map an Azure error to a [`StorageError`], turning 404 into `NotFound`.
fn az_err(err: azure_core_v1::Error, key: &str) -> StorageError {
    if is_not_found(&err) {
        StorageError::NotFound(key.to_string())
    } else {
        StorageError::backend(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The emulator options resolve the well-known Azurite endpoint + credentials, and
    /// a client builds against them without any live call.
    #[test]
    fn emulator_options_build_a_signed_client() {
        let opts = AzureOptions {
            account: String::new(),
            container: "data".into(),
            access_key: None,
            emulator: true,
        };
        assert_eq!(opts.blob_service_url(), AZURITE_BLOB_ENDPOINT);
        let (account, key) = opts.shared_key().unwrap();
        assert_eq!(account, AZURITE_ACCOUNT);
        assert_eq!(key, AZURITE_KEY);
        // The service + container clients build (the Shared Key policy is injected).
        let storage = AzureStorage::connect(opts).unwrap();
        assert_eq!(storage.container_name(), "data");
        assert!(!storage.supports_watch());
    }

    /// A non-emulator account with no access key is refused (fail-closed) — the shared
    /// key is required for signing.
    #[test]
    fn non_emulator_without_key_is_refused() {
        let opts = AzureOptions {
            account: "acct".into(),
            container: "data".into(),
            access_key: None,
            emulator: false,
        };
        assert!(AzureStorage::connect(opts).is_err());
    }

    /// A real account with a key builds the `https://{account}.blob.core.windows.net`
    /// service URL and a signed client.
    #[test]
    fn account_key_options_build_a_signed_client() {
        let opts = AzureOptions {
            account: "acct".into(),
            container: "photos".into(),
            access_key: Some(AZURITE_KEY.to_string()),
            emulator: false,
        };
        assert_eq!(
            opts.blob_service_url(),
            "https://acct.blob.core.windows.net"
        );
        assert_eq!(
            opts.queue_service_url_pub(),
            "https://acct.queue.core.windows.net"
        );
        let storage = AzureStorage::connect(opts).unwrap();
        assert_eq!(storage.container_name(), "photos");
    }

    // ── Live emulator seam (Azurite). Ignored by default; run with a live Azurite:
    //   docker run -p 10000:10000 -p 10001:10001 mcr.microsoft.com/azure-storage/azurite
    //   cargo test -p boatramp-storage --features azure -- --ignored azure_emulator
    // These exercise the real signed round-trip (put → head → get → range → list → delete).
    fn emulator_storage() -> AzureStorage {
        AzureStorage::connect(AzureOptions {
            account: String::new(),
            container: "boatramp-test".into(),
            access_key: None,
            emulator: true,
        })
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires a live Azurite emulator on :10000"]
    async fn azure_emulator_put_head_get_range_list_delete() {
        let storage = emulator_storage();
        // Ensure the container exists (create is idempotent-ish; ignore an existing-conflict).
        let _ = storage.container().create(None).await;

        let key = "hblob/test/roundtrip.txt";
        let payload = Bytes::from_static(b"hello azure 1.x shared key");
        let body: ByteStream = futures::stream::once(async move { Ok(payload.clone()) }).boxed();
        let put = storage
            .put(
                key,
                body,
                PutMeta {
                    content_type: Some("text/plain".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(put.size, Some(26));

        let head = storage.head(key).await.unwrap();
        assert_eq!(head.size, Some(26));
        assert_eq!(head.content_type.as_deref(), Some("text/plain"));

        let got = storage.get(key).await.unwrap();
        let bytes: Vec<u8> = got
            .body
            .try_fold(Vec::new(), |mut acc, chunk| async move {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            })
            .await
            .unwrap();
        assert_eq!(bytes, b"hello azure 1.x shared key");

        let ranged = storage.get_range(key, 6, Some(5)).await.unwrap();
        let rbytes: Vec<u8> = ranged
            .body
            .try_fold(Vec::new(), |mut acc, chunk| async move {
                acc.extend_from_slice(&chunk);
                Ok(acc)
            })
            .await
            .unwrap();
        assert_eq!(&rbytes, b"azure");

        let listed = storage.list("hblob/test/").await.unwrap();
        assert!(listed.iter().any(|m| m.key == key));

        storage.delete(key).await.unwrap();
        // Deleting again (now missing) is not an error.
        storage.delete(key).await.unwrap();
        assert!(matches!(
            storage.head(key).await,
            Err(StorageError::NotFound(_))
        ));
    }
}
