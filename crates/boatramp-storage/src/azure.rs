//! Azure Blob Storage [`Storage`] backend (compile with `--features azure`).
//!
//! Native `azure-sdk-for-rust` (0.21), matching the S3/GCS backends' native-SDK
//! choice. Reads stream by flattening the paged download body; writes stream as a
//! sequence of **staged blocks** committed with one block-list call (the Azure
//! equivalent of S3's multipart), so a whole object is never held in memory. Azure
//! separates object data from metadata, so `get` resolves metadata with a
//! `get_properties` (head) before opening the data stream.

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::{Bytes, BytesMut};
use futures::{StreamExt, TryStreamExt};

use azure_core::error::ErrorKind;
use azure_core::request_options::Range;
use azure_core::StatusCode;
use azure_storage::prelude::StorageCredentials;
use azure_storage_blobs::blob::{Blob, BlobBlockType, BlockList};
use azure_storage_blobs::prelude::{BlobClient, BlockId, ClientBuilder, ContainerClient};

/// Size of each staged block. Azure block blobs are assembled from blocks; 8 MiB
/// keeps the block count low while bounding the in-memory buffer to one block.
const BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Stores objects in an Azure Blob Storage container, streaming reads and writes.
#[derive(Clone)]
pub struct AzureStorage {
    container: ContainerClient,
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

impl AzureStorage {
    /// Build a backend from an existing container client.
    pub fn new(container: ContainerClient) -> Self {
        Self { container }
    }

    /// Build a backend from [`AzureOptions`]. Uses shared-key auth from
    /// `access_key`, or the Azurite emulator credentials when `emulator` is set.
    pub fn connect(opts: AzureOptions) -> Result<Self, StorageError> {
        let container = if opts.emulator {
            ClientBuilder::emulator().container_client(opts.container)
        } else {
            let key = opts.access_key.clone().ok_or_else(|| {
                StorageError::backend("Azure access key required (set --azure-access-key)")
            })?;
            let credentials = StorageCredentials::access_key(opts.account.clone(), key);
            ClientBuilder::new(opts.account, credentials).container_client(opts.container)
        };
        Ok(Self::new(container))
    }

    /// The container this backend targets.
    pub fn container_name(&self) -> &str {
        self.container.container_name()
    }

    /// The underlying container client.
    pub fn container(&self) -> &ContainerClient {
        &self.container
    }

    fn blob_client(&self, key: &str) -> BlobClient {
        self.container.blob_client(key)
    }

    /// Open the object's data stream for `key`, optionally over `range`, by
    /// flattening the paged download body into one byte stream.
    async fn download(&self, key: &str, range: Option<Range>) -> Result<ByteStream, StorageError> {
        let mut builder = self.blob_client(key).get();
        if let Some(range) = range {
            builder = builder.range(range);
        }
        let stream = builder
            .into_stream()
            .map_ok(|response| response.data)
            .try_flatten()
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
        // Azure `Range::new(start, end)` is end-exclusive; `offset..` is open-ended.
        let range = match len {
            Some(n) if n > 0 => Range::new(offset, offset + n),
            _ => Range::from(offset..),
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
        let mut buf = BytesMut::with_capacity(BLOCK_SIZE);
        let mut blocks: Vec<BlobBlockType> = Vec::new();
        let mut total: u64 = 0;

        while let Some(chunk) = body.try_next().await? {
            total += chunk.len() as u64;
            buf.extend_from_slice(&chunk);
            while buf.len() >= BLOCK_SIZE {
                let block = buf.split_to(BLOCK_SIZE).freeze();
                blocks.push(self.stage_block(&blob_client, blocks.len(), block).await?);
            }
        }
        // Commit the remainder as the final block (a block blob needs at least one
        // block; a 0-byte object stages one empty block).
        let block = buf.freeze();
        blocks.push(self.stage_block(&blob_client, blocks.len(), block).await?);

        let mut builder = blob_client.put_block_list(BlockList { blocks });
        if let Some(content_type) = &meta.content_type {
            builder = builder.content_type(content_type.clone());
        }
        builder
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
            .get_properties()
            .await
            .map_err(|err| az_err(err, key))?;
        Ok(blob_meta(key, &response.blob))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match self.blob_client(key).delete().await {
            Ok(_) => Ok(()),
            // Deleting a missing blob is not an error (unlike Azure's own 404).
            Err(err) if is_not_found(&err) => Ok(()),
            Err(err) => Err(StorageError::backend(err.to_string())),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = Vec::new();
        let mut stream = self
            .container
            .list_blobs()
            .prefix(prefix.to_string())
            .into_stream();
        while let Some(page) = stream.next().await {
            let page = page.map_err(|err| StorageError::backend(err.to_string()))?;
            for blob in page.blobs.blobs() {
                out.push(blob_meta(&blob.name, blob));
            }
        }
        Ok(out)
    }
}

impl AzureStorage {
    /// Stage one block of a streamed upload, returning its uncommitted list entry.
    async fn stage_block(
        &self,
        blob_client: &BlobClient,
        index: usize,
        data: Bytes,
    ) -> Result<BlobBlockType, StorageError> {
        // Block ids must be equal-length across a blob; a zero-padded counter is.
        let id = Bytes::from(format!("br-block-{index:08}"));
        blob_client
            .put_block(id.clone(), data)
            .await
            .map_err(|err| StorageError::backend(err.to_string()))?;
        Ok(BlobBlockType::Uncommitted(BlockId::new(id)))
    }
}

/// Map an Azure [`Blob`] to boatramp's [`ObjectMeta`].
fn blob_meta(key: &str, blob: &Blob) -> ObjectMeta {
    ObjectMeta {
        key: key.to_string(),
        size: Some(blob.properties.content_length),
        content_type: Some(blob.properties.content_type.clone()),
        etag: Some(blob.properties.etag.to_string()),
    }
}

/// Whether an Azure error is a 404 (blob/container not found).
fn is_not_found(err: &azure_core::Error) -> bool {
    matches!(err.kind(), ErrorKind::HttpResponse { status, .. } if *status == StatusCode::NotFound)
}

/// Map an Azure error to a [`StorageError`], turning 404 into `NotFound`.
fn az_err(err: azure_core::Error, key: &str) -> StorageError {
    if is_not_found(&err) {
        StorageError::NotFound(key.to_string())
    } else {
        StorageError::backend(err.to_string())
    }
}
