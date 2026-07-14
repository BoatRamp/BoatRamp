//! Google Cloud Storage [`Storage`] backend (compile with `--features gcs`).
//!
//! Native `google-cloud-storage` SDK, matching the S3 backend's native-SDK
//! choice. Reads stream straight from the object's media response; writes stream
//! through a bounded channel into a resumable upload, so a whole object is never
//! held in memory. GCS separates object *media* from object *metadata*, so `get`
//! resolves metadata with a `head` before opening the media stream.

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::Bytes;
use futures::{Stream, StreamExt};

use google_cloud_storage::client::{Client, ClientConfig};
use google_cloud_storage::http::objects::delete::DeleteObjectRequest;
use google_cloud_storage::http::objects::download::Range;
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::list::ListObjectsRequest;
use google_cloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};
use google_cloud_storage::http::objects::Object;
use google_cloud_storage::http::Error as GcsError;

/// Stores objects in a Google Cloud Storage bucket, streaming reads and writes.
#[derive(Clone)]
pub struct GcsStorage {
    client: Client,
    bucket: String,
}

/// Connection options for [`GcsStorage::connect`].
#[derive(Debug, Clone, Default)]
pub struct GcsOptions {
    /// Bucket to store blobs in.
    pub bucket: String,
    /// Custom storage endpoint (e.g. a `fake-gcs-server` emulator). Defaults to
    /// the public GCS JSON API.
    pub endpoint: Option<String>,
    /// Skip credential resolution (the emulator / anonymous access). Real GCS uses
    /// Application Default Credentials.
    pub anonymous: bool,
}

impl GcsStorage {
    /// Build a backend from an existing client and bucket name.
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }

    /// Build a backend from [`GcsOptions`]. Credentials come from Application
    /// Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS` / the metadata server)
    /// unless `anonymous` is set (the emulator).
    pub async fn connect(opts: GcsOptions) -> Result<Self, StorageError> {
        let mut config = if opts.anonymous {
            ClientConfig::default().anonymous()
        } else {
            ClientConfig::default()
                .with_auth()
                .await
                .map_err(|err| StorageError::backend(format!("GCS auth: {err}")))?
        };
        if let Some(endpoint) = opts.endpoint {
            config.storage_endpoint = endpoint;
        }
        Ok(Self::new(Client::new(config), opts.bucket))
    }

    /// The bucket this backend targets.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The underlying GCS client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    fn get_request(&self, key: &str) -> GetObjectRequest {
        GetObjectRequest {
            bucket: self.bucket.clone(),
            object: key.to_string(),
            ..Default::default()
        }
    }

    /// Open the object's media stream for `key` over `range`.
    async fn download(&self, key: &str, range: Range) -> Result<ByteStream, StorageError> {
        let stream = self
            .client
            .download_streamed_object(&self.get_request(key), &range)
            .await
            .map_err(|err| gcs_err(err, key))?;
        Ok(stream
            .map(|chunk| chunk.map_err(|err| StorageError::backend(err.to_string())))
            .boxed())
    }
}

#[async_trait]
impl Storage for GcsStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        // GCS returns media and metadata separately; resolve metadata first so the
        // returned `ObjectMeta` carries the content type + size for serving.
        let meta = self.head(key).await?;
        let body = self.download(key, Range(None, None)).await?;
        Ok(GetObject { meta, body })
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        let meta = self.head(key).await?;
        let range = match len {
            Some(n) if n > 0 => Range(Some(offset), Some(offset + n - 1)),
            _ => Range(Some(offset), None),
        };
        let body = self.download(key, range).await?;
        Ok(GetObject { meta, body })
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        let mut media = Media::new(key.to_string());
        if let Some(content_type) = &meta.content_type {
            media.content_type = content_type.clone().into();
        }
        let request = UploadObjectRequest {
            bucket: self.bucket.clone(),
            ..Default::default()
        };
        let object = self
            .client
            .upload_streamed_object(
                &request,
                synced_upload_stream(body),
                &UploadType::Simple(media),
            )
            .await
            .map_err(|err| StorageError::backend(err.to_string()))?;
        Ok(object_meta(key, &object))
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        let object = self
            .client
            .get_object(&self.get_request(key))
            .await
            .map_err(|err| gcs_err(err, key))?;
        Ok(object_meta(key, &object))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let request = DeleteObjectRequest {
            bucket: self.bucket.clone(),
            object: key.to_string(),
            ..Default::default()
        };
        match self.client.delete_object(&request).await {
            Ok(()) => Ok(()),
            // Deleting a missing object is not an error (unlike GCS's own 404).
            Err(err) if is_not_found(&err) => Ok(()),
            Err(err) => Err(StorageError::backend(err.to_string())),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let resp = self
                .client
                .list_objects(&ListObjectsRequest {
                    bucket: self.bucket.clone(),
                    prefix: Some(prefix.to_string()),
                    page_token: page_token.clone(),
                    ..Default::default()
                })
                .await
                .map_err(|err| StorageError::backend(err.to_string()))?;
            for object in resp.items.unwrap_or_default() {
                let key = object.name.clone();
                out.push(object_meta(&key, &object));
            }
            match resp.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }
        Ok(out)
    }
}

/// Map a GCS [`Object`] to boatramp's [`ObjectMeta`].
fn object_meta(key: &str, object: &Object) -> ObjectMeta {
    ObjectMeta {
        key: key.to_string(),
        size: u64::try_from(object.size).ok(),
        content_type: object.content_type.clone(),
        etag: Some(object.etag.clone()),
    }
}

/// Whether a GCS error is a 404 (object/bucket not found).
fn is_not_found(err: &GcsError) -> bool {
    matches!(err, GcsError::Response(resp) if resp.code == 404)
}

/// Map a GCS error to a [`StorageError`], turning 404 into `NotFound`.
fn gcs_err(err: GcsError, key: &str) -> StorageError {
    if is_not_found(&err) {
        StorageError::NotFound(key.to_string())
    } else {
        StorageError::backend(err.to_string())
    }
}

/// The GCS uploader requires a `Send + Sync + 'static` stream, but boatramp's
/// [`ByteStream`] is `Send`-only. Bridge it through a small **bounded** channel
/// (backpressure ⇒ no whole-object buffer): a task drains the `Send` source into
/// the channel, and [`ChannelStream`] (which *is* `Send + Sync`) feeds the upload.
fn synced_upload_stream(mut body: ByteStream) -> ChannelStream {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::spawn(async move {
        while let Some(item) = body.next().await {
            let is_err = item.is_err();
            let msg = item.map_err(std::io::Error::other);
            if tx.send(msg).await.is_err() {
                break; // the uploader dropped the receiver
            }
            if is_err {
                break; // propagated the stream error; stop
            }
        }
    });
    ChannelStream { rx }
}

/// A `Send + Sync` byte stream over a bounded channel (see [`synced_upload_stream`]).
struct ChannelStream {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl Stream for ChannelStream {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}
