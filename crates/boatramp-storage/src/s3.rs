//! S3-compatible [`Storage`] backend (compile with `--features s3`).
//!
//! Reads stream straight from the object's response body, and writes stream
//! into a multipart upload one part at a time. The only buffer held in memory
//! is a single in-flight part (see [`PART_SIZE`]); a whole object is never
//! collected.

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::{Bytes, BytesMut};
use futures::{StreamExt, TryStreamExt};

use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use aws_sdk_s3::primitives::ByteStream as AwsByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};

/// Size of each multipart-upload part. S3 requires every part except the last
/// to be at least 5 MiB; 8 MiB keeps part counts low while bounding the buffer.
const PART_SIZE: usize = 8 * 1024 * 1024;

/// Stores objects in an S3 (or S3-compatible, e.g. MinIO) bucket.
#[derive(Debug, Clone)]
pub struct S3Storage {
    client: aws_sdk_s3::Client,
    bucket: String,
    /// Optional SQS client for the blob-change **consumer** (FA-5b2). When set,
    /// [`supports_watch`](Storage::supports_watch) is `true` and
    /// [`watch`](Storage::watch) polls the queue provisioned for the prefix.
    sqs: Option<aws_sdk_sqs::Client>,
}

/// Connection options for [`S3Storage::connect`].
#[derive(Debug, Clone, Default)]
pub struct S3Options {
    /// Bucket to store blobs in.
    pub bucket: String,
    /// Custom endpoint URL (e.g. a MinIO server). Defaults to AWS.
    pub endpoint: Option<String>,
    /// Region. Defaults to the ambient AWS region resolution.
    pub region: Option<String>,
    /// Use path-style addressing (required by MinIO and most S3-compatibles).
    pub force_path_style: bool,
}

impl S3Storage {
    /// Build a backend from an existing client and bucket name.
    pub fn new(client: aws_sdk_s3::Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            sqs: None,
        }
    }

    /// Attach an SQS client so this backend can **consume** blob-change
    /// notifications (FA-5b2): [`supports_watch`](Storage::supports_watch) becomes
    /// `true`, and [`watch`](Storage::watch) long-polls the queue provisioned for
    /// the watched prefix (see [`crate::s3_notify`]).
    pub fn with_sqs_notify(mut self, sqs: aws_sdk_sqs::Client) -> Self {
        self.sqs = Some(sqs);
        self
    }

    /// Build a backend from the ambient AWS environment (env vars, shared
    /// config/profile, instance metadata, ...).
    pub async fn from_env(bucket: impl Into<String>) -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self::new(aws_sdk_s3::Client::new(&config), bucket)
    }

    /// Build a backend from explicit [`S3Options`], honoring a custom endpoint
    /// (MinIO and other S3-compatibles), region, and path-style addressing.
    /// Credentials still come from the ambient AWS environment.
    pub async fn connect(opts: S3Options) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = opts.region.clone() {
            loader = loader.region(aws_sdk_s3::config::Region::new(region));
        }
        if let Some(endpoint) = opts.endpoint.clone() {
            loader = loader.endpoint_url(endpoint);
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if opts.force_path_style {
            builder = builder.force_path_style(true);
        }
        Self::new(aws_sdk_s3::Client::from_conf(builder.build()), opts.bucket)
    }

    /// Build a **notify-enabled** backend and its blob-change
    /// [`S3WatchProvider`](crate::s3_notify::S3WatchProvider) from one shared AWS
    /// config (FA-5b2). The returned storage consumes the provisioned SQS queue
    /// (so [`supports_watch`](Storage::supports_watch) is `true`); the provider
    /// creates/retracts the pipeline. `account_id` scopes the queue's
    /// `SendMessage` policy to this account.
    pub async fn connect_with_notify(
        opts: S3Options,
        account_id: impl Into<String>,
    ) -> (Self, crate::s3_notify::S3WatchProvider) {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = opts.region.clone() {
            loader = loader.region(aws_sdk_s3::config::Region::new(region));
        }
        if let Some(endpoint) = opts.endpoint.clone() {
            loader = loader.endpoint_url(endpoint);
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if opts.force_path_style {
            builder = builder.force_path_style(true);
        }
        let s3 = aws_sdk_s3::Client::from_conf(builder.build());
        let sqs = aws_sdk_sqs::Client::new(&shared);
        let storage = Self::new(s3.clone(), opts.bucket.clone()).with_sqs_notify(sqs.clone());
        let provider =
            crate::s3_notify::S3WatchProvider::new(s3, sqs, opts.bucket, account_id.into());
        (storage, provider)
    }

    /// The bucket this backend targets.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The underlying S3 client.
    pub fn client(&self) -> &aws_sdk_s3::Client {
        &self.client
    }

    /// Drain `body` into the multipart upload, emitting one part per
    /// [`PART_SIZE`] chunk (plus a final remainder). Only one part is buffered
    /// at a time.
    async fn upload_parts(
        &self,
        key: &str,
        upload_id: &str,
        mut body: ByteStream,
    ) -> Result<(Vec<CompletedPart>, u64), StorageError> {
        let mut parts = Vec::new();
        let mut buf = BytesMut::with_capacity(PART_SIZE);
        let mut part_number: i32 = 1;
        let mut total: u64 = 0;

        while let Some(chunk) = body.try_next().await? {
            total += chunk.len() as u64;
            buf.extend_from_slice(&chunk);
            while buf.len() >= PART_SIZE {
                let part = buf.split_to(PART_SIZE).freeze();
                parts.push(self.upload_one(key, upload_id, part_number, part).await?);
                part_number += 1;
            }
        }

        // Flush the remainder as the final part (S3 requires at least one part;
        // the last part may be smaller than PART_SIZE).
        let part = buf.freeze();
        parts.push(self.upload_one(key, upload_id, part_number, part).await?);

        Ok((parts, total))
    }

    async fn upload_one(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: Bytes,
    ) -> Result<CompletedPart, StorageError> {
        let resp = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(AwsByteStream::from(data.to_vec()))
            .send()
            .await
            .map_err(sdk_err)?;

        Ok(CompletedPart::builder()
            .part_number(part_number)
            .set_e_tag(resp.e_tag().map(str::to_string))
            .build())
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        let resp =
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
                .map_err(|err| {
                    if err.as_service_error().is_some_and(
                        aws_sdk_s3::operation::get_object::GetObjectError::is_no_such_key,
                    ) {
                        StorageError::NotFound(key.to_string())
                    } else {
                        sdk_err(err)
                    }
                })?;

        let meta = ObjectMeta {
            key: key.to_string(),
            size: resp
                .content_length()
                .and_then(|len| u64::try_from(len).ok()),
            content_type: resp.content_type().map(str::to_string),
            etag: resp.e_tag().map(str::to_string),
        };

        Ok(GetObject {
            meta,
            body: aws_body_to_stream(resp.body),
        })
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        let range = match len {
            Some(n) if n > 0 => format!("bytes={}-{}", offset, offset + n - 1),
            _ => format!("bytes={offset}-"),
        };
        let resp =
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .range(range)
                .send()
                .await
                .map_err(|err| {
                    if err.as_service_error().is_some_and(
                        aws_sdk_s3::operation::get_object::GetObjectError::is_no_such_key,
                    ) {
                        StorageError::NotFound(key.to_string())
                    } else {
                        sdk_err(err)
                    }
                })?;

        let meta = ObjectMeta {
            key: key.to_string(),
            size: resp
                .content_length()
                .and_then(|len| u64::try_from(len).ok()),
            content_type: resp.content_type().map(str::to_string),
            etag: resp.e_tag().map(str::to_string),
        };
        Ok(GetObject {
            meta,
            body: aws_body_to_stream(resp.body),
        })
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        let create = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .set_content_type(meta.content_type.clone())
            .send()
            .await
            .map_err(sdk_err)?;

        let upload_id = create
            .upload_id()
            .ok_or_else(|| StorageError::backend("S3 did not return an upload id"))?
            .to_string();

        match self.upload_parts(key, &upload_id, body).await {
            Ok((parts, total)) => {
                let completed = CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build();
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .multipart_upload(completed)
                    .send()
                    .await
                    .map_err(sdk_err)?;

                Ok(ObjectMeta {
                    key: key.to_string(),
                    size: Some(total),
                    content_type: meta.content_type,
                    etag: None,
                })
            }
            Err(err) => {
                // Best-effort cleanup so a failed stream does not leave an
                // orphaned (and billable) multipart upload behind.
                let _ = self
                    .client
                    .abort_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .send()
                    .await;
                Err(err)
            }
        }
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        let resp =
            self.client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send()
                .await
                .map_err(|err| {
                    if err.as_service_error().is_some_and(
                        aws_sdk_s3::operation::head_object::HeadObjectError::is_not_found,
                    ) {
                        StorageError::NotFound(key.to_string())
                    } else {
                        sdk_err(err)
                    }
                })?;

        Ok(ObjectMeta {
            key: key.to_string(),
            size: resp
                .content_length()
                .and_then(|len| u64::try_from(len).ok()),
            content_type: resp.content_type().map(str::to_string),
            etag: resp.e_tag().map(str::to_string),
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        // S3 deletes are idempotent: removing a missing key succeeds.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(sdk_err)?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;

        loop {
            let resp = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_continuation_token(continuation.clone())
                .send()
                .await
                .map_err(sdk_err)?;

            for object in resp.contents() {
                if let Some(key) = object.key() {
                    out.push(ObjectMeta {
                        key: key.to_string(),
                        size: object.size().and_then(|len| u64::try_from(len).ok()),
                        content_type: None,
                        etag: object.e_tag().map(str::to_string),
                    });
                }
            }

            if resp.is_truncated() == Some(true) {
                continuation = resp.next_continuation_token().map(str::to_string);
                if continuation.is_some() {
                    continue;
                }
            }
            break;
        }

        Ok(out)
    }

    /// S3 can watch once the SQS notification consumer is wired (the pipeline
    /// itself is provisioned per-prefix by
    /// [`S3WatchProvider`](crate::s3_notify::S3WatchProvider) at trigger add).
    fn supports_watch(&self) -> bool {
        self.sqs.is_some()
    }

    async fn watch(
        &self,
        prefix: &str,
    ) -> Result<Option<boatramp_core::ChangeStream>, StorageError> {
        let Some(sqs) = self.sqs.clone() else {
            return Ok(None);
        };
        // The queue name is derived deterministically from the prefix, so no
        // lookup table is needed — provider and consumer agree.
        let name = crate::s3_notify::queue_name(prefix);
        let url = match sqs.get_queue_url().queue_name(&name).send().await {
            Ok(resp) => match resp.queue_url() {
                Some(url) => url.to_string(),
                None => return Ok(None),
            },
            // No queue yet ⇒ not provisioned; the reconcile retries next tick.
            Err(_) => return Ok(None),
        };
        Ok(Some(crate::s3_notify::s3_watch_stream(
            sqs,
            url,
            prefix.to_string(),
        )))
    }
}

/// Adapt an AWS response body into our [`ByteStream`], streaming chunk by chunk.
fn aws_body_to_stream(body: AwsByteStream) -> ByteStream {
    futures::stream::try_unfold(body, |mut stream| async move {
        match stream.next().await {
            Some(Ok(bytes)) => Ok(Some((bytes, stream))),
            Some(Err(err)) => Err(StorageError::backend(err.to_string())),
            None => Ok(None),
        }
    })
    .boxed()
}

/// Map any AWS SDK error into a [`StorageError`] with a readable message.
fn sdk_err<E, R>(err: SdkError<E, R>) -> StorageError
where
    SdkError<E, R>: std::error::Error,
{
    StorageError::backend(DisplayErrorContext(&err).to_string())
}
