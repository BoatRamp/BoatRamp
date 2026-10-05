//! S3-compatible [`Storage`] backend (compile with `--features s3`).
//!
//! Reads stream straight from the object's response body, and writes stream
//! into a multipart upload one part at a time. The only buffer held in memory
//! is a single in-flight part (see [`PART_SIZE`]); a whole object is never
//! collected.

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ListPage, ObjectMeta, PutMeta, Storage, StorageError};
use bytes::{Bytes, BytesMut};
use futures::{StreamExt, TryStreamExt};

use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::RequestId;
use aws_sdk_s3::primitives::ByteStream as AwsByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use std::time::Instant;

use crate::blob_fault;

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
#[derive(Clone, Default)]
pub struct S3Options {
    /// Bucket to store blobs in.
    pub bucket: String,
    /// Custom endpoint URL (e.g. a MinIO server). Defaults to AWS.
    pub endpoint: Option<String>,
    /// Region. Defaults to the ambient AWS region resolution.
    pub region: Option<String>,
    /// Use path-style addressing (required by MinIO and most S3-compatibles).
    pub force_path_style: bool,
    /// An explicit **base credential** `(access_key_id, secret_access_key)` to use instead of the
    /// ambient AWS env chain (#505 sealed-store sourcing). `None` ⇒ credentials come from the ambient
    /// AWS environment (env vars / shared config / instance metadata), the historical behavior. When
    /// `Some`, a static `Credentials` provider is installed on the SDK config so the base key is the
    /// sealed one, never `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`. The secret half is confidential,
    /// so `S3Options` no longer derives `Debug` (it would leak it) — see the manual redacting impl.
    pub credential: Option<(String, String)>,
}

/// `Debug` redacts the `credential` secret half so a struct-`Debug` of `S3Options` in a log/panic
/// cannot leak the sealed base key (#505). All other fields are non-secret and shown; the credential is
/// reduced to whether it is set + its (public) access-key id.
impl std::fmt::Debug for S3Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Options")
            .field("bucket", &self.bucket)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("force_path_style", &self.force_path_style)
            .field(
                "credential",
                &self
                    .credential
                    .as_ref()
                    .map(|(id, _)| {
                        format!("Some(access_key_id={id:?}, secret_access_key=<redacted>)")
                    })
                    .unwrap_or_else(|| "None".to_string()),
            )
            .finish()
    }
}

/// Build the static AWS [`Credentials`](aws_sdk_s3::config::Credentials) provider for an explicit sealed
/// base credential (#505). The provider name `boatramp-sealed` is what shows in any AWS SDK diagnostic
/// as the credential source (never the secret).
fn sealed_credentials_provider(
    access_key_id: &str,
    secret_access_key: &str,
) -> aws_sdk_s3::config::SharedCredentialsProvider {
    aws_sdk_s3::config::SharedCredentialsProvider::new(aws_sdk_s3::config::Credentials::new(
        access_key_id.to_string(),
        secret_access_key.to_string(),
        None,
        None,
        "boatramp-sealed",
    ))
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
    /// Credentials come from the ambient AWS environment UNLESS
    /// [`opts.credential`](S3Options::credential) supplies an explicit sealed base
    /// credential (#505), in which case a static provider is installed instead.
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
        // #505: source the base credential from the sealed store instead of the ambient env chain when
        // configured. `SharedCredentialsProvider::new(Credentials::new(...))` overrides the resolved
        // chain, so the key the backend signs with is the sealed one.
        if let Some((access_key_id, secret_access_key)) = &opts.credential {
            builder = builder.credentials_provider(sealed_credentials_provider(
                access_key_id,
                secret_access_key,
            ));
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
        // #505: install the sealed base credential on the shared config BEFORE `.load()`, so BOTH the S3
        // client and the SQS notify client (built from `&shared` below) sign with the sealed key rather
        // than the ambient env chain. `None` ⇒ the ambient chain (unchanged).
        if let Some((access_key_id, secret_access_key)) = &opts.credential {
            loader = loader.credentials_provider(sealed_credentials_provider(
                access_key_id,
                secret_access_key,
            ));
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

/// The `Range` header for a `get_range(offset, len)` request, or `None` for a whole-object read that
/// must carry NO `Range` (a plain `GetObject`).
///
/// The wasi:blobstore guest reads a whole object with inclusive offsets `get-data(0, u64::MAX)` —
/// "the host clamps the range to its size". The host must NOT forge an explicit out-of-range end
/// (`bytes=0-18446744073709551614`): AWS S3 tolerates it (returns the object, 206), but strict
/// S3-compatible backends — **Tigris** (`server: Tigris OS`), R2, MinIO — reject it with `416
/// InvalidRange`, silently breaking every full-object read. So:
/// - a **bounded** partial read (`Some(n)`, `n>0`, `offset+n` in range, not the whole-object sentinel)
///   ⇒ the exact `bytes={offset}-{offset+n-1}`;
/// - a **whole-object** read from the start (to-end / `len` None|0, or the `u64::MAX`-ish sentinel /
///   an overflowing end, with `offset == 0`) ⇒ `None` (a plain `GetObject`, guaranteed 200 everywhere);
/// - a **to-end read from a non-zero offset** ⇒ the RFC-7233 open-ended `bytes={offset}-`.
fn range_header(offset: u64, len: Option<u64>) -> Option<String> {
    match len {
        // A bounded partial read whose end (`offset + n - 1`) is representable AND is not the
        // "whole object" sentinel a guest passes via `get-data(_, u64::MAX)` (blobstore's inclusive
        // offsets make that arrive here as `len == u64::MAX`).
        Some(n) if n > 0 && n != u64::MAX && offset.checked_add(n).is_some() => {
            Some(format!("bytes={}-{}", offset, offset + n - 1))
        }
        // Whole object from the start ⇒ no Range (plain GET) — never a forged, backend-rejected end.
        _ if offset == 0 => None,
        // From a non-zero offset to the end ⇒ the standard open-ended range.
        _ => Some(format!("bytes={offset}-")),
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        let started = Instant::now();
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|err| s3_read_fault("get", key, started, err))?;

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
        // A whole-object read (offset 0, "to the end") carries NO `Range` header — the guest asks for
        // the whole object via `get-data(0, u64::MAX)` (wasi:blobstore inclusive offsets, documented as
        // "the host clamps the range to its size"). Forging an explicit end (`bytes=0-<huge>`) is what
        // AWS S3 tolerates but strict S3-compatible backends (Tigris/R2/MinIO) reject with 416
        // InvalidRange — so honor the clamp contract here. See `range_header`.
        let Some(range) = range_header(offset, len) else {
            return self.get(key).await;
        };
        let started = Instant::now();
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(range)
            .send()
            .await
            .map_err(|err| s3_read_fault("get_range", key, started, err))?;

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
        let started = Instant::now();
        let resp = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|err| s3_read_fault("head", key, started, err))?;

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

    async fn list_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ListPage, StorageError> {
        // ONE `list_objects_v2` request (unlike `list`, which loops to exhaustion): S3's own
        // `NextContinuationToken` is the opaque cursor, so the whole keyspace is never buffered —
        // this is what keeps a prefix sweep / GC within a handler's wall-clock at 21k+ objects.
        let resp = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .max_keys(limit.clamp(1, 1000) as i32)
            .set_continuation_token(after.map(str::to_string))
            .send()
            .await
            .map_err(sdk_err)?;

        let metas = resp
            .contents()
            .iter()
            .filter_map(|object| {
                object.key().map(|key| ObjectMeta {
                    key: key.to_string(),
                    size: object.size().and_then(|len| u64::try_from(len).ok()),
                    content_type: None,
                    etag: object.e_tag().map(str::to_string),
                })
            })
            .collect();
        // A token is meaningful only when the result was truncated; otherwise the listing is exhausted.
        let cursor = (resp.is_truncated() == Some(true))
            .then(|| resp.next_continuation_token().map(str::to_string))
            .flatten();
        Ok(ListPage { metas, cursor })
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

/// Classify + LOG a failed blob READ (`get`/`get_range`/`head`) with the concrete S3 outcome — HTTP
/// status, error code, and `x-amz-request-id` — plus op/key/latency, instead of one opaque string.
/// A genuine 404 → `StorageError::NotFound` (unchanged, DEBUG-logged); 403/416/throttle/5xx/transport
/// → the structured `StorageError::BackendRead` (WARN). The guest-facing layer still collapses the
/// non-404 cases to a coarse reason — `reason` here is operator-level (the SDK redacts credentials;
/// object bytes never enter the error path).
fn s3_read_fault<E>(op: &str, key: &str, started: Instant, err: SdkError<E>) -> StorageError
where
    E: ProvideErrorMetadata,
    SdkError<E>: std::error::Error,
{
    let status = err.raw_response().map(|r| r.status().as_u16());
    let code = err
        .as_service_error()
        .and_then(ProvideErrorMetadata::code)
        .map(str::to_string);
    let request_id = err.request_id().map(str::to_string);
    let reason = DisplayErrorContext(&err).to_string();
    blob_fault::read_fault(
        op,
        key,
        started.elapsed().as_millis(),
        status,
        code.as_deref(),
        request_id.as_deref(),
        reason,
    )
}

#[cfg(test)]
mod tests {
    use super::range_header;

    /// GATE (v0.7.5, blob-read-404 = 416 InvalidRange on Tigris) — a whole-object read MUST NOT forge
    /// an out-of-range explicit end. Mutation-verified: revert `range_header` to the old
    /// `Some(n) if n>0 => bytes={offset}-{offset+n-1}` and the sentinel case yields
    /// `bytes=0-18446744073709551614` (the exact header Tigris 416'd) instead of `None`, turning the
    /// first assertion red.
    #[test]
    fn range_header_never_forges_an_out_of_range_end_for_a_whole_object_read() {
        // The shim's `blob::get` whole-object read: `get-data(0, u64::MAX)` → `len == u64::MAX`.
        // MUST be a plain GET (no Range), not `bytes=0-<huge>`.
        assert_eq!(
            range_header(0, Some(u64::MAX)),
            None,
            "whole-object sentinel must be a plain GET, never a forged out-of-range end"
        );
        // To-end forms from the start are also a plain GET.
        assert_eq!(range_header(0, None), None);
        assert_eq!(range_header(0, Some(0)), None);
        // A to-end read from a non-zero offset is the RFC open-ended range.
        assert_eq!(range_header(64, None), Some("bytes=64-".to_string()));
        assert_eq!(
            range_header(64, Some(u64::MAX)),
            Some("bytes=64-".to_string())
        );
        // A genuine bounded partial read keeps its exact inclusive range.
        assert_eq!(range_header(0, Some(72)), Some("bytes=0-71".to_string()));
        assert_eq!(
            range_header(100, Some(50)),
            Some("bytes=100-149".to_string())
        );
        // An overflowing end degrades to open-ended, never a wrapped/garbage number.
        assert_eq!(
            range_header(10, Some(u64::MAX - 5)),
            Some("bytes=10-".to_string())
        );
    }
}
