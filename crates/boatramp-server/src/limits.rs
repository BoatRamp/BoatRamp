//! Operational request limits: bound blob uploads in size, time,
//! and concurrency so a single client can't exhaust disk, sockets, or memory —
//! **without breaking streaming** (nothing is buffered to enforce a cap; the
//! upload stream is wrapped and aborted the moment a bound is crossed).
//!
//! These are server-tier (operational) knobs, not per-site config: they protect
//! the host, so they live on the listener, configured by `boatramp serve`.

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::{ByteStream, StorageError};
use futures::StreamExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Server-tier upload limits. All `None` = unlimited (the default; preserves the
/// unbounded streaming behavior for operators who front boatramp with their own
/// limits).
#[derive(Debug, Clone, Default)]
pub struct ServerLimits {
    /// Reject a blob upload larger than this many bytes (413 on a declared
    /// `Content-Length`; the stream is also aborted if it exceeds the cap while
    /// streaming, in case the length was absent or lied).
    pub max_upload_bytes: Option<u64>,
    /// Abort an upload whose body stalls (no bytes) for longer than this —
    /// slowloris protection that doesn't penalize slow-but-steady transfers.
    pub upload_idle_timeout: Option<Duration>,
    /// Cap on simultaneous in-flight blob uploads; further uploads get 503 until
    /// a slot frees. `None` = unbounded.
    pub max_concurrent_uploads: Option<usize>,
}

impl ServerLimits {
    /// Whether any limit is set (so callers can skip wrapping work entirely).
    pub fn is_unlimited(&self) -> bool {
        self.max_upload_bytes.is_none()
            && self.upload_idle_timeout.is_none()
            && self.max_concurrent_uploads.is_none()
    }
}

/// Runtime guard built from [`ServerLimits`], shared across requests as an axum
/// extension. Holds the concurrency semaphore (if any) and the per-upload caps.
#[derive(Clone)]
pub struct UploadGuard {
    max_upload_bytes: Option<u64>,
    upload_idle_timeout: Option<Duration>,
    uploads: Option<Arc<Semaphore>>,
}

impl UploadGuard {
    /// Build a guard from limits (an unbounded guard if `limits.is_unlimited()`).
    pub fn new(limits: ServerLimits) -> Self {
        Self {
            max_upload_bytes: limits.max_upload_bytes,
            upload_idle_timeout: limits.upload_idle_timeout,
            uploads: limits
                .max_concurrent_uploads
                .map(|n| Arc::new(Semaphore::new(n.max(1)))),
        }
    }

    /// Try to claim an upload slot. `Some` (held for the upload's duration) when
    /// admitted — including the unlimited case; `None` when the concurrency cap
    /// is currently saturated.
    pub fn try_acquire(&self) -> Option<UploadPermit> {
        match &self.uploads {
            None => Some(UploadPermit(None)),
            Some(sem) => sem
                .clone()
                .try_acquire_owned()
                .ok()
                .map(|permit| UploadPermit(Some(permit))),
        }
    }

    /// Whether `content_length` already exceeds the size cap (cheap early 413).
    pub fn content_length_rejected(&self, content_length: Option<u64>) -> bool {
        matches!((self.max_upload_bytes, content_length), (Some(max), Some(len)) if len > max)
    }

    /// Wrap an upload body so it is aborted if it exceeds the size cap or stalls
    /// past the idle timeout. A no-op (returns the stream unchanged) when neither
    /// applies, so the unlimited path keeps zero overhead.
    pub fn limit_body(&self, stream: ByteStream) -> ByteStream {
        limited_stream(stream, self.max_upload_bytes, self.upload_idle_timeout)
    }
}

/// An admitted upload slot; the underlying semaphore permit (if any) is released
/// when this is dropped, i.e. when the upload finishes.
pub struct UploadPermit(#[allow(dead_code)] Option<OwnedSemaphorePermit>);

/// Wrap `inner` to enforce a running byte cap and/or an idle (between-chunk)
/// timeout, erroring (and stopping) the instant either is crossed.
fn limited_stream(inner: ByteStream, max: Option<u64>, idle: Option<Duration>) -> ByteStream {
    if max.is_none() && idle.is_none() {
        return inner;
    }
    futures::stream::unfold(
        (inner, 0u64, false),
        move |(mut inner, sent, done)| async move {
            if done {
                return None;
            }
            let next = match idle {
                Some(timeout) => match tokio::time::timeout(timeout, inner.next()).await {
                    Ok(item) => item,
                    Err(_) => {
                        return Some((
                            Err(StorageError::backend("upload idle timeout")),
                            (inner, sent, true),
                        ))
                    }
                },
                None => inner.next().await,
            };
            match next {
                None => None,
                Some(Err(err)) => Some((Err(err), (inner, sent, true))),
                Some(Ok(chunk)) => {
                    let sent = sent + chunk.len() as u64;
                    if let Some(max) = max {
                        if sent > max {
                            return Some((
                                Err(StorageError::backend(format!(
                                    "upload exceeds the {max}-byte limit"
                                ))),
                                (inner, sent, true),
                            ));
                        }
                    }
                    Some((Ok(chunk), (inner, sent, false)))
                }
            }
        },
    )
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn stream_of(chunks: Vec<&'static [u8]>) -> ByteStream {
        futures::stream::iter(chunks.into_iter().map(|c| Ok(Bytes::from_static(c)))).boxed()
    }

    async fn drain(mut s: ByteStream) -> Result<u64, StorageError> {
        let mut total = 0u64;
        while let Some(item) = s.next().await {
            total += item?.len() as u64;
        }
        Ok(total)
    }

    #[tokio::test]
    async fn under_cap_passes_through() {
        let s = limited_stream(stream_of(vec![b"abc", b"de"]), Some(10), None);
        assert_eq!(drain(s).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn over_cap_aborts() {
        let s = limited_stream(stream_of(vec![b"abc", b"defgh", b"more"]), Some(6), None);
        let err = drain(s).await.unwrap_err();
        assert!(err.to_string().contains("6-byte limit"), "{err}");
    }

    #[test]
    fn content_length_early_reject() {
        let guard = UploadGuard::new(ServerLimits {
            max_upload_bytes: Some(100),
            ..Default::default()
        });
        assert!(guard.content_length_rejected(Some(101)));
        assert!(!guard.content_length_rejected(Some(100)));
        assert!(!guard.content_length_rejected(None));
    }

    #[test]
    fn concurrency_cap_admits_then_saturates() {
        let guard = UploadGuard::new(ServerLimits {
            max_concurrent_uploads: Some(1),
            ..Default::default()
        });
        let permit = guard.try_acquire().expect("first admitted");
        assert!(guard.try_acquire().is_none(), "second rejected while held");
        drop(permit);
        assert!(guard.try_acquire().is_some(), "slot freed after drop");
    }

    #[test]
    fn unlimited_always_admits() {
        let guard = UploadGuard::new(ServerLimits::default());
        assert!(guard.try_acquire().is_some());
        assert!(guard.try_acquire().is_some());
    }
}
