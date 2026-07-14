//! Core domain types for boatramp.
//!
//! - [`Storage`] — the streaming-first blob backend trait (filesystem, S3, ...).
//!   No method buffers a whole object in memory.
//! - [`kv`] — a tiny pluggable [`kv::KvStore`] for small deploy metadata, with
//!   an LRU [`kv::CachedKv`] wrapper.
//! - [`deploy`] — content-addressed, atomically-activated deployments built on
//!   top of a [`Storage`] (blobs) plus a [`kv::KvStore`] (manifests + pointers).
//! - [`config`] — deploy-scoped configuration (the `routing` section of
//!   `project.cfg`), folded into the manifest; [`matcher`] — the shared
//!   path-pattern engine it relies on.

use bytes::Bytes;
use futures::stream::BoxStream;

pub mod cache_coherence;
#[cfg(feature = "authz")]
pub mod cedar;
pub mod cert;
pub mod compat;
#[cfg(feature = "authz")]
pub mod cose;
pub mod envelope;
// `compute` extends the wasm-clean `boatramp_types::compute` (re-exported within)
// with the native control-plane layer: the `ComputeBackend` trait, the scheduler,
// and the reconcile logic.
pub mod compute;
pub mod deploy;
pub mod error;
/// Per-node guest-IP pool shared by the VMM (tap) + container (veth) backends.
pub mod ipam;
/// Posture-scaled kernel-trust verification (needs the `authz` signing primitives).
#[cfg(feature = "authz")]
pub mod kernel_trust;
pub mod kv;
pub mod messaging;
pub mod mode;
pub mod sql;

// The shared wasm-clean layer lives in `boatramp-types`; re-export it so the
// `boatramp_core::config`/`::route`/`::matcher`/`::domain_verify`/… paths are
// unchanged. (`compute` is its own module above — it re-exports the types layer.)
pub use boatramp_types::{
    access, authz, config, cron, daemon_config, dns_managed, domain_verify, function, gateway,
    matcher, predicate, route, security, waf, workflow,
};
pub use boatramp_types::{schema_version, SCHEMA_VERSION};

pub use error::{ConfigError, DeployError, KvError, StorageError};
pub use mode::DeploymentMode;

/// A streaming, owned sequence of byte chunks.
///
/// Each chunk is yielded as it becomes available; the full payload is never
/// collected in memory.
pub type ByteStream = BoxStream<'static, Result<Bytes, StorageError>>;

/// Metadata describing a stored object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Storage key (path) of the object.
    pub key: String,
    /// Size in bytes, when known ahead of streaming.
    pub size: Option<u64>,
    /// MIME content type, when known.
    pub content_type: Option<String>,
    /// Backend-specific entity tag, when available.
    pub etag: Option<String>,
}

/// Metadata supplied when writing an object.
#[derive(Debug, Clone, Default)]
pub struct PutMeta {
    /// MIME content type to record for the object.
    pub content_type: Option<String>,
}

/// The result of a streaming read: object metadata plus its byte stream.
pub struct GetObject {
    /// Metadata for the object being read.
    pub meta: ObjectMeta,
    /// The object's body, streamed chunk by chunk.
    pub body: ByteStream,
}

/// How an object under a watched prefix changed (FA-5 blob-change triggers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobChangeKind {
    /// An object was created.
    Created,
    /// An existing object's bytes changed.
    Modified,
    /// An object was removed.
    Removed,
}

/// A single change event under a watched prefix — a backend-native notification
/// ([`Storage::watch`]), never boatramp's own write path (so the semantics are the
/// same whoever wrote it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobChange {
    /// The full storage key that changed.
    pub key: String,
    /// What happened to it.
    pub kind: BlobChangeKind,
}

/// A stream of change events under a watched prefix, live until dropped.
pub type ChangeStream = BoxStream<'static, BlobChange>;

/// A pluggable, streaming object-storage backend.
///
/// Implementations MUST stream data without buffering whole objects in memory.
#[async_trait::async_trait]
pub trait Storage: Send + Sync {
    /// Open an object for streaming reads.
    async fn get(&self, key: &str) -> Result<GetObject, StorageError>;

    /// Open a byte range for streaming reads (for HTTP `Range`). `len == None`
    /// means "from `offset` to the end".
    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError>;

    /// Stream `body` into the backend at `key`, returning the stored metadata.
    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError>;

    /// Fetch object metadata without reading its body.
    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError>;

    /// Delete an object. Deleting a missing object is not an error.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// List object metadata under `prefix`.
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError>;

    /// Whether this backend can natively watch for changes (FA-5 blob-change
    /// triggers). A cheap, side-effect-free capability probe: a `Blob` trigger is
    /// **refused at activation** on a backend that returns `false`, so the
    /// semantics never silently degrade. Defaults to `false`.
    fn supports_watch(&self) -> bool {
        false
    }

    /// Watch for changes under `prefix`, returning a live stream of
    /// [`BlobChange`]s until dropped (backend-native notification — inotify /
    /// FSEvents locally, SQS / Pub/Sub / Event Grid for cloud stores). `Ok(None)`
    /// means this backend does not support watching (the default), matching
    /// [`supports_watch`](Self::supports_watch).
    async fn watch(&self, _prefix: &str) -> Result<Option<ChangeStream>, StorageError> {
        Ok(None)
    }
}
