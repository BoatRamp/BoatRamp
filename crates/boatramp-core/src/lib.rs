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

pub mod blob_provision;
pub mod cache_coherence;
#[cfg(feature = "authz")]
pub mod cedar;
pub mod cert;
pub mod compat;
#[cfg(feature = "authz")]
pub mod cose;
/// Crown-jewel CAS conversion (MF-1): the test-only mutation seam + mutation-verified gate helpers.
pub mod crownjewel;
/// An injectable source of environment-variable values ([`env::EnvSource`]):
/// `SystemEnv` in production, a `MapEnv` in tests, so config-named env resolvers
/// never require mutating the global process environment.
pub mod env;
pub mod envelope;
// `compute` extends the wasm-clean `boatramp_types::compute` (re-exported within)
// with the native control-plane layer: the `ComputeBackend` trait, the scheduler,
// and the reconcile logic.
/// A typed query AST + injection-safe `?N` SQL compiler backing the `orm` handler binding.
pub mod claim_extract;
pub mod compute;
pub mod deploy;
/// Per-project SMTP email-profile store (sealed password) backing the `email`
/// guest capability — credentials host-held, config admin-reconfigurable.
pub mod email_config;
pub mod error;
/// Per-node guest-IP pool shared by the VMM (tap) + container (veth) backends.
pub mod ipam;
/// Posture-scaled kernel-trust verification (needs the `authz` signing primitives).
#[cfg(feature = "authz")]
pub mod kernel_trust;
pub mod kv;
/// Portable, versioned, backend-agnostic KV dump format + a generic `KvStore`↔`KvStore` copier
/// (kv-sql WS7) — the one representation behind `kv export` / `import` / `migrate`.
pub mod kv_dump;
pub mod messaging;
/// Online, resumable migration of a pre-0.2.0 store to the project-scoped layout.
pub mod migrate;
pub mod mode;
pub mod orm;
pub mod project;
pub mod secret_store;
/// The duplex/resumable session delivery-semantics model (Stage 1 of `PLAN-session-primitive`).
pub mod session;
/// Shared-mode coordination (kv-sql WS4): the non-Raft leader lease (C1) + positive control-plane
/// identity / liveness roster (UX-C1) a multi-writer backend uses for N stateless nodes without Raft.
pub mod shared_mode;
pub mod sql;
/// Host-side parse-and-rewrite confinement of a guest's **raw-SQL target read** (R4/D8): the
/// AST-level analog of the `orm` path's `PerTableTarget` per-table confinement, injecting
/// `tenant = B AND <public subset>` onto EVERY table reference so a target read of another tenant
/// `B` can reach only B's declared public rows — the guest cannot reposition or `OR`-escape it.
pub mod target_sql;
/// The one canonical wall-clock read for native crates (`now_unix`/`now_unix_ms`).
pub mod time;

// The shared wasm-clean layer lives in `boatramp-types`; re-export it so the
// `boatramp_core::config`/`::route`/`::matcher`/`::domain_verify`/… paths are
// unchanged. (`compute` is its own module above — it re-exports the types layer.)
pub use boatramp_types::{SCHEMA_VERSION, schema_version};
pub use boatramp_types::{
    access, authz, blob_notify, config, cron, daemon_config, dns_managed, domain_verify, function,
    gateway, geo, host, logs, matcher, predicate, route, security, site, tenancy, waf, workflow,
};

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

/// One bounded page of a prefix listing ([`Storage::list_page`]): the object metadata for
/// this page, plus an OPAQUE `cursor` to resume after. A `None` cursor means the listing is
/// exhausted. The cursor is backend-defined (an S3 `NextContinuationToken`, a GCS
/// `next_page_token`, an Azure marker, or — for the default drain-and-slice body — the last
/// key of this page); it is meaningful ONLY to the same backend, which re-applies the
/// container prefix on resume, so a caller must treat it as opaque and never parse it.
#[derive(Debug, Clone, Default)]
pub struct ListPage {
    /// The object metadata for this page.
    pub metas: Vec<ObjectMeta>,
    /// Opaque resume cursor; `None` once the listing is exhausted.
    pub cursor: Option<String>,
}

/// Encode a container-relative key `suffix` into the OPAQUE default-body list cursor (hex), so a
/// resumable [`Storage::list_page`] cursor from the default body never exposes a readable key/name
/// (incl. the reserved `.boatramp*` namespace) or the backend's internal key scheme — matching the
/// opaque continuation tokens the cloud backends return. Paired with [`decode_list_cursor`].
fn encode_list_cursor(suffix: &str) -> String {
    hex::encode(suffix.as_bytes())
}

/// Decode a default-body list cursor produced by [`encode_list_cursor`] back to the key suffix. A
/// malformed cursor (not hex, or not UTF-8 — e.g. guest-tampered) yields `None`, so the listing simply
/// restarts from the beginning (benign; still confined to the query `prefix`).
fn decode_list_cursor(cursor: &str) -> Option<String> {
    hex::decode(cursor)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
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

    /// List ONE bounded page of object metadata under `prefix`, resuming strictly after the
    /// opaque `cursor` (`after`), at most `limit` entries, returning the page plus the next
    /// cursor (`None` ⇒ exhausted). Unlike [`list`](Self::list), this never buffers the whole
    /// keyspace — it is the primitive behind the guest's prefix-scoped, resumable blob list, so
    /// a maintenance pass (e.g. GC) stays within a handler's wall-clock on a container with tens
    /// of thousands of objects.
    ///
    /// The default drains [`list`](Self::list), sorts by key, and slices one page after the
    /// `after` cursor. Real cloud backends (S3/GCS/Azure) override it with native single-request
    /// pagination, where the cursor is the backend's own continuation token. In BOTH cases the cursor
    /// is OPAQUE to the caller and meaningful only to the same backend: for this default it is a hex
    /// token of the last key's suffix under `prefix`, so it carries neither the backend's internal key
    /// scheme (e.g. an `hblob/{site}/…` container path) NOR any readable key/name — matching the opaque
    /// continuation tokens the cloud backends return. Resume decodes it and re-joins `prefix + suffix`;
    /// a malformed (guest-tampered) cursor decodes to nothing and simply restarts, still confined to
    /// `prefix`. `limit == 0` is treated as 1.
    async fn list_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<ListPage, StorageError> {
        let mut metas = self.list(prefix).await?;
        metas.sort_by(|a, b| a.key.cmp(&b.key));
        let start = match after.and_then(decode_list_cursor) {
            // The decoded cursor is the prior page's last-key suffix under `prefix` (exclusive):
            // re-join to the full key and resume strictly past it. All listed keys begin with
            // `prefix`, so the order is identical on full keys or suffixes. A cursor that does not
            // decode ⇒ restart from the beginning (benign; still confined to `prefix`).
            Some(suffix) => {
                let resume = format!("{prefix}{suffix}");
                metas.partition_point(|m| m.key.as_str() <= resume.as_str())
            }
            None => 0,
        };
        let take = limit.max(1) as usize;
        let end = start.saturating_add(take).min(metas.len());
        let page = metas.get(start..end).unwrap_or(&[]).to_vec();
        let cursor = (end < metas.len())
            .then(|| {
                page.last()
                    .map(|m| encode_list_cursor(m.key.strip_prefix(prefix).unwrap_or(&m.key)))
            })
            .flatten();
        Ok(ListPage {
            metas: page,
            cursor,
        })
    }

    /// If this backend stores objects as local files, memory-map `key` and return
    /// its bytes for zero-copy serving. The blob keyspace is content-addressed and
    /// immutable (a file is never modified after it is written), so a mapping can
    /// never see a truncated/rewritten file — the one hazard that makes `mmap`
    /// unsafe. Returns `None` for remote/opaque backends (S3/GCS/Azure) or on any
    /// error, so the caller falls back to streaming. Large static bodies use this
    /// to skip `tokio::fs`'s internal double-buffering copy (and serve one
    /// content-length body instead of a chunked stream).
    fn mapped(&self, _key: &str) -> Option<bytes::Bytes> {
        None
    }

    /// If this backend stores objects as local files, open `key` and return the
    /// file handle for the zero-copy `sendfile` serving path — the kernel moves the
    /// file's bytes straight to the client socket with no userspace copy (what
    /// nginx/caddy do for plaintext static). Same content-addressed-immutability
    /// guarantee as [`mapped`](Storage::mapped). Returns `None` for remote/opaque
    /// backends (S3/GCS/Azure) or on any error, so the caller falls back to
    /// `mapped`/streaming. The caller decides whether `sendfile` is applicable
    /// (plaintext only — TLS can't zero-copy through userspace crypto).
    fn local_file(&self, _key: &str) -> Option<std::fs::File> {
        None
    }

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

    /// Whether a destructive prune (a GC delete of an unreferenced object) is safe on
    /// this backend. Defaults to `true` — every ordinary backend (fs/S3/GCS/Azure) may
    /// be pruned, because its `list` and `delete` operate over the SAME object set.
    ///
    /// A read-fallback composite (`FallbackStorage`, blob-backend migration Part 2)
    /// returns `false`: its `list` is a **union** of primary + secondary, but its
    /// `delete` is **primary-only**, so GC would count a secondary-only orphan as
    /// reclaimed (it appears in the union `list`) while the delete silently no-ops on
    /// the read-only secondary — and a subsequent read fallback would resurrect it.
    /// The doctrine is drain-then-drop: `boatramp blob migrate` drains the secondary
    /// into the primary, the operator removes `[serve].blob_fallback`, THEN GC prunes.
    /// A caller about to prune-delete MUST consult this and refuse when it is `false`.
    fn allows_prune(&self) -> bool {
        true
    }

    /// If this backend is a read-fallback composite mid-transition, the two halves it can
    /// drain: the read-only OLD secondary (`source`) into the NEW primary (`dest`). Returns
    /// `None` for an ordinary single backend (nothing to drain).
    ///
    /// This is the daemon-mediated drain's *only* input: the client names **no** source or
    /// destination — the running daemon drains **exactly** its own configured
    /// `[serve.blob_fallback]` pair (see `POST /api/blob-drain`). A `FallbackStorage`
    /// (blob-backend migration Part 2) returns `Some(DrainPair { source: secondary, dest:
    /// primary })`; a `CachedStorage` delegates to its inner backend. Mirrors the
    /// [`allows_prune`](Self::allows_prune) opt-in shape: a default of `None` so every ordinary
    /// backend is unaffected, and the composite overrides it.
    fn drain_pair(&self) -> Option<DrainPair> {
        None
    }
}

/// The two halves of a read-fallback composite ([`FallbackStorage`]) a daemon-mediated drain
/// copies between: the read-only OLD `source` (the configured `[serve.blob_fallback]` secondary)
/// into the NEW `dest` (the primary). Returned from [`Storage::drain_pair`]; the daemon copies
/// `source` → `dest` with `boatramp_storage::blob_migrate::migrate`, so after a verified drain the
/// secondary holds no object the primary lacks and can be removed.
///
/// [`FallbackStorage`]: crate::Storage
pub struct DrainPair {
    /// The read-only OLD secondary — the drain SOURCE (never written or deleted).
    pub source: std::sync::Arc<dyn Storage>,
    /// The NEW primary — the drain DESTINATION (gains every object the secondary still holds).
    pub dest: std::sync::Arc<dyn Storage>,
}

#[cfg(test)]
mod list_page_tests {
    use super::*;

    /// A minimal in-memory [`Storage`] whose `list` returns canned keys — just enough to exercise the
    /// DEFAULT [`Storage::list_page`] body (sort + slice + opaque cursor). Non-list ops are unused.
    struct CannedList(Vec<String>);

    #[async_trait::async_trait]
    impl Storage for CannedList {
        async fn get(&self, _key: &str) -> Result<GetObject, StorageError> {
            unimplemented!()
        }
        async fn get_range(
            &self,
            _key: &str,
            _offset: u64,
            _len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            unimplemented!()
        }
        async fn put(
            &self,
            _key: &str,
            _body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            unimplemented!()
        }
        async fn head(&self, _key: &str) -> Result<ObjectMeta, StorageError> {
            unimplemented!()
        }
        async fn delete(&self, _key: &str) -> Result<(), StorageError> {
            unimplemented!()
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .0
                .iter()
                .filter(|k| k.starts_with(prefix))
                .map(|k| ObjectMeta {
                    key: k.clone(),
                    ..Default::default()
                })
                .collect())
        }
    }

    /// The opaque list cursor round-trips, and never carries a readable key/name or the internal key
    /// scheme — so even a reserved `.boatramp*` suffix or an `hblob/{site}/…` path is unreadable in it.
    #[test]
    fn list_cursor_is_opaque_and_round_trips() {
        for suffix in ["der/shaA/0.jpg", ".boatramp-uploads/u-7/part-3", ""] {
            let tok = encode_list_cursor(suffix);
            assert_eq!(decode_list_cursor(&tok).as_deref(), Some(suffix));
            // Opaque: hex, so no readable key material leaks through the cursor.
            assert!(
                !tok.contains(".boatramp") && !tok.contains('/') && !tok.contains("hblob"),
                "cursor must be opaque, got {tok:?}"
            );
        }
        // A malformed (guest-tampered) cursor decodes to nothing → the listing restarts, still confined.
        assert_eq!(decode_list_cursor("not-hex!!"), None);
    }

    /// The default `list_page` body paginates a prefix exactly — every key once, in order, no dup/skip
    /// across pages — and its cursor is opaque (even when a page boundary lands on a reserved key).
    #[tokio::test]
    async fn default_list_page_paginates_exactly_with_opaque_cursor() {
        // Keys under one container prefix, incl. the reserved marker + host-internal staging. `.` sorts
        // before letters, so the reserved keys are the first page boundaries under a limit=1 walk.
        let p = "hblob/site-a/assets/";
        let store = CannedList(vec![
            format!("{p}.boatramp-container"),
            format!("{p}.boatramp-uploads/u-7/part-3"),
            format!("{p}der/shaA/0.jpg"),
            format!("{p}der/shaA/1.jpg"),
            format!("{p}top.txt"),
        ]);

        let mut seen = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..64 {
            let page = store.list_page(p, after.as_deref(), 1).await.unwrap();
            assert!(page.metas.len() <= 1, "limit honored");
            if let Some(cur) = &page.cursor {
                assert!(
                    !cur.contains(".boatramp") && !cur.contains("hblob") && !cur.contains('/'),
                    "cursor must be opaque even on a reserved-key boundary, got {cur:?}"
                );
            }
            seen.extend(page.metas.into_iter().map(|m| m.key));
            match page.cursor {
                Some(cur) => after = Some(cur),
                None => break,
            }
        }
        // Every key, exactly once, in sorted order — no dup, no skip across the paged walk.
        assert_eq!(
            seen,
            vec![
                format!("{p}.boatramp-container"),
                format!("{p}.boatramp-uploads/u-7/part-3"),
                format!("{p}der/shaA/0.jpg"),
                format!("{p}der/shaA/1.jpg"),
                format!("{p}top.txt"),
            ]
        );
    }
}
