//! A small, pluggable key/value store for deploy metadata.
//!
//! boatramp keeps two very different kinds of data apart:
//!
//! - **Blobs** — the (potentially huge) file contents — live in a streaming
//!   [`crate::Storage`] backend (filesystem, S3, ...).
//! - **Metadata** — deploy manifests and the per-site "current" pointer — are
//!   small and read on every request, so they live in a [`KvStore`].
//!
//! Separating them means the server never holds a whole file (or a whole site)
//! in memory: blobs stream, and only the small metadata is resident — and even
//! that is bounded by [`CachedKv`]'s LRU. The trait is deliberately tiny so it
//! can be backed by the filesystem, an embedded store, or a remote KV such as
//! Cloudflare KV when boatramp runs on a Workers-style platform.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use lru::LruCache;

pub use crate::error::KvError;

/// A single write within a [`KvStore::write_batch`].
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// Set `key` to the given value.
    Put(String, Vec<u8>),
    /// Delete `key`.
    Delete(String),
}

/// One `{key, value, version}` record of a portable KV dump (kv-sql WS7). It is what
/// [`KvStore::dump_scan`] yields and what the backend-agnostic
/// [`kv_dump`](crate::kv_dump) copier frames into (and reads back from) the versioned dump format —
/// a LOGICAL snapshot of the store's CONTENT (never the physical LSM/manifest/`.compactions`), so a
/// restore rebuilds a FRESH clean store immune to the torn-manifest / corrupt-`.compactions`
/// physical-corruption classes.
///
/// `version` is the backend's own per-key write counter where it has one (the SQL `kv.version`
/// column); backends with no per-key version (SlateDB, `memory`, Cloudflare KV) report `1` — a fresh
/// logical generation. The field is carried in the dump for fidelity/forensics; a restore into a
/// fresh store regenerates versions through the destination's own writes (fresh ⇒ `1`), which is the
/// whole point of a logical rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvDumpEntry {
    /// The key (the `&str` key, exactly as stored).
    pub key: String,
    /// The value bytes (an empty value is distinct from an absent key, which a dump never carries).
    pub value: Vec<u8>,
    /// The backend's per-key version where it tracks one, else `1`.
    pub version: i64,
}

/// The cold-open recovery policy for the control-plane KV store (v0.9.0 KV-recovery, C3/C7/C8/C11).
/// Defined here (not in `boatramp-storage`) so it is available regardless of the `slatedb` feature —
/// `boatramp-node`'s (non-feature-gated) `build_kv` takes it, and the SlateDB opener consumes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvOpenPolicy {
    /// **Fail LOUD** on ANY torn/unbootable store — the pre-v0.9.0 behavior. The opt-out
    /// (`--strict-kv` / `BOATRAMP_KV_STRICT=1`), and the enforced default for a cluster node-local
    /// durable store (C8 — auto-quarantining a Raft log tail could drop a committed entry / desync
    /// the log↔state-machine; a cluster fails-loud-then-rejoins from peers).
    Strict,
    /// **Self-heal** a provably-safe trailing torn WAL tail (dry-run scan → quarantine → open); fail
    /// LOUD on any UNSAFE shape (out-of-scope torn compacted/L0 SST, mid-range gap/hole, unreadable
    /// manifest). The default for a single-node control-plane store (C8). A non-empty self-heal
    /// writes a durable degraded breadcrumb (C6).
    SelfHeal,
}

/// A durable **degraded-state breadcrumb** (v0.9.0 KV-recovery, C6) written when a self-heal-on-open
/// quarantined a NON-empty torn WAL tail — i.e. the control-plane store came back only after dropping
/// a (bounded) trailing tail that MIGHT have held acked-into-WAL-but-not-yet-L0 writes. It is written
/// as a plain JSON object at `{store-root}/DEGRADED.json` (an object-store file alongside `wal/` /
/// `compacted/` / `manifest/`, so it is readable WITHOUT the LSM store being bootable), surfaced on
/// `GET /api/kv-status` + `boatramp kv status`, and cleared by `boatramp kv status --ack`. A zero-loss
/// self-heal (empty quarantine) writes NO marker (the quiet common path is a single INFO line).
///
/// Defined here (not in `boatramp-storage`) because `serde_json` is unconditional in `boatramp-core`
/// but only feature-optional in `boatramp-storage`; the storage opener builds this + calls
/// [`to_json_bytes`](Self::to_json_bytes) and writes the bytes through the object store, and the
/// readers ([`boatramp kv status`], `GET /api/kv-status`) parse them with
/// [`from_json_bytes`](Self::from_json_bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DegradedMarker {
    /// Unix seconds when the self-heal ran (matches the `wal-quarantine/{stamp}` dir stamp).
    pub stamp: u64,
    /// The WAL ids of the torn trailing tail that was quarantined (dropped from the live store).
    pub quarantined_ids: Vec<u64>,
    /// A human-readable statement of the bounded loss window — the WAL id range beyond the durable
    /// frontier that was quarantined. HONEST (C13): these bytes are preserved for FORENSICS ONLY;
    /// there is no supported recovery of acked KV pairs from a torn version-0 SST. For a pure
    /// last-good-generation manifest rollback (v0.11.0 F2) this is `"none"` — the rollback is
    /// lossless-for-acked (N-1 + WAL replay = a normal open).
    pub loss_window: String,
    /// Where the torn bytes were copied before removal (`{root}/wal-quarantine/{stamp}` for a WAL-tail
    /// self-heal, or `{root}/manifest-quarantine/{stamp}` for a manifest rollback), for forensics.
    pub quarantine_dir: String,
    /// **v0.11.0 legibility (UX C1).** The durable frontier / `last_durable_seq` the store recovered to
    /// (`replay_after_wal_id`). `#[serde(default)]` so a pre-v0.11.0 marker still parses.
    #[serde(default)]
    pub frontier: u64,
    /// **v0.11.0 legibility (UX C1).** Where the recovered frontier came from:
    /// `"manifest_latest"` (clean), `"manifest_gen_rollback"` (F2 rolled back to an older generation),
    /// or `"wal_replay"` (a WAL-tail self-heal). `#[serde(default)]` for backward compatibility (an old
    /// marker deserializes to `""`; a WAL-tail self-heal now stamps `"wal_replay"` explicitly).
    #[serde(default)]
    pub frontier_source: String,
    /// **v0.11.0 F2 manifest-rollback shape (UX C2).** `Some(G)` when a last-good-generation cold-open
    /// recovery rolled back to manifest generation G; `None` for a WAL-tail self-heal. Its presence is
    /// what lets `kv status` LEAD "RECOVERED (lossless)" and suppress the forensic-only note.
    #[serde(default)]
    pub rolled_back_to_generation: Option<u64>,
    /// **v0.11.0 F2 (UX C2).** The torn manifest generation ids quarantined so G became the latest.
    #[serde(default)]
    pub quarantined_manifest_ids: Vec<u64>,
    /// **v0.11.0 F2 (UX C11).** Reclaimable orphaned L0 SST object(s) referenced only by a discarded
    /// torn generation — a space leak the reopened store's GC reclaims, surfaced as a DISTINCT
    /// informational field so it is NEVER conflated with acked loss.
    #[serde(default)]
    pub orphaned_nonacked_objects: Vec<String>,
    /// **v0.11.1 compactions-reset shape.** The `{root}/compactions/{:020}.compactions` ids quarantined
    /// when a corrupt `.compactions` bookkeeping object was reset (`frontier_source = "compactions_reset"`).
    /// The `.compactions` object holds ONLY compactor bookkeeping (pending/recent compactions + the
    /// compactor epoch) — NO acked-data liveness — so resetting it is lossless-for-acked; `loss_window`
    /// is `"none"`. `#[serde(default)]` so an older marker still parses.
    #[serde(default)]
    pub quarantined_compactions_ids: Vec<u64>,
}

impl DegradedMarker {
    /// Serialize to pretty JSON bytes for the `{root}/DEGRADED.json` object.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        // `unwrap` is safe: the struct is plain owned data with no non-serializable fields.
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }

    /// Parse from the `{root}/DEGRADED.json` object bytes; `None` if the bytes are absent/unparseable.
    pub fn from_json_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// How many concurrent writers a [`KvStore`] backend's **own** semantics admit — a
/// capability DECLARATION, exactly like [`supports_cas`](KvStore::supports_cas) /
/// [`atomic_write_batch`](KvStore::atomic_write_batch), NOT a runtime coordinator. It is a
/// **plain enum** and carries no publisher/handle (a [`ChangePublisher`] wraps the store `Arc`
/// and is built externally by the node bootstrap, so embedding one here would be a
/// chicken-and-egg): the runtime coordination model is DERIVED from this × the node count by the
/// bootstrap, never selected as a user knob.
///
/// - [`SingleWriter`](Self::SingleWriter) — one writer at a time; going multi-node needs an
///   EXTERNAL coordinator (the existing Raft cluster). SlateDB (object-store), `memory`,
///   Cloudflare KV, and `sql`+SQLite/libsql-local all declare this. It is the trait **default**
///   ([`KvStore::writer_model`]), so every existing backend keeps it with no change.
/// - [`MultiWriter`](Self::MultiWriter) — the backend's engine serializes concurrent writers
///   itself (the DB *is* the coordinator), so N equal stateless nodes can share one store with no
///   Raft. Declared by `sql`+Postgres/MySQL (wired in a later workstream); not used yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterModel {
    /// One logical writer at a time (external coordination for multi-node). The default.
    SingleWriter,
    /// The backend self-serializes concurrent writers (no external coordinator needed).
    MultiWriter,
}

/// A minimal key/value store for small values, with atomic per-key writes.
#[async_trait]
pub trait KvStore: Send + Sync {
    /// Fetch the value for `key`, or `None` if absent.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError>;

    /// Set `key` to `value`, atomically replacing any previous value.
    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError>;

    /// Delete `key`. Deleting a missing key is not an error.
    async fn delete(&self, key: &str) -> Result<(), KvError>;

    /// List all keys beginning with `prefix`.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError>;

    /// List up to `limit` keys under `prefix` that sort **strictly after**
    /// `{prefix}{after}` (an empty `after` starts at the beginning), in key order
    /// — a bounded, resumable range scan. The default rebuilds it from
    /// [`list_prefix`](Self::list_prefix) (O(keys-under-prefix)); ordered backends
    /// override it with a native seek so a caller paging forward from a cursor is
    /// O(`limit`), not O(prefix size) — the messaging fan-out claim relies on this.
    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        let start = format!("{prefix}{after}");
        let mut keys: Vec<String> = self
            .list_prefix(prefix)
            .await?
            .into_iter()
            .filter(|k| k.as_str() > start.as_str())
            .collect();
        keys.sort();
        keys.truncate(limit);
        Ok(keys)
    }

    /// All `(key, value)` pairs under `prefix`, in ONE scan. The default composes
    /// [`list_prefix`](Self::list_prefix) + a [`get`](Self::get) per key — the historical N+1, kept
    /// so no backend is forced to change. A backend with a native values-returning scan (the SQL
    /// `SELECT key,value … WHERE key LIKE prefix%`, SlateDB's range iterator, the in-memory map)
    /// overrides it with a single round-trip; the caching/checkpoint wrappers forward to the inner
    /// store for authoritative values. Used by hot count/aggregate paths that would otherwise fetch
    /// keys then values separately (e.g. the shared-mode live-member count — review finding M1),
    /// multiplying the round-trips (especially over a networked SQL backend).
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        let keys = self.list_prefix(prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(value) = self.get(&key).await? {
                out.push((key, value));
            }
        }
        Ok(out)
    }

    /// Scan EVERY `{key, value, version}` in the store, in key order — the primitive the portable
    /// KV dump (kv-sql WS7, [`kv_dump`](crate::kv_dump)) exports from. The default rebuilds each
    /// entry from [`list_prefix`](Self::list_prefix)`("")` + [`get`](Self::get), reporting
    /// `version = 1` (a backend with no per-key version — SlateDB, `memory`, Cloudflare KV — has
    /// nothing else to report, and a logical dump's version is informational). A backend that tracks
    /// a per-key version (the SQL `kv.version` column) overrides this with a single ordered scan that
    /// reads the real version; the caching/checkpoint wrappers forward to their inner store so the
    /// dump reads the AUTHORITATIVE values (never a stale LRU). It returns EVERY key — the copier
    /// applies the reserved-feed filter ([`kv_dump::is_reserved_dump_key`](crate::kv_dump::is_reserved_dump_key)),
    /// so this stays a plain "scan all" primitive.
    async fn dump_scan(&self) -> Result<Vec<KvDumpEntry>, KvError> {
        let keys = self.list_prefix("").await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(value) = self.get(&key).await? {
                out.push(KvDumpEntry {
                    key,
                    value,
                    version: 1,
                });
            }
        }
        Ok(out)
    }

    /// Durably persist any buffered writes, keeping the store usable. The default
    /// is a no-op (in-memory + write-through backends are already durable on
    /// return); buffered backends (SlateDB, which flushes on a timer) override it
    /// so a **graceful shutdown** can force the final flush rather than racing the
    /// timer — important for the Raft log/state store, whose durability is the
    /// cluster's correctness boundary.
    async fn flush(&self) -> Result<(), KvError> {
        Ok(())
    }

    /// Durably persist buffered writes AND mark the store closed, releasing its background
    /// writers — the strongest graceful-shutdown primitive. The default delegates to
    /// [`flush`](Self::flush) (an uncached / write-through store has nothing further to close),
    /// so a caller can always `close()` on shutdown and get at-least the flush semantics.
    ///
    /// A buffered LSM backend (SlateDB) overrides this to run its real `close()`, which — unlike
    /// `flush()` (WAL only) — freezes memtables to L0 and **advances the durable frontier**, so a
    /// subsequent cold open has an empty WAL replay range and cannot see a torn tail. The caller
    /// MUST have quiesced every writer BEFORE calling `close()`: a buffered backend marks the store
    /// closed FIRST and then flushes, so a write racing the mark errors or forces a new (torn-able)
    /// WAL segment. A no-op on a read replica.
    async fn close(&self) -> Result<(), KvError> {
        self.flush().await
    }

    /// **Advance the durable frontier NOW** — freeze the in-memory memtable to L0 so every write
    /// acked so far is past the durable replay boundary, WITHOUT closing the store. The default is
    /// a **no-op**: an in-memory / write-through backend has no separate durable frontier, and a
    /// consensus-replicated backend (the cluster `RaftKv`) durably commits every write to a quorum,
    /// so neither has a WAL tail to advance. Only a buffered LSM backend (SlateDB) overrides this to
    /// run `flush_with_options(FlushType::MemTable)`; wrappers ([`CachedKv`], [`CheckpointKv`])
    /// forward it to their inner store.
    ///
    /// This is the primitive that makes the self-heal-on-open default lossless-for-acked (v0.9.0
    /// KV-recovery, C1/C2): a **crown-jewel** control-plane write (sealed secret, RBAC grant/revoke,
    /// domain-ownership record, project/site/function/database identity create) advances the
    /// frontier synchronously via [`put_durable_checkpointed`](Self::put_durable_checkpointed) /
    /// [`write_batch_checkpointed`](Self::write_batch_checkpointed) /
    /// [`delete_checkpointed`](Self::delete_checkpointed) (or by being routed through a
    /// [`CheckpointKv`]) BEFORE it acks, so the write survives even a hard crash whose torn WAL tail
    /// the self-heal quarantines. A periodic cadence task also calls this to bound the loss window
    /// for everything else. A durability-buffered backend SHOULD make it idempotent + cheap when
    /// nothing has changed since the last checkpoint (dirty-gated), so an idle store never churns.
    async fn checkpoint(&self) -> Result<(), KvError> {
        Ok(())
    }

    /// A durable [`put`](Self::put) that ALSO advances the durable frontier before returning — the
    /// **crown-jewel write** variant. Equivalent to `put(..).await?; checkpoint().await`, but named
    /// so the frontier-sync is unmissable at the call site (and greppable for the Security review).
    /// Control-plane crown-jewel writes (see [`checkpoint`](Self::checkpoint)) use this so an acked
    /// write cannot be dropped by the self-heal-on-open trailing-tail quarantine. On a no-op-
    /// checkpoint backend this is exactly a durable `put`, so it is always safe to prefer.
    async fn put_durable_checkpointed(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.put(key, value).await?;
        self.checkpoint().await
    }

    /// A [`delete`](Self::delete) that ALSO advances the durable frontier before returning — the
    /// crown-jewel variant (a crown-jewel DELETE, e.g. revoke/deprovision, must be durable so it
    /// does not resurrect after a crash). See [`put_durable_checkpointed`](Self::put_durable_checkpointed).
    async fn delete_checkpointed(&self, key: &str) -> Result<(), KvError> {
        self.delete(key).await?;
        self.checkpoint().await
    }

    /// A durable [`write_batch`](Self::write_batch) that ALSO advances the durable frontier before
    /// returning — the crown-jewel grouped-write variant. The whole batch commits atomically, then
    /// one checkpoint advances the frontier past it. See
    /// [`put_durable_checkpointed`](Self::put_durable_checkpointed).
    async fn write_batch_checkpointed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.write_batch(ops).await?;
        self.checkpoint().await
    }

    /// Whether [`write_batch`](Self::write_batch) is **atomic** — all-or-nothing across the group, so
    /// a crash can never leave a partially-applied batch. The default is `false`: the default
    /// `write_batch` applies each op sequentially (each atomic per KEY, but not across the group), so
    /// a crash between two ops leaves the first applied and the second not. Backends whose batch is a
    /// single durable commit (SlateDB's `WriteBatch`, the in-memory store under one lock, the Raft
    /// state machine's per-entry apply) override this to `true`.
    ///
    /// This is a **hard prerequisite** for event-driven delivery's ready-set fast path (B2): the
    /// ready-set marker must ride the SAME atomic `write_batch` as the message-index write, else a
    /// crash between the (durable) index put and the (separate) ready put strands the message. A
    /// backend that returns `false` here MUST fall back to the full poll — see
    /// [`Messaging::supports_ready_set`](crate::messaging::Messaging::supports_ready_set), which keys
    /// on this. Fail-closed: an unsure backend inherits the default `false` and simply polls.
    fn atomic_write_batch(&self) -> bool {
        false
    }

    /// Apply several writes together. The default applies them sequentially
    /// (each atomic per key); backends that support grouped commits (e.g.
    /// SlateDB's `WriteBatch`) override this to commit the whole group in one
    /// durable flush — both fewer round-trips and all-or-nothing atomicity.
    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        for op in ops {
            match op {
                WriteOp::Put(key, value) => self.put(&key, value).await?,
                WriteOp::Delete(key) => self.delete(&key).await?,
            }
        }
        Ok(())
    }

    /// Whether [`compare_and_swap`](Self::compare_and_swap) is a **linearizable** compare-and-set —
    /// the read-of-`expected` and the conditional write happen as ONE atomic step with respect to
    /// every other writer, so two racing swappers of the same key can never both succeed. The default
    /// is `false`: the default `compare_and_swap` is a best-effort read-then-write, which is safe only
    /// where there is a single logical writer (a single-node scheduler serializes its own drains), NOT
    /// across concurrent nodes.
    ///
    /// This is the **hard prerequisite for the async-lane shard's CAS claim (B10)**: with the async
    /// drain sharded, the old and new owner of a function may briefly both run its drain (the
    /// double-owner window), and only a linearizable CAS on the invocation record guarantees at most
    /// one node transitions a `Queued`/expired-`Running` invocation to `Running`. A backend that
    /// returns `false` here MUST keep the async drain leader-gated (owns-all, today's behavior) rather
    /// than shard it — see the server's `async_shard_gate`, which keys the shard fast-path on this.
    /// Fail-closed: an unsure backend inherits the default `false` and simply stays unsharded.
    ///
    /// Backends whose CAS is genuinely atomic override this to `true`: [`MemoryKv`] (under its lock),
    /// SlateDB (a single-writer process serialized by an in-process CAS mutex), and the Raft state
    /// machine (a single leader-serialized apply). A non-transactional remote KV (Cloudflare KV) keeps
    /// the default `false`.
    fn supports_cas(&self) -> bool {
        false
    }

    /// The backend's **writer model** ([`WriterModel`]) — how many concurrent writers its own
    /// semantics admit, DECLARED like [`supports_cas`](Self::supports_cas). The node bootstrap reads
    /// this and the node count to DERIVE the runtime coordination model (none / Raft over a
    /// node-local store / a shared stateless fleet); it is never a user knob. The default is
    /// [`WriterModel::SingleWriter`], so every existing backend (SlateDB, `memory`, Cloudflare KV,
    /// and the wrappers) keeps that model with no change. A self-serializing backend (`sql`+Postgres/
    /// MySQL) overrides it to [`WriterModel::MultiWriter`]; `sql`+SQLite/libsql-local stays the
    /// single-writer default.
    fn writer_model(&self) -> WriterModel {
        WriterModel::SingleWriter
    }

    /// **Compare-and-set** `key`: write `new` IFF the current value equals `expected` (`None` =
    /// "expect the key absent"), returning `true` when the swap happened and `false` when the observed
    /// value did not match (so the caller lost the race / the record moved on).
    ///
    /// The default is a **best-effort** read-then-write: it reads the current value, compares, and
    /// writes if it matches — atomic per key, but the read and the write are two operations, so a
    /// second writer can interleave between them. That is safe ONLY on a single-writer node (the async
    /// drain runs from one scheduler loop, and a single-node deployment has exactly one process
    /// writing invocation records). It is NOT safe across concurrent cluster nodes — which is exactly
    /// why [`supports_cas`](Self::supports_cas) gates the sharded fast-path, and a backend without a
    /// linearizable CAS stays leader-gated (owns-all). See B10.
    ///
    /// Callers compare on the EXACT prior bytes they read (whole-record equality), so any concurrent
    /// mutation — a claim by another node, a settle, a redeploy — changes the bytes and the CAS
    /// correctly fails. `expected: None` is a create-if-absent (used for idempotent first writes).
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        // Best-effort default: read, compare, write-if-matched. Atomic only under a single logical
        // writer (see the method + `supports_cas` docs). A linearizable backend overrides this.
        let current = self.get(key).await?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        self.put(key, new).await?;
        Ok(true)
    }

    /// A **durability-relaxed** grouped write: the same atomic group as
    /// [`write_batch`](Self::write_batch), but the backend MAY acknowledge on an
    /// in-memory buffer insert **before** the write is durably persisted (the flush
    /// follows asynchronously). The default impl is **identical to `write_batch`
    /// (fully durable)** — a backend that cannot (or must not) relax durability
    /// simply inherits the strong path, so this can never silently weaken a store
    /// that doesn't opt in. Only [`SlateKv`](../../boatramp_storage/struct.SlateKv.html)
    /// overrides it (SlateDB `await_durable: false`).
    ///
    /// **SAFETY BOUNDARY — bus publish path ONLY.** The ONLY permitted caller is the
    /// single-node messaging group-commit
    /// ([`LogMessaging::group_commit`](crate::messaging::LogMessaging)), and only when
    /// the operator has opted the node into relaxed messaging durability. Every
    /// control-plane write (deploy/config/domain/auth), every guest `wasi:keyvalue`
    /// write, and every messaging **ack/claim/dead-letter** transition (INCLUDING the
    /// event-driven ready-set removals/re-adds — B3) MUST use the durable
    /// [`write_batch`](Self::write_batch) — a shared `KvStore` backs all of them, so
    /// relaxing any of those would be a control-plane / redelivery hazard.
    ///
    /// The sole-caller property is enforced behaviorally: the `CountingKv` durability tests assert
    /// the relaxed path is taken ONLY on the opted-in publish path (zero relaxed calls under the
    /// strong default, and never for a claim-drain prune or nack re-add — see
    /// `ready_set_removals_and_readds_are_never_relaxed`), and the sole in-tree caller is
    /// [`LogMessaging::commit_group`](crate::messaging::LogMessaging). (This is not a source-scanning
    /// lint — a future caller would have to be caught by these tests or review.)
    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.write_batch(ops).await
    }

    /// Drop any locally-cached entries, so subsequent reads come from the
    /// backing store. The default is a no-op (uncached stores — and the cluster
    /// `RaftKv`, which reads local applied state — see every committed write
    /// already); [`CachedKv`] clears its LRU.
    ///
    /// This matters for the **non-consensus shared-backend** topology: several
    /// independent processes over one shared KV (SlateDB-on-S3/R2, Cloudflare
    /// KV), each with its own LRU. A write by one process isn't visible to
    /// another until its LRU evicts; `SIGHUP` → `invalidate_cache` forces the
    /// re-read. In a Raft cluster this is unnecessary — replication applies the
    /// write to every node's state machine and `RaftKv` has no LRU in front.
    fn invalidate_cache(&self) {}

    /// Drop just these keys from any local cache (targeted invalidation),
    /// leaving the rest hot. The default is a no-op;
    /// [`CachedKv`] pops each. This is what the shared-mode changelog poller
    /// calls when it learns another process changed those keys, so a config edit
    /// to one site never flushes the whole working set.
    fn invalidate_keys(&self, keys: &[String]) {
        let _ = keys;
    }
}

/// An in-memory [`KvStore`], primarily for tests and ephemeral runs.
#[derive(Debug, Default, Clone)]
pub struct MemoryKv {
    inner: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl MemoryKv {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KvStore for MemoryKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self.inner.lock().unwrap().get(key).cloned())
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.inner.lock().unwrap().insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.lock().unwrap().remove(key);
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        // Range-seek to the prefix and walk forward only while keys still match — O(keys-under-prefix)
        // on the sorted map, NOT O(total keys). This matters for the event-driven-delivery ready-set
        // scan (`mqready/…`): an idle fleet with many other keys must not pay to scan them all.
        Ok(self
            .inner
            .lock()
            .unwrap()
            .range(prefix.to_string()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect())
    }

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        // One pass over the sorted map range — key+value together, no per-key re-lock (M1).
        Ok(self
            .inner
            .lock()
            .unwrap()
            .range(prefix.to_string()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        // The BTreeMap is already sorted, so seek straight to the cursor and walk
        // forward — O(limit) rather than the default's O(keys-under-prefix).
        let start = format!("{prefix}{after}");
        Ok(self
            .inner
            .lock()
            .unwrap()
            .range((Bound::Excluded(start), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(prefix))
            .take(limit)
            .map(|(key, _)| key.clone())
            .collect())
    }

    fn atomic_write_batch(&self) -> bool {
        // The whole group applies under one mutex (below): other readers see all of it or none of
        // it, and there is no crash boundary within an in-memory store — so its batch is atomic and
        // the ready-set fast path (B2) is safe over it.
        true
    }

    fn supports_cas(&self) -> bool {
        // The compare + swap below happen under one mutex, so it is a linearizable CAS: two racing
        // swappers of the same key can never both win. Safe for the async-lane shard's claim (B10).
        true
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        // Compare + conditional insert under ONE lock — no other writer can interleave, so this is a
        // true atomic CAS (unlike the trait default's separate read-then-write).
        let mut map = self.inner.lock().unwrap();
        let current = map.get(key).map(Vec::as_slice);
        if current != expected {
            return Ok(false);
        }
        map.insert(key.to_string(), new);
        Ok(true)
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // Apply the whole group under one lock: other readers see either all of
        // it or none of it, matching the all-or-nothing semantics of a durable
        // backend's batch.
        let mut map = self.inner.lock().unwrap();
        for op in ops {
            match op {
                WriteOp::Put(key, value) => {
                    map.insert(key, value);
                }
                WriteOp::Delete(key) => {
                    map.remove(&key);
                }
            }
        }
        Ok(())
    }
}

/// Announces locally-made control-plane writes to peer processes (shared-mode
/// cache coherence). [`CachedKv`] calls this after a
/// write so the changelog can record the changed keys for other processes'
/// pollers; the default deployment (single process / Raft) sets none.
#[async_trait]
pub trait ChangePublisher: Send + Sync {
    /// Record that `keys` were just written (best-effort; implementations log
    /// their own failures and must not panic).
    async fn publish(&self, keys: &[String]);
}

/// A write-through LRU cache in front of any [`KvStore`].
///
/// Bounds resident metadata: reads are served from memory when hot, and the
/// cache holds at most `capacity` entries regardless of how many sites or
/// deployments exist.
pub struct CachedKv {
    inner: Arc<dyn KvStore>,
    cache: Mutex<LruCache<String, Vec<u8>>>,
    /// Shared-mode coherence hook: announces local writes to peers. `None` for
    /// single-process / Raft deployments (no peers to notify).
    publisher: Option<Arc<dyn ChangePublisher>>,
}

impl CachedKv {
    /// Wrap `inner`, caching up to `capacity` entries (minimum 1).
    pub fn new(inner: Arc<dyn KvStore>, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            inner,
            cache: Mutex::new(LruCache::new(capacity)),
            publisher: None,
        }
    }

    /// Attach a [`ChangePublisher`] so local writes are announced to peer
    /// processes (shared-mode coherence). Builder-style; the default is none.
    pub fn with_publisher(mut self, publisher: Arc<dyn ChangePublisher>) -> Self {
        self.publisher = Some(publisher);
        self
    }

    /// Announce changed keys to peers, if a publisher is attached.
    async fn announce(&self, keys: Vec<String>) {
        if let Some(publisher) = &self.publisher {
            publisher.publish(&keys).await;
        }
    }

    /// Commit `ops` to the backing store FIRST (its batch is the atomic/durable one — durable via
    /// `write_batch`, or memtable-acked via `write_batch_relaxed` when `relaxed`), then mirror each
    /// write into the cache — so a failed commit never leaves the cache ahead of the store. The
    /// relaxation is purely the inner store's ack timing; the cache ordering is identical.
    async fn commit_then_mirror(&self, ops: Vec<WriteOp>, relaxed: bool) -> Result<(), KvError> {
        if relaxed {
            self.inner.write_batch_relaxed(ops.clone()).await?;
        } else {
            self.inner.write_batch(ops.clone()).await?;
        }
        let mut changed = Vec::with_capacity(ops.len());
        {
            let mut cache = self.cache.lock().unwrap();
            for op in ops {
                match op {
                    WriteOp::Put(key, value) => {
                        changed.push(key.clone());
                        cache.put(key, value);
                    }
                    WriteOp::Delete(key) => {
                        cache.pop(&key);
                        changed.push(key);
                    }
                }
            }
        }
        // One announce for the whole batch (the lock is dropped first).
        self.announce(changed).await;
        Ok(())
    }
}

#[async_trait]
impl KvStore for CachedKv {
    async fn flush(&self) -> Result<(), KvError> {
        // Forward to the backing store (the LRU holds only reads); without this a
        // graceful-shutdown flush would stop at the cache (SHUT-1).
        self.inner.flush().await
    }

    async fn close(&self) -> Result<(), KvError> {
        // Forward to the backing store: the LRU holds only reads, so closing is entirely the
        // inner store's job (freeze memtables → L0, advance the durable frontier). Without this
        // a graceful-shutdown close would stop at the cache and never quiesce SlateDB.
        self.inner.close().await
    }

    async fn checkpoint(&self) -> Result<(), KvError> {
        // Forward to the backing store: the LRU holds only reads, so the durable frontier is
        // entirely the inner store's concern. Without this forward, a crown-jewel write's
        // frontier-sync (and the periodic cadence) would stop at the cache and never freeze the
        // SlateDB memtable — silently defeating the self-heal-lossless-for-acked invariant.
        self.inner.checkpoint().await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(value) = cache.get(key) {
                return Ok(Some(value.clone()));
            }
        }
        let value = self.inner.get(key).await?;
        if let Some(bytes) = &value {
            self.cache
                .lock()
                .unwrap()
                .put(key.to_string(), bytes.clone());
        }
        Ok(value)
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.inner.put(key, value.clone()).await?;
        self.cache.lock().unwrap().put(key.to_string(), value);
        self.announce(vec![key.to_string()]).await;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.delete(key).await?;
        self.cache.lock().unwrap().pop(key);
        self.announce(vec![key.to_string()]).await;
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        // Listing is not cached; it is only used on administrative paths.
        self.inner.list_prefix(prefix).await
    }

    async fn dump_scan(&self) -> Result<Vec<KvDumpEntry>, KvError> {
        // Forward to the backing store so a dump reads the AUTHORITATIVE values (and real versions,
        // for a SQL inner store), never the LRU — the cache is a read-through mirror, not a source.
        self.inner.dump_scan().await
    }

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        // Forward to the inner store: authoritative values (never a stale LRU) + the inner's native
        // single-scan override (M1). Mirrors `dump_scan`/`list_prefix`.
        self.inner.scan_prefix(prefix).await
    }

    fn atomic_write_batch(&self) -> bool {
        // The cache is a pure read-through mirror; the backing store's batch is the atomic/durable
        // one (`commit_then_mirror` commits it FIRST). So the cache is as atomic as its inner store.
        self.inner.atomic_write_batch()
    }

    fn supports_cas(&self) -> bool {
        // The cache never serves the CAS compare (the override below goes straight to the inner
        // store, whose value is authoritative), so the CAS is as atomic as the inner store's.
        self.inner.supports_cas()
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        // The CAS compare MUST run against the backing store's authoritative value, never the LRU
        // (a stale cached value would make the compare wrong and could double-swap). So forward the
        // whole CAS to the inner store, then mirror the new value into the cache only on success —
        // a lost CAS leaves the cache untouched, and a failed inner call never advances it.
        let swapped = self
            .inner
            .compare_and_swap(key, expected, new.clone())
            .await?;
        if swapped {
            self.cache.lock().unwrap().put(key.to_string(), new);
            self.announce(vec![key.to_string()]).await;
        }
        Ok(swapped)
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.commit_then_mirror(ops, false).await
    }

    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // Forward the relaxed path to the inner store (only it can weaken durability), preserving the
        // identical commit-then-mirror ordering so a failed commit never leaves the cache ahead.
        self.commit_then_mirror(ops, true).await
    }

    fn invalidate_cache(&self) {
        // Drop every cached entry; the backing store is untouched, so the next
        // read repopulates from it (picking up writes made elsewhere, e.g. by
        // another cluster node via the replicated store).
        self.cache.lock().unwrap().clear();
    }

    fn invalidate_keys(&self, keys: &[String]) {
        // Pop just these keys; the rest of the cache stays hot.
        let mut cache = self.cache.lock().unwrap();
        for key in keys {
            cache.pop(key);
        }
    }
}

/// A [`KvStore`] wrapper that advances the durable frontier after EVERY successful write — the
/// **can't-miss** frontier-sync for the pure-crown-jewel stores whose writes are ALL irreplaceable
/// (sealed secrets, sealed DB/SMTP credentials). A dropped write in one of these stores is a lost
/// secret with no client-side copy, so rather than rely on per-call-site discipline (which could
/// miss a site) we wrap the store ONCE at construction: every `put` / `delete` / `write_batch` and
/// every successful `compare_and_swap` is immediately followed by a [`checkpoint`](KvStore::checkpoint),
/// so an acked write is past the durable replay boundary before the caller sees success — and cannot
/// be dropped by the self-heal-on-open trailing-tail quarantine (v0.9.0 KV-recovery, C2). Reads and
/// every store advertisement forward transparently.
///
/// Used ONLY for the pure-crown-jewel stores (`SecretStore`, `TenantSecretStore`,
/// `EmailProfileStore`, `ManagedSqlCredentials`). NOT the cert store: `KvCertStore` is built only on
/// the cluster ACME-DNS path over `RaftKv` (Raft-consensus durable, where this wrapper's checkpoint
/// is a no-op anyway), and the single-node ACME path caches certs in a filesystem DirCache, not the
/// control-plane KV — so cert keys never route through `CheckpointKv`. The mixed control-plane
/// `DeployStore` does NOT use this — it selects the frontier-sync PER METHOD (crown-jewel writes
/// call the `*_checkpointed` variants; derived/recomputable writes such as `current/*` pointers,
/// activation history, invocation records and metering stay async), because checkpointing its
/// high-frequency derived writes would churn the manifest. On a no-op-checkpoint backend
/// (`MemoryKv`, `CloudflareKv`, `RaftKv`) the added `checkpoint()` is free, so this wrapper is inert
/// there — the cluster's crown-jewel durability comes from Raft consensus, not a memtable freeze.
pub struct CheckpointKv {
    inner: Arc<dyn KvStore>,
}

impl CheckpointKv {
    /// Wrap `inner` so every successful write advances the durable frontier before returning.
    pub fn new(inner: Arc<dyn KvStore>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl KvStore for CheckpointKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        self.inner.get(key).await
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.inner.put(key, value).await?;
        self.inner.checkpoint().await
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.delete(key).await?;
        self.inner.checkpoint().await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        self.inner.list_prefix(prefix).await
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        self.inner.list_from(prefix, after, limit).await
    }

    async fn dump_scan(&self) -> Result<Vec<KvDumpEntry>, KvError> {
        self.inner.dump_scan().await
    }

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        self.inner.scan_prefix(prefix).await
    }

    async fn flush(&self) -> Result<(), KvError> {
        self.inner.flush().await
    }

    async fn close(&self) -> Result<(), KvError> {
        self.inner.close().await
    }

    async fn checkpoint(&self) -> Result<(), KvError> {
        self.inner.checkpoint().await
    }

    fn atomic_write_batch(&self) -> bool {
        self.inner.atomic_write_batch()
    }

    fn supports_cas(&self) -> bool {
        self.inner.supports_cas()
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        let swapped = self.inner.compare_and_swap(key, expected, new).await?;
        // Only advance the frontier when the swap actually wrote (a lost CAS mutated nothing).
        if swapped {
            self.inner.checkpoint().await?;
        }
        Ok(swapped)
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.inner.write_batch(ops).await?;
        self.inner.checkpoint().await
    }

    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        // A crown-jewel store must never relax durability: commit DURABLY and checkpoint. (No
        // crown-jewel store calls the relaxed path today; this fail-safe keeps that true if one
        // ever did — the bus publish fast-path is the only sanctioned relaxed caller, and it never
        // runs through a `CheckpointKv`.)
        self.inner.write_batch(ops).await?;
        self.inner.checkpoint().await
    }

    fn invalidate_cache(&self) {
        self.inner.invalidate_cache();
    }

    fn invalidate_keys(&self, keys: &[String]) {
        self.inner.invalidate_keys(keys);
    }
}

/// Shared **[`KvStore`] conformance** helpers, so every backend's test suite runs the IDENTICAL
/// assertions (the anti-drift property, B7) rather than a hand-copied variant. Compiled only for
/// tests (`cfg(test)` in this crate) or when a downstream crate's test build enables the
/// `kv-conformance` feature (e.g. `boatramp-storage`'s `SqlKv` suite) — never in a shipped library.
/// `#[doc(hidden)]`: a test-support surface, not public API.
#[cfg(any(test, feature = "kv-conformance"))]
#[doc(hidden)]
pub mod conformance {
    use super::{KvStore, WriteOp};

    /// A shared **conformance suite** every [`KvStore`] must satisfy identically. Running the
    /// same assertions against multiple backends is what keeps them from drifting (B7): a
    /// caching or storage layer that got `list_prefix`, overwrite, delete-of-missing, empty
    /// values, or the value-based `compare_and_swap` subtly wrong fails here rather than in
    /// production. Every in-process backend (SlateDB, `SqlKv`, …) runs it.
    pub async fn kv_conformance(store: &dyn KvStore) {
        // Missing key → None; delete of a missing key is a no-op (idempotent).
        assert_eq!(store.get("missing").await.unwrap(), None);
        store.delete("missing").await.unwrap();

        // Put/get round-trip, including an EMPTY value (distinct from absent) and binary bytes.
        store.put("k/1", b"one".to_vec()).await.unwrap();
        store.put("k/empty", Vec::new()).await.unwrap();
        store.put("k/bin", vec![0u8, 159, 146, 150]).await.unwrap();
        assert_eq!(store.get("k/1").await.unwrap(), Some(b"one".to_vec()));
        assert_eq!(store.get("k/empty").await.unwrap(), Some(Vec::new()));
        assert_eq!(
            store.get("k/bin").await.unwrap(),
            Some(vec![0, 159, 146, 150])
        );

        // Overwrite replaces the value.
        store.put("k/1", b"ONE".to_vec()).await.unwrap();
        assert_eq!(store.get("k/1").await.unwrap(), Some(b"ONE".to_vec()));

        // list_prefix returns exactly the matching keys (not others), regardless of order.
        store.put("other/x", b"x".to_vec()).await.unwrap();
        let mut got = store.list_prefix("k/").await.unwrap();
        got.sort();
        assert_eq!(got, vec!["k/1", "k/bin", "k/empty"]);
        assert_eq!(
            store.list_prefix("nope/").await.unwrap(),
            Vec::<String>::new()
        );

        // list_from is a bounded, resumable range scan: only keys strictly after
        // the cursor, in order, capped at `limit` — the messaging fan-out claim
        // relies on this being identical across backends.
        assert_eq!(
            store.list_from("k/", "", 10).await.unwrap(),
            vec!["k/1", "k/bin", "k/empty"],
            "empty cursor starts at the beginning, in key order"
        );
        assert_eq!(
            store.list_from("k/", "", 2).await.unwrap(),
            vec!["k/1", "k/bin"],
            "limit caps the batch"
        );
        assert_eq!(
            store.list_from("k/", "bin", 10).await.unwrap(),
            vec!["k/empty"],
            "resumes strictly after the cursor"
        );
        assert_eq!(
            store.list_from("k/", "empty", 10).await.unwrap(),
            Vec::<String>::new(),
            "past the last key → empty"
        );
        assert_eq!(
            store.list_from("k/", "1", 10).await.unwrap(),
            vec!["k/bin", "k/empty"],
            "the cursor itself is excluded, and other prefixes never leak in"
        );

        // Delete removes just that key; the prefix set shrinks accordingly.
        store.delete("k/1").await.unwrap();
        assert_eq!(store.get("k/1").await.unwrap(), None);
        let mut after = store.list_prefix("k/").await.unwrap();
        after.sort();
        assert_eq!(after, vec!["k/bin", "k/empty"]);

        // write_batch applies puts + deletes together.
        store
            .write_batch(vec![
                WriteOp::Put("k/2".into(), b"two".to_vec()),
                WriteOp::Delete("k/empty".into()),
            ])
            .await
            .unwrap();
        assert_eq!(store.get("k/2").await.unwrap(), Some(b"two".to_vec()));
        assert_eq!(store.get("k/empty").await.unwrap(), None);

        // compare_and_swap (B10) — the same semantics on every backend, atomic or best-effort.
        // Create-if-absent: expected=None swaps only when the key is missing.
        assert!(
            store
                .compare_and_swap("cas/k", None, b"v1".to_vec())
                .await
                .unwrap(),
            "expected-absent CAS on a missing key swaps"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v1".to_vec()));
        assert!(
            !store
                .compare_and_swap("cas/k", None, b"v2".to_vec())
                .await
                .unwrap(),
            "expected-absent CAS on a present key does NOT swap"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v1".to_vec()));
        // Match on the exact prior bytes swaps; a stale expected does not.
        assert!(
            !store
                .compare_and_swap("cas/k", Some(b"WRONG"), b"v3".to_vec())
                .await
                .unwrap(),
            "CAS with a non-matching expected leaves the value"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v1".to_vec()));
        assert!(
            store
                .compare_and_swap("cas/k", Some(b"v1"), b"v4".to_vec())
                .await
                .unwrap(),
            "CAS with the matching expected swaps"
        );
        assert_eq!(store.get("cas/k").await.unwrap(), Some(b"v4".to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cached_kv_round_trips_and_caches() {
        let backing = Arc::new(MemoryKv::new());
        let kv = CachedKv::new(backing.clone(), 8);

        assert_eq!(kv.get("a").await.unwrap(), None);
        kv.put("a", b"1".to_vec()).await.unwrap();
        assert_eq!(kv.get("a").await.unwrap(), Some(b"1".to_vec()));

        // A direct change to the backing store is masked by the cache.
        backing.put("a", b"2".to_vec()).await.unwrap();
        assert_eq!(kv.get("a").await.unwrap(), Some(b"1".to_vec()));

        kv.delete("a").await.unwrap();
        assert_eq!(kv.get("a").await.unwrap(), None);
    }

    #[tokio::test]
    async fn invalidate_cache_drops_stale_entries() {
        let backing = Arc::new(MemoryKv::new());
        backing.put("k", b"v1".to_vec()).await.unwrap();
        let kv = CachedKv::new(backing.clone(), 8);
        assert_eq!(kv.get("k").await.unwrap(), Some(b"v1".to_vec())); // caches v1

        // Another writer (e.g. a cluster peer via the shared store) updates it.
        backing.put("k", b"v2".to_vec()).await.unwrap();
        assert_eq!(
            kv.get("k").await.unwrap(),
            Some(b"v1".to_vec()),
            "still cached"
        );

        // SIGHUP-style invalidation → the next read pulls the fresh value.
        kv.invalidate_cache();
        assert_eq!(kv.get("k").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn write_batch_applies_puts_and_deletes() {
        let backing = Arc::new(MemoryKv::new());
        backing.put("old", b"gone".to_vec()).await.unwrap();
        let kv = CachedKv::new(backing.clone(), 8);
        // Warm the cache so we can confirm the batch updates it.
        assert_eq!(kv.get("old").await.unwrap(), Some(b"gone".to_vec()));

        kv.write_batch(vec![
            WriteOp::Put("a".into(), b"1".to_vec()),
            WriteOp::Put("b".into(), b"2".to_vec()),
            WriteOp::Delete("old".into()),
        ])
        .await
        .unwrap();

        assert_eq!(kv.get("a").await.unwrap(), Some(b"1".to_vec()));
        assert_eq!(kv.get("b").await.unwrap(), Some(b"2".to_vec()));
        assert_eq!(kv.get("old").await.unwrap(), None);
        // The backing store reflects the same writes.
        assert_eq!(backing.get("a").await.unwrap(), Some(b"1".to_vec()));
        assert_eq!(backing.get("old").await.unwrap(), None);
    }

    /// The atomic-CAS race property (B10): with a linearizable `compare_and_swap`, exactly one of
    /// many racing swappers of the same key from the same observed value wins — the primitive the
    /// async-lane shard claim is built on. A local test helper (it needs a real multi-task runtime,
    /// and `tokio` is only a dev-dependency here), mirrored by each backend's own suite — e.g.
    /// `boatramp-storage`'s `SqlKv` runs the same property over a real SQLite store.
    async fn cas_race_has_exactly_one_winner(store: Arc<dyn KvStore>) {
        if !store.supports_cas() {
            return;
        }
        store.put("race/k", b"start".to_vec()).await.unwrap();
        // 32 tasks all try to swap start→<their id>; a linearizable CAS admits exactly one.
        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let store = store.clone();
            set.spawn(async move {
                store
                    .compare_and_swap("race/k", Some(b"start"), i.to_le_bytes().to_vec())
                    .await
                    .unwrap()
            });
        }
        let mut wins = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one racing CAS wins");
    }

    #[tokio::test]
    async fn memorykv_cas_race_has_exactly_one_winner() {
        cas_race_has_exactly_one_winner(Arc::new(MemoryKv::new())).await;
    }

    #[tokio::test]
    async fn cachedkv_cas_race_has_exactly_one_winner() {
        cas_race_has_exactly_one_winner(Arc::new(CachedKv::new(Arc::new(MemoryKv::new()), 16)))
            .await;
    }

    /// A test store that forwards to a `MemoryKv` and COUNTS `checkpoint()` calls — the probe for
    /// the [`CheckpointKv`] crown-jewel guarantee.
    #[derive(Default)]
    struct CountingCheckpoint {
        inner: MemoryKv,
        checkpoints: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl KvStore for CountingCheckpoint {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
            self.inner.put(key, value).await
        }
        async fn delete(&self, key: &str) -> Result<(), KvError> {
            self.inner.delete(key).await
        }
        async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
            self.inner.list_prefix(prefix).await
        }
        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<&[u8]>,
            new: Vec<u8>,
        ) -> Result<bool, KvError> {
            self.inner.compare_and_swap(key, expected, new).await
        }
        async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
            self.inner.write_batch(ops).await
        }
        fn supports_cas(&self) -> bool {
            true
        }
        async fn checkpoint(&self) -> Result<(), KvError> {
            self.checkpoints
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// GATE (C2) — every successful write through a [`CheckpointKv`] advances the frontier exactly
    /// once, and a LOST compare-and-swap does NOT (it mutated nothing, so there is nothing to
    /// checkpoint). This is the can't-miss frontier-sync the sealed-secret stores rely on.
    #[tokio::test]
    async fn checkpoint_kv_syncs_the_frontier_on_every_write() {
        let checkpoints = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inner = Arc::new(CountingCheckpoint {
            inner: MemoryKv::new(),
            checkpoints: checkpoints.clone(),
        });
        let kv = CheckpointKv::new(inner);
        let count = || checkpoints.load(std::sync::atomic::Ordering::SeqCst);

        kv.put("secret/acme/idp", b"sealed".to_vec()).await.unwrap();
        assert_eq!(count(), 1, "a put checkpoints once");
        kv.write_batch(vec![WriteOp::Put(
            "secret/acme/db".into(),
            b"sealed2".to_vec(),
        )])
        .await
        .unwrap();
        assert_eq!(count(), 2, "a write_batch checkpoints once");
        kv.delete("secret/acme/idp").await.unwrap();
        assert_eq!(count(), 3, "a delete checkpoints once");
        // A WINNING CAS checkpoints; a LOSING CAS does not (it wrote nothing).
        assert!(
            kv.compare_and_swap("cas/k", None, b"v1".to_vec())
                .await
                .unwrap()
        );
        assert_eq!(count(), 4, "a winning CAS checkpoints");
        assert!(
            !kv.compare_and_swap("cas/k", None, b"v2".to_vec())
                .await
                .unwrap()
        );
        assert_eq!(
            count(),
            4,
            "a lost CAS must NOT checkpoint (nothing was written)"
        );
        // Reads never checkpoint.
        let _ = kv.get("secret/acme/db").await.unwrap();
        assert_eq!(count(), 4, "a read never checkpoints");
    }

    /// The wrapper is otherwise semantically identical to its backing store on every op.
    #[tokio::test]
    async fn checkpoint_kv_satisfies_the_conformance_suite() {
        let kv = CheckpointKv::new(Arc::new(MemoryKv::new()));
        conformance::kv_conformance(&kv).await;
    }

    #[tokio::test]
    async fn memorykv_satisfies_the_conformance_suite() {
        conformance::kv_conformance(&MemoryKv::new()).await;
    }

    #[tokio::test]
    async fn cachedkv_satisfies_the_conformance_suite() {
        // The caching layer must be semantically identical to its backing store on every op.
        let kv = CachedKv::new(Arc::new(MemoryKv::new()), 16);
        conformance::kv_conformance(&kv).await;
    }
}
