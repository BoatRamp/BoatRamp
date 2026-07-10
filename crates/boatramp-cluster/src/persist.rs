//! **Durable** Raft log + state-machine stores over a [`KvStore`].
//!
//! The in-memory [`LogStore`](crate::raft::LogStore) /
//! [`StateMachineStore`](crate::raft::StateMachineStore) survive *partial*
//! cluster restarts (a returning node catches up from the leader's snapshot +
//! log). For **full-cluster-restart** durability every node must persist its own
//! Raft log, vote, and applied state to disk. These stores do that over any
//! durable [`KvStore`] (e.g. `boatramp-storage`'s SlateDB backend) — node-local
//! state, distinct from the *replicated* control-plane `KvStore` that
//! [`RaftKv`](crate::raft::RaftKv) fronts.
//!
//! Consensus carries only small metadata, so a `KvStore`
//! (one serialized record per log entry / state key) is an ample substrate; the
//! state machine keeps an in-memory cache for the fast serving-path reads and
//! write-throughs every apply for durability.
//!
//! Validated against openraft's own storage conformance suite
//! (`openraft::testing::Suite`) plus an in-process full-restart test.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use boatramp_core::kv::{KvStore, WriteOp as KvWriteOp};
use openraft::storage::{
    LogFlushed, LogState, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine,
};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, RaftLogReader, Snapshot, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::raft::{apply_op, ApplyTarget, NodeId, TypeConfig, WriteResponse};

// ---- key layout (node-local durable store) ---------------------------------

const KEY_VOTE: &str = "raft/vote";
const KEY_COMMITTED: &str = "raft/committed";
const KEY_PURGED: &str = "raft/purged";
const LOG_PREFIX: &str = "raft/log/";
const KEY_SM_LAST: &str = "raft/sm/last_applied";
const KEY_SM_MEMBERSHIP: &str = "raft/sm/membership";
const SM_DATA_PREFIX: &str = "raft/sm/d/";
const KEY_SNAPSHOT: &str = "raft/snapshot";

/// Log entry key — zero-padded so lexical key order equals numeric index order.
fn log_key(index: u64) -> String {
    format!("{LOG_PREFIX}{index:020}")
}

/// Parse the index out of a `raft/log/{index}` key.
fn log_index(key: &str) -> Option<u64> {
    key.strip_prefix(LOG_PREFIX)?.parse().ok()
}

/// Durable state-machine key for a raw applied-state key.
fn sm_data_key(raw: &str) -> String {
    format!("{SM_DATA_PREFIX}{raw}")
}

// ---- error mapping ---------------------------------------------------------

fn e_read_logs<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::from(StorageIOError::read_logs(&e))
}
fn e_write_logs<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::from(StorageIOError::write_logs(&e))
}
fn e_read_vote<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::from(StorageIOError::read_vote(&e))
}
fn e_write_vote<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::from(StorageIOError::write_vote(&e))
}
fn e_read_sm<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::from(StorageIOError::read_state_machine(&e))
}
fn e_write_sm<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::from(StorageIOError::write_state_machine(&e))
}

// ---- persistent log store --------------------------------------------------

/// A durable Raft log store over a [`KvStore`]: each entry is one serialized
/// record under `raft/log/{index}`, with the vote / committed / purged markers
/// as fixed keys.
#[derive(Clone)]
pub struct PersistentLogStore {
    kv: Arc<dyn KvStore>,
}

impl PersistentLogStore {
    /// Open a log store over the node-local durable `kv`.
    pub fn new(kv: Arc<dyn KvStore>) -> Self {
        Self { kv }
    }

    /// All stored log entries, ascending by index.
    async fn all_entries(&self) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let mut keys = self.kv.list_prefix(LOG_PREFIX).await.map_err(e_read_logs)?;
        keys.sort();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(raw) = self.kv.get(&key).await.map_err(e_read_logs)? {
                out.push(serde_json::from_slice(&raw).map_err(e_read_logs)?);
            }
        }
        Ok(out)
    }
}

impl RaftLogReader<TypeConfig> for PersistentLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        Ok(self
            .all_entries()
            .await?
            .into_iter()
            .filter(|e| range.contains(&e.log_id.index))
            .collect())
    }
}

impl RaftLogStorage<TypeConfig> for PersistentLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged: Option<LogId<NodeId>> =
            match self.kv.get(KEY_PURGED).await.map_err(e_read_logs)? {
                Some(raw) => Some(serde_json::from_slice(&raw).map_err(e_read_logs)?),
                None => None,
            };
        let last = self
            .all_entries()
            .await?
            .last()
            .map(|e| e.log_id)
            .or(last_purged);
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let bytes = serde_json::to_vec(vote).map_err(e_write_vote)?;
        self.kv.put(KEY_VOTE, bytes).await.map_err(e_write_vote)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        match self.kv.get(KEY_VOTE).await.map_err(e_read_vote)? {
            Some(raw) => Ok(Some(serde_json::from_slice(&raw).map_err(e_read_vote)?)),
            None => Ok(None),
        }
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = serde_json::to_vec(&committed).map_err(e_write_logs)?;
        self.kv
            .put(KEY_COMMITTED, bytes)
            .await
            .map_err(e_write_logs)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        match self.kv.get(KEY_COMMITTED).await.map_err(e_read_logs)? {
            Some(raw) => Ok(serde_json::from_slice(&raw).map_err(e_read_logs)?),
            None => Ok(None),
        }
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        let mut batch = Vec::new();
        for entry in entries {
            let bytes = serde_json::to_vec(&entry).map_err(e_write_logs)?;
            batch.push(KvWriteOp::Put(log_key(entry.log_id.index), bytes));
        }
        self.kv.write_batch(batch).await.map_err(e_write_logs)?;
        // The KvStore write is durable on return, so the flush is complete.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Delete the conflicting suffix [log_id.index, ∞).
        let keys = self
            .kv
            .list_prefix(LOG_PREFIX)
            .await
            .map_err(e_write_logs)?;
        let batch: Vec<KvWriteOp> = keys
            .into_iter()
            .filter(|k| log_index(k).is_some_and(|i| i >= log_id.index))
            .map(KvWriteOp::Delete)
            .collect();
        self.kv.write_batch(batch).await.map_err(e_write_logs)
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Record the purge point, then delete the purged prefix (-∞, log_id.index].
        let marker = serde_json::to_vec(&log_id).map_err(e_write_logs)?;
        self.kv
            .put(KEY_PURGED, marker)
            .await
            .map_err(e_write_logs)?;
        let keys = self
            .kv
            .list_prefix(LOG_PREFIX)
            .await
            .map_err(e_write_logs)?;
        let batch: Vec<KvWriteOp> = keys
            .into_iter()
            .filter(|k| log_index(k).is_some_and(|i| i <= log_id.index))
            .map(KvWriteOp::Delete)
            .collect();
        self.kv.write_batch(batch).await.map_err(e_write_logs)
    }
}

// ---- persistent state machine ----------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct SnapshotPayload {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    data: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

#[derive(Default)]
struct SmInner {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    /// In-memory cache of the applied control-plane state (the fast read path);
    /// write-through to the `KvStore` keeps it durable.
    data: BTreeMap<String, Vec<u8>>,
    snapshot_idx: u64,
}

/// A durable Raft state machine over a [`KvStore`]: applies committed `WriteOp`s
/// into an in-memory map for fast reads **and** write-throughs every mutation to
/// the store, so the applied state survives a restart.
#[derive(Clone)]
pub struct PersistentStateMachine {
    kv: Arc<dyn KvStore>,
    inner: Arc<Mutex<SmInner>>,
    /// Post-apply hooks: each is fed the raw mutations of every committed batch so
    /// a subsystem can mirror applied keys into its own view (the mesh trust set
    /// tracks `mesh/trust/*`; the daemon-config runtime reloads on `daemon/*`).
    /// See [`crate::raft::ApplyObserver`].
    observers: Vec<Arc<dyn crate::raft::ApplyObserver>>,
}

impl PersistentStateMachine {
    /// Open a state machine over `kv`, loading any previously-applied state.
    pub async fn new(kv: Arc<dyn KvStore>) -> Result<Self, StorageError<NodeId>> {
        let mut inner = SmInner::default();
        if let Some(raw) = kv.get(KEY_SM_LAST).await.map_err(e_read_sm)? {
            inner.last_applied = serde_json::from_slice(&raw).map_err(e_read_sm)?;
        }
        if let Some(raw) = kv.get(KEY_SM_MEMBERSHIP).await.map_err(e_read_sm)? {
            inner.last_membership = serde_json::from_slice(&raw).map_err(e_read_sm)?;
        }
        for key in kv.list_prefix(SM_DATA_PREFIX).await.map_err(e_read_sm)? {
            if let Some(raw) = kv.get(&key).await.map_err(e_read_sm)? {
                inner
                    .data
                    .insert(key[SM_DATA_PREFIX.len()..].to_string(), raw);
            }
        }
        Ok(Self {
            kv,
            inner: Arc::new(Mutex::new(inner)),
            observers: Vec::new(),
        })
    }

    /// Attach a post-apply [`ApplyObserver`](crate::raft::ApplyObserver) (set
    /// before the state machine is handed to Raft, so no apply is missed).
    /// Repeatable — every registered observer sees each apply/reset.
    pub fn with_observer(mut self, observer: Arc<dyn crate::raft::ApplyObserver>) -> Self {
        self.observers.push(observer);
        self
    }

    /// Read an applied key from the local cache (the serving-path read).
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.lock().await.data.get(key).cloned()
    }

    /// Keys with `prefix` in the local applied state (the serving-path scan).
    pub async fn list_prefix(&self, prefix: &str) -> Vec<String> {
        self.inner
            .lock()
            .await
            .data
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, _)| k.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl crate::raft::AppliedState for PersistentStateMachine {
    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        PersistentStateMachine::get(self, key).await
    }
    async fn list_prefix(&self, prefix: &str) -> Vec<String> {
        PersistentStateMachine::list_prefix(self, prefix).await
    }
}

impl RaftSnapshotBuilder<TypeConfig> for PersistentStateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let (data, meta) = {
            let mut inner = self.inner.lock().await;
            inner.snapshot_idx += 1;
            let last_log_id = inner.last_applied;
            let snapshot_id = format!(
                "{}-{}",
                last_log_id.map(|l| l.index).unwrap_or(0),
                inner.snapshot_idx
            );
            let payload = SnapshotPayload {
                last_applied: inner.last_applied,
                last_membership: inner.last_membership.clone(),
                data: inner.data.clone(),
            };
            let meta = SnapshotMeta {
                last_log_id,
                last_membership: inner.last_membership.clone(),
                snapshot_id,
            };
            let data = serde_json::to_vec(&payload).map_err(|e| {
                StorageError::from(StorageIOError::write_snapshot(Some(meta.signature()), &e))
            })?;
            (data, meta)
        };
        // Persist the snapshot so it survives a restart.
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|e| {
            StorageError::from(StorageIOError::write_snapshot(Some(meta.signature()), &e))
        })?;
        self.kv.put(KEY_SNAPSHOT, bytes).await.map_err(|e| {
            StorageError::from(StorageIOError::write_snapshot(Some(meta.signature()), &e))
        })?;
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for PersistentStateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let inner = self.inner.lock().await;
        Ok((inner.last_applied, inner.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<WriteResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        let mut inner = self.inner.lock().await;
        let mut responses = Vec::new();
        // Accumulate every mutation across the batch, then commit once.
        let mut batch: Vec<KvWriteOp> = Vec::new();
        // The raw-key mutations (pre-translation) handed to the apply observer.
        let mut raw_muts: Vec<KvWriteOp> = Vec::new();
        let mut membership_changed = false;
        for entry in entries {
            inner.last_applied = Some(entry.log_id);
            let response = match entry.payload {
                EntryPayload::Blank => WriteResponse::Kv,
                EntryPayload::Normal(op) => {
                    let mut target = ApplyTarget::new(&mut inner.data);
                    let response = apply_op(&mut target, op);
                    // Translate the raw-key mutations to durable state-machine
                    // keys, keeping the raw keys for the observer.
                    for m in target.muts {
                        batch.push(match &m {
                            KvWriteOp::Put(k, v) => KvWriteOp::Put(sm_data_key(k), v.clone()),
                            KvWriteOp::Delete(k) => KvWriteOp::Delete(sm_data_key(k)),
                        });
                        raw_muts.push(m);
                    }
                    response
                }
                EntryPayload::Membership(membership) => {
                    inner.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                    membership_changed = true;
                    WriteResponse::Kv
                }
            };
            responses.push(response);
        }
        // Persist the applied cursor (+ membership if it moved) atomically with
        // the data mutations.
        batch.push(KvWriteOp::Put(
            KEY_SM_LAST.to_string(),
            serde_json::to_vec(&inner.last_applied).map_err(e_write_sm)?,
        ));
        if membership_changed {
            batch.push(KvWriteOp::Put(
                KEY_SM_MEMBERSHIP.to_string(),
                serde_json::to_vec(&inner.last_membership).map_err(e_write_sm)?,
            ));
        }
        self.kv.write_batch(batch).await.map_err(e_write_sm)?;
        // The state is durable; now let each observer mirror the applied mutations
        // into its live view (mesh trust set; a daemon-config reload; …).
        if !raw_muts.is_empty() {
            for observer in &self.observers {
                observer.on_apply(&raw_muts);
            }
        }
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = snapshot.into_inner();
        let payload: SnapshotPayload = serde_json::from_slice(&bytes).map_err(|e| {
            StorageError::from(StorageIOError::read_snapshot(Some(meta.signature()), &e))
        })?;

        // Replace the durable applied state wholesale: clear the old data keys,
        // write the snapshot's, and update the cursor/membership/snapshot blob.
        let mut batch: Vec<KvWriteOp> = Vec::new();
        for key in self
            .kv
            .list_prefix(SM_DATA_PREFIX)
            .await
            .map_err(e_write_sm)?
        {
            batch.push(KvWriteOp::Delete(key));
        }
        for (k, v) in &payload.data {
            batch.push(KvWriteOp::Put(sm_data_key(k), v.clone()));
        }
        batch.push(KvWriteOp::Put(
            KEY_SM_LAST.to_string(),
            serde_json::to_vec(&payload.last_applied).map_err(e_write_sm)?,
        ));
        batch.push(KvWriteOp::Put(
            KEY_SM_MEMBERSHIP.to_string(),
            serde_json::to_vec(&payload.last_membership).map_err(e_write_sm)?,
        ));
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: bytes,
        };
        batch.push(KvWriteOp::Put(
            KEY_SNAPSHOT.to_string(),
            serde_json::to_vec(&stored).map_err(e_write_sm)?,
        ));
        self.kv.write_batch(batch).await.map_err(e_write_sm)?;

        let mut inner = self.inner.lock().await;
        inner.last_applied = payload.last_applied;
        inner.last_membership = payload.last_membership;
        inner.data = payload.data;
        // A snapshot replaces local state wholesale — let each observer reconcile
        // against the new applied key set (trust set; daemon-config reload; …).
        if !self.observers.is_empty() {
            let keys: Vec<String> = inner.data.keys().cloned().collect();
            for observer in &self.observers {
                observer.on_reset(&keys);
            }
        }
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        match self.kv.get(KEY_SNAPSHOT).await.map_err(e_read_sm)? {
            Some(raw) => {
                let stored: StoredSnapshot = serde_json::from_slice(&raw).map_err(e_read_sm)?;
                Ok(Some(Snapshot {
                    meta: stored.meta,
                    snapshot: Box::new(Cursor::new(stored.data)),
                }))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;
    use openraft::testing::StoreBuilder;
    use openraft::StorageError;

    /// Builds fresh persistent stores over an in-memory `KvStore` for the
    /// openraft conformance suite. (Real on-disk durability is the `KvStore`
    /// backend's concern — covered by `boatramp-storage`'s SlateDB tests; here
    /// we validate the store *logic* against openraft's contract.)
    struct MemBuilder;

    impl StoreBuilder<TypeConfig, PersistentLogStore, PersistentStateMachine> for MemBuilder {
        async fn build(
            &self,
        ) -> Result<((), PersistentLogStore, PersistentStateMachine), StorageError<NodeId>>
        {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let log = PersistentLogStore::new(kv.clone());
            let sm = PersistentStateMachine::new(kv).await?;
            Ok(((), log, sm))
        }
    }

    /// The full openraft storage conformance suite against our persistent stores.
    // The `Result<_, StorageError>` shape is dictated by `Suite::test_all`.
    #[serial_test::serial]
    #[allow(clippy::result_large_err)]
    #[test]
    fn passes_openraft_storage_suite() -> Result<(), StorageError<NodeId>> {
        openraft::testing::Suite::test_all(MemBuilder)
    }

    // ---- full-cluster-restart durability -----------------------------------

    use crate::raft::{NetworkFactory, Registry, WriteOp};
    use openraft::{BasicNode, Config, Raft};
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn test_config() -> Arc<Config> {
        Arc::new(
            Config {
                heartbeat_interval: 100,
                election_timeout_min: 200,
                election_timeout_max: 400,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        )
    }

    /// Spin up `n` Raft nodes whose log + state machine persist to the supplied
    /// per-node durable `kvs` (one each), over a fresh in-process [`Registry`].
    async fn spawn(
        kvs: &[Arc<dyn KvStore>],
    ) -> (
        Registry,
        BTreeMap<NodeId, Raft<TypeConfig>>,
        BTreeMap<NodeId, PersistentStateMachine>,
    ) {
        let registry = Registry::default();
        let config = test_config();
        let mut rafts = BTreeMap::new();
        let mut sms = BTreeMap::new();
        for (i, kv) in kvs.iter().enumerate() {
            let id = i as u64 + 1;
            let log = PersistentLogStore::new(kv.clone());
            let sm = PersistentStateMachine::new(kv.clone()).await.unwrap();
            let raft = Raft::new(
                id,
                config.clone(),
                NetworkFactory::new(registry.clone()),
                log,
                sm.clone(),
            )
            .await
            .unwrap();
            registry.register(id, raft.clone());
            rafts.insert(id, raft);
            sms.insert(id, sm);
        }
        (registry, rafts, sms)
    }

    /// A full-cluster restart: every node's log + applied state persists, so
    /// after **all** nodes shut down and come back over the *same* durable
    /// stores, the cluster recovers its membership from disk (no re-initialize),
    /// re-elects a leader, retains the pre-restart write, and keeps committing.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_survives_full_restart() {
        // Per-node durable stores that persist across the restart (Arc clone).
        let kvs: Vec<Arc<dyn KvStore>> = (0..3)
            .map(|_| Arc::new(MemoryKv::new()) as Arc<dyn KvStore>)
            .collect();

        // --- first lifetime: bootstrap, commit a write, shut all nodes down ---
        {
            let (_registry, rafts, _sms) = spawn(&kvs).await;
            let members: BTreeMap<NodeId, BasicNode> =
                (1..=3u64).map(|id| (id, BasicNode::default())).collect();
            rafts[&1].initialize(members).await.unwrap();
            rafts[&1]
                .wait(Some(Duration::from_secs(10)))
                .metrics(|m| m.current_leader.is_some(), "leader elected")
                .await
                .unwrap();
            let leader = rafts[&1].metrics().borrow().current_leader.unwrap();
            rafts[&leader]
                .client_write(WriteOp::Put {
                    key: "current/blog".into(),
                    value: b"v1".to_vec(),
                })
                .await
                .unwrap();
            for id in 1..=3u64 {
                rafts[&id]
                    .wait(Some(Duration::from_secs(10)))
                    .applied_index_at_least(Some(2), "write applied before restart")
                    .await
                    .unwrap();
            }
            for raft in rafts.into_values() {
                raft.shutdown().await.unwrap();
            }
        }

        // --- second lifetime: rebuild over the SAME stores, no initialize ---
        let (_registry, rafts, sms) = spawn(&kvs).await;

        // The pre-restart write is present on every node from persisted state,
        // even before a new election completes.
        for id in 1..=3u64 {
            assert_eq!(
                sms[&id].get("current/blog").await.as_deref(),
                Some(b"v1".as_slice()),
                "node {id} lost durable applied state across restart"
            );
        }

        // The cluster recovers membership from disk and re-elects.
        rafts[&1]
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |m| m.current_leader.is_some(),
                "leader re-elected from persisted state",
            )
            .await
            .unwrap();
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();

        // And it keeps committing post-restart.
        rafts[&leader]
            .client_write(WriteOp::Put {
                key: "current/shop".into(),
                value: b"v2".to_vec(),
            })
            .await
            .unwrap();
        let target = rafts[&leader].metrics().borrow().last_log_index;
        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(10)))
                .applied_index_at_least(target, "post-restart write applied")
                .await
                .unwrap();
            assert_eq!(
                sms[&id].get("current/shop").await.as_deref(),
                Some(b"v2".as_slice())
            );
        }

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }
}
