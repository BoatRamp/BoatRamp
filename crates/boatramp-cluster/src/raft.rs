//! Embedded-Raft metadata coordination.
//!
//! Cluster mode fronts boatramp's control-plane `KvStore` with a Raft state
//! machine: control-plane writes (activate, alias, config, token, cert) become
//! Raft proposals, and the commit is the cluster-wide linearization point.
//! Reads are served from each node's locally-applied state (content addressing
//! makes a slightly-stale-but-consistent manifest benign).
//!
//! This module is the consensus core: the [openraft](https://docs.rs/openraft)
//! type config, an in-memory log store, a `KvStore`-shaped state machine
//! (applied state is a byte map, snapshot = its serialization), and an
//! in-process registry network used by the multi-node test. A real HTTP
//! transport + a `KvStore` facade over the applied state are follow-up slices.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use boatramp_core::messaging;
use openraft::error::{
    ClientWriteError, InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError,
};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{
    LogFlushed, LogState, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine,
};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, RaftLogReader, Snapshot, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Cluster node id.
pub type NodeId = u64;

/// Derive a node's stable Raft id from its **mesh public key** — the dynamic-join
/// model's self-identification: a node's identity *is* its keypair, and its id is
/// just a label for it, so no id is ever assigned by config or an operator.
///
/// The id is the first 8 bytes (big-endian) of `SHA-256(mesh_pubkey)`, forced
/// non-zero (0 is reserved as "unset" in some tooling). Two distinct keys collide
/// only with ~2⁻⁶⁴ probability; and since the *key* — not the id — is the authority
/// on the mesh, a collision cannot let one node impersonate another (it would only
/// confuse membership bookkeeping, and is astronomically unlikely regardless).
pub fn derive_node_id(mesh_pubkey: &[u8]) -> NodeId {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(mesh_pubkey);
    let id = u64::from_be_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"));
    id | 1 // never 0 (reserved), at the cost of the lowest bit of spread
}

#[cfg(test)]
mod node_id_tests {
    use super::derive_node_id;

    #[test]
    fn derivation_is_deterministic_key_specific_and_nonzero() {
        let key_a = b"mesh-public-key-a-spki-bytes";
        let key_b = b"mesh-public-key-b-spki-bytes";
        // Deterministic: same key → same id.
        assert_eq!(derive_node_id(key_a), derive_node_id(key_a));
        // Key-specific: different keys → different ids.
        assert_ne!(derive_node_id(key_a), derive_node_id(key_b));
        // Never zero (reserved).
        assert_ne!(derive_node_id(key_a), 0);
        assert_ne!(derive_node_id(b""), 0);
    }

    #[test]
    fn ids_spread_across_many_keys() {
        // A sanity spread check: 1000 distinct keys yield 1000 distinct ids.
        let ids: std::collections::HashSet<u64> = (0..1000u32)
            .map(|i| derive_node_id(format!("key-{i}").as_bytes()))
            .collect();
        assert_eq!(ids.len(), 1000);
    }
}

openraft::declare_raft_types!(
    /// The boatramp Raft type configuration: control-plane KV writes as the
    /// request, `u64` node ids, `BasicNode` addressing.
    pub TypeConfig:
        D = WriteOp,
        R = WriteResponse,
);

/// A replicated mutation. `Batch` applies its members atomically (one Raft
/// entry), so a multi-key control-plane write (e.g. set-config + rebuild the
/// host index) commits all-or-nothing.
///
/// The `Mq*` variants make the **messaging coordinator** the Raft leader:
/// the only operation that needs atomicity — `claim` —
/// is a single Raft proposal applied deterministically in the state machine, so
/// a message is never leased to two consumers cluster-wide. Payloads never enter
/// the log (they live in shared `Storage`); only the tiny index record is
/// replicated, keeping consensus volume small.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WriteOp {
    Put {
        key: String,
        value: Vec<u8>,
    },
    Delete {
        key: String,
    },
    Batch(Vec<WriteOp>),
    /// Append a message's index record (`attempts=0`, claimable now). The
    /// payload was already written to shared `Storage` by the publisher.
    MqPublish {
        topic: String,
        id: String,
    },
    /// Atomically claim up to `max_batch` deliverable messages on `topic`,
    /// leasing each until `now_ms + lease_ms` and dead-lettering exhausted ones.
    /// `now_ms` is stamped by the issuing node so every replica applies the same
    /// transition (determinism — the state machine never reads a clock).
    MqClaim {
        topic: String,
        now_ms: u64,
        lease_ms: u64,
        max_batch: u32,
        max_attempts: u32,
    },
    /// Remove a message's index record (ack — processed for good).
    MqAck {
        topic: String,
        id: String,
    },
    /// Reset a message's lease so it is immediately claimable again (nack).
    MqNack {
        topic: String,
        id: String,
    },
    /// Admit a joining node from a verified single-use join token. Applied
    /// deterministically: a **no-op if `jti` was already spent**
    /// (replay/anti-double-admit), else it atomically records the spent handle
    /// and trusts `(node, pubkey_hex)` in one entry. The caller verifies the
    /// token + pubkey ownership *before* proposing this; the state machine
    /// guarantees single-use. Membership (`add_learner`) follows on the leader.
    MeshAdmit {
        /// The join token's single-use handle (its authority revocation id).
        jti: String,
        /// The node id being admitted.
        node: NodeId,
        /// The admitted node's mesh public key (SPKI hex).
        pubkey_hex: String,
        /// The joiner's advertised mesh URL, replicated so **every** node (and a
        /// restart) learns where to dial it — advisory routing (the mesh TLS
        /// re-authenticates by key). `None` ⇒ address unknown.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        addr: Option<String>,
    },
}

/// The replicated-KV prefix for the mesh trust set: one entry per accepted key,
/// `mesh/trust/{node_id}/{pubkey_hex}` with an empty value. Defined here — the
/// apply layer that *writes* it (via [`WriteOp::MeshAdmit`] and plain trust
/// `Put`s) — and read back by the mesh transport (`mesh::parse_trust_key`).
pub const TRUST_PREFIX: &str = "mesh/trust/";

/// The trust-set key trusting `pubkey_hex` (SPKI hex) for `node`.
pub fn trust_key_hex(node: NodeId, pubkey_hex: &str) -> String {
    format!("{TRUST_PREFIX}{node}/{pubkey_hex}")
}

/// The replicated-KV prefix recording spent join-token handles (`jti`), which
/// makes [`WriteOp::MeshAdmit`] single-use across the cluster.
const JOIN_USED_PREFIX: &str = "mesh/join/used/";

/// The replicated-KV prefix of **revocation tombstones**, keyed on the revoked
/// node's **full mesh pubkey** (F4: authority keys on the key, never the id).
/// A tombstone makes `revoke` durable + re-admit-proof (F6): once set, no fresh
/// join token can silently re-admit that key — an explicit un-revoke (tombstone
/// delete) is required. A `revoke` racing an `admit` therefore always ends
/// *revoked*, in either apply order.
pub const REVOKED_PREFIX: &str = "mesh/revoked/";

/// The revocation-tombstone key for `pubkey_hex` (SPKI hex).
pub fn revoked_key(pubkey_hex: &str) -> String {
    format!("{REVOKED_PREFIX}{pubkey_hex}")
}

/// The replicated-KV prefix of the **advisory peer address directory**:
/// `mesh/addr/{node_id}` → mesh URL. Written at admission and mirrored into every
/// node's live [`crate::http::Peers`] (and rehydrated on restart), so a
/// dynamically-joined node keeps its routing across reboots with no static peer
/// map. Advisory only — the mesh TLS authenticates each dial by key.
pub const ADDR_PREFIX: &str = "mesh/addr/";

/// The peer-address key for `node`.
pub fn addr_key(node: NodeId) -> String {
    format!("{ADDR_PREFIX}{node}")
}

/// Parse a `mesh/addr/{node}` key back to its node id (`None` if malformed).
pub fn parse_addr_key(key: &str) -> Option<NodeId> {
    key.strip_prefix(ADDR_PREFIX)?.parse().ok()
}

/// The applied-state byte map plus the **durable mutations** each apply makes,
/// recorded with *raw* keys. The in-memory state machine discards `muts`; the
/// persistent one ([`crate::persist`]) write-throughs them to its `KvStore`, so
/// the apply logic stays one source of truth across both.
pub(crate) struct ApplyTarget<'a> {
    pub(crate) data: &'a mut BTreeMap<String, Vec<u8>>,
    pub(crate) muts: Vec<boatramp_core::kv::WriteOp>,
}

impl<'a> ApplyTarget<'a> {
    /// A target over `data` that records no-op mutations (in-memory path) or
    /// real ones (persistent path) — start empty either way.
    pub(crate) fn new(data: &'a mut BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            data,
            muts: Vec::new(),
        }
    }

    fn put(&mut self, key: String, value: Vec<u8>) {
        self.muts
            .push(boatramp_core::kv::WriteOp::Put(key.clone(), value.clone()));
        self.data.insert(key, value);
    }
    fn remove(&mut self, key: String) {
        self.muts
            .push(boatramp_core::kv::WriteOp::Delete(key.clone()));
        self.data.remove(&key);
    }
}

/// Apply one [`WriteOp`] to the applied state (recursing for batches), returning
/// the operation's response (claim results carry data; the rest are `Kv`) and
/// recording the durable mutations into `target`.
pub(crate) fn apply_op(target: &mut ApplyTarget, op: WriteOp) -> WriteResponse {
    match op {
        WriteOp::Put { key, value } => {
            target.put(key, value);
            WriteResponse::Kv
        }
        WriteOp::Delete { key } => {
            target.remove(key);
            WriteResponse::Kv
        }
        WriteOp::Batch(ops) => {
            for op in ops {
                apply_op(target, op);
            }
            WriteResponse::Kv
        }
        WriteOp::MqPublish { topic, id } => {
            // Idempotent append: a distinct key per message, never overwriting
            // an existing (possibly already-claimed) record.
            let key = messaging::meta_key(&topic, &id);
            if !target.data.contains_key(&key) {
                let fresh =
                    serde_json::to_vec(&messaging::Record::fresh()).expect("record serializes");
                target.put(key, fresh);
            }
            WriteResponse::Kv
        }
        WriteOp::MqClaim {
            topic,
            now_ms,
            lease_ms,
            max_batch,
            max_attempts,
        } => WriteResponse::Claimed(apply_mq_claim(
            target,
            &topic,
            now_ms,
            lease_ms,
            max_batch as usize,
            max_attempts,
        )),
        WriteOp::MqAck { topic, id } => {
            target.remove(messaging::meta_key(&topic, &id));
            WriteResponse::Kv
        }
        WriteOp::MqNack { topic, id } => {
            let key = messaging::meta_key(&topic, &id);
            if let Some(raw) = target.data.get(&key) {
                if let Ok(mut record) = serde_json::from_slice::<messaging::Record>(raw) {
                    record.lease_until_ms = 0; // claimable again now
                    if let Ok(json) = serde_json::to_vec(&record) {
                        target.put(key, json);
                    }
                }
            }
            WriteResponse::Kv
        }
        WriteOp::MeshAdmit {
            jti,
            node,
            pubkey_hex,
            addr,
        } => {
            // Re-admit-proof (F6): a revoked key is refused until an explicit
            // un-revoke removes its tombstone — checked first, and the token is
            // NOT spent, so it stays redeemable once the key is un-revoked. A
            // `revoke` racing this `admit` ends *revoked* in either order (the
            // tombstone here, or `revoke`'s later trust-delete + tombstone).
            if target.data.contains_key(&revoked_key(&pubkey_hex)) {
                WriteResponse::Admitted(AdmitOutcome::Revoked)
            } else if target
                .data
                .contains_key(&format!("{JOIN_USED_PREFIX}{jti}"))
            {
                // Single-use: spending a `jti` is check-and-set inside one apply,
                // so a replayed token (even racing on the leader) never double-admits.
                WriteResponse::Admitted(AdmitOutcome::Spent)
            } else {
                target.put(format!("{JOIN_USED_PREFIX}{jti}"), Vec::new());
                target.put(trust_key_hex(node, &pubkey_hex), Vec::new());
                // Replicate the joiner's advisory address so every node + a restart
                // learns where to dial it (mirrored into the live peer directory).
                if let Some(addr) = addr {
                    target.put(addr_key(node), addr.into_bytes());
                }
                WriteResponse::Admitted(AdmitOutcome::Admitted)
            }
        }
    }
}

/// Run the shared, deterministic claim decision over a topic's index records in
/// the applied state, applying the resulting transitions (lease / dead-letter)
/// in place and returning the leased records for the caller to fetch payloads.
fn apply_mq_claim(
    target: &mut ApplyTarget,
    topic: &str,
    now_ms: u64,
    lease_ms: u64,
    max_batch: usize,
    max_attempts: u32,
) -> Vec<ClaimedRecord> {
    let prefix = messaging::meta_prefix(topic);
    // Gather the topic's direct-child index records.
    let mut records = Vec::new();
    for (key, raw) in target.data.range(prefix.clone()..) {
        if !key.starts_with(&prefix) {
            break;
        }
        if !messaging::is_direct_child(key, &prefix) {
            continue;
        }
        if let Ok(record) = serde_json::from_slice::<messaging::Record>(raw) {
            records.push((key[prefix.len()..].to_string(), record));
        }
    }
    let actions = messaging::plan_claim(records, now_ms, lease_ms, max_batch, max_attempts);

    let mut claimed = Vec::new();
    for action in actions {
        match action {
            messaging::ClaimAction::Lease { id, record } => {
                let json = serde_json::to_vec(&record).expect("record serializes");
                target.put(messaging::meta_key(topic, &id), json);
                claimed.push(ClaimedRecord {
                    id,
                    attempts: record.attempts,
                });
            }
            messaging::ClaimAction::DeadLetter { id, record } => {
                let json = serde_json::to_vec(&record).expect("record serializes");
                target.put(messaging::dead_key(topic, &id), json);
                target.remove(messaging::meta_key(topic, &id));
            }
        }
    }
    claimed
}

/// A message leased by an [`WriteOp::MqClaim`] proposal: the durable id and the
/// attempt charged. The claiming node fetches the payload from shared `Storage`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimedRecord {
    /// The durable message id.
    pub id: String,
    /// Delivery attempts so far, including this one (starts at 1).
    pub attempts: u32,
}

/// The result of applying a [`WriteOp`]: empty for KV/ack/nack/publish, or the
/// leased records for a claim.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum WriteResponse {
    /// A KV-style write (Put/Delete/Batch/publish/ack/nack) — no data.
    #[default]
    Kv,
    /// A claim's leased records (id + attempt count).
    Claimed(Vec<ClaimedRecord>),
    /// A [`WriteOp::MeshAdmit`] outcome (see [`AdmitOutcome`]).
    Admitted(AdmitOutcome),
}

/// The outcome of applying a [`WriteOp::MeshAdmit`]: the joiner was admitted, the
/// token was already spent (replay), or the key is revoked (a tombstone bars it
/// until an explicit un-revoke — F6). Deterministic at the apply layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmitOutcome {
    /// The joiner was trusted mesh-wide and the token spent.
    Admitted,
    /// The join token was already spent (single-use replay refused) → `409`.
    Spent,
    /// The key is revoked; a fresh token cannot re-admit it → an explicit
    /// un-revoke is required (F6).
    Revoked,
}

// ---- log store (in-memory) -------------------------------------------------

#[derive(Default)]
struct LogStoreInner {
    vote: Option<Vote<NodeId>>,
    log: BTreeMap<u64, Entry<TypeConfig>>,
    committed: Option<LogId<NodeId>>,
    last_purged: Option<LogId<NodeId>>,
}

/// An in-memory Raft log store (the persistent SlateDB-backed store is a
/// follow-up).
#[derive(Clone, Default)]
pub struct LogStore {
    inner: Arc<Mutex<LogStoreInner>>,
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        Ok(inner
            .log
            .range(range)
            .map(|(_, entry)| entry.clone())
            .collect())
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        let last = inner
            .log
            .values()
            .next_back()
            .map(|e| e.log_id)
            .or(inner.last_purged);
        Ok(LogState {
            last_purged_log_id: inner.last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.inner.lock().await.vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().await.vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.inner.lock().await.committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().await.committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
    {
        {
            let mut inner = self.inner.lock().await;
            for entry in entries {
                inner.log.insert(entry.log_id.index, entry);
            }
        }
        // In-memory append is durable the moment it returns.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.log.split_off(&log_id.index);
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.last_purged = Some(log_id);
        let keep = inner.log.split_off(&(log_id.index + 1));
        inner.log = keep;
        Ok(())
    }
}

// ---- state machine (KV byte map) -------------------------------------------

#[derive(Clone)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

#[derive(Default)]
struct StateMachineInner {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    /// The applied control-plane state: the replicated `KvStore` contents.
    data: BTreeMap<String, Vec<u8>>,
    current_snapshot: Option<StoredSnapshot>,
}

/// The Raft state machine: applies committed [`WriteOp`]s into an in-memory byte
/// map (the cluster-replicated `KvStore` contents) and snapshots it.
#[derive(Clone, Default)]
pub struct StateMachineStore {
    inner: Arc<Mutex<StateMachineInner>>,
    snapshot_idx: Arc<AtomicU64>,
}

/// The cluster's locally-applied control-plane state, read by the serving path
/// ([`RaftKv`] reads, [`crate::messaging::RaftMessaging`] introspection). Both
/// the in-memory [`StateMachineStore`] and the durable
/// [`PersistentStateMachine`](crate::persist::PersistentStateMachine) implement
/// it, so a node can be assembled with either without changing the facades.
#[async_trait::async_trait]
pub trait AppliedState: Send + Sync {
    /// Read an applied key from local state.
    async fn get(&self, key: &str) -> Option<Vec<u8>>;
    /// Keys with `prefix` in local applied state.
    async fn list_prefix(&self, prefix: &str) -> Vec<String>;
}

/// Notified after each committed batch is applied by the durable state machine,
/// with the raw-key mutations it produced (before durable-key translation). Lets
/// a subsystem mirror specific applied keys into its own in-memory view: the mesh
/// trust set tracks `mesh/trust/*` this way, so a join / rotation / revocation
/// committed on the leader propagates to every node's live trust set through
/// ordinary log replication — no side channel.
pub trait ApplyObserver: Send + Sync {
    /// The raw `WriteOp`s (original keys) applied by one `apply` call.
    fn on_apply(&self, muts: &[boatramp_core::kv::WriteOp]);
    /// Reconcile against the **full applied state** after a snapshot install
    /// wholesale-replaces local state (a lagging/joining node catching up via
    /// snapshot rather than the log). `data` is every applied key→value pair, so
    /// an observer can rebuild a view keyed on either (e.g. the trust set from
    /// keys, or the peer-address directory from values).
    fn on_reset(&self, data: &BTreeMap<String, Vec<u8>>);
}

impl StateMachineStore {
    /// Read an applied key from the local state (the serving-path read).
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
impl AppliedState for StateMachineStore {
    async fn get(&self, key: &str) -> Option<Vec<u8>> {
        StateMachineStore::get(self, key).await
    }
    async fn list_prefix(&self, prefix: &str) -> Vec<String> {
        StateMachineStore::list_prefix(self, prefix).await
    }
}

#[derive(Serialize, Deserialize)]
struct SnapshotPayload {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    data: BTreeMap<String, Vec<u8>>,
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let (payload, meta);
        {
            let inner = self.inner.lock().await;
            let last_log_id = inner.last_applied;
            let snapshot_id = format!(
                "{}-{}",
                last_log_id.map(|l| l.index).unwrap_or(0),
                self.snapshot_idx.fetch_add(1, Ordering::Relaxed)
            );
            payload = SnapshotPayload {
                last_applied: inner.last_applied,
                last_membership: inner.last_membership.clone(),
                data: inner.data.clone(),
            };
            meta = SnapshotMeta {
                last_log_id,
                last_membership: inner.last_membership.clone(),
                snapshot_id,
            };
        }
        let data = serde_json::to_vec(&payload).map_err(|e| {
            StorageError::from(StorageIOError::write_snapshot(Some(meta.signature()), &e))
        })?;
        self.inner.lock().await.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        });
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
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
        for entry in entries {
            inner.last_applied = Some(entry.log_id);
            let response = match entry.payload {
                EntryPayload::Blank => WriteResponse::Kv,
                EntryPayload::Normal(op) => {
                    // In-memory: apply to the map, discard the recorded mutations.
                    let mut target = ApplyTarget::new(&mut inner.data);
                    apply_op(&mut target, op)
                }
                EntryPayload::Membership(membership) => {
                    inner.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                    WriteResponse::Kv
                }
            };
            responses.push(response);
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
        let mut inner = self.inner.lock().await;
        inner.last_applied = payload.last_applied;
        inner.last_membership = payload.last_membership;
        inner.data = payload.data;
        inner.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data: bytes,
        });
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        Ok(self
            .inner
            .lock()
            .await
            .current_snapshot
            .as_ref()
            .map(|s| Snapshot {
                meta: s.meta.clone(),
                snapshot: Box::new(Cursor::new(s.data.clone())),
            }))
    }
}

// ---- in-process network (registry of node handles) -------------------------

/// A shared registry of the cluster's Raft handles. The in-process transport
/// (used by the multi-node test and single-binary clusters); a real HTTP mesh
/// is a follow-up slice.
#[derive(Clone, Default)]
pub struct Registry {
    nodes: Arc<StdMutex<BTreeMap<NodeId, openraft::Raft<TypeConfig>>>>,
}

impl Registry {
    pub fn register(&self, id: NodeId, raft: openraft::Raft<TypeConfig>) {
        self.nodes.lock().unwrap().insert(id, raft);
    }

    fn get(&self, id: NodeId) -> Option<openraft::Raft<TypeConfig>> {
        self.nodes.lock().unwrap().get(&id).cloned()
    }

    /// Drop a node from the registry (e.g. a crashed/removed peer), so writes no
    /// longer forward to it.
    pub fn remove(&self, id: NodeId) {
        self.nodes.lock().unwrap().remove(&id);
    }
}

/// A [`RaftNetworkFactory`] over the in-process [`Registry`].
#[derive(Clone, Default)]
pub struct NetworkFactory {
    registry: Registry,
}

impl NetworkFactory {
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }
}

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = Network;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        Network {
            registry: self.registry.clone(),
            target,
        }
    }
}

/// A network client to one target node, dispatching RPCs in-process.
pub struct Network {
    registry: Registry,
    target: NodeId,
}

impl Network {
    fn unreachable<E: std::error::Error + 'static>(&self) -> RPCError<NodeId, BasicNode, E> {
        RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            format!("node {} not in registry", self.target),
        )))
    }
}

impl RaftNetwork<TypeConfig> for Network {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let raft = self
            .registry
            .get(self.target)
            .ok_or_else(|| self.unreachable())?;
        raft.append_entries(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let raft = self
            .registry
            .get(self.target)
            .ok_or_else(|| self.unreachable())?;
        raft.vote(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let raft = self
            .registry
            .get(self.target)
            .ok_or_else(|| self.unreachable())?;
        raft.install_snapshot(rpc)
            .await
            .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

// ---- KvStore facade over the Raft cluster ----------------------------------

/// A [`KvStore`](boatramp_core::kv::KvStore) backed by the Raft cluster: writes
/// become Raft proposals (forwarded to the leader), reads come from this node's
/// **locally-applied** state. Content addressing makes the slight read lag
/// benign (a node always serves a fully-consistent old-or-new manifest), so
/// `DeployStore` runs unchanged over a cluster.
#[derive(Clone)]
pub struct RaftKv {
    /// Commits writes on the leader (in-process or over the HTTP mesh).
    forward: Arc<dyn Forwarder>,
    /// This node's applied state machine (the local read path) — in-memory or
    /// durable, behind [`AppliedState`].
    state: Arc<dyn AppliedState>,
}

impl RaftKv {
    /// Build over a leader [`Forwarder`] (writes) and the local applied
    /// [`AppliedState`] (reads).
    pub fn new(forward: Arc<dyn Forwarder>, state: Arc<dyn AppliedState>) -> Self {
        Self { forward, state }
    }

    /// Convenience: build with in-process leader forwarding via the [`Registry`]
    /// (single-binary clusters and tests).
    pub fn in_process(
        raft: openraft::Raft<TypeConfig>,
        registry: Registry,
        state: Arc<dyn AppliedState>,
    ) -> Self {
        Self::new(Arc::new(InProcessForwarder::new(raft, registry)), state)
    }

    /// Propose a write to the cluster, committing on the leader, discarding the
    /// (empty) response.
    async fn propose(&self, op: WriteOp) -> Result<(), boatramp_core::kv::KvError> {
        self.forward
            .commit(op)
            .await
            .map(|_| ())
            .map_err(|e| boatramp_core::kv::KvError::backend(e.to_string()))
    }

    /// Propose a write and return the leader's applied [`WriteResponse`] — the
    /// forwarding path for control-plane ops that need the result (mesh admit
    /// reads `Admitted(bool)`). Commits on the leader like any write.
    pub async fn propose_with_response(
        &self,
        op: WriteOp,
    ) -> Result<WriteResponse, boatramp_core::kv::KvError> {
        self.forward
            .commit(op)
            .await
            .map_err(|e| boatramp_core::kv::KvError::backend(e.to_string()))
    }
}

/// Submit `op` to the cluster, committing on the **leader**, and return the
/// leader's applied [`WriteResponse`]. If `raft` is a follower, forward to the
/// current leader (in-process via the [`Registry`]; the HTTP mesh forwards over
/// the wire in a real deployment), retrying briefly while leadership is in flux.
///
/// This is the single forwarding path shared by the [`RaftKv`] control-plane
/// facade and the [`crate::messaging`] coordinator — the only difference between
/// them is how they map the response and error.
/// The openraft client-write error (a write rejected at the Raft layer, or a
/// forward-to-leader signal). Shared by the in-process and mesh forwarders.
pub type ClientWriteRaftError = RaftError<NodeId, ClientWriteError<NodeId, BasicNode>>;

/// A failure committing a write to the cluster leader — the [`Forwarder`] error.
// `ClientWrite` wraps openraft's large `RaftError`; consistent with the crate's
// existing `result_large_err` allow for openraft errors (persist.rs).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    /// No leader is currently available to accept the write (election in flux).
    #[error("no leader available to commit the write")]
    NoLeader,
    /// The metrics name a leader that isn't in the peer directory (mesh).
    #[error("leader {0} not in the peer directory")]
    LeaderNotInDirectory(NodeId),
    /// The Raft layer rejected the client write.
    #[error("raft client-write failed: {0}")]
    ClientWrite(#[from] ClientWriteRaftError),
}

/// A failure changing cluster membership (`add_voter` / `remove_voter`).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum MembershipError {
    /// Refused: a cluster must keep at least one voter.
    #[error("refusing to remove the last voter from the cluster")]
    LastVoter,
    /// The Raft layer rejected the membership change.
    #[error("raft membership change failed: {0}")]
    Raft(#[from] ClientWriteRaftError),
}

pub async fn propose_to_leader(
    raft: &openraft::Raft<TypeConfig>,
    registry: &Registry,
    op: WriteOp,
) -> Result<WriteResponse, ForwardError> {
    let mut target = raft.clone();
    for _ in 0..10 {
        match target.client_write(op.clone()).await {
            Ok(resp) => return Ok(resp.data),
            Err(err) => match err.forward_to_leader() {
                Some(fwd) => match fwd.leader_id.and_then(|id| registry.get(id)) {
                    Some(leader) => target = leader,
                    // No known leader yet — wait for an election and retry.
                    None => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                },
                None => return Err(ForwardError::ClientWrite(err)),
            },
        }
    }
    Err(ForwardError::NoLeader)
}

/// Commits a [`WriteOp`] on the cluster **leader** from this node, hiding *how*
/// a write reaching a follower is forwarded: in-process via the [`Registry`]
/// ([`InProcessForwarder`], single-binary / tests) or over the peer mesh
/// ([`crate::http::HttpForwarder`], real multi-host clusters). The [`RaftKv`]
/// and [`crate::messaging::RaftMessaging`] facades take one of these, so the
/// same coordinator code runs in either deployment.
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync {
    /// Commit `op` on the leader and return its applied response.
    async fn commit(&self, op: WriteOp) -> Result<WriteResponse, ForwardError>;
}

/// A [`Forwarder`] that forwards to the leader **in-process** via the shared
/// [`Registry`] of Raft handles (single-binary clusters and tests).
pub struct InProcessForwarder {
    raft: openraft::Raft<TypeConfig>,
    registry: Registry,
}

impl InProcessForwarder {
    pub fn new(raft: openraft::Raft<TypeConfig>, registry: Registry) -> Self {
        Self { raft, registry }
    }
}

#[async_trait::async_trait]
impl Forwarder for InProcessForwarder {
    async fn commit(&self, op: WriteOp) -> Result<WriteResponse, ForwardError> {
        propose_to_leader(&self.raft, &self.registry, op).await
    }
}

/// Whether `me` is the cluster's **current Raft leader**.
///
/// This is the gate for **leader-only jobs**: cron
/// single-firing, ACME issuance single-flight, and prune all run only on the
/// leader, so the cluster fires each exactly once with no separate lock service.
/// A follower (or a node mid-election) returns `false`, so during a leadership
/// gap no node fires — missed ticks are skipped, never caught up (matching the
/// single-node scheduler's no-catch-up rule).
pub fn is_leader(raft: &openraft::Raft<TypeConfig>, me: NodeId) -> bool {
    raft.metrics().borrow().current_leader == Some(me)
}

/// The current voter set as seen by `raft`.
fn voter_ids(raft: &openraft::Raft<TypeConfig>) -> std::collections::BTreeSet<NodeId> {
    raft.metrics()
        .borrow()
        .membership_config
        .membership()
        .voter_ids()
        .collect()
}

/// **Add a node to the cluster** as a voter (dynamic
/// membership — beyond the static bootstrap list). The new node must already be
/// running and reachable (registered in the in-process [`Registry`], or serving
/// its `/raft/*` over the HTTP mesh). First it joins as a **learner** and
/// catches up (replication only, blocking until caught up), then it is promoted
/// into the voter set via Raft joint consensus. Call on the **leader**.
pub async fn add_voter(
    leader: &openraft::Raft<TypeConfig>,
    id: NodeId,
) -> Result<(), MembershipError> {
    leader.add_learner(id, BasicNode::default(), true).await?;
    let mut voters = voter_ids(leader);
    voters.insert(id);
    leader.change_membership(voters, false).await?;
    Ok(())
}

/// **Remove a node from the cluster's voter set** (dynamic membership). The
/// remaining voters re-form the membership via joint consensus; the removed node
/// can then be shut down. Call on the **leader**. Refuses to remove the last
/// voter (a cluster needs at least one).
pub async fn remove_voter(
    leader: &openraft::Raft<TypeConfig>,
    id: NodeId,
) -> Result<(), MembershipError> {
    let mut voters = voter_ids(leader);
    if voters.len() <= 1 {
        return Err(MembershipError::LastVoter);
    }
    voters.remove(&id);
    leader.change_membership(voters, false).await?;
    Ok(())
}

#[async_trait::async_trait]
impl boatramp_core::kv::KvStore for RaftKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, boatramp_core::kv::KvError> {
        Ok(self.state.get(key).await)
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), boatramp_core::kv::KvError> {
        self.propose(WriteOp::Put {
            key: key.to_string(),
            value,
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), boatramp_core::kv::KvError> {
        self.propose(WriteOp::Delete {
            key: key.to_string(),
        })
        .await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, boatramp_core::kv::KvError> {
        Ok(self.state.list_prefix(prefix).await)
    }

    async fn write_batch(
        &self,
        ops: Vec<boatramp_core::kv::WriteOp>,
    ) -> Result<(), boatramp_core::kv::KvError> {
        // One atomic Raft entry for the whole batch.
        let batch = ops
            .into_iter()
            .map(|op| match op {
                boatramp_core::kv::WriteOp::Put(key, value) => WriteOp::Put { key, value },
                boatramp_core::kv::WriteOp::Delete(key) => WriteOp::Delete { key },
            })
            .collect();
        self.propose(WriteOp::Batch(batch)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::KvStore;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use openraft::{Config, Raft};

    /// `MeshAdmit` is deterministic and single-use at the apply layer: the first
    /// apply of a `jti` admits the node (records the spent handle +
    /// trusts its key in one entry); a replay of that `jti` is a no-op that admits
    /// nothing — so a stolen/replayed join token can never double-admit, even if
    /// two applies race on the leader.
    #[test]
    fn mesh_admit_is_deterministic_and_single_use() {
        let mut data = BTreeMap::new();

        let mut t = ApplyTarget::new(&mut data);
        let first = apply_op(
            &mut t,
            WriteOp::MeshAdmit {
                jti: "jti-1".into(),
                node: 5,
                pubkey_hex: "aa01".into(),
                addr: None,
            },
        );
        assert_eq!(first, WriteResponse::Admitted(AdmitOutcome::Admitted));
        assert!(data.contains_key(&trust_key_hex(5, "aa01")), "node trusted");
        assert!(data.contains_key("mesh/join/used/jti-1"), "handle spent");

        // Replaying the same jti — even for a different key — admits nothing.
        let mut t2 = ApplyTarget::new(&mut data);
        let replay = apply_op(
            &mut t2,
            WriteOp::MeshAdmit {
                jti: "jti-1".into(),
                node: 5,
                pubkey_hex: "bb02".into(),
                addr: None,
            },
        );
        assert_eq!(replay, WriteResponse::Admitted(AdmitOutcome::Spent));
        assert!(
            !data.contains_key(&trust_key_hex(5, "bb02")),
            "a replayed jti must not admit a different key"
        );

        // A fresh jti admits normally (independent tokens are unaffected).
        let mut t3 = ApplyTarget::new(&mut data);
        let second = apply_op(
            &mut t3,
            WriteOp::MeshAdmit {
                jti: "jti-2".into(),
                node: 6,
                pubkey_hex: "cc03".into(),
                addr: None,
            },
        );
        assert_eq!(second, WriteResponse::Admitted(AdmitOutcome::Admitted));
        assert!(data.contains_key(&trust_key_hex(6, "cc03")));
    }

    /// A revocation tombstone bars re-admission (F6): once `mesh/revoked/{key}`
    /// is set, a **fresh** join token for that key is refused (`Revoked`) and the
    /// token is **not** spent — so it becomes redeemable again only after an
    /// explicit un-revoke (tombstone delete). This is the durable, re-admit-proof
    /// property that makes a `revoke` racing an `admit` always end revoked.
    #[test]
    fn revocation_tombstone_bars_readmission_until_unrevoked() {
        let mut data = BTreeMap::new();
        // The key was revoked (tombstone present), trust already gone.
        data.insert(revoked_key("dd04"), Vec::new());

        // A fresh token for the revoked key is refused, trust NOT restored,
        // and — critically — the token handle is NOT consumed.
        let mut t = ApplyTarget::new(&mut data);
        let barred = apply_op(
            &mut t,
            WriteOp::MeshAdmit {
                jti: "jti-revoked".into(),
                node: 7,
                pubkey_hex: "dd04".into(),
                addr: None,
            },
        );
        assert_eq!(barred, WriteResponse::Admitted(AdmitOutcome::Revoked));
        assert!(!data.contains_key(&trust_key_hex(7, "dd04")), "no re-trust");
        assert!(
            !data.contains_key("mesh/join/used/jti-revoked"),
            "a barred admit must not spend the token"
        );

        // Un-revoke (delete the tombstone) → the same token now admits.
        data.remove(&revoked_key("dd04"));
        let mut t2 = ApplyTarget::new(&mut data);
        let now_ok = apply_op(
            &mut t2,
            WriteOp::MeshAdmit {
                jti: "jti-revoked".into(),
                node: 7,
                pubkey_hex: "dd04".into(),
                addr: None,
            },
        );
        assert_eq!(now_ok, WriteResponse::Admitted(AdmitOutcome::Admitted));
        assert!(data.contains_key(&trust_key_hex(7, "dd04")), "re-admitted");
    }

    /// Spin up an in-process 3-node cluster, elect a leader, replicate a write,
    /// and confirm every node's applied state converges (activate on any node,
    /// visible on all).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_node_cluster_elects_and_replicates() {
        let registry = Registry::default();
        let config = Arc::new(
            Config {
                heartbeat_interval: 150,
                election_timeout_min: 300,
                election_timeout_max: 600,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );

        let mut rafts = BTreeMap::new();
        let mut sms: BTreeMap<NodeId, StateMachineStore> = BTreeMap::new();
        for id in 1..=3u64 {
            let sm = StateMachineStore::default();
            let raft = Raft::new(
                id,
                config.clone(),
                NetworkFactory::new(registry.clone()),
                LogStore::default(),
                sm.clone(),
            )
            .await
            .unwrap();
            registry.register(id, raft.clone());
            rafts.insert(id, raft);
            sms.insert(id, sm);
        }

        // Initialize the cluster with all three voters on node 1.
        let members: BTreeMap<NodeId, BasicNode> =
            (1..=3u64).map(|id| (id, BasicNode::default())).collect();
        rafts[&1].initialize(members).await.unwrap();

        // Wait for a leader to emerge.
        rafts[&1]
            .wait(Some(Duration::from_secs(30)))
            .metrics(|m| m.current_leader.is_some(), "a leader is elected")
            .await
            .unwrap();
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();

        // Write a control-plane key through the leader.
        rafts[&leader]
            .client_write(WriteOp::Put {
                key: "current/blog".to_string(),
                value: b"deploy-abc".to_vec(),
            })
            .await
            .unwrap();

        // Every node converges on the committed write in its applied state.
        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(30)))
                .applied_index_at_least(Some(2), "the write applied")
                .await
                .unwrap();
            assert_eq!(
                sms[&id].get("current/blog").await.as_deref(),
                Some(b"deploy-abc".as_slice()),
                "node {id} did not converge on the replicated write"
            );
        }

        let voters: BTreeSet<NodeId> = rafts[&1]
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect();
        assert_eq!(voters, BTreeSet::from([1, 2, 3]));

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// C1 gate's hardest clause: **leader loss → re-election → serving
    /// uninterrupted**. Kill the leader, the survivors elect a new one, and a
    /// write through a surviving node's `KvStore` still commits and is readable
    /// (alongside the pre-failure write).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn leader_loss_reelects_and_keeps_serving() {
        let (registry, mut rafts, sms) = cluster(3).await;
        let old_leader = rafts[&1].metrics().borrow().current_leader.unwrap();

        let kvs: BTreeMap<NodeId, RaftKv> = (1..=3u64)
            .map(|id| {
                (
                    id,
                    RaftKv::in_process(
                        rafts[&id].clone(),
                        registry.clone(),
                        Arc::new(sms[&id].clone()),
                    ),
                )
            })
            .collect();

        // A write before the failure.
        kvs[&old_leader]
            .put("current/blog", b"deploy-1".to_vec())
            .await
            .unwrap();

        // Kill the leader.
        let survivors: Vec<NodeId> = (1..=3u64).filter(|id| *id != old_leader).collect();
        registry.remove(old_leader);
        rafts.remove(&old_leader).unwrap().shutdown().await.unwrap();

        // The survivors elect a new leader.
        rafts[&survivors[0]]
            .wait(Some(Duration::from_secs(30)))
            .metrics(
                |m| matches!(m.current_leader, Some(l) if l != old_leader),
                "a new leader (not the dead one) is elected",
            )
            .await
            .unwrap();

        // A write through a surviving node still commits (forwarded to the new
        // leader) and both keys are readable on the survivors.
        kvs[&survivors[0]]
            .put("current/shop", b"deploy-2".to_vec())
            .await
            .unwrap();
        // Wait each survivor to apply up to the leader's last log index, rather
        // than a hard-coded one: a newly-elected leader appends a no-op entry,
        // which shifts the write's index, so the target must be read live.
        let new_leader = rafts[&survivors[0]]
            .metrics()
            .borrow()
            .current_leader
            .unwrap();
        let target = rafts[&new_leader].metrics().borrow().last_log_index;
        for id in &survivors {
            rafts[id]
                .wait(Some(Duration::from_secs(30)))
                .applied_index_at_least(target, "post-failover write applied")
                .await
                .unwrap();
            assert_eq!(
                kvs[id].get("current/blog").await.unwrap().as_deref(),
                Some(b"deploy-1".as_slice())
            );
            assert_eq!(
                kvs[id].get("current/shop").await.unwrap().as_deref(),
                Some(b"deploy-2".as_slice())
            );
        }

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// **Cron single-firing**: leader-only jobs key off
    /// [`is_leader`], so across the cluster **exactly one** node fires a tick —
    /// and after the leader dies, exactly one (different) node takes over. No
    /// separate lock service.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cron_fires_only_on_leader() {
        let (registry, mut rafts, _sms) = cluster(3).await;

        let firing: Vec<NodeId> = (1..=3u64).filter(|id| is_leader(&rafts[id], *id)).collect();
        assert_eq!(firing.len(), 1, "exactly one node fires the cron tick");
        let old_leader = firing[0];

        // Kill the leader; the survivors elect exactly one new firing node.
        let survivors: Vec<NodeId> = (1..=3u64).filter(|id| *id != old_leader).collect();
        registry.remove(old_leader);
        rafts.remove(&old_leader).unwrap().shutdown().await.unwrap();
        rafts[&survivors[0]]
            .wait(Some(Duration::from_secs(30)))
            .metrics(
                |m| matches!(m.current_leader, Some(l) if l != old_leader),
                "a new leader takes over cron firing",
            )
            .await
            .unwrap();

        let firing: Vec<NodeId> = survivors
            .iter()
            .copied()
            .filter(|id| is_leader(&rafts[id], *id))
            .collect();
        assert_eq!(
            firing.len(),
            1,
            "still exactly one firing node after failover"
        );
        assert_ne!(firing[0], old_leader);

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// Build an initialized `n`-node in-process cluster and wait for a leader.
    async fn cluster(
        n: u64,
    ) -> (
        Registry,
        BTreeMap<NodeId, Raft<TypeConfig>>,
        BTreeMap<NodeId, StateMachineStore>,
    ) {
        let registry = Registry::default();
        let config = Arc::new(
            Config {
                heartbeat_interval: 150,
                election_timeout_min: 300,
                election_timeout_max: 600,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );
        let mut rafts = BTreeMap::new();
        let mut sms = BTreeMap::new();
        for id in 1..=n {
            let sm = StateMachineStore::default();
            let raft = Raft::new(
                id,
                config.clone(),
                NetworkFactory::new(registry.clone()),
                LogStore::default(),
                sm.clone(),
            )
            .await
            .unwrap();
            registry.register(id, raft.clone());
            rafts.insert(id, raft);
            sms.insert(id, sm);
        }
        let members: BTreeMap<NodeId, BasicNode> =
            (1..=n).map(|id| (id, BasicNode::default())).collect();
        rafts[&1].initialize(members).await.unwrap();
        rafts[&1]
            .wait(Some(Duration::from_secs(30)))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .unwrap();
        (registry, rafts, sms)
    }

    /// **Dynamic membership** (beyond the static
    /// bootstrap list): a brand-new node joins a running cluster as a voter,
    /// catches up, and serves the replicated state; then a node is removed and
    /// the survivors keep committing.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn membership_grows_and_shrinks() {
        let (registry, mut rafts, mut sms) = cluster(3).await;
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();

        // A write before the new node joins.
        rafts[&leader]
            .client_write(WriteOp::Put {
                key: "current/blog".into(),
                value: b"v1".to_vec(),
            })
            .await
            .unwrap();

        // Bring up a 4th node and register it on the mesh.
        let config = Arc::new(
            Config {
                heartbeat_interval: 150,
                election_timeout_min: 300,
                election_timeout_max: 600,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );
        let sm4 = StateMachineStore::default();
        let raft4 = Raft::new(
            4,
            config,
            NetworkFactory::new(registry.clone()),
            LogStore::default(),
            sm4.clone(),
        )
        .await
        .unwrap();
        registry.register(4, raft4.clone());
        rafts.insert(4, raft4);
        sms.insert(4, sm4);

        // Add it as a voter (learner catch-up + promotion) and confirm it both
        // joined the voter set and replicated the pre-join write.
        add_voter(&rafts[&leader], 4).await.unwrap();
        rafts[&4]
            .wait(Some(Duration::from_secs(30)))
            .applied_index_at_least(Some(2), "new voter caught up")
            .await
            .unwrap();
        assert!(voter_ids(&rafts[&leader]).contains(&4));
        assert_eq!(
            sms[&4].get("current/blog").await.as_deref(),
            Some(b"v1".as_slice())
        );

        // A write after the grow is visible on the new node. Wait up to the
        // leader's last index (membership changes added entries, so the write's
        // index isn't a fixed number).
        rafts[&leader]
            .client_write(WriteOp::Put {
                key: "current/shop".into(),
                value: b"v2".to_vec(),
            })
            .await
            .unwrap();
        let target = rafts[&leader].metrics().borrow().last_log_index;
        rafts[&4]
            .wait(Some(Duration::from_secs(30)))
            .applied_index_at_least(target, "post-grow write applied")
            .await
            .unwrap();
        assert_eq!(
            sms[&4].get("current/shop").await.as_deref(),
            Some(b"v2".as_slice())
        );

        // Shrink: remove node 4 from the voter set; the cluster keeps committing.
        remove_voter(&rafts[&leader], 4).await.unwrap();
        assert!(!voter_ids(&rafts[&leader]).contains(&4));
        registry.remove(4);
        rafts.remove(&4).unwrap().shutdown().await.unwrap();

        rafts[&leader]
            .client_write(WriteOp::Put {
                key: "current/docs".into(),
                value: b"v3".to_vec(),
            })
            .await
            .unwrap();

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// The `KvStore` facade: a write submitted to a **follower** forwards to the
    /// leader, commits, and is then readable from every node's local applied
    /// state — `DeployStore` semantics over a cluster (C1 KvStore facade).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn raftkv_write_on_follower_forwards_and_replicates() {
        let (registry, rafts, sms) = cluster(3).await;
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();
        let follower = (1..=3u64).find(|id| *id != leader).unwrap();

        let kvs: BTreeMap<NodeId, RaftKv> = (1..=3u64)
            .map(|id| {
                (
                    id,
                    RaftKv::in_process(
                        rafts[&id].clone(),
                        registry.clone(),
                        Arc::new(sms[&id].clone()),
                    ),
                )
            })
            .collect();

        // Write via the follower's KvStore — propose forwards to the leader.
        kvs[&follower]
            .put("current/blog", b"deploy-1".to_vec())
            .await
            .unwrap();
        // An atomic batch via the follower too.
        kvs[&follower]
            .write_batch(vec![
                boatramp_core::kv::WriteOp::Put("alias/blog/staging".into(), b"deploy-1".to_vec()),
                boatramp_core::kv::WriteOp::Put("domain/blog.example.com".into(), b"blog".into()),
            ])
            .await
            .unwrap();

        // Every node converges; reads come from each node's local applied state.
        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(30)))
                .applied_index_at_least(Some(3), "writes applied")
                .await
                .unwrap();
            assert_eq!(
                kvs[&id].get("current/blog").await.unwrap().as_deref(),
                Some(b"deploy-1".as_slice()),
                "node {id}"
            );
            let aliases = kvs[&id].list_prefix("alias/blog/").await.unwrap();
            assert_eq!(aliases, vec!["alias/blog/staging".to_string()], "node {id}");
        }

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// **C9 gate — cluster-managed certs.** Over the replicated control plane
    /// (a `KvCertStore` on each node's `RaftKv`): only the **leader** issues
    /// (single-flight), the cert **replicates to every node**, and followers
    /// serve it from local state **without ever calling the CA**.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_managed_certs_issue_once_serve_everywhere() {
        use boatramp_core::cert::{ensure_cert, CertStore, KvCertStore, StoredCert};
        use boatramp_core::kv::KvStore;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (registry, rafts, sms) = cluster(3).await;
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();

        // A KvCertStore on each node's control-plane KvStore facade.
        let stores: BTreeMap<NodeId, KvCertStore> = (1..=3u64)
            .map(|id| {
                let kv: Arc<dyn KvStore> = Arc::new(RaftKv::in_process(
                    rafts[&id].clone(),
                    registry.clone(),
                    Arc::new(sms[&id].clone()),
                ));
                (id, KvCertStore::new(kv))
            })
            .collect();

        let issues = AtomicUsize::new(0);
        let issue = || {
            issues.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok::<_, String>(StoredCert::new(
                "CHAIN",
                "KEY",
                4_000_000_000,
            )))
        };

        // The leader issues once and writes the cert to the replicated store.
        let issued = ensure_cert(&stores[&leader], "blog.example.com", true, 1000, 100, issue)
            .await
            .unwrap();
        assert!(issued.is_some());
        assert_eq!(issues.load(Ordering::SeqCst), 1);

        // Wait every node to apply the cert write (a Raft proposal).
        let target = rafts[&leader].metrics().borrow().last_log_index;
        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(30)))
                .applied_index_at_least(target, "cert replicated")
                .await
                .unwrap();
        }

        // Every node serves the replicated cert; followers never issue.
        for id in 1..=3u64 {
            let got = stores[&id].get("blog.example.com").await.unwrap();
            assert_eq!(got.unwrap().chain_pem, "CHAIN", "node {id} has the cert");
            if id != leader {
                let follower_issue = || {
                    issues.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok::<_, String>(StoredCert::new("X", "X", 4_000_000_000)))
                };
                ensure_cert(
                    &stores[&id],
                    "blog.example.com",
                    false,
                    2000,
                    100,
                    follower_issue,
                )
                .await
                .unwrap();
            }
        }
        // Still exactly one issuance, cluster-wide.
        assert_eq!(issues.load(Ordering::SeqCst), 1, "only the leader issued");

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }
}
