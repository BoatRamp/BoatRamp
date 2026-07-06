//! Cluster-mode messaging coordinator: **the Raft leader**.
//!
//! [`RaftMessaging`] implements the same [`Messaging`] trait as the single-node
//! [`LogMessaging`](boatramp_core::messaging::LogMessaging), so guests and the
//! dispatcher are byte-for-byte identical across modes. Only the *coordinator*
//! differs: the one operation that needs atomicity — `claim` (never lease one
//! message to two consumers) — is a single Raft proposal applied
//! deterministically in the state machine (via the shared
//! [`plan_claim`](boatramp_core::messaging::plan_claim)), so the leader is the
//! cluster-wide serialization point. `ack`/`nack`/`publish` are likewise tiny
//! proposals.
//!
//! Crucially, **payloads never enter the Raft log**: a publisher writes the body
//! to the shared [`Storage`] first, and only the small index record is
//! replicated. So consensus volume is bounded by the *claim/ack rate*, not the
//! payload throughput, and any node can run a dispatcher that leases a
//! batch from the leader, runs the consumers locally, and acks back — consumer
//! compute distributes across the cluster while claim stays coordinated.
//!
//! Live SSE fan-out (`subscribe`) crosses nodes via a [`StreamBus`]: a published
//! event is broadcast to every node's local [`StreamHubs`], so a client connected
//! to any node sees events published on any node. Cron single-firing keys off
//! Raft leadership ([`crate::raft::is_leader`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use boatramp_core::messaging::{self, ClaimedMessage, Messaging, MessagingError, StreamHubs};
use boatramp_core::{PutMeta, Storage};
use futures::stream::BoxStream;
use futures::StreamExt;

use crate::raft::{AppliedState, Forwarder, NodeId, WriteOp, WriteResponse};

/// Cross-node live-stream fan-out. A published SSE event
/// must reach subscribers connected to **any** node, so on publish a node hands
/// the event to the bus, which delivers it to every node's local
/// [`StreamHubs`]. At-most-once, fire-and-forget: a dropped inter-node hop is
/// tolerated, the same class of drop as a full subscriber buffer.
pub trait StreamBus: Send + Sync {
    /// Deliver a published event to every node's local stream fan-out.
    fn broadcast(&self, topic: &str, id: &str, payload: &[u8]);
}

/// The in-process [`StreamBus`] for single-binary / test clusters: it holds
/// every node's [`StreamHubs`] and fans an event out to all of them. A real
/// multi-host cluster uses an HTTP variant POSTing the event to each peer's
/// stream endpoint — the same peer-mesh shape as the Raft RPC transport.
#[derive(Clone, Default)]
pub struct InProcessStreamBus {
    hubs: Arc<StdMutex<Vec<Arc<StreamHubs>>>>,
}

impl InProcessStreamBus {
    /// A fresh bus with no nodes attached.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a new node: returns its local [`StreamHubs`] (which the node also
    /// serves `subscribe` from), now wired to receive every broadcast.
    pub fn register(&self) -> Arc<StreamHubs> {
        let hubs = Arc::new(StreamHubs::new());
        self.hubs.lock().unwrap().push(hubs.clone());
        hubs
    }
}

impl StreamBus for InProcessStreamBus {
    fn broadcast(&self, topic: &str, id: &str, payload: &[u8]) {
        for hubs in self.hubs.lock().unwrap().iter() {
            hubs.broadcast(topic, id, payload);
        }
    }
}

/// The cluster [`Messaging`]: a durable log whose **index** is the Raft state
/// machine and whose **payloads** live in a shared [`Storage`]. The single-writer
/// coordinator is the Raft leader (claim/ack/nack/publish are proposals).
pub struct RaftMessaging {
    /// Shared blob store for message payloads (never replicated through Raft).
    storage: Arc<dyn Storage>,
    /// Commits claim/ack/nack/publish on the leader (in-process or HTTP mesh).
    forward: Arc<dyn Forwarder>,
    /// This node's applied state machine — the local read path for backlog /
    /// dead-letter introspection (in-memory or durable, behind [`AppliedState`]).
    state: Arc<dyn AppliedState>,
    /// This node's id, mixed into message ids for cluster-wide uniqueness.
    node_id: NodeId,
    /// Per-node tiebreaker for ids minted within the same millisecond.
    seq: AtomicU64,
    /// This node's local SSE fan-out (the `subscribe` source).
    hubs: Arc<StreamHubs>,
    /// Cross-node live-stream delivery (every node's hubs); called on publish.
    bus: Arc<dyn StreamBus>,
}

impl RaftMessaging {
    /// Build a coordinator for one cluster node over the shared payload store,
    /// a leader [`Forwarder`], the node's applied state, and the stream fan-out
    /// (this node's local `hubs` + the cross-node `bus`).
    pub fn new(
        storage: Arc<dyn Storage>,
        forward: Arc<dyn Forwarder>,
        state: Arc<dyn AppliedState>,
        node_id: NodeId,
        hubs: Arc<StreamHubs>,
        bus: Arc<dyn StreamBus>,
    ) -> Self {
        Self {
            storage,
            forward,
            state,
            node_id,
            seq: AtomicU64::new(0),
            hubs,
            bus,
        }
    }

    /// Mint a globally-unique, ≈time-ordered message id. The millis prefix keeps
    /// lexical order ≈ publish order; the node id + per-node sequence guarantee
    /// two nodes publishing in the same millisecond never collide.
    fn next_id(&self) -> String {
        format!(
            "{:013}-{:016x}-{:016x}",
            now_ms(),
            self.node_id,
            self.seq.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Submit a proposal to the leader, mapping failures to [`MessagingError`].
    async fn propose(&self, op: WriteOp) -> Result<WriteResponse, MessagingError> {
        self.forward
            .commit(op)
            .await
            .map_err(|e| MessagingError::Backend(e.to_string()))
    }

    /// Read a message payload from the shared store.
    async fn read_payload(&self, topic: &str, id: &str) -> Result<Vec<u8>, MessagingError> {
        let object = self
            .storage
            .get(&messaging::payload_key(topic, id))
            .await
            .map_err(|e| MessagingError::Backend(e.to_string()))?;
        let mut body = object.body;
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.map_err(|e| MessagingError::Backend(e.to_string()))?);
        }
        Ok(buf)
    }

    /// Count direct-child keys under `prefix` in this node's applied state.
    async fn count_direct(&self, prefix: &str) -> usize {
        self.state
            .list_prefix(prefix)
            .await
            .iter()
            .filter(|k| messaging::is_direct_child(k, prefix))
            .count()
    }

    /// The ids of `topic`'s dead-lettered messages (direct children only), read
    /// from this node's applied state.
    async fn dead_ids(&self, topic: &str) -> Vec<String> {
        let prefix = messaging::dead_prefix(topic);
        self.state
            .list_prefix(&prefix)
            .await
            .into_iter()
            .filter(|k| messaging::is_direct_child(k, &prefix))
            .map(|k| k[prefix.len()..].to_string())
            .collect()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[async_trait]
impl Messaging for RaftMessaging {
    async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError> {
        let id = self.next_id();
        // Payload to shared storage first, then the index proposal — so the
        // replicated record never references a missing payload.
        let bytes = bytes::Bytes::copy_from_slice(payload);
        let body = futures::stream::once(async move { Ok(bytes) }).boxed();
        self.storage
            .put(
                &messaging::payload_key(topic, &id),
                body,
                PutMeta::default(),
            )
            .await
            .map_err(|e| MessagingError::Backend(e.to_string()))?;
        self.propose(WriteOp::MqPublish {
            topic: topic.to_string(),
            id: id.clone(),
        })
        .await?;
        // Live SSE fan-out across the cluster (best-effort, separate from the
        // durable queue): every node's hubs, including this one's.
        self.bus.broadcast(topic, &id, payload);
        Ok(())
    }

    async fn claim(
        &self,
        topic: &str,
        lease: Duration,
        max_batch: usize,
        max_attempts: u32,
    ) -> Result<Vec<ClaimedMessage>, MessagingError> {
        // The claim is one Raft proposal: the leader applies it atomically, so a
        // message is leased to exactly one claimer cluster-wide. The issuing
        // node stamps `now_ms` so every replica applies the same transition.
        let response = self
            .propose(WriteOp::MqClaim {
                topic: topic.to_string(),
                now_ms: now_ms(),
                lease_ms: lease.as_millis() as u64,
                max_batch: max_batch as u32,
                max_attempts,
            })
            .await?;
        let WriteResponse::Claimed(records) = response else {
            return Err(MessagingError::Backend(
                "claim proposal returned a non-claim response".into(),
            ));
        };
        // Fetch payloads from the shared store (bypassing consensus).
        let mut claimed = Vec::with_capacity(records.len());
        for record in records {
            let payload = self.read_payload(topic, &record.id).await?;
            claimed.push(ClaimedMessage {
                id: record.id,
                topic: topic.to_string(),
                payload,
                attempts: record.attempts,
            });
        }
        Ok(claimed)
    }

    async fn ack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
        // Drop the index record first (no longer claimable), then the payload.
        self.propose(WriteOp::MqAck {
            topic: msg.topic.clone(),
            id: msg.id.clone(),
        })
        .await?;
        self.storage
            .delete(&messaging::payload_key(&msg.topic, &msg.id))
            .await
            .map_err(|e| MessagingError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn nack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
        self.propose(WriteOp::MqNack {
            topic: msg.topic.clone(),
            id: msg.id.clone(),
        })
        .await?;
        Ok(())
    }

    async fn backlog(&self, topic: &str) -> Result<usize, MessagingError> {
        Ok(self.count_direct(&messaging::meta_prefix(topic)).await)
    }

    async fn dead_letter_count(&self, topic: &str) -> Result<usize, MessagingError> {
        Ok(self.count_direct(&messaging::dead_prefix(topic)).await)
    }

    async fn purge_dead_letters(&self, topic: &str) -> Result<usize, MessagingError> {
        let ids = self.dead_ids(topic).await;
        if ids.is_empty() {
            return Ok(0);
        }
        // Replicate the dead-record deletes in one proposal (the index is the
        // Raft state machine), then drop the preserved payloads from shared
        // storage (payloads never enter the log).
        let deletes = ids
            .iter()
            .map(|id| WriteOp::Delete {
                key: messaging::dead_key(topic, id),
            })
            .collect();
        self.propose(WriteOp::Batch(deletes)).await?;
        for id in &ids {
            self.storage
                .delete(&messaging::payload_key(topic, id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
        }
        Ok(ids.len())
    }

    async fn redrive_dead_letters(&self, topic: &str) -> Result<usize, MessagingError> {
        let ids = self.dead_ids(topic).await;
        if ids.is_empty() {
            return Ok(0);
        }
        // Per message: re-arm a fresh index record (`MqPublish` is idempotent and
        // the meta key was removed at dead-letter time) and drop the dead record,
        // atomically in one batch. The payload is still in shared storage, reused
        // in place — nothing is copied and no new id is minted.
        let ops = ids
            .iter()
            .flat_map(|id| {
                [
                    WriteOp::MqPublish {
                        topic: topic.to_string(),
                        id: id.clone(),
                    },
                    WriteOp::Delete {
                        key: messaging::dead_key(topic, id),
                    },
                ]
            })
            .collect();
        self.propose(WriteOp::Batch(ops)).await?;
        Ok(ids.len())
    }

    fn subscribe(
        &self,
        topic: &str,
        after: Option<&str>,
    ) -> BoxStream<'static, messaging::StreamEvent> {
        // Serve from this node's local hubs; cross-node events arrive via the
        // bus's broadcast into these same hubs.
        self.hubs.subscribe(topic, after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use boatramp_core::{ByteStream, GetObject, ObjectMeta, StorageError};
    use openraft::{BasicNode, Config, Raft};

    use crate::raft::{
        InProcessForwarder, LogStore, NetworkFactory, Registry, StateMachineStore, TypeConfig,
    };

    /// Minimal in-memory **shared** blob store for the cluster messaging tests
    /// (stands in for the s3/R2 store every node reads payloads from).
    #[derive(Default)]
    struct MemStorage {
        objects: StdMutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let bytes = self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let size = bytes.len() as u64;
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(size),
                    ..Default::default()
                },
                body,
            })
        }
        async fn get_range(
            &self,
            key: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            self.objects.lock().unwrap().insert(key.to_string(), buf);
            Ok(ObjectMeta {
                key: key.to_string(),
                ..Default::default()
            })
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let map = self.objects.lock().unwrap();
            let bytes = map
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(bytes.len() as u64),
                ..Default::default()
            })
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .map(|k| ObjectMeta {
                    key: k.clone(),
                    ..Default::default()
                })
                .collect())
        }
    }

    /// An initialized `n`-node in-process cluster, each node fronted by a
    /// [`RaftMessaging`] over **one shared** payload store. Returns the rafts
    /// (for shutdown) and the per-node coordinators.
    async fn cluster_mq(
        n: u64,
    ) -> (
        BTreeMap<NodeId, Raft<TypeConfig>>,
        BTreeMap<NodeId, Arc<RaftMessaging>>,
    ) {
        let registry = Registry::default();
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let bus = InProcessStreamBus::new();
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
        let mut mqs = BTreeMap::new();
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
            let forward = Arc::new(InProcessForwarder::new(raft.clone(), registry.clone()));
            let mq = Arc::new(RaftMessaging::new(
                storage.clone(),
                forward,
                Arc::new(sm),
                id,
                bus.register(),
                Arc::new(bus.clone()),
            ));
            rafts.insert(id, raft);
            mqs.insert(id, mq);
        }
        let members: BTreeMap<NodeId, BasicNode> =
            (1..=n).map(|id| (id, BasicNode::default())).collect();
        rafts[&1].initialize(members).await.unwrap();
        rafts[&1]
            .wait(Some(Duration::from_secs(10)))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .unwrap();
        (rafts, mqs)
    }

    async fn shutdown(rafts: BTreeMap<NodeId, Raft<TypeConfig>>) {
        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    const LEASE: Duration = Duration::from_secs(60);

    /// **C4 gate:** consumers on every node, **no double-delivery**. Publish a
    /// batch, then have all three nodes claim concurrently (every claim forwards
    /// to the leader, which applies it atomically). With a long lease and no
    /// acks, each message must be leased to *exactly one* node.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_claim_never_double_delivers() {
        let (rafts, mqs) = cluster_mq(3).await;

        // Publish 30 messages (spread the publishers across nodes too).
        const N: usize = 30;
        for i in 0..N {
            let node = (i as u64 % 3) + 1;
            mqs[&node]
                .publish("orders/created", format!("msg-{i}").as_bytes())
                .await
                .unwrap();
        }

        // Every node runs a dispatcher claiming concurrently. A claim returns
        // empty only once nothing claimable remains (long lease, no acks), so
        // each task stops on its first empty batch.
        let collected: Arc<StdMutex<Vec<ClaimedMessage>>> = Arc::new(StdMutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for id in 1..=3u64 {
            let mq = mqs[&id].clone();
            let collected = collected.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let batch = mq.claim("orders/created", LEASE, 4, 5).await.unwrap();
                    if batch.is_empty() {
                        break;
                    }
                    collected.lock().unwrap().extend(batch);
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        // Take ownership out of the mutex so no guard is held across an await.
        let claimed = std::mem::take(&mut *collected.lock().unwrap());
        let ids: HashSet<&str> = claimed.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ids.len(),
            claimed.len(),
            "a message was delivered to more than one node"
        );
        assert_eq!(claimed.len(), N, "every published message was claimed once");
        // Payloads round-tripped through the shared store.
        let payloads: HashSet<String> = claimed
            .iter()
            .map(|m| String::from_utf8(m.payload.clone()).unwrap())
            .collect();
        let expected: HashSet<String> = (0..N).map(|i| format!("msg-{i}")).collect();
        assert_eq!(payloads, expected);

        shutdown(rafts).await;
    }

    /// Lease/attempt state lives in the replicated index, so a redelivery is
    /// visible cluster-wide: claim on one node (zero lease → immediately
    /// re-claimable), then claim on **another** node sees the re-charged attempt.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_redelivery_crosses_nodes() {
        let (rafts, mqs) = cluster_mq(3).await;
        mqs[&1].publish("t", b"x").await.unwrap();

        let first = mqs[&1].claim("t", Duration::ZERO, 10, 5).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].attempts, 1);

        let second = mqs[&2].claim("t", LEASE, 10, 5).await.unwrap();
        assert_eq!(second.len(), 1, "redelivered on a different node");
        assert_eq!(
            second[0].attempts, 2,
            "attempt re-charged via replicated state"
        );

        shutdown(rafts).await;
    }

    /// Ack on any node removes the message cluster-wide (and frees its payload).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_ack_drains_everywhere() {
        let (rafts, mqs) = cluster_mq(3).await;
        mqs[&1].publish("t", b"x").await.unwrap();

        // Claim on a node, ack on another.
        let m = mqs[&2]
            .claim("t", LEASE, 10, 5)
            .await
            .unwrap()
            .pop()
            .unwrap();
        mqs[&3].ack(&m).await.unwrap();

        // Gone everywhere, even after the lease would lapse.
        assert!(mqs[&1]
            .claim("t", Duration::ZERO, 10, 5)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mqs[&1].backlog("t").await.unwrap(), 0);

        shutdown(rafts).await;
    }

    /// Dead-letter after `max_attempts`, decided in the replicated state machine.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_dead_letters_after_max_attempts() {
        let (rafts, mqs) = cluster_mq(3).await;
        mqs[&1].publish("t", b"x").await.unwrap();

        // max_attempts = 2: deliver twice (re-claim via zero lease), then the
        // third claim dead-letters instead of delivering a third time.
        for expected in 1..=2 {
            let m = mqs[&1].claim("t", Duration::ZERO, 10, 2).await.unwrap();
            assert_eq!(m.len(), 1, "attempt {expected}");
            assert_eq!(m[0].attempts, expected);
        }
        let exhausted = mqs[&2].claim("t", Duration::ZERO, 10, 2).await.unwrap();
        assert!(
            exhausted.is_empty(),
            "should dead-letter, not deliver again"
        );
        assert_eq!(mqs[&1].dead_letter_count("t").await.unwrap(), 1);
        assert_eq!(mqs[&1].backlog("t").await.unwrap(), 0);

        shutdown(rafts).await;
    }

    // ---- cross-mode conformance suite --------------------------------------
    //
    // The release gate: the *same* battery of assertions must hold for every
    // coordinator, since the guest-facing behavior contract is identical across
    // modes (only the single-writer coordinator differs). We run it against both
    // coordinators: single-node (`LogMessaging`) and cluster (`RaftMessaging`).
    // Cloudflare runs boatramp's cluster mode on Containers (docs/CLOUDFLARE.md),
    // so it uses *this same* `RaftMessaging` coordinator — there is no separate
    // CF coordinator to conform.

    /// Full publish → FIFO claim → lease → ack → nack → redeliver → dead-letter
    /// battery against any [`Messaging`] coordinator, on a fresh `topic`.
    async fn assert_conformance(mq: &dyn Messaging, topic: &str) {
        const LEASE: Duration = Duration::from_secs(60);

        // Publish three; backlog reflects them; claim preserves publish order
        // (best-effort FIFO) and charges attempt 1.
        for p in [b"a".as_slice(), b"b", b"c"] {
            mq.publish(topic, p).await.unwrap();
        }
        assert_eq!(mq.backlog(topic).await.unwrap(), 3);
        let batch = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(
            batch.iter().map(|m| m.payload.clone()).collect::<Vec<_>>(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "best-effort FIFO"
        );
        assert!(batch.iter().all(|m| m.attempts == 1));

        // Leased: a second claim sees nothing.
        assert!(mq.claim(topic, LEASE, 10, 5).await.unwrap().is_empty());

        // Ack removes one for good.
        mq.ack(&batch[0]).await.unwrap();
        assert_eq!(mq.backlog(topic).await.unwrap(), 2);

        // Nack makes `b` immediately claimable again (attempt re-charged);
        // `c` stays leased.
        mq.nack(&batch[1]).await.unwrap();
        let reclaim = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(reclaim.len(), 1);
        assert_eq!(reclaim[0].payload, b"b");
        assert_eq!(reclaim[0].attempts, 2);
        mq.ack(&reclaim[0]).await.unwrap();
        mq.ack(&batch[2]).await.unwrap();
        assert_eq!(mq.backlog(topic).await.unwrap(), 0);

        // Redelivery on lease expiry (zero lease), then dead-letter after
        // `max_attempts` rather than a further delivery.
        mq.publish(topic, b"z").await.unwrap();
        for expected in 1..=2 {
            let m = mq.claim(topic, Duration::ZERO, 10, 2).await.unwrap();
            assert_eq!(m.len(), 1, "attempt {expected}");
            assert_eq!(m[0].attempts, expected);
        }
        assert!(mq
            .claim(topic, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 1);
        assert_eq!(mq.backlog(topic).await.unwrap(), 0);

        // Redrive: the dead-lettered `z` returns to the live queue with its
        // payload preserved and a fresh attempt count; the DLQ empties.
        assert_eq!(mq.redrive_dead_letters(topic).await.unwrap(), 1);
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 0);
        assert_eq!(mq.backlog(topic).await.unwrap(), 1);
        let revived = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(revived.len(), 1);
        assert_eq!(revived[0].payload, b"z", "payload preserved across redrive");
        assert_eq!(revived[0].attempts, 1, "redrive resets the attempt count");
        mq.ack(&revived[0]).await.unwrap();
        assert_eq!(mq.backlog(topic).await.unwrap(), 0);

        // Purge: re-create a dead letter, then clear it — the DLQ empties and
        // nothing returns to the queue (and purge is idempotent).
        mq.publish(topic, b"poison").await.unwrap();
        for _ in 1..=2 {
            let _ = mq.claim(topic, Duration::ZERO, 10, 2).await.unwrap();
        }
        assert!(mq
            .claim(topic, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 1);
        assert_eq!(mq.purge_dead_letters(topic).await.unwrap(), 1);
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 0);
        assert_eq!(mq.backlog(topic).await.unwrap(), 0);
        assert_eq!(
            mq.purge_dead_letters(topic).await.unwrap(),
            0,
            "purge is idempotent"
        );
    }

    /// Conformance — **single-node** coordinator (`core::messaging::LogMessaging`).
    #[tokio::test]
    async fn conformance_single_node() {
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::messaging::LogMessaging;
        let mq = LogMessaging::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()));
        assert_conformance(&mq, "conformance/topic").await;
    }

    /// Conformance — **cluster** coordinator (`RaftMessaging`). Run on the leader
    /// node, whose locally-applied state is current (so backlog/DLQ reads are
    /// linearizable for the assertions), exercising the identical battery.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn conformance_cluster() {
        let (rafts, mqs) = cluster_mq(3).await;
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();
        assert_conformance(mqs[&leader].as_ref(), "conformance/topic").await;
        shutdown(rafts).await;
    }

    /// **Stream gate:** SSE fan-out crosses nodes. A client subscribed on one
    /// node receives events published on *any* node (peer-mesh broadcast into
    /// every node's local hubs).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_stream_fan_out_crosses_nodes() {
        let (rafts, mqs) = cluster_mq(3).await;

        // Subscribe on node 2; publish on the *other* nodes.
        let mut sub = mqs[&2].subscribe("events", None);

        mqs[&1].publish("events", b"from-node-1").await.unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(5), sub.next())
            .await
            .expect("event should arrive")
            .expect("stream is live");
        assert_eq!(ev.payload, b"from-node-1");

        mqs[&3].publish("events", b"from-node-3").await.unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(5), sub.next())
            .await
            .expect("event should arrive")
            .expect("stream is live");
        assert_eq!(ev.payload, b"from-node-3");

        // A different topic isn't delivered to this subscriber.
        mqs[&1].publish("other", b"nope").await.unwrap();
        mqs[&2].publish("events", b"local").await.unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(5), sub.next())
            .await
            .expect("event should arrive")
            .expect("stream is live");
        assert_eq!(ev.payload, b"local");

        shutdown(rafts).await;
    }
}
