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

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use boatramp_core::time::now_unix_ms;

use async_trait::async_trait;
use boatramp_core::messaging::{
    self, ClaimedMessage, DeadLetter, DeadLetterFilter, GroupInfo, Messaging, MessagingError,
    StreamHubs,
};
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

/// Group-commit (A2/A4): the soft per-turn budget of `MqPublish` ops coalesced into one
/// `WriteOp::Batch` proposal — so a burst of concurrent publishes (or one `publish_batch`) costs one
/// Raft round-trip per group, not one per message. Bounds ops (not jobs) so a large batch can't build
/// an unbounded Raft entry. Intentionally independent of the single-node cap
/// (`boatramp_core::messaging`'s `GROUP_COMMIT_MAX`): the two commit paths bound different resources
/// (one Raft entry vs one `write_batch`).
const GROUP_COMMIT_MAX: usize = 512;

/// The rendezvous-hashing (HRW) score of a `(topic, node)` pair (Phase D topic sharding): a **stable,
/// portable** hash (FNV-1a over the topic bytes mixed with the node id) — NOT [`std::hash`], whose
/// output is not guaranteed identical across builds/architectures, because every node in the cluster
/// MUST compute the identical scores to agree on the owner. The topic with the maximal score for a
/// node is owned by that node ([`RaftMessaging::hrw_owner`]).
fn hrw_score(topic: &str, node: NodeId) -> u64 {
    // FNV-1a 64-bit over the node id bytes then the topic bytes — deterministic and well-distributed.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for b in node.to_le_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    for b in topic.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
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
    /// Approximate inline-payload bytes this node has in-flight (A3/SA1 aggregate budget): once it
    /// reaches [`messaging::INLINE_INFLIGHT_MAX_BYTES`] a publish falls back to object storage, so a
    /// small-message flood can't grow the replicated Raft log/snapshots unbounded. Soft, per-node
    /// (only over-counts — the safe direction; a fully cluster-consistent cap would be a deterministic
    /// state-machine counter, a further hardening).
    inline_inflight_bytes: AtomicUsize,
    /// Group-commit (A2): publishers push their `MqPublish` op here, then take
    /// [`commit_gate`](Self::commit_gate); whoever holds the gate drains the queue and proposes ONE
    /// `WriteOp::Batch` — so N concurrent publishes cost one Raft round-trip, not N. Self-bounding
    /// (every pusher is a gate-waiter).
    commit_queue: StdMutex<Vec<ClusterPublishJob>>,
    /// The group-commit gate (A2): the single propose turn (see [`commit_queue`](Self::commit_queue)).
    commit_gate: futures::lock::Mutex<()>,
    /// Per-node per-topic publish **token bucket** (Feature B `max_rate_per_sec`, best-effort): the
    /// live `(tokens, last_refill_ms)` per rate-capped topic. Per-node by design (a cluster-wide exact
    /// rate would need a replicated counter on the hot path). Only touched by rate-capped topics.
    rate_buckets: StdMutex<std::collections::HashMap<String, ClusterTokenBucket>>,
    /// The fast-path delivery **wake** (event-driven delivery, Part A #2): fired AFTER a publish /
    /// nack / redrive proposal replicates+applies (B12) so this node's leader-gated drainer re-checks
    /// the ready-set promptly instead of waiting for the safety-net timer. Lossy — a missed pulse only
    /// costs latency (the durable, replicated ready-set + safety-net are the authority). In Phase A the
    /// drainer is leader-gated, so waking the local wake on the node that proposed (⇒ the leader that
    /// applied) reaches the draining node.
    wake: messaging::Wake,
    /// Unix-ms this node last completed a full [`rebuild_ready_set`](messaging::Messaging::rebuild_ready_set)
    /// pass, for the `last_rebuild_age_ms` delivery stat (B14). `0` = not yet rebuilt since start.
    last_rebuild_ms: AtomicU64,
}

/// A per-node per-topic token bucket for the best-effort publish rate cap (Feature B), refilling at
/// `max_rate_per_sec` tokens/sec (burst capped at the rate). Mirrors the single-node bucket.
#[derive(Debug, Clone, Copy)]
struct ClusterTokenBucket {
    tokens: f64,
    last_refill_ms: u64,
}

/// One publisher's contribution to a cluster group commit (A2/A4): its `MqPublish` op(s) + a
/// one-shot for the durable (replicated-and-applied) outcome. A single publish contributes one op;
/// a `publish_batch_ctx` contributes N in one job. The gate-holder flattens every job's ops into one
/// `WriteOp::Batch` proposal.
struct ClusterPublishJob {
    ops: Vec<WriteOp>,
    done: futures::channel::oneshot::Sender<Result<(), MessagingError>>,
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
            inline_inflight_bytes: AtomicUsize::new(0),
            commit_queue: StdMutex::new(Vec::new()),
            commit_gate: futures::lock::Mutex::new(()),
            rate_buckets: StdMutex::new(std::collections::HashMap::new()),
            wake: messaging::Wake::new(),
            last_rebuild_ms: AtomicU64::new(0),
        }
    }

    /// Resolve `topic`'s operator [`messaging::TopicPolicy`] (Feature A) by reading this node's
    /// applied state (`mqpolicy/{topic}`) directly — NO cache. Deliberately uncached on the cluster:
    /// the read is an in-memory applied-state lookup, and a publish already pays a Raft round-trip
    /// that dwarfs it, so caching buys nothing but a correctness hazard — a per-node cache would not
    /// see a policy set/changed on ANOTHER node (the operator call can land on any node) until that
    /// node restarted, silently under-enforcing a just-set cap. Reading applied state per publish is
    /// always current fleet-wide (the policy store is replicated). A decode error propagates (the
    /// publish path fails closed rather than treating an unreadable policy as "no cap").
    async fn resolve_policy(
        &self,
        topic: &str,
    ) -> Result<Option<messaging::TopicPolicy>, MessagingError> {
        match self.state.get(&messaging::mqpolicy_key(topic)).await {
            Some(raw) => Ok(Some(
                serde_json::from_slice::<messaging::TopicPolicy>(&raw)
                    .map_err(|e| MessagingError::Decode(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Enforce a resolved policy against a publish of `n` messages onto `topic` (Feature B), BEFORE
    /// proposing anything. Fail-closed in order: (1) `max_depth` — reject with
    /// [`MessagingError::DepthExceeded`] if the current backlog is already at the cap (only queried
    /// when a cap is set — an uncapped topic never reads the backlog); (2) `max_rate_per_sec` — a
    /// per-node token bucket, reject with [`MessagingError::RateExceeded`]. `max_unflushed` is inert
    /// on the cluster (its durability is replication, a different axis).
    async fn enforce_publish_policy(
        &self,
        topic: &str,
        policy: &messaging::TopicPolicy,
        n: usize,
    ) -> Result<(), MessagingError> {
        if let Some(max_depth) = policy.max_depth {
            let backlog = self.backlog(topic).await?;
            if backlog >= max_depth {
                return Err(MessagingError::DepthExceeded(topic.to_string()));
            }
        }
        if let Some(rate) = policy.max_rate_per_sec {
            if !self.try_take_tokens(topic, rate, n) {
                return Err(MessagingError::RateExceeded(topic.to_string()));
            }
        }
        Ok(())
    }

    /// Resolve `topic`'s policy (cached) and enforce depth/rate for `n` messages (Feature B). A
    /// `None` policy (the common case) is a no-op. Shared front half of every publish variant.
    async fn enforce_topic_policy(&self, topic: &str, n: usize) -> Result<(), MessagingError> {
        if let Some(p) = self.resolve_policy(topic).await? {
            self.enforce_publish_policy(topic, &p, n).await?;
        }
        Ok(())
    }

    /// Draw `n` tokens from `topic`'s per-node bucket, refilling at `rate` tokens/sec since the last
    /// draw (burst capped at `rate`). A fresh bucket starts full. Best-effort, per-node.
    fn try_take_tokens(&self, topic: &str, rate: u32, n: usize) -> bool {
        let now = now_unix_ms();
        let cap = f64::from(rate);
        let mut buckets = self.rate_buckets.lock().unwrap();
        let bucket = buckets
            .entry(topic.to_string())
            .or_insert(ClusterTokenBucket {
                tokens: cap,
                last_refill_ms: now,
            });
        let elapsed_ms = now.saturating_sub(bucket.last_refill_ms);
        if elapsed_ms > 0 {
            bucket.tokens = (bucket.tokens + (elapsed_ms as f64) * cap / 1000.0).min(cap);
            bucket.last_refill_ms = now;
        }
        let need = n as f64;
        if bucket.tokens >= need {
            bucket.tokens -= need;
            true
        } else {
            false
        }
    }

    /// Group-commit a publisher's `MqPublish` op(s) (A2/A4): push them, take the gate, and — as the
    /// gate-holder — drain the queue and propose EVERYONE's ops in one `WriteOp::Batch` (one Raft
    /// round-trip), signalling each. A publisher flushed by an earlier gate-holder finds its one-shot
    /// already resolved. Returns only after the group is replicated + applied (at-least-once); a
    /// failed proposal fails every member. Same self-bounded, no-spawn pattern as
    /// `LogMessaging::group_commit`.
    async fn group_commit(&self, ops: Vec<WriteOp>) -> Result<(), MessagingError> {
        use futures::future::{select, Either};
        let (done_tx, mut done_rx) = futures::channel::oneshot::channel();
        self.commit_queue
            .lock()
            .unwrap()
            .push(ClusterPublishJob { ops, done: done_tx });
        // Leader-only gate (mirrors `LogMessaging::group_commit`): a waiter awaits its durable ack
        // WITHOUT taking the gate, so concurrent publishes pile up during the in-flight Raft propose
        // and the leader's drain loop coalesces them into ONE `WriteOp::Batch`. A Raft round-trip is
        // even costlier than a local flush, so steady-state coalescing matters more here. The `select`
        // closes the only stranding race — a publisher either wins the gate (leader, proposes its own
        // job) or its `done` fires first (a leader proposed it); it can never both-miss.
        let gate = self.commit_gate.lock();
        futures::pin_mut!(gate);
        match select(gate, &mut done_rx).await {
            // The current leader replicated our job while we waited — done.
            Either::Right((res, _gate)) => {
                return res.map_err(|_| {
                    MessagingError::Backend("group-commit dropped before durable".into())
                })?
            }
            // We hold the gate: drain + propose in a loop until the queue is empty, so a job pushed
            // during our propose (even after a prior empty check) is never stranded.
            Either::Left((_turn, _done)) => loop {
                // Drain jobs until the per-commit OP budget is met (a batch job carries many ops, so
                // the bound is on ops, not jobs — else one turn could build an unbounded Raft entry).
                // Always take at least one so an oversized single batch (host-bounded by
                // PUBLISH_BATCH_MAX) still makes progress.
                let batch: Vec<ClusterPublishJob> = {
                    let mut q = self.commit_queue.lock().unwrap();
                    if q.is_empty() {
                        break;
                    }
                    let mut n = 0;
                    let mut count = 0;
                    while n < q.len() {
                        if n > 0 && count + q[n].ops.len() > GROUP_COMMIT_MAX {
                            break;
                        }
                        count += q[n].ops.len();
                        n += 1;
                    }
                    q.drain(..n).collect()
                };
                let mut ops = Vec::with_capacity(batch.len());
                let mut dones = Vec::with_capacity(batch.len());
                for mut job in batch {
                    ops.append(&mut job.ops);
                    dones.push(job.done);
                }
                // A proposal can fail AFTER the entry actually committed+applied (leader lost, or the
                // forwarder timed out on the reply). That surfaces here as `Err` for a group that in
                // fact committed — a false NEGATIVE, which is the at-least-once-safe direction: the
                // caller may retry and produce a tolerable duplicate. Never invert this into a false
                // positive (Ok on an uncommitted group).
                let outcome = self.propose(WriteOp::Batch(ops)).await.map(|_| ());
                // Event-driven delivery (B12): the batch (with its ready markers) is now replicated +
                // applied — wake this node's drainer. Fired only on the success path; a failed propose
                // is retried by the caller and its later success wakes then. Lossy + harmless.
                if outcome.is_ok() {
                    self.wake.notify();
                }
                for done in dones {
                    // Clone the shared outcome to every member (fail-all on a failed proposal).
                    let _ = done.send(outcome.clone());
                }
            },
        }
        done_rx
            .await
            .map_err(|_| MessagingError::Backend("group-commit dropped before durable".into()))?
    }

    /// Mint a globally-unique, ≈time-ordered message id. The millis prefix keeps
    /// lexical order ≈ publish order; the node id + per-node sequence guarantee
    /// two nodes publishing in the same millisecond never collide.
    fn next_id(&self) -> String {
        format!(
            "{:013}-{:016x}-{:016x}",
            now_unix_ms(),
            self.node_id,
            self.seq.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Phase D — the topic's **shard owner** under rendezvous (HRW) hashing over the applied voter
    /// set: the node whose `hrw_score(topic, node)` is maximal (ties broken by the larger node id, a
    /// total order so every node computes the identical winner). `None` when the voter set is empty
    /// (unsharded — the caller treats this node as owning everything). Rendezvous hashing gives
    /// MINIMAL reassignment on a join/leave (only ~`1/N` of topics move), so a membership change
    /// reshuffles as little of the topic space as possible. Pure + deterministic (no clock, no live
    /// metrics) so it is safe to recompute per drain cycle and agrees fleet-wide (B8).
    fn hrw_owner(topic: &str, voters: &[NodeId]) -> Option<NodeId> {
        voters.iter().copied().max_by(|&a, &b| {
            hrw_score(topic, a)
                .cmp(&hrw_score(topic, b))
                .then(a.cmp(&b))
        })
    }

    /// Build one message's replicated `MqPublish` op, performing any object-store payload write FIRST
    /// (payload-first: the replicated record never references a missing payload). Shared by
    /// [`publish_ctx`](Messaging::publish_ctx) (single) and
    /// [`publish_batch_ctx`](Messaging::publish_batch_ctx) (A4 batch) so both take the identical
    /// A3-inline / SA1-budget / grouped-retain decisions. Returns the minted id (for the post-commit
    /// broadcast) + the op the caller's group-commit will propose.
    async fn build_publish_op(
        &self,
        topic: &str,
        payload: &[u8],
        signed_context: Option<&str>,
        not_before_ms: u64,
        expires_at_ms: u64,
        priority: u8,
    ) -> Result<(String, WriteOp), MessagingError> {
        let id = self.next_id();
        let retain = self.topic_has_groups(topic).await;
        // A3: a small work-queue payload rides IN the replicated index record (via the proposal
        // below) — no object-store write, no round-trip. Only work-queue (grouped keeps the shared
        // object every group reads) and only up to `INLINE_MAX` (larger ⇒ object store). Otherwise:
        // payload to shared storage FIRST, then the index proposal — the replicated record never
        // references a missing payload.
        // SA1: only inline while under the aggregate in-flight budget (past it, object-store path),
        // so a small-message flood can't grow the replicated log/snapshots unbounded.
        let inline = !retain
            && payload.len() <= messaging::INLINE_MAX
            && self
                .inline_inflight_bytes
                .load(Ordering::Relaxed)
                .saturating_add(payload.len())
                <= messaging::INLINE_INFLIGHT_MAX_BYTES;
        if inline {
            self.inline_inflight_bytes
                .fetch_add(payload.len(), Ordering::Relaxed);
        }
        if !inline {
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
        }
        // On a grouped topic, also write the **retained** fan-out payload before
        // proposing, so the replicated `glog` entry (written in the same proposal
        // when `retain`) never references a missing payload — the same
        // payload-first invariant, split across `Storage` (here) and the log.
        if retain {
            let bytes = bytes::Bytes::copy_from_slice(payload);
            let body = futures::stream::once(async move { Ok(bytes) }).boxed();
            self.storage
                .put(
                    &messaging::gpayload_key(topic, &id),
                    body,
                    PutMeta::default(),
                )
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
        }
        Ok((
            id.clone(),
            WriteOp::MqPublish {
                topic: topic.to_string(),
                id,
                retain,
                signed_context: signed_context.map(str::to_owned),
                inline: inline.then(|| payload.to_vec()),
                not_before_ms,
                expires_at_ms,
                priority,
            },
        ))
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
        self.read_storage(&messaging::payload_key(topic, id)).await
    }

    /// Read a retained fan-out (consumer-group) payload from the shared store.
    async fn read_gpayload(&self, topic: &str, id: &str) -> Result<Vec<u8>, MessagingError> {
        self.read_storage(&messaging::gpayload_key(topic, id)).await
    }

    /// Read + drain a shared-store object into memory.
    async fn read_storage(&self, key: &str) -> Result<Vec<u8>, MessagingError> {
        let object = self
            .storage
            .get(key)
            .await
            .map_err(|e| MessagingError::Backend(e.to_string()))?;
        let mut body = object.body;
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.map_err(|e| MessagingError::Backend(e.to_string()))?);
        }
        Ok(buf)
    }

    /// Whether `topic` has ≥1 registered consumer group, read from this node's
    /// applied state. A publisher uses this to decide whether to **retain** the
    /// fan-out log/payload. It can lag a just-committed registration on a follower;
    /// in the fabric's register-then-publish usage the window is narrow, and the
    /// publisher passes the same decision into the proposal so the replicated log
    /// entry and the `Storage` payload always agree (no dangling log entry).
    async fn topic_has_groups(&self, topic: &str) -> bool {
        let prefix = messaging::gstate_prefix(topic);
        self.state
            .list_prefix(&prefix)
            .await
            .iter()
            .any(|k| messaging::is_direct_child(k, &prefix))
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

    /// `topic`'s grouped (fan-out) dead-letters as `(group, id)`, read from this node's applied
    /// state (`mqgd/{topic}/{group}/{id}`). The work-queue `dead_ids` above and this together are
    /// the full DLQ; before this both count/purge/redrive saw only the work-queue keyspace.
    async fn grouped_dead(&self, topic: &str) -> Vec<(String, String)> {
        let prefix = messaging::gdead_topic_prefix(topic);
        self.state
            .list_prefix(&prefix)
            .await
            .into_iter()
            .filter_map(|k| {
                messaging::split_group_id(&k[prefix.len()..])
                    .map(|(g, i)| (g.to_string(), i.to_string()))
            })
            .collect()
    }

    /// Read every dead-letter on `topic` from this node's applied state as [`DeadLetter`] METADATA
    /// (no payload) across BOTH lanes, id-ordered — the shared read path behind the selective DLQ
    /// list/redrive/discard (P1). Payloads are loaded lazily by `show_dead_letter`.
    async fn collect_dead_letters(&self, topic: &str) -> Vec<DeadLetter> {
        let mut out = Vec::new();
        let wq_prefix = messaging::dead_prefix(topic);
        for key in self.state.list_prefix(&wq_prefix).await {
            if !messaging::is_direct_child(&key, &wq_prefix) {
                continue;
            }
            let Some(raw) = self.state.get(&key).await else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<messaging::Record>(&raw) else {
                continue;
            };
            out.push(DeadLetter {
                id: key[wq_prefix.len()..].to_string(),
                group: String::new(),
                attempts: record.attempts,
                last_error: record.last_error,
                signed_context: record.signed_context,
                payload: None,
            });
        }
        let gprefix = messaging::gdead_topic_prefix(topic);
        for key in self.state.list_prefix(&gprefix).await {
            let Some((group, id)) = messaging::split_group_id(&key[gprefix.len()..]) else {
                continue;
            };
            let Some(raw) = self.state.get(&key).await else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<messaging::Record>(&raw) else {
                continue;
            };
            out.push(DeadLetter {
                id: id.to_string(),
                group: group.to_string(),
                attempts: record.attempts,
                last_error: record.last_error,
                signed_context: record.signed_context,
                payload: None,
            });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

#[async_trait]
impl Messaging for RaftMessaging {
    async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError> {
        self.publish_ctx(topic, payload, None).await
    }

    async fn publish_ctx(
        &self,
        topic: &str,
        payload: &[u8],
        signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        // Feature B: enforce the topic's operator policy (depth/rate) BEFORE building/proposing —
        // a breach rejects the publish with nothing replicated. (`max_unflushed` is inert here: the
        // cluster's durability is replication, not the single-node relaxed-flush axis.)
        self.enforce_topic_policy(topic, 1).await?;
        // Build this message's replicated `MqPublish` op (doing any object-store payload write first),
        // then commit it in one group-commit. Factored so `publish_batch_ctx` reuses the identical
        // A3/SA1/retain decisions and coalesces N messages into one Raft entry.
        let (id, op) = self
            .build_publish_op(topic, payload, signed_context, 0, 0, 0)
            .await?;
        // Group-commit (A2): coalesce this MqPublish with other concurrent ones into a single
        // WriteOp::Batch proposal (one Raft round-trip per group). Returns only after the group is
        // replicated + applied (at-least-once); a failed proposal fails this publish too.
        self.group_commit(vec![op]).await?;
        // Live SSE fan-out across the cluster (best-effort, separate from the
        // durable queue): every node's hubs, including this one's.
        self.bus.broadcast(topic, &id, payload);
        Ok(())
    }

    async fn publish_delayed_ctx(
        &self,
        topic: &str,
        payload: &[u8],
        delay: Duration,
        signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        // Feature B: enforce the topic's operator policy (depth/rate) before proposing.
        self.enforce_topic_policy(topic, 1).await?;
        // Delivery-mode delay (P2): the issuing node stamps the absolute not-before (deterministic
        // across replicas — the apply just copies it into the record's lease). 0 ⇒ claimable now.
        let not_before_ms = if delay.is_zero() {
            0
        } else {
            now_unix_ms().saturating_add(delay.as_millis() as u64)
        };
        let (id, op) = self
            .build_publish_op(topic, payload, signed_context, not_before_ms, 0, 0)
            .await?;
        self.group_commit(vec![op]).await?;
        self.bus.broadcast(topic, &id, payload);
        Ok(())
    }

    async fn publish_with_ttl_ctx(
        &self,
        topic: &str,
        payload: &[u8],
        ttl: Duration,
        signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        // Feature B: enforce the topic's operator policy (depth/rate) before proposing.
        self.enforce_topic_policy(topic, 1).await?;
        // Delivery-mode TTL (P2): the issuing node stamps the absolute expires-at (deterministic).
        // 0 ⇒ no expiry. A claim after expiry dead-letters it (ttl-expired) instead of delivering.
        let expires_at_ms = if ttl.is_zero() {
            0
        } else {
            now_unix_ms().saturating_add(ttl.as_millis() as u64)
        };
        let (id, op) = self
            .build_publish_op(topic, payload, signed_context, 0, expires_at_ms, 0)
            .await?;
        self.group_commit(vec![op]).await?;
        self.bus.broadcast(topic, &id, payload);
        Ok(())
    }

    async fn publish_with_priority_ctx(
        &self,
        topic: &str,
        payload: &[u8],
        priority: u8,
        signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        // Feature B: enforce the topic's operator policy (depth/rate) before proposing.
        self.enforce_topic_policy(topic, 1).await?;
        // Delivery-mode priority (P2): higher leases first (ties FIFO); 0 = normal. Work-queue only.
        let (id, op) = self
            .build_publish_op(topic, payload, signed_context, 0, 0, priority)
            .await?;
        self.group_commit(vec![op]).await?;
        self.bus.broadcast(topic, &id, payload);
        Ok(())
    }

    async fn publish_batch_ctx(
        &self,
        messages: &[(String, Vec<u8>)],
        signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        if messages.is_empty() {
            return Ok(());
        }
        // Feature B — enforce each distinct topic's policy ONCE for the count of messages the batch
        // carries on it (fail-closed: a breach returns before we build/propose, so NOTHING in the
        // batch is replicated). Most topics have no policy → one cached resolve per distinct topic.
        let mut per_topic_count: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for (topic, _) in messages {
            *per_topic_count.entry(topic.as_str()).or_insert(0) += 1;
        }
        for (topic, count) in &per_topic_count {
            self.enforce_topic_policy(topic, *count).await?;
        }
        // A4 — coalesce the WHOLE batch into ONE replicated `WriteOp::Batch`: build every message's
        // `MqPublish` op (each doing its own payload-first object-store write + A3/SA1 decision), then
        // a single `group_commit`. Fail-all: any build error returns before we commit, so no message
        // in the batch is delivered. Every message shares the one host-minted `signed_context`.
        let mut ops = Vec::with_capacity(messages.len());
        let mut broadcasts: Vec<(&str, String, &[u8])> = Vec::with_capacity(messages.len());
        for (topic, payload) in messages {
            let (id, op) = self
                .build_publish_op(topic, payload, signed_context, 0, 0, 0)
                .await?;
            ops.push(op);
            broadcasts.push((topic.as_str(), id, payload.as_slice()));
        }
        self.group_commit(ops).await?;
        for (topic, id, payload) in &broadcasts {
            self.bus.broadcast(topic, id, payload);
        }
        Ok(())
    }

    async fn claim(
        &self,
        topic: &str,
        lease: Duration,
        max_batch: usize,
        max_attempts: u32,
    ) -> Result<Vec<ClaimedMessage>, MessagingError> {
        // Flow control (P2): a paused topic delivers nothing. Soft operator signal — checked against
        // this node's applied state before the claim proposal (publish + in-flight ack/nack flow on).
        if self.is_paused(topic).await? {
            return Ok(Vec::new());
        }
        // The claim is one Raft proposal: the leader applies it atomically, so a
        // message is leased to exactly one claimer cluster-wide. The issuing
        // node stamps `now_ms` so every replica applies the same transition.
        let response = self
            .propose(WriteOp::MqClaim {
                topic: topic.to_string(),
                now_ms: now_unix_ms(),
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
        // Deliver each: an A3-inlined payload came back IN the claim response (it lives in the
        // replicated record, not object storage); otherwise fetch from the shared store.
        let mut claimed = Vec::with_capacity(records.len());
        for record in records {
            let inline = record.inline.is_some();
            let payload = match record.inline {
                Some(bytes) => bytes,
                None => self.read_payload(topic, &record.id).await?,
            };
            claimed.push(ClaimedMessage {
                id: record.id,
                topic: topic.to_string(),
                payload,
                attempts: record.attempts,
                // The default work-queue group; a non-empty group goes through
                // `claim_grouped` below.
                group: String::new(),
                signed_context: record.signed_context,
                inline,
            });
        }
        Ok(claimed)
    }

    async fn claim_grouped(
        &self,
        topic: &str,
        group: &str,
        start: messaging::StartPosition,
        lease: Duration,
        max_batch: usize,
        max_attempts: u32,
    ) -> Result<Vec<ClaimedMessage>, MessagingError> {
        // The default group is the work-queue path (unchanged).
        if group.is_empty() {
            return self.claim(topic, lease, max_batch, max_attempts).await;
        }
        // Flow control (P2): a paused topic delivers nothing to any group.
        if self.is_paused(topic).await? {
            return Ok(Vec::new());
        }
        // One Raft proposal: the leader applies the shared offset-log decision over
        // the group's replicated state, so a message is leased to exactly one
        // claimer of this group cluster-wide. The issuing node stamps `now_ms`.
        let response = self
            .propose(WriteOp::MqClaimGrouped {
                topic: topic.to_string(),
                group: group.to_string(),
                start,
                now_ms: now_unix_ms(),
                lease_ms: lease.as_millis() as u64,
                max_batch: max_batch as u32,
                max_attempts,
            })
            .await?;
        let WriteResponse::Claimed(records) = response else {
            return Err(MessagingError::Backend(
                "grouped claim proposal returned a non-claim response".into(),
            ));
        };
        // Fetch retained fan-out payloads from the shared store. One that is
        // unexpectedly absent is skipped this round (it stays leased in the
        // replicated state and redelivers on lease expiry) — never delivered empty.
        let mut claimed = Vec::with_capacity(records.len());
        for record in records {
            match self.read_gpayload(topic, &record.id).await {
                Ok(payload) => claimed.push(ClaimedMessage {
                    id: record.id,
                    topic: topic.to_string(),
                    payload,
                    attempts: record.attempts,
                    group: group.to_string(),
                    signed_context: record.signed_context,
                    // Grouped payloads are always object-store retained, never inlined.
                    inline: false,
                }),
                Err(_) => continue,
            }
        }
        Ok(claimed)
    }

    async fn ack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
        // A grouped ack drops only this group's in-flight entry (the retained
        // payload stays for the other groups until the sweep reclaims it).
        if !msg.group.is_empty() {
            self.propose(WriteOp::MqAckGrouped {
                topic: msg.topic.clone(),
                group: msg.group.clone(),
                id: msg.id.clone(),
            })
            .await?;
            return Ok(());
        }
        // Work-queue: drop the index record first (no longer claimable), then the payload — unless
        // the payload was A3-inlined in that record (nothing in object storage to delete).
        self.propose(WriteOp::MqAck {
            topic: msg.topic.clone(),
            id: msg.id.clone(),
        })
        .await?;
        if msg.inline {
            // Release the inline bytes from the SA1 budget (saturating — never wrap on a post-restart
            // ack of a pre-restart inline message).
            let _ = self.inline_inflight_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| Some(v.saturating_sub(msg.payload.len())),
            );
        } else {
            self.storage
                .delete(&messaging::payload_key(&msg.topic, &msg.id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    async fn nack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
        self.nack_after(msg, 0).await
    }

    async fn nack_after(&self, msg: &ClaimedMessage, delay_ms: u64) -> Result<(), MessagingError> {
        // The leader stamps the absolute backoff deadline (now + delay) into the proposal so every
        // replica applies the identical lease (the state machine reads no clock) — same discipline as
        // the delayed/TTL publish stamping. 0 ⇒ claimable now (plain nack).
        let until_ms = if delay_ms == 0 {
            0
        } else {
            now_unix_ms().saturating_add(delay_ms)
        };
        if !msg.group.is_empty() {
            self.propose(WriteOp::MqNackGrouped {
                topic: msg.topic.clone(),
                group: msg.group.clone(),
                id: msg.id.clone(),
                until_ms,
            })
            .await?;
            // Event-driven delivery (B12): the nack re-armed the topic's ready marker (in the apply) —
            // wake this node's drainer so it revisits promptly (the due-heap covers a future `until_ms`).
            self.wake.notify();
            return Ok(());
        }
        self.propose(WriteOp::MqNack {
            topic: msg.topic.clone(),
            id: msg.id.clone(),
            until_ms,
        })
        .await?;
        self.wake.notify(); // ready marker re-armed in the apply (B12) — wake the drainer
        Ok(())
    }

    async fn backlog(&self, topic: &str) -> Result<usize, MessagingError> {
        Ok(self.count_direct(&messaging::meta_prefix(topic)).await)
    }

    async fn oldest_pending_ms(&self, topic: &str) -> Result<Option<u64>, MessagingError> {
        // Earliest live work-queue id from this node's applied state (list_prefix is sorted).
        let prefix = messaging::meta_prefix(topic);
        let oldest = self
            .state
            .list_prefix(&prefix)
            .await
            .into_iter()
            .filter(|k| messaging::is_direct_child(k, &prefix))
            .map(|k| messaging::id_millis(&k[prefix.len()..]))
            .min();
        Ok(oldest.map(|ms| now_unix_ms().saturating_sub(ms)))
    }

    async fn in_flight_count(&self, topic: &str) -> Result<usize, MessagingError> {
        let now = now_unix_ms();
        let mut count = 0;
        // Work-queue: records currently leased (from this node's applied state).
        let prefix = messaging::meta_prefix(topic);
        for key in self.state.list_prefix(&prefix).await {
            if !messaging::is_direct_child(&key, &prefix) {
                continue;
            }
            if let Some(raw) = self.state.get(&key).await {
                if let Ok(rec) = serde_json::from_slice::<messaging::Record>(&raw) {
                    if rec.lease_until_ms > now {
                        count += 1;
                    }
                }
            }
        }
        // Grouped: every registered group's currently-leased in-flight entries.
        let gprefix = messaging::gstate_prefix(topic);
        for key in self.state.list_prefix(&gprefix).await {
            if !messaging::is_direct_child(&key, &gprefix) {
                continue;
            }
            if let Some(raw) = self.state.get(&key).await {
                if let Ok(state) = serde_json::from_slice::<messaging::GroupState>(&raw) {
                    count += state
                        .in_flight
                        .iter()
                        .filter(|f| f.lease_until_ms > now)
                        .count();
                }
            }
        }
        Ok(count)
    }

    async fn group_lag(&self, topic: &str, group: &str) -> Result<usize, MessagingError> {
        let Some(raw) = self.state.get(&messaging::gstate_key(topic, group)).await else {
            return Ok(0);
        };
        let Ok(state) = serde_json::from_slice::<messaging::GroupState>(&raw) else {
            return Ok(0);
        };
        // Retained log ids strictly beyond the group's high-water (not-yet-leased for this group).
        let prefix = messaging::glog_prefix(topic);
        let lag = self
            .state
            .list_prefix(&prefix)
            .await
            .into_iter()
            .filter(|k| messaging::is_direct_child(k, &prefix) && k[prefix.len()..] > *state.hwm)
            .count();
        Ok(lag)
    }

    async fn dead_letter_count(&self, topic: &str) -> Result<usize, MessagingError> {
        // Work-queue dead-letters PLUS every consumer group's dead-letters — before this a fan-out
        // consumer's poison messages reported 0 (they live under `mqgd/…`, not `mqdead/…`).
        Ok(self.count_direct(&messaging::dead_prefix(topic)).await
            + self.grouped_dead(topic).await.len())
    }

    async fn purge_dead_letters(&self, topic: &str) -> Result<usize, MessagingError> {
        let ids = self.dead_ids(topic).await;
        let grouped = self.grouped_dead(topic).await;
        if ids.is_empty() && grouped.is_empty() {
            return Ok(0);
        }
        // Replicate the dead-record deletes in one proposal (the index is the Raft state machine).
        // Work-queue: also drop the preserved payload from shared storage. Grouped: delete only the
        // dead record — that un-pins the shared retained payload for the retention sweep, which
        // reclaims it once no group needs it (other groups may still be consuming that message).
        // Classify each work-queue dead record BEFORE the delete proposal removes it: an inline one
        // carried its payload in the record (no object to free) and its bytes are still charged to
        // the SA1 aggregate-inline budget; a non-inline one has an object-store payload to delete.
        let mut inline_release = 0usize;
        let mut object_ids: Vec<String> = Vec::new();
        for id in &ids {
            let inline_len = self
                .state
                .get(&messaging::dead_key(topic, id))
                .await
                .and_then(|raw| serde_json::from_slice::<messaging::Record>(&raw).ok())
                .and_then(|r| r.inline.map(|p| p.len()));
            match inline_len {
                Some(len) => inline_release += len,
                None => object_ids.push(id.clone()),
            }
        }
        let mut deletes: Vec<WriteOp> = ids
            .iter()
            .map(|id| WriteOp::Delete {
                key: messaging::dead_key(topic, id),
            })
            .collect();
        for (group, id) in &grouped {
            deletes.push(WriteOp::Delete {
                key: messaging::gdead_key(topic, group, id),
            });
        }
        self.propose(WriteOp::Batch(deletes)).await?;
        for id in &object_ids {
            self.storage
                .delete(&messaging::payload_key(topic, id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
        }
        // C2: release the purged inline dead-letters' bytes from the SA1 budget (saturating).
        if inline_release > 0 {
            let _ = self.inline_inflight_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| Some(v.saturating_sub(inline_release)),
            );
        }
        Ok(ids.len() + grouped.len())
    }

    async fn redrive_dead_letters(&self, topic: &str) -> Result<usize, MessagingError> {
        let ids = self.dead_ids(topic).await;
        let grouped = self.grouped_dead(topic).await;
        if ids.is_empty() && grouped.is_empty() {
            return Ok(0);
        }
        // Work-queue: re-arm the index record (`MqPublish` is idempotent, the meta key was removed
        // at dead-letter time) and drop the dead record, atomically in one batch. Carry the dead
        // record's signed-context AND its A3-inlined payload forward — reading the preserved record
        // (deterministic applied state) both gives an inline message its body back (it lived in the
        // record, not object storage) and closes the prior context-parity gap with single-node.
        // Grouped: re-arm the id in its group's in-flight + drop the dead record (its retained
        // payload/log was pinned by the dead-letter against the sweep).
        let mut ops: Vec<WriteOp> = Vec::with_capacity(ids.len() * 2 + grouped.len());
        for id in &ids {
            let (signed_context, inline) = self
                .state
                .get(&messaging::dead_key(topic, id))
                .await
                .and_then(|raw| serde_json::from_slice::<messaging::Record>(&raw).ok())
                .map(|r| (r.signed_context, r.inline))
                .unwrap_or((None, None));
            ops.push(WriteOp::MqPublish {
                topic: topic.to_string(),
                id: id.clone(),
                retain: false,
                signed_context,
                inline,
                not_before_ms: 0, // redrive re-arms immediately claimable
                expires_at_ms: 0, // and clears any TTL (an operator redrive is a deliberate retry)
                priority: 0,      // redriven at normal priority
            });
            ops.push(WriteOp::Delete {
                key: messaging::dead_key(topic, id),
            });
        }
        for (group, id) in &grouped {
            ops.push(WriteOp::MqRedriveGroupedDead {
                topic: topic.to_string(),
                group: group.clone(),
                id: id.clone(),
            });
        }
        if !ops.is_empty() {
            self.propose(WriteOp::Batch(ops)).await?;
            self.wake.notify(); // redriven messages are claimable again (markers re-armed) — wake (B12)
        }
        Ok(ids.len() + grouped.len())
    }

    async fn set_last_error(
        &self,
        msg: &ClaimedMessage,
        reason: &str,
    ) -> Result<(), MessagingError> {
        // Grouped last_error capture is a follow-up; the work-queue lane records it today. Replicated
        // via a deterministic read-modify-write op (the reason is sanitized+bounded here, so every
        // replica applies identical bytes).
        if !msg.group.is_empty() {
            return Ok(());
        }
        self.propose(WriteOp::MqSetLastError {
            topic: msg.topic.clone(),
            id: msg.id.clone(),
            reason: messaging::sanitize_reason(reason),
        })
        .await?;
        Ok(())
    }

    async fn list_dead_letters(
        &self,
        topic: &str,
        filter: &DeadLetterFilter,
    ) -> Result<Vec<DeadLetter>, MessagingError> {
        let now = now_unix_ms();
        let mut matched: Vec<DeadLetter> = self
            .collect_dead_letters(topic)
            .await
            .into_iter()
            .filter(|dl| filter.matches(dl, now))
            .collect();
        if let Some(limit) = filter.limit {
            matched.truncate(limit);
        }
        Ok(matched)
    }

    async fn show_dead_letter(
        &self,
        topic: &str,
        group: &str,
        id: &str,
    ) -> Result<Option<DeadLetter>, MessagingError> {
        let key = if group.is_empty() {
            messaging::dead_key(topic, id)
        } else {
            messaging::gdead_key(topic, group, id)
        };
        let Some(raw) = self.state.get(&key).await else {
            return Ok(None);
        };
        let record: messaging::Record =
            serde_json::from_slice(&raw).map_err(|e| MessagingError::Backend(e.to_string()))?;
        // Payload: inlined bodies ride in the record (A3); otherwise the object-store copy (work-queue
        // `payload_key`, or the shared grouped `gpayload_key` pinned by this dead-letter). A missing
        // object yields an empty body rather than failing the inspection.
        let payload = if let Some(inline) = record.inline.clone() {
            inline
        } else if group.is_empty() {
            self.read_payload(topic, id).await.unwrap_or_default()
        } else {
            self.read_gpayload(topic, id).await.unwrap_or_default()
        };
        Ok(Some(DeadLetter {
            id: id.to_string(),
            group: group.to_string(),
            attempts: record.attempts,
            last_error: record.last_error,
            signed_context: record.signed_context,
            payload: Some(payload),
        }))
    }

    async fn redrive_dead_letters_filtered(
        &self,
        topic: &str,
        filter: &DeadLetterFilter,
    ) -> Result<usize, MessagingError> {
        let now = now_unix_ms();
        let mut matched: Vec<DeadLetter> = self
            .collect_dead_letters(topic)
            .await
            .into_iter()
            .filter(|dl| filter.matches(dl, now))
            .collect();
        if let Some(limit) = filter.limit {
            matched.truncate(limit);
        }
        if matched.is_empty() {
            return Ok(0);
        }
        // Same re-arm semantics as the whole-DLQ redrive, but only for the matching ids: work-queue =
        // re-arm the idempotent `MqPublish` (carrying the preserved signed-context + inline payload)
        // + drop the dead record; grouped = `MqRedriveGroupedDead`. One replicated batch.
        let mut ops: Vec<WriteOp> = Vec::with_capacity(matched.len() * 2);
        for dl in &matched {
            if dl.group.is_empty() {
                let (signed_context, inline) = self
                    .state
                    .get(&messaging::dead_key(topic, &dl.id))
                    .await
                    .and_then(|raw| serde_json::from_slice::<messaging::Record>(&raw).ok())
                    .map(|r| (r.signed_context, r.inline))
                    .unwrap_or((None, None));
                ops.push(WriteOp::MqPublish {
                    topic: topic.to_string(),
                    id: dl.id.clone(),
                    retain: false,
                    signed_context,
                    inline,
                    not_before_ms: 0, // redrive re-arms immediately claimable
                    expires_at_ms: 0, // and clears any TTL (an operator redrive is a deliberate retry)
                    priority: 0,      // redriven at normal priority
                });
                ops.push(WriteOp::Delete {
                    key: messaging::dead_key(topic, &dl.id),
                });
            } else {
                ops.push(WriteOp::MqRedriveGroupedDead {
                    topic: topic.to_string(),
                    group: dl.group.clone(),
                    id: dl.id.clone(),
                });
            }
        }
        if !ops.is_empty() {
            self.propose(WriteOp::Batch(ops)).await?;
            self.wake.notify(); // redriven messages are claimable again (markers re-armed) — wake (B12)
        }
        Ok(matched.len())
    }

    async fn discard_dead_letters(
        &self,
        topic: &str,
        filter: &DeadLetterFilter,
    ) -> Result<usize, MessagingError> {
        let now = now_unix_ms();
        let mut matched: Vec<DeadLetter> = self
            .collect_dead_letters(topic)
            .await
            .into_iter()
            .filter(|dl| filter.matches(dl, now))
            .collect();
        if let Some(limit) = filter.limit {
            matched.truncate(limit);
        }
        if matched.is_empty() {
            return Ok(0);
        }
        // Replicate the dead-record deletes in one batch; then drop the work-queue payloads from
        // shared storage (grouped payloads stay — un-pinned, the sweep reclaims them once no group
        // needs them).
        // Classify each work-queue dead-letter BEFORE the delete proposal removes its record: inline
        // ⇒ release its bytes from the SA1 budget (C2), non-inline ⇒ delete the object-store payload.
        let mut deletes: Vec<WriteOp> = Vec::with_capacity(matched.len());
        let mut inline_release = 0usize;
        let mut object_ids: Vec<String> = Vec::new();
        for dl in &matched {
            if dl.group.is_empty() {
                let inline_len = self
                    .state
                    .get(&messaging::dead_key(topic, &dl.id))
                    .await
                    .and_then(|raw| serde_json::from_slice::<messaging::Record>(&raw).ok())
                    .and_then(|r| r.inline.map(|p| p.len()));
                match inline_len {
                    Some(len) => inline_release += len,
                    None => object_ids.push(dl.id.clone()),
                }
                deletes.push(WriteOp::Delete {
                    key: messaging::dead_key(topic, &dl.id),
                });
            } else {
                deletes.push(WriteOp::Delete {
                    key: messaging::gdead_key(topic, &dl.group, &dl.id),
                });
            }
        }
        self.propose(WriteOp::Batch(deletes)).await?;
        for id in &object_ids {
            self.storage
                .delete(&messaging::payload_key(topic, id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
        }
        if inline_release > 0 {
            let _ = self.inline_inflight_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |v| Some(v.saturating_sub(inline_release)),
            );
        }
        Ok(matched.len())
    }

    async fn peek(
        &self,
        topic: &str,
        limit: usize,
    ) -> Result<Vec<boatramp_core::messaging::PeekedMessage>, MessagingError> {
        let now = now_unix_ms();
        let prefix = messaging::meta_prefix(topic);
        let mut keys: Vec<String> = self
            .state
            .list_prefix(&prefix)
            .await
            .into_iter()
            .filter(|k| messaging::is_direct_child(k, &prefix))
            .collect();
        keys.sort(); // ids are time-ordered ⇒ delivery order.
        let mut out = Vec::new();
        for key in keys.into_iter().take(limit) {
            let Some(raw) = self.state.get(&key).await else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<messaging::Record>(&raw) else {
                continue;
            };
            let id = key[prefix.len()..].to_string();
            let payload = match &record.inline {
                Some(bytes) => bytes.clone(),
                None => self.read_payload(topic, &id).await.unwrap_or_default(),
            };
            out.push(boatramp_core::messaging::PeekedMessage {
                id,
                attempts: record.attempts,
                leased: record.lease_until_ms > now,
                signed_context: record.signed_context,
                payload,
            });
        }
        Ok(out)
    }

    async fn replay(
        &self,
        topic: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<boatramp_core::messaging::PeekedMessage>, MessagingError> {
        // Read the retained grouped-fan-out log from applied state (existence markers under
        // `mqglog/{topic}/`). Purely non-destructive: no proposal, no lease, no cursor touch — a live
        // tail and every group's drain are undisturbed. Symmetric to the single-node backend.
        let prefix = messaging::glog_prefix(topic);
        let mut ids: Vec<String> = self
            .state
            .list_prefix(&prefix)
            .await
            .into_iter()
            .filter(|k| messaging::is_direct_child(k, &prefix))
            .map(|k| k[prefix.len()..].to_string())
            .collect();
        ids.sort(); // ids are time-ordered ⇒ publish order.
        let mut out = Vec::new();
        for id in ids {
            // `after` is exclusive — skip everything at or before the caller's last-seen offset.
            if let Some(after) = after {
                if id.as_str() <= after {
                    continue;
                }
            }
            if out.len() >= limit {
                break;
            }
            // Retained fan-out payload (a missing object yields an empty body rather than failing the
            // replay); context re-read best-effort from the shared index record.
            let payload = self.read_gpayload(topic, &id).await.unwrap_or_default();
            let signed_context = self
                .state
                .get(&messaging::meta_key(topic, &id))
                .await
                .and_then(|raw| serde_json::from_slice::<messaging::Record>(&raw).ok())
                .and_then(|r| r.signed_context);
            out.push(boatramp_core::messaging::PeekedMessage {
                id,
                attempts: 0,   // history entries carry no per-group delivery count.
                leased: false, // replay never leases.
                signed_context,
                payload,
            });
        }
        Ok(out)
    }

    async fn list_groups(&self, topic: &str) -> Result<Vec<GroupInfo>, MessagingError> {
        let gprefix = messaging::gstate_prefix(topic);
        let log_prefix = messaging::glog_prefix(topic);
        let log_ids: Vec<String> = self
            .state
            .list_prefix(&log_prefix)
            .await
            .into_iter()
            .filter(|k| messaging::is_direct_child(k, &log_prefix))
            .map(|k| k[log_prefix.len()..].to_string())
            .collect();
        let mut out = Vec::new();
        for key in self.state.list_prefix(&gprefix).await {
            if !messaging::is_direct_child(&key, &gprefix) {
                continue;
            }
            let group = key[gprefix.len()..].to_string();
            let Some(raw) = self.state.get(&key).await else {
                continue;
            };
            let Ok(state) = serde_json::from_slice::<messaging::GroupState>(&raw) else {
                continue;
            };
            let lag = log_ids
                .iter()
                .filter(|id| id.as_str() > state.hwm.as_str())
                .count();
            out.push(GroupInfo {
                group,
                hwm: state.hwm,
                in_flight: state.in_flight.len(),
                lag,
            });
        }
        out.sort_by(|a, b| a.group.cmp(&b.group));
        Ok(out)
    }

    async fn reset_group(
        &self,
        topic: &str,
        group: &str,
        start: messaging::StartPosition,
    ) -> Result<(), MessagingError> {
        // Refuse an unknown group (read from applied state); the apply recomputes hwm deterministically
        // from `start` so every replica lands the same cursor.
        if self
            .state
            .get(&messaging::gstate_key(topic, group))
            .await
            .is_none()
        {
            return Err(MessagingError::Backend(format!(
                "no such consumer group {group:?} on topic {topic:?}"
            )));
        }
        self.propose(WriteOp::MqResetGroup {
            topic: topic.to_string(),
            group: group.to_string(),
            start,
        })
        .await?;
        Ok(())
    }

    async fn delete_group(&self, topic: &str, group: &str) -> Result<(), MessagingError> {
        self.propose(WriteOp::MqDeleteGroup {
            topic: topic.to_string(),
            group: group.to_string(),
        })
        .await?;
        Ok(())
    }

    async fn set_paused(&self, topic: &str, paused: bool) -> Result<(), MessagingError> {
        self.propose(WriteOp::MqSetPaused {
            topic: topic.to_string(),
            paused,
        })
        .await?;
        Ok(())
    }

    async fn is_paused(&self, topic: &str) -> Result<bool, MessagingError> {
        Ok(self.state.get(&messaging::pause_key(topic)).await.is_some())
    }

    async fn set_topic_policy(
        &self,
        topic: &str,
        policy: messaging::TopicPolicy,
    ) -> Result<(), MessagingError> {
        // Feature A: policy is OPERATOR STATE, so it must REPLICATE — a plain `WriteOp::Put` of the
        // JSON under `mqpolicy/{topic}` through the state machine (durable + applied on every node,
        // and naturally version-independent: a plain KV Put, no new op variant, so rolling-upgrade
        // safe). Then invalidate this node's cache so a subsequent local publish re-reads it; other
        // nodes' caches self-heal on their next miss / lazily (a stale cap is best-effort by design).
        let value =
            serde_json::to_vec(&policy).map_err(|e| MessagingError::Backend(e.to_string()))?;
        self.propose(WriteOp::Put {
            key: messaging::mqpolicy_key(topic),
            value,
        })
        .await?;
        // No cache to invalidate — `resolve_policy` reads applied state per publish, so the new
        // policy is enforced fleet-wide as soon as the replicated Put applies (no per-node staleness).
        Ok(())
    }

    async fn topic_policy(
        &self,
        topic: &str,
    ) -> Result<Option<messaging::TopicPolicy>, MessagingError> {
        self.resolve_policy(topic).await
    }

    async fn retention_sweep(
        &self,
        topic: &str,
        retention_ms: u64,
    ) -> Result<usize, MessagingError> {
        // The LEADER computes the exact reclaim set from its applied state (same decision as the
        // single-node `gc_grouped`: a log id is reclaimed when it is not dead-letter-pinned AND either
        // no group still needs it OR it is older than `retention_ms`) and proposes EXPLICIT deletes.
        // This is deliberately NOT a "sweep with a retention param the apply re-evaluates": a
        // per-proposal retention that the apply reads would diverge a mixed-version cluster (an old
        // replica ignoring the field would reclaim a different set). Explicit deletes apply identically
        // on every replica regardless of version. Only the client deletes `Storage` payloads
        // (consensus never touches `Storage`). Idempotent under concurrent sweeps (a repeated delete is
        // a no-op). Same TOCTOU as single-node (a group reset between read and apply is a rare admin op).
        let now = now_unix_ms();

        // Every registered group's compact state (for the "still needed by some group" check).
        let state_prefix = messaging::gstate_prefix(topic);
        let mut states = Vec::new();
        for key in self.state.list_prefix(&state_prefix).await {
            if !messaging::is_direct_child(&key, &state_prefix) {
                continue;
            }
            if let Some(raw) = self.state.get(&key).await {
                if let Ok(state) = serde_json::from_slice::<messaging::GroupState>(&raw) {
                    states.push(state);
                }
            }
        }
        // Dead-lettered ids (any group) pin their retained log+payload against reclaim.
        let dead_ids: std::collections::HashSet<String> = self
            .grouped_dead(topic)
            .await
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        // Every retained log id.
        let log_prefix = messaging::glog_prefix(topic);
        let ids: Vec<String> = self
            .state
            .list_prefix(&log_prefix)
            .await
            .into_iter()
            .filter(|k| messaging::is_direct_child(k, &log_prefix))
            .map(|k| k[log_prefix.len()..].to_string())
            .collect();

        let mut reclaim: Vec<String> = Vec::new();
        for id in ids {
            let pinned = dead_ids.contains(&id);
            let needed = messaging::grouped_message_needed(&states, &id);
            let expired = messaging::id_millis(&id) + retention_ms < now;
            if !pinned && (!needed || expired) {
                reclaim.push(id);
            }
        }
        if reclaim.is_empty() {
            return Ok(0);
        }
        // Replicate the explicit log-entry deletes in one batch (version-independent apply).
        let deletes: Vec<WriteOp> = reclaim
            .iter()
            .map(|id| WriteOp::Delete {
                key: messaging::glog_key(topic, id),
            })
            .collect();
        self.propose(WriteOp::Batch(deletes)).await?;
        // Then free the `Storage` payloads (client-side; consensus never touches Storage).
        for id in &reclaim {
            self.storage
                .delete(&messaging::gpayload_key(topic, id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
        }
        Ok(reclaim.len())
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

    // --- event-driven delivery (Phase A) ------------------------------------------------------

    fn supports_ready_set(&self) -> bool {
        // The cluster ready-set lives in the Raft state machine: a publish/nack/claim's ready-set
        // mutation rides the SAME `apply_op` (⇒ the same replicated entry) as the index write, so
        // atomicity holds BY CONSTRUCTION (B1/B2) regardless of the underlying persistence backend.
        true
    }

    async fn ready_topics(&self) -> Result<Vec<String>, MessagingError> {
        // Read this node's applied ready-set (replicated state — every node converges to it).
        Ok(self
            .state
            .list_prefix(messaging::READY_PREFIX)
            .await
            .iter()
            .filter_map(|k| messaging::topic_of_ready_key(k).map(str::to_owned))
            .collect())
    }

    async fn rebuild_ready_set(&self) -> Result<usize, MessagingError> {
        // The safety-net self-heal (B6/B18), cluster edition: re-derive the topics-with-work set from
        // the AUTHORITATIVE replicated index, then PROPOSE reconciling ready-marker adds/prunes
        // through the leader (the marker is applied state). Per B7 the rebuild is NOT sharded — any
        // node re-derives the identical GLOBAL set (claims are leader-serialized, so a redundant add
        // is safe), so there is never a no-owner gap. The one full-ish scan, on a long cadence.
        let mut with_work: std::collections::HashSet<String> = std::collections::HashSet::new();
        // 1) Work-queue backlog: any live `mq/{topic}/{id}`.
        for key in self.state.list_prefix("mq/").await {
            if let Some(rest) = key.strip_prefix("mq/") {
                if let Some(slash) = rest.rfind('/') {
                    with_work.insert(rest[..slash].to_string());
                }
            }
        }
        // 2) Grouped backlog/in-flight: a registered group behind the retained log or holding work.
        for key in self.state.list_prefix("mqgstate/").await {
            let Some(rest) = key.strip_prefix("mqgstate/") else {
                continue;
            };
            let Some(slash) = rest.rfind('/') else {
                continue;
            };
            let topic = rest[..slash].to_string();
            let group = &rest[slash + 1..];
            if topic.is_empty() || group.is_empty() || with_work.contains(&topic) {
                continue;
            }
            let Some(raw) = self.state.get(&key).await else {
                continue;
            };
            let Ok(state) = serde_json::from_slice::<messaging::GroupState>(&raw) else {
                continue;
            };
            let logmax = self
                .state
                .get(&messaging::logmax_key(&topic))
                .await
                .map(|v| String::from_utf8_lossy(&v).into_owned())
                .unwrap_or_default();
            if !state.in_flight.is_empty() || state.hwm.as_str() < logmax.as_str() {
                with_work.insert(topic);
            }
        }
        // 3) Reconcile: **ADD-ONLY** — heal MISSING markers (a lost publish-wake add / fresh-node
        //    self-populate); do NOT prune (Security review A-1). `with_work` is computed from a stale
        //    applied-state read, so a stale-marker delete proposed here races a concurrent `MqPublish`
        //    applied in between — the same class H-1 closed for the claim path — and would strand the
        //    just-published message until the next rebuild. Pruning is owned SOLELY by `apply_mq_claim`
        //    (empty-only, inside one leader-serialized apply, race-free); a stale marker here just
        //    costs one cheap empty claim that then prunes it (B5). Propose the adds as ONE batch.
        let existing: std::collections::HashSet<String> = self
            .state
            .list_prefix(messaging::READY_PREFIX)
            .await
            .iter()
            .filter_map(|k| messaging::topic_of_ready_key(k).map(str::to_owned))
            .collect();
        let mut ops: Vec<WriteOp> = Vec::new();
        for topic in with_work.difference(&existing) {
            ops.push(WriteOp::Put {
                key: messaging::ready_key(topic),
                value: Vec::new(),
            });
        }
        let added_any = !ops.is_empty();
        if !ops.is_empty() {
            self.propose(WriteOp::Batch(ops)).await?;
        }
        self.last_rebuild_ms.store(now_unix_ms(), Ordering::Relaxed);
        if added_any {
            self.wake.notify(); // a re-added (lost / fresh-node) marker — wake the drainer
        }
        Ok(with_work.len())
    }

    async fn due_topics(&self) -> Result<Vec<(String, u64)>, MessagingError> {
        // Per-topic earliest future lease deadline for the redelivery due-heap (B6), read from this
        // node's applied state. A pure rebuild-from-durable-state source (the heap is a cache).
        let now = now_unix_ms();
        let mut due: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut note = |topic: &str, until: u64| {
            if until > now {
                due.entry(topic.to_string())
                    .and_modify(|e| *e = (*e).min(until))
                    .or_insert(until);
            }
        };
        for key in self.state.list_prefix("mq/").await {
            let Some(rest) = key.strip_prefix("mq/") else {
                continue;
            };
            let Some(slash) = rest.rfind('/') else {
                continue;
            };
            let topic = rest[..slash].to_string();
            if let Some(raw) = self.state.get(&key).await {
                if let Ok(rec) = serde_json::from_slice::<messaging::Record>(&raw) {
                    note(&topic, rec.lease_until_ms);
                }
            }
        }
        for key in self.state.list_prefix("mqgstate/").await {
            let Some(rest) = key.strip_prefix("mqgstate/") else {
                continue;
            };
            let Some(slash) = rest.rfind('/') else {
                continue;
            };
            let topic = rest[..slash].to_string();
            if let Some(raw) = self.state.get(&key).await {
                if let Ok(state) = serde_json::from_slice::<messaging::GroupState>(&raw) {
                    for f in &state.in_flight {
                        note(&topic, f.lease_until_ms);
                    }
                }
            }
        }
        Ok(due.into_iter().collect())
    }

    async fn delivery_stats(
        &self,
        this_node: &str,
    ) -> Result<messaging::DeliveryStats, MessagingError> {
        let ready_set_size = self.ready_topics().await?.len();
        let due_heap_depth = self.due_topics().await?.len();
        let last = self.last_rebuild_ms.load(Ordering::Relaxed);
        let last_rebuild_age_ms = (last != 0).then(|| now_unix_ms().saturating_sub(last));
        // Prefer the caller's node label; fall back to this node's Raft id so the block always
        // identifies WHICH node's delivery view this is (the shard-gap diagnostic, B16).
        let node = if this_node.is_empty() {
            self.node_id.to_string()
        } else {
            this_node.to_string()
        };
        Ok(messaging::DeliveryStats {
            ready_set_size,
            due_heap_depth,
            last_rebuild_age_ms,
            this_node: node,
        })
    }

    fn wake_handle(&self) -> Option<messaging::Wake> {
        Some(self.wake.clone())
    }

    async fn shard_owns(&self, topic: &str) -> bool {
        // Phase D: this node owns `topic`'s delivery iff it is the HRW winner over the APPLIED voter
        // set (B8 — replicated membership, NOT raft.metrics()). An empty voter set (not yet
        // initialized / a degenerate single node) ⇒ own everything (unsharded), so delivery never
        // stalls before membership is known. Recomputed per call (the drain cycle reads it per ready
        // topic); pure + deterministic, so every node agrees. NEVER a correctness gate — a transient
        // wrong answer during a membership change costs at most a redundant/absent empty claim, and
        // the atomic leader claim + the unsharded rebuild (B7) keep at-least-once intact.
        let voters = self.state.applied_voters().await;
        match Self::hrw_owner(topic, &voters) {
            Some(owner) => owner == self.node_id,
            None => true, // no applied membership yet ⇒ unsharded (own all)
        }
    }

    async fn shard_owned(&self, topics: Vec<String>) -> Vec<String> {
        // B8: snapshot the applied voter set ONCE, then HRW-filter all topics against it — one
        // membership read per drain cycle (not per topic). Empty voter set ⇒ unsharded (own all).
        let voters = self.state.applied_voters().await;
        if voters.is_empty() {
            return topics;
        }
        topics
            .into_iter()
            .filter(|t| Self::hrw_owner(t, &voters) == Some(self.node_id))
            .collect()
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
        InProcessForwarder, LogStore, NetworkFactory, RaftKv, Registry, StateMachineStore,
        TypeConfig,
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

    /// Poll `mq`'s applied ready-set until it equals `want` (order-insensitive), within a bounded
    /// window — a cluster read is only linearizable AFTER the write applies locally, so a bare read
    /// right after a forwarded write can race replication. Returns whether it converged.
    async fn poll_ready(mq: &RaftMessaging, want: &[&str]) -> bool {
        let mut want: Vec<String> = want.iter().map(ToString::to_string).collect();
        want.sort();
        for _ in 0..100 {
            let mut got = mq.ready_topics().await.unwrap();
            got.sort();
            if got == want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

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

    /// Event-driven delivery (B1, cluster): a publish flags the topic in the REPLICATED ready-set (in
    /// the same apply as the index record), and a claim that drains it prunes the marker — all
    /// through the leader-serialized apply, so there is no prune-vs-publish race (B4 by construction).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_ready_set_add_on_publish_and_prune_on_drain() {
        let (rafts, mqs) = cluster_mq(3).await;
        // The leader is node 1 (initialized + elected). Read the ready-set from it (linearizable
        // after a forwarded publish/claim, which applies on the leader).
        assert!(mqs[&1].supports_ready_set(), "cluster apply is atomic (B1)");
        assert!(poll_ready(&mqs[&1], &[]).await, "starts empty");
        mqs[&2].publish("t", b"x").await.unwrap();
        assert!(
            poll_ready(&mqs[&1], &["t"]).await,
            "publish (from any node) flags the topic in the replicated ready-set (B1)"
        );
        // Claim the only message on node 3: the marker STAYS (a leased-but-unacked message is still
        // pending work — matches single-node's "prune only when the work-queue is empty" rule).
        let batch = mqs[&3].claim("t", LEASE, 10, 5).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert!(
            poll_ready(&mqs[&1], &["t"]).await,
            "a leased-but-unacked message keeps the replicated marker"
        );
        // Ack it → work-queue empty → the NEXT claim's apply prunes the marker (leader-serialized, B4).
        mqs[&1].ack(&batch[0]).await.unwrap();
        assert!(mqs[&3].claim("t", LEASE, 10, 5).await.unwrap().is_empty());
        assert!(
            poll_ready(&mqs[&1], &[]).await,
            "a claim over the now-empty work-queue prunes the replicated marker (B4)"
        );
        shutdown(rafts).await;
    }

    /// Gate 3 (cluster): a lost ready marker (a crash / snapshot-skew that dropped it) is re-derived
    /// by `rebuild_ready_set` from the authoritative replicated index — no message lost. The rebuild
    /// is NOT sharded (B7): any node re-derives the identical global set and proposes the reconcile.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_rebuild_recovers_a_lost_ready_marker() {
        let (rafts, mqs) = cluster_mq(3).await;
        mqs[&1].publish("t", b"x").await.unwrap();
        // Simulate the lost marker: propose a direct delete of the ready key (leaving the index
        // record — the message — intact). Goes through the leader like any write.
        mqs[&1]
            .propose(WriteOp::Delete {
                key: messaging::ready_key("t"),
            })
            .await
            .unwrap();
        assert!(
            mqs[&1].ready_topics().await.unwrap().is_empty(),
            "marker lost"
        );
        assert_eq!(mqs[&1].backlog("t").await.unwrap(), 1, "message NOT lost");
        // Rebuild on the LEADER (node 1) — the drainer runs the rebuild leader-gated, and the leader's
        // applied state is current (it just applied the publish + the delete), so the derive sees the
        // live `mq/t/...` record. It re-derives the work-set and PROPOSES the reconciling marker add.
        let n = mqs[&1].rebuild_ready_set().await.unwrap();
        assert_eq!(n, 1, "rebuild finds the one topic with work");
        // The re-added marker replicates + applies asynchronously; poll node 1's applied view for it.
        assert!(
            poll_ready(&mqs[&1], &["t"]).await,
            "rebuild re-adds the lost marker from the replicated index (B6/B18)"
        );
        // And it is claimable.
        assert_eq!(mqs[&3].claim("t", LEASE, 10, 5).await.unwrap().len(), 1);
        shutdown(rafts).await;
    }

    /// Phase D — HRW ownership is deterministic, total (a unique owner per topic), and reshuffles
    /// MINIMALLY on a membership change (only topics that hashed to the departing node move). Pure
    /// function test (no cluster needed) — the property every node relies on to agree (B8).
    #[test]
    fn hrw_ownership_is_deterministic_total_and_minimal_churn() {
        let three = [1u64, 2, 3];
        // Deterministic + total: every topic has exactly one owner, stable across calls.
        for i in 0..200 {
            let t = format!("topic-{i}");
            let o1 = RaftMessaging::hrw_owner(&t, &three).unwrap();
            let o2 = RaftMessaging::hrw_owner(&t, &three).unwrap();
            assert_eq!(o1, o2, "owner is stable");
            assert!(three.contains(&o1), "owner is a member");
        }
        // Roughly balanced across the 3 nodes (not a hard bound — just not degenerate).
        let mut counts = std::collections::HashMap::new();
        for i in 0..3000 {
            let o = RaftMessaging::hrw_owner(&format!("t{i}"), &three).unwrap();
            *counts.entry(o).or_insert(0u32) += 1;
        }
        for id in three {
            assert!(
                counts[&id] > 500,
                "node {id} owns a fair share ({:?})",
                counts
            );
        }
        // Minimal churn on node-loss: removing node 3, a topic MOVES only if node 3 owned it. Every
        // topic owned by 1 or 2 keeps its owner (rendezvous hashing's defining property).
        let two = [1u64, 2];
        let mut moved = 0;
        for i in 0..3000 {
            let t = format!("t{i}");
            let before = RaftMessaging::hrw_owner(&t, &three).unwrap();
            let after = RaftMessaging::hrw_owner(&t, &two).unwrap();
            if before != after {
                moved += 1;
                assert_eq!(before, 3, "only topics owned by the departed node 3 move");
            }
        }
        assert!(moved > 0, "some topics did move (node 3's share)");
    }

    /// Phase D — an empty voter set (membership not yet applied) ⇒ own everything (unsharded), so a
    /// node never stalls delivery before it knows the cluster.
    #[test]
    fn hrw_empty_voters_owns_nothing_so_caller_owns_all() {
        assert_eq!(RaftMessaging::hrw_owner("t", &[]), None);
    }

    /// Phase D — the batch `shard_owned` (B8, one membership snapshot for the whole cycle) agrees
    /// exactly with per-topic `shard_owns`, and partitions the candidate set across the cluster (the
    /// union of every node's `shard_owned` == the whole candidate set, disjointly).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_shard_owned_batch_agrees_with_per_topic_and_partitions() {
        let (rafts, mqs) = cluster_mq(3).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let candidates: Vec<String> = (0..90).map(|i| format!("orders/{i}")).collect();
        let mut union: HashSet<String> = HashSet::new();
        for id in 1..=3u64 {
            let owned = mqs[&id].shard_owned(candidates.clone()).await;
            // Batch agrees with per-topic for this node.
            for t in &candidates {
                let per_topic = mqs[&id].shard_owns(t).await;
                assert_eq!(
                    owned.contains(t),
                    per_topic,
                    "shard_owned batch disagrees with shard_owns for {t} on node {id}"
                );
            }
            // Disjoint across nodes.
            for t in &owned {
                assert!(union.insert(t.clone()), "topic {t} owned by two nodes");
            }
        }
        assert_eq!(
            union.len(),
            candidates.len(),
            "every candidate is owned by some node"
        );
        shutdown(rafts).await;
    }

    /// Phase D — over a real 3-node cluster, `shard_owns` partitions the topic space: every topic is
    /// owned by EXACTLY ONE node (no gap, no overlap in steady state), and every node's applied voter
    /// view agrees. This is the assignment the drainers use to each drive their ~1/N share (B8/B9).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_shard_owns_partitions_every_topic_to_one_node() {
        let (rafts, mqs) = cluster_mq(3).await;
        // Let membership fully apply on every node.
        tokio::time::sleep(Duration::from_millis(300)).await;
        for i in 0..60 {
            let topic = format!("orders/{i}");
            let mut owners = Vec::new();
            for id in 1..=3u64 {
                if mqs[&id].shard_owns(&topic).await {
                    owners.push(id);
                }
            }
            assert_eq!(
                owners.len(),
                1,
                "topic {topic} must be owned by exactly one node, got {owners:?}"
            );
        }
        shutdown(rafts).await;
    }

    /// **Gate 6 — sharding node-loss.** Topics distributed across a 3-node cluster (each node drains
    /// its HRW-owned share), a node is KILLED and removed from membership, and its orphaned topics
    /// keep delivering — with NO double-delivery AND NO stranding across the transition, INCLUDING the
    /// no-owner window. Models the server drainer: each node claims its owned topics (sharded), then
    /// an UNSHARDED backstop pass (B7) drains any topic no surviving node yet owns. The atomic
    /// leader-claim guarantees exactly-once regardless of how many drainers look (C4/B9).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gate6_sharding_node_loss_no_double_delivery_no_stranding() {
        let (mut rafts, mqs) = cluster_mq(3).await;
        tokio::time::sleep(Duration::from_millis(300)).await; // let membership apply everywhere

        // Publish one message to each of many topics (spread across all three shard owners).
        const TOPICS: usize = 60;
        for i in 0..TOPICS {
            let topic = format!("orders/{i}");
            mqs[&1]
                .publish(&topic, format!("m-{i}").as_bytes())
                .await
                .unwrap();
        }

        // Collect every delivered id exactly-once across the whole test. A drain step: each surviving
        // node claims (a) its OWNED topics (the sharded fast path) and, when `unsharded`, (b) EVERY
        // topic (the B7 no-owner backstop). Ack each so it is delivered once. Redundant claims are
        // safe (leader-serialized), so an id can be claimed by at most one node per message.
        let delivered: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        async fn drain_once(
            mqs: &BTreeMap<NodeId, Arc<RaftMessaging>>,
            alive: &[NodeId],
            unsharded: bool,
            delivered: &Arc<StdMutex<Vec<String>>>,
        ) {
            for &id in alive {
                let mq = &mqs[&id];
                for i in 0..TOPICS {
                    let topic = format!("orders/{i}");
                    if !unsharded && !mq.shard_owns(&topic).await {
                        continue; // sharded pass: only my share
                    }
                    let batch = mq
                        .claim(&topic, Duration::from_secs(60), 8, 5)
                        .await
                        .unwrap();
                    for m in batch {
                        delivered.lock().unwrap().push(m.id.clone());
                        mq.ack(&m).await.unwrap();
                    }
                }
            }
        }

        // (1) Steady-state sharded drain across all three nodes — each drains its ~1/3 share.
        drain_once(&mqs, &[1, 2, 3], false, &delivered).await;

        // (2) Publish a SECOND wave, then KILL node whose share is non-empty (node 3) mid-flight —
        // BEFORE its share is drained — so its owned topics are orphaned (the node-loss transition).
        for i in 0..TOPICS {
            let topic = format!("orders/{i}");
            mqs[&1]
                .publish(&topic, format!("w2-{i}").as_bytes())
                .await
                .unwrap();
        }
        // Kill node 3 and remove it from membership so HRW reassigns its share to {1,2}.
        rafts.remove(&3).unwrap().shutdown().await.unwrap();
        let new_leader = rafts[&1].metrics().borrow().current_leader.unwrap_or(1);
        // Best-effort membership shrink to {1,2} (so `shard_owns` reassigns node 3's topics). If the
        // leader was 3 the survivors re-elect first; give it a moment.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let leader_id = rafts
            .values()
            .find_map(|r| {
                let m = r.metrics();
                let b = m.borrow();
                (b.current_leader == Some(b.id)).then_some(b.id)
            })
            .unwrap_or(new_leader);
        let _ = rafts[&leader_id]
            .change_membership(std::collections::BTreeSet::from([1u64, 2u64]), false)
            .await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // (3) The survivors drain: first the UNSHARDED backstop (covers node 3's orphaned share
        // during/after the transition — the no-owner window), then a sharded pass for good measure.
        drain_once(&mqs, &[1, 2], true, &delivered).await;
        drain_once(&mqs, &[1, 2], false, &delivered).await;

        // Invariant: every id delivered EXACTLY once (no double-delivery), and BOTH waves' messages
        // were delivered (no stranding) — 2 waves × TOPICS messages, minus none.
        let ids = std::mem::take(&mut *delivered.lock().unwrap());
        let unique: HashSet<&str> = ids.iter().map(String::as_str).collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "gate 6: a message was double-delivered across the node-loss transition"
        );
        assert_eq!(
            ids.len(),
            TOPICS * 2,
            "gate 6: every message from both waves delivered (no stranding across the no-owner window)"
        );
        for raft in rafts.into_values() {
            let _ = raft.shutdown().await;
        }
    }

    /// An initialized `n`-node in-process cluster where each node exposes BOTH a [`RaftKv`] (the
    /// control-plane KV the [`DeployStore`](boatramp_core::deploy::DeployStore) async-lane queue lives
    /// on) AND a [`RaftMessaging`] (whose `shard_owns` is the applied-membership HRW the async drainer
    /// consults). Both facades on a node share the SAME per-node [`StateMachineStore`] and the SAME
    /// registry/forwarder, so the applied membership a `RaftKv` CAS commits is the identical voter set
    /// `shard_owns` reads — exactly the shared-applied-state coupling the server relies on (the KV CAS
    /// serializes claims; the messaging HRW decides ownership). Mirrors [`cluster_mq`] and additionally
    /// builds the `RaftKv` per node. Returns the rafts (for shutdown/kill), the KVs, and the mqs.
    async fn cluster_kv_mq(
        n: u64,
    ) -> (
        BTreeMap<NodeId, Raft<TypeConfig>>,
        BTreeMap<NodeId, Arc<RaftKv>>,
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
        let mut kvs = BTreeMap::new();
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
            // The control-plane KV facade — forwards writes to the leader, reads THIS node's applied
            // state (the same `sm` the mq reads), so a claim CAS is leader-serialized cluster-wide.
            let kv = Arc::new(RaftKv::in_process(
                raft.clone(),
                registry.clone(),
                Arc::new(sm.clone()),
            ));
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
            kvs.insert(id, kv);
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
        (rafts, kvs, mqs)
    }

    /// **Async-lane sharding — multi-node node-loss (the load-bearing safety gate).** The real
    /// async-lane analog of the messaging [`gate6_sharding_node_loss_no_double_delivery_no_stranding`]:
    /// a 3-node in-process Raft cluster runs the *server's* async drain over a `DeployStore`-on-`RaftKv`
    /// queue, sharded by the messaging `shard_owns` HRW. A wave of queued invocations is drained
    /// sharded; a second wave is enqueued; the node that owns a non-empty share is KILLED and removed
    /// from membership; the survivors drain (unsharded backstop, then sharded). The invariant, mirroring
    /// gate6's exactly-once + no-stranding:
    ///   * **No double-execution** (gate6: no double-delivery) — a winning claim is unique per (fn,id).
    ///     The whole-record CAS in [`claim_invocation`](boatramp_core::deploy::DeployStore::claim_invocation)
    ///     admits the `Queued`→`Running` transition for at most ONE node even in the double-owner window,
    ///     exactly as gate6's atomic leader-claim serializes concurrent drainers.
    ///   * **No stranding** (gate6: all delivered) — every seeded invocation is claimed exactly once
    ///     across the transition INCLUDING the no-owner window, because the survivors' UNSHARDED
    ///     backstop pass (B7/B10 safety-net) claims any invocation no surviving node yet owns, just as
    ///     gate6's unsharded rebuild drains the killed node's orphaned topics.
    ///
    /// This is a REAL detector (not a tautology): it drives the SAME `shard_owns` gate + `claim_invocation`
    /// CAS the server uses, and its two invariants are guarded by two INDEPENDENT mechanisms, each
    /// mutation-verified to make the gate fail:
    ///   * **CAS ⇒ no double-execution.** The alive nodes drain CONCURRENTLY, racing the shared queue.
    ///     Replacing the whole-record CAS with a blind `put_invocation` lets every racing drainer "win"
    ///     the same record → the `unique.len() == wins.len()` assertion fails (observed ~84/60). This
    ///     is the exactly-once guard: over-claiming (even a broken ownership gate that owns-all) is safe
    ///     BECAUSE the CAS serializes it — which is exactly why over-ownership alone can NOT double-run,
    ///     the same property the template gate6 has (its atomic leader-claim, not ownership, is the
    ///     exactly-once guard).
    ///   * **Ownership ⇒ no stranding.** The steady-state SHARDED-only wave-1 pass (no backstop) must
    ///     cover every record, which holds only if ownership PARTITIONS the functions across the live
    ///     nodes. A broken `shard_owns` that under-owns (nothing owned) strands wave 1 → the wave-1
    ///     completeness assertion fails (observed 0/30). The post-kill unsharded backstop then proves
    ///     the no-owner window strands nothing either.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gate_async_shard_multinode_node_loss_no_double_execution_no_stranding() {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::function::{Invocation, InvocationStatus, InvokeMode};
        use boatramp_core::project::{ProjectRef, DEFAULT_PROJECT};
        use boatramp_core::time::now_unix;

        let (mut rafts, kvs, mqs) = cluster_kv_mq(3).await;
        tokio::time::sleep(Duration::from_millis(300)).await; // let membership apply everywhere

        // The async-lane shard key is the function identity `{project}/{function}` (mirrors the
        // server's `async_shard_key_function`). ALL invocations of one function share ONE owner, so to
        // spread the seed across all three shard owners we use N DISTINCT functions (one invocation
        // each) — the HRW distributes `default/fn-i` across the nodes, exactly as gate6 uses 60 distinct
        // topics. The shared blob store is unused by the queue (records live in the KV), so the drain
        // never touches it — a claim CAS is the whole mechanism.
        const N: usize = 30;
        let shard_key = |i: usize| format!("{DEFAULT_PROJECT}/fn-{i}");
        let seed_wave = |kv: Arc<RaftKv>, tag: &'static str| async move {
            let deploy = DeployStore::new(
                Arc::new(MemStorage::default()) as Arc<dyn Storage>,
                kv as Arc<dyn boatramp_core::kv::KvStore>,
            );
            let now = now_unix();
            for i in 0..N {
                let inv = Invocation {
                    id: format!("{tag}-{i}"),
                    function: format!("fn-{i}"),
                    version: "hashA".into(),
                    mode: InvokeMode::Async,
                    status: InvocationStatus::Queued,
                    idempotency_key: None,
                    attempts: 0,
                    lease_expires: None,
                    request_b64: None,
                    request_content_type: None,
                    result: None,
                    created: now,
                    updated: now,
                };
                deploy
                    .put_invocation(ProjectRef::DEFAULT, &inv)
                    .await
                    .unwrap();
            }
        };

        // One drain step, modeling the server's `drain_function_invocations` over a cluster. The alive
        // nodes drain CONCURRENTLY — that is the real double-owner window and what makes the CAS
        // load-bearing (gate6's `cluster_claim_never_double_delivers` + the server's gate3 both drive
        // concurrent drainers). Per node, per function: consult ownership (IFF `!unsharded`, the B7
        // backstop owns everything), list the queued record, and for each CLAIMABLE record run the
        // server's whole-record CAS claim (Queued/expired-Running → Running + attempts+1 + a lease). A
        // won claim (`Ok(true)` == the server would run the guest) records the (function,id): that is
        // one EXECUTION. Because the alive nodes race the SAME records, the CAS is the exactly-once
        // guard: it admits at most one claim per record even when several drainers observed it Queued
        // (Invariant 1) — a blind `put_invocation` instead would let every racing drainer "win",
        // double-executing (see the mutation tests for this gate). A long lease means a `Running`
        // record is NOT reclaimable within the test, so redelivery (at-least-once) is never conflated
        // with double-execution; the only re-claims are the legitimate no-owner backstop scans, which
        // the CAS makes idempotent.
        let executed: Arc<StdMutex<Vec<(String, String)>>> = Arc::new(StdMutex::new(Vec::new()));
        async fn drain_node(
            deploy: DeployStore,
            mq: Arc<RaftMessaging>,
            unsharded: bool,
            executed: Arc<StdMutex<Vec<(String, String)>>>,
        ) {
            use boatramp_core::function::InvocationStatus;
            use boatramp_core::project::{ProjectRef, DEFAULT_PROJECT};
            use boatramp_core::time::now_unix;

            for i in 0..N {
                let function = format!("fn-{i}");
                let key = format!("{DEFAULT_PROJECT}/{function}");
                if !unsharded && !mq.shard_owns(&key).await {
                    continue; // sharded pass: only my HRW share
                }
                let queued = deploy
                    .list_invocations(ProjectRef::DEFAULT, &function)
                    .await
                    .unwrap();
                let now = now_unix();
                for observed in queued {
                    // Claimable = freshly queued (or an expired-lease `Running` reclaim); mirror the
                    // server's `claimable` predicate. Settled records are skipped (idempotent).
                    let claimable = match observed.status {
                        InvocationStatus::Queued => true,
                        InvocationStatus::Running => {
                            observed.lease_expires.is_none_or(|e| e <= now)
                        }
                        InvocationStatus::Succeeded | InvocationStatus::Failed => false,
                    };
                    if !claimable {
                        continue;
                    }
                    // Compute the claimed record exactly as the drainer does: Running + a fresh (long)
                    // lease + attempts+1, then CAS it onto the EXACT observed bytes. Yield right before
                    // the CAS so concurrent drainers on the same record are actually interleaved (both
                    // observed it Queued) — the CAS, not scheduling luck, is what serializes them.
                    let mut claimed = observed.clone();
                    claimed.status = InvocationStatus::Running;
                    claimed.attempts = claimed.attempts.saturating_add(1);
                    claimed.lease_expires = Some(now.saturating_add(60));
                    claimed.updated = now;
                    tokio::task::yield_now().await;
                    if deploy
                        .claim_invocation(ProjectRef::DEFAULT, &observed, &claimed)
                        .await
                        .unwrap()
                    {
                        // Won the CAS — this is the one execution for this record.
                        executed
                            .lock()
                            .unwrap()
                            .push((observed.function.clone(), observed.id.clone()));
                    }
                }
            }
        }
        async fn drain_once(
            kvs: &BTreeMap<NodeId, Arc<RaftKv>>,
            mqs: &BTreeMap<NodeId, Arc<RaftMessaging>>,
            alive: &[NodeId],
            unsharded: bool,
            executed: &Arc<StdMutex<Vec<(String, String)>>>,
        ) {
            // Drain the alive nodes CONCURRENTLY so they genuinely race the shared queue.
            let mut tasks = Vec::new();
            for &id in alive {
                let deploy = DeployStore::new(
                    Arc::new(MemStorage::default()) as Arc<dyn Storage>,
                    kvs[&id].clone() as Arc<dyn boatramp_core::kv::KvStore>,
                );
                tasks.push(tokio::spawn(drain_node(
                    deploy,
                    mqs[&id].clone(),
                    unsharded,
                    executed.clone(),
                )));
            }
            for t in tasks {
                t.await.unwrap();
            }
        }

        // (1) Seed wave 1 on node 1's KV (replicates to all nodes) and drain it sharded across all three
        // — each node claims only its ~1/3 HRW share (steady state). NB the sharded pass alone (no
        // unsharded backstop) must cover EVERY wave-1 record: that only holds if ownership partitions
        // the functions across the live nodes. This is a load-bearing ownership assertion — if the
        // shard gate under-owned (a function no live node claims), the sharded-only drain would strand
        // it and this count would fall short (the backstop that would otherwise mask it runs only after
        // the kill, in step 3).
        seed_wave(kvs[&1].clone(), "w1").await;
        drain_once(&kvs, &mqs, &[1, 2, 3], false, &executed).await;
        assert_eq!(
            executed.lock().unwrap().len(),
            N,
            "async-shard: the steady-state SHARDED pass alone drained every wave-1 invocation — \
             ownership must partition the functions across the live nodes (no stranding, no gap)"
        );

        // (2) Seed wave 2, then KILL the node that owns a non-empty share (mirror gate6's node-3 kill)
        // BEFORE its share is drained, so its owned functions are orphaned (the node-loss transition).
        seed_wave(kvs[&1].clone(), "w2").await;
        // Pick a victim with a non-empty applied-membership HRW share (prefer node 3, like gate6). If
        // node 3 somehow owns nothing right now, fall back to any node that owns at least one function.
        let victim = {
            let mut pick = 3u64;
            let mut best_nonempty = None;
            for &cand in &[3u64, 2, 1] {
                let mut owns = 0usize;
                for i in 0..N {
                    if mqs[&cand].shard_owns(&shard_key(i)).await {
                        owns += 1;
                    }
                }
                if cand == 3 && owns > 0 {
                    pick = 3;
                    best_nonempty = Some(3);
                    break;
                }
                if best_nonempty.is_none() && owns > 0 {
                    best_nonempty = Some(cand);
                }
            }
            best_nonempty.unwrap_or(pick)
        };
        let survivors: Vec<NodeId> = [1u64, 2, 3].into_iter().filter(|&n| n != victim).collect();

        // Kill the victim and shrink membership to the survivors so `shard_owns` reassigns its share.
        rafts.remove(&victim).unwrap().shutdown().await.unwrap();
        let fallback = rafts[&survivors[0]]
            .metrics()
            .borrow()
            .current_leader
            .unwrap_or(survivors[0]);
        // If the victim was the leader the survivors re-elect first; give it a moment, then find a live
        // self-leader and best-effort shrink membership (mirror gate6).
        tokio::time::sleep(Duration::from_millis(500)).await;
        let leader_id = rafts
            .values()
            .find_map(|r| {
                let m = r.metrics();
                let b = m.borrow();
                (b.current_leader == Some(b.id)).then_some(b.id)
            })
            .unwrap_or(fallback);
        let _ = rafts[&leader_id]
            .change_membership(
                survivors
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<NodeId>>(),
                false,
            )
            .await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // (3) The survivors drain: first the UNSHARDED backstop (covers the killed node's orphaned share
        // during/after the transition — the no-owner window), then a sharded pass for good measure.
        drain_once(&kvs, &mqs, &survivors, true, &executed).await;
        drain_once(&kvs, &mqs, &survivors, false, &executed).await;

        // Invariant (mirrors gate6): every winning claim is UNIQUE (no invocation executed twice across
        // the handoff — no double-execution), AND every seeded invocation (both waves, 2 × N) was
        // claimed exactly once (no stranding across the no-owner window).
        let wins = std::mem::take(&mut *executed.lock().unwrap());
        let unique: HashSet<(String, String)> = wins.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            wins.len(),
            "async-shard: an invocation was claimed/executed more than once across the node-loss transition (double-execution)"
        );
        assert_eq!(
            wins.len(),
            N * 2,
            "async-shard: every seeded invocation from both waves was claimed exactly once (no stranding across the no-owner window)"
        );

        println!(
            "ASYNC-SHARD MULTINODE NODE-LOSS OK: over a real 3-node in-process Raft cluster (RaftKv \
             async queue + RaftMessaging HRW ownership on one shared applied state), a wave was drained \
             sharded, a second wave was enqueued, and the shard-owning node (node {victim}) was KILLED \
             and removed from membership mid-flight — the survivors' unsharded backstop + sharded passes \
             claimed every one of {} seeded invocations EXACTLY once (the whole-record CAS serialized \
             concurrent/handoff claimers) with NO double-execution and NO stranding across the no-owner \
             window.",
            N * 2
        );

        for raft in rafts.into_values() {
            let _ = raft.shutdown().await;
        }
    }

    /// A nack re-arms the topic's ready marker in the replicated apply (B1), so a redelivery is
    /// visible in the ready-set on every node.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_nack_rearms_ready_marker() {
        let (rafts, mqs) = cluster_mq(3).await;
        mqs[&1].publish("t", b"x").await.unwrap();
        let m = mqs[&1]
            .claim("t", LEASE, 10, 5)
            .await
            .unwrap()
            .pop()
            .unwrap();
        // Simulate a pruned/lost marker (e.g. a claim had emptied it, or a crash lost it) so the nack's
        // re-arm is observable: delete the marker directly (the leased record itself is untouched).
        mqs[&1]
            .propose(WriteOp::Delete {
                key: messaging::ready_key("t"),
            })
            .await
            .unwrap();
        assert!(poll_ready(&mqs[&1], &[]).await, "marker cleared");
        // Nack from another node re-arms the marker in the replicated apply (claimable again, B1).
        mqs[&2].nack(&m).await.unwrap();
        assert!(
            poll_ready(&mqs[&1], &["t"]).await,
            "a nack re-arms the replicated ready marker (B1)"
        );
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
        // queue peek (both backends): read the three in delivery order WITHOUT consuming — no lease,
        // no attempt charge — so the claim immediately below still gets all three at attempt 1.
        let peeked = mq.peek(topic, 10).await.unwrap();
        assert_eq!(
            peeked.iter().map(|p| p.payload.clone()).collect::<Vec<_>>(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "peek returns all three in delivery order"
        );
        assert!(
            peeked.iter().all(|p| !p.leased && p.attempts == 0),
            "peek does not lease or charge an attempt"
        );
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

        // A4: a batch publish durably enqueues every message in one commit (one Raft entry on the
        // cluster path); all are then claimable in publish order. Runs on BOTH backends.
        mq.publish_batch_ctx(
            &[
                (topic.to_string(), b"batch-1".to_vec()),
                (topic.to_string(), b"batch-2".to_vec()),
                (topic.to_string(), b"batch-3".to_vec()),
            ],
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            mq.backlog(topic).await.unwrap(),
            3,
            "batch publish enqueued every message"
        );
        let bexp = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(
            bexp.iter().map(|m| m.payload.clone()).collect::<Vec<_>>(),
            vec![
                b"batch-1".to_vec(),
                b"batch-2".to_vec(),
                b"batch-3".to_vec()
            ],
            "batch messages claimable in publish order"
        );
        for m in &bexp {
            mq.ack(m).await.unwrap();
        }
        assert_eq!(mq.backlog(topic).await.unwrap(), 0);

        // P1 selective DLQ (both backends): capture a sanitized host last_error, then list/show and
        // redrive-by-id / discard-by-filter. Two poison messages exhaust to the DLQ; one is annotated.
        mq.publish(topic, b"poison-x").await.unwrap();
        mq.publish(topic, b"poison-y").await.unwrap();
        let d1 = mq.claim(topic, Duration::ZERO, 10, 1).await.unwrap();
        let px = d1
            .iter()
            .find(|m| m.payload == b"poison-x")
            .unwrap()
            .clone();
        mq.set_last_error(&px, "guest-trap: boom").await.unwrap();
        assert!(mq
            .claim(topic, Duration::ZERO, 10, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 2);
        // list + --match finds only the annotated one; show returns its body + reason.
        let matched = mq
            .list_dead_letters(
                topic,
                &DeadLetterFilter {
                    match_last_error: Some("guest-trap".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id, px.id);
        let shown = mq
            .show_dead_letter(topic, "", &px.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(shown.payload.as_deref(), Some(b"poison-x".as_slice()));
        assert!(shown.last_error.as_deref().unwrap().contains("guest-trap"));
        // redrive only poison-x (by id) → DLQ down to 1; then discard the remainder.
        assert_eq!(
            mq.redrive_dead_letters_filtered(
                topic,
                &DeadLetterFilter {
                    id: Some(px.id.clone()),
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 1);
        assert_eq!(
            mq.discard_dead_letters(topic, &DeadLetterFilter::default())
                .await
                .unwrap(),
            1
        );
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 0);
        // Drain the redriven poison-x so the queue ends empty.
        for m in mq.claim(topic, LEASE, 10, 5).await.unwrap() {
            mq.ack(&m).await.unwrap();
        }
        assert_eq!(mq.backlog(topic).await.unwrap(), 0);

        // --- P2 flow control: pause / resume (both backends) --------------------------
        assert!(!mq.is_paused(topic).await.unwrap());
        mq.publish(topic, b"fc-1").await.unwrap();
        mq.set_paused(topic, true).await.unwrap();
        assert!(mq.is_paused(topic).await.unwrap());
        // Paused: claim delivers NOTHING, but publish still durably enqueues.
        assert!(mq.claim(topic, LEASE, 10, 5).await.unwrap().is_empty());
        mq.publish(topic, b"fc-2").await.unwrap();
        assert_eq!(
            mq.backlog(topic).await.unwrap(),
            2,
            "publish still enqueues while paused"
        );
        // Resume: both flow.
        mq.set_paused(topic, false).await.unwrap();
        assert!(!mq.is_paused(topic).await.unwrap());
        let flowed = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(flowed.len(), 2, "resume delivers what accumulated");
        for m in &flowed {
            mq.ack(m).await.unwrap();
        }
        assert_eq!(mq.backlog(topic).await.unwrap(), 0);

        // --- v0.4.24 per-topic operator policy (Feature A/B, both backends) -----------------------
        // Runs on a fresh child topic so it does not disturb the running backlog sequence on `topic`.
        // set/get roundtrips through the policy store — replicated on the cluster (read from applied
        // Raft state per publish, no node-local cache), KV on single-node.
        let ptopic = &format!("{topic}/policy");
        assert_eq!(
            mq.topic_policy(ptopic).await.unwrap(),
            None,
            "no policy initially"
        );
        mq.set_topic_policy(
            ptopic,
            messaging::TopicPolicy {
                max_depth: Some(2),
                max_rate_per_sec: None,
                max_unflushed: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            mq.topic_policy(ptopic).await.unwrap().unwrap().max_depth,
            Some(2),
            "policy roundtrips (replicated on the cluster, KV on single-node)"
        );
        // Feature B max_depth fail-closed: two fit (backlog 0,1), the third is rejected at the cap of
        // 2, and the rejected publish enqueues nothing.
        mq.publish(ptopic, b"p0").await.unwrap();
        mq.publish(ptopic, b"p1").await.unwrap();
        let over = mq.publish(ptopic, b"p2").await.unwrap_err();
        assert!(
            matches!(over, MessagingError::DepthExceeded(_)),
            "publish at max_depth is rejected fail-closed, got {over:?}"
        );
        assert_eq!(
            mq.backlog(ptopic).await.unwrap(),
            2,
            "the rejected publish enqueued nothing"
        );
        // Drain the policy topic so it leaves no residue.
        let drained = mq.claim(ptopic, LEASE, 10, 5).await.unwrap();
        for m in &drained {
            mq.ack(m).await.unwrap();
        }
        assert_eq!(mq.backlog(ptopic).await.unwrap(), 0);

        // --- P1 redelivery backoff: nack_after holds a message leased, both backends --------------
        let btopic = format!("{topic}/backoff");
        mq.publish(&btopic, b"boff").await.unwrap();
        let claimed = mq.claim(&btopic, LEASE, 10, 5).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempts, 1);
        // A far-future backoff: the message is NOT immediately re-claimable (held leased until the
        // deadline), but its attempt count is preserved (it still dead-letters at max_attempts).
        mq.nack_after(&claimed[0], 3_600_000).await.unwrap();
        assert!(
            mq.claim(&btopic, LEASE, 10, 5).await.unwrap().is_empty(),
            "a backed-off nack holds the message leased until the backoff elapses"
        );
        // A plain nack (delay 0) makes it claimable immediately; the attempt is then re-charged.
        mq.nack(&claimed[0]).await.unwrap();
        let again = mq.claim(&btopic, LEASE, 10, 5).await.unwrap();
        assert_eq!(again.len(), 1, "nack (no backoff) redelivers immediately");
        assert_eq!(
            again[0].attempts, 2,
            "attempts preserved across backoff then nack"
        );
        for m in &again {
            mq.ack(m).await.unwrap();
        }

        // --- P2 delivery modes: delayed publish (both backends, deterministic deferral) -----------
        // A far-future delay defers delivery; a no-delay companion flows immediately. (Delivery AFTER
        // the delay elapses is the same lease-expiry mechanism already covered by lease_expiry tests.)
        mq.publish_delayed_ctx(topic, b"later", Duration::from_secs(3600), None)
            .await
            .unwrap();
        mq.publish_delayed_ctx(topic, b"now", Duration::ZERO, None)
            .await
            .unwrap();
        assert_eq!(
            mq.backlog(topic).await.unwrap(),
            2,
            "both are durably enqueued (the delayed one counts as pending)"
        );
        let ready = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(
            ready.iter().map(|m| m.payload.clone()).collect::<Vec<_>>(),
            vec![b"now".to_vec()],
            "only the non-delayed message is claimable; the delayed one is deferred"
        );
        mq.ack(&ready[0]).await.unwrap();
        // Delivery AFTER a short delay elapses (the not-before expiry path): publish with 100ms delay,
        // confirm it's deferred, wait past it, then it's delivered as the first attempt.
        mq.publish_delayed_ctx(topic, b"soon", Duration::from_millis(100), None)
            .await
            .unwrap();
        assert!(
            mq.claim(topic, LEASE, 10, 5).await.unwrap().is_empty(),
            "still deferred right after publish"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        let soon = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(soon.len(), 1, "delivered once the delay elapsed");
        assert_eq!(soon[0].payload, b"soon");
        assert_eq!(
            soon[0].attempts, 1,
            "delayed delivery is still the first attempt"
        );
        mq.ack(&soon[0]).await.unwrap();

        // --- P2 delivery modes: TTL (both backends) --------------------------------------------
        // A short-TTL message not consumed in time is dead-lettered (ttl-expired), not delivered; a
        // companion with no TTL is delivered normally.
        mq.publish_with_ttl_ctx(topic, b"perishable", Duration::from_millis(100), None)
            .await
            .unwrap();
        mq.publish_with_ttl_ctx(topic, b"keeps", Duration::ZERO, None)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let after_ttl = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(
            after_ttl
                .iter()
                .map(|m| m.payload.clone())
                .collect::<Vec<_>>(),
            vec![b"keeps".to_vec()],
            "the expired message is not delivered; the no-TTL one is"
        );
        mq.ack(&after_ttl[0]).await.unwrap();
        assert_eq!(
            mq.dead_letter_count(topic).await.unwrap(),
            1,
            "the expired message was dead-lettered"
        );
        let dl = mq
            .list_dead_letters(
                topic,
                &boatramp_core::messaging::DeadLetterFilter::default(),
            )
            .await
            .unwrap();
        assert_eq!(dl.len(), 1);
        assert_eq!(
            dl[0].last_error.as_deref(),
            Some("ttl-expired"),
            "the dead-letter records why it expired"
        );
        // Redrive the ttl dead-letter: it must become claimable + deliverable, NOT immediately
        // re-expire (both backends must clear expires_at on redrive — a deliberate operator retry).
        assert_eq!(mq.redrive_dead_letters(topic).await.unwrap(), 1);
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 0);
        let revived = mq.claim(topic, LEASE, 10, 5).await.unwrap();
        assert_eq!(
            revived
                .iter()
                .map(|m| m.payload.clone())
                .collect::<Vec<_>>(),
            vec![b"perishable".to_vec()],
            "the redriven ttl message is delivered, not re-expired"
        );
        for m in &revived {
            mq.ack(m).await.unwrap();
        }
        assert_eq!(mq.dead_letter_count(topic).await.unwrap(), 0);

        // --- P2 delivery modes: priority (both backends) ---------------------------------------
        // On its OWN sub-topic (the shared `topic` still holds the far-future delayed "later"). Two
        // normal then one high-priority; claim delivers the high one FIRST, then the two normal FIFO.
        let pt = format!("{topic}/prio");
        mq.publish_with_priority_ctx(&pt, b"lo-1", 0, None)
            .await
            .unwrap();
        mq.publish_with_priority_ctx(&pt, b"lo-2", 0, None)
            .await
            .unwrap();
        mq.publish_with_priority_ctx(&pt, b"HIGH", 9, None)
            .await
            .unwrap();
        let ordered = mq.claim(&pt, LEASE, 10, 5).await.unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|m| m.payload.clone())
                .collect::<Vec<_>>(),
            vec![b"HIGH".to_vec(), b"lo-1".to_vec(), b"lo-2".to_vec()],
            "high priority leases first, then the normal ones FIFO"
        );
        for m in &ordered {
            mq.ack(m).await.unwrap();
        }
        assert_eq!(mq.backlog(&pt).await.unwrap(), 0);
    }

    /// Conformance — **single-node** coordinator (`core::messaging::LogMessaging`).
    #[tokio::test]
    async fn conformance_single_node() {
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::messaging::LogMessaging;
        let mq = LogMessaging::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()));
        assert_conformance(&mq, "conformance/topic").await;
        // CI-hard poison-pill/DLQ matrix marker (see ci.yml `test-messaging-dlq`).
        println!("MESSAGING WQ DLQ MATRIX OK [single-node]");
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
        println!("MESSAGING WQ DLQ MATRIX OK [cluster]");
    }

    fn payloads(msgs: &[ClaimedMessage]) -> Vec<Vec<u8>> {
        msgs.iter().map(|m| m.payload.clone()).collect()
    }

    /// The **consumer-group** conformance battery: durable fan-out, independent
    /// per-group ack/nack, configurable start position, dead-letter, and the
    /// retention sweep — the same assertions must hold for every coordinator, so
    /// grouped delivery is identical single-node and cluster. Each sub-scenario
    /// runs on its own topic (fan-out means every publish reaches every group).
    async fn assert_grouped_conformance(mq: &dyn Messaging, base: &str) {
        use boatramp_core::messaging::StartPosition;
        const LEASE: Duration = Duration::from_secs(60);

        // --- fan-out + independent ack/nack + start position -------------------
        let t = base;
        for g in ["billing", "audit"] {
            assert!(mq
                .claim_grouped(t, g, StartPosition::Latest, LEASE, 10, 5)
                .await
                .unwrap()
                .is_empty());
        }
        mq.publish(t, b"a").await.unwrap();
        mq.publish(t, b"b").await.unwrap();

        // Each group independently receives BOTH, in order, attempt 1.
        let billing = mq
            .claim_grouped(t, "billing", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&billing), vec![b"a".to_vec(), b"b".to_vec()]);
        assert!(billing.iter().all(|m| m.attempts == 1));
        let audit = mq
            .claim_grouped(t, "audit", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&audit), vec![b"a".to_vec(), b"b".to_vec()]);

        // Leased: a re-claim sees nothing until ack/nack/expiry.
        assert!(mq
            .claim_grouped(t, "billing", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());

        // billing acks both → billing drains; audit is untouched.
        for m in &billing {
            mq.ack(m).await.unwrap();
        }
        assert!(mq
            .claim_grouped(t, "billing", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());

        // audit nacks both → redelivered with the attempt re-charged.
        for m in &audit {
            mq.nack(m).await.unwrap();
        }
        let audit2 = mq
            .claim_grouped(t, "audit", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&audit2), vec![b"a".to_vec(), b"b".to_vec()]);
        assert!(audit2.iter().all(|m| m.attempts == 2));
        for m in &audit2 {
            mq.ack(m).await.unwrap();
        }

        // A NEW `earliest` group replays the retained backlog; a NEW `latest`
        // group starts empty (only events after it subscribes).
        let replay = mq
            .claim_grouped(t, "replay", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&replay), vec![b"a".to_vec(), b"b".to_vec()]);
        for m in &replay {
            mq.ack(m).await.unwrap();
        }
        assert!(mq
            .claim_grouped(t, "live", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
        mq.publish(t, b"c").await.unwrap();
        let live = mq
            .claim_grouped(t, "live", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&live), vec![b"c".to_vec()]);
        for m in &live {
            mq.ack(m).await.unwrap();
        }

        // --- grouped dead-letter (own topic, single group) ---------------------
        let dl = format!("{base}-dl");
        assert!(mq
            .claim_grouped(&dl, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        mq.publish(&dl, b"z").await.unwrap();
        for expected in 1..=2 {
            let m = mq
                .claim_grouped(&dl, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
                .await
                .unwrap();
            assert_eq!(m.len(), 1, "grouped attempt {expected}");
            assert_eq!(m[0].attempts, expected);
        }
        // Third claim exhausts attempts → dead-letter, deliver nothing, stay empty.
        assert!(mq
            .claim_grouped(&dl, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        assert!(mq
            .claim_grouped(&dl, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        // The grouped dead-letter is VISIBLE, REDRIVABLE, and PURGEABLE — identically in single-node
        // and cluster (this conformance runs in both). Before the fix a fan-out dead-letter lived in
        // `mqgd/…` while the operator ops saw only `mqdead/…`, so `dead_letters` reported 0.
        assert_eq!(
            mq.dead_letter_count(&dl).await.unwrap(),
            1,
            "grouped DLQ counted"
        );
        assert_eq!(
            mq.redrive_dead_letters(&dl).await.unwrap(),
            1,
            "grouped redrive requeues it"
        );
        assert_eq!(mq.dead_letter_count(&dl).await.unwrap(), 0);
        // Redriven: it redelivers with its payload and a reset attempt count.
        let back = mq
            .claim_grouped(&dl, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
            .await
            .unwrap();
        assert_eq!(
            payloads(&back),
            vec![b"z".to_vec()],
            "redriven grouped message keeps its payload"
        );
        assert_eq!(back[0].attempts, 1, "redrive reset attempts");
        // Exhaust once more (attempt 2, then dead), then purge removes exactly it.
        assert_eq!(
            mq.claim_grouped(&dl, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(mq
            .claim_grouped(&dl, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count(&dl).await.unwrap(), 1);
        assert_eq!(
            mq.purge_dead_letters(&dl).await.unwrap(),
            1,
            "grouped purge removes it"
        );
        assert_eq!(mq.dead_letter_count(&dl).await.unwrap(), 0);

        // --- retention sweep reclaims only fully-consumed messages -------------
        let gc = format!("{base}-gc");
        for g in ["one", "two"] {
            assert!(mq
                .claim_grouped(&gc, g, StartPosition::Earliest, LEASE, 10, 5)
                .await
                .unwrap()
                .is_empty());
        }
        mq.publish(&gc, b"a").await.unwrap();
        mq.publish(&gc, b"b").await.unwrap();
        let one = mq
            .claim_grouped(&gc, "one", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        for m in &one {
            mq.ack(m).await.unwrap();
        }
        // "two" still needs both → nothing reclaimable yet.
        assert_eq!(
            mq.retention_sweep(&gc, messaging::GROUP_RETENTION_MS)
                .await
                .unwrap(),
            0
        );
        let two = mq
            .claim_grouped(&gc, "two", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&two), vec![b"a".to_vec(), b"b".to_vec()]);
        for m in &two {
            mq.ack(m).await.unwrap();
        }
        // Both consumed by every group → the sweep reclaims both, idempotently.
        assert_eq!(
            mq.retention_sweep(&gc, messaging::GROUP_RETENTION_MS)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            mq.retention_sweep(&gc, messaging::GROUP_RETENTION_MS)
                .await
                .unwrap(),
            0,
            "sweep is idempotent"
        );
        // A caught-up group still returns empty (state intact, log reclaimed).
        assert!(mq
            .claim_grouped(&gc, "one", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());

        // --- P2 group lifecycle: list / reset / delete (both backends) ------------------
        let lc = format!("{base}/lifecycle");
        for g in ["alpha", "beta"] {
            assert!(mq
                .claim_grouped(&lc, g, StartPosition::Earliest, LEASE, 10, 5)
                .await
                .unwrap()
                .is_empty());
        }
        mq.publish(&lc, b"L1").await.unwrap();
        mq.publish(&lc, b"L2").await.unwrap();
        // `alpha` consumes both (leaving them in-flight, unacked); `beta` stays at the head.
        let a = mq
            .claim_grouped(&lc, "alpha", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(a.len(), 2);
        // list_groups sees both, with alpha holding 2 in-flight and beta lagging 2.
        let groups = mq.list_groups(&lc).await.unwrap();
        assert_eq!(
            groups.iter().map(|g| g.group.clone()).collect::<Vec<_>>(),
            vec!["alpha".to_string(), "beta".to_string()],
            "both groups listed, name-ordered"
        );
        let alpha = groups.iter().find(|g| g.group == "alpha").unwrap();
        let beta = groups.iter().find(|g| g.group == "beta").unwrap();
        assert_eq!(alpha.in_flight, 2, "alpha holds two in-flight");
        assert_eq!(beta.lag, 2, "beta has not consumed the two messages");
        // reset alpha to Earliest → drops its in-flight + re-consumes the backlog.
        mq.reset_group(&lc, "alpha", StartPosition::Earliest)
            .await
            .unwrap();
        let re = mq
            .claim_grouped(&lc, "alpha", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(re.len(), 2, "reset re-consumes the whole backlog");
        // reset of a non-existent group fails closed.
        assert!(mq
            .reset_group(&lc, "ghost", StartPosition::Latest)
            .await
            .is_err());
        // delete beta → gone from the listing; alpha remains.
        mq.delete_group(&lc, "beta").await.unwrap();
        let after = mq.list_groups(&lc).await.unwrap();
        assert_eq!(
            after.iter().map(|g| g.group.clone()).collect::<Vec<_>>(),
            vec!["alpha".to_string()],
            "beta deleted, alpha remains"
        );
        // No-loss: deleting beta did NOT remove the shared retained log — alpha, reset to Earliest,
        // still re-consumes both messages (a delete only releases that group's pin, never shared data).
        mq.reset_group(&lc, "alpha", StartPosition::Earliest)
            .await
            .unwrap();
        assert_eq!(
            mq.claim_grouped(&lc, "alpha", StartPosition::Earliest, LEASE, 10, 5)
                .await
                .unwrap()
                .len(),
            2,
            "the retained backlog survived a sibling group's deletion"
        );

        // --- P2 durable replay: read retained grouped history from an offset, non-destructively -----
        let rp = format!("{base}/replay");
        // Register a group so the topic retains its fan-out log, then publish a backlog.
        assert!(mq
            .claim_grouped(&rp, "reader", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
        mq.publish(&rp, b"R1").await.unwrap();
        mq.publish(&rp, b"R2").await.unwrap();
        mq.publish(&rp, b"R3").await.unwrap();
        // Replay the whole retained history in publish order — a pure read (no lease, no attempt).
        let hist = mq.replay(&rp, None, 10).await.unwrap();
        assert_eq!(
            hist.iter().map(|m| m.payload.clone()).collect::<Vec<_>>(),
            vec![b"R1".to_vec(), b"R2".to_vec(), b"R3".to_vec()],
            "replay returns the retained history in publish order"
        );
        assert!(
            hist.iter().all(|m| m.attempts == 0 && !m.leased),
            "replay is a pure read: no lease, no attempt charge"
        );
        // `after` is exclusive — replaying past R1 yields only R2, R3.
        let tail = mq.replay(&rp, Some(&hist[0].id), 10).await.unwrap();
        assert_eq!(
            tail.iter().map(|m| m.payload.clone()).collect::<Vec<_>>(),
            vec![b"R2".to_vec(), b"R3".to_vec()],
            "replay from an offset is exclusive"
        );
        // `limit` is respected.
        assert_eq!(
            mq.replay(&rp, None, 2).await.unwrap().len(),
            2,
            "replay honours the limit"
        );
        // Non-destructive: replay touched no cursor, so it is repeatable AND a fresh `earliest` group
        // still consumes the whole backlog (nothing was consumed by the reads above).
        assert_eq!(
            mq.replay(&rp, None, 10).await.unwrap().len(),
            3,
            "replay is repeatable — it consumes nothing"
        );
        let consumer = mq
            .claim_grouped(&rp, "consumer", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(
            payloads(&consumer),
            vec![b"R1".to_vec(), b"R2".to_vec(), b"R3".to_vec()],
            "the retained history survived replay for a live consumer"
        );
        for m in &consumer {
            mq.ack(m).await.unwrap();
        }
    }

    /// Grouped conformance — **single-node** (`LogMessaging`).
    #[tokio::test]
    async fn conformance_grouped_single_node() {
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::messaging::LogMessaging;
        let mq = LogMessaging::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()));
        assert_grouped_conformance(&mq, "bus/grouped").await;
        // The P0 fix: grouped/fan-out dead-letters are visible/redrivable/purgeable single-node.
        println!("MESSAGING GROUPED DLQ MATRIX OK [single-node]");
    }

    /// Grouped conformance — **cluster** (`RaftMessaging`), on the leader. The
    /// identical battery proving the offset-log fan-out is byte-for-byte the same
    /// across modes (the shared `plan_claim_grouped` decision, applied in the SM).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn conformance_grouped_cluster() {
        let (rafts, mqs) = cluster_mq(3).await;
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();
        assert_grouped_conformance(mqs[&leader].as_ref(), "bus/grouped").await;
        shutdown(rafts).await;
        // The P0 fix proven at cluster parity (deterministic Raft apply can't touch object storage).
        println!("MESSAGING GROUPED DLQ MATRIX OK [cluster]");
    }

    /// **Cluster group-commit throughput bench** — proves the leader-only-gate fix coalesces
    /// concurrent publishes on the Raft path (each group ⇒ ONE `WriteOp::Batch` round-trip, not one
    /// per message). `#[ignore]`d (a perf measurement, not a merge gate); run manually / on a box:
    /// `cargo test -p boatramp-cluster --features raft,http --lib cluster_group_commit_concurrent_bench -- --ignored --nocapture`
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "cluster perf bench — run manually with --ignored"]
    async fn cluster_group_commit_concurrent_bench() {
        let (rafts, mqs) = cluster_mq(3).await;
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();
        let mq = mqs[&leader].clone();
        let payload = vec![b'x'; 256];

        // Baseline: one sequential publisher — one Raft round-trip per message.
        let seq_n = 500usize;
        let t = std::time::Instant::now();
        for _ in 0..seq_n {
            mq.publish("bench-seq", &payload).await.unwrap();
        }
        let seq = seq_n as f64 / t.elapsed().as_secs_f64();

        // Concurrent: CONC publishers in flight — the leader-only group-commit should drain them into
        // ONE WriteOp::Batch per round-trip, so aggregate throughput vastly exceeds the serial floor.
        let conc = 128usize;
        let per = 40usize;
        let t = std::time::Instant::now();
        let mut hs = Vec::with_capacity(conc);
        for _ in 0..conc {
            let mq = mq.clone();
            let p = payload.clone();
            hs.push(tokio::spawn(async move {
                for _ in 0..per {
                    mq.publish("bench-conc", &p).await.unwrap();
                }
            }));
        }
        for h in hs {
            h.await.unwrap();
        }
        let conc_rate = (conc * per) as f64 / t.elapsed().as_secs_f64();
        shutdown(rafts).await;

        println!(
            "CLUSTER GROUP-COMMIT BENCH: single {seq:.0} msg/s, concurrent(CONC={conc}) {conc_rate:.0} msg/s ({:.1}x)",
            conc_rate / seq
        );
        assert!(
            conc_rate > seq * 3.0,
            "the Raft group-commit must coalesce concurrent publishes: concurrent {conc_rate:.0} msg/s \
             should be >>3x the serial floor {seq:.0} msg/s"
        );
    }

    /// **C2 (cluster): purging an inline dead-letter releases its SA1 budget.** An A3-inlined
    /// work-queue payload is charged to `inline_inflight_bytes` at publish and stays charged while
    /// it sits dead-lettered (the record still carries the bytes). `purge_dead_letters` must release
    /// that charge — otherwise a flood of small messages that all dead-letter would permanently pin
    /// the aggregate-inline budget and force every later publish onto the object-store path. This is
    /// the cluster analog of the single-node C2 release; it reads the dead record from applied Raft
    /// state, classifies it inline, and decrements the budget.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_purge_releases_inline_budget() {
        use std::sync::atomic::Ordering::Relaxed;
        let (rafts, mqs) = cluster_mq(1).await;
        let mq = mqs[&1].clone();

        // Small work-queue payload ⇒ A3-inline ⇒ charged to the SA1 aggregate budget.
        let payload = b"inline-dead";
        mq.publish("t", payload).await.unwrap();
        assert_eq!(
            mq.inline_inflight_bytes.load(Relaxed),
            payload.len(),
            "an inlined work-queue publish charges the SA1 budget"
        );

        // Force a dead-letter: max_attempts=2 ⇒ two zero-lease claims, then the third dead-letters.
        for expected in 1..=2 {
            let m = mq.claim("t", Duration::ZERO, 10, 2).await.unwrap();
            assert_eq!(m.len(), 1, "attempt {expected}");
        }
        assert!(mq
            .claim("t", Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 1);
        assert_eq!(
            mq.inline_inflight_bytes.load(Relaxed),
            payload.len(),
            "the charge persists while the inline payload sits dead-lettered (record still holds it)"
        );

        // C2: purging the dead-letter releases the inline bytes back to the budget.
        assert_eq!(mq.purge_dead_letters("t").await.unwrap(), 1);
        assert_eq!(
            mq.inline_inflight_bytes.load(Relaxed),
            0,
            "purge releases the inline dead-letter's bytes from the SA1 budget"
        );

        shutdown(rafts).await;
    }

    /// **Grouped no-double-delivery across nodes.** A group registered cluster-wide
    /// is drained concurrently from every node; the leader serializes each group's
    /// claim, so each message is delivered to the group exactly once regardless of
    /// which node claimed it.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cluster_groups_fan_out_across_nodes() {
        use boatramp_core::messaging::StartPosition;
        let (rafts, mqs) = cluster_mq(3).await;
        let t = "bus/work";

        // Register the group (earliest, retention on) before publishing.
        assert!(mqs[&1]
            .claim_grouped(t, "g", StartPosition::Earliest, LEASE, 4, 5)
            .await
            .unwrap()
            .is_empty());
        const N: usize = 30;
        for i in 0..N {
            let node = (i as u64 % 3) + 1;
            mqs[&node]
                .publish(t, format!("m-{i}").as_bytes())
                .await
                .unwrap();
        }

        // Every node drains the same group concurrently; a long lease + no acks
        // means each stops on its first empty batch.
        let collected: Arc<StdMutex<Vec<ClaimedMessage>>> = Arc::new(StdMutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for id in 1..=3u64 {
            let mq = mqs[&id].clone();
            let collected = collected.clone();
            tasks.push(tokio::spawn(async move {
                // Drain until the group has yielded all N (shared count), tolerating TRANSIENT empty
                // batches. A grouped claim forwards to the leader (linearizable), but under CPU load a
                // just-published straggler may not be claimable at the instant a node polls, and if all
                // three nodes broke on their first empty batch a message could be left unclaimed (a
                // delivery-timing flake, not a loss). A long lease + no acks means re-polling is safe —
                // a claimed message stays leased and never reappears — so a bounded straggler window
                // removes the flake WITHOUT masking a real defect: the post-loop assertions still
                // require exactly N and zero duplicates.
                let mut empty_rounds = 0;
                loop {
                    if collected.lock().unwrap().len() >= N {
                        break;
                    }
                    let batch = mq
                        .claim_grouped(t, "g", StartPosition::Earliest, LEASE, 4, 5)
                        .await
                        .unwrap();
                    if batch.is_empty() {
                        empty_rounds += 1;
                        if empty_rounds >= 50 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                    empty_rounds = 0;
                    collected.lock().unwrap().extend(batch);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        let claimed = std::mem::take(&mut *collected.lock().unwrap());
        let ids: HashSet<&str> = claimed.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ids.len(),
            claimed.len(),
            "a grouped message was delivered to more than one node"
        );
        assert_eq!(
            claimed.len(),
            N,
            "every message reached the group exactly once"
        );
        let got: HashSet<String> = claimed
            .iter()
            .map(|m| String::from_utf8(m.payload.clone()).unwrap())
            .collect();
        let expected: HashSet<String> = (0..N).map(|i| format!("m-{i}")).collect();
        assert_eq!(got, expected);

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
