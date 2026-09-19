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
        }
    }

    /// Group-commit a publisher's `MqPublish` op(s) (A2/A4): push them, take the gate, and — as the
    /// gate-holder — drain the queue and propose EVERYONE's ops in one `WriteOp::Batch` (one Raft
    /// round-trip), signalling each. A publisher flushed by an earlier gate-holder finds its one-shot
    /// already resolved. Returns only after the group is replicated + applied (at-least-once); a
    /// failed proposal fails every member. Same self-bounded, no-spawn pattern as
    /// `LogMessaging::group_commit`.
    async fn group_commit(&self, ops: Vec<WriteOp>) -> Result<(), MessagingError> {
        let (done_tx, done_rx) = futures::channel::oneshot::channel();
        self.commit_queue
            .lock()
            .unwrap()
            .push(ClusterPublishJob { ops, done: done_tx });
        {
            let _turn = self.commit_gate.lock().await;
            // Drain jobs until the per-commit OP budget is met (a batch job carries many ops, so the
            // bound is on ops, not jobs — else one turn could build an unbounded Raft entry). Always
            // take at least one job so an oversized single batch (bounded by the host's
            // PUBLISH_BATCH_MAX) still makes progress.
            let batch: Vec<ClusterPublishJob> = {
                let mut q = self.commit_queue.lock().unwrap();
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
            if !batch.is_empty() {
                let mut ops = Vec::with_capacity(batch.len());
                let mut dones = Vec::with_capacity(batch.len());
                for job in batch {
                    let mut job = job;
                    ops.append(&mut job.ops);
                    dones.push(job.done);
                }
                // A proposal can fail AFTER the entry actually committed+applied (leader lost, or the
                // forwarder timed out on the reply). That surfaces here as `Err` for a group that in
                // fact committed — a false NEGATIVE, which is the at-least-once-safe direction: the
                // caller may retry and produce a tolerable duplicate. Never invert this into a false
                // positive (Ok on an uncommitted group).
                let outcome = self.propose(WriteOp::Batch(ops)).await.map(|_| ());
                for done in dones {
                    // Clone the shared outcome to every member (fail-all on a failed proposal).
                    let _ = done.send(outcome.clone());
                }
            }
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
        // Build this message's replicated `MqPublish` op (doing any object-store payload write first),
        // then commit it in one group-commit. Factored so `publish_batch_ctx` reuses the identical
        // A3/SA1/retain decisions and coalesces N messages into one Raft entry.
        let (id, op) = self
            .build_publish_op(topic, payload, signed_context, 0, 0)
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
        // Delivery-mode delay (P2): the issuing node stamps the absolute not-before (deterministic
        // across replicas — the apply just copies it into the record's lease). 0 ⇒ claimable now.
        let not_before_ms = if delay.is_zero() {
            0
        } else {
            now_unix_ms().saturating_add(delay.as_millis() as u64)
        };
        let (id, op) = self
            .build_publish_op(topic, payload, signed_context, not_before_ms, 0)
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
        // Delivery-mode TTL (P2): the issuing node stamps the absolute expires-at (deterministic).
        // 0 ⇒ no expiry. A claim after expiry dead-letters it (ttl-expired) instead of delivering.
        let expires_at_ms = if ttl.is_zero() {
            0
        } else {
            now_unix_ms().saturating_add(ttl.as_millis() as u64)
        };
        let (id, op) = self
            .build_publish_op(topic, payload, signed_context, 0, expires_at_ms)
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
        // A4 — coalesce the WHOLE batch into ONE replicated `WriteOp::Batch`: build every message's
        // `MqPublish` op (each doing its own payload-first object-store write + A3/SA1 decision), then
        // a single `group_commit`. Fail-all: any build error returns before we commit, so no message
        // in the batch is delivered. Every message shares the one host-minted `signed_context`.
        let mut ops = Vec::with_capacity(messages.len());
        let mut broadcasts: Vec<(&str, String, &[u8])> = Vec::with_capacity(messages.len());
        for (topic, payload) in messages {
            let (id, op) = self
                .build_publish_op(topic, payload, signed_context, 0, 0)
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
        if !msg.group.is_empty() {
            self.propose(WriteOp::MqNackGrouped {
                topic: msg.topic.clone(),
                group: msg.group.clone(),
                id: msg.id.clone(),
            })
            .await?;
            return Ok(());
        }
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
        for id in &ids {
            self.storage
                .delete(&messaging::payload_key(topic, id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
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
        self.propose(WriteOp::Batch(ops)).await?;
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
        self.propose(WriteOp::Batch(ops)).await?;
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
        let mut deletes: Vec<WriteOp> = Vec::with_capacity(matched.len());
        for dl in &matched {
            let key = if dl.group.is_empty() {
                messaging::dead_key(topic, &dl.id)
            } else {
                messaging::gdead_key(topic, &dl.group, &dl.id)
            };
            deletes.push(WriteOp::Delete { key });
        }
        self.propose(WriteOp::Batch(deletes)).await?;
        for dl in matched.iter().filter(|dl| dl.group.is_empty()) {
            self.storage
                .delete(&messaging::payload_key(topic, &dl.id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
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

    async fn retention_sweep(&self, topic: &str) -> Result<usize, MessagingError> {
        // The state machine reclaims the replicated log entries no group needs and
        // returns their ids; only the client can delete the `Storage` payloads
        // (consensus never touches `Storage`). Idempotent under concurrent sweeps:
        // the SM applies proposals in order, so a second sweep sees the first's
        // deletions, and a repeated `Storage` delete is a no-op.
        let response = self
            .propose(WriteOp::MqSweepGrouped {
                topic: topic.to_string(),
                now_ms: now_unix_ms(),
            })
            .await?;
        let WriteResponse::Reclaimed(ids) = response else {
            return Err(MessagingError::Backend(
                "sweep proposal returned a non-sweep response".into(),
            ));
        };
        for id in &ids {
            self.storage
                .delete(&messaging::gpayload_key(topic, id))
                .await
                .map_err(|e| MessagingError::Backend(e.to_string()))?;
        }
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
        assert_eq!(
            mq.purge_dead_letters(topic).await.unwrap(),
            1,
            "purge clears the ttl dead-letter"
        );
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
        assert_eq!(mq.retention_sweep(&gc).await.unwrap(), 0);
        let two = mq
            .claim_grouped(&gc, "two", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&two), vec![b"a".to_vec(), b"b".to_vec()]);
        for m in &two {
            mq.ack(m).await.unwrap();
        }
        // Both consumed by every group → the sweep reclaims both, idempotently.
        assert_eq!(mq.retention_sweep(&gc).await.unwrap(), 2);
        assert_eq!(
            mq.retention_sweep(&gc).await.unwrap(),
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
