//! boatramp's internal messaging substrate: durable topics with at-least-once
//! consumer delivery, built on the existing [`Storage`] + [`kv::KvStore`]
//! backends — **no external broker**.
//!
//! It factors into three parts, only one of which is mode-specific:
//!
//! 1. a **durable append-only log** — message payloads in [`Storage`], the
//!    per-topic index/state in [`kv::KvStore`]. Publish touches a distinct key
//!    per message, so it needs **no coordination** and works on any backend.
//! 2. a **single-writer coordinator** over the one operation that needs
//!    atomicity — **claim** (never deliver one message to two consumers) — plus
//!    the ack / lease / visibility-timeout / dead-letter transitions. This is
//!    the thin per-mode piece; [`LogMessaging`] is the **single-node** one (an
//!    in-process mutex; cluster/Cloudflare coordinators plug in later behind the
//!    [`Messaging`] trait).
//! 3. a **dispatcher** (the server) that claims messages and runs consumer
//!    components under the handler limits regime.
//!
//! Guarantees: **at-least-once** with a visibility-timeout lease, redelivery on
//! lease expiry, **dead-letter after N attempts**, best-effort per-topic FIFO
//! (redelivery may reorder — documented). State lives in `KvStore`, so the
//! queue **survives restart** (a leased-but-expired message is simply
//! re-claimable). Topic strings are already namespaced by the caller (per
//! site/alias, with preview isolation).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::time::now_unix_ms;

use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::kv::KvStore;
use crate::{PutMeta, Storage};

/// A message claimed for delivery to a consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedMessage {
    /// Unique, roughly time-ordered message id.
    pub id: String,
    /// The topic it was published to.
    pub topic: String,
    /// The message body.
    pub payload: Vec<u8>,
    /// Delivery attempts so far, including this one (starts at 1).
    pub attempts: u32,
}

/// Why a messaging operation failed.
#[derive(Debug, Clone)]
pub enum MessagingError {
    /// A backend (storage/KV) or transport failure.
    Backend(String),
    /// A stored record could not be decoded.
    Decode(String),
}

impl MessagingError {
    fn backend<E: std::fmt::Display>(err: E) -> Self {
        Self::Backend(err.to_string())
    }
}

impl std::fmt::Display for MessagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(m) => write!(f, "messaging backend error: {m}"),
            Self::Decode(m) => write!(f, "messaging decode error: {m}"),
        }
    }
}

impl std::error::Error for MessagingError {}

/// A durable pub/sub topic substrate with at-least-once consumer delivery. The
/// concrete coordinator (single-node mutex, cluster Raft leader, Cloudflare
/// Durable Object) lives behind this trait, so the queue logic and the guest
/// `wasi:messaging` interface stay identical across deployment modes.
#[async_trait]
pub trait Messaging: Send + Sync {
    /// Append a message to `topic`. Coordination-free (a distinct key per
    /// message), so concurrent publishers never contend.
    async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError>;

    /// Atomically claim up to `max_batch` deliverable messages from `topic`,
    /// leasing each for `lease` (after which an un-acked message is redelivered).
    /// A message that has already been delivered `max_attempts` times is moved to
    /// the dead-letter store instead of being delivered again.
    async fn claim(
        &self,
        topic: &str,
        lease: Duration,
        max_batch: usize,
        max_attempts: u32,
    ) -> Result<Vec<ClaimedMessage>, MessagingError>;

    /// Acknowledge successful processing — the message is removed for good.
    async fn ack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError>;

    /// Negative-acknowledge — make the message immediately claimable again
    /// (a faster redelivery than waiting for the lease to expire). The attempt
    /// count is preserved, so it still dead-letters after `max_attempts`.
    async fn nack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError>;

    /// Number of messages still queued on `topic` (claimable *or* leased) — the
    /// consumer backlog / lag, for ops introspection. Default
    /// `0` for backends without introspection.
    async fn backlog(&self, _topic: &str) -> Result<usize, MessagingError> {
        Ok(0)
    }

    /// Number of dead-lettered messages on `topic` (exhausted `max_attempts`),
    /// for ops introspection. Default `0`.
    async fn dead_letter_count(&self, _topic: &str) -> Result<usize, MessagingError> {
        Ok(0)
    }

    /// **Purge** every dead-lettered message on `topic` — delete the preserved
    /// records *and* their payloads, reclaiming the space. Returns the number
    /// purged. The one operator action that clears the otherwise
    /// retained-until-cleared dead-letter store. Default no-op (`0`).
    async fn purge_dead_letters(&self, _topic: &str) -> Result<usize, MessagingError> {
        Ok(0)
    }

    /// **Redrive** every dead-lettered message on `topic` back onto the live
    /// queue with a fresh attempt count, so consumers retry them (the payload was
    /// preserved at dead-letter time, so nothing is lost). For replaying messages
    /// once the cause of failure is fixed. Returns the number redriven. Default
    /// no-op (`0`).
    async fn redrive_dead_letters(&self, _topic: &str) -> Result<usize, MessagingError> {
        Ok(0)
    }

    /// Subscribe to a **live, at-most-once** broadcast of `topic` — for SSE
    /// streams, *not* the durable consumer path. Every
    /// message published after the subscription is delivered once to each live
    /// subscriber; a slow subscriber that can't keep up **drops** messages
    /// (fire-and-forget). Each [`StreamEvent`] carries the durable message id so
    /// a client can resume via `Last-Event-ID`.
    ///
    /// `after` is the client's last-seen id (its `Last-Event-ID`): a backend
    /// that keeps a recent ring replays the buffered events with a strictly
    /// greater id before switching to the live feed (best-effort — the ring is
    /// bounded and only spans currently-subscribed topics). The default backend
    /// has no live channel (empty stream).
    fn subscribe(
        &self,
        _topic: &str,
        _after: Option<&str>,
    ) -> futures::stream::BoxStream<'static, StreamEvent> {
        futures::stream::empty().boxed()
    }
}

/// A live broadcast event delivered to SSE subscribers: the durable message id
/// (so clients can resume with `Last-Event-ID`) plus the payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEvent {
    /// The publishing message's durable id (monotonic, sortable as a string).
    pub id: String,
    /// The message body.
    pub payload: Vec<u8>,
}

/// Per-message index record. The payload itself lives in [`Storage`]; only this
/// tiny record is coordinated (in `KvStore` for single-node, in the Raft state
/// machine for a cluster — same shape either way, so the claim logic is shared).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// Pinned schema discriminant (`v1`), like every boatramp schema.
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// Delivery attempts charged so far.
    pub attempts: u32,
    /// Unix-millis until which the message is leased; `0` = claimable now.
    pub lease_until_ms: u64,
}

impl Record {
    /// A freshly-published record: never delivered, claimable immediately.
    pub fn fresh() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            attempts: 0,
            lease_until_ms: 0,
        }
    }
}

/// One transition the [`plan_claim`] decision produces for a single message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimAction {
    /// Lease the message to the claimer: write `record` back (attempt charged,
    /// lease set) and deliver it.
    Lease {
        /// The message id.
        id: String,
        /// The updated record to persist.
        record: Record,
    },
    /// The message exhausted `max_attempts`: move it to the dead-letter store
    /// (`record` preserved) instead of delivering it.
    DeadLetter {
        /// The message id.
        id: String,
        /// The record to preserve under the dead-letter key.
        record: Record,
    },
}

/// The **pure, deterministic** claim/dead-letter decision shared by every
/// coordinator (the single-node mutex, the cluster Raft state machine, ...).
///
/// Given a topic's index `records` and the claim parameters, it returns the
/// transitions to apply, in order — no I/O, no clock reads (the caller stamps
/// `now_ms`), so a cluster's replicas all compute the *same* result and
/// converge. Records are leased in id (≈ publish) order until `max_batch` are
/// leased; a record still under lease is skipped, and one that has already been
/// delivered `max_attempts` times is dead-lettered (not charged against the
/// batch).
pub fn plan_claim(
    mut records: Vec<(String, Record)>,
    now_ms: u64,
    lease_ms: u64,
    max_batch: usize,
    max_attempts: u32,
) -> Vec<ClaimAction> {
    // Lexical order on `{millis}-{...}` ids ≈ publish order (best-effort FIFO).
    records.sort_by(|a, b| a.0.cmp(&b.0));
    let mut actions = Vec::new();
    let mut leased = 0;
    for (id, mut record) in records {
        if leased >= max_batch {
            break;
        }
        if record.lease_until_ms > now_ms {
            continue; // still leased to someone else
        }
        if record.attempts >= max_attempts {
            actions.push(ClaimAction::DeadLetter { id, record });
            continue;
        }
        record.attempts += 1;
        record.lease_until_ms = now_ms + lease_ms;
        actions.push(ClaimAction::Lease { id, record });
        leased += 1;
    }
    actions
}

/// KV/state key for a message's index record.
pub fn meta_key(topic: &str, id: &str) -> String {
    format!("mq/{topic}/{id}")
}
/// KV/state prefix for a topic's index records.
pub fn meta_prefix(topic: &str) -> String {
    format!("mq/{topic}/")
}
/// [`Storage`] key for a message's payload bytes.
pub fn payload_key(topic: &str, id: &str) -> String {
    format!("mqp/{topic}/{id}")
}
/// KV/state key for a dead-lettered message's preserved record.
pub fn dead_key(topic: &str, id: &str) -> String {
    format!("mqdead/{topic}/{id}")
}
/// KV/state prefix for a topic's dead-lettered records.
pub fn dead_prefix(topic: &str) -> String {
    format!("mqdead/{topic}/")
}

/// True when `key` is a *direct* child of `prefix` (its id segment has no
/// further `/`), so a parent topic's scan never includes its subtopics.
pub fn is_direct_child(key: &str, prefix: &str) -> bool {
    key.len() > prefix.len() && !key[prefix.len()..].contains('/')
}

/// Per-topic live state: the bounded ring of recent events (for best-effort
/// `Last-Event-ID` resume) plus the set of live SSE subscribers. A hub exists
/// only while a topic has at least one subscriber — so idle topics keep no ring
/// and the live map stays bounded by the number of *active* streams.
#[derive(Default)]
struct TopicHub {
    /// Recent events retained for resume (newest at the back), capped at
    /// [`STREAM_RING`].
    recent: std::collections::VecDeque<StreamEvent>,
    /// Live subscribers' channels.
    subscribers: Vec<futures::channel::mpsc::Sender<StreamEvent>>,
}

/// How many recent events each live topic retains for `Last-Event-ID` resume.
const STREAM_RING: usize = 64;

/// The **local** live-stream fan-out for SSE (`subscribe`): per-topic hubs with
/// a bounded resume ring, shared by every coordinator. Single-node uses one
/// instance directly; in a cluster each node holds one and a stream bus calls
/// [`broadcast`](StreamHubs::broadcast) on **every** node's instance when an
/// event is published, so a client connected to any node sees events published
/// on any node. At-most-once, fire-and-forget: a full
/// subscriber buffer drops the message; a tolerated inter-node hop loss is the
/// same class of drop.
#[derive(Default)]
pub struct StreamHubs {
    /// Live SSE-stream hubs per topic. A plain mutex: only non-blocking work
    /// (`try_send`, ring trim) runs under it, never an await.
    live: std::sync::Mutex<HashMap<String, TopicHub>>,
}

impl StreamHubs {
    /// A fresh, empty set of hubs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fan a published event out to this node's live subscribers of `topic` and
    /// append it to the topic's resume ring. Disconnected subscribers are
    /// dropped; a subscriber whose buffer is full has the message skipped (not
    /// blocked). Does nothing for a topic with no local hub (no subscribers), so
    /// idle topics accrue no ring.
    pub fn broadcast(&self, topic: &str, id: &str, payload: &[u8]) {
        let event = StreamEvent {
            id: id.to_string(),
            payload: payload.to_vec(),
        };
        let mut live = self.live.lock().unwrap();
        let Some(hub) = live.get_mut(topic) else {
            return; // no subscribers → nothing to buffer or deliver
        };
        hub.subscribers
            .retain_mut(|tx| match tx.try_send(event.clone()) {
                Ok(()) => true,
                Err(err) => !err.is_disconnected(), // keep on full, drop if gone
            });
        hub.recent.push_back(event);
        while hub.recent.len() > STREAM_RING {
            hub.recent.pop_front();
        }
        // When the last subscriber has gone, drop the hub (and its ring): resume
        // is best-effort and only spans overlapping subscribers.
        if hub.subscribers.is_empty() {
            live.remove(topic);
        }
    }

    /// Subscribe to this node's live feed for `topic`, replaying the buffered
    /// resume tail strictly after `after` (its `Last-Event-ID`) before the live
    /// events. See [`Messaging::subscribe`] for the full contract.
    pub fn subscribe(
        &self,
        topic: &str,
        after: Option<&str>,
    ) -> futures::stream::BoxStream<'static, StreamEvent> {
        // Bounded so a stalled SSE client can't grow memory unbounded; a full
        // buffer drops messages (at-most-once).
        let (tx, rx) = futures::channel::mpsc::channel(64);
        // Register the subscriber and snapshot the resume backlog under the same
        // lock, so no event published concurrently is missed *or* duplicated:
        // anything already in the ring is replayed; anything published after we
        // register arrives only on the live channel.
        let replay: Vec<StreamEvent> = {
            let mut live = self.live.lock().unwrap();
            let hub = live.entry(topic.to_string()).or_default();
            let replay = match after {
                Some(after) => hub
                    .recent
                    .iter()
                    .filter(|event| event.id.as_str() > after)
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };
            hub.subscribers.push(tx);
            replay
        };
        if replay.is_empty() {
            rx.boxed()
        } else {
            futures::stream::iter(replay).chain(rx).boxed()
        }
    }
}

/// The **single-node** [`Messaging`]: a durable log over [`Storage`] +
/// [`kv::KvStore`] with an in-process mutex as the single-writer coordinator.
pub struct LogMessaging {
    storage: Arc<dyn Storage>,
    kv: Arc<dyn KvStore>,
    /// Serializes `claim` so a message is never leased to two consumers — the
    /// single-node coordinator (cluster/Cloudflare swap this for Raft/DO). A
    /// runtime-agnostic async mutex, held across the await points in `claim`.
    claim_lock: futures::lock::Mutex<()>,
    /// Process-local tiebreaker for message ids published within the same ms.
    seq: AtomicU64,
    /// Local live SSE-stream fan-out (at-most-once + resume ring).
    hubs: StreamHubs,
}

impl LogMessaging {
    /// Build over the given blob + KV backends.
    pub fn new(storage: Arc<dyn Storage>, kv: Arc<dyn KvStore>) -> Self {
        Self {
            storage,
            kv,
            claim_lock: futures::lock::Mutex::new(()),
            seq: AtomicU64::new(0),
            hubs: StreamHubs::new(),
        }
    }

    async fn read_payload(&self, topic: &str, id: &str) -> Result<Vec<u8>, MessagingError> {
        let object = self
            .storage
            .get(&payload_key(topic, id))
            .await
            .map_err(MessagingError::backend)?;
        let mut body = object.body;
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.map_err(MessagingError::backend)?);
        }
        Ok(buf)
    }

    /// Count KV keys that are *direct* children of `prefix` (the id segment has
    /// no further `/`), so a parent topic's count never includes its subtopics —
    /// the same scoping rule `claim` uses.
    async fn count_direct(&self, prefix: &str) -> Result<usize, MessagingError> {
        let keys = self
            .kv
            .list_prefix(prefix)
            .await
            .map_err(MessagingError::backend)?;
        Ok(keys.iter().filter(|k| is_direct_child(k, prefix)).count())
    }
}

#[async_trait]
impl Messaging for LogMessaging {
    async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError> {
        let id = format!(
            "{:013}-{:016x}",
            now_unix_ms(),
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        // Payload first, then the index record — so the record never references
        // a missing payload.
        let bytes = bytes::Bytes::copy_from_slice(payload);
        let body = futures::stream::once(async move { Ok(bytes) }).boxed();
        self.storage
            .put(&payload_key(topic, &id), body, PutMeta::default())
            .await
            .map_err(MessagingError::backend)?;
        let json = serde_json::to_vec(&Record::fresh()).map_err(MessagingError::backend)?;
        self.kv
            .put(&meta_key(topic, &id), json)
            .await
            .map_err(MessagingError::backend)?;
        // Notify live SSE subscribers (best-effort, separate from the durable
        // queue above).
        self.hubs.broadcast(topic, &id, payload);
        Ok(())
    }

    async fn claim(
        &self,
        topic: &str,
        lease: Duration,
        max_batch: usize,
        max_attempts: u32,
    ) -> Result<Vec<ClaimedMessage>, MessagingError> {
        // Single-writer: only one claim runs at a time, so a message is leased
        // to exactly one consumer (the per-process coordinator — a cluster swaps
        // this mutex for the Raft leader applying the same `plan_claim`).
        let _guard = self.claim_lock.lock().await;
        let now = now_unix_ms();
        let prefix = meta_prefix(topic);
        let keys = self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?;

        // Load the topic's direct-child index records, then run the shared,
        // deterministic decision over them.
        let mut records = Vec::new();
        for key in keys {
            if !is_direct_child(&key, &prefix) {
                continue; // skip sub-topics sharing the prefix
            }
            let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? else {
                continue; // raced with an ack
            };
            let record: Record =
                serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
            records.push((key[prefix.len()..].to_string(), record));
        }
        let actions = plan_claim(
            records,
            now,
            lease.as_millis() as u64,
            max_batch,
            max_attempts,
        );

        let mut claimed = Vec::new();
        for action in actions {
            match action {
                ClaimAction::Lease { id, record } => {
                    let json = serde_json::to_vec(&record).map_err(MessagingError::backend)?;
                    self.kv
                        .put(&meta_key(topic, &id), json)
                        .await
                        .map_err(MessagingError::backend)?;
                    let payload = self.read_payload(topic, &id).await?;
                    claimed.push(ClaimedMessage {
                        id,
                        topic: topic.to_string(),
                        payload,
                        attempts: record.attempts,
                    });
                }
                ClaimAction::DeadLetter { id, record } => {
                    // Exhausted: move the record to the dead-letter store
                    // (keep the payload), stop delivering.
                    let json = serde_json::to_vec(&record).map_err(MessagingError::backend)?;
                    self.kv
                        .put(&dead_key(topic, &id), json)
                        .await
                        .map_err(MessagingError::backend)?;
                    self.kv
                        .delete(&meta_key(topic, &id))
                        .await
                        .map_err(MessagingError::backend)?;
                }
            }
        }
        Ok(claimed)
    }

    async fn ack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
        self.kv
            .delete(&meta_key(&msg.topic, &msg.id))
            .await
            .map_err(MessagingError::backend)?;
        self.storage
            .delete(&payload_key(&msg.topic, &msg.id))
            .await
            .map_err(MessagingError::backend)?;
        Ok(())
    }

    async fn backlog(&self, topic: &str) -> Result<usize, MessagingError> {
        self.count_direct(&meta_prefix(topic)).await
    }

    async fn dead_letter_count(&self, topic: &str) -> Result<usize, MessagingError> {
        self.count_direct(&dead_prefix(topic)).await
    }

    async fn nack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
        let key = meta_key(&msg.topic, &msg.id);
        let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? else {
            return Ok(()); // already acked/gone
        };
        let mut record: Record =
            serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
        record.lease_until_ms = 0; // claimable again now
        let json = serde_json::to_vec(&record).map_err(MessagingError::backend)?;
        self.kv
            .put(&key, json)
            .await
            .map_err(MessagingError::backend)?;
        Ok(())
    }

    async fn purge_dead_letters(&self, topic: &str) -> Result<usize, MessagingError> {
        let prefix = dead_prefix(topic);
        let keys = self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?;
        let mut purged = 0;
        for key in keys {
            if !is_direct_child(&key, &prefix) {
                continue; // a subtopic's dead letters aren't this topic's
            }
            let id = &key[prefix.len()..];
            // Drop the preserved payload (kept at dead-letter time) then the
            // dead record — order mirrors `ack` (payload, then index).
            self.storage
                .delete(&payload_key(topic, id))
                .await
                .map_err(MessagingError::backend)?;
            self.kv
                .delete(&key)
                .await
                .map_err(MessagingError::backend)?;
            purged += 1;
        }
        Ok(purged)
    }

    async fn redrive_dead_letters(&self, topic: &str) -> Result<usize, MessagingError> {
        let prefix = dead_prefix(topic);
        let keys = self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?;
        let mut redriven = 0;
        for key in keys {
            if !is_direct_child(&key, &prefix) {
                continue;
            }
            let id = &key[prefix.len()..];
            // Re-arm a fresh, immediately-claimable record (the payload is still
            // present), *then* drop the dead record — so a crash in between leaves
            // the message recoverable (live) rather than orphaning its payload.
            let json = serde_json::to_vec(&Record::fresh()).map_err(MessagingError::backend)?;
            self.kv
                .put(&meta_key(topic, id), json)
                .await
                .map_err(MessagingError::backend)?;
            self.kv
                .delete(&key)
                .await
                .map_err(MessagingError::backend)?;
            redriven += 1;
        }
        Ok(redriven)
    }

    fn subscribe(
        &self,
        topic: &str,
        after: Option<&str>,
    ) -> futures::stream::BoxStream<'static, StreamEvent> {
        self.hubs.subscribe(topic, after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryKv;
    use crate::{ByteStream, GetObject, ObjectMeta, StorageError};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Minimal in-memory blob store for the messaging tests.
    #[derive(Default)]
    struct MemStorage {
        objects: Mutex<HashMap<String, Vec<u8>>>,
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
            let size = buf.len() as u64;
            self.objects.lock().unwrap().insert(key.to_string(), buf);
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(size),
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

    fn mq() -> LogMessaging {
        LogMessaging::new(Arc::new(MemStorage::default()), Arc::new(MemoryKv::new()))
    }

    const LEASE: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn publish_claim_ack_roundtrip_and_fifo() {
        let mq = mq();
        mq.publish("orders/created", b"a").await.unwrap();
        mq.publish("orders/created", b"b").await.unwrap();

        let batch = mq.claim("orders/created", LEASE, 10, 5).await.unwrap();
        assert_eq!(batch.len(), 2);
        // Best-effort FIFO: published order preserved.
        assert_eq!(batch[0].payload, b"a");
        assert_eq!(batch[1].payload, b"b");
        assert_eq!(batch[0].attempts, 1);

        // Leased: a second claim sees nothing until the lease lapses or an ack.
        assert!(mq
            .claim("orders/created", LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());

        for m in &batch {
            mq.ack(m).await.unwrap();
        }
        // Acked messages are gone.
        assert!(mq
            .claim("orders/created", LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn topic_scoping_excludes_subtopics() {
        let mq = mq();
        mq.publish("orders", b"top").await.unwrap();
        mq.publish("orders/created", b"sub").await.unwrap();
        let batch = mq.claim("orders", LEASE, 10, 5).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload, b"top");
    }

    #[tokio::test]
    async fn lease_expiry_redelivers() {
        let mq = mq();
        mq.publish("t", b"x").await.unwrap();
        // Zero lease: the message is immediately re-claimable (redelivery).
        let first = mq.claim("t", Duration::ZERO, 10, 5).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].attempts, 1);
        let second = mq.claim("t", LEASE, 10, 5).await.unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].attempts, 2); // redelivered, attempt charged again
    }

    #[tokio::test]
    async fn nack_makes_claimable_again() {
        let mq = mq();
        mq.publish("t", b"x").await.unwrap();
        let m = mq.claim("t", LEASE, 10, 5).await.unwrap().pop().unwrap();
        mq.nack(&m).await.unwrap();
        let again = mq.claim("t", LEASE, 10, 5).await.unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].attempts, 2);
    }

    #[tokio::test]
    async fn subscribe_receives_live_broadcast() {
        use futures::StreamExt;
        let mq = mq();
        let mut sub = mq.subscribe("events", None);
        // A message published *before* subscribing isn't replayed (live only),
        // so publish after subscribing.
        mq.publish("events", b"hello").await.unwrap();
        mq.publish("events", b"world").await.unwrap();
        assert_eq!(sub.next().await.unwrap().payload, b"hello");
        assert_eq!(sub.next().await.unwrap().payload, b"world");
        // A different topic isn't delivered here.
        mq.publish("other", b"nope").await.unwrap();
        mq.publish("events", b"again").await.unwrap();
        assert_eq!(sub.next().await.unwrap().payload, b"again");
    }

    #[tokio::test]
    async fn last_event_id_replays_recent_then_goes_live() {
        use futures::StreamExt;
        let mq = mq();
        // A first subscriber keeps the topic's hub (and ring) alive while three
        // events are published.
        let mut keepalive = mq.subscribe("events", None);
        mq.publish("events", b"one").await.unwrap();
        mq.publish("events", b"two").await.unwrap();
        mq.publish("events", b"three").await.unwrap();
        // Capture the id of the first event (the keepalive sub sees them live).
        let first = keepalive.next().await.unwrap();
        assert_eq!(first.payload, b"one");

        // A late subscriber resuming from the first id gets the buffered tail
        // (two, three) before any live event.
        let mut resumed = mq.subscribe("events", Some(&first.id));
        assert_eq!(resumed.next().await.unwrap().payload, b"two");
        assert_eq!(resumed.next().await.unwrap().payload, b"three");
        // Then it switches to the live feed.
        mq.publish("events", b"four").await.unwrap();
        assert_eq!(resumed.next().await.unwrap().payload, b"four");
    }

    #[tokio::test]
    async fn dropped_subscriber_is_pruned_without_error() {
        let mq = mq();
        {
            let _sub = mq.subscribe("events", None);
        } // dropped
          // Publishing after the subscriber is gone must not error.
        mq.publish("events", b"x").await.unwrap();
    }

    #[tokio::test]
    async fn dead_letters_after_max_attempts() {
        let mq = mq();
        mq.publish("t", b"x").await.unwrap();
        // max_attempts = 2: deliver twice (re-claiming via zero lease), then the
        // third claim dead-letters instead of delivering.
        for expected in 1..=2 {
            let m = mq.claim("t", Duration::ZERO, 10, 2).await.unwrap();
            assert_eq!(m.len(), 1, "attempt {expected}");
            assert_eq!(m[0].attempts, expected);
        }
        let exhausted = mq.claim("t", Duration::ZERO, 10, 2).await.unwrap();
        assert!(
            exhausted.is_empty(),
            "should dead-letter, not deliver a 3rd time"
        );
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn purge_dead_letters_clears_records_and_payloads() {
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mq = LogMessaging::new(storage.clone(), kv);
        mq.publish("t", b"x").await.unwrap();
        // max_attempts = 1: deliver once, then the next claim dead-letters.
        let id = mq.claim("t", Duration::ZERO, 10, 1).await.unwrap()[0]
            .id
            .clone();
        assert!(mq
            .claim("t", Duration::ZERO, 10, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 1);

        let purged = mq.purge_dead_letters("t").await.unwrap();
        assert_eq!(purged, 1);
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 0);
        // The payload is reclaimed too, not just the index record.
        assert!(
            storage.head(&payload_key("t", &id)).await.is_err(),
            "purge frees the dead-lettered payload"
        );
    }

    #[tokio::test]
    async fn redrive_dead_letters_requeues_with_fresh_attempts() {
        let mq = mq();
        mq.publish("t", b"x").await.unwrap();
        assert_eq!(mq.claim("t", Duration::ZERO, 10, 1).await.unwrap().len(), 1);
        assert!(mq
            .claim("t", Duration::ZERO, 10, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 1);

        let redriven = mq.redrive_dead_letters("t").await.unwrap();
        assert_eq!(redriven, 1);
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 0);
        assert_eq!(mq.backlog("t").await.unwrap(), 1);
        // Claimable again — original payload, attempt count reset to fresh.
        let again = mq.claim("t", LEASE, 10, 5).await.unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].payload, b"x");
        assert_eq!(again[0].attempts, 1, "fresh attempts after redrive");
    }

    /// The "survives restart" guarantee: queue state
    /// lives in `Storage`/`KvStore`, so a fresh `LogMessaging` over the same
    /// backends still has the un-acked message (re-claimable) and not the acked
    /// one.
    #[tokio::test]
    async fn survives_restart_over_shared_backends() {
        // Shared durable backends across the simulated restart.
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());

        // First "process": publish two, claim both (zero lease → still
        // claimable), ack only the first, then drop the messaging instance.
        {
            let mq = LogMessaging::new(storage.clone(), kv.clone());
            mq.publish("orders", b"a").await.unwrap();
            mq.publish("orders", b"b").await.unwrap();
            let batch = mq.claim("orders", Duration::ZERO, 10, 5).await.unwrap();
            assert_eq!(batch.len(), 2);
            mq.ack(&batch[0]).await.unwrap(); // ack "a"
        } // mq dropped — simulate a restart

        // Second "process" over the same backends: the durable index/payload
        // survived. "a" is gone (acked); "b" is re-claimable (attempt re-charged).
        let mq = LogMessaging::new(storage, kv);
        let batch = mq.claim("orders", LEASE, 10, 5).await.unwrap();
        assert_eq!(batch.len(), 1, "only the un-acked message survives");
        assert_eq!(batch[0].payload, b"b");
        assert_eq!(batch[0].attempts, 2, "redelivery re-charges the attempt");
    }
}
