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
    /// The consumer group this was claimed for. Empty (`""`) is the default
    /// work-queue (competing consumers, delete-on-ack); a non-empty group is a
    /// durable fan-out subscriber with its own cursor. `ack`/`nack` branch on it.
    pub group: String,
}

// A new consumer group's start position — defined in `boatramp-types` (so the
// deploy config can carry it) and re-exported here for the messaging API.
pub use boatramp_types::config::StartPosition;

/// Why a messaging operation failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MessagingError {
    /// A backend (storage/KV) or transport failure.
    #[error("messaging backend error: {0}")]
    Backend(String),
    /// A stored record could not be decoded.
    #[error("messaging decode error: {0}")]
    Decode(String),
}

impl MessagingError {
    fn backend<E: std::fmt::Display>(err: E) -> Self {
        Self::Backend(err.to_string())
    }
}

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

    /// Claim up to `max_batch` deliverable messages for a **consumer group** — a
    /// durable fan-out subscriber that consumes *every* message on `topic`
    /// independently of other groups (its own cursor, lease, retry, dead-letter),
    /// as opposed to [`claim`](Self::claim)'s competing-consumer work-queue. A new
    /// group's initial cursor is set by `start`. The claimed messages carry
    /// `group`, so [`ack`](Self::ack) / [`nack`](Self::nack) route to the group's
    /// state. The default impl supports only the default group (`""`, delegating
    /// to `claim`) and errors otherwise, so a backend without group support fails
    /// closed rather than silently under-delivering.
    async fn claim_grouped(
        &self,
        topic: &str,
        group: &str,
        _start: StartPosition,
        lease: Duration,
        max_batch: usize,
        max_attempts: u32,
    ) -> Result<Vec<ClaimedMessage>, MessagingError> {
        if group.is_empty() {
            return self.claim(topic, lease, max_batch, max_attempts).await;
        }
        Err(MessagingError::Backend(
            "this messaging backend does not support consumer groups".into(),
        ))
    }

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

    /// Reclaim the retained fan-out log + payloads on a **grouped** `topic` that
    /// every consumer group has already consumed (a message below every group's
    /// high-water with none holding it in-flight), with an age-based TTL backstop.
    /// A *periodic* maintenance sweep the scheduler calls off the hot claim path —
    /// bounds a grouped topic's storage without slowing delivery. Returns the
    /// number reclaimed; default no-op (`0`) for backends without a retained log.
    async fn retention_sweep(&self, _topic: &str) -> Result<usize, MessagingError> {
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

// --- consumer-group (durable fan-out) keyspace: the offset-log model ---
// The default work-queue above deletes a message on the single ack. Fan-out
// needs the message **retained** until every group has consumed it, so a grouped
// topic keeps one parallel, retained **append-only log** (`mqglog`) + payload
// (`mqgp`), plus a per-topic `logmax` gate marker. A group is **not** a row per
// backlog message: it is one compact `GroupState { hwm, in_flight }` value
// (`mqgstate`) — the high-water it has leased up to, and its bounded in-flight
// set. New messages for a group are simply the log ids **> hwm** (a bounded
// range scan, never a full-log materialization). Retention is reclaimed by a
// **separate** [`LogMessaging::gc_grouped`] sweep, not the hot claim path.

/// KV key for a grouped topic's retained log entry (existence marker; the id
/// carries the publish time, so no value is needed).
pub fn glog_key(topic: &str, id: &str) -> String {
    format!("mqglog/{topic}/{id}")
}
/// KV prefix for a grouped topic's retained log.
pub fn glog_prefix(topic: &str) -> String {
    format!("mqglog/{topic}/")
}
/// [`Storage`] key for a grouped topic's retained payload (kept until the
/// retention sweep, independent of any single group's ack).
pub fn gpayload_key(topic: &str, id: &str) -> String {
    format!("mqgp/{topic}/{id}")
}
/// KV key for a consumer group's compact state (`hwm` + `in_flight`). Its
/// existence also registers the group on the topic (⇒ publish retains the log).
pub fn gstate_key(topic: &str, group: &str) -> String {
    format!("mqgstate/{topic}/{group}")
}
/// KV prefix over a topic's group states (⇒ the set of registered groups).
pub fn gstate_prefix(topic: &str) -> String {
    format!("mqgstate/{topic}/")
}
/// KV key for a per-topic "latest published id" marker — the backlog gate. An
/// idle claim whose `hwm` already equals this returns without a range scan (and
/// a `latest`-start group initializes its `hwm` from it).
pub fn logmax_key(topic: &str) -> String {
    format!("mqlogmax/{topic}")
}
/// KV key for a group's dead-lettered record.
pub fn gdead_key(topic: &str, group: &str, id: &str) -> String {
    format!("mqgd/{topic}/{group}/{id}")
}

/// One leased-but-unacked message in a consumer group's [`GroupState`]. The set
/// is bounded by `max_batch` × the lease window, **not** by the backlog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InFlight {
    /// The message's log id.
    pub id: String,
    /// Delivery attempts charged so far (including the current lease).
    pub attempts: u32,
    /// Unix-millis until which this delivery is leased; `0` = claimable now.
    pub lease_until_ms: u64,
}

/// A consumer group's entire durable state — one compact KV value per
/// `(topic, group)`, the heart of the offset-log model. `hwm` is the high-water:
/// the max log id ever **leased** to this group, so its un-seen backlog is
/// exactly the log ids `> hwm` (found by a bounded range scan, never
/// materialized). `in_flight` is the bounded leased-but-unacked set. The group's
/// retention low-water is `min(in_flight)` if any, else `hwm` — everything below
/// it is acked and reclaimable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupState {
    /// Pinned schema discriminant (`v1`), like every boatramp schema.
    #[serde(default = "crate::schema_version")]
    pub version: u32,
    /// High-water: the max log id ever leased to this group.
    pub hwm: String,
    /// Leased-but-unacked messages (bounded by batch × lease, not by backlog).
    pub in_flight: Vec<InFlight>,
}

impl GroupState {
    /// A freshly-registered group starting at high-water `hwm` with nothing
    /// in-flight (`latest` passes the current max id, `earliest` passes `""`).
    pub fn new(hwm: String) -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            hwm,
            in_flight: Vec::new(),
        }
    }
}

/// The transitions a grouped claim produces, from [`plan_claim_grouped`]. The
/// `state` it was computed over is mutated in place (in-flight + high-water
/// advanced); this carries what the *caller* must still do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupedClaim {
    /// `(id, attempts)` to **deliver** — the caller fetches each payload and
    /// returns a [`ClaimedMessage`]. Redelivered in-flight messages and freshly
    /// leased new ones both appear here, oldest-first.
    pub leased: Vec<(String, u32)>,
    /// `(id, attempts)` that exhausted `max_attempts` → the caller writes each to
    /// the group's dead-letter store ([`gdead_key`]) and it is already dropped
    /// from `state.in_flight`.
    pub dead: Vec<(String, u32)>,
}

/// The **pure, deterministic** consumer-group claim decision — the offset-log
/// analogue of [`plan_claim`], shared by every coordinator (the single-node
/// [`LogMessaging`], the cluster Raft state machine, ...) so grouped delivery is
/// identical across modes by construction, not by mirroring.
///
/// Given the group's `state` and the batch parameters, plus `new_ids` (the log
/// ids `> state.hwm`, oldest-first, already filtered to direct children and
/// capped at `max_batch` by the caller — the one I/O the caller does), it:
/// processes the bounded in-flight set (keep still-leased, redeliver expired
/// charging an attempt up to the batch budget, dead-letter exhausted), then, if
/// budget remains, leases new ids in order — appending them to `in_flight` and
/// advancing `hwm`. No I/O, no clock reads (`now_ms` is stamped by the caller),
/// so a cluster's replicas all compute the same result and converge.
pub fn plan_claim_grouped(
    state: &mut GroupState,
    now_ms: u64,
    lease_ms: u64,
    max_batch: usize,
    max_attempts: u32,
    new_ids: &[String],
) -> GroupedClaim {
    let mut out = GroupedClaim::default();
    let mut budget = max_batch;

    // 1) The bounded in-flight set, in deterministic id order.
    let mut in_flight = std::mem::take(&mut state.in_flight);
    in_flight.sort_by(|a, b| a.id.cmp(&b.id));
    let mut kept = Vec::with_capacity(in_flight.len());
    for mut entry in in_flight {
        if entry.lease_until_ms > now_ms {
            kept.push(entry); // still leased to a live delivery
            continue;
        }
        if entry.attempts >= max_attempts {
            out.dead.push((entry.id.clone(), entry.attempts)); // dropped from in-flight
            continue;
        }
        if budget == 0 {
            kept.push(entry); // expired but no room; a later claim redelivers it
            continue;
        }
        entry.attempts += 1;
        entry.lease_until_ms = now_ms + lease_ms;
        budget -= 1;
        out.leased.push((entry.id.clone(), entry.attempts));
        kept.push(entry);
    }
    state.in_flight = kept;

    // 2) Lease new messages (log ids > hwm) while the batch has room.
    for id in new_ids {
        if budget == 0 {
            break;
        }
        if id.as_str() <= state.hwm.as_str() {
            continue; // defensive: the caller already filtered to > hwm
        }
        state.hwm = id.clone();
        state.in_flight.push(InFlight {
            id: id.clone(),
            attempts: 1,
            lease_until_ms: now_ms + lease_ms,
        });
        out.leased.push((id.clone(), 1));
        budget -= 1;
    }
    out
}

/// Whether message `id` is still needed by **any** consumer group — the shared
/// retention predicate for the grouped-log sweep. A group needs `id` if it is in
/// that group's `in_flight` (leased, unacked) **or** `id > hwm` (future backlog it
/// has not leased yet). A message below every group's high-water that no group
/// holds in-flight has been consumed by all and is reclaimable.
pub fn grouped_message_needed(states: &[GroupState], id: &str) -> bool {
    states
        .iter()
        .any(|s| id > s.hwm.as_str() || s.in_flight.iter().any(|f| f.id == id))
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
    /// Cache of topics that have ≥1 registered consumer group, so `publish` writes
    /// the retained fan-out log **only** for grouped topics (a non-grouped topic
    /// pays nothing extra). `None` until lazily loaded from the persisted
    /// group-state registry on first use.
    grouped_topics: std::sync::Mutex<Option<std::collections::HashSet<String>>>,
}

/// How long a grouped topic retains a message (its log + payload) before the
/// retention sweep's TTL backstop reclaims it, derived from the millis embedded
/// in the id. A group must consume within this window; a slow/absent group loses
/// aged-out messages (bounded retention, like Kafka's `retention.ms`). Shared by
/// the single-node sweep and the cluster state machine.
pub const GROUP_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// Parse the leading unix-millis out of a message id (`{013 millis}-{...}`) — the
/// retention TTL's age source, shared across coordinators.
pub fn id_millis(id: &str) -> u64 {
    id.split('-')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or(0)
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
            grouped_topics: std::sync::Mutex::new(None),
        }
    }

    /// Whether `topic` has ≥1 registered consumer group (so `publish` retains the
    /// fan-out log/payload + advances the `logmax` gate). Loads the set once from
    /// the persisted group-state registry (`mqgstate/…`) so it survives a restart,
    /// then serves from memory.
    async fn topic_has_groups(&self, topic: &str) -> bool {
        {
            let cache = self.grouped_topics.lock().unwrap();
            if let Some(set) = cache.as_ref() {
                return set.contains(topic);
            }
        }
        // Not loaded yet: scan every group state once and extract its topic.
        let keys = self.kv.list_prefix("mqgstate/").await.unwrap_or_default();
        let mut set = std::collections::HashSet::new();
        for key in keys {
            // `mqgstate/{topic}/{group}` → topic is everything between the first
            // and last `/`.
            if let Some(rest) = key.strip_prefix("mqgstate/") {
                if let Some(slash) = rest.rfind('/') {
                    set.insert(rest[..slash].to_string());
                }
            }
        }
        let has = set.contains(topic);
        *self.grouped_topics.lock().unwrap() = Some(set);
        has
    }

    /// Mark `topic` as grouped in the in-memory cache (called when a group first
    /// registers), so subsequent publishes retain its fan-out log.
    fn mark_grouped(&self, topic: &str) {
        let mut cache = self.grouped_topics.lock().unwrap();
        cache
            .get_or_insert_with(std::collections::HashSet::new)
            .insert(topic.to_string());
    }

    async fn read_payload(&self, topic: &str, id: &str) -> Result<Vec<u8>, MessagingError> {
        self.read_storage(&payload_key(topic, id)).await
    }

    /// Read a retained fan-out payload (the grouped-consumer store).
    async fn read_gpayload(&self, topic: &str, id: &str) -> Result<Vec<u8>, MessagingError> {
        self.read_storage(&gpayload_key(topic, id)).await
    }

    async fn read_storage(&self, key: &str) -> Result<Vec<u8>, MessagingError> {
        let object = self
            .storage
            .get(key)
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

    /// The per-topic `logmax` gate marker: the id of the last message published
    /// to a grouped topic (`""` if none yet). Both the backlog gate and a
    /// `latest`-start group's initial high-water read this — one O(1) `get`.
    async fn read_logmax(&self, topic: &str) -> Result<String, MessagingError> {
        Ok(self
            .kv
            .get(&logmax_key(topic))
            .await
            .map_err(MessagingError::backend)?
            .map(|raw| String::from_utf8_lossy(&raw).into_owned())
            .unwrap_or_default())
    }

    /// Persist a group's compact state.
    async fn put_group_state(
        &self,
        topic: &str,
        group: &str,
        state: &GroupState,
    ) -> Result<(), MessagingError> {
        let json = serde_json::to_vec(state).map_err(MessagingError::backend)?;
        self.kv
            .put(&gstate_key(topic, group), json)
            .await
            .map_err(MessagingError::backend)
    }

    /// Load a group's compact state, if it is registered.
    async fn get_group_state(
        &self,
        topic: &str,
        group: &str,
    ) -> Result<Option<GroupState>, MessagingError> {
        let Some(raw) = self
            .kv
            .get(&gstate_key(topic, group))
            .await
            .map_err(MessagingError::backend)?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|e| MessagingError::Decode(e.to_string()))
    }

    /// Collect up to `limit` **new** log ids strictly after `after` (direct
    /// children only — subtopics sharing the prefix are skipped), oldest-first.
    /// A bounded, resumable range scan (`KvStore::list_from`): O(`limit`) on an
    /// ordered backend, not O(retained log). This is what makes a grouped claim
    /// cost O(batch + in-flight), independent of the backlog size.
    async fn log_ids_after(
        &self,
        topic: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, MessagingError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let prefix = glog_prefix(topic);
        let mut out = Vec::new();
        let mut cursor = after.to_string();
        loop {
            let batch = self
                .kv
                .list_from(&prefix, &cursor, limit)
                .await
                .map_err(MessagingError::backend)?;
            let Some(last) = batch.last().cloned() else {
                break; // scan exhausted
            };
            let scanned = batch.len();
            for key in batch {
                if is_direct_child(&key, &prefix) {
                    out.push(key[prefix.len()..].to_string());
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
            // Advance past the last key we saw; stop once the backend returned a
            // short page (nothing more to scan).
            cursor = last[prefix.len()..].to_string();
            if scanned < limit {
                break;
            }
        }
        Ok(out)
    }

    /// **Retention sweep** for a grouped topic — a *separate* periodic action,
    /// deliberately **not** on the hot claim path. Reclaims every retained log
    /// entry + payload that **no** registered group still needs, with the id's
    /// embedded age as a secondary TTL backstop so an abandoned group can't pin
    /// the log forever. Returns the number of messages reclaimed.
    ///
    /// A group still needs message `id` iff it is in that group's `in_flight`
    /// (leased, unacked) **or** `id > hwm` (future backlog it hasn't leased yet).
    /// A message below every group's high-water with no group holding it in-flight
    /// has been consumed by all and is safe to drop.
    pub async fn gc_grouped(&self, topic: &str) -> Result<usize, MessagingError> {
        let _guard = self.claim_lock.lock().await;
        let now = now_unix_ms();

        // Snapshot every registered group's compact state once.
        let state_prefix = gstate_prefix(topic);
        let state_keys = self
            .kv
            .list_prefix(&state_prefix)
            .await
            .map_err(MessagingError::backend)?;
        let mut states = Vec::new();
        for key in state_keys {
            if !is_direct_child(&key, &state_prefix) {
                continue;
            }
            let group = &key[state_prefix.len()..];
            if let Some(state) = self.get_group_state(topic, group).await? {
                states.push(state);
            }
        }

        let log_prefix = glog_prefix(topic);
        let log_keys = self
            .kv
            .list_prefix(&log_prefix)
            .await
            .map_err(MessagingError::backend)?;
        let mut reclaimed = 0;
        for key in log_keys {
            if !is_direct_child(&key, &log_prefix) {
                continue;
            }
            let id = &key[log_prefix.len()..];
            let needed = grouped_message_needed(&states, id);
            let expired = id_millis(id) + GROUP_RETENTION_MS < now;
            if !needed || expired {
                let _ = self.storage.delete(&gpayload_key(topic, id)).await;
                let _ = self.kv.delete(&glog_key(topic, id)).await;
                reclaimed += 1;
            }
        }
        Ok(reclaimed)
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
        // Grouped (fan-out) topics keep a **retained** copy of the payload + an
        // append-only log entry, so each group can consume the message on its own
        // high-water long after the default queue's ack would have deleted it, and
        // advance the per-topic `logmax` gate marker (so an idle group's claim
        // early-returns without a scan). Only paid on topics with a registered group.
        if self.topic_has_groups(topic).await {
            let bytes = bytes::Bytes::copy_from_slice(payload);
            let body = futures::stream::once(async move { Ok(bytes) }).boxed();
            self.storage
                .put(&gpayload_key(topic, &id), body, PutMeta::default())
                .await
                .map_err(MessagingError::backend)?;
            self.kv
                .put(&glog_key(topic, &id), Vec::new())
                .await
                .map_err(MessagingError::backend)?;
            // Advance the gate to the max id seen — never backward, so two
            // concurrent same-ms publishes can't leave it below a retained id
            // (which would wrongly close the gate on the higher one).
            let cur = self
                .kv
                .get(&logmax_key(topic))
                .await
                .map_err(MessagingError::backend)?
                .map(|v| String::from_utf8_lossy(&v).into_owned())
                .unwrap_or_default();
            if id.as_str() > cur.as_str() {
                self.kv
                    .put(&logmax_key(topic), id.clone().into_bytes())
                    .await
                    .map_err(MessagingError::backend)?;
            }
        }
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
                        group: String::new(),
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

    async fn claim_grouped(
        &self,
        topic: &str,
        group: &str,
        start: StartPosition,
        lease: Duration,
        max_batch: usize,
        max_attempts: u32,
    ) -> Result<Vec<ClaimedMessage>, MessagingError> {
        // The default group is the legacy work-queue (unchanged, released format).
        if group.is_empty() {
            return self.claim(topic, lease, max_batch, max_attempts).await;
        }
        let _guard = self.claim_lock.lock().await;
        let now = now_unix_ms();
        let lease_ms = lease.as_millis() as u64;

        // Load the group's compact state, or register it on first claim: `latest`
        // starts at the current max id (skip the backlog), `earliest` at `""`
        // (replay everything retained). Registering turns on publish-time retention.
        let (mut state, existed) = match self.get_group_state(topic, group).await? {
            Some(state) => (state, true),
            None => {
                self.mark_grouped(topic);
                let hwm = match start {
                    StartPosition::Latest => self.read_logmax(topic).await?,
                    StartPosition::Earliest => String::new(),
                };
                (GroupState::new(hwm), false)
            }
        };

        // Fetch the new-message candidates (log ids > hwm, up to the batch) only
        // when the gate is open — an idle caught-up group does no scan at all.
        let new_ids = if state.hwm.as_str() < self.read_logmax(topic).await?.as_str() {
            self.log_ids_after(topic, &state.hwm, max_batch).await?
        } else {
            Vec::new()
        };

        // The shared, deterministic decision advances `state` (in-flight + hwm) and
        // tells us what to deliver and what to dead-letter.
        let plan = plan_claim_grouped(&mut state, now, lease_ms, max_batch, max_attempts, &new_ids);

        // Dead-letter the exhausted ones (preserve the record under the group's DLQ).
        for (id, attempts) in &plan.dead {
            let record = Record {
                version: crate::SCHEMA_VERSION,
                attempts: *attempts,
                lease_until_ms: 0,
            };
            let json = serde_json::to_vec(&record).map_err(MessagingError::backend)?;
            self.kv
                .put(&gdead_key(topic, group, id), json)
                .await
                .map_err(MessagingError::backend)?;
        }

        // The plan mutated `state` (in-flight + hwm) iff it leased or dead-lettered
        // anything; persist then, or when the group was just registered.
        let changed = !existed || !plan.leased.is_empty() || !plan.dead.is_empty();

        // Deliver each leased id, fetching its retained payload. A payload that is
        // unexpectedly absent (a publish still landing, or reclaimed) is simply not
        // delivered this round — the id stays leased and redelivers on lease expiry.
        let mut claimed = Vec::new();
        for (id, attempts) in plan.leased {
            match self.read_gpayload(topic, &id).await {
                Ok(payload) => claimed.push(ClaimedMessage {
                    id,
                    topic: topic.to_string(),
                    payload,
                    attempts,
                    group: group.to_string(),
                }),
                Err(_) => continue,
            }
        }

        if changed {
            self.put_group_state(topic, group, &state).await?;
        }
        Ok(claimed)
    }

    async fn ack(&self, msg: &ClaimedMessage) -> Result<(), MessagingError> {
        // A grouped ack drops only *this group's* in-flight entry; the retained
        // payload stays for the other groups (the retention sweep reclaims it once
        // every group has passed it). Serialized with `claim` — both mutate the
        // single compact group-state value.
        if !msg.group.is_empty() {
            let _guard = self.claim_lock.lock().await;
            let Some(mut state) = self.get_group_state(&msg.topic, &msg.group).await? else {
                return Ok(()); // group gone
            };
            let before = state.in_flight.len();
            state.in_flight.retain(|f| f.id != msg.id);
            if state.in_flight.len() != before {
                self.put_group_state(&msg.topic, &msg.group, &state).await?;
            }
            return Ok(());
        }
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
        // A grouped nack resets the in-flight entry's lease to `0` (claimable now)
        // in the compact group-state value; serialized with `claim`.
        if !msg.group.is_empty() {
            let _guard = self.claim_lock.lock().await;
            let Some(mut state) = self.get_group_state(&msg.topic, &msg.group).await? else {
                return Ok(()); // group gone
            };
            let mut changed = false;
            for entry in &mut state.in_flight {
                if entry.id == msg.id {
                    entry.lease_until_ms = 0;
                    changed = true;
                    break;
                }
            }
            if changed {
                self.put_group_state(&msg.topic, &msg.group, &state).await?;
            }
            return Ok(());
        }
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

    async fn retention_sweep(&self, topic: &str) -> Result<usize, MessagingError> {
        self.gc_grouped(topic).await
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

    fn payloads(msgs: &[ClaimedMessage]) -> Vec<Vec<u8>> {
        msgs.iter().map(|m| m.payload.clone()).collect()
    }

    #[tokio::test]
    async fn consumer_groups_fan_out_and_ack_independently() {
        let mq = mq();
        let t = "bus/orders";
        // Two groups subscribe (first claim registers them + turns on retention),
        // *then* events flow — the fabric shape (workers deployed before events).
        assert!(mq
            .claim_grouped(t, "billing", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
        assert!(mq
            .claim_grouped(t, "audit", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
        mq.publish(t, b"a").await.unwrap();
        mq.publish(t, b"b").await.unwrap();

        // Each group independently receives BOTH messages, in order.
        let billing = mq
            .claim_grouped(t, "billing", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&billing), vec![b"a".to_vec(), b"b".to_vec()]);
        let audit = mq
            .claim_grouped(t, "audit", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&audit), vec![b"a".to_vec(), b"b".to_vec()]);

        // Billing acks both; that removes only billing's copies — audit is untouched.
        for m in &billing {
            mq.ack(m).await.unwrap();
        }
        assert!(mq
            .claim_grouped(t, "billing", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
        // Audit still has its two (leased) messages: nack makes them claimable now.
        for m in &audit {
            mq.nack(m).await.unwrap();
        }
        let audit_again = mq
            .claim_grouped(t, "audit", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&audit_again), vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[tokio::test]
    async fn consumer_group_start_position_latest_vs_earliest() {
        let mq = mq();
        let t = "bus/events";
        // A registered group turns on retention, then two events are published.
        assert!(mq
            .claim_grouped(t, "seed", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
        mq.publish(t, b"a").await.unwrap();
        mq.publish(t, b"b").await.unwrap();

        // A NEW `earliest` group replays the retained backlog…
        let replay = mq
            .claim_grouped(t, "replay", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&replay), vec![b"a".to_vec(), b"b".to_vec()]);
        // …while a NEW `latest` group starts empty (only events after it subscribes).
        let live = mq
            .claim_grouped(t, "live", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert!(live.is_empty());
        mq.publish(t, b"c").await.unwrap();
        let live_after = mq
            .claim_grouped(t, "live", StartPosition::Latest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&live_after), vec![b"c".to_vec()]);
    }

    #[tokio::test]
    async fn consumer_group_batches_backlog_by_max_batch() {
        // A group replays a backlog larger than one batch across successive claims,
        // advancing its high-water by at most `max_batch` each time (the bounded
        // range scan, not a full-log materialization).
        let mq = mq();
        let t = "bus/jobs";
        assert!(mq
            .claim_grouped(t, "worker", StartPosition::Earliest, LEASE, 2, 5)
            .await
            .unwrap()
            .is_empty());
        for n in 0..5u8 {
            mq.publish(t, &[b'0' + n]).await.unwrap();
        }
        // Three claims of batch 2 drain 2 + 2 + 1, in order, with no overlap.
        let first = mq
            .claim_grouped(t, "worker", StartPosition::Earliest, LEASE, 2, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&first), vec![b"0".to_vec(), b"1".to_vec()]);
        let second = mq
            .claim_grouped(t, "worker", StartPosition::Earliest, LEASE, 2, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&second), vec![b"2".to_vec(), b"3".to_vec()]);
        let third = mq
            .claim_grouped(t, "worker", StartPosition::Earliest, LEASE, 2, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&third), vec![b"4".to_vec()]);
        // Caught up: the gate is closed, so a further claim scans nothing.
        assert!(mq
            .claim_grouped(t, "worker", StartPosition::Earliest, LEASE, 2, 5)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn consumer_group_dead_letters_after_max_attempts() {
        // A grouped message that never acks dead-letters after `max_attempts`
        // rather than redelivering forever, and is dropped from in-flight.
        let mq = mq();
        let t = "bus/flaky";
        assert!(mq
            .claim_grouped(t, "g", StartPosition::Earliest, LEASE, 10, 2)
            .await
            .unwrap()
            .is_empty());
        mq.publish(t, b"x").await.unwrap();
        // Zero lease ⇒ each claim finds the in-flight entry immediately expired.
        for expected in 1..=2 {
            let batch = mq
                .claim_grouped(t, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
                .await
                .unwrap();
            assert_eq!(batch.len(), 1, "attempt {expected}");
            assert_eq!(batch[0].attempts, expected);
        }
        // Third claim exhausts attempts → dead-letter, deliver nothing, and stay empty.
        assert!(mq
            .claim_grouped(t, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        assert!(mq
            .claim_grouped(t, "g", StartPosition::Earliest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn consumer_group_survives_restart() {
        // The group's compact state lives in the KV, so a fresh LogMessaging over
        // the same backends resumes at the same high-water — an already-acked
        // message is not redelivered, and un-acked work is.
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let t = "bus/resume";
        {
            let mq = LogMessaging::new(storage.clone(), kv.clone());
            assert!(mq
                .claim_grouped(t, "g", StartPosition::Earliest, LEASE, 10, 5)
                .await
                .unwrap()
                .is_empty());
            mq.publish(t, b"a").await.unwrap();
            mq.publish(t, b"b").await.unwrap();
            // Zero lease so the un-acked message is immediately re-claimable after
            // the restart (no need to wait out a real lease in a test).
            let batch = mq
                .claim_grouped(t, "g", StartPosition::Earliest, Duration::ZERO, 10, 5)
                .await
                .unwrap();
            assert_eq!(payloads(&batch), vec![b"a".to_vec(), b"b".to_vec()]);
            mq.ack(&batch[0]).await.unwrap(); // ack "a" only
        } // restart

        let mq = LogMessaging::new(storage, kv);
        // The resumed state still holds "b" in-flight with an expired lease → it
        // redelivers; "a" (acked, dropped from in-flight) never comes back.
        let redelivered = mq
            .claim_grouped(t, "g", StartPosition::Earliest, Duration::ZERO, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&redelivered), vec![b"b".to_vec()]);
        assert_eq!(
            redelivered[0].attempts, 2,
            "redelivery re-charges the attempt"
        );
    }

    #[tokio::test]
    async fn gc_grouped_reclaims_only_fully_consumed_messages() {
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mq = LogMessaging::new(storage.clone(), kv);
        let t = "bus/retain";
        // Two groups; publish two messages both retain.
        for g in ["one", "two"] {
            assert!(mq
                .claim_grouped(t, g, StartPosition::Earliest, LEASE, 10, 5)
                .await
                .unwrap()
                .is_empty());
        }
        mq.publish(t, b"a").await.unwrap();
        mq.publish(t, b"b").await.unwrap();

        // Group "one" claims + acks both; "two" hasn't consumed anything yet.
        let one = mq
            .claim_grouped(t, "one", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        for m in &one {
            mq.ack(m).await.unwrap();
        }
        // Nothing is reclaimable: "two" still needs both (id > its hwm of "").
        assert_eq!(mq.gc_grouped(t).await.unwrap(), 0);

        // "two" claims + acks both → now every group has consumed both.
        let two = mq
            .claim_grouped(t, "two", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(payloads(&two), vec![b"a".to_vec(), b"b".to_vec()]);
        for m in &two {
            mq.ack(m).await.unwrap();
        }
        // Both are fully consumed → the sweep reclaims both log entries + payloads.
        assert_eq!(mq.gc_grouped(t).await.unwrap(), 2);
        let ids: Vec<String> = one.iter().map(|m| m.id.clone()).collect();
        for id in &ids {
            assert!(
                storage.head(&gpayload_key(t, id)).await.is_err(),
                "reclaimed payload for {id}"
            );
        }
        // A caught-up group still returns empty (state intact, log gone).
        assert!(mq
            .claim_grouped(t, "one", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
    }

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
