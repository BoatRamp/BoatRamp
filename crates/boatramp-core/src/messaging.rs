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

use crate::kv::{KvStore, WriteOp};
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
    /// The host-minted **durable signed-context** envelope stamped at publish from the producer's
    /// own-tenant principal (R1), or `None` when the producer had no resolved tenant. Opaque here —
    /// the consumer's tenant resolver verifies it (signature + expiry) against the fleet anchor and
    /// resolves the `signed_context` source; a forged/absent envelope fails an "own" op closed.
    pub signed_context: Option<String>,
    /// Whether this message's payload was **inlined** in its index record (A3) rather than stored
    /// as a separate object — so `ack` can skip the object-store delete (there is no object to
    /// delete). Set by the claim path from the record; internal bookkeeping, not guest-visible.
    pub inline: bool,
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

    /// Append a message to `topic`, stamping the host-minted **durable signed-context** envelope
    /// (R1) onto its index record so a consumer declaring `sources: [signed_context]` resolves the
    /// producer's own-tenant (Stage 4). The envelope is host-issued from the producer's principal —
    /// the guest never names a tenant. The default drops the context and delegates to
    /// [`publish`](Self::publish) (backends that don't persist a per-message record); the durable
    /// backends override it. `None` ⇒ identical to `publish` (an unscoped producer).
    async fn publish_ctx(
        &self,
        topic: &str,
        payload: &[u8],
        _signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        self.publish(topic, payload).await
    }

    /// Publish a **batch** of messages in ONE durable commit — the guest-facing pipelined-publish
    /// primitive (A4). Each entry is `(topic, payload)`; entries may target different topics. Every
    /// message shares the one host-minted `signed_context`: a batch comes from a single producer
    /// invocation, so there is exactly one producer principal and no cross-tenant mixing. Returns
    /// only after the WHOLE batch is durably committed (at-least-once); on failure NONE are
    /// acknowledged as published (fail-all, symmetric to the group-commit contract). An empty batch
    /// is a no-op `Ok`. The default impl publishes sequentially (correct but uncoalesced); the
    /// durable backends override it to coalesce every message's index write into a single
    /// `write_batch` / one Raft entry — the whole point of the primitive.
    async fn publish_batch_ctx(
        &self,
        messages: &[(String, Vec<u8>)],
        signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        for (topic, payload) in messages {
            self.publish_ctx(topic, payload, signed_context).await?;
        }
        Ok(())
    }

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

    /// Age in ms of the OLDEST still-pending message on `topic` (the earliest live id, claimable or
    /// leased), or `None` if empty — the "how stale is my backlog" signal (≈ JetStream's
    /// oldest-unacked age). Ids are time-ordered, so it's the age of the earliest live id. Scoped to
    /// the work-queue index (grouped topics track a per-group frontier — use group lag). Default
    /// `None` for backends without introspection.
    async fn oldest_pending_ms(&self, _topic: &str) -> Result<Option<u64>, MessagingError> {
        Ok(None)
    }

    /// Number of IN-FLIGHT (leased-but-unacked) messages on `topic` — distinct from `backlog`
    /// (claimable *plus* leased), so an operator can tell "queued and draining" from "queued and
    /// wedged" (≈ JetStream's ack-pending). Counts the work-queue's leased records and every
    /// consumer group's in-flight set. Default `0`.
    async fn in_flight_count(&self, _topic: &str) -> Result<usize, MessagingError> {
        Ok(0)
    }

    /// Consumer-group **lag** on a grouped `topic`: retained messages `group` has not yet leased
    /// (log ids strictly beyond its high-water). The fan-out analog of `backlog` — the "who's
    /// lagging" signal. `0` for the work-queue (empty group) or an unknown group. Default `0`.
    async fn group_lag(&self, _topic: &str, _group: &str) -> Result<usize, MessagingError> {
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

    /// Record a sanitized HOST reason for the most recent failed delivery of `msg`, so it survives
    /// into the dead-letter record for `dlq ls/show` and `--match` (P1/SEC6). Called by the
    /// dispatcher on a failed consume (before the message may later dead-letter). `reason` is a host
    /// classification (never guest bytes); the backend sanitizes + bounds it via
    /// [`sanitize_reason`]. A no-op on a message that has since been acked/gone. Default no-op
    /// (backends without a per-message record).
    async fn set_last_error(
        &self,
        _msg: &ClaimedMessage,
        _reason: &str,
    ) -> Result<(), MessagingError> {
        Ok(())
    }

    /// **List** the dead-letters on `topic` matching `filter` (P1 `dlq ls`) — metadata only
    /// (`DeadLetter::payload` is `None`; use [`show_dead_letter`](Self::show_dead_letter) for a body).
    /// Covers BOTH the work-queue and every consumer group's DLQ, ordered by id. Default empty.
    async fn list_dead_letters(
        &self,
        _topic: &str,
        _filter: &DeadLetterFilter,
    ) -> Result<Vec<DeadLetter>, MessagingError> {
        Ok(Vec::new())
    }

    /// **Show** one dead-letter in full, including its payload (P1 `dlq show <topic> <id>`). `group`
    /// selects the lane (`""` = work-queue). `None` if no such dead-letter. Default `None`.
    async fn show_dead_letter(
        &self,
        _topic: &str,
        _group: &str,
        _id: &str,
    ) -> Result<Option<DeadLetter>, MessagingError> {
        Ok(None)
    }

    /// **Redrive** only the dead-letters matching `filter` (P1 `dlq redrive --id|--older-than|--match
    /// |--limit`). Same re-arm semantics as [`redrive_dead_letters`](Self::redrive_dead_letters) but
    /// selective. Returns the number redriven. Default no-op (`0`).
    async fn redrive_dead_letters_filtered(
        &self,
        _topic: &str,
        _filter: &DeadLetterFilter,
    ) -> Result<usize, MessagingError> {
        Ok(0)
    }

    /// **Discard** only the dead-letters matching `filter` (P1 `dlq discard …`) — delete the records
    /// (+ work-queue payloads), never re-queuing. The selective analog of
    /// [`purge_dead_letters`](Self::purge_dead_letters). Returns the number discarded. Default `0`.
    async fn discard_dead_letters(
        &self,
        _topic: &str,
        _filter: &DeadLetterFilter,
    ) -> Result<usize, MessagingError> {
        Ok(0)
    }

    /// **Peek** up to `limit` messages on `topic`'s work-queue WITHOUT claiming them — no lease is
    /// taken and no attempt is charged, so it is a pure read (`queue peek`). Ordered by id (delivery
    /// order); each carries whether it is currently `leased` (in-flight) or claimable. Default empty.
    async fn peek(
        &self,
        _topic: &str,
        _limit: usize,
    ) -> Result<Vec<PeekedMessage>, MessagingError> {
        Ok(Vec::new())
    }

    /// **List** the consumer groups registered on a grouped `topic` (P2 `queue groups`) with each
    /// group's cursor + health (hwm, in-flight, lag). Read-only. Default empty (no groups).
    async fn list_groups(&self, _topic: &str) -> Result<Vec<GroupInfo>, MessagingError> {
        Ok(Vec::new())
    }

    /// **Reset** a consumer group's cursor (P2 `queue group-reset`): move its high-water to `start`
    /// (`Earliest` ⇒ re-consume the whole retained backlog; `Latest` ⇒ skip to the current head) and
    /// drop its in-flight set. An admin action — a deliberate re-consume/skip. Default: refuse
    /// (backends without consumer groups), so an unsupported reset fails closed rather than silently
    /// doing nothing.
    async fn reset_group(
        &self,
        _topic: &str,
        _group: &str,
        _start: StartPosition,
    ) -> Result<(), MessagingError> {
        Err(MessagingError::Backend(
            "this messaging backend does not support consumer groups".into(),
        ))
    }

    /// **Delete** a consumer group (P2 `queue group-delete`): remove its durable state + its
    /// dead-letters. The shared retained log/payloads it was pinning are reclaimed by the retention
    /// sweep once no remaining group needs them. Default no-op (`0` groups to delete).
    async fn delete_group(&self, _topic: &str, _group: &str) -> Result<(), MessagingError> {
        Ok(())
    }

    /// **Pause / resume** a topic (P2 flow control `queue pause|resume|drain`). While paused, `claim`
    /// and `claim_grouped` deliver NOTHING (new deliveries suppressed) — publish still durably
    /// enqueues, and in-flight leases still ack/nack/expire, so "drain" = pause + let outstanding
    /// finish. An operator backpressure/maintenance control. Default no-op.
    async fn set_paused(&self, _topic: &str, _paused: bool) -> Result<(), MessagingError> {
        Ok(())
    }

    /// Whether `topic` is currently paused (P2 flow control) — for stats/CLI. Default `false`.
    async fn is_paused(&self, _topic: &str) -> Result<bool, MessagingError> {
        Ok(false)
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
    /// The host-minted durable signed-context envelope (R1) — the producer's stamped own-tenant,
    /// carried across the durability boundary so a consumer declaring `sources: [signed_context]`
    /// resolves it. `None` when the producer had no resolved tenant. Absent on records written by
    /// an older binary (`#[serde(default)]`); elided when `None` so those records stay byte-identical
    /// (`skip_serializing_if`). Verified — never trusted — at consume time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_context: Option<String>,
    /// **Inlined payload** (A3): for a small work-queue message (`<= INLINE_MAX`, no consumer
    /// groups) the body rides IN this index record instead of a separate object-store object — so
    /// publish is one local durable write (no object-store round-trip) and claim needs no fetch. It
    /// travels with the record through lease/dead-letter/redrive transparently. `None` ⇒ the payload
    /// lives in [`Storage`] at [`payload_key`] (grouped topics + payloads over `INLINE_MAX`). Elided
    /// when absent so pre-A3 records stay byte-identical (`#[serde(default)]` + `skip_serializing_if`).
    #[serde(default, with = "inline_b64", skip_serializing_if = "Option::is_none")]
    pub inline: Option<Vec<u8>>,
    /// **Last failure reason** (P1 selective DLQ, SEC6): a sanitized, host-classified reason for the
    /// most recent failed delivery (e.g. `guest-error`, `guest-trap`, `timeout`) — never guest-supplied
    /// bytes and never PII, capped at [`LAST_ERROR_MAX`] chars. Set by the dispatcher via
    /// [`set_last_error`](Messaging::set_last_error) so it survives into the dead-letter record for
    /// `dlq ls/show` and `--match` filtering. `None` for a message that never failed, or written by an
    /// older binary. Elided when absent (`skip_serializing_if`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// serde codec for [`Record::inline`]: base64 (not a JSON byte-array) so an inlined payload stays
/// compact in the record's JSON — the whole point of inlining is to avoid a fat encoding on the
/// hot durable-write path (and in the Raft log for a cluster).
mod inline_b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => {
                s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(text) => base64::engine::general_purpose::STANDARD
                .decode(text.as_bytes())
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Max payload size (bytes) inlined into the index record (A3). Above this, the payload takes the
/// object-store path (boatramp's large-blob strength). Conservative on purpose: inlined payloads
/// ride the durable index (and the Raft log/snapshots in a cluster), so this bounds per-message
/// index bloat. (SA1 aggregate-cap-with-fallback is a documented pre-release hardening.)
pub const INLINE_MAX: usize = 4096;

/// Aggregate cap (SA1): total inline-payload bytes a node keeps in-flight before new publishes fall
/// back to the object-store path — so a stuck consumer + small-message flood can't grow the durable
/// index (and the replicated Raft log/snapshots) without bound. Sized so the worst-case inline
/// footprint stays modest (32 MiB ≈ 8k messages at `INLINE_MAX`); large-blob loads are unaffected
/// (they never inline). A soft, per-node guard (see [`LogMessaging::inline_inflight_bytes`]).
pub const INLINE_INFLIGHT_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Group-commit (A2): the soft per-turn budget of index writes (OPS, not jobs) coalesced into one
/// durable `write_batch`. Concurrent publishers that pile up during a flush form the next group; the
/// committer drains jobs until this many ops accumulate (always ≥1 job for progress), so neither a
/// burst of single publishes nor a large `publish_batch` (A4, itself bounded by the host's
/// PUBLISH_BATCH_MAX) can build an unbounded batch. The queue is self-bounded — every pusher is a
/// gate-waiter.
const GROUP_COMMIT_MAX: usize = 512;

/// One publisher's contribution to a group commit (A2): its index ops + a one-shot to signal the
/// durable outcome. The committer coalesces many of these into ONE `write_batch` then signals each —
/// a publisher's `publish` returns only AFTER its group's commit is durable (at-least-once), and a
/// failed group commit fails EVERY member (no partial success on the synchronous path).
struct PublishJob {
    ops: Vec<WriteOp>,
    done: futures::channel::oneshot::Sender<Result<(), MessagingError>>,
}

impl Record {
    /// A freshly-published record: never delivered, claimable immediately, carrying the optional
    /// host-minted signed-context envelope stamped from the producer's own-tenant.
    pub fn fresh(signed_context: Option<String>) -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            attempts: 0,
            lease_until_ms: 0,
            signed_context,
            inline: None,
            last_error: None,
        }
    }
}

/// The most bytes a [`Record::last_error`] may hold (SEC6): a bounded, sanitized host reason — long
/// enough to be useful, short enough that it can never bloat the durable index or a log line.
pub const LAST_ERROR_MAX: usize = 256;

/// Sanitize a host failure reason for durable storage as [`Record::last_error`] (SEC6): control
/// characters (newlines, escapes) become spaces so it can never break a JSON field or a log line,
/// then it is byte-bounded to [`LAST_ERROR_MAX`]. The dispatcher already passes a HOST classification
/// (never raw guest bytes); this is the defensive floor.
pub fn sanitize_reason(reason: &str) -> String {
    let mut out = String::new();
    for c in reason.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > LAST_ERROR_MAX {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

/// An inspectable dead-letter (P1 `dlq ls`/`show`). Host-side metadata; `payload` is populated only
/// by [`show_dead_letter`](Messaging::show_dead_letter) (a listing is metadata-only, so `dlq ls`
/// never loads bodies). `group` is `""` for a work-queue dead-letter, else the consumer group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadLetter {
    /// The message's durable id (time-ordered).
    pub id: String,
    /// The consumer group (`""` = the competing-consumer work queue).
    pub group: String,
    /// Delivery attempts charged before it dead-lettered.
    pub attempts: u32,
    /// The sanitized host reason for the last failed delivery (see [`Record::last_error`]).
    pub last_error: Option<String>,
    /// The producer's durable signed-context envelope, if any (carried through the DLQ).
    pub signed_context: Option<String>,
    /// The message body — `Some` only from `show_dead_letter`; `None` in a metadata listing.
    pub payload: Option<Vec<u8>>,
}

/// A message peeked from a live work-queue (P1 `queue peek`) — inspected WITHOUT claiming it (no
/// lease taken, no attempt charged). `leased` marks a message currently in-flight to a consumer (vs
/// claimable now); `payload` is the message body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeekedMessage {
    /// The message's durable id (time-ordered = delivery order).
    pub id: String,
    /// Delivery attempts charged so far.
    pub attempts: u32,
    /// Currently leased (in-flight to a consumer) rather than claimable now.
    pub leased: bool,
    /// The producer's durable signed-context envelope, if any.
    pub signed_context: Option<String>,
    /// The message body.
    pub payload: Vec<u8>,
}

/// A consumer group's operator-facing summary (P2 group lifecycle `queue groups`): its name plus the
/// same health signals as the per-consumer stat, read from the group's compact durable state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    /// The consumer group name.
    pub group: String,
    /// High-water: the max log id ever leased to this group (its cursor).
    pub hwm: String,
    /// Leased-but-unacked messages currently held by this group.
    pub in_flight: usize,
    /// Retained messages this group has not yet leased (log ids strictly beyond `hwm`).
    pub lag: usize,
}

/// An AND-composed filter over a topic's dead-letters (P1 selective DLQ). A dead-letter matches iff
/// it satisfies EVERY set predicate; an all-`None` filter matches everything (the whole-DLQ op). Used
/// by [`list_dead_letters`](Messaging::list_dead_letters),
/// [`redrive_dead_letters_filtered`](Messaging::redrive_dead_letters_filtered), and
/// [`discard_dead_letters`](Messaging::discard_dead_letters).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeadLetterFilter {
    /// Exact message id.
    pub id: Option<String>,
    /// Restrict to a lane: `Some("")` = work-queue only, `Some(group)` = that group, `None` = all.
    pub group: Option<String>,
    /// Only messages published more than this many ms ago (age derived from the time-ordered id — no
    /// dead-letter timestamp is stored). `--older-than`.
    pub older_than_ms: Option<u64>,
    /// Case-sensitive substring match on `last_error` (a dead-letter with no `last_error` never
    /// matches). `--match`, scoped to the host reason only (never the payload).
    pub match_last_error: Option<String>,
    /// Cap the number acted on / listed (applied after ordering by id). `--limit`.
    pub limit: Option<usize>,
}

impl DeadLetterFilter {
    /// Does `dl` satisfy every set predicate? `now_ms` anchors the age test. Public so a backend in
    /// another crate (the cluster coordinator) applies the identical AND-composition.
    pub fn matches(&self, dl: &DeadLetter, now_ms: u64) -> bool {
        if let Some(id) = &self.id {
            if &dl.id != id {
                return false;
            }
        }
        if let Some(group) = &self.group {
            if &dl.group != group {
                return false;
            }
        }
        if let Some(older) = self.older_than_ms {
            match id_age_ms(&dl.id, now_ms) {
                Some(age) if age >= older => {}
                _ => return false,
            }
        }
        if let Some(needle) = &self.match_last_error {
            match &dl.last_error {
                Some(err) if err.contains(needle.as_str()) => {}
                _ => return false,
            }
        }
        true
    }
}

/// The age in ms of a message from its time-ordered id (the `{:013}` unix-millis prefix), or `None`
/// if the prefix doesn't parse (a foreign id shape) — a non-parsing id is never matched by an
/// age filter (fail-closed: `--older-than` can't accidentally sweep it).
fn id_age_ms(id: &str, now_ms: u64) -> Option<u64> {
    let millis: u64 = id.split('-').next()?.parse().ok()?;
    Some(now_ms.saturating_sub(millis))
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
/// KV/state key for a topic's **pause** flag (P2 flow control): its existence = paused (new
/// deliveries suppressed; publish + in-flight ack/nack unaffected). A tiny marker; absent = flowing.
pub fn pause_key(topic: &str) -> String {
    format!("mqpause/{topic}")
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
/// KV prefix over ALL of a topic's grouped dead-letters (every group). Entries below it are
/// `{group}/{id}` (two segments), NOT direct children — iterate with [`split_group_id`].
pub fn gdead_topic_prefix(topic: &str) -> String {
    format!("mqgd/{topic}/")
}
/// Split a `mqgd/{topic}/` suffix into `(group, id)`. A valid entry is exactly two non-empty
/// segments (`{group}/{id}`); the id is `{millis}-{hex}` (no `/`) and the group is a validated
/// single-segment name. Returns `None` for anything else — in particular a **subtopic** bleed
/// (`{subtopic}/{group}/{id}`, ≥3 segments) is rejected so a topic's ops never touch a subtopic's
/// grouped dead-letters (the grouped analog of [`is_direct_child`]).
pub fn split_group_id(suffix: &str) -> Option<(&str, &str)> {
    let (group, id) = suffix.split_once('/')?;
    if group.is_empty() || id.is_empty() || id.contains('/') {
        return None;
    }
    Some((group, id))
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
    /// Approximate count of inline-payload bytes currently in-flight on this node (A3/SA1): the
    /// aggregate-inline budget. Incremented when a publish inlines, decremented when an inline
    /// message is acked. Once it reaches [`INLINE_INFLIGHT_MAX_BYTES`] a publish falls back to the
    /// object-store path — so a stuck consumer + small-message flood can't grow the durable index
    /// (and the Raft log/snapshots in a cluster) unbounded. Deliberately a soft guard: it only
    /// **over**-counts (a dead-lettered/purged inline record isn't decremented until acked, and a
    /// restart resets it to `0` — under-count is bounded to one budget-worth of pre-existing inline),
    /// and over-counting is the SAFE direction (it just falls back to object storage sooner).
    inline_inflight_bytes: std::sync::atomic::AtomicUsize,
    /// The aggregate-inline budget in bytes (default [`INLINE_INFLIGHT_MAX_BYTES`]); a publish inlines
    /// only while `inline_inflight_bytes` stays under it, else falls back to object storage. Tunable
    /// via [`with_inline_budget`](Self::with_inline_budget).
    inline_budget_bytes: usize,
    /// Group-commit (A2), runtime-agnostic (no spawned task — core uses `futures`, not `tokio`):
    /// a publisher pushes its index ops here, then takes [`commit_gate`](Self::commit_gate); whoever
    /// holds the gate drains this queue and commits everyone's ops in ONE `write_batch`, signalling
    /// each. Self-bounding — every pusher is also a gate-waiter, so the queue never holds more than
    /// the number of concurrent publishers.
    commit_queue: std::sync::Mutex<Vec<PublishJob>>,
    /// The group-commit gate (A2): the single durable-flush turn. Held only across the drain +
    /// `write_batch`, so publishers that pile up during a flush coalesce into the next batch.
    commit_gate: futures::lock::Mutex<()>,
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
            inline_inflight_bytes: std::sync::atomic::AtomicUsize::new(0),
            inline_budget_bytes: INLINE_INFLIGHT_MAX_BYTES,
            commit_queue: std::sync::Mutex::new(Vec::new()),
            commit_gate: futures::lock::Mutex::new(()),
        }
    }

    /// Group-commit a publisher's index ops (A2): push the job, take the gate, and — as whoever holds
    /// the gate — drain the queue and commit EVERYONE's ops in one `write_batch`, signalling each.
    /// A publisher that pushed but was flushed by an earlier gate-holder simply finds its one-shot
    /// already resolved. Returns only after this job's group is durably committed (at-least-once); a
    /// failed group commit fails every member (no partial success). Runtime-agnostic: no spawned task.
    async fn group_commit(&self, ops: Vec<WriteOp>) -> Result<(), MessagingError> {
        let (done_tx, done_rx) = futures::channel::oneshot::channel();
        self.commit_queue
            .lock()
            .unwrap()
            .push(PublishJob { ops, done: done_tx });
        {
            // Whoever holds the gate is the committer for this turn.
            let _turn = self.commit_gate.lock().await;
            // Drain jobs until the per-commit OP budget is met (a batch job carries many ops, so the
            // bound must be on ops, not jobs — else one turn could build an unbounded `write_batch`).
            // Always take at least one job so an oversized single batch (already bounded by the host's
            // PUBLISH_BATCH_MAX) still makes progress. The rest wait for the next turn. An already-empty
            // queue means an earlier committer flushed our job — fall through to await it.
            let batch: Vec<PublishJob> = {
                let mut q = self.commit_queue.lock().unwrap();
                let mut n = 0;
                let mut ops = 0;
                while n < q.len() {
                    if n > 0 && ops + q[n].ops.len() > GROUP_COMMIT_MAX {
                        break;
                    }
                    ops += q[n].ops.len();
                    n += 1;
                }
                q.drain(..n).collect()
            };
            if !batch.is_empty() {
                let mut all_ops = Vec::new();
                let mut dones = Vec::with_capacity(batch.len());
                for job in batch {
                    let mut job = job;
                    all_ops.append(&mut job.ops);
                    dones.push(job.done);
                }
                let outcome = self
                    .kv
                    .write_batch(all_ops)
                    .await
                    .map_err(MessagingError::backend);
                for done in dones {
                    // A dropped receiver (cancelled publisher) is harmless — the message is still
                    // durably committed; at-least-once/redelivery is unaffected.
                    let _ = done.send(outcome.clone());
                }
            }
        }
        // Our own outcome: signalled by whichever committer flushed our job (possibly us).
        done_rx
            .await
            .map_err(|_| MessagingError::backend("group-commit dropped before durable"))?
    }

    /// Set the aggregate-inline byte budget (SA1) — the total inline-payload bytes this node keeps
    /// in-flight before publishes fall back to object storage. Defaults to
    /// [`INLINE_INFLIGHT_MAX_BYTES`]; lower it on a memory-tight node (or in tests).
    #[must_use]
    pub fn with_inline_budget(mut self, bytes: usize) -> Self {
        self.inline_budget_bytes = bytes;
        self
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

    /// Build one message's durable INDEX ops, performing any object-store payload write FIRST
    /// (payload-first ordering: a committed record never references a missing payload). Shared by
    /// [`publish_ctx`](Self::publish_ctx) (single) and [`publish_batch_ctx`](Self::publish_batch_ctx)
    /// (A4 batch) so both take the identical A3-inline / SA1-budget / grouped-retain decisions.
    /// Returns the minted id (for the post-commit broadcast) + the ops the caller's group-commit will
    /// durably commit. The SA1 inline-budget `fetch_add` happens here; if the caller then fails to
    /// commit, the budget over-counts — the documented safe direction (falls back to object storage
    /// sooner), and a restart resets it.
    async fn build_publish_ops(
        &self,
        topic: &str,
        payload: &[u8],
        signed_context: Option<&str>,
    ) -> Result<(String, Vec<WriteOp>), MessagingError> {
        let id = format!(
            "{:013}-{:016x}",
            now_unix_ms(),
            self.seq.fetch_add(1, Ordering::Relaxed)
        );
        let retain = self.topic_has_groups(topic).await;
        // A3 — inline a small work-queue payload IN the index record: it is then written in the one
        // batch below (no object-store round-trip) and read straight off the record at claim. Only
        // for the work-queue (a retained/grouped topic keeps the shared object-store copy every group
        // reads) and only up to `INLINE_MAX` (larger payloads take the object-store path — boatramp's
        // large-blob strength). Otherwise: payload first to object storage, then the index record —
        // so the record never references a missing payload.
        // SA1: only inline while under the aggregate in-flight budget; past it, fall back to the
        // object-store path so a stuck consumer can't grow the durable index unbounded.
        let inline = !retain
            && payload.len() <= INLINE_MAX
            && self
                .inline_inflight_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_add(payload.len())
                <= self.inline_budget_bytes;
        if inline {
            self.inline_inflight_bytes
                .fetch_add(payload.len(), std::sync::atomic::Ordering::Relaxed);
        }
        if !inline {
            let bytes = bytes::Bytes::copy_from_slice(payload);
            let body = futures::stream::once(async move { Ok(bytes) }).boxed();
            self.storage
                .put(&payload_key(topic, &id), body, PutMeta::default())
                .await
                .map_err(MessagingError::backend)?;
        }
        // Coalesce this publish's INDEX writes into ONE durable `write_batch` (A1): the meta record
        // (carrying an inlined payload when A3 applies), and — on a grouped topic — the retained-log
        // marker + the `logmax` gate advance, in a single flush instead of 2–4 separate awaited puts.
        // The durable signed-context (R1) rides on the meta record, deleted with it on ack/dead-letter.
        let mut ops: Vec<WriteOp> = Vec::with_capacity(3);
        let mut record = Record::fresh(signed_context.map(str::to_owned));
        if inline {
            record.inline = Some(payload.to_vec());
        }
        ops.push(WriteOp::Put(
            meta_key(topic, &id),
            serde_json::to_vec(&record).map_err(MessagingError::backend)?,
        ));
        // Grouped (fan-out) topics keep a **retained** copy of the payload + an append-only log
        // entry, so each group consumes on its own high-water long after the work-queue ack would
        // have deleted it, and advance the per-topic `logmax` gate marker (so an idle group's claim
        // early-returns without a scan). Only paid on topics with a registered group.
        if retain {
            let bytes = bytes::Bytes::copy_from_slice(payload);
            let body = futures::stream::once(async move { Ok(bytes) }).boxed();
            self.storage
                .put(&gpayload_key(topic, &id), body, PutMeta::default())
                .await
                .map_err(MessagingError::backend)?;
            ops.push(WriteOp::Put(glog_key(topic, &id), Vec::new()));
            // Advance the gate to the max id seen — never backward, so two concurrent same-ms
            // publishes can't leave it below a retained id (which would wrongly close the gate on
            // the higher one).
            let cur = self
                .kv
                .get(&logmax_key(topic))
                .await
                .map_err(MessagingError::backend)?
                .map(|v| String::from_utf8_lossy(&v).into_owned())
                .unwrap_or_default();
            if id.as_str() > cur.as_str() {
                ops.push(WriteOp::Put(logmax_key(topic), id.clone().into_bytes()));
            }
        }
        Ok((id, ops))
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

    /// Best-effort read of a message's durable signed-context envelope from its index record
    /// (the grouped fan-out path has no per-message record of its own, so it re-reads the shared
    /// index record). Any miss (record gone, decode error) ⇒ `None`, so the consumer's
    /// `signed_context` source simply fails closed rather than erroring the whole claim.
    ///
    /// Caveat (fail-closed, not a breach): if the *same* topic is also drained by the default
    /// work-queue, a work-queue `ack` deletes the shared index record, after which a grouped
    /// consumer's `read_ctx` misses and that delivery carries no context (its "own" op then fails
    /// closed). A `signed_context` grouped consumer should therefore not share a topic with a
    /// work-queue drain — use a dedicated `bus:<topic>` per group.
    async fn read_ctx(&self, topic: &str, id: &str) -> Option<String> {
        let raw = self.kv.get(&meta_key(topic, id)).await.ok()??;
        let record: Record = serde_json::from_slice(&raw).ok()?;
        record.signed_context
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

    /// Read every dead-letter on `topic` as [`DeadLetter`] METADATA (no payload) across BOTH lanes —
    /// the work-queue (`mqdead/{topic}/{id}`) and every consumer group (`mqgd/{topic}/{group}/{id}`) —
    /// ordered by id. The shared read path behind `list`/`redrive_filtered`/`discard` (P1 selective
    /// DLQ). Payloads are loaded lazily by `show_dead_letter`, so a large DLQ lists cheaply.
    async fn collect_dead_letters(&self, topic: &str) -> Result<Vec<DeadLetter>, MessagingError> {
        let mut out = Vec::new();
        // Work-queue lane.
        let wq_prefix = dead_prefix(topic);
        for key in self
            .kv
            .list_prefix(&wq_prefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if !is_direct_child(&key, &wq_prefix) {
                continue;
            }
            let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? else {
                continue;
            };
            let record: Record =
                serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
            out.push(DeadLetter {
                id: key[wq_prefix.len()..].to_string(),
                group: String::new(),
                attempts: record.attempts,
                last_error: record.last_error,
                signed_context: record.signed_context,
                payload: None,
            });
        }
        // Grouped lanes (every group).
        let gprefix = gdead_topic_prefix(topic);
        for key in self
            .kv
            .list_prefix(&gprefix)
            .await
            .map_err(MessagingError::backend)?
        {
            let Some((group, id)) = split_group_id(&key[gprefix.len()..]) else {
                continue;
            };
            let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? else {
                continue;
            };
            let record: Record =
                serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
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
        Ok(out)
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

        // A dead-lettered message PINS its retained payload against reclaim (any group's dead-letter
        // for this topic), so a redrive/purge always has the payload — no separate dead-letter copy
        // needed, and this is the ONE mechanism that also works cluster-side (the deterministic Raft
        // apply cannot write to object storage). Gather the dead-lettered ids across all groups once.
        let gdead_prefix = gdead_topic_prefix(topic);
        let mut dead_ids = std::collections::HashSet::new();
        for key in self
            .kv
            .list_prefix(&gdead_prefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if let Some((_, id)) = split_group_id(&key[gdead_prefix.len()..]) {
                dead_ids.insert(id.to_string());
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
            // A dead-lettered message's payload is pinned unconditionally (even past retention age)
            // until the dead-letter is redriven or purged — so a redrive always has its payload.
            let pinned = dead_ids.contains(id);
            let needed = grouped_message_needed(&states, id);
            let expired = id_millis(id) + GROUP_RETENTION_MS < now;
            if !pinned && (!needed || expired) {
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
        self.publish_ctx(topic, payload, None).await
    }

    async fn publish_ctx(
        &self,
        topic: &str,
        payload: &[u8],
        signed_context: Option<&str>,
    ) -> Result<(), MessagingError> {
        // Build this message's index ops (doing any object-store payload write first), then commit
        // them in one durable group-commit. Factored so `publish_batch_ctx` reuses the identical
        // A3-inline / SA1-budget / grouped-retain decisions and coalesces N messages into one commit.
        let (id, ops) = self
            .build_publish_ops(topic, payload, signed_context)
            .await?;
        // Group-commit (A2): concurrent publishes coalesce their index writes into one durable
        // `write_batch`. Returns only after this message's group is durably committed
        // (at-least-once); a failed group fails this publish too. Payloads (object store) were
        // already written by `build_publish_ops` (payload-first), so only the index writes are here.
        self.group_commit(ops).await?;
        // Notify live SSE subscribers (best-effort, separate from the durable queue above).
        self.hubs.broadcast(topic, &id, payload);
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
        // A4 — coalesce the WHOLE batch's index writes into ONE durable `write_batch`: build every
        // message's ops (each doing its own payload-first object-store write + A3/SA1 decision), then
        // a single `group_commit`. Fail-all: any build error returns before we commit, so no message
        // in the batch is delivered (the same all-or-nothing the single group-commit gives). Every
        // message shares the one host-minted `signed_context` (one producer principal per batch).
        let mut all_ops: Vec<WriteOp> = Vec::with_capacity(messages.len());
        let mut broadcasts: Vec<(&str, String, &[u8])> = Vec::with_capacity(messages.len());
        for (topic, payload) in messages {
            let (id, ops) = self
                .build_publish_ops(topic, payload, signed_context)
                .await?;
            all_ops.extend(ops);
            broadcasts.push((topic.as_str(), id, payload.as_slice()));
        }
        self.group_commit(all_ops).await?;
        for (topic, id, payload) in &broadcasts {
            self.hubs.broadcast(topic, id, payload);
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
        // Flow control (P2): a paused topic delivers nothing (publish + in-flight ack/nack unaffected).
        if self.is_paused(topic).await? {
            return Ok(Vec::new());
        }
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
                    // A3: an inlined payload rides the record — no object-store fetch.
                    let inline = record.inline.is_some();
                    let payload = match record.inline {
                        Some(bytes) => bytes,
                        None => self.read_payload(topic, &id).await?,
                    };
                    claimed.push(ClaimedMessage {
                        id,
                        topic: topic.to_string(),
                        payload,
                        attempts: record.attempts,
                        group: String::new(),
                        signed_context: record.signed_context,
                        inline,
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
        // Flow control (P2): a paused topic delivers nothing to any group.
        if self.is_paused(topic).await? {
            return Ok(Vec::new());
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

        // Dead-letter the exhausted ones under the group's DLQ, capturing the producer's
        // signed-context so a redriven message still resolves its tenant. The retained payload
        // (`mqgp/…`) is left in place and PINNED against the retention sweep by the dead-letter
        // record (see `gc_grouped`) — so the DLQ is inspectable/redrivable/purgeable without a
        // separate payload copy (the mechanism that also works cluster-side).
        for (id, attempts) in &plan.dead {
            let signed_context = self.read_ctx(topic, id).await;
            let record = Record {
                version: crate::SCHEMA_VERSION,
                attempts: *attempts,
                lease_until_ms: 0,
                signed_context,
                // Grouped payloads are object-store retained (pinned by this dead-letter), never inlined.
                inline: None,
                // Grouped last_error capture needs a per-in-flight reason (GroupState::InFlight) — a
                // follow-up; work-queue dead-letters carry it today (that's construens' poison path).
                last_error: None,
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
                Ok(payload) => {
                    let signed_context = self.read_ctx(topic, &id).await;
                    claimed.push(ClaimedMessage {
                        id,
                        topic: topic.to_string(),
                        payload,
                        attempts,
                        group: group.to_string(),
                        signed_context,
                        // Grouped/fan-out payloads are always object-store retained, never inlined.
                        inline: false,
                    });
                }
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
        // A3: an inlined payload lived IN the record just deleted — no object-store object exists, so
        // skip the delete (avoids a wasted object-store round-trip, the whole point of inlining), and
        // release its bytes from the SA1 aggregate-inline budget.
        if msg.inline {
            // Saturating (never wrap on underflow — a post-restart ack of a pre-restart inline
            // message would otherwise underflow the counter and wedge the budget at "full").
            let _ = self.inline_inflight_bytes.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |v| Some(v.saturating_sub(msg.payload.len())),
            );
        } else {
            self.storage
                .delete(&payload_key(&msg.topic, &msg.id))
                .await
                .map_err(MessagingError::backend)?;
        }
        Ok(())
    }

    async fn backlog(&self, topic: &str) -> Result<usize, MessagingError> {
        self.count_direct(&meta_prefix(topic)).await
    }

    async fn oldest_pending_ms(&self, topic: &str) -> Result<Option<u64>, MessagingError> {
        // The earliest live work-queue id (ids are time-ordered; `list_prefix` is sorted, so the
        // first direct child is the oldest). Age = now − its embedded publish time.
        let prefix = meta_prefix(topic);
        let mut oldest: Option<u64> = None;
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if !is_direct_child(&key, &prefix) {
                continue;
            }
            let ms = id_millis(&key[prefix.len()..]);
            oldest = Some(oldest.map_or(ms, |o| o.min(ms)));
        }
        Ok(oldest.map(|ms| now_unix_ms().saturating_sub(ms)))
    }

    async fn in_flight_count(&self, topic: &str) -> Result<usize, MessagingError> {
        let now = now_unix_ms();
        // Work-queue: records currently leased (lease_until_ms in the future).
        let prefix = meta_prefix(topic);
        let mut count = 0;
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if !is_direct_child(&key, &prefix) {
                continue;
            }
            if let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? {
                if let Ok(rec) = serde_json::from_slice::<Record>(&raw) {
                    if rec.lease_until_ms > now {
                        count += 1;
                    }
                }
            }
        }
        // Grouped: every registered group's currently-leased in-flight entries.
        let gprefix = gstate_prefix(topic);
        for key in self
            .kv
            .list_prefix(&gprefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if !is_direct_child(&key, &gprefix) {
                continue;
            }
            let group = &key[gprefix.len()..];
            if let Some(state) = self.get_group_state(topic, group).await? {
                count += state
                    .in_flight
                    .iter()
                    .filter(|f| f.lease_until_ms > now)
                    .count();
            }
        }
        Ok(count)
    }

    async fn group_lag(&self, topic: &str, group: &str) -> Result<usize, MessagingError> {
        let Some(state) = self.get_group_state(topic, group).await? else {
            return Ok(0);
        };
        // Retained log ids strictly beyond the group's high-water = not-yet-leased for this group.
        let prefix = glog_prefix(topic);
        let mut lag = 0;
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if !is_direct_child(&key, &prefix) {
                continue;
            }
            if key[prefix.len()..] > *state.hwm {
                lag += 1;
            }
        }
        Ok(lag)
    }

    async fn dead_letter_count(&self, topic: &str) -> Result<usize, MessagingError> {
        // Work-queue dead-letters (`mqdead/{topic}/{id}`) PLUS every consumer group's dead-letters
        // (`mqgd/{topic}/{group}/{id}`). Before v0.4.24 only the work-queue keyspace was counted, so
        // a fan-out consumer's poison messages reported `0` and were invisible to the operator.
        let wq = self.count_direct(&dead_prefix(topic)).await?;
        let gprefix = gdead_topic_prefix(topic);
        let grouped = self
            .kv
            .list_prefix(&gprefix)
            .await
            .map_err(MessagingError::backend)?
            .into_iter()
            .filter(|k| split_group_id(&k[gprefix.len()..]).is_some())
            .count();
        Ok(wq + grouped)
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
        let mut purged = 0;
        // Work-queue dead-letters: drop the preserved payload then the record (payload-then-index,
        // mirroring `ack`).
        let prefix = dead_prefix(topic);
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if !is_direct_child(&key, &prefix) {
                continue; // a subtopic's dead letters aren't this topic's
            }
            let id = &key[prefix.len()..];
            // Only delete an object-store payload for a NON-inlined dead record; an inlined one's
            // payload lived in the record we're about to delete (no object exists to free).
            let inline = self
                .kv
                .get(&key)
                .await
                .map_err(MessagingError::backend)?
                .and_then(|raw| serde_json::from_slice::<Record>(&raw).ok())
                .is_some_and(|r| r.inline.is_some());
            if !inline {
                self.storage
                    .delete(&payload_key(topic, id))
                    .await
                    .map_err(MessagingError::backend)?;
            }
            self.kv
                .delete(&key)
                .await
                .map_err(MessagingError::backend)?;
            purged += 1;
        }
        // Grouped dead-letters (every group): drop the dead-letter record. That un-pins the shared
        // retained payload (`mqgp/…`); the retention sweep reclaims it once no group needs it — we
        // don't delete it here because other groups may still be consuming that message.
        let gprefix = gdead_topic_prefix(topic);
        for key in self
            .kv
            .list_prefix(&gprefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if split_group_id(&key[gprefix.len()..]).is_none() {
                continue;
            }
            self.kv
                .delete(&key)
                .await
                .map_err(MessagingError::backend)?;
            purged += 1;
        }
        Ok(purged)
    }

    async fn redrive_dead_letters(&self, topic: &str) -> Result<usize, MessagingError> {
        let mut redriven = 0;
        // Work-queue: re-arm a fresh, immediately-claimable `mq/` record (the payload is still
        // present), *then* drop the dead record — a crash in between leaves the message recoverable
        // (live) rather than orphaning its payload. Carry the preserved signed-context forward so a
        // redriven message still resolves the producer's tenant on retry.
        let prefix = dead_prefix(topic);
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?
        {
            if !is_direct_child(&key, &prefix) {
                continue;
            }
            let id = &key[prefix.len()..];
            // Re-arm from the preserved dead record: reset attempts + lease (claimable now) but KEEP
            // its signed-context AND its inlined payload (A3) — so a redriven inline message still
            // carries its body without any object-store object.
            let mut record = self
                .kv
                .get(&key)
                .await
                .map_err(MessagingError::backend)?
                .and_then(|raw| serde_json::from_slice::<Record>(&raw).ok())
                .unwrap_or_else(|| Record::fresh(None));
            record.attempts = 0;
            record.lease_until_ms = 0;
            let json = serde_json::to_vec(&record).map_err(MessagingError::backend)?;
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
        // Grouped: restore each dead-letter's preserved payload into the shared retained slot, re-arm
        // the id in its group's in-flight (fresh attempts, claimable now), then drop the dead record
        // + its preserved payload. Serialized with `claim` — it mutates the compact group state.
        let gprefix = gdead_topic_prefix(topic);
        let gkeys = self
            .kv
            .list_prefix(&gprefix)
            .await
            .map_err(MessagingError::backend)?;
        if !gkeys.is_empty() {
            let _guard = self.claim_lock.lock().await;
            for key in gkeys {
                let Some((group, id)) = split_group_id(&key[gprefix.len()..]) else {
                    continue;
                };
                // The retained payload (`mqgp/…`) is still present — it was pinned by this dead-letter
                // record against the retention sweep — so we only re-arm the id in the group's
                // in-flight (fresh attempts, claimable now) and drop the dead record. Create the
                // group at the current head if it was deregistered, so only the redriven id is
                // in-flight (no backlog replay).
                let mut state = match self.get_group_state(topic, group).await? {
                    Some(state) => state,
                    None => {
                        self.mark_grouped(topic);
                        GroupState::new(self.read_logmax(topic).await?)
                    }
                };
                if !state.in_flight.iter().any(|f| f.id == id) {
                    state.in_flight.push(InFlight {
                        id: id.to_string(),
                        attempts: 0,
                        lease_until_ms: 0,
                    });
                }
                self.put_group_state(topic, group, &state).await?;
                self.kv
                    .delete(&key)
                    .await
                    .map_err(MessagingError::backend)?;
                redriven += 1;
            }
        }
        Ok(redriven)
    }

    async fn set_last_error(
        &self,
        msg: &ClaimedMessage,
        reason: &str,
    ) -> Result<(), MessagingError> {
        // Grouped last_error capture (GroupState::InFlight) is a follow-up; today the work-queue lane
        // records it (construens' poison path). A grouped call is a safe no-op, never an error.
        if !msg.group.is_empty() {
            return Ok(());
        }
        let key = meta_key(&msg.topic, &msg.id);
        let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? else {
            return Ok(()); // acked/gone since the failed delivery — nothing to annotate.
        };
        let mut record: Record =
            serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
        record.last_error = Some(sanitize_reason(reason));
        let json = serde_json::to_vec(&record).map_err(MessagingError::backend)?;
        self.kv
            .put(&key, json)
            .await
            .map_err(MessagingError::backend)?;
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
            .await?
            .into_iter()
            .filter(|dl| filter.matches(dl, now))
            .collect();
        if let Some(limit) = filter.limit {
            matched.truncate(limit); // collect_dead_letters ordered by id, so this keeps the earliest.
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
            dead_key(topic, id)
        } else {
            gdead_key(topic, group, id)
        };
        let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? else {
            return Ok(None);
        };
        let record: Record =
            serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
        // Payload: an inlined body rides in the record (A3); otherwise it is object-store retained —
        // the work-queue copy (`payload_key`) or the shared grouped copy (`gpayload_key`, pinned by
        // this dead-letter). A missing object yields an empty body rather than failing the inspection.
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
        let matched: Vec<DeadLetter> = {
            let mut m: Vec<DeadLetter> = self
                .collect_dead_letters(topic)
                .await?
                .into_iter()
                .filter(|dl| filter.matches(dl, now))
                .collect();
            if let Some(limit) = filter.limit {
                m.truncate(limit);
            }
            m
        };
        let mut redriven = 0;
        // Work-queue matches: re-arm a fresh `mq/` record from the preserved dead record (attempts +
        // lease reset, signed-context + inline payload kept), then drop the dead record.
        for dl in matched.iter().filter(|dl| dl.group.is_empty()) {
            let dead = dead_key(topic, &dl.id);
            let Some(raw) = self.kv.get(&dead).await.map_err(MessagingError::backend)? else {
                continue;
            };
            let mut record: Record =
                serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
            record.attempts = 0;
            record.lease_until_ms = 0;
            record.last_error = None; // a fresh life — the prior failure reason no longer applies.
            let json = serde_json::to_vec(&record).map_err(MessagingError::backend)?;
            self.kv
                .put(&meta_key(topic, &dl.id), json)
                .await
                .map_err(MessagingError::backend)?;
            self.kv
                .delete(&dead)
                .await
                .map_err(MessagingError::backend)?;
            redriven += 1;
        }
        // Grouped matches: re-arm each id in its group's in-flight (fresh attempts, claimable now) and
        // drop the dead record — the retained payload stays pinned until then. One `claim_lock` turn.
        let grouped: Vec<&DeadLetter> = matched.iter().filter(|dl| !dl.group.is_empty()).collect();
        if !grouped.is_empty() {
            let _guard = self.claim_lock.lock().await;
            for dl in grouped {
                let dead = gdead_key(topic, &dl.group, &dl.id);
                if self
                    .kv
                    .get(&dead)
                    .await
                    .map_err(MessagingError::backend)?
                    .is_none()
                {
                    continue;
                }
                let mut state = match self.get_group_state(topic, &dl.group).await? {
                    Some(state) => state,
                    None => {
                        self.mark_grouped(topic);
                        GroupState::new(self.read_logmax(topic).await?)
                    }
                };
                if !state.in_flight.iter().any(|f| f.id == dl.id) {
                    state.in_flight.push(InFlight {
                        id: dl.id.clone(),
                        attempts: 0,
                        lease_until_ms: 0,
                    });
                }
                self.put_group_state(topic, &dl.group, &state).await?;
                self.kv
                    .delete(&dead)
                    .await
                    .map_err(MessagingError::backend)?;
                redriven += 1;
            }
        }
        Ok(redriven)
    }

    async fn discard_dead_letters(
        &self,
        topic: &str,
        filter: &DeadLetterFilter,
    ) -> Result<usize, MessagingError> {
        let now = now_unix_ms();
        let matched: Vec<DeadLetter> = {
            let mut m: Vec<DeadLetter> = self
                .collect_dead_letters(topic)
                .await?
                .into_iter()
                .filter(|dl| filter.matches(dl, now))
                .collect();
            if let Some(limit) = filter.limit {
                m.truncate(limit);
            }
            m
        };
        let mut discarded = 0;
        for dl in &matched {
            if dl.group.is_empty() {
                // Work-queue: drop the object-store payload (unless inlined) then the record.
                let dead = dead_key(topic, &dl.id);
                let inline = self
                    .kv
                    .get(&dead)
                    .await
                    .map_err(MessagingError::backend)?
                    .and_then(|raw| serde_json::from_slice::<Record>(&raw).ok())
                    .is_some_and(|r| r.inline.is_some());
                if !inline {
                    self.storage
                        .delete(&payload_key(topic, &dl.id))
                        .await
                        .map_err(MessagingError::backend)?;
                }
                self.kv
                    .delete(&dead)
                    .await
                    .map_err(MessagingError::backend)?;
            } else {
                // Grouped: drop the dead record; the shared retained payload un-pins and the sweep
                // reclaims it once no group needs it (another group may still consume this message).
                self.kv
                    .delete(&gdead_key(topic, &dl.group, &dl.id))
                    .await
                    .map_err(MessagingError::backend)?;
            }
            discarded += 1;
        }
        Ok(discarded)
    }

    async fn peek(&self, topic: &str, limit: usize) -> Result<Vec<PeekedMessage>, MessagingError> {
        let now = now_unix_ms();
        let prefix = meta_prefix(topic);
        let mut keys: Vec<String> = self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(MessagingError::backend)?
            .into_iter()
            .filter(|k| is_direct_child(k, &prefix))
            .collect();
        keys.sort(); // ids are time-ordered ⇒ delivery order.
        let mut out = Vec::new();
        for key in keys.into_iter().take(limit) {
            let Some(raw) = self.kv.get(&key).await.map_err(MessagingError::backend)? else {
                continue;
            };
            let record: Record =
                serde_json::from_slice(&raw).map_err(|e| MessagingError::Decode(e.to_string()))?;
            let id = key[prefix.len()..].to_string();
            // Read-only: never mutate the lease or attempts. Inline rides in the record; otherwise the
            // object-store copy (a missing object yields an empty body rather than failing the peek).
            let payload = match &record.inline {
                Some(bytes) => bytes.clone(),
                None => self.read_payload(topic, &id).await.unwrap_or_default(),
            };
            out.push(PeekedMessage {
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
        let gprefix = gstate_prefix(topic);
        let group_keys = self
            .kv
            .list_prefix(&gprefix)
            .await
            .map_err(MessagingError::backend)?;
        // The retained log ids once, for each group's lag (ids strictly beyond its hwm).
        let log_prefix = glog_prefix(topic);
        let log_ids: Vec<String> = self
            .kv
            .list_prefix(&log_prefix)
            .await
            .map_err(MessagingError::backend)?
            .into_iter()
            .filter(|k| is_direct_child(k, &log_prefix))
            .map(|k| k[log_prefix.len()..].to_string())
            .collect();
        let mut out = Vec::new();
        for key in group_keys {
            if !is_direct_child(&key, &gprefix) {
                continue;
            }
            let group = key[gprefix.len()..].to_string();
            let Some(state) = self.get_group_state(topic, &group).await? else {
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
        start: StartPosition,
    ) -> Result<(), MessagingError> {
        // Serialize with claim/ack — it replaces the group's compact state.
        let _guard = self.claim_lock.lock().await;
        if self.get_group_state(topic, group).await?.is_none() {
            return Err(MessagingError::Backend(format!(
                "no such consumer group {group:?} on topic {topic:?}"
            )));
        }
        // Move the cursor + DROP the in-flight set: Earliest ⇒ hwm "" (re-consume the whole retained
        // backlog), Latest ⇒ hwm = current logmax (skip to the head). GroupState::new clears in_flight.
        let hwm = match start {
            StartPosition::Earliest => String::new(),
            StartPosition::Latest => self.read_logmax(topic).await?,
        };
        self.put_group_state(topic, group, &GroupState::new(hwm))
            .await?;
        Ok(())
    }

    async fn delete_group(&self, topic: &str, group: &str) -> Result<(), MessagingError> {
        let _guard = self.claim_lock.lock().await;
        // Delete this group's dead-letters, then its state. The shared retained log/payloads it pinned
        // are reclaimed by the retention sweep once no remaining group needs them.
        let dprefix = format!("mqgd/{topic}/{group}/");
        for key in self
            .kv
            .list_prefix(&dprefix)
            .await
            .map_err(MessagingError::backend)?
        {
            self.kv
                .delete(&key)
                .await
                .map_err(MessagingError::backend)?;
        }
        self.kv
            .delete(&gstate_key(topic, group))
            .await
            .map_err(MessagingError::backend)?;
        Ok(())
    }

    async fn set_paused(&self, topic: &str, paused: bool) -> Result<(), MessagingError> {
        let key = pause_key(topic);
        if paused {
            self.kv
                .put(&key, Vec::new())
                .await
                .map_err(MessagingError::backend)?;
        } else {
            self.kv
                .delete(&key)
                .await
                .map_err(MessagingError::backend)?;
        }
        Ok(())
    }

    async fn is_paused(&self, topic: &str) -> Result<bool, MessagingError> {
        Ok(self
            .kv
            .get(&pause_key(topic))
            .await
            .map_err(MessagingError::backend)?
            .is_some())
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

    /// A `KvStore` whose durable-commit boundary (`put`/`write_batch`) always fails — drives the
    /// group-commit fail-all path (`publish`/`publish_batch` → `group_commit` → `write_batch` → error).
    struct FailingKv;
    #[async_trait]
    impl KvStore for FailingKv {
        async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, crate::kv::KvError> {
            Ok(None)
        }
        async fn put(&self, _: &str, _: Vec<u8>) -> Result<(), crate::kv::KvError> {
            Err(crate::kv::KvError::backend("commit failed"))
        }
        async fn delete(&self, _: &str) -> Result<(), crate::kv::KvError> {
            Ok(())
        }
        async fn list_prefix(&self, _: &str) -> Result<Vec<String>, crate::kv::KvError> {
            Ok(Vec::new())
        }
        async fn write_batch(&self, _: Vec<crate::kv::WriteOp>) -> Result<(), crate::kv::KvError> {
            Err(crate::kv::KvError::backend("commit failed"))
        }
    }

    /// A `KvStore` that delegates to an inner [`MemoryKv`] and counts `write_batch` calls — proves a
    /// group/batch coalesces into ONE durable commit rather than one per message.
    struct CountingKv {
        inner: MemoryKv,
        batches: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl KvStore for CountingKv {
        async fn get(&self, k: &str) -> Result<Option<Vec<u8>>, crate::kv::KvError> {
            self.inner.get(k).await
        }
        async fn put(&self, k: &str, v: Vec<u8>) -> Result<(), crate::kv::KvError> {
            self.inner.put(k, v).await
        }
        async fn delete(&self, k: &str) -> Result<(), crate::kv::KvError> {
            self.inner.delete(k).await
        }
        async fn list_prefix(&self, p: &str) -> Result<Vec<String>, crate::kv::KvError> {
            self.inner.list_prefix(p).await
        }
        async fn write_batch(
            &self,
            ops: Vec<crate::kv::WriteOp>,
        ) -> Result<(), crate::kv::KvError> {
            self.batches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.write_batch(ops).await
        }
    }

    /// A `KvStore` that delegates to an inner [`MemoryKv`] but BLOCKS the first `write_batch` until
    /// released — so a test can hold one publisher inside the durable commit (holding the group-commit
    /// gate) while it stages another publisher behind it. `new()` returns the store plus an `entered`
    /// receiver (fires when the first commit begins) and a `release` sender (unblocks it). Uses
    /// `futures::channel::oneshot` (core's runtime-agnostic dep; tokio's `sync` isn't enabled here).
    struct GateKv {
        inner: MemoryKv,
        calls: std::sync::atomic::AtomicUsize,
        entered_tx: std::sync::Mutex<Option<futures::channel::oneshot::Sender<()>>>,
        release_rx: std::sync::Mutex<Option<futures::channel::oneshot::Receiver<()>>>,
    }
    impl GateKv {
        fn new() -> (
            Arc<Self>,
            futures::channel::oneshot::Receiver<()>,
            futures::channel::oneshot::Sender<()>,
        ) {
            let (entered_tx, entered_rx) = futures::channel::oneshot::channel();
            let (release_tx, release_rx) = futures::channel::oneshot::channel();
            let kv = Arc::new(Self {
                inner: MemoryKv::new(),
                calls: std::sync::atomic::AtomicUsize::new(0),
                entered_tx: std::sync::Mutex::new(Some(entered_tx)),
                release_rx: std::sync::Mutex::new(Some(release_rx)),
            });
            (kv, entered_rx, release_tx)
        }
    }
    #[async_trait]
    impl KvStore for GateKv {
        async fn get(&self, k: &str) -> Result<Option<Vec<u8>>, crate::kv::KvError> {
            self.inner.get(k).await
        }
        async fn put(&self, k: &str, v: Vec<u8>) -> Result<(), crate::kv::KvError> {
            self.inner.put(k, v).await
        }
        async fn delete(&self, k: &str) -> Result<(), crate::kv::KvError> {
            self.inner.delete(k).await
        }
        async fn list_prefix(&self, p: &str) -> Result<Vec<String>, crate::kv::KvError> {
            self.inner.list_prefix(p).await
        }
        async fn write_batch(
            &self,
            ops: Vec<crate::kv::WriteOp>,
        ) -> Result<(), crate::kv::KvError> {
            if self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                if let Some(tx) = self.entered_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                // Take the receiver OUT of the lock before awaiting (never hold a std guard across await).
                let rx = self.release_rx.lock().unwrap().take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
            }
            self.inner.write_batch(ops).await
        }
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

    // A **grouped** (fan-out) consumer's poison message must land in an INSPECTABLE dead-letter
    // store — counted, redrivable (with its payload), purgeable — not silently invisible. Before
    // the fix, grouped dead-letters went to `mqgd/…` while the operator ops scanned only `mqdead/…`,
    // so `dead_letters` reported 0 for exactly the construens fan-out case. Mirrors the work-queue
    // DLQ tests, for a group.
    #[tokio::test]
    async fn grouped_dead_letters_are_visible_redrivable_and_purgeable() {
        let mq = mq();
        let t = "bus/sync";
        // Register the group (first claim), publish one poison message.
        assert!(mq
            .claim_grouped(t, "worker", StartPosition::Latest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        mq.publish(t, b"poison").await.unwrap();
        // max_attempts = 2: two deliveries (ZERO lease ⇒ immediate re-claim), then the 3rd
        // dead-letters instead of delivering.
        for expected in 1..=2 {
            let m = mq
                .claim_grouped(t, "worker", StartPosition::Latest, Duration::ZERO, 10, 2)
                .await
                .unwrap();
            assert_eq!(m.len(), 1, "grouped attempt {expected}");
            assert_eq!(m[0].attempts, expected);
        }
        assert!(mq
            .claim_grouped(t, "worker", StartPosition::Latest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        // VISIBLE: the grouped poison message is counted (the fix).
        assert_eq!(mq.dead_letter_count(t).await.unwrap(), 1);

        // REDRIVABLE: requeues exactly it, and it redelivers with its payload + fresh attempts.
        assert_eq!(mq.redrive_dead_letters(t).await.unwrap(), 1);
        assert_eq!(mq.dead_letter_count(t).await.unwrap(), 0);
        let again = mq
            .claim_grouped(t, "worker", StartPosition::Latest, Duration::ZERO, 10, 2)
            .await
            .unwrap();
        assert_eq!(payloads(&again), vec![b"poison".to_vec()]);
        assert_eq!(again[0].attempts, 1, "redrive reset the attempt count");

        // PURGEABLE: exhaust it again (attempt 2, then dead), then purge removes exactly it.
        assert_eq!(
            mq.claim_grouped(t, "worker", StartPosition::Latest, Duration::ZERO, 10, 2)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(mq
            .claim_grouped(t, "worker", StartPosition::Latest, Duration::ZERO, 10, 2)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count(t).await.unwrap(), 1);
        assert_eq!(mq.purge_dead_letters(t).await.unwrap(), 1);
        assert_eq!(mq.dead_letter_count(t).await.unwrap(), 0);
    }

    // P1 inspection stats: in-flight (leased-but-unacked) is a subset of backlog, and
    // oldest_pending_ms exposes the backlog frontier — so an operator can tell "draining" from
    // "wedged" and "how stale". Read-only; never mutate the queue.
    #[tokio::test]
    async fn stats_expose_in_flight_and_oldest_pending() {
        let mq = mq();
        // Empty topic: nothing pending, nothing in-flight.
        assert_eq!(mq.oldest_pending_ms("t").await.unwrap(), None);
        assert_eq!(mq.in_flight_count("t").await.unwrap(), 0);
        // Published but unclaimed: pending (an age exists — the id carries the publish time), but
        // nothing is leased yet.
        mq.publish("t", b"a").await.unwrap();
        mq.publish("t", b"b").await.unwrap();
        assert!(mq.oldest_pending_ms("t").await.unwrap().is_some());
        assert_eq!(mq.in_flight_count("t").await.unwrap(), 0);
        // Claim both with a long lease → in-flight == 2 (backlog also 2, still pending).
        let claimed = mq.claim("t", Duration::from_secs(60), 10, 5).await.unwrap();
        assert_eq!(claimed.len(), 2);
        assert_eq!(mq.in_flight_count("t").await.unwrap(), 2);
        assert_eq!(mq.backlog("t").await.unwrap(), 2);
        // Ack one → in-flight drops to 1 and backlog to 1.
        mq.ack(&claimed[0]).await.unwrap();
        assert_eq!(mq.in_flight_count("t").await.unwrap(), 1);
        assert_eq!(mq.backlog("t").await.unwrap(), 1);

        // Group lag: a group registered `earliest` then two messages published → lag 2; after it
        // leases them, lag 0 (they're beyond nothing / at its high-water).
        let g = "bus/lag";
        assert!(mq
            .claim_grouped(g, "w", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap()
            .is_empty());
        mq.publish(g, b"x").await.unwrap();
        mq.publish(g, b"y").await.unwrap();
        assert_eq!(
            mq.group_lag(g, "w").await.unwrap(),
            2,
            "two retained, none leased yet"
        );
        let got = mq
            .claim_grouped(g, "w", StartPosition::Earliest, LEASE, 10, 5)
            .await
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            mq.group_lag(g, "w").await.unwrap(),
            0,
            "caught up to the high-water"
        );
    }

    // A3: a small work-queue payload rides IN the index record (no object-store object), so publish
    // is one local durable write and claim needs no fetch; a large payload keeps the object path.
    #[tokio::test]
    async fn small_work_queue_payload_is_inlined_large_takes_object_store() {
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mq = LogMessaging::new(storage.clone(), kv);

        // Small → inlined.
        mq.publish("t", b"small").await.unwrap();
        let m = mq.claim("t", Duration::from_secs(60), 10, 5).await.unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].payload, b"small");
        assert!(m[0].inline, "small payload inlined into the record");
        assert!(
            storage.head(&payload_key("t", &m[0].id)).await.is_err(),
            "inlined ⇒ no object-store object written"
        );
        // Ack cleans up (no object-store object to free); nothing left.
        mq.ack(&m[0]).await.unwrap();
        assert_eq!(mq.backlog("t").await.unwrap(), 0);

        // Larger than INLINE_MAX → object-store path (boatramp's large-blob strength).
        let big = vec![7u8; INLINE_MAX + 1];
        mq.publish("t", &big).await.unwrap();
        let m = mq.claim("t", Duration::from_secs(60), 10, 5).await.unwrap();
        assert_eq!(m[0].payload, big);
        assert!(!m[0].inline, "large payload not inlined");
        assert!(
            storage.head(&payload_key("t", &m[0].id)).await.is_ok(),
            "large payload lives in object storage"
        );
    }

    // SA1: the aggregate-inline budget bounds inline bytes in-flight — past it, publishes fall back
    // to the object-store path; acking an inline message frees budget so later publishes inline again.
    #[tokio::test]
    async fn inline_budget_falls_back_to_object_store_when_exhausted() {
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        // Budget = 10 bytes: the first 5-byte payload inlines; the second would exceed it → object store.
        let mq = LogMessaging::new(storage.clone(), kv).with_inline_budget(10);
        mq.publish("t", b"aaaaa").await.unwrap(); // 5 bytes inline (5 <= 10)
        mq.publish("t", b"bbbbb").await.unwrap(); // 5 + 5 = 10 <= 10 → inline
        mq.publish("t", b"ccccc").await.unwrap(); // 10 + 5 = 15 > 10 → object store
        let got = mq.claim("t", Duration::from_secs(60), 10, 5).await.unwrap();
        assert_eq!(got.len(), 3);
        let inline_count = got.iter().filter(|m| m.inline).count();
        assert_eq!(
            inline_count, 2,
            "budget admitted exactly two inline messages"
        );
        // The third rode object storage.
        let obj = got.iter().find(|m| !m.inline).unwrap();
        assert!(
            storage.head(&payload_key("t", &obj.id)).await.is_ok(),
            "the over-budget message fell back to the object store"
        );
        // Ack an inline message → frees budget → a new small publish inlines again.
        let inline_msg = got.iter().find(|m| m.inline).unwrap().clone();
        mq.ack(&inline_msg).await.unwrap();
        mq.publish("t", b"ddddd").await.unwrap();
        let more = mq.claim("t", Duration::from_secs(60), 10, 5).await.unwrap();
        assert!(
            more.iter().any(|m| m.payload == b"ddddd" && m.inline),
            "after ack freed budget, the next small publish inlines again"
        );
    }

    // A2: many concurrent publishes coalesce through the group-commit gate; each returns Ok ONLY
    // after its group is durably committed (at-least-once), and every message is claimable.
    #[tokio::test]
    async fn group_commit_coalesces_concurrent_publishes() {
        let mq = Arc::new(mq());
        let mut handles = Vec::new();
        for i in 0..64u32 {
            let mq = mq.clone();
            handles.push(tokio::spawn(async move {
                mq.publish("t", format!("m{i}").as_bytes()).await
            }));
        }
        for h in handles {
            h.await
                .unwrap()
                .expect("each publish returns Ok after its durable group commit");
        }
        // All 64 are durably enqueued and claimable (nothing lost, no double-count).
        let mut seen = 0;
        loop {
            let batch = mq
                .claim("t", Duration::from_secs(60), 100, 5)
                .await
                .unwrap();
            if batch.is_empty() {
                break;
            }
            seen += batch.len();
        }
        assert_eq!(
            seen, 64,
            "all concurrent publishes were durably committed and claimable"
        );
    }

    // A2 fail-all: when the group's durable commit fails, EVERY member publish fails — no partial
    // success (a publisher never believes it succeeded when its message wasn't committed).
    #[tokio::test]
    async fn group_commit_fails_all_members_when_the_commit_fails() {
        let mq = Arc::new(LogMessaging::new(
            Arc::new(MemStorage::default()),
            Arc::new(FailingKv),
        ));
        // A single publish surfaces the group-commit failure.
        assert!(
            mq.publish("t", b"x").await.is_err(),
            "a failed group commit fails the publish"
        );
        // Concurrent publishes ALL fail — fail-all, no partial success.
        let mut handles = Vec::new();
        for i in 0..16u32 {
            let mq = mq.clone();
            handles.push(tokio::spawn(async move {
                mq.publish("t", format!("m{i}").as_bytes()).await
            }));
        }
        for h in handles {
            assert!(
                h.await.unwrap().is_err(),
                "every member of a failed group commit fails (fail-all)"
            );
        }
    }

    // A4: a publish_batch commits the WHOLE batch in ONE durable write_batch (not one per message),
    // across mixed topics, and every message is claimable carrying the shared producer context.
    #[tokio::test]
    async fn publish_batch_commits_all_messages_in_one_write_batch() {
        use std::sync::atomic::Ordering as O;
        let kv = Arc::new(CountingKv {
            inner: MemoryKv::new(),
            batches: std::sync::atomic::AtomicUsize::new(0),
        });
        let mq = LogMessaging::new(Arc::new(MemStorage::default()), kv.clone());
        // Five messages across two topics in one batch.
        let msgs: Vec<(String, Vec<u8>)> = (0..5)
            .map(|i| (format!("t{}", i % 2), format!("m{i}").into_bytes()))
            .collect();
        mq.publish_batch_ctx(&msgs, Some("ctx-1")).await.unwrap();
        assert_eq!(
            kv.batches.load(O::Relaxed),
            1,
            "the whole batch was durably committed in ONE write_batch"
        );
        // Every message is durably enqueued on its topic, carrying the shared host context.
        let t0 = mq.claim("t0", LEASE, 10, 5).await.unwrap();
        let t1 = mq.claim("t1", LEASE, 10, 5).await.unwrap();
        assert_eq!(
            t0.len() + t1.len(),
            5,
            "all batch messages durably enqueued and claimable"
        );
        assert!(
            t0.iter()
                .chain(&t1)
                .all(|m| m.signed_context.as_deref() == Some("ctx-1")),
            "every message carries the one shared producer context"
        );
    }

    // A4 fail-all: a failed durable commit fails the WHOLE batch — nothing is enqueued (all-or-nothing,
    // the same contract the single group-commit gives, extended to the batch primitive).
    #[tokio::test]
    async fn publish_batch_fails_whole_when_the_commit_fails() {
        let mq = LogMessaging::new(Arc::new(MemStorage::default()), Arc::new(FailingKv));
        let msgs: Vec<(String, Vec<u8>)> =
            (0..8).map(|i| ("t".to_string(), vec![i as u8])).collect();
        assert!(
            mq.publish_batch_ctx(&msgs, None).await.is_err(),
            "a failed commit fails the whole batch"
        );
    }

    // A4: publish_batch preserves publish order — claim returns the batch in the order it was handed
    // in (a durable work-queue must not reorder a producer's own batch). JetStream: stream order.
    #[tokio::test]
    async fn publish_batch_preserves_publish_order() {
        let mq = mq();
        let msgs: Vec<(String, Vec<u8>)> = (0..20)
            .map(|i| ("t".to_string(), format!("m{i:02}").into_bytes()))
            .collect();
        mq.publish_batch_ctx(&msgs, None).await.unwrap();
        let got = mq.claim("t", LEASE, 100, 5).await.unwrap();
        assert_eq!(
            payloads(&got),
            msgs.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>(),
            "the batch is claimable in publish order"
        );
    }

    // A2/A4 op-bounded drain: a single batch whose op count exceeds GROUP_COMMIT_MAX is still taken
    // WHOLE and committed in ONE write_batch — proves the drain always makes progress on an oversized
    // single job (the `n > 0` guard) rather than starving it.
    #[tokio::test]
    async fn oversized_single_batch_commits_whole_in_one_write_batch() {
        use std::sync::atomic::Ordering as O;
        let kv = Arc::new(CountingKv {
            inner: MemoryKv::new(),
            batches: std::sync::atomic::AtomicUsize::new(0),
        });
        let mq = LogMessaging::new(Arc::new(MemStorage::default()), kv.clone());
        // GROUP_COMMIT_MAX + 100 messages = one PublishJob whose op count exceeds the per-turn budget.
        let n = GROUP_COMMIT_MAX + 100;
        let msgs: Vec<(String, Vec<u8>)> =
            (0..n).map(|i| ("t".to_string(), vec![i as u8])).collect();
        mq.publish_batch_ctx(&msgs, None).await.unwrap();
        assert_eq!(
            kv.batches.load(O::Relaxed),
            1,
            "the oversized single batch committed in exactly one write_batch (drain took it whole)"
        );
        let mut seen = 0;
        loop {
            let b = mq.claim("t", LEASE, 10_000, 5).await.unwrap();
            if b.is_empty() {
                break;
            }
            seen += b.len();
        }
        assert_eq!(
            seen, n,
            "every message in the oversized batch is durably enqueued"
        );
    }

    // A2 durability edge (JetStream-parity: at-least-once never loses an in-flight write): a publisher
    // CANCELLED after pushing its group-commit job but before taking the gate is still committed by a
    // LATER gate-holder. A cancelled publish may thus still deliver (the safe direction) — it must
    // NEVER silently vanish mid-commit.
    #[tokio::test]
    async fn cancelled_publisher_is_still_committed_by_a_later_gate_holder() {
        let (kv, entered_rx, release_tx) = GateKv::new();
        let mq = Arc::new(LogMessaging::new(Arc::new(MemStorage::default()), kv));

        // Q: a publish that blocks inside its durable commit → holds the group-commit gate.
        let q = {
            let mq = mq.clone();
            tokio::spawn(async move { mq.publish("t", b"Q").await })
        };
        entered_rx.await.unwrap(); // Q is now inside write_batch, holding the gate.

        // P: drive one poll so it builds its ops and PUSHES its job, then blocks on the held gate —
        // then drop the future (cancel P after it enqueued but before it could commit).
        {
            let mut p = Box::pin(mq.publish("t", b"P"));
            let polled = futures::poll!(p.as_mut());
            assert!(
                polled.is_pending(),
                "P pushed its job and is now blocked on the gate Q holds"
            );
        } // P dropped — cancelled after pushing.

        // Release Q: it commits its own job; P's job stays queued (its owner is gone).
        release_tx.send(()).unwrap();
        q.await.unwrap().unwrap();

        // R: a later publisher drains the queue — including P's orphaned job — and commits both.
        mq.publish("t", b"R").await.unwrap();

        let mut seen = Vec::new();
        loop {
            let b = mq.claim("t", LEASE, 100, 5).await.unwrap();
            if b.is_empty() {
                break;
            }
            seen.extend(b.into_iter().map(|m| m.payload));
        }
        assert!(seen.contains(&b"Q".to_vec()), "Q committed");
        assert!(seen.contains(&b"R".to_vec()), "R committed");
        assert!(
            seen.contains(&b"P".to_vec()),
            "the cancelled publisher's message was still durably committed (never silently lost)"
        );
    }

    // A3 × DLQ: an inlined message that dead-letters keeps its payload in the record, so redrive
    // redelivers it with its body and purge needs no object-store touch.
    #[tokio::test]
    async fn inlined_message_dead_letters_and_redrives_with_its_payload() {
        let mq = mq();
        mq.publish("t", b"poison").await.unwrap();
        // max_attempts=1: one delivery, next claim dead-letters.
        let m = mq.claim("t", Duration::ZERO, 10, 1).await.unwrap();
        assert!(m[0].inline);
        assert!(mq
            .claim("t", Duration::ZERO, 10, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 1);
        // Redrive → redelivers with the inlined payload intact.
        assert_eq!(mq.redrive_dead_letters("t").await.unwrap(), 1);
        let back = mq.claim("t", Duration::from_secs(60), 10, 1).await.unwrap();
        assert_eq!(back[0].payload, b"poison");
        assert!(back[0].inline);
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

    // P1 selective DLQ: last_error capture (sanitized), list/show, and redrive/discard by an
    // AND-composed filter (--id / --match / --limit), work-queue lane.
    #[tokio::test]
    async fn selective_dlq_list_show_redrive_discard_by_filter() {
        let mq = mq();
        for p in [b"aaa".as_slice(), b"bbb", b"ccc"] {
            mq.publish("t", p).await.unwrap();
        }
        // Deliver once (attempt 1, max_attempts=1), annotate "bbb" with a host failure reason that
        // includes control characters (must be sanitized), then the next claim dead-letters all three.
        let first = mq.claim("t", Duration::ZERO, 10, 1).await.unwrap();
        let bbb = first.iter().find(|m| m.payload == b"bbb").unwrap().clone();
        mq.set_last_error(&bbb, "guest-trap:\n injected\u{7} reason")
            .await
            .unwrap();
        assert!(mq
            .claim("t", Duration::ZERO, 10, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 3);

        // list: metadata only (no payloads); "bbb" carries the SANITIZED reason (control chars gone).
        let all = mq
            .list_dead_letters("t", &DeadLetterFilter::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|d| d.payload.is_none()));
        let bbb_dl = all.iter().find(|d| d.id == bbb.id).unwrap();
        let err = bbb_dl.last_error.as_deref().unwrap();
        assert!(err.contains("guest-trap"));
        assert!(
            !err.contains('\n') && !err.contains('\u{7}'),
            "control characters are sanitized out of last_error"
        );

        // --match (substring on last_error) → only bbb.
        let matched = mq
            .list_dead_letters(
                "t",
                &DeadLetterFilter {
                    match_last_error: Some("guest-trap".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id, bbb.id);

        // --limit caps the (id-ordered) result.
        let limited = mq
            .list_dead_letters(
                "t",
                &DeadLetterFilter {
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(limited.len(), 2);

        // show returns the full body + reason.
        let shown = mq
            .show_dead_letter("t", "", &bbb.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(shown.payload.as_deref(), Some(b"bbb".as_slice()));
        assert!(shown.last_error.as_deref().unwrap().contains("guest-trap"));

        // redrive ONLY bbb (by id) → back on the live queue with a fresh life; DLQ now 2.
        let n = mq
            .redrive_dead_letters_filtered(
                "t",
                &DeadLetterFilter {
                    id: Some(bbb.id.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 2);
        let back = mq.claim("t", LEASE, 10, 5).await.unwrap();
        let revived = back.iter().find(|m| m.payload == b"bbb").unwrap();
        assert_eq!(revived.attempts, 1, "redrive resets attempts");

        // discard the remaining two (all-match filter) → DLQ empty.
        let d = mq
            .discard_dead_letters("t", &DeadLetterFilter::default())
            .await
            .unwrap();
        assert_eq!(d, 2);
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 0);
    }

    // P1 selective DLQ: --older-than filters by the message's own age (derived from its time-ordered
    // id), and a foreign/unparseable id is never swept by an age filter (fail-closed).
    #[tokio::test]
    async fn selective_dlq_older_than_uses_id_age() {
        let mq = mq();
        mq.publish("t", b"recent").await.unwrap();
        assert_eq!(mq.claim("t", Duration::ZERO, 10, 1).await.unwrap().len(), 1);
        assert!(mq
            .claim("t", Duration::ZERO, 10, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mq.dead_letter_count("t").await.unwrap(), 1);
        // The message was published moments ago, so a 1-hour `older_than` matches nothing…
        let none = mq
            .list_dead_letters(
                "t",
                &DeadLetterFilter {
                    older_than_ms: Some(3_600_000),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            none.is_empty(),
            "a just-published dead-letter isn't 'older than' 1h"
        );
        // …but `older_than: 0` matches it (age >= 0).
        let any = mq
            .list_dead_letters(
                "t",
                &DeadLetterFilter {
                    older_than_ms: Some(0),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(any.len(), 1);
    }

    // SEC6: sanitize_reason strips control characters (no log/JSON injection) and byte-bounds to
    // LAST_ERROR_MAX without splitting a multi-byte char (the security review's UTF-8-boundary note).
    #[test]
    fn sanitize_reason_strips_control_chars_and_bounds_bytes() {
        let s = sanitize_reason("guest-trap:\n\t\u{7}boom");
        assert!(s.contains("guest-trap") && s.contains("boom"));
        assert!(!s.chars().any(char::is_control), "no control chars survive");
        // 4-byte chars: 100 emoji = 400 bytes → bounded to <=256, still valid UTF-8 (a String always
        // is; the point is the boundary check never panics or truncates mid-char).
        let emoji = sanitize_reason(&"😀".repeat(100));
        assert!(emoji.len() <= LAST_ERROR_MAX);
        assert_eq!(
            emoji.len() % 4,
            0,
            "bounded on a whole 4-byte char boundary"
        );
        // 3-byte chars.
        assert!(sanitize_reason(&"€".repeat(200)).len() <= LAST_ERROR_MAX);
        // All-control input collapses to empty (trimmed).
        assert_eq!(sanitize_reason("\n\r\t\u{0}"), "");
    }

    // Site-confinement underpinning (the review's traversal note): a DLQ op is confined to its
    // namespaced topic — listing/discarding one site's queue never sees or touches another's, because
    // the KV keyspace is literal-prefixed (no path normalization). Proven at the substrate that the
    // operator's `{site}/…` namespacing relies on.
    #[tokio::test]
    async fn dead_letter_ops_are_confined_to_their_namespaced_topic() {
        let mq = mq();
        for t in ["siteA/orders", "siteB/orders"] {
            mq.publish(t, format!("{t}-poison").as_bytes())
                .await
                .unwrap();
            assert_eq!(mq.claim(t, Duration::ZERO, 10, 1).await.unwrap().len(), 1);
            assert!(mq.claim(t, Duration::ZERO, 10, 1).await.unwrap().is_empty());
        }
        // A list on site A sees ONLY A's dead-letter.
        let a = mq
            .list_dead_letters("siteA/orders", &DeadLetterFilter::default())
            .await
            .unwrap();
        assert_eq!(a.len(), 1);
        assert!(!a[0].id.is_empty() && a.iter().all(|d| !d.id.contains("siteB")));
        // A discard on site A leaves site B's dead-letter untouched.
        assert_eq!(
            mq.discard_dead_letters("siteA/orders", &DeadLetterFilter::default())
                .await
                .unwrap(),
            1
        );
        assert_eq!(mq.dead_letter_count("siteA/orders").await.unwrap(), 0);
        assert_eq!(
            mq.dead_letter_count("siteB/orders").await.unwrap(),
            1,
            "another site's DLQ is untouched"
        );
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
