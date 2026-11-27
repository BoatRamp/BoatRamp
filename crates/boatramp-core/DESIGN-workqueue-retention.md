# DESIGN — age-based work-queue retention (the third mq-robustness fix)

Status: **SCOPE ONLY — not implemented.** This note frames an **owner decision**; it deliberately
wires nothing. The two shipped fixes in this branch (`feat/mq-workqueue-reclaim`) are the operator
**recovery** primitive (`purge_work_queue` + endpoints) and the subscriber-aware **orphan signal**.
This third fix is **automatic** reclamation, which changes a durability contract, so it is the
owner's call.

## The problem it would solve

An ungrouped **work-queue** topic (a plain `wasi:messaging publish`, competing-consumer,
delete-on-ack) with **no consumer** accumulates `mq/{topic}/{id}` index records (+ their payloads)
**forever**: a record is deleted only on ack-after-claim, so a never-claimed record is immortal.
There is no age-based GC today, and the existing mechanisms do NOT cover it:

- `publish_with_ttl` dead-letters a message **at claim time** — a never-claimed message never hits
  that path (its TTL is evaluated in `plan_claim`, which never runs with no consumer).
- `retention_sweep` / `gc_grouped` are **grouped-only** (they reclaim the `mqglog`/`mqgp` fan-out
  log once every group has passed a message); they never touch the `mq/` work-queue keyspace.
- `purge_work_queue` (this branch) is a **manual** operator action, not automatic.

So absent an operator noticing the orphan-ready warn (fix #2) and running a purge (fix #1), the
backlog grows without bound.

## The decision: default-on vs opt-in

A **default** age-GC would silently change the competing-consumer durability contract. Today the
work-queue is **produce-now / consume-later with no deadline**: a producer may enqueue work hours
before any consumer exists, and every message is retained until claimed+acked. An unconditional
age-GC makes that **lossy** — a message older than the window is dropped even though it was never
delivered. That is a semantic change to at-least-once for the no-consumer / slow-consumer window,
and it can mask the very orphan the fix #2 signal is meant to surface.

Recommended shape (for the owner to accept/adjust):

1. **Opt-in, not default.** No age-GC unless an operator sets a retention window. The default stays
   "retain until acked" (unchanged contract). The orphan-ready signal (fix #2) + the manual purge
   (fix #1) remain the safety path for the default posture.
2. **Config as a policy, two tiers:**
   - a node/operator **default** window (e.g. `messaging.work_queue_retention_ms`, unset ⇒ infinite /
     disabled), and
   - a **per-topic override** on the existing `TopicPolicy` (a new
     `work_queue_retention_ms: Option<u64>` field, `None` ⇒ inherit the node default). `TopicPolicy`
     is already persisted (`mqpolicy/{topic}`), cached, and set via `queue policy` — so the override
     reuses a shipped surface with no new keyspace. **Caveat:** `TopicPolicy` is a published-crate
     public struct; adding a field is a breaking change unless it is `#[serde(default)]` +
     `#[non_exhaustive]`/builder — fold into a versioned cut (see the `non_exhaustive` memory).
3. **Age basis = the embedded publish time.** The id is `{millis}-{hex}` (`id_millis`), so "older
   than the window" is `id_millis(id) + retention_ms < now` — the SAME test `gc_grouped` already uses
   for the retained log. A dropped message should be **dead-lettered** (`retention-expired`), not hard
   deleted, so it stays inspectable/redrivable via the existing DLQ surface — strictly safer than a
   silent drop and consistent with `ttl-expired`. (If the owner wants a true hard-drop tier, make it a
   distinct explicit policy value, never the default.)

## Where the sweep hooks in

The scheduler's **orphan-detection block** (`crates/boatramp-server/src/scheduler.rs`, the
`maintenance && is_leader` arm that already iterates `messaging.indexed_topics()`), NOT the hot claim
path. That block already:

- is **leader-gated** (so a cluster sweeps once, not per-node),
- runs on the **maintenance cadence** (not per-message),
- enumerates every **indexed** topic and reads each topic's `TopicPolicy` is cheap/cached.

Critically, the sweep must run over **all indexed/orphaned-ready topics, not just grouped ones** —
that is the whole gap. It would, for each indexed topic with a retention window in force, reclaim
`mq/{topic}/{id}` records whose `id_millis + retention_ms < now` (dead-lettering them), mirroring
`gc_grouped`'s structure but over the work-queue keyspace. A new `Messaging` trait method
(`work_queue_retention_sweep(topic, retention_ms) -> count`) is the clean seam — single-node deletes
locally; the sweep is called from the same block that computes the orphan signal.

## The cluster replicated-delete requirement (hard constraint)

Exactly as `purge_work_queue` and `gc_grouped` in this branch: on a cluster the index IS the Raft
state machine, so the sweep **must** reclaim via an **explicit replicated delete proposal routed
through the leader** (`WriteOp::Batch` of `WriteOp::Delete`/`MqAck`-shaped ops + the
dead-letter re-home), **never** a raw local KV delete. And — per `retention_sweep`'s precedent — it
must propose **explicit deletes**, not "a sweep with a retention param the apply re-evaluates": a
per-proposal retention the apply reads would **diverge a mixed-version cluster** (an old replica
ignoring the field reclaims a different set). The leader computes the victim set from its applied
state and proposes version-independent explicit deletes that apply identically on every replica.

## Open questions for the owner

- Should the default posture ever enable a window, or stay infinite-retention forever (manual purge +
  orphan signal only)?
- Dead-letter the expired message (inspectable, redrivable, recommended) vs hard-drop (reclaims the
  DLQ space too, but truly lossy)? A per-policy choice?
- Interaction with `publish_with_ttl`: a per-message TTL is a producer deadline; a retention window is
  an operator backstop. Keep both, with TTL taking precedence when shorter.
