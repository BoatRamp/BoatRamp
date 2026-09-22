# B10 — Async-lane sharding: design note (build phase)

This note captures the implemented design for the 3-role review panel: the invariants, the
CAS-claim mechanism, the wiring, and the honest residuals. It is the companion to `B10-DEV-BRIEF.md`
(the authoritative *what*); this is the *how it was built*.

## One-paragraph summary

Phase D shipped messaging **topic** sharding (HRW over applied Raft membership). B10 shards the three
loops still pinned to the leader-gate — the **async-lane function drain**, **crons**, and **blob
watchers** — by reusing the *same* applied-membership HRW helper (`Messaging::shard_owns`) keyed on a
**function identity** (`{project}/{function}`, or `{project}/{site}#cron:{idx}` for a site-level cron).
Because the async lane's claim is a per-invocation durable lease (a different keyspace/mechanism than
messaging's leader-serialized `MqClaim`), removing the single-writer leader-gate means two nodes can
briefly both drain a function. The load-bearing new mechanism is therefore a **compare-and-set (CAS)
claim**: the `Queued → Running` (or expired-lease reclaim) transition is a conditional write that
succeeds for **at most one node**. The sharded fast-path is the common case; an **unsharded
safety-net drain** is the backstop for the no-owner window. A backend without a linearizable CAS
stays leader-gated (owns-all) — the fail-closed default.

## The five invariants (as implemented)

### Invariant 1 — no double-execution (the central gate)

In a membership transition the old and new owner may briefly both own function F (the *double-owner
window*). With the leader-gate gone, the old plain read-then-write claim would let both transition the
same invocation `Queued → Running` and run it twice — a double side effect. So the claim is now a
**CAS on the exact observed record bytes**:

- `function_runtime.rs::drain_function_invocations` reads an invocation, decides it is claimable
  (`Queued`, or `Running` with an elapsed lease), computes the claimed record (`Running` + fresh lease
  + `attempts+1`), and calls `DeployStore::claim_invocation(observed, claimed)`.
- `claim_invocation` serializes `observed` to bytes and does `KvStore::compare_and_swap(key,
  Some(observed_bytes), claimed_bytes)`. The swap fires only if the stored value **still equals** what
  this node read. A racing node observed the same `Queued` record, computes its own claim, and its CAS
  fails because the winner already changed the bytes — it re-scans, never re-runs.
- **Cluster CAS** is a new `WriteOp::CompareAndSwap` applied as **one leader-serialized Raft apply**
  (`raft.rs::apply_op`), returning `WriteResponse::Cas(bool)` — linearizable cluster-wide, analogous to
  `apply_mq_claim`. **Single-node CAS** is atomic under `MemoryKv`'s mutex / `SlateKv`'s in-process
  `cas_lock` (SlateDB is single-writer, so the only racers are tasks in the one writer process).

Proven by: `gate2_cas_claim_has_exactly_one_winner` (16 racers → 1 win), the cluster
`raftkv_compare_and_swap_has_exactly_one_winner` + `compare_and_swap_swaps_at_most_once_per_observed_value`
apply-determinism test, and the double-owner half of `gate3` (two runtimes over one KV both drain →
exactly one execution, `hits == 1`).

### Invariant 2 — no stranding (the no-owner window, B7)

During a transition F may momentarily be owned by **no** node (the HRW winner just departed; the new
assignment hasn't been derived yet). Backstop, exactly like messaging:

- A **coarse unsharded safety-net drain pass** runs on a periodic cadence (`AsyncPass::UnshardedSafetyNet`
  in `scheduler.rs`): every node re-derives *every* function's queue regardless of ownership and drains
  it. The CAS from Invariant 1 makes these redundant scans idempotent — a safety-net node and an owner
  can both scan; only one CAS wins.
- A **lease-expired `Running`** invocation is reclaimable by any node via the *same* CAS (the claimable
  predicate admits `Running` with an elapsed lease), so a crashed/departed owner never strands work.
- The safety-net is the **guarantee**; the shard is the **optimization** — the same split as B4/B7.

Proven by: the no-owner half of `gate3` (the sharded fast path correctly drains nothing when no node
owns F; the unsharded safety-net then drains it — `hits` advances, nothing stranded) and
`gate4_lease_expiry_reclaimed_exactly_once`.

### Invariant 3 — the lease-WRITE is still leader-bound (B9 residual)

Sharding distributes the drain **DECISION** + the queue **scan** + payload I/O + guest **compute**. But
the CAS claim write is still a **single leader apply** on a cluster (`WriteOp::CompareAndSwap` forwards
to the leader like every other write). So "the leader is no longer the async funnel" means it no longer
does O(all functions) of scan/compute work — it still funnels the atomic claim **writes**. State this in
the release so no one over-reads "leader stops being a bottleneck." (Identical to the messaging B9
residual: the topic decision is sharded; the `MqClaim` apply is leader-bound.)

### Invariant 4 — blob-watcher single-fire

- A function's blob watchers run on the **one node that owns its identity** (`reconcile_blob_watchers`
  now folds ownership into the `desired` set). Exactly one node watches ⇒ exactly one enqueue per change.
- **Rebuild-on-membership-change comes for free**: a function this node no longer owns is left OUT of
  `desired`, so the existing `retain` step aborts its watcher on the next reconcile — re-covering the
  no-owner window (mirroring B11's rebuild-on-deploy-change).
- **A change missed/duplicated during a transition is caught idempotently**: the blob-change invocation
  id is now a **content hash** of `(project, function, version, key, kind)` (`blob_change_invocation_id`),
  so two watchers that both observe the same change in the double-owner window enqueue the **identical**
  record key — the second write overwrites an identical `Queued` record instead of creating a duplicate.
- The unsharded safety-net pass never (re)spawns watchers (a non-owner watching would double-enqueue).

Proven by: `gate5_blob_change_enqueue_is_idempotent` (two concurrent enqueues of the same change → one
invocation record).

### Invariant 5 — cron single-fire

- Only the **owner** fires a cron (`AsyncPass::Sharded`, gated on `{project}/{site}#cron:{idx}` for a
  site cron / the function identity for a function-bound cron). The existing per-node `cron_state` /
  `last_fired_minute` within-minute dedup still guards a within-minute double on the owner.
- Crons **never** fire on the unsharded safety-net pass — a cron has no cross-node dedup for *firing*
  (only the per-node within-minute guard), so a non-owner firing would double-fire.
- A cron tick missed during a rare membership transition is **bounded and acceptable** (crons are
  best-effort periodic) — the design does not add a cross-node cron-fire ledger to close this, by
  explicit choice (B17 config/complexity discipline).

Proven by: `gate6_cron_fires_owner_only_never_double` (non-owner + safety-net fire nothing; the owner
fires exactly once) and `gate7_transparent_upgrade_skew_no_double_no_unowned`.

## The CAS-claim design in detail

**Where:** `crates/boatramp-server/src/function_runtime.rs::drain_function_invocations` (the claim site,
formerly a blind `put_invocation`, now `deploy.claim_invocation(project, &observed, &claimed)`).

**The primitive (`crates/boatramp-core/src/kv.rs`):**
- `KvStore::supports_cas() -> bool` (default `false`) — advertises a **linearizable** CAS.
- `KvStore::compare_and_swap(key, expected: Option<&[u8]>, new) -> Result<bool>` — write `new` iff the
  current value equals `expected` (`None` = expect-absent); returns whether the swap happened. The
  default is a best-effort read-then-write (safe only under a single logical writer); atomic backends
  override it.
- Backends: `MemoryKv` (atomic under its mutex), `CachedKv` (forwards CAS to the inner store — the
  compare must run against the authoritative value, never the LRU), `SlateKv` (in-process `cas_lock`;
  single-writer ⇒ linearizable within the writer), `RaftKv` (`WriteOp::CompareAndSwap`, one leader
  apply). `CloudflareKv` keeps the default `false` (no transactional CAS) → stays leader-gated.

**The domain wrapper (`crates/boatramp-core/src/deploy.rs`):**
- `DeployStore::claim_invocation(project, observed, claimed)` — serializes `observed` as the CAS
  `expected` and `claimed` as the new value; whole-record compare (any concurrent mutation — a claim, a
  settle, a redeploy — changes the bytes, so the CAS fails closed).
- `DeployStore::supports_invocation_cas()` — gates whether the async lane may shard at all.

**Why whole-record compare (not a generation counter):** `Invocation` is `#[serde(deny_unknown_fields)]`
and append-only-ABI-sensitive; adding a generation field is a schema change with rolling-upgrade
implications. A whole-record CAS is strictly correct (stronger than a generation guard — it also
catches a settle/redeploy that a generation counter might not) and needs no schema change. The cost is
that a benign concurrent metadata touch on the same record would also fail the CAS — but the only writer
of an invocation record between scan and claim is *another claimer*, which is exactly what we want to
lose the race.

## Wiring (Step 2)

- `HandlerRuntimeInner::async_shard_owns(deploy, key) -> bool` resolves ownership: a test/wiring
  override (`set_async_shard_gate`) if set, else `messaging.shard_owns(key)` (the **same** applied-
  membership HRW the topic drainer uses) — but **only** when `supports_invocation_cas()` (else own-all,
  so a non-CAS backend never shards with a racy claim). No messaging ⇒ own-all.
- `scheduler.rs::AsyncPass { Legacy, Sharded, UnshardedSafetyNet }` selects how a maintenance pass
  treats the async lane / crons / watchers (orthogonal to `ConsumerFilter`, which selects delivery
  topics). The three former `cron_leader_gate` checks (`scheduler.rs` crons, async drain, and
  `reconcile_blob_watchers`) are replaced by identity-keyed `async_shard_owns` calls; the safety-net
  pass ignores the gate for the drain and skips crons/watchers.
- The **cluster path needs zero extra wiring**: the `RaftMessaging` trait object already flows into
  `HandlerRuntimeInner::messaging` (via `NodeInput.messaging`), so `async_shard_owns` automatically
  consults `RaftMessaging::shard_owns` and `RaftKv::supports_cas() == true`.

## Config discipline (B17)

**No new knobs.** The unsharded async safety-net reuses the existing delivery `safetynet_interval`
(`DeliveryConfig`). Sharding is a pure topology decision (CAS-capable KV + a messaging substrate) — no
operator toggle.

## Observability (B14/B15 mirror)

`AsyncShardStats` on the operator stats endpoint (`operator.rs`): per-owned-function `owning_node` +
queued-count-per-shard, plus a `safetynet_only_drains` counter (bumped when a claim wins on the safety
net rather than the owner's fast path — the shard-gap early-warning, mirroring the delivery
`this_node` + safety-net-only signal). Answers "which node drains F" and "is this a shard gap vs a
drain bug" with no server logs.

## Transparent upgrade (B18)

An old node with no async-shard support behaves as **owns-all** (leader-gated, `AsyncPass::Legacy`); a
new node is `Sharded`. During the skew no function is unowned — the old node drains everything, and the
new node's CAS makes its redundant owned drains safe. Asserted by `gate7`.

## Scope boundaries and honest residuals (please scrutinize)

1. **Workflow runs are NOT sharded** (kept strictly leader-gated). A `WorkflowRun` record has no
   CAS-safe claim (it is a read-modify-write of the run's step map, not a `Queued → Running` lease), so
   sharding it would reopen a double-advance hazard. B10's scope is the async-lane function drain,
   crons, and blob watchers; workflows stay on the leader. **This is a deliberate residual** — a future
   item would give workflow-run advancement its own CAS.

2. **The unit/integration battery uses an injectable shard gate + the atomic `MemoryKv` CAS** to prove
   the ownership + race behaviors deterministically without spinning a live multi-node Raft cluster.
   The RaftKv CAS itself has its own live-Raft race test in `boatramp-cluster`. A **true end-to-end
   multi-node cluster gate** (kill a node, watch its functions reassign and keep draining exactly once)
   is the natural next gate to add on top of the existing cluster failover tests — flagged for the
   panel as the one coverage gap between "mechanism proven" and "proven in a live fleet."

3. **The best-effort default CAS** (a non-atomic `compare_and_swap` for backends that don't override it)
   is only correct under a single logical writer. This is safe because `supports_cas()` gates sharding:
   a backend on the best-effort default returns `false` and the async lane stays leader-gated
   (single-writer). Worth a reviewer's eye that no code path shards on a best-effort-CAS backend.

4. **Whole-record CAS granularity** (see above) — confirm the reviewer is comfortable that no benign
   concurrent writer touches an invocation record between a drain's scan and its claim (today only
   another claimer does).

5. **Cron missed-tick during a transition** is accepted as bounded (Invariant 5), not closed with a
   cross-node fire ledger. Confirm this is acceptable for the cron contract (it matches the pre-B10
   leader-change behavior, where a cron tick during a leadership flap could also be missed).

## What was verified (build phase)

- `cargo build --all-features` — clean.
- `cargo test` for the touched crates (`boatramp-core`, `boatramp-cluster --features http`,
  `boatramp-storage`, `boatramp-server --features handlers`) — green, including the 7-gate B10 battery
  and the CAS conformance/race tests, and the 304 pre-existing server tests (single-node unchanged).
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo fmt --all --check` + `typos crates/` — clean.
- CI marker `ASYNC-SHARD NODE-LOSS OK` wired into `.github/workflows/ci.yml` as a grep-checked gate.
