# B10 — Async-lane sharding (Phase D, distinct keyspace)

Forked from `main` @ v0.4.27 (`5007a3b`). Branch `b10-async-lane-sharding`, worktree
`/Users/jwk/Projects/br-b10-async-shard`. Owner-approved *what* (Phase D of
`PLAN-messaging-event-driven-delivery.md` B10); the *how* below is the implementation design.

**SHIP GATING (do not skip):** B10 is architecturally significant + correctness-sensitive
(double-execution of side-effecting async functions). It ships ONLY after: a 3-role panel
(Backend/Senior Architect + UX + Security) all PASS → owner approval → Security-review loop to
convergence → a CI-hard live gate → its own reviewed release. This worktree is the BUILD phase;
do not merge or tag from here.

## Scope

Phase A/D shipped messaging topic sharding (B7/B8/B9). B10 shards the **three loops still on the
leader-gate**: the **async-lane function drain**, **crons**, and **blob watchers**. The async lane's
claim is a **per-invocation durable lease** (persisted in the `Invocation` KV record) — a *different
keyspace/mechanism* than the leader-serialized atomic `MqClaim`. That difference is the whole reason
B10 is a separate, separately-tested item.

## Current mechanisms (from the repo map)

- Async-lane drain: `crates/boatramp-server/src/scheduler.rs:821` (`invoke_enabled` gate) →
  `function_runtime.rs:1633` `drain_function_invocations`. Keyspace
  `project/{project}/functions/{name}/invocations/{id}` (`boatramp-types/src/function.rs:759`).
  Claim = read invocation, if `Queued` or lease-expired `Running` write `status=Running` +
  `lease_expires` + `attempts+=1` (`function_runtime.rs:1671`). **Plain read-then-write — safe only
  because leader-gated (single writer).**
- Leader gate: `CronLeaderGate = Arc<dyn Fn() -> bool>` (`lib.rs:518`), `cron_leader_gate`
  (`lib.rs:327`), set via `set_cron_leader_gate` (`lib.rs:896`). Guards crons (`scheduler.rs:764`),
  async drain (`scheduler.rs:828`), blob watchers (`scheduler.rs:362`).
- HRW helper (REUSE): `boatramp-cluster/src/messaging.rs` `hrw_score` (:97), `hrw_owner` (:381),
  `shard_owns(&str)->bool` (:1774), `shard_owned(Vec<String>)->Vec<String>` (:1789), over
  `AppliedState::applied_voters()` (`raft.rs:1131`, impl :1180 reads applied `last_membership`).
  Empty voters ⇒ own all (single-node). `hrw_owner`/`applied_voters` already key on an arbitrary
  `&str`, so the async lane can reuse them directly with a function-identity key.
- Stats to mirror: `DeliveryStats` (`boatramp-core/src/messaging.rs:930`, impl
  `messaging.rs:1747`) with `this_node`; B15 `owning_node` on per-consumer stat.

## Design

**Ownership key = function identity `{project}/{function}`.** All invocations of a function, its blob
watchers, and its crons drain on the one node that HRW-owns that key. (Rejected: per-invocation-id
sharding — scatters a function's queue, decouples blob/cron colocation.) Crons that are site-level
(not function-bound) shard on `{project}/{site}#cron:{id}`.

**Invariant 1 — no double-execution (THE central gate).** In a membership transition the old and new
owner may briefly both own function F (double-owner window). With the leader-gate gone the plain
read-then-write claim would let both transition the same invocation Queued→Running → double side
effect. So the claim MUST become a **conditional/CAS**: transition succeeds only if the observed
record is still `Queued` (or its lease is expired) under a generation/version guard, serialized as a
single leader apply (analogous to `apply_mq_claim` in `boatramp-cluster`). At most one node wins;
the loser re-scans. This CAS is the primary new mechanism and the first thing to build + test.

**Invariant 2 — no stranding (no-owner window, B7).** During a transition F may momentarily be owned
by no node. Backstop exactly like messaging: keep a **coarse unsharded safety-net drain pass** (any
node re-derives global work; the CAS makes redundant scans idempotent) as the backstop, with the
sharded fast-path as the common case. A lease-expired `Running` invocation is reclaimable by any node
via the CAS, so a crashed owner never strands work. The safety-net is the guarantee, the shard the
optimization — same split as B4/B7.

**Invariant 3 — lease-write still leader-bound (B9 residual).** Sharding distributes the drain
DECISION + scan + payload I/O + guest compute; the CAS claim write is still a leader apply. State this
in the release so "leader no longer the bottleneck" is not overread.

**Invariant 4 — blob-watcher single-fire.** Shard the watcher by function identity → only the owner
watches → exactly one enqueue per change. Rebuild watcher ownership on membership-change (mirror B11
rebuild-on-deploy-change) so the no-owner window is re-covered; a periodic re-scan of the blob prefix
(or content-hash-idempotent enqueue) catches a change missed during a transition.

**Invariant 5 — cron single-fire.** Only the owner fires; existing per-node `cron_state` dedup still
guards a within-minute double. A cron tick missed during a rare membership transition is bounded/
acceptable (crons are best-effort periodic) — state it, don't over-engineer.

**Wiring.** Add an async-lane shard gate in `boatramp-server` parallel to `cron_leader_gate`, e.g.
`async_shard_gate: Arc<dyn Fn(&str) -> bool + Send + Sync>` = "do I own this key". Default (single
node / empty voters / unset) ⇒ `true` (own all) so single-node behavior is byte-for-byte unchanged.
Populate it from the cluster's `shard_owns`. Replace the three `cron_leader_gate` checks with
`shard_gate(key)` where the key is the function/cron identity; the safety-net pass ignores the gate.

**Transparent upgrade (B18).** An old node with no async-shard support behaves as "owns all"
(leader-gated) — during version skew no function is unowned (old leader drains everything; a new
node's CAS makes its redundant drains safe). Assert the ACTUAL skew pair (old owns-all ⊕ new sharded).

**Observability (B14/B15 mirror).** Add `owning_node` per function-shard + a queued-count-per-shard +
a safety-net-only-drain counter to the operator/function stats. Answer "which node drains F" and "is
this a shard gap vs a drain bug" with no server logs.

**Config (B17 discipline).** Prefer NO new knobs; reuse the existing maintenance/safety-net cadence.
Add a knob only if the async safety-net cadence genuinely needs independent tuning.

## CI-hard gates (mirror the #478 battery; all required)

1. **Single-node unchanged** — empty voters ⇒ own all ⇒ current behavior byte-for-byte.
2. **CAS claim** — two nodes race the same `Queued` invocation → exactly one → `Running` (unit + cluster).
3. **Node-loss transition (THE gate)** — across a membership change: no double-execution AND no
   stranding, including the no-owner window.
4. **Lease-expiry reclaim** — a crashed owner's expired `Running` invocation reclaimed by the new
   owner exactly once.
5. **Blob-watcher single-fire under sharding** — one enqueue per change cluster-wide; a change during
   a transition is not lost.
6. **Cron single-fire under sharding** — owner-only; skew pair never double-fires.
7. **Transparent upgrade** — old owns-all ⊕ new sharded, no function unowned during the deploy window.

Grep a success marker per live gate in `ci.yml` (e.g. `ASYNC-SHARD NODE-LOSS OK`), same pattern as
`MESSAGING-STATS TENANT-SCOPED OK`.

## Definition of done for THIS worktree (build phase)

Implementation + all unit/integration tests green locally (`cargo test`, `cargo clippy --all-targets
--all-features`, `cargo fmt --all --check`, `typos`). A short design note capturing invariants 1–5 and
the B9 residual, ready for the 3-role panel. Do NOT bump the version, merge, or tag.
