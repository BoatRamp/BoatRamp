//! Shared-mode coordination primitives (kv-sql workstream 4) — the machinery a **multi-writer**
//! backend (Postgres/MySQL) needs so N equal, stateless nodes over one shared SQL KV behave as one
//! control plane WITHOUT Raft. Two pieces, both built over the existing linearizable
//! [`compare_and_swap`](crate::kv::KvStore::compare_and_swap) primitive (MF-2), so they work
//! identically over [`MemoryKv`](crate::kv::MemoryKv) (tests) and a real multi-writer `SqlKv`:
//!
//! - [`LeaderLease`] (Architect C1) — a **non-Raft single-writer election**. In shared mode EVERY
//!   node would otherwise run the five leader-gated singletons (cert/ACME, compute reconcile,
//!   domain-verify, cron sweep, membership) because the single-node path hardwires `is_leader = ||
//!   true`. The lease makes exactly ONE node the leader at a time, with bounded failover on holder
//!   death, feeding the `is_leader` closure the node bootstrap passes to the server.
//! - [`ControlPlaneIdentity`] (UX-C1) — a **positive control-plane identity + liveness roster**
//!   stamped in the shared DB on open, so silent *commingle* (N nodes unexpectedly on the SAME db)
//!   and *split-brain* (N nodes each on a DIFFERENT db when they should share one) become a line read
//!   every boot instead of a mystery.
//!
//! ## Why a CAS-lease and not a Postgres session advisory lock
//! A `pg_advisory_lock` auto-releases when the holder's session dies (clean failover, no TTL), which
//! is attractive. But the control-plane SQL layer ([`SqlBackend`](crate::sql::SqlBackend)) draws a
//! FRESH pooled connection per transaction and returns it on commit/rollback — it exposes no
//! primitive to PIN one connection off-pool for the whole process lifetime, which is exactly what a
//! SESSION-level advisory lock requires (the lock releases the instant that connection returns to the
//! pool). Making it fit would mean adding an off-pool long-lived-connection seam to the sqlx layer
//! (plus a keepalive to defeat idle-in-transaction timeouts) AND a local flag + background task for
//! the *synchronous* `is_leader` closure anyway — strictly more new surface, and an unmanaged
//! off-pool connection is itself the "doesn't fit the pool model" the design calls out. The CAS-lease
//! needs none of that: it is pure `KvStore` ops, and its single-leader guarantee REDUCES to the same
//! linearizable-CAS invariant the campaign already mutation-gates
//! (`cas_race_has_exactly_one_winner`). MySQL's `GET_LOCK` is the analogous native primitive and has
//! the same pool-fit problem; it is left as a clearly-marked seam for the MySQL workstream (WS6).
//!
//! ## Single-leader + bounded-failover guarantee (the make-or-break)
//! The lease record is a single CAS'd value `{holder, epoch, renewed_at_ms}` at [`LEADER_KEY`]. A
//! node believes itself leader only while `now < leader_until` (a LOCAL fence set to `now + ttl` on
//! each successful acquire/renew) AND its last [`tick`](LeaderLease::tick) held the record. Then:
//! - **At most one leader.** A challenger takes the lease only by a CAS from the exact observed bytes;
//!   the CAS is linearizable (MF-2), so of two challengers racing an expired lease, exactly one wins
//!   and bumps `epoch`, changing the bytes. The displaced holder's next renew CAS (which expects the
//!   OLD bytes) then fails and it drops leadership immediately (`leader_until = 0`).
//! - **Bounded failover.** A challenger only takes over once `now - renewed_at_ms > ttl` by ITS
//!   clock; a live holder renews every `ttl/3`, so it is never seen expired. A dead/stalled holder's
//!   OWN `leader_until` fence expires at `ttl` from its last renew — before any challenger (which
//!   waits the full `ttl`) acts — so with `ttl` chosen generously vs the renew interval + tolerable
//!   clock skew, the two leadership intervals never overlap *in effect*. Failover completes within one
//!   challenger tick after `ttl`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::kv::{KvError, KvStore};
use crate::time::now_unix_ms;

/// Reserved key namespace for shared-mode coordination rows. Starts with `_` (like the changelog's
/// `_inval/`) so it never collides with a control-plane key, and the layout migrate check / the
/// changelog both already ignore the underscore namespace.
pub const CP_PREFIX: &str = "_cp/";

/// The control-plane identity row (a stable uuid stamped create-if-absent on first open).
pub const CP_ID_KEY: &str = "_cp/control_plane_id";

/// Prefix for the per-node liveness rows (`_cp/members/{node_id}` = last-seen millis).
pub const MEMBERS_PREFIX: &str = "_cp/members/";

/// The single leader-lease row.
pub const LEADER_KEY: &str = "_cp/leader";

/// Default leader-lease TTL: a holder that cannot renew within this window loses the lease, and a
/// challenger waits this long before taking over. Generous vs [`DEFAULT_RENEW_INTERVAL`] so ordinary
/// clock skew + a slow renew never trip a spurious failover.
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(15);

/// Default renew cadence (TTL/3): the holder refreshes `renewed_at_ms` three times per TTL, so a
/// single missed renew (transient DB blip) never costs leadership.
pub const DEFAULT_RENEW_INTERVAL: Duration = Duration::from_secs(5);

/// Default liveness window for [`ControlPlaneIdentity`] member counting: a member row touched within
/// this window counts as a live peer in the banner / `kv-status`.
pub const DEFAULT_MEMBER_WINDOW: Duration = Duration::from_secs(60);

/// Whether the C1 leader-lease mutation seam is armed — the lease then SKIPS its CAS and every node
/// unconditionally believes itself leader, so `shared_election_single_leader_under_concurrency` goes
/// RED (proving the lock is load-bearing). ALWAYS `false` in a shipped build: the env check compiles
/// in ONLY under `cfg(test)` (this crate's own gates) or the `shared-mode-gate-mutation` feature
/// (enabled by a downstream test lane — `boatramp-storage`'s live-Postgres gates — exactly like the
/// existing cross-crate `crownjewel-cas-gate-mutation` seam). Mirrors the MF-2 `drop_cas_predicate`
/// seam; shares the one `BOATRAMP_KVSQL_MUTATION` env var.
fn election_lock_disabled() -> bool {
    #[cfg(any(test, feature = "shared-mode-gate-mutation"))]
    {
        std::env::var("BOATRAMP_KVSQL_MUTATION").as_deref() == Ok("disable_leader_lock")
    }
    #[cfg(not(any(test, feature = "shared-mode-gate-mutation")))]
    {
        false
    }
}

/// Whether the UX-C1 control-plane-identity mutation seam is armed — [`ControlPlaneIdentity::join`]
/// then SKIPS stamping the cp-id, so two opens against the same DB no longer share a positive id and
/// `shared_control_plane_identity_detects_commingle_and_split_brain` goes RED (proving the stamp is
/// what makes commingle / split-brain detectable). Same gating as [`election_lock_disabled`].
fn cp_id_stamp_skipped() -> bool {
    #[cfg(any(test, feature = "shared-mode-gate-mutation"))]
    {
        std::env::var("BOATRAMP_KVSQL_MUTATION").as_deref() == Ok("skip_cp_id_stamp")
    }
    #[cfg(not(any(test, feature = "shared-mode-gate-mutation")))]
    {
        false
    }
}

/// The on-disk leader-lease record (one CAS'd JSON value at [`LEADER_KEY`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LeaseRecord {
    /// The node id that currently holds the lease.
    holder: String,
    /// Monotonically-increasing takeover epoch (bumped on every ownership CHANGE), so a stale
    /// holder's renew CAS from the old bytes fails and ownership is observable/orderable.
    epoch: u64,
    /// Wall-clock millis of the holder's last acquire/renew — a challenger compares it (by its own
    /// clock) against the TTL to decide whether the lease has expired.
    renewed_at_ms: u64,
}

/// A non-Raft single-writer election over a shared [`KvStore`] (Architect C1). Construct one per node
/// in shared mode; drive [`tick`](Self::tick) on the [`renew_interval`](Self::renew_interval) cadence
/// (the node bootstrap spawns that loop — `boatramp-core` stays spawn-free), and feed
/// [`gate`](Self::gate) to the server's `is_leader`. In single-writer mode the election is never
/// built and `is_leader` stays `|| true` (unchanged).
pub struct LeaderLease {
    store: Arc<dyn KvStore>,
    node_id: String,
    ttl_ms: u64,
    /// Local leadership fence, shared with every [`gate`](Self::gate) closure: this node is leader
    /// only while `now_unix_ms() < leader_until_ms`. `0` ⇒ not leader. Updated by [`tick`](Self::tick).
    leader_until_ms: Arc<AtomicU64>,
}

impl LeaderLease {
    /// Build a lease for `node_id` over `store`, with lease TTL `ttl`. Starts NOT leader (the first
    /// [`tick`](Self::tick) acquires). `ttl` is clamped to ≥ 1s so a misconfigured zero can't make
    /// every lease instantly expired.
    pub fn new(store: Arc<dyn KvStore>, node_id: impl Into<String>, ttl: Duration) -> Self {
        Self {
            store,
            node_id: node_id.into(),
            ttl_ms: (ttl.as_millis() as u64).max(1_000),
            leader_until_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// This node's election id.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The renew cadence the bootstrap's background loop should tick at (TTL/3, floored at 1s).
    pub fn renew_interval(&self) -> Duration {
        Duration::from_millis((self.ttl_ms / 3).max(1_000))
    }

    /// Whether this node is the leader RIGHT NOW (the local fence — cheap, lock-free).
    pub fn is_leader(&self) -> bool {
        now_unix_ms() < self.leader_until_ms.load(Ordering::Acquire)
    }

    /// An `is_leader` gate (the server's `CronLeaderGate` shape) reading this lease's fence. Cheap +
    /// lock-free, callable from the serving/reconcile hot paths.
    pub fn gate(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        let fence = self.leader_until_ms.clone();
        Arc::new(move || now_unix_ms() < fence.load(Ordering::Acquire))
    }

    /// One acquire-or-renew attempt. Returns whether this node is the leader AFTER the attempt. A
    /// transient error leaves the current fence untouched (so a blip doesn't drop a live leader before
    /// its own `leader_until` expires) and propagates for the caller to log.
    pub async fn tick(&self) -> Result<bool, KvError> {
        // MUTATION (disable_leader_lock): skip the CAS entirely — every node just declares itself
        // leader, so `shared_election_single_leader_under_concurrency` sees multiple winners → RED.
        if election_lock_disabled() {
            let now = now_unix_ms();
            self.leader_until_ms
                .store(now + self.ttl_ms, Ordering::Release);
            return Ok(true);
        }

        let now = now_unix_ms();
        let observed = self.store.get(LEADER_KEY).await?;
        let current: Option<LeaseRecord> = observed
            .as_deref()
            .and_then(|b| serde_json::from_slice(b).ok());

        let won = match current {
            // Absent / unparseable (a corrupt row is treated as absent so a bad write can't wedge the
            // election forever): create-if-absent. Exactly one creator wins the linearizable CAS.
            None => {
                let rec = LeaseRecord {
                    holder: self.node_id.clone(),
                    epoch: 1,
                    renewed_at_ms: now,
                };
                let expected = observed.as_deref();
                self.store
                    .compare_and_swap(LEADER_KEY, expected, encode(&rec))
                    .await?
            }
            // I already hold it → renew: CAS the observed bytes to a fresh `renewed_at_ms`, same
            // epoch. A failing renew means someone took over; drop leadership.
            Some(rec) if rec.holder == self.node_id => {
                let next = LeaseRecord {
                    holder: self.node_id.clone(),
                    epoch: rec.epoch,
                    renewed_at_ms: now,
                };
                self.store
                    .compare_and_swap(LEADER_KEY, observed.as_deref(), encode(&next))
                    .await?
            }
            // Held by someone else → take over ONLY if expired by my clock; bump the epoch so the old
            // holder's renew CAS (old bytes) fails. Of multiple challengers, the linearizable CAS
            // admits exactly one.
            Some(rec) => {
                let expired = now.saturating_sub(rec.renewed_at_ms) > self.ttl_ms;
                if expired {
                    let next = LeaseRecord {
                        holder: self.node_id.clone(),
                        epoch: rec.epoch + 1,
                        renewed_at_ms: now,
                    };
                    self.store
                        .compare_and_swap(LEADER_KEY, observed.as_deref(), encode(&next))
                        .await?
                } else {
                    false
                }
            }
        };

        if won {
            self.leader_until_ms
                .store(now + self.ttl_ms, Ordering::Release);
        } else {
            // Not (or no longer) the leader: drop the fence immediately so a displaced holder stops
            // acting at once, not at its old `leader_until`.
            self.leader_until_ms.store(0, Ordering::Release);
        }
        Ok(won)
    }

    /// Best-effort graceful resignation on shutdown: if this node currently holds the lease, CAS it
    /// to an already-expired record so a successor takes over at once instead of waiting a full TTL.
    /// Never errors out of shutdown (a lost race / DB blip just leaves the lease to expire normally).
    pub async fn resign(&self) {
        self.leader_until_ms.store(0, Ordering::Release);
        let Ok(observed) = self.store.get(LEADER_KEY).await else {
            return;
        };
        let Some(rec) = observed
            .as_deref()
            .and_then(|b| serde_json::from_slice::<LeaseRecord>(b).ok())
        else {
            return;
        };
        if rec.holder != self.node_id {
            return;
        }
        // Rewrite our own record as long-expired (keep the holder name for forensics, bump epoch),
        // so the next challenger's TTL check passes immediately.
        let vacated = LeaseRecord {
            holder: self.node_id.clone(),
            epoch: rec.epoch + 1,
            renewed_at_ms: now_unix_ms().saturating_sub(self.ttl_ms.saturating_mul(2)),
        };
        let _ = self
            .store
            .compare_and_swap(LEADER_KEY, observed.as_deref(), encode(&vacated))
            .await;
    }
}

/// What [`ControlPlaneIdentity::join`] learned on open — reported in the startup banner and
/// `kv-status` so commingle / split-brain is legible (UX-C1).
#[derive(Debug, Clone)]
pub struct ControlPlaneJoinReport {
    /// The shared control plane's stable id (a uuid). Empty ONLY under the `skip_cp_id_stamp`
    /// mutation (which the identity gate asserts makes commingle/split-brain undetectable → RED).
    pub control_plane_id: String,
    /// `true` when THIS node stamped the id — i.e. it opened a brand-new, empty database. If peers
    /// were expected, they are on a DIFFERENT database (split-brain).
    pub created_new: bool,
    /// This node's own member id.
    pub this_node: String,
    /// Distinct members (incl. self) whose liveness row was touched within the window — the peer
    /// count. `> 1` on a shared DB; `1` for a fresh/solo node (commingle shows as an UNEXPECTEDLY
    /// high count).
    pub members_seen: usize,
}

impl ControlPlaneJoinReport {
    /// The short display form of the control-plane id (`cp-<first 8 hex>`), for banners / status.
    pub fn short_id(&self) -> String {
        if self.control_plane_id.is_empty() {
            return "cp-<unstamped>".to_string();
        }
        let short: String = self
            .control_plane_id
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        format!("cp-{short}")
    }

    /// The boot banner line (UX-C1): a positive statement of which control plane this node joined and
    /// how many peers touched the SAME database — turning silent commingle / split-brain into a line
    /// read every boot.
    pub fn banner(&self) -> String {
        if self.created_new {
            format!(
                "control plane: created a NEW empty control plane {} in the shared SQL KV — this \
                 node is member 1 of {}. If you expected to JOIN peers, they are on a DIFFERENT \
                 database (check the connection URL / database name).",
                self.short_id(),
                self.members_seen.max(1),
            )
        } else {
            format!(
                "control plane: joined control plane {} — this node is 1 of {} members seen on this \
                 database recently. If you expected ISOLATION, other nodes are sharing this database \
                 (commingle).",
                self.short_id(),
                self.members_seen,
            )
        }
    }
}

/// Positive control-plane identity + liveness roster over a shared [`KvStore`] (UX-C1). On open a
/// node [`join`](Self::join)s: it stamps (create-if-absent) a stable cp-id, records its own liveness
/// row, and counts live members — so commingle and split-brain are observable. After join the node
/// keeps its liveness row fresh via [`heartbeat`](Self::heartbeat) on a cadence (bootstrap-spawned).
pub struct ControlPlaneIdentity {
    store: Arc<dyn KvStore>,
    node_id: String,
    window_ms: u64,
}

impl ControlPlaneIdentity {
    /// Build an identity helper for `node_id` over `store`, counting members touched within `window`.
    pub fn new(store: Arc<dyn KvStore>, node_id: impl Into<String>, window: Duration) -> Self {
        Self {
            store,
            node_id: node_id.into(),
            window_ms: (window.as_millis() as u64).max(1_000),
        }
    }

    /// This node's member id.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Stamp-or-read the cp-id, record this node's liveness, and count live members — the one call the
    /// bootstrap makes on open to produce the [`ControlPlaneJoinReport`].
    pub async fn join(&self) -> Result<ControlPlaneJoinReport, KvError> {
        let (control_plane_id, created_new) = self.stamp_or_read_id().await?;
        self.heartbeat().await?;
        let members_seen = self.count_live_members().await?;
        Ok(ControlPlaneJoinReport {
            control_plane_id,
            created_new,
            this_node: self.node_id.clone(),
            members_seen,
        })
    }

    /// Record (or refresh) this node's `_cp/members/{node_id}` liveness row with the current millis.
    /// Called on open and then on a cadence so a crashed node's row ages out of the window.
    pub async fn heartbeat(&self) -> Result<(), KvError> {
        let key = format!("{MEMBERS_PREFIX}{}", self.node_id);
        self.store
            .put(&key, now_unix_ms().to_string().into_bytes())
            .await
    }

    /// Create-if-absent the cp-id, returning `(id, created_new)`. A CAS race to create resolves to
    /// exactly one creator (linearizable CAS); every other node reads the winner's id.
    async fn stamp_or_read_id(&self) -> Result<(String, bool), KvError> {
        loop {
            if let Some(bytes) = self.store.get(CP_ID_KEY).await? {
                return Ok((String::from_utf8_lossy(&bytes).into_owned(), false));
            }
            // MUTATION (skip_cp_id_stamp): don't stamp. Two nodes on the SAME db then both see no id
            // (returns empty, created_new=false), so the identity gate's "same db ⇒ same non-empty
            // id" and "different dbs ⇒ different ids" assertions both fail → RED.
            if cp_id_stamp_skipped() {
                return Ok((String::new(), false));
            }
            let id = new_cp_id();
            if self
                .store
                .compare_and_swap(CP_ID_KEY, None, id.clone().into_bytes())
                .await?
            {
                return Ok((id, true));
            }
            // Lost the create race — loop and read the winner's id.
        }
    }

    /// Count distinct members whose liveness row is within the window (incl. self, since join
    /// heartbeats first). A stale/crashed node's row ages out, so this is the LIVE peer count.
    async fn count_live_members(&self) -> Result<usize, KvError> {
        let cutoff = now_unix_ms().saturating_sub(self.window_ms);
        let keys = self.store.list_prefix(MEMBERS_PREFIX).await?;
        let mut live = 0usize;
        for key in keys {
            if let Some(bytes) = self.store.get(&key).await?
                && let Ok(text) = std::str::from_utf8(&bytes)
                && let Ok(ms) = text.trim().parse::<u64>()
                && ms >= cutoff
            {
                live += 1;
            }
        }
        Ok(live)
    }
}

/// Serialize a lease record to bytes (infallible for this plain struct).
fn encode(rec: &LeaseRecord) -> Vec<u8> {
    serde_json::to_vec(rec).unwrap_or_default()
}

/// A random, stable control-plane id (128 random bits, hex) — the positive identity a node stamps
/// into a fresh shared DB.
fn new_cp_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("system RNG");
    hex::encode(bytes)
}

/// Test-support (never shipped): write an already-EXPIRED lease record held by `holder` into
/// `store`, so a downstream gate (e.g. `boatramp-storage`'s live-Postgres election gate) can prove
/// bounded failover — a survivor's next [`tick`](LeaderLease::tick) takes over — WITHOUT sleeping a
/// full TTL. Compiled only in a test build or under the `kv-conformance` feature (the same gate the
/// shared conformance suite uses), so it can never reach a shipped binary. `#[doc(hidden)]`.
#[cfg(any(test, feature = "kv-conformance"))]
#[doc(hidden)]
pub async fn seed_expired_lease(store: &Arc<dyn KvStore>, holder: &str) -> Result<(), KvError> {
    let rec = LeaseRecord {
        holder: holder.to_string(),
        epoch: 99,
        renewed_at_ms: now_unix_ms().saturating_sub(24 * 60 * 60 * 1000),
    };
    store.put(LEADER_KEY, encode(&rec)).await
}

/// A random per-process node id (64 random bits, hex) for shared-mode membership/election — mirrors
/// the changelog's writer id. Prefer passing a stable operator-set id where one exists; absent that,
/// a per-process id is honest (each running process is a distinct member).
pub fn random_node_id() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("system RNG");
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryKv;

    fn shared_store() -> Arc<dyn KvStore> {
        Arc::new(MemoryKv::new())
    }

    /// GATE (C1, over MemoryKv's linearizable CAS) — N nodes contend for one lease and EXACTLY ONE is
    /// leader at a time; when the holder dies, another acquires within the TTL bound.
    #[tokio::test]
    #[serial_test::serial(shared_mode_env)]
    async fn shared_election_single_leader_under_concurrency() {
        let store = shared_store();
        let ttl = Duration::from_secs(10);

        // All eight tick once, concurrently — exactly one acquires the empty lease.
        let mut set = tokio::task::JoinSet::new();
        for i in 0..8 {
            let store = store.clone();
            let id = format!("node-{i}");
            set.spawn(async move {
                let l = LeaderLease::new(store, id, ttl);
                l.tick().await.unwrap()
            });
        }
        let mut wins = 0;
        while let Some(r) = set.join_next().await {
            if r.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one node acquires the empty lease");

        // Re-run deterministically on ONE set of leases so we can inspect `is_leader()`: tick each,
        // then assert exactly one believes it is leader.
        let store = shared_store();
        let leases: Vec<LeaderLease> = (0..8)
            .map(|i| LeaderLease::new(store.clone(), format!("n-{i}"), ttl))
            .collect();
        for l in &leases {
            l.tick().await.unwrap();
        }
        let leaders: Vec<&str> = leases
            .iter()
            .filter(|l| l.is_leader())
            .map(|l| l.node_id())
            .collect();
        assert_eq!(
            leaders.len(),
            1,
            "exactly one leader after a round of ticks"
        );
        let holder = leaders[0].to_string();

        // A non-leader cannot take over while the lease is fresh (another tick changes nothing).
        for l in &leases {
            l.tick().await.unwrap();
        }
        assert_eq!(
            leases.iter().filter(|l| l.is_leader()).count(),
            1,
            "still exactly one leader while the lease is fresh"
        );
        assert!(
            leases
                .iter()
                .find(|l| l.node_id() == holder)
                .unwrap()
                .is_leader(),
            "the original holder keeps the lease by renewing"
        );

        // Holder DIES: simulate by writing an EXPIRED lease record for it directly (no sleeping), then
        // a surviving node takes over on its next tick — bounded failover.
        let dead = LeaseRecord {
            holder: holder.clone(),
            epoch: 9,
            renewed_at_ms: now_unix_ms().saturating_sub(ttl.as_millis() as u64 * 2),
        };
        store.put(LEADER_KEY, encode(&dead)).await.unwrap();
        let survivor = leases.iter().find(|l| l.node_id() != holder).unwrap();
        assert!(
            survivor.tick().await.unwrap(),
            "a survivor takes over an expired lease"
        );
        assert!(survivor.is_leader(), "the survivor is now the leader");
    }

    /// The `disable_leader_lock` MUTATION must make the single-leader gate RED: every node's `tick`
    /// returns leader, so more than one is leader at once.
    #[tokio::test]
    #[serial_test::serial(shared_mode_env)]
    async fn mutation_disables_leader_lock_makes_multiple_leaders() {
        // SAFETY: single-threaded within this #[serial] test; cleared before returning.
        unsafe { std::env::set_var("BOATRAMP_KVSQL_MUTATION", "disable_leader_lock") };
        let store = shared_store();
        let a = LeaderLease::new(store.clone(), "a", Duration::from_secs(10));
        let b = LeaderLease::new(store.clone(), "b", Duration::from_secs(10));
        assert!(a.tick().await.unwrap());
        assert!(b.tick().await.unwrap());
        assert!(
            a.is_leader() && b.is_leader(),
            "mutation: BOTH nodes think they are leader (gate would be RED)"
        );
        unsafe { std::env::remove_var("BOATRAMP_KVSQL_MUTATION") };
    }

    /// GATE (UX-C1) — two opens against the SAME store share one cp-id and see both members;
    /// two opens against DIFFERENT stores get DIFFERENT cp-ids (split-brain is detectable).
    #[tokio::test]
    #[serial_test::serial(shared_mode_env)]
    async fn shared_control_plane_identity_detects_commingle_and_split_brain() {
        // Commingle: both nodes on ONE db.
        let shared = shared_store();
        let a = ControlPlaneIdentity::new(shared.clone(), "node-a", DEFAULT_MEMBER_WINDOW);
        let b = ControlPlaneIdentity::new(shared.clone(), "node-b", DEFAULT_MEMBER_WINDOW);
        let ra = a.join().await.unwrap();
        let rb = b.join().await.unwrap();
        assert!(
            !ra.control_plane_id.is_empty(),
            "the first open stamps a cp-id"
        );
        assert!(ra.created_new, "the first open created the control plane");
        assert!(
            !rb.created_new,
            "the second open JOINED the existing control plane"
        );
        assert_eq!(
            ra.control_plane_id, rb.control_plane_id,
            "both nodes on the same db share the SAME cp-id"
        );
        assert_eq!(rb.members_seen, 2, "both members are seen on the shared db");

        // Split-brain: two SEPARATE dbs each get their own cp-id.
        let db1 = shared_store();
        let db2 = shared_store();
        let n1 = ControlPlaneIdentity::new(db1, "solo", DEFAULT_MEMBER_WINDOW)
            .join()
            .await
            .unwrap();
        let n2 = ControlPlaneIdentity::new(db2, "solo", DEFAULT_MEMBER_WINDOW)
            .join()
            .await
            .unwrap();
        assert_ne!(
            n1.control_plane_id, n2.control_plane_id,
            "nodes on DIFFERENT dbs have DIFFERENT cp-ids (split-brain detectable)"
        );
        assert_eq!(n1.members_seen, 1, "each solo db sees only its own member");
    }

    /// The `skip_cp_id_stamp` MUTATION must make the identity gate RED: with no stamp, two opens on
    /// the same db cannot confirm they share a control plane (empty id), and two dbs are
    /// indistinguishable (both empty).
    #[tokio::test]
    #[serial_test::serial(shared_mode_env)]
    async fn mutation_skips_cp_id_stamp_hides_commingle_and_split_brain() {
        unsafe { std::env::set_var("BOATRAMP_KVSQL_MUTATION", "skip_cp_id_stamp") };
        let shared = shared_store();
        let a = ControlPlaneIdentity::new(shared.clone(), "a", DEFAULT_MEMBER_WINDOW)
            .join()
            .await
            .unwrap();
        assert!(
            a.control_plane_id.is_empty(),
            "mutation: no cp-id is stamped (the shared-id assertion would be RED)"
        );
        let db2 = shared_store();
        let b = ControlPlaneIdentity::new(db2, "a", DEFAULT_MEMBER_WINDOW)
            .join()
            .await
            .unwrap();
        assert_eq!(
            a.control_plane_id, b.control_plane_id,
            "mutation: two different dbs both yield an EMPTY id — split-brain undetectable (RED)"
        );
        unsafe { std::env::remove_var("BOATRAMP_KVSQL_MUTATION") };
    }

    /// A fresh single node reports itself as the sole member and the banner names a NEW control plane.
    #[tokio::test]
    #[serial_test::serial(shared_mode_env)]
    async fn solo_node_banner_names_a_new_control_plane() {
        let store = shared_store();
        let report = ControlPlaneIdentity::new(store, "solo", DEFAULT_MEMBER_WINDOW)
            .join()
            .await
            .unwrap();
        assert!(report.created_new);
        assert_eq!(report.members_seen, 1);
        assert!(report.short_id().starts_with("cp-"));
        assert!(report.banner().contains("NEW empty control plane"));
    }

    /// A displaced holder drops leadership on its next renew (its CAS from the old bytes fails once a
    /// challenger has rewritten the record).
    #[tokio::test]
    #[serial_test::serial(shared_mode_env)]
    async fn displaced_holder_drops_leadership_on_renew() {
        let store = shared_store();
        let ttl = Duration::from_secs(10);
        let a = LeaderLease::new(store.clone(), "a", ttl);
        assert!(a.tick().await.unwrap(), "a acquires");
        assert!(a.is_leader());

        // Simulate a takeover by another node rewriting the record (as if `a`'s lease had expired).
        let taken = LeaseRecord {
            holder: "b".to_string(),
            epoch: 5,
            renewed_at_ms: now_unix_ms(),
        };
        store.put(LEADER_KEY, encode(&taken)).await.unwrap();

        assert!(
            !a.tick().await.unwrap(),
            "a's renew CAS fails (record moved on) → not leader"
        );
        assert!(!a.is_leader(), "a immediately drops its leadership fence");
    }
}
