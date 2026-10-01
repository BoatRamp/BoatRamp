//! Crown-jewel CAS conversion (MF-1) — the shared test seam + mutation-verified gate helpers.
//!
//! The crown-jewel control-plane writes (sealed-secret set/delete, per-tenant secret set + the
//! name-count cap, and the RBAC policy edit) are converted from blind read-modify-write to a
//! VALUE-based [`compare_and_swap`](crate::kv::KvStore::compare_and_swap) over the cross-node
//! linearizable primitive (MF-2). Under the new multi-writer (N-node Postgres) topology a blind
//! RMW loses rotations / resurrects deleted secrets / loses revokes / bypasses the cap when two
//! nodes race; the CAS makes "exactly one winner, no lost update" hold cross-node.
//!
//! [`cas_mutation_active`] is the load-bearing test seam: when armed (NEVER in a shipped build) it
//! reverts each converted write to the old blind path, so every MF-1 gate goes RED — proving the
//! CAS/If-Match is load-bearing, not decoration. It mirrors the MF-2 `drop_cas_predicate` seam.

/// Whether the MF-1 crown-jewel CAS mutation is armed — the converted writes then revert to the
/// pre-MF-1 blind read-modify-write (secret set/delete), the list-then-write cap TOCTOU
/// (tenant secret), and the whole-doc blind put with no version guard (policy). ALWAYS `false` in a
/// shipped build: the env check compiles in ONLY under `cfg(test)` (this crate's own test build, so
/// the `boatramp-core` gates can arm it) or the `crownjewel-cas-gate-mutation` feature (enabled by a
/// downstream test lane — e.g. `boatramp-storage`'s live-Postgres gates — exactly like the existing
/// cross-crate `blob-drain-gate-mutation` seam). Prod pins the safe CAS path.
pub(crate) fn cas_mutation_active() -> bool {
    #[cfg(any(test, feature = "crownjewel-cas-gate-mutation"))]
    {
        std::env::var("BOATRAMP_KVSQL_MUTATION").as_deref() == Ok("drop_crownjewel_cas")
    }
    #[cfg(not(any(test, feature = "crownjewel-cas-gate-mutation")))]
    {
        false
    }
}

/// Shared, backend-agnostic helpers for the MF-1 crown-jewel concurrency gates, so `boatramp-core`
/// (over [`MemoryKv`](crate::kv::MemoryKv)) and `boatramp-storage` (over a real Postgres `SqlKv`)
/// run the IDENTICAL load-bearing assertions against their backend (the anti-drift property, B7).
/// Only the concurrency driver (spawning racers) lives per-crate — `boatramp-core` has `tokio` just
/// as a dev-dependency, so a shared helper here must not spawn; it carries the pure setup + the
/// invariants. Compiled only in a test build or under the downstream `kv-conformance` feature;
/// never shipped. `#[doc(hidden)]`: a test-support surface, not public API.
#[cfg(any(test, feature = "kv-conformance"))]
#[doc(hidden)]
pub mod gate {
    use crate::authz::AuthzPolicy;
    use crate::envelope::{EnvelopeError, KeyEnvelope};
    use crate::project::ProjectRef;

    /// A reversible test envelope (XOR with a constant): a "sealed" blob is visibly different from
    /// the plaintext yet round-trips — so the gates seal through the real `SecretStore` path.
    pub struct GateEnvelope;

    #[async_trait::async_trait]
    impl KeyEnvelope for GateEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(wrapped.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    /// The project the secret gates key under.
    #[must_use]
    pub fn gate_project() -> ProjectRef<'static> {
        ProjectRef::new("crownjewel-gate")
    }

    /// Two DISTINCT policies derived from the built-in default, used to drive the concurrent
    /// policy-edit gate — each adds an empty role under a unique name, so the serialized bytes (and
    /// hence the version/ETag) differ.
    #[must_use]
    pub fn distinct_policy(tag: &str) -> AuthzPolicy {
        let mut p = AuthzPolicy::default_policy();
        p.roles.insert(format!("crownjewel-edit-{tag}"), Vec::new());
        p
    }

    /// THE load-bearing no-lost-update invariant (gate 1), factored so every backend asserts it
    /// identically. `base_rev` is the seed revision before the race; `successful_revs` the revision
    /// each winning `set` returned; `final_rev` the revision actually stored afterwards.
    ///
    /// Under a VALUE-CAS, concurrent rotations of one key serialize: each winner's precondition is
    /// the exact prior bytes, so two winners can never share a revision — the winners' revisions are
    /// UNIQUE, CONTIGUOUS and MONOTONIC from `base_rev+1`, and the stored record is the highest
    /// winner. Under the blind-put mutation two racers read the same prior and both write
    /// `base_rev+1` → a duplicate revision and a silently-clobbered rotation → this panics (RED).
    pub fn assert_no_lost_update(base_rev: u32, mut successful_revs: Vec<u32>, final_rev: u32) {
        assert!(
            !successful_revs.is_empty(),
            "at least one concurrent rotation must win"
        );
        successful_revs.sort_unstable();
        let k = successful_revs.len() as u32;
        let expected: Vec<u32> = (base_rev + 1..=base_rev + k).collect();
        assert_eq!(
            successful_revs, expected,
            "concurrent rotations must have UNIQUE, contiguous, monotonic revisions (no lost \
             update / no duplicate revision)"
        );
        assert_eq!(
            final_rev,
            base_rev + k,
            "the stored record must be the highest winning revision (no lost update)"
        );
    }
}

#[cfg(test)]
mod tests {
    //! The MF-1 crown-jewel gates over the in-process [`MemoryKv`](crate::kv::MemoryKv) — a
    //! linearizable CAS backend, so the gates run with no external dependency as part of
    //! `cargo test -p boatramp-core`. The live-Postgres twins (the cross-node property the panel
    //! gated on) run the IDENTICAL gates against a real multi-writer `SqlKv` in `boatramp-storage`.
    //! Each gate is mutation-verified: with `BOATRAMP_KVSQL_MUTATION=drop_crownjewel_cas` the
    //! converted write reverts to the blind path and the gate goes RED (proving it load-bearing).
    //! Multi-thread runtime + real `tokio::spawn` so the racers genuinely contend (the mutation is
    //! only observable under true concurrency — a serial run has no lost update even when blind).

    use super::gate::*;
    use crate::deploy::{policy_read_versioned, policy_set_if_match};
    use crate::error::DeployError;
    use crate::kv::{KvStore, MemoryKv};
    use crate::secret_store::{
        MAX_TENANT_SECRET_NAMES, SecretError, SecretStore, TenantSecretStore,
    };
    use std::sync::Arc;

    fn kv() -> Arc<dyn KvStore> {
        Arc::new(MemoryKv::new())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crownjewel_concurrent_secret_rotation_no_lost_update() {
        let store = Arc::new(SecretStore::new(kv(), Arc::new(GateEnvelope)));
        let p = gate_project();
        let base = store.set(p, "k", b"seed").await.unwrap().revision; // revision 1

        let mut set = tokio::task::JoinSet::new();
        for i in 0..32u32 {
            let store = store.clone();
            set.spawn(async move { store.set(p, "k", format!("v{i}").as_bytes()).await });
        }
        let mut wins = Vec::new();
        while let Some(res) = set.join_next().await {
            match res.unwrap() {
                Ok(meta) => wins.push(meta.revision),
                Err(SecretError::Conflict(_)) => {}
                Err(e) => panic!("unexpected secret error: {e}"),
            }
        }
        let final_rev = store
            .list(p)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.name == "k")
            .unwrap()
            .revision;
        assert_no_lost_update(base, wins, final_rev);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crownjewel_rotate_vs_delete_no_resurrection() {
        let store = Arc::new(SecretStore::new(kv(), Arc::new(GateEnvelope)));
        let p = gate_project();
        let mut resurrections = 0usize;
        for round in 0..200u32 {
            let name = format!("k{round}");
            let seed = store.set(p, &name, b"OLD").await.unwrap();
            assert_eq!(seed.revision, 1);

            let s1 = store.clone();
            let n1 = name.clone();
            let setter =
                tokio::spawn(async move { s1.set(p, &n1, b"NEW").await.map(|m| m.revision) });
            let s2 = store.clone();
            let n2 = name.clone();
            let deleter = tokio::spawn(async move { s2.delete(p, &n2).await });

            let _set_res = setter.await.unwrap();
            let del_res = deleter.await.unwrap();

            // Resurrection signal: the delete committed, yet a STALE rotation (one that read OLD,
            // hence revision == 2) is now live — i.e. a blind put landed after the delete, bringing
            // the deleted secret back. Under value-CAS this can never happen (the stale set's CAS
            // on OLD fails once the record is tombstoned); a fresh re-create would be revision 1.
            if matches!(del_res, Ok(true)) {
                let live_stale = store
                    .list(p)
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|m| m.name == name)
                    .is_some_and(|m| m.revision == 2);
                if live_stale {
                    resurrections += 1;
                }
            }
        }
        assert_eq!(
            resurrections, 0,
            "a committed delete must not be undone by a stale concurrent rotation (resurrection)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crownjewel_tenant_name_cap_holds_under_concurrency() {
        let store = Arc::new(TenantSecretStore::new(kv(), Arc::new(GateEnvelope)));
        let p = gate_project();
        let tenant = "firm-1";
        for i in 0..(MAX_TENANT_SECRET_NAMES - 1) {
            store.set(p, tenant, &format!("n{i}"), b"v").await.unwrap();
        }

        let mut set = tokio::task::JoinSet::new();
        for i in 0..8u32 {
            let store = store.clone();
            set.spawn(async move { store.set(p, tenant, &format!("new-{i}"), b"v").await });
        }
        let (mut ok, mut rejected) = (0usize, 0usize);
        while let Some(res) = set.join_next().await {
            match res.unwrap() {
                Ok(_) => ok += 1,
                Err(SecretError::TooManyNames { .. }) | Err(SecretError::Conflict(_)) => {
                    rejected += 1;
                }
                Err(e) => panic!("unexpected secret error: {e}"),
            }
        }
        assert_eq!(
            ok, 1,
            "exactly one new name admitted at the cap boundary (got ok={ok}, rejected={rejected})"
        );
        let live = store.list(p, tenant).await.unwrap().len();
        assert_eq!(
            live, MAX_TENANT_SECRET_NAMES,
            "the per-tenant name cap must hold under concurrency (not be bypassed)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn crownjewel_concurrent_policy_edit_no_lost_write() {
        let kv = kv();
        for round in 0..16u32 {
            let (_cur, ver) = policy_read_versioned(kv.as_ref()).await.unwrap();
            let k1 = kv.clone();
            let v1 = ver.clone();
            let a = distinct_policy(&format!("a{round}"));
            let ta = tokio::spawn(async move { policy_set_if_match(k1.as_ref(), &v1, &a).await });
            let k2 = kv.clone();
            let v2 = ver.clone();
            let b = distinct_policy(&format!("b{round}"));
            let tb = tokio::spawn(async move { policy_set_if_match(k2.as_ref(), &v2, &b).await });

            let ra = ta.await.unwrap();
            let rb = tb.await.unwrap();
            let oks = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
            let conflicts = [&ra, &rb]
                .iter()
                .filter(|r| matches!(r, Err(DeployError::Conflict(_))))
                .count();
            assert_eq!(
                oks, 1,
                "round {round}: exactly one concurrent policy edit may win"
            );
            assert_eq!(
                conflicts, 1,
                "round {round}: the losing edit must Conflict (409) — no silent lost write"
            );
        }
    }
}
