//! `KeyedSemaphores` — the one audited home for the "lazily-created per-key concurrency semaphore"
//! pattern that recurs across the serve / stream / consumer paths.
//!
//! Before this type, `Mutex<HashMap<String, Arc<Semaphore>>>` was open-coded in several places
//! (per-site, per-scope, per-consumer gates). Each copy re-implemented the same discipline, which is
//! exactly the kind of thing that rots when the next copy drops a subtlety. Folding them onto one type
//! puts the invariant in a single reviewable place:
//!
//! 1. **The `std::sync::Mutex` is NEVER held across an `.await`.** [`gate`](KeyedSemaphores::gate) is
//!    synchronous: it takes the map lock only for a get/insert (microseconds), clones out the
//!    `Arc<Semaphore>`, and drops the guard. The caller then `try_acquire`s or `acquire().await`s on
//!    the returned `Arc` OUTSIDE the lock. `std::sync::Mutex` (not `tokio::sync::Mutex`) is therefore
//!    the correct choice — there is no guard-across-await to reason about, and it is faster.
//! 2. **The entry is rebuilt when the effective cap changes**, so a config reload that changes a
//!    `max_concurrency`-style knob actually takes effect (the older open-coded `or_insert_with` gates
//!    silently ignored cap changes until a restart — this type fixes that uniformly).
//! 3. **Growth is bounded by the KEY SET, and entries are never evicted.** That is safe ONLY for keys
//!    drawn from a bounded, trusted space (a site / scope / consumer name / component hash — all
//!    config- or deploy-derived). Do **not** key this on untrusted/unbounded input (a client IP, a
//!    guest-supplied name): it would grow without bound. For an untrusted key, use a self-cleaning
//!    counter that removes its entry at zero (see the server's per-IP stream counter) or a
//!    capacity-bounded `LruCache`.
//!
//! A rebuild on cap-change leaves any permits already handed out against the OLD semaphore
//! outstanding, so the effective concurrency can transiently exceed the new cap until those drop —
//! bounded and self-correcting, matching the prior `ConsumerGates` behavior.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;

/// A set of lazily-created per-key concurrency semaphores. See the module docs for the invariant.
///
/// Keys MUST come from a bounded, trusted space (never a client IP or guest-supplied string) — the
/// map does not evict.
#[derive(Default)]
pub struct KeyedSemaphores(Mutex<HashMap<String, (usize, Arc<Semaphore>)>>);

impl KeyedSemaphores {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The `Arc<Semaphore>` for `key`, sized `cap` (floored at 1). If an entry exists with the same
    /// effective cap it is reused; if the cap changed (a config reload) the entry is rebuilt at the
    /// new size. Synchronous and cheap — the lock is held only for the map get/insert, never across an
    /// `.await`. The caller decides the acquire discipline:
    ///
    /// - non-blocking shed (a hard cap → 503): `gate(..).try_acquire_owned()`;
    /// - blocking admission (queue the excess cheaply): `gate(..).acquire_owned().await`.
    pub fn gate(&self, key: &str, cap: usize) -> Arc<Semaphore> {
        let cap = cap.max(1);
        let mut map = self.0.lock().unwrap();
        match map.get(key) {
            Some((c, s)) if *c == cap => Arc::clone(s),
            _ => {
                let s = Arc::new(Semaphore::new(cap));
                map.insert(key.to_string(), (cap, Arc::clone(&s)));
                s
            }
        }
    }

    /// Number of distinct keys currently tracked (for observability / tests).
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// Whether no keys are tracked yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_same_cap_reuses_the_semaphore() {
        let gates = KeyedSemaphores::new();
        let a = gates.gate("k", 4);
        let b = gates.gate("k", 4);
        assert!(Arc::ptr_eq(&a, &b), "same (key, cap) must reuse the Arc");
        assert_eq!(a.available_permits(), 4);
        assert_eq!(gates.len(), 1);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let gates = KeyedSemaphores::new();
        let a = gates.gate("a", 2);
        let b = gates.gate("b", 2);
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(gates.len(), 2);
    }

    #[test]
    fn cap_change_rebuilds_the_entry() {
        let gates = KeyedSemaphores::new();
        let a = gates.gate("k", 2);
        let b = gates.gate("k", 5);
        assert!(
            !Arc::ptr_eq(&a, &b),
            "a changed cap must rebuild the semaphore"
        );
        assert_eq!(b.available_permits(), 5);
        // The old Arc still reflects its own (old) size — outstanding permits against it stay valid.
        assert_eq!(a.available_permits(), 2);
        assert_eq!(gates.len(), 1);
    }

    #[test]
    fn cap_is_floored_at_one() {
        let gates = KeyedSemaphores::new();
        assert_eq!(gates.gate("k", 0).available_permits(), 1);
    }

    #[tokio::test]
    async fn gate_result_is_acquirable_without_holding_the_map_lock() {
        // The returned Arc is awaited OUTSIDE gate(), so acquiring never touches the map lock.
        let gates = KeyedSemaphores::new();
        let sem = gates.gate("k", 1);
        let _permit = sem.clone().acquire_owned().await.unwrap();
        // A second gate() call for the same key still returns promptly (lock is free).
        assert!(Arc::ptr_eq(&gates.gate("k", 1), &sem));
    }
}
