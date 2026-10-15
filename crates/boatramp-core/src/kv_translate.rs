//! Backward-read-compat for an **un-migrated** control-plane store: a [`KvStore`] decorator that lets
//! a current binary serve a store still on the pre-default-scope-re-home (Finding 8) data-plane layout
//! WITHOUT first running `boatramp migrate` — so rolling the binary is a true no-op (no crash-loop, no
//! 503 window, nothing appears to vanish) and the re-home becomes an explicit, deliberate, reversible
//! step.
//!
//! An un-migrated store physically holds the default project's guest KV + messaging-index keys at the
//! bare one-segment scope (`hkv/{base}/…`, `mq*/{base}/…`), but the current runtime composes the
//! two-segment scope (`hkv/default/{base}/…`) via [`ProjectRef::qualified`](crate::project::ProjectRef::qualified).
//! This decorator bridges the two, host-internally, across EVERY data-plane family
//! ([`DEFAULT_SCOPE_FAMILIES`]):
//!
//! - **new→old on every input key** ([`down`](DefaultScopeCompatKv::down)) — reads AND writes land on
//!   the bare old key the store holds. It is a FULL translation (not a read-only fallback): a guest
//!   write/delete goes to the one canonical old key, so there is no second (new) spelling to resurrect
//!   a delete or strand a write, and a rollback to the prior binary reads exactly what this binary
//!   wrote. This read+write symmetry is why the decorator is used ONLY in the un-migrated mode; a
//!   `dual`-soak store needs no KV compat at all (its forward stage already COPIED the keys to the new
//!   spelling, so the runtime reads them directly), and the blob substrate — whose re-home drain is a
//!   separate deferred step — keeps its own soak-time read-fallback.
//! - **old→new on every key returned** ([`up`](DefaultScopeCompatKv::up)) — a `list`/`scan` result is
//!   mapped back to the spelling the runtime expects, project-aware (via
//!   [`rehome_default_scope`](crate::migrate::rehome_default_scope)) so a named project's key is left
//!   untouched and only a genuine bare-default key is re-spelled.
//!
//! Only the `hkv/` + `mq*/` families translate; every control-plane key (`project/…`, `secret/…`,
//! `manifests/…`, `schema/…`, …) passes through byte-identical, so the single wrapped store is safe to
//! hand to the whole handler runtime (guest bindings AND messaging), never missing a data-plane site.
//! On a fully-migrated / fresh store the wrap is not installed at all (see
//! [`default_scope_compat_kv`]), so the steady state is byte-for-byte unchanged.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::kv::{KvDumpEntry, KvError, KvStore, WriteOp, WriterModel};
use crate::migrate::{
    DEFAULT_SCOPE_FAMILIES, default_scope_compat_needed, default_scope_to_bare, known_projects,
    rehome_default_scope,
};

/// A [`KvStore`] decorator applying the un-migrated-store default-scope backward-read-compat (see the
/// module docs). Holds the named-project set (read once at construction) for the project-aware
/// old→new output translation.
pub struct DefaultScopeCompatKv {
    inner: Arc<dyn KvStore>,
    projects: Arc<HashSet<String>>,
}

impl DefaultScopeCompatKv {
    /// Wrap `inner`, translating the default project's `hkv/`/`mq*/` keys between the runtime's
    /// two-segment spelling and the store's bare one-segment spelling. `projects` is the named-project
    /// set used to leave a named project's (already two-segment) keys untouched on output.
    pub fn new(inner: Arc<dyn KvStore>, projects: Arc<HashSet<String>>) -> Self {
        Self { inner, projects }
    }

    /// new→old: translate an input key the runtime composed (`{fam}default/…`) to the bare old key the
    /// un-migrated store physically holds. A key under no default-scope family — or under one but not
    /// `default/`-scoped — borrows through unchanged (control-plane keys, named-project keys).
    fn down<'a>(&self, key: &'a str) -> Cow<'a, str> {
        for fam in DEFAULT_SCOPE_FAMILIES {
            if let Some(old) = default_scope_to_bare(fam, key) {
                return Cow::Owned(old);
            }
        }
        Cow::Borrowed(key)
    }

    /// old→new: translate a key read from the store back to the two-segment spelling the runtime
    /// expects, against a CURRENT named-project set. Project-aware: a named project's key and an
    /// already-`default/` key are returned unchanged (`rehome_default_scope` yields `None`); only a
    /// genuine bare default scope is re-spelled. `projects` is read FRESH per list/scan (see
    /// [`current_projects`](Self::current_projects)), NOT snapshotted at construction — so a tenant
    /// project created AFTER this decorator was built is never wrongly rewritten under the default scope,
    /// which would otherwise surface its topics/keys as `default/{proj}/…` to node-wide messaging
    /// sweeps (Security finding H-1).
    fn up_with(&self, key: String, projects: &HashSet<String>) -> String {
        for fam in DEFAULT_SCOPE_FAMILIES {
            if key.starts_with(fam) {
                return match rehome_default_scope(fam, &key, projects) {
                    Some(new_key) => new_key,
                    None => key,
                };
            }
        }
        key
    }

    /// The CURRENT named-project set, re-read from the store on every list/scan so the old→new
    /// back-translation can never mislabel a tenant project created after this decorator was built
    /// (H-1). Falls back to the construction-time snapshot only if the (cheap `projectmeta/`) read
    /// transiently fails — never staler than before, and the common path is always fresh.
    async fn current_projects(&self) -> HashSet<String> {
        known_projects(self.inner.as_ref())
            .await
            .unwrap_or_else(|_| (*self.projects).clone())
    }

    fn down_ops(&self, ops: Vec<WriteOp>) -> Vec<WriteOp> {
        ops.into_iter()
            .map(|op| match op {
                WriteOp::Put(k, v) => WriteOp::Put(self.down(&k).into_owned(), v),
                WriteOp::Delete(k) => WriteOp::Delete(self.down(&k).into_owned()),
            })
            .collect()
    }
}

#[async_trait]
impl KvStore for DefaultScopeCompatKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        self.inner.get(&self.down(key)).await
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.inner.put(&self.down(key), value).await
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.delete(&self.down(key)).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        let keys = self.inner.list_prefix(&self.down(prefix)).await?;
        let projects = self.current_projects().await;
        Ok(keys
            .into_iter()
            .map(|k| self.up_with(k, &projects))
            .collect())
    }

    async fn list_from(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> Result<Vec<String>, KvError> {
        // `after` is the suffix AFTER `prefix`; the new→old translation only ever strips the
        // `default/` scope SEGMENT (which lives inside `prefix`, never in `after`), so the cursor is
        // spelling-invariant and passes through unchanged. (Every real caller — the messaging log
        // pager — uses a scoped `{fam}{scope}/` prefix; see `kv::KvStore::list_from`.)
        let keys = self
            .inner
            .list_from(&self.down(prefix), after, limit)
            .await?;
        let projects = self.current_projects().await;
        Ok(keys
            .into_iter()
            .map(|k| self.up_with(k, &projects))
            .collect())
    }

    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, KvError> {
        let pairs = self.inner.scan_prefix(&self.down(prefix)).await?;
        let projects = self.current_projects().await;
        Ok(pairs
            .into_iter()
            .map(|(k, v)| (self.up_with(k, &projects), v))
            .collect())
    }

    async fn dump_scan(&self) -> Result<Vec<KvDumpEntry>, KvError> {
        // A full physical snapshot: forward RAW (no translation). A dump is a physical-truth export;
        // the compat decorator must never be the `kv export`/migration handle (those use the
        // undecorated store), so returning the store's real keys is correct here.
        self.inner.dump_scan().await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> Result<bool, KvError> {
        self.inner
            .compare_and_swap(&self.down(key), expected, new)
            .await
    }

    async fn write_batch(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.inner.write_batch(self.down_ops(ops)).await
    }

    async fn write_batch_relaxed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.inner.write_batch_relaxed(self.down_ops(ops)).await
    }

    async fn put_durable_checkpointed(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.inner
            .put_durable_checkpointed(&self.down(key), value)
            .await
    }

    async fn delete_checkpointed(&self, key: &str) -> Result<(), KvError> {
        self.inner.delete_checkpointed(&self.down(key)).await
    }

    async fn write_batch_checkpointed(&self, ops: Vec<WriteOp>) -> Result<(), KvError> {
        self.inner
            .write_batch_checkpointed(self.down_ops(ops))
            .await
    }

    // ---- capability + lifecycle advertisements: pure pass-through (no key involved) ----
    fn atomic_write_batch(&self) -> bool {
        self.inner.atomic_write_batch()
    }
    fn supports_cas(&self) -> bool {
        self.inner.supports_cas()
    }
    fn writer_model(&self) -> WriterModel {
        self.inner.writer_model()
    }
    async fn flush(&self) -> Result<(), KvError> {
        self.inner.flush().await
    }
    async fn close(&self) -> Result<(), KvError> {
        self.inner.close().await
    }
    async fn checkpoint(&self) -> Result<(), KvError> {
        self.inner.checkpoint().await
    }
    async fn maintenance_gc(&self, min_age: Duration) -> Result<(), KvError> {
        self.inner.maintenance_gc(min_age).await
    }
    fn invalidate_cache(&self) {
        self.inner.invalidate_cache();
    }
    fn invalidate_keys(&self, keys: &[String]) {
        // The cache-coherence changelog carries PHYSICAL (stored) keys, which match the inner store's
        // cache keyspace — forward unchanged (the decorator is transparent to coherence).
        self.inner.invalidate_keys(keys);
    }
}

/// Wrap `kv` in the un-migrated backward-read-compat decorator IFF the store needs it
/// ([`default_scope_compat_needed`] — below the re-home version AND carrying bare default-scoped data).
/// A fresh/migrated/dual store is returned unchanged (byte-for-byte steady state). On any error reading
/// the schema state or the project set, returns `kv` unchanged (fail-open to the raw store: a transient
/// read error must never silently change the layout, and a stale new-spelling read is a miss — never a
/// cross-tenant leak). This is the KV analogue of `boatramp_node::blobs::default_scope_blob_fallback`.
pub async fn default_scope_compat_kv(kv: Arc<dyn KvStore>) -> Arc<dyn KvStore> {
    match default_scope_compat_needed(kv.as_ref()).await {
        Ok(true) => {}
        Ok(false) => return kv,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not read schema state to decide default-scope backward-read-compat; serving \
                 the store undecorated (new spelling). If this is an un-migrated legacy store its \
                 default-project data will read empty until `boatramp migrate` runs."
            );
            return kv;
        }
    }
    let projects = match known_projects(kv.as_ref()).await {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not read the named-project set for default-scope backward-read-compat; serving \
                 undecorated to avoid wrongly attributing commingled data. Run `boatramp migrate`."
            );
            return kv;
        }
    };
    tracing::warn!(
        "serving an UN-MIGRATED store on the OLD (pre-default-scope-re-home) data-plane layout: the \
         default project's guest KV + messaging indices are read AND written at their bare \
         `{{family}}{{base}}` spelling, so rolling this binary is a no-op and nothing is lost. Run \
         `boatramp migrate` (dry-runnable; reversible with `boatramp migrate --abort`) to re-home to \
         the `default/` layout, then `boatramp migrate --finalize` to retire the old keys."
    );
    Arc::new(DefaultScopeCompatKv::new(kv, Arc::new(projects)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryKv;
    use crate::migrate::{SCHEMA_KEY, SchemaState};

    /// A legacy (un-migrated) store carrying BOTH the default project's bare data-plane keys AND a
    /// named tenant project's two-segment keys — a MULTI-TENANT fixture, so an isolation claim is not
    /// structurally blind (a single-tenant fixture could pass while leaking).
    async fn seed_unmigrated_multitenant() -> Arc<MemoryKv> {
        let kv = Arc::new(MemoryKv::new());
        kv.put("projectmeta/default", b"h".to_vec()).await.unwrap();
        kv.put("projectmeta/acme", b"h".to_vec()).await.unwrap();
        // default project (bare, pre-fix) guest data.
        kv.put("hkv/blog/counter", b"7".to_vec()).await.unwrap();
        kv.put("mqready/blog", b"".to_vec()).await.unwrap();
        // tenant project `acme` (two-segment) guest data — MUST stay untouched.
        kv.put("hkv/acme/shop/x", b"42".to_vec()).await.unwrap();
        // No schema marker ⇒ version 0; migration 2 is applicable (bare default data present).
        kv
    }

    #[tokio::test]
    async fn unmigrated_store_round_trips_old_layout_and_isolates_the_tenant() {
        // GATE: `ROLL-NOOP OLD-LAYOUT OK` — the new binary serves an un-migrated store's old layout in
        // place (reads AND writes), and a named tenant's keyspace is never served under / pulled into
        // the default scope.
        let raw = seed_unmigrated_multitenant().await;
        let compat = default_scope_compat_kv(raw.clone()).await;
        // The decorator was installed (not the same Arc).
        assert!(
            !Arc::ptr_eq(&(raw.clone() as Arc<dyn KvStore>), &compat),
            "an un-migrated store must be wrapped"
        );

        // READ: the runtime composes the NEW spelling; it is served from the OLD bare key.
        assert_eq!(
            compat.get("hkv/default/blog/counter").await.unwrap(),
            Some(b"7".to_vec())
        );
        // WRITE: a new-spelling write lands on the OLD key (not the new one) — so a rollback to the
        // prior binary reads exactly this, and there is no second spelling to strand.
        compat
            .put("hkv/default/blog/fresh", b"v".to_vec())
            .await
            .unwrap();
        assert_eq!(
            raw.get("hkv/blog/fresh").await.unwrap(),
            Some(b"v".to_vec()),
            "write must land on the bare OLD key"
        );
        assert!(
            raw.get("hkv/default/blog/fresh").await.unwrap().is_none(),
            "write must NOT create a new-spelling key"
        );
        // DELETE round-trips to the old key.
        compat.delete("hkv/default/blog/fresh").await.unwrap();
        assert!(raw.get("hkv/blog/fresh").await.unwrap().is_none());

        // TENANT ISOLATION: the tenant's own (two-segment) data is served unchanged — never
        // down-translated, never wrongly attributed to the default scope.
        assert_eq!(
            compat.get("hkv/acme/shop/x").await.unwrap(),
            Some(b"42".to_vec())
        );
        // A family-wide list maps ONLY the default's bare keys up to the new spelling, and returns the
        // tenant's keys verbatim (never pulled under `hkv/default/`).
        let mut listed = compat.list_prefix("hkv/").await.unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec![
                "hkv/acme/shop/x".to_string(),
                "hkv/default/blog/counter".to_string(),
            ]
        );
        // A single-segment marker family round-trips too.
        assert_eq!(
            compat.list_prefix("mqready/").await.unwrap(),
            vec!["mqready/default/blog".to_string()]
        );
        println!("ROLL-NOOP OLD-LAYOUT OK");
    }

    #[tokio::test]
    async fn post_construction_tenant_is_never_pulled_under_default() {
        // H-1 regression: a tenant project created AFTER the decorator is built (the pre-migration
        // serve window stays live) must NOT have its data-plane keys surfaced under the default scope
        // by a family-wide list — which the drain/ready-set sweeps run over the decorated handle. The
        // construction-time project snapshot would mislabel it; the per-list fresh read must not.
        let raw = Arc::new(MemoryKv::new());
        raw.put("projectmeta/default", b"h".to_vec()).await.unwrap();
        raw.put("hkv/blog/x", b"1".to_vec()).await.unwrap(); // a bare default key (makes v2 applicable)
        // No `evil` project exists yet → it is ABSENT from the decorator's construction snapshot.
        let compat = default_scope_compat_kv(raw.clone()).await;
        assert!(
            !Arc::ptr_eq(&(raw.clone() as Arc<dyn KvStore>), &compat),
            "the un-migrated store must be wrapped"
        );
        // NOW create tenant `evil` + its data (the post-construction window).
        raw.put("projectmeta/evil", b"h".to_vec()).await.unwrap();
        raw.put("hkv/evil/site/y", b"2".to_vec()).await.unwrap();
        raw.put("mq/evil/base/1-aa", b"m".to_vec()).await.unwrap();

        // A family-wide list maps the DEFAULT's bare key up, and leaves `evil`'s keys VERBATIM —
        // never `hkv/default/evil/…` (which a stale snapshot would have produced).
        let mut hkv = compat.list_prefix("hkv/").await.unwrap();
        hkv.sort();
        assert_eq!(
            hkv,
            vec![
                "hkv/default/blog/x".to_string(),
                "hkv/evil/site/y".to_string(),
            ]
        );
        assert!(
            !hkv.iter().any(|k| k.starts_with("hkv/default/evil/")),
            "a post-construction tenant must never be pulled under the default scope"
        );
        assert_eq!(
            compat.list_prefix("mq/").await.unwrap(),
            vec!["mq/evil/base/1-aa".to_string()],
            "the tenant's topic index stays under its own scope, not default/"
        );
    }

    #[tokio::test]
    async fn migrated_and_fresh_stores_are_not_wrapped() {
        // A FINALIZED store (version 2) must not be decorated — the steady state is byte-for-byte.
        let kv = Arc::new(MemoryKv::new());
        kv.put("hkv/default/blog/k", b"v".to_vec()).await.unwrap();
        kv.put(
            SCHEMA_KEY,
            serde_json::to_vec(&SchemaState {
                version: 2,
                ..Default::default()
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let compat = default_scope_compat_kv(kv.clone()).await;
        assert!(
            Arc::ptr_eq(&(kv as Arc<dyn KvStore>), &compat),
            "a migrated store must be returned unwrapped"
        );

        // A FRESH store (version 0, no bare default data) must not be wrapped either — it already
        // composes + persists the new spelling, so wrapping would wrongly strip its writes to old.
        let fresh = Arc::new(MemoryKv::new());
        fresh
            .put("projectmeta/default", b"h".to_vec())
            .await
            .unwrap();
        let compat2 = default_scope_compat_kv(fresh.clone()).await;
        assert!(
            Arc::ptr_eq(&(fresh as Arc<dyn KvStore>), &compat2),
            "a fresh store with no bare default data must be returned unwrapped"
        );
    }

    #[tokio::test]
    async fn control_plane_keys_pass_through_untranslated() {
        // The decorator must touch ONLY the data-plane families — a control-plane key (project/…,
        // secret/…, schema/…) passes through byte-identical even when the store is wrapped.
        let raw = seed_unmigrated_multitenant().await;
        raw.put("project/default/site/blog", b"ptr".to_vec())
            .await
            .unwrap();
        raw.put("secret/api-key", b"s".to_vec()).await.unwrap();
        let compat = default_scope_compat_kv(raw.clone()).await;
        assert_eq!(
            compat.get("project/default/site/blog").await.unwrap(),
            Some(b"ptr".to_vec())
        );
        assert_eq!(
            compat.get("secret/api-key").await.unwrap(),
            Some(b"s".to_vec())
        );
        compat.put("secret/new", b"n".to_vec()).await.unwrap();
        assert_eq!(raw.get("secret/new").await.unwrap(), Some(b"n".to_vec()));
    }
}
