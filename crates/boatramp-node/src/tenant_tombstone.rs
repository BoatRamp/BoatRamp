//! Soft-delete **tombstones** for the per-tenant managed-database feature
//! (PLAN-per-tenant-db, safe deprovision).
//!
//! # Why a tombstone exists
//!
//! A project/site delete used to hard-`DROP DATABASE` a tenant's managed database
//! immediately, which is **irreversible data loss** the instant a delete is issued.
//! For the one cell where the engine supports it — a **Shared Postgres** tenant —
//! the deprovision path instead *soft*-deletes: it renames the tenant's database
//! aside (`<db>__deleted_<unixts>`), disables the tenant's login role, and records a
//! [`Tombstone`] here. The renamed data then survives a configurable **grace window**
//! during which:
//!
//! - a [reaper](crate::tenant_sql::spawn_tenant_tombstone_reaper) hard-drops it once
//!   `delete_after` has passed (freeing the aside name + role + sealed credential), and
//! - an operator can [`recover`](crate::tenant_sql::recover_tenant) the tenant before
//!   then (renaming the database back, re-enabling the role).
//!
//! Every *other* delete cell (Shared **MySQL** — no database rename; **all Single** —
//! the unit is a whole container/volume) stays an immediate, irreversible drop and
//! writes no tombstone.
//!
//! # Store scheme
//!
//! A tombstone lives in the control-plane KV under
//! `tenant-tombstone/<project>/<renamed_db>` (JSON, matching the encoding
//! [`DeployStore`](boatramp_core::deploy::DeployStore) uses for its own KV values).
//! Keying on the *renamed* database name — which is unique per soft-delete because it
//! carries the delete's unix-second timestamp — means two soft-deletes of the same
//! logical tenant (delete, re-create, delete again) never collide on one key.

#![cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]

use std::sync::Arc;

use boatramp_core::kv::KvStore;
use serde::{Deserialize, Serialize};

/// The KV key prefix under which soft-delete tombstones live.
const TOMBSTONE_PREFIX: &str = "tenant-tombstone";

/// A soft-delete tombstone: the record a reaper hard-drops (or an operator recovers)
/// a soft-deleted **Shared Postgres** tenant from. Serialized as JSON into the
/// control-plane KV under [`Tombstone::key`].
///
/// The sealed per-tenant credential is deliberately **not** deleted at soft-delete
/// time (it's needed to recover the role); the reaper deletes it on hard-drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// Schema version, pinned at 1 (project convention — no migration until release).
    #[serde(default = "one")]
    pub version: u32,
    /// The deleted tenant's project (the credential's KV project scope).
    pub project: String,
    /// The database's **renamed-aside** name (`<original_db>__deleted_<unixts>`) —
    /// the live physical database the reaper will `DROP` / recovery will rename back.
    pub renamed_db: String,
    /// The database's **original** name — restored by [recovery](crate::tenant_sql::recover_tenant).
    pub original_db: String,
    /// The tenant's login role (disabled `NOLOGIN` by the soft delete).
    pub role: String,
    /// The engine string (`postgres`) — recorded for the reaper/recovery, though only
    /// Shared Postgres is ever soft-deleted.
    pub engine: String,
    /// The compute workload (the shared server) the tenant's database lives on.
    pub compute: String,
    /// The Shared server's superuser (the binding's `user`) — recorded so the reaper
    /// can reach the maintenance database to hard-drop without needing the binding
    /// config, and so recovery uses the same superuser.
    pub superuser: String,
    /// The per-tenant credential's KV **workload** segment (so the reaper can delete
    /// exactly the sealed credential this tenant used).
    pub cred_workload: String,
    /// Unix seconds when the soft delete happened.
    pub deleted_at: u64,
    /// Unix seconds at/after which the reaper may hard-drop this tenant (=
    /// `deleted_at + grace`).
    pub delete_after: u64,
}

/// serde default for [`Tombstone::version`].
fn one() -> u32 {
    1
}

impl Tombstone {
    /// The KV key for this tombstone: `tenant-tombstone/<project>/<renamed_db>`.
    pub fn key(&self) -> String {
        key_for(&self.project, &self.renamed_db)
    }

    /// Whether this tombstone is due for a hard-drop at wall-clock `now` (unix
    /// seconds) — i.e. its grace window has elapsed.
    pub fn is_due(&self, now: u64) -> bool {
        self.delete_after <= now
    }
}

/// The KV key for a tombstone of `renamed_db` under `project`.
fn key_for(project: &str, renamed_db: &str) -> String {
    format!("{TOMBSTONE_PREFIX}/{project}/{renamed_db}")
}

/// Write (or overwrite) a tombstone into the KV.
pub async fn put(kv: &Arc<dyn KvStore>, ts: &Tombstone) -> Result<(), String> {
    let bytes = serde_json::to_vec(ts).map_err(|e| format!("serialize tombstone: {e}"))?;
    kv.put(&ts.key(), bytes)
        .await
        .map_err(|e| format!("store tombstone {}: {e}", ts.key()))
}

/// Fetch a single tombstone by its `(project, renamed_db)` identity, if present.
pub async fn get(
    kv: &Arc<dyn KvStore>,
    project: &str,
    renamed_db: &str,
) -> Result<Option<Tombstone>, String> {
    let key = key_for(project, renamed_db);
    match kv.get(&key).await.map_err(|e| e.to_string())? {
        Some(bytes) => {
            let ts = serde_json::from_slice(&bytes)
                .map_err(|e| format!("deserialize tombstone {key}: {e}"))?;
            Ok(Some(ts))
        }
        None => Ok(None),
    }
}

/// List every tombstone across all projects (the reaper's input). A value that
/// fails to deserialize is skipped with a warning rather than failing the whole
/// sweep, so one bad record can't wedge the reaper.
pub async fn list(kv: &Arc<dyn KvStore>) -> Result<Vec<Tombstone>, String> {
    let prefix = format!("{TOMBSTONE_PREFIX}/");
    let keys = kv
        .list_prefix(&prefix)
        .await
        .map_err(|e| format!("list tombstones: {e}"))?;
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        // A key that vanished between list and get is fine — just skip it.
        if let Some(bytes) = kv.get(&key).await.map_err(|e| e.to_string())? {
            match serde_json::from_slice::<Tombstone>(&bytes) {
                Ok(ts) => out.push(ts),
                Err(e) => {
                    tracing::warn!(%key, error = %e, "skipping undeserializable tenant tombstone");
                }
            }
        }
    }
    Ok(out)
}

/// Delete a tombstone (after a successful hard-drop or a recovery). Idempotent —
/// deleting an absent key is a no-op in the underlying KV.
pub async fn delete(kv: &Arc<dyn KvStore>, ts: &Tombstone) -> Result<(), String> {
    kv.delete(&ts.key())
        .await
        .map_err(|e| format!("delete tombstone {}: {e}", ts.key()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::kv::MemoryKv;

    fn sample() -> Tombstone {
        Tombstone {
            version: 1,
            project: "acme".into(),
            renamed_db: "appdb_acme__deleted_1700000000".into(),
            original_db: "appdb_acme".into(),
            role: "appdb_acme_role".into(),
            engine: "postgres".into(),
            compute: "pg".into(),
            superuser: "super".into(),
            cred_workload: "pg/acme_hash".into(),
            deleted_at: 1_700_000_000,
            delete_after: 1_700_604_800, // +7 days
        }
    }

    #[test]
    fn key_scheme_folds_project_and_renamed_db() {
        let ts = sample();
        assert_eq!(
            ts.key(),
            "tenant-tombstone/acme/appdb_acme__deleted_1700000000"
        );
    }

    #[test]
    fn is_due_only_at_or_after_delete_after() {
        let ts = sample();
        assert!(!ts.is_due(ts.delete_after - 1), "before grace: not due");
        assert!(ts.is_due(ts.delete_after), "at delete_after: due");
        assert!(ts.is_due(ts.delete_after + 1), "after grace: due");
    }

    /// The tombstone round-trips through the KV: put → get → list all return the
    /// exact same record, then delete removes it.
    #[tokio::test]
    async fn tombstone_kv_round_trip() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let ts = sample();

        put(&kv, &ts).await.unwrap();

        let got = get(&kv, &ts.project, &ts.renamed_db)
            .await
            .unwrap()
            .expect("tombstone present after put");
        assert_eq!(got, ts, "get round-trips the exact record");

        let listed = list(&kv).await.unwrap();
        assert_eq!(listed, vec![ts.clone()], "list returns the one tombstone");

        delete(&kv, &ts).await.unwrap();
        assert!(
            get(&kv, &ts.project, &ts.renamed_db)
                .await
                .unwrap()
                .is_none(),
            "tombstone gone after delete"
        );
        assert!(
            list(&kv).await.unwrap().is_empty(),
            "list empty after delete"
        );
    }

    /// Two soft-deletes of the same logical tenant (distinct timestamps ⇒ distinct
    /// renamed names) get distinct keys and both survive in the store.
    #[tokio::test]
    async fn distinct_renamed_names_do_not_collide() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let mut a = sample();
        a.renamed_db = "appdb_acme__deleted_1700000000".into();
        let mut b = sample();
        b.renamed_db = "appdb_acme__deleted_1700000500".into();
        b.deleted_at = 1_700_000_500;

        put(&kv, &a).await.unwrap();
        put(&kv, &b).await.unwrap();

        assert_ne!(a.key(), b.key());
        let mut listed = list(&kv).await.unwrap();
        listed.sort_by(|x, y| x.renamed_db.cmp(&y.renamed_db));
        assert_eq!(listed, vec![a, b], "both tombstones coexist");
    }
}
