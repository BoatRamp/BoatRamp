//! The `migrate-ddl` capability host binding: a migration **function step** runs owner-role DDL /
//! DML / verification queries (`boatramp:handlers/migrate-ddl`) against its project's managed
//! database.
//!
//! The authority is host-mediated and intrinsically owner-scoped: the server-side
//! [`MigrateDdl`](boatramp_core::sql::MigrateDdl) seam holds the orchestrator-owned **owner-role**
//! connection and runs each statement on it — the guest never holds the credential (v0.4.25 BR-7).
//! It is attached **only** inside a `Project·Admin` migration run (the server sets the migration
//! context per invocation); a normal request/consumer/cron invocation of the same component has NO
//! binding, so every verb returns `not-a-migration` — a self-explaining refusal, not a bare
//! `access-denied`, so a migration author can tell "you're not in a migration" from "your DDL was
//! wrong" (U4). Deny-by-default.
//!
//! The DDL runs at project-owner altitude (a non-superuser role Postgres denies cross-database /
//! role-escalation / `COPY … TO PROGRAM`), never as a cluster superuser. The ledger-schema (S3) and
//! transaction-control (S4) guards live in the server-side seam impl, so the guest sees a typed
//! `ledger-protected` / `txn-control` refusal.

use std::sync::Arc;

use boatramp_core::sql::{MigrateDdl, MigrateDdlError};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/migrate-ddl-host",
        async: {
            only_imports: ["exec", "exec-batch", "query"],
        },
    });
}

use generated::boatramp::handlers::{
    migrate_ddl as migrate_iface, migrate_ddl_types as migrate_types,
};

/// A migration-step `migrate-ddl` grant: the project+db-scoped owner-DDL seam. Present only when the
/// server invoked this component as a migration step (context-gated).
#[derive(Clone)]
pub struct MigrateBinding {
    pub(crate) ddl: Arc<dyn MigrateDdl>,
}

/// Per-invocation view over the (optional) migrate-ddl grant.
pub struct MigrateHost<'a> {
    binding: Option<&'a MigrateBinding>,
}

impl<'a> MigrateHost<'a> {
    pub fn new(binding: Option<&'a MigrateBinding>) -> Self {
        Self { binding }
    }

    /// The owner-DDL seam, or `not-a-migration` when the capability is ungranted (this component was
    /// not invoked as a migration step). Returns an owned `Arc` so no borrow of `self` is held across
    /// the subsequent `.await`.
    fn ddl(&self) -> Result<Arc<dyn MigrateDdl>, migrate_types::MigrateError> {
        let binding = self
            .binding
            .ok_or(migrate_types::MigrateError::NotAMigration)?;
        Ok(binding.ddl.clone())
    }
}

fn to_wit(err: MigrateDdlError) -> migrate_types::MigrateError {
    match err {
        MigrateDdlError::LedgerProtected => migrate_types::MigrateError::LedgerProtected,
        MigrateDdlError::TxnControl => migrate_types::MigrateError::TxnControl,
        MigrateDdlError::Sql(m) => migrate_types::MigrateError::Sql(m),
    }
}

impl migrate_iface::Host for MigrateHost<'_> {
    async fn exec(&mut self, script: String) -> Result<(), migrate_types::MigrateError> {
        let d = self.ddl()?;
        d.exec(&script).await.map_err(to_wit)
    }

    async fn exec_batch(
        &mut self,
        scripts: Vec<String>,
    ) -> Result<(), migrate_types::MigrateError> {
        let d = self.ddl()?;
        d.exec_batch(scripts).await.map_err(to_wit)
    }

    async fn query(&mut self, sql: String) -> Result<String, migrate_types::MigrateError> {
        let d = self.ddl()?;
        let rows = d.query(&sql).await.map_err(to_wit)?;
        Ok(rows.to_json_string())
    }
}

/// Wire the `migrate-ddl` host into `linker`, drawing the per-invocation grant from `get`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    get: impl Fn(&mut T) -> MigrateHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    migrate_iface::add_to_linker_get_host(linker, get)
}

#[cfg(test)]
mod tests {
    use super::migrate_iface::Host as _;
    use super::*;
    use async_trait::async_trait;
    use boatramp_core::sql::SqlRows;

    /// A recording seam that just proves the host routes each verb to the trait and maps errors.
    struct FakeDdl;
    #[async_trait]
    impl MigrateDdl for FakeDdl {
        async fn exec(&self, script: &str) -> Result<(), MigrateDdlError> {
            if script.contains("boatramp_migrations") {
                Err(MigrateDdlError::LedgerProtected)
            } else if script.to_ascii_uppercase().contains("BEGIN") {
                Err(MigrateDdlError::TxnControl)
            } else {
                Ok(())
            }
        }
        async fn exec_batch(&self, scripts: Vec<String>) -> Result<(), MigrateDdlError> {
            for s in &scripts {
                self.exec(s).await?;
            }
            Ok(())
        }
        async fn query(&self, _sql: &str) -> Result<SqlRows, MigrateDdlError> {
            Ok(SqlRows {
                columns: vec!["n".into()],
                rows: vec![vec![boatramp_core::sql::SqlValue::Integer(1)]],
            })
        }
    }

    #[tokio::test]
    async fn ungranted_capability_is_not_a_migration() {
        let mut host = MigrateHost::new(None);
        assert!(matches!(
            host.exec("CREATE TABLE t(x int)".into()).await.unwrap_err(),
            migrate_types::MigrateError::NotAMigration
        ));
        assert!(matches!(
            host.query("SELECT 1".into()).await.unwrap_err(),
            migrate_types::MigrateError::NotAMigration
        ));
    }

    #[tokio::test]
    async fn granted_routes_to_the_seam_and_maps_errors() {
        let b = MigrateBinding {
            ddl: Arc::new(FakeDdl),
        };
        let mut host = MigrateHost::new(Some(&b));
        // A plain DDL succeeds.
        host.exec("CREATE TABLE t(x int)".into()).await.unwrap();
        // The guards surface as typed refusals.
        assert!(matches!(
            host.exec("DROP TABLE boatramp_migrations.schema_migrations".into())
                .await
                .unwrap_err(),
            migrate_types::MigrateError::LedgerProtected
        ));
        assert!(matches!(
            host.exec("BEGIN; DROP TABLE t; COMMIT".into())
                .await
                .unwrap_err(),
            migrate_types::MigrateError::TxnControl
        ));
        // query round-trips through the JSON encoder.
        let json = host.query("SELECT 1 AS n".into()).await.unwrap();
        assert!(json.contains("\"columns\""));
        assert!(json.contains("\"n\""));
    }
}
