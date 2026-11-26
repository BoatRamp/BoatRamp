//! **Live gate (pgvector): the typed `boatramp-core::ddl` builder's output is correct on a real
//! Postgres** — the runtime half of roadmap #13 (the compile-time half is the pure unit/round-trip
//! battery in `boatramp_core::ddl`).
//!
//! It drives the EXACT three-identity owner-role model the migration seam uses (`provision_ddl` +
//! `grant_app_role_ddl`), stands the builder's DDL up as the non-superuser **owner** role, and
//! proves at the SQL level:
//!
//! 1. **Tenant-scoped kNN returns ZERO foreign rows.** The builder's tenant-scoped `CreateTable`
//!    emits the RLS policy + `FORCE ROW LEVEL SECURITY`; with **two tenants' rows in one shared
//!    `vector` keyspace** (the other tenant's rows deliberately placed NEAREST the probe), a kNN
//!    `ORDER BY embedding <=> $probe` run as the non-superuser **runtime** role (subject to RLS,
//!    `NOBYPASSRLS`) sees ONLY its own tenant's rows — the emitted policy filters at the row source
//!    before `ORDER BY`/`LIMIT`. An unset tenant GUC fails closed (zero rows). ([[tenancy-gate-needs-multi-tenant-fixture]])
//! 2. **The emitted hnsw `vector_cosine_ops` index is actually used.** `EXPLAIN` of the kNN (with
//!    `enable_seqscan = off`) shows an `Index Scan using <the builder's index>`, never a `Seq Scan`
//!    — so the metric→opclass coupling the builder derives is correct (a mismatched opclass would be
//!    unusable and the plan would seq-scan).
//! 3. **The builder emits the hand-written DDL.** The owner role applies the builder's output
//!    verbatim and it executes (the byte-for-byte equality to the hand-written form is asserted in
//!    the pure unit battery; here it must actually run on a real engine).
//!
//! `CREATE EXTENSION vector` is the operator-allowlisted precondition (§8) — run here by the
//! superuser, NEVER by the builder (which has no op that emits it). Requires `BOATRAMP_TEST_PG_URL`
//! = a **pgvector** superuser URL (skips cleanly when unset). Prints
//! `DDL BUILDER TENANT-SCOPED KNN OK [postgres]` and `DDL BUILDER HNSW INDEX SCAN OK [postgres]`
//! (the CI grep markers).
#![cfg(feature = "sql-postgres")]

use boatramp_core::ddl::{
    ColumnDef, ColumnType, CreateIndex, CreateTable, Ddl, IndexColumn, IndexMethod, ScalarDefault,
    TableConstraint, TenantScope,
};
use boatramp_core::orm::Metric;
use boatramp_core::sql::{Dialect, SqlValue};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{grant_app_role_ddl, provision_ddl};

const DB: &str = "ddl_appdb";
const ROLE: &str = "ddl_role";
const ROLE_PW: &str = "rolepw";
const OWNER: &str = "ddl_owner";
const OWNER_PW: &str = "0wnerpw";
const GUC: &str = "app.tenant_id";
const PROBE: &str = "[0,0,1]"; // nearest tenant B's rows; orthogonal to tenant A's.

/// Rewrite a superuser URL to connect as `user`/`pw` to database `db` (the harness pattern).
fn as_role(su_url: &str, user: &str, pw: &str, db: &str) -> String {
    let (scheme, rest) = su_url.split_once("://").expect("url has scheme");
    let after_at = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
    let (hostport, _tail) = after_at.split_once('/').unwrap_or((after_at, ""));
    format!("{scheme}://{user}:{pw}@{hostport}/{db}")
}

/// The tenant-scoped `embeddings` table, built ENTIRELY through the typed `ddl` builder.
fn embeddings_table() -> Ddl {
    Ddl::CreateTable(CreateTable {
        table: "embeddings".into(),
        if_not_exists: false,
        columns: vec![
            ColumnDef {
                name: "id".into(),
                ty: ColumnType::Uuid,
                nullable: false,
                default: Some(ScalarDefault::GenRandomUuid),
            },
            ColumnDef::new("tenant_id", ColumnType::Text),
            ColumnDef::new("embedding", ColumnType::Vector { dim: 3 }),
            ColumnDef {
                name: "content".into(),
                ty: ColumnType::Text,
                nullable: true,
                default: None,
            },
        ],
        constraints: vec![TableConstraint::PrimaryKey {
            columns: vec!["id".into()],
        }],
        tenant_scope: Some(TenantScope {
            tenant_column: "tenant_id".into(),
            guc: GUC.into(),
            policy: "tenant_isolation".into(),
        }),
    })
}

/// The hnsw `vector_cosine_ops` index, built through the typed `ddl` builder.
fn embeddings_index() -> Ddl {
    Ddl::CreateIndex(CreateIndex {
        name: "embeddings_embedding_hnsw".into(),
        table: "embeddings".into(),
        method: IndexMethod::Hnsw,
        columns: vec![IndexColumn::vector("embedding", Metric::Cosine)],
        unique: false,
        if_not_exists: false,
        concurrently: false,
    })
}

#[tokio::test]
async fn ddl_builder_tenant_scoped_vector_is_correct_on_real_pgvector() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip ddl_builder_sqlx_live: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let su = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_url.clone()),
    )
    .unwrap();

    // --- teardown any prior run (re-runnable). ---
    for stmt in [
        &format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"),
        &format!("DROP ROLE IF EXISTS \"{ROLE}\""),
        &format!("DROP ROLE IF EXISTS \"{OWNER}\""),
    ] {
        let _ = su.run_script(stmt).await;
    }

    // --- setup: the REAL three-identity provisioning model (owner + runtime roles + DB). ---
    for stmt in provision_ddl(
        ExternalSqlKind::Postgres,
        DB,
        ROLE,
        ROLE_PW,
        OWNER,
        OWNER_PW,
        false,
    ) {
        su.run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("provision `{stmt}`: {e}"));
    }
    let su_tenant_url = {
        let (scheme, rest) = su_url.split_once("://").unwrap();
        let (creds, after) = rest.split_once('@').unwrap();
        let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
        format!("{scheme}://{creds}@{hostport}/{DB}")
    };
    let su_tenant = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_tenant_url),
    )
    .unwrap();
    for stmt in grant_app_role_ddl(ExternalSqlKind::Postgres, ROLE, OWNER) {
        su_tenant
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("grant `{stmt}`: {e}"));
    }
    // The extension is the operator-allowlisted precondition (§8), NEVER emitted by the builder.
    su_tenant
        .run_script("CREATE EXTENSION IF NOT EXISTS vector")
        .await
        .expect("operator enables pgvector (the builder never emits CREATE EXTENSION)");

    // --- apply the BUILDER's DDL as the non-superuser OWNER role (the migration-seam altitude). ---
    let owner = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(as_role(&su_url, OWNER, OWNER_PW, DB)),
    )
    .unwrap();
    let table_sql = embeddings_table().emit(Dialect::Postgres).unwrap().sql;
    owner.run_script(&table_sql).await.unwrap_or_else(|e| {
        panic!("builder tenant-scoped CREATE TABLE must apply: {e}\n{table_sql}")
    });
    let index_sql = embeddings_index().emit(Dialect::Postgres).unwrap().sql;
    owner
        .run_script(&index_sql)
        .await
        .unwrap_or_else(|e| panic!("builder hnsw CREATE INDEX must apply: {e}\n{index_sql}"));

    // --- seed two tenants in ONE shared keyspace, as the SUPERUSER (bypasses RLS). Tenant B's
    //     vectors are placed NEAREST the probe, so a broken isolation would surface B's rows. ---
    su_tenant
        .run_script(
            "INSERT INTO embeddings (tenant_id, content, embedding) VALUES \
             ('A','a-own-1','[1,0,0]'),('A','a-own-2','[0.9,0.1,0]'),('A','a-own-3','[0.8,0,0.2]'), \
             ('B','b-secret-1','[0,0,1]'),('B','b-secret-2','[0.05,0,0.95]'),('B','b-secret-3','[0,0.05,0.95]')",
        )
        .await
        .expect("seed both tenants");

    // --- (1) tenant-scoped kNN as the NON-SUPERUSER runtime role → ZERO foreign rows. ---
    let app = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(as_role(&su_url, ROLE, ROLE_PW, DB)),
    )
    .unwrap();

    for tenant in ["A", "B"] {
        let mut tx = app.begin().await.unwrap();
        tx.execute(
            &format!("SELECT set_config('{GUC}', '{tenant}', true)"),
            &[],
        )
        .await
        .unwrap();
        let rows = tx
            .query(
                &format!(
                    "SELECT tenant_id FROM embeddings ORDER BY embedding <=> '{PROBE}'::vector LIMIT 100"
                ),
                &[],
            )
            .await
            .expect("tenant-scoped kNN runs");
        assert!(
            !rows.rows.is_empty(),
            "tenant {tenant} must see its OWN nearest rows"
        );
        for r in &rows.rows {
            assert_eq!(
                r[0],
                SqlValue::Text(tenant.into()),
                "kNN for tenant {tenant} leaked a FOREIGN row — the emitted RLS policy failed to isolate the shared vector keyspace"
            );
        }
        tx.commit().await.unwrap();
    }

    // Unset tenant GUC ⇒ the policy fails closed (zero rows), never the whole table.
    {
        let mut tx = app.begin().await.unwrap();
        let rows = tx
            .query(
                &format!(
                    "SELECT tenant_id FROM embeddings ORDER BY embedding <=> '{PROBE}'::vector LIMIT 100"
                ),
                &[],
            )
            .await
            .unwrap();
        assert!(
            rows.rows.is_empty(),
            "an unset tenant GUC must fail closed (zero rows), got {} rows",
            rows.rows.len()
        );
        tx.commit().await.unwrap();
    }
    println!("DDL BUILDER TENANT-SCOPED KNN OK [postgres]");

    // --- (2) the builder's hnsw vector_cosine_ops index is USED (Index Scan, not Seq Scan). As the
    //     superuser (RLS-exempt), so the plan is the clean index scan; enable_seqscan off makes the
    //     planner pick the index iff the metric→opclass coupling is correct (a mismatch is unusable). ---
    {
        let mut tx = su_tenant.begin().await.unwrap();
        tx.execute("SET LOCAL enable_seqscan = off", &[])
            .await
            .unwrap();
        let plan = tx
            .query(
                &format!(
                    "EXPLAIN SELECT id FROM embeddings ORDER BY embedding <=> '{PROBE}'::vector LIMIT 5"
                ),
                &[],
            )
            .await
            .expect("EXPLAIN runs");
        let text: String = plan
            .rows
            .iter()
            .flatten()
            .filter_map(|v| match v {
                SqlValue::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("embeddings_embedding_hnsw"),
            "the kNN must use the builder's hnsw index, got plan:\n{text}"
        );
        assert!(
            text.contains("Index Scan"),
            "the kNN plan must be an Index Scan, got:\n{text}"
        );
        assert!(
            !text.contains("Seq Scan"),
            "the kNN must NOT seq-scan (a metric/opclass mismatch would), got:\n{text}"
        );
        tx.commit().await.unwrap();
    }
    println!("DDL BUILDER HNSW INDEX SCAN OK [postgres]");

    // Teardown (best-effort).
    let _ = su
        .run_script(&format!("DROP DATABASE IF EXISTS \"{DB}\" WITH (FORCE)"))
        .await;
    let _ = su
        .run_script(&format!("DROP ROLE IF EXISTS \"{ROLE}\""))
        .await;
    let _ = su
        .run_script(&format!("DROP ROLE IF EXISTS \"{OWNER}\""))
        .await;
}
