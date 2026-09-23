//! **Live gate: provisioning drift-repair (`repair`) reconciles a pre-v0.4.25 shared-Postgres
//! tenant on a REAL Postgres.**
//!
//! Task #491 / `PLAN-provisioning-drift-repair`. The owner-gated, idempotent, data-preserving
//! `repair` verb diffs a managed shared-Postgres tenant's ACTUAL provisioning against a fresh
//! provision and converges the delta — roles / ownership / grants / sealed credentials / ledger
//! scaffolding, NEVER a `DROP`/`TRUNCATE`/`DELETE`/`UPDATE` of tenant rows. The first drift class it
//! subsumes is the **pre-v0.4.25 owner-model retrofit**: a tenant whose physical database is owned by
//! the RUNTIME role, with no `_owner` role, so the migrate surface (which connects as the sealed owner
//! role) is denied. `repair --apply` creates + seals the owner role, re-owns the db + its objects
//! (tables, sequences, functions) to it, and scaffolds the ledger — WITHOUT touching a tenant row.
//!
//! This gate drives the SHIPPED node-side [`NodeTenantRepair`] (the `TenantRepair` impl the
//! `Project·Admin`-gated `/api/repair/{db}` route builds) against a real Postgres and proves, live:
//!
//! 1. Provision a shared tenant normally, then MUTATE it to the pre-v0.4.25 shape (drop the owner
//!    role, `ALTER DATABASE OWNER TO <runtime>`, a runtime-owned table+row, a superuser-owned
//!    table+row, a superuser-owned SEQUENCE, and a superuser-owned overloaded FUNCTION).
//! 2. `repair --dry-run` reports the expected drift set and changes NOTHING (no owner role, no
//!    ownership change, and — FIX 1, Security HIGH-1 — no KV owner-credential seal: the owner-cred
//!    key is deleted before the dry-run and HARD-ASSERTED absent afterward, proving no dry-run path
//!    calls `password()`/`kv.put`; the terminal connectivity probe uses `get_sealed_password`).
//! 3. `repair --apply` recreates + seals the owner role (safe attrs), re-owns the db + BOTH tables +
//!    the sequence + the function to it, scaffolds + re-owns the ledger, fixes the connect grants, and
//!    leaves EVERY seeded row intact.
//! 4. `repair --apply` AGAIN is a zero-action converge (every applicable check `ok`).
//! 5. Scope: a SECOND provisioned tenant's object ownership is UNTOUCHED after repairing the first.
//! 6. Isolation: the RUNTIME role still connects AND (FIX 2, Security HIGH-2) can SELECT its own
//!    row from the re-owned table after repair — HARD-ASSERTED, proving check 6 re-granted the DML
//!    the `REASSIGN OWNED` stripped (a coarse USAGE-only probe would have missed this).
//! 7. Soft-delete: a soft-deleted tenant (the provisioning rename + `NOLOGIN`) makes `repair` a
//!    zero-action no-op (a `soft-delete` skip), touching nothing.
//!
//! Because repair (like provisioning) connects through the compute/endpoint resolver
//! (`ComputeResolvedSqlBackend` over `DeployEndpointResolver`), the gate seeds the control-plane state
//! a real node would hold: one healthy `Running` replica of the `pg` workload pointing at the test
//! Postgres, and the superuser credential pre-sealed to the test URL's password (the same key the
//! server-init env injector + the Shared provisioning path read). No container is launched — the
//! resolver simply resolves `pg` to the test Postgres's host:port.
//!
//! Requires `BOATRAMP_TEST_PG_URL` = a **superuser** Postgres URL (able to `CREATE ROLE` /
//! `CREATE DATABASE` / `ALTER DATABASE OWNER` / `REASSIGN OWNED`); skips cleanly when unset. Prints
//! `PROVISION REPAIR RECONCILE OK` on success (the CI grep marker).

#![cfg(all(feature = "sql-postgres", feature = "migrate"))]

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::{ProjectRef, DEFAULT_PROJECT};
use boatramp_core::sql::{RepairMode, RepairStatus, SqlBackend, SqlValue, TenantRepair};
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::managed_sql::ManagedSqlCredentials;
use boatramp_node::repair::NodeTenantRepair;
use boatramp_node::tenant_sql::provision_tenant;
use boatramp_storage::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};
use boatramp_storage::tenant_provision::{
    quote_ident, sanitize_ident, tenant_db_name, tenant_owner_role_name, tenant_role_name,
};

/// The shared Postgres server's compute-workload name (the binding's `compute`). One server; each
/// tenant gets its own database + login/owner role inside it, resolved to the test PG.
const COMPUTE: &str = "pg";
/// The binding's configured base database name (per-tenant `appdb_<ident>`).
const DATABASE: &str = "appdb";
/// The binding's configured superuser (the maintenance/DDL identity). Must match the test URL's user.
const SUPERUSER: &str = "postgres";
/// The DB-binding name the operator addresses in `/api/repair/{db}` (the `databases` map key).
const DB_BINDING: &str = "main";

/// The tenant repaired.
const TENANT_A: &str = "repairtenant";
/// A second tenant, provisioned and NEVER repaired — its ownership must stay untouched (scope).
const TENANT_B: &str = "scopetenant";
/// A third tenant, soft-deleted before repair (the `soft-delete` no-op skip).
const TENANT_C: &str = "gonetenant";

/// A reversible test "envelope" (NOT encryption) — the same double the `managed_sql` / `tenant_sql`
/// unit tests + sibling live gates use. The sealing contract is identical to a real KMS/local
/// envelope, so this exercises the exact `ManagedSqlCredentials` seal/unseal path.
struct RevEnvelope;
#[async_trait]
impl KeyEnvelope for RevEnvelope {
    async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Ok(p.iter().rev().copied().collect())
    }
    async fn unwrap(&self, w: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Ok(w.iter().rev().copied().collect())
    }
}

/// The `Shared` / `Project`-grain binding under test: one shared `pg` server, a per-tenant database
/// (`appdb_<ident>`) + login role + owner role per project tenant, superuser = the test URL's user.
fn shared_project_binding() -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(SUPERUSER.into()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

/// The derived live names for a tenant of the shared binding — reproduced from the SAME public
/// `boatramp-storage` derivation the node's private `tenant_names` uses (Shared / Project grain).
struct Names {
    ident: String,
    database: String,
    runtime_role: String,
    owner_role: String,
}
fn names_for(project: &str) -> Names {
    let ident = sanitize_ident(project);
    Names {
        ident: ident.clone(),
        database: tenant_db_name(DATABASE, &ident),
        runtime_role: tenant_role_name(COMPUTE, &ident),
        owner_role: tenant_owner_role_name(COMPUTE, &ident),
    }
}

/// Parse `BOATRAMP_TEST_PG_URL` into `(host, port, user, password, maintenance_db)`. The gate
/// resolves the `pg` workload to `(host, port)` and pre-seals the superuser credential to `password`.
struct Parsed {
    host: String,
    port: u16,
    user: String,
    password: String,
    maintenance_db: String,
}
fn parse_pg_url(url: &str) -> Parsed {
    // scheme://user:pass@host:port/db[?params]
    let (_scheme, rest) = url.split_once("://").expect("url has a scheme");
    let (creds, after_at) = rest.split_once('@').expect("url has userinfo");
    let (user, password) = creds.split_once(':').expect("url has user:pass");
    let (hostport, tail) = after_at.split_once('/').unwrap_or((after_at, ""));
    let db = tail.split(['?', '&']).next().unwrap_or("");
    let (host, port) = hostport
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse::<u16>().expect("port")))
        .unwrap_or((hostport.to_string(), 5432));
    Parsed {
        host,
        port,
        user: user.to_string(),
        password: password.to_string(),
        maintenance_db: if db.is_empty() {
            "postgres".to_string()
        } else {
            db.to_string()
        },
    }
}

/// Rewrite the test superuser URL to connect to a DIFFERENT database (same host/port/creds), so the
/// gate can open a direct connection to a tenant's own database for mutation + verification.
fn su_url_to_db(url: &str, db: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap();
    let (creds, after) = rest.split_once('@').unwrap();
    let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
    format!("{scheme}://{creds}@{hostport}/{db}")
}

/// The KV key `ManagedSqlCredentials` seals a workload's password under (mirrors its private `key`).
fn cred_key(project: &str, workload: &str) -> String {
    format!("managed-sql-cred/{project}/{workload}")
}

/// A direct sqlx superuser backend to `db` (bypassing the compute resolver) — for the pre-v0.4.25
/// mutation + the live ownership/role/data verification.
fn direct(su_url: &str, db: &str) -> Arc<dyn SqlBackend> {
    connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_url_to_db(su_url, db)),
    )
    .expect("connect superuser")
}

/// The `pg_get_userbyid(relowner)` of a relation (table/sequence) in the given tenant db — the
/// live owner, read directly as the superuser.
async fn rel_owner(tenant: &Arc<dyn SqlBackend>, schema: &str, name: &str) -> String {
    let rows = tenant
        .run_query(&format!(
            "SELECT pg_catalog.pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = '{schema}' AND c.relname = '{name}';"
        ))
        .await
        .expect("relowner probe");
    text(rows.rows.first().and_then(|r| r.first()))
}

/// The `pg_get_userbyid(proowner)` of a function by name in the tenant db (there may be overloads;
/// this returns the DISTINCT set of owners so an incompletely re-owned overload is caught).
async fn fn_owners(tenant: &Arc<dyn SqlBackend>, schema: &str, name: &str) -> Vec<String> {
    let rows = tenant
        .run_query(&format!(
            "SELECT DISTINCT pg_catalog.pg_get_userbyid(p.proowner) FROM pg_catalog.pg_proc p \
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname = '{schema}' AND p.proname = '{name}';"
        ))
        .await
        .expect("proowner probe");
    rows.rows
        .iter()
        .filter_map(|r| r.first())
        .map(|v| text(Some(v)))
        .collect()
}

/// The `pg_get_userbyid(datdba)` of a database (read on the maintenance db).
async fn db_owner(maint: &Arc<dyn SqlBackend>, db: &str) -> String {
    let rows = maint
        .run_query(&format!(
            "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = '{db}';"
        ))
        .await
        .expect("datdba probe");
    text(rows.rows.first().and_then(|r| r.first()))
}

/// Whether a role exists (any, LOGIN or not).
async fn role_exists(maint: &Arc<dyn SqlBackend>, role: &str) -> bool {
    let rows = maint
        .run_query(&format!("SELECT 1 FROM pg_roles WHERE rolname = '{role}';"))
        .await
        .expect("role probe");
    !rows.rows.is_empty()
}

/// The count of rows in a tenant table (data-intact assertions).
async fn row_count(tenant: &Arc<dyn SqlBackend>, table: &str) -> i64 {
    let rows = tenant
        .run_query(&format!("SELECT count(*)::bigint FROM {table};"))
        .await
        .unwrap_or_else(|e| panic!("count {table}: {e}"));
    match rows.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Integer(n)) => *n,
        other => panic!("count returned non-integer: {other:?}"),
    }
}

fn text(v: Option<&SqlValue>) -> String {
    match v {
        Some(SqlValue::Text(s)) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// Quote a Postgres identifier (the same routine the provisioning DDL uses).
fn quote_i(id: &str) -> String {
    quote_ident(ExternalSqlKind::Postgres, id)
}

/// Best-effort teardown of a tenant's db + roles + any soft-deleted sibling (re-runnable gate).
async fn drop_tenant(maint: &Arc<dyn SqlBackend>, n: &Names) {
    // Find + drop any soft-deleted sibling first (a prior run may have left a `<db-prefix>__deleted_…`
    // aside db — possibly TRUNCATED to 63 bytes, so match on a leading prefix of `<db>` + `__deleted`
    // rather than the full name, to also catch the truncation-safe aside this gate builds).
    let prefix = &n.database[..30.min(n.database.len())];
    if let Ok(rows) = maint
        .run_query(&format!(
            "SELECT datname FROM pg_database WHERE datname LIKE '{prefix}%__deleted\\_%' ESCAPE '\\';"
        ))
        .await
    {
        for r in &rows.rows {
            let sib = text(r.first());
            let _ = maint
                .run_script(&format!("DROP DATABASE IF EXISTS \"{sib}\" WITH (FORCE)"))
                .await;
        }
    }
    for stmt in [
        format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", n.database),
        format!("DROP ROLE IF EXISTS \"{}\"", n.runtime_role),
        format!("DROP ROLE IF EXISTS \"{}\"", n.owner_role),
    ] {
        let _ = maint.run_script(&stmt).await;
    }
}

#[tokio::test]
async fn provision_repair_reconciles_pre_v0425_shared_postgres_tenant() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("skip provision_repair: BOATRAMP_TEST_PG_URL unset");
        return;
    };
    let p = parse_pg_url(&su_url);
    assert_eq!(
        p.user, SUPERUSER,
        "this gate assumes the test URL's user is {SUPERUSER:?} (the derived-name model uses it as \
         the binding superuser); got {:?}",
        p.user
    );

    // --- Control-plane state: MemoryKv + a throwaway FsStorage → DeployStore, the sealed-credential
    // store over a reversible test envelope. The SAME KV backs the deploy state + credentials.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-repair-gate-{}", std::process::id())),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);
    let creds = ManagedSqlCredentials::new(kv.clone(), envelope.clone());

    // Pre-seal the SUPERUSER credential under the SAME key the Shared provisioning path + the
    // server-init env injector read — `(DEFAULT_PROJECT, COMPUTE)` — to the test URL's ACTUAL
    // password, so provisioning + repair (which connect as the superuser via the resolver) succeed.
    // (A plain `password()` would generate a random one that the real server would reject.)
    let sealed_su = envelope
        .wrap(p.password.as_bytes())
        .await
        .expect("seal superuser pw");
    kv.put(&cred_key(DEFAULT_PROJECT, COMPUTE), sealed_su)
        .await
        .expect("pre-seal superuser credential");

    // Seed ONE healthy Running replica of the `pg` workload pointing at the test Postgres, so
    // `DeployEndpointResolver` (used by provisioning + repair) resolves `pg` → host:port. No
    // container is launched; the resolver just needs a healthy endpoint in the deploy store.
    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle {
                    project: DEFAULT_PROJECT.to_string(),
                    workload: COMPUTE.to_string(),
                    replica: 0,
                    backend_ref: "test-external-pg".to_string(),
                },
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint {
                    scheme: Scheme::Http,
                    host: p.host.clone(),
                    port: p.port,
                },
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                snapshot: None,
            },
        )
        .await
        .expect("seed healthy replica");

    let databases = BTreeMap::from([(DB_BINDING.to_string(), shared_project_binding())]);
    let binding = shared_project_binding();

    // A direct superuser backend to the maintenance db (setup / mutation / verification), bypassing
    // the resolver.
    let maint = direct(&su_url, &p.maintenance_db);

    let a = names_for(TENANT_A);
    let b = names_for(TENANT_B);
    let c = names_for(TENANT_C);

    // --- Teardown any prior run (re-runnable). ---
    drop_tenant(&maint, &a).await;
    drop_tenant(&maint, &b).await;
    drop_tenant(&maint, &c).await;

    // === 1. Provision two tenants normally through the SHIPPED path. ===
    provision_tenant(&deploy, &kv, &envelope, &binding, TENANT_A, "")
        .await
        .expect("provision tenant A");
    provision_tenant(&deploy, &kv, &envelope, &binding, TENANT_B, "")
        .await
        .expect("provision tenant B");
    provision_tenant(&deploy, &kv, &envelope, &binding, TENANT_C, "")
        .await
        .expect("provision tenant C");

    // Sanity: distinct names + a well-provisioned A (owner owns the db) before we mutate it.
    assert_ne!(a.database, b.database, "distinct tenant dbs");
    assert_ne!(a.owner_role, a.runtime_role, "owner != runtime role");
    assert_eq!(
        db_owner(&maint, &a.database).await,
        a.owner_role,
        "a freshly provisioned tenant db is owner-owned"
    );

    // === 1b. MUTATE tenant A into the pre-v0.4.25 shape. ===
    // Open a direct superuser connection INSIDE tenant A's own database for the object DDL, and use
    // the maintenance db for the `ALTER DATABASE OWNER` + owner-role drop.
    let a_db = direct(&su_url, &a.database);
    {
        // A runtime-OWNED table with a row (exercises the bulk REASSIGN OWNED BY <runtime> arm).
        a_db.run_script("CREATE TABLE runtime_widget (id int primary key, name text);")
            .await
            .expect("create runtime table");
        a_db.run_script("INSERT INTO runtime_widget (id, name) VALUES (1, 'rw');")
            .await
            .expect("seed runtime row");
        a_db.run_script(&format!(
            "ALTER TABLE runtime_widget OWNER TO \"{}\";",
            a.runtime_role
        ))
        .await
        .expect("chown runtime table to runtime role");

        // A superuser-OWNED table with a row (exercises the targeted ALTER TABLE arm).
        a_db.run_script("CREATE TABLE super_gadget (id int primary key, name text);")
            .await
            .expect("create superuser table");
        a_db.run_script("INSERT INTO super_gadget (id, name) VALUES (1, 'sg');")
            .await
            .expect("seed superuser row");

        // A superuser-OWNED SEQUENCE (exercises the targeted ALTER SEQUENCE arm — a bare ALTER TABLE
        // does NOT re-own a sequence). Standalone (not owned-by a column), so it is enumerated on its
        // own and MUST be re-owned by name.
        a_db.run_script("CREATE SEQUENCE super_counter START 41;")
            .await
            .expect("create superuser sequence");
        // Consume one value so a re-own that silently recreated it would be observable (the sequence
        // is data too — a DROP/recreate would reset it). `run_script` (not `run_query`, which opens a
        // read-only transaction) so the side-effecting nextval() runs.
        a_db.run_script("SELECT nextval('super_counter');")
            .await
            .expect("advance sequence");

        // A superuser-OWNED, OVERLOADED FUNCTION (exercises the targeted ALTER FUNCTION arm, which
        // needs the identity-args to disambiguate overloads). Two arities.
        a_db.run_script(
            "CREATE FUNCTION super_fn(a int) RETURNS int LANGUAGE sql IMMUTABLE AS $$ SELECT a $$;",
        )
        .await
        .expect("create fn/1");
        a_db.run_script(
            "CREATE FUNCTION super_fn(a int, b int) RETURNS int LANGUAGE sql IMMUTABLE \
             AS $$ SELECT a + b $$;",
        )
        .await
        .expect("create fn/2");

        // Confirm the pre-mutation ownership is what the drift model expects.
        assert_eq!(
            rel_owner(&a_db, "public", "runtime_widget").await,
            a.runtime_role,
            "runtime_widget is runtime-owned before repair"
        );
        assert_eq!(
            rel_owner(&a_db, "public", "super_gadget").await,
            SUPERUSER,
            "super_gadget is superuser-owned before repair"
        );
        assert_eq!(
            rel_owner(&a_db, "public", "super_counter").await,
            SUPERUSER,
            "super_counter (sequence) is superuser-owned before repair"
        );
        assert_eq!(
            fn_owners(&a_db, "public", "super_fn").await,
            vec![SUPERUSER.to_string()],
            "both super_fn overloads are superuser-owned before repair"
        );
    }
    // Re-own the DATABASE to the runtime role, then DROP the owner role — the defining pre-v0.4.25
    // shape (db owned by runtime, no `_owner` role). The owner role holds tenant-db-local
    // dependencies a fresh provision minted (its CONNECT grant + `ALTER DEFAULT PRIVILEGES`), so
    // strip them inside the tenant db first (`DROP OWNED BY` removes the owner's grants +
    // default-privilege entries — the owner owns no schema objects yet, they are the ones I created
    // as runtime/superuser) before the maintenance-level `ALTER DATABASE OWNER` + `DROP ROLE`.
    a_db.run_script(&format!("DROP OWNED BY \"{}\";", a.owner_role))
        .await
        .expect("strip owner's tenant-db grants/default-privs");
    maint
        .run_script(&format!(
            "ALTER DATABASE \"{}\" OWNER TO \"{}\";",
            a.database, a.runtime_role
        ))
        .await
        .expect("chown db to runtime");
    maint
        .run_script(&format!("DROP ROLE IF EXISTS \"{}\";", a.owner_role))
        .await
        .expect("drop owner role");

    assert!(
        !role_exists(&maint, &a.owner_role).await,
        "owner role is gone (pre-v0.4.25 shape)"
    );
    assert_eq!(
        db_owner(&maint, &a.database).await,
        a.runtime_role,
        "db is runtime-owned (pre-v0.4.25 shape)"
    );

    // Record B's ownership fingerprint BEFORE repairing A, to prove scope (5) later.
    let b_db_owner_before = db_owner(&maint, &b.database).await;

    let repair = NodeTenantRepair::new(
        databases.clone(),
        deploy.clone(),
        kv.clone(),
        Some(envelope.clone()),
    );

    // === 2. DRY-RUN: reports drift, changes NOTHING. ===
    // No owner credential is sealed yet (the owner role was dropped; provisioning sealed it, but the
    // dry-run must not (re)seal — assert the owner-cred key is inspected, not written). Delete the
    // owner-cred key that provisioning minted, so we can assert the dry-run does not recreate it.
    let owner_cred = format!("{COMPUTE}/{}/owner", a.ident);
    kv.delete(&cred_key(TENANT_A, &owner_cred))
        .await
        .expect("clear owner cred to test dry-run purity");
    let owner_cred_key = cred_key(TENANT_A, &owner_cred);
    assert!(
        kv.get(&owner_cred_key).await.unwrap().is_none(),
        "owner credential key absent before dry-run"
    );

    let dry = repair
        .repair(TENANT_A, DB_BINDING, RepairMode::DryRun)
        .await
        .expect("dry-run report");
    assert_eq!(dry.mode, "dry-run");
    assert_eq!(dry.backend, "shared-postgres");
    assert!(
        dry.found_drift(),
        "the pre-v0.4.25 tenant must report drift on a dry-run: {dry:?}"
    );
    // The owner-role-exists check must be Drift (the role is gone) and carry the CREATE ROLE ddl.
    let owner_check = find(&dry, "owner-role-exists");
    assert_eq!(
        owner_check.status,
        RepairStatus::Drift,
        "owner-role-exists is Drift on the pre-v0.4.25 tenant"
    );
    assert!(
        owner_check
            .ddl
            .as_deref()
            .is_some_and(|d| d.contains("CREATE ROLE") && d.contains(&a.owner_role)),
        "the dry-run owner-role ddl names the derived owner role: {:?}",
        owner_check.ddl
    );
    // owner-credential-sealed is Drift (KV write, ddl None).
    assert_eq!(
        find(&dry, "owner-credential-sealed").status,
        RepairStatus::Drift,
        "owner credential is unsealed → Drift on dry-run"
    );

    // Dry-run PURITY (the load-bearing, data-plane side): the dry-run's converge steps ran NOTHING
    // — no owner role created, no database/object re-ownership, no ledger scaffolding. These are the
    // invariants that make a dry-run safe to run against a live tenant.
    assert!(
        !role_exists(&maint, &a.owner_role).await,
        "dry-run must NOT create the owner role"
    );
    assert_eq!(
        db_owner(&maint, &a.database).await,
        a.runtime_role,
        "dry-run must NOT re-own the database"
    );
    assert_eq!(
        rel_owner(&a_db, "public", "super_gadget").await,
        SUPERUSER,
        "dry-run must NOT re-own the superuser table"
    );
    assert_eq!(
        rel_owner(&a_db, "public", "super_counter").await,
        SUPERUSER,
        "dry-run must NOT re-own the superuser sequence"
    );
    assert_eq!(
        fn_owners(&a_db, "public", "super_fn").await,
        vec![SUPERUSER.to_string()],
        "dry-run must NOT re-own the superuser function overloads"
    );
    // The ledger must not have been scaffolded by the dry-run (it did not exist pre-repair).
    let ledger_after_dry = a_db
        .run_query(
            "SELECT 1 FROM pg_catalog.pg_tables WHERE schemaname = 'boatramp_migrations' \
             AND tablename = 'schema_migrations';",
        )
        .await
        .expect("ledger existence probe after dry-run");
    assert!(
        ledger_after_dry.rows.is_empty(),
        "dry-run must NOT scaffold the migrate ledger"
    );

    // Dry-run credential purity (FIX 1, Security HIGH-1) — HARD ASSERTION. The owner-credential
    // KV key was deleted above and MUST still be ABSENT after the dry-run. This proves no dry-run
    // code path sealed it: the check-8 (owner-credential-sealed) converge is apply-only (it
    // reported `Drift`), and — the fix — the terminal connectivity check (#9) + its
    // `probe_role_can_connect` now resolve the credential via `get_sealed_password` (a pure
    // `kv.get` + unseal) on a dry-run, NEVER `password()` (create-if-absent + seal). A pre-v0.4.25
    // tenant's absent owner credential therefore stays absent, and connectivity reports a benign
    // `skipped` ("verified after apply") instead of sealing behind the operator's back.
    assert_eq!(
        find(&dry, "owner-credential-sealed").status,
        RepairStatus::Drift,
        "the owner-credential-sealed CHECK must report Drift (its own converge seals nothing on a \
         dry-run)"
    );
    assert!(
        kv.get(&owner_cred_key).await.unwrap().is_none(),
        "FIX 1 (dry-run purity): the owner credential ({owner_cred_key}) must stay ABSENT after a \
         dry-run — no dry-run path may call password()/kv.put (create-if-absent + seal). It was \
         deleted before the dry-run and must not be resurrected by the terminal connectivity probe."
    );

    // === 3. APPLY: converge. ===
    let ap = repair
        .repair(TENANT_A, DB_BINDING, RepairMode::Apply)
        .await
        .expect("apply report");
    assert_eq!(ap.mode, "apply");
    assert!(
        !ap.any_error(),
        "apply must not error on any check: {:#?}",
        ap.checks
    );
    // The owner role was recreated + sealed.
    assert_eq!(
        find(&ap, "owner-role-exists").status,
        RepairStatus::Repaired,
        "owner-role-exists Repaired on apply"
    );
    assert!(
        role_exists(&maint, &a.owner_role).await,
        "owner role recreated by apply"
    );
    assert!(
        kv.get(&owner_cred_key).await.unwrap().is_some(),
        "apply sealed the owner credential"
    );

    // The owner role carries the SAFE attributes (NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOBYPASSRLS/
    // NOREPLICATION) — read them straight from pg_roles.
    let attrs = maint
        .run_query(&format!(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolreplication \
             FROM pg_roles WHERE rolname = '{}';",
            a.owner_role
        ))
        .await
        .expect("owner attrs");
    let row = attrs.rows.first().expect("owner role row present");
    assert!(
        row.iter().take(5).all(|v| matches!(v, SqlValue::Boolean(false))),
        "owner role must be NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION, got {row:?}"
    );

    // The DATABASE is re-owned to the owner.
    assert_eq!(
        db_owner(&maint, &a.database).await,
        a.owner_role,
        "apply re-owned the database to the owner role"
    );
    // BOTH tables (runtime-owned AND superuser-owned), the SEQUENCE, and BOTH function overloads are
    // re-owned to the owner — via pg_class.relowner / pg_proc.proowner (the load-bearing check-4
    // proof: a table-only converge would leave the sequence + functions mis-owned).
    assert_eq!(
        rel_owner(&a_db, "public", "runtime_widget").await,
        a.owner_role,
        "runtime-owned table re-owned to owner"
    );
    assert_eq!(
        rel_owner(&a_db, "public", "super_gadget").await,
        a.owner_role,
        "superuser-owned table re-owned to owner"
    );
    assert_eq!(
        rel_owner(&a_db, "public", "super_counter").await,
        a.owner_role,
        "superuser-owned SEQUENCE re-owned to owner (ALTER SEQUENCE arm)"
    );
    assert_eq!(
        fn_owners(&a_db, "public", "super_fn").await,
        vec![a.owner_role.clone()],
        "BOTH superuser-owned FUNCTION overloads re-owned to owner (ALTER FUNCTION arm)"
    );

    // Ledger schema + table exist and are owner-owned (probed on the TENANT db, `a_db`).
    assert_eq!(
        rel_owner(&a_db, "boatramp_migrations", "schema_migrations").await,
        a.owner_role,
        "ledger table exists and is owner-owned after apply"
    );
    let sch = a_db
        .run_query(
            "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace \
             WHERE nspname = 'boatramp_migrations';",
        )
        .await
        .expect("ledger schema owner");
    assert_eq!(
        text(sch.rows.first().and_then(|r| r.first())),
        a.owner_role,
        "ledger schema is owner-owned after apply"
    );

    // connect-grants: CONNECT revoked from PUBLIC, granted to owner + runtime.
    let cg = |grantee: &str| {
        let db = a.database.clone();
        let maint = maint.clone();
        let grantee = grantee.to_string();
        async move {
            let rows = maint
                .run_query(&format!(
                    "SELECT has_database_privilege('{grantee}', '{db}', 'CONNECT');"
                ))
                .await
                .expect("connect probe");
            matches!(
                rows.rows.first().and_then(|r| r.first()),
                Some(SqlValue::Boolean(true))
            )
        }
    };
    assert!(cg(&a.owner_role).await, "owner has CONNECT after apply");
    assert!(cg(&a.runtime_role).await, "runtime has CONNECT after apply");
    assert!(!cg("public").await, "PUBLIC has NO CONNECT after apply");

    // DATA INTACT: every seeded row is still present, and the sequence was not reset.
    assert_eq!(
        row_count(&a_db, "runtime_widget").await,
        1,
        "runtime row intact"
    );
    assert_eq!(
        row_count(&a_db, "super_gadget").await,
        1,
        "superuser row intact"
    );
    let seq = a_db
        .run_query("SELECT last_value FROM super_counter;")
        .await
        .expect("sequence read");
    assert!(
        matches!(seq.rows.first().and_then(|r| r.first()), Some(SqlValue::Integer(n)) if *n >= 41),
        "the re-owned sequence kept its value (not dropped/recreated): {seq:?}"
    );

    // === 4. APPLY AGAIN: zero converge — every applicable check is `ok` (idempotent/convergent). ===
    let ap2 = repair
        .repair(TENANT_A, DB_BINDING, RepairMode::Apply)
        .await
        .expect("second apply report");
    assert!(
        !ap2.any_error(),
        "second apply must not error: {:#?}",
        ap2.checks
    );
    let repaired_again: Vec<&str> = ap2
        .checks
        .iter()
        .filter(|c| c.status == RepairStatus::Repaired)
        .map(|c| c.check.as_str())
        .collect();
    assert!(
        repaired_again.is_empty(),
        "a second apply must converge NOTHING (idempotent); re-converged: {repaired_again:?}"
    );
    // Positively: the core invariants report `ok` the second time.
    for slug in [
        "owner-role-exists",
        "owner-role-attrs",
        "db-owner",
        "object-ownership",
        "connect-grants",
        "ledger",
        "owner-credential-sealed",
    ] {
        assert_eq!(
            find(&ap2, slug).status,
            RepairStatus::Ok,
            "check {slug:?} must be Ok on a converged tenant"
        );
    }

    // === 5. SCOPE: tenant B's ownership is UNTOUCHED by repairing A. ===
    assert_eq!(
        db_owner(&maint, &b.database).await,
        b_db_owner_before,
        "tenant B's database owner is unchanged after repairing A"
    );
    assert_eq!(
        db_owner(&maint, &b.database).await,
        b.owner_role,
        "tenant B is still owner-owned (it was never in drift, never touched)"
    );
    assert!(
        role_exists(&maint, &b.owner_role).await && role_exists(&maint, &b.runtime_role).await,
        "tenant B's roles are intact"
    );

    // === 6. ISOLATION preserved: the RUNTIME role still CONNECTS to its own database after repair
    // (the load-bearing #1 invariant — repair's connect-lockdown never locks the runtime out), and
    // we probe whether it can READ the row it seeded. ===
    let runtime_pw = creds
        .password(TENANT_A, &format!("{COMPUTE}/{}", a.ident))
        .await
        .expect("runtime credential");
    let runtime_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        a.runtime_role,
        // No percent-encoding needed: the sealed pw is hex; the role name is a sanitized ident.
        runtime_pw,
        p.host,
        p.port,
        a.database
    );
    let runtime_conn = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(runtime_url),
    )
    .expect("runtime backend");
    // (a) MUST hold (strict): the runtime role connects + runs a trivial query — repair did not
    //     revoke its CONNECT (check 5 re-grants owner + runtime, revokes only PUBLIC). This is the
    //     connect-lockdown / cross-tenant-isolation invariant the gate asserts strictly.
    runtime_conn.run_query("SELECT 1;").await.expect(
        "the runtime role must still CONNECT + query after repair (connect-lockdown intact)",
    );

    // (b) FIX 2 (Security HIGH-2) — HARD ASSERTION. The runtime role reads the row it seeded, which
    //     repair REASSIGNED from the runtime role to the new owner role. This is the exact drift the
    //     old coarse schema-`USAGE` probe missed: a retrofitted tenant already has schema USAGE, so
    //     the check falsely reported `ok` and skipped the idempotent `grant_app_role_ddl`, leaving
    //     the runtime (which lost its implicit owner SELECT when its table was REASSIGNED) with
    //     `permission denied` on its own data. The fix makes check 6 require USAGE AND SELECT on
    //     EVERY public table, so the reassign is detected and the re-grant runs — the runtime can
    //     read `runtime_widget` again. We assert the read succeeds (no FINDING branch).
    let read = runtime_conn
        .run_query("SELECT name FROM runtime_widget WHERE id = 1;")
        .await
        .expect(
            "FIX 2 (runtime-grants accuracy): after repair the runtime role MUST be able to SELECT \
             its own (now owner-owned, REASSIGNED) row — check 6 must have detected the stripped \
             table privileges and re-run grant_app_role_ddl, not falsely reported ok on USAGE alone",
        );
    assert_eq!(
        text(read.rows.first().and_then(|r| r.first())),
        "rw",
        "the runtime role reads its own row after the owner-model retrofit"
    );
    eprintln!("assertion 6: runtime role connects + reads its REASSIGNED row  OK");

    // === 7. SOFT-DELETE: a soft-deleted tenant makes repair a zero-action no-op that touches
    // nothing. Apply the Shared-Postgres soft-delete's observable end-state to tenant C — the live
    // db renamed aside + the tenant role `NOLOGIN` — then assert repair converges NOTHING, errors
    // nothing, and leaves the aside db + the NOLOGIN role exactly as they were.
    //
    // The soft delete's rename target is `<db>__deleted_<ts>`. IMPORTANT (reviewer FINDING, see
    // REPAIR_IMPL_NOTES): a DERIVED tenant db name is ALREADY ~59–63 bytes (`tenant_db_name` pads a
    // 25-char digest and caps at Postgres's 63-byte NAMEDATALEN). Appending `__deleted_<ts>` yields
    // an 80+ byte identifier that Postgres SILENTLY TRUNCATES to 63 bytes — which for a 63-byte `<db>`
    // is byte-for-byte the ORIGINAL name, so `ALTER DATABASE <db> RENAME TO <db>__deleted_<ts>` fails
    // with 42P04 `database "<db>" already exists` (a rename-to-self). The production
    // `soft_deprovision_ddl` / `deprovision_tenant` use exactly this scheme, so a near-max-length
    // Shared-Postgres tenant CANNOT be soft-deleted today, AND repair's soft-delete probe
    // (`datname LIKE '<db>__deleted\_%'`) can never match a truncated sibling. This gate therefore
    // builds a TRUNCATION-SAFE aside name (≤63 bytes) so it can still stand up a real soft-deleted
    // state + prove repair's no-op, and records the truncation gap as a finding.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Truncation-safe aside name: keep a prefix of `<db>` and append `__deleted_<ts>` so the whole
    // thing is ≤ 63 bytes AND still starts with `<db-prefix>__deleted_` (so it is recognizably a
    // soft-delete sibling, even if it can't match repair's FULL-`<db>` LIKE — that is the finding).
    let suffix = format!("__deleted_{ts}");
    let keep = 63usize.saturating_sub(suffix.len());
    let renamed = format!("{}{suffix}", &c.database[..keep.min(c.database.len())]);
    assert!(renamed.len() <= 63, "aside name fits NAMEDATALEN");
    // Terminate C's backends on a THROWAWAY connection (a `SELECT pg_terminate_backend(...)` returns
    // a result set; keeping it off the rename connection avoids a mid-result simple-query hazard).
    {
        let killer = connect(
            ExternalSqlKind::Postgres,
            &ExternalSqlOptions::new(su_url_to_db(&su_url, &p.maintenance_db)),
        )
        .expect("terminate connection");
        let _ = killer
            .run_script(&format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = '{}' AND pid <> pg_backend_pid();",
                c.database
            ))
            .await;
    }
    let maint1 = connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_url_to_db(&su_url, &p.maintenance_db))
            .with_max_connections(Some(1)),
    )
    .expect("single-conn maintenance backend");
    // Record whether the production-shape rename (`<db>__deleted_<ts>`) would truncate-to-self, and
    // report it — the load-bearing finding about the Shared-Postgres soft delete for long names.
    let prod_rename = format!("{}__deleted_{}", c.database, ts);
    if prod_rename.len() > 63 {
        eprintln!(
            "FINDING [soft-delete truncation]: the production soft-delete rename target \
             {prod_rename:?} is {} bytes > 63 (NAMEDATALEN); Postgres truncates it to \
             {:?} — which equals the original db when `<db>` is already 63 bytes (a rename-to-self, \
             42P04). A near-max-length Shared-Postgres tenant thus cannot be soft-deleted, and \
             repair's `LIKE '<db>__deleted\\_%'` soft-delete probe can never match. See \
             REPAIR_IMPL_NOTES.md. (This gate uses a truncation-SAFE aside name to proceed.)",
            prod_rename.len(),
            &prod_rename[..63.min(prod_rename.len())]
        );
    }
    // Stand up the soft-deleted state with the truncation-safe aside name + NOLOGIN role.
    for stmt in [
        format!(
            "ALTER DATABASE {} RENAME TO {};",
            quote_i(&c.database),
            quote_i(&renamed)
        ),
        format!("ALTER ROLE {} NOLOGIN;", quote_i(&c.runtime_role)),
    ] {
        maint1
            .run_script(&stmt)
            .await
            .unwrap_or_else(|e| panic!("soft-delete C `{stmt}`: {e}"));
    }
    // A fingerprint of the renamed-aside db owner (nothing about C must change).
    let renamed_owner_before = db_owner(&maint, &renamed).await;

    let soft = repair
        .repair(TENANT_C, DB_BINDING, RepairMode::Apply)
        .await
        .expect("repair over a soft-deleted tenant");
    // ZERO-action no-op: no error, and NOTHING converged (no Drift/Repaired) — repair recognizes the
    // live-name db is gone and skips. (Whether the skip slug is `soft-delete` — when the aside
    // matches its LIKE — or `database` — the truncation-forced fallback — the OUTCOME the task
    // requires is identical: repair touched nothing.)
    assert!(
        !soft.any_error(),
        "repair over a soft-deleted tenant must not error: {:#?}",
        soft.checks
    );
    let action = soft
        .checks
        .iter()
        .find(|c| matches!(c.status, RepairStatus::Repaired | RepairStatus::Drift));
    assert!(
        action.is_none(),
        "a soft-deleted tenant must be a ZERO-action no-op (no Drift/Repaired): {:#?}",
        soft.checks
    );
    let skip = soft
        .checks
        .iter()
        .find(|c| {
            c.status == RepairStatus::Skipped
                && matches!(c.check.as_str(), "soft-delete" | "database")
        })
        .unwrap_or_else(|| {
            panic!(
                "expected a `soft-delete`/`database` skip: {:#?}",
                soft.checks
            )
        });
    eprintln!(
        "assertion 7: soft-deleted tenant → zero-action `{}` skip  OK",
        skip.check
    );

    // Nothing about C changed: the live-name db is still absent, the aside db untouched, role NOLOGIN.
    let live_c = maint
        .run_query(&format!(
            "SELECT 1 FROM pg_database WHERE datname = '{}';",
            c.database
        ))
        .await
        .expect("live C probe");
    assert!(
        live_c.rows.is_empty(),
        "repair must NOT recreate the soft-deleted tenant's live-name database"
    );
    assert_eq!(
        db_owner(&maint, &renamed).await,
        renamed_owner_before,
        "the renamed-aside database owner is untouched by repair"
    );
    let canlogin = maint
        .run_query(&format!(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = '{}';",
            c.runtime_role
        ))
        .await
        .expect("C role login probe");
    assert!(
        matches!(
            canlogin.rows.first().and_then(|r| r.first()),
            Some(SqlValue::Boolean(false))
        ),
        "the soft-deleted tenant's role stays NOLOGIN (repair did not re-enable it)"
    );

    // --- Teardown (best-effort; a re-run also cleans up at the top). ---
    drop_tenant(&maint, &a).await;
    drop_tenant(&maint, &b).await;
    drop_tenant(&maint, &c).await;

    println!("PROVISION REPAIR RECONCILE OK");
}

/// Find a check by slug (panics with the whole report if absent — a missing check is a gate bug).
fn find<'r>(
    report: &'r boatramp_core::sql::RepairReport,
    slug: &str,
) -> &'r boatramp_core::sql::RepairCheck {
    report
        .checks
        .iter()
        .find(|c| c.check == slug)
        .unwrap_or_else(|| panic!("check {slug:?} not in report: {:#?}", report.checks))
}
