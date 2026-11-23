//! **Live regression gate: the construens self-heal must NOT empty the live db (v0.59.8).**
//!
//! This is the FLIPPED construens empty-mirror gate. On v0.59.7 the existing-dest self-heal
//! (`untangle_colliding_orphan_roles`, the function the shadow-restore runs BEFORE it creates the
//! shadow + replays the dump) DESTRUCTIVELY emptied the live db up front — it soft-deprovisioned the
//! populated live db to a `__deleted_` tombstone and fresh-provisioned an EMPTY live db — so if the
//! subsequent restore then failed (for ANY reason), the tenant was stranded on an empty mirror.
//!
//! v0.59.8 makes the self-heal NON-DESTRUCTIVE to the live db: it clears the stray scratch asides and
//! reprovisions the tangled roles, but only DIVORCES the live db's ownership to the superuser (so the
//! roles can be dropped) — it never renames or empties it. The single destructive moment moves to the
//! atomic shadow swap. So immediately after the self-heal, BEFORE any restore, the live db must STILL
//! be serving its original data.
//!
//! This drives the SHIPPED self-heal directly against a real Postgres (pure sqlx — no docker,
//! deterministic) and asserts the INVARIANT: live still populated + serving, and no `__deleted_`
//! tombstone of the live db yet (the live db becomes a tombstone only at the atomic swap). Reverting
//! the fix (restoring the up-front live emptying) turns this RED. Requires `BOATRAMP_TEST_PG_URL` (a
//! superuser Postgres URL); skips cleanly when unset. Prints
//! `CONSTRUENS SELFHEAL PRESERVES LIVE OK` on success.

#![cfg(feature = "sql-postgres")]

use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{Endpoint, InstanceHandle, ObservedInstance, ReplicaPhase, Scheme};
use boatramp_core::deploy::DeployStore;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::{DEFAULT_PROJECT, ProjectRef};
use boatramp_core::sql::{SqlBackend, SqlValue};
use boatramp_node::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
use boatramp_node::tenant_sql::{
    DEFAULT_DEPROVISION_GRACE_SECS, SelfHealReport, provision_tenant,
    untangle_colliding_orphan_roles,
};
use boatramp_storage::sql_sqlx::{ExternalSqlKind, ExternalSqlOptions, connect};
use boatramp_storage::tenant_provision::{
    bounded_aside_db_name, sanitize_ident, tenant_db_name, tenant_owner_role_name, tenant_role_name,
};

const COMPUTE: &str = "pg";
const DATABASE: &str = "appdb";
/// A non-default project ⇒ the Shared per-tenant cell (the only cell with derived owner/login roles a
/// prior-failed sync can tangle; the reserved default tenant is a no-op for the self-heal).
const TENANT: &str = "construens";

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

struct Parsed {
    host: String,
    port: u16,
    user: String,
    password: String,
    maintenance_db: String,
}
fn parse_pg_url(url: &str) -> Parsed {
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

fn su_url_to_db(url: &str, db: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap();
    let (creds, after) = rest.split_once('@').unwrap();
    let (hostport, _) = after.split_once('/').unwrap_or((after, ""));
    format!("{scheme}://{creds}@{hostport}/{db}")
}

fn direct(su_url: &str, db: &str) -> Arc<dyn SqlBackend> {
    connect(
        ExternalSqlKind::Postgres,
        &ExternalSqlOptions::new(su_url_to_db(su_url, db)),
    )
    .expect("connect superuser")
}

fn cred_key(project: &str, workload: &str) -> String {
    format!("managed-sql-cred/{project}/{workload}")
}

fn shared_binding(superuser: &str) -> ExternalDatabaseConfig {
    ExternalDatabaseConfig {
        kind: "postgres".into(),
        compute: Some(COMPUTE.into()),
        database: Some(DATABASE.into()),
        user: Some(superuser.into()),
        tenant: TenantIsolation::Shared,
        tenant_scope: TenantScope::Project,
        connect_timeout_secs: Some(10),
        ..Default::default()
    }
}

async fn text1(b: &Arc<dyn SqlBackend>, sql: &str) -> Option<String> {
    let rows = b.run_query(sql).await.ok()?;
    match rows.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

async fn user_table_count(b: &Arc<dyn SqlBackend>) -> i64 {
    let rows = b
        .run_query(
            "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname NOT IN ('pg_catalog','information_schema','pg_toast') \
             AND c.relkind IN ('r','p','m','S','f')) \
             + (SELECT count(*) FROM pg_largeobject_metadata)",
        )
        .await
        .expect("user object count");
    match rows.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Integer(n)) => *n,
        Some(SqlValue::Text(s)) => s.trim().parse().unwrap_or(-1),
        other => panic!("count returned non-integer: {other:?}"),
    }
}

#[tokio::test]
async fn construens_selfheal_preserves_live_until_swap_live() {
    let Ok(su_url) = std::env::var("BOATRAMP_TEST_PG_URL") else {
        eprintln!("SKIP: BOATRAMP_TEST_PG_URL unset (construens self-heal preserve-live gate)");
        return;
    };
    let p = parse_pg_url(&su_url);
    let superuser = p.user.clone();

    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let storage: Arc<dyn boatramp_core::Storage> = Arc::new(boatramp_storage::FsStorage::new(
        std::env::temp_dir().join(format!("boatramp-construens-gate-{}", std::process::id())),
    ));
    let deploy = DeployStore::new(storage, kv.clone());
    let envelope: Arc<dyn KeyEnvelope> = Arc::new(RevEnvelope);

    let sealed_su = envelope.wrap(p.password.as_bytes()).await.unwrap();
    kv.put(&cred_key(DEFAULT_PROJECT, COMPUTE), sealed_su)
        .await
        .unwrap();

    deploy
        .set_replica_state(
            ProjectRef::DEFAULT,
            &ObservedInstance {
                handle: InstanceHandle::new(
                    DEFAULT_PROJECT.to_string(),
                    COMPUTE.to_string(),
                    0,
                    "test-external-pg".to_string(),
                ),
                node: 0,
                backend: "external".to_string(),
                endpoint: Endpoint::new(Scheme::Http, p.host.clone(), p.port),
                region: None,
                healthy: true,
                started_at: None,
                phase: ReplicaPhase::Running,
                readiness: boatramp_core::compute::Readiness::Provisioned,
                data_dir: None,
                snapshot: None,
                active_spec: None,
            },
        )
        .await
        .unwrap();

    let binding = shared_binding(&superuser);
    let ident = sanitize_ident(TENANT);
    let live_db = tenant_db_name(DATABASE, &ident);
    let owner_role = tenant_owner_role_name(COMPUTE, &ident);
    let runtime_role = tenant_role_name(COMPUTE, &ident);

    let maint = direct(&su_url, &p.maintenance_db);

    let cleanup = |maint: Arc<dyn SqlBackend>,
                   live_db: String,
                   owner_role: String,
                   runtime_role: String| async move {
        if let Ok(rows) = maint
            .run_query(&format!(
                "SELECT datname FROM pg_database WHERE datname LIKE '{p}%'",
                p = &live_db[..live_db.len().min(30)]
            ))
            .await
        {
            for r in &rows.rows {
                if let Some(SqlValue::Text(d)) = r.first() {
                    let _ = maint
                        .run_script(&format!("DROP DATABASE IF EXISTS \"{d}\" WITH (FORCE)"))
                        .await;
                }
            }
        }
        for role in [&owner_role, &runtime_role] {
            let _ = maint
                .run_script(&format!("DROP ROLE IF EXISTS \"{role}\""))
                .await;
        }
    };
    cleanup(
        maint.clone(),
        live_db.clone(),
        owner_role.clone(),
        runtime_role.clone(),
    )
    .await;

    // === 1. Provision the Shared tenant through the SHIPPED path (derived roles + live db). ===
    provision_tenant(&deploy, &kv, &envelope, &binding, TENANT, "")
        .await
        .expect("provision construens tenant");

    // === 2. Seed the LIVE db with the tenant's OLD data (the 91 MB analog — one marker row). ===
    let live = direct(&su_url, &live_db);
    live.run_script("CREATE TABLE old_marker(v text);")
        .await
        .expect("create old_marker");
    live.run_script("INSERT INTO old_marker(v) VALUES ('OLD-DATA-construens');")
        .await
        .expect("seed old data");
    assert_eq!(
        user_table_count(&live).await,
        1,
        "precondition: the live db is POPULATED before the self-heal"
    );

    // === 3. Fabricate the PRIOR-FAILED-SYNC TANGLE: a stray `__old_` swap-aside db OWNED by the
    //        tenant's derived OWNER role (what makes `classify_role_tangle` see an EXCLUSIVE tangle ⇒
    //        the FULL existing-dest `fresh_dest=false` self-heal, not a cheap NoOp). ===
    let stray_aside = bounded_aside_db_name(&live_db, "__old_", "1");
    assert_ne!(
        stray_aside, live_db,
        "the bounded aside must not collapse to the live name"
    );
    maint
        .run_script(&format!(
            "CREATE DATABASE \"{stray_aside}\" OWNER \"{owner_role}\""
        ))
        .await
        .expect("create stray __old_ aside owned by the derived owner role");

    // === 4. Run the SHIPPED self-heal — existing-dest (`fresh_dest=false`), tombstones PRESERVED. ===
    let report = untangle_colliding_orphan_roles(
        &deploy,
        &kv,
        &envelope,
        &binding,
        TENANT,
        /*fresh_dest=*/ false,
        /*drop_soft_deleted=*/ false,
        DEFAULT_DEPROVISION_GRACE_SECS,
    )
    .await
    .expect("self-heal must succeed");
    assert!(
        matches!(report, SelfHealReport::Healed { .. }),
        "expected a FULL Healed self-heal (the construens existing-dest shape), got {report:?}"
    );

    // === 5. THE INVARIANT (v0.59.8 fix — inverts the old empty-mirror assertion): immediately after
    //        the self-heal, with NO restore having run, the live db is STILL SERVING its original data.
    //        The self-heal did NOT empty it. ===
    let live_after = direct(&su_url, &live_db);
    let live_tables = user_table_count(&live_after).await;
    assert_eq!(
        live_tables, 1,
        "LIVE-PRESERVED-AFTER-SELFHEAL (the fix): the live db must STILL hold its data ({live_tables} \
         user objects found) — the self-heal must NOT empty live before a verified restore. Reverting \
         the fix (up-front live emptying) turns this RED."
    );
    assert_eq!(
        text1(&live_after, "SELECT v FROM old_marker LIMIT 1")
            .await
            .as_deref(),
        Some("OLD-DATA-construens"),
        "the original marker row must still be SERVING from the live db after the self-heal"
    );

    // === 6. And the self-heal created NO `__deleted_` tombstone of the live db — the live db becomes a
    //        tombstone ONLY at the atomic swap, on a verified restore (the stray empty `__old_` aside is
    //        hard-dropped, not tombstoned). ===
    let tombstones = maint
        .run_query(&format!(
            "SELECT datname FROM pg_database WHERE datname LIKE '{p}%__deleted\\_%' ESCAPE '\\'",
            p = &live_db[..live_db.len().min(30)]
        ))
        .await
        .expect("enumerate tombstones");
    assert!(
        tombstones.rows.is_empty(),
        "the self-heal must NOT mint a `__deleted_` tombstone of the live db (that happens only at the \
         atomic swap, on a verified restore); found {:?}",
        tombstones.rows
    );

    println!(
        "CONSTRUENS SELFHEAL PRESERVES LIVE OK (live db {live_db} still serving its original data after the self-heal)"
    );

    cleanup(
        maint.clone(),
        live_db.clone(),
        owner_role.clone(),
        runtime_role.clone(),
    )
    .await;
    let _ = maint
        .run_script(&format!(
            "DROP DATABASE IF EXISTS \"{stray_aside}\" WITH (FORCE)"
        ))
        .await;
}
