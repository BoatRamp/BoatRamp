//! The **project export/import driver** (`boatramp_core::project_export::ProjectExport`
//! impl) — the cross-crate orchestration that assembles / reads a `BRPROJ` bundle by
//! driving every engine:
//!
//! - **pg** (managed, compute-backed): version-detect via `OperatorSql::query("SHOW
//!   server_version_num")` → [`pg_client_image_for_server_version`] → assemble the
//!   connection from [`operator_target`](crate::managed_sql) + the replica endpoint +
//!   the unsealed credential → `run_ephemeral(pg_dump …)` streaming the dump to a bundle
//!   member (import: `run_ephemeral(pg_restore …)` streaming the member back in via
//!   stdin, after a schema-ledger fingerprint SKEW check).
//! - **control-plane KV**: `deploy.checkpoint()` (durable frontier) then
//!   `kv_dump::export_to_bytes`. Import applies it with `plan_import`/`apply_import`
//!   ONLY for a FULL bundle — a `--data-only` bundle carries app data only (no
//!   identity/RBAC/routing), so its KV slice is NOT restored (a later phase).
//! - **blobs**: `blob_migrate::migrate` of the project's blob prefix into a staging
//!   `FsStorage`, whose files become bundle members (import: the reverse).
//! - **libsql**: the [`snapshot_into`](boatramp_storage::sql_libsql::LibsqlSqlBackends::snapshot_into)
//!   primitive for the explicitly-targeted `(site, name)` databases (full per-site
//!   enumeration is a documented follow-up).
//!
//! Reachability: an external DSN host is used verbatim; a colocated managed DB in
//! `Published` endpoint mode (host-loopback publish, unreachable from a sibling
//! container) is reached at its container **bridge IP** via
//! [`ComputeBackend::replica_direct_host`](boatramp_core::compute::ComputeBackend::replica_direct_host).
//!
//! Phase 1 first cut: **docker backend, pg + libsql + KV + blobs, `--data-only` + full**.
//! mysql and external-URL (non-managed) pg bindings are skipped with a note; the native
//! container backend's `run_ephemeral` is `Unsupported`.
#![cfg(feature = "project-export")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use boatramp_core::Storage;
use boatramp_core::compute::{ComputeBackend, ReplicaPhase};
use boatramp_core::deploy::DeployStore;
use boatramp_core::env::EnvSource;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_core::project_export::{
    ImportOptions, ImportReport, ProjectExport, ProjectExportError,
};
use boatramp_core::sql::SqlValue;
use boatramp_storage::sql_libsql::LibsqlSqlBackends;

use crate::config::ExternalDatabaseConfig;
use crate::managed_sql::{ManagedSqlCredentials, operator_target};
use crate::pg_client::{
    MysqlConnection, PgConnection, mysql_restore_invocation, mysqldump_invocation,
    pg_dump_invocation, pg_restore_invocation,
};
use crate::project_bundle::{
    self, KV_MEMBER_PATH, MemberKind, PgMemberInfo, SourceInfo, StagedMember,
};

type Perr = ProjectExportError;

fn other<E: std::fmt::Display>(e: E) -> Perr {
    Perr::Other(e.to_string())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-mutation-gated in the merge gate)
// ---------------------------------------------------------------------------

/// Whether a binding `kind` names Postgres.
fn kind_is_postgres(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "postgres" | "postgresql" | "pg"
    )
}

/// Whether a binding `kind` names libsql/SQLite.
fn kind_is_libsql(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "libsql" | "sqlite" | "sqlite3"
    )
}

/// Whether a binding `kind` names MySQL/MariaDB (MariaDB is detected + refused later by
/// the version banner, not the kind string).
fn kind_is_mysql(kind: &str) -> bool {
    matches!(kind.to_ascii_lowercase().as_str(), "mysql" | "mariadb")
}

/// Parse a `postgres://` / `mysql://` DSN into `(user, password, host, port, database)`
/// for an EXTERNAL (bring-your-own-URL) binding. Best-effort for the standard shape; the
/// password is split on the FIRST `:` so a `:`-bearing password survives. `None` for a
/// shape we don't recognize (the caller then refuses rather than misconnect).
fn parse_sql_url(url: &str) -> Option<(String, String, String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme {
        "postgres" | "postgresql" => 5432,
        "mysql" | "mariadb" => 3306,
        _ => return None,
    };
    let (userinfo, hostpart) = rest.rsplit_once('@')?;
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    let (hostport, db) = hostpart.split_once('/')?;
    let db = db.split(['?', '&']).next().unwrap_or(db).to_string();
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), default_port),
    };
    Some((user, password, host, port, db))
}

/// The bundle member path for a Postgres database dump.
fn pg_member_path(db: &str) -> String {
    format!("sql/{db}.pgc")
}

/// Recover the database name from a `sql/<db>.pgc` member path.
fn db_from_pg_member(path: &str) -> Option<&str> {
    path.strip_prefix("sql/")
        .and_then(|s| s.strip_suffix(".pgc"))
}

/// The bundle member path for a MySQL database dump.
fn mysql_member_path(db: &str) -> String {
    format!("sql/{db}.sql")
}

/// Recover the database name from a `sql/<db>.sql` member path.
fn db_from_mysql_member(path: &str) -> Option<&str> {
    path.strip_prefix("sql/")
        .and_then(|s| s.strip_suffix(".sql"))
}

/// The bundle member path for a site's default libsql database.
fn libsql_member_path(project: &str, site: &str) -> String {
    format!("libsql/{project}/{site}/default.sqlite")
}

/// Recover the SITE from a `libsql/<project>/<site>/default.sqlite` member path (the
/// source project segment is discarded — the import re-qualifies with the TARGET
/// project).
fn site_from_libsql_member(path: &str) -> Option<&str> {
    let body = path
        .strip_prefix("libsql/")?
        .strip_suffix("/default.sqlite")?;
    // body = "<project>/<site>"; site is the last segment (project/site carry no `/`).
    Some(body.rsplit_once('/').map(|(_, s)| s).unwrap_or(body))
}

/// The blob-store key prefix covering a project's objects.
///
/// Every blob key is `hblob/{qualified-site}/{container}/{key}` where the qualified site
/// is `ProjectRef::qualified(project, site) = "{project}/{site}"` for EVERY project —
/// including the reserved `default` (`hblob/default/{site}/…`, the v0.31.0 Finding-8
/// two-segment default scope; see `blob_shim`'s `format!("hblob/{qualified_site}/")`).
/// So a project's objects all live under `hblob/{project}/`, with no over-capture (the
/// trailing `/` means `hblob/foo/` never matches a sibling `hblob/foobar/`).
fn blob_project_prefix(project: &str) -> String {
    format!("hblob/{project}/")
}

/// Choose the host a sibling ephemeral client should connect to: in `Published` docker
/// endpoint mode the operator endpoint is a host-loopback publish a sibling cannot
/// route to, so prefer the replica's direct (bridge) host when one was resolved;
/// otherwise (external DSN, `Bridge` mode) the endpoint host is directly reachable.
fn choose_host(endpoint_host: &str, direct_host: Option<&str>, published: bool) -> String {
    match (published, direct_host) {
        (true, Some(h)) if !h.is_empty() => h.to_string(),
        _ => endpoint_host.to_string(),
    }
}

/// The first cell of a single-value query result, as a string.
fn scalar_text(rows: &boatramp_core::sql::SqlRows) -> Option<String> {
    match rows.rows.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(s)) => Some(s.clone()),
        Some(SqlValue::Integer(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// A stable fingerprint of a schema-ledger query result — a canonical serialization of
/// every row, hashed. Identical input rows (same migrations applied, same content
/// hashes) yield an identical fingerprint on both export (source) and import (target),
/// so a `--data-only` import can detect schema skew.
fn fingerprint_rows(rows: &boatramp_core::sql::SqlRows) -> String {
    let mut hasher = Sha256::new();
    for row in &rows.rows {
        for cell in row {
            let s = match cell {
                SqlValue::Text(s) => s.clone(),
                SqlValue::Integer(n) => n.to_string(),
                other => format!("{other:?}"),
            };
            hasher.update((s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());
        }
        hasher.update(b"\x00");
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// The node's [`ProjectExport`] implementation.
///
/// Always constructible from the node's always-present deps (deploy + KV + blobs); the
/// engine contexts attach optionally — [`with_managed_pg`](Self::with_managed_pg) for the
/// pg/mysql ephemeral-dump path, [`with_libsql`](Self::with_libsql) for the embedded
/// libsql path — so a libsql-only project (no managed SQL at all) still exports its
/// libsql + KV + blobs.
pub struct NodeProjectExport {
    databases: BTreeMap<String, ExternalDatabaseConfig>,
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    blobs: Arc<dyn Storage>,
    /// The LOCAL libsql backend, when the project's `sql` binding is embedded libsql
    /// (not remote sqld). `None` ⇒ no local libsql to snapshot (remote, or no binding).
    /// The driver enumerates the project's sites AUTHORITATIVELY from the deploy store
    /// and snapshots each site's default DB that actually exists on disk.
    libsql: Option<Arc<LibsqlSqlBackends>>,
    /// The compute backend running the ephemeral `pg_dump`/`mysqldump` client. `None` ⇒
    /// no pg/mysql export/import on this node.
    backend: Option<Arc<dyn ComputeBackend>>,
    /// The secrets envelope used to unseal a managed DB credential. `None` with a managed
    /// binding ⇒ that binding can't be dumped (fail-closed per database).
    envelope: Option<Arc<dyn KeyEnvelope>>,
    /// The operator-SQL seam used to version-detect (`SHOW server_version_num` /
    /// `SELECT VERSION()`) + fingerprint the schema ledger. `None` ⇒ no pg/mysql path.
    operator_sql: Option<Arc<dyn boatramp_core::sql::OperatorSql>>,
    /// Host-env source for an EXTERNAL binding's `url_env` lookup. Production is
    /// [`SystemEnv`](boatramp_core::env::SystemEnv); a test injects a map.
    env_source: Arc<dyn EnvSource>,
    published_endpoint: bool,
    work_dir: PathBuf,
    connect_timeout_secs: u32,
}

impl NodeProjectExport {
    /// Build the driver from the always-present node deps. Attach the pg/mysql context
    /// with [`with_managed_pg`](Self::with_managed_pg) and the libsql backend with
    /// [`with_libsql`](Self::with_libsql). `work_dir` holds staging + bundle temp files.
    pub fn new(
        databases: BTreeMap<String, ExternalDatabaseConfig>,
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        blobs: Arc<dyn Storage>,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            databases,
            deploy,
            kv,
            blobs,
            libsql: None,
            backend: None,
            envelope: None,
            operator_sql: None,
            env_source: Arc::new(boatramp_core::env::SystemEnv),
            published_endpoint: true,
            work_dir,
            connect_timeout_secs: 10,
        }
    }

    /// Replace the host-env source (for an external binding's `url_env`). Tests inject a
    /// map; production keeps [`SystemEnv`](boatramp_core::env::SystemEnv).
    #[must_use]
    pub fn with_env_source(mut self, env_source: Arc<dyn EnvSource>) -> Self {
        self.env_source = env_source;
        self
    }

    /// Attach the pg/mysql ephemeral-dump context: the compute backend that runs the
    /// client container, the secrets envelope (to unseal a managed credential), the
    /// operator-SQL seam (version-detect + schema fingerprint), and whether the backend's
    /// endpoints are host-loopback publishes (so a colocated DB must be reached at its
    /// bridge IP).
    #[must_use]
    pub fn with_managed_pg(
        mut self,
        backend: Arc<dyn ComputeBackend>,
        envelope: Arc<dyn KeyEnvelope>,
        operator_sql: Arc<dyn boatramp_core::sql::OperatorSql>,
        published_endpoint: bool,
    ) -> Self {
        self.backend = Some(backend);
        self.envelope = Some(envelope);
        self.operator_sql = Some(operator_sql);
        self.published_endpoint = published_endpoint;
        self
    }

    /// Attach the LOCAL libsql backend so the driver snapshots each site's embedded DB on
    /// export and places members back on import. Pass `None`-equivalent (don't call this)
    /// for a remote-sqld project (no local file to snapshot).
    #[must_use]
    pub fn with_libsql(mut self, libsql: Arc<LibsqlSqlBackends>) -> Self {
        self.libsql = Some(libsql);
        self
    }

    /// The compute backend that runs the ephemeral SQL client, or a clear `Unavailable`
    /// error (a node with no docker backend cannot dump/restore pg/mysql).
    fn require_backend(&self) -> Result<&Arc<dyn ComputeBackend>, Perr> {
        self.backend.as_ref().ok_or_else(|| {
            Perr::Unavailable(
                "pg/mysql export/import needs a compute backend to run the client container — \
                 none on this node"
                    .into(),
            )
        })
    }

    /// The operator-SQL seam (version-detect + schema fingerprint), or `Unavailable`.
    fn require_op(&self) -> Result<&Arc<dyn boatramp_core::sql::OperatorSql>, Perr> {
        self.operator_sql.as_ref().ok_or_else(|| {
            Perr::Unavailable(
                "pg/mysql export/import needs the operator-SQL seam (a managed SQL binding) — \
                 not configured on this node"
                    .into(),
            )
        })
    }

    /// Resolve a SQL database (managed compute-backed OR external bring-your-own-URL) to
    /// its reachable endpoint parts `(host, port, user, password, database)`.
    async fn resolve_endpoint(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<SqlEndpoint, Perr> {
        if cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) {
            self.resolve_managed_endpoint(project, db, cfg).await
        } else if !cfg.url_env.is_empty() {
            // EXTERNAL: the DSN lives in `url_env`; use its host VERBATIM (the daemon
            // bridge NATs egress to it). The credential comes from the URL, never a sealed
            // store, so no envelope is needed.
            let url = self.env_source.get(&cfg.url_env).ok_or_else(|| {
                Perr::Other(format!(
                    "database {db:?}: external URL env var {} is unset",
                    cfg.url_env
                ))
            })?;
            let (user, password, host, port, database) = parse_sql_url(&url).ok_or_else(|| {
                // Never echo the URL (it carries the credential) — name only the env var.
                Perr::Other(format!(
                    "database {db:?}: external URL in {} is not a parseable \
                     postgres://|mysql:// DSN",
                    cfg.url_env
                ))
            })?;
            Ok(SqlEndpoint {
                host,
                port,
                user,
                password,
                database,
            })
        } else {
            Err(Perr::Other(format!(
                "database {db:?}: neither compute-backed (managed) nor `url_env` (external) — \
                 nothing to dump"
            )))
        }
    }

    /// Resolve a managed compute-backed SQL database to its reachable endpoint parts —
    /// the same derivation the runtime uses (`operator_target` + the healthy replica
    /// endpoint + the unsealed credential), with a colocated `Published` DB reached at its
    /// container bridge IP.
    async fn resolve_managed_endpoint(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<SqlEndpoint, Perr> {
        let backend = self.require_backend()?;
        let envelope = self.envelope.as_ref().ok_or_else(|| {
            Perr::Unavailable(format!(
                "managed database {db:?} needs a [secrets] envelope to unseal its credential — \
                 none on this node"
            ))
        })?;
        let target = operator_target(cfg, project, db).map_err(other)?;
        let states = self
            .deploy
            .list_replica_states(ProjectRef::new(&target.endpoint_project), &target.workload)
            .await
            .map_err(other)?;
        let replica = states
            .into_iter()
            .find(|s| s.phase == ReplicaPhase::Running && s.healthy)
            .ok_or_else(|| {
                Perr::Other(format!(
                    "database {db:?}: no healthy running replica of workload {:?} to dump/restore",
                    target.workload
                ))
            })?;
        let direct = if self.published_endpoint {
            backend.replica_direct_host(&replica.handle).await
        } else {
            None
        };
        let host = choose_host(
            &replica.endpoint.host,
            direct.as_deref(),
            self.published_endpoint,
        );
        let password = ManagedSqlCredentials::new(self.kv.clone(), envelope.clone())
            .password(&target.cred_project, &target.cred_workload)
            .await
            .map_err(Perr::Other)?;
        Ok(SqlEndpoint {
            host,
            port: replica.endpoint.port,
            user: target.user,
            password,
            database: target.database,
        })
    }

    /// Resolve a Postgres database (managed or external) to a `PgConnection` + the
    /// matching client image + the detected `server_version_num`.
    async fn resolve_pg(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<(PgConnection, String, String), Perr> {
        let op = self.require_op()?;
        let ep = self.resolve_endpoint(project, db, cfg).await?;
        // Version detect via the operator-SQL seam (works for managed + external).
        let banner = op
            .query(project, db, "SHOW server_version_num")
            .await
            .map_err(other)?;
        let server_version_num = scalar_text(&banner).ok_or_else(|| {
            Perr::Other(format!(
                "database {db:?}: empty SHOW server_version_num result"
            ))
        })?;
        let image = boatramp_core::compute::pg_client_image_for_server_version(&server_version_num)
            .map_err(|e| Perr::Other(format!("database {db:?}: {e}")))?;
        Ok((
            ep.into_pg(self.connect_timeout_secs),
            image,
            server_version_num,
        ))
    }

    /// Resolve a MySQL database (managed or external) to a `MysqlConnection` + the
    /// matching `mysql:<maj.min>` client image + the detected version banner. A MariaDB
    /// banner is REFUSED (distinct dialect — see [`mysql_client_image_for_server_version`]).
    async fn resolve_mysql(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<(MysqlConnection, String, String), Perr> {
        let op = self.require_op()?;
        let ep = self.resolve_endpoint(project, db, cfg).await?;
        let banner = op
            .query(project, db, "SELECT VERSION()")
            .await
            .map_err(other)?;
        let version = scalar_text(&banner).ok_or_else(|| {
            Perr::Other(format!("database {db:?}: empty SELECT VERSION() result"))
        })?;
        let image = boatramp_core::compute::mysql_client_image_for_server_version(&version)
            .map_err(|e| Perr::Other(format!("database {db:?}: {e}")))?;
        Ok((ep.into_mysql(self.connect_timeout_secs), image, version))
    }

    /// Best-effort schema-ledger fingerprint of a Postgres database (the applied
    /// migration set + content hashes). `None` if the ledger can't be read (e.g. no
    /// migrations table, or no operator-SQL seam) — the skew check then has nothing to
    /// compare.
    async fn schema_fingerprint(&self, project: &str, db: &str) -> Option<String> {
        let op = self.operator_sql.as_ref()?;
        let sql = "SELECT id, ordinal, content_hash FROM boatramp_migrations.schema_migrations \
                   ORDER BY ordinal, id";
        match op.query(project, db, sql).await {
            Ok(rows) => Some(fingerprint_rows(&rows)),
            Err(_) => None,
        }
    }

    /// Run a SQL client (`pg_dump`/`pg_restore`/`mysqldump`/`mysql`) in an ephemeral
    /// container, streaming `stdin` in (optional) and stdout to `stdout_path`. Returns
    /// the exit code.
    async fn run_sql_client(
        &self,
        image: &str,
        argv: &[String],
        env: &[(String, String)],
        stdin_path: Option<&Path>,
        stdout_path: &Path,
    ) -> Result<i32, Perr> {
        let backend = self.require_backend()?;
        let out = tokio::fs::File::create(stdout_path).await.map_err(other)?;
        let mut sink = out.compat_write();
        let code = if let Some(inp) = stdin_path {
            let f = tokio::fs::File::open(inp).await.map_err(other)?;
            let mut rdr = f.compat();
            backend
                .run_ephemeral(image, argv, env, Some(&mut rdr), &mut sink)
                .await
                .map_err(other)?
        } else {
            backend
                .run_ephemeral(image, argv, env, None, &mut sink)
                .await
                .map_err(other)?
        };
        Ok(code)
    }
}

/// The resolved reachable endpoint of a SQL database (managed or external) — the raw
/// parts the ephemeral client connects with.
struct SqlEndpoint {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
}

impl SqlEndpoint {
    fn into_pg(self, connect_timeout_secs: u32) -> PgConnection {
        PgConnection {
            host: self.host,
            port: self.port,
            user: self.user,
            password: self.password,
            database: self.database,
            connect_timeout_secs,
        }
    }

    fn into_mysql(self, connect_timeout_secs: u32) -> MysqlConnection {
        MysqlConnection {
            host: self.host,
            port: self.port,
            user: self.user,
            password: self.password,
            database: self.database,
            connect_timeout_secs,
        }
    }
}

#[async_trait]
impl ProjectExport for NodeProjectExport {
    async fn export(&self, project: &str, data_only: bool) -> Result<PathBuf, Perr> {
        let created_at = now_secs();
        let session = self.work_dir.join(format!("export-{project}-{created_at}"));
        let stage = session.join("stage");
        tokio::fs::create_dir_all(&stage).await.map_err(other)?;
        let mut staged: Vec<StagedMember> = Vec::new();

        // --- control-plane KV slice (always) ---
        self.deploy.checkpoint().await.map_err(other)?;
        let kv_bytes = boatramp_core::kv_dump::export_to_bytes(self.kv.as_ref(), created_at)
            .await
            .map_err(other)?;
        let kv_path = stage.join("kv.brkvdump");
        tokio::fs::write(&kv_path, &kv_bytes).await.map_err(other)?;
        staged.push(StagedMember {
            path: KV_MEMBER_PATH.to_string(),
            kind: MemberKind::Kv,
            source: kv_path,
            pg: None,
        });

        // --- per-engine dumps (pg + mysql; managed OR external bring-your-own-URL) ---
        for (db, cfg) in &self.databases {
            // A binding is dumpable here iff it is compute-backed (managed) OR names an
            // external DSN env var; a `libsql` binding's per-site DBs go through the
            // authoritative site enumeration below instead.
            let dumpable =
                cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) || !cfg.url_env.is_empty();
            if kind_is_postgres(&cfg.kind) && dumpable {
                let (conn, image, server_version_num) = self.resolve_pg(project, db, cfg).await?;
                let inv = pg_dump_invocation(&conn, data_only);
                let out = stage.join(format!("{db}.pgc"));
                let code = self
                    .run_sql_client(&image, &inv.argv, &inv.env, None, &out)
                    .await?;
                if code != 0 {
                    return Err(Perr::Other(format!("pg_dump for {db:?} exited {code}")));
                }
                let schema_fingerprint = self.schema_fingerprint(project, db).await;
                staged.push(StagedMember {
                    path: pg_member_path(db),
                    kind: MemberKind::PgDump,
                    source: out,
                    pg: Some(PgMemberInfo {
                        server_version_num,
                        client_image: image,
                        schema_fingerprint,
                    }),
                });
            } else if kind_is_mysql(&cfg.kind) && dumpable {
                let (conn, image, version) = self.resolve_mysql(project, db, cfg).await?;
                let inv = mysqldump_invocation(&conn, data_only);
                let out = stage.join(format!("{db}.sql"));
                let code = self
                    .run_sql_client(&image, &inv.argv, &inv.env, None, &out)
                    .await?;
                if code != 0 {
                    return Err(Perr::Other(format!("mysqldump for {db:?} exited {code}")));
                }
                let schema_fingerprint = self.schema_fingerprint(project, db).await;
                staged.push(StagedMember {
                    path: mysql_member_path(db),
                    kind: MemberKind::MysqlDump,
                    source: out,
                    pg: Some(PgMemberInfo {
                        server_version_num: version,
                        client_image: image,
                        schema_fingerprint,
                    }),
                });
            }
            // A `libsql` binding (or a binding with neither compute nor url_env) is handled
            // by the per-site libsql enumeration below — nothing to do in this loop.
        }

        // --- libsql snapshots: enumerate the project's sites AUTHORITATIVELY from the
        //     deploy store (never a filesystem walk), and snapshot each site's embedded
        //     default libsql DB that actually exists on disk. A managed-pg/external
        //     project has no local libsql backend wired (`self.libsql` is `None`), so its
        //     sites are skipped here and go through the pg path instead. ---
        if let Some(libsql) = &self.libsql {
            let sites = self
                .deploy
                .list_sites(ProjectRef::new(project))
                .await
                .map_err(other)?;
            for site in sites {
                let qsite = ProjectRef::new(project).qualified(&site);
                if !libsql.local_database_exists(&qsite, "") {
                    continue; // a site that never wrote SQL — nothing to snapshot
                }
                let dest = stage.join(format!("libsql-{}.sqlite", sanitize(&site)));
                libsql
                    .snapshot_into(&qsite, "", &dest)
                    .await
                    .map_err(other)?;
                staged.push(StagedMember {
                    path: libsql_member_path(project, &site),
                    kind: MemberKind::Libsql,
                    source: dest,
                    pg: None,
                });
            }
        }

        // --- blobs: migrate the project prefix into a staging FsStorage ---
        let blob_stage = stage.join("blobs");
        tokio::fs::create_dir_all(&blob_stage)
            .await
            .map_err(other)?;
        let dest: Arc<dyn Storage> = Arc::new(boatramp_storage::FsStorage::new(&blob_stage));
        let opts = boatramp_storage::blob_migrate::MigrateOptions {
            prefix: blob_project_prefix(project),
            ..Default::default()
        };
        boatramp_storage::blob_migrate::migrate(self.blobs.clone(), dest, &opts)
            .await
            .map_err(other)?;

        // --- assemble the tar (sync; walk staged blobs into members, then write) ---
        let bundle = self
            .work_dir
            .join(format!("export-{project}-{created_at}.brproj"));
        let bundle_for_task = bundle.clone();
        let source = SourceInfo {
            project: project.to_string(),
            site: None,
        };
        let blob_stage_for_task = blob_stage.clone();
        tokio::task::spawn_blocking(move || -> Result<(), project_bundle::BundleError> {
            let mut members = staged;
            // Blob members: every file staged under blobs/ becomes `blobs/<relpath>`.
            collect_blob_members(&blob_stage_for_task, &mut members)?;
            project_bundle::write_bundle(
                &bundle_for_task,
                created_at,
                data_only,
                source,
                &members,
            )?;
            Ok(())
        })
        .await
        .map_err(other)?
        .map_err(other)?;

        // Best-effort cleanup of the staging tree (the bundle file remains for the caller).
        let _ = tokio::fs::remove_dir_all(&session).await;
        Ok(bundle)
    }

    async fn import(
        &self,
        project: &str,
        bundle: &Path,
        opts: ImportOptions,
    ) -> Result<ImportReport, Perr> {
        let session = self
            .work_dir
            .join(format!("import-{project}-{}", now_secs()));
        let extract = session.join("extract");
        tokio::fs::create_dir_all(&extract).await.map_err(other)?;

        let bundle_owned = bundle.to_path_buf();
        let extract_for_task = extract.clone();
        let manifest = tokio::task::spawn_blocking(move || {
            project_bundle::extract_and_verify(&bundle_owned, &extract_for_task)
        })
        .await
        .map_err(other)?
        .map_err(other)?;

        let mut report = ImportReport {
            dry_run: !opts.apply,
            ..Default::default()
        };

        // Order: blobs -> pg/libsql -> kv.

        // --- blobs ---
        let blob_src_dir = extract.join("blobs");
        if blob_src_dir.exists() {
            let src: Arc<dyn Storage> = Arc::new(boatramp_storage::FsStorage::new(&blob_src_dir));
            let bopts = boatramp_storage::blob_migrate::MigrateOptions {
                dry_run: !opts.apply,
                ..Default::default()
            };
            let rep = boatramp_storage::blob_migrate::migrate(src, self.blobs.clone(), &bopts)
                .await
                .map_err(other)?;
            report.blobs = rep.copied_objects;
        }

        // --- pg: schema-skew check, then restore (apply) ---
        for m in manifest.pg_members() {
            let db = db_from_pg_member(&m.path)
                .ok_or_else(|| Perr::Other(format!("bad pg member path {:?}", m.path)))?;
            let cfg = self.databases.get(db).ok_or_else(|| {
                Perr::Other(format!("import: no database named {db:?} on this node"))
            })?;
            let (conn, image, _ver) = self.resolve_pg(project, db, cfg).await?;

            // Schema-ledger fingerprint SKEW check (both sides must agree for --data-only).
            let src_fp = m.pg.as_ref().and_then(|p| p.schema_fingerprint.clone());
            let tgt_fp = self.schema_fingerprint(project, db).await;
            if let (Some(src_fp), Some(tgt_fp)) = (src_fp, tgt_fp)
                && src_fp != tgt_fp
            {
                report.schema_skew.push(db.to_string());
                if !opts.allow_schema_skew {
                    return Err(Perr::SchemaSkew(vec![db.to_string()]));
                }
            }

            if opts.apply {
                let inv = pg_restore_invocation(&conn, manifest.data_only);
                let member_file = extract.join(&m.path);
                let devnull = session.join(format!("{db}.restore.out"));
                let code = self
                    .run_sql_client(&image, &inv.argv, &inv.env, Some(&member_file), &devnull)
                    .await?;
                if code != 0 {
                    return Err(Perr::Other(format!("pg_restore for {db:?} exited {code}")));
                }
            }
            report.pg_databases += 1;
        }

        // --- mysql: schema-skew check, then restore (apply) ---
        for m in manifest
            .members
            .iter()
            .filter(|m| m.kind == MemberKind::MysqlDump)
        {
            let db = db_from_mysql_member(&m.path)
                .ok_or_else(|| Perr::Other(format!("bad mysql member path {:?}", m.path)))?;
            let cfg = self.databases.get(db).ok_or_else(|| {
                Perr::Other(format!("import: no database named {db:?} on this node"))
            })?;
            let (conn, image, _ver) = self.resolve_mysql(project, db, cfg).await?;

            // Schema-ledger fingerprint SKEW check (both sides must agree for --data-only).
            let src_fp = m.pg.as_ref().and_then(|p| p.schema_fingerprint.clone());
            let tgt_fp = self.schema_fingerprint(project, db).await;
            if let (Some(src_fp), Some(tgt_fp)) = (src_fp, tgt_fp)
                && src_fp != tgt_fp
            {
                report.schema_skew.push(db.to_string());
                if !opts.allow_schema_skew {
                    return Err(Perr::SchemaSkew(vec![db.to_string()]));
                }
            }

            if opts.apply {
                let inv = mysql_restore_invocation(&conn, manifest.data_only);
                let member_file = extract.join(&m.path);
                let devnull = session.join(format!("{db}.myrestore.out"));
                let code = self
                    .run_sql_client(&image, &inv.argv, &inv.env, Some(&member_file), &devnull)
                    .await?;
                if code != 0 {
                    return Err(Perr::Other(format!(
                        "mysql restore for {db:?} exited {code}"
                    )));
                }
            }
            report.pg_databases += 1;
        }

        // --- libsql members: place each verified snapshot into the target site's
        //     embedded DB (no-clobber + integrity verify), re-qualifying the site under
        //     the TARGET project. Requires the local libsql backend. ---
        for m in manifest
            .members
            .iter()
            .filter(|m| m.kind == MemberKind::Libsql)
        {
            let Some(libsql) = &self.libsql else {
                return Err(Perr::Unavailable(
                    "bundle carries libsql members but this node has no local libsql backend to \
                     restore them into"
                        .into(),
                ));
            };
            let site = site_from_libsql_member(&m.path)
                .ok_or_else(|| Perr::Other(format!("bad libsql member path {:?}", m.path)))?;
            let qsite = ProjectRef::new(project).qualified(site);
            if opts.apply {
                libsql
                    .restore_snapshot(&qsite, "", &extract.join(&m.path))
                    .await
                    .map_err(other)?;
            }
            report.libsql_databases += 1;
        }

        // --- control-plane KV (FULL bundles only; --data-only carries app data only) ---
        if manifest.data_only {
            report
                .notes
                .push("control-plane KV (identity/RBAC/routing) NOT imported: --data-only".into());
        } else {
            let kv_file = extract.join(KV_MEMBER_PATH);
            if kv_file.exists() {
                let bytes = tokio::fs::read(&kv_file).await.map_err(other)?;
                let decoded = boatramp_core::kv_dump::decode_dump(&bytes).map_err(other)?;
                if opts.apply {
                    match boatramp_core::kv_dump::apply_import(
                        self.kv.as_ref(),
                        &decoded.entries,
                        opts.force,
                    )
                    .await
                    {
                        Ok(rep) => {
                            report.kv_records = rep.written;
                            report.kv_verified = rep.verified;
                        }
                        Err(boatramp_core::kv_dump::ImportError::Commingle(_)) => {
                            return Err(Perr::Commingle(
                                "control-plane KV import refused a non-empty destination; \
                                 re-run with --force to overlay it"
                                    .into(),
                            ));
                        }
                        Err(e) => return Err(other(e)),
                    }
                } else {
                    let plan = boatramp_core::kv_dump::plan_import(
                        self.kv.as_ref(),
                        &decoded.entries,
                        opts.force,
                    )
                    .await
                    .map_err(other)?;
                    report.kv_records = plan.would_write;
                }
            }
        }

        let _ = tokio::fs::remove_dir_all(&session).await;
        Ok(report)
    }
}

/// Sanitize a member path into a flat staging filename.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Walk `dir` recursively, adding each file as a bundle member at `blobs/<relpath>`.
fn collect_blob_members(
    dir: &Path,
    members: &mut Vec<StagedMember>,
) -> Result<(), project_bundle::BundleError> {
    fn walk(base: &Path, dir: &Path, members: &mut Vec<StagedMember>) -> std::io::Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, members)?;
            } else {
                let rel = path.strip_prefix(base).unwrap_or(&path);
                let member_path = format!("blobs/{}", rel.to_string_lossy());
                members.push(StagedMember {
                    path: member_path,
                    kind: MemberKind::Blob,
                    source: path.clone(),
                    pg: None,
                });
            }
        }
        Ok(())
    }
    walk(dir, dir, members).map_err(project_bundle::BundleError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_detection() {
        assert!(kind_is_postgres("postgres"));
        assert!(kind_is_postgres("PostgreSQL"));
        assert!(kind_is_postgres("pg"));
        assert!(!kind_is_postgres("libsql"));
        assert!(kind_is_libsql("libsql"));
        assert!(kind_is_libsql("sqlite3"));
        assert!(!kind_is_libsql("mysql"));
        assert!(kind_is_mysql("mysql"));
        assert!(kind_is_mysql("MariaDB"));
        assert!(!kind_is_mysql("postgres"));
    }

    #[test]
    fn mysql_member_path_round_trips() {
        assert_eq!(mysql_member_path("shop"), "sql/shop.sql");
        assert_eq!(db_from_mysql_member("sql/shop.sql"), Some("shop"));
        // A pg member (`.pgc`) is NOT a mysql member.
        assert_eq!(db_from_mysql_member("sql/app.pgc"), None);
    }

    #[test]
    fn parse_sql_url_handles_pg_and_mysql_dsns() {
        assert_eq!(
            parse_sql_url("postgres://u:p@h:5432/db"),
            Some(("u".into(), "p".into(), "h".into(), 5432, "db".into()))
        );
        assert_eq!(
            parse_sql_url("mysql://svc:pw@10.0.0.6:3306/shop?ssl=true"),
            Some((
                "svc".into(),
                "pw".into(),
                "10.0.0.6".into(),
                3306,
                "shop".into()
            ))
        );
        // Default ports when omitted.
        assert_eq!(
            parse_sql_url("postgres://u:p@h/db").map(|t| t.3),
            Some(5432)
        );
        assert_eq!(parse_sql_url("mysql://u:p@h/db").map(|t| t.3), Some(3306));
        // A ':'-bearing password survives (split on the FIRST ':').
        assert_eq!(
            parse_sql_url("mysql://u:a:b@h:3306/db").map(|t| t.1),
            Some("a:b".into())
        );
        // Unknown scheme / garbage -> None (refuse, don't misconnect).
        assert_eq!(parse_sql_url("redis://h/0"), None);
        assert_eq!(parse_sql_url("not-a-url"), None);
    }

    #[test]
    fn pg_member_path_round_trips() {
        assert_eq!(pg_member_path("app"), "sql/app.pgc");
        assert_eq!(db_from_pg_member("sql/app.pgc"), Some("app"));
        assert_eq!(db_from_pg_member("libsql/x.sqlite"), None);
    }

    #[test]
    fn libsql_member_path_round_trips_the_site() {
        assert_eq!(
            libsql_member_path("acme", "blog"),
            "libsql/acme/blog/default.sqlite"
        );
        // The SITE is recovered (the source project segment is discarded on import).
        assert_eq!(
            site_from_libsql_member("libsql/acme/blog/default.sqlite"),
            Some("blog")
        );
        assert_eq!(
            site_from_libsql_member("libsql/default/www/default.sqlite"),
            Some("www")
        );
        assert_eq!(site_from_libsql_member("sql/app.pgc"), None);
        assert_eq!(site_from_libsql_member("libsql/bad"), None);
    }

    #[test]
    fn blob_prefix_is_two_segment_for_every_project() {
        // Post-0.31.0 (Finding 8): EVERY project's blobs live under `hblob/{project}/`,
        // including the reserved default — NOT the pre-fix bare `hblob/` root.
        assert_eq!(blob_project_prefix("acme"), "hblob/acme/");
        assert_eq!(blob_project_prefix("default"), "hblob/default/");
        // The trailing `/` prevents a sibling-project over-capture: `foo`'s prefix is
        // NOT a prefix of `foobar`'s keys.
        assert!(!blob_project_prefix("foobar").starts_with(&blob_project_prefix("foo")));
    }

    #[test]
    fn choose_host_prefers_bridge_only_under_published() {
        // Published + a resolved bridge IP -> the sibling-reachable bridge IP.
        assert_eq!(
            choose_host("127.0.0.1", Some("172.17.0.3"), true),
            "172.17.0.3"
        );
        // Published but no bridge IP -> fall back to the endpoint host.
        assert_eq!(choose_host("127.0.0.1", None, true), "127.0.0.1");
        // Bridge mode / external DSN -> the endpoint host verbatim (ignore any direct).
        assert_eq!(
            choose_host("db.example.com", Some("172.17.0.3"), false),
            "db.example.com"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_order_sensitive() {
        use boatramp_core::sql::SqlRows;
        let a = SqlRows {
            columns: vec!["id".into()],
            rows: vec![
                vec![SqlValue::Text("m1".into()), SqlValue::Integer(1)],
                vec![SqlValue::Text("m2".into()), SqlValue::Integer(2)],
            ],
        };
        let same = SqlRows {
            columns: vec!["id".into()],
            rows: vec![
                vec![SqlValue::Text("m1".into()), SqlValue::Integer(1)],
                vec![SqlValue::Text("m2".into()), SqlValue::Integer(2)],
            ],
        };
        let different = SqlRows {
            columns: vec!["id".into()],
            rows: vec![vec![SqlValue::Text("m1".into()), SqlValue::Integer(1)]],
        };
        assert_eq!(fingerprint_rows(&a), fingerprint_rows(&same));
        assert_ne!(fingerprint_rows(&a), fingerprint_rows(&different));
    }
}
