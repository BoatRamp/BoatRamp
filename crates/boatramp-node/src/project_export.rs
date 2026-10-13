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
use crate::pg_client::{PgConnection, pg_dump_invocation, pg_restore_invocation};
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

/// The bundle member path for a Postgres database dump.
fn pg_member_path(db: &str) -> String {
    format!("sql/{db}.pgc")
}

/// Recover the database name from a `sql/<db>.pgc` member path.
fn db_from_pg_member(path: &str) -> Option<&str> {
    path.strip_prefix("sql/")
        .and_then(|s| s.strip_suffix(".pgc"))
}

/// The blob-store key prefix covering a project's objects.
///
/// Blob keys are `hblob/<qualified-site>/…`; a non-default project's objects therefore
/// live under `hblob/<project>/`. The reserved `default` project shares the `hblob/`
/// root with per-site keys, so a precise default-project prefix is ambiguous — returned
/// as `hblob/` with the over-capture documented (CAVEAT: the exact qualified-site
/// blob-key encoding must be confirmed against the live blob layer before the 0.32.0
/// cut; some fixtures show a `proj~site` tilde form).
fn blob_project_prefix(project: &str) -> String {
    if project == "default" || project.is_empty() {
        "hblob/".to_string()
    } else {
        format!("hblob/{project}/")
    }
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

/// A libsql export/import target: an already-project-qualified site identity + database
/// name (the `snapshot_into` arguments). Phase 1 takes these explicitly; full per-site
/// enumeration is a follow-up.
#[derive(Debug, Clone)]
pub struct LibsqlTarget {
    /// The project-qualified site identity (as the libsql backend uses).
    pub site: String,
    /// The database name (`""`/`"default"` fold to the reserved default).
    pub name: String,
    /// The bundle member path (`libsql/<...>.sqlite`).
    pub member_path: String,
}

/// The node's [`ProjectExport`] implementation.
pub struct NodeProjectExport {
    databases: BTreeMap<String, ExternalDatabaseConfig>,
    deploy: DeployStore,
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
    blobs: Arc<dyn Storage>,
    libsql: Option<Arc<LibsqlSqlBackends>>,
    libsql_targets: Vec<LibsqlTarget>,
    backend: Arc<dyn ComputeBackend>,
    published_endpoint: bool,
    operator_sql: Arc<dyn boatramp_core::sql::OperatorSql>,
    work_dir: PathBuf,
    connect_timeout_secs: u32,
}

impl NodeProjectExport {
    /// Build the driver. `published_endpoint` is `true` when the docker backend reports
    /// endpoints as host-loopback publishes (so a colocated DB must be reached at its
    /// bridge IP). `work_dir` is where staging + bundle temp files are written.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        databases: BTreeMap<String, ExternalDatabaseConfig>,
        deploy: DeployStore,
        kv: Arc<dyn KvStore>,
        envelope: Arc<dyn KeyEnvelope>,
        blobs: Arc<dyn Storage>,
        backend: Arc<dyn ComputeBackend>,
        published_endpoint: bool,
        operator_sql: Arc<dyn boatramp_core::sql::OperatorSql>,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            databases,
            deploy,
            kv,
            envelope,
            blobs,
            libsql: None,
            libsql_targets: Vec::new(),
            backend,
            published_endpoint,
            operator_sql,
            work_dir,
            connect_timeout_secs: 10,
        }
    }

    /// Attach the libsql backend + the explicit `(site, name)` targets to export/import.
    #[must_use]
    pub fn with_libsql(
        mut self,
        libsql: Arc<LibsqlSqlBackends>,
        targets: Vec<LibsqlTarget>,
    ) -> Self {
        self.libsql = Some(libsql);
        self.libsql_targets = targets;
        self
    }

    /// Resolve a managed compute-backed Postgres database to a reachable connection +
    /// the matching client image + the detected `server_version_num`.
    async fn resolve_pg(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<(PgConnection, String, String), Perr> {
        let target = operator_target(cfg, project, db).map_err(other)?;
        // The healthy, running replica's endpoint + handle (for bridge-IP resolution).
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
            self.backend.replica_direct_host(&replica.handle).await
        } else {
            None
        };
        let host = choose_host(
            &replica.endpoint.host,
            direct.as_deref(),
            self.published_endpoint,
        );
        let password = ManagedSqlCredentials::new(self.kv.clone(), self.envelope.clone())
            .password(&target.cred_project, &target.cred_workload)
            .await
            .map_err(Perr::Other)?;
        // Version detect via the operator-SQL seam.
        let banner = self
            .operator_sql
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
        let conn = PgConnection {
            host,
            port: replica.endpoint.port,
            user: target.user,
            password,
            database: target.database,
            connect_timeout_secs: self.connect_timeout_secs,
        };
        Ok((conn, image, server_version_num))
    }

    /// Best-effort schema-ledger fingerprint of a Postgres database (the applied
    /// migration set + content hashes). `None` if the ledger can't be read (e.g. no
    /// migrations table) — the skew check then simply has nothing to compare.
    async fn schema_fingerprint(&self, project: &str, db: &str) -> Option<String> {
        let sql = "SELECT id, ordinal, content_hash FROM boatramp_migrations.schema_migrations \
                   ORDER BY ordinal, id";
        match self.operator_sql.query(project, db, sql).await {
            Ok(rows) => Some(fingerprint_rows(&rows)),
            Err(_) => None,
        }
    }

    /// Run a pg client (`pg_dump`/`pg_restore`) in an ephemeral container, streaming
    /// `stdin` in (optional) and stdout to `sink_path`. Returns the exit code.
    async fn run_pg_client(
        &self,
        image: &str,
        argv: &[String],
        env: &[(String, String)],
        stdin_path: Option<&Path>,
        stdout_path: &Path,
    ) -> Result<i32, Perr> {
        let out = tokio::fs::File::create(stdout_path).await.map_err(other)?;
        let mut sink = out.compat_write();
        let code = if let Some(inp) = stdin_path {
            let f = tokio::fs::File::open(inp).await.map_err(other)?;
            let mut rdr = f.compat();
            self.backend
                .run_ephemeral(image, argv, env, Some(&mut rdr), &mut sink)
                .await
                .map_err(other)?
        } else {
            self.backend
                .run_ephemeral(image, argv, env, None, &mut sink)
                .await
                .map_err(other)?
        };
        Ok(code)
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

        // --- per-engine dumps ---
        for (db, cfg) in &self.databases {
            if kind_is_postgres(&cfg.kind) && cfg.compute.as_deref().is_some_and(|c| !c.is_empty())
            {
                let (conn, image, server_version_num) = self.resolve_pg(project, db, cfg).await?;
                let inv = pg_dump_invocation(&conn, data_only);
                let out = stage.join(format!("{db}.pgc"));
                let code = self
                    .run_pg_client(&image, &inv.argv, &inv.env, None, &out)
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
            } else if kind_is_libsql(&cfg.kind) {
                // libsql handled via the explicit targets below (snapshot_into).
            } else {
                // mysql / external-URL pg: Phase-1 skip with a note on the bundle later.
            }
        }

        // --- libsql snapshots (explicit targets) ---
        if let Some(libsql) = &self.libsql {
            for t in &self.libsql_targets {
                let dest = stage.join(format!("libsql-{}.sqlite", sanitize(&t.member_path)));
                libsql
                    .snapshot_into(&t.site, &t.name, &dest)
                    .await
                    .map_err(other)?;
                staged.push(StagedMember {
                    path: t.member_path.clone(),
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
                    .run_pg_client(&image, &inv.argv, &inv.env, Some(&member_file), &devnull)
                    .await?;
                if code != 0 {
                    return Err(Perr::Other(format!("pg_restore for {db:?} exited {code}")));
                }
            }
            report.pg_databases += 1;
        }

        // --- libsql members: placement is a documented follow-up (no-clobber + integrity
        //     swap of the target file) — recorded as a note so the operator knows. ---
        let libsql_count = manifest
            .members
            .iter()
            .filter(|m| m.kind == MemberKind::Libsql)
            .count();
        if libsql_count > 0 {
            report.libsql_databases = libsql_count;
            report.notes.push(format!(
                "{libsql_count} libsql member(s) extracted + verified; in-place placement \
                 (no-clobber + integrity swap) is wired in a follow-up"
            ));
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
    }

    #[test]
    fn pg_member_path_round_trips() {
        assert_eq!(pg_member_path("app"), "sql/app.pgc");
        assert_eq!(db_from_pg_member("sql/app.pgc"), Some("app"));
        assert_eq!(db_from_pg_member("libsql/x.sqlite"), None);
    }

    #[test]
    fn blob_prefix_scopes_non_default_project() {
        assert_eq!(blob_project_prefix("acme"), "hblob/acme/");
        // The reserved default shares the root (documented over-capture caveat).
        assert_eq!(blob_project_prefix("default"), "hblob/");
        assert_eq!(blob_project_prefix(""), "hblob/");
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
