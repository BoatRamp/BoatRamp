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

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use futures::io::{AsyncReadExt, AsyncWriteExt};
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
    ExportOptions, IdentityChoice, ImportOptions, ImportReport, ProjectExport, ProjectExportError,
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
    self, IDENTITY_MEMBER_PATH, KV_MEMBER_PATH, MemberKind, MemberSpec, PgMemberInfo, SourceInfo,
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

/// Bound of the in-flight byte channel bridging the blocking v2 tar reader/writer to the
/// async sink/source. A handful of ~tar-block writes — small, fixed memory; the staging
/// bound (one member on disk) is what the format's streaming guarantee rests on.
const STREAM_BYTE_CHANNEL: usize = 16;

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

/// Whether a binding `kind` names libsql/SQLite. Completes the kind-classification trio
/// (`postgres`/`mysql`/`libsql`) and is exercised by the `kind_detection` gate; the export loop
/// routes a libsql binding through the per-site snapshot path rather than this classifier, so it
/// has no non-test caller.
#[allow(dead_code)]
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

/// Defense-in-depth project-slug validation at the DRIVER entry (the admin handler
/// already rejects an invalid slug, but a direct driver caller must be guarded too — the
/// `project` string flows into temp paths, libsql `local_path`, the blob prefix, and
/// `ProjectRef::qualified`, so a `..`/`/` would traverse). Mirrors the canonical
/// resource-name validator every other surface uses.
fn check_project_slug(project: &str) -> Result<(), Perr> {
    boatramp_core::project::validate_resource_name("project", project)
        .map_err(|e| Perr::Other(e.to_string()))
}

/// Whether a `--data-only` import must REFUSE (absent `--allow-schema-skew`): it may
/// proceed ONLY when both schema-ledger fingerprints are present AND equal (proven
/// compatible). A mismatch — OR a MISSING fingerprint on either side — cannot prove the
/// target's existing schema matches the data, so it blocks (fail-closed).
fn data_only_skew_blocks(src_fp: Option<&str>, tgt_fp: Option<&str>) -> bool {
    !matches!((src_fp, tgt_fp), (Some(s), Some(t)) if s == t)
}

/// Re-qualify ONE streamed blob member to the TARGET project's scope — the per-blob,
/// forward-pass analogue of the v1 whole-directory rename, and THE tenancy-critical seam of
/// the streaming import. A blob member path is `blobs/hblob/{source}/{site}/{container}/…`;
/// this strips the `blobs/` wrapper and rewrites the leading `hblob/{source}/` segment to
/// `hblob/{target}/`, returning the TARGET-scope storage key `hblob/{target}/…`.
///
/// **Fail-closed.** A member whose key is NOT under `hblob/{source}/` is REFUSED (never
/// silently `put` under a foreign scope), and the key is only ever rebuilt as
/// `hblob/{target}/…` — so every imported object lands in the target project's scope and no
/// source-scope (or other-tenant) key can survive a rename. This mirrors the C1 KV re-key
/// (`rekey_owned_key`) at the blob layer; a leak here shipped a CRITICAL once, so the mapping
/// is explicit and total, not best-effort.
fn target_blob_key(member_path: &str, source: &str, target: &str) -> Result<String, Perr> {
    let src_key = member_path.strip_prefix("blobs/").ok_or_else(|| {
        Perr::Other(format!(
            "blob member path {member_path:?} is missing its 'blobs/' prefix"
        ))
    })?;
    let src_pref = format!("hblob/{source}/");
    let rest = src_key.strip_prefix(&src_pref).ok_or_else(|| {
        Perr::Other(format!(
            "blob member {src_key:?} is not under the source project scope {src_pref:?}; \
             refusing to import a wrong-scope blob (cross-tenant isolation)"
        ))
    })?;
    Ok(format!("hblob/{target}/{rest}"))
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
/// What the identity export needs to know about the node's secrets envelope — a minimal,
/// NON-secret projection of the node's `EnvelopeSpec` (never the Vault token). Set via
/// [`with_identity_source`](NodeProjectExport::with_identity_source); absent ⇒
/// `--include-identity` is refused (no local KEK to carry).
#[derive(Debug, Clone)]
pub enum IdentityEnvelope {
    /// A local KEK file (raw 32 bytes) — the only kind whose KEK is transportable.
    Local { kek_file: PathBuf },
    /// A Vault/KMS-backed KEK — never extractable, so `--include-identity` is refused.
    Vault,
    /// No secrets envelope — nothing is sealed, nothing to carry.
    None,
}

/// Magic for the identity payload carried INSIDE the transport container.
const IDENTITY_PAYLOAD_MAGIC: &[u8; 6] = b"BRIDP1";

/// Serialize the identity payload: currently just the raw KEK, framed
/// `[magic][u8 version=1][u8 kek_len][kek]` — unambiguous and extensible (a future version
/// may append on-disk sealed key files). The payload is sealed by the AEAD transport
/// container, so this framing only needs to round-trip deterministically.
fn identity_payload_bytes(kek: &[u8]) -> Result<Vec<u8>, Perr> {
    if kek.len() > u8::MAX as usize {
        return Err(Perr::Other("KEK too large for the identity payload".into()));
    }
    let mut v = Vec::with_capacity(IDENTITY_PAYLOAD_MAGIC.len() + 2 + kek.len());
    v.extend_from_slice(IDENTITY_PAYLOAD_MAGIC);
    v.push(1u8);
    v.push(kek.len() as u8);
    v.extend_from_slice(kek);
    Ok(v)
}

/// Parse an [`identity_payload_bytes`] blob back to the raw KEK (import `--identity adopt`).
fn parse_identity_payload(bytes: &[u8]) -> Result<Vec<u8>, Perr> {
    let rest = bytes
        .strip_prefix(IDENTITY_PAYLOAD_MAGIC.as_slice())
        .ok_or_else(|| Perr::Other("identity payload: bad magic".into()))?;
    if rest.len() < 2 {
        return Err(Perr::Other("identity payload: truncated header".into()));
    }
    if rest[0] != 1 {
        return Err(Perr::Other(format!(
            "identity payload: unsupported version {}",
            rest[0]
        )));
    }
    let kek_len = rest[1] as usize;
    let kek = &rest[2..];
    if kek.len() != kek_len {
        return Err(Perr::Other("identity payload: KEK length mismatch".into()));
    }
    Ok(kek.to_vec())
}

/// Install `kek` at `path` as the node's `secrets/kek`, `0600` (owner-only) — the master
/// secret must never be world/group-readable. Used by `--identity adopt`.
async fn write_kek_file(path: &std::path::Path, kek: &[u8]) -> Result<(), Perr> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(other)?;
    }
    let path = path.to_path_buf();
    let kek = kek.to_vec();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            // O_EXCL (`create_new`): never clobber or truncate an existing KEK. The adopt caller
            // has already read-and-compared any existing KEK (no-clobber); creating exclusively
            // here closes the check→write TOCTOU window — if a KEK appeared in between, the write
            // fails loudly rather than overwriting the master secret.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(&kek)
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, &kek)
        }
    })
    .await
    .map_err(other)?
    .map_err(other)
}

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
    /// The secrets-envelope projection for `--include-identity` (local KEK path / Vault /
    /// none). `None` ⇒ identity export is refused. Never holds a secret (no Vault token).
    identity_source: Option<IdentityEnvelope>,
    work_dir: PathBuf,
    connect_timeout_secs: u32,
    /// Operator digest-pin / override for the ephemeral Postgres client image
    /// (`pg_dump`/`pg_restore`/`psql`). `Some` ⇒ used verbatim instead of the version-computed
    /// `pgvector/pgvector:pg{major}` tag — e.g. a `@sha256:`-pinned ref accepted under the
    /// multi-tenant posture. `None` ⇒ the computed tag.
    pg_client_image: Option<String>,
    /// MySQL counterpart — overrides the computed `mysql:<maj.min>` client image.
    mysql_client_image: Option<String>,
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
            identity_source: None,
            work_dir,
            connect_timeout_secs: 10,
            pg_client_image: None,
            mysql_client_image: None,
        }
    }

    /// Supply an operator override for the ephemeral SQL-client images (the `pg_dump`/`mysqldump`/
    /// `psql` one-shots). Each `Some(ref)` is used VERBATIM in place of the version-computed tag —
    /// so a digest-pinned ref (`pgvector/pgvector:pg16@sha256:<hex>`) can be accepted under the
    /// multi-tenant posture with no rootfs staging. `None` keeps the computed tag.
    #[must_use]
    pub fn with_client_images(
        mut self,
        pg_client_image: Option<String>,
        mysql_client_image: Option<String>,
    ) -> Self {
        self.pg_client_image = pg_client_image;
        self.mysql_client_image = mysql_client_image;
        self
    }

    /// The Postgres client image for `server_version_num`: the operator override
    /// ([`with_client_images`](Self::with_client_images)) used VERBATIM, else the version-computed
    /// `pgvector/pgvector:pg{major}` tag. A verbatim override lets a `@sha256:`-pinned ref be
    /// accepted under the multi-tenant posture; a wrong-major pin fails loud at `pg_dump` time.
    fn pg_image(
        &self,
        server_version_num: &str,
    ) -> Result<String, boatramp_core::compute::VersionMapError> {
        match &self.pg_client_image {
            Some(pinned) => Ok(pinned.clone()),
            None => boatramp_core::compute::pg_client_image_for_server_version(server_version_num),
        }
    }

    /// MySQL counterpart of [`pg_image`](Self::pg_image) — the override verbatim, else the
    /// computed `mysql:<maj.min>` tag.
    fn mysql_image(
        &self,
        version: &str,
    ) -> Result<String, boatramp_core::compute::VersionMapError> {
        match &self.mysql_client_image {
            Some(pinned) => Ok(pinned.clone()),
            None => boatramp_core::compute::mysql_client_image_for_server_version(version),
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

    /// Attach the secrets-envelope projection so `--include-identity` can carry the project
    /// KEK (local envelope only). Not called ⇒ `--include-identity` is refused.
    #[must_use]
    pub fn with_identity_source(mut self, source: IdentityEnvelope) -> Self {
        self.identity_source = Some(source);
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
        let image = self
            .pg_image(&server_version_num)
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
        let image = self
            .mysql_image(&version)
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

// ---------------------------------------------------------------------------
// Streaming bridge — the sync `project_bundle` tar reader/writer runs in a
// `spawn_blocking` task and talks to the async driver (which owns `self` and the
// caller's async sink/source) over bounded channels. No `block_on` is nested on a
// runtime thread, so this is deadlock-free on BOTH the current-thread and the
// multi-thread tokio runtime; the channel bounds keep the bundle from ever buffering
// in memory, and each member is staged/restored one at a time (O(largest member)).
// ---------------------------------------------------------------------------

/// A synchronous [`Write`] that forwards each write to an async drain over a bounded
/// channel — the bridge from the blocking v2 tar writer to the caller's async `sink`.
/// A full channel backpressures the blocking writer, so the bundle never buffers in memory.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.blocking_send(buf.to_vec()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "export sink closed")
        })?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A synchronous [`Read`] fed by an async feeder over a bounded channel — the bridge from
/// the caller's async `src` to the blocking v2 single-pass reader. Bounded memory; `None`
/// from the channel is clean EOF.
struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.blocking_recv() {
                Some(chunk) if !chunk.is_empty() => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Some(_) => continue, // skip an empty chunk rather than mistaking it for EOF
                None => return Ok(0), // all senders dropped ⇒ EOF
            }
        }
        let n = std::cmp::min(out.len(), self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// One member staged on disk by the export driver, computed just-in-time by the async stager
/// when the blocking v2 writer requests it. Carries only what the stager's `self`-driven work
/// needs; the big bytes land in a bounded temp the writer deletes right after appending.
enum StageJob {
    /// The passphrase-wrapped identity transport container (already produced at plan time).
    Identity { container: Vec<u8> },
    /// The control-plane KV logical slice — scanned + project-scoped + encoded at stage time.
    Kv { created_at: u64 },
    /// A Postgres `pg_dump` into a staging temp.
    Pg {
        conn: PgConnection,
        image: String,
        data_only: bool,
    },
    /// A MySQL `mysqldump` into a staging temp.
    Mysql {
        conn: MysqlConnection,
        image: String,
        data_only: bool,
    },
    /// A libsql `VACUUM INTO` snapshot of the project-qualified site DB.
    Libsql { qsite: String },
    /// A single blob object, streamed from the source store into a staging temp.
    Blob { key: String },
}

/// The export stager's request: "stage the member at `path`, reply with its temp path".
struct StageReq {
    path: String,
    reply: tokio::sync::oneshot::Sender<Result<PathBuf, ()>>,
}

/// The import servicer's request, sent by the blocking v2 reader as it streams.
enum ImportMsg {
    /// The bundle head (surfaced before any member) — the source project + data-only flag.
    Head {
        data_only: bool,
        source_project: String,
    },
    /// A member staged to `temp`; the servicer restores it then replies so the reader may
    /// advance (one member staged at a time ⇒ O(largest member)).
    Member {
        spec: MemberSpec,
        temp: PathBuf,
        reply: tokio::sync::oneshot::Sender<Result<(), ()>>,
    },
}

#[async_trait]
impl ProjectExport for NodeProjectExport {
    async fn export(
        &self,
        project: &str,
        opts: &ExportOptions,
        sink: &mut (dyn futures::io::AsyncWrite + Send + Unpin),
    ) -> Result<(), Perr> {
        check_project_slug(project)?;
        // A data-only bundle carries NO control-plane / identity material at all, so the
        // two flags are mutually exclusive — refuse the contradiction rather than silently
        // pick one.
        if opts.data_only && opts.include_identity {
            return Err(Perr::Other(
                "--data-only and --include-identity are mutually exclusive: a data-only \
                 bundle carries application data only (no control-plane KV, no identity)"
                    .into(),
            ));
        }
        let data_only = opts.data_only;
        let created_at = now_secs();
        let session = self.work_dir.join(format!("export-{project}-{created_at}"));
        let stage_dir = session.join("stage");
        tokio::fs::create_dir_all(&stage_dir).await.map_err(other)?;

        // 1. PLAN: enumerate every member up front — version-detect each pg/mysql DB, list the
        //    project's blobs + sites — in the v2 RESTORE order (identity → blobs → pg → mysql
        //    → libsql → KV). The v2 MANIFEST lists these before any member body exists, so the
        //    member SET is decided here; each member's BIG bytes are produced later, one at a
        //    time, by the stager. (A failure here is before the first byte, so the handler can
        //    still turn it into an error status.)
        let (specs, jobs, source) = self.plan_export(project, opts, created_at).await?;

        // 2. STREAM: run the sync v2 writer in a blocking task, bridged to (a) the caller's
        //    async `sink` over a bounded byte channel + drain, and (b) the async stager over a
        //    one-slot request channel. `write_bundle_streaming` stages → appends → deletes ONE
        //    member at a time, so the transient on-disk staging never exceeds the largest
        //    single member — never the whole bundle (the env-clone disk-fill fix).
        let (byte_tx, mut byte_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BYTE_CHANNEL);
        let (stage_tx, mut stage_rx) = tokio::sync::mpsc::channel::<StageReq>(1);
        let writer_out = ChannelWriter { tx: byte_tx };
        let stage_tx_task = stage_tx.clone();
        let specs_for_task = specs.clone();
        let source_for_task = source.clone();
        let write_handle =
            tokio::task::spawn_blocking(move || -> Result<(), project_bundle::BundleError> {
                project_bundle::write_bundle_streaming(
                    writer_out,
                    created_at,
                    data_only,
                    source_for_task,
                    specs_for_task,
                    |spec| {
                        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                        stage_tx_task
                            .blocking_send(StageReq {
                                path: spec.path.clone(),
                                reply: reply_tx,
                            })
                            .map_err(|_| {
                                project_bundle::BundleError::MalformedStream(
                                    "export stager gone".into(),
                                )
                            })?;
                        match reply_rx.blocking_recv() {
                            Ok(Ok(tmp)) => Ok(tmp),
                            _ => Err(project_bundle::BundleError::MalformedStream(
                                "export staging failed".into(),
                            )),
                        }
                    },
                )
            });
        drop(stage_tx); // only the blocking task keeps the request channel alive now

        // Async stager: produce each requested member to a bounded temp, using `self`.
        let stager = async {
            let mut idx = 0usize;
            while let Some(req) = stage_rx.recv().await {
                let res = match jobs.get(&req.path) {
                    Some(job) => self.stage_job(project, job, &stage_dir, idx).await,
                    None => Err(Perr::Other(format!(
                        "export: internal error — no stage job for member {:?}",
                        req.path
                    ))),
                };
                idx += 1;
                match res {
                    Ok(tmp) => {
                        let _ = req.reply.send(Ok(tmp));
                    }
                    Err(e) => {
                        let _ = req.reply.send(Err(()));
                        return Err::<(), Perr>(e);
                    }
                }
            }
            Ok(())
        };

        // Async drain: forward the bundle bytes to the caller's sink as they are produced.
        let drain = async {
            while let Some(chunk) = byte_rx.recv().await {
                sink.write_all(&chunk)
                    .await
                    .map_err(|e| Perr::Other(format!("export sink write failed: {e}")))?;
            }
            sink.flush()
                .await
                .map_err(|e| Perr::Other(format!("export sink flush failed: {e}")))?;
            Ok::<(), Perr>(())
        };

        let (stage_res, drain_res, write_res) = tokio::join!(stager, drain, write_handle);
        let _ = tokio::fs::remove_dir_all(&session).await;

        // Error precedence: a staging failure is the most specific cause, a writer/bundle
        // error next, a sink error last.
        stage_res?;
        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(be)) => return Err(other(be)),
            Err(je) => return Err(other(je)),
        }
        drain_res?;
        Ok(())
    }

    async fn import(
        &self,
        project: &str,
        src: &mut (dyn futures::io::AsyncRead + Send + Unpin),
        opts: ImportOptions,
    ) -> Result<ImportReport, Perr> {
        check_project_slug(project)?;
        let session = self
            .work_dir
            .join(format!("import-{project}-{}", now_secs()));
        let stage_dir = session.join("stage");
        tokio::fs::create_dir_all(&stage_dir).await.map_err(other)?;

        // Bridge: the async feeder pumps the caller's bundle stream into a bounded byte
        // channel → `ChannelReader` → the sync v2 single-pass reader (in a blocking task).
        // The reader's restore closure stages ONE member to a bounded temp then hands it to
        // the async servicer (which owns `self`) and BLOCKS until it finishes — so disk never
        // holds more than the largest single member, and the members are restored in the v2
        // declared (restore) order. Reads v2 and legacy v1 bundles alike.
        let (byte_tx, byte_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BYTE_CHANNEL);
        let (req_tx, mut req_rx) = tokio::sync::mpsc::channel::<ImportMsg>(1);
        let reader = ChannelReader::new(byte_rx);
        let stage_dir_task = stage_dir.clone();
        let req_tx_task = req_tx.clone();
        let read_handle = tokio::task::spawn_blocking(
            move || -> Result<Vec<MemberSpec>, project_bundle::BundleError> {
                let mut idx = 0usize;
                let head_tx = req_tx_task.clone();
                let on_head = move |data_only: bool, source: &SourceInfo| {
                    // Surfaced before any member: the servicer needs the source project (to
                    // re-key each member to the TARGET) and the data-only flag.
                    let _ = head_tx.blocking_send(ImportMsg::Head {
                        data_only,
                        source_project: source.project.clone(),
                    });
                };
                project_bundle::read_bundle_streaming_with_head(
                    reader,
                    on_head,
                    |spec, _size, body| {
                        // Stage this member to a bounded temp. Reading `body` to completion
                        // here is what drives the v2 reader's own per-member SHA-256 + size
                        // verification (a corrupt/truncated member is caught LOUD at its end).
                        let temp = stage_dir_task.join(format!("m{idx}"));
                        idx += 1;
                        {
                            let mut f = std::io::BufWriter::new(
                                std::fs::File::create(&temp)
                                    .map_err(project_bundle::BundleError::Io)?,
                            );
                            let mut buf = [0u8; 64 * 1024];
                            loop {
                                let n = body
                                    .read(&mut buf)
                                    .map_err(project_bundle::BundleError::Io)?;
                                if n == 0 {
                                    break;
                                }
                                f.write_all(&buf[..n])
                                    .map_err(project_bundle::BundleError::Io)?;
                            }
                            f.flush().map_err(project_bundle::BundleError::Io)?;
                        }
                        // Hand to the servicer and wait, so the NEXT member is not read (nor its
                        // temp created) until this one is restored + freed.
                        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                        req_tx_task
                            .blocking_send(ImportMsg::Member {
                                spec: spec.clone(),
                                temp: temp.clone(),
                                reply: reply_tx,
                            })
                            .map_err(|_| {
                                project_bundle::BundleError::MalformedStream(
                                    "import servicer gone".into(),
                                )
                            })?;
                        match reply_rx.blocking_recv() {
                            Ok(Ok(())) => Ok(()),
                            _ => Err(project_bundle::BundleError::MalformedStream(
                                "import restore aborted".into(),
                            )),
                        }
                    },
                )
            },
        );
        drop(req_tx); // only the blocking reader keeps the request channel alive now

        // Async feeder: pump the caller's bundle stream into the blocking reader.
        let feeder = async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = src
                    .read(&mut buf)
                    .await
                    .map_err(|e| Perr::Other(format!("import body read failed: {e}")))?;
                if n == 0 {
                    break;
                }
                if byte_tx.send(buf[..n].to_vec()).await.is_err() {
                    break; // the reader stopped (error / early finish) — nothing more to feed
                }
            }
            drop(byte_tx);
            Ok::<(), Perr>(())
        };

        // Async servicer: restore each staged member using `self`, in arrival (restore) order.
        let servicer = async {
            let mut report = ImportReport {
                dry_run: !opts.apply,
                ..Default::default()
            };
            let mut data_only = false;
            let mut source_project = String::new();
            let mut saw_identity = false;
            while let Some(msg) = req_rx.recv().await {
                match msg {
                    ImportMsg::Head {
                        data_only: d,
                        source_project: s,
                    } => {
                        data_only = d;
                        source_project = s;
                    }
                    ImportMsg::Member { spec, temp, reply } => {
                        let r = self
                            .restore_member(
                                project,
                                data_only,
                                &source_project,
                                &spec,
                                &temp,
                                &opts,
                                &mut report,
                                &mut saw_identity,
                            )
                            .await;
                        let _ = tokio::fs::remove_file(&temp).await;
                        match r {
                            Ok(()) => {
                                let _ = reply.send(Ok(()));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(()));
                                return Err::<_, Perr>(e);
                            }
                        }
                    }
                }
            }
            Ok((report, data_only, saw_identity))
        };

        let (feed_res, serv_res, read_res) = tokio::join!(feeder, servicer, read_handle);

        // Error precedence: a restore failure is the most specific cause; a bundle-integrity
        // error (SHA / size / order / truncation) next; a body-read error last. On ANY error
        // skip the post-stream steps (fresh-drop etc.) so a half-stream never half-finishes.
        let (mut report, data_only, saw_identity) = match serv_res {
            Ok(v) => v,
            Err(e) => {
                let _ = tokio::fs::remove_dir_all(&session).await;
                return Err(e);
            }
        };
        match read_res {
            Ok(Ok(_specs)) => {}
            Ok(Err(be)) => {
                let _ = tokio::fs::remove_dir_all(&session).await;
                return Err(other(be));
            }
            Err(je) => {
                let _ = tokio::fs::remove_dir_all(&session).await;
                return Err(other(je));
            }
        }
        if let Err(e) = feed_res {
            let _ = tokio::fs::remove_dir_all(&session).await;
            return Err(e);
        }

        // --- post-stream steps (only after a clean, fully-verified pass) ---

        // A `--data-only` bundle carries app data only; record that KV was not restored.
        if data_only {
            report
                .notes
                .push("control-plane KV (identity/RBAC/routing) NOT imported: --data-only".into());
        }

        // `adopt` requires the bundle to carry an identity member. For a FULL bundle this is
        // enforced earlier (at the KV member, before any sealed KV byte is written); this
        // final check also covers a bundle with no KV member (e.g. data-only + adopt).
        if matches!(opts.identity, IdentityChoice::Adopt { .. }) && !saw_identity {
            let _ = tokio::fs::remove_dir_all(&session).await;
            return Err(Perr::Other(
                "--identity adopt requires a bundle exported with --include-identity \
                 (no identity member present); use --identity fresh to import a bundle \
                 without identity"
                    .into(),
            ));
        }

        // --- fresh identity: drop the source sealed-secret keyspace (Ask-4c) ---
        // A `fresh` import of a FULL bundle just restored the SOURCE's KEK-sealed secrets
        // (operator/app + per-tenant), which can never unseal under this node's own
        // (different) KEK. Drop them so the target starts clean and re-provisions — making
        // "zero source-sealed artifacts that unwrap" a POSITIVE absence rather than
        // present-but-inert. Only for a FULL bundle (data-only carries no KV/secrets) and
        // only when applying.
        if matches!(opts.identity, IdentityChoice::Fresh) && !data_only && opts.apply {
            let prefixes =
                boatramp_core::project_export::sealed_secret_prefixes(ProjectRef::new(project));
            let mut dropped = 0usize;
            for prefix in &prefixes {
                for key in self.kv.list_prefix(prefix).await.map_err(other)? {
                    self.kv.delete_checkpointed(&key).await.map_err(other)?;
                    dropped += 1;
                }
            }
            report.notes.push(format!(
                "identity: --fresh dropped {dropped} source-sealed secret key(s); re-provision \
                 secrets + the managed-DB credential on the target"
            ));
        }

        // Operational prerequisites after a FULL control-plane restore — the portable bundle
        // deliberately carries no function/component CODE (deploy artifacts live in blob storage,
        // not this slice), no TLS private keys and no global routing ownership. Surface the
        // follow-up steps so the target is not silently half-restored.
        if !data_only {
            report.notes.push(
                "post-import: re-deploy function/component code (deploy artifacts are not \
                 bundled), re-verify + re-attach the project's domains, and let ACME re-issue TLS \
                 certs (routing + certs are intentionally not carried in a portable bundle)"
                    .into(),
            );
        }

        let _ = tokio::fs::remove_dir_all(&session).await;
        Ok(report)
    }
}

impl NodeProjectExport {
    /// Enumerate every bundle member UP FRONT, in the v2 RESTORE order (identity → blobs → pg
    /// → mysql → libsql → KV), returning the ordered [`MemberSpec`] list the v2 MANIFEST
    /// declares, a per-member [`StageJob`] (how to produce each one's bytes later), and the
    /// bundle [`SourceInfo`]. Version-detects each pg/mysql DB (so the manifest can carry its
    /// provenance), lists the project's blobs + sites, and checkpoints the KV frontier for a
    /// full export — all CHEAP relative to the member bodies, which are produced one at a time
    /// by [`stage_job`](Self::stage_job) during the stream.
    async fn plan_export(
        &self,
        project: &str,
        opts: &ExportOptions,
        created_at: u64,
    ) -> Result<(Vec<MemberSpec>, HashMap<String, StageJob>, SourceInfo), Perr> {
        let data_only = opts.data_only;
        let mut ordered: Vec<(MemberSpec, StageJob)> = Vec::new();

        // --- identity transport container (`--include-identity` only) — FIRST (an adopt
        //     import must install the KEK before the KV slice). Local envelope only. ---
        if opts.include_identity {
            let transport_key = opts
                .transport_key
                .as_deref()
                .ok_or_else(|| Perr::Other("--include-identity requires a transport key".into()))?;
            match self.identity_source.as_ref() {
                Some(IdentityEnvelope::Local { kek_file }) => {
                    let kek = tokio::fs::read(kek_file).await.map_err(|e| {
                        Perr::Other(format!("reading KEK {}: {e}", kek_file.display()))
                    })?;
                    let payload = identity_payload_bytes(&kek)?;
                    let container =
                        boatramp_server::envelope::transport_wrap(&payload, transport_key)
                            .map_err(|e| {
                                Perr::Other(format!("wrapping the identity container: {e}"))
                            })?;
                    ordered.push((
                        MemberSpec {
                            path: IDENTITY_MEMBER_PATH.to_string(),
                            kind: MemberKind::Identity,
                            pg: None,
                        },
                        StageJob::Identity { container },
                    ));
                }
                Some(IdentityEnvelope::Vault) => {
                    return Err(Perr::Other(
                        "--include-identity is not supported for a Vault KEK: the key never \
                         leaves the KMS and cannot be bundled. For a faithful recovery, point \
                         the target node's [secrets.vault] at the same key; otherwise use \
                         --identity fresh."
                            .into(),
                    ));
                }
                Some(IdentityEnvelope::None) | None => {
                    return Err(Perr::Other(
                        "--include-identity requires a local KEK envelope \
                         ([secrets].envelope = \"local\"); none is configured on this node"
                            .into(),
                    ));
                }
            }
        }

        // Checkpoint the durable KV frontier BEFORE we enumerate (full export only), so the
        // KV slice staged later reflects a consistent frontier.
        if !data_only {
            self.deploy.checkpoint().await.map_err(other)?;
        }

        // --- blobs: enumerate the project's objects (metadata only; bodies stream later). A
        //     blob key is `hblob/{project}/…`; the member path wraps it as `blobs/{key}`
        //     (identical to the v1 layout), so the import re-keys the leading project segment
        //     to the TARGET on the way back in. ---
        let blob_metas = self
            .blobs
            .list(&blob_project_prefix(project))
            .await
            .map_err(other)?;
        for meta in blob_metas {
            let member_path = format!("blobs/{}", meta.key);
            ordered.push((
                MemberSpec {
                    path: member_path,
                    kind: MemberKind::Blob,
                    pg: None,
                },
                StageJob::Blob { key: meta.key },
            ));
        }

        // --- per-engine dumps (pg + mysql; managed OR external bring-your-own-URL) ---
        for (db, cfg) in &self.databases {
            let dumpable =
                cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) || !cfg.url_env.is_empty();
            if kind_is_postgres(&cfg.kind) && dumpable {
                let (conn, image, server_version_num) = self.resolve_pg(project, db, cfg).await?;
                let schema_fingerprint = self.schema_fingerprint(project, db).await;
                ordered.push((
                    MemberSpec {
                        path: pg_member_path(db),
                        kind: MemberKind::PgDump,
                        pg: Some(PgMemberInfo {
                            server_version_num,
                            client_image: image.clone(),
                            schema_fingerprint,
                        }),
                    },
                    StageJob::Pg {
                        conn,
                        image,
                        data_only,
                    },
                ));
            } else if kind_is_mysql(&cfg.kind) && dumpable {
                let (conn, image, version) = self.resolve_mysql(project, db, cfg).await?;
                let schema_fingerprint = self.schema_fingerprint(project, db).await;
                ordered.push((
                    MemberSpec {
                        path: mysql_member_path(db),
                        kind: MemberKind::MysqlDump,
                        pg: Some(PgMemberInfo {
                            server_version_num: version,
                            client_image: image.clone(),
                            schema_fingerprint,
                        }),
                    },
                    StageJob::Mysql {
                        conn,
                        image,
                        data_only,
                    },
                ));
            }
        }

        // --- libsql snapshots: enumerate the project's sites AUTHORITATIVELY from the deploy
        //     store (never a filesystem walk), one member per site whose embedded default DB
        //     exists on disk. ---
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
                ordered.push((
                    MemberSpec {
                        path: libsql_member_path(project, &site),
                        kind: MemberKind::Libsql,
                        pg: None,
                    },
                    StageJob::Libsql { qsite },
                ));
            }
        }

        // --- control-plane KV slice (FULL export only) — LAST in restore order. A
        //     `--data-only` bundle carries application data ONLY, never the KV slice (RBAC,
        //     routing, personas, sealed secrets), so it is not even staged for data-only. ---
        if !data_only {
            ordered.push((
                MemberSpec {
                    path: KV_MEMBER_PATH.to_string(),
                    kind: MemberKind::Kv,
                    pg: None,
                },
                StageJob::Kv { created_at },
            ));
        }

        let specs: Vec<MemberSpec> = ordered.iter().map(|(s, _)| s.clone()).collect();
        let jobs: HashMap<String, StageJob> =
            ordered.into_iter().map(|(s, j)| (s.path, j)).collect();
        Ok((
            specs,
            jobs,
            SourceInfo {
                project: project.to_string(),
                site: None,
            },
        ))
    }

    /// Produce ONE member's bytes into a bounded staging temp (`stage_dir/m{idx}`), returning
    /// its path. The v2 writer appends the temp then deletes it immediately, so at most one
    /// member is ever staged on disk (the O(largest-member) footprint).
    async fn stage_job(
        &self,
        project: &str,
        job: &StageJob,
        stage_dir: &Path,
        idx: usize,
    ) -> Result<PathBuf, Perr> {
        let tmp = stage_dir.join(format!("m{idx}"));
        match job {
            StageJob::Identity { container } => {
                tokio::fs::write(&tmp, container).await.map_err(other)?;
            }
            StageJob::Kv { created_at } => {
                // Scope the control-plane KV slice to THIS project (C1 cross-tenant isolation):
                // keep ONLY the project's owned keyspace + the site-config bodies it references,
                // dropping every other tenant's material and the global TLS/routing/daemon keys
                // (fail-closed).
                let all = boatramp_core::kv_dump::scan_dumpable(self.kv.as_ref())
                    .await
                    .map_err(other)?;
                let scoped = boatramp_core::project_export::scope_entries_to_project(
                    all,
                    ProjectRef::new(project),
                );
                let kv_bytes = boatramp_core::kv_dump::encode_dump(&scoped, *created_at);
                tokio::fs::write(&tmp, &kv_bytes).await.map_err(other)?;
            }
            StageJob::Pg {
                conn,
                image,
                data_only,
            } => {
                let inv = pg_dump_invocation(conn, *data_only);
                let code = self
                    .run_sql_client(image, &inv.argv, &inv.env, None, &tmp)
                    .await?;
                if code != 0 {
                    return Err(Perr::Other(format!("pg_dump exited {code}")));
                }
            }
            StageJob::Mysql {
                conn,
                image,
                data_only,
            } => {
                let inv = mysqldump_invocation(conn, *data_only);
                let code = self
                    .run_sql_client(image, &inv.argv, &inv.env, None, &tmp)
                    .await?;
                if code != 0 {
                    return Err(Perr::Other(format!("mysqldump exited {code}")));
                }
            }
            StageJob::Libsql { qsite } => {
                let libsql = self.libsql.as_ref().ok_or_else(|| {
                    Perr::Other("internal error: libsql stage job with no libsql backend".into())
                })?;
                libsql.snapshot_into(qsite, "", &tmp).await.map_err(other)?;
            }
            StageJob::Blob { key } => {
                // Stream the object from the source store straight into the temp — never
                // buffer the whole object in memory.
                let obj = self.blobs.get(key).await.map_err(other)?;
                let mut body = obj.body;
                let mut f = tokio::fs::File::create(&tmp).await.map_err(other)?;
                use tokio::io::AsyncWriteExt as _;
                while let Some(chunk) = body.next().await {
                    let chunk = chunk.map_err(other)?;
                    f.write_all(chunk.as_ref()).await.map_err(other)?;
                }
                f.flush().await.map_err(other)?;
            }
        }
        Ok(tmp)
    }

    /// Restore ONE streamed member (already staged at `temp`) into the TARGET `project`,
    /// routed by `spec.kind`. Mutates `report`; tracks whether an identity member has been
    /// seen (`saw_identity`) so an `adopt` import can be refused before the KV slice is
    /// written if the bundle carries no identity.
    #[allow(clippy::too_many_arguments)]
    async fn restore_member(
        &self,
        project: &str,
        data_only: bool,
        source_project: &str,
        spec: &MemberSpec,
        temp: &Path,
        opts: &ImportOptions,
        report: &mut ImportReport,
        saw_identity: &mut bool,
    ) -> Result<(), Perr> {
        match spec.kind {
            MemberKind::Identity => {
                *saw_identity = true;
                match &opts.identity {
                    IdentityChoice::Adopt { transport_key } => {
                        match self.identity_source.as_ref() {
                            Some(IdentityEnvelope::Local { kek_file }) => {
                                let container = tokio::fs::read(temp).await.map_err(other)?;
                                let payload = boatramp_server::envelope::transport_unwrap(
                                    &container,
                                    transport_key,
                                )
                                .map_err(|e| {
                                    Perr::Other(format!(
                                        "opening the identity container (wrong transport key?): {e}"
                                    ))
                                })?;
                                let kek = parse_identity_payload(&payload)?;
                                // No-clobber: never adopt OVER a different live KEK.
                                match tokio::fs::read(kek_file).await {
                                    Ok(existing) if existing != kek => {
                                        return Err(Perr::Other(format!(
                                            "refusing to adopt: this node already holds a DIFFERENT \
                                         KEK at {} — adopt is for recovery onto a fresh node; use \
                                         --identity fresh to import into a different environment",
                                            kek_file.display()
                                        )));
                                    }
                                    Ok(_) => { /* identical KEK already present — idempotent */ }
                                    Err(_) => {
                                        if opts.apply {
                                            write_kek_file(kek_file, &kek).await?;
                                        }
                                    }
                                }
                                report
                                    .notes
                                    .push("identity: adopted the source KEK (recovery)".into());
                            }
                            Some(IdentityEnvelope::Vault) | Some(IdentityEnvelope::None) | None => {
                                return Err(Perr::Other(
                                "--identity adopt installs a local KEK from the bundle, but this \
                                 node's secrets envelope is not local; for a Vault recovery point \
                                 [secrets.vault] at the same key, or use --identity fresh"
                                    .into(),
                            ));
                            }
                        }
                    }
                    IdentityChoice::Fresh => {
                        report.notes.push(
                            "identity: bundle carries an identity member, but --identity fresh \
                             was selected; the source KEK was NOT installed"
                                .into(),
                        );
                    }
                }
            }
            MemberKind::Blob => {
                // RE-QUALIFY to the TARGET project's scope, FAIL-CLOSED — the tenancy-critical
                // seam. Every imported object lands under `hblob/{project}/`; a wrong-scope
                // member is refused, so no source-scope (or other-tenant) key can survive a
                // rename.
                let target_key = target_blob_key(&spec.path, source_project, project)?;
                report.blobs += 1;
                if opts.apply {
                    // Stream the staged member into the target key via the `Storage::put`
                    // byte-stream path (reuses `FsStorage`'s streaming get) — the whole blob is
                    // never buffered in memory.
                    let staged_dir = temp.parent().ok_or_else(|| {
                        Perr::Other("blob staging temp has no parent directory".into())
                    })?;
                    let staged_name = temp
                        .file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| Perr::Other("blob staging temp has no file name".into()))?;
                    let staged = boatramp_storage::FsStorage::new(staged_dir);
                    let obj = staged.get(staged_name).await.map_err(other)?;
                    self.blobs
                        .put(
                            &target_key,
                            obj.body,
                            boatramp_core::PutMeta { content_type: None },
                        )
                        .await
                        .map_err(other)?;
                }
            }
            MemberKind::PgDump => {
                let db = db_from_pg_member(&spec.path)
                    .ok_or_else(|| Perr::Other(format!("bad pg member path {:?}", spec.path)))?;
                let cfg = self.databases.get(db).ok_or_else(|| {
                    Perr::Other(format!("import: no database named {db:?} on this node"))
                })?;
                let (conn, image, _ver) = self.resolve_pg(project, db, cfg).await?;
                if data_only {
                    let src_fp = spec.pg.as_ref().and_then(|p| p.schema_fingerprint.clone());
                    let tgt_fp = self.schema_fingerprint(project, db).await;
                    if data_only_skew_blocks(src_fp.as_deref(), tgt_fp.as_deref()) {
                        report.schema_skew.push(db.to_string());
                        if !opts.allow_schema_skew {
                            return Err(Perr::SchemaSkew(vec![db.to_string()]));
                        }
                    }
                }
                if opts.apply {
                    let inv = pg_restore_invocation(&conn, data_only);
                    let devnull = temp.with_extension("restore.out");
                    let code = self
                        .run_sql_client(&image, &inv.argv, &inv.env, Some(temp), &devnull)
                        .await?;
                    let _ = tokio::fs::remove_file(&devnull).await;
                    if code != 0 {
                        return Err(Perr::Other(format!("pg_restore for {db:?} exited {code}")));
                    }
                }
                report.pg_databases += 1;
            }
            MemberKind::MysqlDump => {
                let db = db_from_mysql_member(&spec.path)
                    .ok_or_else(|| Perr::Other(format!("bad mysql member path {:?}", spec.path)))?;
                let cfg = self.databases.get(db).ok_or_else(|| {
                    Perr::Other(format!("import: no database named {db:?} on this node"))
                })?;
                let (conn, image, _ver) = self.resolve_mysql(project, db, cfg).await?;
                if data_only {
                    let src_fp = spec.pg.as_ref().and_then(|p| p.schema_fingerprint.clone());
                    let tgt_fp = self.schema_fingerprint(project, db).await;
                    if data_only_skew_blocks(src_fp.as_deref(), tgt_fp.as_deref()) {
                        report.schema_skew.push(db.to_string());
                        if !opts.allow_schema_skew {
                            return Err(Perr::SchemaSkew(vec![db.to_string()]));
                        }
                    }
                }
                if opts.apply {
                    let inv = mysql_restore_invocation(&conn, data_only);
                    let devnull = temp.with_extension("myrestore.out");
                    let code = self
                        .run_sql_client(&image, &inv.argv, &inv.env, Some(temp), &devnull)
                        .await?;
                    let _ = tokio::fs::remove_file(&devnull).await;
                    if code != 0 {
                        return Err(Perr::Other(format!(
                            "mysql restore for {db:?} exited {code}"
                        )));
                    }
                }
                report.pg_databases += 1;
            }
            MemberKind::Libsql => {
                let Some(libsql) = &self.libsql else {
                    return Err(Perr::Unavailable(
                        "bundle carries libsql members but this node has no local libsql backend \
                         to restore them into"
                            .into(),
                    ));
                };
                let site = site_from_libsql_member(&spec.path).ok_or_else(|| {
                    Perr::Other(format!("bad libsql member path {:?}", spec.path))
                })?;
                let qsite = ProjectRef::new(project).qualified(site);
                if opts.apply {
                    libsql
                        .restore_snapshot(&qsite, "", temp)
                        .await
                        .map_err(other)?;
                }
                report.libsql_databases += 1;
            }
            MemberKind::Kv => {
                if data_only {
                    // A data-only bundle should not carry a KV slice; ignore one if present
                    // (the post-stream note records that KV is not imported for data-only).
                    return Ok(());
                }
                // `adopt` must have installed the source KEK (from an identity member that
                // precedes the KV slice in v2 restore order) BEFORE any sealed KV byte is
                // written — otherwise the sealed secrets could never unseal. Refuse here,
                // fail-closed, if adopt was requested without an identity member.
                if matches!(opts.identity, IdentityChoice::Adopt { .. }) && !*saw_identity {
                    return Err(Perr::Other(
                        "--identity adopt requires a bundle exported with --include-identity \
                         (no identity member present); use --identity fresh to import a bundle \
                         without identity"
                            .into(),
                    ));
                }
                let bytes = tokio::fs::read(temp).await.map_err(other)?;
                let mut decoded = boatramp_core::kv_dump::decode_dump(&bytes).map_err(other)?;
                // Re-qualify the control-plane slice to the TARGET project (matches the blob +
                // libsql re-qualification), so a project-rename import lands every owned key in
                // the target's scope — and the --fresh drop (keyed on the target) removes the
                // right sealed keys rather than nothing.
                boatramp_core::project_export::rekey_entries_to_target(
                    &mut decoded.entries,
                    source_project,
                    project,
                );
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the streaming export into an in-memory buffer (the v2 bundle bytes) — the
    /// in-process stand-in for the HTTP response the handler wires the sink to.
    async fn export_to_buf(
        drv: &NodeProjectExport,
        project: &str,
        opts: &ExportOptions,
    ) -> Result<Vec<u8>, Perr> {
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        drv.export(project, opts, &mut sink).await?;
        Ok(sink.into_inner())
    }

    /// Read a v2 bundle buffer back into its `data_only` flag + every member (spec + bytes).
    fn read_members(bytes: &[u8]) -> (bool, Vec<(MemberSpec, Vec<u8>)>) {
        let mut data_only = false;
        let mut got: Vec<(MemberSpec, Vec<u8>)> = Vec::new();
        project_bundle::read_bundle_streaming_with_head(
            bytes,
            |d, _s| data_only = d,
            |spec, _sz, body| {
                let mut v = Vec::new();
                body.read_to_end(&mut v)
                    .map_err(project_bundle::BundleError::Io)?;
                got.push((spec.clone(), v));
                Ok(())
            },
        )
        .expect("read back the exported v2 bundle");
        (data_only, got)
    }

    /// Import a bundle buffer through the streaming driver — the in-process stand-in for the
    /// HTTP request body the handler wires the source to.
    async fn import_buf(
        drv: &NodeProjectExport,
        project: &str,
        bytes: &[u8],
        opts: ImportOptions,
    ) -> Result<ImportReport, Perr> {
        let mut src = futures::io::Cursor::new(bytes.to_vec());
        drv.import(project, &mut src, opts).await
    }

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
    fn client_image_override_is_used_verbatim_else_computed() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("blobs")));
        let deploy = DeployStore::new(blobs.clone(), kv.clone());
        let drv =
            NodeProjectExport::new(BTreeMap::new(), deploy, kv, blobs, tmp.path().join("work"));

        // No override: delegates to the version computer (and errors on an unmappable version).
        assert_eq!(
            drv.pg_image("160004").unwrap(),
            boatramp_core::compute::pg_client_image_for_server_version("160004").unwrap()
        );
        assert!(drv.pg_image("not-a-number").is_err());

        // Override: used VERBATIM and bypasses the version map entirely — a `@sha256:`-pinned ref
        // is returned even for a version the computer would reject, so the operator's pin reaches
        // `resolve_client_rootfs` (accepted under the multi-tenant posture) unchanged.
        let pinned = drv.with_client_images(
            Some("pgvector/pgvector:pg16@sha256:dead".into()),
            Some("mysql:8.4@sha256:beef".into()),
        );
        assert_eq!(
            pinned.pg_image("not-a-number").unwrap(),
            "pgvector/pgvector:pg16@sha256:dead"
        );
        assert_eq!(
            pinned.mysql_image("not-a-version").unwrap(),
            "mysql:8.4@sha256:beef"
        );
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
    fn check_project_slug_rejects_traversal() {
        assert!(check_project_slug("acme").is_ok());
        assert!(check_project_slug("preview-b").is_ok());
        // A traversing / separator-bearing project is refused (defense-in-depth).
        assert!(check_project_slug("../etc").is_err());
        assert!(check_project_slug("a/b").is_err());
        assert!(check_project_slug("").is_err());
    }

    #[test]
    fn data_only_skew_fails_closed_on_a_missing_fingerprint() {
        // Proven compatible ONLY when both present AND equal.
        assert!(!data_only_skew_blocks(Some("abc"), Some("abc")));
        // Mismatch blocks.
        assert!(data_only_skew_blocks(Some("abc"), Some("xyz")));
        // A MISSING fingerprint on EITHER side blocks (fail-closed) — the security fix.
        assert!(data_only_skew_blocks(None, Some("abc")));
        assert!(data_only_skew_blocks(Some("abc"), None));
        assert!(data_only_skew_blocks(None, None));
    }

    /// Driver-level (in-process, no Docker): a `--data-only` export must NOT stage the
    /// control-plane KV slice, while a FULL export must. Drives the real
    /// `NodeProjectExport::export` with an empty `databases` map (no pg/mysql ⇒ no
    /// ephemeral container) + no libsql, so only the KV/blob orchestration runs. This is
    /// the mutation gate for the Ask-4(a) invariant (a data-only bundle carries no
    /// identity/RBAC/routing/secret bytes).
    #[tokio::test]
    async fn data_only_export_omits_the_control_plane_kv_slice() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        // An OWNED control-plane key so the FULL slice is non-trivial — exactly the kind of
        // config/secret byte a data-only bundle must never carry (and that the C1 allowlist
        // scopes INTO a full export, unlike a synthetic non-owned key).
        kv.put("project/acme/config/tenancy", b"{}".to_vec())
            .await
            .unwrap();
        let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("blobs")));
        let deploy = DeployStore::new(blobs.clone(), kv.clone());
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let drv = NodeProjectExport::new(BTreeMap::new(), deploy, kv.clone(), blobs.clone(), work);

        // FULL export carries the control-plane KV slice...
        let full = export_to_buf(
            &drv,
            "acme",
            &ExportOptions {
                data_only: false,
                ..Default::default()
            },
        )
        .await
        .expect("full export");
        let (full_data_only, full_members) = read_members(&full);
        assert!(!full_data_only, "full manifest is not data-only");
        assert!(
            full_members.iter().any(|(m, _)| m.kind == MemberKind::Kv),
            "a FULL bundle must carry the control-plane KV slice"
        );

        // ...a data-only export must NOT (the Ask-4(a) safety invariant).
        let donly = export_to_buf(
            &drv,
            "acme",
            &ExportOptions {
                data_only: true,
                ..Default::default()
            },
        )
        .await
        .expect("data-only export");
        let (donly_data_only, donly_members) = read_members(&donly);
        assert!(donly_data_only, "data-only manifest flags data_only");
        assert!(
            !donly_members.iter().any(|(m, _)| m.kind == MemberKind::Kv),
            "a data-only bundle must NOT carry the control-plane KV slice (Ask-4a leak)"
        );
    }

    /// Driver-level (in-process): `--include-identity` wraps the KEK into an Identity member
    /// that round-trips under the transport key, and the refusals hold (data-only+identity,
    /// no transport key, a Vault source). Default export carries NO identity member. The
    /// Ask-4(d) gate: identity is excluded by default and only present under the flag.
    #[tokio::test]
    async fn include_identity_wraps_the_kek_and_refusals_hold() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let kek = [0x5Au8; 32];
        let kek_file = tmp.path().join("kek");
        std::fs::write(&kek_file, kek).unwrap();

        let mk = |suffix: &str, src: Option<IdentityEnvelope>| {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let blobs: Arc<dyn Storage> =
                Arc::new(FsStorage::new(tmp.path().join(format!("b{suffix}"))));
            let deploy = DeployStore::new(blobs.clone(), kv.clone());
            let work = tmp.path().join(format!("w{suffix}"));
            std::fs::create_dir_all(&work).unwrap();
            let mut d = NodeProjectExport::new(BTreeMap::new(), deploy, kv, blobs, work);
            if let Some(s) = src {
                d = d.with_identity_source(s);
            }
            d
        };

        let pass = b"operator-transport-passphrase".to_vec();
        let drv = mk(
            "local",
            Some(IdentityEnvelope::Local {
                kek_file: kek_file.clone(),
            }),
        );

        // include-identity (full) → an Identity member that unwraps to the exact KEK.
        let bundle = export_to_buf(
            &drv,
            "acme",
            &ExportOptions {
                data_only: false,
                include_identity: true,
                transport_key: Some(pass.clone()),
            },
        )
        .await
        .expect("include-identity export");
        let (_do, members) = read_members(&bundle);
        let (idspec, container) = members
            .iter()
            .find(|(m, _)| m.kind == MemberKind::Identity)
            .expect("identity member present");
        assert_eq!(
            idspec.path, IDENTITY_MEMBER_PATH,
            "identity member at the declared path"
        );
        let payload =
            boatramp_server::envelope::transport_unwrap(container, &pass).expect("unwrap");
        assert_eq!(
            parse_identity_payload(&payload).unwrap(),
            kek,
            "the wrapped KEK round-trips"
        );
        assert!(
            boatramp_server::envelope::transport_unwrap(container, b"wrong").is_err(),
            "wrong transport key cannot open the container"
        );

        // The identity member is FIRST in the v2 restore order (an adopt import installs the
        // KEK before the KV slice).
        assert_eq!(
            members.first().map(|(m, _)| m.kind),
            Some(MemberKind::Identity),
            "identity is the first member in restore order"
        );

        // Default export → NO identity member.
        let plain = export_to_buf(&drv, "acme", &ExportOptions::default())
            .await
            .expect("default export");
        let (_do2, m2) = read_members(&plain);
        assert!(
            !m2.iter().any(|(m, _)| m.kind == MemberKind::Identity),
            "default bundle carries no identity member"
        );

        // Refusals: data-only+identity, missing transport key, and a Vault source.
        assert!(
            export_to_buf(
                &drv,
                "acme",
                &ExportOptions {
                    data_only: true,
                    include_identity: true,
                    transport_key: Some(pass.clone()),
                },
            )
            .await
            .is_err(),
            "data-only + include-identity is refused"
        );
        assert!(
            export_to_buf(
                &drv,
                "acme",
                &ExportOptions {
                    data_only: false,
                    include_identity: true,
                    transport_key: None,
                },
            )
            .await
            .is_err(),
            "include-identity without a transport key is refused"
        );
        let vault = mk("vault", Some(IdentityEnvelope::Vault));
        assert!(
            export_to_buf(
                &vault,
                "acme",
                &ExportOptions {
                    data_only: false,
                    include_identity: true,
                    transport_key: Some(pass.clone()),
                },
            )
            .await
            .is_err(),
            "include-identity on a Vault envelope is refused"
        );
    }

    /// Driver-level (in-process): `adopt` installs the source KEK and keeps the KV slice's
    /// sealed secrets; `fresh` installs no KEK and DROPS the source sealed-secret keyspace;
    /// neither imports `_cp/*`; and `adopt` on a bundle with no identity member is refused.
    /// The Ask-4(b) (never import `_cp/*`) + Ask-4(c) (fresh ⇒ zero source-sealed artifacts)
    /// gate.
    #[tokio::test]
    async fn adopt_installs_kek_and_fresh_drops_source_secrets() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let kek = [0x3Cu8; 32];
        let src_kek_file = tmp.path().join("src-kek");
        std::fs::write(&src_kek_file, kek).unwrap();

        // Source: a sealed secret, a per-tenant secret, a reserved `_cp/*` key (must NOT
        // export), and a non-secret control-plane key (routing — kept on fresh).
        let src_kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        for (k, v) in [
            ("project/acme/secret/api-key", &b"sealed"[..]),
            ("project/acme/tenant-secret/t1/token", &b"sealed-t"[..]),
            ("project/acme/email/smtp", &b"sealed-pw"[..]), // H1: email is sealed → dropped on fresh
            ("managed-sql-cred/acme/pg", &b"sealed-cred"[..]), // H1: DB cred → dropped on fresh
            ("_cp/leader", &b"node-1"[..]),
            // A real OWNED, non-secret control-plane key — kept on fresh (and scoped into the
            // export, unlike a synthetic non-owned key which the C1 allowlist would exclude).
            ("project/acme/config/tenancy", &b"{}"[..]),
        ] {
            src_kv.put(k, v.to_vec()).await.unwrap();
        }
        let src_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("src-blobs")));
        let src = NodeProjectExport::new(
            BTreeMap::new(),
            DeployStore::new(src_blobs.clone(), src_kv.clone()),
            src_kv.clone(),
            src_blobs,
            {
                let w = tmp.path().join("src-work");
                std::fs::create_dir_all(&w).unwrap();
                w
            },
        )
        .with_identity_source(IdentityEnvelope::Local {
            kek_file: src_kek_file.clone(),
        });
        let pass = b"transport-pass".to_vec();
        let bundle = export_to_buf(
            &src,
            "acme",
            &ExportOptions {
                data_only: false,
                include_identity: true,
                transport_key: Some(pass.clone()),
            },
        )
        .await
        .expect("export with identity");

        // Build a fresh target driver (empty KV, a kek_file path that does not yet exist).
        let target = |tag: &str| {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let blobs: Arc<dyn Storage> =
                Arc::new(FsStorage::new(tmp.path().join(format!("{tag}-blobs"))));
            let work = tmp.path().join(format!("{tag}-work"));
            std::fs::create_dir_all(&work).unwrap();
            let kek_file = tmp.path().join(format!("{tag}-kek"));
            let drv = NodeProjectExport::new(
                BTreeMap::new(),
                DeployStore::new(blobs.clone(), kv.clone()),
                kv.clone(),
                blobs,
                work,
            )
            .with_identity_source(IdentityEnvelope::Local {
                kek_file: kek_file.clone(),
            });
            (drv, kv, kek_file)
        };

        // --- adopt: installs the KEK, keeps sealed secrets, never writes _cp/* ---
        let (adopt_drv, a_kv, a_kek) = target("a");
        import_buf(
            &adopt_drv,
            "acme",
            &bundle,
            ImportOptions {
                apply: true,
                identity: IdentityChoice::Adopt {
                    transport_key: pass.clone(),
                },
                ..Default::default()
            },
        )
        .await
        .expect("adopt import");
        assert_eq!(
            std::fs::read(&a_kek).unwrap(),
            kek,
            "adopt installed the source KEK"
        );
        assert!(
            a_kv.get("project/acme/secret/api-key")
                .await
                .unwrap()
                .is_some(),
            "adopt keeps the sealed secret (it unseals under the adopted KEK)"
        );
        assert!(
            a_kv.get("project/acme/email/smtp").await.unwrap().is_some()
                && a_kv
                    .get("managed-sql-cred/acme/pg")
                    .await
                    .unwrap()
                    .is_some(),
            "adopt keeps the sealed email profile + managed-DB credential"
        );
        assert!(
            a_kv.get("_cp/leader").await.unwrap().is_none(),
            "import never writes a reserved _cp/* key (Ask-4b)"
        );

        // --- fresh: installs NO KEK, drops the source sealed-secret keyspace ---
        let (fresh_drv, f_kv, f_kek) = target("f");
        import_buf(
            &fresh_drv,
            "acme",
            &bundle,
            ImportOptions {
                apply: true,
                identity: IdentityChoice::Fresh,
                ..Default::default()
            },
        )
        .await
        .expect("fresh import");
        assert!(!f_kek.exists(), "fresh installs no KEK");
        assert!(
            f_kv.get("project/acme/secret/api-key")
                .await
                .unwrap()
                .is_none(),
            "fresh dropped the source sealed secret (Ask-4c)"
        );
        assert!(
            f_kv.get("project/acme/tenant-secret/t1/token")
                .await
                .unwrap()
                .is_none(),
            "fresh dropped the source per-tenant secret (Ask-4c)"
        );
        assert!(
            f_kv.get("project/acme/email/smtp").await.unwrap().is_none(),
            "fresh dropped the source SMTP profile's sealed password (H1)"
        );
        assert!(
            f_kv.get("managed-sql-cred/acme/pg")
                .await
                .unwrap()
                .is_none(),
            "fresh dropped the source managed-DB credential (H1)"
        );
        assert!(
            f_kv.get("project/acme/config/tenancy")
                .await
                .unwrap()
                .is_some(),
            "fresh keeps non-secret, environment-neutral control-plane config (tenancy map)"
        );
        assert!(
            f_kv.get("_cp/leader").await.unwrap().is_none(),
            "import never writes a reserved _cp/* key (Ask-4b)"
        );

        // --- adopt on a bundle WITHOUT an identity member is refused ---
        let plain = export_to_buf(&src, "acme", &ExportOptions::default())
            .await
            .expect("plain export");
        let (no_id_drv, no_id_kv, _f) = target("n");
        assert!(
            import_buf(
                &no_id_drv,
                "acme",
                &plain,
                ImportOptions {
                    apply: true,
                    identity: IdentityChoice::Adopt {
                        transport_key: pass.clone(),
                    },
                    ..Default::default()
                },
            )
            .await
            .is_err(),
            "adopt on a bundle with no identity member is refused"
        );
        // ...and refused BEFORE the sealed KV slice is written (the KV-member guard): no
        // source-sealed secret landed on the target despite the plain bundle carrying one.
        assert!(
            no_id_kv
                .get("project/acme/secret/api-key")
                .await
                .unwrap()
                .is_none(),
            "a refused adopt must not have written the source-sealed KV slice"
        );
    }

    #[test]
    fn blob_rekey_lands_in_target_scope_and_fails_closed() {
        // Same project → the member's own scope (no rename).
        assert_eq!(
            target_blob_key("blobs/hblob/acme/web/c/obj", "acme", "acme").unwrap(),
            "hblob/acme/web/c/obj"
        );
        // Rename → the object lands under the TARGET project's scope, never the source's.
        let t = target_blob_key("blobs/hblob/preview-a/web/c/obj", "preview-a", "preview-b")
            .expect("rename re-key");
        assert_eq!(t, "hblob/preview-b/web/c/obj");
        assert!(
            !t.contains("preview-a"),
            "NO source-scope segment survives a rename re-key"
        );
        // FAIL-CLOSED (the tenancy-critical mutation): a member NOT under the source project
        // scope is REFUSED, never silently landed in a foreign scope — a sibling-prefix project
        // (`acmecorp` vs `acme`) is not over-captured, and a bare key missing the `blobs/`
        // wrapper is rejected.
        assert!(target_blob_key("blobs/hblob/globex/secret/obj", "acme", "beta").is_err());
        assert!(target_blob_key("blobs/hblob/acmecorp/x", "acme", "beta").is_err());
        assert!(target_blob_key("hblob/acme/x", "acme", "beta").is_err());
        assert!(target_blob_key("blobs/not-hblob/x", "acme", "beta").is_err());
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
