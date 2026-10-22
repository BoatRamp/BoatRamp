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
//!
//! ## Atomicity (inc2 chunked + shadow-restore)
//! A FULL **managed, dedicated/Single** pg/mysql/libsql member streams O(chunk) (no whole-member
//! temp) and is applied into a SHADOW — a not-yet-live database/file — then swapped in atomically
//! ONLY after its trailing SHA verifies; any abort (SHA mismatch, truncation, restore error,
//! disconnect) tears the shadow down and leaves live untouched (PER-MEMBER all-or-nothing,
//! default #2).
//!
//! HIGH-1 (Build-2 Security re-review): the pg/mysql dump in a bundle is attacker-crafted, so it is
//! applied by a freshly-minted, per-import EPHEMERAL non-superuser role (pg: `NOSUPERUSER
//! NOCREATEDB NOCREATEROLE`, owns the shadow; mysql: a user granted ONLY on the shadow db, no
//! `SUPER`/`FILE`/`*.*`) with `--no-owner --no-privileges` — NOT the binding's configured user,
//! which on a managed co-located server is the BOOTSTRAP SUPERUSER. A fail-closed probe REFUSES the
//! apply unless the role is provably non-superuser. The superuser/maintenance connection runs ONLY
//! our own trusted DDL (`CREATE ROLE`/`CREATE/ALTER/DROP DATABASE`/`REASSIGN OWNED`), and pre-creates
//! the operator trusted-extension allowlist in the shadow so a legit `CREATE EXTENSION IF NOT EXISTS
//! <ext>` (pgvector) no-ops under the non-superuser apply. Residuals / boundaries: a `--data-only`
//! member and a Shared/external member are NOT chunked, and a MANAGED sidecar apply is REFUSED
//! fail-closed (it would apply as superuser — a least-privilege sidecar apply is the follow-up); an
//! EXTERNAL bring-your-own-URL binding applies with the OPERATOR'S OWN credential against the
//! operator's own database (their trust boundary); a Shared multi-tenant server is refused for
//! chunked shadow-restore (the per-import physical shadow db is a cross-tenant surface deferred to
//! the temp-schema follow-up, default #3 = temp-DB for dedicated/Single). The bundle is NOT
//! whole-bundle atomic (cross-member window); overwriting a populated DB peaks at ~2× its size.
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
    MysqlConnection, PgConnection, mysql_admin_invocation, mysql_restore_invocation,
    mysql_shadow_invocation, mysqldump_invocation, mysqldump_tables_only_invocation,
    pg_dump_invocation, pg_restore_invocation, pg_restore_shadow_invocation, psql_invocation,
};
use crate::project_bundle::{
    self, IDENTITY_MEMBER_PATH, KV_MEMBER_PATH, MemberKind, MemberSpec, PgMemberInfo, SourceInfo,
};
use boatramp_storage::ExternalSqlKind;
use boatramp_storage::tenant_provision::quote_ident;

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

/// The chunk size (bytes) for a `ChunkedTrailer` member — inc2 default #6: a **64 MiB** constant,
/// not operator-tunable. Overridable only in tests (so a chunked round-trip is fast) via
/// [`NodeProjectExport::with_chunk_size`].
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Defense-in-depth per-member import ceiling (inc2 default #6 / the inc1 LOW-1 follow-up): a
/// hostile bundle must not stream unbounded bytes into one member. A generous default (a real
/// member is far smaller), tightenable in tests via [`NodeProjectExport::with_import_caps`].
const DEFAULT_IMPORT_MEMBER_CAP: u64 = 256 * 1024 * 1024 * 1024; // 256 GiB

/// Defense-in-depth whole-bundle import ceiling (inc2 default #6 / inc1 LOW-1): the feeder aborts
/// once the TOTAL bytes streamed from the source exceed this, so a bundle can't stream forever.
const DEFAULT_IMPORT_TOTAL_CAP: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB

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

/// Whether a binding is MANAGED (compute-backed) — i.e. one of OUR co-located managed DB servers
/// whose configured user is a cluster superuser — vs. an EXTERNAL bring-your-own-URL binding (the
/// operator's own database + credential). The untrusted-dump apply must never run as a superuser on
/// a managed binding (HIGH-1).
fn is_managed_binding(cfg: &ExternalDatabaseConfig) -> bool {
    cfg.compute.as_deref().is_some_and(|c| !c.is_empty())
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
    /// The chunk size for a `ChunkedTrailer` member (default [`DEFAULT_CHUNK_SIZE`]; test override).
    chunk_size: usize,
    /// Per-member import byte ceiling (default [`DEFAULT_IMPORT_MEMBER_CAP`]).
    import_member_cap: u64,
    /// Whole-bundle import byte ceiling (default [`DEFAULT_IMPORT_TOTAL_CAP`]).
    import_total_cap: u64,
    /// The operator trusted-extension allowlist (`handlers.bindings.sql.migrate_trusted_extensions`)
    /// the superuser pre-creates in a pg shadow before the NON-superuser apply, so a legit `CREATE
    /// EXTENSION IF NOT EXISTS <ext>` (e.g. pgvector) in an untrusted dump no-ops. A dump naming an
    /// extension NOT on this list fails fail-closed under the non-superuser apply.
    trusted_extensions: Vec<String>,
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
            chunk_size: DEFAULT_CHUNK_SIZE,
            import_member_cap: DEFAULT_IMPORT_MEMBER_CAP,
            import_total_cap: DEFAULT_IMPORT_TOTAL_CAP,
            trusted_extensions: Vec::new(),
        }
    }

    /// Set the operator trusted-extension allowlist (from
    /// `handlers.bindings.sql.migrate_trusted_extensions`) the superuser pre-creates in a pg shadow
    /// before the NON-superuser apply — so a legit `CREATE EXTENSION IF NOT EXISTS <ext>` (pgvector)
    /// in an untrusted dump no-ops instead of failing under the non-superuser apply.
    #[must_use]
    pub fn with_trusted_extensions(mut self, extensions: Vec<String>) -> Self {
        self.trusted_extensions = extensions;
        self
    }

    /// Override the chunk size for `ChunkedTrailer` members (TEST ONLY — production uses the
    /// [`DEFAULT_CHUNK_SIZE`] 64 MiB constant). A small size makes a chunked round-trip test
    /// produce multiple `.part` entries without a large fixture.
    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size.max(1);
        self
    }

    /// Override the import byte ceilings (TEST ONLY — production uses the generous defaults). Lets
    /// a test prove the per-member / total caps reject an over-large bundle cheaply.
    #[must_use]
    pub fn with_import_caps(mut self, member_cap: u64, total_cap: u64) -> Self {
        self.import_member_cap = member_cap;
        self.import_total_cap = total_cap;
        self
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
    /// container bridge IP. Uses the OPERATOR identity (the configured/superuser role); the
    /// untrusted-dump apply NEVER uses this identity — it uses a freshly-minted ephemeral
    /// non-superuser role (see [`PgShadowPlan`]/[`MysqlShadowPlan`]).
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

    /// Run a SQL client capturing its stdout as a trimmed string (plus the exit code) — for the
    /// trusted-DDL utility queries of the inc2 shadow swap (pg `SELECT 1 FROM pg_database …`, mysql
    /// `information_schema` table enumeration). The stdout temp lives under `stage_dir` and is
    /// removed after.
    async fn run_sql_capture(
        &self,
        image: &str,
        argv: &[String],
        env: &[(String, String)],
        stdin_path: Option<&Path>,
        stage_dir: &Path,
    ) -> Result<(i32, String), Perr> {
        let out = stage_dir.join(format!("cap-{}.out", shadow_suffix()));
        let code = self
            .run_sql_client(image, argv, env, stdin_path, &out)
            .await?;
        let s = tokio::fs::read_to_string(&out).await.unwrap_or_default();
        let _ = tokio::fs::remove_file(&out).await;
        Ok((code, s.trim().to_string()))
    }
}

/// A process-unique shadow suffix (`<nanos>_<pid>`) — same shape libsql's `shadow_path_for` uses,
/// so two imports in the same second never collide and the `*__shadow_*` / `*__old_*` sweep matches.
fn shadow_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}_{}", std::process::id())
}

/// Quote a Postgres **string literal** (single-quoted, doubling any embedded `'`) — for the
/// `datname = '<db>'` predicate of our own generated `pg_terminate_backend` / `pg_database`
/// utility SQL (the db name is driver-derived, never a credential or bundle data).
fn pg_lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
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

/// An async [`futures::io::AsyncWrite`] that forwards each write into a bounded tokio channel —
/// the bridge from a `run_ephemeral` stdout sink (`pg_dump`/`mysqldump`) straight into a
/// ChunkedTrailer body channel (inc2 Stage C/D), so the SQL dump streams O(chunk) with NO temp.
/// A full channel backpressures the dump via `Poll::Pending`; a closed channel is a broken pipe.
struct AsyncChannelWriter {
    sender: tokio_util::sync::PollSender<Vec<u8>>,
}

impl AsyncChannelWriter {
    fn new(tx: tokio::sync::mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            sender: tokio_util::sync::PollSender::new(tx),
        }
    }
}

impl futures::io::AsyncWrite for AsyncChannelWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let me = self.get_mut();
        match me.sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => match me.sender.send_item(buf.to_vec()) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "export dump sink closed",
                ))),
            },
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "export dump sink closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.get_mut().sender.close();
        std::task::Poll::Ready(Ok(()))
    }
}

/// An async [`futures::io::AsyncRead`] fed by a bounded tokio channel — the bridge from a
/// ChunkedTrailer member's body channel into a `run_ephemeral` stdin reader (`pg_restore`/`mysql`)
/// on the IMPORT side (inc2 Stage C/D). Bounded memory; a closed channel is clean EOF so the
/// restore client sees stdin half-close and exits.
struct AsyncChannelReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl AsyncChannelReader {
    fn new(rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl futures::io::AsyncRead for AsyncChannelReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let me = self.get_mut();
        while me.pos >= me.buf.len() {
            match me.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) if !chunk.is_empty() => {
                    me.buf = chunk;
                    me.pos = 0;
                }
                Poll::Ready(Some(_)) => continue, // skip an empty chunk, not EOF
                Poll::Ready(None) => return Poll::Ready(Ok(0)), // all senders dropped ⇒ EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = std::cmp::min(out.len(), me.buf.len() - me.pos);
        out[..n].copy_from_slice(&me.buf[me.pos..me.pos + n]);
        me.pos += n;
        Poll::Ready(Ok(n))
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

/// The export stager's request: "produce the member at `path`". `chunked` selects a
/// [`StageReply::Chunked`] body stream (ChunkedTrailer framing — O(chunk), no temp) vs a
/// [`StageReply::Sidecar`] staged temp (Sidecar framing).
struct StageReq {
    path: String,
    chunked: bool,
    reply: tokio::sync::oneshot::Sender<StageReply>,
}

/// The stager's reply to a [`StageReq`].
enum StageReply {
    /// A Sidecar member staged whole to this bounded temp (the writer appends then deletes it).
    Sidecar(PathBuf),
    /// A ChunkedTrailer member's body — the writer reads this receiver straight through
    /// `append_member_chunked` (O(chunk)); `poison` is set by the producer task on error so a
    /// premature channel close becomes a loud IO error (never a silently-truncated member).
    Chunked {
        rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        poison: Arc<std::sync::atomic::AtomicBool>,
    },
    /// Production failed — fail the writer (the specific error is surfaced by the stager).
    Err,
}

/// A started chunked-member body producer: the body-channel receiver, the `poison` flag the
/// producer sets on error, and its `JoinHandle` (awaited by the stager so a producer error fails
/// the export). Returned by [`NodeProjectExport::open_chunked_producer`].
type ChunkedProducer = (
    tokio::sync::mpsc::Receiver<Vec<u8>>,
    Arc<std::sync::atomic::AtomicBool>,
    tokio::task::JoinHandle<Result<(), Perr>>,
);

/// A synchronous [`Read`] over a chunked member's body channel (export) that distinguishes a
/// CLEAN end-of-stream from a PRODUCER FAILURE: on channel close it returns an IO error iff the
/// shared `poison` flag is set (the producer errored), so `append_member_chunked` never writes a
/// valid trailer over a short/incomplete member.
struct ChunkedBodyReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    poison: Arc<std::sync::atomic::AtomicBool>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChunkedBodyReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.blocking_recv() {
                Some(chunk) if !chunk.is_empty() => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Some(_) => continue,
                None => {
                    if self.poison.load(std::sync::atomic::Ordering::SeqCst) {
                        return Err(std::io::Error::other("export member producer failed"));
                    }
                    return Ok(0); // clean EOF
                }
            }
        }
        let n = std::cmp::min(out.len(), self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// The import servicer's request, sent by the blocking atomic reader as it streams.
enum ImportMsg {
    /// The bundle head (surfaced before any member) — the source project + data-only flag.
    Head {
        data_only: bool,
        source_project: String,
    },
    /// A Sidecar member staged + size/SHA-verified at `temp`; the servicer restores it then
    /// replies so the reader may advance (one member staged at a time ⇒ O(largest member)).
    Member {
        spec: MemberSpec,
        temp: PathBuf,
        reply: tokio::sync::oneshot::Sender<Result<(), ()>>,
    },
    /// Begin a ChunkedTrailer member: the servicer opens the sink (a libsql shadow, or a staging
    /// temp for a blob/KV member) and drains `body_rx` into it, replying once opened.
    ChunkBegin {
        spec: MemberSpec,
        body_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        reply: tokio::sync::oneshot::Sender<Result<(), ()>>,
    },
    /// Finish the in-flight ChunkedTrailer member: `verified` is whether the trailer matched —
    /// COMMIT the sink on true, DROP it on false (the reader then raises the loud mismatch).
    ChunkFinish {
        verified: bool,
        reply: tokio::sync::oneshot::Sender<Result<(), ()>>,
    },
}

/// The blocking atomic reader's [`BundleRestorer`](project_bundle::BundleRestorer) — it bridges the
/// sync reader to the async servicer over the `req` channel (for sidecar members + chunk
/// begin/finish) and a per-member `body` channel (for chunk bytes). It also enforces the
/// per-member import byte CAP (inc2 default #6 / inc1 LOW-1): a sidecar member's staged size and a
/// chunked member's streamed total are both checked against `member_cap`, so one hostile member
/// can't stream unbounded bytes.
struct ImportBridge {
    req_tx: tokio::sync::mpsc::Sender<ImportMsg>,
    /// The in-flight chunked member's body channel (between begin and finish).
    body_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// Bytes streamed into the in-flight chunked member so far (for the per-member cap).
    chunked_bytes: u64,
    member_cap: u64,
}

impl ImportBridge {
    fn gone() -> project_bundle::BundleError {
        project_bundle::BundleError::MalformedStream("import servicer gone".into())
    }
    fn over_cap(cap: u64) -> project_bundle::BundleError {
        project_bundle::BundleError::MalformedStream(format!(
            "import refused: a member exceeds the per-member byte cap of {cap} bytes"
        ))
    }
}

impl project_bundle::BundleRestorer for ImportBridge {
    fn restore_sidecar(
        &mut self,
        spec: &MemberSpec,
        temp: &std::path::Path,
    ) -> Result<(), project_bundle::BundleError> {
        if let Ok(m) = std::fs::metadata(temp)
            && m.len() > self.member_cap
        {
            return Err(Self::over_cap(self.member_cap));
        }
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.req_tx
            .blocking_send(ImportMsg::Member {
                spec: spec.clone(),
                temp: temp.to_path_buf(),
                reply: reply_tx,
            })
            .map_err(|_| Self::gone())?;
        match reply_rx.blocking_recv() {
            Ok(Ok(())) => Ok(()),
            _ => Err(project_bundle::BundleError::MalformedStream(
                "import restore aborted".into(),
            )),
        }
    }

    fn begin_chunked(&mut self, spec: &MemberSpec) -> Result<(), project_bundle::BundleError> {
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BYTE_CHANNEL);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.req_tx
            .blocking_send(ImportMsg::ChunkBegin {
                spec: spec.clone(),
                body_rx,
                reply: reply_tx,
            })
            .map_err(|_| Self::gone())?;
        self.body_tx = Some(body_tx);
        self.chunked_bytes = 0;
        match reply_rx.blocking_recv() {
            Ok(Ok(())) => Ok(()),
            _ => Err(project_bundle::BundleError::MalformedStream(
                "import chunk begin aborted".into(),
            )),
        }
    }

    fn write_chunk(
        &mut self,
        _spec: &MemberSpec,
        buf: &[u8],
    ) -> Result<(), project_bundle::BundleError> {
        self.chunked_bytes = self.chunked_bytes.saturating_add(buf.len() as u64);
        if self.chunked_bytes > self.member_cap {
            return Err(Self::over_cap(self.member_cap));
        }
        match self.body_tx.as_ref() {
            Some(tx) => tx.blocking_send(buf.to_vec()).map_err(|_| {
                project_bundle::BundleError::MalformedStream("chunk sink closed".into())
            }),
            None => Err(project_bundle::BundleError::MalformedStream(
                "write_chunk without begin".into(),
            )),
        }
    }

    fn finish_chunked(
        &mut self,
        _spec: &MemberSpec,
        verified: bool,
    ) -> Result<(), project_bundle::BundleError> {
        // Drop the body channel → EOF to the servicer's drain, THEN ask it to commit/abort.
        self.body_tx = None;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.req_tx
            .blocking_send(ImportMsg::ChunkFinish {
                verified,
                reply: reply_tx,
            })
            .map_err(|_| Self::gone())?;
        match reply_rx.blocking_recv() {
            Ok(Ok(())) => Ok(()),
            _ => Err(project_bundle::BundleError::MalformedStream(
                "import chunk finish aborted".into(),
            )),
        }
    }
}

/// The servicer's in-flight chunked-member sink, held between `ChunkBegin` and `ChunkFinish`.
enum ChunkState {
    /// A libsql member streaming into an atomic shadow DB (committed-or-dropped at finish).
    Libsql {
        shadow: boatramp_storage::sql_libsql::DumpShadow,
        feed_err: Option<Perr>,
    },
    /// A blob/KV member staged to a bounded temp, then restored via the SAME `restore_member`
    /// (re-key / scope-enforce) as a sidecar member at finish — framing is never a tenancy bypass.
    Staged {
        spec: MemberSpec,
        temp: PathBuf,
        write_err: Option<Perr>,
    },
    /// A Postgres member streaming into a SHADOW database (inc2 Stage C). The restore subprocess
    /// (`pg_restore` as the NON-SUPERUSER owner role) reads the body channel as stdin while it runs;
    /// at finish the shadow is atomically swapped in (verified) or dropped (abort) via trusted DDL.
    Pg {
        plan: Box<PgShadowPlan>,
        restore: tokio::task::JoinHandle<Result<i32, Perr>>,
        out_path: PathBuf,
    },
    /// A MySQL member streaming into a SHADOW database (inc2 Stage D), mirror of [`Pg`](Self::Pg):
    /// `mysql <shadow>` applies the tables-only dump as the non-superuser role; finish swaps via an
    /// atomic `RENAME TABLE` (verified) or drops the shadow (abort).
    Mysql {
        plan: Box<MysqlShadowPlan>,
        restore: tokio::task::JoinHandle<Result<i32, Perr>>,
        out_path: PathBuf,
    },
}

/// The resolved plan for a Postgres atomic shadow-restore (inc2 Stage C).
///
/// THE SECURITY CORE (HIGH-1 fix): the untrusted dump is applied by an EPHEMERAL, per-import
/// `NOSUPERUSER NOCREATEDB NOCREATEROLE` role (`eph_role`), created by the superuser for exactly
/// this import and dropped afterwards — so the confinement holds REGARDLESS of what the binding's
/// configured user is (on a Single/dedicated managed pg that user is the bootstrap SUPERUSER, so
/// relying on `owner_target` would NOT confine). The SUPERUSER / maintenance connection (`maint`,
/// on the `postgres` db) runs ONLY our own trusted `CREATE ROLE`/`CREATE/ALTER/DROP DATABASE`/
/// `REASSIGN OWNED`/`pg_terminate_backend` DDL — never a byte of the bundle's dump. On success the
/// shadow's objects are `REASSIGN OWNED` from the ephemeral role to `owner_user` (the configured
/// role that normally owns the tenant db) before the ephemeral role is dropped.
#[derive(Clone)]
struct PgShadowPlan {
    /// The live (target) database name.
    live_db: String,
    /// The transient shadow database (`<live>__shadow_<suffix>`) the dump restores into.
    shadow_db: String,
    /// The per-process-unique suffix (also names the rename-aside `<live>__old_<suffix>`).
    suffix: String,
    /// The SUPERUSER / maintenance connection (database = `postgres`) for the trusted DDL.
    maint: PgConnection,
    /// The EPHEMERAL non-superuser role name the untrusted dump is applied as.
    eph_role: String,
    /// The ephemeral role's randomly-generated login password.
    eph_password: String,
    /// The configured role that normally owns the tenant db — the shadow's objects are reassigned
    /// to it on a successful swap (so the swapped-in live db has its usual ownership).
    owner_user: String,
    /// The client image (`pg_dump`/`pg_restore`/`psql`).
    image: String,
    /// The operator trusted-extension allowlist the superuser pre-creates in the shadow (so a legit
    /// `CREATE EXTENSION IF NOT EXISTS <ext>` in the dump no-ops under the non-superuser apply).
    trusted_extensions: Vec<String>,
}

impl PgShadowPlan {
    /// The SUPERUSER connection pointed at the SHADOW db (for extension pre-create + `REASSIGN
    /// OWNED`, which must run connected to the db they target).
    fn maint_on_shadow(&self) -> PgConnection {
        let mut c = self.maint.clone();
        c.database = self.shadow_db.clone();
        c
    }
    /// The NON-SUPERUSER apply connection (the ephemeral role) pointed at the shadow db.
    fn apply_conn(&self) -> PgConnection {
        let mut c = self.maint.clone();
        c.user = self.eph_role.clone();
        c.password = self.eph_password.clone();
        c.database = self.shadow_db.clone();
        c
    }
}

/// The resolved plan for a MySQL atomic shadow-restore (inc2 Stage D), mirror of [`PgShadowPlan`]:
/// the untrusted dump is applied by an EPHEMERAL `mysql` user granted ONLY on the shadow db (never
/// `*.*`, `SUPER`, or `FILE`), created + dropped by the superuser around the import.
#[derive(Clone)]
struct MysqlShadowPlan {
    live_db: String,
    shadow_db: String,
    suffix: String,
    /// The SUPERUSER / maintenance connection (no default db) for the trusted DDL + enumeration.
    maint: MysqlConnection,
    /// The EPHEMERAL non-superuser user the untrusted dump is applied as.
    eph_user: String,
    /// The ephemeral user's randomly-generated password.
    eph_password: String,
    image: String,
}

impl MysqlShadowPlan {
    /// The NON-SUPERUSER apply connection (the ephemeral user).
    fn apply_conn(&self) -> MysqlConnection {
        let mut c = self.maint.clone();
        c.user = self.eph_user.clone();
        c.password = self.eph_password.clone();
        c.database = self.shadow_db.clone();
        c
    }
}

/// A random token (32 hex chars) for an ephemeral role's login password — never persisted, never
/// handed to a handler; it exists only for the lifetime of one import's shadow apply.
fn random_token() -> String {
    let mut bytes = [0u8; 16];
    // A failed RNG is fatal to the import, not silently weak.
    getrandom::getrandom(&mut bytes).expect("os rng for ephemeral role password");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

        // 2. STREAM: run the sync v3 writer in a blocking task, bridged to (a) the caller's async
        //    `sink` over a bounded byte channel + drain, and (b) the async stager over a one-slot
        //    request channel. `write_bundle_streaming_v3` dispatches each member by framing: a
        //    Sidecar member is staged → appended → deleted (O(largest-member)); a ChunkedTrailer
        //    member's body is piped STRAIGHT through `append_member_chunked` in `chunk_size` pieces
        //    with NO temp (O(chunk) — the libsql `.dump` + large-blob streaming win over inc1).
        let chunk_size = self.chunk_size;
        let (byte_tx, mut byte_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BYTE_CHANNEL);
        let (stage_tx, mut stage_rx) = tokio::sync::mpsc::channel::<StageReq>(1);
        let writer_out = ChannelWriter { tx: byte_tx };
        let stage_tx_task = stage_tx.clone();
        let specs_for_task = specs.clone();
        let source_for_task = source.clone();
        let write_handle =
            tokio::task::spawn_blocking(move || -> Result<(), project_bundle::BundleError> {
                let request = |path: &str,
                               chunked: bool|
                 -> Result<StageReply, project_bundle::BundleError> {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    stage_tx_task
                        .blocking_send(StageReq {
                            path: path.to_string(),
                            chunked,
                            reply: reply_tx,
                        })
                        .map_err(|_| {
                            project_bundle::BundleError::MalformedStream(
                                "export stager gone".into(),
                            )
                        })?;
                    reply_rx.blocking_recv().map_err(|_| {
                        project_bundle::BundleError::MalformedStream("export stager dropped".into())
                    })
                };
                project_bundle::write_bundle_streaming_v3(
                    writer_out,
                    created_at,
                    data_only,
                    source_for_task,
                    specs_for_task,
                    chunk_size,
                    // Sidecar: ask the stager to stage the member to a temp.
                    |spec| match request(&spec.path, false)? {
                        StageReply::Sidecar(tmp) => Ok(tmp),
                        _ => Err(project_bundle::BundleError::MalformedStream(
                            "export staging failed".into(),
                        )),
                    },
                    // ChunkedTrailer: ask the stager to START a body producer; read it straight through.
                    |spec| match request(&spec.path, true)? {
                        StageReply::Chunked { rx, poison } => Ok(Box::new(ChunkedBodyReader {
                            rx,
                            poison,
                            buf: Vec::new(),
                            pos: 0,
                        })
                            as Box<dyn Read>),
                        _ => Err(project_bundle::BundleError::MalformedStream(
                            "export chunked member open failed".into(),
                        )),
                    },
                )
            });
        drop(stage_tx); // only the blocking task keeps the request channel alive now

        // Async stager: produce each requested member, using `self`. A Sidecar member is staged to
        // a bounded temp; a ChunkedTrailer member spawns a producer task that streams its body
        // (libsql `.dump` / blob get) into a bounded channel the writer drains. Producer handles
        // are collected and awaited after the writer finishes, so a producer error FAILS the export
        // (and poisons the body stream so no valid trailer is written over a short member).
        let stager = async {
            let mut idx = 0usize;
            let mut producers: Vec<tokio::task::JoinHandle<Result<(), Perr>>> = Vec::new();
            while let Some(req) = stage_rx.recv().await {
                let job = jobs.get(&req.path);
                if req.chunked {
                    match self.open_chunked_producer(job) {
                        Ok((rx, poison, handle)) => {
                            producers.push(handle);
                            let _ = req.reply.send(StageReply::Chunked { rx, poison });
                        }
                        Err(e) => {
                            let _ = req.reply.send(StageReply::Err);
                            return Err::<(), Perr>(e);
                        }
                    }
                } else {
                    let res = match job {
                        Some(job) => self.stage_job(project, job, &stage_dir, idx).await,
                        None => Err(Perr::Other(format!(
                            "export: internal error — no stage job for member {:?}",
                            req.path
                        ))),
                    };
                    idx += 1;
                    match res {
                        Ok(tmp) => {
                            let _ = req.reply.send(StageReply::Sidecar(tmp));
                        }
                        Err(e) => {
                            let _ = req.reply.send(StageReply::Err);
                            return Err::<(), Perr>(e);
                        }
                    }
                }
            }
            // The writer has finished (channel closed) and fully drained every producer; surface
            // any producer error now (a failed dump/blob-get is an export failure).
            for h in producers {
                match h.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(je) => return Err(other(je)),
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

        // MEDIUM-1(a): refuse a clone into a TARGET PROJECT that already holds its own data
        // (owned KV prefixes OR blob scope) unless `overwrite` is set — a clone into a FRESH
        // target is the safe default; replacing a populated project is opt-in. This is distinct
        // from `force` (the store-wide KV commingle override); env-clone creates a fresh target,
        // so this does not break it.
        if !opts.overwrite {
            for prefix in
                boatramp_core::project_export::project_owned_prefixes(ProjectRef::new(project))
            {
                if !self
                    .kv
                    .list_prefix(&prefix)
                    .await
                    .map_err(other)?
                    .is_empty()
                {
                    return Err(Perr::Other(format!(
                        "import refused: target project {project:?} already has control-plane \
                         data under {prefix:?}; pass overwrite=true to replace an existing \
                         project (a clone into a fresh target needs no overwrite)"
                    )));
                }
            }
            if !self
                .blobs
                .list(&blob_project_prefix(project))
                .await
                .map_err(other)?
                .is_empty()
            {
                return Err(Perr::Other(format!(
                    "import refused: target project {project:?} already has blobs; pass \
                     overwrite=true to replace an existing project"
                )));
            }
        }

        let session = self
            .work_dir
            .join(format!("import-{project}-{}", now_secs()));
        let stage_dir = session.join("stage");
        tokio::fs::create_dir_all(&stage_dir).await.map_err(other)?;

        // Bridge: the async feeder pumps the caller's bundle stream into a bounded byte channel →
        // `ChannelReader` → the sync v1/v2/v3 ATOMIC reader (in a blocking task). The `ImportBridge`
        // restorer hands a Sidecar member (staged + size/SHA-VERIFIED at a bounded temp) to the
        // async servicer and BLOCKS until it finishes (verify-then-apply, O(largest member)); a
        // ChunkedTrailer member streams begin/chunk/finish to the servicer, which applies a libsql
        // member into an ATOMIC shadow (committed only on a verified trailer — nothing partial ever
        // reaches live) and stages a blob/KV member to a temp restored via the SAME re-key/enforce
        // as a sidecar member. Reads v1, v2 AND v3 bundles.
        let member_cap = self.import_member_cap;
        let (byte_tx, byte_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BYTE_CHANNEL);
        let (req_tx, mut req_rx) = tokio::sync::mpsc::channel::<ImportMsg>(1);
        let reader = ChannelReader::new(byte_rx);
        let stage_dir_task = stage_dir.clone();
        let req_tx_task = req_tx.clone();
        let read_handle = tokio::task::spawn_blocking(
            move || -> Result<Vec<MemberSpec>, project_bundle::BundleError> {
                let head_tx = req_tx_task.clone();
                let on_head = move |data_only: bool, source: &SourceInfo| {
                    // Surfaced before any member: the servicer needs the source project (to
                    // re-key each member to the TARGET) and the data-only flag.
                    let _ = head_tx.blocking_send(ImportMsg::Head {
                        data_only,
                        source_project: source.project.clone(),
                    });
                };
                let mut bridge = ImportBridge {
                    req_tx: req_tx_task,
                    body_tx: None,
                    chunked_bytes: 0,
                    member_cap,
                };
                project_bundle::read_bundle_streaming_atomic(
                    reader,
                    &stage_dir_task,
                    on_head,
                    &mut bridge,
                )
            },
        );
        drop(req_tx); // only the blocking reader keeps the request channel alive now

        // Async feeder: pump the caller's bundle stream into the blocking reader, enforcing the
        // whole-bundle byte CAP (inc2 default #6 / inc1 LOW-1) so a hostile bundle can't stream
        // forever (memory is already bounded by the channel + one member on disk; this bounds the
        // TOTAL).
        let total_cap = self.import_total_cap;
        let feeder = async {
            let mut buf = vec![0u8; 64 * 1024];
            let mut total: u64 = 0;
            loop {
                let n = src
                    .read(&mut buf)
                    .await
                    .map_err(|e| Perr::Other(format!("import body read failed: {e}")))?;
                if n == 0 {
                    break;
                }
                total = total.saturating_add(n as u64);
                if total > total_cap {
                    return Err(Perr::Other(format!(
                        "import refused: bundle exceeds the total byte cap of {total_cap} bytes"
                    )));
                }
                if byte_tx.send(buf[..n].to_vec()).await.is_err() {
                    break; // the reader stopped (error / early finish) — nothing more to feed
                }
            }
            drop(byte_tx);
            Ok::<(), Perr>(())
        };

        // Async servicer: restore each member using `self`, in arrival (restore) order. A Sidecar
        // member goes through `restore_member`; a ChunkedTrailer member opens a sink on
        // `ChunkBegin` (a libsql shadow, or a staging temp for a blob/KV member), drains its body
        // INLINE, and commits/drops it on `ChunkFinish`.
        let servicer = async {
            let mut report = ImportReport {
                dry_run: !opts.apply,
                ..Default::default()
            };
            let mut data_only = false;
            let mut source_project = String::new();
            let mut saw_identity = false;
            let mut pending_chunk: Option<ChunkState> = None;
            let mut chunk_idx = 0usize;
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
                    ImportMsg::ChunkBegin {
                        spec,
                        mut body_rx,
                        reply,
                    } => {
                        // Open the sink for this chunked member by kind, reply so the reader may
                        // stream, then drain the body INLINE into the sink (feeding until EOF).
                        match spec.kind {
                            MemberKind::Libsql => {
                                let site = match site_from_libsql_member(&spec.path) {
                                    Some(s) => s,
                                    None => {
                                        let _ = reply.send(Err(()));
                                        return Err(Perr::Other(format!(
                                            "bad libsql member path {:?}",
                                            spec.path
                                        )));
                                    }
                                };
                                let Some(libsql) = self.libsql.as_ref() else {
                                    let _ = reply.send(Err(()));
                                    return Err(Perr::Unavailable(
                                        "bundle carries a libsql member but this node has no local \
                                         libsql backend to restore it into"
                                            .into(),
                                    ));
                                };
                                let qsite = ProjectRef::new(project).qualified(site);
                                if opts.apply {
                                    match libsql.begin_dump_shadow(&qsite, "", opts.overwrite).await
                                    {
                                        Ok(mut shadow) => {
                                            let _ = reply.send(Ok(()));
                                            let mut feed_err = None;
                                            while let Some(chunk) = body_rx.recv().await {
                                                if feed_err.is_none()
                                                    && let Err(e) = shadow.feed(&chunk).await
                                                {
                                                    feed_err = Some(other(e));
                                                }
                                            }
                                            pending_chunk =
                                                Some(ChunkState::Libsql { shadow, feed_err });
                                        }
                                        Err(e) => {
                                            let _ = reply.send(Err(()));
                                            return Err(other(e));
                                        }
                                    }
                                } else {
                                    // Dry-run: don't open a shadow — just drain + count.
                                    let _ = reply.send(Ok(()));
                                    while body_rx.recv().await.is_some() {}
                                    report.libsql_databases += 1;
                                    pending_chunk = None;
                                }
                            }
                            MemberKind::Blob | MemberKind::Kv => {
                                // Stage the chunk stream to a bounded temp, then restore it via the
                                // SAME `restore_member` (re-key / enforce) as a sidecar member.
                                let temp = stage_dir.join(format!("chunk-{chunk_idx}"));
                                chunk_idx += 1;
                                match tokio::fs::File::create(&temp).await {
                                    Ok(mut f) => {
                                        let _ = reply.send(Ok(()));
                                        use tokio::io::AsyncWriteExt as _;
                                        let mut write_err = None;
                                        while let Some(chunk) = body_rx.recv().await {
                                            if write_err.is_none()
                                                && let Err(e) = f.write_all(&chunk).await
                                            {
                                                write_err = Some(other(e));
                                            }
                                        }
                                        if write_err.is_none()
                                            && let Err(e) = f.flush().await
                                        {
                                            write_err = Some(other(e));
                                        }
                                        drop(f);
                                        pending_chunk = Some(ChunkState::Staged {
                                            spec,
                                            temp,
                                            write_err,
                                        });
                                    }
                                    Err(e) => {
                                        let _ = reply.send(Err(()));
                                        return Err(other(e));
                                    }
                                }
                            }
                            MemberKind::PgDump => {
                                // The UNTRUSTED pg dump → an atomic SHADOW database (inc2 Stage C).
                                // Tenancy: the member path `sql/<db>.pgc` names a BINDING, not a
                                // project; `self.databases.get(db)` + `resolve_pg(project, …)`
                                // resolve the TARGET project's OWN managed db — a pg member can only
                                // ever land in the target's tenant-keyed db, so there is no
                                // cross-tenant surface (no re-key needed; the sidecar PgDump arm
                                // does exactly the same).
                                let db = match db_from_pg_member(&spec.path) {
                                    Some(d) => d.to_string(),
                                    None => {
                                        let _ = reply.send(Err(()));
                                        return Err(Perr::Other(format!(
                                            "bad pg member path {:?}",
                                            spec.path
                                        )));
                                    }
                                };
                                let cfg = match self.databases.get(&db) {
                                    Some(c) => c.clone(),
                                    None => {
                                        let _ = reply.send(Err(()));
                                        return Err(Perr::Other(format!(
                                            "import: no database named {db:?} on this node"
                                        )));
                                    }
                                };
                                if !opts.apply {
                                    // Dry-run: don't touch the server — drain + count.
                                    let _ = reply.send(Ok(()));
                                    while body_rx.recv().await.is_some() {}
                                    report.pg_databases += 1;
                                    pending_chunk = None;
                                } else {
                                    let plan = match self.pg_shadow_plan(project, &db, &cfg).await {
                                        Ok(p) => p,
                                        Err(e) => {
                                            let _ = reply.send(Err(()));
                                            return Err(e);
                                        }
                                    };
                                    // TRUSTED DDL (superuser/maint): mint the ephemeral NON-SUPERUSER
                                    // role + the shadow it owns + pre-create the allowlisted exts.
                                    if let Err(e) = self.pg_create_shadow(&plan, &stage_dir).await {
                                        self.pg_drop_shadow(&plan, &stage_dir).await;
                                        let _ = reply.send(Err(()));
                                        return Err(e);
                                    }
                                    // FAIL-CLOSED: refuse the untrusted apply unless the apply role is
                                    // provably a non-superuser.
                                    if let Err(e) = self
                                        .pg_assert_not_superuser(
                                            &plan.apply_conn(),
                                            &plan.image,
                                            &stage_dir,
                                        )
                                        .await
                                    {
                                        self.pg_drop_shadow(&plan, &stage_dir).await;
                                        let _ = reply.send(Err(()));
                                        return Err(e);
                                    }
                                    let out_path =
                                        stage_dir.join(format!("pgrestore-{chunk_idx}.out"));
                                    chunk_idx += 1;
                                    let restore = match self.spawn_pg_restore(
                                        &plan,
                                        body_rx,
                                        out_path.clone(),
                                    ) {
                                        Ok(h) => h,
                                        Err(e) => {
                                            // Shadow was created — tear it down before failing.
                                            self.pg_drop_shadow(&plan, &stage_dir).await;
                                            let _ = reply.send(Err(()));
                                            return Err(e);
                                        }
                                    };
                                    let _ = reply.send(Ok(()));
                                    pending_chunk = Some(ChunkState::Pg {
                                        plan: Box::new(plan),
                                        restore,
                                        out_path,
                                    });
                                }
                            }
                            MemberKind::MysqlDump => {
                                let db = match db_from_mysql_member(&spec.path) {
                                    Some(d) => d.to_string(),
                                    None => {
                                        let _ = reply.send(Err(()));
                                        return Err(Perr::Other(format!(
                                            "bad mysql member path {:?}",
                                            spec.path
                                        )));
                                    }
                                };
                                let cfg = match self.databases.get(&db) {
                                    Some(c) => c.clone(),
                                    None => {
                                        let _ = reply.send(Err(()));
                                        return Err(Perr::Other(format!(
                                            "import: no database named {db:?} on this node"
                                        )));
                                    }
                                };
                                if !opts.apply {
                                    let _ = reply.send(Ok(()));
                                    while body_rx.recv().await.is_some() {}
                                    report.pg_databases += 1;
                                    pending_chunk = None;
                                } else {
                                    let plan =
                                        match self.mysql_shadow_plan(project, &db, &cfg).await {
                                            Ok(p) => p,
                                            Err(e) => {
                                                let _ = reply.send(Err(()));
                                                return Err(e);
                                            }
                                        };
                                    if let Err(e) =
                                        self.mysql_create_shadow(&plan, &stage_dir).await
                                    {
                                        self.mysql_drop_shadow(&plan, &stage_dir).await;
                                        let _ = reply.send(Err(()));
                                        return Err(e);
                                    }
                                    // FAIL-CLOSED: refuse unless the apply user is least-privilege.
                                    if let Err(e) =
                                        self.mysql_assert_not_superuser(&plan, &stage_dir).await
                                    {
                                        self.mysql_drop_shadow(&plan, &stage_dir).await;
                                        let _ = reply.send(Err(()));
                                        return Err(e);
                                    }
                                    let out_path =
                                        stage_dir.join(format!("myrestore-{chunk_idx}.out"));
                                    chunk_idx += 1;
                                    let restore = match self.spawn_mysql_restore(
                                        &plan,
                                        body_rx,
                                        out_path.clone(),
                                    ) {
                                        Ok(h) => h,
                                        Err(e) => {
                                            self.mysql_drop_shadow(&plan, &stage_dir).await;
                                            let _ = reply.send(Err(()));
                                            return Err(e);
                                        }
                                    };
                                    let _ = reply.send(Ok(()));
                                    pending_chunk = Some(ChunkState::Mysql {
                                        plan: Box::new(plan),
                                        restore,
                                        out_path,
                                    });
                                }
                            }
                            _ => {
                                let _ = reply.send(Err(()));
                                return Err(Perr::Unavailable(format!(
                                    "chunked framing is not wired for member kind {:?}",
                                    spec.kind
                                )));
                            }
                        }
                    }
                    ImportMsg::ChunkFinish { verified, reply } => {
                        let state = pending_chunk.take();
                        let res: Result<(), Perr> = match state {
                            Some(ChunkState::Libsql { shadow, feed_err }) => {
                                if let Some(e) = feed_err {
                                    drop(shadow); // RAII: tear down the shadow
                                    Err(e)
                                } else if !verified {
                                    drop(shadow); // abort: nothing reaches live; reader raises the mismatch
                                    Ok(())
                                } else {
                                    match self
                                        .libsql
                                        .as_ref()
                                        .expect("libsql shadow implies a libsql backend")
                                        .commit_dump_shadow(shadow)
                                        .await
                                    {
                                        Ok(()) => {
                                            report.libsql_databases += 1;
                                            Ok(())
                                        }
                                        Err(e) => Err(other(e)),
                                    }
                                }
                            }
                            Some(ChunkState::Staged {
                                spec,
                                temp,
                                write_err,
                            }) => {
                                let r = if let Some(e) = write_err {
                                    Err(e)
                                } else if !verified {
                                    Ok(()) // abort: drop the temp below; reader raises the mismatch
                                } else {
                                    self.restore_member(
                                        project,
                                        data_only,
                                        &source_project,
                                        &spec,
                                        &temp,
                                        &opts,
                                        &mut report,
                                        &mut saw_identity,
                                    )
                                    .await
                                };
                                let _ = tokio::fs::remove_file(&temp).await;
                                r
                            }
                            Some(ChunkState::Pg {
                                plan,
                                restore,
                                out_path,
                            }) => {
                                // The reader dropped body_tx → stdin EOF; await the restore client.
                                let code = restore.await;
                                let out = tokio::fs::read_to_string(&out_path)
                                    .await
                                    .unwrap_or_default();
                                let _ = tokio::fs::remove_file(&out_path).await;
                                match code {
                                    Ok(Ok(0)) if verified => {
                                        // Restore clean AND trailer matched → atomic swap.
                                        match self.pg_swap_shadow(&plan, &stage_dir).await {
                                            Ok(()) => {
                                                report.pg_databases += 1;
                                                Ok(())
                                            }
                                            Err(e) => {
                                                self.pg_drop_shadow(&plan, &stage_dir).await;
                                                Err(e)
                                            }
                                        }
                                    }
                                    Ok(Ok(0)) => {
                                        // Restore clean but trailer MISMATCH/truncation → abort:
                                        // drop the shadow (live untouched); the reader raises the
                                        // loud SHA/size error.
                                        self.pg_drop_shadow(&plan, &stage_dir).await;
                                        Ok(())
                                    }
                                    Ok(Ok(c)) => {
                                        // Non-zero pg_restore exit — a crafted superuser-only escape
                                        // refused as the non-superuser role lands here (as do other
                                        // restore failures). Drop the shadow; live untouched.
                                        self.pg_drop_shadow(&plan, &stage_dir).await;
                                        Err(Perr::Other(format!(
                                            "pg_restore into shadow {:?} exited {c}; live untouched: {out}",
                                            plan.shadow_db
                                        )))
                                    }
                                    Ok(Err(e)) => {
                                        self.pg_drop_shadow(&plan, &stage_dir).await;
                                        Err(e)
                                    }
                                    Err(je) => {
                                        self.pg_drop_shadow(&plan, &stage_dir).await;
                                        Err(other(je))
                                    }
                                }
                            }
                            Some(ChunkState::Mysql {
                                plan,
                                restore,
                                out_path,
                            }) => {
                                let code = restore.await;
                                let out = tokio::fs::read_to_string(&out_path)
                                    .await
                                    .unwrap_or_default();
                                let _ = tokio::fs::remove_file(&out_path).await;
                                match code {
                                    Ok(Ok(0)) if verified => {
                                        match self.mysql_swap_shadow(&plan, &stage_dir).await {
                                            Ok(()) => {
                                                report.pg_databases += 1;
                                                Ok(())
                                            }
                                            Err(e) => {
                                                self.mysql_drop_shadow(&plan, &stage_dir).await;
                                                Err(e)
                                            }
                                        }
                                    }
                                    Ok(Ok(0)) => {
                                        self.mysql_drop_shadow(&plan, &stage_dir).await;
                                        Ok(())
                                    }
                                    Ok(Ok(c)) => {
                                        self.mysql_drop_shadow(&plan, &stage_dir).await;
                                        Err(Perr::Other(format!(
                                            "mysql restore into shadow {:?} exited {c}; live untouched: {out}",
                                            plan.shadow_db
                                        )))
                                    }
                                    Ok(Err(e)) => {
                                        self.mysql_drop_shadow(&plan, &stage_dir).await;
                                        Err(e)
                                    }
                                    Err(je) => {
                                        self.mysql_drop_shadow(&plan, &stage_dir).await;
                                        Err(other(je))
                                    }
                                }
                            }
                            None => {
                                // A dry-run libsql/pg/mysql chunk (no sink opened) — nothing to commit.
                                Ok(())
                            }
                        };
                        match res {
                            Ok(()) => {
                                let _ = reply.send(Ok(()));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(()));
                                return Err(e);
                            }
                        }
                    }
                }
            }
            // Safety net: if the reader died WITHOUT a ChunkFinish (e.g. a panic / broken req
            // channel) while a pg/mysql shadow was in flight, tear it down so no orphan db remains
            // (the libsql/staged shadows self-clean on Drop; the startup sweep covers a crash).
            match pending_chunk.take() {
                Some(ChunkState::Pg { plan, restore, .. }) => {
                    restore.abort();
                    self.pg_drop_shadow(&plan, &stage_dir).await;
                }
                Some(ChunkState::Mysql { plan, restore, .. }) => {
                    restore.abort();
                    self.mysql_drop_shadow(&plan, &stage_dir).await;
                }
                _ => {}
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
                        MemberSpec::sidecar(
                            IDENTITY_MEMBER_PATH.to_string(),
                            MemberKind::Identity,
                            None,
                        ),
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
            // A blob whose KNOWN size exceeds the chunk threshold is framed ChunkedTrailer so the
            // EXPORT streams its body straight through `append_member_chunked` (O(chunk), no
            // whole-object temp — the inc2 win over inc1's stage-the-whole-blob); a small or
            // unknown-size blob stays Sidecar (inc1's staged verify-before-apply, unchanged).
            let spec = if meta.size.is_some_and(|s| s > self.chunk_size as u64) {
                MemberSpec::chunked(member_path, MemberKind::Blob, None)
            } else {
                MemberSpec::sidecar(member_path, MemberKind::Blob, None)
            };
            ordered.push((spec, StageJob::Blob { key: meta.key }));
        }

        // --- per-engine dumps (pg + mysql; managed OR external bring-your-own-URL) ---
        for (db, cfg) in &self.databases {
            let is_managed = cfg.compute.as_deref().is_some_and(|c| !c.is_empty());
            let dumpable = is_managed || !cfg.url_env.is_empty();
            // A MANAGED, DEDICATED/Single pg/mysql FULL dump is framed ChunkedTrailer → the inc2
            // streamed dump + atomic shadow-restore (Stage C/D). A `--data-only` import stays on the
            // inc1 sidecar path (default #1: FULL-restore atomicity only); an EXTERNAL
            // bring-your-own-URL binding stays sidecar (we never CREATE/RENAME/DROP databases on an
            // operator's own server); and a SHARED multi-tenant server stays sidecar (HIGH-1 / #6:
            // the per-import physical shadow db is a cross-tenant surface deferred to the temp-schema
            // follow-up). So: chunked IFF managed AND full AND not-Shared.
            let is_shared = matches!(cfg.tenant, crate::config::TenantIsolation::Shared);
            let chunked = is_managed && !data_only && !is_shared;
            if kind_is_postgres(&cfg.kind) && dumpable {
                let (conn, image, server_version_num) = self.resolve_pg(project, db, cfg).await?;
                let schema_fingerprint = self.schema_fingerprint(project, db).await;
                let pg = Some(PgMemberInfo {
                    server_version_num,
                    client_image: image.clone(),
                    schema_fingerprint,
                });
                let spec = if chunked {
                    MemberSpec::chunked(pg_member_path(db), MemberKind::PgDump, pg)
                } else {
                    MemberSpec::sidecar(pg_member_path(db), MemberKind::PgDump, pg)
                };
                ordered.push((
                    spec,
                    StageJob::Pg {
                        conn,
                        image,
                        data_only,
                    },
                ));
            } else if kind_is_mysql(&cfg.kind) && dumpable {
                let (conn, image, version) = self.resolve_mysql(project, db, cfg).await?;
                let schema_fingerprint = self.schema_fingerprint(project, db).await;
                let pg = Some(PgMemberInfo {
                    server_version_num: version,
                    client_image: image.clone(),
                    schema_fingerprint,
                });
                let spec = if chunked {
                    MemberSpec::chunked(mysql_member_path(db), MemberKind::MysqlDump, pg)
                } else {
                    MemberSpec::sidecar(mysql_member_path(db), MemberKind::MysqlDump, pg)
                };
                ordered.push((
                    spec,
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
                    // ChunkedTrailer: the libsql member is a streamed `.dump` SQL text (inc2
                    // default #4 — true O(chunk), NOT a staged VACUUM-INTO file), piped straight
                    // through `append_member_chunked`; the import applies it into an atomic shadow.
                    MemberSpec::chunked(
                        libsql_member_path(project, &site),
                        MemberKind::Libsql,
                        None,
                    ),
                    StageJob::Libsql { qsite },
                ));
            }
        }

        // --- control-plane KV slice (FULL export only) — LAST in restore order. A
        //     `--data-only` bundle carries application data ONLY, never the KV slice (RBAC,
        //     routing, personas, sealed secrets), so it is not even staged for data-only. ---
        if !data_only {
            ordered.push((
                MemberSpec::sidecar(KV_MEMBER_PATH.to_string(), MemberKind::Kv, None),
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

    /// Start a producer task for a ChunkedTrailer member, returning its body-channel receiver, a
    /// `poison` flag the producer sets on error (so a premature channel close is a loud IO error,
    /// never a silently-truncated member), and its `JoinHandle` (awaited by the stager — a producer
    /// error FAILS the export). The body streams O(chunk): the libsql `.dump` (bounded by one
    /// statement) or the blob get (bounded by one chunk), NEVER staging the whole member to disk.
    fn open_chunked_producer(&self, job: Option<&StageJob>) -> Result<ChunkedProducer, Perr> {
        use std::sync::atomic::Ordering::SeqCst;
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BYTE_CHANNEL);
        let poison = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let poison2 = poison.clone();
        let handle = match job {
            Some(StageJob::Libsql { qsite }) => {
                let libsql = self.libsql.clone().ok_or_else(|| {
                    Perr::Other("internal: libsql chunked job with no libsql backend".into())
                })?;
                let qsite = qsite.clone();
                tokio::spawn(async move {
                    let r = libsql
                        .dump_database(&qsite, "", &body_tx)
                        .await
                        .map_err(other);
                    if r.is_err() {
                        poison2.store(true, SeqCst);
                    }
                    drop(body_tx); // EOF the reader AFTER the poison store
                    r
                })
            }
            Some(StageJob::Blob { key }) => {
                let blobs = self.blobs.clone();
                let key = key.clone();
                tokio::spawn(async move {
                    let r: Result<(), Perr> = async {
                        let obj = blobs.get(&key).await.map_err(other)?;
                        let mut body = obj.body;
                        while let Some(chunk) = body.next().await {
                            let chunk = chunk.map_err(other)?;
                            body_tx
                                .send(chunk.as_ref().to_vec())
                                .await
                                .map_err(|_| Perr::Other("export blob body sink closed".into()))?;
                        }
                        Ok(())
                    }
                    .await;
                    if r.is_err() {
                        poison2.store(true, SeqCst);
                    }
                    drop(body_tx);
                    r
                })
            }
            Some(StageJob::Pg { conn, image, .. }) => {
                // FULL `pg_dump -Fc` stdout → body channel, NO temp (inc2 Stage C). The chunked pg
                // path is FULL-only (default #1), so `data_only` is ignored here (plan_export only
                // frames pg chunked when !data_only).
                let backend = self.require_backend()?.clone();
                let conn = conn.clone();
                let image = image.clone();
                tokio::spawn(async move {
                    let mut sink = AsyncChannelWriter::new(body_tx);
                    let r: Result<(), Perr> = async {
                        let inv = pg_dump_invocation(&conn, false);
                        let code = backend
                            .run_ephemeral(&image, &inv.argv, &inv.env, None, &mut sink)
                            .await
                            .map_err(other)?;
                        if code != 0 {
                            return Err(Perr::Other(format!("pg_dump exited {code}")));
                        }
                        Ok(())
                    }
                    .await;
                    // Set poison BEFORE closing the sink, so a short/failed dump becomes a loud IO
                    // error at the reader (never a valid trailer over an incomplete member).
                    if r.is_err() {
                        poison2.store(true, SeqCst);
                    }
                    drop(sink); // closes the PollSender → body_rx EOF, after the poison store
                    r
                })
            }
            Some(StageJob::Mysql { conn, image, .. }) => {
                // Tables-only FULL `mysqldump` stdout → body channel, NO temp (inc2 Stage D).
                let backend = self.require_backend()?.clone();
                let conn = conn.clone();
                let image = image.clone();
                tokio::spawn(async move {
                    let mut sink = AsyncChannelWriter::new(body_tx);
                    let r: Result<(), Perr> = async {
                        let inv = mysqldump_tables_only_invocation(&conn);
                        let code = backend
                            .run_ephemeral(&image, &inv.argv, &inv.env, None, &mut sink)
                            .await
                            .map_err(other)?;
                        if code != 0 {
                            return Err(Perr::Other(format!("mysqldump exited {code}")));
                        }
                        Ok(())
                    }
                    .await;
                    if r.is_err() {
                        poison2.store(true, SeqCst);
                    }
                    drop(sink);
                    r
                })
            }
            _ => {
                return Err(Perr::Other(
                    "export: chunked framing is wired only for pg/mysql, libsql + large blobs"
                        .into(),
                ));
            }
        };
        Ok((body_rx, poison, handle))
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
                    // HIGH-1: a SIDECAR pg member (data-only, or a Shared/dedicated FULL that was not
                    // chunked) is still ATTACKER-CRAFTED. Applying it via `resolve_pg` would connect
                    // as the configured user, which on a MANAGED co-located server is the BOOTSTRAP
                    // SUPERUSER — a crafted archive's `COPY … TO PROGRAM` / `CREATE FUNCTION … LANGUAGE
                    // c` / `CREATE EXTENSION` would then execute = RCE. The chunked FULL path confines
                    // this with an ephemeral non-superuser role + shadow; a least-privilege sidecar
                    // apply (data-only into a live schema) is the follow-up, so until it lands we
                    // REFUSE a managed sidecar apply fail-closed rather than apply as superuser. An
                    // EXTERNAL bring-your-own-URL binding applies with the OPERATOR'S OWN credential
                    // against the OPERATOR'S OWN database (their trust boundary, not our managed
                    // cluster), so it is still applied.
                    if is_managed_binding(cfg) {
                        return Err(Perr::Unavailable(format!(
                            "import refused: a MANAGED pg database ({db:?}) can only be restored via \
                             the atomic chunked shadow path (a FULL, dedicated/Single bundle). A \
                             data-only or Shared sidecar restore would apply the untrusted dump as \
                             the bootstrap superuser (RCE risk); a least-privilege sidecar apply is a \
                             pending follow-up. Re-export as a FULL dedicated bundle, or import into \
                             an external (bring-your-own-URL) binding."
                        )));
                    }
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
                    // HIGH-1 (mirror of the pg sidecar arm): refuse a MANAGED sidecar mysql apply —
                    // it would connect as the bootstrap superuser against our co-located server. An
                    // EXTERNAL binding applies with the operator's own credential (their trust).
                    if is_managed_binding(cfg) {
                        return Err(Perr::Unavailable(format!(
                            "import refused: a MANAGED mysql database ({db:?}) can only be restored \
                             via the atomic chunked shadow path (a FULL, dedicated/Single bundle); a \
                             data-only/Shared sidecar restore would apply the untrusted dump as a \
                             superuser (RCE risk). Re-export as a FULL dedicated bundle, or import \
                             into an external binding."
                        )));
                    }
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
                    // Sidecar libsql (a v1/v2 VACUUM-INTO member) → atomic shadow+rename,
                    // overwrite-gated. A v3 chunked libsql member takes the streamed-shadow path in
                    // the servicer, never this arm.
                    libsql
                        .restore_snapshot(&qsite, "", temp, opts.overwrite)
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
                // HIGH-1: SYMMETRIC, FAIL-CLOSED tenancy enforcement on the trust boundary —
                // the mirror of the export-side scope filter. After re-key, EVERY surviving key
                // MUST be under the target's owned prefixes (the one exception is a referenced,
                // content-verified `siteconfig/<hash>`); anything else (another tenant's
                // `project/…`, a global `cert/`/`domain/`/`wildcard/`, a node `daemonconfig/`, a
                // reserved `_cp/`/`_inval/`, or a poisoned siteconfig) ABORTS the import — a
                // crafted bundle must never write node-wide outside the target's scope.
                boatramp_core::project_export::enforce_target_scoped_kv(
                    &decoded.entries,
                    ProjectRef::new(project),
                )
                .map_err(Perr::Other)?;
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

    // -----------------------------------------------------------------------
    // inc2 Stage C — Postgres atomic shadow-restore
    //
    // THE SECURITY-CRITICAL SPLIT (the pg analogue of Build 1's libsql ATTACH-authorizer fix):
    // a pg dump in a bundle is ATTACKER-CRAFTED (the trailer SHA is integrity, not authenticity),
    // and run as a SUPERUSER a crafted dump can `COPY … TO/FROM PROGRAM/FILE`, `CREATE FUNCTION …
    // LANGUAGE c`, `CREATE EXTENSION`, … = arbitrary code/file execution on the box.
    //
    // HIGH-1 (Build-2 Security re-review): the configured binding user is NOT reliably a
    // non-superuser — on a Single/dedicated managed pg it is the bootstrap SUPERUSER (POSTGRES_USER),
    // and `owner_target` only yields a genuine non-superuser role for `Shared && !default`. So the
    // apply MUST NOT use the configured/owner identity. Instead the superuser creates an EPHEMERAL
    // per-import `NOSUPERUSER NOCREATEDB NOCREATEROLE` role (random password), the shadow is OWNED by
    // it, `pg_restore` applies the untrusted dump CONNECTING AS THAT ephemeral role (so every
    // superuser-only escape FAILS regardless of `cfg.user`), and a fail-closed probe REFUSES the
    // apply if the resolved role is somehow a superuser. The SUPERUSER / maintenance connection
    // (`plan.maint`, on `postgres`) runs ONLY our own trusted DDL — never a byte of the dump — and,
    // before the apply, pre-creates the operator trusted-extension allowlist in the shadow so a legit
    // `CREATE EXTENSION IF NOT EXISTS <ext>` (e.g. pgvector) no-ops under the non-superuser apply.
    // Chunked shadow-restore is for DEDICATED/Single managed servers only; a Shared multi-tenant
    // server is refused here (the per-import physical shadow db is a cross-tenant surface deferred to
    // the temp-schema follow-up).
    // -----------------------------------------------------------------------

    /// Resolve the [`PgShadowPlan`] for a MANAGED, non-Shared pg binding: the superuser/maintenance
    /// connection (on `postgres`), a freshly-minted EPHEMERAL non-superuser apply role + password,
    /// the client image, the shadow name, and the trusted-extension allowlist. External
    /// (bring-your-own-URL) bindings are refused — we must not `CREATE/RENAME/DROP` databases on an
    /// operator's own server — and a Shared multi-tenant server is refused (dedicated/Single only).
    async fn pg_shadow_plan(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<PgShadowPlan, Perr> {
        if !cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) {
            return Err(Perr::Unavailable(format!(
                "database {db:?}: the atomic chunked pg shadow-restore is for MANAGED \
                 (compute-backed) databases only; an external bring-your-own-URL binding uses the \
                 sidecar path"
            )));
        }
        if matches!(cfg.tenant, crate::config::TenantIsolation::Shared) {
            return Err(Perr::Unavailable(format!(
                "database {db:?}: the atomic chunked pg shadow-restore is for DEDICATED/Single \
                 managed servers only; a Shared multi-tenant server's per-import physical shadow db \
                 is a cross-tenant surface deferred to the temp-schema follow-up"
            )));
        }
        // Operator identity (configured/superuser) + version-detect → client image. Its endpoint
        // (host/port) + the live tenant db name + the configured owner seed the maintenance conn.
        let (operator_conn, image, _ver) = self.resolve_pg(project, db, cfg).await?;
        let live_db = operator_conn.database.clone();
        let owner_user = operator_conn.user.clone();
        let mut maint = operator_conn;
        // CREATE/ALTER/DROP DATABASE cannot run connected to the tenant db — point at `postgres`.
        maint.database = "postgres".to_string();
        let suffix = shadow_suffix();
        let shadow_db = format!("{live_db}__shadow_{suffix}");
        let eph_role = format!("brexp_apply_{suffix}");
        Ok(PgShadowPlan {
            live_db,
            shadow_db,
            suffix,
            maint,
            eph_role,
            eph_password: random_token(),
            owner_user,
            image,
            trusted_extensions: self.trusted_extensions.clone(),
        })
    }

    /// Fail-closed defense-in-depth probe: confirm the resolved apply identity (`conn`) is NOT a
    /// superuser before any untrusted dump reaches it. Refuses the import loudly otherwise, so the
    /// non-superuser confinement can never be silently absent.
    async fn pg_assert_not_superuser(
        &self,
        conn: &PgConnection,
        image: &str,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let inv = psql_invocation(
            conn,
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
        );
        let (code, out) = self
            .run_sql_capture(image, &inv.argv, &inv.env, None, stage_dir)
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg shadow: could not probe the apply role's superuser attribute (exit {code}): {out}"
            )));
        }
        if out.trim() != "f" {
            return Err(Perr::Other(format!(
                "pg shadow REFUSED: the resolved apply role is a SUPERUSER (rolsuper={:?}); an \
                 untrusted bundle dump must only be applied by a non-superuser role",
                out.trim()
            )));
        }
        Ok(())
    }

    /// Run ONE trusted DDL/utility statement through the SUPERUSER / maintenance connection
    /// (`psql -c`). The caller passes a single statement (psql wraps a multi-statement `-c` string
    /// as one implicit transaction, which `CREATE DATABASE`/`ALTER DATABASE … RENAME` forbid).
    async fn pg_run_ddl(
        &self,
        plan: &PgShadowPlan,
        sql: &str,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let inv = psql_invocation(&plan.maint, sql);
        let (code, out) = self
            .run_sql_capture(&plan.image, &inv.argv, &inv.env, None, stage_dir)
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg shadow DDL exited {code} ({sql}): {out}"
            )));
        }
        Ok(())
    }

    /// Whether a database `name` exists (via the maintenance connection) — so the swap can skip the
    /// rename-aside when cloning into a target that has no live db yet.
    async fn pg_db_exists(
        &self,
        plan: &PgShadowPlan,
        name: &str,
        stage_dir: &Path,
    ) -> Result<bool, Perr> {
        let sql = format!("SELECT 1 FROM pg_database WHERE datname = {}", pg_lit(name));
        let inv = psql_invocation(&plan.maint, &sql);
        let (code, out) = self
            .run_sql_capture(&plan.image, &inv.argv, &inv.env, None, stage_dir)
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg shadow: could not probe database {name:?} (exit {code}): {out}"
            )));
        }
        Ok(out.trim() == "1")
    }

    /// TRUSTED DDL (superuser): mint the EPHEMERAL non-superuser apply role, create the shadow
    /// database OWNED by it (so the `pg_restore` apply as that role can create objects), and
    /// pre-create the operator trusted-extension allowlist in the shadow (so a legit `CREATE
    /// EXTENSION IF NOT EXISTS <ext>` in the untrusted dump no-ops under the non-superuser apply —
    /// the pgvector wrinkle). The role name + shadow name are per-process unique, so no pre-drop is
    /// needed. A dump that references an extension NOT on the allowlist fails fail-closed under the
    /// non-superuser apply (correct: we never let an untrusted bundle install an arbitrary extension).
    async fn pg_create_shadow(&self, plan: &PgShadowPlan, stage_dir: &Path) -> Result<(), Perr> {
        let role_q = quote_ident(ExternalSqlKind::Postgres, &plan.eph_role);
        let shadow_q = quote_ident(ExternalSqlKind::Postgres, &plan.shadow_db);
        // The random password is a trusted, we-generate-it literal (not a credential that leaks via
        // argv — psql's -c SQL is not a process listing concern on the DB host, and it never reaches
        // a handler); still, quote it as a SQL literal defensively.
        self.pg_run_ddl(
            plan,
            &format!(
                "CREATE ROLE {role_q} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS",
                pg_lit(&plan.eph_password)
            ),
            stage_dir,
        )
        .await?;
        self.pg_run_ddl(
            plan,
            &format!("CREATE DATABASE {shadow_q} OWNER {role_q}"),
            stage_dir,
        )
        .await?;
        // Pre-create the allowlisted extensions in the shadow, as the SUPERUSER, connected to the
        // shadow (extensions are database-local). `IF NOT EXISTS` so a re-run is a no-op.
        if !plan.trusted_extensions.is_empty() {
            let maint_shadow = PgShadowPlan {
                maint: plan.maint_on_shadow(),
                ..plan.clone()
            };
            for ext in &plan.trusted_extensions {
                let ext_q = quote_ident(ExternalSqlKind::Postgres, ext);
                self.pg_run_ddl(
                    &maint_shadow,
                    &format!("CREATE EXTENSION IF NOT EXISTS {ext_q}"),
                    stage_dir,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Best-effort TEARDOWN of the shadow + ephemeral role (abort / RAII): terminate any lingering
    /// restore connection, `DROP DATABASE IF EXISTS` (which removes the ephemeral-owned objects),
    /// then `DROP ROLE IF EXISTS` the ephemeral role (it owns nothing once the shadow is gone).
    /// Called on EVERY abort path; the startup sweep covers the crash case.
    async fn pg_drop_shadow(&self, plan: &PgShadowPlan, stage_dir: &Path) {
        let shadow_q = quote_ident(ExternalSqlKind::Postgres, &plan.shadow_db);
        let role_q = quote_ident(ExternalSqlKind::Postgres, &plan.eph_role);
        let _ = self
            .pg_run_ddl(
                plan,
                &format!(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                     WHERE datname = {} AND pid <> pg_backend_pid()",
                    pg_lit(&plan.shadow_db)
                ),
                stage_dir,
            )
            .await;
        if let Err(e) = self
            .pg_run_ddl(
                plan,
                &format!("DROP DATABASE IF EXISTS {shadow_q}"),
                stage_dir,
            )
            .await
        {
            tracing::warn!(error = %e, shadow = %plan.shadow_db, "pg shadow drop-on-abort failed; the startup sweep will reclaim it");
        }
        if let Err(e) = self
            .pg_run_ddl(plan, &format!("DROP ROLE IF EXISTS {role_q}"), stage_dir)
            .await
        {
            tracing::warn!(error = %e, role = %plan.eph_role, "pg ephemeral apply-role drop-on-abort failed; the startup sweep will reclaim it");
        }
    }

    /// TRUSTED DDL: atomically swap the verified shadow in for live. Terminate live sessions,
    /// `ALTER DATABASE <live> RENAME TO <live>__old_<suffix>` (skipped if there is no live db yet),
    /// terminate shadow sessions, `ALTER DATABASE <shadow> RENAME TO <live>`, then drop the aside
    /// copy. A sub-ms window exists between the two renames where no `<live>` db is present
    /// (acceptable for an import/clone, not a live cutover). If the shadow→live rename fails after
    /// the aside, the aside is renamed back so live is never lost.
    async fn pg_swap_shadow(&self, plan: &PgShadowPlan, stage_dir: &Path) -> Result<(), Perr> {
        let live_q = quote_ident(ExternalSqlKind::Postgres, &plan.live_db);
        let shadow_q = quote_ident(ExternalSqlKind::Postgres, &plan.shadow_db);
        let role_q = quote_ident(ExternalSqlKind::Postgres, &plan.eph_role);
        let owner_q = quote_ident(ExternalSqlKind::Postgres, &plan.owner_user);
        let old_db = format!("{}__old_{}", plan.live_db, plan.suffix);
        let old_q = quote_ident(ExternalSqlKind::Postgres, &old_db);
        // Reassign the restored objects (owned by the ephemeral role after a `--no-owner` restore)
        // to the configured owner, then re-own the database, so the swapped-in live db has its usual
        // ownership and the ephemeral role can be dropped. REASSIGN OWNED must run connected to the
        // db it targets (the shadow); ALTER DATABASE OWNER runs from the maintenance db.
        let maint_shadow = PgShadowPlan {
            maint: plan.maint_on_shadow(),
            ..plan.clone()
        };
        self.pg_run_ddl(
            &maint_shadow,
            &format!("REASSIGN OWNED BY {role_q} TO {owner_q}"),
            stage_dir,
        )
        .await?;
        self.pg_run_ddl(
            plan,
            &format!("ALTER DATABASE {shadow_q} OWNER TO {owner_q}"),
            stage_dir,
        )
        .await?;
        let live_exists = self.pg_db_exists(plan, &plan.live_db, stage_dir).await?;
        if live_exists {
            self.pg_run_ddl(
                plan,
                &format!(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                     WHERE datname = {} AND pid <> pg_backend_pid()",
                    pg_lit(&plan.live_db)
                ),
                stage_dir,
            )
            .await?;
            self.pg_run_ddl(
                plan,
                &format!("ALTER DATABASE {live_q} RENAME TO {old_q}"),
                stage_dir,
            )
            .await?;
        }
        // Terminate the restore connection to the shadow before renaming it.
        self.pg_run_ddl(
            plan,
            &format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = {} AND pid <> pg_backend_pid()",
                pg_lit(&plan.shadow_db)
            ),
            stage_dir,
        )
        .await?;
        if let Err(e) = self
            .pg_run_ddl(
                plan,
                &format!("ALTER DATABASE {shadow_q} RENAME TO {live_q}"),
                stage_dir,
            )
            .await
        {
            // Roll the aside back to live so a failed swap never loses the original.
            if live_exists {
                let _ = self
                    .pg_run_ddl(
                        plan,
                        &format!("ALTER DATABASE {old_q} RENAME TO {live_q}"),
                        stage_dir,
                    )
                    .await;
            }
            return Err(e);
        }
        if live_exists {
            // The swap succeeded; the aside copy is obsolete (best-effort drop).
            let _ = self
                .pg_run_ddl(
                    plan,
                    &format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                         WHERE datname = {} AND pid <> pg_backend_pid()",
                        pg_lit(&old_db)
                    ),
                    stage_dir,
                )
                .await;
            let _ = self
                .pg_run_ddl(plan, &format!("DROP DATABASE IF EXISTS {old_q}"), stage_dir)
                .await;
        }
        // The ephemeral apply role has no objects left (reassigned) — drop it.
        let _ = self
            .pg_run_ddl(plan, &format!("DROP ROLE IF EXISTS {role_q}"), stage_dir)
            .await;
        Ok(())
    }

    /// Spawn the `pg_restore` subprocess that applies the untrusted dump into the shadow, connecting
    /// as the EPHEMERAL NON-SUPERUSER role, reading the chunked member's body channel as stdin (so
    /// the dump streams in O(chunk)). Returns its `JoinHandle` (awaited at `ChunkFinish`).
    fn spawn_pg_restore(
        &self,
        plan: &PgShadowPlan,
        body_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        out_path: PathBuf,
    ) -> Result<tokio::task::JoinHandle<Result<i32, Perr>>, Perr> {
        let backend = self.require_backend()?.clone();
        let image = plan.image.clone();
        let inv = pg_restore_shadow_invocation(&plan.apply_conn(), &plan.shadow_db);
        Ok(tokio::spawn(async move {
            let mut reader = AsyncChannelReader::new(body_rx);
            let out = tokio::fs::File::create(&out_path).await.map_err(other)?;
            let mut sink = out.compat_write();
            backend
                .run_ephemeral(&image, &inv.argv, &inv.env, Some(&mut reader), &mut sink)
                .await
                .map_err(other)
        }))
    }

    // -----------------------------------------------------------------------
    // inc2 Stage D — MySQL atomic shadow-restore (secondary; construens is pg). Same
    // non-superuser-apply split: `mysql <shadow>` applies the attacker dump as the owner role;
    // the maintenance connection runs the trusted `CREATE DATABASE` + atomic `RENAME TABLE` swap.
    // -----------------------------------------------------------------------

    /// Resolve the [`MysqlShadowPlan`] for a MANAGED, non-Shared mysql binding (external bindings
    /// stay sidecar; Shared multi-tenant is refused — dedicated/Single only). Mints an EPHEMERAL
    /// apply user + password (HIGH-1: the configured user is the bootstrap superuser on a dedicated
    /// instance, so the apply must NOT use it).
    async fn mysql_shadow_plan(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<MysqlShadowPlan, Perr> {
        if !cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) {
            return Err(Perr::Unavailable(format!(
                "database {db:?}: the atomic chunked mysql shadow-restore is for MANAGED \
                 (compute-backed) databases only; an external binding uses the sidecar path"
            )));
        }
        if matches!(cfg.tenant, crate::config::TenantIsolation::Shared) {
            return Err(Perr::Unavailable(format!(
                "database {db:?}: the atomic chunked mysql shadow-restore is for DEDICATED/Single \
                 managed servers only; a Shared multi-tenant server is deferred"
            )));
        }
        let (operator_conn, image, _ver) = self.resolve_mysql(project, db, cfg).await?;
        let live_db = operator_conn.database.clone();
        let maint = operator_conn; // mysql names no default db for the admin SQL
        let suffix = shadow_suffix();
        let shadow_db = format!("{live_db}__shadow_{suffix}");
        let eph_user = format!("brexp_apply_{suffix}");
        Ok(MysqlShadowPlan {
            live_db,
            shadow_db,
            suffix,
            maint,
            eph_user,
            eph_password: random_token(),
            image,
        })
    }

    /// Fail-closed probe: refuse the untrusted mysql apply unless the ephemeral user's grants carry
    /// NO `SUPER`, `FILE`, or `ALL PRIVILEGES ON *.*` — so a crafted dump cannot `INTO OUTFILE` /
    /// `LOAD DATA INFILE` / otherwise escape. Runs as the apply user (`SHOW GRANTS FOR CURRENT_USER`).
    async fn mysql_assert_not_superuser(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let apply = plan.apply_conn();
        let inv = mysql_admin_invocation(&apply);
        let in_path = stage_dir.join(format!("mysql-probe-{}.sql", shadow_suffix()));
        tokio::fs::write(&in_path, "SHOW GRANTS FOR CURRENT_USER();")
            .await
            .map_err(other)?;
        let r = self
            .run_sql_capture(&plan.image, &inv.argv, &inv.env, Some(&in_path), stage_dir)
            .await;
        let _ = tokio::fs::remove_file(&in_path).await;
        let (code, out) = r?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not probe the apply user's grants (exit {code}): {out}"
            )));
        }
        // Refuse SUPER/FILE (global-only escape privileges) or any NON-trivial `*.*` grant. The
        // baseline `GRANT USAGE ON *.* TO …` that every user carries is harmless (USAGE = "no
        // privileges") and must NOT trip the probe.
        for line in out.lines() {
            let up = line.to_ascii_uppercase();
            let dangerous_global = up.contains("ON *.*") && !up.contains("USAGE ON *.*");
            if up.contains("SUPER") || up.contains("FILE") || dangerous_global {
                return Err(Perr::Other(format!(
                    "mysql shadow REFUSED: the resolved apply user holds SUPER/FILE/*.* privileges; \
                     an untrusted bundle dump must only be applied by a least-privilege user. \
                     grants: {out}"
                )));
            }
        }
        Ok(())
    }

    /// Run trusted mysql SQL (fed on stdin, no default db) through the maintenance connection,
    /// capturing stdout (for the table enumeration) + the exit code.
    async fn mysql_run_admin(
        &self,
        plan: &MysqlShadowPlan,
        sql: &str,
        stage_dir: &Path,
    ) -> Result<(i32, String), Perr> {
        let inv = mysql_admin_invocation(&plan.maint);
        let in_path = stage_dir.join(format!("mysql-admin-{}.sql", shadow_suffix()));
        tokio::fs::write(&in_path, sql).await.map_err(other)?;
        let r = self
            .run_sql_capture(&plan.image, &inv.argv, &inv.env, Some(&in_path), stage_dir)
            .await;
        let _ = tokio::fs::remove_file(&in_path).await;
        r
    }

    /// List the base tables of a database via `information_schema` (maintenance connection).
    async fn mysql_list_tables(
        &self,
        plan: &MysqlShadowPlan,
        db: &str,
        stage_dir: &Path,
    ) -> Result<Vec<String>, Perr> {
        let sql = format!(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = {} AND table_type = 'BASE TABLE';",
            mysql_lit(db)
        );
        let (code, out) = self.mysql_run_admin(plan, &sql, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not list tables of {db:?} (exit {code}): {out}"
            )));
        }
        Ok(out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// TRUSTED DDL: create the shadow database + mint the EPHEMERAL apply user granted ONLY on the
    /// shadow db (never `*.*`, `SUPER`, or `FILE`), so a crafted dump applied as that user cannot
    /// escape. The ephemeral user is dropped on swap/abort.
    async fn mysql_create_shadow(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let shadow_q = quote_ident(ExternalSqlKind::Mysql, &plan.shadow_db);
        let user_lit = mysql_lit(&plan.eph_user);
        let pw_lit = mysql_lit(&plan.eph_password);
        let (code, out) = self
            .mysql_run_admin(
                plan,
                &format!(
                    "CREATE DATABASE {shadow_q}; \
                     CREATE USER {user_lit}@'%' IDENTIFIED BY {pw_lit}; \
                     GRANT ALL PRIVILEGES ON {shadow_q}.* TO {user_lit}@'%';"
                ),
                stage_dir,
            )
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow create (db + ephemeral user) exited {code}: {out}"
            )));
        }
        Ok(())
    }

    /// Best-effort shadow + ephemeral-user teardown (abort / RAII).
    async fn mysql_drop_shadow(&self, plan: &MysqlShadowPlan, stage_dir: &Path) {
        let shadow_q = quote_ident(ExternalSqlKind::Mysql, &plan.shadow_db);
        let user_lit = mysql_lit(&plan.eph_user);
        if let Err(e) = self
            .mysql_run_admin(
                plan,
                &format!("DROP DATABASE IF EXISTS {shadow_q}; DROP USER IF EXISTS {user_lit}@'%';"),
                stage_dir,
            )
            .await
        {
            tracing::warn!(error = %e, shadow = %plan.shadow_db, "mysql shadow drop-on-abort failed; the startup sweep will reclaim it");
        }
    }

    /// TRUSTED DDL: atomically swap the verified shadow in for live via ONE `RENAME TABLE` that
    /// moves every live table aside (`<live>.<t>` → `<live>.__old_<suffix>_<t>`) AND every shadow
    /// table in (`<shadow>.<t>` → `<live>.<t>`) — MySQL applies a multi-table `RENAME TABLE`
    /// atomically — then drops the aside tables + the shadow database.
    async fn mysql_swap_shadow(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let live_tables = self
            .mysql_list_tables(plan, &plan.live_db, stage_dir)
            .await?;
        let shadow_tables = self
            .mysql_list_tables(plan, &plan.shadow_db, stage_dir)
            .await?;
        let liveq = |t: &str| {
            format!(
                "{}.{}",
                quote_ident(ExternalSqlKind::Mysql, &plan.live_db),
                quote_ident(ExternalSqlKind::Mysql, t)
            )
        };
        let shadowq = |t: &str| {
            format!(
                "{}.{}",
                quote_ident(ExternalSqlKind::Mysql, &plan.shadow_db),
                quote_ident(ExternalSqlKind::Mysql, t)
            )
        };
        let aside_name = |t: &str| format!("__old_{}_{t}", plan.suffix);
        let mut moves: Vec<String> = Vec::new();
        for t in &live_tables {
            moves.push(format!("{} TO {}", liveq(t), liveq(&aside_name(t))));
        }
        for t in &shadow_tables {
            moves.push(format!("{} TO {}", shadowq(t), liveq(t)));
        }
        if !moves.is_empty() {
            let (code, out) = self
                .mysql_run_admin(
                    plan,
                    &format!("RENAME TABLE {};", moves.join(", ")),
                    stage_dir,
                )
                .await?;
            if code != 0 {
                return Err(Perr::Other(format!(
                    "mysql shadow swap (RENAME TABLE) exited {code}: {out}"
                )));
            }
        }
        // Drop the aside tables + the now-empty shadow db (best-effort — the swap already landed).
        for t in &live_tables {
            let _ = self
                .mysql_run_admin(
                    plan,
                    &format!("DROP TABLE IF EXISTS {};", liveq(&aside_name(t))),
                    stage_dir,
                )
                .await;
        }
        self.mysql_drop_shadow(plan, stage_dir).await;
        Ok(())
    }

    /// Spawn the `mysql <shadow>` subprocess that applies the untrusted tables-only dump as the
    /// EPHEMERAL least-privilege user, reading the body channel as stdin.
    fn spawn_mysql_restore(
        &self,
        plan: &MysqlShadowPlan,
        body_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        out_path: PathBuf,
    ) -> Result<tokio::task::JoinHandle<Result<i32, Perr>>, Perr> {
        let backend = self.require_backend()?.clone();
        let image = plan.image.clone();
        let inv = mysql_shadow_invocation(&plan.apply_conn(), &plan.shadow_db);
        Ok(tokio::spawn(async move {
            let mut reader = AsyncChannelReader::new(body_rx);
            let out = tokio::fs::File::create(&out_path).await.map_err(other)?;
            let mut sink = out.compat_write();
            backend
                .run_ephemeral(&image, &inv.argv, &inv.env, Some(&mut reader), &mut sink)
                .await
                .map_err(other)
        }))
    }

    /// Startup sweep of stale `*__shadow_*` / `*__old_*` databases left by a crash mid-import (the
    /// RAII drop-on-abort only fires in-process). Best-effort per MANAGED pg/mysql binding: a
    /// not-yet-ready or unreachable managed server simply yields no sweep (logged), never a boot
    /// failure. Runs at node startup (no import is in flight yet). Returns the count dropped.
    pub async fn sweep_stale_sql_shadows(&self, project: &str) -> usize {
        let mut dropped = 0usize;
        let session = self.work_dir.join(format!("shadow-sweep-{}", now_secs()));
        if tokio::fs::create_dir_all(&session).await.is_err() {
            return 0;
        }
        for (db, cfg) in &self.databases {
            if !cfg.compute.as_deref().is_some_and(|c| !c.is_empty()) {
                continue; // external bindings have no shadow dbs of ours
            }
            if kind_is_postgres(&cfg.kind) {
                if let Ok(plan) = self.pg_shadow_plan(project, db, cfg).await {
                    let sql = "SELECT datname FROM pg_database \
                               WHERE datname LIKE '%\\_\\_shadow\\_%' OR datname LIKE '%\\_\\_old\\_%'";
                    let inv = psql_invocation(&plan.maint, sql);
                    if let Ok((0, out)) = self
                        .run_sql_capture(&plan.image, &inv.argv, &inv.env, None, &session)
                        .await
                    {
                        for name in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                            let q = quote_ident(ExternalSqlKind::Postgres, name);
                            if self
                                .pg_run_ddl(
                                    &plan,
                                    &format!("DROP DATABASE IF EXISTS {q}"),
                                    &session,
                                )
                                .await
                                .is_ok()
                            {
                                dropped += 1;
                            }
                        }
                    }
                    // Orphan ephemeral apply ROLES (`brexp_apply_%`) left by a crash — drop them
                    // AFTER their shadow dbs are gone (they then own nothing). Each has a random,
                    // never-persisted password and owns nothing, so this is tidiness, not security.
                    let role_sql =
                        "SELECT rolname FROM pg_roles WHERE rolname LIKE 'brexp\\_apply\\_%'";
                    let role_inv = psql_invocation(&plan.maint, role_sql);
                    if let Ok((0, out)) = self
                        .run_sql_capture(&plan.image, &role_inv.argv, &role_inv.env, None, &session)
                        .await
                    {
                        for role in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                            let q = quote_ident(ExternalSqlKind::Postgres, role);
                            // Best-effort: skips a role that still owns objects (its shadow lingered).
                            if self
                                .pg_run_ddl(&plan, &format!("DROP ROLE IF EXISTS {q}"), &session)
                                .await
                                .is_ok()
                            {
                                dropped += 1;
                            }
                        }
                    }
                }
            } else if kind_is_mysql(&cfg.kind)
                && let Ok(plan) = self.mysql_shadow_plan(project, db, cfg).await
            {
                let sql = "SELECT schema_name FROM information_schema.schemata \
                           WHERE schema_name LIKE '%\\_\\_shadow\\_%';";
                if let Ok((0, out)) = self.mysql_run_admin(&plan, sql, &session).await {
                    for name in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                        let q = quote_ident(ExternalSqlKind::Mysql, name);
                        if let Ok((0, _)) = self
                            .mysql_run_admin(
                                &plan,
                                &format!("DROP DATABASE IF EXISTS {q};"),
                                &session,
                            )
                            .await
                        {
                            dropped += 1;
                        }
                    }
                }
                // Orphan ephemeral apply USERS (`brexp_apply_%`) left by a crash — drop them after
                // their shadow dbs are gone (tidiness: each has a random, never-persisted password
                // and only ever held a grant on the now-dropped shadow db).
                let user_sql = "SELECT user FROM mysql.user WHERE user LIKE 'brexp\\_apply\\_%';";
                if let Ok((0, out)) = self.mysql_run_admin(&plan, user_sql, &session).await {
                    for u in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                        let user_lit = mysql_lit(u);
                        if let Ok((0, _)) = self
                            .mysql_run_admin(
                                &plan,
                                &format!("DROP USER IF EXISTS {user_lit}@'%';"),
                                &session,
                            )
                            .await
                        {
                            dropped += 1;
                        }
                    }
                }
            }
        }
        let _ = tokio::fs::remove_dir_all(&session).await;
        dropped
    }
}

/// Quote a MySQL **string literal** (single-quoted, doubling embedded `'`) — for our own generated
/// `information_schema` predicates + grant user literals (db/role names are driver-derived).
fn mysql_lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
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
