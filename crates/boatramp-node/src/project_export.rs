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
//! member and a Shared/external member are NOT chunked. A MANAGED **FULL** sidecar member (a Shared
//! tenant's pg export is framed sidecar; also any FULL dedicated dump staged sidecar) is applied via
//! the SAME non-superuser ephemeral-role + shadow + atomic-swap mechanism (`pg_sidecar_shadow_restore`
//! → `pg_shadow_plan`/`pg_create_shadow`/`pg_restore_shadow_invocation`/`pg_swap_shadow`): for a
//! Shared tenant the per-tenant physical shadow is grant-isolated at creation (REVOKE PUBLIC) and the
//! swapped-in db is re-provisioned to the per-tenant grants, so a cloned Shared tenant db is never a
//! cross-tenant surface and is servable exactly like a provisioned one. A MANAGED **data-only**
//! sidecar member is STILL refused fail-closed (an overlay into a live schema has no atomic shadow —
//! a least-privilege overlay apply is the follow-up); an EXTERNAL bring-your-own-URL binding applies
//! with the OPERATOR'S OWN credential against the operator's own database (their trust boundary). The
//! bundle is NOT whole-bundle atomic (cross-member window); overwriting a populated DB peaks at ~2×.
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
    BundleHead, BundleScope, CloneBlobRef, CloneManifest, CloneSkip, ContinueErrorKind,
    ExportOptions, IdentityChoice, ImportOptions, ImportReport, ManagedRestore, ProjectExport,
    ProjectExportError, SkipManifest, SkippedBlob,
};
use boatramp_core::sql::SqlValue;
use boatramp_storage::sql_libsql::LibsqlSqlBackends;

use crate::config::ExternalDatabaseConfig;
use crate::managed_sql::{ManagedSqlCredentials, operator_target, owner_target};
use crate::pg_client::{
    MysqlConnection, PgConnection, mysql_admin_invocation, mysql_restore_invocation,
    mysql_shadow_invocation, mysqlbinlog_capture_invocation, mysqldump_capture_base_invocation,
    mysqldump_definer_objects_invocation, mysqldump_invocation, mysqldump_tables_only_invocation,
    mysqldump_views_invocation, pg_dump_invocation, pg_restore_invocation,
    pg_restore_shadow_invocation, pg_server_major, psql_invocation, psql_script_invocation,
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

/// Turn a bundle error into a [`Perr`], expanding an ENUMERATE-ALL
/// [`MembersMismatched`](project_bundle::BundleError::MembersMismatched) aggregate (which carries
/// only a count) into a legible per-member report — path · class · size/checksum · declared vs
/// streamed — so the operator sees the full scope the one-pass scan found. Every other bundle error
/// passes through [`other`] unchanged.
fn enumerated_import_error(
    be: project_bundle::BundleError,
    mismatches: &[project_bundle::MemberMismatch],
) -> Perr {
    match &be {
        project_bundle::BundleError::MembersMismatched { count } => {
            let mut lines = Vec::with_capacity(mismatches.len() + 1);
            lines.push(format!(
                "{count} member(s) failed integrity verification (declared ≠ streamed):"
            ));
            for m in mismatches {
                lines.push(format!(
                    "  • {} [{}] {:?}: declared {}, streamed {}",
                    m.path,
                    m.class.label(),
                    m.kind,
                    m.declared,
                    m.streamed
                ));
            }
            Perr::Other(lines.join("\n"))
        }
        _ => other(be),
    }
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

/// Defense-in-depth cap on the number of blob refs a clone MANIFEST may carry before the target's
/// per-ref HEAD fan-out ([`NodeProjectExport::diff_clone_blobs`]) — so a hostile/huge source
/// manifest can neither OOM the diff nor drive an unbounded HEAD storm against the target's bucket.
/// Consistent with (and below) what the 64 MiB manifest-body cap admits (~2M refs).
const MAX_CLONE_MANIFEST_BLOBS: usize = 2_000_000;

/// How many per-blob HEAD presence checks the clone DIFF runs concurrently against the target's
/// own bucket ([`NodeProjectExport::diff_clone_blobs`]). A serial `for b in blobs { head(b) }` loop
/// is an O(blob-count) round-trip crawl — minutes for an ~18k-blob / ~33 GB env-clone before a
/// single byte can move — so the fan-out is bound-parallelized. The bound is a belt: the COUNT cap
/// ([`MAX_CLONE_MANIFEST_BLOBS`]) still fires FIRST, so this caps in-flight HEADs, never the total
/// (same HEAD storm the serial path issued, just concurrently — same result set, order-independent).
const CLONE_DIFF_CONCURRENCY: usize = 64;

/// Max size of a MySQL binlog TRUE-delta member (SQL true-delta). Unlike every other member, this
/// one is read WHOLE INTO MEMORY on both sides (drained into a buffer at export, read into a Vec at
/// restore to pipe into `mysql`), so it carries its own fail-closed RAM bound (LOW-4). A capture
/// whose drained member exceeds this falls back to a full dump (graceful); a restore whose member
/// exceeds it is refused (fail-closed). Generous — a real row-delta since the base is far smaller —
/// but finite, so a crafted/pathological member cannot OOM the node.
const MYSQL_DELTA_MEMBER_MAX: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

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

/// The sealed-credential KV keys that THIS node's own managed-DB self-provisioning
/// (`ensure_target_db_provisioned` → [`crate::tenant_sql::provision_tenant`], run during a clone's
/// member restore) mints for the tenant `(project, "")` across `databases`.
///
/// Re-derived the SAME way `provision_tenant` seals them (via [`crate::tenant_sql::tenant_key`] +
/// [`crate::tenant_sql::tenant_names`] + the credential-key helpers) — the established "re-derive the
/// tenant's names rather than guess" pattern in this crate — so the set can never drift from what a
/// fresh provision actually writes. It is the `--fresh` identity drop's keep-set: those creds are
/// locally minted + sealed under THIS node's KEK and the live roles/containers already authenticate
/// with them, so the drop must NOT delete them (dropping one desyncs the sealed credential from the
/// live role → the cloned tenant's own role can no longer connect). Every other `managed-sql-cred`
/// key under the project is source-carried (a `--include-identity` KV member) and IS dropped.
///
/// Mirrors `provision_tenant`'s scope rules: a site-scoped binding is skipped (the clone
/// self-provision refuses it, so it mints nothing); a Shared DEFAULT tenant mints nothing (the
/// superuser is the app user); a Shared non-default tenant mints the login + owner creds; a Single
/// tenant mints its workload cred (under its own `(cred_project, workload)`).
fn self_provisioned_managed_cred_keys(
    databases: &std::collections::BTreeMap<String, ExternalDatabaseConfig>,
    project: &str,
) -> std::collections::BTreeSet<String> {
    use crate::config::{TenantIsolation, TenantScope};
    use crate::tenant_sql::{
        credential_workload_key, owner_credential_workload_key, single_credential_project,
        tenant_key, tenant_names,
    };
    // The KV key layout `ManagedSqlCredentials` seals under (kept in lockstep with
    // `ManagedSqlCredentials::key`, which is private, and with the `managed-sql-cred/{project}/`
    // prefix in `sealed_secret_prefixes`).
    let cred_key = |project: &str, workload: &str| format!("managed-sql-cred/{project}/{workload}");

    let mut keys = std::collections::BTreeSet::new();
    for cfg in databases.values() {
        let Some(compute) = cfg.compute.as_deref().filter(|c| !c.is_empty()) else {
            continue; // bring-your-own url_env binding — not ours to provision.
        };
        if ExternalSqlKind::parse(&cfg.kind).is_none() {
            continue; // config validation rejects this before serve.
        }
        // The clone self-provision only provisions a project-scoped binding (a site-scoped one is
        // skipped by `ensure_target_db_provisioned`), so only that mints a credential.
        if matches!(cfg.tenant_scope, TenantScope::Site) {
            continue;
        }
        let database = cfg.database.as_deref().unwrap_or_default();
        let (tenant_ident_raw, is_default) = tenant_key(cfg.tenant_scope, project, "");
        let names = tenant_names(cfg.tenant, compute, database, &tenant_ident_raw, is_default);
        match cfg.tenant {
            TenantIsolation::Single => {
                let cred_project = single_credential_project(project, is_default);
                keys.insert(cred_key(&cred_project, &names.workload));
            }
            TenantIsolation::Shared => {
                if is_default {
                    continue; // the default shared tenant is the plain install — mints nothing.
                }
                let ident = boatramp_storage::tenant_provision::sanitize_ident(&tenant_ident_raw);
                keys.insert(cred_key(project, &credential_workload_key(compute, &ident)));
                keys.insert(cred_key(
                    project,
                    &owner_credential_workload_key(compute, &ident),
                ));
            }
        }
    }
    keys
}

/// How a SIDECAR (non-chunked) MANAGED-engine dump member (pg OR mysql) must be applied on import —
/// the narrowed post-HIGH-1 policy (the untrusted dump must never reach the bootstrap superuser). A
/// pure (managed × [`ManagedRestore`]) decision, engine-agnostic, factored out so the narrowing is
/// unit-testable without a live backend. Both the pg sidecar arm and the mysql sidecar arm route
/// through this ONE classifier.
#[derive(Debug, PartialEq, Eq)]
enum SidecarManagedApply {
    /// EXTERNAL bring-your-own-URL binding: the operator's OWN database + credential (their trust
    /// boundary, not our managed cluster) — the dump is applied directly.
    External,
    /// MANAGED + [`ManagedRestore::ShadowSwap`]: apply via the atomic NON-superuser ephemeral-role
    /// shadow+swap. The untrusted dump never reaches the bootstrap superuser, and the
    /// self-provisioned target is replaced atomically (fresh or overwrite) — never a partial live
    /// overlay. This serves a Shared tenant's sidecar-framed FULL export and any FULL dedicated dump
    /// staged sidecar.
    ManagedShadowSwap,
    /// MANAGED + [`ManagedRestore::Overlay`]: an OVERLAY into the target's existing live schema.
    /// There is NO atomic shadow for an overlay, and a direct apply would run as the bootstrap
    /// superuser (RCE) — REFUSED fail-closed (a least-privilege overlay apply is a pending follow-up).
    RefuseManagedDataOnly,
}

/// Decide how a SIDECAR managed-engine (pg/mysql) dump member is applied, from the binding's
/// managed-ness and the bundle's
/// [`ManagedRestore`] mode. EXACTLY: a managed [`ShadowSwap`](ManagedRestore::ShadowSwap) dump is
/// applied via the atomic non-superuser shadow+swap; a managed [`Overlay`](ManagedRestore::Overlay)
/// dump is REFUSED (overlay into a live schema, no atomic shadow); an external binding is applied
/// directly. NB: this reads the managed-restore mode, NOT a conflated `data_only` scope flag — a
/// `DataPlane`-scoped bundle whose managed members are `ShadowSwap` (what `project sync` produces)
/// now lands here as `ManagedShadowSwap`, where before the coupling forced it to refuse.
fn sidecar_managed_apply(is_managed: bool, restore: ManagedRestore) -> SidecarManagedApply {
    match (is_managed, restore) {
        (false, _) => SidecarManagedApply::External,
        (true, ManagedRestore::ShadowSwap) => SidecarManagedApply::ManagedShadowSwap,
        (true, ManagedRestore::Overlay) => SidecarManagedApply::RefuseManagedDataOnly,
    }
}

/// Whether a MANAGED engine member (pg/mysql) is framed CHUNKED (a streamed dump → the atomic
/// shadow-restore, Stage C/D) vs SIDECAR, from the binding's managed-ness, the bundle's
/// [`ManagedRestore`] mode, and whether the tenant is Shared. Chunked IFF managed AND ShadowSwap AND
/// not-Shared — a dedicated/Single managed ShadowSwap dump. The complementary cases stay SIDECAR: a
/// Shared managed ShadowSwap reaches the shadow via `pg_sidecar_shadow_restore`
/// ([`SidecarManagedApply::ManagedShadowSwap`]); an Overlay dump or an external binding applies on the
/// sidecar arm too. The pure framing decision behind `plan_export`, keyed on the SPLIT managed-restore
/// mode (NOT a conflated scope flag) so a `DataPlane`-scope `project sync` still frames a dedicated
/// managed DB chunked.
fn managed_member_chunked(is_managed: bool, restore: ManagedRestore, is_shared: bool) -> bool {
    is_managed && matches!(restore, ManagedRestore::ShadowSwap) && !is_shared
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

/// The bundle member path for a Postgres logical-WAL **true-delta** (SQL true-delta program).
fn pgwal_member_path(db: &str) -> String {
    format!("sql/{db}.pgwal")
}

/// Recover the database name from a `sql/<db>.pgwal` true-delta member path.
fn db_from_pgwal_member(path: &str) -> Option<&str> {
    path.strip_prefix("sql/")
        .and_then(|s| s.strip_suffix(".pgwal"))
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

/// The bundle member path for a MySQL binlog **true-delta** (SQL true-delta program).
fn mysqlbinlog_member_path(db: &str) -> String {
    format!("sql/{db}.mysqlbinlog")
}

/// Recover the database name from a `sql/<db>.mysqlbinlog` true-delta member path.
fn db_from_mysqlbinlog_member(path: &str) -> Option<&str> {
    path.strip_prefix("sql/")
        .and_then(|s| s.strip_suffix(".mysqlbinlog"))
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

/// The bundle member path for a site's libsql **changeset** true-delta (SQL true-delta program,
/// Stage 4). Sibling of [`libsql_member_path`] with a `.changeset` leaf so a reader tells a true
/// row-delta member from a full `.sqlite` dump.
fn libsql_changeset_member_path(project: &str, site: &str) -> String {
    format!("libsql/{project}/{site}/default.changeset")
}

/// Recover the SITE from a `libsql/<project>/<site>/default.changeset` true-delta member path (the
/// source project segment is discarded — the import re-qualifies with the TARGET project).
fn site_from_libsql_changeset_member(path: &str) -> Option<&str> {
    let body = path
        .strip_prefix("libsql/")?
        .strip_suffix("/default.changeset")?;
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
    // Defense-in-depth: the re-keyed REMAINDER must be a clean relative path — no empty segment,
    // no `.`/`..`, no absolute/root component — so a crafted member (`…/../../hblob/victim/…` or an
    // absolute key) can never traverse OUT of `hblob/{target}/` into another tenant's scope or the
    // bucket root. The storage layer also screens keys, but this tenancy-critical seam self-defends
    // rather than relying on it (a leak here shipped a CRITICAL once).
    use std::path::{Component, Path};
    if rest.is_empty() {
        return Err(Perr::Other(format!(
            "blob member {src_key:?} has an empty key under the source scope; refusing"
        )));
    }
    if !Path::new(rest)
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(Perr::Other(format!(
            "blob member {src_key:?} has an unsafe path component (absolute or `.`/`..`); \
             refusing to re-key a traversing blob (cross-tenant isolation)"
        )));
    }
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

/// The clear, actionable error for a delta export against a `delta_capture`-enabled db
/// whose server has not actually adopted it yet (PLAN-sql-true-delta Stage 1b).
fn delta_capture_not_restarted_message(db: &str) -> String {
    format!(
        "database {db:?}: delta export refused — `delta_capture` is enabled but the server has \
         not been restarted to adopt it yet (true-delta needs wal_level=logical / binary \
         logging, which only take effect at server start); ensure `delta_capture: true` is set \
         and run `boatramp db restart --db {db}` (or apply with `restart_policy: auto`) before \
         a delta export of this database"
    )
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

/// Build the member-mismatch [`VerifyPolicy`](project_bundle::VerifyPolicy) from the import options.
/// Clone-robustness (PLAN-clone-robustness #2): member-mismatch tolerance is the OR of the legacy
/// `skip_member_mismatch` flag and `continue_on_error` forgiving [`ContinueErrorKind::MemberMismatch`]
/// — so `--continue-on-error=member-mismatch` is a true back-compat ALIAS for `--skip-member-mismatch`,
/// routed through the ONE policy. The skip SCOPE stays `der/`-only unless `skip_any_blob_mismatch`
/// broadens it (the louder opt-in, unchanged). Extracted as a free fn so the routing is unit-testable
/// without driving a whole import.
fn verify_policy_from_opts(opts: &ImportOptions) -> project_bundle::VerifyPolicy {
    let skip_mismatch = opts.skip_member_mismatch
        || opts
            .continue_on_error
            .forgives(ContinueErrorKind::MemberMismatch);
    project_bundle::VerifyPolicy {
        enumerate_all: opts.enumerate_mismatches,
        skip_mismatch,
        skip_scope: if opts.skip_any_blob_mismatch {
            project_bundle::SkipScope::AnyBlob
        } else {
            project_bundle::SkipScope::DerivativesOnly
        },
    }
}

/// Whether the `--only-blobs` repair filter SKIPS this member (does not write/apply it): a blob
/// whose TARGET key is NOT in the manifest set, or ANY non-blob member (a repair is blobs-only). No
/// filter (`None`) keeps every member. `target_key` is `None` for a non-blob member. Pure so the
/// filter is unit-testable.
fn only_blobs_skips(
    only_blobs: Option<&std::collections::BTreeSet<String>>,
    is_blob: bool,
    target_key: Option<&str>,
) -> bool {
    match only_blobs {
        None => false,
        Some(set) => match (is_blob, target_key) {
            (true, Some(key)) => !set.contains(key),
            // A non-blob member (or a blob whose key could not be derived) is never part of a
            // blobs-only repair.
            _ => true,
        },
    }
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
    /// The configured base directory under which operator-named resumable export/import
    /// directories live (`[serve] resumable_export_dir`). `None` ⇒ the resumable surface is
    /// DISABLED and every resumable call is refused fail-closed. An operator passes only a
    /// relative name under this base; the host confines it (no escape) — the caller never
    /// supplies an absolute node path.
    resumable_base: Option<PathBuf>,
    /// TEST-ONLY restore-window widener (milliseconds). `0` in every production build — only a
    /// debug/test build can set it via [`with_shadow_restore_test_delay_ms`](Self::with_shadow_restore_test_delay_ms)
    /// (that builder does not even compile under `--release`). When non-zero, `pg_create_shadow`
    /// holds the SHARED shadow in existence (locked down: PUBLIC CONNECT already revoked + swept)
    /// for this long before the restore proceeds, so the cross-tenant live gate can observe the
    /// shadow while it exists and prove a sibling can never CONNECT to it. The hold is a plain
    /// `tokio::time::sleep` that owns no DB connection; it changes no DDL and no statement order.
    shadow_restore_test_delay_ms: u64,
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
            resumable_base: None,
            shadow_restore_test_delay_ms: 0,
        }
    }

    /// TEST-ONLY: hold the SHARED pg shadow in existence for `ms` milliseconds inside
    /// `pg_create_shadow` — AFTER the shadow is created AND locked down (PUBLIC CONNECT revoked +
    /// a terminate-sweep) — before the restore proceeds. Lets the cross-tenant live gate
    /// (`project_export_clone_self_provisions_a_fresh_shared_tenant_live`) observe the shadow while
    /// it exists and prove a sibling tenant can never CONNECT to it. Inert by default — the field
    /// stays `0` unless a test sets it, so a release binary (which never calls this setter) runs
    /// with no added delay. It widens only the window — it changes no DDL, no statement order, and
    /// holds no DB connection. NOT `cfg(debug_assertions)`-gated: the integration test links the
    /// library as built in CI (a non-debug profile), where that gate would hide the setter → E0599.
    #[must_use]
    pub fn with_shadow_restore_test_delay_ms(mut self, ms: u64) -> Self {
        self.shadow_restore_test_delay_ms = ms;
        self
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

    /// Set the base directory under which operator-named resumable export/import dirs live
    /// (`[serve] resumable_export_dir`). `None`/not-called ⇒ the resumable surface stays
    /// DISABLED (every resumable call refuses, fail-closed). The operator names only a
    /// relative subdir under this base; [`resolve_resumable_dir`](Self::resolve_resumable_dir)
    /// confines it.
    #[must_use]
    pub fn with_resumable_base(mut self, base: Option<PathBuf>) -> Self {
        self.resumable_base = base;
        self
    }

    /// Confine an operator-supplied resumable directory NAME to a path under the configured
    /// [`resumable_base`](Self::resumable_base). The load-bearing control for the resumable
    /// surface: the name reaches the node from an API caller, so an unconfined path would be
    /// arbitrary node read/write. Fail-closed:
    /// - no base configured ⇒ refuse (the surface is disabled);
    /// - empty, absolute, or any non-`Normal` component (`..`, `.`, root/prefix) ⇒ refuse
    ///   (kills lexical traversal + absolute escape);
    /// - after join, canonicalize + assert the result stays under the canonical base ⇒ this
    ///   catches a SYMLINK escape (a symlink in the path resolves out and fails `starts_with`).
    ///
    /// `create` ⇒ create the base + the target dir (export); otherwise the target must exist
    /// (import). Returns the confined, canonicalized absolute path.
    pub(crate) async fn resolve_resumable_dir(
        &self,
        dir_name: &str,
        create: bool,
    ) -> Result<PathBuf, Perr> {
        use std::path::Component;
        let base = self.resumable_base.as_ref().ok_or_else(|| {
            Perr::Other(
                "resumable export/import is not enabled on this node; set \
                 `[serve] resumable_export_dir` to a base directory"
                    .into(),
            )
        })?;
        if dir_name.is_empty() {
            return Err(Perr::Other("resumable directory name is required".into()));
        }
        let rel = Path::new(dir_name);
        if rel.is_absolute() {
            return Err(Perr::Other(
                "resumable directory must be a relative name under the configured base, \
                 not an absolute path"
                    .into(),
            ));
        }
        for comp in rel.components() {
            if !matches!(comp, Component::Normal(_)) {
                return Err(Perr::Other(
                    "resumable directory name must not contain `..`, `.`, or a root/prefix \
                     component"
                        .into(),
                ));
            }
        }
        // The base must exist to canonicalize it (create it on the export path).
        if create {
            tokio::fs::create_dir_all(base).await.map_err(other)?;
        }
        let canon_base = tokio::fs::canonicalize(base).await.map_err(|e| {
            Perr::Other(format!(
                "resumable base {} is not accessible: {e}",
                base.display()
            ))
        })?;
        let joined = canon_base.join(rel);
        if create {
            tokio::fs::create_dir_all(&joined).await.map_err(other)?;
        } else if !tokio::fs::try_exists(&joined).await.map_err(other)? {
            return Err(Perr::Other(format!(
                "resumable directory {dir_name:?} does not exist under the configured base"
            )));
        }
        // Canonicalize the target and REFUSE if it escaped the base (symlink guard).
        let canon = tokio::fs::canonicalize(&joined).await.map_err(other)?;
        if !canon.starts_with(&canon_base) {
            return Err(Perr::Other(
                "resumable directory escapes the configured base (symlink?)".into(),
            ));
        }
        Ok(canon)
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

    /// Refuse LOUD if `db`'s `delta_capture` opt-in has not actually taken effect on the
    /// LIVE server yet (`wal_level` still not `logical`) — the operator enabled it but has
    /// not restarted the database (PLAN-sql-true-delta Stage 1b's restart primitive). A
    /// connectivity failure checking it is deliberately NOT treated as this condition (it
    /// is left to surface on its own, later in the plan) — this only short-circuits on an
    /// ANSWERED, non-`logical` `wal_level`, so it never masks an unrelated transient error
    /// behind a misleading "not restarted" message.
    async fn assert_pg_delta_capture_live(&self, project: &str, db: &str) -> Result<(), Perr> {
        let op = self.require_op()?;
        if let Ok(rows) = op.query(project, db, "SHOW wal_level").await
            && let Some(level) = scalar_text(&rows)
            && !level.trim().eq_ignore_ascii_case("logical")
        {
            return Err(Perr::Other(delta_capture_not_restarted_message(db)));
        }
        Ok(())
    }

    /// The mysql analogue of [`assert_pg_delta_capture_live`](Self::assert_pg_delta_capture_live):
    /// refuse LOUD if `db`'s `delta_capture` opt-in has not taken effect yet (binary logging
    /// still off, `@@GLOBAL.log_bin` != `1`) because the server has not been restarted.
    async fn assert_mysql_delta_capture_live(&self, project: &str, db: &str) -> Result<(), Perr> {
        let op = self.require_op()?;
        if let Ok(rows) = op.query(project, db, "SELECT @@GLOBAL.log_bin").await
            && let Some(v) = scalar_text(&rows)
            && v.trim() != "1"
        {
            return Err(Perr::Other(delta_capture_not_restarted_message(db)));
        }
        Ok(())
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
                // External DSN: the host is reachable directly (daemon NAT egress) — no project
                // network to join.
                ephemeral_network: None,
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
        // On the remote-Docker backend each project's workloads live on an ISOLATED per-project
        // network, so a one-shot export/import client must JOIN that network to reach this managed
        // DB (whether by the bridge IP in `host` or the DB's workload-name alias). Gate on the
        // backend actually being `docker` — the native container backend keeps one shared bridge
        // the ephemeral client already shares, so it needs no join. `endpoint_project` is the
        // project the DB workload is registered under (the reserved default for a Shared default
        // tenant), which is exactly the network the DB container joined at launch.
        //
        // TENANCY INVARIANT (keeps the backend's dual-attach safe): every field of this endpoint —
        // `host`/port (from the healthy replica's deploy-registry endpoint or the backend's own
        // bridge IP), `user`/`database` (from the operator target derived from `project`+`db`), and
        // the password (unsealed by the caller's own `cred_project`/`cred_workload`) — is derived
        // STRUCTURALLY from the authenticated caller's own project and operator config, never from
        // guest/tenant-writable input or dump content. The one-shot therefore dials only this
        // caller-owned DB with the caller's own credential; it cannot be redirected at a foreign
        // tenant. Any future "custom DB host override" / content-derived DSN MUST re-examine the
        // docker backend's dual-attach, since it would turn the one-shot into a cross-tenant pivot.
        let ephemeral_network = (backend.id() == "docker")
            .then(|| boatramp_docker::project_network_name(&target.endpoint_project));
        Ok(SqlEndpoint {
            host,
            port: replica.endpoint.port,
            user: target.user,
            password,
            database: target.database,
            ephemeral_network,
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

    /// Clone/import self-provision (PLAN-clone-self-provision-managed-db): before an import's
    /// pg/mysql member restore connects to the TARGET's managed database, make sure it actually
    /// EXISTS. Reuses the EXISTING lazy provisioner, [`tenant_sql::provision_tenant`] — the SAME
    /// code the platform already runs on a normal managed-sql access (`provision_single`'s
    /// workload registration) and on the `boatramp apply` / `db ensure database` declare path
    /// (`NodeManagedDbDeclare::provision`). Without this, a clone onto a FRESH target (project
    /// shell created, managed db never touched) fails the readiness probe with a confusing
    /// "database … does not exist" instead of actually provisioning it (construens's clone
    /// failure shape).
    ///
    /// - **Idempotent**: "already exists" is success (re-running on an already-provisioned
    ///   target is a no-op — [`tenant_sql::provision_tenant`]'s own contract).
    /// - **Target-scoped ONLY**: provisions exactly `(project, "")`'s OWN binding — the tenant
    ///   name/database/role are derived from `project` (the clone's TARGET), never from anything
    ///   source-carried, and never another project's. This is the tenancy-sensitive seam a
    ///   Security review gates.
    /// - A no-op for a bring-your-own (`url_env`) binding (nothing of ours to provision) and for
    ///   a **site-scoped** managed database: operator SQL (the seam `resolve_pg`/`resolve_mysql`
    ///   use) is project-level only and refuses a site-scoped binding regardless
    ///   ([`crate::managed_sql::operator_target`]), so there is nothing reachable here to
    ///   provision — the existing refusal stands unchanged.
    async fn ensure_target_db_provisioned(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<(), Perr> {
        if !is_managed_binding(cfg) {
            return Ok(()); // bring-your-own URL — the operator's own database, not ours to create.
        }
        if matches!(cfg.tenant_scope, crate::config::TenantScope::Site) {
            return Ok(()); // operator SQL can't target a site's db anyway; resolve_* refuses it.
        }
        let envelope = self.envelope.as_ref().ok_or_else(|| {
            Perr::Unavailable(format!(
                "managed database {db:?} needs a [secrets] envelope to unseal its credential — \
                 none on this node"
            ))
        })?;
        crate::tenant_sql::provision_tenant(&self.deploy, &self.kv, envelope, cfg, project, "")
            .await
            .map_err(|e| {
                Perr::Other(format!(
                    "clone self-provision of database {db:?} failed: {e}"
                ))
            })
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
    /// trusted-DDL / maintenance statements + probe queries of the inc2 shadow swap (pg `CREATE
    /// DATABASE`/`ALTER … RENAME`/`SELECT rolsuper …`/`SELECT 1 FROM pg_database …`, mysql
    /// `information_schema` table enumeration). The stdout temp lives under `stage_dir` and is
    /// removed after.
    ///
    /// The run is wrapped with [`merge_stderr_argv`] so the client's STDERR — where psql/mysql
    /// write a failed statement's error ("ERROR: database … already exists", "permission denied",
    /// a refused untrusted object) — merges into the captured string; without it `run_ephemeral`
    /// drops stderr on a non-zero exit and a failed DDL surfaces causelessly. A SUCCESSFUL psql/
    /// mysql SELECT or DDL emits nothing on stderr, so the parsed probes are unaffected on success
    /// and only gain the diagnostic on failure. Safe here because stdout is a small parsed result
    /// or discarded — never a dump member (which must NOT merge stderr; see `merge_stderr_argv`).
    async fn run_sql_capture(
        &self,
        image: &str,
        argv: &[String],
        env: &[(String, String)],
        stdin_path: Option<&Path>,
        stage_dir: &Path,
    ) -> Result<(i32, String), Perr> {
        let out = stage_dir.join(format!("cap-{}.out", shadow_suffix()));
        let merged = merge_stderr_argv(argv);
        let code = self
            .run_sql_client(image, &merged, env, stdin_path, &out)
            .await?;
        let s = tokio::fs::read_to_string(&out).await.unwrap_or_default();
        let _ = tokio::fs::remove_file(&out).await;
        Ok((code, s.trim().to_string()))
    }

    /// Like [`run_sql_capture`](Self::run_sql_capture) but WITHOUT the [`merge_stderr_argv`] wrap, so
    /// the captured stdout is PURE command output and the client's stderr can never co-mingle into
    /// it. The one caller whose stdout is a DATA payload — the pg WAL drain, whose stdout is the
    /// hex-encoded `pgoutput` stream (PLAN-sql-true-delta LOW A1) — MUST use this, not the merging
    /// variant (`merge_stderr_argv` is documented must-NOT-wrap-data). On a non-zero exit
    /// `run_ephemeral` drops the container's stderr, so the diagnostic is just the exit code (the
    /// caller fails closed / falls back) — an accepted trade for never corrupting the data stream.
    async fn run_sql_capture_nomerge(
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

/// A SHORT process-unique suffix for a MySQL ephemeral identifier. MySQL caps a USER name at 32
/// chars, and the general `shadow_suffix()` (`<nanos>_<pid>`, ~27 chars) overflows `brexp_apply_` /
/// `brexp_rd_` — so the mysql shadow + binlog-capture ephemeral users use this 16-hex-char suffix
/// instead (`brexp_apply_<16hex>` = 28 chars). Random, so collision-free across concurrent imports;
/// the `brexp_apply_%` / `brexp_rd_%` / `%__shadow_%` sweep LIKE-patterns match it unchanged.
fn mysql_eph_suffix() -> String {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("os rng for mysql ephemeral suffix");
    b.iter().map(|x| format!("{x:02x}")).collect()
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

/// Postgres `NAMEDATALEN - 1`: the maximum BYTE length of a stored identifier before the server
/// silently TRUNCATES it to this prefix (emitting a `NOTICE: identifier … will be truncated`).
/// MySQL's identifier cap is 64 bytes, so bounding a derived name to this value is safe for BOTH
/// engines.
const MAX_DERIVED_DB_NAME_LEN: usize = 63;

/// Compose a transient database name `<live_db><marker><suffix>` (the `__shadow_` / `__old_` aside
/// names) that NEVER exceeds Postgres's 63-byte identifier limit.
///
/// A Shared-tenant live db name is tenant-qualified and already close to the 63-byte cap, so the
/// naive `format!("{live_db}{marker}{suffix}")` can push the identifier past `NAMEDATALEN`.
/// Postgres then TRUNCATES the name back to its first 63 bytes — which, for a long live db,
/// collapses right back to the LIVE name — so the shadow `CREATE DATABASE` fails with
/// `database … already exists` and the clone/import fails. (Latent for ANY live db long enough
/// that `<live><marker><suffix>` crosses 63 bytes, not only Shared tenants.)
///
/// Contract:
/// - **Short names unchanged.** When `<live_db><marker><suffix>` already fits in 63 bytes the
///   result is byte-identical to `format!("{live_db}{marker}{suffix}")`, so the dedicated/chunked
///   path and every existing shadow-name test keep their exact names.
/// - **Long names bounded.** Otherwise the `live_db` PREFIX is truncated (on a UTF-8 char
///   boundary, never splitting a multi-byte sequence) to whatever room is left, so the whole name
///   is ≤ 63 bytes while the FULL `{marker}{suffix}` distinguisher is preserved intact and within
///   the first 63 bytes. This guarantees the result is (a) ≤ 63 bytes; (b) distinct from `live_db`
///   truncated to 63 bytes (it ends in the `{marker}{suffix}` tail that a plain truncation of
///   `live_db` drops — the exact collapse that caused the bug); (c) collision-free across imports,
///   because the per-import-unique `suffix` is retained verbatim; and (d) still carrying the intact
///   `marker` substring, so the `%__shadow_%` / `%__old_%` startup-sweep LIKE-patterns keep
///   matching it. The marker (and suffix) are NEVER truncated — only the `live_db` prefix is.
fn bounded_derived_db_name(live_db: &str, marker: &str, suffix: &str) -> String {
    let tail_len = marker.len() + suffix.len();
    if live_db.len() + tail_len <= MAX_DERIVED_DB_NAME_LEN {
        return format!("{live_db}{marker}{suffix}");
    }
    // Keep the whole `{marker}{suffix}` distinguisher; give the live_db prefix whatever bytes are
    // left (possibly zero). Floor the cut at a UTF-8 char boundary so a multi-byte char is intact.
    let keep = MAX_DERIVED_DB_NAME_LEN.saturating_sub(tail_len);
    let mut end = keep.min(live_db.len());
    while end > 0 && !live_db.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{marker}{suffix}", &live_db[..end])
}

/// Quote a Postgres **string literal** (single-quoted, doubling any embedded `'`) — for the
/// `datname = '<db>'` predicate of our own generated `pg_terminate_backend` / `pg_database`
/// utility SQL (the db name is driver-derived, never a credential or bundle data).
fn pg_lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Compose the superuser terminate-sweep that evicts EVERY backend attached to database `db`
/// except our own. On the SHARED shadow path this clears any session a sibling tenant slipped
/// onto the shadow during the (now batched, gap-minimized) `CREATE DATABASE` → `REVOKE CONNECT …
/// FROM PUBLIC` window — `REVOKE` blocks only NEW connects, so the sweep is what evicts a session
/// that connected before the revoke took effect. Run immediately before the untrusted restore so
/// the restore begins on a shadow with ZERO foreign sessions.
///
/// `db` is a driver-derived name (never attacker-controlled); it is quoted as a SQL string literal
/// via [`pg_lit`] for the `datname =` predicate — the SAME quoting the swap/teardown sweeps use.
fn pg_terminate_backends_sql(db: &str) -> String {
    format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = {} AND pid <> pg_backend_pid()",
        pg_lit(db)
    )
}

/// POSIX-single-quote each token of a driver-composed argv and join with spaces, so the
/// command can run under `sh -c '… 2>&1'` (merging stderr into the captured sink). Only
/// ever applied to driver-derived flags + identifiers — never a credential (the password
/// rides in the env, e.g. PGPASSWORD), so the single-quoting is defense-in-depth, not a
/// trust boundary. Each embedded `'` is closed, escaped as `'\''`, and reopened.
fn sh_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Wrap a driver-composed SQL-client invocation so the container's STDERR merges into the
/// captured stdout sink (`sh -c 'exec … 2>&1'`). `run_ephemeral` keeps only the container's
/// stdout and DROPS stderr on a non-zero exit, so a failed trusted-DDL / maintenance / sidecar
/// restore run otherwise surfaces causelessly ("exited N" with no reason) — the psql / pg_restore
/// / mysql client writes its error text to stderr. Merging lets that text reach the error message.
///
/// MUST NOT be used where stdout is a DATA payload (a `pg_dump`/`mysqldump` whose stdout IS the
/// bundle member, or a chunked producer streaming into the bundle body) — merging stderr would
/// corrupt the member. It is only for runs whose stdout is a small parsed result (a probe) or
/// discarded (a maintenance DDL / a sidecar restore to a throwaway sink): a successful psql/mysql
/// SELECT emits NOTHING on stderr, so a parsed probe is unaffected on success and only GAINS the
/// diagnostic on failure. `exec` keeps the reported exit status the client's own; each token is
/// POSIX single-quoted by [`sh_join`]. The connection password is NOT composed in (it rides in the
/// env — PGPASSWORD/MYSQL_PWD); the only secret that can appear is a we-generate-it SQL literal (the
/// ephemeral role's random password in a `CREATE ROLE … PASSWORD` the maintenance DDL already placed
/// in psql's argv), whose exposure is unchanged by this wrap — it stays argv-resident on the same
/// ephemeral DB-client container, an exposure the trusted-DDL path already accepts.
fn merge_stderr_argv(argv: &[String]) -> Vec<String> {
    vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("exec {} 2>&1", sh_join(argv)),
    ]
}

/// The resolved reachable endpoint of a SQL database (managed or external) — the raw
/// parts the ephemeral client connects with.
struct SqlEndpoint {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
    /// The per-project docker network a one-shot client must JOIN to reach this endpoint — `Some`
    /// only for a MANAGED DB on the remote-Docker backend (which isolates each project on its own
    /// network). Flows into the [`PgConnection`]/[`MysqlConnection`] network-join hint; `None` for
    /// an external DSN (reachable directly) or the native backend (one shared bridge).
    ephemeral_network: Option<String>,
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
            ephemeral_network: self.ephemeral_network,
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
            ephemeral_network: self.ephemeral_network,
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
        /// The detected `SHOW server_version_num` — selects the `pg_dump` comment-handling
        /// strategy (PG17+ `--exclude-extension` vs the blunt `--no-comments`).
        server_version_num: String,
        /// Dump with `--no-publications` — set for a `delta_capture` db, so the ephemeral
        /// `brexp_pub_*` capture publication (which must exist from base time for pgoutput's
        /// historical decode) never lands in the dump and cannot fail the non-superuser shadow
        /// restore (`CREATE PUBLICATION … FOR ALL TABLES` is superuser-only). PLAN-sql-true-delta.
        no_publications: bool,
    },
    /// A MySQL `mysqldump` into a staging temp.
    Mysql {
        conn: MysqlConnection,
        image: String,
        data_only: bool,
        /// Dump TABLES-ONLY ([`mysqldump_tables_only_invocation`] — a positional `<db>`, no
        /// `--databases`, so NO `CREATE DATABASE`/`USE <original>`) rather than the FULL
        /// [`mysqldump_invocation`]. Set for a MANAGED **Shared** ShadowSwap member so the sidecar
        /// shadow+swap can apply it into a differently-named per-tenant shadow db — exactly the dump
        /// shape the dedicated CHUNKED path already streams. External/Overlay members keep the FULL
        /// (`--databases`) dump.
        tables_only: bool,
    },
    /// A libsql `VACUUM INTO` snapshot of the project-qualified site DB.
    Libsql { qsite: String },
    /// A single blob object, streamed from the source store into a staging temp.
    Blob { key: String },
    /// A control-plane KV **delta** member (`kv.brkvdelta`) — the upserts + tombstones already
    /// computed + encoded at plan time (a DELTA export only).
    KvDelta { bytes: Vec<u8> },
    /// A blob **tombstone** member (`blobs.brtombstones`) — the deleted blob keys already computed
    /// + encoded at plan time (a DELTA export only).
    BlobTombstone { bytes: Vec<u8> },
    /// A Postgres logical-WAL **delta** member (`sql/<db>.pgwal`) — the framed `pgoutput` change
    /// stream drained from the parent base's capture slot, already produced at plan time (an
    /// incremental DELTA export of a managed pg db with `delta_capture`). Replayed onto the
    /// restored base inside the atomic shadow (see `restore_pg_true_delta_in_chain`).
    PgWalDelta { bytes: Vec<u8> },
    /// A MySQL binlog **delta** member (`sql/<db>.mysqlbinlog`) — the framed raw binlog captured
    /// (via `mysqlbinlog --read-from-remote-server --raw`) since the parent base's snapshot GTID,
    /// already produced at plan time (an incremental DELTA export of a managed mysql db with
    /// `delta_capture`). Replayed onto the restored base inside the atomic shadow (see
    /// `restore_mysql_true_delta_in_chain`).
    MysqlBinlogDelta { bytes: Vec<u8> },
    /// A libsql/SQLite **changeset** delta member (`libsql/<project>/<site>/default.changeset`) — the
    /// framed SQLite changeset (session diff of the base snapshot vs the current DB), already
    /// produced at plan time (a DELTA export of a capture-eligible libsql site). Replayed onto the
    /// restored base snapshot inside the atomic shadow (see `restore_libsql_true_delta_in_chain`).
    /// SQL true-delta program, Stage 4.
    LibsqlChangeset { bytes: Vec<u8> },
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
    /// The bundle head (surfaced before any member) — the source project + the two orthogonal
    /// bundle-head descriptors ([`BundleHead`]: its [`BundleScope`] drives the control-plane
    /// post-stream steps; its [`ManagedRestore`] drives each managed member's restore routing).
    Head {
        head: BundleHead,
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
    /// the restore task drains the body to `dump_path`, rewrites its `DEFINER=` clauses, and applies
    /// the dump as the non-superuser role; finish carries the DEFINER objects + swaps via the atomic
    /// `RENAME TABLE` (verified) or drops the shadow (abort).
    Mysql {
        plan: Box<MysqlShadowPlan>,
        restore: tokio::task::JoinHandle<Result<i32, Perr>>,
        out_path: PathBuf,
        /// The staged dump file the restore task drains + rewrites (cleaned up at finish/abort).
        dump_path: PathBuf,
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
    /// SHARED multi-tenant re-provisioning context (`Some` only for a Shared NON-default tenant;
    /// `None` for Single/dedicated + Shared-DEFAULT, which keep the original swap behavior). When
    /// set, the shadow is grant-isolated at creation (`pg_create_shadow` REVOKEs PUBLIC CONNECT) and
    /// the swapped-in db is re-provisioned to the per-tenant isolation + serving grants
    /// (`pg_swap_shadow` re-runs the idempotent tenant provisioning). See [`SharedReprovision`].
    shared_reprovision: Option<SharedReprovision>,
}

/// Post-swap re-provisioning context for a SHARED multi-tenant managed binding (a NON-default
/// tenant). A Shared tenant's physical database is a sibling of OTHER tenants' databases on ONE
/// shared cluster (grant-isolated, not process-isolated), so making a cloned tenant db
/// indistinguishable from a freshly-provisioned one — and never a cross-tenant surface — takes two
/// extra, idempotent steps beyond the dedicated swap:
///
/// 1. **At shadow creation** (`pg_create_shadow`): `REVOKE CONNECT ON DATABASE <shadow> FROM PUBLIC`
///    the moment the shadow exists — the ephemeral role OWNS the shadow so it still connects, but no
///    SIBLING tenant role can reach the restoring dump during the restore window (the same REVOKE
///    the normal per-tenant provisioning applies).
/// 2. **After the atomic rename** (`pg_swap_shadow`): re-run the idempotent [`provision_tenant`],
///    re-asserting the per-tenant isolation + serving grants on the swapped-in db (owner/login
///    roles, REVOKE PUBLIC, GRANT CONNECT/ALL, and the app-role table grants on the restored,
///    now-owner-owned objects). The REASSIGN/ALTER-OWNER in the swap already points the db + its
///    objects at the tenant OWNER role (not the superuser), so this re-provision completes the model.
///
/// This never widens the untrusted-apply surface: the dump is still applied ONLY by the ephemeral
/// non-superuser role; all of the above is our own trusted DDL run by the superuser/maintenance
/// connection.
#[derive(Clone)]
struct SharedReprovision {
    /// The TARGET project whose per-tenant db was cloned (the project the re-provision runs for).
    project: String,
    /// The managed Shared binding (carries compute/database/tenant/scope — the exact input
    /// `provision_tenant` re-derives the tenant's db + role names from).
    binding: ExternalDatabaseConfig,
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
    /// Where the swapped-in db's carried DEFINER-bearing objects (triggers/routines/events) have
    /// their `DEFINER` RE-POINTED after the atomic swap — NEVER the ephemeral apply user (dropped
    /// at swap) and NEVER a superuser/another tenant. For a Shared NON-default tenant this is the
    /// tenant's own db-scoped LOGIN role (`` `<role>`@`%` ``); for Single/dedicated + Shared-DEFAULT
    /// it is [`MysqlDefinerTarget::Strip`] (the clause is removed, so `DEFINER` defaults to the admin
    /// connection that re-creates the object — i.e. the server's own served identity). See
    /// [`rewrite_mysql_definers`].
    repoint: MysqlDefinerTarget,
}

/// Where a mysqldump `DEFINER=` clause is (re)pointed by [`rewrite_mysql_definers`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum MysqlDefinerTarget {
    /// Point every DEFINER at `` `<name>`@`%` ``: the ephemeral apply user at restore-into-shadow
    /// time (so the untrusted objects create successfully as a non-superuser), or a Shared tenant's
    /// own db-scoped LOGIN role at post-swap re-point time (so a malicious object body runs only with
    /// the tenant's own grants — never cross-tenant or server-wide).
    Account(String),
    /// REMOVE the DEFINER clause entirely, so the object's DEFINER defaults to the CREATE statement's
    /// issuer. Used for the dedicated/Single + Shared-DEFAULT post-swap re-point, where the admin
    /// connection that re-creates the object IS the served identity (there is no separate per-tenant
    /// role on a single-tenant server), so defaulting to it introduces no authority the tenant's own
    /// app does not already hold.
    Strip,
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

/// Rewrite the STRUCTURAL mysqldump `DEFINER=`user`@`host`` clause of each object definition in
/// `sql` to `target`, PRECISELY and SAFELY. The crux of the DEFINER-handling security story, so the
/// matching is deliberately narrow — it rewrites a DEFINER clause ONLY where mysqldump actually emits
/// an object's definer, in two forms, and ONLY the ONE structural clause per line (never a DEFINER
/// that appears later on the same line inside a trigger/routine BODY or a string literal):
///
/// 1. **A mysqldump executable-comment line** (first non-whitespace is `/*!`). A TRIGGER's, EVENT's,
///    and VIEW's definer rides inside a `/*!NNNNN DEFINER=…*/` version-gated comment that is the
///    FIRST `DEFINER=` on the line (the object body/select text, which could contain the literal
///    "DEFINER=", comes AFTER it on the line, or on later lines — and is left untouched).
/// 2. **A plain top-level `CREATE [OR REPLACE] [ALGORITHM=…] DEFINER=… {PROCEDURE|FUNCTION|VIEW|
///    TRIGGER|EVENT}` statement line.** mysqldump emits a stored PROCEDURE/FUNCTION (and a plain-form
///    VIEW) definer OUTSIDE any `/*!…*/` wrapper — `CREATE DEFINER=`root`@`%` PROCEDURE …` — because
///    the body must execute. The structural prefix (`CREATE`, then only `OR REPLACE` / `ALGORITHM=…`
///    before `DEFINER=`) is matched, so this fires ONLY on a real object header, never on an
///    `INSERT …`/`SET …` data line or a routine BODY line (which do not start with that prefix).
///
/// In BOTH forms, only the exact `DEFINER=`‹quoted-ident›`@`‹quoted-ident›`` shape (backtick quoting,
/// doubled `` `` `` for a literal backtick — the shape mysqldump/`SHOW CREATE` always emit) is
/// replaced; a `DEFINER=` not in that shape is copied through. The rewrite can only ever REDUCE
/// privilege (point at the least-privilege apply user, the tenant's own role, or strip to the
/// issuer) — never raise it — so even a crafted edge that slipped a DEFINER through would at worst
/// fail the non-superuser restore FAIL-CLOSED, never escalate. `SQL SECURITY DEFINER` is deliberately
/// LEFT INTACT: safety rides the re-pointed DEFINER being the tenant's own db-scoped role (or the
/// served identity on a single-tenant server), so DEFINER semantics run within the tenant's authority.
fn rewrite_mysql_definers(sql: &str, target: &MysqlDefinerTarget) -> String {
    let mut out = String::with_capacity(sql.len());
    for line in sql.split_inclusive('\n') {
        match structural_definer_offset(line) {
            Some(off) => rewrite_one_definer_clause_at(line, off, target, &mut out),
            None => out.push_str(line),
        }
    }
    out
}

/// The byte offset within `line` of the ONE structural object-definer `DEFINER=` to rewrite, or
/// `None` if this line carries no object definer. Handles both the `/*!…*/` comment form (trigger/
/// event/view) and the plain `CREATE [OR REPLACE] [ALGORITHM=…] DEFINER=…` statement form (stored
/// routine / plain view). Never matches a `DEFINER=` inside row data, a body, or a string literal.
fn structural_definer_offset(line: &str) -> Option<usize> {
    let ws = line.len() - line.trim_start().len();
    let t = &line[ws..];
    if t.starts_with("/*!") {
        // The object's definer is the FIRST `DEFINER=` on a mysqldump version-comment line (the
        // `CREATE*/` preamble before it carries none; the body/select AFTER it we must not touch).
        return line.find("DEFINER=");
    }
    // A plain top-level CREATE-with-DEFINER object header (stored PROCEDURE/FUNCTION, plain VIEW).
    plain_create_definer_offset(t).map(|off| ws + off)
}

/// If the whitespace-trimmed line `t` is a top-level `CREATE [OR REPLACE] [ALGORITHM=<token>]
/// DEFINER=…` object header, return the byte offset (within `t`) of `DEFINER=`. ONLY `OR REPLACE` and
/// `ALGORITHM=<token>` may sit between `CREATE` and `DEFINER=`, so a routine BODY line, a `SET …`
/// save/restore line, or an `INSERT …` data line (none of which start with this exact prefix) is
/// never matched — the structural guard the security review relies on.
fn plain_create_definer_offset(t: &str) -> Option<usize> {
    let rest = t.strip_prefix("CREATE")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let mut rest = rest.trim_start();
    if let Some(r) = rest.strip_prefix("OR REPLACE") {
        if !r.starts_with(char::is_whitespace) {
            return None;
        }
        rest = r.trim_start();
    }
    if let Some(r) = rest.strip_prefix("ALGORITHM=") {
        // Consume the algorithm token (UNDEFINED/MERGE/TEMPTABLE) up to the next whitespace.
        let after = r.trim_start_matches(|c: char| !c.is_whitespace());
        if after.len() == r.len() {
            return None; // no token consumed — malformed
        }
        rest = after.trim_start();
    }
    rest.starts_with("DEFINER=").then(|| t.len() - rest.len())
}

/// Rewrite the single `DEFINER=` clause at byte offset `off` in `line` into `out`, copying the rest
/// of the line verbatim. Only the exact backtick-quoted `` `u`@`h` `` shape is replaced.
fn rewrite_one_definer_clause_at(
    line: &str,
    off: usize,
    target: &MysqlDefinerTarget,
    out: &mut String,
) {
    out.push_str(&line[..off]);
    let after = &line[off + "DEFINER=".len()..];
    match mysql_definer_account_len(after) {
        Some(consumed) => match target {
            MysqlDefinerTarget::Account(name) => {
                out.push_str("DEFINER=");
                out.push_str(&quote_ident(ExternalSqlKind::Mysql, name));
                out.push_str("@`%`");
                out.push_str(&after[consumed..]);
            }
            MysqlDefinerTarget::Strip => {
                // Drop the clause AND a single trailing space, so `/*!50017 DEFINER=…*/` collapses to
                // `/*!50017 */` and `CREATE DEFINER=…`@`…` PROCEDURE …` to `CREATE PROCEDURE …`.
                let rest = &after[consumed..];
                out.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            }
        },
        None => {
            // A `DEFINER=` not in the exact backtick-quoted shape — copy it through verbatim (never
            // corrupt text we do not recognize).
            out.push_str("DEFINER=");
            out.push_str(after);
        }
    }
}

/// If `s` begins with a complete `` `user`@`host` `` MySQL account spec (each a backtick-quoted
/// identifier, doubled `` `` `` for a literal backtick), return its byte length; else `None`.
fn mysql_definer_account_len(s: &str) -> Option<usize> {
    let user = mysql_quoted_ident_len(s)?;
    let at = &s[user..];
    let at = at.strip_prefix('@')?;
    let host = mysql_quoted_ident_len(at)?;
    Some(user + 1 + host)
}

/// Byte length of a leading `` `…` `` backtick-quoted identifier (doubled `` `` `` = one literal
/// backtick), or `None` if `s` does not start with a complete one.
fn mysql_quoted_ident_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.first() != Some(&b'`') {
        return None;
    }
    let mut i = 1;
    while i < b.len() {
        if b[i] == b'`' {
            if b.get(i + 1) == Some(&b'`') {
                i += 2; // doubled backtick = a literal backtick inside the identifier
                continue;
            }
            return Some(i + 1); // the closing backtick
        }
        i += 1;
    }
    None // unterminated
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
        // An ordinary export is the clone stream with an EMPTY skip set (the degenerate
        // "send everything, skip nothing" case; the target-driven reader is the superset).
        self.export_clone(project, opts, &CloneSkip::default(), sink)
            .await
    }

    async fn export_clone(
        &self,
        project: &str,
        opts: &ExportOptions,
        skip: &CloneSkip,
        sink: &mut (dyn futures::io::AsyncWrite + Send + Unpin),
    ) -> Result<(), Perr> {
        check_project_slug(project)?;
        // A data-only bundle carries NO control-plane / identity material at all, so the
        // two flags are mutually exclusive — refuse the contradiction rather than silently
        // pick one.
        if opts.scope.is_data_only() && opts.include_identity {
            return Err(Perr::Other(
                "--data-only and --include-identity are mutually exclusive: a data-only \
                 bundle carries application data only (no control-plane KV, no identity)"
                    .into(),
            ));
        }
        let head = opts.head();
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
        let (mut specs, mut jobs, source) = self.plan_export(project, opts, created_at).await?;
        // CLONE per-SHA skip: drop the blob members the target already holds (content-matched in
        // ITS OWN scope — see `diff_clone_blobs`). ONLY blob members are skippable; a non-blob
        // skip entry is IGNORED so a skip set can never drop a DB/KV/identity member. Removed from
        // BOTH the spec list (so the MANIFEST omits them) and the stage jobs (so the stager is
        // never asked for them), keeping the stream internally consistent for the inc2 atomic
        // reader — the omitted objects are already present on the target bucket.
        if !skip.skip_member_paths.is_empty() {
            specs.retain(|s| {
                !(s.kind == MemberKind::Blob && skip.skip_member_paths.contains(&s.path))
            });
            jobs.retain(|path, _| specs.iter().any(|s| &s.path == path));
        }

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
                    head,
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
        // Clone-robustness (PLAN-clone-robustness #1 + #2): the member-mismatch tolerance policy,
        // built from the import options. Strict by default (hard-fail the first declared≠streamed
        // mismatch); `enumerate_mismatches` scans all + fails at the end; `skip_member_mismatch`
        // warns + continues past a re-generable `der/` mismatch (broadened by `skip_any_blob_mismatch`
        // to any blob — never a non-blob member).
        let verify_policy = verify_policy_from_opts(&opts);
        let (byte_tx, byte_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BYTE_CHANNEL);
        let (req_tx, mut req_rx) = tokio::sync::mpsc::channel::<ImportMsg>(1);
        let reader = ChannelReader::new(byte_rx);
        let stage_dir_task = stage_dir.clone();
        let req_tx_task = req_tx.clone();
        // The blocking reader returns BOTH its result AND the mismatch sink (so the enumerate/skip
        // detail survives even on the `MembersMismatched` error path, for the report + the error).
        type ReadOutput = (
            Result<Vec<MemberSpec>, project_bundle::BundleError>,
            Vec<project_bundle::MemberMismatch>,
        );
        let read_handle = tokio::task::spawn_blocking(move || -> ReadOutput {
            let head_tx = req_tx_task.clone();
            let on_head = move |head: BundleHead, source: &SourceInfo| {
                // Surfaced before any member: the servicer needs the source project (to re-key each
                // member to the TARGET) and the bundle head (scope + managed-restore mode).
                let _ = head_tx.blocking_send(ImportMsg::Head {
                    head,
                    source_project: source.project.clone(),
                });
            };
            let mut bridge = ImportBridge {
                req_tx: req_tx_task,
                body_tx: None,
                chunked_bytes: 0,
                member_cap,
            };
            let mut mismatches = Vec::new();
            let res = project_bundle::read_bundle_streaming_atomic_policy(
                reader,
                &stage_dir_task,
                &verify_policy,
                &mut mismatches,
                on_head,
                &mut bridge,
            );
            (res, mismatches)
        });
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
            // Defaults until the Head arrives (a bundle always sends Head first): the safe
            // Full-scope + ShadowSwap head, so a malformed head-less stream never silently
            // down-scopes or routes a managed member to the refused overlay.
            let mut head = BundleHead {
                scope: BundleScope::Full,
                managed_restore: ManagedRestore::ShadowSwap,
            };
            let mut source_project = String::new();
            let mut saw_identity = false;
            let mut pending_chunk: Option<ChunkState> = None;
            let mut chunk_idx = 0usize;
            while let Some(msg) = req_rx.recv().await {
                match msg {
                    ImportMsg::Head {
                        head: h,
                        source_project: s,
                    } => {
                        head = h;
                        source_project = s;
                    }
                    ImportMsg::Member { spec, temp, reply } => {
                        let r = self
                            .restore_member(
                                project,
                                head,
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
                                // `--only-blobs` repair (clone-robustness #3) is BLOBS-ONLY: skip a
                                // DB member entirely (drain + count, open no shadow), exactly like a
                                // dry-run, so a repair never re-applies the database.
                                if opts.apply && opts.only_blobs.is_none() {
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
                                // Dry-run OR an `--only-blobs` (blobs-only) repair: don't touch the
                                // server — drain + count, open no shadow.
                                if !opts.apply || opts.only_blobs.is_some() {
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
                                // Dry-run OR an `--only-blobs` (blobs-only) repair: don't touch the
                                // server — drain + count, open no shadow.
                                if !opts.apply || opts.only_blobs.is_some() {
                                    let _ = reply.send(Ok(()));
                                    while body_rx.recv().await.is_some() {}
                                    report.pg_databases += 1;
                                    pending_chunk = None;
                                } else {
                                    // Defense-in-depth: only a DEDICATED/Single managed ShadowSwap
                                    // member is framed chunked, so refuse a Shared one here
                                    // (`allow_shared = false`) — a Shared managed mysql reaches the
                                    // shadow via the SIDECAR path instead.
                                    let plan = match self
                                        .mysql_shadow_plan(project, &db, &cfg, false)
                                        .await
                                    {
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
                                    let dump_path =
                                        stage_dir.join(format!("mydump-{chunk_idx}.sql"));
                                    chunk_idx += 1;
                                    let restore = match self.spawn_mysql_restore(
                                        &plan,
                                        body_rx,
                                        out_path.clone(),
                                        dump_path.clone(),
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
                                        dump_path,
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
                                        head,
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
                                dump_path,
                            }) => {
                                let code = restore.await;
                                let out = tokio::fs::read_to_string(&out_path)
                                    .await
                                    .unwrap_or_default();
                                let _ = tokio::fs::remove_file(&out_path).await;
                                let _ = tokio::fs::remove_file(&dump_path).await;
                                match code {
                                    Ok(Ok(0)) if verified => {
                                        // Carry the DEFINER objects + atomic swap + re-point to the
                                        // tenant's own role (the ONE DEFINER-handling seam the sidecar
                                        // path shares).
                                        match self.mysql_finalize_shadow(&plan, &stage_dir).await {
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
            Ok((report, head, saw_identity, source_project))
        };

        let (feed_res, serv_res, read_res) = tokio::join!(feeder, servicer, read_handle);

        // Error precedence: a restore failure is the most specific cause; a bundle-integrity
        // error (SHA / size / order / truncation) next; a body-read error last. On ANY error
        // skip the post-stream steps (fresh-drop etc.) so a half-stream never half-finishes.
        let (mut report, head, saw_identity, source_project) = match serv_res {
            Ok(v) => v,
            Err(e) => {
                let _ = tokio::fs::remove_dir_all(&session).await;
                return Err(e);
            }
        };
        let member_mismatches = match read_res {
            Ok((Ok(_specs), mm)) => mm,
            Ok((Err(be), mm)) => {
                let _ = tokio::fs::remove_dir_all(&session).await;
                // Expand an ENUMERATE-ALL aggregate into a legible per-member report; other bundle
                // errors pass through unchanged.
                return Err(enumerated_import_error(be, &mm));
            }
            Err(je) => {
                let _ = tokio::fs::remove_dir_all(&session).await;
                return Err(other(je));
            }
        };
        if let Err(e) = feed_res {
            let _ = tokio::fs::remove_dir_all(&session).await;
            return Err(e);
        }

        // Clone-robustness (PLAN-clone-robustness #2): record every TOLERATED member-mismatch skip
        // in the report notes, so the operator sees exactly which re-generable derivatives were
        // skipped (and thus will be re-derived on the target on next access). A clean strict pass
        // leaves this empty. ALSO record each as a structured `SkippedBlob` (clone-robustness #3) so
        // it lands in the skip MANIFEST alongside any backend skips — its `key` is the TARGET key
        // (re-keyed to this project's own scope, so `--only-blobs` can re-stream it if the operator
        // wants the exact bytes rather than a target-side re-derivation).
        for m in &member_mismatches {
            if m.skipped {
                report.notes.push(format!(
                    "SKIPPED member {:?} [{}] ({:?} mismatch: declared {}, streamed {}) — NOT \
                     applied; the target re-derives it on access",
                    m.path,
                    m.class.label(),
                    m.kind,
                    m.declared,
                    m.streamed
                ));
                // Re-key to the target scope when it is a blob member; fall back to the raw member
                // path if the re-key fails closed (a non-blob / wrong-scope member — never skipped
                // by the mismatch policy, but recorded faithfully rather than dropped).
                let key = target_blob_key(&m.path, &source_project, project)
                    .unwrap_or_else(|_| m.path.clone());
                report.skipped.push(SkippedBlob {
                    key,
                    kind: ContinueErrorKind::MemberMismatch.as_str().to_string(),
                    reason: format!(
                        "{:?} mismatch [{}]: declared {}, streamed {}",
                        m.kind,
                        m.class.label(),
                        m.declared,
                        m.streamed
                    ),
                });
            }
        }

        // --- post-stream steps (only after a clean, fully-verified pass) ---

        // A data-plane-scope bundle carries app data only; record that KV was not restored.
        if head.scope.is_data_only() {
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
        if matches!(opts.identity, IdentityChoice::Fresh)
            && head.scope.carries_control_plane()
            && opts.apply
        {
            let prefixes =
                boatramp_core::project_export::sealed_secret_prefixes(ProjectRef::new(project));
            // The managed-SQL credential prefix needs special handling. This import's OWN managed-DB
            // self-provisioning (`ensure_target_db_provisioned` → `provision_tenant`, run during
            // member restore) MINTS the target tenant's login/owner (Shared) or workload (Single)
            // credential under `managed-sql-cred/{project}/…`, sealed under THIS node's KEK, and
            // sets the live role's password (or inits the container) to exactly it. Dropping one of
            // THOSE would desync the sealed credential from the live role: the next
            // `creds.password(...)` would mint a fresh random value that no longer authenticates the
            // role (psql exit 2 — "password authentication failed", not "permission denied"), so the
            // cloned tenant's own runtime/owner role could never connect. So keep exactly the keys
            // this target's own self-provisioning owns (re-derived the same way `provision_tenant`
            // seals them) and drop every OTHER managed cred under the prefix — a source-carried one
            // (restored via a `--include-identity` KV member) is un-unsealable here and must go.
            let managed_cred_prefix = format!("managed-sql-cred/{project}/");
            let keep_managed = self_provisioned_managed_cred_keys(&self.databases, project);
            let mut dropped = 0usize;
            let mut kept_minted = 0usize;
            for prefix in &prefixes {
                for key in self.kv.list_prefix(prefix).await.map_err(other)? {
                    if prefix == &managed_cred_prefix && keep_managed.contains(&key) {
                        kept_minted += 1;
                        continue;
                    }
                    self.kv.delete_checkpointed(&key).await.map_err(other)?;
                    dropped += 1;
                }
            }
            report.notes.push(format!(
                "identity: --fresh dropped {dropped} source-sealed secret key(s); kept \
                 {kept_minted} self-provisioned managed-DB credential(s) (they match the cloned \
                 tenant's live roles); re-provision application secrets on the target"
            ));
        }

        // Operational prerequisites after a FULL control-plane restore — the portable bundle
        // deliberately carries no function/component CODE (deploy artifacts live in blob storage,
        // not this slice), no TLS private keys and no global routing ownership. Surface the
        // follow-up steps so the target is not silently half-restored.
        if head.scope.carries_control_plane() {
            report.notes.push(
                "post-import: re-deploy function/component code (deploy artifacts are not \
                 bundled), re-verify + re-attach the project's domains, and let ACME re-issue TLS \
                 certs (routing + certs are intentionally not carried in a portable bundle)"
                    .into(),
            );
        }

        // Clone-robustness (PLAN-clone-robustness #3): if ANYTHING was skipped (backend and/or
        // member-mismatch), write a skip-report MANIFEST under the node base — one entry per skipped
        // blob — and surface its path + count in the report. Written to `self.work_dir` (the base),
        // NOT the per-import `session` dir, so it SURVIVES the session cleanup below. This makes an
        // applied op that left blobs behind a DISTINCT "completed with N skipped" outcome (the
        // caller renders it as such), and the manifest round-trips into a later `--only-blobs`
        // repair. On a clean pass nothing is written. Only when APPLYING (a dry-run mutates
        // nothing, so there is nothing to repair).
        if opts.apply && report.completed_with_skips() {
            let manifest = SkipManifest {
                project: project.to_string(),
                skipped: report.skipped.clone(),
            };
            let path = self
                .work_dir
                .join(format!("skip-manifest-{project}-{}.json", now_secs()));
            match tokio::fs::write(&path, manifest.to_json()).await {
                Ok(()) => {
                    let n = report.skipped.len();
                    let shown = path.display().to_string();
                    report.skip_manifest = Some(shown.clone());
                    report.notes.push(format!(
                        "completed with {n} blob(s) skipped — skip manifest written to {shown}; \
                         re-stream them with `import --only-blobs {shown}`"
                    ));
                }
                Err(e) => {
                    // The import itself succeeded; only the manifest write failed. Surface it as a
                    // note (the structured `skipped` list is still in the report) rather than
                    // failing the whole op after the data already landed.
                    report.notes.push(format!(
                        "WARNING: completed with {} blob(s) skipped but the skip manifest could not \
                         be written to {}: {e}; the skipped list is in this report",
                        report.skipped.len(),
                        path.display(),
                    ));
                }
            }
        }

        let _ = tokio::fs::remove_dir_all(&session).await;
        Ok(report)
    }

    async fn export_resumable(
        &self,
        project: &str,
        opts: &ExportOptions,
        dir_name: &str,
    ) -> Result<(), Perr> {
        // Confine the operator-named subdir under the configured base (fail-closed if no
        // base / on any escape), creating it, then run the core member-object export.
        let dir = self.resolve_resumable_dir(dir_name, true).await?;
        self.export_resumable_dir(project, opts, &dir).await
    }

    async fn import_resumable(
        &self,
        project: &str,
        dir_name: &str,
        opts: ImportOptions,
    ) -> Result<ImportReport, Perr> {
        // Confine the operator-named subdir under the configured base; it must already
        // exist (read, not create), then run the core member-object import-as-chain.
        let dir = self.resolve_resumable_dir(dir_name, false).await?;
        self.import_resumable_dir(project, &dir, opts).await
    }

    async fn clone_manifest(
        &self,
        project: &str,
        opts: &ExportOptions,
    ) -> Result<CloneManifest, Perr> {
        self.build_clone_manifest(project, opts).await
    }

    async fn clone_blobs_present(
        &self,
        project: &str,
        source_project: &str,
        blobs: &[CloneBlobRef],
    ) -> Result<CloneSkip, Perr> {
        self.diff_clone_blobs(project, source_project, blobs).await
    }
}

impl NodeProjectExport {
    /// CLONE SOURCE — produce the cheap [`CloneManifest`] for the manifest-first handshake: LIST
    /// the project's own blob objects (member path + size + etag, from a prefix list — never a
    /// body read) for the target's per-SHA diff, plus a light enumeration of the non-blob member
    /// paths (pg/mysql/libsql/kv/identity) the stream will always carry. Blobs are scoped
    /// STRUCTURALLY by the project prefix (`hblob/{project}/`, whose trailing `/` excludes a
    /// sibling-prefix tenant), so no other tenant's object can appear — the manifest is itself a
    /// cross-tenant boundary. Deliberately AVOIDS the engine version-detection `plan_export` does
    /// (no DB round-trip), so the manifest stays cheap and never fails on a down database.
    async fn build_clone_manifest(
        &self,
        project: &str,
        opts: &ExportOptions,
    ) -> Result<CloneManifest, Perr> {
        check_project_slug(project)?;
        if opts.scope.is_data_only() && opts.include_identity {
            return Err(Perr::Other(
                "--data-only and --include-identity are mutually exclusive".into(),
            ));
        }
        let carries_control_plane = opts.scope.carries_control_plane();

        // Blobs: a metadata-only LIST under the project's OWN scope (`hblob/{project}/`).
        let blob_metas = self
            .blobs
            .list(&blob_project_prefix(project))
            .await
            .map_err(other)?;
        let blobs: Vec<CloneBlobRef> = blob_metas
            .into_iter()
            .map(|m| CloneBlobRef {
                member_path: format!("blobs/{}", m.key),
                size: m.size,
                etag: m.etag,
            })
            .collect();

        // Non-blob members (informational): the member PATHS the stream will carry, derived from
        // config + the stores WITHOUT a version-detect/dump — cheap and never hits the DB.
        let mut non_blob_members: Vec<String> = Vec::new();
        if opts.include_identity {
            non_blob_members.push(project_bundle::IDENTITY_MEMBER_PATH.to_string());
        }
        for (db, cfg) in &self.databases {
            let is_managed = cfg.compute.as_deref().is_some_and(|c| !c.is_empty());
            let dumpable = is_managed || !cfg.url_env.is_empty();
            if kind_is_postgres(&cfg.kind) && dumpable {
                non_blob_members.push(pg_member_path(db));
            } else if kind_is_mysql(&cfg.kind) && dumpable {
                non_blob_members.push(mysql_member_path(db));
            }
        }
        if let Some(libsql) = &self.libsql {
            let sites = self
                .deploy
                .list_sites(ProjectRef::new(project))
                .await
                .map_err(other)?;
            for site in sites {
                let qsite = ProjectRef::new(project).qualified(&site);
                if libsql.local_database_exists(&qsite, "") {
                    non_blob_members.push(libsql_member_path(project, &site));
                }
            }
        }
        if carries_control_plane {
            non_blob_members.push(project_bundle::KV_MEMBER_PATH.to_string());
        }

        Ok(CloneManifest {
            source_project: project.to_string(),
            data_only: opts.scope.is_data_only(),
            blobs,
            non_blob_members,
        })
    }

    /// CLONE TARGET — the per-SHA presence DIFF: for each source blob ref, re-key its member path
    /// to THIS target's own scope (`source_project` → `project`, via the SAME [`target_blob_key`]
    /// the restore uses) and check presence in the target's OWN bucket. A ref whose path is NOT
    /// under `hblob/{source_project}/` is REFUSED fail-closed — the diff is confined to the
    /// target's own scope and never trusts a source-declared path to reach a foreign key.
    ///
    /// A blob is marked present (⇒ the source will SKIP it) only on POSITIVE content-identity
    /// evidence: the target already holds an object at the re-keyed key AND either (a) both the
    /// manifest and the target carry an `etag` and they are equal (the strong content hash on
    /// S3/GCS), or (b) no etag is available on either side and the declared sizes match (the
    /// resume case on a fresh target — a present object there was written by a prior attempt of
    /// THIS clone, so same key + same size ⇒ same bytes under the content-addressed-immutable
    /// blob keyspace). Otherwise the blob is pulled and overwritten idempotently.
    ///
    // TODO(project-clone): replace the size-only fallback with a per-object content hash once the
    // at-rest-encryption × content-addressing open question (PLAN §9.1) is resolved — a
    // per-tenant-KEK-encrypted store breaks "same key ⇒ same ciphertext", so the strong-hash path
    // must be mandatory there rather than the size fallback.
    async fn diff_clone_blobs(
        &self,
        project: &str,
        source_project: &str,
        blobs: &[CloneBlobRef],
    ) -> Result<CloneSkip, Perr> {
        check_project_slug(project)?;
        check_project_slug(source_project)?;
        // DoS/OOM guard: a hostile source manifest could list an absurd number of blob refs, each
        // driving a HEAD against the target's own bucket. Cap the COUNT before the fan-out. The
        // 64 MiB manifest-body cap in the server already bounds this transitively (~2M refs max);
        // this is the explicit belt-and-suspenders bound at the driver seam.
        if blobs.len() > MAX_CLONE_MANIFEST_BLOBS {
            return Err(Perr::Other(format!(
                "clone manifest lists {} blob refs, exceeding the maximum of {MAX_CLONE_MANIFEST_BLOBS}; \
                 refusing the diff",
                blobs.len()
            )));
        }
        // Bound-parallelize the per-ref HEAD fan-out (the serial crawl was O(blob-count) round
        // trips — minutes before a byte moves at ~18k blobs). Each future runs the SAME per-ref
        // logic the serial loop did: re-key to the target's own scope (fail-closed on a
        // foreign/malformed path — unchanged scope guard), HEAD the target's own bucket, and decide
        // presence on the SAME content-identity rule. The count cap above already fired, so this
        // caps in-flight HEADs (≤ CLONE_DIFF_CONCURRENCY), never the total. `try_collect` is
        // fail-closed — the first HEAD error (other than NotFound) short-circuits the whole diff,
        // exactly as the serial `return Err(..)` did. Results collect into a set, so the
        // completion-order of the unordered fan-out does not affect the skip set.
        use futures::stream::TryStreamExt; // `StreamExt` (map/buffer_unordered) is imported module-wide
        // Own each ref's fields up front and fan out over OWNED items — a stream of borrowed
        // `&CloneBlobRef` forces the per-item async closure to satisfy a higher-ranked lifetime it
        // cannot (the future would borrow the stream item across its await). `source_project` /
        // `project` are borrowed for the whole call (not from a stream item), which is fine.
        let reqs: Vec<(String, Option<String>, Option<u64>)> = blobs
            .iter()
            .map(|b| (b.member_path.clone(), b.etag.clone(), b.size))
            .collect();
        let present: Vec<Option<String>> = futures::stream::iter(reqs)
            .map(|(member_path, etag, size)| {
                let blobs_store = self.blobs.clone();
                async move {
                    let target_key = target_blob_key(&member_path, source_project, project)?;
                    match blobs_store.head(&target_key).await {
                        Ok(meta) => {
                            let is_present = match (&etag, &meta.etag) {
                                (Some(src), Some(dst)) => src == dst,
                                _ => match (size, meta.size) {
                                    (Some(s), Some(d)) => s == d,
                                    _ => false,
                                },
                            };
                            Ok(is_present.then_some(member_path))
                        }
                        Err(boatramp_core::StorageError::NotFound(_)) => Ok(None), // absent ⇒ pull it
                        Err(e) => Err(other(e)),
                    }
                }
            })
            .buffer_unordered(CLONE_DIFF_CONCURRENCY)
            .try_collect()
            .await?;
        let mut skip = CloneSkip::default();
        skip.skip_member_paths.extend(present.into_iter().flatten());
        Ok(skip)
    }

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
        // The two orthogonal concepts the old single `data_only` flag conflated, now kept apart:
        //   - `carries_control_plane` (SCOPE): does the bundle carry the KV slice + identity?
        //   - `managed_restore`       (MODE):  how are MANAGED members dumped/restored?
        // `overlay_dump` is the `--data-only` toggle passed to pg_dump/mysqldump (an Overlay dump is
        // schema-less; a ShadowSwap dump is FULL). These were always equal before the split; the new
        // `DataPlane + ShadowSwap` combination (what `project sync` requests) is what makes a managed
        // DB's data land via the safe shadow+swap without dragging in the control-plane KV slice.
        let carries_control_plane = opts.scope.carries_control_plane();
        let managed_restore = opts.managed_restore;
        let overlay_dump = managed_restore.is_overlay();
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

        // Checkpoint the durable KV frontier BEFORE we enumerate (full-SCOPE export only), so the
        // KV slice staged later reflects a consistent frontier.
        if carries_control_plane {
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
            // A MANAGED, DEDICATED/Single pg/mysql ShadowSwap dump is framed ChunkedTrailer → the
            // inc2 streamed dump + atomic shadow-restore (Stage C/D). An Overlay (schema-less
            // `--data-only`) dump stays on the inc1 sidecar path (default #1: FULL-restore atomicity
            // only); an EXTERNAL bring-your-own-URL binding stays sidecar (we never CREATE/RENAME/DROP
            // databases on an operator's own server); and a SHARED multi-tenant server stays sidecar
            // (reaching the shadow via `pg_sidecar_shadow_restore`). So: chunked IFF managed AND
            // ShadowSwap AND not-Shared. NB: keyed on the MANAGED-RESTORE mode, NOT the bundle scope —
            // a `DataPlane` sync bundle still frames a dedicated managed DB chunked (ShadowSwap).
            let is_shared = matches!(cfg.tenant, crate::config::TenantIsolation::Shared);
            let chunked = managed_member_chunked(is_managed, managed_restore, is_shared);
            if kind_is_postgres(&cfg.kind) && dumpable {
                let (conn, image, server_version_num) = self.resolve_pg(project, db, cfg).await?;
                let schema_fingerprint = self.schema_fingerprint(project, db).await;
                let pg = Some(PgMemberInfo {
                    server_version_num: server_version_num.clone(),
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
                        data_only: overlay_dump,
                        server_version_num,
                        no_publications: cfg.delta_capture,
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
                        data_only: overlay_dump,
                        // A MANAGED Shared ShadowSwap member is framed SIDECAR but must restore into
                        // a differently-named per-tenant shadow db, so it needs the TABLES-ONLY dump
                        // (no `CREATE DATABASE <livedb>; USE <livedb>;`) — the exact dump the chunked
                        // path streams. A dedicated managed ShadowSwap is framed chunked (its producer
                        // already uses the tables-only dump), and external/Overlay members keep the
                        // FULL `--databases` dump, so they are not tables-only here.
                        tables_only: is_managed
                            && is_shared
                            && matches!(managed_restore, ManagedRestore::ShadowSwap),
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

        // --- control-plane KV slice (FULL-SCOPE export only) — LAST in restore order. A
        //     `DataPlane`-scope bundle carries application data ONLY, never the KV slice (RBAC,
        //     routing, personas, sealed secrets), so it is not even staged for a data-plane bundle. ---
        if carries_control_plane {
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
            Some(StageJob::Pg {
                conn,
                image,
                server_version_num,
                no_publications,
                ..
            }) => {
                // FULL `pg_dump -Fc` stdout → body channel, NO temp (inc2 Stage C). The chunked pg
                // path is FULL-only (default #1), so `data_only` is ignored here (plan_export only
                // frames pg chunked when !data_only).
                let backend = self.require_backend()?.clone();
                let conn = conn.clone();
                let image = image.clone();
                let server_version_num = server_version_num.clone();
                let no_publications = *no_publications;
                // The chunked member is applied into a SHADOW that pre-creates the operator
                // trusted-extension allowlist, so (on PG17+) the dump can `--exclude-extension`
                // exactly those and keep every other object comment (see `pg_dump_invocation`).
                let exclude_extensions = self.trusted_extensions.clone();
                tokio::spawn(async move {
                    let mut sink = AsyncChannelWriter::new(body_tx);
                    let r: Result<(), Perr> = async {
                        let inv = pg_dump_invocation(
                            &conn,
                            false,
                            &server_version_num,
                            &exclude_extensions,
                            no_publications,
                        );
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
                server_version_num,
                no_publications,
            } => {
                // SIDECAR (data-only, Shared, or external bring-your-own-URL): the restore applies
                // the dump's OWN `CREATE EXTENSION` (we never pre-create extensions on a non-shadow
                // target), so pass an EMPTY exclude list — this keeps the conservative
                // `--no-comments` regardless of server version (see `pg_dump_invocation`).
                let inv =
                    pg_dump_invocation(conn, *data_only, server_version_num, &[], *no_publications);
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
                tables_only,
            } => {
                // A Shared managed ShadowSwap member stages TABLES-ONLY (so the sidecar shadow+swap
                // can restore it into a differently-named per-tenant shadow); external/Overlay keep
                // the FULL `--databases` dump.
                let inv = if *tables_only {
                    mysqldump_tables_only_invocation(conn)
                } else {
                    mysqldump_invocation(conn, *data_only)
                };
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
            StageJob::KvDelta { bytes }
            | StageJob::BlobTombstone { bytes }
            | StageJob::PgWalDelta { bytes }
            | StageJob::MysqlBinlogDelta { bytes }
            | StageJob::LibsqlChangeset { bytes } => {
                // A delta member whose bytes were computed + encoded at plan time (the KV
                // upserts+tombstones / the blob tombstone key list / the drained + framed
                // pgoutput WAL change stream / the framed raw mysql binlog / the framed libsql
                // changeset). Just persist them.
                tokio::fs::write(&tmp, bytes).await.map_err(other)?;
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
        head: BundleHead,
        source_project: &str,
        spec: &MemberSpec,
        temp: &Path,
        opts: &ImportOptions,
        report: &mut ImportReport,
        saw_identity: &mut bool,
    ) -> Result<(), Perr> {
        // The bundle's two orthogonal descriptors: `head.scope` (does it carry the control-plane KV
        // slice?) gates the Kv/KvDelta arms; `head.managed_restore` (Overlay vs ShadowSwap) routes
        // each managed engine member. `overlay` is the `--data-only` toggle for an EXTERNAL binding's
        // direct restore (a managed Overlay is refused before it reaches the invocation).
        let overlay = head.managed_restore.is_overlay();
        // --only-blobs REPAIR (clone-robustness #3): restore ONLY the blob members named in the
        // manifest; SKIP every other member (non-blob members, and blobs not in the set). The body
        // was already streamed to its bounded temp by the reader — skipping means simply NOT writing
        // it; nothing is buffered or re-staged. A wrong-scope blob key still fails closed below in
        // `target_blob_key`, so the repair never trusts a member path to reach a foreign key.
        if opts.only_blobs.is_some() {
            let is_blob = spec.kind == MemberKind::Blob;
            let target_key = if is_blob {
                Some(target_blob_key(&spec.path, source_project, project)?)
            } else {
                None
            };
            if only_blobs_skips(opts.only_blobs.as_ref(), is_blob, target_key.as_deref()) {
                return Ok(());
            }
        }
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
                    match self
                        .blobs
                        .put(
                            &target_key,
                            obj.body,
                            boatramp_core::PutMeta { content_type: None },
                        )
                        .await
                    {
                        Ok(_) => report.blobs += 1,
                        // BACKEND continue-on-error (clone-robustness #2): the target-write failed
                        // AFTER the backend's own bounded retries AND the `complete` HEAD-recovery
                        // (s3 Part 1), so the object genuinely did not land. If the policy forgives
                        // `backend`, WARN + RECORD (key, kind, reason) + SKIP this ONE blob and move
                        // on — the body is NOT buffered or re-staged (the stream has already passed
                        // it). Otherwise HARD-FAIL the whole import (the historical behaviour).
                        Err(e) if opts.continue_on_error.forgives(ContinueErrorKind::Backend) => {
                            let reason = e.to_string();
                            tracing::warn!(
                                key = %target_key,
                                reason = %reason,
                                "clone-robustness: SKIPPING a blob whose target-write failed \
                                 (continue-on-error=backend); re-stream it later with --only-blobs"
                            );
                            report.skipped.push(SkippedBlob {
                                key: target_key,
                                kind: ContinueErrorKind::Backend.as_str().to_string(),
                                reason,
                            });
                        }
                        Err(e) => return Err(other(e)),
                    }
                } else {
                    // Dry-run: count what WOULD be copied, writing nothing.
                    report.blobs += 1;
                }
            }
            MemberKind::PgDump => {
                let db = db_from_pg_member(&spec.path)
                    .ok_or_else(|| Perr::Other(format!("bad pg member path {:?}", spec.path)))?;
                let cfg = self.databases.get(db).ok_or_else(|| {
                    Perr::Other(format!("import: no database named {db:?} on this node"))
                })?;
                // Clone self-provision (PLAN-clone-self-provision-managed-db): a Shared-tenant
                // managed pg database restores via THIS sidecar arm (plan_export frames it
                // non-chunked), so this is the seam that must provision a Shared tenant's own
                // db before connecting. Gated on `opts.apply`: a verify/dry-run must mutate
                // nothing — `resolve_pg` below still runs un-provisioned on a dry-run, exactly
                // as before (an honest "not ready yet" is fine for a verify pass).
                if opts.apply {
                    self.ensure_target_db_provisioned(project, db, cfg).await?;
                }
                let (conn, image, _ver) = self.resolve_pg(project, db, cfg).await?;
                if overlay {
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
                    // HIGH-1 (narrowed): a SIDECAR pg member is ATTACKER-CRAFTED (the trailing SHA is
                    // integrity, not authenticity). It must NEVER be applied as the binding's
                    // configured user, which on a MANAGED co-located server is the BOOTSTRAP SUPERUSER
                    // — a crafted `COPY … TO PROGRAM` / `CREATE FUNCTION … LANGUAGE c` / untrusted
                    // `CREATE EXTENSION` would then execute = RCE. `sidecar_managed_apply` encodes the
                    // (managed × ManagedRestore) policy, and the confinement is NON-SUPERUSER-APPLY,
                    // not DDL/flag inspection (the managed-restore mode is itself an untrusted manifest
                    // flag that does not constrain the member's bytes — a lying ShadowSwap can at worst
                    // fail / empty-restore in a fresh shadow as a NOSUPERUSER role, never RCE).
                    match sidecar_managed_apply(is_managed_binding(cfg), head.managed_restore) {
                        SidecarManagedApply::RefuseManagedDataOnly => {
                            // Still REFUSED: a data-only sidecar is an OVERLAY into the target's
                            // EXISTING live schema (rows into tables that must already exist) — there
                            // is no atomic shadow+swap for an overlay (the shadow is a FRESH db, not
                            // the live schema), and a direct apply would run the untrusted dump as the
                            // bootstrap superuser. A least-privilege overlay apply is a pending
                            // follow-up (OPEN questions: grant surface on LIVE tenant tables,
                            // FK/trigger ordering without superuser, non-atomic partial-apply
                            // semantics). Fail-closed.
                            return Err(Perr::Unavailable(format!(
                                "import refused: a data-only restore of MANAGED pg database \
                                 ({db:?}) is not supported — it would overlay the untrusted dump \
                                 onto the live schema as the bootstrap superuser (RCE risk), with no \
                                 atomic shadow+swap; a least-privilege data-only/overlay apply is a \
                                 pending follow-up. Re-export as a FULL bundle, or import into an \
                                 external (bring-your-own-URL) binding."
                            )));
                        }
                        SidecarManagedApply::ManagedShadowSwap => {
                            // NOW SAFE: a FULL managed sidecar dump (a Shared tenant's pg export is
                            // framed sidecar/non-chunked; also any FULL dedicated dump staged
                            // sidecar). Apply it through the SAME non-superuser ephemeral-role +
                            // shadow + atomic-swap mechanism the chunked path uses — the untrusted
                            // `-Fc` dump is applied ONLY as the ephemeral NOSUPERUSER role into a
                            // shadow db, then the verified shadow is atomically swapped into the
                            // self-provisioned target (so the bootstrap superuser never applies a
                            // byte of it, and the target is replaced atomically — never a partial
                            // live overlay).
                            let stage_dir = temp.parent().ok_or_else(|| {
                                Perr::Other("sidecar pg member temp has no parent dir".into())
                            })?;
                            self.pg_sidecar_shadow_restore(project, db, cfg, temp, stage_dir)
                                .await?;
                        }
                        SidecarManagedApply::External => {
                            // EXTERNAL bring-your-own-URL binding: the OPERATOR'S OWN database +
                            // credential (their trust boundary, not our managed cluster) — apply the
                            // dump directly. Capture stderr via `sh -c '… 2>&1'` so a failed restore
                            // is diagnosable instead of a causeless "exited N" (run_ephemeral drops
                            // stderr on nonzero).
                            let inv = pg_restore_invocation(&conn, overlay);
                            let merged = merge_stderr_argv(&inv.argv);
                            let outfile = temp.with_extension("restore.out");
                            let code = self
                                .run_sql_client(&image, &merged, &inv.env, Some(temp), &outfile)
                                .await?;
                            if code != 0 {
                                let diag = tokio::fs::read_to_string(&outfile)
                                    .await
                                    .unwrap_or_default();
                                let _ = tokio::fs::remove_file(&outfile).await;
                                return Err(Perr::Other(format!(
                                    "pg_restore for {db:?} exited {code}: {}",
                                    diag.trim()
                                )));
                            }
                            let _ = tokio::fs::remove_file(&outfile).await;
                        }
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
                // Clone self-provision — mirror of the PgDump arm above (same seam, same
                // apply-gating rationale).
                if opts.apply {
                    self.ensure_target_db_provisioned(project, db, cfg).await?;
                }
                let (conn, image, _ver) = self.resolve_mysql(project, db, cfg).await?;
                if overlay {
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
                    // HIGH-1 (mirror of the pg sidecar arm, same engine-agnostic classifier): a
                    // SIDECAR mysql member is ATTACKER-CRAFTED and must NEVER be applied as the
                    // binding's configured user, which on a MANAGED co-located server is the BOOTSTRAP
                    // SUPERUSER — a crafted `LOAD DATA INFILE`/`INTO OUTFILE`/privileged routine would
                    // then execute = RCE. `sidecar_managed_apply` encodes the (managed × ManagedRestore)
                    // policy; the confinement is NON-SUPERUSER-APPLY, not DDL/flag inspection.
                    match sidecar_managed_apply(is_managed_binding(cfg), head.managed_restore) {
                        SidecarManagedApply::RefuseManagedDataOnly => {
                            // STILL REFUSED (the RCE guard, preserved): a data-only/Overlay restore is
                            // an OVERLAY into the target's EXISTING live schema — there is no atomic
                            // shadow+swap for an overlay (the shadow is a FRESH db, not the live
                            // schema), and a direct apply would run the untrusted dump as the bootstrap
                            // superuser. A least-privilege overlay apply is a pending follow-up.
                            // Fail-closed.
                            return Err(Perr::Unavailable(format!(
                                "import refused: a data-only restore of MANAGED mysql database \
                                 ({db:?}) is not supported — it would overlay the untrusted dump \
                                 onto the live schema as the bootstrap superuser (RCE risk), with no \
                                 atomic shadow+swap; a least-privilege data-only/overlay apply is a \
                                 pending follow-up. Re-export as a FULL bundle, or import into an \
                                 external (bring-your-own-URL) binding."
                            )));
                        }
                        SidecarManagedApply::ManagedShadowSwap => {
                            // NOW SAFE: a FULL managed sidecar mysql dump — a Shared tenant's mysql
                            // export is framed sidecar/non-chunked (a dedicated/Single managed
                            // ShadowSwap is framed chunked and never reaches this arm). Apply it
                            // through the SAME non-superuser ephemeral-user + shadow + atomic-swap
                            // mechanism the chunked path uses — the untrusted dump is applied ONLY as
                            // the ephemeral least-privilege user into a shadow db, then the verified
                            // shadow is atomically swapped into the self-provisioned per-tenant target.
                            let stage_dir = temp.parent().ok_or_else(|| {
                                Perr::Other("sidecar mysql member temp has no parent dir".into())
                            })?;
                            self.mysql_sidecar_shadow_restore(project, db, cfg, temp, stage_dir)
                                .await?;
                        }
                        SidecarManagedApply::External => {
                            // EXTERNAL bring-your-own-URL binding: the operator's OWN database +
                            // credential (their trust boundary) — apply the dump directly. Capture the
                            // mysql client's stderr via `sh -c '… 2>&1'` so a failed restore is
                            // diagnosable, not a causeless "exited N" (run_ephemeral drops stderr on
                            // nonzero).
                            let inv = mysql_restore_invocation(&conn, overlay);
                            let merged = merge_stderr_argv(&inv.argv);
                            let outfile = temp.with_extension("myrestore.out");
                            let code = self
                                .run_sql_client(&image, &merged, &inv.env, Some(temp), &outfile)
                                .await?;
                            if code != 0 {
                                let diag = tokio::fs::read_to_string(&outfile)
                                    .await
                                    .unwrap_or_default();
                                let _ = tokio::fs::remove_file(&outfile).await;
                                return Err(Perr::Other(format!(
                                    "mysql restore for {db:?} exited {code}: {}",
                                    diag.trim()
                                )));
                            }
                            let _ = tokio::fs::remove_file(&outfile).await;
                        }
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
                if head.scope.is_data_only() {
                    // A data-plane bundle should not carry a KV slice; ignore one if present
                    // (the post-stream note records that KV is not imported for a data-plane bundle).
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
                // SYSTEM-PRINCIPAL NEUTRALIZATION (Security F3, release-gating): `project import` is
                // `Project·Admin`-gated exactly like `project sync`, so the control-plane slice must
                // never WRITE a site's `current-principal/<site>` (`system:<id>`) marker — that would
                // let a tenant Project·Admin GRANT the node-global System principal to a site without
                // holding System·Admin (forged bundle, or inherited source marker). Strip it here,
                // fail-closed (the authoritative dest-side drop, mirroring the sync endpoint); the
                // marker may only be (re)granted by a dest-side System·Admin activation.
                let neutralized = boatramp_core::project_export::strip_system_principal_markers(
                    &mut decoded.entries,
                );
                if !neutralized.is_empty() {
                    tracing::warn!(
                        project = %project,
                        count = neutralized.len(),
                        "project import: dropped system-principal marker(s) from the control-plane \
                         KV slice (a Project·Admin import never grants a site the System principal; \
                         re-grant via a dest-side System·Admin activation)"
                    );
                }
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
            MemberKind::KvDelta => {
                // The control-plane KV DELTA slice (a delta bundle only): the upserts + tombstones
                // since the base. A data-plane bundle carries no KV, so ignore one if present.
                if head.scope.is_data_only() {
                    return Ok(());
                }
                // adopt must have installed the source KEK before any sealed KV byte is written
                // (same ordering invariant as the full `Kv` arm).
                if matches!(opts.identity, IdentityChoice::Adopt { .. }) && !*saw_identity {
                    return Err(Perr::Other(
                        "--identity adopt requires a bundle exported with --include-identity \
                         (no identity member present); use --identity fresh"
                            .into(),
                    ));
                }
                let bytes = tokio::fs::read(temp).await.map_err(other)?;
                let delta = boatramp_core::project_delta::decode_kv_delta(&bytes).map_err(other)?;

                // UPSERTS: re-key to the TARGET project + the SAME fail-closed tenancy enforcement
                // as a full KV slice (the upserts are attacker-influenceable — a delta crosses the
                // same trust boundary — so they must be target-scoped before any write).
                let mut upserts = delta.upserts;
                boatramp_core::project_export::rekey_entries_to_target(
                    &mut upserts,
                    source_project,
                    project,
                );
                boatramp_core::project_export::enforce_target_scoped_kv(
                    &upserts,
                    ProjectRef::new(project),
                )
                .map_err(Perr::Other)?;
                // SYSTEM-PRINCIPAL NEUTRALIZATION (Security F3): the delta's UPSERTS can carry a
                // `current-principal/<site>` marker exactly like a full slice — strip it fail-closed
                // (a delta tombstone that DELETES the marker is safe and left alone: it only ever
                // CLEARS authority). Same authoritative dest-side drop as the full-slice arm.
                let neutralized =
                    boatramp_core::project_export::strip_system_principal_markers(&mut upserts);
                if !neutralized.is_empty() {
                    tracing::warn!(
                        project = %project,
                        count = neutralized.len(),
                        "project import (delta): dropped system-principal marker(s) from the \
                         control-plane KV delta upserts (never grant System via a Project·Admin seam)"
                    );
                }

                // TOMBSTONES: a deleted key is equally attacker-influenceable; a tombstone that
                // escaped the target's owned scope would be a CROSS-TENANT DELETE. Re-key each then
                // REFUSE fail-closed any key not under the target's owned prefixes.
                let mut delete_keys = Vec::with_capacity(delta.tombstones.len());
                for k in &delta.tombstones {
                    let rk =
                        boatramp_core::project_export::rekey_owned_key(k, source_project, project);
                    if !boatramp_core::project_export::project_owns_key(
                        &rk,
                        ProjectRef::new(project),
                    ) {
                        return Err(Perr::Other(format!(
                            "control-plane KV delta import refused: tombstone {k:?} is outside the \
                             target project {project}'s owned scope after re-key — a delta must not \
                             delete another tenant's or a global (routing / TLS / daemon) key"
                        )));
                    }
                    delete_keys.push(rk);
                }

                if opts.apply {
                    // A delta OVERLAYS the already-restored base, so the KV dest is non-pristine by
                    // design — force the overlay (the base restore enforced the fresh-target gate).
                    match boatramp_core::kv_dump::apply_import(self.kv.as_ref(), &upserts, true)
                        .await
                    {
                        Ok(rep) => {
                            report.kv_records += rep.written;
                            report.kv_verified += rep.verified;
                        }
                        Err(e) => return Err(other(e)),
                    }
                    for k in &delete_keys {
                        self.kv.delete_checkpointed(k).await.map_err(other)?;
                    }
                } else {
                    report.kv_records += upserts.len();
                }
                report.notes.push(format!(
                    "kv delta: {} upsert(s), {} tombstone(s)",
                    upserts.len(),
                    delete_keys.len()
                ));
            }
            MemberKind::BlobTombstone => {
                // The blob tombstone list (a delta bundle only): blob storage keys deleted since
                // the base. Each key is stored under the SOURCE scope (`hblob/<source>/…`); re-key
                // to the target + REFUSE fail-closed any wrong-scope key (cross-tenant delete),
                // reusing the same `blobs/`-prefixed re-qualify the add path uses.
                let bytes = tokio::fs::read(temp).await.map_err(other)?;
                let keys =
                    boatramp_core::project_delta::decode_blob_tombstones(&bytes).map_err(other)?;
                let mut deleted = 0u64;
                for storage_key in &keys {
                    let target_key =
                        target_blob_key(&format!("blobs/{storage_key}"), source_project, project)?;
                    if opts.apply {
                        self.blobs.delete(&target_key).await.map_err(other)?;
                    }
                    deleted += 1;
                }
                report
                    .notes
                    .push(format!("blob delta: {deleted} tombstone(s)"));
            }
            // SQL TRUE-delta members (the SQL true-delta program, PLAN-sql-true-delta.md). The pg
            // WAL true-delta is REPLAYED onto the restored base inside the atomic shadow by
            // `restore_pg_true_delta_in_chain` (the delta-chain import SKIPS a managed `PgWalDelta`
            // here and hands it to that pass). So this arm is reached ONLY by a path that does not
            // run the shadow pass — a `PgWalDelta` in a non-delta bundle, a non-managed pg binding,
            // or the (unbuilt) mysql binlog / libsql changeset engines — all of which this build
            // cannot faithfully restore, so it refuses loudly (never a silent/partial restore).
            MemberKind::PgWalDelta | MemberKind::MysqlBinlogDelta | MemberKind::LibsqlChangeset => {
                return Err(Perr::Other(format!(
                    "this build cannot restore a SQL true-delta member ({:?}) here — a pg WAL delta \
                     is replayed only via the managed-pg atomic-shadow chain restore; the {} replay \
                     engine is not available on this path (SQL true-delta program)",
                    spec.kind,
                    match spec.kind {
                        MemberKind::PgWalDelta => "Postgres WAL (non-managed/non-chain)",
                        MemberKind::MysqlBinlogDelta => "MySQL binlog",
                        _ => "libsql changeset",
                    }
                )));
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // T3 Phase 1 — resumable, chained export (member-object layout)
    //
    // The default export streams a single tar to a forward-only `AsyncWrite` sink, so an
    // interrupted export restarts from scratch. The resumable mode lays the SAME members
    // out as one object per member under a local directory, each written atomically with
    // its size+SHA, so a re-run RESUMES: an already-complete member is skipped (presence +
    // SHA), a partial one is re-produced. Import reads the directory and restores member by
    // member in the MANIFEST's authoritative order, reusing the SAME per-member producers
    // (`stage_job` / `open_chunked_producer`) and restorer (`restore_member`) as the tar
    // path — so the per-project tenancy scoping is byte-for-byte identical and unweakened:
    // the KV slice's `scope_entries_to_project` lives in `stage_job`, and the import
    // re-key / target-scope enforcement lives in `restore_member`. This mode adds NO new
    // data path to a tenant's bytes; it only changes the CONTAINER (a dir of objects).
    //
    // HONEST LIMIT: resume is per-MEMBER, not intra-member — a huge single pg_dump redumps
    // on resume. The win is a many-member export (thousands of blobs, many sites) and
    // surviving a drop BETWEEN members. (An S3-multipart target + byte-range intra-member
    // resume are Phase 2; a delta-onto-a-base export is a separate follow-on program.)

    /// Resumable export to a local directory `dir` (member-object layout). Writes — or, on
    /// resume, reads — an authoritative `MANIFEST`, then one object per member, skipping any
    /// already present + SHA-valid. `dir` is on the NODE's filesystem (a persistent/mounted
    /// path), so a resume actually avoids re-producing the expensive members.
    /// Core resumable export to an ALREADY-CONFINED absolute `dir` (the trait method
    /// [`ProjectExport::export_resumable`] confines an operator-named subdir under the
    /// configured base, then calls this). See the member-object layout + per-member resume
    /// in the body.
    pub async fn export_resumable_dir(
        &self,
        project: &str,
        opts: &ExportOptions,
        dir: &Path,
    ) -> Result<(), Perr> {
        check_project_slug(project)?;
        if opts.scope.is_data_only() && opts.include_identity {
            return Err(Perr::Other(
                "--data-only and --include-identity are mutually exclusive".into(),
            ));
        }
        tokio::fs::create_dir_all(dir).await.map_err(other)?;
        let created_at = now_secs();
        let session = self
            .work_dir
            .join(format!("export-res-{project}-{created_at}"));
        let stage_dir = session.join("stage");
        tokio::fs::create_dir_all(&stage_dir).await.map_err(other)?;

        // PLAN: a FULL export reuses `plan_export`; a DELTA export (`opts.delta`) diffs the
        // current state against the base chain's frontier and emits delta members (KV delta +
        // blob adds/tombstones + SQL full-dump fallback). Both return the ordered member set, the
        // per-member jobs, the source, and — for a delta — the `DeltaInfo` the manifest records.
        let (specs, jobs, source, delta_info) = match &opts.delta {
            None => {
                let (s, j, src) = self.plan_export(project, opts, created_at).await?;
                (s, j, src, None)
            }
            Some(req) => {
                let (s, j, src, di) = self
                    .plan_delta_export(project, opts, req, created_at)
                    .await?;
                (s, j, src, Some(di))
            }
        };

        // The MANIFEST is AUTHORITATIVE. First run: write it. Resume: read it and use ITS
        // member set (members added since are ignored; nothing not in it can be produced) —
        // strict, MANIFEST-wins. Refuse a dir that already holds another project's manifest.
        let manifest_path = dir.join(project_bundle::MANIFEST_PATH);
        let specs = if tokio::fs::try_exists(&manifest_path).await.map_err(other)? {
            let bytes = tokio::fs::read(&manifest_path).await.map_err(other)?;
            let m: project_bundle::StreamManifest = serde_json::from_slice(&bytes)
                .map_err(|e| Perr::Other(format!("read resumable MANIFEST: {e}")))?;
            if m.source.project != source.project {
                return Err(Perr::Other(format!(
                    "resumable export dir holds a MANIFEST for project {:?}, not {:?} — \
                     refusing to mix projects in one dir",
                    m.source.project, source.project
                )));
            }
            m.members
        } else {
            let m = project_bundle::StreamManifest {
                magic: project_bundle::BUNDLE_MAGIC.to_string(),
                format_version: project_bundle::BUNDLE_FORMAT_VERSION_V3,
                created_at,
                data_only: opts.scope.is_data_only(),
                managed_restore: Some(opts.managed_restore),
                source: source.clone(),
                members: specs.clone(),
                delta: delta_info,
            };
            let bytes = serde_json::to_vec_pretty(&m)
                .map_err(|e| Perr::Other(format!("encode MANIFEST: {e}")))?;
            write_atomic(&manifest_path, &bytes).await?;
            specs
        };

        // SQL true-delta capture (PLAN-sql-true-delta Stage 2): a BASE (full) resumable export of a
        // `delta_capture` managed pg db mints the capture's ephemeral REPLICATION role + the
        // `FOR ALL TABLES` publication NOW (before the slot's consistent point). The pgoutput SLOT
        // itself is created LATER, SNAPSHOT-PINNED, by `produce_pg_capture_base` in the member loop,
        // over a held `replication=database` session across `pg_dump --snapshot` — so the base dump
        // and the slot share one consistent point and the base↔WAL overlap window is CLOSED. A delta
        // export (`opts.delta`) does not create slots; it drains the PARENT's slot (see
        // `plan_delta_export`).
        if opts.delta.is_none() {
            self.pg_capture_base_slots(project, dir, &stage_dir).await;
        }

        // Produce each member that is not already complete.
        for (idx, spec) in specs.iter().enumerate() {
            let obj = dir.join(member_object_name(idx));
            let meta = dir.join(member_meta_name(idx));
            if member_object_valid(&obj, &meta).await? {
                continue; // resume: already produced + SHA-valid.
            }
            // Clear any stale partial before re-producing.
            let _ = tokio::fs::remove_file(&obj).await;
            let _ = tokio::fs::remove_file(dir.join(member_part_name(idx))).await;
            // SQL true-delta (mysql binlog, PLAN-sql-true-delta Stage 3): a BASE (full) resumable
            // export of a capture-eligible managed mysql db dumps it SNAPSHOT-PINNED (`--source-data`,
            // SQL_LOG_BIN stripped) so a later incremental delta can stream the binlog since the
            // base's recorded GTID. Produced specially (staged + stripped) regardless of the spec's
            // framing — in the resumable layout every member is one `m{idx}` object, so framing is
            // irrelevant here. A delta export (`opts.delta`) keeps the normal production (it drains
            // the parent's binlog at plan time, see `plan_delta_export`).
            let capture_base_mysql = opts.delta.is_none()
                && spec.kind == MemberKind::MysqlDump
                && db_from_mysql_member(&spec.path)
                    .and_then(|d| self.databases.get(d))
                    .is_some_and(Self::mysql_capture_eligible);
            // SQL true-delta (pg WAL, PLAN-sql-true-delta Stage 2): a BASE export of a
            // capture-eligible managed pg db dumps it SNAPSHOT-PINNED to its just-created capture
            // slot (close the base↔WAL overlap window) — produced specially regardless of the spec's
            // framing (every resumable member is one `m{idx}` object). A delta export keeps the
            // normal production (it drains the parent's slot at plan time).
            let capture_base_pg = opts.delta.is_none()
                && spec.kind == MemberKind::PgDump
                && db_from_pg_member(&spec.path)
                    .and_then(|d| self.databases.get(d))
                    .is_some_and(Self::pg_capture_eligible);
            let digest = if capture_base_mysql {
                let db = db_from_mysql_member(&spec.path).expect("mysql member path");
                let cfg = self.databases.get(db).expect("capture-eligible db").clone();
                self.produce_mysql_capture_base(project, dir, idx, db, &cfg, &stage_dir)
                    .await?
            } else if capture_base_pg {
                let db = db_from_pg_member(&spec.path).expect("pg member path");
                let cfg = self.databases.get(db).expect("capture-eligible db").clone();
                self.produce_pg_capture_base(project, dir, idx, db, &cfg, &stage_dir)
                    .await?
            } else {
                let job = jobs.get(&spec.path);
                match spec.framing {
                    project_bundle::MemberFraming::Sidecar => {
                        let job = job.ok_or_else(|| {
                            Perr::Other(format!("resumable export: no stage job for {}", spec.path))
                        })?;
                        let tmp = self.stage_job(project, job, &stage_dir, idx).await?;
                        let d = write_member_from_file(dir, idx, &tmp).await?;
                        let _ = tokio::fs::remove_file(&tmp).await;
                        d
                    }
                    project_bundle::MemberFraming::ChunkedTrailer => {
                        let producer = self.open_chunked_producer(job)?;
                        write_member_from_producer(dir, idx, producer).await?
                    }
                }
            };
            let meta_bytes = serde_json::to_vec(&digest)
                .map_err(|e| Perr::Other(format!("encode member meta: {e}")))?;
            write_atomic(&meta, &meta_bytes).await?;
        }

        // SQL true-delta capture (mysql binlog, PLAN-sql-true-delta Stage 3): a BASE export records
        // the snapshot GTID + start binlog of each capture-eligible managed mysql db in
        // `mysql_capture.json` (parsed from the just-produced base member headers), so a later
        // incremental delta can stream the binlog since the base. (The mysql analogue of
        // `pg_capture_base_slots` — but AFTER member production, because the coordinate lives in the
        // base dump itself; there is no long-lived slot to create beforehand.)
        if opts.delta.is_none() {
            self.mysql_capture_base_gtids(project, dir, &specs).await;
        }

        // SQL true-delta capture (libsql changeset, SQL true-delta program, Stage 4): snapshot every
        // local libsql site's DB into `libsql_capture/` + record its sha in `libsql_capture.json`.
        // Run on BOTH base AND delta exports (unlike pg/mysql) so a FIXED base snapshot is always
        // available to diff against (differential, vs the root) AND each delta leaves a fresh snapshot
        // for the next link (incremental). Best-effort: a site that fails to snapshot simply
        // full-dumps at the next delta. Feature-gated — off builds never capture (today's behaviour).
        #[cfg(feature = "sql-delta-libsql")]
        self.libsql_capture_base_snapshots(project, dir).await;

        let _ = tokio::fs::remove_dir_all(&session).await;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Incremental / delta export (follow-on program; owner-RESOLVED 2026-10-25)
    //
    // A DELTA export reuses the resumable member-object layout + per-member resume, but its
    // member SET is the DIFF against a referenced base: only the KV upserts/tombstones and the
    // changed/new blobs (+ blob tombstones) ride, while the SQL families full-dump as the
    // all-families-consistent fallback (decision 3) until their true-deltas land (decisions 1/2,
    // scaffolded in `boatramp_core::project_delta`). `--mode differential` diffs vs a FIXED base;
    // `--mode incremental` diffs vs the parent (a chain). Restore resolves the chain and applies
    // base → each delta in order (decision 5). The pure diff/replay algebra lives in core; this
    // driver wires it to the live KV scan + blob store + the base chain's member objects.
    // -----------------------------------------------------------------------

    /// Plan a DELTA export: resolve the base/parent chain, replay its frontier (KV key→value +
    /// blob key→{size,sha}), diff the CURRENT state against it, and emit the delta member set — a
    /// KV delta member (upserts + tombstones), the new/changed blobs as full members
    /// (adds-as-full-members), a blob-tombstone member for deletes, and the SQL families as FULL
    /// dumps (the all-families-consistent fallback). Returns the ordered specs, the per-member
    /// jobs, the source, and the `DeltaInfo` the manifest records.
    async fn plan_delta_export(
        &self,
        project: &str,
        opts: &ExportOptions,
        req: &boatramp_core::project_delta::DeltaRequest,
        created_at: u64,
    ) -> Result<
        (
            Vec<MemberSpec>,
            HashMap<String, StageJob>,
            SourceInfo,
            boatramp_core::project_delta::DeltaInfo,
        ),
        Perr,
    > {
        use boatramp_core::project_delta as pd;

        if opts.scope.is_data_only() {
            return Err(Perr::Other(
                "delta export is not supported for a --data-only bundle (a delta carries the \
                 control-plane KV delta, which a data-only bundle excludes)"
                    .into(),
            ));
        }
        if opts.include_identity {
            return Err(Perr::Other(
                "delta export does not carry the identity transport container; include identity \
                 only in the FULL base bundle (import it with --identity adopt), then chain deltas"
                    .into(),
            ));
        }

        // Resolve the base/parent resumable dir (confined under the node base) + walk its chain to
        // the ROOT full bundle. Differential requires a FULL base; incremental may chain a delta.
        let base_dir = self
            .resolve_resumable_dir(&req.base_reference, false)
            .await?;
        let base_manifest = self.read_resumable_manifest(&base_dir).await?;
        if matches!(req.mode, pd::DeltaMode::Differential) && base_manifest.delta.is_some() {
            return Err(Perr::Other(format!(
                "differential delta requires a FULL base bundle, but {:?} is itself a delta — use \
                 --mode incremental to chain onto a delta",
                req.base_reference
            )));
        }
        let chain = self.resolve_chain(&base_dir, &base_manifest).await?;
        if chain[0].1.data_only {
            return Err(Perr::Other(
                "delta export refused: the root base bundle is --data-only; a delta needs a FULL \
                 base (with the control-plane KV slice) to diff against"
                    .into(),
            ));
        }
        if chain[0].1.source.project != project {
            return Err(Perr::Other(format!(
                "delta export refused: the base chain's root is for project {:?}, not {project:?}",
                chain[0].1.source.project
            )));
        }

        // Delta-capture readiness (PLAN-sql-true-delta Stage 1b): `delta_capture` flips a
        // START-ONLY server setting (`wal_level=logical` / `--log-bin`), so an operator who
        // enabled it but has not yet RESTARTED the database (`boatramp db restart`) would
        // otherwise silently get a full-dump delta member for it with no indication why — the
        // capture machinery's own fallback is deliberately non-fatal (true-delta is
        // best-effort). An explicit `delta_capture` opt-in is a stated expectation of a true
        // delta, so refuse LOUD here, up front, rather than let it fall through to that silent
        // fallback. Every capture-eligible db covered by this export is checked; a connectivity
        // failure checking it is NOT this condition (it is left to surface on its own, later).
        for (db, cfg) in &self.databases {
            if Self::pg_capture_eligible(cfg) {
                self.assert_pg_delta_capture_live(project, db).await?;
            } else if Self::mysql_capture_eligible(cfg) {
                self.assert_mysql_delta_capture_live(project, db).await?;
            }
        }

        // Frontier = replay the chain (metadata only): the effective KV + blob state at the base.
        let (kv_frontier, blob_frontier) = self.compute_chain_frontier(&chain).await?;

        // The FULL plan (SQL full-dumps + every blob job + the KV member), then transformed into
        // the delta member set.
        let full_opts = ExportOptions {
            delta: None,
            ..opts.clone()
        };
        let (full_specs, mut full_jobs, source) =
            self.plan_export(project, &full_opts, created_at).await?;

        // --- KV delta: diff the current scoped scan against the frontier ---
        let all_kv = boatramp_core::kv_dump::scan_dumpable(self.kv.as_ref())
            .await
            .map_err(other)?;
        let current_kv = boatramp_core::project_export::scope_entries_to_project(
            all_kv,
            ProjectRef::new(project),
        );
        let base_kv_entries: Vec<boatramp_core::kv::KvDumpEntry> = kv_frontier
            .iter()
            .map(|(k, v)| boatramp_core::kv::KvDumpEntry {
                key: k.clone(),
                value: v.clone(),
                version: 1,
            })
            .collect();
        let kv_delta = pd::compute_kv_delta(&base_kv_entries, &current_kv);
        let kv_delta_bytes = pd::encode_kv_delta(&kv_delta, created_at);

        // --- current blob metadata (sizes) for the cheap diff pre-filter ---
        let current_blob_metas = self
            .blobs
            .list(&blob_project_prefix(project))
            .await
            .map_err(other)?;
        let mut current_sizes: HashMap<String, Option<u64>> = HashMap::new();
        let mut current_keys: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for m in &current_blob_metas {
            current_sizes.insert(m.key.clone(), m.size);
            current_keys.insert(m.key.clone());
        }

        // --- SQL true-delta (pg WAL) setup: only an INCREMENTAL delta whose PARENT base recorded a
        // capture slot (in its `pg_capture.json` sidecar) can ship a WAL delta; a differential delta
        // keeps the full-dump fallback (a single advancing slot cannot re-emit the same base→N
        // interval for every differential delta). The drain is a live, slot-advancing operation, so
        // it runs here at plan time and its bytes ride as a `StageJob::PgWalDelta`.
        let parent_capture = if matches!(req.mode, pd::DeltaMode::Incremental) {
            read_pg_capture_sidecar(&base_dir).await
        } else {
            None
        };
        // The mysql analogue (PLAN-sql-true-delta Stage 3): only an INCREMENTAL delta whose PARENT
        // base recorded a snapshot coordinate (in `mysql_capture.json`) can ship a binlog delta.
        let parent_mysql_capture = if matches!(req.mode, pd::DeltaMode::Incremental) {
            read_mysql_capture_sidecar(&base_dir).await
        } else {
            None
        };
        // The libsql analogue (SQL true-delta program, Stage 4). Unlike pg/mysql (a single advancing
        // slot / a one-shot binlog coordinate ⇒ incremental-only), the libsql base is a FIXED FILE
        // snapshot every delta can re-diff, so BOTH modes are eligible: differential diffs each delta
        // vs the root base's stored snapshot; incremental diffs vs the parent's (each export stores a
        // fresh snapshot). Read the capture sidecar from `base_dir` (the fixed base in differential,
        // the parent in incremental) in either mode.
        let parent_libsql_capture = read_libsql_capture_sidecar(&base_dir).await;
        let cap_dir = self
            .work_dir
            .join(format!("delta-capture-{project}-{created_at}"));
        if parent_capture.is_some()
            || parent_mysql_capture.is_some()
            || parent_libsql_capture.is_some()
        {
            tokio::fs::create_dir_all(&cap_dir).await.map_err(other)?;
        }
        let mut any_pg_true_delta = false;
        let mut any_mysql_true_delta = false;
        let mut any_libsql_true_delta = false;

        // --- build the ordered delta member set from the full plan ---
        let mut ordered: Vec<(MemberSpec, StageJob)> = Vec::new();
        for spec in &full_specs {
            match spec.kind {
                MemberKind::Identity => { /* a delta carries no identity (guarded above) */ }
                MemberKind::Kv => {
                    ordered.push((
                        MemberSpec::sidecar(
                            project_bundle::KV_DELTA_MEMBER_PATH.to_string(),
                            MemberKind::KvDelta,
                            None,
                        ),
                        StageJob::KvDelta {
                            bytes: kv_delta_bytes.clone(),
                        },
                    ));
                }
                MemberKind::Blob => {
                    let storage_key = spec
                        .path
                        .strip_prefix("blobs/")
                        .unwrap_or(&spec.path)
                        .to_string();
                    let base_sig = blob_frontier.get(&storage_key);
                    let cur_size = current_sizes.get(&storage_key).copied().flatten();
                    let is_add = match pd::blob_decision_by_size(base_sig, cur_size) {
                        pd::BlobDecision::Add => true,
                        pd::BlobDecision::NeedsContentCheck => match base_sig {
                            // Size matched (or unknown) → content-check: hash the current object.
                            Some(b) => self.blob_sha256(&storage_key).await? != b.sha256,
                            None => true,
                        },
                    };
                    if is_add {
                        // Reuse the full plan's Blob job + spec verbatim (keeps the chunked framing
                        // for a large object) — adds-as-full-members.
                        let job = full_jobs.remove(&spec.path).ok_or_else(|| {
                            Perr::Other(format!(
                                "delta export: no stage job for blob {}",
                                spec.path
                            ))
                        })?;
                        ordered.push((spec.clone(), job));
                    }
                }
                MemberKind::PgDump => {
                    // pg WAL true-delta (PLAN-sql-true-delta Stage 2): if this db is a managed,
                    // capture-eligible binding whose PARENT base recorded a slot, and the schema is
                    // unchanged since the base, DRAIN the slot into a `PgWalDelta` member IN PLACE
                    // OF the full dump. Any miss (not eligible, no parent slot, schema drifted,
                    // slot lost, or the drain fails) FALLS BACK to the full dump — the
                    // all-families-consistent invariant (decision 3) + best-effort true-delta.
                    let db = db_from_pg_member(&spec.path);
                    let wal_member = match (db, parent_capture.as_ref()) {
                        (Some(db), Some(sidecar)) => {
                            self.try_pg_wal_delta(project, db, sidecar, &cap_dir).await
                        }
                        _ => None,
                    };
                    if let Some((bytes, cursor)) = wal_member {
                        any_pg_true_delta = true;
                        let db = db.expect("wal_member implies a parsed db");
                        ordered.push((
                            MemberSpec::sidecar(
                                pgwal_member_path(db),
                                MemberKind::PgWalDelta,
                                None,
                            )
                            .with_sql_cursor(cursor),
                            StageJob::PgWalDelta { bytes },
                        ));
                        // The full dump job for this db is now superseded — drop it.
                        let _ = full_jobs.remove(&spec.path);
                    } else {
                        // SQL full-dump fallback (decision 3): keep the full member verbatim.
                        let job = full_jobs.remove(&spec.path).ok_or_else(|| {
                            Perr::Other(format!("delta export: no stage job for {}", spec.path))
                        })?;
                        ordered.push((spec.clone(), job));
                    }
                }
                MemberKind::MysqlDump => {
                    // mysql binlog true-delta (PLAN-sql-true-delta Stage 3): if this db is a managed,
                    // capture-eligible binding whose PARENT base recorded a snapshot coordinate, and
                    // the schema is unchanged + no DDL in the range, STREAM the binlog since the base
                    // into a `MysqlBinlogDelta` member IN PLACE OF the full dump. Any miss falls back
                    // to the full dump (the all-families-consistent invariant + best-effort delta).
                    let db = db_from_mysql_member(&spec.path);
                    let binlog_member = match (db, parent_mysql_capture.as_ref()) {
                        (Some(db), Some(sidecar)) => {
                            self.try_mysql_binlog_delta(project, db, sidecar, &cap_dir)
                                .await
                        }
                        _ => None,
                    };
                    if let Some((bytes, cursor)) = binlog_member {
                        any_mysql_true_delta = true;
                        let db = db.expect("binlog_member implies a parsed db");
                        ordered.push((
                            MemberSpec::sidecar(
                                mysqlbinlog_member_path(db),
                                MemberKind::MysqlBinlogDelta,
                                None,
                            )
                            .with_sql_cursor(cursor),
                            StageJob::MysqlBinlogDelta { bytes },
                        ));
                        let _ = full_jobs.remove(&spec.path);
                    } else {
                        // SQL full-dump fallback (decision 3): keep the full member verbatim.
                        let job = full_jobs.remove(&spec.path).ok_or_else(|| {
                            Perr::Other(format!("delta export: no stage job for {}", spec.path))
                        })?;
                        ordered.push((spec.clone(), job));
                    }
                }
                MemberKind::Libsql => {
                    // libsql changeset true-delta (SQL true-delta program, Stage 4): if this site's
                    // base recorded a snapshot in the parent's `libsql_capture.json`, and the schema
                    // is unchanged + every table has a PK, DIFF the current DB against that base
                    // snapshot into a `LibsqlChangeset` member IN PLACE OF the full dump. Any miss
                    // (engine not built, no base snapshot, schema drift, diff failure) FALLS BACK to
                    // the full dump — the all-families-consistent invariant + best-effort true-delta.
                    let site = site_from_libsql_member(&spec.path);
                    let cs_member = match (site, parent_libsql_capture.as_ref()) {
                        (Some(site), Some(sidecar)) => match sidecar.sites.get(site) {
                            Some(entry) => {
                                self.try_libsql_changeset_delta(
                                    project, site, entry, &base_dir, &cap_dir,
                                )
                                .await
                            }
                            None => None,
                        },
                        _ => None,
                    };
                    if let Some((bytes, cursor)) = cs_member {
                        any_libsql_true_delta = true;
                        let site = site.expect("cs_member implies a parsed site");
                        ordered.push((
                            MemberSpec::sidecar(
                                libsql_changeset_member_path(project, site),
                                MemberKind::LibsqlChangeset,
                                None,
                            )
                            .with_sql_cursor(cursor),
                            StageJob::LibsqlChangeset { bytes },
                        ));
                        // The full libsql dump for this site is now superseded — drop it.
                        let _ = full_jobs.remove(&spec.path);
                    } else {
                        // SQL full-dump fallback (decision 3): keep the full member verbatim.
                        let job = full_jobs.remove(&spec.path).ok_or_else(|| {
                            Perr::Other(format!("delta export: no stage job for {}", spec.path))
                        })?;
                        ordered.push((spec.clone(), job));
                    }
                }
                MemberKind::KvDelta
                | MemberKind::BlobTombstone
                | MemberKind::PgWalDelta
                | MemberKind::MysqlBinlogDelta
                | MemberKind::LibsqlChangeset => {
                    // plan_export (a FULL plan) never emits delta/true-delta members; unreachable
                    // here. The SQL arm above keeps the full dump (fallback); the per-engine
                    // true-delta capture that would REPLACE a PgDump/MysqlDump/Libsql member with a
                    // PgWalDelta/MysqlBinlogDelta/LibsqlChangeset lands in its own stage.
                }
            }
        }

        // --- blob tombstones: base storage keys gone from the current listing ---
        let base_blob_keys: std::collections::BTreeSet<String> =
            blob_frontier.keys().cloned().collect();
        let tombstones = pd::compute_blob_tombstones(&base_blob_keys, &current_keys);
        if !tombstones.is_empty() {
            ordered.push((
                MemberSpec::sidecar(
                    project_bundle::BLOB_TOMBSTONE_MEMBER_PATH.to_string(),
                    MemberKind::BlobTombstone,
                    None,
                ),
                StageJob::BlobTombstone {
                    bytes: pd::encode_blob_tombstones(&tombstones),
                },
            ));
        }

        // The capture temp dir only held transient psql stdout for the drain — reclaim it.
        let _ = tokio::fs::remove_dir_all(&cap_dir).await;

        let specs: Vec<MemberSpec> = ordered.iter().map(|(s, _)| s.clone()).collect();
        let jobs: HashMap<String, StageJob> =
            ordered.into_iter().map(|(s, j)| (s.path, j)).collect();
        let delta_info = pd::DeltaInfo {
            mode: req.mode,
            base_reference: req.base_reference.clone(),
            base_created_at: base_manifest.created_at,
            // Record a true-delta strategy when at least one SQL member shipped as a true row-delta
            // (so a reader can tell a true row-delta bundle from an all-full-dump fallback); else the
            // all-families full-dump fallback. The per-member `sql_cursor` carries the authoritative
            // per-engine strategy, so when a bundle mixes engines this single hint names pg first.
            sql_strategy: if any_pg_true_delta {
                pd::SqlDeltaKind::PgWalReplay
            } else if any_mysql_true_delta {
                pd::SqlDeltaKind::MysqlBinlogReplay
            } else if any_libsql_true_delta {
                pd::SqlDeltaKind::LibsqlChangeset
            } else {
                pd::SqlDeltaKind::FullDumpFallback
            },
        };
        Ok((specs, jobs, source, delta_info))
    }

    /// Read + parse the `MANIFEST` of a resumable member-object directory.
    async fn read_resumable_manifest(
        &self,
        dir: &Path,
    ) -> Result<project_bundle::StreamManifest, Perr> {
        let manifest_path = dir.join(project_bundle::MANIFEST_PATH);
        let bytes = tokio::fs::read(&manifest_path).await.map_err(|e| {
            Perr::Other(format!(
                "read base/parent MANIFEST at {}: {e}",
                manifest_path.display()
            ))
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Perr::Other(format!("parse base/parent MANIFEST: {e}")))
    }

    /// Resolve a delta CHAIN from `start_dir` (a base or parent) back to the ROOT full bundle,
    /// returning `[root, …, start]` (root first). Walks each manifest's `delta.base_reference`
    /// (confined under the node base), asserting the recorded `base_created_at` matches the
    /// resolved parent — a consistency check that catches a stale or mismatched base (NOT a
    /// cryptographic anti-tamper guarantee: a forged manifest could forge the timestamp too; the
    /// structural defenses are the base-confinement here + the one-source coherence check on
    /// import). Has a cycle/length guard.
    async fn resolve_chain(
        &self,
        start_dir: &Path,
        start_manifest: &project_bundle::StreamManifest,
    ) -> Result<Vec<(PathBuf, project_bundle::StreamManifest)>, Perr> {
        let mut chain = vec![(start_dir.to_path_buf(), start_manifest.clone())];
        let mut guard = 0usize;
        while let Some(di) = chain.last().unwrap().1.delta.clone() {
            guard += 1;
            if guard > 256 {
                return Err(Perr::Other(
                    "delta chain exceeds 256 links (cycle or runaway) — refusing".into(),
                ));
            }
            let parent_dir = self
                .resolve_resumable_dir(&di.base_reference, false)
                .await?;
            let parent_manifest = self.read_resumable_manifest(&parent_dir).await?;
            if parent_manifest.created_at != di.base_created_at {
                return Err(Perr::Other(format!(
                    "delta base mismatch: {:?} records base created_at {} but the resolved base has \
                     {} — refusing a stale or mismatched base",
                    di.base_reference, di.base_created_at, parent_manifest.created_at
                )));
            }
            chain.push((parent_dir, parent_manifest));
        }
        chain.reverse();
        Ok(chain)
    }

    /// Replay a resolved chain `[root, …]` into the effective FRONTIER at its tail: the KV state
    /// (key → value bytes) and the blob state (key → {size, sha256}). Metadata-only — it reads the
    /// root's full KV member + each blob member's recorded `{size,sha}` meta, then applies each
    /// delta's KV upserts/tombstones + blob adds/tombstones in order (the export-side mirror of the
    /// import-side sequential apply).
    async fn compute_chain_frontier(
        &self,
        chain: &[(PathBuf, project_bundle::StreamManifest)],
    ) -> Result<
        (
            BTreeMap<String, Vec<u8>>,
            BTreeMap<String, boatramp_core::project_delta::BlobSig>,
        ),
        Perr,
    > {
        use boatramp_core::project_delta as pd;
        let mut kv: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut blobs: BTreeMap<String, pd::BlobSig> = BTreeMap::new();
        for (dir, m) in chain {
            for (idx, spec) in m.members.iter().enumerate() {
                match spec.kind {
                    MemberKind::Kv => {
                        let bytes = self.read_member_object(dir, idx).await?;
                        let decoded = boatramp_core::kv_dump::decode_dump(&bytes).map_err(other)?;
                        for e in decoded.entries {
                            kv.insert(e.key, e.value);
                        }
                    }
                    MemberKind::KvDelta => {
                        let bytes = self.read_member_object(dir, idx).await?;
                        let delta = pd::decode_kv_delta(&bytes).map_err(other)?;
                        pd::apply_kv_delta_to_frontier(&mut kv, &delta);
                    }
                    MemberKind::Blob => {
                        let storage_key = spec
                            .path
                            .strip_prefix("blobs/")
                            .unwrap_or(&spec.path)
                            .to_string();
                        let meta = self.read_member_meta(dir, idx).await?;
                        blobs.insert(
                            storage_key,
                            pd::BlobSig {
                                size: meta.size,
                                sha256: meta.sha256,
                            },
                        );
                    }
                    MemberKind::BlobTombstone => {
                        let bytes = self.read_member_object(dir, idx).await?;
                        for k in pd::decode_blob_tombstones(&bytes).map_err(other)? {
                            blobs.remove(&k);
                        }
                    }
                    // SQL/libsql/identity do not contribute to the KV/blob frontier.
                    _ => {}
                }
            }
        }
        Ok((kv, blobs))
    }

    /// Read the whole member object `m{idx}` bytes from a resumable dir.
    async fn read_member_object(&self, dir: &Path, idx: usize) -> Result<Vec<u8>, Perr> {
        tokio::fs::read(dir.join(member_object_name(idx)))
            .await
            .map_err(|e| Perr::Other(format!("read member object m{idx:05}: {e}")))
    }

    /// Read + parse the `{size, sha256}` meta sidecar of member `idx`.
    async fn read_member_meta(
        &self,
        dir: &Path,
        idx: usize,
    ) -> Result<project_bundle::MemberMeta, Perr> {
        let bytes = tokio::fs::read(dir.join(member_meta_name(idx)))
            .await
            .map_err(|e| Perr::Other(format!("read member meta m{idx:05}: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Perr::Other(format!("parse member meta m{idx:05}: {e}")))
    }

    /// Stream a blob from the source store and return its lowercase-hex SHA-256 (the authoritative
    /// blob content comparator for the delta diff). Never buffers the whole object.
    async fn blob_sha256(&self, storage_key: &str) -> Result<String, Perr> {
        let obj = self.blobs.get(storage_key).await.map_err(other)?;
        let mut body = obj.body;
        let mut hasher = Sha256::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(other)?;
            hasher.update(chunk.as_ref());
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Restore a DELTA member-object directory: resolve the full chain `[root, …, this]` and apply
    /// base → each delta in order (owner decision 5 — sequential apply). The root's KV+blobs are
    /// restored in full; each delta's KV-delta + blob adds/tombstones overlay; the SQL families are
    /// applied ONLY from the NEWEST delta (its full-dump fallback supersedes the base/intermediate
    /// SQL — so a huge DB is restored once, not once per link). Identity members are not applied on
    /// the delta path (a delta clone is `--identity fresh` data movement; adopt-recovery restores
    /// the base bundle directly).
    async fn import_delta_chain(
        &self,
        project: &str,
        this_dir: &Path,
        this_manifest: &project_bundle::StreamManifest,
        opts: &ImportOptions,
    ) -> Result<ImportReport, Perr> {
        let di = this_manifest
            .delta
            .as_ref()
            .ok_or_else(|| Perr::Other("import_delta_chain called on a non-delta bundle".into()))?;
        let base_dir = self
            .resolve_resumable_dir(&di.base_reference, false)
            .await?;
        let base_manifest = self.read_resumable_manifest(&base_dir).await?;
        let mut chain = self.resolve_chain(&base_dir, &base_manifest).await?; // [root … parent]
        chain.push((this_dir.to_path_buf(), this_manifest.clone())); // … this
        if chain[0].1.delta.is_some() {
            return Err(Perr::Other(
                "delta chain does not terminate in a FULL base bundle — refusing".into(),
            ));
        }

        // Chain coherence: every link must share ONE source project. A delta is only meaningful
        // against a base from the same logical source, and `restore_member` re-keys each member
        // from ITS OWN `source.project` → the target — so links that disagree on origin would
        // re-key from different source prefixes and restore an incoherent mix. (The target may
        // still differ from the source: a cross-project clone re-keys the whole coherent chain to
        // `project`. What we forbid is a chain spliced from two different sources.) This defends a
        // resumable chain assembled on an addressable target against a grafted-in foreign base.
        let root_src = &chain[0].1.source;
        if let Some((bad_dir, bad)) = chain
            .iter()
            .find(|(_, m)| m.source.project != root_src.project || m.source.site != root_src.site)
        {
            return Err(Perr::Other(format!(
                "delta import refused: chain link {:?} is for source {:?}/{:?}, but the chain root \
                 is {:?}/{:?} — a delta chain must share one source",
                bad_dir, bad.source.project, bad.source.site, root_src.project, root_src.site
            )));
        }

        // The SAME fresh-target guard as a full resumable import (unless overwrite).
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
                        "import refused: target project {project:?} already has control-plane data \
                         under {prefix:?}; pass overwrite=true"
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
                     overwrite=true"
                )));
            }
        }

        let session = self
            .work_dir
            .join(format!("import-delta-{project}-{}", now_secs()));
        tokio::fs::create_dir_all(&session).await.map_err(other)?;

        let mut report = ImportReport::default();
        let mut saw_identity = false;
        let last = chain.len() - 1;
        // Sites whose libsql family is restored by the atomic changeset pass
        // (`restore_libsql_true_delta_in_chain`) AFTER this loop: any site carrying a
        // `LibsqlChangeset` member anywhere in the chain. Their base full `Libsql` member is replayed
        // by that pass too (base snapshot + changesets), so the main loop must SKIP it — exactly as a
        // managed pg/mysql full dump is skipped. A libsql site with NO changeset (pure full-dump
        // fallback) is not here, so it still restores via `restore_member` (newest link). Computed
        // even when the engine feature is off: a bundle built elsewhere may carry changeset members,
        // and the pass below then refuses loudly rather than silently full-dumping the stale base.
        let libsql_changeset_sites: std::collections::BTreeSet<String> = chain
            .iter()
            .flat_map(|(_, m)| m.members.iter())
            .filter(|s| s.kind == MemberKind::LibsqlChangeset)
            .filter_map(|s| site_from_libsql_changeset_member(&s.path).map(str::to_string))
            .collect();
        for (pos, (dir, m)) in chain.iter().enumerate() {
            let is_newest = pos == last;
            for (idx, spec) in m.members.iter().enumerate() {
                let obj = dir.join(member_object_name(idx));
                let meta = dir.join(member_meta_name(idx));
                if !member_object_valid(&obj, &meta).await? {
                    let _ = tokio::fs::remove_dir_all(&session).await;
                    return Err(Perr::Other(format!(
                        "delta restore: chain member {idx} ({}) in {} is missing or fails its SHA",
                        spec.path,
                        dir.display()
                    )));
                }
                // Which members apply at this chain position: the SQL families only from the
                // NEWEST delta (full-dump fallback supersedes the base/intermediate SQL); identity
                // never; KV/blob at every link (base full + each delta's overlay).
                let apply_here = match spec.kind {
                    // Managed pg SQL — a full dump OR a WAL true-delta — is restored by the atomic
                    // shadow pass (`restore_pg_true_delta_in_chain`) AFTER this loop (restore_member
                    // fail-closes on a managed pg member). An EXTERNAL pg full dump still restores
                    // here via restore_member, newest-link only.
                    MemberKind::PgDump => {
                        !db_from_pg_member(&spec.path)
                            .map(|db| self.is_managed_pg(db))
                            .unwrap_or(false)
                            && is_newest
                    }
                    MemberKind::PgWalDelta => false,
                    // Managed mysql SQL — a full dump OR a binlog true-delta — is restored by the
                    // atomic shadow pass (`restore_mysql_true_delta_in_chain`) AFTER this loop
                    // (restore_member fail-closes on a managed mysql member). An EXTERNAL mysql full
                    // dump still restores here via restore_member, newest-link only.
                    MemberKind::MysqlDump => {
                        !db_from_mysql_member(&spec.path)
                            .map(|db| self.is_managed_mysql(db))
                            .unwrap_or(false)
                            && is_newest
                    }
                    MemberKind::MysqlBinlogDelta => false,
                    // A libsql full dump whose site has a changeset in the chain is restored by the
                    // atomic changeset pass (base snapshot + changesets); skip it here. A site with
                    // no changeset still restores its newest full dump via `restore_member`.
                    MemberKind::Libsql => {
                        is_newest
                            && !site_from_libsql_member(&spec.path)
                                .map(|s| libsql_changeset_sites.contains(s))
                                .unwrap_or(false)
                    }
                    // A libsql changeset is replayed only by the atomic changeset pass below.
                    MemberKind::LibsqlChangeset => false,
                    MemberKind::Identity => false,
                    _ => true,
                };
                if !apply_here {
                    continue;
                }
                if let Err(e) = self
                    .restore_member(
                        project,
                        m.head(),
                        &m.source.project,
                        spec,
                        &obj,
                        opts,
                        &mut report,
                        &mut saw_identity,
                    )
                    .await
                {
                    let _ = tokio::fs::remove_dir_all(&session).await;
                    return Err(e);
                }
            }
        }
        // Managed pg SQL families (full-dump fallback OR WAL true-delta): restore the chain's newest
        // full dump into a fresh atomic shadow, replay each subsequent PgWalDelta onto it as the
        // ephemeral non-superuser role, then swap. Independent of the KV/blob overlay above.
        if let Err(e) = self
            .restore_pg_true_delta_in_chain(project, &chain, opts, &mut report, &session)
            .await
        {
            let _ = tokio::fs::remove_dir_all(&session).await;
            return Err(e);
        }
        // Managed mysql SQL families (full-dump fallback OR binlog true-delta): restore the chain's
        // newest full dump into a fresh atomic shadow, replay each subsequent MysqlBinlogDelta onto
        // it as the ephemeral apply user, then swap. Independent of the KV/blob overlay above.
        if let Err(e) = self
            .restore_mysql_true_delta_in_chain(project, &chain, opts, &mut report, &session)
            .await
        {
            let _ = tokio::fs::remove_dir_all(&session).await;
            return Err(e);
        }
        // libsql changeset true-delta (SQL true-delta program, Stage 4): for each site with a
        // changeset in the chain, copy the base snapshot into a fresh atomic shadow, apply each
        // changeset onto it (confined to the base's own tables, abort-on-conflict), integrity-check,
        // then atomically swap. Independent of the KV/blob overlay above.
        if let Err(e) = self
            .restore_libsql_true_delta_in_chain(
                project,
                &chain,
                &libsql_changeset_sites,
                opts,
                &mut report,
            )
            .await
        {
            let _ = tokio::fs::remove_dir_all(&session).await;
            return Err(e);
        }
        let _ = tokio::fs::remove_dir_all(&session).await;
        report.notes.push(format!(
            "delta restore: applied a {}-link chain ({} base + {} delta(s)) in {} mode",
            chain.len(),
            1,
            chain.len() - 1,
            di.mode.as_flag()
        ));
        Ok(report)
    }

    /// Import a resumable member-object directory (the output of [`export_resumable`]):
    /// restore members in the MANIFEST's authoritative order, reusing [`restore_member`]
    /// per member — identical per-member tenancy re-key/enforce as the streaming import.
    /// Core resumable import from an ALREADY-CONFINED absolute `dir` (the trait method
    /// [`ProjectExport::import_resumable`] confines the operator-named subdir first).
    pub async fn import_resumable_dir(
        &self,
        project: &str,
        dir: &Path,
        opts: ImportOptions,
    ) -> Result<ImportReport, Perr> {
        check_project_slug(project)?;
        let manifest_path = dir.join(project_bundle::MANIFEST_PATH);
        let bytes = tokio::fs::read(&manifest_path)
            .await
            .map_err(|e| Perr::Other(format!("read resumable MANIFEST: {e}")))?;
        let manifest: project_bundle::StreamManifest = serde_json::from_slice(&bytes)
            .map_err(|e| Perr::Other(format!("parse resumable MANIFEST: {e}")))?;

        // A DELTA bundle resolves its base chain and applies base → each delta in order (its own
        // fresh-target guard runs inside). A FULL bundle takes the straight per-member path below.
        if manifest.delta.is_some() {
            return self
                .import_delta_chain(project, dir, &manifest, &opts)
                .await;
        }

        // The same fresh-target guard as the streaming import (unless overwrite).
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
                         data under {prefix:?}; pass overwrite=true"
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
                     overwrite=true"
                )));
            }
        }

        let session = self
            .work_dir
            .join(format!("import-res-{project}-{}", now_secs()));
        tokio::fs::create_dir_all(&session).await.map_err(other)?;

        let mut report = ImportReport::default();
        let mut saw_identity = false;
        for (idx, spec) in manifest.members.iter().enumerate() {
            let obj = dir.join(member_object_name(idx));
            let meta = dir.join(member_meta_name(idx));
            if !member_object_valid(&obj, &meta).await? {
                return Err(Perr::Other(format!(
                    "resumable import: member {idx} ({}) is missing or fails its SHA — the \
                     export directory is incomplete or corrupt",
                    spec.path
                )));
            }
            self.restore_member(
                project,
                manifest.head(),
                &manifest.source.project,
                spec,
                &obj,
                &opts,
                &mut report,
                &mut saw_identity,
            )
            .await?;
        }
        let _ = tokio::fs::remove_dir_all(&session).await;
        Ok(report)
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
    // The shadow-restore serves BOTH DEDICATED/Single and SHARED multi-tenant managed servers. On a
    // Shared server each tenant has its OWN physical DATABASE, so the DATABASE-level shadow+swap
    // applies exactly as for a dedicated server; the per-tenant physical shadow is tenancy-hardened
    // (`shared_reprovision`): REVOKE PUBLIC at creation closes the restore-window cross-tenant
    // surface, a per-tenant OWNER role owns the swapped-in db + its objects, and a post-swap
    // re-provision re-asserts the per-tenant isolation + serving grants — so a cloned Shared tenant
    // db is never a cross-tenant surface and is servable exactly like a freshly-provisioned one. The
    // chunked streaming path still runs only for FULL dedicated/Single members (a Shared pg export is
    // framed sidecar and reaches the shadow via `pg_sidecar_shadow_restore`).
    // -----------------------------------------------------------------------

    /// Resolve the [`PgShadowPlan`] for a MANAGED pg binding: the superuser/maintenance connection
    /// (on `postgres`), a freshly-minted EPHEMERAL non-superuser apply role + password, the client
    /// image, the shadow name, the trusted-extension allowlist, and (for a Shared NON-default tenant)
    /// the [`SharedReprovision`] context. External (bring-your-own-URL) bindings are refused — we
    /// must not `CREATE/RENAME/DROP` databases on an operator's own server.
    ///
    /// Both DEDICATED/Single and SHARED multi-tenant managed servers are handled. On a Shared server
    /// each tenant has its OWN physical DATABASE (grant-isolated), so the DATABASE-level atomic
    /// shadow+swap applies exactly as it does for a dedicated server; the untrusted dump is still
    /// confined to the ephemeral non-superuser role. The only Shared-specific additions (driven by
    /// `shared_reprovision`) are tenancy hygiene on the physical shadow: a per-tenant OWNER role for
    /// the swapped-in db + its objects, a REVOKE-PUBLIC lockdown of the shadow at creation, and a
    /// post-swap re-provision — see [`SharedReprovision`].
    async fn pg_shadow_plan(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
    ) -> Result<PgShadowPlan, Perr> {
        if cfg.compute.as_deref().is_none_or(|c| c.is_empty()) {
            return Err(Perr::Unavailable(format!(
                "database {db:?}: the atomic pg shadow-restore is for MANAGED (compute-backed) \
                 databases only; an external bring-your-own-URL binding uses the sidecar path"
            )));
        }
        // Clone self-provision (PLAN-clone-self-provision-managed-db): every caller reaches here
        // only under `opts.apply` (their dry-run arms return first), so this is unconditional. A
        // target whose tenant db / dedicated workload was never provisioned gets provisioned now
        // (idempotent — `provision_tenant`'s own contract); for Shared this also mints the per-tenant
        // OWNER + login roles that the swap re-assigns ownership to + re-grants on.
        self.ensure_target_db_provisioned(project, db, cfg).await?;
        // Operator identity (configured/superuser) + version-detect → client image. Its endpoint
        // (host/port) + the live tenant db name seed the maintenance conn (always the SUPERUSER —
        // it runs ONLY trusted DDL, never the dump).
        let (operator_conn, image, _ver) = self.resolve_pg(project, db, cfg).await?;
        let live_db = operator_conn.database.clone();
        // The role the swapped-in db + its restored objects are re-owned to. For a SHARED NON-default
        // tenant this is the per-tenant non-superuser OWNER role (so the clone's db + schema are
        // owned exactly as a provisioned tenant's — its future migrations run as that role); for
        // Single/dedicated + Shared-DEFAULT it is the configured operator identity (the role that
        // normally owns the whole-server db). The untrusted dump is NEVER applied as this role — it
        // is applied as the ephemeral non-superuser role; this only names the post-restore owner.
        let (_tenant_ident, is_default) =
            crate::tenant_sql::tenant_key(cfg.tenant_scope, project, "");
        let shared_nondefault =
            matches!(cfg.tenant, crate::config::TenantIsolation::Shared) && !is_default;
        let owner_user = if shared_nondefault {
            owner_target(cfg, project, db).map_err(other)?.user
        } else {
            operator_conn.user.clone()
        };
        let shared_reprovision = shared_nondefault.then(|| SharedReprovision {
            project: project.to_string(),
            binding: cfg.clone(),
        });
        let mut maint = operator_conn;
        // CREATE/ALTER/DROP DATABASE cannot run connected to the tenant db — point at `postgres`.
        maint.database = "postgres".to_string();
        let suffix = shadow_suffix();
        // Bounded to Postgres's 63-byte NAMEDATALEN (truncating the live-db prefix, never the
        // `__shadow_<suffix>` distinguisher) so a tenant-qualified Shared live db name does not push
        // the shadow name past the limit and collapse it back to the live name on truncation.
        let shadow_db = bounded_derived_db_name(&live_db, "__shadow_", &suffix);
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
            shared_reprovision,
        })
    }

    /// Apply a FULL MANAGED **sidecar** pg dump (already staged + SHA-verified at `temp`) through the
    /// SAME non-superuser ephemeral-role + shadow + atomic-swap mechanism the chunked/dedicated path
    /// uses — now also serving a SHARED tenant's sidecar-framed FULL export (and any FULL dedicated
    /// dump staged sidecar rather than chunked). Mirrors the chunked servicer's create → fail-closed
    /// non-superuser probe → restore → swap sequence, but reads the staged member FILE as stdin
    /// (sidecar) rather than a streamed body channel.
    ///
    /// THE INVARIANT (absolute): the untrusted `-Fc --no-owner --no-privileges` dump is restored
    /// CONNECTED AS the ephemeral `NOSUPERUSER NOCREATEDB NOCREATEROLE` role into the shadow — so a
    /// crafted `COPY … TO/FROM PROGRAM/FILE` / `CREATE FUNCTION … LANGUAGE c` / untrusted `CREATE
    /// EXTENSION` FAILS at apply (Postgres denies it to a non-superuser), exactly as the chunked path
    /// and the `project_export_pg_crafted_superuser_escape_refused_live` gate prove. The superuser /
    /// maintenance connection runs ONLY our own trusted scaffolding DDL (create shadow + eph role,
    /// pre-create allow-listed extensions, the atomic swap, Shared re-provision) — never a byte of
    /// the dump. Any create/restore/swap failure tears the shadow down and leaves live untouched.
    async fn pg_sidecar_shadow_restore(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        temp: &Path,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let plan = self.pg_shadow_plan(project, db, cfg).await?;
        // TRUSTED DDL (superuser/maint): mint the ephemeral NON-SUPERUSER role + the shadow it owns +
        // (Shared) the REVOKE-PUBLIC lockdown + pre-create the allow-listed extensions.
        if let Err(e) = self.pg_create_shadow(&plan, stage_dir).await {
            self.pg_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        // FAIL-CLOSED: refuse the untrusted apply unless the apply role is PROVABLY a non-superuser.
        if let Err(e) = self
            .pg_assert_not_superuser(&plan.apply_conn(), &plan.image, stage_dir)
            .await
        {
            self.pg_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        // SHARED tenancy, immediately before the UNTRUSTED restore runs: one last terminate-sweep on
        // the shadow (belt-and-suspenders to the create-time REVOKE + sweep in `pg_create_shadow`).
        // At this point no LEGITIMATE session is on the shadow — the restore has not started, and each
        // prior step (create/lockdown, the non-superuser probe) ran in its own now-closed container —
        // so this evicts ONLY a sibling tenant that slipped a CONNECT into the (now minimized) create
        // window. REVOKE blocks new connects; this sweep drops the slipped-in one, so the restore
        // begins on a shadow with zero foreign sessions. No-op off the Shared path (no sibling).
        if plan.shared_reprovision.is_some()
            && let Err(e) = self
                .pg_run_ddl(
                    &plan,
                    &pg_terminate_backends_sql(&plan.shadow_db),
                    stage_dir,
                )
                .await
        {
            self.pg_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        // Apply the untrusted dump into the shadow AS the ephemeral role, reading the staged member
        // FILE on stdin. `--single-transaction` (in `pg_restore_shadow_invocation`) makes the shadow
        // restore all-or-nothing; stderr is merged so a refused/failed object is diagnosable
        // (`run_ephemeral` drops a container's stderr on a non-zero exit).
        let inv = pg_restore_shadow_invocation(&plan.apply_conn(), &plan.shadow_db);
        let merged = merge_stderr_argv(&inv.argv);
        let outfile = stage_dir.join(format!("pgrestore-sidecar-{}.out", shadow_suffix()));
        let code = match self
            .run_sql_client(&plan.image, &merged, &inv.env, Some(temp), &outfile)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                let _ = tokio::fs::remove_file(&outfile).await;
                self.pg_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
        };
        if code != 0 {
            let diag = tokio::fs::read_to_string(&outfile)
                .await
                .unwrap_or_default();
            let _ = tokio::fs::remove_file(&outfile).await;
            self.pg_drop_shadow(&plan, stage_dir).await;
            return Err(Perr::Other(format!(
                "pg_restore into shadow {:?} for {db:?} exited {code}; live untouched: {}",
                plan.shadow_db,
                diag.trim()
            )));
        }
        let _ = tokio::fs::remove_file(&outfile).await;
        // Restore clean (and the sidecar member was SHA-verified at staging) → atomic swap. A swap
        // failure tears the shadow down (its own rollback keeps live intact); live is untouched.
        if let Err(e) = self.pg_swap_shadow(&plan, stage_dir).await {
            self.pg_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        Ok(())
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

    /// Run SEVERAL trusted DDL/utility statements through the SUPERUSER / maintenance connection in
    /// ONE psql process (a REPEATED `-c` per statement — see [`psql_script_invocation`]), each in
    /// its own implicit transaction. Used to keep a sequence that must be GAP-FREE inside a single
    /// connection/container launch — the SHARED shadow's `CREATE DATABASE` + `REVOKE CONNECT … FROM
    /// PUBLIC` + terminate-sweep — so no sibling tenant can slip a PUBLIC CONNECT into a
    /// cross-container gap. `ON_ERROR_STOP=1` aborts the whole run on the first failed statement.
    async fn pg_run_ddl_script(
        &self,
        plan: &PgShadowPlan,
        statements: &[String],
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let inv = psql_script_invocation(&plan.maint, statements);
        let (code, out) = self
            .run_sql_capture(&plan.image, &inv.argv, &inv.env, None, stage_dir)
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg shadow DDL script exited {code} ({statements:?}): {out}"
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
        // SHARED tenancy lockdown: the shadow is a sibling of OTHER tenants' databases on ONE shared
        // cluster. A fresh `CREATE DATABASE` grants PUBLIC CONNECT by default, so until it is stripped
        // a sibling tenant's role can reach the restoring dump — the restore-window cross-tenant
        // surface. Close it with THREE moves run GAP-FREE in ONE psql process (a repeated `-c` per
        // statement — each its own txn, so `CREATE DATABASE` is legal):
        //   1. CREATE DATABASE (OWNED by the ephemeral role, so the apply still connects).
        //   2. REVOKE CONNECT … FROM PUBLIC — blocks any NEW sibling connect.
        //   3. a terminate-sweep — evicts a sibling session that connected in the sub-statement
        //      window before the REVOKE took effect (REVOKE alone does not drop an existing session).
        // Running these as ONE invocation (not three separate `pg_run_ddl` container spawns) shrinks
        // the PUBLIC-connectable window from a whole container launch to a few back-to-back statements
        // on one connection; a second terminate-sweep runs immediately before the untrusted restore
        // (`pg_sidecar_shadow_restore`) as belt-and-suspenders. This is the same REVOKE the normal
        // per-tenant provisioning applies, re-granted to the tenant's roles on the swapped-in db by
        // the post-swap re-provision. No-op for Single/dedicated + Shared-DEFAULT (`shared_reprovision`
        // is `None`), whose server hosts no sibling tenant.
        if plan.shared_reprovision.is_some() {
            self.pg_run_ddl_script(
                plan,
                &[
                    format!("CREATE DATABASE {shadow_q} OWNER {role_q}"),
                    format!("REVOKE CONNECT ON DATABASE {shadow_q} FROM PUBLIC"),
                    pg_terminate_backends_sql(&plan.shadow_db),
                ],
                stage_dir,
            )
            .await?;
            // PG≤14 defense-in-depth (cheap extra layer; PG15+ already revokes CREATE on `public`
            // from PUBLIC by default): make it unconditional so even a hypothetical in-window connect
            // cannot leave a SURVIVING object in schema `public` (the swap's `REASSIGN OWNED` only
            // moves eph-role-owned objects — an intruder-owned one would survive the swap). Must run
            // CONNECTED to the shadow (schema-local). Two statements:
            //   1. REVOKE CREATE ON SCHEMA public FROM PUBLIC — a gap-intruder cannot create in public.
            //   2. ALTER SCHEMA public OWNER TO <eph_role> — WHY this is REQUIRED, not optional: on
            //      PG≤14 the DB-owner does NOT implicitly get CREATE on `public` (that comes only from
            //      PUBLIC's default grant, which step 1 just removed), so without this the NON-superuser
            //      restore (and later the tenant owner's migrations) could not create objects in public.
            //      Making the ephemeral role OWN public restores its CREATE right, and the swap's
            //      existing `REASSIGN OWNED BY <eph_role> TO <owner>` then transfers `public` (like
            //      every other eph-owned object) to the tenant owner — so the cloned tenant's owner
            //      keeps CREATE on public (no PG≤14 regression) while PUBLIC stays locked out.
            let maint_shadow = PgShadowPlan {
                maint: plan.maint_on_shadow(),
                ..plan.clone()
            };
            self.pg_run_ddl_script(
                &maint_shadow,
                &[
                    "REVOKE CREATE ON SCHEMA public FROM PUBLIC".to_string(),
                    format!("ALTER SCHEMA public OWNER TO {role_q}"),
                ],
                stage_dir,
            )
            .await?;
            // TEST-ONLY widener (inert in production — field is 0, its setter does not compile under
            // `--release`): hold here, with the shadow created but LOCKED DOWN (PUBLIC CONNECT revoked
            // + swept above), so the cross-tenant live gate can observe the shadow while it exists and
            // prove a sibling can never CONNECT to it. A plain sleep owning no DB connection; it moves
            // no statement and changes no DDL.
            if self.shadow_restore_test_delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    self.shadow_restore_test_delay_ms,
                ))
                .await;
            }
        } else {
            self.pg_run_ddl(
                plan,
                &format!("CREATE DATABASE {shadow_q} OWNER {role_q}"),
                stage_dir,
            )
            .await?;
        }
        // Pre-create the allowlisted extensions in the shadow AS THE SUPERUSER, connected to the
        // shadow (extensions are database-local). `IF NOT EXISTS` so a re-run is a no-op. A
        // non-trusted extension (e.g. pgvector — its control file sets no `trusted = true`) can
        // only be installed by a superuser, so the pre-create MUST be the superuser; the untrusted
        // dump's `CREATE EXTENSION IF NOT EXISTS <ext>` then no-ops under the non-superuser apply
        // (the existence check precedes the privilege check, so an already-present extension needs
        // no privilege). The dump's OWNER-only `COMMENT ON EXTENSION <ext>` — which the
        // non-superuser apply could NOT run on this superuser-owned extension — is kept out of the
        // bundle by dumping with `--no-comments` (see `pg_dump_invocation`); the extension's
        // comment is re-set by CREATE EXTENSION regardless, so nothing is lost for the extension.
        // A dump that references an extension NOT on the allowlist fails fail-closed under the
        // non-superuser apply (correct: an untrusted bundle must not install an arbitrary extension).
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
        // Derive the rename-aside name through the SAME bounded helper as the shadow (above), so a
        // long live db name keeps both the shadow and the `__old_<suffix>` aside within the 63-byte
        // NAMEDATALEN limit and the `ALTER DATABASE … RENAME TO <old>` cannot overflow + collapse.
        let old_db = bounded_derived_db_name(&plan.live_db, "__old_", &plan.suffix);
        let old_q = quote_ident(ExternalSqlKind::Postgres, &old_db);
        // SWAP-SAFETY INVARIANT (defense in depth; mirror of the mysql guard): never rename live
        // aside + drop the aside without the shadow REPLACEMENT present. pg renames the whole shadow
        // DATABASE in, so the invariant is "the shadow db must EXIST before we touch live" — abort
        // leaving live intact otherwise. (pg's shadow name is per-process random — `<live>__shadow_
        // <nanos>_<pid>` — so it does NOT suffer the mysql true-delta deterministic-name collision
        // race; this guard is cheap insurance, not a fix for a known pg hole.)
        if !self.pg_db_exists(plan, &plan.shadow_db, stage_dir).await? {
            return Err(Perr::Other(format!(
                "pg shadow swap REFUSED: the shadow database {:?} is absent — refusing to rename \
                 live {:?} aside without a replacement. Live left intact.",
                plan.shadow_db, plan.live_db
            )));
        }
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
        // SHARED tenancy: the swapped-in db now carries ONLY the shadow's grants (owner-owned via the
        // REASSIGN/ALTER-OWNER above, PUBLIC CONNECT revoked at creation) — NOT the per-tenant login
        // grants a served tenant db needs. Re-run the idempotent tenant provisioning so the cloned db
        // is grant-isolated + servable EXACTLY like a freshly-provisioned tenant db: it re-asserts
        // REVOKE CONNECT FROM PUBLIC, GRANTs CONNECT/ALL to the owner + login roles, and GRANTs the
        // app-role table privileges on the restored (now owner-owned) objects. The dump already
        // landed atomically; this is our own trusted DDL (the superuser via `provision_tenant`'s own
        // admin connection), never a byte of the untrusted dump. A failure here is loud — the clone
        // is safely live but un-granted, and a later normal resolve re-runs the same idempotent path.
        if let Some(rp) = &plan.shared_reprovision {
            let envelope = self.envelope.as_ref().ok_or_else(|| {
                Perr::Unavailable(format!(
                    "shared clone re-provision of {:?} needs a [secrets] envelope to unseal its \
                     credential — none on this node",
                    plan.live_db
                ))
            })?;
            crate::tenant_sql::provision_tenant(
                &self.deploy,
                &self.kv,
                envelope,
                &rp.binding,
                &rp.project,
                "",
            )
            .await
            .map_err(|e| {
                Perr::Other(format!(
                    "shared clone re-provision of {:?} failed after the atomic swap: {e}",
                    plan.live_db
                ))
            })?;
        }
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
        // Run the restore under `sh -c '… 2>&1'` so pg_restore's STDERR — where Postgres
        // reports a refused/failed object — merges into the captured sink that the caller
        // reads for the error message. `run_ephemeral` keeps only the container's stdout
        // and DROPS stderr on a non-zero exit, so without this a failed import (a refused
        // superuser-only escape, or any restore error) surfaces as an empty, causeless
        // "exited N; live untouched: ". Only driver-derived flags + the shadow-db
        // identifier (`[A-Za-z0-9_]`) are composed into the command — never the password,
        // which rides in `inv.env` (PGPASSWORD); each token is POSIX single-quoted, and
        // `exec` keeps the reported exit status pg_restore's own.
        let cmd = format!("exec {} 2>&1", sh_join(&inv.argv));
        let argv = vec!["sh".to_string(), "-c".to_string(), cmd];
        let env = inv.env;
        Ok(tokio::spawn(async move {
            let mut reader = AsyncChannelReader::new(body_rx);
            let out = tokio::fs::File::create(&out_path).await.map_err(other)?;
            let mut sink = out.compat_write();
            backend
                .run_ephemeral(&image, &argv, &env, Some(&mut reader), &mut sink)
                .await
                .map_err(other)
        }))
    }

    // -----------------------------------------------------------------------
    // inc2 Stage D — MySQL atomic shadow-restore (secondary; production is pg). Same
    // non-superuser-apply split: `mysql <shadow>` applies the attacker dump as the owner role;
    // the maintenance connection runs the trusted `CREATE DATABASE` + atomic `RENAME TABLE` swap.
    // -----------------------------------------------------------------------

    /// Resolve the [`MysqlShadowPlan`] for a MANAGED mysql binding (external bindings stay sidecar).
    /// Mints an EPHEMERAL apply user + password (HIGH-1: the configured user is the bootstrap
    /// superuser on a dedicated instance, so the apply must NOT use it).
    ///
    /// `allow_shared` gates the Shared multi-tenant tenancy: the CHUNKED servicer caller passes
    /// `false` (defense-in-depth — a dedicated/Single managed ShadowSwap is the only member framed
    /// chunked, so a Shared one reaching the chunked arm is a bug), while the SIDECAR shadow+swap
    /// caller ([`mysql_sidecar_shadow_restore`](Self::mysql_sidecar_shadow_restore)) passes `true`.
    /// A Shared tenant's per-tenant physical database is resolved tenant-qualified by
    /// [`resolve_mysql`](Self::resolve_mysql) → `resolve_endpoint` (the same derivation served Shared
    /// mysql uses), and [`ensure_target_db_provisioned`](Self::ensure_target_db_provisioned) has
    /// already created that live per-tenant db + its login grant before the restore — so the
    /// DATABASE-level shadow+swap applies exactly as for a dedicated server (MySQL has no PUBLIC
    /// connect surface, so no restore-window lockdown is needed, and the tenant's db-level grant
    /// already covers the swapped-in tables, so no post-swap re-provision is needed).
    async fn mysql_shadow_plan(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        allow_shared: bool,
    ) -> Result<MysqlShadowPlan, Perr> {
        if cfg.compute.as_deref().is_none_or(|c| c.is_empty()) {
            return Err(Perr::Unavailable(format!(
                "database {db:?}: the atomic mysql shadow-restore is for MANAGED \
                 (compute-backed) databases only; an external binding uses the sidecar path"
            )));
        }
        if !allow_shared && matches!(cfg.tenant, crate::config::TenantIsolation::Shared) {
            return Err(Perr::Unavailable(format!(
                "database {db:?}: the atomic CHUNKED mysql shadow-restore is for DEDICATED/Single \
                 managed servers only; a Shared multi-tenant server restores via the sidecar \
                 shadow+swap (mysql_sidecar_shadow_restore)"
            )));
        }
        // Clone self-provision — mirror of `pg_shadow_plan`'s call above (both callers only
        // reach here under `opts.apply`; see that function's comment for the rationale).
        self.ensure_target_db_provisioned(project, db, cfg).await?;
        let (operator_conn, image, _ver) = self.resolve_mysql(project, db, cfg).await?;
        let live_db = operator_conn.database.clone();
        let maint = operator_conn; // mysql names no default db for the admin SQL
        // A SHORT suffix: `brexp_apply_<suffix>` must fit MySQL's 32-char USER-name cap.
        let suffix = mysql_eph_suffix();
        // Bounded to 63 bytes (≤ MySQL's 64-char identifier cap) by truncating the live-db prefix,
        // keeping the `__shadow_<suffix>` distinguisher intact — latent overflow for a long db name.
        let shadow_db = bounded_derived_db_name(&live_db, "__shadow_", &suffix);
        let eph_user = format!("brexp_apply_{suffix}");
        // The post-swap DEFINER re-point target for carried triggers/routines/events/views. For a
        // SHARED NON-default tenant this is the tenant's OWN db-scoped login role (`` `<role>`@`%` ``)
        // — the same role the runtime serves the tenant's db as, so a carried object runs with exactly
        // the tenant's own grants, never SUPER/cross-tenant.
        //
        // For the two NON-shared-nondefault cases `Strip` removes the clause so the DEFINER defaults
        // to the ADMIN connection that re-creates it, and what that admin IS differs by posture:
        //   - SINGLE / dedicated: the admin IS the tenant's own served app user (its dedicated
        //     server), so Strip re-points to the SAME identity the app already connects as — it grants
        //     the object NO authority the tenant's app doesn't already hold on its own server.
        //   - SHARED-DEFAULT (the plain install's default tenant): the admin is the cluster SUPERUSER,
        //     so Strip defaults the DEFINER to that superuser. This is NOT a cross-tenant escalation
        //     (the default tenant IS the operator-owned install, there is no OTHER tenant whose data it
        //     could reach via its own server-wide privileges), but it is broader than a db-scoped role.
        // LOW-3 regression note (security follow-up): if a lower-privilege per-replica RUNTIME login
        // role is ever introduced for Single/dedicated (as the pg Phase-2 dynamic-role work does),
        // switch THAT posture's re-point from `Strip` to `Account(<runtime_role>)` here — otherwise
        // Strip-to-the-admin would silently become an escalation relative to that new, narrower runtime
        // identity. (Today Single/dedicated genuinely has no narrower role, so Strip is correct.)
        let (tenant_ident_raw, is_default) =
            crate::tenant_sql::tenant_key(cfg.tenant_scope, project, "");
        let shared_nondefault =
            matches!(cfg.tenant, crate::config::TenantIsolation::Shared) && !is_default;
        let repoint = if shared_nondefault {
            let ident = boatramp_storage::tenant_provision::sanitize_ident(&tenant_ident_raw);
            let compute = cfg.compute.as_deref().unwrap_or_default();
            MysqlDefinerTarget::Account(boatramp_storage::tenant_provision::tenant_role_name(
                compute, &ident,
            ))
        } else {
            MysqlDefinerTarget::Strip
        };
        Ok(MysqlShadowPlan {
            live_db,
            shadow_db,
            suffix,
            maint,
            eph_user,
            eph_password: random_token(),
            image,
            repoint,
        })
    }

    /// Apply a FULL MANAGED **sidecar** mysql dump (already staged + SHA-verified at `temp`) through
    /// the SAME non-superuser ephemeral-user + shadow + atomic-swap mechanism the chunked/dedicated
    /// path uses — now serving a SHARED tenant's sidecar-framed TABLES-ONLY export. The mysql analogue
    /// of [`pg_sidecar_shadow_restore`](Self::pg_sidecar_shadow_restore); the Shared mysql case is
    /// SIMPLER than Shared pg: MySQL has NO PUBLIC-connect surface, so there is no restore-window
    /// lockdown, and the tenant's db-level `GRANT ALL ON <db>.*` already covers the swapped-in tables,
    /// so there is no post-swap re-provision.
    ///
    /// THE INVARIANT (absolute): the untrusted tables-only dump is applied CONNECTED AS the ephemeral
    /// least-privilege user ([`mysql_shadow_invocation`], `--local-infile=0`) into the shadow — so a
    /// crafted `LOAD DATA INFILE` / `INTO OUTFILE` / privileged-routine statement FAILS at apply
    /// (MySQL denies it to a user without `FILE`/`SUPER`), exactly as the chunked path and the
    /// `mysql_assert_not_superuser` fail-closed probe prove. The SUPERUSER / maintenance connection
    /// runs ONLY our own trusted scaffolding DDL (create shadow + eph user, the atomic `RENAME TABLE`
    /// swap) — never a byte of the dump. Any create/apply/swap failure tears the shadow down and
    /// leaves live untouched.
    async fn mysql_sidecar_shadow_restore(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        temp: &Path,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let plan = self.mysql_shadow_plan(project, db, cfg, true).await?;
        // TRUSTED DDL (superuser/maint): create the shadow db + mint the EPHEMERAL least-privilege
        // apply user granted ONLY on the shadow.
        if let Err(e) = self.mysql_create_shadow(&plan, stage_dir).await {
            self.mysql_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        // FAIL-CLOSED: refuse the untrusted apply unless the apply user is PROVABLY least-privilege
        // (no SUPER/FILE/`*.*`).
        if let Err(e) = self.mysql_assert_not_superuser(&plan, stage_dir).await {
            self.mysql_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        // Rewrite every `DEFINER=` clause in the staged dump to the ephemeral apply user, then apply
        // the untrusted tables-only dump into the shadow AS that user (so its triggers/routines/
        // events create successfully as a non-superuser). Any apply failure tears the shadow down;
        // live is untouched.
        if let Err(e) = self
            .mysql_apply_staged_to_shadow(&plan, temp, stage_dir)
            .await
        {
            self.mysql_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        // Capture the carried DEFINER objects, drop the shadow's triggers, atomic `RENAME TABLE`
        // swap, then re-create the objects in live with the DEFINER re-pointed to the tenant's own
        // role. Any failure tears the shadow down (the swap keeps live intact on a pre-swap failure;
        // a post-swap re-point failure is loud — the tables are live but the carried objects are not).
        if let Err(e) = self.mysql_finalize_shadow(&plan, stage_dir).await {
            self.mysql_drop_shadow(&plan, stage_dir).await;
            return Err(e);
        }
        Ok(())
    }

    /// Rewrite every `DEFINER=` clause in the staged mysql dump FILE to the ephemeral apply user
    /// ([`rewrite_mysql_definers`]), then APPLY the rewritten dump into the shadow CONNECTED AS that
    /// ephemeral non-superuser user ([`mysql_shadow_invocation`], `--local-infile=0`), reading it on
    /// stdin. The DEFINER rewrite is what lets the untrusted triggers/routines/events create under the
    /// non-superuser apply (a non-SUPER user cannot create an object with a FOREIGN definer); after
    /// the swap the driver re-points them to the tenant's own role. Shared by the sidecar and chunked
    /// paths. stderr is merged (`sh -c '… 2>&1'`) so a refused/failed statement is diagnosable.
    async fn mysql_apply_staged_to_shadow(
        &self,
        plan: &MysqlShadowPlan,
        staged_dump: &Path,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let raw = tokio::fs::read_to_string(staged_dump)
            .await
            .map_err(other)?;
        let rewritten =
            rewrite_mysql_definers(&raw, &MysqlDefinerTarget::Account(plan.eph_user.clone()));
        let rewritten_path = stage_dir.join(format!("myapply-{}.sql", shadow_suffix()));
        tokio::fs::write(&rewritten_path, rewritten.as_bytes())
            .await
            .map_err(other)?;
        let inv = mysql_shadow_invocation(&plan.apply_conn(), &plan.shadow_db);
        let merged = merge_stderr_argv(&inv.argv);
        let outfile = stage_dir.join(format!("myapply-{}.out", shadow_suffix()));
        let r = self
            .run_sql_client(
                &plan.image,
                &merged,
                &inv.env,
                Some(&rewritten_path),
                &outfile,
            )
            .await;
        let _ = tokio::fs::remove_file(&rewritten_path).await;
        let code = match r {
            Ok(c) => c,
            Err(e) => {
                let _ = tokio::fs::remove_file(&outfile).await;
                return Err(e);
            }
        };
        if code != 0 {
            let diag = tokio::fs::read_to_string(&outfile)
                .await
                .unwrap_or_default();
            let _ = tokio::fs::remove_file(&outfile).await;
            return Err(Perr::Other(format!(
                "mysql apply into shadow {:?} exited {code}; live untouched: {}",
                plan.shadow_db,
                diag.trim()
            )));
        }
        let _ = tokio::fs::remove_file(&outfile).await;
        Ok(())
    }

    /// Finalize a populated shadow: carry its DEFINER-bearing objects (triggers / stored routines /
    /// events / VIEWS) across the atomic swap with their `DEFINER` RE-POINTED to the tenant's own
    /// role. Shared by BOTH the sidecar and the dedicated chunked mysql paths (ONE DEFINER-handling
    /// seam).
    ///
    /// The mechanics MySQL forces on us: a trigger blocks a cross-schema `RENAME TABLE` (ERROR 1435
    /// "Trigger in wrong schema"), and stored routines + events + views are SCHEMA-level — they do
    /// NOT ride `RENAME TABLE` at all and would be lost when the shadow db is dropped. So, in order:
    ///   1. CAPTURE the objects as clean DDL from the shadow (they exist there with `DEFINER` = the
    ///      ephemeral apply user, having proven they are creatable by a non-superuser — fail-closed
    ///      otherwise). Routines/events/triggers in one dump; VIEWS by name in a second (a
    ///      `--no-create-info` dump drops views). Done BEFORE the swap (the swap drops the shadow).
    ///   2. DROP the shadow's triggers (so the `RENAME TABLE` swap won't hit error 1435).
    ///   3. Atomic `RENAME TABLE` swap — the base tables move shadow→live; the shadow db + ephemeral
    ///      user are dropped.
    ///   4. RE-CREATE the captured objects in LIVE via the ADMIN connection, with every `DEFINER`
    ///      re-pointed (`plan.repoint`) to the tenant's own db-scoped role (Shared) or stripped to the
    ///      admin/served identity (dedicated) — ROUTINES/EVENTS/TRIGGERS first, then VIEWS (a view's
    ///      referenced tables/functions/views must already exist; a routine's references resolve
    ///      lazily at call time, so routines-first is safe, and the view dump is internally
    ///      dependency-ordered). The admin sets the definer; the object itself is only stored (CREATE
    ///      does not run a body), and when it later runs it runs with the re-pointed definer's
    ///      grants — the tenant's own, never SUPER/another tenant.
    ///
    /// A pre-swap failure leaves live intact; a post-swap re-create failure is LOUD (the tables are
    /// live but the carried objects did not land) — the same loud-but-live shape the pg shared
    /// re-provision has.
    async fn mysql_finalize_shadow(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let objects_sql = self.mysql_dump_definer_objects(plan, stage_dir).await?;
        let views_sql = self.mysql_dump_shadow_views(plan, stage_dir).await?;
        // A dump with no trigger/routine/event/view carries no `DEFINER=` clause at all.
        let has_objects = objects_sql.contains("DEFINER=");
        let has_views = views_sql.contains("DEFINER=");
        if has_objects {
            // Only triggers block the cross-schema RENAME; drop them (routines/events/views do not).
            self.mysql_drop_shadow_triggers(plan, stage_dir).await?;
        }
        self.mysql_swap_shadow(plan, stage_dir).await?;
        if has_objects {
            self.mysql_apply_definer_objects_to_live(plan, &objects_sql, stage_dir)
                .await?;
        }
        if has_views {
            // Views LAST — their referenced tables (now live) + any functions (created above) exist.
            self.mysql_apply_definer_objects_to_live(plan, &views_sql, stage_dir)
                .await?;
        }
        Ok(())
    }

    /// Re-extract the shadow's VIEWS as CREATE-VIEW DDL (DEFINER-bearing, dependency-ordered) via the
    /// admin connection. Views are suppressed by `--no-create-info`, so they are captured by NAME
    /// ([`mysqldump_views_invocation`]) — enumerated from `information_schema.views`. Returns an EMPTY
    /// string when the shadow has no views (so the caller skips the view re-create entirely — never
    /// runs a bare `mysqldump <db>` that would dump the whole database).
    async fn mysql_dump_shadow_views(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<String, Perr> {
        let sql = format!(
            "SELECT table_name FROM information_schema.views WHERE table_schema = {};",
            mysql_lit(&plan.shadow_db)
        );
        let (code, out) = self.mysql_run_admin(plan, &sql, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not list views of {:?} (exit {code}): {out}",
                plan.shadow_db
            )));
        }
        let views: Vec<String> = out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if views.is_empty() {
            return Ok(String::new());
        }
        let inv = mysqldump_views_invocation(&plan.maint, &plan.shadow_db, &views);
        let outfile = stage_dir.join(format!("myviews-{}.sql", shadow_suffix()));
        let code = self
            .run_sql_client(&plan.image, &inv.argv, &inv.env, None, &outfile)
            .await?;
        let content = tokio::fs::read_to_string(&outfile)
            .await
            .unwrap_or_default();
        let _ = tokio::fs::remove_file(&outfile).await;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not capture view DDL of {:?} (exit {code})",
                plan.shadow_db
            )));
        }
        Ok(content)
    }

    /// Re-extract the shadow's DEFINER-bearing objects (triggers/routines/events) as clean,
    /// `DELIMITER`-wrapped DDL ([`mysqldump_definer_objects_invocation`]) via the admin connection.
    /// Their `DEFINER` is the ephemeral apply user at this point; the re-point happens at apply time.
    async fn mysql_dump_definer_objects(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<String, Perr> {
        let inv = mysqldump_definer_objects_invocation(&plan.maint, &plan.shadow_db);
        let outfile = stage_dir.join(format!("mydefiner-{}.sql", shadow_suffix()));
        let code = self
            .run_sql_client(&plan.image, &inv.argv, &inv.env, None, &outfile)
            .await?;
        let content = tokio::fs::read_to_string(&outfile)
            .await
            .unwrap_or_default();
        let _ = tokio::fs::remove_file(&outfile).await;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not capture trigger/routine/event DDL of {:?} (exit {code})",
                plan.shadow_db
            )));
        }
        Ok(content)
    }

    /// Drop every trigger on the SHADOW's tables (via the admin connection), so the cross-schema
    /// `RENAME TABLE` swap does not hit ERROR 1435 "Trigger in wrong schema". The triggers are
    /// re-created in LIVE after the swap from the captured DDL.
    async fn mysql_drop_shadow_triggers(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let sql = format!(
            "SELECT trigger_name FROM information_schema.triggers WHERE trigger_schema = {};",
            mysql_lit(&plan.shadow_db)
        );
        let (code, out) = self.mysql_run_admin(plan, &sql, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not list triggers of {:?} (exit {code}): {out}",
                plan.shadow_db
            )));
        }
        let triggers: Vec<String> = out
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if triggers.is_empty() {
            return Ok(());
        }
        let shadow_q = quote_ident(ExternalSqlKind::Mysql, &plan.shadow_db);
        let mut stmts = String::new();
        for t in &triggers {
            let tq = quote_ident(ExternalSqlKind::Mysql, t);
            stmts.push_str(&format!("DROP TRIGGER IF EXISTS {shadow_q}.{tq};\n"));
        }
        let (code, out) = self.mysql_run_admin(plan, &stmts, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not drop triggers of {:?} (exit {code}): {out}",
                plan.shadow_db
            )));
        }
        Ok(())
    }

    /// Re-create a captured DEFINER-object DDL batch (routines/events/triggers, OR views) in the LIVE
    /// (swapped-in) db via the ADMIN connection, with every `DEFINER` RE-POINTED to the tenant's own
    /// role (`plan.repoint`). The attacker-shaped object BODIES are only stored here (CREATE does not
    /// execute a routine/trigger/event/view body); when they later run they run with the re-pointed
    /// definer's grants — the tenant's own db-scoped role (Shared) or the served identity (dedicated),
    /// NEVER SUPER or another tenant. A missing-privilege object fails this step FAIL-CLOSED (loud)
    /// rather than escalating.
    async fn mysql_apply_definer_objects_to_live(
        &self,
        plan: &MysqlShadowPlan,
        objects_sql: &str,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let rewritten = rewrite_mysql_definers(objects_sql, &plan.repoint);
        // The DDL is unqualified (positional-db dump), so `USE` the live db to land it there.
        // TODO(security follow-up, LOW-1): this re-create runs over the full maint/superuser admin
        // connection. CREATE never executes an object body, and the DEFINER is re-pointed to the
        // tenant's own role (so run-time authority is tenant-scoped), so the only residual surface is
        // a hypothetical create-TIME MySQL-parser breakout on the attacker-shaped DDL. To shrink that
        // blast radius we could mint a one-shot role holding ONLY `SET_USER_ID` (enough to set a
        // foreign DEFINER) + the tenant db's grants, and run this apply as it instead of the superuser.
        let live_q = quote_ident(ExternalSqlKind::Mysql, &plan.live_db);
        let script = format!("USE {live_q};\n{rewritten}");
        let (code, out) = self.mysql_run_admin(plan, &script, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not re-create carried trigger/routine/event/view objects in \
                 live {:?} (exit {code}); the tables swapped in but the carried objects did not \
                 land: {out}",
                plan.live_db
            )));
        }
        Ok(())
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
        // privileges") and must NOT trip the probe. Match the privilege TOKENS (the part BEFORE
        // " ON "), never the whole line — else a db named e.g. `supervisors`/`profiles` in the grant
        // TARGET (`GRANT ALL ON \`profiles\`.* …` → "FILE"/"SUPER" substring) false-refuses a legit
        // restore.
        for line in out.lines() {
            let privs = mysql_grant_privileges(line).to_ascii_uppercase();
            let up = line.to_ascii_uppercase();
            let dangerous_global = up.contains(" ON *.*") && !up.contains("USAGE ON *.*");
            if privs.contains("SUPER") || privs.contains("FILE") || dangerous_global {
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

    /// Whether a database `name` exists (via `information_schema.schemata`, maintenance connection) —
    /// the mysql analogue of [`pg_db_exists`](Self::pg_db_exists). Used by the true-delta restore's
    /// COLLISION guard: the binlog-delta shadow name is deterministic per db, so a pre-existing one
    /// means a concurrent same-db import is in flight and this import must refuse WITHOUT dropping it.
    async fn mysql_db_exists(
        &self,
        plan: &MysqlShadowPlan,
        name: &str,
        stage_dir: &Path,
    ) -> Result<bool, Perr> {
        let sql = format!(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = {};",
            mysql_lit(name)
        );
        let (code, out) = self.mysql_run_admin(plan, &sql, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql shadow: could not probe database {name:?} (exit {code}): {out}"
            )));
        }
        Ok(out.trim() == "1")
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
        // SWAP-SAFETY INVARIANT: never move live aside + drop the aside without a populated shadow
        // replacement present. An empty shadow while live is non-empty (e.g. a concurrent same-db
        // import dropped this import's populated shadow) would DESTROY tenant data — abort, leaving
        // LIVE INTACT (no RENAME-aside, no DROP). The caller tears down the (bogus/empty) shadow.
        if swap_would_destroy_live(&live_tables, &shadow_tables) {
            return Err(Perr::Other(format!(
                "mysql shadow swap REFUSED: the shadow {:?} is EMPTY while live {:?} has \
                 {} table(s) — swapping would destroy live data (a concurrent same-db import may \
                 have dropped this import's shadow). Live left intact.",
                plan.shadow_db,
                plan.live_db,
                live_tables.len()
            )));
        }
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

    /// Spawn the task that applies the untrusted tables-only dump into the shadow as the EPHEMERAL
    /// least-privilege user. It DRAINS the streamed body to a staged `dump_path`, REWRITES every
    /// `DEFINER=` clause to the ephemeral apply user ([`rewrite_mysql_definers`]) — so the carried
    /// triggers/routines/events create under the non-superuser apply — then applies the rewritten
    /// dump on stdin (`mysql <shadow>`, `--local-infile=0`, stderr merged). The DEFINER re-point to
    /// the tenant's own role happens after the swap in [`mysql_finalize_shadow`]. (Draining to a file
    /// is why the chunked path and the sidecar path share ONE file-based DEFINER-rewrite seam.)
    fn spawn_mysql_restore(
        &self,
        plan: &MysqlShadowPlan,
        body_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        out_path: PathBuf,
        dump_path: PathBuf,
    ) -> Result<tokio::task::JoinHandle<Result<i32, Perr>>, Perr> {
        use futures::io::AsyncWriteExt as _;
        let backend = self.require_backend()?.clone();
        let image = plan.image.clone();
        let apply_conn = plan.apply_conn();
        let shadow_db = plan.shadow_db.clone();
        let eph_user = plan.eph_user.clone();
        Ok(tokio::spawn(async move {
            // 1. Drain the streamed body to a staged file.
            {
                let mut reader = AsyncChannelReader::new(body_rx);
                let f = tokio::fs::File::create(&dump_path).await.map_err(other)?;
                let mut sink = f.compat_write();
                futures::io::copy(&mut reader, &mut sink)
                    .await
                    .map_err(other)?;
                sink.flush().await.map_err(other)?;
            }
            // 2. Rewrite every `DEFINER=` clause to the ephemeral apply user.
            let raw = tokio::fs::read_to_string(&dump_path).await.map_err(other)?;
            let rewritten = rewrite_mysql_definers(&raw, &MysqlDefinerTarget::Account(eph_user));
            tokio::fs::write(&dump_path, rewritten.as_bytes())
                .await
                .map_err(other)?;
            // 3. Apply the rewritten dump into the shadow AS the ephemeral user. `sh -c '… 2>&1'`
            //    merges stderr so a refused/failed object is diagnosable (run_ephemeral drops a
            //    container's stderr on a non-zero exit); the mysql apply writes nothing to stdout, so
            //    the merge never corrupts a data stream. Only driver-derived flags + the shadow-db
            //    identifier are composed into the command — never the password (it rides in the env).
            let inv = mysql_shadow_invocation(&apply_conn, &shadow_db);
            let cmd = format!("exec {} 2>&1", sh_join(&inv.argv));
            let argv = vec!["sh".to_string(), "-c".to_string(), cmd];
            let infile = tokio::fs::File::open(&dump_path).await.map_err(other)?;
            let mut rdr = infile.compat();
            let out = tokio::fs::File::create(&out_path).await.map_err(other)?;
            let mut sink = out.compat_write();
            backend
                .run_ephemeral(&image, &argv, &inv.env, Some(&mut rdr), &mut sink)
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
        // The capture artifacts a PENDING base→delta chain still references (so the orphan sweep
        // never reclaims a slot a legitimately-pending base still needs). §4 orphan sweep.
        let wanted_capture = self.collect_pending_capture_names().await;
        for (db, cfg) in &self.databases {
            if cfg.compute.as_deref().is_none_or(|c| c.is_empty()) {
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
                    // Orphan pg WAL CAPTURE artifacts (PLAN-sql-true-delta §4): a `brexp_slot_%`
                    // logical slot PINS WAL, so a slot left by an abandoned base→delta chain must be
                    // reclaimed — unless a PENDING base still references it (`wanted_capture`). The
                    // WAL ceiling already bounds the disk; this reclaims the pin promptly. Drop
                    // inactive orphan slots, then their capture roles, then (on the tenant db) their
                    // publications.
                    let slot_sql = "SELECT slot_name FROM pg_replication_slots \
                                    WHERE slot_name LIKE 'brexp\\_slot\\_%' AND NOT active";
                    let slot_inv = psql_invocation(&plan.maint, slot_sql);
                    if let Ok((0, out)) = self
                        .run_sql_capture(&plan.image, &slot_inv.argv, &slot_inv.env, None, &session)
                        .await
                    {
                        for slot in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                            if wanted_capture.contains(slot) {
                                continue;
                            }
                            if self
                                .pg_run_ddl(
                                    &plan,
                                    &format!("SELECT pg_drop_replication_slot({})", pg_lit(slot)),
                                    &session,
                                )
                                .await
                                .is_ok()
                            {
                                dropped += 1;
                            }
                        }
                    }
                    let crole_sql =
                        "SELECT rolname FROM pg_roles WHERE rolname LIKE 'brexp\\_capture\\_%'";
                    let crole_inv = psql_invocation(&plan.maint, crole_sql);
                    if let Ok((0, out)) = self
                        .run_sql_capture(
                            &plan.image,
                            &crole_inv.argv,
                            &crole_inv.env,
                            None,
                            &session,
                        )
                        .await
                    {
                        for role in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                            if wanted_capture.contains(role) {
                                continue;
                            }
                            let q = quote_ident(ExternalSqlKind::Postgres, role);
                            if self
                                .pg_run_ddl(&plan, &format!("DROP ROLE IF EXISTS {q}"), &session)
                                .await
                                .is_ok()
                            {
                                dropped += 1;
                            }
                        }
                    }
                    // Publications are per-db — connect to the tenant db to reclaim orphans (tidiness;
                    // a publication pins no WAL on its own).
                    let maint_live = {
                        let mut c = plan.maint.clone();
                        c.database = plan.live_db.clone();
                        c
                    };
                    let pub_sql =
                        "SELECT pubname FROM pg_publication WHERE pubname LIKE 'brexp\\_pub\\_%'";
                    let pub_inv = psql_invocation(&maint_live, pub_sql);
                    if let Ok((0, out)) = self
                        .run_sql_capture(&plan.image, &pub_inv.argv, &pub_inv.env, None, &session)
                        .await
                    {
                        for p in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
                            if wanted_capture.contains(p) {
                                continue;
                            }
                            let q = quote_ident(ExternalSqlKind::Postgres, p);
                            let pdrop = psql_invocation(
                                &maint_live,
                                &format!("DROP PUBLICATION IF EXISTS {q}"),
                            );
                            if let Ok((0, _)) = self
                                .run_sql_capture(
                                    &plan.image,
                                    &pdrop.argv,
                                    &pdrop.env,
                                    None,
                                    &session,
                                )
                                .await
                            {
                                dropped += 1;
                            }
                        }
                    }
                }
            } else if kind_is_mysql(&cfg.kind)
                && let Ok(plan) = self.mysql_shadow_plan(project, db, cfg, true).await
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
                // Orphan ephemeral apply USERS (`brexp_apply_%`) + binlog-capture READER USERS
                // (`brexp_rd_%`) left by a crash — drop them after their shadow dbs are gone
                // (tidiness: each has a random, never-persisted password and only ever held a grant
                // on the now-dropped shadow db, or REPLICATION SLAVE/CLIENT for the read). The reader
                // user pins no server resource (unlike a pg slot), so this is pure tidiness.
                let user_sql = "SELECT user FROM mysql.user \
                                WHERE user LIKE 'brexp\\_apply\\_%' OR user LIKE 'brexp\\_rd\\_%';";
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

// ===========================================================================================
// pg logical-WAL true-delta: CAPTURE (export) + REPLAY (restore) — PLAN-sql-true-delta Stage 2.
//
// CAPTURE. A managed, dedicated/Single pg db with `delta_capture` sources a row-level delta from
// the server's logical WAL. A BASE (full) resumable export of such a db mints a `FOR ALL TABLES`
// publication + an ephemeral `REPLICATION NOSUPERUSER …` role, then — SNAPSHOT-PINNED — creates a
// `pgoutput` logical replication SLOT over a held `replication=database` session across the base
// `pg_dump --snapshot=<exported snapshot>` (`produce_pg_capture_base`), so the base dump and the
// slot share ONE consistent point and the base↔WAL overlap window is CLOSED (a write committing in
// the old slot-create→dump gap now lands in the WAL ONLY, never also in the dump). Their names + the
// slot's consistent-point LSN + the schema fingerprint are recorded in a `pg_capture.json` sidecar
// beside the resumable member objects. An INCREMENTAL delta export then DRAINS the parent's slot
// (`pg_logical_slot_get_binary_changes` — GET, not peek, so it advances the slot + releases the
// pinned WAL; the drain's hex DATA runs through a NON-merging capture so stderr never co-mingles),
// length-frames each drained message (`pgoutput::frame_message`) into the `PgWalDelta` member, and
// DROPS the slot+publication+role (bounded retention, §4 — also on any drain error). A schema change
// since the base, a lost/missing slot, or `--mode
// differential` all fall back to a full dump for that db.
//
// REPLAY. `restore_pg_true_delta_in_chain` restores the chain's newest FULL dump into the inc2
// atomic shadow, then replays each subsequent `PgWalDelta` onto it — `pgoutput::decode_framed` +
// `pgoutput::render_changes` (injection-safe: identifiers quote_ident'd, values quote_literal'd),
// EXECUTED as the ephemeral NON-superuser owner role (the inc2 HIGH-1 confinement) under
// `standard_conforming_strings = on` + `ON_ERROR_STOP` — before the atomic swap. A render error
// (e.g. `REPLICA IDENTITY NOTHING`) or a replay failure fails the import LOUD (never a partial).
//
// SCOPE: managed dedicated/Single pg only (same as the inc2 shadow path; external + Shared refused).
// Only BASE exports create slots, so an incremental chain WAL-deltas its FIRST delta and full-dumps
// any later link (graceful, consistent). mysql/libsql true-delta are separate later engines.
// ===========================================================================================

/// The capture-sidecar filename written beside a resumable export dir's member objects.
const PG_CAPTURE_SIDECAR: &str = "pg_capture.json";

/// Stale-resumable-base TTL (§4): how long an abandoned-but-resumable BASE export's capture slot is
/// shielded from the startup orphan sweep. A legitimate base→delta chain drains + drops its slot
/// within one base→delta interval; past this age the base is treated as abandoned and the sweep
/// reclaims the slot's WAL pin (the delta that never came falls back to a full dump). Generous (7
/// days) so a deliberate multi-day base→delta workflow still true-deltas; the `max_slot_wal_keep_size`
/// ceiling bounds the disk regardless. Pre-TTL sidecars (no `created_at`) fall back to the file mtime.
const STALE_RESUMABLE_CAPTURE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// The `CREATE_REPLICATION_SLOT` **replication-protocol** command that creates `slot` as a pgoutput
/// logical slot AND exports a consistent snapshot (the point the slot's WAL decoding starts from),
/// to be run over a `replication=database` session that stays OPEN across the paired
/// `pg_dump --snapshot`. PG15+ takes the generic option list `(SNAPSHOT 'export')`; PG9.4–14 takes
/// the positional `EXPORT_SNAPSHOT` keyword. `slot` is a driver-derived identifier (never bundle
/// data / a credential), double-quoted for the replication grammar.
fn create_replication_slot_export_sql(slot: &str, server_version_num: &str) -> String {
    let slot_q = format!("\"{}\"", slot.replace('"', "\"\""));
    let opts = match pg_server_major(server_version_num) {
        Some(m) if m >= 15 => "(SNAPSHOT 'export')",
        _ => "EXPORT_SNAPSHOT",
    };
    format!("CREATE_REPLICATION_SLOT {slot_q} LOGICAL pgoutput {opts};")
}

/// One managed-pg db's capture artifacts, recorded in the resumable dir's `pg_capture.json` so a
/// later INCREMENTAL delta (which references this dir as its parent) can drain the slot. Carries
/// only NON-secret names + the base LSN + the base schema fingerprint — never the ephemeral role's
/// password (the superuser mints it fresh at create and resets it fresh at drain, so no credential
/// is ever persisted on disk).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PgCaptureEntry {
    /// The `pgoutput` logical replication slot name (`brexp_slot_<suffix>`).
    slot: String,
    /// The `FOR ALL TABLES` publication name (`brexp_pub_<suffix>`).
    publication: String,
    /// The ephemeral `REPLICATION NOSUPERUSER …` capture role (`brexp_capture_<suffix>`).
    role: String,
    /// The slot's consistent-point LSN — the point a delta replays FROM. EMPTY until the
    /// SNAPSHOT-PINNED base producer ([`NodeProjectExport::produce_pg_capture_base`]) has created
    /// the slot and read back its `confirmed_flush_lsn`: `pg_begin_capture` only mints the role +
    /// publication, so a sidecar entry with an empty `base_lsn` is a slot that was never
    /// successfully pinned (its delta falls back to a full dump).
    base_lsn: String,
    /// The source schema-ledger fingerprint at capture time. A delta whose current fingerprint
    /// differs MUST fall back to a full dump (logical decoding carries no DDL).
    #[serde(default)]
    schema_fingerprint: Option<String>,
    /// Unix seconds when this capture was begun (the base's slot minted). Used by the startup
    /// orphan sweep's stale-resumable-base TTL (§4): an abandoned-but-resumable base older than
    /// [`STALE_RESUMABLE_CAPTURE_TTL_SECS`] no longer shields its slot from reclamation, so a
    /// forgotten base's WAL pin is freed instead of being held forever. `0` (a pre-TTL sidecar,
    /// absent in the JSON) ⇒ fall back to the sidecar file's mtime for the age.
    #[serde(default)]
    created_at: u64,
}

/// A resumable dir's capture sidecar: per-db capture artifacts keyed by the node's DB binding name.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct PgCaptureSidecar {
    dbs: BTreeMap<String, PgCaptureEntry>,
}

/// Read the capture sidecar from a resumable dir (absent/corrupt ⇒ `None`).
async fn read_pg_capture_sidecar(dir: &Path) -> Option<PgCaptureSidecar> {
    let bytes = tokio::fs::read(dir.join(PG_CAPTURE_SIDECAR)).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The age (seconds) of a resumable dir's capture sidecar FILE, from its mtime — the fallback age
/// for the stale-resumable-base TTL (§4 LOW 4b) when a pre-TTL entry carries no `created_at`. A
/// file we cannot stat / whose mtime is in the future returns `0` (treated as fresh, so the sweep
/// never reclaims a base it cannot age — fail-safe toward retention).
async fn pg_capture_sidecar_age_secs(dir: &Path, now: u64) -> u64 {
    let Ok(meta) = tokio::fs::metadata(dir.join(PG_CAPTURE_SIDECAR)).await else {
        return 0;
    };
    let Ok(modified) = meta.modified() else {
        return 0;
    };
    let mtime_secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(mtime_secs)
}

/// Whether a capture sidecar entry still SHIELDS its slot from the startup orphan sweep (§4 LOW 4b):
/// `true` while the base is within the TTL, `false` once it is stale (abandoned-but-resumable) so the
/// sweep may reclaim the slot's WAL pin. The entry's age is its own `created_at` when recorded
/// (`> 0`), else the `file_age_secs` fallback (the sidecar file's mtime, for a pre-TTL entry). Pure
/// so the §4 TTL decision is unit-mutation-gated (flip the comparison and this flags it).
fn capture_entry_shielded(created_at: u64, file_age_secs: u64, now: u64, ttl: u64) -> bool {
    let age = if created_at > 0 {
        now.saturating_sub(created_at)
    } else {
        file_age_secs
    };
    age <= ttl
}

/// Build a capture-role connection by swapping the identity of a superuser connection (same
/// host/port/db; the ephemeral role + its freshly-minted password).
fn capture_role_conn(su: &PgConnection, role: &str, password: &str) -> PgConnection {
    let mut c = su.clone();
    c.user = role.to_string();
    c.password = password.to_string();
    c
}

impl NodeProjectExport {
    /// Whether a db binding is eligible for pg WAL true-delta capture: MANAGED + postgres +
    /// `delta_capture` on + dedicated/Single (NOT external, NOT Shared — the inc2 shadow-path
    /// restriction). A Shared multi-tenant server's cross-tenant publication is out of scope.
    fn pg_capture_eligible(cfg: &ExternalDatabaseConfig) -> bool {
        is_managed_binding(cfg)
            && kind_is_postgres(&cfg.kind)
            && cfg.delta_capture
            && !matches!(cfg.tenant, crate::config::TenantIsolation::Shared)
    }

    /// Whether a configured db is a MANAGED postgres binding (its SQL members take the atomic
    /// shadow true-delta restore path, not `restore_member`).
    fn is_managed_pg(&self, db: &str) -> bool {
        self.databases
            .get(db)
            .map(|c| is_managed_binding(c) && kind_is_postgres(&c.kind))
            .unwrap_or(false)
    }

    /// Run ONE trusted/driver-generated pg statement as `conn` (psql `-tAc`, ON_ERROR_STOP),
    /// returning `(exit_code, trimmed stdout+stderr)`. A thin wrapper over the containerized client.
    async fn pg_capture_sql(
        &self,
        conn: &PgConnection,
        image: &str,
        sql: &str,
        stage_dir: &Path,
    ) -> Result<(i32, String), Perr> {
        let inv = psql_invocation(conn, sql);
        self.run_sql_capture(image, &inv.argv, &inv.env, None, stage_dir)
            .await
    }

    /// Create one managed pg db's NON-slot capture artifacts at BASE time: an ephemeral
    /// `REPLICATION NOSUPERUSER …` role + a `FOR ALL TABLES` publication (both by the SUPERUSER).
    /// The pgoutput logical SLOT is deliberately NOT created here — it is created SNAPSHOT-PINNED by
    /// [`produce_pg_capture_base`] over a held `replication=database` session, so the base dump
    /// (`pg_dump --snapshot=<name>`) and the slot share ONE consistent point and the base↔WAL
    /// overlap window is closed (PLAN-sql-true-delta Stage-2 MEDIUM). Returns a [`PgCaptureEntry`]
    /// whose `base_lsn` is EMPTY (pending — the producer fills it from the slot's
    /// `confirmed_flush_lsn`). Rolls back the role on a publication failure.
    ///
    /// The role is created with a throwaway random password: it is never persisted, and the
    /// snapshot-pinned producer / the drain each RESET it (superuser `ALTER ROLE … PASSWORD`) to a
    /// fresh value just before use — so no capture-role credential ever lands on disk or outlives
    /// the one operation that needs it.
    async fn pg_begin_capture(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        stage_dir: &Path,
    ) -> Result<PgCaptureEntry, Perr> {
        let (su, image, _ver) = self.resolve_pg(project, db, cfg).await?;
        let suffix = shadow_suffix();
        let slot = format!("brexp_slot_{suffix}");
        let publication = format!("brexp_pub_{suffix}");
        let role = format!("brexp_capture_{suffix}");
        let role_pw = random_token();
        let role_q = quote_ident(ExternalSqlKind::Postgres, &role);
        let pub_q = quote_ident(ExternalSqlKind::Postgres, &publication);

        // SUPERUSER: the ephemeral least-privilege REPLICATION role (so the WAL drain + the
        // snapshot-export session are NOT run as the bootstrap superuser — defence in depth), then
        // the publication. The publication MUST exist before the slot's consistent point (the slot
        // is created just after, by the snapshot-pinned producer): pgoutput decodes the WAL against
        // the HISTORICAL catalog snapshot at each change's LSN, so a publication created AFTER a
        // change's LSN is "not visible" there and the drain errors. `FOR ALL TABLES` is
        // superuser-only; a dedicated/Single db is wholly one tenant's, so it is correct here. The
        // base full dump of a delta_capture db is taken with `pg_dump --no-publications` (see
        // `StageJob::Pg.no_publications`) so this capture publication never lands in the dump and
        // cannot fail the non-superuser shadow restore (`CREATE PUBLICATION` is superuser-only).
        let create_role = format!(
            "CREATE ROLE {role_q} LOGIN PASSWORD {} REPLICATION NOSUPERUSER NOCREATEDB \
             NOCREATEROLE NOBYPASSRLS",
            pg_lit(&role_pw)
        );
        let (code, out) = self
            .pg_capture_sql(&su, &image, &create_role, stage_dir)
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg capture: CREATE capture role for {db:?} exited {code}: {out}"
            )));
        }
        let (code, out) = self
            .pg_capture_sql(
                &su,
                &image,
                &format!("CREATE PUBLICATION {pub_q} FOR ALL TABLES"),
                stage_dir,
            )
            .await?;
        if code != 0 {
            let _ = self
                .pg_capture_sql(
                    &su,
                    &image,
                    &format!("DROP ROLE IF EXISTS {role_q}"),
                    stage_dir,
                )
                .await;
            return Err(Perr::Other(format!(
                "pg capture: CREATE PUBLICATION for {db:?} exited {code}: {out}"
            )));
        }

        let schema_fingerprint = self.schema_fingerprint(project, db).await;
        Ok(PgCaptureEntry {
            slot,
            publication,
            role,
            base_lsn: String::new(), // PENDING — produce_pg_capture_base pins + fills it
            schema_fingerprint,
            created_at: now_secs(),
        })
    }

    /// Produce ONE capture-eligible managed-pg db's BASE member object, SNAPSHOT-PINNED to its
    /// capture slot (PLAN-sql-true-delta Stage-2 MEDIUM — close the base↔WAL overlap window). The
    /// slot (`entry.slot`, minted role + publication already created by `pg_begin_capture`) is
    /// created here, inside ONE ephemeral client container, over a `replication=database` session
    /// that is HELD OPEN across the base `pg_dump --snapshot=<exported snapshot>`: the slot's
    /// consistent point and the dump's snapshot are then the SAME, so a write committing in the old
    /// slot-create→dump window lands in the WAL ONLY (never ALSO in the dump), and its replay is a
    /// clean INSERT — not a duplicate-key `ON_ERROR_STOP` abort. On success the sidecar entry's
    /// `base_lsn` is filled from the slot's `confirmed_flush_lsn` (== the consistent point for a
    /// freshly-created, un-consumed slot).
    ///
    /// Robust + best-effort: if the snapshot-pin cannot be established (replication disabled, an old
    /// slot can't be dropped, the session/dump errors) it DROPS any partial slot, REMOVES the db's
    /// sidecar entry (so its future delta falls back to a full dump), and produces a plain
    /// (un-pinned) base dump — the BASE export still succeeds. Idempotent on resume: a pre-existing
    /// slot of this name is dropped and re-pinned so the dump and slot always share one point.
    async fn produce_pg_capture_base(
        &self,
        project: &str,
        dir: &Path,
        idx: usize,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        stage_dir: &Path,
    ) -> Result<project_bundle::MemberMeta, Perr> {
        let (conn, image, server_version_num) = self.resolve_pg(project, db, cfg).await?;
        // The capture artifacts `pg_begin_capture` recorded (role + publication + slot NAME). Absent
        // ⇒ capture never began for this db; fall straight back to a plain base dump.
        let entry = read_pg_capture_sidecar(dir)
            .await
            .and_then(|s| s.dbs.get(db).cloned());
        let staged = stage_dir.join(format!("pgcap-base-{idx}"));

        if let Some(entry) = entry {
            match self
                .pg_snapshot_pinned_dump(
                    &conn,
                    &image,
                    &server_version_num,
                    &entry,
                    &staged,
                    stage_dir,
                )
                .await
            {
                Ok(base_lsn) => {
                    // Record the consistent point so the manifest cursor is the slot's own LSN.
                    self.pg_sidecar_set_base_lsn(dir, db, &base_lsn).await;
                    let meta = write_member_from_file(dir, idx, &staged).await?;
                    let _ = tokio::fs::remove_file(&staged).await;
                    return Ok(meta);
                }
                Err(e) => {
                    tracing::warn!(db = %db, error = %e, "pg delta capture: could not snapshot-pin the base; this db's delta will fall back to a full dump");
                    // Reclaim the (possibly half-created) slot + forget the entry so neither the
                    // orphan sweep nor the ceiling has to, and the future delta cleanly full-dumps.
                    self.pg_drop_capture(project, db, cfg, &entry, stage_dir)
                        .await;
                    self.pg_sidecar_remove_db(dir, db).await;
                }
            }
        }

        // FALLBACK: a plain (un-pinned) base dump — robustness over true-delta (best-effort).
        let _ = tokio::fs::remove_file(&staged).await;
        let exclude_extensions = self.trusted_extensions.clone();
        let inv = pg_dump_invocation(
            &conn,
            false,
            &server_version_num,
            &exclude_extensions,
            cfg.delta_capture,
        );
        let code = self
            .run_sql_client(&image, &inv.argv, &inv.env, None, &staged)
            .await?;
        if code != 0 {
            let _ = tokio::fs::remove_file(&staged).await;
            return Err(Perr::Other(format!(
                "pg capture base fallback dump for {db:?} exited {code}"
            )));
        }
        let meta = write_member_from_file(dir, idx, &staged).await?;
        let _ = tokio::fs::remove_file(&staged).await;
        Ok(meta)
    }

    /// Create `entry.slot` with an EXPORTED SNAPSHOT over a held `replication=database` session and
    /// run `pg_dump --snapshot=<name>` pinned to it, inside ONE ephemeral container, streaming the
    /// `-Fc` archive to `staged`. Returns the slot's consistent-point LSN
    /// (`confirmed_flush_lsn`). The session is the capture role (non-superuser `REPLICATION`); its
    /// password is RESET fresh by the superuser just before use (never persisted). A pre-existing
    /// slot of the name is dropped first (idempotent re-pin on resume).
    async fn pg_snapshot_pinned_dump(
        &self,
        conn: &PgConnection,
        image: &str,
        server_version_num: &str,
        entry: &PgCaptureEntry,
        staged: &Path,
        stage_dir: &Path,
    ) -> Result<String, Perr> {
        let role_q = quote_ident(ExternalSqlKind::Postgres, &entry.role);
        let slot_lit = pg_lit(&entry.slot);
        // SUPERUSER: drop any stale slot of this name (prior incomplete run), so the dump + slot
        // always share one fresh consistent point; never drop one that isn't ours by name.
        let (code, out) = self
            .pg_capture_sql(
                conn,
                image,
                &format!(
                    "SELECT pg_drop_replication_slot({slot_lit}) WHERE EXISTS (SELECT 1 FROM \
                     pg_replication_slots WHERE slot_name = {slot_lit})"
                ),
                stage_dir,
            )
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg capture: drop stale slot {:?} before re-pin exited {code}: {out}",
                entry.slot
            )));
        }
        // SUPERUSER: reset the capture role's password to a fresh, never-persisted value so the
        // held replication session authenticates (mirrors the drain's reset-on-use pattern).
        let role_pw = random_token();
        let (code, out) = self
            .pg_capture_sql(
                conn,
                image,
                &format!("ALTER ROLE {role_q} PASSWORD {}", pg_lit(&role_pw)),
                stage_dir,
            )
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg capture: reset capture-role password exited {code}: {out}"
            )));
        }

        // The pg_dump flags (NON-pinned) the base would normally use: --no-owner/--no-privileges,
        // the extension-comment handling, --no-publications (the capture publication must not land
        // in the dump), -Fc. We append `--snapshot=<exported snapshot>` in the orchestration.
        let exclude_extensions = self.trusted_extensions.clone();
        let dump = pg_dump_invocation(conn, false, server_version_num, &exclude_extensions, true);
        // argv[0] is "pg_dump"; the rest are flags (no credential, no bundle data) — sh-quote them.
        let dump_flags = sh_join(&dump.argv[1..]);
        let slot_cmd = create_replication_slot_export_sql(&entry.slot, server_version_num);

        // ONE container runs BOTH the held snapshot-export session (as the capture role) and the
        // pinned pg_dump (as the tenant conn). The replication session's stdin is a FIFO kept open
        // by fd 9 so psql never hits EOF (which would close the connection + drop the exported
        // snapshot); after the dump we close fd 9 to release it. The capture-role password rides in
        // $BREXP_CAP_PW (env, never argv); the slot name + flags are driver-derived identifiers.
        let script = format!(
            r#"set -u
COORD=$(mktemp) || exit 91
ERRF=$(mktemp) || exit 91
FIFO=$(mktemp -u) || exit 91
mkfifo "$FIFO" || exit 91
# The held replication session's query result → $COORD; its own stdout → /dev/null so NOTHING but
# the foreground pg_dump's `-Fc` archive ever reaches the container stdout (the member sink).
PGPASSWORD="$BREXP_CAP_PW" psql "host=$PGHOST port=$PGPORT user=$BREXP_CAP_ROLE dbname=$PGDATABASE replication=database" -At -F'|' -o "$COORD" <"$FIFO" >/dev/null 2>"$ERRF" &
REPL=$!
exec 9>"$FIFO"
printf '%s\n' {slot_cmd_q} >&9
SNAP=""
i=0
while [ $i -lt 600 ]; do
  SNAP=$(awk -F'|' 'NR==1{{print $3; exit}}' "$COORD" 2>/dev/null)
  [ -n "$SNAP" ] && break
  i=$((i+1)); sleep 0.1
done
if [ -z "$SNAP" ]; then
  echo "brexp: snapshot export failed: $(cat "$ERRF" 2>/dev/null)" >&2
  exec 9>&-; wait "$REPL" 2>/dev/null; exit 92
fi
pg_dump {dump_flags} --snapshot="$SNAP"
RC=$?
exec 9>&-
wait "$REPL" 2>/dev/null
exit $RC
"#,
            slot_cmd_q = sh_join(&[slot_cmd]),
            dump_flags = dump_flags,
        );
        let mut env = conn.env();
        env.push(("BREXP_CAP_ROLE".to_string(), entry.role.clone()));
        env.push(("BREXP_CAP_PW".to_string(), role_pw));
        let argv = vec!["sh".to_string(), "-c".to_string(), script];
        let code = self
            .run_sql_client(image, &argv, &env, None, staged)
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg capture: snapshot-pinned base dump for slot {:?} exited {code} (snapshot export \
                 or pg_dump failed)",
                entry.slot
            )));
        }
        // The slot now exists at its consistent point; read it back as the recorded base cursor.
        // `confirmed_flush_lsn` of a freshly-created, never-consumed logical slot IS the exported
        // snapshot's consistent point (verified live). Empty ⇒ the slot vanished ⇒ treat as failure.
        let (code, lsn) = self
            .pg_capture_sql(
                conn,
                image,
                &format!(
                    "SELECT confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = {slot_lit}"
                ),
                stage_dir,
            )
            .await?;
        let lsn = lsn.trim().lines().next().unwrap_or("").trim().to_string();
        if code != 0 || lsn.is_empty() {
            return Err(Perr::Other(format!(
                "pg capture: snapshot-pinned slot {:?} has no confirmed_flush_lsn after creation \
                 (exit {code})",
                entry.slot
            )));
        }
        Ok(lsn)
    }

    /// Set `db`'s `base_lsn` in a resumable dir's capture sidecar (the snapshot-pin producer records
    /// the slot's consistent point once the slot is created). No-op if the sidecar/entry is gone.
    async fn pg_sidecar_set_base_lsn(&self, dir: &Path, db: &str, base_lsn: &str) {
        let Some(mut sidecar) = read_pg_capture_sidecar(dir).await else {
            return;
        };
        if let Some(e) = sidecar.dbs.get_mut(db) {
            e.base_lsn = base_lsn.to_string();
            if let Ok(bytes) = serde_json::to_vec_pretty(&sidecar) {
                let _ = write_atomic(&dir.join(PG_CAPTURE_SIDECAR), &bytes).await;
            }
        }
    }

    /// Remove `db`'s entry from a resumable dir's capture sidecar (the snapshot-pin fell back to a
    /// plain dump, so there is no slot to drain — the future delta full-dumps). Deletes the sidecar
    /// file entirely if it becomes empty.
    async fn pg_sidecar_remove_db(&self, dir: &Path, db: &str) {
        let Some(mut sidecar) = read_pg_capture_sidecar(dir).await else {
            return;
        };
        if sidecar.dbs.remove(db).is_some() {
            if sidecar.dbs.is_empty() {
                let _ = tokio::fs::remove_file(dir.join(PG_CAPTURE_SIDECAR)).await;
            } else if let Ok(bytes) = serde_json::to_vec_pretty(&sidecar) {
                let _ = write_atomic(&dir.join(PG_CAPTURE_SIDECAR), &bytes).await;
            }
        }
    }

    /// Drain one managed pg db's capture slot into a framed `pgoutput` byte stream (the `PgWalDelta`
    /// member), then DROP the slot+publication+role (bounded retention, §4). The superuser resets
    /// the capture role's password to a fresh value (so no role credential is persisted), then the
    /// drain runs AS the capture role (non-superuser). Returns `Ok(None)` when the slot is
    /// gone/invalid (reclaimed by the WAL ceiling) — the caller then falls back to a full dump.
    async fn pg_drain_capture(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        entry: &PgCaptureEntry,
        stage_dir: &Path,
    ) -> Result<Option<Vec<u8>>, Perr> {
        let (su, image, _ver) = self.resolve_pg(project, db, cfg).await?;
        let slot_lit = pg_lit(&entry.slot);
        let role_q = quote_ident(ExternalSqlKind::Postgres, &entry.role);

        // Is the slot still present + usable? A slot the WAL ceiling invalidated has wal_status
        // 'lost'; a dropped/absent slot has no row. Either ⇒ no faithful WAL-delta ⇒ full-dump.
        let probe = format!(
            "SELECT coalesce((SELECT wal_status FROM pg_replication_slots WHERE slot_name = \
             {slot_lit}), 'missing')"
        );
        let (code, status) = self.pg_capture_sql(&su, &image, &probe, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg capture: probe slot {:?} exited {code}: {status}",
                entry.slot
            )));
        }
        let status = status.trim();
        if status == "missing" || status == "lost" {
            self.pg_drop_capture(project, db, cfg, entry, stage_dir)
                .await;
            return Ok(None);
        }

        // Reset the capture role's password (superuser), so no credential is persisted on disk. A
        // failure here leaves the slot pinning WAL, so DROP it before returning (§4 LOW 4a:
        // drop-slot-on-drain-error — reclaim the WAL pin promptly; the delta then full-dumps).
        let role_pw = random_token();
        let (code, out) = self
            .pg_capture_sql(
                &su,
                &image,
                &format!("ALTER ROLE {role_q} PASSWORD {}", pg_lit(&role_pw)),
                stage_dir,
            )
            .await?;
        if code != 0 {
            self.pg_drop_capture(project, db, cfg, entry, stage_dir)
                .await;
            return Err(Perr::Other(format!(
                "pg capture: reset capture-role password for {db:?} exited {code}: {out}"
            )));
        }

        // Drain AS the capture role: GET (not peek) advances the slot + releases its pinned WAL.
        // Each row is one raw pgoutput message; hex-encode it over psql's text output (so a binary
        // stream survives the client cleanly), decode, and length-frame for the delta member. The
        // drain's stdout IS a DATA payload (the hex stream), so it runs through the NON-merging
        // capture (§4 LOW A1) — `merge_stderr_argv` must never wrap a data payload, lest a stderr
        // line co-mingle into the hex. On a non-zero exit stderr is dropped (fail-closed).
        let role_conn = capture_role_conn(&su, &entry.role, &role_pw);
        let drain = format!(
            "SELECT encode(data, 'hex') FROM pg_logical_slot_get_binary_changes({slot_lit}, NULL, \
             NULL, 'proto_version', '1', 'publication_names', {})",
            pg_lit(&entry.publication)
        );
        let drain_inv = psql_invocation(&role_conn, &drain);
        let (code, out) = self
            .run_sql_capture_nomerge(&image, &drain_inv.argv, &drain_inv.env, None, stage_dir)
            .await?;
        if code != 0 {
            // §4 LOW 4a: a drain error on a non-`lost`/non-`missing` path reclaims the slot now
            // (the WAL ceiling would eventually, but promptly is better) — the delta full-dumps.
            self.pg_drop_capture(project, db, cfg, entry, stage_dir)
                .await;
            return Err(Perr::Other(format!(
                "pg capture: drain slot {:?} for {db:?} exited {code}",
                entry.slot
            )));
        }
        let mut framed = Vec::new();
        for line in out.lines() {
            let h = line.trim();
            if h.is_empty() {
                continue;
            }
            let raw = match hex::decode(h) {
                Ok(r) => r,
                Err(e) => {
                    // A non-hex drained row (never expected on a clean drain) ⇒ reclaim the slot
                    // (§4 LOW 4a) and fail closed; the delta falls back to a full dump.
                    self.pg_drop_capture(project, db, cfg, entry, stage_dir)
                        .await;
                    return Err(Perr::Other(format!(
                        "pg capture: a drained row is not valid hex for {db:?}: {e}"
                    )));
                }
            };
            framed.extend_from_slice(&boatramp_core::pgoutput::frame_message(&raw));
        }

        // Bounded retention: the delta is captured ⇒ drop the slot+publication+role now.
        self.pg_drop_capture(project, db, cfg, entry, stage_dir)
            .await;
        Ok(Some(framed))
    }

    /// Best-effort teardown of one db's capture artifacts (slot ⇒ publication ⇒ role), as the
    /// SUPERUSER. Called on drain completion, on abort, and from the startup orphan sweep. The slot
    /// is dropped before the role that owns it.
    async fn pg_drop_capture(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        entry: &PgCaptureEntry,
        stage_dir: &Path,
    ) {
        let Ok((su, image, _ver)) = self.resolve_pg(project, db, cfg).await else {
            return;
        };
        let role_q = quote_ident(ExternalSqlKind::Postgres, &entry.role);
        let pub_q = quote_ident(ExternalSqlKind::Postgres, &entry.publication);
        let slot_lit = pg_lit(&entry.slot);
        // Drop the slot only if it still exists (the SQL-function drain leaves no active backend,
        // so a plain drop succeeds). `WHERE EXISTS` keeps it a no-op if already gone.
        let _ = self
            .pg_capture_sql(
                &su,
                &image,
                &format!(
                    "SELECT pg_drop_replication_slot({slot_lit}) WHERE EXISTS (SELECT 1 FROM \
                     pg_replication_slots WHERE slot_name = {slot_lit})"
                ),
                stage_dir,
            )
            .await;
        let _ = self
            .pg_capture_sql(
                &su,
                &image,
                &format!("DROP PUBLICATION IF EXISTS {pub_q}"),
                stage_dir,
            )
            .await;
        let _ = self
            .pg_capture_sql(
                &su,
                &image,
                &format!("DROP ROLE IF EXISTS {role_q}"),
                stage_dir,
            )
            .await;
    }

    /// Try to produce a pg WAL true-delta member for one db from the PARENT base's capture sidecar.
    /// Returns `Some((framed_pgoutput_bytes, PgLsn cursor))` when a faithful WAL delta is available,
    /// or `None` to signal the caller to keep the full-dump fallback. A capture hiccup (drain error)
    /// is logged + treated as a fallback — the delta export itself never fails for a best-effort
    /// true-delta. Falls back when: the db is not capture-eligible, the parent recorded no slot for
    /// it, the SCHEMA FINGERPRINT changed since the base (logical decoding carries no DDL), or the
    /// slot is gone/lost (reclaimed by the WAL ceiling).
    async fn try_pg_wal_delta(
        &self,
        project: &str,
        db: &str,
        sidecar: &PgCaptureSidecar,
        cap_dir: &Path,
    ) -> Option<(Vec<u8>, boatramp_core::project_delta::SqlMemberCursor)> {
        let cfg = self.databases.get(db)?;
        if !Self::pg_capture_eligible(cfg) {
            return None;
        }
        let entry = sidecar.dbs.get(db)?;
        // PENDING/INCOMPLETE capture: an empty `base_lsn` is a sidecar entry whose slot was never
        // successfully snapshot-pinned (the base producer fell back / crashed before filling it), so
        // there is no reliable slot to drain ⇒ full-dump.
        if entry.base_lsn.is_empty() {
            tracing::info!(db = %db, "pg delta: base capture never completed (no pinned slot) — falling back to a full dump");
            return None;
        }
        // SCHEMA-FINGERPRINT FALLBACK: a DDL change between base and delta cannot be WAL-replayed.
        // Treat None==None as "unchanged"; any difference (incl. one side absent) forces a dump.
        let current_fp = self.schema_fingerprint(project, db).await;
        if current_fp != entry.schema_fingerprint {
            tracing::info!(db = %db, "pg delta: schema fingerprint changed since the base — falling back to a full dump");
            return None;
        }
        match self
            .pg_drain_capture(project, db, cfg, entry, cap_dir)
            .await
        {
            Ok(Some(bytes)) => Some((
                bytes,
                boatramp_core::project_delta::SqlMemberCursor::PgLsn {
                    lsn: entry.base_lsn.clone(),
                },
            )),
            Ok(None) => None, // slot lost/missing ⇒ full-dump fallback
            Err(e) => {
                tracing::warn!(error = %e, db = %db, "pg delta: WAL drain failed — falling back to a full dump");
                None
            }
        }
    }

    /// Collect every capture artifact name (slot / role / publication) a PENDING, NOT-YET-STALE base
    /// still references, by scanning the resumable base for `pg_capture.json` sidecars. The orphan
    /// sweep drops only `brexp_*` artifacts NOT in this set, so a legitimately-pending base→delta
    /// chain's slot is never reclaimed from under it — EXCEPT once the base is older than
    /// [`STALE_RESUMABLE_CAPTURE_TTL_SECS`] (§4 LOW 4b): a stale entry stops shielding its slot, so an
    /// abandoned-but-resumable base's WAL pin is reclaimed rather than held forever. An entry's age is
    /// its recorded `created_at` (falling back to the sidecar file's mtime for a pre-TTL sidecar).
    /// Bounded walk; no resumable base ⇒ empty set.
    async fn collect_pending_capture_names(&self) -> std::collections::HashSet<String> {
        let mut wanted = std::collections::HashSet::new();
        let Some(base) = self.resumable_base.as_ref() else {
            return wanted;
        };
        let now = now_secs();
        let mut stack = vec![base.clone()];
        let mut budget = 4096usize; // bound the walk against a pathological tree
        while let Some(dir) = stack.pop() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            if let Some(sidecar) = read_pg_capture_sidecar(&dir).await {
                // A pre-TTL sidecar (every entry `created_at == 0`) has no per-entry age — fall back
                // to the sidecar FILE's mtime as the base's age, computed once per dir.
                let file_age_secs = pg_capture_sidecar_age_secs(&dir, now).await;
                for e in sidecar.dbs.values() {
                    if !capture_entry_shielded(
                        e.created_at,
                        file_age_secs,
                        now,
                        STALE_RESUMABLE_CAPTURE_TTL_SECS,
                    ) {
                        continue; // stale/abandoned base — stop shielding its slot (§4 LOW 4b)
                    }
                    wanted.insert(e.slot.clone());
                    wanted.insert(e.role.clone());
                    wanted.insert(e.publication.clone());
                }
            }
            if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
                while let Ok(Some(ent)) = rd.next_entry().await {
                    if ent.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                        stack.push(ent.path());
                    }
                }
            }
        }
        wanted
    }

    /// Mint the NON-slot capture artifacts (ephemeral REPLICATION role + `FOR ALL TABLES`
    /// publication) for every capture-eligible pg db covered by a BASE (full) resumable export,
    /// writing a PENDING `pg_capture.json` entry (empty `base_lsn`) per db so the later
    /// snapshot-pinned producer can create the slot + fill the LSN, and so a later incremental delta
    /// can drain it. The publication must exist before the slot's consistent point, so this runs
    /// BEFORE member production (the slot is created SNAPSHOT-PINNED during the base dump, see
    /// [`produce_pg_capture_base`]). Idempotent on resume (skips if a sidecar already exists). Failure
    /// to begin capture for one db is NON-fatal: that db simply has no sidecar entry and its future
    /// delta full-dumps (true-delta is best-effort; the export itself must not fail for it).
    async fn pg_capture_base_slots(&self, project: &str, dir: &Path, stage_dir: &Path) {
        if read_pg_capture_sidecar(dir).await.is_some() {
            return; // resume: role+publication already minted (+ any slot the producer pinned).
        }
        let mut sidecar = PgCaptureSidecar::default();
        for (db, cfg) in &self.databases {
            if !Self::pg_capture_eligible(cfg) {
                continue;
            }
            match self.pg_begin_capture(project, db, cfg, stage_dir).await {
                Ok(entry) => {
                    sidecar.dbs.insert(db.clone(), entry);
                }
                Err(e) => {
                    tracing::warn!(error = %e, db = %db, "pg delta capture: could not create a base slot; this db's delta will fall back to a full dump");
                }
            }
        }
        if !sidecar.dbs.is_empty()
            && let Ok(bytes) = serde_json::to_vec_pretty(&sidecar)
        {
            let _ = write_atomic(&dir.join(PG_CAPTURE_SIDECAR), &bytes).await;
        }
    }

    /// Restore every managed-pg db covered by a resolved delta chain via the atomic shadow: the
    /// newest FULL dump in the chain is restored into a fresh shadow, every subsequent `PgWalDelta`
    /// is REPLAYED onto it as the ephemeral NON-superuser role, then the shadow is atomically
    /// swapped in. A render/replay/restore failure drops the shadow (live untouched) and fails the
    /// import loud. (An external pg db never produces a `PgWalDelta` — capture is managed-only — so
    /// a chain carrying one for a non-managed db is a malformed bundle and is refused.)
    async fn restore_pg_true_delta_in_chain(
        &self,
        project: &str,
        chain: &[(PathBuf, project_bundle::StreamManifest)],
        opts: &ImportOptions,
        report: &mut ImportReport,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        // Per managed-pg db: the newest FULL dump (base, or a fallback delta) + the WAL deltas AFTER
        // it, in chain order (a newer full dump supersedes earlier WAL).
        struct DbPlan {
            base: Option<(PathBuf, usize)>,
            wal: Vec<(PathBuf, usize)>,
        }
        let mut per_db: BTreeMap<String, DbPlan> = BTreeMap::new();
        for (dir, m) in chain {
            for (idx, spec) in m.members.iter().enumerate() {
                match spec.kind {
                    MemberKind::PgDump => {
                        if let Some(db) =
                            db_from_pg_member(&spec.path).filter(|d| self.is_managed_pg(d))
                        {
                            let e = per_db.entry(db.to_string()).or_insert(DbPlan {
                                base: None,
                                wal: Vec::new(),
                            });
                            e.base = Some((dir.clone(), idx));
                            e.wal.clear();
                        }
                    }
                    MemberKind::PgWalDelta => {
                        if let Some(db) = db_from_pgwal_member(&spec.path) {
                            if !self.is_managed_pg(db) {
                                return Err(Perr::Other(format!(
                                    "pg true-delta restore: a PgWalDelta member {:?} names db {db:?} \
                                     which is not a managed pg binding on this node — malformed bundle",
                                    spec.path
                                )));
                            }
                            per_db
                                .entry(db.to_string())
                                .or_insert(DbPlan {
                                    base: None,
                                    wal: Vec::new(),
                                })
                                .wal
                                .push((dir.clone(), idx));
                        }
                    }
                    _ => {}
                }
            }
        }
        if per_db.is_empty() {
            return Ok(());
        }
        if !opts.apply {
            // Dry-run: account for each db, touch nothing live.
            report.pg_databases += per_db.len();
            return Ok(());
        }
        for (db, plan_db) in per_db {
            let Some((base_dir, base_idx)) = plan_db.base else {
                return Err(Perr::Other(format!(
                    "pg true-delta restore: db {db:?} has WAL delta member(s) but no full base dump \
                     in the chain — cannot replay onto nothing"
                )));
            };
            let cfg = self
                .databases
                .get(&db)
                .ok_or_else(|| {
                    Perr::Other(format!("import: no database named {db:?} on this node"))
                })?
                .clone();
            let plan = self.pg_shadow_plan(project, &db, &cfg).await?;
            if let Err(e) = self.pg_create_shadow(&plan, stage_dir).await {
                self.pg_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            // FAIL-CLOSED: the replay applies UNTRUSTED decoded SQL, so the apply role MUST be a
            // provable non-superuser (inc2 HIGH-1) — the same guard the chunked dump restore uses.
            if let Err(e) = self
                .pg_assert_not_superuser(&plan.apply_conn(), &plan.image, stage_dir)
                .await
            {
                self.pg_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            let base_obj = base_dir.join(member_object_name(base_idx));
            if let Err(e) = self
                .pg_restore_base_into_shadow(&plan, &base_obj, stage_dir)
                .await
            {
                self.pg_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            for (dir, idx) in &plan_db.wal {
                let framed = tokio::fs::read(dir.join(member_object_name(*idx)))
                    .await
                    .map_err(other)?;
                if let Err(e) = self.pg_replay_wal(&plan, &framed, stage_dir).await {
                    self.pg_drop_shadow(&plan, stage_dir).await;
                    return Err(e);
                }
            }
            if let Err(e) = self.pg_swap_shadow(&plan, stage_dir).await {
                self.pg_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            report.pg_databases += 1;
        }
        Ok(())
    }

    /// Stream a base full-dump member object into a freshly-created shadow via `pg_restore` (as the
    /// ephemeral non-superuser role). A non-zero exit drops nothing here (the caller tears the
    /// shadow down) but surfaces the client's error.
    async fn pg_restore_base_into_shadow(
        &self,
        plan: &PgShadowPlan,
        base_obj: &Path,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let out_path = stage_dir.join(format!("pgwal-base-restore-{}.out", shadow_suffix()));
        let restore = self.spawn_pg_restore(plan, rx, out_path.clone())?;
        // Feed the base dump member object (the raw `pg_dump -Fc` bytes) into the restore's stdin.
        let src = base_obj.to_path_buf();
        let feeder = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut f = tokio::fs::File::open(&src).await?;
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = f.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            Ok::<(), std::io::Error>(())
        });
        let code = restore.await;
        let _ = feeder.await;
        let out = tokio::fs::read_to_string(&out_path)
            .await
            .unwrap_or_default();
        let _ = tokio::fs::remove_file(&out_path).await;
        match code {
            Ok(Ok(0)) => Ok(()),
            Ok(Ok(c)) => Err(Perr::Other(format!(
                "pg true-delta base restore into shadow {:?} exited {c}: {out}",
                plan.shadow_db
            ))),
            Ok(Err(e)) => Err(e),
            Err(je) => Err(other(je)),
        }
    }

    /// Decode + render + EXECUTE one `PgWalDelta` member onto the shadow, as the ephemeral
    /// NON-superuser owner role. The decode/render is the UNTRUSTED-delta trust boundary: a value
    /// that cannot be rendered faithfully (e.g. `REPLICA IDENTITY NOTHING`) is a loud error (the
    /// bundle should then have fallen back to a full dump). `standard_conforming_strings = on`
    /// makes `quote_literal`'s single-quote-doubling the only escaping; `ON_ERROR_STOP` aborts the
    /// psql run on the first failed statement (and the caller drops the shadow — live untouched).
    async fn pg_replay_wal(
        &self,
        plan: &PgShadowPlan,
        framed: &[u8],
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let changes = boatramp_core::pgoutput::decode_framed(framed)
            .map_err(|e| Perr::Other(format!("pg WAL delta: decode failed: {e}")))?;
        let stmts = boatramp_core::pgoutput::render_changes(&changes).map_err(|e| {
            Perr::Other(format!(
                "pg WAL delta: cannot faithfully replay ({e}); such a delta must fall back to a \
                 full dump — refusing a partial restore"
            ))
        })?;
        if stmts.is_empty() {
            return Ok(());
        }
        // The replay script: SCS on (so the rendered literals are the only quoting), then each
        // rendered statement `;`-terminated. `render_changes` emits BEGIN/COMMIT so a source
        // transaction stays atomic on replay; a mid-script failure under ON_ERROR_STOP aborts the
        // run (the caller drops the shadow, so nothing partial reaches live).
        let mut script = String::from("SET standard_conforming_strings = on;\n");
        for s in &stmts {
            script.push_str(s);
            script.push_str(";\n");
        }
        let script_path = stage_dir.join(format!("pgwal-replay-{}.sql", shadow_suffix()));
        tokio::fs::write(&script_path, script.as_bytes())
            .await
            .map_err(other)?;
        let apply = plan.apply_conn();
        // psql reads the replay script from STDIN (so the delta's quoted data never enters argv).
        let argv = vec![
            "psql".to_string(),
            "-v".to_string(),
            "ON_ERROR_STOP=1".to_string(),
        ];
        let r = self
            .run_sql_capture(
                &plan.image,
                &argv,
                &apply.env(),
                Some(&script_path),
                stage_dir,
            )
            .await;
        let _ = tokio::fs::remove_file(&script_path).await;
        let (code, out) = r?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "pg WAL delta replay into shadow {:?} exited {code}: {out}",
                plan.shadow_db
            )));
        }
        Ok(())
    }
}

/// Quote a MySQL **string literal** (single-quoted, doubling embedded `'`) — for our own generated
/// `information_schema` predicates + grant user literals (db/role names are driver-derived).
fn mysql_lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

// ===========================================================================================
// MySQL binlog true-delta: CAPTURE (export) + REPLAY (restore) — PLAN-sql-true-delta Stage 3.
// (Kept textually separate from the pg engine above to minimize merge conflict; it reuses only the
// shared primitives — the inc2 mysql atomic shadow + the resumable member-object layout.)
//
// CAPTURE. A managed, dedicated/Single mysql db with `delta_capture` (the launch argv carries
// `--log-bin --binlog-format=ROW --gtid-mode=ON …`) sources a row-level delta from the server's
// binlog. Unlike pg (whose slot pins a point BEFORE the base dump, leaving an overlap window), the
// mysql base is SNAPSHOT-PINNED: the BASE (full) resumable export dumps it with
// `mysqldump --source-data=2 --set-gtid-purged=COMMENTED` so the dump header records its OWN
// consistent-snapshot `gtid_executed` + binlog file. The driver STRIPS the privileged
// `SET @@SESSION.SQL_LOG_BIN` toggles mysqldump injects (so the member still restores under the
// least-privilege shadow apply user) and records `{base_gtid, start_log, schema_fingerprint}` in a
// `mysql_capture.json` sidecar — the mysql analogue of `pg_capture.json`. There is NO long-lived
// slot: the server retains the binlog (`binlog_expire_logs_seconds`), so an INCREMENTAL delta mints
// an EPHEMERAL `REPLICATION SLAVE, REPLICATION CLIENT` reader user, streams the binlog since the base
// (`mysqlbinlog --read-from-remote-server --raw` — no server-filesystem access), `tar`s the raw files
// into the `MysqlBinlogDelta` member, then drops the reader user. A schema change since the base
// (fingerprint), a DDL `QUERY_EVENT` in the range, a purged start log, or a drain error all fall back
// to a full dump for that db (best-effort true-delta; the delta bundle is always restorable).
//
// REPLAY. `restore_mysql_true_delta_in_chain` restores the chain's newest FULL dump into the inc2
// atomic mysql shadow, then replays each subsequent `MysqlBinlogDelta` onto it. The raw files are
// decoded LOCALLY (so `--exclude-gtids` + `--rewrite-db` are both allowed, unlike a remote read):
// `mysqlbinlog --skip-gtids --exclude-gtids=<base> --rewrite-db='<live>-><shadow>' --database=<shadow>
// … | mysql <shadow>`, EXECUTED as an EPHEMERAL apply user holding `REPLICATION_APPLIER` +
// `SESSION_VARIABLES_ADMIN` + `ALL ON <shadow>.*` ONLY (NO SUPER/FILE/BINLOG_ADMIN, NO global DML) —
// so a crafted binlog's `BINLOG` row event targeting any table outside the shadow is REFUSED by the
// table-privilege check (validated: the applier privilege does NOT bypass it), and the
// `--rewrite-db`/`--database` pair redirects the source db's events to the shadow + DROPS every
// foreign-db event (defense in depth). Then the atomic `RENAME TABLE` swap. A decode/replay failure
// drops the shadow (live untouched) and fails the import loud.
//
// IMAGE. `mysqlbinlog` ships in the DEBIAN variant of the mysql image, not the (Oracle-Linux) default
// `mysql:<maj.min>` the dump/restore use — so capture + replay run in `mysql:<maj.min>-debian`
// (see `mysql_binlog_image`). SCOPE: managed dedicated/Single mysql only (Shared refused, like pg).
// ===========================================================================================

/// The mysql-capture sidecar filename written beside a resumable export dir's member objects.
const MYSQL_CAPTURE_SIDECAR: &str = "mysql_capture.json";

/// One managed-mysql db's base capture coordinate, recorded in the resumable dir's
/// `mysql_capture.json` so a later INCREMENTAL delta can stream the binlog since the base. Carries
/// only NON-secret coordinates (no credential — the ephemeral reader user is minted fresh at drain
/// with a never-persisted password).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MysqlCaptureEntry {
    /// The `gtid_executed` at the base dump's consistent snapshot (parsed from its COMMENTED
    /// `SET @@GLOBAL.GTID_PURGED`). The delta's `--exclude-gtids` replays from exactly this point.
    base_gtid: String,
    /// The binlog file at the base snapshot (parsed from the dump's COMMENTED `CHANGE MASTER TO
    /// MASTER_LOG_FILE`). The delta's `mysqlbinlog -R` streams from this file to the current end.
    start_log: String,
    /// The source schema-ledger fingerprint at capture time. A delta whose current fingerprint
    /// differs MUST fall back to a full dump (binlog ROW events carry no faithful cross-DDL replay).
    #[serde(default)]
    schema_fingerprint: Option<String>,
}

/// A resumable dir's mysql-capture sidecar: per-db base coordinates keyed by the node's binding name.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct MysqlCaptureSidecar {
    dbs: BTreeMap<String, MysqlCaptureEntry>,
}

/// Read the mysql-capture sidecar from a resumable dir (absent/corrupt ⇒ `None`).
async fn read_mysql_capture_sidecar(dir: &Path) -> Option<MysqlCaptureSidecar> {
    let bytes = tokio::fs::read(dir.join(MYSQL_CAPTURE_SIDECAR))
        .await
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The `mysqlbinlog`-bearing client image for a resolved `mysql:<maj.min>` dump/restore image: the
/// DEBIAN variant. The Oracle-Linux default `mysql:<maj.min>` ships `mysql`/`mysqldump` but NOT
/// `mysqlbinlog`; the `-debian` variant ships the full client suite. Idempotent (never double-adds).
fn mysql_binlog_image(client_image: &str) -> String {
    if client_image.ends_with("-debian") {
        client_image.to_string()
    } else {
        format!("{client_image}-debian")
    }
}

/// The transient SHADOW database name a mysql binlog true-delta is captured-rewritten to AND restored
/// into. Derived deterministically from the binding's live db so the CAPTURE rewrite target
/// (`mysqlbinlog --rewrite-db='<live>-><this>'`) and the RESTORE shadow are the SAME db — the member
/// is decoded SQL text (not re-rewritable at replay), so the rewrite is baked at capture against this
/// name. The `__shadow_` infix makes the startup `%__shadow_%` sweep reclaim a crashed one.
///
/// NOTE: this is FIXED per db (not per-import), so two concurrent true-delta imports of the SAME db
/// would collide on `CREATE DATABASE` (a clean refusal, never corruption — the restore never drops a
/// pre-existing shadow). Concurrent-import support is a tracked follow-up.
fn mysql_delta_shadow_db(live_db: &str) -> String {
    // Bounded to the 63-byte limit (truncating the live-db prefix, never the `__shadow_brdelta`
    // marker). Both the CAPTURE rewrite target and the RESTORE shadow call THIS function, so they
    // stay the SAME derived name even after truncation.
    bounded_derived_db_name(live_db, "__shadow_", "brdelta")
}

/// SWAP-SAFETY INVARIANT (data-loss guard): `true` when swapping the shadow in for live would move
/// the LIVE tables aside with NO shadow replacement to put back — i.e. the shadow is EMPTY while
/// live is non-empty. A swap in this state would `RENAME` live aside + `DROP` the aside, DESTROYING
/// tenant data (the same-db import collision race: a colliding import can drop another import's
/// populated shadow, leaving this swap to see an empty shadow). The swap MUST abort here, leaving
/// live intact, rather than empty a tenant's database. (Importing a legitimately-empty database over
/// a non-empty live is also refused by this — an accepted trade for never destroying live data; a
/// genuine "empty the db" is done out of band.)
fn swap_would_destroy_live(live_tables: &[String], shadow_tables: &[String]) -> bool {
    !live_tables.is_empty() && shadow_tables.is_empty()
}

/// Whether a dump line is one of mysqldump's privileged `SQL_LOG_BIN` toggles (emitted by
/// `--source-data`). These need `SESSION_VARIABLES_ADMIN`, which the least-privilege shadow apply
/// user does NOT hold, so the capture-base producer STRIPS them — leaving the COMMENTED GTID/file
/// coordinates (which the sidecar parses) but no executable privileged statement.
fn mysql_line_is_sql_log_bin_toggle(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("SET @MYSQLDUMP_TEMP_LOG_BIN") || t.starts_with("SET @@SESSION.SQL_LOG_BIN")
}

/// The PRIVILEGE part of a `SHOW GRANTS` line — everything BEFORE the first " ON " (which separates
/// the privilege list from the grant TARGET, e.g. `GRANT ALL PRIVILEGES ON \`db\`.* TO …`). The
/// confinement probes match dangerous privilege TOKENS against THIS, never the whole line, so a db
/// NAMED after " ON " (e.g. `supervisors`, `filestore`, `profiles` → "SUPER"/"FILE") cannot
/// false-trip the SUPER/FILE/BINLOG_ADMIN substring checks. A backticked target db that itself
/// contains " ON " stays after the first split, so the privilege part is unaffected.
fn mysql_grant_privileges(line: &str) -> &str {
    line.split(" ON ").next().unwrap_or(line)
}

/// Parse the base snapshot coordinate `(base_gtid, start_log)` from a `--source-data=2
/// --set-gtid-purged=COMMENTED` dump header: the COMMENTED `SET @@GLOBAL.GTID_PURGED='+<gtid>'` and
/// the COMMENTED `CHANGE MASTER TO MASTER_LOG_FILE='<file>'`. `None` if either is absent (⇒ the db
/// is not binlog/GTID-enabled as expected, so the delta falls back to a full dump).
fn parse_mysql_base_coord(header: &str) -> Option<(String, String)> {
    let between = |hay: &str, open: &str| -> Option<String> {
        let start = hay.find(open)? + open.len();
        let rest = &hay[start..];
        let end = rest.find('\'')?;
        Some(rest[..end].to_string())
    };
    let gtid = between(header, "GTID_PURGED='")?;
    // The COMMENTED form prefixes the set with a `+` (`'+<gtid>'`); drop it for the raw GTID set.
    let gtid = gtid.trim_start_matches('+').to_string();
    let start_log = between(header, "MASTER_LOG_FILE='")?;
    if gtid.is_empty() || start_log.is_empty() {
        return None;
    }
    Some((gtid, start_log))
}

/// Whether a `mysqlbinlog`-decoded delta carries a DDL `QUERY_EVENT` in the range — in which case the
/// delta MUST fall back to a full dump (binlog ROW events replay DML faithfully, but a schema change
/// between base and delta cannot be row-replayed onto the base). In `binlog_format=ROW`, DML is a
/// `BINLOG '…'` base64 statement (zero bare SQL), so the ONLY bare SQL statements a clean ROW delta
/// emits are the session-context `SET`s + transaction control (`BEGIN`/`COMMIT`/…); ANY other bare
/// statement (a `CREATE`/`ALTER`/`DROP`/`RENAME`/`TRUNCATE`/`GRANT`/…) is a DDL event ⇒ fall back.
fn mysql_binlog_decoded_has_ddl(decoded: &str) -> bool {
    for raw in decoded.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#') // event header / verbose comment
            || line.starts_with("/*") // conditional-comment-wrapped directive
            || line.starts_with("DELIMITER")
            || line.starts_with("SET ") // session context + GTID_NEXT + PSEUDO_SLAVE_MODE
            || line.starts_with("BINLOG ") // the base64 ROW payload opener
            || line == "'" // BINLOG payload terminators / `'/*!*/;`
            || line.starts_with("'/*")
        {
            continue;
        }
        let up = line.to_ascii_uppercase();
        // Transaction control is not DDL.
        if up.starts_with("BEGIN")
            || up.starts_with("COMMIT")
            || up.starts_with("ROLLBACK")
            || up.starts_with("START TRANSACTION")
            || up.starts_with("SAVEPOINT")
            || up.starts_with("RELEASE SAVEPOINT")
        {
            continue;
        }
        // A base64 payload body line (no SQL keywords, just base64) — treat as continuation.
        if line
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            continue;
        }
        // Anything else that reaches here is a bare SQL statement ⇒ a DDL event in the range.
        return true;
    }
    false
}

/// Build a reader connection (ephemeral `REPLICATION SLAVE, REPLICATION CLIENT` user) by swapping the
/// identity of the superuser/operator connection (same host/port; fresh user + never-persisted pw).
fn mysql_reader_conn(op: &MysqlConnection, user: &str, password: &str) -> MysqlConnection {
    let mut c = op.clone();
    c.user = user.to_string();
    c.password = password.to_string();
    c
}

impl NodeProjectExport {
    /// Whether a db binding is eligible for mysql binlog true-delta capture: MANAGED + mysql +
    /// `delta_capture` on + dedicated/Single (NOT external, NOT Shared — the inc2 shadow-path
    /// restriction; a Shared multi-tenant server's cross-db binlog is out of scope).
    fn mysql_capture_eligible(cfg: &ExternalDatabaseConfig) -> bool {
        is_managed_binding(cfg)
            && kind_is_mysql(&cfg.kind)
            && cfg.delta_capture
            && !matches!(cfg.tenant, crate::config::TenantIsolation::Shared)
    }

    /// Whether a configured db is a MANAGED mysql binding (its SQL members take the atomic shadow
    /// true-delta restore path, not `restore_member`).
    fn is_managed_mysql(&self, db: &str) -> bool {
        self.databases
            .get(db)
            .map(|c| is_managed_binding(c) && kind_is_mysql(&c.kind))
            .unwrap_or(false)
    }

    /// Run ONE trusted/driver-generated mysql statement on a bare connection (no shadow plan), as
    /// `-N --batch` admin SQL fed on stdin. Used for the ephemeral reader-user lifecycle (which has no
    /// shadow). Returns `(exit_code, trimmed stdout+stderr)`.
    async fn mysql_admin_sql(
        &self,
        conn: &MysqlConnection,
        image: &str,
        sql: &str,
        stage_dir: &Path,
    ) -> Result<(i32, String), Perr> {
        let inv = mysql_admin_invocation(conn);
        let in_path = stage_dir.join(format!("mysql-adm-{}.sql", shadow_suffix()));
        tokio::fs::write(&in_path, sql).await.map_err(other)?;
        let r = self
            .run_sql_capture(image, &inv.argv, &inv.env, Some(&in_path), stage_dir)
            .await;
        let _ = tokio::fs::remove_file(&in_path).await;
        r
    }

    /// Produce ONE capture-eligible managed-mysql db's BASE member object (resumable layout): dump it
    /// `--source-data=2 --set-gtid-purged=COMMENTED` (tables-only, snapshot-pinned) to a staging temp,
    /// STRIP the privileged `SET @@SESSION.SQL_LOG_BIN` toggles so the member restores under the
    /// least-privilege shadow apply user, then write it as `m{idx}` (+ meta). The COMMENTED GTID/file
    /// coordinates survive the strip for `mysql_capture_base_gtids` to parse. Mirrors the generic
    /// Sidecar production (stage → `write_member_from_file`) but with the capture dump + strip.
    async fn produce_mysql_capture_base(
        &self,
        project: &str,
        dir: &Path,
        idx: usize,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        stage_dir: &Path,
    ) -> Result<project_bundle::MemberMeta, Perr> {
        let (conn, image, _ver) = self.resolve_mysql(project, db, cfg).await?;
        let inv = mysqldump_capture_base_invocation(&conn);
        let raw = stage_dir.join(format!("mysqlcap-raw-{idx}"));
        let code = self
            .run_sql_client(&image, &inv.argv, &inv.env, None, &raw)
            .await?;
        if code != 0 {
            let _ = tokio::fs::remove_file(&raw).await;
            return Err(Perr::Other(format!(
                "mysql capture base dump for {db:?} exited {code}"
            )));
        }
        // Strip the privileged SQL_LOG_BIN toggles, streaming line-by-line (header+footer only, but
        // scan the whole file) into the final staged temp.
        let stripped = stage_dir.join(format!("mysqlcap-strip-{idx}"));
        {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
            let rd = tokio::fs::File::open(&raw).await.map_err(other)?;
            let mut lines = tokio::io::BufReader::new(rd).lines();
            let mut wr = tokio::fs::File::create(&stripped).await.map_err(other)?;
            while let Some(line) = lines.next_line().await.map_err(other)? {
                if mysql_line_is_sql_log_bin_toggle(&line) {
                    continue;
                }
                wr.write_all(line.as_bytes()).await.map_err(other)?;
                wr.write_all(b"\n").await.map_err(other)?;
            }
            wr.flush().await.map_err(other)?;
        }
        let _ = tokio::fs::remove_file(&raw).await;
        let meta = write_member_from_file(dir, idx, &stripped).await?;
        let _ = tokio::fs::remove_file(&stripped).await;
        Ok(meta)
    }

    /// Write the `mysql_capture.json` base sidecar from the committed base member objects (post the
    /// resumable member loop, mirror of pg's `pg_capture_base_slots` but READING the produced dumps):
    /// for each capture-eligible managed-mysql db, parse the base GTID + start binlog file from its
    /// `sql/<db>.sql` member header + record the schema fingerprint. Idempotent on resume (skips if a
    /// sidecar already exists). A db whose coordinate can't be parsed simply has no entry (its future
    /// delta full-dumps). Non-fatal throughout — true-delta is best-effort.
    async fn mysql_capture_base_gtids(&self, project: &str, dir: &Path, specs: &[MemberSpec]) {
        if read_mysql_capture_sidecar(dir).await.is_some() {
            return; // resume: coordinates already recorded.
        }
        let mut sidecar = MysqlCaptureSidecar::default();
        for (idx, spec) in specs.iter().enumerate() {
            if spec.kind != MemberKind::MysqlDump {
                continue;
            }
            let Some(db) = db_from_mysql_member(&spec.path) else {
                continue;
            };
            let Some(cfg) = self.databases.get(db) else {
                continue;
            };
            if !Self::mysql_capture_eligible(cfg) {
                continue;
            }
            // Read just the dump header (the COMMENTED coordinates are near the top).
            let obj = dir.join(member_object_name(idx));
            let header = match read_file_prefix(&obj, 16 * 1024).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(error = %e, db = %db, "mysql delta: could not read base member header; this db's delta will fall back to a full dump");
                    continue;
                }
            };
            let Some((base_gtid, start_log)) = parse_mysql_base_coord(&header) else {
                tracing::warn!(db = %db, "mysql delta: base dump carries no GTID/binlog coordinate (binlog/gtid not enabled?); this db's delta will fall back to a full dump");
                continue;
            };
            let schema_fingerprint = self.schema_fingerprint(project, db).await;
            sidecar.dbs.insert(
                db.to_string(),
                MysqlCaptureEntry {
                    base_gtid,
                    start_log,
                    schema_fingerprint,
                },
            );
        }
        if !sidecar.dbs.is_empty()
            && let Ok(bytes) = serde_json::to_vec_pretty(&sidecar)
        {
            let _ = write_atomic(&dir.join(MYSQL_CAPTURE_SIDECAR), &bytes).await;
        }
    }

    /// Try to produce a mysql binlog true-delta member for one db from the PARENT base's capture
    /// sidecar. Returns `Some((member_tar_bytes, MysqlGtid cursor))` when a faithful binlog delta is
    /// available, or `None` to keep the full-dump fallback. Falls back when: the db is not
    /// capture-eligible, the parent recorded no coordinate, the SCHEMA FINGERPRINT changed since the
    /// base, the range carries a DDL `QUERY_EVENT`, the start binlog was purged, or the drain errors.
    async fn try_mysql_binlog_delta(
        &self,
        project: &str,
        db: &str,
        sidecar: &MysqlCaptureSidecar,
        cap_dir: &Path,
    ) -> Option<(Vec<u8>, boatramp_core::project_delta::SqlMemberCursor)> {
        let cfg = self.databases.get(db)?;
        if !Self::mysql_capture_eligible(cfg) {
            return None;
        }
        let entry = sidecar.dbs.get(db)?;
        // SCHEMA-FINGERPRINT FALLBACK (mirror pg): a DDL change base→delta cannot be row-replayed.
        let current_fp = self.schema_fingerprint(project, db).await;
        if current_fp != entry.schema_fingerprint {
            tracing::info!(db = %db, "mysql delta: schema fingerprint changed since the base — falling back to a full dump");
            return None;
        }
        match self
            .mysql_drain_binlog(project, db, cfg, entry, cap_dir)
            .await
        {
            Ok(Some(bytes)) => Some((
                bytes,
                boatramp_core::project_delta::SqlMemberCursor::MysqlGtid {
                    gtid: entry.base_gtid.clone(),
                },
            )),
            Ok(None) => None, // purged start log / DDL in range ⇒ full-dump fallback
            Err(e) => {
                tracing::warn!(error = %e, db = %db, "mysql delta: binlog drain failed — falling back to a full dump");
                None
            }
        }
    }

    /// Stream one managed-mysql db's binlog since the base into a `tar` of raw binlog files (the
    /// `MysqlBinlogDelta` member). Mints an EPHEMERAL `REPLICATION SLAVE, REPLICATION CLIENT` reader
    /// user (superuser-created, random never-persisted password), runs `mysqlbinlog -R --raw` from the
    /// base's start binlog `--to-last-log` into the container's bounded `/tmp` tmpfs, `tar`s the raw
    /// files to stdout, then DROPS the reader user. Returns `Ok(None)` (full-dump fallback) when the
    /// start binlog is purged (capture exits non-zero) or the range carries a DDL event.
    async fn mysql_drain_binlog(
        &self,
        project: &str,
        db: &str,
        cfg: &ExternalDatabaseConfig,
        entry: &MysqlCaptureEntry,
        stage_dir: &Path,
    ) -> Result<Option<Vec<u8>>, Perr> {
        let (op, image, _ver) = self.resolve_mysql(project, db, cfg).await?;
        let binlog_image = mysql_binlog_image(&image);
        let live_db = cfg.database.clone().unwrap_or_else(|| db.to_string());
        let shadow_db = mysql_delta_shadow_db(&live_db);
        // A SHORT suffix: `brexp_rd_<suffix>` must fit MySQL's 32-char USER-name cap.
        let suffix = mysql_eph_suffix();
        let reader = format!("brexp_rd_{suffix}");
        let reader_pw = random_token();
        let reader_lit = mysql_lit(&reader);

        // SUPERUSER: mint the ephemeral least-privilege reader user (so the binlog stream is NOT read
        // as the bootstrap superuser — defence in depth). REPLICATION SLAVE + CLIENT are exactly what
        // `mysqlbinlog --read-from-remote-server` needs; nothing else.
        let create = format!(
            "CREATE USER {reader_lit}@'%' IDENTIFIED BY {}; \
             GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO {reader_lit}@'%';",
            mysql_lit(&reader_pw)
        );
        let (code, out) = self
            .mysql_admin_sql(&op, &image, &create, stage_dir)
            .await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql capture: CREATE reader user for {db:?} exited {code}: {out}"
            )));
        }

        // CAPTURE as the reader user: DB-SCOPED + REWRITTEN + gtid-filtered at capture (NOT --raw),
        // decoding straight to stdout = the member. `--rewrite-db='<live>-><shadow>' --database=
        // <shadow>' make the member contain ONLY the app db's events (retargeted to the shadow) — no
        // `mysql`-schema account DDL / other-tenant rows ever enter the exported member (the
        // disclosure fix). `--skip-gtids --exclude-gtids=<base>` give a clean, overlap-free, directly-
        // replayable stream. STDERR is discarded so a failure (purged start log) is a clean non-zero
        // exit ⇒ full-dump fallback, not a corrupt member.
        let reader_conn = mysql_reader_conn(&op, &reader, &reader_pw);
        let cap = mysqlbinlog_capture_invocation(
            &reader_conn,
            &live_db,
            &shadow_db,
            &entry.base_gtid,
            &entry.start_log,
        );
        let cmd = format!("exec {} 2>/tmp/caperr", sh_join(&cap.argv));
        let argv = vec!["sh".to_string(), "-c".to_string(), cmd];
        let member_path = stage_dir.join(format!("mysqlbinlog-{suffix}.sql"));
        let code = self
            .run_sql_client(&binlog_image, &argv, &cap.env, None, &member_path)
            .await;

        // Drop the ephemeral reader user regardless of capture outcome (bounded retention).
        let drop_sql = format!("DROP USER IF EXISTS {reader_lit}@'%';");
        let _ = self
            .mysql_admin_sql(&op, &image, &drop_sql, stage_dir)
            .await;

        let code = code?;
        if code != 0 {
            // Purged start log / unreachable ⇒ best-effort fallback to a full dump.
            let _ = tokio::fs::remove_file(&member_path).await;
            tracing::info!(db = %db, "mysql delta: binlog capture exited non-zero (start log purged, or server unreachable) — falling back to a full dump");
            return Ok(None);
        }
        // LOW-4 bound (export side): the member is read whole into RAM here + at restore; a delta
        // larger than the cap FALLS BACK to a full dump (graceful) rather than ship an unbounded
        // member. The restore enforces the same cap fail-closed for a crafted/oversized member.
        let member_len = tokio::fs::metadata(&member_path)
            .await
            .map_err(other)?
            .len();
        if member_len > MYSQL_DELTA_MEMBER_MAX {
            let _ = tokio::fs::remove_file(&member_path).await;
            tracing::info!(db = %db, member_len, "mysql delta: binlog delta exceeds the member cap — falling back to a full dump");
            return Ok(None);
        }
        let bytes = tokio::fs::read(&member_path).await.map_err(other)?;
        let _ = tokio::fs::remove_file(&member_path).await;

        // DDL-in-range guard: the member is already decoded (db-scoped) SQL text, so scan it directly
        // and fall back to a full dump if the range carries a DDL statement (a schema change the
        // base→delta row replay cannot faithfully reproduce). The fingerprint check already caught NET
        // schema changes; this catches any app-db DDL even if net-neutral. (`mysql`-schema account DDL
        // is already dropped by `--database=<shadow>`, so it never trips this.)
        let decoded = String::from_utf8_lossy(&bytes);
        if mysql_binlog_decoded_has_ddl(&decoded) {
            tracing::info!(db = %db, "mysql delta: a DDL statement is present in the binlog range — falling back to a full dump");
            return Ok(None);
        }
        Ok(Some(bytes))
    }
}

impl NodeProjectExport {
    /// Restore every managed-mysql db covered by a resolved delta chain via the atomic shadow: the
    /// newest FULL dump in the chain is restored into a fresh shadow, every subsequent
    /// `MysqlBinlogDelta` is REPLAYED onto it as the ephemeral apply user (REPLICATION_APPLIER +
    /// SESSION_VARIABLES_ADMIN + ALL on the shadow ONLY), then the shadow is atomically swapped in.
    /// A render/replay/restore failure drops the shadow (live untouched) and fails the import loud.
    /// (An external mysql db never produces a `MysqlBinlogDelta` — capture is managed-only — so a
    /// chain carrying one for a non-managed db is a malformed bundle and is refused.)
    async fn restore_mysql_true_delta_in_chain(
        &self,
        project: &str,
        chain: &[(PathBuf, project_bundle::StreamManifest)],
        opts: &ImportOptions,
        report: &mut ImportReport,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        // Per managed-mysql db: the newest FULL dump (base/fallback) + the binlog deltas AFTER it.
        struct DbPlan {
            base: Option<(PathBuf, usize)>,
            binlog: Vec<(PathBuf, usize)>,
        }
        let mut per_db: BTreeMap<String, DbPlan> = BTreeMap::new();
        for (dir, m) in chain {
            for (idx, spec) in m.members.iter().enumerate() {
                match spec.kind {
                    MemberKind::MysqlDump => {
                        if let Some(db) =
                            db_from_mysql_member(&spec.path).filter(|d| self.is_managed_mysql(d))
                        {
                            let e = per_db.entry(db.to_string()).or_insert(DbPlan {
                                base: None,
                                binlog: Vec::new(),
                            });
                            e.base = Some((dir.clone(), idx));
                            e.binlog.clear();
                        }
                    }
                    MemberKind::MysqlBinlogDelta => {
                        if let Some(db) = db_from_mysqlbinlog_member(&spec.path) {
                            if !self.is_managed_mysql(db) {
                                return Err(Perr::Other(format!(
                                    "mysql true-delta restore: a MysqlBinlogDelta member {:?} names \
                                     db {db:?} which is not a managed mysql binding on this node — \
                                     malformed bundle",
                                    spec.path
                                )));
                            }
                            per_db
                                .entry(db.to_string())
                                .or_insert(DbPlan {
                                    base: None,
                                    binlog: Vec::new(),
                                })
                                .binlog
                                .push((dir.clone(), idx));
                        }
                    }
                    _ => {}
                }
            }
        }
        if per_db.is_empty() {
            return Ok(());
        }
        if !opts.apply {
            report.pg_databases += per_db.len();
            return Ok(());
        }
        for (db, plan_db) in per_db {
            let Some((base_dir, base_idx)) = plan_db.base else {
                return Err(Perr::Other(format!(
                    "mysql true-delta restore: db {db:?} has binlog delta member(s) but no full base \
                     dump in the chain — cannot replay onto nothing"
                )));
            };
            let cfg = self
                .databases
                .get(&db)
                .ok_or_else(|| {
                    Perr::Other(format!("import: no database named {db:?} on this node"))
                })?
                .clone();
            // mysql true-delta capture/replay is DEDICATED/Single-only (same scope as pg), so a
            // Shared binding never reaches here — pass `allow_shared = false` (defense-in-depth).
            let mut plan = self.mysql_shadow_plan(project, &db, &cfg, false).await?;
            // The delta member's row events were db-REWRITTEN at capture to the deterministic delta
            // shadow name (the member is SQL text, not re-rewritable at replay), so the shadow MUST be
            // exactly that name — override the per-import `__shadow_<hex>` the plan minted. The base
            // tables-only dump restores into any name, so it lands here too; the `RENAME TABLE` swap
            // then moves these tables onto the live db.
            plan.shadow_db = mysql_delta_shadow_db(&plan.live_db);
            // COLLISION guard (data-loss race fix): the delta shadow name is DETERMINISTIC per db,
            // so a pre-existing one means a concurrent same-db import owns it (populated + about to
            // swap). We MUST refuse WITHOUT dropping it — dropping another import's populated shadow
            // would leave ITS swap seeing an empty shadow and destroy live data. Refuse cleanly.
            if self
                .mysql_db_exists(&plan, &plan.shadow_db, stage_dir)
                .await?
            {
                return Err(Perr::Unavailable(format!(
                    "mysql true-delta restore: the delta shadow {:?} already exists — a concurrent \
                     import of db {db:?} is in flight (the binlog-delta shadow name is \
                     deterministic). Retry after it completes.",
                    plan.shadow_db
                )));
            }
            // Now CREATE it (we own it from here). If CREATE fails — including a TOCTOU race where a
            // concurrent import created it between the check above and here — we did NOT create it,
            // so DO NOT drop it (dropping a shadow we don't own is the exact data-loss race): `?`
            // propagates the error WITHOUT a teardown, unlike the drop-on-failure steps below. The
            // ephemeral apply USER is per-import-random, so a create failure is a DB collision, not
            // our user/grant; a startup `%__shadow_%` sweep reclaims any rare half-created leak.
            self.mysql_create_shadow(&plan, stage_dir).await?;
            // The binlog replay needs the apply user to run `BINLOG` row events + the session-context
            // SETs mysqlbinlog emits — grant REPLICATION_APPLIER + SESSION_VARIABLES_ADMIN (on top of
            // the shadow-only ALL). FAIL-CLOSED: then PROVE the apply user is still confined (no
            // SUPER/FILE/BINLOG_ADMIN, no `ALL`/DML on `*.*`), so a crafted binlog cannot escape.
            if let Err(e) = self.mysql_grant_replay(&plan, stage_dir).await {
                self.mysql_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            if let Err(e) = self
                .mysql_assert_replay_user_confined(&plan, stage_dir)
                .await
            {
                self.mysql_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            // Restore the base tables-only dump into the shadow AS the apply user (the inc2 split).
            if let Err(e) = self
                .mysql_restore_base_into_shadow(
                    &plan,
                    &base_dir.join(member_object_name(base_idx)),
                    stage_dir,
                )
                .await
            {
                self.mysql_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            // Replay each `MysqlBinlogDelta` member onto the shadow. The member is db-scoped SQL text
            // (`BINLOG '…'` row events) already rewritten to the shadow at capture, so the replay is a
            // direct `mysql <shadow> < member` as the ephemeral apply user — no `mysqlbinlog` decode,
            // no rewrite, no gtid flags (all baked at capture).
            for (dir, idx) in &plan_db.binlog {
                let member_path = dir.join(member_object_name(*idx));
                // LOW-4: the member is read WHOLE into RAM here (the db-scoped SQL-text member is
                // applied via stdin). Cap it fail-closed so a crafted/oversized member cannot OOM the
                // node (the previous `--raw`-to-tmpfs path bounded this at 64 MiB; the SQL-text path
                // needs its own bound). A legit delta beyond the cap full-dumps at EXPORT instead.
                let member_len = tokio::fs::metadata(&member_path)
                    .await
                    .map_err(other)?
                    .len();
                if member_len > MYSQL_DELTA_MEMBER_MAX {
                    self.mysql_drop_shadow(&plan, stage_dir).await;
                    return Err(Perr::Other(format!(
                        "mysql true-delta restore REFUSED: binlog delta member {} is {member_len} \
                         bytes, over the {MYSQL_DELTA_MEMBER_MAX}-byte cap — refusing to read an \
                         oversized untrusted member into memory",
                        member_path.display()
                    )));
                }
                let member = tokio::fs::read(&member_path).await.map_err(other)?;
                if let Err(e) = self.mysql_replay_binlog(&plan, &member, stage_dir).await {
                    self.mysql_drop_shadow(&plan, stage_dir).await;
                    return Err(e);
                }
            }
            if let Err(e) = self.mysql_swap_shadow(&plan, stage_dir).await {
                self.mysql_drop_shadow(&plan, stage_dir).await;
                return Err(e);
            }
            report.pg_databases += 1;
        }
        Ok(())
    }

    /// Restore a base full-dump member object into the freshly-created shadow via `mysql <shadow>`
    /// (as the ephemeral apply user). The member is the tables-only base dump; a non-zero exit
    /// surfaces the client's error (the caller tears the shadow down).
    async fn mysql_restore_base_into_shadow(
        &self,
        plan: &MysqlShadowPlan,
        base_obj: &Path,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let inv = mysql_shadow_invocation(&plan.apply_conn(), &plan.shadow_db);
        let merged = merge_stderr_argv(&inv.argv);
        let out = stage_dir.join(format!("mysqlbase-{}.out", shadow_suffix()));
        let code = self
            .run_sql_client(&plan.image, &merged, &inv.env, Some(base_obj), &out)
            .await?;
        let diag = tokio::fs::read_to_string(&out).await.unwrap_or_default();
        let _ = tokio::fs::remove_file(&out).await;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql true-delta base restore into shadow {:?} exited {code}: {}",
                plan.shadow_db,
                diag.trim()
            )));
        }
        Ok(())
    }

    /// TRUSTED DDL: grant the shadow apply user the two dynamic privileges the binlog replay needs —
    /// `REPLICATION_APPLIER` (to execute `BINLOG` row events) and `SESSION_VARIABLES_ADMIN` (to set
    /// the session-context vars mysqlbinlog emits, e.g. `pseudo_slave_mode`/`pseudo_thread_id`).
    /// NEITHER grants table access outside the shadow nor `SUPER`/`FILE`/`BINLOG_ADMIN`, so the apply
    /// stays confined (asserted next). Run by the SUPERUSER / maintenance connection.
    async fn mysql_grant_replay(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let user_lit = mysql_lit(&plan.eph_user);
        let sql =
            format!("GRANT REPLICATION_APPLIER, SESSION_VARIABLES_ADMIN ON *.* TO {user_lit}@'%';");
        let (code, out) = self.mysql_run_admin(plan, &sql, stage_dir).await?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql true-delta: GRANT replay privileges to the apply user exited {code}: {out}"
            )));
        }
        Ok(())
    }

    /// Fail-closed probe: refuse the untrusted binlog replay unless the apply user's grants carry NO
    /// `SUPER`, `FILE`, or `BINLOG_ADMIN`, and NO privilege on `*.*` BEYOND the exact two replay
    /// dynamics (`REPLICATION_APPLIER`, `SESSION_VARIABLES_ADMIN`) plus the harmless `USAGE`. So a
    /// crafted binlog applied as this user cannot escape the shadow (its DML on any table outside the
    /// shadow is refused by the table-privilege check — the applier privilege does NOT bypass it).
    async fn mysql_assert_replay_user_confined(
        &self,
        plan: &MysqlShadowPlan,
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let apply = plan.apply_conn();
        let inv = mysql_admin_invocation(&apply);
        let in_path = stage_dir.join(format!("mysql-replay-probe-{}.sql", shadow_suffix()));
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
                "mysql replay: could not probe the apply user's grants (exit {code}): {out}"
            )));
        }
        for line in out.lines() {
            // Match the privilege TOKENS (BEFORE " ON "), never the whole line — else a db named e.g.
            // `supervisors`/`filestore`/`profiles` in the grant TARGET false-refuses a legit restore.
            let privs = mysql_grant_privileges(line).to_ascii_uppercase();
            let up = line.to_ascii_uppercase();
            if privs.contains("SUPER") || privs.contains("FILE") || privs.contains("BINLOG_ADMIN") {
                return Err(Perr::Other(format!(
                    "mysql replay REFUSED: the apply user holds SUPER/FILE/BINLOG_ADMIN; an untrusted \
                     binlog must only be replayed by a least-privilege user. grants: {out}"
                )));
            }
            // A `… ON *.*` grant is allowed ONLY when its PRIVILEGES are exactly the replay dynamics
            // (or USAGE). The db-scoped `ALL ON \`<shadow>\`.*` grant has no " ON *.*" and is fine.
            if up.contains(" ON *.*") {
                let ok = privs.contains("USAGE")
                    || privs.contains("REPLICATION_APPLIER")
                    || privs.contains("SESSION_VARIABLES_ADMIN");
                let has_broad_dml = privs.contains("ALL PRIVILEGES")
                    || privs.contains("INSERT")
                    || privs.contains("UPDATE")
                    || privs.contains("DELETE")
                    || privs.contains("CREATE")
                    || privs.contains("DROP");
                if !ok || has_broad_dml {
                    return Err(Perr::Other(format!(
                        "mysql replay REFUSED: the apply user holds a global `*.*` privilege beyond \
                         the replay dynamics (REPLICATION_APPLIER / SESSION_VARIABLES_ADMIN); an \
                         untrusted binlog must stay confined to the shadow. grants: {out}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// EXECUTE one `MysqlBinlogDelta` member onto the shadow, as the ephemeral apply user. The member
    /// is already-decoded, db-SCOPED SQL text (`BINLOG '…'` row events) rewritten to the shadow AT
    /// CAPTURE, so the replay is a direct `mysql <shadow> < member` — NO `mysqlbinlog`, NO rewrite, NO
    /// gtid flags (all baked at capture). The apply user holds `REPLICATION_APPLIER` (to run the
    /// `BINLOG` events) + `SESSION_VARIABLES_ADMIN` (the session-context SETs) + `ALL ON <shadow>.*`
    /// only, and `--local-infile=0` disables client-side `LOAD DATA LOCAL`. CONFINEMENT: a tampered
    /// member whose events name a db outside the shadow is DENIED by the table-privilege check (the
    /// applier privilege does NOT bypass it — validated), `mysql` errors, and the caller drops the
    /// shadow — nothing partial reaches live. Garbage bytes likewise fail to parse and are refused.
    async fn mysql_replay_binlog(
        &self,
        plan: &MysqlShadowPlan,
        member: &[u8],
        stage_dir: &Path,
    ) -> Result<(), Perr> {
        let apply = plan.apply_conn();
        // `mysql <shadow> --local-infile=0` reading the member SQL text on stdin, as the apply user.
        // `merge_stderr_argv` folds the client's STDERR (a denied/failed statement) into the captured
        // sink so a refusal is diagnosable (run_ephemeral drops stderr on a non-zero exit).
        let inv = mysql_shadow_invocation(&apply, &plan.shadow_db);
        let merged = merge_stderr_argv(&inv.argv);
        let member_path = stage_dir.join(format!("mysqlreplay-{}.sql", shadow_suffix()));
        tokio::fs::write(&member_path, member)
            .await
            .map_err(other)?;
        let out = stage_dir.join(format!("mysqlreplay-{}.out", shadow_suffix()));
        let code = self
            .run_sql_client(&plan.image, &merged, &inv.env, Some(&member_path), &out)
            .await;
        let _ = tokio::fs::remove_file(&member_path).await;
        let diag = tokio::fs::read_to_string(&out).await.unwrap_or_default();
        let _ = tokio::fs::remove_file(&out).await;
        let code = code?;
        if code != 0 {
            return Err(Perr::Other(format!(
                "mysql binlog delta replay into shadow {:?} exited {code}: {}",
                plan.shadow_db,
                diag.trim()
            )));
        }
        Ok(())
    }
}

// ===========================================================================================
// libsql CHANGESET true-delta: CAPTURE (export) + REPLAY (restore) — SQL true-delta program, Stage 4.
// (Textually separate from the pg/mysql engines above to minimize merge conflict; it reuses only the
// resumable member-object layout + the libsql backend's atomic shadow primitives.)
//
// CAPTURE. libsql has no server change stream, so the base is a FIXED FILE: every resumable export
// (base AND delta) snapshots each local libsql site's DB (`snapshot_delta_base` = VACUUM INTO +
// integrity-check) into `libsql_capture/<n>.db` and records its SHA-256 in a `libsql_capture.json`
// sidecar (keyed by SITE) — the libsql analogue of `pg_capture.json`/`mysql_capture.json`. A later
// DELTA export whose base recorded a snapshot diffs the live DB against it with the SQLite session
// engine (`capture_delta_changeset`), shipping the resulting changeset as a `LibsqlChangeset` member
// IN PLACE OF the full dump. A schema change since the base, a PK-less table, a missing/mismatched
// base snapshot, or any diff failure FALLS BACK to a full dump for that site (best-effort true-delta;
// the delta bundle is always a complete point-in-time). BOTH differential (vs the fixed root base)
// and incremental (vs the parent) modes are supported — the base snapshot is a re-diffable file,
// unlike pg's single advancing slot / mysql's one-shot binlog coordinate (incremental-only).
//
// REPLAY. `restore_libsql_true_delta_in_chain` resolves, per site, the newest FULL base `Libsql`
// member (its snapshot + sha from that link's `libsql_capture.json`) + the subsequent `LibsqlChangeset`
// members, and hands them to `restore_delta_changeset_chain`: copy the sha-verified base snapshot
// into a fresh `*.shadow_*`, apply each changeset CONFINED to the base's own tables (abort on any
// conflict / refuse any foreign table), integrity-check, then atomically rename the shadow over live.
// A decode/apply failure drops the shadow (live untouched) and fails the import loud. In-process,
// no Docker — the engine is embedded libsql.
//
// SCOPE: local single-node libsql (the managed default). Feature-gated (`sql-delta-libsql`); an
// off build never captures and REFUSES to restore a changeset member (never a silent full-dump).
// ===========================================================================================

/// The libsql-capture sidecar filename written beside a resumable export dir's member objects.
const LIBSQL_CAPTURE_SIDECAR: &str = "libsql_capture.json";

/// One libsql site's base-snapshot record in `libsql_capture.json`: the snapshot file (RELATIVE to
/// the resumable dir) a later delta diffs against + the restore applies changesets onto, and its
/// SHA-256 (the base cursor — it NAMES the base and lets capture + restore prove same bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LibsqlCaptureEntry {
    /// The base snapshot path, RELATIVE to the resumable dir (e.g. `libsql_capture/0.db`).
    snapshot_file: String,
    /// The base snapshot's SHA-256 (lowercase hex) — the `LibsqlChangesetBase` cursor value.
    base_sha256: String,
}

/// A resumable dir's libsql-capture sidecar: per-site base snapshots keyed by SITE name.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct LibsqlCaptureSidecar {
    sites: BTreeMap<String, LibsqlCaptureEntry>,
}

/// Read the libsql-capture sidecar from a resumable dir (absent/corrupt ⇒ `None`).
async fn read_libsql_capture_sidecar(dir: &Path) -> Option<LibsqlCaptureSidecar> {
    let bytes = tokio::fs::read(dir.join(LIBSQL_CAPTURE_SIDECAR))
        .await
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// CONFINE a base-snapshot path from the (untrusted) `libsql_capture.json` sidecar under `base_dir`
/// before it is read/copied — the `snapshot_file` string travels with the bundle across the import
/// trust boundary, so it is treated exactly like `resolve_resumable_dir` treats an operator-named
/// dir: reject an empty / absolute / `..`-or-`.`-bearing relative path, then canonicalize and assert
/// the result still lives under `base_dir` (defeats a symlink planted in the bundle dir). Returns the
/// confined absolute path or a loud [`Perr`] — never a path that escapes the bundle dir. (Security
/// review Stage 4, Finding 1: an unconfined join enabled `/dev/zero` DoS + out-of-tree file reads.)
#[cfg(any(feature = "sql-delta-libsql", test))]
fn confine_bundle_snapshot(base_dir: &Path, snapshot_file: &str) -> Result<PathBuf, Perr> {
    use std::path::Component;
    let rel = Path::new(snapshot_file);
    if rel.as_os_str().is_empty()
        || rel.is_absolute()
        || rel.components().any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(Perr::Other(format!(
            "libsql delta: refusing out-of-tree base snapshot path {snapshot_file:?}"
        )));
    }
    let joined = base_dir.join(rel);
    // Resolve symlinks + `.`; the canonical path MUST stay under the canonical base dir.
    let canon_base = std::fs::canonicalize(base_dir).map_err(|e| {
        Perr::Other(format!(
            "libsql delta: canonicalize base dir {}: {e}",
            base_dir.display()
        ))
    })?;
    let canon = std::fs::canonicalize(&joined).map_err(|e| {
        Perr::Other(format!(
            "libsql delta: base snapshot {snapshot_file:?} not found/canonicalize: {e}"
        ))
    })?;
    if !canon.starts_with(&canon_base) {
        return Err(Perr::Other(format!(
            "libsql delta: base snapshot path {snapshot_file:?} escapes the bundle dir (symlink?)"
        )));
    }
    Ok(canon)
}

impl NodeProjectExport {
    /// Snapshot every local libsql site's DB as a delta BASE into `dir/libsql_capture/` and record
    /// each one's sha in `libsql_capture.json`. Best-effort: a site that fails to snapshot is simply
    /// omitted (it full-dumps at the next delta). Enumerates sites AUTHORITATIVELY from the deploy
    /// store (never a filesystem walk), exactly like `plan_export`.
    #[cfg(feature = "sql-delta-libsql")]
    async fn libsql_capture_base_snapshots(&self, project: &str, dir: &Path) {
        let Some(libsql) = &self.libsql else {
            return;
        };
        let sites = match self.deploy.list_sites(ProjectRef::new(project)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%project, error = %e, "libsql delta capture: list_sites failed; skipping base snapshots");
                return;
            }
        };
        let mut sidecar = LibsqlCaptureSidecar::default();
        for (i, site) in sites.into_iter().enumerate() {
            let qsite = ProjectRef::new(project).qualified(&site);
            if !libsql.local_database_exists(&qsite, "") {
                continue; // a site that never wrote SQL — nothing to snapshot
            }
            // Opaque per-site filename (the sidecar records the site→file mapping, so the name needs
            // no site-derived escaping).
            let rel = format!("libsql_capture/{i}.db");
            let dest = dir.join(&rel);
            match libsql.snapshot_delta_base(&qsite, "", &dest).await {
                Ok(sha) => {
                    sidecar.sites.insert(
                        site,
                        LibsqlCaptureEntry {
                            snapshot_file: rel,
                            base_sha256: sha,
                        },
                    );
                }
                Err(e) => {
                    tracing::warn!(%project, %site, error = %e, "libsql delta capture: base snapshot failed; this site will full-dump at the next delta");
                }
            }
        }
        if !sidecar.sites.is_empty()
            && let Ok(bytes) = serde_json::to_vec_pretty(&sidecar)
        {
            let _ = write_atomic(&dir.join(LIBSQL_CAPTURE_SIDECAR), &bytes).await;
        }
    }

    /// Try to produce a libsql CHANGESET delta for `site` against the parent base snapshot named by
    /// `entry`. Returns `Some((framed_changeset_bytes, cursor))` on success, or `None` for ANY
    /// fallback (engine not built, no libsql backend, missing/mismatched base, schema drift, PK-less
    /// table, or a diff failure) — the caller then keeps the full dump.
    async fn try_libsql_changeset_delta(
        &self,
        project: &str,
        site: &str,
        entry: &LibsqlCaptureEntry,
        base_dir: &Path,
        cap_dir: &Path,
    ) -> Option<(Vec<u8>, boatramp_core::project_delta::SqlMemberCursor)> {
        // Silence unused-param warnings in an off build (no engine to call).
        let _ = (project, site, entry, base_dir, cap_dir);
        #[cfg(feature = "sql-delta-libsql")]
        {
            use boatramp_storage::sql_libsql_changeset::ChangesetCapture;
            let libsql = self.libsql.as_ref()?;
            let qsite = ProjectRef::new(project).qualified(site);
            if !libsql.local_database_exists(&qsite, "") {
                return None; // site has no live DB now → keep the full-dump member path
            }
            // Confine the sidecar-named base snapshot under base_dir before use (a bad/escaping path
            // → full-dump fallback, never a traversal). Trusted side here (our own export output),
            // but held to the same confinement as the restore side — defense in depth.
            let base_snapshot = match confine_bundle_snapshot(base_dir, &entry.snapshot_file) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(%project, %site, error = %e, "libsql delta: base snapshot path rejected; full-dump fallback");
                    return None;
                }
            };
            match libsql
                .capture_delta_changeset(&qsite, "", &base_snapshot, &entry.base_sha256, cap_dir)
                .await
            {
                Ok(ChangesetCapture::Changeset(cs)) => {
                    let framed = boatramp_core::project_delta::encode_libsql_changeset(&cs);
                    let cursor =
                        boatramp_core::project_delta::SqlMemberCursor::LibsqlChangesetBase {
                            base_sha256: entry.base_sha256.clone(),
                        };
                    Some((framed, cursor))
                }
                Ok(ChangesetCapture::Fallback(reason)) => {
                    tracing::info!(%project, %site, %reason, "libsql delta: full-dump fallback");
                    None
                }
                Err(e) => {
                    tracing::warn!(%project, %site, error = %e, "libsql delta: changeset capture failed; full-dump fallback");
                    None
                }
            }
        }
        #[cfg(not(feature = "sql-delta-libsql"))]
        {
            None
        }
    }

    /// Replay every libsql changeset chain into the atomic shadow. For each site in
    /// `changeset_sites`: resolve the newest FULL base `Libsql` member (a newer full dump supersedes
    /// earlier changesets, like pg/mysql) + its stored base snapshot + the subsequent
    /// `LibsqlChangeset` members in chain order, then `restore_delta_changeset_chain`. A site with no
    /// changeset is restored by the main loop's `restore_member` and never reaches here.
    async fn restore_libsql_true_delta_in_chain(
        &self,
        project: &str,
        chain: &[(PathBuf, project_bundle::StreamManifest)],
        changeset_sites: &std::collections::BTreeSet<String>,
        opts: &ImportOptions,
        report: &mut ImportReport,
    ) -> Result<(), Perr> {
        if changeset_sites.is_empty() {
            return Ok(());
        }
        // Per site: the newest FULL base libsql member (dir) + the changeset members AFTER it.
        struct SitePlan {
            base_dir: Option<PathBuf>,
            changesets: Vec<(PathBuf, usize)>,
        }
        let mut per_site: BTreeMap<String, SitePlan> = BTreeMap::new();
        for (dir, m) in chain {
            for (idx, spec) in m.members.iter().enumerate() {
                match spec.kind {
                    MemberKind::Libsql => {
                        if let Some(site) = site_from_libsql_member(&spec.path)
                            .filter(|s| changeset_sites.contains(*s))
                        {
                            let e = per_site.entry(site.to_string()).or_insert(SitePlan {
                                base_dir: None,
                                changesets: Vec::new(),
                            });
                            e.base_dir = Some(dir.clone());
                            e.changesets.clear();
                        }
                    }
                    MemberKind::LibsqlChangeset => {
                        if let Some(site) = site_from_libsql_changeset_member(&spec.path) {
                            per_site
                                .entry(site.to_string())
                                .or_insert(SitePlan {
                                    base_dir: None,
                                    changesets: Vec::new(),
                                })
                                .changesets
                                .push((dir.clone(), idx));
                        }
                    }
                    _ => {}
                }
            }
        }
        per_site.retain(|_, p| !p.changesets.is_empty());
        if per_site.is_empty() {
            return Ok(());
        }

        #[cfg(not(feature = "sql-delta-libsql"))]
        {
            let _ = (project, opts, report);
            Err(Perr::Unavailable(
                "bundle carries libsql changeset true-delta members but this build lacks the libsql \
                 changeset engine (feature `sql-delta-libsql`) — refusing to restore (never a silent \
                 stale-base full-dump)"
                    .into(),
            ))
        }
        #[cfg(feature = "sql-delta-libsql")]
        {
            let Some(libsql) = self.libsql.clone() else {
                return Err(Perr::Unavailable(
                    "bundle carries libsql changeset members but this node has no local libsql \
                     backend to restore them into"
                        .into(),
                ));
            };
            if !opts.apply {
                report.libsql_databases += per_site.len();
                return Ok(());
            }
            for (site, plan) in per_site {
                let Some(base_dir) = plan.base_dir else {
                    return Err(Perr::Other(format!(
                        "libsql true-delta restore: site {site:?} has changeset member(s) but no full \
                         base libsql member in the chain — cannot replay onto nothing"
                    )));
                };
                // The base snapshot + sha come from the base link's libsql_capture.json sidecar.
                let sidecar = read_libsql_capture_sidecar(&base_dir).await.ok_or_else(|| {
                    Perr::Other(format!(
                        "libsql true-delta restore: base dir {} has no {LIBSQL_CAPTURE_SIDECAR} — \
                         cannot resolve the base snapshot for site {site:?}",
                        base_dir.display()
                    ))
                })?;
                let entry = sidecar.sites.get(&site).ok_or_else(|| {
                    Perr::Other(format!(
                        "libsql true-delta restore: no base snapshot recorded for site {site:?} in \
                         {LIBSQL_CAPTURE_SIDECAR}"
                    ))
                })?;
                // CONFINE the sidecar-named base snapshot under base_dir before reading/copying it
                // (the sidecar is untrusted bundle data) — a bad/escaping path is a hard error, never
                // a traversal / out-of-tree read (Stage 4 security review, Finding 1).
                let base_snapshot = confine_bundle_snapshot(&base_dir, &entry.snapshot_file)?;
                // Decode each changeset member (chain order) into its raw changeset blob.
                let mut changesets: Vec<Vec<u8>> = Vec::with_capacity(plan.changesets.len());
                for (dir, idx) in &plan.changesets {
                    let obj = dir.join(member_object_name(*idx));
                    let bytes = tokio::fs::read(&obj).await.map_err(other)?;
                    let cs = boatramp_core::project_delta::decode_libsql_changeset(&bytes)
                        .map_err(|e| {
                            Perr::Other(format!(
                                "libsql true-delta restore: decode changeset member {}: {e}",
                                obj.display()
                            ))
                        })?;
                    changesets.push(cs);
                }
                let qsite = ProjectRef::new(project).qualified(&site);
                libsql
                    .restore_delta_changeset_chain(
                        &qsite,
                        "",
                        &base_snapshot,
                        &entry.base_sha256,
                        changesets,
                        opts.overwrite,
                    )
                    .await
                    .map_err(other)?;
                report.libsql_databases += 1;
            }
            Ok(())
        }
    }
}

/// Read up to `max` bytes from the start of `path` as a UTF-8 (lossy) string — for parsing a dump's
/// header (the COMMENTED GTID/binlog coordinate) without loading a large member whole.
async fn read_file_prefix(path: &Path, max: usize) -> Result<String, Perr> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await.map_err(other)?;
    let mut buf = vec![0u8; max];
    let n = f.read(&mut buf).await.map_err(other)?;
    buf.truncate(n);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// --- T3 Phase 1: resumable member-object layout helpers --------------------------------

/// The object filename for member `idx` in a resumable export directory. Zero-padded so a
/// directory listing sorts in member (restore) order.
fn member_object_name(idx: usize) -> String {
    format!("m{idx:05}")
}
/// The per-member `{size, sha256}` sidecar filename (a committed member has both).
fn member_meta_name(idx: usize) -> String {
    format!("m{idx:05}.meta")
}
/// The in-progress partial filename (renamed to the object only once fully written).
fn member_part_name(idx: usize) -> String {
    format!("m{idx:05}.part")
}

/// Write `bytes` to `path` atomically: a sibling `.tmp` then rename (so a crash never
/// leaves a half-written manifest/meta that a resume would trust).
async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Perr> {
    let tmp = path.with_extension("writing.tmp");
    tokio::fs::write(&tmp, bytes).await.map_err(other)?;
    tokio::fs::rename(&tmp, path).await.map_err(other)?;
    Ok(())
}

/// Stream-hash a file: its byte length + lowercase-hex SHA-256, read in bounded chunks so a
/// large member never loads whole into memory (preserving the O(chunk) footprint).
async fn sha256_and_size_of_file(path: &Path) -> Result<(u64, String), Perr> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await.map_err(other)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await.map_err(other)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((size, hex::encode(hasher.finalize())))
}

/// Whether member `obj` is COMPLETE: the object + its `.meta` sidecar both exist and the
/// object's streamed size + SHA-256 match the recorded [`MemberMeta`]. A missing sidecar,
/// an unparsable meta, or any size/SHA mismatch (a truncated/partial object) ⇒ not complete,
/// so the resume re-produces it. This is the per-member resume decision.
async fn member_object_valid(obj: &Path, meta: &Path) -> Result<bool, Perr> {
    if !tokio::fs::try_exists(obj).await.map_err(other)?
        || !tokio::fs::try_exists(meta).await.map_err(other)?
    {
        return Ok(false);
    }
    let meta_bytes = tokio::fs::read(meta).await.map_err(other)?;
    let recorded: project_bundle::MemberMeta = match serde_json::from_slice(&meta_bytes) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    let (size, sha) = sha256_and_size_of_file(obj).await?;
    Ok(size == recorded.size && sha == recorded.sha256)
}

/// Produce member `idx`'s object by copying a staged sidecar temp into `dir`, streaming its
/// bytes through the hasher so no whole-member buffer is held. Writes `m{idx}.part` then
/// renames to `m{idx}`; returns the member's `{size, sha256}`.
async fn write_member_from_file(
    dir: &Path,
    idx: usize,
    src: &Path,
) -> Result<project_bundle::MemberMeta, Perr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let part = dir.join(member_part_name(idx));
    let mut rd = tokio::fs::File::open(src).await.map_err(other)?;
    let mut wr = tokio::fs::File::create(&part).await.map_err(other)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = rd.read(&mut buf).await.map_err(other)?;
        if n == 0 {
            break;
        }
        wr.write_all(&buf[..n]).await.map_err(other)?;
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    wr.flush().await.map_err(other)?;
    drop(wr);
    tokio::fs::rename(&part, dir.join(member_object_name(idx)))
        .await
        .map_err(other)?;
    Ok(project_bundle::MemberMeta {
        size,
        sha256: hex::encode(hasher.finalize()),
    })
}

/// Produce member `idx`'s object by draining a chunked body producer into `m{idx}.part`,
/// hashing as it goes, then rename to `m{idx}`. Fails LOUD (no rename, no meta) if the
/// producer POISONED (a short/failed dump) or errored, so a partial member can never be
/// recorded as complete.
async fn write_member_from_producer(
    dir: &Path,
    idx: usize,
    producer: ChunkedProducer,
) -> Result<project_bundle::MemberMeta, Perr> {
    use std::sync::atomic::Ordering::SeqCst;
    use tokio::io::AsyncWriteExt;
    let (mut rx, poison, handle) = producer;
    let part = dir.join(member_part_name(idx));
    let mut wr = tokio::fs::File::create(&part).await.map_err(other)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    while let Some(chunk) = rx.recv().await {
        wr.write_all(&chunk).await.map_err(other)?;
        hasher.update(&chunk);
        size += chunk.len() as u64;
    }
    wr.flush().await.map_err(other)?;
    drop(wr);
    // The producer task's own result + the poison flag are the authenticity of the body:
    // a failed/short dump must NOT be committed as a valid member.
    match handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(Perr::Other(format!("export member producer panicked: {e}"))),
    }
    if poison.load(SeqCst) {
        return Err(Perr::Other(format!(
            "export member {idx} producer poisoned (incomplete body) — not committing"
        )));
    }
    tokio::fs::rename(&part, dir.join(member_object_name(idx)))
        .await
        .map_err(other)?;
    Ok(project_bundle::MemberMeta {
        size,
        sha256: hex::encode(hasher.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_replication_slot_export_sql_is_version_aware_and_quoted() {
        // PG15+ takes the generic option list `(SNAPSHOT 'export')`…
        let pg16 = create_replication_slot_export_sql("brexp_slot_x", "160004");
        assert_eq!(
            pg16,
            "CREATE_REPLICATION_SLOT \"brexp_slot_x\" LOGICAL pgoutput (SNAPSHOT 'export');"
        );
        let pg17 = create_replication_slot_export_sql("brexp_slot_x", "170000");
        assert!(pg17.contains("(SNAPSHOT 'export')"));
        // …PG9.4–14 take the positional EXPORT_SNAPSHOT keyword.
        let pg14 = create_replication_slot_export_sql("brexp_slot_x", "140010");
        assert!(
            pg14.ends_with("LOGICAL pgoutput EXPORT_SNAPSHOT;"),
            "pre-15 must use the positional keyword: {pg14}"
        );
        // An unparseable banner is conservative (treat as old → positional keyword).
        let bad = create_replication_slot_export_sql("brexp_slot_x", "garbage");
        assert!(bad.ends_with("EXPORT_SNAPSHOT;"));
        // The slot name is double-quoted for the replication grammar, embedded `"` doubled.
        let weird = create_replication_slot_export_sql("s\"lot", "160004");
        assert!(
            weird.contains("\"s\"\"lot\""),
            "slot name must be quoted: {weird}"
        );
    }

    #[test]
    fn capture_entry_shielded_applies_the_stale_resumable_ttl() {
        let ttl = STALE_RESUMABLE_CAPTURE_TTL_SECS;
        let now = 1_000_000u64;
        // A FRESH base (created just now) is shielded; one older than the TTL is NOT (§4 LOW 4b).
        assert!(capture_entry_shielded(now - 10, 0, now, ttl));
        assert!(capture_entry_shielded(now - ttl, 0, now, ttl)); // exactly at the TTL still shielded
        assert!(!capture_entry_shielded(now - ttl - 1, 0, now, ttl)); // past the TTL → reclaimable
        // A pre-TTL entry (created_at == 0) falls back to the sidecar FILE age.
        assert!(capture_entry_shielded(0, ttl - 1, now, ttl)); // recent file → shielded
        assert!(!capture_entry_shielded(0, ttl + 1, now, ttl)); // old file → stale
        // A future/garbled created_at never under-ages into staleness (saturating_sub → 0 → shielded).
        assert!(capture_entry_shielded(now + 5, 0, now, ttl));
    }

    /// The `--fresh` drop's keep-set: `self_provisioned_managed_cred_keys` must name EXACTLY the
    /// managed-SQL credential keys this node's own self-provisioning mints for `(project, "")` — so
    /// the drop keeps the freshly cloned tenant's live-matching creds and drops only source-carried
    /// ones. Regression for the clone live gate's 4th issue (fresh tenant's own role could not
    /// connect because the drop wiped its just-minted credential).
    #[test]
    fn self_provisioned_managed_cred_keys_names_only_this_tenants_own_creds() {
        use crate::config::{ExternalDatabaseConfig, TenantIsolation, TenantScope};
        use boatramp_core::project::DEFAULT_PROJECT;
        use std::collections::BTreeMap;

        let binding = |tenant, scope| ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("appdb".into()),
            user: Some("postgres".into()),
            tenant,
            tenant_scope: scope,
            ..Default::default()
        };

        // Shared, project-scoped, NON-default tenant → the login + owner creds (both under the
        // project, the owner one carrying the `/owner` suffix) — and NOTHING else.
        let shared = BTreeMap::from([(
            "app".to_string(),
            binding(TenantIsolation::Shared, TenantScope::Project),
        )]);
        let keys = self_provisioned_managed_cred_keys(&shared, "acme");
        assert_eq!(
            keys.len(),
            2,
            "shared non-default mints login + owner: {keys:?}"
        );
        assert!(
            keys.iter()
                .all(|k| k.starts_with("managed-sql-cred/acme/pg/")),
            "keys are scoped to the project + compute: {keys:?}"
        );
        assert_eq!(
            keys.iter().filter(|k| k.ends_with("/owner")).count(),
            1,
            "exactly one owner-role credential: {keys:?}"
        );

        // No managed bindings → NOTHING is self-provisioned, so a source-carried managed cred
        // restored under this project IS dropped (the `adopt_..._fresh_drops_source_secrets` path).
        assert!(
            self_provisioned_managed_cred_keys(&BTreeMap::new(), "acme").is_empty(),
            "no bindings → empty keep-set"
        );

        // A SITE-scoped binding is skipped by the clone self-provision, so it mints nothing.
        let site = BTreeMap::from([(
            "app".to_string(),
            binding(TenantIsolation::Shared, TenantScope::Site),
        )]);
        assert!(
            self_provisioned_managed_cred_keys(&site, "acme").is_empty(),
            "site-scoped binding mints nothing"
        );

        // The reserved DEFAULT project (shared) is the plain install — the superuser is the app
        // user, so no per-tenant cred is minted.
        assert!(
            self_provisioned_managed_cred_keys(&shared, DEFAULT_PROJECT).is_empty(),
            "the default shared tenant mints nothing"
        );

        // Single, project-scoped → ONE workload credential (no `/owner` role — the container is the
        // isolation), keyed under the tenant's project.
        let single = BTreeMap::from([(
            "app".to_string(),
            binding(TenantIsolation::Single, TenantScope::Project),
        )]);
        let keys = self_provisioned_managed_cred_keys(&single, "acme");
        assert_eq!(
            keys.len(),
            1,
            "single mints exactly one workload cred: {keys:?}"
        );
        let k = keys.iter().next().unwrap();
        assert!(
            k.starts_with("managed-sql-cred/acme/pg-") && !k.ends_with("/owner"),
            "single's cred is the per-tenant workload, not an owner role: {k}"
        );
    }

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
            |h, _s| data_only = h.scope.is_data_only(),
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

    // ---------------------------------------------------------------------------------------------
    // Clone-robustness (PLAN-clone-robustness #2/#3) — fault-injecting target + its tests.
    // ---------------------------------------------------------------------------------------------

    /// A fault-injecting [`Storage`] that wraps an inner backend and fails `put` for a configured set
    /// of keys with a BACKEND error — the stand-in for a blob whose target-write survives the
    /// backend's own bounded retries AND the `complete` HEAD-recovery (s3 Part 1) yet still fails.
    /// Everything else delegates to the inner store. Introduces NO disk buffering: a failed `put`
    /// consumes the body ONE chunk at a time (discarding each — never accumulating a whole blob) and
    /// writes nothing; the inner store streams normally.
    struct FaultStorage {
        inner: std::sync::Arc<dyn boatramp_core::Storage>,
        fail_put_keys: std::collections::BTreeSet<String>,
    }

    #[async_trait::async_trait]
    impl boatramp_core::Storage for FaultStorage {
        async fn get(
            &self,
            key: &str,
        ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            self.inner.get(key).await
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            self.inner.get_range(key, offset, len).await
        }
        async fn put(
            &self,
            key: &str,
            body: boatramp_core::ByteStream,
            meta: boatramp_core::PutMeta,
        ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            if self.fail_put_keys.contains(key) {
                // Consume the body chunk-by-chunk (nothing accumulated, nothing spooled) so the
                // source read completes exactly as a real backend would, THEN fail.
                let mut body = body;
                while let Some(chunk) = body.next().await {
                    chunk?;
                }
                return Err(boatramp_core::StorageError::backend(format!(
                    "injected backend fault writing {key} (survived retries + complete HEAD-recovery)"
                )));
            }
            self.inner.put(key, body, meta).await
        }
        async fn head(
            &self,
            key: &str,
        ) -> Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            self.inner.head(key).await
        }
        async fn delete(&self, key: &str) -> Result<(), boatramp_core::StorageError> {
            self.inner.delete(key).await
        }
        async fn list(
            &self,
            prefix: &str,
        ) -> Result<Vec<boatramp_core::ObjectMeta>, boatramp_core::StorageError> {
            self.inner.list(prefix).await
        }
    }

    /// Seed a source driver with the given blobs, data-only export it to a bundle buffer. Returns
    /// the bundle bytes. (A data-only bundle carries blobs but no KV/DB, keeping these tests focused
    /// on the blob restore seam.)
    async fn source_bundle_with_blobs(
        tmp: &std::path::Path,
        tag: &str,
        blobs: &[(&'static str, Vec<u8>)],
    ) -> Vec<u8> {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let store: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join(format!("{tag}-blobs"))));
        let deploy = DeployStore::new(store.clone(), kv.clone());
        let work = tmp.join(format!("{tag}-work"));
        std::fs::create_dir_all(&work).unwrap();
        let drv = NodeProjectExport::new(BTreeMap::new(), deploy, kv, store.clone(), work);
        for (key, bytes) in blobs {
            let bytes = bytes.clone();
            let body: boatramp_core::ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            store
                .put(key, body, boatramp_core::PutMeta { content_type: None })
                .await
                .unwrap();
        }
        export_to_buf(
            &drv,
            "acme",
            &ExportOptions {
                scope: boatramp_core::project_export::BundleScope::DataPlane,
                managed_restore: boatramp_core::project_export::ManagedRestore::Overlay,
                ..Default::default()
            },
        )
        .await
        .expect("source export")
    }

    /// GATE (clone-robustness #2): a blob whose target-write always fails (`backend`) HARD-FAILS the
    /// whole import by default; with `continue_on_error=backend` it is WARNED + RECORDED + SKIPPED,
    /// the op is a DISTINCT "completed with N skipped" (never a silent success), and a skip MANIFEST
    /// under the node base lists it and round-trips. A `=member-mismatch` policy does NOT forgive a
    /// backend fault (still hard-fails) — the reverse of `=backend` (test #2 + the backend half of #3).
    #[tokio::test]
    async fn backend_failure_hard_fails_by_default_and_is_skipped_under_continue_on_error() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_core::project_export::{ContinueErrorKind, ContinueOnError, SkipManifest};
        use boatramp_storage::fs::FsStorage;
        use std::collections::{BTreeMap, BTreeSet};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let bundle = source_bundle_with_blobs(
            tmp.path(),
            "src",
            &[
                ("hblob/acme/web/assets/a.bin", b"aaaa".to_vec()),
                ("hblob/acme/web/assets/b.bin", b"bbbb".to_vec()),
            ],
        )
        .await;

        // The target fails to write exactly b.bin (a same-name import keeps the key unchanged).
        let fail_key = "hblob/acme/web/assets/b.bin".to_string();
        let mk_target = |tag: &str| {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let fs: Arc<dyn Storage> =
                Arc::new(FsStorage::new(tmp.path().join(format!("{tag}-blobs"))));
            let blobs: Arc<dyn Storage> = Arc::new(FaultStorage {
                inner: fs.clone(),
                fail_put_keys: BTreeSet::from([fail_key.clone()]),
            });
            let deploy = DeployStore::new(blobs.clone(), kv.clone());
            let work = tmp.path().join(format!("{tag}-work"));
            std::fs::create_dir_all(&work).unwrap();
            let drv =
                NodeProjectExport::new(BTreeMap::new(), deploy, kv, blobs.clone(), work.clone());
            (drv, fs, work)
        };

        // (1) DEFAULT (Off): the backend fault HARD-FAILS the whole import.
        let (tgt_off, _, _) = mk_target("off");
        assert!(
            import_buf(
                &tgt_off,
                "acme",
                &bundle,
                ImportOptions {
                    apply: true,
                    ..Default::default()
                },
            )
            .await
            .is_err(),
            "a backend write fault must hard-fail by default"
        );

        // (2) `=member-mismatch` does NOT forgive a backend fault ⇒ still HARD-FAILS (the reverse).
        let (tgt_mm, _, _) = mk_target("mm");
        assert!(
            import_buf(
                &tgt_mm,
                "acme",
                &bundle,
                ImportOptions {
                    apply: true,
                    continue_on_error: ContinueOnError::Kinds(BTreeSet::from([
                        ContinueErrorKind::MemberMismatch
                    ])),
                    ..Default::default()
                },
            )
            .await
            .is_err(),
            "=member-mismatch must NOT forgive a backend fault"
        );

        // (3) `=backend`: WARN + RECORD + SKIP + continue → "completed with 1 skipped" + manifest.
        let (tgt_be, tgt_fs, _work) = mk_target("be");
        let report = import_buf(
            &tgt_be,
            "acme",
            &bundle,
            ImportOptions {
                apply: true,
                continue_on_error: ContinueOnError::Kinds(BTreeSet::from([
                    ContinueErrorKind::Backend,
                ])),
                ..Default::default()
            },
        )
        .await
        .expect("=backend tolerates the backend fault");
        assert_eq!(report.blobs, 1, "only the writable blob was copied");
        assert!(
            report.completed_with_skips(),
            "a skipped blob is a DISTINCT outcome, not a silent success"
        );
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].key, fail_key);
        assert_eq!(report.skipped[0].kind, "backend");
        // The MANIFEST exists under the node base + round-trips to the same skipped set.
        let manifest_path = report
            .skip_manifest
            .clone()
            .expect("a manifest was written");
        let parsed =
            SkipManifest::from_json(&std::fs::read(&manifest_path).unwrap()).expect("round-trip");
        assert_eq!(parsed.blob_keys(), BTreeSet::from([fail_key.clone()]));
        // The good blob LANDED in the inner store; the skipped one did NOT.
        assert!(
            tgt_fs.head("hblob/acme/web/assets/a.bin").await.is_ok(),
            "the writable blob landed"
        );
        assert!(
            tgt_fs.head("hblob/acme/web/assets/b.bin").await.is_err(),
            "the skipped blob was NOT written"
        );
    }

    /// GATE (clone-robustness #3): `only_blobs` restores ONLY the listed blob keys (re-streamed),
    /// skipping every other member — and the key list ROUND-TRIPS through the Part-3 manifest
    /// writer/reader ([`SkipManifest::to_json`] → [`SkipManifest::from_json`]). (Test #4.)
    #[tokio::test]
    async fn only_blobs_transfers_only_the_listed_keys() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_core::project_export::{SkipManifest, SkippedBlob};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let bundle = source_bundle_with_blobs(
            tmp.path(),
            "src",
            &[
                ("hblob/acme/web/assets/a.bin", b"aaaa".to_vec()),
                ("hblob/acme/web/assets/b.bin", b"bbbb".to_vec()),
                ("hblob/acme/web/assets/c.bin", b"cccc".to_vec()),
            ],
        )
        .await;

        // A repair manifest listing ONLY a.bin + c.bin — serialise then parse it back (round-trip),
        // and drive the import from the PARSED keys (so the manifest format is proven round-trippable).
        let manifest = SkipManifest {
            project: "acme".into(),
            skipped: vec![
                SkippedBlob {
                    key: "hblob/acme/web/assets/a.bin".into(),
                    kind: "backend".into(),
                    reason: "prior fault".into(),
                },
                SkippedBlob {
                    key: "hblob/acme/web/assets/c.bin".into(),
                    kind: "backend".into(),
                    reason: "prior fault".into(),
                },
            ],
        };
        let round = SkipManifest::from_json(manifest.to_json().as_bytes()).expect("round-trip");
        let only = round.blob_keys();

        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let tgt_blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("tgt-blobs")));
        let deploy = DeployStore::new(tgt_blobs.clone(), kv.clone());
        let work = tmp.path().join("tgt-work");
        std::fs::create_dir_all(&work).unwrap();
        let tgt = NodeProjectExport::new(BTreeMap::new(), deploy, kv, tgt_blobs.clone(), work);

        let report = import_buf(
            &tgt,
            "acme",
            &bundle,
            ImportOptions {
                apply: true,
                only_blobs: Some(only.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("only-blobs import");
        assert_eq!(
            report.blobs, 2,
            "exactly the two LISTED blobs were transferred"
        );
        assert!(
            tgt_blobs.head("hblob/acme/web/assets/a.bin").await.is_ok(),
            "a.bin (listed) transferred"
        );
        assert!(
            tgt_blobs.head("hblob/acme/web/assets/c.bin").await.is_ok(),
            "c.bin (listed) transferred"
        );
        assert!(
            tgt_blobs.head("hblob/acme/web/assets/b.bin").await.is_err(),
            "b.bin (NOT listed) must NOT be transferred"
        );
    }

    /// GATE (clone-robustness #2 routing): `continue_on_error` maps to the RIGHT seams —
    /// `member-mismatch` drives the member-mismatch `VerifyPolicy.skip_mismatch` (the generalised
    /// `--skip-member-mismatch`) but does NOT forgive `backend`; `backend` is the reverse; `all`
    /// forgives both; `off` neither; and the legacy flag still drives mismatch tolerance (the ALIAS).
    /// Composes with the existing `project_bundle` member-mismatch e2e tests (which prove
    /// skip_mismatch=true tolerates a der/ mismatch and strict hard-fails). (The routing half of #3.)
    #[test]
    fn continue_on_error_routes_to_the_right_seams() {
        use boatramp_core::project_export::{ContinueErrorKind, ContinueOnError};
        use std::collections::BTreeSet;
        let opts = |c: ContinueOnError, skip: bool| ImportOptions {
            continue_on_error: c,
            skip_member_mismatch: skip,
            ..Default::default()
        };

        // =member-mismatch → VerifyPolicy skips mismatches, but backend is NOT forgiven.
        let mm = opts(
            ContinueOnError::Kinds(BTreeSet::from([ContinueErrorKind::MemberMismatch])),
            false,
        );
        assert!(verify_policy_from_opts(&mm).skip_mismatch);
        assert!(!mm.continue_on_error.forgives(ContinueErrorKind::Backend));

        // =backend → backend forgiven, mismatch NOT tolerated by the policy.
        let be = opts(
            ContinueOnError::Kinds(BTreeSet::from([ContinueErrorKind::Backend])),
            false,
        );
        assert!(!verify_policy_from_opts(&be).skip_mismatch);
        assert!(be.continue_on_error.forgives(ContinueErrorKind::Backend));

        // all → both; off → neither.
        let all = opts(ContinueOnError::AllKinds, false);
        assert!(verify_policy_from_opts(&all).skip_mismatch);
        assert!(all.continue_on_error.forgives(ContinueErrorKind::Backend));
        let off = opts(ContinueOnError::Off, false);
        assert!(!verify_policy_from_opts(&off).skip_mismatch);
        assert!(!off.continue_on_error.forgives(ContinueErrorKind::Backend));

        // Back-compat ALIAS: the legacy `skip_member_mismatch` flag still drives mismatch tolerance.
        assert!(verify_policy_from_opts(&opts(ContinueOnError::Off, true)).skip_mismatch);

        // Parse: bare → AllKinds; None → Off; a list → Kinds; an unknown token → Err (fail-closed).
        assert_eq!(
            ContinueOnError::parse(Some("all")).unwrap(),
            ContinueOnError::AllKinds
        );
        assert_eq!(ContinueOnError::parse(None).unwrap(), ContinueOnError::Off);
        assert_eq!(
            ContinueOnError::parse(Some("backend,member-mismatch")).unwrap(),
            ContinueOnError::Kinds(BTreeSet::from([
                ContinueErrorKind::Backend,
                ContinueErrorKind::MemberMismatch
            ]))
        );
        assert!(ContinueOnError::parse(Some("backend,bogus")).is_err());
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

    /// A reversible, in-memory [`KeyEnvelope`] fake for a unit test — no real KMS/KEK, so a
    /// test never touches the network or disk for credential sealing.
    struct TestEnvelope;
    #[async_trait]
    impl KeyEnvelope for TestEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(p.iter().rev().copied().collect())
        }
        async fn unwrap(
            &self,
            w: &[u8],
        ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(w.iter().rev().copied().collect())
        }
    }

    /// A minimal driver + control-plane fixture for [`NodeProjectExport::ensure_target_db_provisioned`]
    /// unit tests: `MemoryKv` + a throwaway `FsStorage`-backed `DeployStore` + the reversible
    /// `TestEnvelope` — no live backend/operator-SQL needed (this helper never connects to one).
    fn provision_fixture() -> (NodeProjectExport, DeployStore, Arc<dyn KvStore>) {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;

        let tmp = tempfile::tempdir().unwrap();
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("blobs")));
        let deploy = DeployStore::new(blobs.clone(), kv.clone());
        let mut drv = NodeProjectExport::new(
            BTreeMap::new(),
            deploy.clone(),
            kv.clone(),
            blobs,
            tmp.path().join("work"),
        );
        // Set the envelope directly (same module ⇒ private field access) — equivalent to
        // `with_managed_pg` without needing a fake compute backend / operator-SQL seam, which
        // `ensure_target_db_provisioned` never touches.
        drv.envelope = Some(Arc::new(TestEnvelope) as Arc<dyn KeyEnvelope>);
        (drv, deploy, kv)
    }

    /// PLAN-clone-self-provision-managed-db: a bring-your-own (`url_env`) binding is the
    /// OPERATOR's own database — self-provision must be a clean no-op (never attempt to
    /// `CREATE DATABASE` on someone else's server).
    #[tokio::test]
    async fn ensure_target_db_provisioned_noop_for_external_binding() {
        let (drv, _deploy, _kv) = provision_fixture();
        let cfg = ExternalDatabaseConfig {
            kind: "postgres".into(),
            url_env: "SOME_DSN".into(),
            ..Default::default()
        };
        drv.ensure_target_db_provisioned("acme", "app", &cfg)
            .await
            .expect("external binding self-provision is a no-op");
    }

    /// A **site-scoped** managed binding: operator SQL (the seam the restore path's
    /// `resolve_pg`/`resolve_mysql` use) refuses it regardless (project-level only), so
    /// self-provision must no-op rather than provision a bogus `site=""` tenant.
    #[tokio::test]
    async fn ensure_target_db_provisioned_noop_for_site_scoped_binding() {
        let (drv, deploy, _kv) = provision_fixture();
        let cfg = ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("app".into()),
            user: Some("postgres".into()),
            tenant: crate::config::TenantIsolation::Single,
            tenant_scope: crate::config::TenantScope::Site,
            ..Default::default()
        };
        drv.ensure_target_db_provisioned("acme", "app", &cfg)
            .await
            .expect("site-scoped binding self-provision is a no-op");
        // No workload was registered as a side effect (nothing was actually provisioned).
        let workloads = deploy
            .list_compute_workloads(ProjectRef::new("acme"))
            .await
            .unwrap();
        assert!(
            workloads.is_empty(),
            "a site-scoped binding must register nothing"
        );
    }

    /// PLAN-clone-self-provision-managed-db, the **dedicated/Single** half of the fix: before
    /// this commit, nothing in the restore path registered a fresh target's dedicated managed-db
    /// workload — `pg_shadow_plan` went straight to `resolve_pg` against a workload that might
    /// never have been registered. `ensure_target_db_provisioned` now reuses the SAME lazy
    /// provisioner (`tenant_sql::provision_tenant` → `provision_single`) the platform runs on a
    /// normal first `sql` access, which durably REGISTERS the dedicated `<compute>-<ident>`
    /// workload (idempotent — a re-run is a no-op). Registration is pure `DeployStore`/`KvStore`
    /// I/O (no network connection), so this is provable without a live Postgres.
    #[tokio::test]
    async fn ensure_target_db_provisioned_registers_a_fresh_single_tenant_workload() {
        let (drv, deploy, _kv) = provision_fixture();
        let cfg = ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("app".into()),
            user: Some("postgres".into()),
            tenant: crate::config::TenantIsolation::Single,
            tenant_scope: crate::config::TenantScope::Project,
            ..Default::default()
        };
        let target = "acme-fresh";
        // Nothing registered yet — the exact "fresh target" shape a clone onto a brand-new
        // project shell has.
        assert!(
            deploy
                .list_compute_workloads(ProjectRef::new(target))
                .await
                .unwrap()
                .is_empty()
        );
        drv.ensure_target_db_provisioned(target, "app", &cfg)
            .await
            .expect("Single self-provision registers the dedicated workload");
        let workloads = deploy
            .list_compute_workloads(ProjectRef::new(target))
            .await
            .unwrap();
        assert_eq!(
            workloads.len(),
            1,
            "exactly the target's own dedicated workload is registered"
        );
        // Idempotent: a second call (the retry-safe / already-provisioned-target shape) changes
        // nothing — still exactly one workload, no clobber.
        drv.ensure_target_db_provisioned(target, "app", &cfg)
            .await
            .expect("re-provisioning an already-provisioned target is a no-op");
        let workloads_again = deploy
            .list_compute_workloads(ProjectRef::new(target))
            .await
            .unwrap();
        assert_eq!(
            workloads_again.len(),
            1,
            "idempotent — no duplicate/clobber"
        );

        // TARGET-SCOPED ONLY: an unrelated project is never touched by provisioning `target`.
        let other = deploy
            .list_compute_workloads(ProjectRef::new("some-other-tenant"))
            .await
            .unwrap();
        assert!(
            other.is_empty(),
            "self-provisioning one project must not register/touch another project's workload"
        );
    }

    /// A **Shared**-tenant managed binding with no replica registered anywhere: self-provision
    /// genuinely ATTEMPTS the real `provision_shared` DDL (reaching for the resolver / a
    /// connection) rather than silently no-op'ing — it fails with a clear "no replica" / "not
    /// ready" shape, never a panic and never a silent `Ok(())` that would mask the gap this fix
    /// closes. (The success path — the server IS up and the tenant db gets created on it,
    /// construens's exact failure shape going from broken to fixed — is proven live in
    /// `project_export_roundtrip.rs`'s `project_export_clone_self_provisions_shared_tenant_live`,
    /// which needs a real Postgres.)
    #[tokio::test]
    async fn ensure_target_db_provisioned_shared_without_a_replica_fails_informatively() {
        let (drv, _deploy, _kv) = provision_fixture();
        let cfg = ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("app".into()),
            user: Some("postgres".into()),
            tenant: crate::config::TenantIsolation::Shared,
            tenant_scope: crate::config::TenantScope::Project,
            connect_timeout_secs: Some(1),
            ..Default::default()
        };
        let err = drv
            .ensure_target_db_provisioned("acme-fresh", "app", &cfg)
            .await
            .expect_err("Shared self-provision with no registered replica cannot succeed");
        let msg = err.to_string();
        assert!(
            msg.contains("clone self-provision"),
            "error is attributed to the self-provision call: {msg}"
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
    fn mysqlbinlog_member_path_round_trips() {
        assert_eq!(mysqlbinlog_member_path("app"), "sql/app.mysqlbinlog");
        assert_eq!(
            db_from_mysqlbinlog_member("sql/app.mysqlbinlog"),
            Some("app")
        );
        // The full-dump and true-delta member paths are distinct namespaces.
        assert_eq!(db_from_mysqlbinlog_member("sql/app.sql"), None);
        assert_eq!(db_from_mysql_member("sql/app.mysqlbinlog"), None);
    }

    #[test]
    fn mysql_binlog_image_appends_debian_once() {
        // mysqlbinlog ships in the DEBIAN variant, not the Oracle-Linux default image.
        assert_eq!(mysql_binlog_image("mysql:8.0"), "mysql:8.0-debian");
        assert_eq!(mysql_binlog_image("mysql:8.4"), "mysql:8.4-debian");
        // Idempotent — never double-adds.
        assert_eq!(mysql_binlog_image("mysql:8.0-debian"), "mysql:8.0-debian");
    }

    #[test]
    fn mysql_sql_log_bin_toggle_detection() {
        // The exact privileged lines `--source-data` injects (stripped from the capture base so the
        // least-privilege shadow user can restore it).
        assert!(mysql_line_is_sql_log_bin_toggle(
            "SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN;"
        ));
        assert!(mysql_line_is_sql_log_bin_toggle(
            "SET @@SESSION.SQL_LOG_BIN= 0;"
        ));
        assert!(mysql_line_is_sql_log_bin_toggle(
            "SET @@SESSION.SQL_LOG_BIN = @MYSQLDUMP_TEMP_LOG_BIN;"
        ));
        // A normal dump statement is NOT stripped.
        assert!(!mysql_line_is_sql_log_bin_toggle(
            "INSERT INTO `t` VALUES (1,'a');"
        ));
        assert!(!mysql_line_is_sql_log_bin_toggle(
            "/* SET @@GLOBAL.GTID_PURGED='+uuid:1-9';*/"
        ));
    }

    #[test]
    fn parse_mysql_base_coord_extracts_gtid_and_log_file() {
        let header = "-- Server version\tn8.0.46\n\
            SET @@SESSION.SQL_LOG_BIN= 0;\n\
            /* SET @@GLOBAL.GTID_PURGED='+142694f1-d0bc-11f1:1-9';*/\n\
            -- CHANGE MASTER TO MASTER_LOG_FILE='node-bin.000003', MASTER_LOG_POS=1068;\n\
            DROP TABLE IF EXISTS `t`;\n";
        let (gtid, log) = parse_mysql_base_coord(header).expect("coord parses");
        assert_eq!(gtid, "142694f1-d0bc-11f1:1-9"); // leading '+' stripped
        assert_eq!(log, "node-bin.000003");
        // A dump with no coordinate (binlog/gtid off) ⇒ None ⇒ the delta full-dumps.
        assert_eq!(parse_mysql_base_coord("DROP TABLE IF EXISTS `t`;"), None);
    }

    #[test]
    fn mysql_grant_privileges_splits_before_the_target_db() {
        // The privilege part is everything before the first " ON " — the db NAME in the target must
        // never bleed into a SUPER/FILE/BINLOG_ADMIN substring match (LOW-1).
        let g = |l: &str| mysql_grant_privileges(l).to_ascii_uppercase();
        // A legit least-priv grant on a db whose NAME contains "SUPER"/"FILE"/"PROFILE".
        assert_eq!(
            g("GRANT ALL PRIVILEGES ON `supervisors__shadow_ab`.* TO 'x'@'%'"),
            "GRANT ALL PRIVILEGES"
        );
        assert!(!g("GRANT ALL PRIVILEGES ON `supervisors`.* TO 'x'@'%'").contains("SUPER"));
        assert!(!g("GRANT ALL PRIVILEGES ON `filestore`.* TO 'x'@'%'").contains("FILE"));
        assert!(!g("GRANT ALL PRIVILEGES ON `profiles`.* TO 'x'@'%'").contains("FILE"));
        // A genuinely dangerous privilege IS in the privilege part.
        assert!(g("GRANT SUPER ON *.* TO 'x'@'%'").contains("SUPER"));
        assert!(g("GRANT FILE ON *.* TO 'x'@'%'").contains("FILE"));
        assert!(
            g("GRANT REPLICATION_APPLIER, SESSION_VARIABLES_ADMIN ON *.* TO 'x'@'%'")
                .contains("REPLICATION_APPLIER")
        );
        // The replay dynamics do NOT contain the dangerous tokens.
        let dyn_privs = g("GRANT REPLICATION_APPLIER, SESSION_VARIABLES_ADMIN ON *.* TO 'x'@'%'");
        assert!(
            !dyn_privs.contains("SUPER")
                && !dyn_privs.contains("FILE")
                && !dyn_privs.contains("BINLOG_ADMIN")
        );
    }

    #[test]
    fn mysql_delta_shadow_db_is_deterministic_and_sweepable() {
        assert_eq!(mysql_delta_shadow_db("app"), "app__shadow_brdelta");
        // Carries the `__shadow_` infix so the startup `%__shadow_%` sweep reclaims a crashed one.
        assert!(mysql_delta_shadow_db("tenant_x").contains("__shadow_"));
    }

    #[test]
    fn bounded_derived_db_name_fits_63_bytes_and_stays_distinct() {
        // SHORT live db: byte-identical to the old `format!("{live}{marker}{suffix}")` — the
        // dedicated/chunked path and the existing shadow-name tests keep their exact names.
        assert_eq!(
            bounded_derived_db_name("appdb", "__shadow_", "1700000000_42"),
            "appdb__shadow_1700000000_42"
        );
        assert_eq!(
            bounded_derived_db_name("appdb", "__old_", "1700000000_42"),
            "appdb__old_1700000000_42"
        );
        assert_eq!(
            bounded_derived_db_name("app", "__shadow_", "brdelta"),
            "app__shadow_brdelta"
        );

        // LONG live db (the Shared-tenant shape): ~62 bytes, so the naive name would be ~98 bytes
        // and Postgres would truncate it back to the live name. The real `shadow_suffix()` shape.
        let live = "clonesp_clonesp_fresh_1793655865_7rmx_4ahtlf3v6btes2g18bq7820bx";
        assert!(live.len() >= 60, "fixture must exercise the bounded path");
        let suffix = "1793655865123456789_4242";
        let name = bounded_derived_db_name(live, "__shadow_", suffix);

        // (result) ≤ 63 bytes — never overflows NAMEDATALEN.
        assert!(
            name.len() <= MAX_DERIVED_DB_NAME_LEN,
            "derived name {name:?} is {} bytes (> {MAX_DERIVED_DB_NAME_LEN})",
            name.len()
        );
        // (b) the FULL `__shadow_<suffix>` marker+distinguisher survives intact, within the first
        // 63 bytes — so the `%__shadow_%` sweep still matches and the suffix still disambiguates.
        let marker_tail = format!("__shadow_{suffix}");
        assert!(
            name.ends_with(&marker_tail) && name.contains("__shadow_"),
            "derived name {name:?} dropped part of its {marker_tail:?} distinguisher"
        );
        // (a) distinct from the live db name truncated to 63 bytes — the exact collapse that caused
        // `CREATE DATABASE … already exists`. The derived name keeps the `__shadow_…` tail a plain
        // truncation of `live` would have thrown away.
        let live_trunc = &live[..live.len().min(MAX_DERIVED_DB_NAME_LEN)];
        assert_ne!(
            name, live_trunc,
            "derived name collapsed back to the live name"
        );

        // (c) collision-free: two different per-import suffixes yield two different names.
        let other = bounded_derived_db_name(live, "__shadow_", "1793655865999999999_4242");
        assert_ne!(
            name, other,
            "distinct suffixes must yield distinct shadow names (collision-free across imports)"
        );

        // The `__old_` aside for the same long live db is also bounded and distinct from the shadow.
        let old = bounded_derived_db_name(live, "__old_", suffix);
        assert!(old.len() <= MAX_DERIVED_DB_NAME_LEN);
        assert!(old.ends_with(&format!("__old_{suffix}")));
        assert_ne!(old, name);
        assert_ne!(old, live_trunc);
    }

    #[test]
    fn swap_safety_refuses_empty_shadow_over_nonempty_live() {
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // THE data-loss state: live has tables, shadow is EMPTY → swapping would move live aside +
        // drop it with nothing to put back → DESTROY live. MUST be flagged (the swap aborts).
        assert!(swap_would_destroy_live(&s(&["t", "victim"]), &s(&[])));
        // Safe: a populated shadow replaces live (the normal swap).
        assert!(!swap_would_destroy_live(&s(&["t"]), &s(&["t"])));
        // Safe: live is empty (first import into a fresh db) — nothing to lose.
        assert!(!swap_would_destroy_live(&s(&[]), &s(&["t"])));
        assert!(!swap_would_destroy_live(&s(&[]), &s(&[])));
        // The pre-fix swap built RENAME moves from exactly this (empty-shadow, nonempty-live) state
        // and processed it destructively — the guard above is what the fix adds, so this is not a
        // tautology: a shadow with ANY table is NOT flagged (a partial restore is a separate concern).
        assert!(!swap_would_destroy_live(&s(&["t", "victim"]), &s(&["t"])));
    }

    #[test]
    fn mysql_binlog_ddl_scan_distinguishes_row_dml_from_ddl() {
        // A clean ROW-only delta: comments, session SETs, a BINLOG base64 block, BEGIN/COMMIT.
        let row_only = "/*!50530 SET @@SESSION.PSEUDO_SLAVE_MODE=1*/;\n\
            # at 197\n\
            SET @@session.sql_mode=1168113696/*!*/;\n\
            BEGIN\n\
            /*!*/;\n\
            BINLOG '\n\
            jnneag8BAAAAegAAAH4AAAA=\n\
            '/*!*/;\n\
            COMMIT\n\
            /*!*/;\n";
        assert!(
            !mysql_binlog_decoded_has_ddl(row_only),
            "a pure ROW/DML delta carries no DDL"
        );
        // A DDL event in the range (statement-logged even in ROW format) ⇒ fall back to a full dump.
        let with_ddl = format!("{row_only}ALTER TABLE `t` ADD COLUMN `c` int\n/*!*/;\n");
        assert!(
            mysql_binlog_decoded_has_ddl(&with_ddl),
            "an ALTER in the range must be detected as DDL"
        );
        let with_create = format!("{row_only}CREATE TABLE `u` (id int)\n/*!*/;\n");
        assert!(mysql_binlog_decoded_has_ddl(&with_create));
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

    /// The SIDECAR pg apply decision (the pure dispatch behind the restore_member PgDump arm), now
    /// keyed on the SPLIT [`ManagedRestore`] mode rather than a conflated `data_only` flag. Pins the
    /// precise boundary: a MANAGED `ShadowSwap` dump applies via the atomic non-superuser shadow+swap
    /// (so a Shared tenant's sidecar-framed FULL clone AND a `project sync` DataPlane+ShadowSwap
    /// clone succeed), while a MANAGED `Overlay` dump is STILL refused (overlay into a live schema,
    /// no atomic shadow) — the guard must fire on a genuine overlay only. An external binding is
    /// applied directly regardless of the mode. (The live shadow apply itself needs Docker + pg;
    /// this unit test fixes the dispatch that the `*_live` gates then exercise end-to-end.)
    #[test]
    fn sidecar_managed_apply_dispatches_by_managed_restore_mode() {
        use ManagedRestore::{Overlay, ShadowSwap};
        // MANAGED + ShadowSwap: the SAFE case — atomic non-superuser shadow+swap. This is the arm a
        // `project sync` of a Shared managed pg now reaches (DataPlane scope + ShadowSwap mode); the
        // pre-split coupling forced it to refuse because `data_only` implied Overlay.
        assert_eq!(
            sidecar_managed_apply(true, ShadowSwap),
            SidecarManagedApply::ManagedShadowSwap,
            "a ShadowSwap managed sidecar dump applies via the non-superuser shadow+swap"
        );
        // MANAGED + Overlay: STILL refused — the RefuseManagedDataOnly guard must keep firing for a
        // genuine overlay (external/BYO overlay, allow-schema-skew overlay), never over-opened.
        assert_eq!(
            sidecar_managed_apply(true, Overlay),
            SidecarManagedApply::RefuseManagedDataOnly,
            "an Overlay managed sidecar dump must STAY refused — no atomic shadow for an overlay (RCE guard)"
        );
        // EXTERNAL (not managed): applied directly with the operator's own credential, either mode.
        assert_eq!(
            sidecar_managed_apply(false, ShadowSwap),
            SidecarManagedApply::External
        );
        assert_eq!(
            sidecar_managed_apply(false, Overlay),
            SidecarManagedApply::External
        );
    }

    /// The SECURITY-load-bearing DEFINER rewrite, against REAL `mysqldump --routines --events` output
    /// (NOT fabricated): it must re-point EVERY object's own definer — a stored PROCEDURE's and
    /// FUNCTION's definer are on a PLAIN `CREATE DEFINER=…` line (NO `/*!…*/` wrapper, because the
    /// body executes), while a TRIGGER's/EVENT's/VIEW's definer rides a `/*!…*/` comment — and NEVER
    /// touch row data or a routine body (a string literal containing "DEFINER=" stays). Mutation
    /// proof: the old `/*!`-only matcher leaves the procedure+function definers as `root@%`, so the
    /// non-superuser restore would hit ERROR 1227 — exactly the live regression this replaces. These
    /// fixtures are the actual lines MySQL 8.0 `mysqldump` emits.
    #[test]
    fn rewrite_mysql_definers_repoints_real_mysqldump_objects() {
        let apply = MysqlDefinerTarget::Account("brexp_apply_deadbeef".to_string());

        // A faithful fragment of `mysqldump --routines --events` of a db with a procedure, a
        // function, a trigger, an event, a `/*!`-form view, a plain-form view, a data line whose
        // string literal contains "DEFINER=", and a trigger whose BODY string literal (same line)
        // contains "DEFINER=". Every OBJECT definer is `root@%`; the two NON-object DEFINER= texts
        // are `evil@host` and must survive untouched.
        let dump = "\
/*!50003 DROP PROCEDURE IF EXISTS `addrow` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
DELIMITER ;;
CREATE DEFINER=`root`@`%` PROCEDURE `addrow`(IN i INT, IN sv TEXT)
INSERT INTO t VALUES (i, sv) ;;
DELIMITER ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 DROP FUNCTION IF EXISTS `dbl` */;
DELIMITER ;;
CREATE DEFINER=`root`@`%` FUNCTION `dbl`(x INT) RETURNS int
    DETERMINISTIC
RETURN x * 2 ;;
DELIMITER ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`%`*/ /*!50003 TRIGGER `trg` AFTER INSERT ON `t` FOR EACH ROW INSERT INTO audit VALUES (NEW.id) */;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`%`*/ /*!50003 TRIGGER `trg2` BEFORE INSERT ON `t` FOR EACH ROW INSERT INTO audit VALUES ('DEFINER=`evil`@`host`') */;;
DELIMITER ;
/*!50106 SET @save_time_zone= @@TIME_ZONE */ ;
DELIMITER ;;
/*!50106 CREATE*/ /*!50117 DEFINER=`root`@`%`*/ /*!50106 EVENT `ev` ON SCHEDULE EVERY 1 HOUR STARTS '2026-01-01 00:00:00' ON COMPLETION NOT PRESERVE ENABLE DO DELETE FROM audit WHERE n < 0 */ ;;
DELIMITER ;
/*!50001 DROP VIEW IF EXISTS `vw`*/;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`root`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `vw` AS select `t`.`id` AS `id`,`t`.`v` AS `v` from `t` */;
CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`%` SQL SECURITY DEFINER VIEW `vw2` AS select 1 AS `one`;
INSERT INTO `logs` VALUES (1,'note CREATE DEFINER=`evil`@`host` PROCEDURE foo');
";
        let got = rewrite_mysql_definers(dump, &apply);

        // Every object's OWN definer is re-pointed — including the PLAIN-line routine headers (this is
        // the case the old `/*!`-only matcher MISSED → ERROR 1227 on the live path).
        for needle in [
            "CREATE DEFINER=`brexp_apply_deadbeef`@`%` PROCEDURE `addrow`",
            "CREATE DEFINER=`brexp_apply_deadbeef`@`%` FUNCTION `dbl`",
            "/*!50017 DEFINER=`brexp_apply_deadbeef`@`%`*/ /*!50003 TRIGGER `trg` ",
            "/*!50017 DEFINER=`brexp_apply_deadbeef`@`%`*/ /*!50003 TRIGGER `trg2` ",
            "/*!50117 DEFINER=`brexp_apply_deadbeef`@`%`*/ /*!50106 EVENT `ev`",
            "/*!50013 DEFINER=`brexp_apply_deadbeef`@`%` SQL SECURITY DEFINER */",
            "CREATE ALGORITHM=UNDEFINED DEFINER=`brexp_apply_deadbeef`@`%` SQL SECURITY DEFINER VIEW `vw2`",
        ] {
            assert!(
                got.contains(needle),
                "object definer not re-pointed: {needle}\n--- in ---\n{got}"
            );
        }
        // No object definer `root@%` survives.
        assert!(
            !got.contains("DEFINER=`root`@`%`"),
            "an object definer was left un-re-pointed:\n{got}"
        );
        // The 7 structural object definers are re-pointed; the 2 NON-object "DEFINER=" texts
        // (the trigger-body string literal + the INSERT data line) are UNTOUCHED (`evil@host` stays,
        // never rewritten to the apply user).
        assert_eq!(
            got.matches("DEFINER=`brexp_apply_deadbeef`@`%`").count(),
            7,
            "exactly the 7 object headers re-pointed:\n{got}"
        );
        assert_eq!(
            got.matches("DEFINER=`evil`@`host`").count(),
            2,
            "the two DEFINER= texts inside a body/string literal are left byte-for-byte:\n{got}"
        );
        // The INSERT data line is byte-identical.
        assert!(
            got.contains(
                "INSERT INTO `logs` VALUES (1,'note CREATE DEFINER=`evil`@`host` PROCEDURE foo');"
            ),
            "the INSERT data line must be untouched:\n{got}"
        );

        // Edge cases on single lines.
        // A doubled-backtick account name parses as one identifier (not a premature close).
        let weird = "/*!50017 DEFINER=`we``ird`@`%`*/ /*!50003 TRIGGER `t` */;;\n";
        assert!(
            rewrite_mysql_definers(weird, &apply).contains("DEFINER=`brexp_apply_deadbeef`@`%`"),
            "a doubled-backtick definer account is parsed + re-pointed"
        );
        // STRIP removes the clause (and one trailing space) for both forms.
        let proc1 = "CREATE DEFINER=`root`@`%` PROCEDURE `p`() SELECT 1;\n";
        let stripped = rewrite_mysql_definers(proc1, &MysqlDefinerTarget::Strip);
        assert_eq!(
            stripped, "CREATE PROCEDURE `p`() SELECT 1;\n",
            "strip collapses `CREATE DEFINER=… PROCEDURE` to `CREATE PROCEDURE` with no double space"
        );
        let trig1 = "/*!50017 DEFINER=`root`@`%`*/ /*!50003 TRIGGER `t` */;;\n";
        assert!(
            rewrite_mysql_definers(trig1, &MysqlDefinerTarget::Strip).contains("/*!50017 */"),
            "strip collapses a `/*!…*/` definer comment to an empty version comment"
        );
        // A re-point target's own backtick is doubled in the emitted identifier.
        let role = MysqlDefinerTarget::Account("ro`le".to_string());
        assert!(
            rewrite_mysql_definers(proc1, &role).contains("DEFINER=`ro``le`@`%`"),
            "a re-point target's backtick is doubled in the emitted identifier"
        );
    }

    /// The EXPORT-side framing decision behind `plan_export` (the pure complement of the import-side
    /// `sidecar_managed_apply`): a managed member is CHUNKED iff managed AND ShadowSwap AND not-Shared.
    /// Pins that `project sync` (ShadowSwap) frames a DEDICATED managed DB chunked (→ the atomic
    /// chunked shadow) and a SHARED one sidecar (→ `pg_sidecar_shadow_restore`), while an Overlay or
    /// external binding is always sidecar. `plan_export` itself needs a live DB (version-detect), so
    /// this fixes the decision the `*_live` gate then exercises end-to-end.
    #[test]
    fn managed_member_framing_follows_shadow_swap_and_tenancy() {
        use ManagedRestore::{Overlay, ShadowSwap};
        // Dedicated managed + ShadowSwap → CHUNKED (streamed dump → atomic shadow). The sync case.
        assert!(managed_member_chunked(true, ShadowSwap, false));
        // Shared managed + ShadowSwap → SIDECAR (reaches the shadow via pg_sidecar_shadow_restore).
        assert!(!managed_member_chunked(true, ShadowSwap, true));
        // Managed + Overlay → SIDECAR (the refused/direct-overlay path), dedicated or Shared.
        assert!(!managed_member_chunked(true, Overlay, false));
        assert!(!managed_member_chunked(true, Overlay, true));
        // External (not managed) → always SIDECAR (we never CREATE/RENAME/DROP on the operator's db).
        assert!(!managed_member_chunked(false, ShadowSwap, false));
        assert!(!managed_member_chunked(false, Overlay, false));
    }

    /// The legacy `data_only` wire bool maps, via [`BundleHead`], to exactly the pre-split coupling:
    /// `true → DataPlane + Overlay`, `false → Full + ShadowSwap`. This is what keeps a pre-split
    /// bundle (and every legacy caller) behaving UNCHANGED after the overload was split, and what
    /// makes the `sidecar_managed_apply` boundary above equivalent to the old `(managed × data_only)` one
    /// for any bundle that did NOT ask for the new `DataPlane + ShadowSwap` combination.
    #[test]
    fn bundle_head_from_bool_reproduces_the_legacy_coupling() {
        let data_only_head = BundleHead::from(true);
        assert_eq!(data_only_head.scope, BundleScope::DataPlane);
        assert_eq!(data_only_head.managed_restore, ManagedRestore::Overlay);
        let full_head = BundleHead::from(false);
        assert_eq!(full_head.scope, BundleScope::Full);
        assert_eq!(full_head.managed_restore, ManagedRestore::ShadowSwap);
        // A managed pg under the legacy coupling: data_only → refuse; full → shadow+swap. Identical
        // to the pre-split boundary, so nothing that did not opt into the new combination changes.
        assert_eq!(
            sidecar_managed_apply(true, BundleHead::from(true).managed_restore),
            SidecarManagedApply::RefuseManagedDataOnly
        );
        assert_eq!(
            sidecar_managed_apply(true, BundleHead::from(false).managed_restore),
            SidecarManagedApply::ManagedShadowSwap
        );
    }

    /// The SHARED-shadow restore-window closer's terminate-sweep SQL composes correctly: it targets
    /// the shadow by its `datname` (a safely-quoted SQL string LITERAL, not an identifier) and
    /// EXCLUDES our own backend. A mutation that dropped the `pid <> pg_backend_pid()` self-exclusion
    /// (self-terminating the maintenance session) or misquoted the db name fails here. This is the
    /// exact sweep run both in `pg_create_shadow` (batched after the REVOKE) and immediately before
    /// the untrusted restore in `pg_sidecar_shadow_restore`.
    #[test]
    fn terminate_backends_sweep_targets_the_db_literal_and_spares_self() {
        let sql = pg_terminate_backends_sql("clonesp_fresh__shadow_1700_42");
        assert!(sql.starts_with("SELECT pg_terminate_backend(pid) FROM pg_stat_activity"));
        // The db name is a single-quoted STRING LITERAL (datname is text), never an identifier.
        assert!(
            sql.contains("datname = 'clonesp_fresh__shadow_1700_42'"),
            "the shadow db must be matched as a quoted datname literal: {sql}"
        );
        // Never evict our own maintenance backend (which runs the sweep).
        assert!(
            sql.contains("pid <> pg_backend_pid()"),
            "the sweep must spare the running backend: {sql}"
        );
        // A db name bearing a quote is doubled (defensive — the name is driver-derived, not attacker
        // input, but the literal quoting must be correct regardless).
        let tricky = pg_terminate_backends_sql("od'd");
        assert!(
            tricky.contains("datname = 'od''d'"),
            "embedded quote doubled: {tricky}"
        );
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
                scope: boatramp_core::project_export::BundleScope::Full,
                managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
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
                scope: boatramp_core::project_export::BundleScope::DataPlane,
                managed_restore: boatramp_core::project_export::ManagedRestore::Overlay,
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
                scope: boatramp_core::project_export::BundleScope::Full,
                managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
                include_identity: true,
                transport_key: Some(pass.clone()),
                delta: None,
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
                    scope: boatramp_core::project_export::BundleScope::DataPlane,
                    managed_restore: boatramp_core::project_export::ManagedRestore::Overlay,
                    include_identity: true,
                    transport_key: Some(pass.clone()),
                    delta: None,
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
                    scope: boatramp_core::project_export::BundleScope::Full,
                    managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
                    include_identity: true,
                    transport_key: None,
                    delta: None,
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
                    scope: boatramp_core::project_export::BundleScope::Full,
                    managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
                    include_identity: true,
                    transport_key: Some(pass.clone()),
                    delta: None,
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
                scope: boatramp_core::project_export::BundleScope::Full,
                managed_restore: boatramp_core::project_export::ManagedRestore::ShadowSwap,
                include_identity: true,
                transport_key: Some(pass.clone()),
                delta: None,
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

    /// A blob LARGER than the chunk size takes the ChunkedTrailer streaming framing and round-trips
    /// byte-identical through export AND import into a re-keyed target scope — the per-member
    /// streaming guarantee (never buffer a whole large blob): export streams the body O(chunk) with
    /// no whole-object temp, import stages the chunk stream to a bounded temp then streams it into
    /// the target store. A small blob stays Sidecar. Round-trip equality over a 5 KB body (≫ the
    /// 16 B test chunk) proves the `.part` framing reassembles the large body exactly.
    #[tokio::test]
    async fn large_blob_round_trips_through_the_chunked_streaming_path() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();

        let mk = |tag: &str| {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let blobs: Arc<dyn Storage> =
                Arc::new(FsStorage::new(tmp.path().join(format!("{tag}-blobs"))));
            let deploy = DeployStore::new(blobs.clone(), kv.clone());
            let work = tmp.path().join(format!("{tag}-work"));
            std::fs::create_dir_all(&work).unwrap();
            // chunk size 16 B so a modest blob is framed ChunkedTrailer.
            let drv = NodeProjectExport::new(BTreeMap::new(), deploy, kv, blobs.clone(), work)
                .with_chunk_size(16);
            (drv, blobs)
        };

        let (src, src_blobs) = mk("src");

        // A blob much larger than the chunk size (→ ChunkedTrailer) + a tiny one (→ Sidecar);
        // distinct, non-trivial bytes so a wrongly reassembled body is caught.
        let big: Vec<u8> = (0u32..5000).map(|i| (i % 251) as u8).collect();
        let small = b"tiny".to_vec();
        let put = |blobs: Arc<dyn Storage>, key: &'static str, bytes: Vec<u8>| async move {
            let body: boatramp_core::ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            blobs
                .put(key, body, boatramp_core::PutMeta { content_type: None })
                .await
                .unwrap();
        };
        put(
            src_blobs.clone(),
            "hblob/acme/web/assets/big.bin",
            big.clone(),
        )
        .await;
        put(
            src_blobs.clone(),
            "hblob/acme/web/assets/small.txt",
            small.clone(),
        )
        .await;

        // data-only export: carries blobs (never gated on data_only) but no KV/identity — keeps the
        // round-trip focused on the blob streaming path.
        let bundle = export_to_buf(
            &src,
            "acme",
            &ExportOptions {
                scope: boatramp_core::project_export::BundleScope::DataPlane,
                managed_restore: boatramp_core::project_export::ManagedRestore::Overlay,
                ..Default::default()
            },
        )
        .await
        .expect("export");

        // The bundle is v3 (it carries a chunked member); the v2-only `read_members` helper cannot
        // read it, so parse the MANIFEST (first tar entry) directly to assert the LARGE blob took
        // the ChunkedTrailer streaming framing and the small one stayed Sidecar. The large body's
        // byte-identity is proven by the import round-trip below (which DOES read v3).
        let manifest: project_bundle::StreamManifest = {
            use std::io::Read as _;
            let mut ar = tar::Archive::new(std::io::Cursor::new(&bundle));
            let mut first = ar
                .entries()
                .unwrap()
                .next()
                .expect("manifest entry")
                .unwrap();
            let mut json = String::new();
            first.read_to_string(&mut json).unwrap();
            serde_json::from_str(&json).expect("parse the v3 StreamManifest")
        };
        assert_eq!(
            manifest.format_version,
            project_bundle::BUNDLE_FORMAT_VERSION_V3,
            "a bundle carrying a chunked member is v3"
        );
        let framing = |path: &str| {
            manifest
                .members
                .iter()
                .find(|m| m.path == path)
                .map(|m| m.framing)
        };
        assert_eq!(
            framing("blobs/hblob/acme/web/assets/big.bin"),
            Some(project_bundle::MemberFraming::ChunkedTrailer),
            "a blob larger than the chunk size must take the chunked streaming framing"
        );
        assert_eq!(
            framing("blobs/hblob/acme/web/assets/small.txt"),
            Some(project_bundle::MemberFraming::Sidecar),
            "a small blob stays sidecar"
        );

        // Import into a FRESH target project "acme2": the large blob streams per-member back into
        // the target store under the re-keyed scope, byte-identical.
        let (tgt, tgt_blobs) = mk("tgt");
        let report = import_buf(
            &tgt,
            "acme2",
            &bundle,
            ImportOptions {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .expect("import");
        assert!(
            report.blobs >= 2,
            "both blobs imported (got {})",
            report.blobs
        );

        let got = tgt_blobs
            .get("hblob/acme2/web/assets/big.bin")
            .await
            .expect("the large blob landed under the re-keyed target scope");
        let mut body = got.body;
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(chunk.unwrap().as_ref());
        }
        assert_eq!(
            buf, big,
            "the large blob is byte-identical after a chunked export+import round-trip"
        );
    }

    /// GATE (project-clone, C1 cross-tenant isolation — the 0.32 env-clone-leak class): a
    /// streaming clone of ONE tenant, driven through the REAL source→target stream (manifest →
    /// per-SHA diff → filtered export → inc2 atomic import), lands EXACTLY that tenant's data under
    /// the target scope with ZERO foreign bytes, and leaves the SOURCE byte-unchanged. The fixture
    /// seeds TWO tenants (`acme`, `globex`) sharing ONE blob bucket + ONE KV store — a single-tenant
    /// fixture is structurally blind to a leak (rule 3). This test actually RUNS (not `#[ignore]`d),
    /// wiring the live source→target stream, so a regression that leaked a foreign object or trusted
    /// a source-declared scope fails here (rule 4).
    #[tokio::test]
    async fn clone_isolates_one_tenant_zero_foreign_bytes_source_unchanged() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let mk = |tag: &str| {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let blobs: Arc<dyn Storage> =
                Arc::new(FsStorage::new(tmp.path().join(format!("{tag}-blobs"))));
            let deploy = DeployStore::new(blobs.clone(), kv.clone());
            let work = tmp.path().join(format!("{tag}-work"));
            std::fs::create_dir_all(&work).unwrap();
            // chunk size 16 B so the (modest) blobs exercise the ChunkedTrailer streaming path too.
            let drv =
                NodeProjectExport::new(BTreeMap::new(), deploy, kv.clone(), blobs.clone(), work)
                    .with_chunk_size(16);
            (drv, kv, blobs)
        };
        let put = |blobs: Arc<dyn Storage>, key: &'static str, bytes: Vec<u8>| async move {
            let body: boatramp_core::ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            blobs
                .put(key, body, boatramp_core::PutMeta { content_type: None })
                .await
                .unwrap();
        };
        let read_blob = |blobs: Arc<dyn Storage>, key: String| async move {
            let got = blobs.get(&key).await.ok()?;
            let mut body = got.body;
            let mut buf = Vec::new();
            while let Some(c) = body.next().await {
                buf.extend_from_slice(c.unwrap().as_ref());
            }
            Some(buf)
        };

        // --- SOURCE: two tenants sharing ONE bucket + ONE KV store (the shared keyspace). ---
        let (src, src_kv, src_blobs) = mk("src");
        let acme_bytes: Vec<u8> = (0u32..3000).map(|i| (i % 251) as u8).collect();
        let globex_bytes: Vec<u8> = (0u32..2000).map(|i| ((i * 7) % 251) as u8).collect();
        put(
            src_blobs.clone(),
            "hblob/acme/web/assets/a.bin",
            acme_bytes.clone(),
        )
        .await;
        put(
            src_blobs.clone(),
            "hblob/acme/web/assets/small.txt",
            b"acme-tiny".to_vec(),
        )
        .await;
        put(
            src_blobs.clone(),
            "hblob/globex/web/assets/g.bin",
            globex_bytes.clone(),
        )
        .await;
        // Non-secret, environment-neutral owned KV (survives a `--identity fresh` import) for each.
        src_kv
            .put("project/acme/config/tenancy", b"{\"acme\":1}".to_vec())
            .await
            .unwrap();
        src_kv
            .put("project/globex/config/tenancy", b"{\"globex\":1}".to_vec())
            .await
            .unwrap();

        let opts = ExportOptions::default(); // full bundle (carries the control-plane KV slice)

        // --- TARGET: a fresh, SEPARATE node. Clone acme (same-name) via the live handshake. ---
        let (tgt, tgt_kv, tgt_blobs) = mk("tgt");

        // 1. SOURCE manifest (cheap LIST): must carry ONLY acme's blobs — the manifest is itself a
        //    tenancy boundary (scoped by `hblob/acme/`).
        let manifest = src
            .clone_manifest("acme", &opts)
            .await
            .expect("clone manifest");
        assert_eq!(manifest.source_project, "acme");
        assert_eq!(
            manifest.blobs.len(),
            2,
            "manifest lists exactly acme's two blobs"
        );
        assert!(
            manifest
                .blobs
                .iter()
                .all(|b| b.member_path.starts_with("blobs/hblob/acme/")),
            "NO foreign-tenant object may appear in acme's clone manifest: {:?}",
            manifest.blobs
        );

        // 2. TARGET per-SHA diff: fresh target holds nothing ⇒ an EMPTY skip set (pull everything).
        let skip = tgt
            .clone_blobs_present("acme", &manifest.source_project, &manifest.blobs)
            .await
            .expect("diff");
        assert!(
            skip.skip_member_paths.is_empty(),
            "fresh target skips nothing"
        );

        // 3. SOURCE filtered stream → 4. TARGET inc2 atomic restore (the live source→target stream).
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        src.export_clone("acme", &opts, &skip, &mut sink)
            .await
            .expect("filtered clone export");
        let bundle = sink.into_inner();
        let mut rd = futures::io::Cursor::new(bundle.clone());
        let report = tgt
            .import(
                "acme",
                &mut rd,
                ImportOptions {
                    apply: true,
                    ..Default::default()
                },
            )
            .await
            .expect("clone import");
        assert!(
            report.blobs >= 2,
            "acme's blobs restored (got {})",
            report.blobs
        );

        // --- ASSERT: target holds EXACTLY acme's data under the target scope. ---
        assert_eq!(
            read_blob(tgt_blobs.clone(), "hblob/acme/web/assets/a.bin".into()).await,
            Some(acme_bytes.clone()),
            "acme's blob landed byte-identical under the target scope"
        );
        assert_eq!(
            tgt_kv.get("project/acme/config/tenancy").await.unwrap(),
            Some(b"{\"acme\":1}".to_vec()),
            "acme's owned control-plane KV landed on the target"
        );

        // --- ASSERT: ZERO foreign bytes in the target (the load-bearing isolation gate). ---
        let tgt_keys = tgt_blobs.list("hblob/").await.unwrap();
        assert!(
            tgt_keys.iter().all(|m| m.key.starts_with("hblob/acme/")),
            "NO foreign-tenant object in the target bucket: {:?}",
            tgt_keys.iter().map(|m| &m.key).collect::<Vec<_>>()
        );
        assert!(
            read_blob(tgt_blobs.clone(), "hblob/globex/web/assets/g.bin".into())
                .await
                .is_none(),
            "globex's object must be ABSENT from the target"
        );
        assert!(
            tgt_kv
                .get("project/globex/config/tenancy")
                .await
                .unwrap()
                .is_none(),
            "NO foreign-tenant control-plane KV in the target"
        );
        assert!(
            tgt_kv
                .list_prefix("project/globex/")
                .await
                .unwrap()
                .is_empty(),
            "the target carries no globex keyspace at all"
        );

        // --- ASSERT: the SOURCE is left byte-unchanged (a clone is a read on the source). ---
        assert_eq!(
            read_blob(src_blobs.clone(), "hblob/acme/web/assets/a.bin".into()).await,
            Some(acme_bytes.clone()),
            "source acme blob intact"
        );
        assert_eq!(
            read_blob(src_blobs.clone(), "hblob/globex/web/assets/g.bin".into()).await,
            Some(globex_bytes.clone()),
            "source globex blob intact + untouched by acme's clone"
        );
        assert_eq!(
            src_kv.get("project/globex/config/tenancy").await.unwrap(),
            Some(b"{\"globex\":1}".to_vec()),
            "source globex KV intact"
        );

        // --- RESUME / per-SHA skip: a re-diff against the now-populated target marks acme's blobs
        //     PRESENT ⇒ the source would skip them (O(remaining), not a full re-stream). ---
        let skip2 = tgt
            .clone_blobs_present("acme", &manifest.source_project, &manifest.blobs)
            .await
            .expect("re-diff");
        assert_eq!(
            skip2.skip_member_paths.len(),
            2,
            "a re-run skips both already-present acme blobs: {:?}",
            skip2.skip_member_paths
        );
        // The filtered re-export omits the skipped blob members (nothing left to re-stream), yet a
        // re-import is still correct (idempotent) and leaves the target isolated.
        let mut sink2 = futures::io::Cursor::new(Vec::<u8>::new());
        src.export_clone("acme", &opts, &skip2, &mut sink2)
            .await
            .expect("resumed filtered export");
        let mut rd2 = futures::io::Cursor::new(sink2.into_inner());
        tgt.import(
            "acme",
            &mut rd2,
            ImportOptions {
                apply: true,
                overwrite: true, // the target project already holds its own data
                force: true,     // overlay the now-non-empty control-plane KV destination
                ..Default::default()
            },
        )
        .await
        .expect("resumed import");
        let tgt_keys2 = tgt_blobs.list("hblob/").await.unwrap();
        assert!(
            tgt_keys2.iter().all(|m| m.key.starts_with("hblob/acme/")),
            "a resumed clone still leaks ZERO foreign bytes"
        );

        // --- FAIL-CLOSED: the diff refuses a source-declared ref OUTSIDE the declared source
        //     scope — the target never trusts a crafted manifest to reach a foreign key. ---
        let foreign = vec![CloneBlobRef {
            member_path: "blobs/hblob/globex/web/assets/g.bin".to_string(),
            size: Some(10),
            etag: None,
        }];
        assert!(
            tgt.clone_blobs_present("acme", "acme", &foreign)
                .await
                .is_err(),
            "a ref outside hblob/{{source}}/ must be refused fail-closed"
        );
    }

    /// GATE (project-clone, Security review Part B #5): the CROSS-NAME variant of the tenancy gate —
    /// cloning `preview-a` → `preview-b` exercises the `target_blob_key` + KV re-key END-TO-END
    /// through the live stream (the same-name `acme→acme` case is an identity no-op on the re-key).
    /// A foreign tenant (`other`) shares the source bucket/KV. Asserts the target holds preview-b's
    /// data under the RE-KEYED `hblob/preview-b/` + `project/preview-b/` scopes, byte-identical, with
    /// ZERO `preview-a` or `other` bytes, and the source is byte-unchanged.
    #[tokio::test]
    async fn clone_cross_name_rekeys_end_to_end_zero_foreign_bytes() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let mk = |tag: &str| {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let blobs: Arc<dyn Storage> =
                Arc::new(FsStorage::new(tmp.path().join(format!("{tag}-blobs"))));
            let deploy = DeployStore::new(blobs.clone(), kv.clone());
            let work = tmp.path().join(format!("{tag}-work"));
            std::fs::create_dir_all(&work).unwrap();
            let drv =
                NodeProjectExport::new(BTreeMap::new(), deploy, kv.clone(), blobs.clone(), work)
                    .with_chunk_size(16);
            (drv, kv, blobs)
        };
        let put = |blobs: Arc<dyn Storage>, key: &'static str, bytes: Vec<u8>| async move {
            let body: boatramp_core::ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            blobs
                .put(key, body, boatramp_core::PutMeta { content_type: None })
                .await
                .unwrap();
        };
        let read_blob = |blobs: Arc<dyn Storage>, key: String| async move {
            let got = blobs.get(&key).await.ok()?;
            let mut body = got.body;
            let mut buf = Vec::new();
            while let Some(c) = body.next().await {
                buf.extend_from_slice(c.unwrap().as_ref());
            }
            Some(buf)
        };

        // SOURCE: preview-a (the clone subject) + `other` (a foreign tenant) share one bucket + KV.
        let (src, src_kv, src_blobs) = mk("src");
        let a_bytes: Vec<u8> = (0u32..3000).map(|i| (i % 251) as u8).collect();
        put(
            src_blobs.clone(),
            "hblob/preview-a/web/assets/a.bin",
            a_bytes.clone(),
        )
        .await;
        put(
            src_blobs.clone(),
            "hblob/other/web/assets/o.bin",
            b"foreign".to_vec(),
        )
        .await;
        src_kv
            .put("project/preview-a/config/tenancy", b"{\"a\":1}".to_vec())
            .await
            .unwrap();
        src_kv
            .put("project/other/config/tenancy", b"{\"other\":1}".to_vec())
            .await
            .unwrap();

        let opts = ExportOptions::default();
        let (tgt, tgt_kv, tgt_blobs) = mk("tgt");

        // Clone preview-a → preview-b through the live stream (source_project != target).
        let manifest = src
            .clone_manifest("preview-a", &opts)
            .await
            .expect("manifest");
        assert_eq!(
            manifest.blobs.len(),
            1,
            "manifest lists ONLY preview-a's blob"
        );
        assert!(
            manifest.blobs[0]
                .member_path
                .starts_with("blobs/hblob/preview-a/"),
            "no foreign object in preview-a's manifest"
        );
        let skip = tgt
            .clone_blobs_present("preview-b", &manifest.source_project, &manifest.blobs)
            .await
            .expect("diff");
        assert!(
            skip.skip_member_paths.is_empty(),
            "fresh target skips nothing"
        );
        let mut sink = futures::io::Cursor::new(Vec::<u8>::new());
        src.export_clone("preview-a", &opts, &skip, &mut sink)
            .await
            .expect("filtered export");
        let mut rd = futures::io::Cursor::new(sink.into_inner());
        tgt.import(
            "preview-b",
            &mut rd,
            ImportOptions {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .expect("cross-name clone import");

        // The blob landed under the RE-KEYED target scope (preview-a → preview-b), byte-identical.
        assert_eq!(
            read_blob(tgt_blobs.clone(), "hblob/preview-b/web/assets/a.bin".into()).await,
            Some(a_bytes.clone()),
            "the blob re-keyed to the preview-b scope, byte-identical"
        );
        // The owned KV re-keyed too (project/preview-a/… → project/preview-b/…).
        assert_eq!(
            tgt_kv
                .get("project/preview-b/config/tenancy")
                .await
                .unwrap(),
            Some(b"{\"a\":1}".to_vec()),
            "the owned control-plane KV re-keyed to preview-b"
        );
        // ZERO source-scope or foreign bytes in the target (the load-bearing re-key isolation gate).
        let tgt_keys = tgt_blobs.list("hblob/").await.unwrap();
        assert!(
            tgt_keys
                .iter()
                .all(|m| m.key.starts_with("hblob/preview-b/")),
            "the target bucket holds ONLY preview-b objects: {:?}",
            tgt_keys.iter().map(|m| &m.key).collect::<Vec<_>>()
        );
        assert!(
            tgt_kv
                .list_prefix("project/preview-a/")
                .await
                .unwrap()
                .is_empty(),
            "NO un-re-keyed source-scope KV survives on the target"
        );
        assert!(
            tgt_kv
                .list_prefix("project/other/")
                .await
                .unwrap()
                .is_empty(),
            "NO foreign-tenant KV on the target"
        );
        // The SOURCE is byte-unchanged (a clone reads the source).
        assert_eq!(
            read_blob(src_blobs.clone(), "hblob/preview-a/web/assets/a.bin".into()).await,
            Some(a_bytes),
            "source preview-a blob intact"
        );
        assert_eq!(
            read_blob(src_blobs.clone(), "hblob/other/web/assets/o.bin".into()).await,
            Some(b"foreign".to_vec()),
            "source foreign tenant intact + untouched"
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

        // Defense-in-depth (Security review Part B #4): the re-keyed REMAINDER must be a clean
        // relative path — a `..`/`.`/absolute/empty component is REFUSED, so a crafted member can
        // never traverse OUT of `hblob/{target}/` into another tenant's scope or the bucket root,
        // even though the key IS under the declared source prefix. Mutation witness: drop the
        // component check in `target_blob_key` and these go from Err → Ok (a traversal escape).
        assert!(
            target_blob_key("blobs/hblob/acme/../globex/obj", "acme", "beta").is_err(),
            "a `..` that climbs out of the acme scope toward globex must be refused"
        );
        assert!(
            target_blob_key("blobs/hblob/acme/a/../../etc/x", "acme", "beta").is_err(),
            "a `..` chain escaping the target scope must be refused"
        );
        assert!(
            target_blob_key("blobs/hblob/acme/./obj", "acme", "beta").is_err(),
            "a `.` component in the remainder must be refused"
        );
        assert!(
            target_blob_key("blobs/hblob/acme/", "acme", "beta").is_err(),
            "an empty remainder (no object key) must be refused"
        );
    }

    /// Security review Part B #2 (OOM/DoS guard): `diff_clone_blobs` REFUSES a manifest whose blob
    /// count exceeds the cap BEFORE the per-ref HEAD fan-out, so a hostile source cannot OOM the
    /// diff or storm the target's bucket with HEADs. A count at/under the cap is accepted.
    #[tokio::test]
    async fn diff_clone_blobs_caps_the_manifest_blob_count() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("blobs")));
        let drv = NodeProjectExport::new(
            BTreeMap::new(),
            DeployStore::new(blobs.clone(), kv.clone()),
            kv,
            blobs,
            tmp.path().join("work"),
        );
        // One ref over the cap → refused before any HEAD (the refs point nowhere; a non-capped run
        // would instead HEAD each, but the cap check fires first).
        let over: Vec<CloneBlobRef> = (0..MAX_CLONE_MANIFEST_BLOBS + 1)
            .map(|i| CloneBlobRef {
                member_path: format!("blobs/hblob/acme/web/c/obj-{i}"),
                size: Some(1),
                etag: None,
            })
            .collect();
        let err = drv
            .diff_clone_blobs("acme", "acme", &over)
            .await
            .expect_err("a manifest over the blob-count cap must be refused");
        assert!(
            format!("{err}").contains("exceeding the maximum"),
            "the refusal names the cap: {err}"
        );
        // An empty manifest (well under the cap) is fine and skips nothing.
        let skip = drv
            .diff_clone_blobs("acme", "acme", &[])
            .await
            .expect("an under-cap manifest diffs cleanly");
        assert!(skip.skip_member_paths.is_empty());
    }

    /// The bound-parallelized diff yields EXACTLY the skip set a serial per-ref pass would: for a
    /// mixed manifest (size-matched present, size-mismatched absent, not-found absent) the
    /// `buffer_unordered` fan-out and an independent serial reference agree set-for-set. The
    /// completion order of the unordered fan-out must not change the result (the skip is a set).
    #[tokio::test]
    async fn diff_clone_blobs_parallel_matches_serial() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("blobs")));
        let put = |store: Arc<dyn Storage>, key: String, bytes: Vec<u8>| async move {
            let body: boatramp_core::ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            store
                .put(&key, body, boatramp_core::PutMeta { content_type: None })
                .await
                .unwrap();
        };

        // Seed the target's OWN bucket (same-name acme→acme ⇒ identity re-key: target key is
        // `hblob/acme/<rest>`). 150 refs to make the concurrent fan-out meaningful:
        //   - i % 3 == 0 → object present with a MATCHING size  ⇒ skipped
        //   - i % 3 == 1 → object present with a MISMATCHED size ⇒ pulled (not skipped)
        //   - i % 3 == 2 → NO object at the key                  ⇒ NotFound ⇒ pulled
        let mut refs: Vec<CloneBlobRef> = Vec::new();
        for i in 0..150u32 {
            let rest = format!("web/c/obj-{i}");
            let member_path = format!("blobs/hblob/acme/{rest}");
            let size = 8u64 + u64::from(i % 5); // a few distinct sizes
            match i % 3 {
                0 => {
                    put(
                        blobs.clone(),
                        format!("hblob/acme/{rest}"),
                        vec![0u8; size as usize],
                    )
                    .await;
                    refs.push(CloneBlobRef {
                        member_path,
                        size: Some(size),
                        etag: None,
                    });
                }
                1 => {
                    put(
                        blobs.clone(),
                        format!("hblob/acme/{rest}"),
                        vec![0u8; size as usize],
                    )
                    .await;
                    refs.push(CloneBlobRef {
                        member_path,
                        size: Some(size + 100), // declared size disagrees ⇒ NOT present
                        etag: None,
                    });
                }
                _ => refs.push(CloneBlobRef {
                    member_path,
                    size: Some(size),
                    etag: None,
                }),
            }
        }

        let drv = NodeProjectExport::new(
            BTreeMap::new(),
            DeployStore::new(blobs.clone(), kv.clone()),
            kv.clone(),
            blobs.clone(),
            tmp.path().join("work"),
        );

        // Independent SERIAL reference: the same decision, one HEAD at a time.
        let mut serial = std::collections::BTreeSet::new();
        for b in &refs {
            let target_key = target_blob_key(&b.member_path, "acme", "acme").unwrap();
            match blobs.head(&target_key).await {
                Ok(meta) => {
                    let present = match (&b.etag, &meta.etag) {
                        (Some(s), Some(d)) => s == d,
                        _ => matches!((b.size, meta.size), (Some(s), Some(d)) if s == d),
                    };
                    if present {
                        serial.insert(b.member_path.clone());
                    }
                }
                Err(boatramp_core::StorageError::NotFound(_)) => {}
                Err(e) => panic!("serial head failed: {e}"),
            }
        }

        let parallel = drv
            .diff_clone_blobs("acme", "acme", &refs)
            .await
            .expect("parallel diff");

        assert_eq!(
            parallel.skip_member_paths, serial,
            "the parallel fan-out must yield the identical skip set to a serial pass"
        );
        // 50 of the 150 refs (i % 3 == 0) are size-matched present.
        assert_eq!(parallel.skip_member_paths.len(), 50);
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
        // The changeset sibling path round-trips too.
        assert_eq!(
            libsql_changeset_member_path("acme", "blog"),
            "libsql/acme/blog/default.changeset"
        );
        assert_eq!(
            site_from_libsql_changeset_member("libsql/acme/blog/default.changeset"),
            Some("blog")
        );
        assert_eq!(
            site_from_libsql_changeset_member("libsql/acme/blog/default.sqlite"),
            None
        );
    }

    /// Stage-4 security review Finding 1: the (untrusted) `libsql_capture.json` `snapshot_file` is
    /// CONFINED under the bundle dir before any read/copy — an absolute path, a `..` traversal, a
    /// `.`-bearing path, or an empty string is REFUSED; a plain relative name that exists resolves to
    /// an in-tree absolute path. (A symlink that escapes is rejected by the canonicalize+starts_with
    /// guard — not exercised here as it needs a filesystem fixture; the component/absolute checks are
    /// the load-bearing lexical guard.)
    #[test]
    fn confine_bundle_snapshot_refuses_out_of_tree_paths() {
        let base = tempfile::tempdir().unwrap();
        let cap = base.path().join("libsql_capture");
        std::fs::create_dir_all(&cap).unwrap();
        std::fs::write(cap.join("0.db"), b"x").unwrap();

        // A legit in-tree relative path resolves under base.
        let ok = confine_bundle_snapshot(base.path(), "libsql_capture/0.db").expect("in-tree ok");
        assert!(ok.starts_with(std::fs::canonicalize(base.path()).unwrap()));

        // Every out-of-tree shape is refused BEFORE any read.
        for bad in [
            "/dev/zero",
            "/etc/passwd",
            "../../../etc/passwd",
            "libsql_capture/../../escape",
            "./libsql_capture/0.db", // a leading `.` is a non-Normal component → refused
            "",
        ] {
            assert!(
                confine_bundle_snapshot(base.path(), bad).is_err(),
                "an out-of-tree snapshot path must be refused: {bad:?}"
            );
        }
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

    // --- T3 Phase 1: resumable member-object layout + per-member resume decision ---------

    #[tokio::test]
    async fn resumable_member_object_write_and_resume_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Produce member 0 from a staged sidecar temp, then persist its {size,sha256} meta
        // exactly as `export_resumable` does.
        let src = dir.join("staged-src");
        tokio::fs::write(&src, b"hello-member-zero").await.unwrap();
        let meta = write_member_from_file(dir, 0, &src).await.unwrap();
        assert_eq!(meta.size, b"hello-member-zero".len() as u64);
        write_atomic(
            &dir.join(member_meta_name(0)),
            &serde_json::to_vec(&meta).unwrap(),
        )
        .await
        .unwrap();

        let obj0 = dir.join(member_object_name(0));
        let meta0 = dir.join(member_meta_name(0));
        // Complete + SHA-valid → resume SKIPS it.
        assert!(member_object_valid(&obj0, &meta0).await.unwrap());
        // The `.part` was renamed away (no stray partial).
        assert!(!dir.join(member_part_name(0)).exists());

        // A member never produced → not valid (resume must produce it).
        assert!(
            !member_object_valid(
                &dir.join(member_object_name(1)),
                &dir.join(member_meta_name(1))
            )
            .await
            .unwrap()
        );

        // A TRUNCATED/corrupt object → fails its SHA → not valid → resume re-produces it.
        tokio::fs::write(&obj0, b"trunc").await.unwrap();
        assert!(
            !member_object_valid(&obj0, &meta0).await.unwrap(),
            "a truncated object must fail its recorded SHA and be re-produced on resume"
        );
    }

    #[tokio::test]
    async fn resumable_chunked_member_commits_and_poison_fails_loud() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Happy path: a producer that streams two chunks then returns Ok, poison clear.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        let poison = Arc::new(AtomicBool::new(false));
        let h = tokio::spawn(async move {
            tx.send(b"ab".to_vec()).await.unwrap();
            tx.send(b"cd".to_vec()).await.unwrap();
            Ok(())
        });
        let meta = write_member_from_producer(dir, 2, (rx, poison, h))
            .await
            .unwrap();
        assert_eq!(meta.size, 4);
        assert!(dir.join(member_object_name(2)).exists());

        // Poison path: a producer that writes a partial body then POISONS → must fail loud,
        // committing NO object (a partial member can never be recorded complete).
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        let poison = Arc::new(AtomicBool::new(false));
        let p2 = poison.clone();
        let h = tokio::spawn(async move {
            tx.send(b"partial".to_vec()).await.unwrap();
            p2.store(true, SeqCst);
            Ok(())
        });
        let r = write_member_from_producer(dir, 3, (rx, poison, h)).await;
        assert!(
            r.is_err(),
            "a poisoned (incomplete) producer must fail loud"
        );
        assert!(
            !dir.join(member_object_name(3)).exists(),
            "no member object may be committed when the producer poisoned"
        );
    }

    /// The load-bearing security control for the resumable surface: an operator-named dir is
    /// CONFINED under the configured base. No base ⇒ refused (surface disabled); `..` /
    /// absolute ⇒ refused (traversal); a plain name ⇒ resolved under the base.
    #[tokio::test]
    async fn resumable_dir_is_confined_under_the_configured_base() {
        use boatramp_core::Storage;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let mk = |base: Option<PathBuf>| {
            let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let blobs: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("blobs")));
            let deploy = DeployStore::new(blobs.clone(), kv.clone());
            NodeProjectExport::new(BTreeMap::new(), deploy, kv, blobs, tmp.path().join("work"))
                .with_resumable_base(base)
        };

        // No base configured ⇒ the whole surface is refused (fail-closed).
        assert!(
            mk(None).resolve_resumable_dir("ok", true).await.is_err(),
            "no configured base must refuse the resumable surface"
        );

        let base = tmp.path().join("exports");
        let drv = mk(Some(base.clone()));

        // A plain name resolves to a dir UNDER the canonical base.
        let resolved = drv
            .resolve_resumable_dir("snap1", true)
            .await
            .expect("a plain name is confined + created");
        let canon_base = tokio::fs::canonicalize(&base).await.unwrap();
        assert!(
            resolved.starts_with(&canon_base),
            "resolved {resolved:?} must be under the base {canon_base:?}"
        );

        // Traversal, absolute, and `.`-components are all refused (lexical + absolute escape).
        for bad in ["../escape", "a/../../etc", "/etc/passwd", "", "./x"] {
            assert!(
                drv.resolve_resumable_dir(bad, true).await.is_err(),
                "confinement must refuse {bad:?}"
            );
        }
        // A symlink escaping the base is refused (canonicalize + starts_with guard).
        let outside = tmp.path().join("outside");
        tokio::fs::create_dir_all(&outside).await.unwrap();
        tokio::fs::create_dir_all(&canon_base).await.unwrap();
        #[cfg(unix)]
        {
            let link = base.join("sneaky");
            let _ = std::os::unix::fs::symlink(&outside, &link);
            assert!(
                drv.resolve_resumable_dir("sneaky", false).await.is_err(),
                "a symlink escaping the base must be refused"
            );
        }
    }

    // ---------------------------------------------------------------------------------
    // Incremental / delta export — driver-level round trips (in-process; no Docker/SQL).
    // ---------------------------------------------------------------------------------

    /// Build a delta-capable driver (KV + blob backends, a SHARED resumable base so the base
    /// chain is resolvable on the importing node), returning it plus its kv + blob handles.
    #[cfg(test)]
    fn mk_delta_driver(
        tmp: &std::path::Path,
        shared_base: &std::path::Path,
        tag: &str,
    ) -> (
        NodeProjectExport,
        std::sync::Arc<dyn boatramp_core::kv::KvStore>,
        std::sync::Arc<dyn boatramp_core::Storage>,
    ) {
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::{KvStore, MemoryKv};
        use boatramp_storage::fs::FsStorage;
        use std::collections::BTreeMap;
        use std::sync::Arc;
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let blobs: Arc<dyn boatramp_core::Storage> =
            Arc::new(FsStorage::new(tmp.join(format!("{tag}-blobs"))));
        let deploy = DeployStore::new(blobs.clone(), kv.clone());
        let work = tmp.join(format!("{tag}-work"));
        std::fs::create_dir_all(&work).unwrap();
        let drv = NodeProjectExport::new(BTreeMap::new(), deploy, kv.clone(), blobs.clone(), work)
            .with_resumable_base(Some(shared_base.to_path_buf()));
        (drv, kv, blobs)
    }

    #[cfg(test)]
    async fn seed_blob(store: &dyn boatramp_core::Storage, key: &str, data: &[u8]) {
        use boatramp_core::{ByteStream, PutMeta, StorageError};
        use bytes::Bytes;
        let data = data.to_vec();
        let stream: ByteStream =
            futures::stream::once(async move { Ok::<Bytes, StorageError>(Bytes::from(data)) })
                .boxed();
        store
            .put(key, stream, PutMeta { content_type: None })
            .await
            .expect("seed blob");
    }

    #[cfg(test)]
    async fn read_blob(store: &dyn boatramp_core::Storage, key: &str) -> Option<Vec<u8>> {
        match store.get(key).await {
            Ok(obj) => {
                let mut body = obj.body;
                let mut buf = Vec::new();
                while let Some(chunk) = body.next().await {
                    buf.extend_from_slice(chunk.ok()?.as_ref());
                }
                Some(buf)
            }
            Err(_) => None,
        }
    }

    /// END-TO-END (decisions 3/4/5): a FULL base + a DIFFERENTIAL delta carrying only the KV
    /// upserts/tombstones + the changed/new blobs (+ a blob tombstone), restored onto a FRESH node
    /// = base reconstructed + the drift applied. Proves base-reference resolution, adds-as-full +
    /// deletes-as-tombstones drift, and the sequential shadow apply, all without SQL/Docker.
    #[tokio::test]
    async fn delta_differential_round_trip_kv_and_blobs() {
        use boatramp_core::project_delta::{DeltaMode, DeltaRequest};
        use boatramp_core::project_export::ProjectExport;

        let tmp = tempfile::tempdir().unwrap();
        let shared_base = tmp.path().join("exports");
        let (src, kv_s, blobs_s) = mk_delta_driver(tmp.path(), &shared_base, "src");

        // Seed the source: two KV config keys + two blobs (all project-owned/scoped).
        kv_s.put("project/acme/config/a", b"one".to_vec())
            .await
            .unwrap();
        kv_s.put("project/acme/config/b", b"two".to_vec())
            .await
            .unwrap();
        seed_blob(blobs_s.as_ref(), "hblob/acme/web/x", b"X-v1").await;
        seed_blob(blobs_s.as_ref(), "hblob/acme/web/y", b"Y-v1").await;

        // FULL base export.
        src.export_resumable("acme", &ExportOptions::default(), "base")
            .await
            .expect("full base export");

        // DRIFT: change b, add c, delete a; change x's bytes, add z, delete y.
        kv_s.put("project/acme/config/b", b"TWO".to_vec())
            .await
            .unwrap();
        kv_s.put("project/acme/config/c", b"new".to_vec())
            .await
            .unwrap();
        kv_s.delete("project/acme/config/a").await.unwrap();
        seed_blob(blobs_s.as_ref(), "hblob/acme/web/x", b"X-v2-longer").await;
        seed_blob(blobs_s.as_ref(), "hblob/acme/web/z", b"Z-v1").await;
        blobs_s.delete("hblob/acme/web/y").await.unwrap();

        // DIFFERENTIAL delta against the fixed base.
        let delta_opts = ExportOptions {
            delta: Some(DeltaRequest {
                mode: DeltaMode::Differential,
                base_reference: "base".to_string(),
            }),
            ..Default::default()
        };
        src.export_resumable("acme", &delta_opts, "d1")
            .await
            .expect("differential delta export");

        // Inspect the delta MANIFEST: it is a delta, names the base, and carries ONLY the drift
        // (a KV-delta member, the two changed/new blobs, a blob-tombstone member — NO full KV
        // member, NO member for the unchanged/deleted blobs).
        let d1_dir = src.resolve_resumable_dir("d1", false).await.unwrap();
        let m = src.read_resumable_manifest(&d1_dir).await.unwrap();
        let di = m.delta.as_ref().expect("delta manifest carries DeltaInfo");
        assert_eq!(di.mode, DeltaMode::Differential);
        assert_eq!(di.base_reference, "base");
        assert_eq!(
            di.sql_strategy,
            boatramp_core::project_delta::SqlDeltaKind::FullDumpFallback
        );
        let kinds: Vec<MemberKind> = m.members.iter().map(|s| s.kind).collect();
        assert!(
            kinds.contains(&MemberKind::KvDelta),
            "a delta carries a KV-delta member"
        );
        assert!(
            kinds.contains(&MemberKind::BlobTombstone),
            "a delta with a deleted blob carries a blob-tombstone member"
        );
        assert!(
            !kinds.contains(&MemberKind::Kv),
            "a delta carries NO full KV member"
        );
        let blob_adds: Vec<&str> = m
            .members
            .iter()
            .filter(|s| s.kind == MemberKind::Blob)
            .map(|s| s.path.as_str())
            .collect();
        assert_eq!(
            blob_adds.len(),
            2,
            "exactly the changed (x) + new (z) blobs ship, got {blob_adds:?}"
        );
        assert!(
            blob_adds
                .iter()
                .all(|p| p.contains("/x") || p.contains("/z"))
        );

        // RESTORE onto a FRESH target node (shares the export base so the chain resolves).
        let (tgt, kv_t, blobs_t) = mk_delta_driver(tmp.path(), &shared_base, "tgt");
        let report = tgt
            .import_resumable(
                "acme",
                "d1",
                ImportOptions {
                    apply: true,
                    ..Default::default()
                },
            )
            .await
            .expect("delta chain restore");
        assert!(
            report.notes.iter().any(|n| n.contains("delta restore")),
            "{:?}",
            report.notes
        );

        // Final KV state = base + delta: a DELETED, b CHANGED, c ADDED.
        assert_eq!(
            kv_t.get("project/acme/config/a").await.unwrap(),
            None,
            "a was tombstoned"
        );
        assert_eq!(
            kv_t.get("project/acme/config/b").await.unwrap().as_deref(),
            Some(b"TWO".as_slice())
        );
        assert_eq!(
            kv_t.get("project/acme/config/c").await.unwrap().as_deref(),
            Some(b"new".as_slice())
        );
        // Final blob state: x CHANGED, z ADDED, y DELETED.
        assert_eq!(
            read_blob(blobs_t.as_ref(), "hblob/acme/web/x")
                .await
                .as_deref(),
            Some(b"X-v2-longer".as_slice())
        );
        assert_eq!(
            read_blob(blobs_t.as_ref(), "hblob/acme/web/z")
                .await
                .as_deref(),
            Some(b"Z-v1".as_slice())
        );
        assert_eq!(
            read_blob(blobs_t.as_ref(), "hblob/acme/web/y").await,
            None,
            "y was tombstoned"
        );
    }

    /// INCREMENTAL chain (decision 4): base ← d1 ← d2, each diffed against its parent, restored as
    /// base + replay(d1, d2). Proves chain resolution (walking parent links to the root) and the
    /// cumulative drift of a multi-link chain.
    #[tokio::test]
    async fn delta_incremental_chain_round_trip() {
        use boatramp_core::project_delta::{DeltaMode, DeltaRequest};
        use boatramp_core::project_export::ProjectExport;

        let tmp = tempfile::tempdir().unwrap();
        let shared_base = tmp.path().join("exports");
        let (src, kv_s, blobs_s) = mk_delta_driver(tmp.path(), &shared_base, "src");

        // Base: k1, k2 + blob p.
        kv_s.put("project/acme/config/k1", b"1".to_vec())
            .await
            .unwrap();
        kv_s.put("project/acme/config/k2", b"2".to_vec())
            .await
            .unwrap();
        seed_blob(blobs_s.as_ref(), "hblob/acme/web/p", b"P1").await;
        src.export_resumable("acme", &ExportOptions::default(), "base")
            .await
            .expect("base");

        // d1 (incremental vs base): change k1, add blob q.
        kv_s.put("project/acme/config/k1", b"1b".to_vec())
            .await
            .unwrap();
        seed_blob(blobs_s.as_ref(), "hblob/acme/web/q", b"Q1").await;
        let inc = |base: &str| ExportOptions {
            delta: Some(DeltaRequest {
                mode: DeltaMode::Incremental,
                base_reference: base.to_string(),
            }),
            ..Default::default()
        };
        src.export_resumable("acme", &inc("base"), "d1")
            .await
            .expect("d1");

        // d2 (incremental vs d1): delete k2, delete blob p, add k3.
        kv_s.delete("project/acme/config/k2").await.unwrap();
        kv_s.put("project/acme/config/k3", b"3".to_vec())
            .await
            .unwrap();
        blobs_s.delete("hblob/acme/web/p").await.unwrap();
        src.export_resumable("acme", &inc("d1"), "d2")
            .await
            .expect("d2");

        // d2's manifest chains onto d1 (its parent), proving the incremental linkage.
        let d2_dir = src.resolve_resumable_dir("d2", false).await.unwrap();
        let m2 = src.read_resumable_manifest(&d2_dir).await.unwrap();
        assert_eq!(m2.delta.as_ref().unwrap().base_reference, "d1");
        assert_eq!(m2.delta.as_ref().unwrap().mode, DeltaMode::Incremental);

        // Restore d2 onto a fresh node = base + d1 + d2 replayed.
        let (tgt, kv_t, blobs_t) = mk_delta_driver(tmp.path(), &shared_base, "tgt");
        tgt.import_resumable(
            "acme",
            "d2",
            ImportOptions {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .expect("incremental chain restore");

        // k1 changed (d1), k2 deleted (d2), k3 added (d2); blob p deleted (d2), q present (d1).
        assert_eq!(
            kv_t.get("project/acme/config/k1").await.unwrap().as_deref(),
            Some(b"1b".as_slice())
        );
        assert_eq!(
            kv_t.get("project/acme/config/k2").await.unwrap(),
            None,
            "k2 tombstoned in d2"
        );
        assert_eq!(
            kv_t.get("project/acme/config/k3").await.unwrap().as_deref(),
            Some(b"3".as_slice())
        );
        assert_eq!(
            read_blob(blobs_t.as_ref(), "hblob/acme/web/p").await,
            None,
            "p tombstoned in d2"
        );
        assert_eq!(
            read_blob(blobs_t.as_ref(), "hblob/acme/web/q")
                .await
                .as_deref(),
            Some(b"Q1".as_slice())
        );
    }

    /// SECURITY (chain coherence): a delta is only valid against a base from the SAME source.
    /// A resumable chain lives on an addressable target, so a base exported from a FOREIGN source
    /// could be grafted under a delta. `import_delta_chain` refuses a chain whose links disagree on
    /// `source.project` — without it, `restore_member` would re-key each link from a different
    /// source prefix and restore an incoherent cross-tenant mix. The mutation that drops this
    /// refusal is exactly the foreign-base-graft it guards.
    #[tokio::test]
    async fn delta_import_refuses_a_chain_with_a_foreign_base_source() {
        use boatramp_core::project_delta::{DeltaMode, DeltaRequest};
        use boatramp_core::project_export::ProjectExport;

        let tmp = tempfile::tempdir().unwrap();
        let shared_base = tmp.path().join("exports");
        let (src, kv_s, blobs_s) = mk_delta_driver(tmp.path(), &shared_base, "src");

        // A valid base + one incremental delta, both for project "acme".
        kv_s.put("project/acme/config/k1", b"1".to_vec())
            .await
            .unwrap();
        seed_blob(blobs_s.as_ref(), "hblob/acme/web/p", b"P1").await;
        src.export_resumable("acme", &ExportOptions::default(), "base")
            .await
            .expect("base");
        kv_s.put("project/acme/config/k1", b"1b".to_vec())
            .await
            .unwrap();
        src.export_resumable(
            "acme",
            &ExportOptions {
                delta: Some(DeltaRequest {
                    mode: DeltaMode::Incremental,
                    base_reference: "base".into(),
                }),
                ..Default::default()
            },
            "d1",
        )
        .await
        .expect("d1");

        // Tamper the ROOT base MANIFEST on disk to claim a FOREIGN source project (simulating a
        // base grafted in from another tenant on the shared addressable target).
        let base_dir = src.resolve_resumable_dir("base", false).await.unwrap();
        let mpath = base_dir.join(project_bundle::MANIFEST_PATH);
        let mut m: project_bundle::StreamManifest =
            serde_json::from_slice(&tokio::fs::read(&mpath).await.unwrap()).unwrap();
        m.source.project = "evil".into();
        tokio::fs::write(&mpath, serde_json::to_vec_pretty(&m).unwrap())
            .await
            .unwrap();

        // Importing d1 now resolves a chain [base(evil), d1(acme)] — mismatched sources → refuse,
        // before any member is applied.
        let (tgt, _kv_t, _blobs_t) = mk_delta_driver(tmp.path(), &shared_base, "tgt");
        let err = tgt
            .import_resumable(
                "acme",
                "d1",
                ImportOptions {
                    apply: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("a foreign-base chain must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("must share one source"),
            "expected a one-source coherence refusal, got: {msg}"
        );
    }

    /// SECURITY (the tenancy-critical delta seam): a KV-delta's tombstone keys are
    /// attacker-influenceable; a tombstone that escapes the target's owned scope would be a
    /// CROSS-TENANT delete. The `KvDelta` restore arm REFUSES it fail-closed. The mutation that
    /// drops this refuse is exactly the cross-tenant-delete bug it guards.
    #[tokio::test]
    async fn delta_restore_refuses_a_cross_tenant_kv_tombstone() {
        use boatramp_core::kv::KvDumpEntry;
        use boatramp_core::project_delta::{self as pd, KvDelta};

        let tmp = tempfile::tempdir().unwrap();
        let shared_base = tmp.path().join("exports");
        let (drv, kv, _blobs) = mk_delta_driver(tmp.path(), &shared_base, "t");
        // A victim key another tenant owns — it must survive a hostile delta aimed at it.
        kv.put("project/globex/secret/x", b"victim".to_vec())
            .await
            .unwrap();

        // A hostile delta: a legit target upsert, but a tombstone pointed at the victim's key.
        let hostile = KvDelta {
            upserts: vec![KvDumpEntry {
                key: "project/acme/config/ok".to_string(),
                value: b"v".to_vec(),
                version: 1,
            }],
            tombstones: vec!["project/globex/secret/x".to_string()],
        };
        let temp = tmp.path().join("hostile.brkvdelta");
        tokio::fs::write(&temp, pd::encode_kv_delta(&hostile, 0))
            .await
            .unwrap();

        let spec = project_bundle::MemberSpec::sidecar(
            project_bundle::KV_DELTA_MEMBER_PATH.to_string(),
            MemberKind::KvDelta,
            None,
        );
        let mut report = ImportReport::default();
        let mut saw = false;
        // Import AS "acme": the tombstone re-keys to itself (globex is not acme's source), lands
        // outside acme's owned scope → REFUSED fail-closed.
        let r = drv
            .restore_member(
                "acme",
                BundleHead::from(false),
                "acme",
                &spec,
                &temp,
                &ImportOptions {
                    apply: true,
                    ..Default::default()
                },
                &mut report,
                &mut saw,
            )
            .await;
        assert!(r.is_err(), "a cross-tenant tombstone must be refused");
        assert!(
            format!("{}", r.unwrap_err()).contains("outside the target project"),
            "the refusal names the cross-tenant scope violation"
        );
        // The victim's key is UNTOUCHED (fail-closed BEFORE any delete).
        assert_eq!(
            kv.get("project/globex/secret/x").await.unwrap().as_deref(),
            Some(b"victim".as_slice()),
            "a refused delta deletes NOTHING"
        );
    }
}
