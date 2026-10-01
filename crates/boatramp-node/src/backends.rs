//! Backend-selection enums for a node's blob + KV stores (node-library N2b).
//!
//! These are the domain types the store-construction assembly dispatches on. They
//! live here (not the binary) so the assembly can move into the library; the
//! `clap::ValueEnum` derive is behind the optional `clap` feature so the CLI
//! binary uses them directly in its args, while a non-CLI embedder never pulls
//! clap. (`build_kv`/`build_blobs` join this module as they migrate off the
//! binary's `ServeArgs`.)

use std::path::Path;
use std::sync::Arc;

use boatramp_core::kv::{KvOpenPolicy, KvStore, MemoryKv};

use crate::error::Result;

/// Blob (file-content) backend.
///
/// `Deserialize` (lowercase: `fs`/`s3`/`gcs`/`azure`) so `[serve].blobs` in `boatramp.cfg` can
/// select the backend — the config-level analog of the `--blobs` flag, which `boatramp blob
/// migrate` reads to build a source/destination backend from a config file alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum BlobBackend {
    /// Local filesystem (`<data-dir>/blobs`).
    Fs,
    /// S3-compatible object store (requires `--features s3`).
    S3,
    /// Google Cloud Storage (requires `--features gcs`).
    Gcs,
    /// Azure Blob Storage (requires `--features azure`).
    Azure,
}

/// Metadata (manifest + pointer) backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum KvBackend {
    /// Transactional LSM over object storage; durable local default
    /// (`<data-dir>/kv-slate`). Requires `--features slatedb` (on by default).
    Slatedb,
    /// In-memory (ephemeral; lost on restart).
    Memory,
    /// Cloudflare KV over REST (requires `--features cloudflare-kv`).
    Cloudflare,
    /// SQL-backed KV. SQLite/libsql-LOCAL single-writer today (a simple, robust single-node/dev
    /// store with no SlateDB torn-manifest class); Postgres/MySQL (multi-writer) land later.
    /// Connection via `[serve.kv.sql]` / `BOATRAMP_KV_SQL_*`. Requires `--features sql` (implied by
    /// `handlers`, so on in the default build).
    Sql,
}

/// Flush interval for the control-plane SlateDB store: tiny, so a control-plane
/// write is durable almost immediately (correctness over throughput).
pub const CONTROL_PLANE_FLUSH: std::time::Duration = std::time::Duration::from_millis(5);

/// Where the SlateDB control-plane store lives when it runs on an S3-compatible
/// object store (Cloudflare R2) instead of local disk — the durable, remote-state
/// deployment. Credentials come from the ambient AWS environment
/// (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), matching the S3 blob backend.
#[derive(Debug, Clone)]
pub struct SlateKvS3 {
    /// The bucket the store lives in (shared with S3 blobs, under `prefix`).
    pub bucket: String,
    /// Custom endpoint (R2: `https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: Option<String>,
    /// Region (R2 uses `auto`).
    pub region: Option<String>,
    /// Use path-style addressing (R2 accepts it).
    pub path_style: bool,
    /// Key prefix within the bucket (keeps the LSM files apart from the blobs).
    pub prefix: String,
}

/// Build the metadata KV store for the selected [`KvBackend`]. When `slate_s3` is
/// set (and the backend is SlateDB), the store runs on R2/S3 (durable across a
/// scale-to-zero container stop) rather than the local `data_dir`.
///
/// `policy` (v0.9.0 KV-recovery, C3/C7/C8/C11) is the cold-open recovery policy for the SlateDB
/// backend (a no-op for Memory/Cloudflare). This is the SINGLE-NODE control-plane open site, so its
/// default is [`KvOpenPolicy::SelfHeal`]; the caller passes [`KvOpenPolicy::Strict`] for
/// `--strict-kv`. (The cluster node-local Raft store opens elsewhere and stays strict — C8.)
///
/// `sql` is the `[serve.kv.sql]` connection config (env-resolved by the caller), consulted only for
/// [`KvBackend::Sql`] and ignored otherwise.
pub async fn build_kv(
    kv: KvBackend,
    data_dir: &Path,
    slate_s3: Option<&SlateKvS3>,
    policy: KvOpenPolicy,
    sql: Option<&crate::config::SqlKvConfig>,
) -> Result<Arc<dyn KvStore>> {
    match kv {
        KvBackend::Slatedb => build_slatedb_kv(data_dir, slate_s3, policy).await,
        KvBackend::Memory => Ok(Arc::new(MemoryKv::new())),
        KvBackend::Cloudflare => build_cloudflare_kv(),
        KvBackend::Sql => build_sql_kv(sql).await,
    }
}

/// Build the SQL control-plane KV from its `[serve.kv.sql]` config. Wires the embedded single-node
/// **SQLite / libsql-local** path (`kind = sqlite`, by on-disk `path`, single-writer) and the
/// **Postgres** primary (`kind = postgres`, by `url_env`-named URL, multi-writer). `mysql` and a
/// remote-sqld `libsql` `url_env` are later workstreams and are refused with a clear, actionable
/// message rather than silently mis-opened.
#[cfg(feature = "sql")]
async fn build_sql_kv(sql: Option<&crate::config::SqlKvConfig>) -> Result<Arc<dyn KvStore>> {
    use crate::error::Error;
    let cfg = sql.ok_or_else(|| {
        Error::SqlKvConfig(
            "`--kv sql` needs a `[serve.kv.sql]` config block (or the `BOATRAMP_KV_SQL_*` env)"
                .to_string(),
        )
    })?;
    // `kind` uses the same alias set as the `databases:` block; empty defaults to sqlite.
    match cfg.kind.trim().to_ascii_lowercase().as_str() {
        "" | "sqlite" | "sqlite3" | "libsql" => {
            let path = cfg
                .path
                .as_deref()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| {
                    Error::SqlKvConfig(
                    "`[serve.kv.sql] kind = sqlite` needs `path` (an on-disk file) — set it or \
                     `BOATRAMP_KV_SQL_PATH`"
                        .to_string(),
                )
                })?;
            Ok(Arc::new(
                boatramp_storage::SqlKv::open_sqlite_local(path).await?,
            ))
        }
        engine @ ("postgres" | "postgresql" | "pg") => build_pg_kv(cfg, engine).await,
        engine @ ("mysql" | "mariadb") => Err(Error::SqlKvConfig(format!(
            "the `{engine}` SQL KV backend is wired in a later workstream; `--kv sql` currently \
             supports `sqlite` (libsql-local, single node) and `postgres` (multi-writer)"
        ))),
        other => Err(Error::SqlKvConfig(format!(
            "unknown `[serve.kv.sql] kind` {other:?}: expected sqlite | postgres | mysql"
        ))),
    }
}

/// Open the Postgres control-plane KV from `cfg`, resolving the connection URL from the env var
/// `cfg.url_env` NAMES (UX-C2 — never a raw URL in config) and passing `cfg.pool_max` to the pool.
/// Requires the `sql-postgres` engine; a build without it refuses with an actionable rebuild hint.
#[cfg(all(feature = "sql", feature = "sql-postgres"))]
async fn build_pg_kv(cfg: &crate::config::SqlKvConfig, engine: &str) -> Result<Arc<dyn KvStore>> {
    use crate::error::Error;
    let url_env = cfg
        .url_env
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::SqlKvConfig(format!(
                "`[serve.kv.sql] kind = {engine}` needs `url_env` (the NAME of the env var holding \
                 the connection URL — never a raw URL in config) — set it or `BOATRAMP_KV_SQL_URL_ENV`"
            ))
        })?;
    let url = std::env::var(url_env)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            Error::SqlKvConfig(format!(
                "`[serve.kv.sql] url_env = {url_env:?}` names an unset or empty env var; set \
                 {url_env} to the Postgres connection URL"
            ))
        })?;
    Ok(Arc::new(
        boatramp_storage::SqlKv::open_postgres(url, cfg.pool_max).await?,
    ))
}

#[cfg(all(feature = "sql", not(feature = "sql-postgres")))]
async fn build_pg_kv(_cfg: &crate::config::SqlKvConfig, engine: &str) -> Result<Arc<dyn KvStore>> {
    Err(crate::error::Error::SqlKvConfig(format!(
        "the `{engine}` SQL KV backend needs the Postgres engine — rebuild with `--features sql-postgres`"
    )))
}

#[cfg(not(feature = "sql"))]
async fn build_sql_kv(_sql: Option<&crate::config::SqlKvConfig>) -> Result<Arc<dyn KvStore>> {
    Err(crate::error::Error::NoSqlSupport)
}

#[cfg(feature = "slatedb")]
async fn build_slatedb_kv(
    data_dir: &Path,
    slate_s3: Option<&SlateKvS3>,
    policy: KvOpenPolicy,
) -> Result<Arc<dyn KvStore>> {
    match slate_s3 {
        Some(s3) => Ok(Arc::new(
            boatramp_storage::SlateKv::open_s3_with_flush_policy(
                &boatramp_storage::S3StoreConfig {
                    bucket: s3.bucket.clone(),
                    endpoint: s3.endpoint.clone(),
                    region: s3.region.clone(),
                    path_style: s3.path_style,
                },
                &s3.prefix,
                CONTROL_PLANE_FLUSH,
                policy,
            )
            .await?,
        )),
        None => Ok(Arc::new(
            boatramp_storage::SlateKv::open_local_with_flush_policy(
                data_dir.join("kv-slate"),
                CONTROL_PLANE_FLUSH,
                policy,
            )
            .await?,
        )),
    }
}

#[cfg(not(feature = "slatedb"))]
async fn build_slatedb_kv(
    _data_dir: &Path,
    _slate_s3: Option<&SlateKvS3>,
    _policy: KvOpenPolicy,
) -> Result<Arc<dyn KvStore>> {
    Err(crate::error::Error::NoSlatedbSupport)
}

#[cfg(feature = "cloudflare-kv")]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Ok(Arc::new(boatramp_storage::CloudflareKv::from_env()?))
}

#[cfg(not(feature = "cloudflare-kv"))]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Err(crate::error::Error::NoCloudflareKvSupport)
}
