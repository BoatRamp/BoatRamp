//! Pluggable, streaming storage backends and KV stores for boatramp.
//!
//! Two backend families, selected at compile time via cargo features so unused
//! ones (and their dependencies) are never pulled into a build:
//!
//! **Blob storage** ([`boatramp_core::Storage`]) — streams file contents:
//! - `fs` (default): [`fs::FsStorage`], local filesystem.
//! - `s3`: [`s3::S3Storage`], S3-compatible.
//!
//! **KV stores** ([`boatramp_core::kv::KvStore`]) — small deploy metadata:
//! - `slatedb` (default): [`kv_slatedb::SlateKv`], transactional LSM over any
//!   `object_store` backend (local fs, S3/R2, GCS, ...). The durable default.
//! - `cloudflare-kv`: [`kv_cloudflare::CloudflareKv`], Cloudflare KV over REST.
//!
//! An in-memory `MemoryKv` and an LRU `CachedKv` wrapper live in
//! [`boatramp_core::kv`].

#[cfg(feature = "fs")]
pub mod fs;

#[cfg(feature = "s3")]
pub mod s3;

#[cfg(feature = "s3")]
pub mod s3_notify;

#[cfg(feature = "gcs")]
pub mod gcs;

#[cfg(feature = "gcs")]
pub mod gcs_notify;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "azure")]
pub mod azure_notify;

// The hand-rolled Shared Key (account-key/Azurite) request-signing policy for the 1.x
// Azure SDK, which is AAD-first and dropped native shared-key auth. Shared by the blob
// backend (`azure`) and the queue notify path (`azure_notify`).
#[cfg(feature = "azure")]
pub mod azure_shared_key;

#[cfg(feature = "slatedb")]
pub mod kv_slatedb;

/// The `object_store` crate slatedb builds against, re-exported so downstream crates (the
/// `boatramp kv repair` CLI) can name the `ObjectStore` trait / `Arc<dyn ObjectStore>` without a
/// direct `object_store` / `slatedb` dependency of their own (and without a version-mismatch risk).
#[cfg(feature = "slatedb")]
pub use slatedb::object_store;

/// Opt-in WAL tail repair for the SlateDB control-plane store (P0, v0.7.2): quarantine a
/// torn TRAILING WAL tail beyond the durable frontier so a crash-frozen store opens, with a
/// data-loss guard that refuses on a mid-range gap or an unreadable manifest.
#[cfg(feature = "slatedb")]
pub mod wal_repair;

#[cfg(feature = "cloudflare-kv")]
pub mod kv_cloudflare;

#[cfg(feature = "sql")]
pub mod sql_libsql;
// The SQL-backed control-plane KV ([`KvStore`](boatramp_core::kv::KvStore)) — SQLite/libsql-local
// single-writer (`sql`), the Postgres multi-writer primary (`sql-postgres`), and the MySQL/MariaDB
// multi-writer primary (`sql-mysql`). Available under ANY engine feature; each backing's code is
// gated on the feature that constructs it, so `--features sql-mysql` compiles it with no libsql.
#[cfg(any(feature = "sql", feature = "sql-postgres", feature = "sql-mysql"))]
pub mod kv_sql;
#[cfg(any(feature = "sql", feature = "sql-postgres", feature = "sql-mysql"))]
mod sql_placeholders;

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod sql_compute;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod sql_sqlx;
// Pure per-tenant managed-database provisioning: sanitized name derivation and
// idempotent DDL generation (no IO, no async). The caller runs the DDL.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod tenant_provision;

#[cfg(feature = "cache")]
pub mod cache;

#[cfg(feature = "fallback")]
pub mod fallback;

/// The backend-agnostic **blob-backend migration** copy engine (`list`/`head`/`get`/`put`
/// over the [`Storage`](boatramp_core::Storage) trait). Drives both the offline node-local
/// `boatramp blob migrate` (re-exported as `boatramp_node::blob_migrate`) and the
/// daemon-mediated `POST /api/blob-drain` control-plane drain (v0.6.3), which streams
/// [`blob_migrate::MigrateProgress`] via [`blob_migrate::MigrateOptions::on_progress`].
pub mod blob_migrate;

/// The backend-agnostic **drained-source purge** engine (v0.6.4): reclaim the OLD read-only
/// secondary of a blob-backend migration by deleting each source key ONLY once it is provably
/// duplicated (present at matching size) in the NEW primary — the decommission half of the
/// migration. Backs the `DrainedSource` mode of `POST /api/blob-purge` (the `Unreferenced` mode
/// runs [`DeployStore::collect_garbage`](boatramp_core::deploy)). Its safety decision is a single
/// pure predicate ([`blob_purge::drained_source_deletable`]) so the gate rests on the test-runner
/// exit code, not a println marker.
pub mod blob_purge;

#[cfg(feature = "fs")]
pub use fs::FsStorage;

#[cfg(feature = "s3")]
pub use s3::{S3Options, S3Storage};

#[cfg(feature = "s3")]
pub use s3_notify::S3WatchProvider;

#[cfg(feature = "gcs")]
pub use gcs::{GcsOptions, GcsStorage};

#[cfg(feature = "gcs")]
pub use gcs_notify::GcsWatchProvider;

#[cfg(feature = "azure")]
pub use azure::{AzureOptions, AzureStorage};

#[cfg(feature = "azure")]
pub use azure_notify::AzureWatchProvider;

#[cfg(feature = "slatedb")]
pub use kv_slatedb::{S3StoreConfig, SlateKv};

#[cfg(feature = "cloudflare-kv")]
pub use kv_cloudflare::CloudflareKv;

#[cfg(any(feature = "sql", feature = "sql-postgres", feature = "sql-mysql"))]
pub use kv_sql::SqlKv;

#[cfg(feature = "sql")]
pub use sql_libsql::{LibsqlSql, LibsqlSqlBackends};

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub use sql_sqlx::{ExternalSqlKind, ExternalSqlOptions};

#[cfg(feature = "cache")]
pub use cache::CachedStorage;

#[cfg(feature = "fallback")]
pub use fallback::{FallbackStorage, FallbackWhen};
