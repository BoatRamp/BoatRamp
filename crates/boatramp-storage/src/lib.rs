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

#[cfg(feature = "slatedb")]
pub mod kv_slatedb;

#[cfg(feature = "cloudflare-kv")]
pub mod kv_cloudflare;

#[cfg(feature = "sql")]
pub mod sql_libsql;

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod sql_sqlx;

#[cfg(feature = "cache")]
pub mod cache;

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
pub use kv_slatedb::SlateKv;

#[cfg(feature = "cloudflare-kv")]
pub use kv_cloudflare::CloudflareKv;

#[cfg(feature = "sql")]
pub use sql_libsql::{LibsqlSql, LibsqlSqlBackends};

#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub use sql_sqlx::{ExternalSqlKind, ExternalSqlOptions};

#[cfg(feature = "cache")]
pub use cache::CachedStorage;
