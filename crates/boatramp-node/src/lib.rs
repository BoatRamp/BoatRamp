//! Node assembly for boatramp.
//!
//! The `boatramp` binary was historically the only place that turned parsed
//! configuration into a running node (store + backends + handler runtime +
//! reconcile loops + router). That assembly is not reachable as a library, so an
//! embedder — or an in-process fidelity test — can't exercise the same wiring the
//! `boatramp serve` binary runs (see `PLAN-node-library`).
//!
//! This crate is the extraction target. It starts with the parsed **config model**
//! ([`config`]) and grows, incrementally and behaviour-preservingly, to host the
//! `assemble(config) -> RunningNode` path. The binary re-exports [`config`] under
//! its own `crate::config`, so moving the module here changes no call site.
//!
//! It depends on the concrete backend crates (Docker, storage, …) that
//! `boatramp-server` deliberately does not, keeping `boatramp-server` a
//! backend-agnostic library while this crate is the batteries-included assembler.

pub mod auth;
pub mod backends;
/// The `BLOB FALLBACK ZERO-GAP OK` mutation-verified gate (blob-backend migration Part 2). Compiled
/// ONLY under the `blob-fallback-gate-mutation` feature (the CI gate lane): it drives the real
/// [`FallbackStorage`](boatramp_storage::FallbackStorage) composite over real `FsStorage` tempdir
/// backends + a real `DeployStore` for the GC-refusal invariant, and prints the marker only on a
/// clean run.
#[cfg(feature = "blob-fallback-gate-mutation")]
pub mod blob_fallback;
/// Offline, node-local blob-backend migration (`boatramp blob migrate`) — the copy engine over
/// the [`Storage`](boatramp_core::Storage) primitives. Relocated into `boatramp-storage` in
/// v0.6.3 (so the daemon-mediated `POST /api/blob-drain` can drive it too); re-exported here so
/// the offline CLI + `build_blobs` callers keep compiling unchanged (`boatramp_node::blob_migrate`).
/// Gated on the exact set of node features that activate the optional `boatramp-storage` dep (every
/// blob backend implies `fallback`; `cloudflare-kv`/`slatedb`/`handlers` pull it directly), so the
/// re-export exists precisely when `boatramp_storage` is linkable — which is exactly when the offline
/// `blob migrate` / `blob drain` client path (which needs a real backend) is reachable. A truly lean
/// node (no storage) compiles fine with the re-export absent (nothing references it there).
#[cfg(any(
    feature = "fallback",
    feature = "cloudflare-kv",
    feature = "slatedb",
    feature = "handlers"
))]
pub use boatramp_storage::blob_migrate;
pub mod blobs;
pub mod compute;
pub mod config;
pub mod error;
pub use error::Error;
pub mod handlers;
// The managed-SQL module carries the Postgres/MySQL operator-SQL + credential machinery (sqlx) AND
// the migration substrate. It compiles whenever a sqlx engine OR `migrate` (⇒ the embedded libsql
// migration runner) is on, so the libsql migrate parity is reachable on a node with no external sqlx
// engine. The sqlx-specific items inside the module stay gated on the sqlx features.
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql", feature = "migrate"))]
pub mod managed_sql;
// The project-scoped declarative managed-database front door (#501 Stage B): lowering
// + the two-source merge point + the `ManagedDbDeclare` capability. Needs a sqlx engine
// (it provisions a Postgres/MySQL managed DB).
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod managed_db_declare;
pub mod node;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod repair;
/// Node-level base S3 credential sourcing from the `[secrets]` sealed store (#505).
pub mod s3_credential;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod tenant_sql;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod tenant_tombstone;
pub use node::{NodeInput, RunningNode, assemble};
