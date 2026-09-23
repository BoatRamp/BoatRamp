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
pub mod node;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod repair;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod tenant_sql;
#[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
pub mod tenant_tombstone;
pub use node::{assemble, NodeInput, RunningNode};
