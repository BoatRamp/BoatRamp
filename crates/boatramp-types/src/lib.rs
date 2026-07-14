//! Shared, **wasm-clean** boatramp types: the serde wire models + the pure
//! routing/config logic, with no IO, async, or backend dependencies. The
//! server, the CLI, and the edge Worker all depend on this crate, so the wire
//! format and the routing decisions can't drift between them — and it compiles
//! to `wasm32-unknown-unknown` (the edge target) where the full `boatramp-core`
//! (Storage/KV/wasmtime) cannot.
//!
//! `boatramp-core` re-exports every module here (`boatramp_core::config`,
//! `::route`, …), so existing `boatramp_core::*` paths are unchanged.

pub mod access;
pub mod authz;
pub mod cert;
pub mod compute;
pub mod config;
pub mod cron;
pub mod daemon_config;
pub mod deploy;
pub mod dns_managed;
pub mod domain_verify;
pub mod error;
pub mod file;
pub mod function;
pub mod gateway;
pub mod manifest;
pub mod matcher;
pub mod predicate;
pub mod route;
pub mod security;
pub mod waf;

pub use error::ConfigError;

/// Schema version stamped on every persisted boatramp document (manifests,
/// deploy/site configs, and KV records).
///
/// Pre-release this is **pinned at 1 and never bumped**: the discriminant is
/// present from the start so a future release can dispatch on it, but while
/// unreleased we change formats freely *under* v1 — no migration code, and every
/// reader assumes v1. The first release freezes v1's
/// meaning; only then do bumps + migrations begin.
pub const SCHEMA_VERSION: u32 = 1;

/// serde `default` for the `version` field on schema types, so documents
/// written before the field existed (or by hand) still read as v1.
pub fn schema_version() -> u32 {
    SCHEMA_VERSION
}
