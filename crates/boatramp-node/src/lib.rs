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
pub mod node;
pub use node::{assemble, NodeInput, RunningNode};
