//! boatramp self-hosted **cluster mode**.
//!
//! N boatramp nodes coordinate among themselves via an embedded Raft library —
//! no external coordinator. Control-plane metadata (manifests, pointers,
//! aliases, certs, tokens, and message claim/index ops) is replicated through
//! Raft; blobs and message payloads stay in the shared `Storage`. Everything
//! here is behind the `raft` feature so the default single-node binary stays
//! zero-dependency.

#[cfg(feature = "raft")]
pub mod raft;

#[cfg(feature = "raft")]
pub mod persist;

#[cfg(feature = "raft")]
pub mod messaging;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "http")]
pub mod mesh;

#[cfg(feature = "http")]
pub mod node;
