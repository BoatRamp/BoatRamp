//! # boatramp overlay fabric — async runtime
//!
//! The transport and node machinery of the overlay, built on the pure core in
//! [`boatramp_overlay_proto`]: QUIC endpoints on raw-public-key TLS ([`quic`]),
//! and (as the fabric grows) the relay-blind E2EE splice, the resumable circuit
//! pump, ICE/NAT traversal, direct-path promotion, and the relay/egress/
//! client-edge node roles.
//!
//! ## Dependency direction (hard rule)
//!
//! This crate depends only on boatramp **substrate** (`-overlay-proto`,
//! `-rpktls`, `-core`, `-storage`) — never on the platform
//! (`boatramp-server`/`-node`/`-handlers`/compute), so boatramp can later carry
//! its own cluster mesh over the overlay without a dependency cycle.

#![forbid(unsafe_code)]

pub mod quic;

pub use quic::{QuicError, client_endpoint, peer_endpoint, server_endpoint};
