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

pub mod circuit;
pub mod direct;
pub mod e2ee;
pub mod ice;
pub mod net;
pub mod quic;

pub use circuit::{
    CircuitError, CircuitId, CircuitRegistry, CircuitStats, LinkHalves, run_circuit_duplex,
};
pub use direct::{PathMode, negotiate_direct};
pub use e2ee::{SpliceError, establish, splice};
pub use net::{
    ExposerRegistry, NetError, RegisterReject, RelayClientAuth, forward_flow, forward_relay,
    run_egress_router, run_forwarding_router, run_ingress_router, run_published_service,
    terminate_one,
};
pub use quic::{
    QuicError, accept, client_endpoint, client_endpoint_server_auth, dial, dial_mesh_peer,
    mesh_endpoint, peer_endpoint, server_endpoint, server_endpoint_with_trust,
};
// Re-export the rpktls types the mesh transport (IU-9) builds endpoints from, and quinn itself, so
// a consumer (e.g. boatramp-cluster's overlay mesh transport) depends on this one integration crate.
pub use boatramp_rpktls::{PeerId, RpkTls, TrustSet};
pub use quinn;

// Re-export the pure-core types a consumer (e.g. the `boatramp forward` CLI) needs, so it can
// depend on this one crate.
pub use boatramp_overlay_proto::{
    DialRequest, DialVerdict, OverlayId, OverlayIdError, OverlayPeerPolicy, OverlaySecret,
};
