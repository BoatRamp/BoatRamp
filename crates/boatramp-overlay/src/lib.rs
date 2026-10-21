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
pub mod pair;
pub mod quic;

pub use circuit::{
    CircuitError, CircuitId, CircuitRegistry, CircuitStats, LinkHalves, run_circuit_duplex,
};
pub use direct::{PathMode, negotiate_direct};
pub use e2ee::{SpliceError, establish, splice};
// Client-edge + shared surface: the dialing/forwarding/exposing client roles and the wire types the
// client half of the registration protocol parses (`RegisterReject`, carried in `NetError`). Always
// available — this is what the embeddable `boatramp-overlay-client` SDK links against.
pub use net::{
    NetError, PairReject, RegisterReject, forward_flow, pair_relay_park,
    pair_relay_park_authenticated, pair_relay_redeem, pair_relay_redeem_short,
    run_published_service,
};
// Server/relay/control-plane roles (overlay follow-up #4): the forwarding/egress/ingress routers,
// the exposer registry, the pairing rendezvous (follow-up #2 inc2), the pairing SHORT-CODE alias
// table (follow-up #2 inc3), the relay client-auth posture, and the per-relay open-vs-authenticated
// pairing-park mode (overlay pairing PARK operator config). Behind `server` so the client SDK never
// links them.
#[cfg(feature = "server")]
pub use net::{
    ExposerRegistry, PairRendezvous, PairShortCodeError, PairShortCodes, PairingParkMode,
    RelayClientAuth, forward_relay, run_egress_router, run_forwarding_router, run_ingress_router,
    terminate_one,
};
pub use pair::{PairError, VerifiedPeer, VerifiedPeers, pair_handshake};
// The dial/publish trust-root type that appears in `run_published_service`'s (and `terminate_one`'s)
// public signature — re-exported so a consumer (the `boatramp-overlay-client` SDK, `boatramp expose`)
// names it through this one crate rather than reaching into `boatramp-core`.
pub use boatramp_core::cose::TokenPublicKey;
// Client/shared QUIC endpoints: dial-only, pairing-dial, and the dial+accept peer socket the
// direct-path promotion hole-punch needs.
pub use quic::{
    QuicError, client_endpoint, client_endpoint_server_auth, dial, pair_dial_endpoint,
    peer_endpoint,
};
// Server/mesh QUIC constructors (accept-side + the IU-9 cluster-mesh seam). Behind `server`.
#[cfg(feature = "server")]
pub use quic::{
    accept, dial_mesh_peer, mesh_endpoint, server_endpoint, server_endpoint_with_trust,
};
// Re-export the rpktls types the mesh transport (IU-9) builds endpoints from so a server consumer
// (e.g. boatramp-cluster's overlay mesh transport) depends on this one integration crate. Behind
// `server` — the client edge never touches the mesh identity/trust-set types.
#[cfg(feature = "server")]
pub use boatramp_rpktls::{PeerId, RpkTls, TrustSet};
// quinn itself stays available to the client edge: the SDK holds a `quinn::Endpoint` for its dial
// socket, and a consumer may name the connection/stream types.
pub use quinn;

// Re-export the pure-core types a consumer (e.g. the `boatramp forward` CLI) needs, so it can
// depend on this one crate.
pub use boatramp_overlay_proto::{
    DialRequest, DialVerdict, Fingerprint, OverlayId, OverlayIdError, OverlayPeerPolicy,
    OverlaySecret, PAIR_RENDEZVOUS_ID_LEN, PAIR_SHORT_CODE_DIGITS_DEFAULT,
    PAIR_SHORT_CODE_DIGITS_MAX, PAIR_SHORT_CODE_DIGITS_MIN, PairCode, PairCodeError, Role, SasCode,
    ShortCode, ShortCodeError, identity_fp,
};
