//! # boatramp overlay fabric — pure protocol & crypto core
//!
//! This crate is the **pure core** of the boatramp overlay network: identity,
//! peer-trust policy, the relay-blind E2EE session crypto, the resumable
//! circuit framing, and the capability-dial wire types. It holds **no async
//! runtime and no transport stack** — there is deliberately no `tokio`, no
//! `quinn`, no sockets here. The async drivers (QUIC endpoints, the E2EE splice
//! pumps, the circuit duplex loop, ICE, direct-path promotion, the node roles
//! and the CLI) live in the sibling `boatramp-overlay` crate.
//!
//! Splitting the core out this way makes the two load-bearing security
//! invariants hold **by the crate graph**, not by discipline:
//! - the data-path signer is a local Ed25519 op (never a network KMS), and
//! - a relay forwards ciphertext it cannot read or forge,
//!
//! because the code that enforces them links neither a transport nor a remote
//! signer. Security review reasons over this small, dependency-light surface.
//!
//! ## Substrate, not reinvention
//!
//! The overlay is a fresh, boatramp-idiom build of an overlay-network design;
//! it is **not** a vendor of any reference implementation, and no foreign
//! vocabulary survives (see [`wire`]). It stands on boatramp's existing
//! substrate and rebuilds only the overlay proper:
//! - identity & local signing → [`boatramp_core::cose`]
//!   (`TokenPublicKey`, `LocalSigner`, the COSE capability machinery);
//! - raw-public-key (RFC 7250) trust → [`boatramp_rpktls`] (`RpkIdentity`,
//!   `TrustSet`).
//!
//! ## Dependency direction (hard rule)
//!
//! This crate depends only on boatramp **substrate** crates, never on the
//! platform (`boatramp-server`/`-node`/`-handlers`/compute) — so boatramp can
//! later run its own cluster mesh on top of the overlay without a cycle.

#![forbid(unsafe_code)]

pub mod circuit;
pub mod dial;
pub mod e2ee;
pub mod identity;
pub mod peer_policy;
pub mod wire;

pub use circuit::{RxPortal, TxPortal, XgressFrame};
pub use dial::{DialReject, DialRequest, DialVerdict, authorize_dial};
pub use e2ee::{E2eeError, HybridInitiator, Opener, Role, Sealer, Session, hybrid_respond};
pub use identity::{OverlayId, OverlayIdError, OverlaySecret};
pub use peer_policy::OverlayPeerPolicy;
