//! BoatRamp's owned HTTP serving stack.
//!
//! One accept loop over hand-rolled HTTP/1.1 and HTTP/2 codecs, with the kernel
//! `splice()`/kTLS reverse-proxy body fast-paths hyper structurally can't do. The
//! protocols live as sibling modules over shared serving types:
//!
//! - [`h1`] — the HTTP/1.1 codec (built here, **test-first**: see its module docs and
//!   the `tests/` harness).
//! - [`h2`] — the concurrent multiplexed HTTP/2 driver (formerly the `boatramp-h2`
//!   crate, folded in — Stage 1 of `DESIGN-serving.md`).
//! - [`serve`] — the unified accept-loop dispatcher (TLS ALPN / plaintext h2c-preface
//!   sniff → h1 vs h2), replacing the `boatramp-server` mux-serve bridge + `splice.rs`
//!   (Stage 3 of `DESIGN-serving.md`, built: [`serve_connection`] /
//!   [`serve_connection_with`] classify an accepted connection and drive it through the
//!   right codec).
//!
//! The shared serving types ([`Body`], [`Handler`], [`Request`], [`Response`]) are
//! re-exported at the crate root — the surface both codecs produce/consume and the
//! serve dispatcher hands to a `tower::Service` (the axum Router).

pub mod h1;
pub mod h2;
pub mod serve;
pub use serve::{Config, serve_connection, serve_connection_graceful, serve_connection_with};

// The caller-held graceful-shutdown signal shared by the h1 + h2 serve loops.
mod shutdown;
pub use shutdown::GracefulShutdown;

// The shared serving abstraction (`Request`/`Response`/`Body`/`Handler`) — homed at the
// crate root, the surface both codecs produce/consume.
mod serving;
pub use serving::{Body, BodyChunk, BodyError, Handler, ReqBody, Request, Response, response};

// HTTP/1.1 connection upgrade (WebSocket + generic `Connection: upgrade`) — replaces
// `hyper::upgrade` so the serving path owns upgrades.
pub mod upgrade;
pub use upgrade::{OnUpgrade, Upgraded, is_upgrade_request, on_upgrade, sec_websocket_accept};

// The verification kit (corpus + normalized-verdict model + combinatorial generators)
// shared by the h1 gate, the differential-vs-hyper driver, and the fuzz targets — one
// canonical, per-aspect-grouped source so coverage is auditable and reused across all
// three layers. Data-only + dev-oriented; it ships in this (publish=false) spike crate.
pub mod testkit;
