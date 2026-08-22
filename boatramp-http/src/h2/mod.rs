//! The HTTP/2 codec — a minimal, **h2spec-conformance-gated** server.
//!
//! # Why this exists
//!
//! Off-the-shelf Rust HTTP/2 (`h2` via `hyper`) leaves throughput on the table for a
//! large-body reverse proxy. This codec owns the framing so the concurrent multiplexed
//! driver ([`serve_connection_mux`]) can stream response bodies to rustls with vectored,
//! copy-free writes across multiplexed streams — which **matches or beats Envoy on
//! `tls-proxy-h2-100k`** (see `../README.md`). (A kernel `splice()`/kTLS body path was
//! built and benchmarked, in both h2 and h1, and retired: userspace rustls + the mux's
//! cross-stream batching win outright — see the crate README's kTLS verdict.)
//!
//! # Conformance is a hard gate, not an afterthought
//!
//! A hand-rolled HTTP/2 is a bug farm if you only build the happy path (a
//! benchmark-shaped prototype passed just 60 of h2spec's 145 cases). So this codec was
//! built **red→green against h2spec** (RFC 7540 + RFC 7541) plus a differential oracle
//! (identical requests through this server and `hyper`/`h2` must produce byte-identical
//! responses) plus fuzzing of the frame + HPACK parsers. Anything the fast-path does not
//! implement degrades to a graceful `GOAWAY` — never to wrong behavior (h2 has no clean
//! mid-connection fallback the way HTTP/1 does). Both drivers are h2spec 143/143.

pub mod conn;
pub mod error;
pub mod frame;
pub mod hpack;
pub mod mux;
pub mod settings;
pub mod stream;
mod wire;

// The serving types (`Body`/`Handler`/`Request`/`Response`) live at the crate root now
// (shared with the h1 codec); the h2 driver's `http` module re-exports them plus its
// own request-decode helper.
pub mod http;

pub use conn::serve_connection;
pub use error::{ErrorCode, H2Error};
pub use frame::{FrameHeader, FrameType};
pub use mux::serve_connection_mux;
pub use settings::Settings;
pub use stream::StreamState;
// Re-export the shared serving types so `h2` is a self-contained facade (the h2 driver's
// public API is `Handler`/`Request`/`Response`/`Body` + the `serve_connection*` fns).
pub use crate::serving::{response, Body, BodyChunk, BodyError, Handler, Request, Response};

/// The HTTP/2 connection preface a client sends first (RFC 7540 §3.5).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
