//! The HTTP/2 codec — a minimal, **h2spec-conformance-gated** server with a kernel
//! zero-copy response-body fast-path (`splice()`/kTLS).
//!
//! # Why this exists
//!
//! Off-the-shelf Rust HTTP/2 (`h2` via `hyper`) copies the response body through
//! userspace to frame + encrypt it. For a large-body reverse proxy that is the
//! throughput ceiling. This codec owns the framing so the body can be moved
//! **kernel-to-kernel** — spliced from the upstream socket straight into a kTLS client
//! socket, where the kernel encrypts on TX — with only the 9-byte DATA frame headers
//! touching userspace. Its concurrent multiplexed driver ([`serve_connection_mux`])
//! matches or beats Envoy on `tls-proxy-h2-100k` (see `../README.md`).
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

// First-party kTLS handoff (Linux) — replaces the `ktls` crate, which cannot build on
// musl. Only reachable through `serve_connection_ktls`, so it is Linux-gated with it.
#[cfg(target_os = "linux")]
mod ktls;

// The serving types (`Body`/`Handler`/`Request`/`Response`) live at the crate root now
// (shared with the h1 codec); the h2 driver's `http` module re-exports them plus its
// own request-decode helper.
pub mod http;

pub use conn::serve_connection;
#[cfg(target_os = "linux")]
pub use conn::{serve_connection_ktls, serve_connection_tcp};
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
