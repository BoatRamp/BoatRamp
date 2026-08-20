//! `boatramp-h2` — a minimal, conformance-gated HTTP/2 **server** with a kernel
//! zero-copy response-body fast-path (`splice()`/kTLS).
//!
//! # Why this exists
//!
//! Off-the-shelf Rust HTTP/2 (`h2` via `hyper`) copies the response body through
//! userspace to frame + encrypt it. For a large-body reverse proxy that is the
//! throughput ceiling. This crate owns the framing so the body can be moved
//! **kernel-to-kernel** — spliced from the upstream socket straight into a kTLS
//! client socket, where the kernel encrypts on TX — with only the 9-byte DATA
//! frame headers touching userspace. That is the one thing `h2` structurally
//! cannot do, and the only lever measured to bring BoatRamp to Envoy parity on the
//! `tls-proxy-h2-100k` cell.
//!
//! # Conformance is a hard gate, not an afterthought
//!
//! A hand-rolled HTTP/2 is a bug farm if you only build the happy path (a
//! benchmark-shaped prototype passed just 60 of h2spec's 145 cases). So this crate
//! is built **red→green against h2spec** (RFC 7540 + RFC 7541) plus a differential
//! oracle (identical requests through this server and `hyper`/`h2` must produce
//! byte-identical responses) plus fuzzing of the frame + HPACK parsers. Anything
//! the fast-path does not implement degrades to a graceful `GOAWAY` — never to
//! wrong behavior (h2 has no clean mid-connection fallback the way HTTP/1 does).
//!
//! # Status
//!
//! Foundation only: the frame codec, error taxonomy, and SETTINGS validation are
//! implemented and unit-tested. The connection driver, stream state machine, HPACK
//! integration, server API, and the splice body seam are the next milestones — see
//! `README.md`.

pub mod conn;
pub mod error;
pub mod frame;
pub mod hpack;
pub mod http;
pub mod settings;
pub mod stream;

pub use conn::serve_connection;
#[cfg(target_os = "linux")]
pub use conn::serve_connection_tcp;
pub use error::{ErrorCode, H2Error};
pub use frame::{FrameHeader, FrameType};
pub use http::{Body, Handler, Request, Response};
pub use settings::Settings;
pub use stream::StreamState;

/// The HTTP/2 connection preface a client sends first (RFC 7540 §3.5).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
