//! S3-compatible external blob ingress (PLAN-blob-s3-ingress).
//!
//! **M1 — the SDK-independent security core.** This module owns the pieces that are pure and
//! unit-testable, with no live listener, no cloud SDKs, and no `Arc<dyn Storage>` wiring:
//!
//! - [`credential`] — the temporary-credential model: the HKDF-derived `secret_access_key` from a
//!   **dedicated** ingress root (hard domain separation from the KEK + COSE signing key), rotation
//!   with an overlap window, and the fail-closed multi-node startup guard. (The `session_token` COSE
//!   type — `KIND_S3_SESSION` — lives in `boatramp_core::cose`, co-located with the other token
//!   kinds.)
//! - [`sigv4`] — the AWS Signature Version 4 engine: canonical-request → string-to-sign → signature,
//!   both signing and constant-time verification, covering header-auth, presigned-query-auth,
//!   `UNSIGNED-PAYLOAD`, real-hash payloads, and `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked)
//!   with a per-chunk signature chain verified while streaming (never buffering the body).
//!
//! The local S3 face (M2), the mint surfaces (M3), and cloud brokering (M4) build on top of these.

pub mod credential;
pub mod sigv4;
