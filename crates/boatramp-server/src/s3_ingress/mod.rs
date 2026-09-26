//! S3-compatible external blob ingress (PLAN-blob-s3-ingress).
//!
//! **M1 — the SDK-independent security core.** These modules are pure and unit-testable, with no
//! live listener, no cloud SDKs, and no `Arc<dyn Storage>` wiring:
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
//! **M2 — the local S3 face.** These modules build the dedicated S3-compatible listener over
//! `Arc<dyn Storage>`, so an object uploaded via S3 lands at
//! `hblob/{project-qualified-site}/{container}/{key}` and the existing guest `compat::blob` reads it
//! unchanged:
//!
//! - [`keypath`] — the key-composition choke point (percent-decode once → `validate_object_key` →
//!   re-anchor under the host-forced `hblob/…` prefix); staging lives under the reserved
//!   `.boatramp-uploads` namespace.
//! - [`error`] — standards-shaped S3 error XML with a greppable boatramp `<Code>` vocabulary, and the
//!   uniform-403 no-oracle auth refusal (`refuse`).
//! - [`config`] — the face state (`S3IngressState`): trust anchor, ingress secret, storage/KV,
//!   `UploadGuard`, per-container policy (CORS + DoS/size ceilings).
//! - [`auth`] — the fail-closed SigV4 + session-token + scope authorization pipeline (with the
//!   SignedHeaders policy, trailer rejection, and opt-in revocation).
//! - [`multipart`] — fleet-issued, scope-bound `uploadId`s; staging + all-or-nothing assembly + GC.
//! - [`face`] — the request engine tying it together (PutObject + the multipart quartet + HEAD +
//!   OPTIONS/CORS), streaming bodies, content-addressing verification, create-only precondition.
//! - [`listener`] — the dedicated listener wiring (`serve_s3`) + the router + the fail-closed
//!   multi-node startup guard.
//!
//! The mint surfaces (M3) and cloud brokering (M4) build on top of these.

pub mod auth;
pub mod chunked;
pub mod config;
pub mod credential;
pub mod error;
pub mod face;
pub mod gate_mutation;
pub mod keypath;
pub mod listener;
pub mod multipart;
pub mod sigv4;

// The mutation-verified `S3 INGRESS SCOPED+SIGV4 OK` live gate (M5). Compiled only under the gate lane
// feature AND `cfg(test)` (it is a `#[tokio::test]` battery + harness that exists solely to run under
// `cargo test`); the mutation SEAMS it drives live in `gate_mutation` + the product choke points and are
// compiled whenever the feature is on.
#[cfg(all(test, feature = "s3-ingress-gate-mutation"))]
mod gate;

// The in-memory `MapStorage` test double is used by both the `#[cfg(test)]` e2e tests and the gate
// battery; both are `cfg(test)`, so a plain `#[cfg(test)]` suffices.
#[cfg(test)]
pub(crate) mod test_support;
