//! The server-side implementations of the guest `blob-upload` mint seam
//! ([`boatramp_handlers::BlobUploadMinter`], PLAN-blob-s3-ingress §6 / §"Cloud STS scoping").
//!
//! The binding ([`boatramp-handlers/src/bindings/blob_upload.rs`]) has already enforced
//! deny-by-default, the write/multipart right split, the `upload_containers` allowlist, the host-forced
//! project+site, the TTL/max-bytes clamp, and the fail-closed no-resolved-site check, so every minter
//! here receives a fully pre-confined [`MintScope`](boatramp_handlers::MintScope) and CANNOT widen the
//! scope — it can only *shape* the returned credential for its backing store. This is the security
//! invariant the whole design rests on: a cloud minter derives its policy resource-scope + action-scope
//! from the `MintScope`'s host-stamped `(project, site, container, target)`, never from anything the
//! guest chose.
//!
//! # The minters
//!
//! - [`local`] ([`ServerBlobUploadMinter`]) — **M3**: the local S3 face. Mints a fleet-signed
//!   `KIND_S3_SESSION` token + an HKDF-derived `secret_access_key`; the face verifies SigV4 + the scope
//!   itself, so every constraint is HARD-enforced (advisory is empty).
//! - [`aws`] ([`aws::AwsBlobUploadMinter`]) — **M4**: brokers a native scoped AWS credential. Default
//!   `AssumeRole` + a **session policy** resource-scoped to the exact `hblob/…` prefix and action-scoped
//!   to `s3:PutObject` + the multipart quartet only (`GetFederationToken` for IAM-user deployments); a
//!   single-key/PUT-only credential returns a per-object **presigned PUT** instead. The client talks to
//!   real S3; bytes never transit the node.
//! - [`gcs`] ([`gcs::GcsBlobUploadMinter`]) — **M4**: a per-object **V4 signed PUT URL** (single key), or
//!   a **prefix** credential via a hand-rolled **STS Credential-Access-Boundary** token-exchange
//!   (`sts.googleapis.com/v1/token`) downscoped to the exact `hblob/…` object-prefix.
//! - [`azure`] ([`azure::AzureBlobUploadMinter`]) — **M4**: a **user-delegation SAS** (AAD) scoped to a
//!   single blob or the whole container. Azure SAS cannot bind an arbitrary sub-prefix in the general
//!   case, so a prefix credential is reflected honestly (see [`cloud`] enforced/advisory).
//!
//! # enforced vs advisory (the security crux — folded "Cloud STS scoping", M3-review M4 caveat)
//!
//! The `enforced`/`advisory` split on [`TempCredentials`](boatramp_handlers::TempCredentials) is a
//! TRUST ANCHOR. A minter MUST label a constraint it CANNOT actually cap in-policy as **`advisory`**,
//! never `enforced`. The local face enforces everything. A cloud session policy / SAS / signed URL can
//! bind the *prefix* and the *actions*, but generally CANNOT cap object *size* or *content-type* — so on
//! cloud those are advisory unless content-addressing makes them enforceable. Content-addressing
//! (`require_sha256`) is the mandatory cross-cloud strong enforcement (the store's checksum condition +
//! the key==sha256 identity), so it is always labelled `enforced`. See [`cloud::constraint_contract`].

// The shared cloud helpers (prefix scoping + the enforced/advisory contract) are only referenced by
// the cloud minters; compile them only when at least one cloud minter is enabled.
#[cfg(any(
    feature = "blob-upload-aws",
    feature = "blob-upload-gcs",
    feature = "blob-upload-azure"
))]
pub mod cloud;
pub mod local;
#[cfg(any(
    feature = "blob-upload-aws",
    feature = "blob-upload-gcs",
    feature = "blob-upload-azure"
))]
pub mod wiring;

#[cfg(feature = "blob-upload-aws")]
pub mod aws;
#[cfg(feature = "blob-upload-azure")]
pub mod azure;
#[cfg(feature = "blob-upload-gcs")]
pub mod gcs;

// The M3 local-face minter surface is re-exported at the module root so the historical paths
// (`crate::blob_upload_minter::ServerBlobUploadMinter` / `::BlobUploadFaceConfig` / `::mint_config`)
// keep resolving unchanged — the M4 split is additive.
pub use local::{BlobUploadFaceConfig, ServerBlobUploadMinter, mint_config};
