# PLAN — #505 sealed-store credential sourcing for the S3 blob backend + AWS cloud minter

**Branch:** `sealed-blob-creds` · **Base:** v0.6.0 (`2f5a554`) · **Release:** v0.6.1 (additive, NON-breaking).
Owner-approved (2026-09-27, "build it + make it the default later"). construens Tigris follow-up
(`tigris-blob-storage.md`). Security-sensitive (base cloud credential) → Security-review loop +
mutation-verified gate → release. Bounded/additive (mirrors the existing `ManagedSqlCredentials` KEK
pattern) → no 3-role panel unless a fork surfaces.

## The gap
Today the S3 blob **object backend** (`boatramp-storage` `S3Backend`/`S3Options`, built via
`S3Options::from_env` — `backends.rs:51`) AND the AWS blob-upload **cloud minter**
(`AwsCloudMinter::new(sdk_config, …)`, `blob_upload_minter/aws.rs:84`, wired in
`crates/boatramp/src/serve.rs::wire_cloud_blob_upload` ~811) both take their **base AWS credential from
the ambient env chain** (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`). There is no way to source that base
credential from boatramp's `[secrets]` sealed store. construens' Tigris move ships NOW via fly-env; this
feature adds the sealed-store option and makes it the recommended path.

## Design
- **Config (additive):** a node-level **sealed S3 credential source** consumed by BOTH the S3 blob object
  backend AND the AWS cloud minter (construens has ONE Tigris bucket key → one source, both consumers).
  Shape: `access_key_id: String` (an identifier, not secret — plain config) + `secret_access_key` sourced
  from a **sealed `boatramp:` ref** resolved via the `[secrets]` `KeyEnvelope` (never env/argv/git/logs).
  Put it where the blob-backend + `S3IngressCloud` config live (`boatramp-node/src/config.rs`); the CLI
  `serve` args (`crates/boatramp/src/serve.rs`) thread it. Decide: one shared `[serve].s3_credential`
  block, or a field on each — prefer ONE shared node-level source (both consumers read it) since it's the
  same bucket key.
- **Unseal:** at node/serve startup / backend-build time, unseal the ref via the already-threaded
  `secrets_envelope: Arc<dyn KeyEnvelope>` (mirror `ManagedSqlCredentials` `managed_sql.rs:83`,
  `boatramp_core::envelope::KeyEnvelope`). Hold the unsealed `secret_access_key` in memory only. Requires
  `[secrets]` configured — fail-closed with a clear error if a sealed ref is set but no envelope.
- **Inject (both consumers):**
  - Blob backend: `S3Options` gains an optional explicit-credential (`Option<(access_key_id,
    secret_access_key)>` or a provider); `S3Backend::from_options` sets
    `.credentials_provider(SharedCredentialsProvider::new(aws_credential_types::Credentials::new(id,
    secret, None, None, "boatramp-sealed")))` when present, else the ambient loader (unchanged).
  - Cloud minter: build the `aws_config::SdkConfig` passed to `AwsCloudMinter::new` with the same explicit
    provider when the sealed source is set; else ambient (unchanged).
- **Backward compat:** sealed source ABSENT ⇒ the ambient AWS env chain (current behavior). NON-breaking →
  v0.6.1 patch. (The SlateDB R2/S3 KV store `SlateKvS3` also uses the env chain — OUT OF SCOPE here unless
  trivial to include the same source; note it, don't force it.)
- **Guest exposure:** unchanged — the guest never sees the base key; the minter still returns only a
  scoped presigned URL / STS cred. The `allow_env_secret_refs` posture governs whether a `boatramp:` ref
  may originate from env (respect it).

## Security invariants (mutation-verified gate, marker e.g. `S3 SEALED-CRED SOURCING OK`)
1. When the sealed source is configured, the built S3 backend + the minter use the **sealed** credential,
   NOT the env chain (assert the injected provider's key id == the configured one, not an env value).
2. The `secret_access_key` is unsealed via the `KeyEnvelope` — a sealed ref set with NO `[secrets]`
   envelope FAILS CLOSED (startup error, no silent env fallback that would mask a misconfig).
3. The secret NEVER appears in `Debug`/logs/serialized config (grep + a redaction test; the config field
   holding it is not `Debug`-printed in clear — mirror `S3IngressSecret`/`Secret` redaction).
4. Absent source ⇒ ambient env chain (non-breaking) — the existing behavior still works.
Mutation: bypass the envelope-unseal (or leak the secret in Debug) ⇒ gate FAILS. Wire into ci.yml mirroring
the existing gate conventions.

## Release mechanics
Additive → v0.6.1 (bump all 17 pins 0.6.0→0.6.1). Full local `--all-features --all-targets` musl clippy +
fmt + typos before tag. No shim (no guest WIT change). construens: once shipped, migrate the Tigris key
from fly-env → the sealed `boatramp:` store with no data movement; make it the recommended path in the
tigris doc.

## Constraints for the build
- Build + test only; no version tag/push/release (I drive the release). DO the version bump as part of the
  work? — NO, bump at release time (v0.6.1) after Security review, to keep the branch reviewable at 0.6.0.
  (Actually: bump is fine to include; but the release/tag is mine.)
- Reuse `KeyEnvelope`/`ManagedSqlCredentials` patterns; mirror `Secret` redaction. Edition 2024 let-chains;
  `-D warnings`; clippy/fmt/typos clean on touched crates. `Co-Authored-By: Claude Opus 4.8 (1M context)
  <noreply@anthropic.com>` trailer (`PRE_COMMIT_ALLOW_NO_CONFIG=1` if needed).
