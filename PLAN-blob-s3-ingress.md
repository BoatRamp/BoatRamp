# PLAN — S3-compatible external ingress into a blob container (STS + SigV4)

**Branch:** `blob-s3-ingress` · **Base:** v0.5.6 (`331aff8`) · **Construens request:** `boatramp-blob-external-ingress-request.md`
**Status:** APPROVED — 3-role panel PASS-WITH-CONDITIONS (all three); owner approved 2026-09-25. See §APPROVAL (rev 2) at the bottom, which supersedes the sections above where they conflict.

## 1. Goal (the shaped primitive)

A **general platform primitive**: let a client *outside* the wasm sandbox upload large binary objects
*into* a project's blob container, authenticated, resumable, at scale — such that the wasm guest then
reads the object by key via the **existing** `compat::blob` (`has`/`get`) with **zero guest change**.

The client speaks **one protocol — S3** — everywhere. It configures any S3 SDK (opendal, aws-sdk-*,
boto3, rclone, minio-js) or a browser with **short-lived, scoped temporary credentials** and uploads
directly, using native S3 multipart for resume. Two realizations, chosen per backend, but identical
client code:

- **Cloud-backed container** (S3/GCS/Azure): boatramp **brokers native scoped temp credentials** (S3
  STS `GetFederationToken`/AssumeRole session policy; GCS downscoped/CAB token; Azure user-delegation
  SAS). The client talks to the **real store**; **bytes never transit the boatramp node**.
- **Local-backed container** (fs, in-memory): boatramp exposes its **own S3-compatible endpoint** over
  `Arc<dyn Storage>`, **issues its own STS-style temp credentials, and verifies SigV4 itself**. Bytes
  transit the node (unavoidable for local disk), but the wire protocol is standard S3.

The two use cases the request names are the same primitive with different *scope shape*:
- **Browser UGC** — a guest handler, under the end-user's session, mints a credential scoped to **one
  object key** (`hblob/<site>/<ctr>/avatars/<user>/<uuid>`), `image/*`, size-capped, TTL in minutes.
- **Bulk agent** — the operator/app mints a credential scoped to a **prefix** (`hblob/<site>/<ctr>/*`),
  longer TTL; a premises agent writes thousands of keys with the normal SDK + native multipart.

Both decisions (full SigV4 + STS, day one, local **and** cloud) are **owner-directed**.

## 2. What already exists (reuse) vs net-new

Reuse: COSE/fleet `Signer` + `[secrets]` KEK envelope (credential-signing key material); `Arc<dyn
Storage>` streaming backends incl. **native SDKs that already presign/scope** — `aws-sdk-s3`
(`put_object().presigned()`, multipart `CompletedMultipartUpload`), `google-cloud-storage` (V4 signed
URL + resumable), `azure_storage_blobs` (SAS + block blobs); `UploadGuard` (size/concurrency);
`validate_resource_name` (v0.5.0 path screening); `blob_provision.rs` blob-change notifications ("upload
happened"); authz `Resource`/`Right` model.

Net-new: (a) an **STS credential issuer** (local: own creds; cloud: broker native); (b) a **SigV4
verifier + S3 REST subset server** for local backends; (c) the **guest `compat` mint binding** + the
**operator CLI**; (d) **multipart staging + GC** for local; (e) policy knobs (per-container ceiling,
cred-TTL clamp, CORS).

## 3. Auth model — stateless STS + SigV4

**Temporary credential** = `{ access_key_id, secret_access_key, session_token, expiry }`.

**Stateless issuance (local path)** — no server-side credential store, survives restart, cluster-uniform:
- `access_key_id` = random public id (e.g. `BRUP` + base32(rand)).
- `session_token` = a **fleet-signed** (COSE, existing `Signer`) blob encoding the full scope:
  `{ project, site, container, key | prefix, perms (write/multipart only by default), constraints
  (max_bytes, content_type, require_sha256), iat, exp, cti }`. Client-opaque; boatramp verifies it.
- `secret_access_key` = `HMAC(cluster_kek_derived_key, access_key_id)` — derivable by any node, never
  stored, never leaves the host. The client receives it once at mint.

**SigV4 verification (local S3 face)** on each request:
1. Parse `Authorization` (or presigned query) → `access_key_id`, signed headers, client signature.
2. Recompute `secret_access_key = HMAC(k, access_key_id)`; recompute the SigV4 canonical-request →
   string-to-sign → signature; **constant-time compare**; mismatch → `403`.
3. Verify `session_token` signature + `exp > now` (fail-closed on expired/malformed).
4. Authorize the concrete request (bucket=container, key, method) against the token's scope +
   constraints; any escape → `403`.

Support the payload-signing modes real SDKs send: `x-amz-content-sha256` = a real hash,
`UNSIGNED-PAYLOAD`, and `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked) — the last is required for
streamed PUTs and is the trickiest verifier surface.

**Cloud path**: boatramp does **not** verify SigV4 (the cloud store does). It only **brokers** a scoped
native temp credential via the cloud's own STS/CAB/delegation, using boatramp's base store credential.
Per-cloud operator setup (IAM perms for `GetFederationToken`, GCS CAB, Azure delegation key) is required
and documented.

## 4. The S3 REST subset (local server)

Path-style addressing (`/{bucket}/{key}`), bucket = container (project/site come from the credential
scope, never the URL). Write-only ingress — **no external GET/LIST** (read stays guest-only; this is not
a data-exfil surface).
- `PUT /{bucket}/{key}` — PutObject (single-shot).
- `POST /{bucket}/{key}?uploads` — CreateMultipartUpload → `UploadId`.
- `PUT /{bucket}/{key}?partNumber=N&uploadId=U` — UploadPart → `ETag`.
- `POST /{bucket}/{key}?uploadId=U` — CompleteMultipartUpload (XML part list) → assemble → write final
  object at `hblob/{site}/{ctr}/{key}`.
- `DELETE /{bucket}/{key}?uploadId=U` — AbortMultipartUpload → drop staging.
- `HEAD /{bucket}/{key}` — HeadObject (probe; scoped like PUT). Optional if a target SDK needs it.

Mount at a distinct prefix/listener that cannot collide with `serve_by_host` fallback or `/api`
(candidate: dedicated path root `/_s3/` or an optional dedicated listener port). Its own auth (SigV4),
**outside** `require_auth`.

**Multipart staging (local):** parts written to `hblob/{site}/{ctr}/.boatramp-uploads/{uploadId}/part-N`
(the reserved `.boatramp*` namespace `validate_object_key` rejects for a client key, so a client key can
never collide with staging — M1-review MEDIUM-3); Complete concatenates in part order → writes the final
key → deletes staging; Abort/expiry → GC deletes staging. UploadId isolation prevents cross-upload
collision.

## 5. Storage + key mapping (guest read-through)

Every object lands at exactly `hblob/{project-qualified-site}/{container}/{key}` — the **same prefix the
guest `compat::blob` binding reads** — so `has(key)`/`get(key)` sees it immediately, no guest change. The
`{key}` is screened (reuse `validate_resource_name` semantics: no `..`, no `/`-escape, no ctrl/abs) so it
cannot escape the scoped prefix. **Content-addressed mode:** key MUST equal `sha256(bytes)`; verified
as-streamed on local (reuse `put_blob`'s hash-verify); on cloud enforced via the store's checksum
condition. Idempotent, dedupes, a retried/interrupted upload converges.

## 6. Mint surfaces

- **Guest `compat` binding** (new, e.g. `boatramp:handlers/blob-upload`):
  `mint(container, key|prefix, perms, {max_bytes, content_type, require_sha256}, ttl) -> Credentials`.
  Project/site **host-forced** from the invocation scope (never guest-supplied); container/key/ttl/
  constraints guest-supplied; ttl **clamped** to operator ceiling. **Deny-by-default** (needs a granted
  `blob-upload` capability; empty ⇒ refuse). Host holds all store creds; guest only ever receives the
  *scoped* temp credential. Symmetric to the existing `capability.rs` minter.
- **Operator CLI**: `boatramp blob upload-credentials --container C (--key K | --prefix P) --perms …
  --ttl … [--content-type … --max-bytes … --sha256]` → prints creds + endpoint + a ready SDK snippet.
  Gated by an operator token holding the new blob-upload right.

## 7. Authz

New scoped resource/action for the **mint** operation (the ingress itself is authorized by the temp
credential, not the control-plane bearer). Candidate: extend `Resource::Blobs` from global to a
**container-scoped** target for a new `Action` (e.g. `Blobs·Write` scoped `"<project>/<site>/<container>"`,
or a dedicated `Resource::BlobUpload`). Deny-by-default; the operator route gated **above** any broad
`/api/blobs/` Deploy arm (no publisher escalation), mirroring the v0.5.2 repair-route placement.

## 8. Policy knobs (all general, config)

per-container **size ceiling**; credential **TTL ceiling** (operator clamp); **staging-GC TTL** (local
incomplete-multipart); **max concurrent uploads** (local, reuse `UploadGuard`); **CORS allowed origins**
(local S3 face for browsers; cloud = the bucket's own CORS, which boatramp documents/optionally helps set
via provisioning); **allowed perms** (write/multipart only unless explicitly granted read).

## 9. GC

Local: sweep `…/.boatramp-uploads/{uploadId}/` older than the staging TTL; Complete/Abort delete immediately.
Cloud: rely on the store's incomplete-multipart lifecycle rule (operator-set, or boatramp sets it via
`blob_provision`). Committed-but-app-unreferenced objects are **app-owned** — the guest is the reference
authority; the platform does not (cannot) infer "unreferenced" for committed objects.

## 10. Security invariants (panel focus)

1. A temp credential authorizes ONLY its host-stamped scope (project, site, container, key|prefix, perms);
   cross-container/cross-project is **structurally impossible** (scope is in the signed session-token,
   never client-supplied / never in the URL authority).
2. SigV4 verification is correct + **fail-closed** + **constant-time** on the secret compare; expired or
   malformed cred/token/signature ⇒ `403`, no partial write.
3. `secret_access_key = HMAC(cluster key, access_key_id)`; the cluster key never leaves the host; a leaked
   temp cred is bounded to its scope + short TTL.
4. Guest mint is **deny-by-default**, host-scoped to the guest's own site; a guest can never mint a
   credential broader than its own authority.
5. The external S3 face is **write/multipart-only** by default — no external read/list/delete of arbitrary
   objects (ingress, not exfil). Read stays guest-only.
6. Key screening blocks prefix escape (`..`, `/`-escape, absolute, ctrl) — object cannot land outside the
   scoped prefix.
7. Constraints (size/content-type/sha256) enforced fail-closed at the local face; the cloud enforcement
   **asymmetry** (session-policy can't cap object size on all clouds) is documented; content-addressing is
   the strong cross-cloud enforcement.
8. Multipart parts isolated per `uploadId`, GC'd on abort/expiry; a dead client can neither leak nor
   collide; Complete is all-or-nothing (no partial object at the final key).
9. Content-addressed: `key != sha256(bytes)` ⇒ reject; no committed partial.

## 11. CI-hard, mutation-verified live gate

Marker `S3 INGRESS SCOPED+SIGV4 OK`. On a real local backend, drive a real SigV4 client:
- mint a cred scoped to container A / key `k` → PUT `k` succeeds → **guest `compat::blob.get("k")` reads
  the exact bytes back** (proves guest read-through at `hblob/`).
- same cred → PUT `../../escape` or container B ⇒ `403` (scope escape blocked).
- tampered signature / expired cred ⇒ `403`.
- multipart Create/UploadPart×2/Complete ⇒ object assembled + guest-readable; Abort ⇒ staging gone.
- content-addressed: bytes whose sha256 ≠ declared key ⇒ reject, key absent afterward.
- **Mutation-verified:** neuter the scope check ⇒ cross-container PUT succeeds ⇒ gate FAILS; neuter SigV4
  verify ⇒ tampered signature accepted ⇒ gate FAILS.

## 12. Open questions for the panel

- **Endpoint topology**: dedicated path prefix (`/_s3/`) on the existing listener vs a dedicated S3
  listener port. Virtual-host vs path-style addressing (path-style avoids per-bucket DNS).
- **Streaming payload verification**: is supporting `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked)
  required day one (aws-sdk default for unknown-length PUTs), or can we require `UNSIGNED-PAYLOAD` +
  size/hash constraints and reject chunked-signed? (Smaller, safer verifier if we can.)
- **STS realization on cloud**: `GetFederationToken` (no role, session policy — simpler) vs AssumeRole
  (needs a role); GCS CAB; Azure user-delegation SAS — confirm each is scriptable with the base cred we
  already hold, and the operator setup burden is acceptable.
- **Credential state**: stateless HMAC-derived secret (proposed) vs a short-lived KV credential record
  (revocable, but adds state + a replication dependency). Stateless is simpler + restart-safe; do we need
  revocation-before-expiry?
- **Shim**: does the guest mint binding need a `boatramp-uchron-shim` companion rev (WIT surface)? Likely
  yes → byte-faithful WIT + off-by-default feature + pin-by-rev.

---

# APPROVAL (rev 2) — owner-approved, panel-conditioned design

## Approvals
- **3-role panel:** Senior/Backend Architect, UX Architect, Security Engineer — **all PASS-WITH-CONDITIONS**
  (no FAIL). Conditions folded below.
- **Owner decisions (2026-09-25):**
  - **Cloud coverage → "Bump GCS/Azure SDKs first"** so all three clouds get the *strong* scoped-credential
    primitive (no weaker per-cloud fallback).
  - **aws-chunked → "Build the hardened verifier day one"**: the local S3 face supports
    `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (full per-chunk signature-chain verify) in v1, behind a
    differential-fuzz + SigV4-conformance gate.
  - **Sequencing → "All clouds in one big release"** (after seeing the §SDK research): v1 lands strong on
    local + AWS + GCS + Azure at once, accepting the Azure `azure.rs` rewrite + the GCS crate bump + the
    hand-rolled GCS STS.
  - **Engineering call (mine, veto-able) → GCS crate = yoshidan `gcloud-storage` 1.3.0** (edition 2021),
    NOT official `google-cloud-storage` 1.19 — to avoid a workspace-wide Rust 1.91 / edition-2024 migration
    and the `aws-lc-rs`/ring musl-CI crypto clash. Cost contained to the reqwest 0.12/0.13 split + a single
    workspace rustls provider. GCS prefix credential = hand-rolled STS token-exchange (no Rust crate exists).

## Owner-directed scope (maximal)
Full SigV4 + STS, day one, **local and all three clouds**, both single-shot and multipart/resumable,
browser-UGC and bulk-agent. One S3 protocol to the client everywhere.

## Folded conditions (binding on implementation)

### Credential model (Security CRITICAL-1 / Architect BLOCKER-2)
- `secret_access_key = HKDF-SHA256(root = dedicated ingress secret, info = b"boatramp-s3-ingress/hmac/v1",
  salt = access_key_id ‖ session_token.cti)`. **Dedicated, independently-rotatable root** — NEVER the
  `[secrets]` KEK and NEVER the COSE signing key (hard domain separation).
- New replicated key material `s3_ingress_secret`, envelope-wrapped, on the same path as the KEK.
  **Fail-closed startup guard**: refuse to enable the local S3 face on a multi-node deployment without an
  explicitly configured, cluster-uniform ingress secret (do NOT silently reuse the auto-generating
  `LocalKek`).
- **Rotation with an overlap window** (mirror `auth rotate-root`): verify against current + previous
  derived key so in-flight credentials survive rotation. Rotation is the coarse revocation lever.
- Session token is COSE_Sign1 (existing fleet `Signer`), new **`KIND_S3_SESSION`** (domain-separated —
  never redeemable as role/capability/context, and vice-versa), **mandatory `exp`**, carries the full
  host-stamped scope `{project, site, container, key|prefix, perms, constraints, cti}`.
- **Opt-in `cti` revocation** on the verify path (reuse `authz/revoked/<cti>`) for long-TTL bulk creds;
  off by default to keep the stateless fast path.

### SigV4 verifier (Security CRITICAL-2 / Architect MEDIUM-2) — full, day one
- Support header-auth, presigned-query-auth, `UNSIGNED-PAYLOAD`, real-hash payloads, **and**
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked, incl. trailing-checksum) — per-chunk signature chain
  verified while streaming (never buffer the whole body).
- Canonicalization built against the **AWS SigV4 test-suite vectors** + **differential-fuzzed** vs a
  reference impl. **Constant-time** signature compare (`aws_lc_rs`, already in-tree). **Bounded clock
  skew** (tight window, cf. `POP_SKEW_SECS`/`POP_WINDOW_SECS`). Fail-closed uniform `403`, no
  which-check-failed oracle (mirror `tenant_secrets::refuse`).
- **Replay posture (explicit):** stateless creds ⇒ a signed request can be replayed within TTL.
  Mitigations, enforced not optional: mandatory content-addressing for any non-single-key/non-create-only
  credential (replayed PUT = idempotent no-op); single-consume `uploadId`; short TTL bounds the window.

### Scope confinement (Security HIGH-2 / Architect HIGH-1)
- **Path-aware object-key normalizer** (NOT the `/`-rejecting `validate_resource_name`): percent-decode
  once; split on `/`; reject empty/`.`/`..`/control/NUL/`*`/leading-`/`/absolute segments; bound length;
  re-anchor under the host-forced `hblob/{project-qualified-site}/{container}/` prefix. Enforced at the
  **S3-face key-composition choke point** so **cloud backends are covered** (the `fs::resolve` traversal
  backstop is fs-only). Container name stays a single segment (validator applies).
- `uploadId` is fleet-issued and **scope-bound** (scope hash embedded, staging keyed under
  `hblob/{site}/{ctr}/.boatramp-uploads/{uploadId}/`); every `UploadPart`/`Complete`/`Abort` **re-verifies
  the request scope matches the upload's origin scope** — never trust the `uploadId` alone.
- **Guest cannot read in-flight parts**: staging lives under the reserved `.boatramp*` segment namespace,
  which `validate_object_key` rejects for a guest/client key — so `get`/`list` can never reach the
  `.boatramp-uploads/` staging prefix.

### Overwrite / write-only (Security HIGH-1)
- External face is **write/multipart-only** (no external GET/LIST/DELETE). Caller-chosen-key (UGC) creds
  default **create-only** (no-overwrite) via an `If-None-Match: *`-style head precondition; overwrite is
  safe only for content-addressed keys (same bytes → same key). Mint constraint carries the create-only
  flag; UGC default = create-only.

### Multipart on local (Architect HIGH-3)
- Full SigV4 + server-side multipart **assembly restricted to `fs`/in-memory** backends (cheap
  concat/rename). An **object-store-backed "local"** brokers the store's **native** multipart instead of
  re-transiting bytes. Complete is **all-or-nothing** (streaming concat of staged parts into `Storage::put`
  at the final key; never a partial object at the final key). Total size capped via `UploadGuard`.

### Cloud STS scoping (Security HIGH-3 / Architect MEDIUM-1/3)
- AWS: **`AssumeRole` + session policy** as default (works from an assumed role; `GetFederationToken`
  only for IAM-user deployments). Add **`aws-sdk-sts` as a direct dep**. Session policy **resource-scoped
  to the exact prefix**, **action-scoped to `PutObject` + the multipart quartet only** (no
  get/list/delete/bucket-level).
- GCS / Azure: on the **bumped SDKs** (per owner decision) — GCS downscoped/CAB token or IAM `signBlob`;
  Azure **user-delegation SAS** (AAD). Exact targets from the background SDK research (see §SDK below).
- Where a cloud can't cap object size in-policy, **content-addressing is the mandatory cross-cloud
  enforcement**; do NOT overclaim size/content-type enforcement on cloud — surface it in the credential's
  `enforced` vs `advisory` contract.

### Guest mint discipline (Security MEDIUM-1 / matches capability.rs + tenant_secrets.rs)
- Binding `boatramp:handlers/blob-upload`. **Deny-by-default** (no binding / zero ceiling ⇒ access-denied).
  **Project AND site host-forced** from the resolved invocation scope — **no project/site parameter in the
  WIT surface**. Guest names only container/key|prefix/perms/constraints/ttl. **Clamp** TTL and `max_bytes`
  to operator ceilings (guest can only narrow). `perms` default write/multipart-only. **Fail closed** on an
  `all`/anon/unscoped invocation with no single resolved site (cf. `NoResolvedTenant`).
- Imports as independent rights **`blob-upload:write` / `blob-upload:multipart`** (bare `blob-upload` is
  NOT a grant; no `blob-upload:*`). Per-handler **`upload_containers: Vec<String>` allowlist** (empty ⇒
  deny-all), mirroring `tenant_secret_names`.

### Mint return shape / DX (UX P1/P2/P7)
- Return a **variant**: `presigned-put(url, method, required-headers, expires_at, expires_in_secs)` for the
  single-key/PUT-only/browser case (no SigV4-in-JS); `temp-credentials(access_key_id, secret,
  session_token, endpoint, region, bucket, force_path_style, expires_at, expires_in_secs, enforced[],
  advisory[])` for prefix/multipart/bulk. **Self-describing** (client feeds it verbatim to its SDK / a
  `fetch()`); explicit **enforced-vs-advisory** constraint contract. Surface the **clamped** TTL.

### Authz / routing (Security MEDIUM-2 / Architect MEDIUM-4)
- New **`Resource::BlobUpload`**, target `"<project>/<site>/<container>"`, added to `Resource::ALL`
  (so `admin` expands to it). **Not** granted to default `publisher`/`deployer`/`project_*` roles. The
  operator mint route gets its **own prefix, gated ABOVE** any `/api/blobs/` + `/api/sql/` catch-all
  (repair/migrate-placement precedent). The ingress itself is authorized by the temp credential, not the
  control-plane bearer.

### Endpoint topology (Architect HIGH-4 / UX)
- **Dedicated S3 listener/port** for the local face (clean auth boundary; no `serve_by_host`/`require_auth`
  entanglement; independent CORS). **Path-style** addressing (bucket = container in the path; credential
  carries `force_path_style: true`). Prove-by-test it never reaches the control-plane router or
  `serve_by_host`.

### CORS (UX P3)
- **First-class per-container `cors_allowed_origins`** knob; the local S3 face answers `OPTIONS` preflight
  and echoes only allowed origins (never `*` on a credentialed write endpoint, never reflect arbitrary
  `Origin`). Operator verb `boatramp blob cors --container C --origin …` sets bucket CORS on cloud (via the
  `blob_provision` path); the CLI/mint warns when a cloud target lacks a CORS rule for the intended origin.

### CLI / errors / observability (UX P4/P5/P6)
- CLI verb **`boatramp blob mint-upload`** (NOT `upload-credentials`; the existing `blob put` is the
  *control-plane artifact* namespace — distinct). `--emit {env|aws|rclone|json}` (default human table +
  `env` block). Local face returns **standards-shaped S3 error XML** with a **stable, greppable boatramp
  `<Code>` vocabulary** (`BoatrampScopeEscape`, `BoatrampCredExpired`, `BoatrampSha256Mismatch`,
  `BoatrampSizeExceeded`, …); document that cloud errors are the store's native codes. Rejected
  mint/upload attempts recorded + surfaced via the existing stats/notification surface.

### DoS caps (Security MEDIUM-3)
- Cap parts-per-upload, concurrent open uploads (per credential/site), total staged bytes; **aggressive,
  enforced staging-GC TTL**; reuse `UploadGuard` (concurrency + Content-Length early-reject). Cloud:
  incomplete-MPU lifecycle rule (operator-set or via `blob_provision`).

### Shim (Architect LOW-2)
- Guest mint binding ⇒ companion `boatramp-uchron-shim` rev: byte-faithful WIT, off-by-default feature,
  pin-by-rev.

## Strengthened, mutation-verified gate — `S3 INGRESS SCOPED+SIGV4 OK`
Each check must FAIL the gate when its mechanism is neutered (anti-hollow-gate), run on **both** an
fs-local backend **and** a cloud/S3-emulator backend where relevant:
1. Scope confinement — cred for container A cannot PUT to B / sibling site / `..`/`%2e%2e`-escaped key
   (neuter key-screen or scope check ⇒ cross-container PUT succeeds ⇒ FAIL). Runs on cloud-emulator too.
2. SigV4 verify — flipped-bit sig / swapped SignedHeaders / modified host / expired token ⇒ 403; assert an
   AWS SigV4 test-vector (neuter verify ⇒ tampered sig accepted ⇒ FAIL). Include an aws-chunked vector.
3. Secret key separation — secret = HKDF(dedicated root, domain, akid‖cti); mutating the domain `info` or
   feeding the KEK/COSE key ⇒ different secret (proves separation is real).
4. Replay inert — replayed content-addressed PUT is a no-op; different bytes ⇒ key/hash mismatch ⇒ reject
   (neuter sha256 verify ⇒ mismatched bytes accepted ⇒ FAIL).
5. Guest over-mint — guest cannot mint outside host-forced (project, site); ungranted ⇒ access-denied; TTL
   + max_bytes clamped (assert clamped values) (neuter host-forcing ⇒ cross-site mint ⇒ FAIL).
6. Route authz — `publisher`/`project_publisher` cannot reach the mint route (neuter placement ⇒ publisher
   mints ⇒ FAIL).
7. Multipart isolation + all-or-nothing — Create/UploadPart×2/Complete ⇒ guest-readable object at
   `hblob/…`; A's uploadId can't be driven by B's cred; Abort/expiry removes staging; no partial at final.
8. Overwrite — create-only (UGC) cred cannot overwrite an existing key (neuter precondition ⇒ overwrite
   succeeds ⇒ FAIL).
9. Cloud STS policy tightness — captured brokered session policy is prefix-resource-scoped + put/multipart
   action-scoped only (neuter to bucket-wide/`*` ⇒ FAIL).
Plus **guest read-through**: after each successful upload, a real `compat::blob.get(key)` returns the exact
bytes.

## Milestones (ONE release — owner: "all clouds in one big release"; internal build order)
- **M1 — SDK-independent security core** (in progress): `validate_object_key` ✓; then `Resource::BlobUpload`
  authz; the credential model (HKDF-derived secret from a dedicated ingress key + `KIND_S3_SESSION` COSE
  token + rotation + fail-closed multi-node guard); the SigV4 engine (canonical-request/string-to-sign/
  sign+verify incl. aws-chunked) built against AWS test vectors + differential fuzz. Pure, unit-testable.
- **M2 — local S3 face** ✓ (done): dedicated listener (`s3_ingress::listener::serve_s3`, own SigV4 auth
  surface, no `/api`/`serve_by_host`), path-style, PutObject + multipart quartet (fs/in-memory assembly)
  + scope-bound `uploadId` + staging/GC under `.boatramp-uploads`, per-container CORS (never `*`),
  greppable S3 error `<Code>` vocabulary, `UploadGuard` + DoS caps. Wired to `Arc<dyn Storage>` at
  `hblob/{project-qualified-site}/{container}/{key}` (guest read-through). Folds the M1-review fixes:
  MEDIUM-2 (trailer fail-closed), MEDIUM-3 (`.boatramp-uploads` staging namespace), LOW-1 (required
  SignedHeaders), INFO-3 (uniform-403 no-oracle). Opt-in `cti` revocation. Config: `[serve]
  .s3_ingress_addr` + `.s3_ingress_secret_file`, spawned single-node + cluster (fail-closed multi-node
  secret guard). NOT yet: the guest `blob-upload` mint binding + CLI (M3).
- **M3 — mint surfaces**: guest `blob-upload` binding (deny-by-default, host-forced project+site, clamps,
  `upload_containers` allowlist) + `boatramp blob mint-upload` CLI (`--emit env|aws|rclone|json`); the
  presigned-put | temp-credentials variant.
- **M4 — cloud brokering**: AWS `AssumeRole`+session-policy (add `aws-sdk-sts` direct); GCS bump to yoshidan
  `gcloud-storage` 1.3.0 + per-object signed URL via IAM `signBlob` + hand-rolled STS prefix downscoping;
  Azure bump to `azure_storage_blob`/`azure_storage_sas`/`azure_identity` 1.x (**`azure.rs` rewrite**) +
  user-delegation SAS. Resolve reqwest 0.12/0.13 + one workspace rustls provider.
- **M5 — gate + shim + docs**: the mutation-verified `S3 INGRESS SCOPED+SIGV4 OK` live gate (all 9
  invariants, run on fs + a cloud/S3-emulator); companion `boatramp-uchron-shim` rev; CHANGELOG + the 3
  canonical recipes. Then version-bump + release.
Checkpoint with the owner at M1→M2 and before the cloud bumps (M4) given the dependency/MSRV churn.

## SDK bump targets (§SDK) — research complete (2026-09-25)

**The "bump SDKs → strong prefix credential on all clouds" premise only partly holds:**

- **AWS — fully native, no bump.** `AssumeRole`+session-policy (prefix-scoped) + presigned PUT (per-object)
  via `aws-sdk-s3`/`aws-sdk-sts` (sts is transitive today → add as a **direct** dep). Strong on both shapes.
- **Azure — strong SAS exists, but forces a backend rewrite.** User-delegation SAS is clean on the **new GA
  SDK**: `azure_storage_blob` 1.1.0 (`BlobServiceClient::get_user_delegation_key`) + `azure_storage_sas`
  1.0.0 (`SasBuilder`) + `azure_identity` 1.0.0 (AAD `TokenCredential`). But this is a **different SDK
  generation** from the pinned `azure_storage_blobs` 0.21 → bumping **forces a rewrite of `azure.rs`**
  (client model change; block-blob multipart parity via `stage_block`/`commit_block_list` is intact). MSRV
  1.88 (mild). SAS scopes to a **single blob or a whole container** — no arbitrary sub-prefix.
- **GCS — the strong prefix primitive is NOT in any stable Rust crate.** Credential Access Boundary /
  downscoped STS tokens exist only in Python/Java/Go/Node; in Rust they must be **hand-rolled against
  `sts.googleapis.com/v1/token`**. The clean *native* option is a **per-object V4 PUT signed URL via IAM
  `signBlob`** (keyless, Workload-Identity-friendly; needs `roles/iam.serviceAccountTokenCreator`) — but
  that needs an SDK bump too: **yoshidan `gcloud-storage` 1.3.0** (`SignBy::SignBytes`, edition 2021, but
  pulls **reqwest 0.13** → a duplicate reqwest/hyper stack vs the workspace's 0.12) **OR** official
  **`google-cloud-storage` 1.19.0** (`SignedUrlBuilder::sign_with`, but requires **Rust 1.91 + edition
  2024** → a workspace MSRV/edition jump, signed-url behind an *unstable* feature, and defaults to
  `aws-lc-rs` rustls → a **CryptoProvider clash risk on the musl CI** if the workspace standardizes on ring).

**Net:** prefix-scoped *native* bulk credential = **AWS only**. Azure = per-blob/per-container SAS (+ rewrite).
GCS prefix = hand-rolled STS (custom code we own) or per-object signed URLs (+ crate bump w/ MSRV/dep ripple).
**Per-object (UGC/content-addressed) works on all three + local.**

Recommended crate pins IF we proceed per-cloud: Azure → `azure_storage_blob`/`azure_storage_sas`/
`azure_identity` 1.x (accept the `azure.rs` rewrite); GCS → **yoshidan `gcloud-storage` 1.3.0** (avoids the
1.91/edition-2024 jump; must resolve the reqwest 0.12/0.13 split + pick one rustls provider workspace-wide).
