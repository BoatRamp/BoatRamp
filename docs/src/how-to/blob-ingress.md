# Ingest large uploads over S3 (blob-ingress)

A wasm guest reads blob objects by key through the `wasi:blobstore` binding, but
it can't accept a multi-gigabyte upload streamed through the sandbox — and a
browser or a bulk agent shouldn't have to POST bytes through your handler at all.
**Blob-ingress** lets a client *outside* the sandbox upload binary objects
**directly into a project's blob container**, authenticated, resumable, at scale,
speaking **one protocol — S3 — everywhere**. The guest then reads the object by
key through the unchanged `wasi:blobstore` (`has`/`get`) with **zero guest
change**: every object lands at `hblob/{project-qualified-site}/{container}/{key}`,
the exact prefix the guest already reads.

The client configures any S3 SDK (`aws-sdk-*`, `boto3`, `rclone`, `minio-js`,
`opendal`) or a browser `fetch()` with **short-lived, scoped temporary
credentials** and uploads directly. There are two realizations, chosen per
backend, but **identical client code**:

- **Local-backed container** (`fs`, in-memory): boatramp exposes its **own
  S3-compatible endpoint** over the storage backend, **issues its own STS-style
  temp credentials, and verifies SigV4 itself**. Bytes transit the node
  (unavoidable for local disk), but the wire protocol is standard S3.
- **Cloud-backed container** (S3 / GCS / Azure): boatramp **brokers a native
  scoped temporary credential** (AWS STS session policy, GCS signed URL / STS
  downscoping, Azure user-delegation SAS). The client talks to the **real
  store**; **bytes never transit the node**.

Two mint surfaces produce those credentials:

- a **guest** capability (`boatramp:handlers/blob-upload`) — a handler or
  function, under the end-user's session, mints a credential scoped to one key
  or a prefix;
- an **operator** CLI (`boatramp blob mint-upload`) — for bulk / out-of-band
  provisioning.

Both are **deny-by-default** and **host-scoped**: the project **and** site are
host-forced, never named by the guest; a credential is structurally confined to
its origin tenant.

> Feature-gated. The local S3 face + both mint surfaces are behind the
> `blob-upload` cargo feature (on in the batteries-included build). Each cloud
> broker is behind `blob-upload-aws` / `blob-upload-gcs` / `blob-upload-azure`
> (or `blob-upload-cloud` for all three), off in the default build.

## Enable the local S3 face

Add an `[serve]` listener for the S3 face — a **dedicated address**, separate
from the control-plane `addr`, with its own SigV4 auth boundary (it never
reaches the control-plane router or `serve_by_host`):

```toml
[serve]
addr = "0.0.0.0:8080"                       # the control plane / site edge
s3_ingress_addr = "0.0.0.0:9000"            # the dedicated S3 face
# A raw 32-byte file — the dedicated HKDF root that derives every credential's
# secret_access_key. MUST be the SAME file on every node in a cluster (the face
# refuses to start on a multi-node deployment without an explicit, uniform one).
s3_ingress_secret_file = "/etc/boatramp/s3-ingress.key"
# The publicly-reachable base URL the client SDK / a browser targets. Absent ⇒
# derived from s3_ingress_addr as http://<addr> (fine for localhost/dev; set the
# real public URL in production, e.g. behind a TLS terminator).
s3_ingress_public_url = "https://uploads.example.com"
# Operator ceilings the mint clamps down to (a guest can only narrow):
s3_ingress_mint_max_ttl_secs = 3600         # cred TTL ceiling (default 1h)
s3_ingress_mint_max_bytes = 104857600       # per-cred max object size (100 MiB)
```

Generate the secret once and copy it to every node:

```console
$ head -c 32 /dev/urandom > /etc/boatramp/s3-ingress.key
$ chmod 600 /etc/boatramp/s3-ingress.key
```

The local face signs under a **fixed** SigV4 region `boatramp` and service `s3`,
uses **path-style** addressing (`/{container}/{key}`), and is **write /
multipart-only** — there is no external GET / LIST / DELETE (it is an ingress
surface, not a data-exfil one; read stays guest-only).

## Grant the guest mint capability

A guest mints only what its component is granted. Two **independent** rights:

- `blob-upload:write` — single-shot `PutObject` credentials;
- `blob-upload:multipart` — the multipart quartet (create / upload-part /
  complete / abort).

Bare `blob-upload` is **not** a grant, and there is no `blob-upload:*`. Grant a
right in the site's handler config, and list the containers the component may
mint for (**empty ⇒ deny-all**):

```ron
// a site's [handlers] handler config
(
    route: "/api/*",
    component: "api.wasm",
    imports: ["blob-upload:write", "blob-upload:multipart"],
    // Per-component container allowlist — least-privilege, mirrors
    // tenant_secret_names. A container not listed here is access-denied.
    upload_containers: ["avatars", "bulk-ingest"],
)
```

A site handler mints for **its own host-routed site**. A **standalone top-level
function** has no single routed site, so it names the site it mints for in its
own config — **host-forced, never guest-supplied** — and the host validates that
site belongs to the function's project before minting:

```ron
// a top-level function config
(
    imports: ["blob-upload:multipart"],
    upload_containers: ["bulk-ingest"],
    // The site this function mints for. The host validates it exists in the
    // function's (host-forced) project; unset, or a site not in the project ⇒
    // fail-closed (no binding is attached, every mint is no-resolved-site).
    blob_upload_site: "app",
)
```

In both cases the project is host-forced from the invocation and the site is
host-forced (routed, or config-declared + project-validated); the guest can
override neither, and the WIT surface has **no project/site parameter**.

## Recipe 1 — browser UGC (presigned PUT, single key, content-type)

The single-key / PUT-only shape returns a **presigned PUT URL** — no SigV4 in the
browser, one `fetch()`. A handler under the user's session mints it:

```rust
// inside a wasm handler (imports "blob-upload:write"). The exact generated names
// come from the `boatramp:handlers/blob-upload` WIT via the guest bindings; the
// shape below is faithful (WIT kebab-case maps to snake_case in Rust).
let creds = mint(&MintRequest {
    container: "avatars".into(),
    // Exactly one object key — the browser-UGC shape. Create-only by default.
    target: UploadTarget { key: Some(format!("users/{user_id}/{uuid}.jpg")), prefix: None },
    perms: vec![UploadPerm::Put],
    constraints: UploadConstraints {
        max_bytes: Some(5 * 1024 * 1024),        // ≤ 5 MiB (clamped to the ceiling)
        content_type: Some("image/*".into()),    // an exact type or a type/* family
        require_sha256: false,
        create_only: true,                        // refuse to overwrite (default for a key)
    },
    ttl_seconds: 300,                             // 5 min (clamped to the ceiling)
})?;
```

The handler returns the presigned form to the browser, which uploads with a
single request:

```js
// creds is the presigned-put variant: { url, method, required_headers, expires_in_secs }
await fetch(creds.url, {
  method: creds.method,                 // "PUT"
  headers: Object.fromEntries(creds.required_headers), // e.g. Content-Type: image/jpeg
  body: file,
});
```

The guest then reads it back by key with the unchanged blobstore binding:
`blobstore.get_container("avatars")?.get_data(&format!("users/{user_id}/{uuid}.jpg"), ..)`.

## Recipe 2 — bulk agent (prefix temp-credentials, multipart)

The prefix / multipart shape returns **STS-style temp credentials** — feed them
verbatim to any S3 SDK. Mint from the operator CLI (or a guest with
`blob-upload:multipart`):

```console
$ boatramp blob mint-upload \
    --site app --container bulk-ingest \
    --prefix "imports/2026-09/" \
    --perms multipart,put \
    --ttl 3600 \
    --emit env
# ── an env block for an S3 SDK ──
export AWS_ACCESS_KEY_ID=BRUP...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
export AWS_ENDPOINT_URL=https://uploads.example.com
export AWS_REGION=boatramp
export AWS_S3_FORCE_PATH_STYLE=true
```

`--emit` selects the output form: `env` (a shell `export` block), `aws` (an
`~/.aws/credentials` profile), `rclone` (an rclone remote block), `json` (the raw
credential), or the default human table + `env` block. A premises agent then
writes thousands of keys with the normal SDK and **native S3 multipart** for
resume:

```console
$ aws s3 cp ./big-archive.tar s3://bulk-ingest/imports/2026-09/archive.tar \
    --endpoint-url "$AWS_ENDPOINT_URL"     # aws-cli does multipart automatically for large files
```

On a **local** container the face assembles multipart parts server-side (parts
stage under the reserved `.boatramp-uploads/{uploadId}/` namespace a client key
can never collide with, GC'd on abort/expiry; Complete is all-or-nothing). On a
**cloud** container the client drives the store's **native** multipart directly.

## Recipe 3 — content-addressed upload (idempotent, replay-inert)

Set `--sha256` (`require_sha256`) so the object key **must equal
`sha256(bytes)`**. On a local container the face verifies the hash as-streamed
and rejects a mismatch (`BoatrampSha256Mismatch`); a retried or replayed upload
of the same bytes is an idempotent no-op, and different bytes can never land at
the declared key. This is the **mandatory strong enforcement across clouds** (a
cloud session policy / SAS generally can't cap object size or content-type, but
content-addressing is enforceable everywhere the store pins the hash):

```console
$ boatramp blob mint-upload \
    --site app --container artifacts \
    --key "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" \
    --sha256 \
    --content-type "application/octet-stream" \
    --emit json
```

Because the key is the digest, an upload is **replay-inert**: replaying the
signed request writes the same bytes to the same key — a no-op. Content-addressed
mode is why a long-TTL bulk credential is safe even though a stateless SigV4
request can be replayed within its TTL.

## Enforced vs advisory constraints

A temp-credential's response carries an explicit **`enforced`** and
**`advisory`** list. This is a **trust contract**, not decoration:

- The **local** face enforces *everything* (size, content-type, sha256,
  create-only) — every stamped constraint is a hard, fail-closed check.
- A **cloud** broker labels a constraint it **cannot** cap in-policy as
  `advisory` — a session policy / SAS / signed URL binds the *prefix* and the
  *actions*, but generally **cannot cap object size** (and can't pin content-type
  on a broad prefix). `require_sha256` is always `enforced` where the store pins
  the hash and is the recommended way to make size effectively moot.

Never treat an `advisory` constraint as a guarantee. Prefer content-addressing
for cloud bulk credentials.

## Per-cloud operator setup

Enable the cloud broker feature for your store (`blob-upload-aws`,
`blob-upload-gcs`, `blob-upload-azure`) and configure `[serve.s3_ingress_cloud]`.
The client SDK usage and both recipes are **identical** — only the operator setup
differs.

### AWS

boatramp brokers `sts:AssumeRole` (default) with an inline **session policy**
resource-scoped to the exact `hblob/{qualified-site}/{container}/…` prefix and
action-scoped to `s3:PutObject` + the multipart quartet only (no get / list /
delete / bucket-level). Use `sts:GetFederationToken` for an IAM-user deployment.

```toml
[serve.s3_ingress_cloud]
# The role boatramp's base credential assumes (its trust policy must allow the
# base principal to assume it). Grant it s3:PutObject + CreateMultipartUpload +
# UploadPart + CompleteMultipartUpload + AbortMultipartUpload on the bucket.
aws_role_arn = "arn:aws:iam::123456789012:role/boatramp-blob-ingress"
# IAM-user base credential with no role to assume ⇒ GetFederationToken instead.
# aws_use_federation_token = true
```

The role's **trust policy** must let boatramp's base principal assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::123456789012:role/boatramp-node" },
    "Action": "sts:AssumeRole"
  }]
}
```

A single-key / browser mint returns a per-object **presigned PUT** (content-type
enforced when signed into the request); a prefix / multipart mint returns temp
credentials via the STS session policy.

### GCS

The single-key shape is a per-object **V4 signed PUT URL** via IAM `signBlob`
(keyless, Workload-Identity-friendly). The prefix shape is a hand-rolled **STS
Credential-Access-Boundary** token-exchange against
`https://sts.googleapis.com/v1/token`, scoped with a CEL condition
(`resource.name.startsWith('…/{hblob-prefix}')`) and the single role
`roles/storage.objectCreator` (object-create only — no viewer/admin).

Grant the boatramp service account **`roles/iam.serviceAccountTokenCreator`** (on
itself, so it can `signBlob` and mint the STS token):

```console
$ gcloud iam service-accounts add-iam-policy-binding \
    boatramp@PROJECT.iam.gserviceaccount.com \
    --member="serviceAccount:boatramp@PROJECT.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator"
# and the object-creator role on the bucket:
$ gcloud storage buckets add-iam-policy-binding gs://YOUR_BUCKET \
    --member="serviceAccount:boatramp@PROJECT.iam.gserviceaccount.com" \
    --role="roles/storage.objectCreator"
```

```toml
[serve.s3_ingress_cloud]
gcs_client_email = "boatramp@PROJECT.iam.gserviceaccount.com"  # absent ⇒ from ADC
```

### Azure

A **user-delegation SAS** (AAD, no account key). The boatramp identity needs the
**`Storage Blob Delegator`** role (to obtain a user-delegation key) plus a
write/create role such as **`Storage Blob Data Contributor`** on the container.

An Azure SAS scopes to a **single blob** or a **directory prefix** — but a
directory-scoped SAS only *confines* on a **hierarchical-namespace (ADLS Gen2)**
account; on a flat account it silently widens to container-wide. So a **prefix**
mint requires you to declare the account has HNS with **`azure_hns = true`**
(fail-closed otherwise):

```toml
[serve.s3_ingress_cloud]
azure_account = "mystorageacct"
# azure_service_url = "https://mystorageacct.blob.core.windows.net/"  # else derived
# REQUIRED for a prefix credential: the account has a hierarchical namespace.
azure_hns = true
```

```console
$ az role assignment create \
    --assignee "$BOATRAMP_PRINCIPAL_ID" \
    --role "Storage Blob Delegator" \
    --scope "/subscriptions/.../storageAccounts/mystorageacct"
$ az role assignment create \
    --assignee "$BOATRAMP_PRINCIPAL_ID" \
    --role "Storage Blob Data Contributor" \
    --scope "/subscriptions/.../storageAccounts/mystorageacct/blobServices/default/containers/YOUR_CONTAINER"
```

> **Testing against Azurite.** The Azure blob-ingress live gate runs against the
> Azurite emulator. Start it with `azurite --skipApiVersionCheck` — the 1.x Azure
> SDK sends a newer `x-ms-version` than the emulator's default allowlist, so
> without that flag Azurite rejects the request with a version error.

## CORS (browser uploads)

The local S3 face is a **credentialed write endpoint**, so it never reflects an
arbitrary `Origin` and never answers `*`. Set a first-class per-container
allowlist so the face answers the browser's `OPTIONS` preflight for exactly your
origins. On a cloud target you set the **bucket's own** CORS (the mint/CLI warns
when a cloud target lacks a rule for the intended origin).

## Error codes (local face)

The local face returns standards-shaped S3 error XML with a **stable, greppable
`<Code>` vocabulary**. Auth failures deliberately all collapse to a uniform
`AccessDenied` (no which-check oracle); the rest name a specific, non-oracle
condition:

| `<Code>` | HTTP | Meaning |
|---|---|---|
| `AccessDenied` | 403 | The uniform auth/authz refusal (bad signature / scope / expiry / token / revocation — no oracle) |
| `BoatrampScopeEscape` | 403 | The composed key escaped its scoped prefix (traversal / absolute / reserved namespace) |
| `BoatrampCredExpired` | 403 | The credential (session token) is expired |
| `BoatrampOperationNotPermitted` | 403 | An operation the credential's `perms` do not grant (e.g. multipart on a put-only cred) |
| `BoatrampSha256Mismatch` | 400 | A content-addressed upload's bytes did not hash to the declared key |
| `BoatrampContentTypeRejected` | 400 | The `Content-Type` did not satisfy the required constraint |
| `BoatrampMultipartInvalid` | 400 | Malformed multipart (bad part list, unknown `uploadId`, bad part number) |
| `MalformedRequest` | 400 | Malformed request body / framing (bad XML, bad chunk framing) |
| `BoatrampSizeExceeded` | 413 | Object exceeded the credential's `max_bytes` or the per-container ceiling |
| `BoatrampOverwriteDenied` | 412 | A create-only credential attempted to overwrite an existing key |
| `BoatrampQuotaExceeded` | 429 | A DoS cap was hit (too many parts / concurrent uploads / staged bytes) |
| `MethodNotAllowed` | 405 | The method/route is not one the face implements |
| `InternalError` | 500 | A storage-backend fault (native S3 code so SDKs retry) |

A **cloud** container returns the store's **native** S3 / GCS / Azure error codes,
not this vocabulary — the client talks to the real store.

## Security model (why a credential can't escape its scope)

- **Project AND site are host-supplied, never guest-supplied.** The WIT surface
  has no project/site parameter; the credential is structurally confined to its
  origin tenant.
- **The secret is HKDF-derived** from a dedicated, independently-rotatable
  ingress root (never the `[secrets]` KEK, never the COSE signing key). The root
  never leaves the host; a leaked temp cred is bounded to its scope and short
  TTL.
- **SigV4 is verified fail-closed and constant-time** on the local face;
  expired / malformed / tampered ⇒ a uniform 403, no partial write.
- **Deny-by-default everywhere**: no grant ⇒ no binding; an empty
  `upload_containers` ⇒ deny-all; a zero TTL ceiling disables minting.
- **Keys are traversal-screened** at the mint choke point (covers cloud too) and
  re-anchored under the host-forced `hblob/…` prefix — an object can never land
  outside its scoped prefix.
