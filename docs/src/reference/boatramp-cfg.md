# boatramp.cfg schema

`boatramp.cfg` is the server config, read by `boatramp serve`. It is
[RON](https://github.com/ron-rs/ron). Every value can also be set as a flag or an
environment variable, which take precedence. The whole file is optional — `serve`
runs with defaults without it.

```sh
boatramp serve --config boatramp.cfg
```

Precedence for any value: **flag / environment variable > `boatramp.cfg` >
built-in default**.

Top-level sections, all optional:

| Section | Purpose |
| --- | --- |
| `serve` | Bind address, data dir, auth keys, upload limits. |
| `security` | Operator security posture (profile + per-knob overrides). |
| `secrets` | Envelope encryption for cert private keys at rest. |
| `handlers` | Wasm handler runtime (needs the `handlers` feature). |
| `cluster` | Self-hosted Raft cluster (needs the `cluster` feature). |
| `compute` | Container / microVM execution backends. |

## `serve`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `addr` | socket address | `127.0.0.1:8080` | Bind address. Env `BOATRAMP_ADDR`. |
| `data_dir` | path | `./data` | Root for the filesystem blob + KV backends. Env `BOATRAMP_DATA_DIR`. |
| `auth_root_private_key` | `"<alg>:<hex>"` | — | Root signing key: this node verifies **and** mints tokens. Env `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`. |
| `auth_root_public_key` | `"<alg>:<hex>"` | — | Root verify key: this node verifies only, cannot mint. Env `BOATRAMP_AUTH_ROOT_PUBLIC_KEY`. |
| `bootstrap_secret` | string | — | Single-use secret enabling `token bootstrap`. Prefer the env var / flag so it is not written to disk. Env `BOATRAMP_BOOTSTRAP_SECRET`. |
| `signer` | signer enum | — | External signer (KMS/HSM/Vault) in place of an in-process key. See [below](#serve-signer). |
| `max_upload_bytes` | integer | unlimited | Reject blob uploads larger than this. |
| `default_site` | string | — | Site served for a `Host` matching no domain, instead of `404`. |
| `protect_previews` | bool | `false` | Require a control-plane token to view `/_deploy` previews. |
| `pop_origin` | string | — | The fleet's canonical public origin (e.g. `https://cp.example.com`) a per-request proof-of-possession must bind (`aud`). Required for holder-bound (`cnf`/PoP) tokens; compared against the proof, never a `Host`/`X-Forwarded-*` header. Env `BOATRAMP_POP_ORIGIN`. See [PoP-bind a token](../how-to/pop-tokens.md). |
| `blob_notify_tier` | `dry-run` \| `provision` \| `verify-only` \| `refuse` | — | Cloud blob-change notification provisioning tier for `blob` triggers on a cloud object store (S3→SQS / GCS→Pub/Sub / Azure→Event Grid). Absent ⇒ no provisioning (blob triggers work only on a self-watching backend like `fs`). See [Cloud blob triggers](../how-to/functions.md#cloud-blob-triggers-auto-provisioning). |
| `blob_notify_account_id` | string | — | Scopes the provisioned notification pipeline: the **AWS account id** (S3 queue policy) or **GCP project id** (GCS topic + notificationConfig). Unused by Azure (the queue shares the account's shared-key auth). |
| `s3_credential` | table | — | Node-level base S3 credential sourced from the sealed `[secrets]` store (shared by the S3 blob backend and the AWS ingress minter). See [`serve.s3_credential`](#serves3_credential). |
| `blob_fallback` | table | — | A read-only secondary blob backend for a zero-downtime backend switch. See [`serve.blob_fallback`](#serveblob_fallback). |
| `s3_ingress_addr` | socket address | — | Bind for the dedicated S3-upload ingress listener; see [S3 upload ingress](#serves3-upload-ingress). |
| `s3_ingress_secret_file` | path | — | On-node HKDF root for the local S3 ingress face; see [S3 upload ingress](#serves3-upload-ingress). |
| `s3_ingress_public_url` | string | — | Public base URL a minted upload credential embeds; see [S3 upload ingress](#serves3-upload-ingress). |
| `s3_ingress_mint_max_ttl_secs` | int | `3600` | Operator ceiling on a minted upload credential's TTL; see [S3 upload ingress](#serves3-upload-ingress). |
| `s3_ingress_mint_max_bytes` | int | — | Operator ceiling on a minted credential's object-size cap; see [S3 upload ingress](#serves3-upload-ingress). |
| `s3_ingress_cloud` | table | — | Cloud-brokering identity for the ingress minter (upload direct to a cloud store). See [`serve.s3_ingress_cloud`](#serves3_ingress_cloud). |

> **Warning:** with no `auth_root_*` key configured, control-plane auth is
> disabled. Under the default `multi-tenant` posture, `serve` refuses to start
> that way on a non-loopback `addr`. Configure a key, bind `127.0.0.1`, or select
> a looser [security posture](#security).

### `serve.signer`

Selects an external signer so the root key never sits in process memory. Written
as a RON enum. Credentials (tokens, PINs) come from the named environment
variables, never this file.

| Variant | Fields |
| --- | --- |
| `Local` | `private_key: "<alg>:<hex>"` |
| `Vault` | `address`, `key`, `token_env`, `alg` (`Es256` \| `Ed25519`) |
| `AwsKms` | `key_id`, `region` (optional) |
| `GcpKms` | `key_version`, `access_token_env` |
| `AzureKv` | `vault_url`, `key`, `key_version`, `access_token_env` |
| `Pkcs11` | `module`, `token_label`, `key_label`, `pin_env`, `alg` |

```ron
serve: ( signer: Vault(
    address: "https://vault:8200",
    key: "boatramp-root",
    token_env: "VAULT_TOKEN",
    alg: Es256,
) )
```

See [Hold the signing key in a KMS/HSM/Vault](../how-to/external-signer.md).

### `serve.s3_credential` (v0.6.1)

A **node-level base S3 credential** sourced from the sealed [`secrets`](#secrets)
store instead of the ambient `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env
chain. One source feeds **both** consumers — the S3 blob object backend
(`--blobs s3`) and the AWS blob-upload cloud minter
([`serve.s3_ingress_cloud`](#serves3_ingress_cloud)) — because it is the same
bucket key. Absent ⇒ the ambient AWS env chain (unchanged, non-breaking).

| Field | Type | Description |
| --- | --- | --- |
| `access_key_id` | string | The AWS **access key id** — a public identifier, so it is plain config. Empty is refused at startup. |
| `secret_access_key` | string | The secret access key as a **reference**, never the raw secret in-file: `boatramp:<name>` (the project-scoped sealed store, resolved under the default project via the `[secrets]` envelope), or `env:<VAR>` / a bare `<VAR>` (the operator's own environment, honored **only** when the posture's `allow_env_secret_refs` is set). Unsealed at startup; the resolved value is redacted from `Debug`/logs. |

```ron
serve: ( s3_credential: (
    access_key_id: "tid_public_akid",              // a public identifier — plain config
    secret_access_key: "boatramp:tigris-secret",   // a sealed secret REFERENCE, not the secret
) )
```

Seal the secret once with `boatramp secrets set` (default project), then
reference it here.

- **Fail-closed:** a `boatramp:` / `env:` ref configured with **no** `[secrets]`
  envelope is a **startup error** — boatramp does not silently fall back to the
  ambient env chain (which would mask the misconfig).
- **Cluster caveat:** blob storage is built before the replicated control plane,
  so a `boatramp:` (KV-backed) ref is refused fail-closed on a **cluster** node
  (the sealed store is single-node) — use an `env:<VAR>` ref there. The AWS cloud
  minter is likewise single-node this release.

See [Encrypt secrets at rest](../how-to/secrets-at-rest.md).

### `serve.blob_fallback` (v0.6.2)

A **read-only secondary blob backend** enabling a zero-downtime blob-backend
switch (fs→cloud, provider→provider, region→region). While it is attached,
serving reads the **primary** (the `[serve]` `blobs` / `s3_*` / `gcs_*` /
`azure_*` fields) first and, only on a **definitive miss** for a boatramp-owned
key, falls through to this secondary — so there is no serving gap while the old
backend drains into the new one. A **transient** primary error propagates (never
serves stale/secondary bytes on a blip); the fall-through is
**prefix-allowlisted** to content-addressed blobs, `hblob/`, and `mqgp/` (a
control-plane-shaped key never resurrects off the secondary); keys are forwarded
byte-identical so tenant isolation is preserved. `put` and `delete` are
**primary-only** — the secondary is strictly read-only, never written.

This block takes the **same backend-descriptor shape as the primary** — a `blobs`
selector plus the matching per-backend option fields — plus its own optional
`s3_credential` and a read timeout.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `blobs` | `fs` \| `s3` \| `gcs` \| `azure` | `fs` | The secondary backend — the OLD backend to fall back to. |
| `s3_bucket` | string | — | S3 bucket (secondary `blobs = s3`). |
| `s3_endpoint` | string | — | S3 endpoint URL (a MinIO/R2/Tigris endpoint) for the secondary. |
| `s3_region` | string | — | S3 region for the secondary. |
| `s3_path_style` | bool | `false` | Path-style addressing (MinIO) for the secondary. |
| `s3_credential` | table | — | The secondary's own sealed base S3 credential ([`serve.s3_credential`](#serves3_credential) shape). Absent ⇒ the ambient AWS env chain. |
| `gcs_bucket` | string | — | GCS bucket (secondary `blobs = gcs`). |
| `gcs_endpoint` | string | — | GCS endpoint URL (a `fake-gcs-server` emulator) for the secondary. |
| `gcs_anonymous` | bool | `false` | Skip GCS credential resolution (anonymous — the emulator) for the secondary. |
| `azure_account` | string | — | Azure storage account name (secondary `blobs = azure`). |
| `azure_container` | string | — | Azure container name for the secondary. |
| `azure_access_key` | string | — | Azure storage account access key (shared-key auth) for the secondary. |
| `azure_emulator` | bool | `false` | Use the Azurite emulator for the secondary. |
| `secondary_timeout_secs` | int | `5` | Bound (seconds) on each secondary read, so a wedged secondary degrades a primary miss to `NotFound` rather than hanging the serve path. |

```ron
serve: (
    blobs: s3,                                  // the NEW (primary) backend
    s3_bucket: "acme-blobs-new",
    s3_region: "auto",
    blob_fallback: (                            // the OLD backend to read through
        blobs: fs,
        secondary_timeout_secs: 5,
    ),
)
```

This is a **bounded transition aid**. Rollout: deploy `primary = new,
blob_fallback = old`, drain the old backend into the new one with
`boatramp blob migrate` (a bare `blob migrate` with a `blob_fallback` configured
drains the fallback → primary), then **remove this block and restart**. While a
fallback is attached the node logs a prominent transition-mode **WARNING** at
startup and blob GC **refuses to prune** (a prune returns `409`) — a union
`list` over a primary-only `delete` would otherwise reclaim a secondary-only
object that a read could resurrect. See
[Switch the blob backend with zero downtime](../how-to/blob-backend-migration.md).

### `serve.s3-upload-ingress` (v0.5.9)

The **external S3 upload ingress** — the daemon-config side of letting a client
outside the wasm sandbox upload directly into a project's blob container over the
S3 protocol, which the guest then reads unchanged through `wasi:blobstore`. These
are the `[serve]`-level knobs; the guest capability, operator CLI, and per-recipe
UX are covered in [Ingest large uploads over S3](../how-to/blob-ingress.md).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `s3_ingress_addr` | socket address | — | Bind for the **dedicated** SigV4 ingress listener — a separate listener from `serve.addr` with its own auth surface (it never reaches `serve_by_host` or the `/api` router). Absent ⇒ the local S3 face is not served (opt-in; a deployment that only brokers cloud credentials never needs it). |
| `s3_ingress_secret_file` | path | — | Path to the raw 32-byte **HKDF root** the local face derives each credential's `secret_access_key` from — **distinct** from the `[secrets]` KEK and the COSE signing key (hard domain separation). Holds a path, never key material. **The same file must be present on every node in a cluster.** Absent on a single node ⇒ an ephemeral per-process root; absent on a **multi-node** deployment ⇒ the face is refused (fail-closed). |
| `s3_ingress_public_url` | string | derived | The publicly-reachable base URL a **minted** upload credential embeds (the presigned-PUT prefix, or the SDK endpoint for temp-credentials). Absent ⇒ derived from `s3_ingress_addr` as `http://<addr>` (fine for a same-host dev loop; set the TLS-terminated public URL in production). |
| `s3_ingress_mint_max_ttl_secs` | int | `3600` | Operator **ceiling** (seconds) on a minted credential's TTL — a guest/operator can only request a shorter lifetime (the mint clamps to this). `0` disables minting entirely (the binding is never attached). |
| `s3_ingress_mint_max_bytes` | int | — | Operator ceiling (bytes) on a minted credential's `max_bytes` — a guest can only request a smaller cap. Absent ⇒ no host-side clamp (the per-container face ceiling still applies). |

```ron
serve: (
    addr: "0.0.0.0:8080",                       // control plane / site edge
    s3_ingress_addr: "0.0.0.0:9000",            // the dedicated S3 face
    s3_ingress_secret_file: "/etc/boatramp/s3-ingress.key",
    s3_ingress_public_url: "https://uploads.example.com",
    s3_ingress_mint_max_ttl_secs: 3600,         // TTL ceiling (default 1h)
    s3_ingress_mint_max_bytes: 104857600,       // per-cred object cap (100 MiB)
)
```

When the node's blob backend is a **cloud** object store, add
[`serve.s3_ingress_cloud`](#serves3_ingress_cloud) so the mint brokers a native,
scoped, short-lived cloud credential and the client uploads **directly** to the
real store (bytes never transit the node) instead of the local face.

### `serve.s3_ingress_cloud` (v0.5.9)

Cloud-brokering identity for the upload minter. Only the fields for the **active**
blob backend are consulted; absent ⇒ the local S3 face mints. See
[Ingest large uploads over S3 — per-cloud setup](../how-to/blob-ingress.md#per-cloud-operator-setup).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `aws_role_arn` | string | — | **AWS:** the IAM role ARN the base credential assumes (`sts:AssumeRole`, the default) to broker the scoped session-policy credential. |
| `aws_use_federation_token` | bool | `false` | **AWS:** use `sts:GetFederationToken` instead of `AssumeRole` (an IAM-user base credential, not itself a session). |
| `gcs_client_email` | string | ADC | **GCS:** the service-account client email whose V4 signed URLs / IAM-signed uploads the minter produces. Absent ⇒ resolved from ADC. |
| `azure_account` | string | blob-arg | **Azure:** the storage account name (SAS signature + blob URL). Absent ⇒ taken from the `azure_account` blob-backend arg. |
| `azure_service_url` | string | derived | **Azure:** the blob service URL (`https://{account}.blob.core.windows.net/`). Absent ⇒ derived from the account name. |
| `azure_hns` | bool | `false` | **Azure:** declare the account has a **hierarchical namespace** (HNS/ADLS-Gen2). A directory-scoped SAS only confines to a sub-prefix on an HNS account, so a **prefix** mint is refused unless this is `true` (fail-closed). A single-key mint is unaffected. |

## `security`

The operator security posture: a profile preset plus per-knob overrides. Absent
means the strict `multi-tenant` default. This section is operator-only — it is
never part of site config, so a site writer cannot relax it. Inspect the resolved
posture with `boatramp security explain`.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `profile` | string | `multi-tenant` | `multi-tenant` (strict), `single-tenant` (one trusted operator), `dev` (loopback-loose), or a name from `profiles`. |
| `overrides` | knob table | — | Individual knobs; a knob is the source of truth, a profile is sugar. |
| `profiles` | map | — | Custom named profiles, each a set of overrides over the strict baseline. |
| `projects` | map | — | Per-project overrides of the four tenancy/capability sub-knobs — see [Per-project posture](#securityprojects). |

Override knobs (byte caps: `0` = unlimited):

| Knob | Description |
| --- | --- |
| `allow_unauthenticated_public_bind` | Permit a non-loopback bind with auth off. |
| `max_upload_bytes` | Blob upload cap. |
| `allow_site_unix_upstreams` | Let a site's gateway target `unix:` sockets. |
| `allow_site_private_upstreams` | Let a site's gateway target private IPs. |
| `allow_guest_private_egress` | Let a handler guest's outbound `wasi:http` reach private/loopback IPs. Off under `multi-tenant` (the SSRF default — guests reach only public hosts); on under `single-tenant`/`dev`. A guest calling its own site or a sibling function uses the capability-gated `invoke` binding instead, which is unaffected by this knob. |
| `allow_guest_self_egress` | Let a handler guest's outbound `wasi:http` reach **this instance's own serve socket** (loopback on the serve port) even when `allow_guest_private_egress` is off — a much tighter grant, exposing only boatramp's own front door (which re-applies host routing + auth + rate-limit). Self-recursion is depth-capped. On by default in every posture. |
| `max_handler_blob_bytes` | Per-handler blobstore write cap. |
| `max_component_bytes` | Wasm component size cap. |
| `oidc_require_audience` | Require an `aud` claim on OIDC exchange. |
| `domain_verify_allow_private` | Allow domain-verification probes to private hosts. |
| `domain_verify_self_serve` | Serve pending HTTP ownership challenges from the edge (before host routing) so an unattached host can verify itself. On by default; disable to require out-of-band token placement. |
| `allow_shared_kernel_compute` | Permit container (shared-kernel) compute; off ⇒ microVM only. |
| `ratelimit_fail_open` | Serve rather than reject if the rate-limit store is unavailable. |
| `allow_implicit_routing` | Resolve an unmatched host to a site without a registered domain (first-label `<site>.host` / sole site). Off under `multi-tenant`; a loopback bind enables it regardless. See [addressing](../explanation/addressing.md). |
| `require_pop` | Require **every** control-plane token to be holder-bound (`cnf`) and present a valid per-request proof-of-possession. Off by default (a `cnf` token always requires a proof regardless; this knob additionally bans plain bearer tokens fleet-wide). Needs `pop_origin` set. See [PoP-bind a token](../how-to/pop-tokens.md). |
| `require_domain_verification` | Refuse to serve a **non-local** `Host` that isn't a verified, attached virtualhost — the request gets the "verification pending" holding page instead of any `default_site`/implicit fallback. **On under `multi-tenant`/`single-tenant`, off under `dev`** (which serves arbitrary local test hosts). Local hosts (`localhost`/`*.localhost`/`*.local`/IP literals) always serve. Disable it fleet-wide here, or exclude one host with `domain add <host> --unverified`. |
| `allow_compute_exec` | Permit `boatramp compute exec` — running a command inside a running workload (docker-exec style), i.e. arbitrary code execution in the workload. **Off in every profile but `dev`**; opt in for migrations/backups/debug. Container + docker backends only. |
| `allow_env_secret_refs` | Permit a handler's / function's `secrets` map to name a **bare** / `env:`-scheme reference into the serve process's own (the *operator's*) environment. **Off under `multi-tenant`** (an untrusted config author could exfiltrate any host env var — another tenant's DB password, a cloud key), on under `single-tenant`/`dev`. When off, such a reference is refused fail-closed. |
| `allow_guest_email` | Permit a guest handler/function's `email` capability to actually send. **Off under `multi-tenant`** (an untrusted tenant can't use the shared node's SMTP egress), on under `single-tenant`/`dev`. When off the `send` verb is absent and returns `access-denied`. Independent of the guest-HTTP egress knobs; the SMTP relay host is still held to the SSRF rule. |
| `allow_guest_mint_capability` | Permit a guest's `capability` capability to **mint** fleet-signed target-capability tokens. A minted token's audience is host-forced to the guest's own project and its TTL clamped to `max_guest_capability_ttl_secs`. **Off under `multi-tenant`**, on under `single-tenant`/`dev`. When off the `mint` verb is absent and returns `access-denied`. |
| `max_guest_capability_ttl_secs` | Operator ceiling (seconds) on a guest-minted capability's TTL; a `mint` requesting more is clamped to this. `0` disables minting outright. Default `900` (multi-tenant) / `3600` (single-tenant/dev). |
| `allow_guest_admin_domains` | Permit a guest's `admin` capability (`admin:domains` import) to manage the project's **domains** (add/verify/attach-verified/remove) via `boatramp:handlers/admin`. **Off under `multi-tenant`**, on under `single-tenant`/`dev`. Domain attach still runs the real ownership probe; there is no guest path to the unverified-attach route. |
| `allow_guest_admin_email` | Permit a guest's `admin` capability (`admin:email`) to manage the project's **SMTP email profiles** (set/delete). Passwords stay sealed, never returned to the guest. **Off under `multi-tenant`**, on under `single-tenant`/`dev`. |
| `allow_guest_admin_site` | Permit a guest's `admin` capability (`admin:site`) to write the project's **site config + aliases** (routing, headers, cache). A config write can't attach an unverified domain. **Off under `multi-tenant`**, on under `single-tenant`/`dev`. |
| `allow_guest_admin_secrets` | Permit a guest's `admin` capability (`admin:secrets`) to write the project's **sealed secrets** (set/rotate/delete — write-only, redacted). The most sensitive admin surface; an operator can withhold it while still allowing domains/email/site. **Off under `multi-tenant`**, on under `single-tenant`/`dev`. |
| `require_tenancy_declaration` | Require every function/handler that opens a `sql`/`orm` database to make an **explicit** in-site tenancy decision (`disabled` or `scoped`) — an undeclared importer is refused at activation, so serving a database unscoped is always a reviewed choice, never an accidental omission. **On under `multi-tenant`**, off under `single-tenant`/`dev` (which treat undeclared as `disabled`). See [Isolate tenants within a project](../how-to/tenant-isolation.md). |
| `allow_cross_tenant_db` | Permit a function/handler to declare a cross-tenant (`all`) read/write access mode — reaching every tenant's rows in a shared database. **Off under `multi-tenant`** (an `all` mode is capped down to `own`, so no guest can read across tenants even if it asks), on under `single-tenant`/`dev`. See [Isolate tenants within a project](../how-to/tenant-isolation.md). |

### `security.projects` (per-project posture, v0.4.7)

A `[security.projects.<project>]` block overrides the **four tenancy/capability sub-knobs** for one
project only, layered over the resolved fleet posture. It lets a single serve process host a
strict-isolation project beside a looser one on a shared, multi-project machine.

```ron
security: (
    profile: "multi-tenant",                 // the fleet default
    projects: {
        "acme-preview": (                     // looser, just this project
            allow_cross_tenant_db: true,
            allow_guest_mint_capability: true,
        ),
    },
)
```

| Per-project knob | Description |
| --- | --- |
| `require_tenancy_declaration` | Override the fleet `require_tenancy_declaration` for this project. |
| `allow_cross_tenant_db` | Override the fleet `allow_cross_tenant_db` for this project. |
| `allow_guest_mint_capability` | Override the fleet `allow_guest_mint_capability` for this project. |
| `max_guest_capability_ttl_secs` | Override the fleet `max_guest_capability_ttl_secs` (the mint TTL ceiling) for this project. |

Only these four in-project knobs are per-project-overridable; every other knob (egress, upload caps,
domain verification, guest-admin surfaces, …) stays fleet-wide. Each `Some` field of the override
wins; the rest fall through to the fleet posture, so the override **composes** with the global one.
**Cross-project isolation is structural** (project = database) — never a knob, so a per-project
override can only tune that project's own in-project strictness and its guests' capability-mint
ceiling, never its reach into another project. These four knobs are also `BOATRAMP_SECURITY_*`
env-settable at the **fleet** level (see [env.md](./env.md#security-posture)); per-project overrides
are config-file only.

See [Choose & inspect a security posture](../how-to/security-posture.md) and
[The security posture model](../explanation/security-posture.md).

## `secrets`

Envelope-encrypt cluster-managed certificate private keys so they are never
cleartext in the replicated control plane. Absent means keys are stored
cleartext.

| Field | Type | Description |
| --- | --- | --- |
| `envelope` | string | `local` (machine-local AES-256-GCM KEK) or `vault` (Vault Transit). |
| `kek_file` | path | Local KEK file (auto-generated `0600`). In a cluster the **same file** must be on every node. |
| `vault` | table | For `envelope: "vault"`: `addr`, `key` (a Transit key), `token_env`. |

See [Encrypt secrets at rest](../how-to/secrets-at-rest.md).

## `handlers`

Wasm handler runtime. Parsed always, consumed only with the `handlers` feature.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `pooling` | bool | `false` | Use the wasmtime pooling allocator (faster instantiation, large virtual-memory reservation). |
| `sync_max_timeout_ms` | int | `10000` | Safety-max wall-clock for a **connection-bearing** invocation (a site handler or a synchronous function/webhook invoke). A route/function may declare a *lower* timeout, never a higher one. Kept tight: a client + proxy + the shared request pool block while it runs. |
| `async_max_timeout_ms` | int | `900000` | Safety-max for a **durable async** invocation — the drain running `?mode=async` calls, workflow steps, cron/queue/blob triggers, and messaging consumers. No client is connected and the work is retried + dead-lettered, so this can be far larger (default 15 min). Runs on its own concurrency budget, so a long job never starves live traffic. |
| `async_max_concurrency` | int | `8` | Max concurrent in-flight async-lane invocations — a pool separate from (and smaller than) the request pool, so a burst of long background jobs can't exhaust the slots live site traffic needs. |
| `serve_concurrency` | int | host-derived | **Per-component serve-admission cap.** How many requests to the SAME component (keyed by content hash) may be concurrently inside the expensive build-bindings + instantiate + serve-to-head region; a burst beyond it (e.g. a gallery firing dozens of image thumbnails) queues cheaply on a semaphore instead of oversubscribing the async workers, which on a small-core node makes each request's await-resumptions pile into a multi-second scheduling stall. Absent ⇒ `available_parallelism × 4` (floored at 8), so a small node is bounded out of the box; `0` disables the gate (legacy unbounded serve). Raise on a big node, or lower if one hot component should be tighter. Read once at startup (a change needs a restart); the node logs the effective cap. A re-entrant self-egress call (a guest making a blocking HTTP call back to its own node) is exempt, so it can't deadlock against the outer request's permit. |
| `sync_max_concurrency` | int | host-derived | **Global sync-lane concurrency ceiling.** The node-wide cap on concurrent *connection-bearing* serves (site handlers, synchronous invokes, and the `/graphql` gateway's subgraph fan-out) — the aggregate ceiling the per-component `serve_concurrency` gate hands off to. Absent ⇒ `available_parallelism × 4` floored at **64**, so it is unchanged (64) on nodes up to ~16 vCPU and scales only ABOVE that; before this knob the lane was pinned at 64 regardless of host size, so adding vCPUs past ~16 bought no extra concurrent live throughput. Raise it on a big node to let the sync lane use more cores. Read once at startup (a change needs a restart); the node logs the effective cap. With `pooling` on, the shared instance pool is sized off the summed lane concurrencies, so a larger value enlarges the up-front virtual reservation. |
| `async_max_fuel` | int | — | Optional CPU **fuel** ceiling for an async-lane invocation. A large async timeout bounds only wall-clock; pair it with a fuel bound to keep a CPU-bound guest from spinning the whole window. Omit ⇒ unmetered. |
| `async_max_memory_mb` | int | `64` | **Linear-memory ceiling for a durable async invocation**, in MiB. The async lane is where heavy, retryable, no-client-connected work belongs (image decode/resize, PDF/thumbnail, document processing), so this is the knob to raise for memory-hungry workers. Raise it only as high as the heaviest async component needs — see the memory-ceiling note below. |
| `sync_max_memory_mb` | int | `64` | Linear-memory ceiling for a **connection-bearing** invocation, in MiB. Kept tight by default (a client + proxy + the shared request pool block while it runs); raise it only if a synchronous handler genuinely needs more. |
| `streaming_max_memory_mb` | int | `64` | Linear-memory ceiling for a **long-lived streaming** invocation (SSE / chunked / token streaming), in MiB. |
| `messaging_max_unflushed_msgs` | int | `0` | **Relaxed messaging-publish durability** (opt-in). `0` (default) = **strong**: `publish()` returns only after the message is crash-durable — *stronger* than NATS JetStream's default sync publish. `N > 0` fast-acks publishes from the in-memory buffer (≈tens of µs vs ≈one flush interval), forcing a durable checkpoint every `N` messages, so **at most `N` acknowledged-but-unflushed messages are lost on a process crash / OOM / SIGKILL / power loss**. Affects ONLY the bus publish path (control-plane, auth, and consumer ack/redelivery durability are unaffected); single-node only. The loss window is bounded by **both** `N` **and** the store's `flush_interval` (the background WAL-flush timer, ~5 ms) — so the effective steady-state bound is `min(N messages, one flush_interval)`, and on a low `flush_interval` a large `N` rarely binds. A node with `N > 0` logs a startup warning. See [Publish durability](../how-to/background-work.md#publish-durability-strong-by-default). |
| `outbound_timeout_ms` | int | — | Optional ceiling on a guest's **outbound** `wasi:http` call (connect + first-byte), independent of the invocation timeout, so a hung upstream is bounded on its own terms. The streaming (between-bytes) timeout is left at the default so a slow token stream isn't cut. Omit ⇒ wasmtime default. |
| `bindings.sql` | table | — | The `sql` host binding. Omit for single-node (a per-site embedded libsql file); set `url` for a shared `sqld`. |

`bindings.sql` fields: `dir`, `url`, `admin_url`, `replica_url`, `token_env`,
`admin_token_env`, `preview_mode` (`empty` \| `branch` \| `shared`),
`preview_init`, `databases`. See
[Use handler bindings](../how-to/handler-bindings.md).

### Memory ceilings per lane

Every lane defaults to a **64 MiB** per-component linear-memory ceiling. The
`*_max_memory_mb` knobs raise that ceiling for a lane; the ceiling is the maximum
any component on the lane may use, not a per-component allocation. A component
right-sizes itself **down** from the ceiling with its own `limits.memory_mb`
(per-function) or the site's `max_memory_mb`; a component with neither inherits
the lane ceiling. So the model is: set the lane ceiling high enough for the
heaviest component, and let each component cap itself lower where it should. A
per-component value above the lane ceiling is clamped to it — a component can
**never** raise its own memory above the operator-set lane ceiling (fail-closed,
operator-gated). Leaving every knob unset keeps the historical 64 MiB everywhere.

Cost: without `pooling` there is **no** up-front reservation — each invocation
sizes its store to its effective ceiling on demand. With `pooling = true` the
allocator reserves roughly `max-lane-memory × total-slots` of **virtual** address
space up front (slots = the sum of the three lanes' concurrency), so a raised
ceiling enlarges that reservation; the node logs the estimate at startup and
fails loudly if the reservation can't be made, rather than OOM-ing on the first
invocation. Prefer raising only `async_max_memory_mb` (the durable lane) for heavy
jobs, so the tighter sync/streaming lanes don't inflate the reservation.

A component that exceeds its effective ceiling at runtime no longer dead-letters
as an opaque `trap`: the terminal outcome and the `/metrics`
`boatramp_handler_invocations_total{outcome="out-of-memory"}` counter read
**`out-of-memory`**, so memory exhaustion is distinguishable from a logic crash.

### External SQL databases

`bindings.sql.databases` is a map of `name → external database`, each a
Postgres/MySQL a guest opens by that name (`sql.open("<name>")`) instead of a
per-site libsql one. Needs the `sql-postgres` / `sql-mysql` build feature.
Isolation is the operator's — such a database is shared across every guest
granted the `sql` binding — so it bypasses the per-site libsql boundary; libsql
stays the managed default. A name here shadows the same name on the libsql
default.

Each database has **one of two sources**, mutually exclusive:

- **Bring-your-own (`url_env`)** — you run the database anywhere; boatramp reads
  its connection URL from an env var.
- **Compute-backed (`compute`)** — the database is a compute workload *boatramp
  runs* (see [`compute`](#compute)). boatramp resolves the workload's live
  endpoint on demand and builds the connection, so there is no URL to hand-map
  and it follows the workload across restarts. With `password_env` set you bring
  the credential; **omit it and boatramp fully manages the credential** — it
  generates a strong password once, seals it with the [`secrets`](#secrets)
  envelope, injects it into the DB workload's server-init env at launch, and
  connects the handler with it, so you set no DB secret at all. A managed
  database therefore **requires a `[secrets]` envelope** (it refuses to store a
  credential it cannot seal) and a **persistent volume** on the DB workload (so
  the password the server was initialized with survives a restart).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `kind` | string | — | Engine: `postgres` (aliases `postgresql`/`pg`) or `mysql` (alias `mariadb`). Required. |
| `url_env` | string | — | **Bring-your-own source.** Env var holding the connection URL, e.g. `postgres://user:pw@host/db`. A secret — never the URL in-file. Required unless `compute` is set. |
| `read_url_env` | string | — | Env var holding a read-replica URL. When set, `open-read-only` routes there; writes stay on `url_env`. |
| `compute` | string | — | **Compute-backed source.** Name of a `compute` workload (a Postgres/MySQL boatramp runs) to source this database from. Mutually exclusive with `url_env`. |
| `database` | string | — | Compute-backed: the database name inside the server (non-secret). Required with `compute`. |
| `user` | string | — | Compute-backed: the connecting user (non-secret). Required with `compute`. |
| `password_env` | string | — | Compute-backed: env var holding the password for `user`. **Omit to let boatramp generate + manage the credential** (needs `[secrets]`); set it to bring your own. |
| `pool_max` | int | `8` | Maximum pooled connections. |
| `read_only` | bool | `false` | Open every transaction `READ ONLY` (the engine rejects writes). |
| `allow_preview` | bool | `false` | Permit preview deployments to reach it. Default refuses them, so a preview can't touch live external data. |
| `connect_timeout_secs` | int | `10` | Connection/acquire timeout, in seconds. |

## `cluster`

Self-hosted Raft cluster. Parsed always, consumed only with the `cluster`
feature. The peer mesh runs over RFC 7250 raw-public-key mutual TLS. A cluster is
defined by its **root of trust** — there is no peer map; nodes self-identify and
**join** by redeeming a ticket.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `listen` | socket address | — | Bind for the Raft peer mesh (distinct from `serve.addr`). |
| `root_pubkeys` | list of strings | `serve.auth_root_public_key` | The cluster **root anchor set** (`es256:`/`ed25519:` hex). Every join/trust decision verifies against it. A *set* enables make-before-break root rotation. |
| `seeds` | list of strings | — | Control-plane addresses of existing members. Present ⇒ this node **joins**; absent + `--cluster-init` ⇒ it **founds**. |
| `join_token` | string | — | The single-use bearer join token used when `seeds` are set. Keep the secret out of the file: `env:VAR`, `path:/file`, or an inline literal. |
| `store_dir` | path | `<data-dir>/raft` | This node's durable Raft store. Never shared between nodes. |
| `mesh` | table | — | Mesh identity + TLS: `key_file`, `key_rotation`, `join_token_ttl`, `gate_client_writes`. |

The node id is **derived** from the node's mesh key — there is no `node_id`
field. Founding and joining are driven from the command line: `serve
--cluster-init` founds a new cluster, `serve --cluster-join <ticket>` joins one
(from `cluster add`). The old static-genesis fields (`node_id`, `peers`,
`voters`, `bootstrap`) have been **removed**.

> **Warning:** a non-loopback `listen` refuses to start with an empty trust set
> (found with `--cluster-init` or join with `--cluster-join <ticket>`). Never
> point two nodes at one `store_dir`.

See [Deploy a self-hosted cluster](../how-to/deploy-cluster.md) and
[Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md).

## `compute`

Container / microVM execution backends. Present ⇒ this node advertises compute
capacity to the scheduler; backends are capability-detected: the native
`container` backend on Linux; the KVM microVM (`vmm-embedded`) where `/dev/kvm`
exists; the **macOS-native microVM (`vmm-vz`)** on Apple silicon + macOS 15+,
which boots each replica as a Linux VM via Virtualization.framework (strong
per-VM isolation, the same user surface as the KVM backend — no config change);
and remote `docker` wherever a Docker daemon is reachable. macOS 26 is
recommended for the `vmm-vz` backend: macOS 15's vmnet cannot do
container-to-container networking, so multi-replica cross-VM comms needs 26
(single-node serve works on 15). Nothing in the spec, CLI, or the fields below
differs by backend — the environment difference lives behind the backend.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `bridge` | string | `br-boatramp` | Bridge the guest veths / VM taps attach to. |
| `subnet` | string | `10.0.0.0/24` | Guest IP subnet. |
| `vcpus` | integer | detect | vCPUs this node advertises as schedulable (`0` = detect). |
| `mem_mib` | integer | `1024` | Memory (MiB) advertised as schedulable (`0` = 1 GiB). |
| `sql_shim_url` | url | — | Guest-reachable base URL of the compute **sql-shim** — set ⇒ a workload's `--bind sql` reaches the managed database through a listener bound on `0.0.0.0:<port>`. Use the address the *guest* reaches the host at: the compute bridge gateway for the native container backend (`http://10.0.0.1:8081`), the docker bridge gateway for rootful docker (`http://172.17.0.1:8081`), or `http://host.containers.internal:8081` for rootless podman. `None` ⇒ compute sql bindings off. |
| `docker_endpoint` | `published` \| `bridge` | `published` | How the remote-Docker backend reports a workload's reachable endpoint. `published` publishes the container port on `127.0.0.1:<ephemeral>` and routes there, so a host-native `serve` reaches it on any daemon — including Docker Desktop / macOS, where the container bridge IP is not host-routable. `bridge` routes to the container bridge IP directly; only reachable when `serve` shares the daemon's network (e.g. `serve` itself runs in a container on the same Docker bridge). |
| `docker_volume_mode` | `named` \| `bind` | `named` | How the remote-Docker backend backs a workload's persistent volumes. `named` attaches a daemon-managed `docker volume` by name (portable — works with a remote daemon and Docker Desktop / macOS). `bind` bind-mounts a host directory under `<data_dir>/compute/volumes/<name>` (matches the native-container layout, local daemon only). Docker volumes are node-local and outside the blob-snapshot durability story (consistent with the docker backend's no scale-to-zero); named volumes survive restarts but not cross-node migration. |
| `region` | string | — | This node's region tag (FA-8). Advertised on the node so a gateway routing to a `compute:`-backed workload with `--lb nearest` sends each request to the nearest replica by its node's region — no manual `--region` map. See [Route to the nearest region](../how-to/gateway.md#route-to-the-nearest-region). |
| `kernel_signing_pubkeys` | list | boatramp's built-in key | **Static** trust anchors (`"<alg>:<hex>"`) for the strict-posture kernel bar; a signed default kernel must verify against one. |
| `kernel_allowed_hashes` | list | the released `boatramp-vmlinux` hash | **Static** allow-list of kernel content hashes a dynamic default may select under `multi-tenant`. Ships pre-seeded with the first-party signed release so it verifies out of the box; replace it to allow only your own kernels. |
| `internal_dns` | bool | `true` | Run the per-project **internal DNS** resolver on the bridge gateway so a container resolves a sibling workload — or its managed DB — by name within its project. Every container's `/etc/resolv.conf` is pointed at the gateway; resolution is source-IP-scoped (a tenant sees only its own project's names). Linux + container backend only. See [Reach a sibling workload by name](../how-to/compute.md#reach-a-sibling-workload-by-name-internal-dns). |
| `dns_upstream` | string | `1.1.1.1:53` | Upstream resolver (`host:port`) the internal DNS forwards external names (and anything outside a project's namespace) to. |
| `dns_domain` | string | `boatramp.internal` | The internal DNS suffix names live under: a workload `web` in project `acme` answers to both bare `web` and `web.acme.boatramp.internal`. |

The kernel-signing keys and hash allow-list are static (host-access-gated) trust
anchors — the fleet **default kernel** itself is a
[dynamic setting](./daemon-config.md) (`compute.default_kernel`), changeable
without a restart but verified against these anchors at boot. See
[Run a container or microVM](../how-to/compute.md#the-kernel-and-its-trust).

Note: `vcpus`, `mem_mib`, and the default kernel are also settable at runtime via
[`boatramp config`](./daemon-config.md) — the `boatramp.cfg` values are the
baseline a dynamic override layers over.
