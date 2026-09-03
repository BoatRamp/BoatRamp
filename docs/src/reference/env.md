# Environment variables

boatramp reads its configuration from three places, in precedence order:
**command-line flag > environment variable > config file**. Every variable below
overrides the corresponding config field and is itself overridden by an explicit
flag. Secrets (tokens, signing keys) belong in the environment rather than in a
config file on disk.

## Client commands

Read by `sync`, `build`, `bundle`, and the other project commands. See
[project.cfg](./project-cfg.md).

| Variable | Overrides | Description |
| --- | --- | --- |
| `BOATRAMP_SERVER` | `publish.server` | Server base URL. |
| `BOATRAMP_SITE` | `publish.site` | Site to publish to. |
| `BOATRAMP_PROJECT` | `publish.project` | Target [project](../how-to/projects.md) for site-scoped commands; falls back to `[publish].project`, then the `default` project. |
| `BOATRAMP_TOKEN` | `publish.token` | Control-plane token. Prefer the env var so it is never on disk. |
| `BOATRAMP_TOKEN_HOLDER_KEY` | — | Holder **private** key (`"<alg>:<hex>"`) for a PoP-bound token: every request is signed with a fresh proof. Inert unless set alongside `BOATRAMP_TOKEN` + `BOATRAMP_POP_ORIGIN`. See [PoP-bind a token](../how-to/pop-tokens.md). |
| `BOATRAMP_POP_ORIGIN` | — | The server's canonical origin the PoP proof binds (`aud`); must equal the server's `serve.pop_origin`. |
| `BOATRAMP_MCP_CONFIG` | — | Path to the [MCP](../how-to/mcp.md) instance registry (default `~/.config/boatramp/mcp.toml`). |

## Server (`serve`)

Read by `boatramp serve`. Each maps to a `serve.*` field in
[boatramp.cfg](./boatramp-cfg.md); the flag of the same name wins over both.

| Variable | Description |
| --- | --- |
| `BOATRAMP_ADDR` | Address to bind (e.g. `0.0.0.0:8080`). |
| `BOATRAMP_DATA_DIR` | Data directory (blobs + embedded KV). |
| `BOATRAMP_DEFAULT_SITE` | Site to serve for an unmatched `Host` instead of 404. |
| `BOATRAMP_POP_ORIGIN` | Canonical origin a per-request proof-of-possession must bind (`serve.pop_origin`). Required for holder-bound (`cnf`/PoP) tokens; compared against the proof, never a request header. |
| `BOATRAMP_HTTP_REDIRECT_ADDR` | In a TLS mode, a second plain-HTTP listener that 308-redirects to HTTPS (e.g. `0.0.0.0:80`). |
| `BOATRAMP_PROTECT_PREVIEWS` | Require a valid token to view deployment previews. |
| `BOATRAMP_LOG_FORMAT` | `json` for structured logs (anything else = human-readable). |

### Upload limits

| Variable | Description |
| --- | --- |
| `BOATRAMP_MAX_UPLOAD_BYTES` | Reject blob uploads larger than this (default: unlimited). |
| `BOATRAMP_UPLOAD_IDLE_TIMEOUT` | Abort an upload stalled this many seconds (slowloris guard). |
| `BOATRAMP_MAX_CONCURRENT_UPLOADS` | Cap simultaneous uploads; further uploads get 503 until a slot frees. |

## Authentication & tokens

See [Bootstrap authentication](../how-to/auth-bootstrap.md) and
[Authentication & authorization](../explanation/auth-model.md).

| Variable | Description |
| --- | --- |
| `BOATRAMP_AUTH_ROOT_PUBLIC_KEY` | The trust anchor. Every node needs it to verify tokens. |
| `BOATRAMP_AUTH_ROOT_PRIVATE_KEY` | The signing key. Needed **only** where tokens are minted; keep it off verify-only nodes. |
| `BOATRAMP_BOOTSTRAP_SECRET` | Single-use secret that mints the first admin token, then is retired. |
| `BOATRAMP_HOLDER_KEY` | Holder private key used to sign an offline [delegation](../how-to/ci-token.md) with `token attenuate`. |

An external signer (KMS/HSM/Vault) replaces `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`
with its own credentials — see
[Hold the signing key in a KMS/HSM/Vault](../how-to/external-signer.md).

### OIDC federation

For exchanging an identity-provider JWT for a boatramp token. See
[Federate CI auth with OIDC](../how-to/oidc.md).

| Variable | Description |
| --- | --- |
| `BOATRAMP_OIDC_ISSUER` | Trusted issuer URL (its JWKS is fetched for verification). |
| `BOATRAMP_OIDC_AUDIENCE` | Required audience claim. |
| `BOATRAMP_OIDC_SCOPE_CLAIM` | Claim carrying the granted roles. |

## Cluster & shared-store frontends

| Variable | Description |
| --- | --- |
| `BOATRAMP_CLUSTER_RATE_LIMIT` | Rate-limit cluster-wide via the shared KV instead of per-node buckets. |
| `BOATRAMP_SHARED_CACHE_COHERENCE` | Keep local config caches coherent across frontends sharing one KV. See [Cache coherence](../explanation/cache-coherence.md). |
| `BOATRAMP_BLOBS` | Blob backend (`fs`, `s3`, `gcs`, `azure`); env form of `--blobs`. |
| `BOATRAMP_KV` | Metadata KV backend (`slatedb`, `memory`, `cloudflare`); env form of `--kv`. |
| `BOATRAMP_KV_S3` | Run the SlateDB control-plane KV on the S3/R2 object store (reusing the `--blobs s3` config) instead of local disk — durable metadata for a volumeless container. Env form of `--kv-s3`. |
| `BOATRAMP_KV_S3_PREFIX` | Key prefix for the `--kv-s3` store within the bucket (default `_kv`). |
| `BOATRAMP_S3_BUCKET` | S3/R2 bucket for `s3` blobs and (with `--kv-s3`) the SlateDB KV. |
| `BOATRAMP_S3_ENDPOINT` | S3-compatible endpoint URL (R2: `https://<account>.r2.cloudflarestorage.com`). |
| `BOATRAMP_S3_REGION` | Bucket region (R2 uses `auto`). |
| `BOATRAMP_S3_PATH_STYLE` | Use path-style addressing (for non-AWS endpoints; R2 accepts it). |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Credentials for the `s3`/R2 backend (standard AWS resolution). |

## Compute backend

Map to the `[compute]` section in [boatramp.cfg](./boatramp-cfg.md). Set any of
these and the section is enabled even without a config file (a set variable wins
over its file value; an unset one defers to the file/default). See
[Run compute workloads](../how-to/compute.md).

| Variable | Overrides | Description |
| --- | --- | --- |
| `BOATRAMP_COMPUTE_BRIDGE` | `compute.bridge` | Bridge the container veths / VM taps attach to (default `br-boatramp`). |
| `BOATRAMP_COMPUTE_SUBNET` | `compute.subnet` | Guest IP subnet (default `10.0.0.0/24`). |
| `BOATRAMP_COMPUTE_VCPUS` | `compute.vcpus` | vCPUs advertised as schedulable (`0` = detect from the host). |
| `BOATRAMP_COMPUTE_MEM_MIB` | `compute.mem_mib` | Memory (MiB) advertised as schedulable (`0` = a 1 GiB default). |
| `BOATRAMP_COMPUTE_REGION` | `compute.region` | This node's region tag for nearest-replica routing. |
| `BOATRAMP_COMPUTE_SQL_SHIM_URL` | `compute.sql_shim_url` | Guest-reachable base URL of the compute SQL shim (enables a workload's `--bind sql`). |
| `BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE` | `compute.managed_db_privilege` | How a managed DB image runs on a shared-kernel backend: `rootless` (default) or `caps`. |
| `BOATRAMP_COMPUTE_DOCKER_ENDPOINT` | `compute.docker_endpoint` | Remote-Docker endpoint mode: `published` (default) or `bridge`. |
| `BOATRAMP_COMPUTE_DOCKER_VOLUME_MODE` | `compute.docker_volume_mode` | Remote-Docker volume mode: `named` (default) or `bind`. |
| `BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS` | `compute.kernel_signing_pubkeys` | Comma-separated `<alg>:<hex>` kernel-signing trust anchors (replaces, not appends to, the defaults). |
| `BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES` | `compute.kernel_allowed_hashes` | Comma-separated sha256-hex allow-list of kernel content hashes (replaces the defaults). |
| `BOATRAMP_COMPUTE_INTERNAL_DNS` | `compute.internal_dns` | Run the per-project internal DNS resolver on the bridge gateway so a guest resolves a sibling workload by name (default `true`; Linux + container backend). See [internal name resolution](../how-to/compute.md#reach-a-sibling-workload-by-name-internal-dns). |
| `BOATRAMP_COMPUTE_DNS_UPSTREAM` | `compute.dns_upstream` | Upstream resolver (`host:port`) the internal DNS forwards external names to (default `1.1.1.1:53`). |
| `BOATRAMP_COMPUTE_DNS_DOMAIN` | `compute.dns_domain` | Internal DNS suffix names live under, `<workload>.<project>.<domain>` (default `boatramp.internal`). |

**Security-critical:** `BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS` and
`BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES` are the kernel trust anchors for the
posture-scaled kernel bar — a value here decides which kernels a `multi-tenant`
node will boot. In a 12-factor deployment the environment is the operator's
trusted config source (a `fly.toml` `[env]` is committed the same as a file), so
they are settable here; but the environment is *more* visible than a file (it
leaks through `/proc/<pid>/environ` and is inherited by subprocesses), so prefer
a config file for them when one is available.

## Security posture

Map to the `[security]` section in [boatramp.cfg](./boatramp-cfg.md). Setting any
of these materialises the posture even without a config file: an unset section
resolves to the strict `multi-tenant` default and each variable layers over it
exactly as a file `overrides` block would (a set variable wins over the file).
See [boatramp.cfg](./boatramp-cfg.md) and
`boatramp security explain`. Byte caps take `0` = unlimited; booleans accept
`true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`.

| Variable | Overrides | Description |
| --- | --- | --- |
| `BOATRAMP_SECURITY_PROFILE` | `security.profile` | Base profile: `multi-tenant` (default), `single-tenant`, `dev`, or a custom `profiles` name. |
| `BOATRAMP_SECURITY_ALLOW_UNAUTHENTICATED_PUBLIC_BIND` | `overrides.allow_unauthenticated_public_bind` | Permit a non-loopback bind with control-plane auth disabled. |
| `BOATRAMP_SECURITY_MAX_UPLOAD_BYTES` | `overrides.max_upload_bytes` | Default blob-upload cap in bytes (`0` = unlimited). |
| `BOATRAMP_SECURITY_ALLOW_SITE_UNIX_UPSTREAMS` | `overrides.allow_site_unix_upstreams` | Permit site-declared `unix:` gateway upstreams. |
| `BOATRAMP_SECURITY_ALLOW_SITE_PRIVATE_UPSTREAMS` | `overrides.allow_site_private_upstreams` | Permit site-declared gateway upstreams to private/loopback IPs. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_PRIVATE_EGRESS` | `overrides.allow_guest_private_egress` | Permit a guest's outbound `wasi:http` to reach private/loopback IPs. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_SELF_EGRESS` | `overrides.allow_guest_self_egress` | Permit a guest's outbound `wasi:http` to reach this instance's own serve socket. |
| `BOATRAMP_SECURITY_MAX_HANDLER_BLOB_BYTES` | `overrides.max_handler_blob_bytes` | Cap on handler blobstore host reads/ranges/copies (`0` = unlimited). |
| `BOATRAMP_SECURITY_MAX_COMPONENT_BYTES` | `overrides.max_component_bytes` | Cap on a Wasm component blob (`0` = unlimited). |
| `BOATRAMP_SECURITY_OIDC_REQUIRE_AUDIENCE` | `overrides.oidc_require_audience` | Require an OIDC audience when OIDC is enabled. |
| `BOATRAMP_SECURITY_DOMAIN_VERIFY_ALLOW_PRIVATE` | `overrides.domain_verify_allow_private` | Permit HTTP domain-verification probes to private hosts. |
| `BOATRAMP_SECURITY_DOMAIN_VERIFY_SELF_SERVE` | `overrides.domain_verify_self_serve` | Serve pending ownership challenges from the edge (the domain-attach fix). |
| `BOATRAMP_SECURITY_ALLOW_SHARED_KERNEL_COMPUTE` | `overrides.allow_shared_kernel_compute` | Permit untrusted workloads on shared-kernel compute backends. |
| `BOATRAMP_SECURITY_ALLOW_COMPUTE_EXEC` | `overrides.allow_compute_exec` | Permit `boatramp compute exec` (run a command inside a running workload). **Off** in every profile but `dev` — it is arbitrary code execution in the workload; opt in for migrations/backups/debug. |
| `BOATRAMP_SECURITY_RATELIMIT_FAIL_OPEN` | `overrides.ratelimit_fail_open` | Fail **open** instead of closed when the rate-limit KV is unreadable. |
| `BOATRAMP_SECURITY_ALLOW_IMPLICIT_ROUTING` | `overrides.allow_implicit_routing` | Resolve an unmatched `Host` to a site without an explicit domain registration. |
| `BOATRAMP_SECURITY_REQUIRE_POP` | `overrides.require_pop` | Require every token to be `cnf`-bound and PoP-proven fleet-wide. |
| `BOATRAMP_SECURITY_REQUIRE_DOMAIN_VERIFICATION` | `overrides.require_domain_verification` | Refuse to serve a non-local `Host` that isn't a verified, attached virtualhost. |

## Handler backends

The `[handlers.bindings.sql]` knobs (the single managed-SQL backend) map to
these; set any and the section is created even without a config file (env wins
over the file value; secrets stay indirected via the `*_TOKEN_ENV` names, never
the token itself). See [Handler bindings](../how-to/handler-bindings.md).

| Variable | Overrides | Description |
| --- | --- | --- |
| `BOATRAMP_HANDLERS_SQL_DIR` | `bindings.sql.dir` | Single-node: root dir for the per-site embedded databases (default `<data-dir>/handlers-sql`). |
| `BOATRAMP_HANDLERS_SQL_URL` | `bindings.sql.url` | Cluster: base sqld data URL — switches from single-node to a shared sqld cluster. |
| `BOATRAMP_HANDLERS_SQL_ADMIN_URL` | `bindings.sql.admin_url` | Cluster: sqld admin API base URL (required when `url` is set). |
| `BOATRAMP_HANDLERS_SQL_REPLICA_URL` | `bindings.sql.replica_url` | Cluster: optional read-replica data URL for read-only transactions. |
| `BOATRAMP_HANDLERS_SQL_TOKEN_ENV` | `bindings.sql.token_env` | Name of the env var holding the sqld data auth token. |
| `BOATRAMP_HANDLERS_SQL_ADMIN_TOKEN_ENV` | `bindings.sql.admin_token_env` | Name of the env var holding the sqld admin API key. |
| `BOATRAMP_HANDLERS_SQL_PREVIEW_MODE` | `bindings.sql.preview_mode` | Preview-database policy: `empty` (default), `branch`, or `shared`. |
| `BOATRAMP_HANDLERS_SQL_PREVIEW_INIT` | `bindings.sql.preview_init` | Path to an idempotent SQL script run when an `empty` preview db is first opened. |
| `BOATRAMP_HANDLERS_SQL_DEPROVISION_GRACE_SECS` | `bindings.sql.deprovision_grace_secs` | Soft-delete grace window (seconds) for a per-tenant managed DB. Default `604800` (7 days). On a project/site delete, a **Shared + Postgres** tenant is *soft*-deleted (its database renamed aside, role disabled) and stays recoverable for this long before a reaper hard-drops it; `0` disables the soft path (immediate, irreversible hard drop). MySQL and all `Single` tenants always hard-drop immediately. |
| `BOATRAMP_SQL_TOKEN` | — | Auth token for a remote libsql database referenced by the SQL binding. |
| _(your `url_env`)_ | — | Connection URL (a secret) for an external bring-your-own SQL database — the var name is whatever you set as `url_env` / `read_url_env` under `[handlers.bindings.sql.databases]`. See [Bring your own database](../how-to/handler-bindings.md#bring-your-own-database-external-postgres--mysql). |
| `BOATRAMP_FC_*` | — | Embedded-VMM / Firecracker compute-backend settings (kernel, rootfs, bridge, subnet, …). See [Run compute workloads](../how-to/compute.md). |
| `BOATRAMP_VMM_SERIAL` | — | Attach the microVM serial console (debugging). |

### External SQL databases (`[handlers.bindings.sql.databases]`)

The bring-your-own / managed-compute database map is env-settable too, so a
managed co-located Postgres needs no config file. Each database `<NAME>` is
declared by setting one or more `BOATRAMP_HANDLERS_SQL_DB_<NAME>_<FIELD>`
variables; the member names are discovered from the environment (there is no
file to enumerate them). An env-declared database is merged over — per field, by
key — whatever the file declared under that name.

The default database (the empty-string map key, opened as `sql.open("")`) is
addressed by the reserved name token **`DEFAULT`**:
`BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND` populates the `""` key.

`<FIELD>` is one of `KIND`, `URL_ENV`, `READ_URL_ENV`, `COMPUTE`, `DATABASE`,
`USER`, `PASSWORD_ENV`, `POOL_MAX`, `READ_ONLY`, `ALLOW_PREVIEW`,
`CONNECT_TIMEOUT_SECS`, `IMAGE`, `VOLUME_SIZE_MIB`, `STARTUP_GRACE_SECS` (each
mirrors a field of the RON `databases` entry; secrets stay indirected via the
`*_ENV` names). `STARTUP_GRACE_SECS` sets how long a freshly launched managed-DB
replica may take to become healthy before the reconcile treats it as a broken
launch; omit it for the per-engine default (Postgres 60 s, MySQL 120 s). See
[Startup grace](../how-to/compute.md#startup-grace-slow-starting-images). Example — a
managed Postgres as the default database, with boatramp managing the credential (no
`PASSWORD_ENV`):

```
BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND=postgres
BOATRAMP_HANDLERS_SQL_DB_DEFAULT_COMPUTE=pg
BOATRAMP_HANDLERS_SQL_DB_DEFAULT_DATABASE=appdb
BOATRAMP_HANDLERS_SQL_DB_DEFAULT_USER=app
```

For a **managed co-located** database (`COMPUTE` set, no `PASSWORD_ENV`), boatramp
**auto-registers the backing compute workload** — so the four lines above are enough
to boot a Postgres; no separate `compute set` / `apply` step. `IMAGE` overrides the
stock image (default `pgvector/pgvector:pg16` for postgres, `mysql:8.0` for mysql)
and `VOLUME_SIZE_MIB` the persistent data-volume size (default `10240` = 10 GiB). An
operator-declared workload of the same name always wins over the auto-registered one.

Handler `secrets` are injected by *reference*: the site config names a host
env-var, and the server resolves it at instantiation so the literal never lands
in a manifest. See [Handler host bindings](../how-to/handler-bindings.md).

## Secrets envelope

Map to the `[secrets]` section in [boatramp.cfg](./boatramp-cfg.md) — envelope
encryption for private keys at rest. Set any and the section is created even
without a config file. `kek_file` holds a *path* (never key material); the Vault
token stays indirected via `token_env` (a variable name, not the token).

| Variable | Overrides | Description |
| --- | --- | --- |
| `BOATRAMP_SECRETS_ENVELOPE` | `secrets.envelope` | Backend: `local` (machine-local AES-256-GCM KEK) or `vault` (Vault Transit). |
| `BOATRAMP_SECRETS_KEK_FILE` | `secrets.kek_file` | Path to the local-KEK key file (auto-generated `0600` if absent). Default `<data-dir>/secrets/kek`. |
| `BOATRAMP_SECRETS_VAULT_ADDR` | `secrets.vault.addr` | Vault address, e.g. `https://vault:8200`. |
| `BOATRAMP_SECRETS_VAULT_KEY` | `secrets.vault.key` | Vault Transit key name to wrap under. |
| `BOATRAMP_SECRETS_VAULT_TOKEN_ENV` | `secrets.vault.token_env` | Name of the env var holding the Vault token (default `VAULT_TOKEN`). |

## Cluster section (`[cluster]`)

Map to the `[cluster]` section in [boatramp.cfg](./boatramp-cfg.md) — the
self-hosted cluster mode's own config, distinct from the founding/joining
*action* flags in the [Cluster & shared-store frontends](#cluster--shared-store-frontends)
table above (`BOATRAMP_CLUSTER_INIT` / `BOATRAMP_CLUSTER_JOIN` /
`BOATRAMP_CLUSTER_ADVERTISE_ADDR`). A `BOATRAMP_CLUSTER_LISTEN` materialises an
absent section (a node must know where to bind its mesh); the other fields then
layer on. List-valued vars are comma-separated.

| Variable | Overrides | Description |
| --- | --- | --- |
| `BOATRAMP_CLUSTER_LISTEN` | `cluster.listen` | Address to bind this node's Raft peer mesh on (e.g. `10.0.0.2:7000`). Required to materialise an absent section. |
| `BOATRAMP_CLUSTER_ROOT_PUBKEYS` | `cluster.root_pubkeys` | Comma-separated `es256:`/`ed25519:` root anchor set defining the cluster identity. |
| `BOATRAMP_CLUSTER_SEEDS` | `cluster.seeds` | Comma-separated control-plane addresses of existing members to join through. |
| `BOATRAMP_CLUSTER_JOIN_TOKEN` | `cluster.join_token` | Single-use join token (kept out of plain sight via an `env:VAR` / `path:/file` prefix). |
| `BOATRAMP_CLUSTER_STORE_DIR` | `cluster.store_dir` | Directory for this node's durable Raft log/state (default `<data-dir>/raft`). |
| `BOATRAMP_CLUSTER_MESH_KEY_FILE` | `cluster.mesh.key_file` | Path to this node's Ed25519 mesh identity key (auto-generated `0600`). |
| `BOATRAMP_CLUSTER_MESH_KEY_ROTATION` | `cluster.mesh.key_rotation` | Automatic mesh key-rotation cadence (e.g. `30d`). |
| `BOATRAMP_CLUSTER_MESH_JOIN_TOKEN_TTL` | `cluster.mesh.join_token_ttl` | TTL for a single-use join token (e.g. `1h`). |
| `BOATRAMP_CLUSTER_MESH_GATE_CLIENT_WRITES` | `cluster.mesh.gate_client_writes` | Gate mesh client-writes behind a control-plane cluster-write capability. |

## TLS / ACME (incl. wildcard DNS-01)

The listener's TLS mode and the ACME issuance parameters — previously `serve` flags
only — are env-settable too, so wildcard DNS-01 can be configured with no config file
(e.g. a fly `[env]`). The DNS provider *credentials* are already env-only (below).

| Variable | Flag | Description |
| --- | --- | --- |
| `BOATRAMP_TLS` | `--tls` | Listener TLS mode: `off` (default), `custom`, `acme`, `acme-dns`, `acme-tls`, `rpk`. Use `acme-dns` for wildcard certs. |
| `BOATRAMP_ACME_DOMAINS` | `--acme-domain` | Comma-separated domains to certify. An explicit wildcard (`*.example.com`) is issued via DNS-01. |
| `BOATRAMP_ACME_DNS_PROVIDER` | `--acme-dns-provider` | DNS-01 provider: `manual`, `cloudflare`, `route53`, `oci`, `digitalocean`, `hetzner`, `ns1`, `dnsimple`, `gcp`, `azure`, `akamai`. |
| `BOATRAMP_ACME_CONTACT` | `--acme-contact` | Contact email for the ACME account. |
| `BOATRAMP_ACME_DIRECTORY` | `--acme-directory` | ACME directory URL (default Let's Encrypt production). |
| `BOATRAMP_ACME_CACHE` | `--acme-cache` | Certificate cache directory (default `./data/acme`). |
| `BOATRAMP_ACME_CA_CERT` | `--acme-ca-cert` | Extra root CA (PEM) to trust for the ACME server (e.g. Pebble's). |
| `BOATRAMP_ACME_WILDCARD_PREVIEW` | `--acme-wildcard-preview` | Also issue a `*.deploy.<domain>` wildcard for preview hosts (`true`/`false`). |

An **exact** host (an apex/`www`/`console` site or cert) always wins over a wildcard,
in both host→site routing and SNI cert selection — so `*.example.com` never shadows a
declared exact host.

## DNS provider credentials

Auto-DNS and `--tls acme-dns` read provider credentials (`CLOUDFLARE_API_TOKEN`,
`AWS_KEY`, `HETZNER_DNS_TOKEN`, …) from the environment. Each provider's exact
variables are listed in
[DNS providers & credentials](./dns-providers.md).

## Test-only variables

Variables prefixed `BOATRAMP_TEST_` gate `#[ignore]` live integration tests
(cloud KMS, SoftHSM, libsql, Docker, S3). They have no effect on a running
server and are not part of the operational surface.
