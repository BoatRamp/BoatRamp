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
| `BOATRAMP_CLONE_SOURCE_TOKEN` | — | Fallback for `project import --clone-from`: the operator's **source-node** `Project·Admin` bearer (sent in a request header over TLS, never on argv). Overridden by `--clone-source-token-file`. See [Streaming clone](../how-to/clone-project.md#streaming-clone-pull-from-a-live-source-node). |

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

### Node/system-health alerting (`[serve.alerts]`)

Env parity for the alerting subsystem (the `serve` segment is dropped). See
[Alert on node & system health](../how-to/node-health-alerting.md).

| Variable | Description |
| --- | --- |
| `BOATRAMP_ALERTS_ENABLED` | Master toggle for the alerting loop (default off). |
| `BOATRAMP_ALERTS_INTERVAL_SECS` | Evaluation cadence in seconds (default 60; floored at 5). |
| `BOATRAMP_ALERTS_DISK_ENABLED` | Enable the `/data` fullness signal (default on). |
| `BOATRAMP_ALERTS_DISK_WARN_PCT` / `_CRITICAL_PCT` | `/data` warn / critical percent-used (default 75 / 90). |
| `BOATRAMP_ALERTS_MANAGED_SQL_ENABLED` | Enable the managed-SQL replica-health signal (default on). |
| `BOATRAMP_ALERTS_MANAGED_SQL_GRACE_SECS` | Seconds a desired replica may be `HEALTHY=NO` before alerting (default 300). |
| `BOATRAMP_ALERTS_ORPHAN_ENABLED` | Enable the orphaned-replica signal (default on). |
| `BOATRAMP_ALERTS_ORPHAN_GRACE_SECS` | Minimum orphan age before alerting (default 86400). |
| `BOATRAMP_ALERTS_REAPER_ENABLED` | Turn ON the destructive orphan reaper (default off). |
| `BOATRAMP_ALERTS_REAPER_DRY_RUN` | Report-only unless `false` (default true). |
| `BOATRAMP_ALERTS_REAPER_GRACE_SECS` | Minimum orphan age the reaper requires (default 604800). |
| `BOATRAMP_ALERTS_REAPER_RECLAIM_VOLUMES` | Also delete the orphan's stranded volume staging (default off). |
| `BOATRAMP_ALERTS_WEBHOOK_URL_SECRET` | Sealed `boatramp:<name>` reference to the webhook URL. |
| `BOATRAMP_ALERTS_WEBHOOK_ALLOW_PRIVATE` | Permit a private webhook address past the SSRF floor (default off). |
| `BOATRAMP_ALERTS_EMAIL_PROJECT` / `_PROFILE` | The email profile's project (default `default`) + name. |
| `BOATRAMP_ALERTS_EMAIL_TO` | Comma-separated recipient addresses. |

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
| `BOATRAMP_COMPUTE_BLOB_SHIM_URL` | `compute.blob_shim_url` | Guest-reachable base URL of the compute blob shim (enables a workload's `--bind blob`). |
| `BOATRAMP_COMPUTE_MESSAGING_SHIM_URL` | `compute.messaging_shim_url` | Guest-reachable base URL of the compute messaging shim (enables a workload's `--bind messaging` — both publish and consume: `/publish`, `/claim`, `/ack`, `/nack`). |
| `BOATRAMP_COMPUTE_KV_SHIM_URL` | `compute.kv_shim_url` | Guest-reachable base URL of the compute kv shim (enables a workload's `--bind kv` — `/{key}` for the default bucket, `/b/{bucket}/{key}` for a named one). |
| `BOATRAMP_COMPUTE_BLOB_SHIM_MAX_OBJECT_BYTES` | `compute.blob_shim_max_object_bytes` | Per-object `PUT` ceiling (bytes) for the compute blob-shim; `413` on an oversize `PUT`. Unset ⇒ the shim's built-in default (5 GiB); `0` ⇒ unlimited. |
| `BOATRAMP_COMPUTE_KV_SHIM_MAX_VALUE_BYTES` | `compute.kv_shim_max_value_bytes` | Per-value `PUT` ceiling (bytes) for the compute kv-shim; `413` on an oversize `PUT`. Unset ⇒ the shim's built-in default (1 MiB); `0` ⇒ unlimited. |
| `BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE` | `compute.managed_db_privilege` | How a managed DB image runs on a shared-kernel backend: `rootless` (default) or `caps`. |
| `BOATRAMP_COMPUTE_DOCKER_ENDPOINT` | `compute.docker_endpoint` | Remote-Docker endpoint mode: `published` (default) or `bridge`. |
| `BOATRAMP_COMPUTE_DOCKER_VOLUME_MODE` | `compute.docker_volume_mode` | Remote-Docker volume mode: `named` (default) or `bind`. |
| `BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS` | `compute.kernel_signing_pubkeys` | Comma-separated `<alg>:<hex>` kernel-signing trust anchors (replaces, not appends to, the defaults). |
| `BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES` | `compute.kernel_allowed_hashes` | Comma-separated sha256-hex allow-list of kernel content hashes (replaces the defaults). |
| `BOATRAMP_COMPUTE_INTERNAL_DNS` | `compute.internal_dns` | Run the per-project internal DNS resolver on the bridge gateway so a guest resolves a sibling workload by name (default `true`; Linux + container backend). See [internal name resolution](../how-to/compute.md#reach-a-sibling-workload-by-name-internal-dns). |
| `BOATRAMP_COMPUTE_DNS_UPSTREAM` | `compute.dns_upstream` | Upstream resolver (`host:port`) the internal DNS forwards external names to (default `1.1.1.1:53`). |
| `BOATRAMP_COMPUTE_DNS_DOMAIN` | `compute.dns_domain` | Internal DNS suffix names live under, `<workload>.<project>.<domain>` (default `boatramp.internal`). |
| `BOATRAMP_COMPUTE_BACKEND` | `compute.backend` | Compute-backend selection (mailroom #26). `kubernetes` pins the [Kubernetes backend](../how-to/compute.md#the-kubernetes-backend-boatramp-on-k8s) (managed compute as native k8s `StatefulSet`/`Service`/`PVC` via the in-cluster API) and suppresses the capability-detected docker / native-container / VMM backends — for boatramp running AS a pod. Unset (default) keeps capability detection but still **auto-detects** an in-cluster environment and defaults to the Kubernetes backend there. Only effective with the `k8s-backend` feature. |
| `BOATRAMP_COMPUTE_K8S_STORAGE_CLASS` | `compute.k8s_storage_class` | PVC `StorageClass` for the Kubernetes backend's managed-DB data volumes. Unset ⇒ the cluster default (which must allow volume expansion for grow-in-place). |
| `BOATRAMP_COMPUTE_K8S_RETAIN_PVC` | `compute.k8s_retain_pvc` | Whether the Kubernetes backend retains a managed DB's PVC on `stop` (default `true` — a DB's data survives a routine teardown; an explicit destroy deletes it). |
| `BOATRAMP_COMPUTE_K8S_IMAGE_PULL_SECRET` | `compute.k8s_image_pull_secret` | Name of a pre-existing `kubernetes.io/dockerconfigjson` `Secret` in the serve pod's namespace to attach to launched pods as an `imagePullSecret` (private registries). Unset ⇒ anonymous/public pulls. The secret is managed out-of-band (the backend's Role grants no `secrets` verb). |
| `BOATRAMP_COMPUTE_K8S_VOLUME_SNAPSHOT_CLASS` | `compute.k8s_volume_snapshot_class` | CSI `VolumeSnapshotClass` for the Kubernetes backend's volume snapshot/restore. Unset ⇒ snapshot/restore is a clean "unsupported". |

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
| `BOATRAMP_SECURITY_ALLOW_GUEST_EGRESS_EXTRA_CA` | `overrides.allow_guest_egress_extra_ca` | Permit the guest egress TLS client to trust an operator-supplied extra CA (`BOATRAMP_GUEST_EGRESS_EXTRA_CA_FILE`) on top of the webpki roots. Widens trust, never bypasses verification. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_TCP_EGRESS` | `overrides.allow_guest_tcp_egress` | Permit a guest's gated `wasi:sockets` to open a host-mediated outbound TCP `connect`, and a guest's `dns-resolve` to resolve MX/addresses. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_TCP_LISTENER` | `overrides.allow_guest_tcp_listener` | Permit a host-owned inbound-TCP listener (`[serve.listeners.<name>]`) to dispatch an accepted connection to a guest. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_DNS_PUBLISH` | `overrides.allow_guest_dns_publish` | Permit a guest's `dns-publish` capability to WRITE DNS records through a host-held provider credential (cap-req #24). **Off in every built-in profile.** |
| `BOATRAMP_SECURITY_GUEST_DNS_PUBLISH_NS` | `overrides.guest_dns_publish_ns` | Posture for a guest's sub-zone `NS` delegation via `dns-publish`: `none` (refuse all, `multi-tenant` default), `allowlist` (only a `dns_publish_ns_targets`-listed target, `single-tenant` default), or `any` (`dev` default). |
| `BOATRAMP_SECURITY_MAX_HANDLER_BLOB_BYTES` | `overrides.max_handler_blob_bytes` | Cap on handler blobstore host reads/ranges/copies (`0` = unlimited). |
| `BOATRAMP_SECURITY_MAX_COMPONENT_BYTES` | `overrides.max_component_bytes` | Cap on a Wasm component blob (`0` = unlimited). |
| `BOATRAMP_SECURITY_OIDC_REQUIRE_AUDIENCE` | `overrides.oidc_require_audience` | Require an OIDC audience when OIDC is enabled. |
| `BOATRAMP_SECURITY_DOMAIN_VERIFY_ALLOW_PRIVATE` | `overrides.domain_verify_allow_private` | Permit HTTP domain-verification probes to private hosts. |
| `BOATRAMP_SECURITY_DOMAIN_VERIFY_SELF_SERVE` | `overrides.domain_verify_self_serve` | Serve pending ownership challenges from the edge (the domain-attach fix). |
| `BOATRAMP_SECURITY_ALLOW_SHARED_KERNEL_COMPUTE` | `overrides.allow_shared_kernel_compute` | Permit untrusted workloads on shared-kernel compute backends. |
| `BOATRAMP_SECURITY_ALLOW_COMPUTE_EXEC` | `overrides.allow_compute_exec` | Permit `boatramp compute exec` (run a command inside a running workload). **Off** in every profile but `dev` — it is arbitrary code execution in the workload; opt in for migrations/backups/debug. |
| `BOATRAMP_SECURITY_ALLOW_DEV_BLOB_BIND` | `overrides.allow_dev_blob_bind` | Permit `boatramp compute bind-blob` (mint a blob-shim URL + token for a non-managed local process — a dev/CI affordance). **Off** in every profile but `dev`. |
| `BOATRAMP_SECURITY_ALLOW_DEV_MESSAGING_BIND` | `overrides.allow_dev_messaging_bind` | Permit `boatramp compute bind-messaging` (mint a messaging-shim URL + token — publish AND consume — for a non-managed local process — a dev/CI affordance). **Off** in every profile but `dev`. |
| `BOATRAMP_SECURITY_RATELIMIT_FAIL_OPEN` | `overrides.ratelimit_fail_open` | Fail **open** instead of closed when the rate-limit KV is unreadable. |
| `BOATRAMP_SECURITY_ALLOW_IMPLICIT_ROUTING` | `overrides.allow_implicit_routing` | Resolve an unmatched `Host` to a site without an explicit domain registration. |
| `BOATRAMP_SECURITY_REQUIRE_POP` | `overrides.require_pop` | Require every token to be `cnf`-bound and PoP-proven fleet-wide. |
| `BOATRAMP_SECURITY_REQUIRE_DOMAIN_VERIFICATION` | `overrides.require_domain_verification` | Refuse to serve a non-local `Host` that isn't a verified, attached virtualhost. |
| `BOATRAMP_SECURITY_ALLOW_ENV_SECRET_REFS` | `overrides.allow_env_secret_refs` | Permit a handler's / function's `secrets` map to name a bare / `env:`-scheme reference into the serve process's own environment. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_REQUIRE_TENANCY_DECLARATION` | `overrides.require_tenancy_declaration` | Require every `sql`/`orm`-opening component to make an explicit in-site tenancy decision (`disabled` or `scoped`). On under `multi-tenant`. |
| `BOATRAMP_SECURITY_ALLOW_CROSS_TENANT_DB` | `overrides.allow_cross_tenant_db` | Permit a component to declare a cross-tenant (`all`) read/write access mode. Off under `multi-tenant` (capped to `own`). |
| `BOATRAMP_SECURITY_ALLOW_GUEST_MINT_CAPABILITY` | `overrides.allow_guest_mint_capability` | Permit a guest's `capability` capability to mint fleet-signed target-capability tokens. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_MAX_GUEST_CAPABILITY_TTL_SECS` | `overrides.max_guest_capability_ttl_secs` | Operator ceiling (seconds) on a guest-minted capability's TTL; a larger request is clamped. `0` disables minting. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_EMAIL` | `overrides.allow_guest_email` | Permit a guest handler's/function's `email` capability to send. Off under `multi-tenant` (an SMTP profile + secrets envelope still gate actual delivery). |
| `BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_DOMAINS` | `overrides.allow_guest_admin_domains` | Permit a guest's `admin` capability to manage the project's domains. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_EMAIL` | `overrides.allow_guest_admin_email` | Permit a guest's `admin` capability to manage the project's SMTP email profiles. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SITE` | `overrides.allow_guest_admin_site` | Permit a guest's `admin` capability to write the project's site config + aliases. Off under `multi-tenant`. |
| `BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SECRETS` | `overrides.allow_guest_admin_secrets` | Permit a guest's `admin` capability to write the project's sealed secrets. Off under `multi-tenant`. |

The four tenancy/capability variables above set the **fleet** posture; a **per-project** override of
the same knobs is config-file only (see
[`security.projects`](./boatramp-cfg.md#securityprojects)). Guest-admin surface knobs
(`allow_guest_admin_*`) and `allow_guest_email` are **file-only** — not env-settable.

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
| _(your `url_env`)_ | — | Connection URL (a secret) for an external bring-your-own SQL database — the var name is whatever you set as `url_env` / `read_url_env` under `[handlers.bindings.sql.databases]`. See [Bring your own database](../how-to/handler-binding-sql.md#bring-your-own-database-external-postgres--mysql). |
| `BOATRAMP_HANDLERS_BLOB_READ_CACHE_BYTES` | `blob_read_cache_bytes` | Size (bytes) of the serve-path **blob read-through cache** that fronts each blob backend, so a warm content-addressed `/img` derivative is answered from memory instead of a backend GET. Default `134217728` (128 MiB); `0` disables it. See [`[handlers]`](./boatramp-cfg.md#handlers). |
| `BOATRAMP_FC_*` | — | Embedded-VMM / Firecracker compute-backend settings (kernel, rootfs, bridge, subnet, …). See [Run compute workloads](../how-to/compute.md). |
| `BOATRAMP_VMM_SERIAL` | — | Attach the microVM serial console (debugging). |

Other scalar `[handlers]` runtime levers (the serve-admission / blob-hedge / cold-start
knobs) follow the same `BOATRAMP_HANDLERS_<FIELD>` convention; the authoritative list +
defaults are in the [`[handlers]`](./boatramp-cfg.md#handlers) config reference.

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
| `BOATRAMP_TLS` | `--tls` | Listener TLS mode: `off` (default), `custom`, `acme`, `acme-dns`, `rpk`. Use `acme-dns` for wildcard certs. |
| `BOATRAMP_ACME_DOMAINS` | `--acme-domain` | Comma-separated domains to certify. An explicit wildcard (`*.example.com`) is issued via DNS-01. |
| `BOATRAMP_ACME_DNS_PROVIDER` | `--acme-dns-provider` | DNS-01 provider: `manual`, `cloudflare`, `route53`, `oci`, `digitalocean`, `hetzner`, `ns1`, `dnsimple`, `gcp`, `azure`, `akamai`. |
| `BOATRAMP_ACME_CONTACT` | `--acme-contact` | Contact email for the ACME account. |
| `BOATRAMP_ACME_DIRECTORY` | `--acme-directory` | ACME directory URL (default Let's Encrypt production). |
| `BOATRAMP_ACME_CACHE` | `--acme-cache` | Certificate cache directory (default `./data/acme`). |
| `BOATRAMP_ACME_CA_CERT` | `--acme-ca-cert` | Extra root CA (PEM) to trust for the ACME server (e.g. Pebble's). |
| `BOATRAMP_ACME_WILDCARD_PREVIEW` | `--acme-wildcard-preview` | Also issue a `*.deploy.<domain>` wildcard for preview hosts (`true`/`false`). |
| `BOATRAMP_ACME_PROPAGATION_WAIT` | `--acme-propagation-wait-secs` | DNS-01 only: **max** seconds to wait for the `_acme-challenge` TXT to become visible before telling the CA to validate — a real readiness poll against the zone's authoritative nameservers, not a blind sleep (default `45`). |
| `BOATRAMP_ACME_PROPAGATION_POLL_INTERVAL` | `--acme-propagation-poll-interval-secs` | DNS-01 only: how often (seconds) to re-check DNS while waiting for the TXT to propagate (default `2`). |
| `BOATRAMP_ACME_PROPAGATION_RESOLVER` | — | DNS-01 only: override the **recursive** resolver used for zone/NS discovery and the fallback propagation check with a comma-separated list of `ip[:port]` resolvers (UDP). Absent ⇒ the host's system resolver. The primary check queries the zone's authoritative nameservers directly regardless of this; use it when the container's `/etc/resolv.conf` resolver caches negatives aggressively, or to pin a known-good public resolver (e.g. `1.1.1.1,8.8.8.8`). |
| `BOATRAMP_DNS_TARGET` | `--dns-target` | `--tls acme-dns` only: point every site's verified **custom** domains (never the `*.deploy.<host>` preview wildcard) at this address via a leader-gated background reconcile loop — an IPv4/IPv6 literal becomes an A/AAAA record, anything else a CNAME. Unset (default) disables the loop entirely; `dns configure-domain` remains the manual, one-shot path. See [Automate DNS with a provider](../how-to/auto-dns.md). |
| `BOATRAMP_DNS_RECONCILE_TICK` | `--dns-reconcile-tick-secs` | How often (seconds) the `--dns-target` reconcile loop re-sweeps every site's verified custom domains (default `300`). Ignored when `--dns-target` is unset. |
| `BOATRAMP_DNS_RECONCILE_TTL` | `--dns-reconcile-ttl` | TTL (seconds) for the A/AAAA/CNAME records the `--dns-target` reconcile loop writes (default `300`). Ignored when `--dns-target` is unset. |
| `BOATRAMP_DNS_PUBLISH_PROVIDER` | `--dns-publish-provider` | Install a host-held DNS provider for the guest **`dns-publish` WRITE** capability (same provider grammar as `BOATRAMP_ACME_DNS_PROVIDER`; `manual` for an offline proof). Unset (default) ⇒ nothing wired ⇒ every guest `dns-publish` is `access-denied` (fail-closed). A distinct authority from the ACME DNS provider. Credentials come from the same per-provider env vars `--acme-dns-provider` reads. See [`serve.dns_publish`](./boatramp-cfg.md#servedns_publish). |
| `BOATRAMP_DNS_PUBLISH_ZONE_ROOT` | `--dns-publish-zone-root` | The authoritative zone apex the `dns-publish` provider credential writes (e.g. `example.com`). Required once `BOATRAMP_DNS_PUBLISH_PROVIDER` is set. |

An **exact** host (an apex/`www`/`console` site or cert) always wins over a wildcard,
in both host→site routing and SNI cert selection — so `*.example.com` never shadows a
declared exact host.

### On-demand TLS (`[serve.on_demand_tls]`)

Env parity for the on-demand per-SNI issuer (**Concept 2** — issuing **other** tenant
domains' certs, distinct from the node's own `--acme-domain` cert). The `serve` segment
is dropped (like `[serve.alerts]`). Previously file-only; now every scalar is
env-settable. See [`serve.on_demand_tls`](./boatramp-cfg.md#serveon_demand_tls).

| Variable | Description |
| --- | --- |
| `BOATRAMP_ON_DEMAND_TLS_ENABLED` | Master toggle for the on-demand engine (default off). |
| `BOATRAMP_ON_DEMAND_TLS_CHALLENGE` | Challenge: `tls-alpn-01` (default) or `dns-01`. |
| `BOATRAMP_ON_DEMAND_TLS_DIRECTORY_URL` | ACME directory URL (default Let's Encrypt production). |
| `BOATRAMP_ON_DEMAND_TLS_CONTACT_EMAIL` | ACME account contact email. |
| `BOATRAMP_ON_DEMAND_TLS_MAX_INFLIGHT` | Max concurrent in-flight issuances (default 4). |
| `BOATRAMP_ON_DEMAND_TLS_NEGATIVE_TTL_SECS` | How long a refused/failed SNI is negatively cached (default 300). |
| `BOATRAMP_ON_DEMAND_TLS_RATE_LIMIT_PER_HOUR` | Max CA orders per rolling hour (default 50; `0` ⇒ unlimited). |
| `BOATRAMP_ON_DEMAND_TLS_PROPAGATION_WAIT_SECS` | DNS-01 only: max seconds to wait for the `_acme-challenge` TXT to become visible (default 45). |
| `BOATRAMP_ON_DEMAND_TLS_PROPAGATION_POLL_INTERVAL_SECS` | DNS-01 only: how often (seconds) to re-check DNS while waiting (default 2). |

The per-control-plane-domain challenge override
([`serve.control_plane_tls`](./boatramp-cfg.md#servecontrol_plane_tls), **Concept 1**) is
**file-only** — like [`serve.dns_providers`](./boatramp-cfg.md#servedns_providers), it is
not env-settable.

## DNS provider credentials

Auto-DNS and `--tls acme-dns` read provider credentials (`CLOUDFLARE_API_TOKEN`,
`AWS_KEY`, `HETZNER_DNS_TOKEN`, …) from the environment. Each provider's exact
variables are listed in
[DNS providers & credentials](./dns-providers.md).

## Test-only variables

Variables prefixed `BOATRAMP_TEST_` gate `#[ignore]` live integration tests
(cloud KMS, SoftHSM, libsql, Docker, S3). They have no effect on a running
server and are not part of the operational surface.
