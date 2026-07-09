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

Override knobs (byte caps: `0` = unlimited):

| Knob | Description |
| --- | --- |
| `allow_unauthenticated_public_bind` | Permit a non-loopback bind with auth off. |
| `max_upload_bytes` | Blob upload cap. |
| `allow_site_unix_upstreams` | Let a site's gateway target `unix:` sockets. |
| `allow_site_private_upstreams` | Let a site's gateway target private IPs. |
| `max_handler_blob_bytes` | Per-handler blobstore write cap. |
| `max_component_bytes` | Wasm component size cap. |
| `oidc_require_audience` | Require an `aud` claim on OIDC exchange. |
| `domain_verify_allow_private` | Allow domain-verification probes to private hosts. |
| `allow_shared_kernel_compute` | Permit container (shared-kernel) compute; off ⇒ microVM only. |
| `ratelimit_fail_open` | Serve rather than reject if the rate-limit store is unavailable. |
| `allow_implicit_routing` | Resolve an unmatched host to a site without a registered domain (first-label `<site>.host` / sole site). Off under `multi-tenant`; a loopback bind enables it regardless. See [addressing](../explanation/addressing.md). |

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
| `bindings.sql` | table | — | The `sql` host binding. Omit for single-node (a per-site embedded libsql file); set `url` for a shared `sqld`. |

`bindings.sql` fields: `dir`, `url`, `admin_url`, `replica_url`, `token_env`,
`admin_token_env`, `preview_mode` (`empty` \| `branch` \| `shared`),
`preview_init`. See [Use handler bindings](../how-to/handler-bindings.md).

## `cluster`

Self-hosted Raft cluster. Parsed always, consumed only with the `cluster`
feature. The peer mesh runs over RFC 7250 raw-public-key mutual TLS.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `node_id` | integer | — | This node's stable id, unique in the cluster. |
| `listen` | socket address | — | Bind for the Raft peer mesh (distinct from `serve.addr`). |
| `peers` | map | — | `id → (url, pubkey)` for every node. The `pubkey` (logged at startup) seeds the mesh trust set. |
| `voters` | list of ids | all peers | The voting quorum; peers not listed join as learners. |
| `store_dir` | path | `<data-dir>/raft` | This node's durable Raft store. Never shared between nodes. |
| `bootstrap` | bool | `false` | Set on exactly one node at first bring-up. |
| `mesh` | table | — | Mesh identity + TLS: `key_file`, `key_rotation`, `join_token_ttl`, `gate_client_writes`. |

> **Warning:** a non-loopback `listen` refuses to start until every node's
> `pubkey` is in `peers`. Never point two nodes at one `store_dir`.

See [Deploy a self-hosted cluster](../how-to/deploy-cluster.md).

## `compute`

Container / microVM execution backends. Present ⇒ this node advertises compute
capacity to the scheduler; backends are capability-detected (container on Linux,
microVM where `/dev/kvm` exists).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `bridge` | string | `br-boatramp` | Bridge the guest veths / VM taps attach to. |
| `subnet` | string | `10.0.0.0/24` | Guest IP subnet. |
| `vcpus` | integer | detect | vCPUs this node advertises as schedulable (`0` = detect). |
| `mem_mib` | integer | `1024` | Memory (MiB) advertised as schedulable (`0` = 1 GiB). |

See [Run a container or microVM](../how-to/compute.md).
