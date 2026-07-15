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
| `BOATRAMP_TOKEN` | `publish.token` | Control-plane token. Prefer the env var so it is never on disk. |
| `BOATRAMP_TOKEN_HOLDER_KEY` | — | Holder **private** key (`"<alg>:<hex>"`) for a PoP-bound token: every request is signed with a fresh proof. Inert unless set alongside `BOATRAMP_TOKEN` + `BOATRAMP_POP_ORIGIN`. See [PoP-bind a token](../how-to/pop-tokens.md). |
| `BOATRAMP_POP_ORIGIN` | — | The server's canonical origin the PoP proof binds (`aud`); must equal the server's `serve.pop_origin`. |

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
| `BOATRAMP_S3_BUCKET` | Object-store bucket backing the KV (SlateDB over S3/R2). |
| `BOATRAMP_S3_ENDPOINT` | S3-compatible endpoint URL. |
| `BOATRAMP_S3_REGION` | Bucket region. |
| `BOATRAMP_S3_PATH_STYLE` | Use path-style addressing (for non-AWS endpoints). |

## Handler backends

| Variable | Description |
| --- | --- |
| `BOATRAMP_SQL_TOKEN` | Auth token for a remote libsql database referenced by the SQL binding. |
| _(your `url_env`)_ | Connection URL (a secret) for an external bring-your-own SQL database — the var name is whatever you set as `url_env` / `read_url_env` under `[handlers.bindings.sql.databases]`. See [Bring your own database](../how-to/handler-bindings.md#bring-your-own-database-external-postgres--mysql). |
| `BOATRAMP_FC_*` | Embedded-VMM / Firecracker compute-backend settings (kernel, rootfs, bridge, subnet, …). See [Run compute workloads](../how-to/compute.md). |
| `BOATRAMP_VMM_SERIAL` | Attach the microVM serial console (debugging). |

Handler `secrets` are injected by *reference*: the site config names a host
env-var, and the server resolves it at instantiation so the literal never lands
in a manifest. See [Handler host bindings](../how-to/handler-bindings.md).

## DNS provider credentials

Auto-DNS and `--tls acme-dns` read provider credentials (`CLOUDFLARE_API_TOKEN`,
`AWS_KEY`, `HETZNER_DNS_TOKEN`, …) from the environment. Each provider's exact
variables are listed in
[DNS providers & credentials](./dns-providers.md).

## Test-only variables

Variables prefixed `BOATRAMP_TEST_` gate `#[ignore]` live integration tests
(cloud KMS, SoftHSM, libsql, Docker, S3). They have no effect on a running
server and are not part of the operational surface.
