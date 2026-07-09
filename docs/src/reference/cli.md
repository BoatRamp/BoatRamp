# CLI

`boatramp` is one binary: the server (`serve`) and every client command. This
page lists the commands and details the flags of `serve`; each command also
prints its own flags with `boatramp <command> --help`.

Precedence for any overridable value: **flag / environment variable > config
file > built-in default**. Project commands read `project.cfg`; `serve` reads
`boatramp.cfg`.

## Global flags

| Flag | Default | Description |
| --- | --- | --- |
| `--config <path>` | `project.cfg` / `boatramp.cfg` | Config file to read. |
| `-h`, `--help` | — | Print help for the binary or a subcommand. |
| `-V`, `--version` | — | Print the version. |

## Commands

| Command | What it does |
| --- | --- |
| `serve` | Run the HTTP server and publishing API. |
| `sync <dir>` | Build (optional) and publish a folder as a new atomic deployment. |
| `build` | Run the configured build command only. |
| `bundle` | Bundle JS/TS + CSS in-process (`bundler` feature). |
| `validate` | Parse and check a `project.cfg` (its `routing` section). |
| `deployments` | List a site's deployment history. |
| `rollback` | Roll back to the previous (or a specific) deployment. |
| `status` | Show a site's current deployment (id, age, size). |
| `domain` | Attach or detach hostnames for a site. |
| `alias` | Manage named pointers (staging, previews) to deployments. |
| `access` | Configure visitor access control (basic auth, IP rules, rate limit). |
| `token` | Manage control-plane API tokens. |
| `cluster` | Operate a cluster's mesh membership (mint join tokens). |
| `security` | Inspect the operator security posture (`security explain`). |
| `auth` | Generate or inspect the control-plane root key. |
| `gateway` | Publish a private service through the edge reverse proxy. |
| `compute` | Manage microVM / container compute workloads. |
| `dns` | Configure DNS and issue wildcard preview certs (`acme-dns` feature). |
| `logs` | Tail a site's captured guest stdout/stderr. |
| `stats` | Show handler invocation stats, consumer lag, and dead letters. |
| `dlq` | Purge or redrive a consumer topic's dead-letter queue. |
| `prune` | Delete orphan deployments and unreferenced blobs. |
| `scrub` | Verify every stored blob still hashes to its key. |
| `cert-status` | Show cluster-managed certificate status (domain, expiry). |
| `completions <shell>` | Print a shell-completion script. |
| `man` | Render the man page to stdout. |
| `cloudflare` | Generate a Cloudflare Containers deployment (`cluster` feature). |

Each command's tasks are covered in the guides — see the [How-to
guides](../how-to/install.md) and the per-topic reference pages. Exit status is
`0` on success and non-zero on failure; see [Errors & exit
codes](./errors.md).

## `boatramp serve`

Run the server: selects backends, TLS, auth, and (with the `cluster` feature)
cluster mode.

### Address, storage, cache

| Flag | Env | Default | Description |
| --- | --- | --- | --- |
| `--addr <host:port>` | `BOATRAMP_ADDR` | `127.0.0.1:8080` | Bind address. |
| `--data-dir <path>` | `BOATRAMP_DATA_DIR` | `./data` | Blob + KV root for the filesystem backends. |
| `--blobs <fs\|s3>` | — | `fs` | Blob backend (`s3` needs `--features s3`). |
| `--kv <slatedb\|memory\|cloudflare>` | — | `slatedb` | KV backend (`cloudflare` needs `--features cloudflare-kv`). |
| `--s3-bucket <name>` | `BOATRAMP_S3_BUCKET` | — | S3 bucket (`--blobs s3`). |
| `--s3-endpoint <url>` | `BOATRAMP_S3_ENDPOINT` | — | S3 endpoint (MinIO / R2). |
| `--s3-region <region>` | `BOATRAMP_S3_REGION` | — | S3 region. |
| `--s3-path-style` | `BOATRAMP_S3_PATH_STYLE` | `false` | Use path-style S3 addressing. |
| `--cache-entries <n>` | — | `256` | Front metadata cache size. |

### Authentication

| Flag | Env | Default | Description |
| --- | --- | --- | --- |
| `--auth-root-private-key <alg:hex>` | `BOATRAMP_AUTH_ROOT_PRIVATE_KEY` | — | Root key: verify **and** mint tokens. |
| `--auth-root-public-key <alg:hex>` | `BOATRAMP_AUTH_ROOT_PUBLIC_KEY` | — | Root key: verify only. |
| `--bootstrap-secret <secret>` | `BOATRAMP_BOOTSTRAP_SECRET` | — | Single-use secret enabling `token bootstrap`. |
| `--oidc-issuer <url>` | `BOATRAMP_OIDC_ISSUER` | — | Enable OIDC → token exchange for this issuer. |
| `--oidc-audience <aud>` | `BOATRAMP_OIDC_AUDIENCE` | — | Required audience claim. |
| `--oidc-scope-claim <name>` | `BOATRAMP_OIDC_SCOPE_CLAIM` | — | Claim mapped to boatramp roles. |

> **Warning:** with no root key, control-plane auth is disabled. Under the default
> `multi-tenant` posture, `serve` refuses to start that way on a non-loopback
> `--addr`. Configure a key, bind `127.0.0.1`, or select a looser
> [security posture](../how-to/security-posture.md).

### TLS

| Flag | Default | Description |
| --- | --- | --- |
| `--tls <off\|custom\|acme\|acme-dns>` | `off` | TLS mode (HTTPS needs the `tls` feature). |
| `--tls-cert <path>` / `--tls-key <path>` | — | Certificate + key for `--tls custom`. |
| `--acme-domain <domain>` | — | Domain to issue for (repeatable). |
| `--acme-directory <url>` | Let's Encrypt production | ACME directory URL. |
| `--acme-contact <email>` | — | ACME account contact. |
| `--acme-ca-cert <path>` | — | Extra CA root (for a private ACME CA). |
| `--acme-cache <path>` | `./data/acme` | Certificate cache directory. |
| `--acme-dns-provider <name>` | `manual` | DNS-01 provider (`--tls acme-dns`); see [DNS providers](./dns-providers.md). |
| `--acme-wildcard-preview` | `false` | Also issue `*.deploy.<domain>` for by-id previews. |
| `--http-redirect-addr <host:port>` | `BOATRAMP_HTTP_REDIRECT_ADDR` | Second listener that `308`s plain HTTP to HTTPS. |

### Uploads, serving, cluster

| Flag | Env | Default | Description |
| --- | --- | --- | --- |
| `--max-upload-bytes <n>` | `BOATRAMP_MAX_UPLOAD_BYTES` | unlimited | Reject larger blob uploads. |
| `--upload-idle-timeout-secs <n>` | `BOATRAMP_UPLOAD_IDLE_TIMEOUT` | — | Abort an upload idle this long. |
| `--max-concurrent-uploads <n>` | `BOATRAMP_MAX_CONCURRENT_UPLOADS` | — | Cap simultaneous uploads. |
| `--default-site <name>` | `BOATRAMP_DEFAULT_SITE` | — | Site served for an unmatched `Host`. |
| `--protect-previews` | `BOATRAMP_PROTECT_PREVIEWS` | `false` | Require a token to view `/_deploy` previews. |
| `--cluster-rate-limit` | `BOATRAMP_CLUSTER_RATE_LIMIT` | `false` | Rate-limit cluster-wide via the KV, not per node. |
| `--shared-cache-coherence` | `BOATRAMP_SHARED_CACHE_COHERENCE` | `false` | Keep the config cache coherent across processes sharing one KV. |

The `cluster:` and `compute:` sections are configured in
[`boatramp.cfg`](./boatramp-cfg.md), not on the command line.

Example:

```sh
boatramp serve --config boatramp.cfg \
  --addr 0.0.0.0:8080 --tls acme --acme-domain pad.example.com
```

```text
control-plane auth enabled (issuer)
serving https://0.0.0.0:8080 — data /var/lib/boatramp
```
