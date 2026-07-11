# CLI

`boatramp` is one binary: the server (`serve`) and every client command. This
page documents each command. Any command also prints its own flags with
`boatramp <command> --help`, and group commands list their sub-actions with
`boatramp <command> help`.

Precedence for any overridable value: **flag / environment variable > config
file > built-in default**. Project commands read `project.cfg`; `serve` reads
`boatramp.cfg`.

## Global flags

| Flag | Description |
| --- | --- |
| `--config <path>` | Config file (`project.cfg` for client commands, `boatramp.cfg` for `serve`). |
| `-h`, `--help` | Print help for the binary or a subcommand. |
| `-V`, `--version` | Print the version. |

## Common client flags

Most client commands accept these, so the per-command tables below list only the
flags unique to each command:

| Flag | Env | Description |
| --- | --- | --- |
| `--server <url>` | `BOATRAMP_SERVER` | Server base URL (overrides `publish.server`). |
| `--site <name>` | `BOATRAMP_SITE` | Target site (overrides `publish.site`). |
| — | `BOATRAMP_SERVER_PUBKEY` | Pin the control plane to a `--tls rpk` server's raw public key (the hex it prints at startup). See [Reach the control plane on day zero](../how-to/bootstrap-tls.md). |

## Commands

| Command | What it does |
| --- | --- |
| [`serve`](#boatramp-serve) | Run the HTTP server and publishing API. |
| [`sync <dir>`](#boatramp-sync) | Build (optional) and publish a folder as a new atomic deployment. |
| [`build`](#boatramp-build) | Run the configured build command only. |
| [`bundle`](#boatramp-bundle) | Bundle JS/TS + CSS in-process (`bundler` feature). |
| [`validate`](#boatramp-validate) | Parse and check a `project.cfg` (its `routing` section). |
| [`deployments`](#boatramp-deployments) | List a site's deployment history. |
| [`rollback`](#boatramp-rollback) | Roll back to the previous (or a specific) deployment. |
| [`status`](#boatramp-status) | Show a site's current deployment. |
| [`domain`](#boatramp-domain) | Attach/detach hostnames to a site. |
| [`alias`](#boatramp-alias) | Manage named pointers to deployments. |
| [`access`](#boatramp-access) | Configure visitor access control. |
| [`token`](#boatramp-token) | Manage control-plane API tokens. |
| [`cluster`](#boatramp-cluster) | Operate a cluster's mesh membership. |
| [`security`](#boatramp-security) | Inspect the operator security posture. |
| [`auth`](#boatramp-auth) | Generate/inspect the root key; edit the RBAC policy. |
| [`gateway`](#boatramp-gateway) | Publish a private service through the reverse-proxy gateway. |
| [`compute`](#boatramp-compute) | Manage microVM compute workloads. |
| [`blob`](#boatramp-blob) | Upload a file as a content-addressed blob. |
| [`config`](#boatramp-config) | Read/change the dynamic daemon config (no restart). |
| [`dns`](#boatramp-dns) | Configure DNS and issue wildcard preview certs (`acme-dns` feature). |
| [`logs`](#boatramp-logs) | Tail a site's captured guest stdout/stderr. |
| [`stats`](#boatramp-stats) | Show handler stats, consumer lag, and dead letters. |
| [`dlq`](#boatramp-dlq) | Purge or redrive a consumer topic's dead-letter queue. |
| [`prune`](#boatramp-prune) | Delete orphan deployments and unreferenced blobs. |
| [`scrub`](#boatramp-scrub) | Verify every stored blob still hashes to its key. |
| [`cert-status`](#boatramp-cert-status) | Show cluster-managed certificate status. |
| [`completions <shell>`](#boatramp-completions-man) | Print a shell-completion script. |
| [`man`](#boatramp-completions-man) | Render the man page to stdout. |
| [`cloudflare`](#boatramp-cloudflare) | Generate a Cloudflare Containers deployment (`cluster` feature). |

Exit status is `0` on success and non-zero on failure; see
[Errors & exit codes](./errors.md).

## `boatramp serve`

Run the server: selects backends, TLS, auth, and (with the `cluster` feature)
cluster mode. The `cluster:` and `compute:` sections are configured in
[`boatramp.cfg`](./boatramp-cfg.md), not on the command line.

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

| Flag | Env | Description |
| --- | --- | --- |
| `--auth-root-private-key <alg:hex>` | `BOATRAMP_AUTH_ROOT_PRIVATE_KEY` | Root key: verify **and** mint tokens. |
| `--auth-root-public-key <alg:hex>` | `BOATRAMP_AUTH_ROOT_PUBLIC_KEY` | Root key: verify only. |
| `--bootstrap-secret <secret>` | `BOATRAMP_BOOTSTRAP_SECRET` | Single-use secret enabling `token bootstrap`. |
| `--oidc-issuer <url>` | `BOATRAMP_OIDC_ISSUER` | Enable OIDC → token exchange for this issuer. |
| `--oidc-audience <aud>` | `BOATRAMP_OIDC_AUDIENCE` | Required audience claim. |
| `--oidc-scope-claim <name>` | `BOATRAMP_OIDC_SCOPE_CLAIM` | Claim mapped to boatramp roles. |

> **Warning:** with no root key, control-plane auth is disabled. Under the default
> `multi-tenant` posture, `serve` refuses to start that way on a non-loopback
> `--addr`. Configure a key, bind `127.0.0.1`, or select a looser
> [security posture](../how-to/security-posture.md).

### TLS

| Flag | Default | Description |
| --- | --- | --- |
| `--tls <off\|custom\|acme\|acme-dns\|rpk>` | `off` | TLS mode (HTTPS needs the `tls` feature). `rpk` = a pinned raw-public-key control channel; see [Reach the control plane on day zero](../how-to/bootstrap-tls.md). |
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
| `--default-site <name>` | `BOATRAMP_DEFAULT_SITE` | — | Site served for an unmatched `Host` (see [addressing](../explanation/addressing.md)). |
| `--pop-origin <url>` | `BOATRAMP_POP_ORIGIN` | — | Canonical origin a per-request proof-of-possession must bind. Required for holder-bound (`cnf`/PoP) tokens. See [PoP-bind a token](../how-to/pop-tokens.md). |
| `--protect-previews` | `BOATRAMP_PROTECT_PREVIEWS` | `false` | Require a token to view `/_deploy` previews. |
| `--cluster-rate-limit` | `BOATRAMP_CLUSTER_RATE_LIMIT` | `false` | Rate-limit cluster-wide via the KV, not per node. |
| `--shared-cache-coherence` | `BOATRAMP_SHARED_CACHE_COHERENCE` | `false` | Keep the config cache coherent across processes sharing one KV. |

```sh
boatramp serve --config boatramp.cfg \
  --addr 0.0.0.0:8080 --tls acme --acme-domain pad.example.com
```

## `boatramp sync`

Build (optional) and publish a folder as a new atomic deployment. Argument:
`[PATH]` — the directory to publish (defaults to `build.output`, then `.`).

| Flag | Description |
| --- | --- |
| `--build` / `--no-build` | Force or skip the configured build command. |
| `--no-activate` | Upload the deployment but do not make it current. |
| `-m`, `--message <msg>` | Deploy message recorded with the deployment. |
| `--source <rev>` | Source revision (defaults to the current git commit SHA). |
| `--branch <branch>` | Source branch (defaults to the current git branch). |
| `--author <author>` | Deploy author. |

## `boatramp build`

Run the configured build command only.

| Flag | Description |
| --- | --- |
| `--command <cmd>` | Override the configured build command. |

## `boatramp bundle`

Bundle JS/TS (Rolldown) + CSS (lightningcss) in-process. Needs the `bundler`
feature; configured by the `bundle` section of [`project.cfg`](./project-cfg.md).

## `boatramp validate`

Parse and check a `project.cfg` (its `routing` section). Argument: `[PATH]` —
the config to validate (default `project.cfg`). See the
[routing schema](./routing.md).

## `boatramp deployments`

List a site's deployment history.

| Flag | Default | Description |
| --- | --- | --- |
| `--limit <n>` | `20` | Maximum number of deployments to show. |

## `boatramp rollback`

Roll back to the previous (or a specific) deployment.

| Flag | Description |
| --- | --- |
| `--to <id>` | Deployment id (or unique prefix) to activate. Defaults to the previous one. |

## `boatramp status`

Show a site's current deployment (id, age, size). No command-specific flags.

## `boatramp domain`

Attach/detach hostnames to a site (virtualhost routing). See
[Attach a custom domain](../how-to/custom-domain.md).

| Sub-action | Description |
| --- | --- |
| `add <host>` | Verify ownership and attach (use `*.example.com` for a wildcard). Verifies + attaches in one step when the host already resolves here; otherwise prints the challenge to finish with `verify`. |
| `verify <host>` | Check the challenge; on success the host is attached. |
| `rm <host>` | Detach a hostname and drop its verification. |
| `ls` | List the site's hostnames and pending verifications. |

`domain add` flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--method <http\|dns>` | `http` | Serve a token file (`http`) or publish a TXT record (`dns`, needs `domain-verify-dns`). |
| `--provider <name>` | — | Managed-DNS provider (e.g. `cloudflare`, `route53`): publish the `_boatramp-verify` TXT, poll, and attach — no manual DNS edit. Implies `--method dns`; needs `acme-dns`. |
| `--no-wait` | — | Only start the challenge and print instructions; skip the immediate verify+attach self-check. |

## `boatramp alias`

Manage named pointers (staging, previews) to deployments. See
[Publish, roll back & alias](../how-to/publish.md).

| Sub-action | Description |
| --- | --- |
| `set <name> <deployment>` | Point an alias at a deployment id (or unique history prefix). |
| `rm <name>` | Remove a named alias. |
| `ls` | List the site's aliases. |

## `boatramp access`

Configure visitor access control. See
[Restrict visitor access](../how-to/visitor-access.md).

| Sub-action | Description |
| --- | --- |
| `show` | Show the site's current access-control policy. |
| `basic-auth add\|rm\|clear` | Manage HTTP Basic auth credentials. `add` reads the password from `--password` or stdin. |
| `ip allow\|deny\|clear` | Manage IP allow/deny rules (CIDR or bare address); deny wins over allow. |
| `rate-limit set\|off` | Set the per-client requests/second (+ optional burst) or disable it. |
| `trusted-proxy add\|clear` | Trust a reverse proxy by CIDR so its `X-Forwarded-For` is believed. |

## `boatramp token`

Manage control-plane API tokens. See
[Bootstrap authentication](../how-to/auth-bootstrap.md) and the
[RBAC reference](./rbac.md).

| Sub-action | Description |
| --- | --- |
| `create <label>` | Mint a token (printed once). |
| `bootstrap` | Mint the first token with the single-use `BOATRAMP_BOOTSTRAP_SECRET` — no admin token needed. |
| `mint` | Mint a token **offline** via the configured signer (local key or KMS/HSM), no server. |
| `attenuate <credential>` | Narrow a delegatable token **offline** by signing a restrict-only block. |
| `ls` | List issued tokens (short id, label, roles, expiry). |
| `rm <id>` | Revoke a token by its id or a unique prefix. |

`create` / `mint` flags:

| Flag | Description |
| --- | --- |
| `--role <role>` | Role, repeatable: `<role>` (global) or `<role>:<site>` (scoped). Required. |
| `--ttl-secs <n>` | Time-to-live in seconds (omit for no expiry). |
| `--holder-pub <alg:hex>` | Make the token delegatable: embed this holder public key as the `cnf`. |
| `--pop` | Make the token PoP-bound: generate a holder keypair, mint against its public half, and print `BOATRAMP_TOKEN` + `BOATRAMP_TOKEN_HOLDER_KEY` exports. Conflicts with `--holder-pub`. See [PoP-bind a token](../how-to/pop-tokens.md). |

`attenuate` flags:

| Flag | Env | Description |
| --- | --- | --- |
| `--holder-key <alg:hex>` | `BOATRAMP_HOLDER_KEY` | Holder private key the parent block's `cnf` authorized. Required. |
| `--only-site <site>` | — | Restrict to a single site. |
| `--read-only` | — | Restrict to read-only operations. |
| `--not-after <unix-secs>` | — | Shorten the lifetime. |
| `--next-holder-pub <alg:hex>` | — | Permit one further attenuation by this key; omit to make this the last block. |

## `boatramp cluster`

Operate a self-hosted cluster's mesh membership. See
[Manage cluster mesh certificates](../how-to/cluster-certs.md).

| Sub-action | Description |
| --- | --- |
| `join-token` | Mint a single-use mesh join token, bound to the joining node's id and mesh public key. |
| `rotate-key` | Rotate the `--server` node's own mesh key, make-before-break (node-local). |
| `revoke` | Revoke a node from the mesh cluster-wide and drop it from the quorum (target the leader). |

## `boatramp security`

Inspect the operator security posture. See
[Security posture](../explanation/security-posture.md).

| Sub-action | Description |
| --- | --- |
| `explain` | Print the resolved posture from `boatramp.cfg` (profile + every knob's value and source). |

## `boatramp auth`

Generate/inspect the control-plane root key and edit the RBAC policy. See
[Authentication & authorization](../explanation/auth-model.md).

| Sub-action | Description |
| --- | --- |
| `init` | Generate a fresh ES256 root keypair. |
| `pubkey <alg:hex>` | Derive the public key from a root private key. |
| `policy get` | Print the active RBAC policy as JSON (the built-in default if none is stored). |
| `policy set <file.json>` | Replace the policy from a JSON file (validated server-side). |

## `boatramp gateway`

Publish a private service through the reverse-proxy gateway. See
[Expose a private service](../how-to/gateway.md).

| Sub-action | Description |
| --- | --- |
| `ls` | List declared upstreams and routes. |
| `upstream add <name> …` | Declare/replace an upstream: a single `target`, a pool of `--backend` URLs, or `--discover-host`/`--discover-port` for a DNS-discovered pool. |
| `upstream rm <name>` | Remove an upstream and any routes that reference it. |
| `route add <match> <upstream>` | Forward a path `match` to an upstream (appended to the end). |
| `route rm <match>` | Remove the route with this `match`. |

## `boatramp compute`

Manage Firecracker microVM compute workloads. See
[Run a container or microVM](../how-to/compute.md).

| Sub-action | Description |
| --- | --- |
| `ls` | List workloads and their reconcile state. |
| `get <name>` | Print one workload's desired state as JSON. |
| `set <name> …` | Create/update a workload from already-pushed rootfs/kernel blobs. |
| `build <name> …` | Build an ext4 rootfs from an OCI image, upload it, and set the workload (needs `mke2fs`). |
| `rm <name>` | Remove a workload (its replicas are stopped). |

`set` flags (`build` shares the runtime flags and replaces `--rootfs` with
`--image` + `--size-mib`):

| Flag | Default | Description |
| --- | --- | --- |
| `--rootfs <hash\|file\|url>` | — | The ext4 rootfs image (`set` only). A blob hash, a local file, or a URL (file/URL is uploaded for you). Required. |
| `--image <ref>` | — | OCI image to build a rootfs from (`build` only). Required. |
| `--kernel <hash\|file\|url>` | — | The vmlinux kernel the microVM boots — a blob hash, a local file, or a URL. Required. See [the kernel note](#the-kernel-blob). |
| `--size-mib <n>` | `1024` | ext4 rootfs image size (`build` only). |
| `--port <n>` | — | In-guest TCP port the app listens on. Required. |
| `--vcpus <n>` | `1` | Virtual CPUs. |
| `--mem-mib <n>` | `256` | Guest memory (MiB). |
| `--replicas <n>` | `1` | Desired replica count. |
| `--entrypoint <arg>` | — | In-guest entrypoint argv (repeatable). |
| `--env <K=V>` | — | Environment variable (repeatable). |
| `--restart <always\|…>` | `always` | Restart policy. |
| `--scale-to-zero` | `false` | Snapshot + stop when idle; restore on the next request. |
| `--isolation <trusted\|untrusted>` | `trusted` | `untrusted` forces a microVM (never a shared kernel). |
| `--region <name>` | — | Allowed placement region (repeatable; empty = any). |

### The kernel blob

A microVM boots an **uncompressed Linux kernel (`vmlinux`)** plus an ext4 rootfs.
`--kernel` accepts a local file, a URL, or the content-addressed **blob hash** of
a kernel already uploaded; a file or URL is uploaded for you, and the server
fetches the blob and boots it. Supply a Firecracker-compatible `vmlinux` (build
one, or use a released microVM kernel) and provision it once, shared across
workloads. See [Run a container or microVM](../how-to/compute.md).

## `boatramp blob`

Upload a file as a content-addressed blob — the general way to provision an
artifact (a microVM kernel, a prebuilt rootfs) that another command references by
hash.

| Sub-action | Description |
| --- | --- |
| `put <file>` | Upload a file as a blob; prints its hash (the key to pass to `compute set --kernel/--rootfs`). |

## `boatramp config`

Read and change the **dynamic daemon config** — operational knobs that converge
fleet-wide without a restart. See the
[dynamic daemon config reference](./daemon-config.md) and
[the configuration model](../explanation/config-model.md).

| Sub-action | Description |
| --- | --- |
| `get [key]` | Print the active config + its generation, or one key's value. |
| `set <key> <value>` | Set one dynamic key (`null`/`unset` clears it); converges fleet-wide, validated server-side. |
| `rollback` | Revert to the previous generation. |
| `apply -f <file>` | Replace the whole dynamic config from a JSON file. |
| `list` | List the dynamic (runtime-settable) keys. |
| `describe <key>` | A key's change class (`dynamic` vs `restart`). |

`config set` on a `restart`-class key (a trust anchor, posture, or listener
setting) fails with a pointer to `boatramp.cfg` rather than silently doing
nothing.

## `boatramp dns`

Configure DNS and issue wildcard preview certificates. Needs the `acme-dns`
feature. Every sub-action takes `--provider <name>`; each provider reads its
credentials from the environment (see [DNS providers](./dns-providers.md)).

| Sub-action | Description |
| --- | --- |
| `setup --provider <p> --host <h> --target <t>` | Create the `*.deploy.<host>` record so by-id preview subdomains resolve here. |
| `configure-domain <host> --provider <p> --target <t>` | Point a **verified** custom domain at this server (upsert A/AAAA/CNAME). `--proxied` for Cloudflare orange-cloud. |
| `cert --provider <p> --host <h>` | Issue/renew the `*.deploy.<host>` wildcard cert via ACME DNS-01. |

## `boatramp logs`

Tail a site's captured guest stdout/stderr. See
[Observe a running server](../how-to/observe.md).

| Flag | Default | Description |
| --- | --- | --- |
| `--stream <stdout\|stderr>` | both | Only show one stream. |
| `--limit <n>` | `200` | Number of recent lines to show. |
| `-f`, `--follow` | — | Keep polling for new lines (like `tail -f`). |

## `boatramp stats`

Show a site's handler invocation stats, consumer lag, and dead letters. No
command-specific flags.

## `boatramp dlq`

Purge or redrive a consumer topic's dead-letter queue. See
[Run background work](../how-to/background-work.md).

| Sub-action | Description |
| --- | --- |
| `purge <topic>` | Drop a topic's dead-lettered messages (records + payloads). |
| `redrive <topic>` | Requeue a topic's dead-lettered messages with a fresh attempt count. |

## `boatramp prune`

Delete orphan deployments and unreferenced blobs. See
[Prune & scrub](../how-to/prune-scrub.md).

| Flag | Default | Description |
| --- | --- | --- |
| `--dry-run` | — | Only report what would be removed. |
| `-y`, `--yes` | — | Delete without confirmation. |
| `--keep-last <n>` | — | Keep at most this many recent deployments per site. |
| `--keep-age <secs>` | — | Also keep any deployment activated within this many seconds. |
| `--grace <secs>` | `3600` | Never collect a deployment first seen this recently (races an in-flight deploy). |

## `boatramp scrub`

Verify every stored blob still hashes to its key (integrity scrub). No
command-specific flags.

## `boatramp cert-status`

Show cluster-managed certificate status (domain + expiry). No command-specific
flags.

## `boatramp completions` / `man`

| Command | Description |
| --- | --- |
| `completions <shell>` | Print a shell-completion script (`bash`, `zsh`, `fish`, …). |
| `man` | Render the man page to stdout (`boatramp man > boatramp.1`). |

## `boatramp cloudflare`

Generate (and optionally apply) a Cloudflare Containers deployment — boatramp's
cluster mode on CF Containers plus an edge Worker. Needs the `cluster` feature.
See [Deploy on Cloudflare Containers](../how-to/deploy-cloudflare.md).
