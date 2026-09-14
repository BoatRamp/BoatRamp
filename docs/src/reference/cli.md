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
| `--project <name>` | `BOATRAMP_PROJECT` | Target [project](../how-to/projects.md) for site-scoped commands. Falls back to `[publish].project` → the reserved `default` project; omitting it is byte-identical to pre-0.2.0. |
| — | `BOATRAMP_SERVER_PUBKEY` | Pin the control plane to a `--tls rpk` server's raw public key (the hex it prints at startup). See [Reach the control plane on day zero](../how-to/bootstrap-tls.md). |

## Commands

| Command | What it does |
| --- | --- |
| [`serve`](#boatramp-serve) | Run the HTTP server and publishing API. |
| [`project`](#boatramp-project) | Manage projects — the Workspace that owns sites, functions, and compute. |
| [`apply`](#boatramp-apply) | Reconcile a whole project (sites + functions + compute) from a declarative `apply.cfg` manifest. |
| [`migrate`](#boatramp-migrate) | Migrate a pre-0.2.0 control-plane store to the project-scoped layout. |
| [`sync <dir>`](#boatramp-sync) | Build (optional) and publish a folder as a new atomic deployment. |
| [`build`](#boatramp-build) | Run the configured build command only. |
| [`bundle`](#boatramp-bundle) | Bundle JS/TS + CSS in-process (`bundler` feature). |
| [`compose`](#boatramp-compose) | Fuse several Wasm components into one linked handler. |
| [`validate`](#boatramp-validate) | Parse and check a `project.cfg` (its `routing` section). |
| [`deployments`](#boatramp-deployments) | List a site's deployment history. |
| [`rollback`](#boatramp-rollback) | Roll back to the previous (or a specific) deployment. |
| [`status`](#boatramp-status) | Show a site's current deployment. |
| [`domain`](#boatramp-domain) | Attach/detach hostnames to a site. |
| [`alias`](#boatramp-alias) | Manage named pointers to deployments. |
| [`access`](#boatramp-access) | Configure visitor access control. |
| [`handlers`](#boatramp-handlers) | Manage a site's handler policy (enable/disable, import allowlist, caps, edge cache, cookie auth). |
| [`function`](#boatramp-function) | Manage top-level functions (deploy, invoke, triggers, local dev). |
| [`graphql`](#boatramp-graphql) | Manage a project's GraphQL admin (persisted-op safelist + federation subgraphs). |
| [`tenancy`](#boatramp-tenancy) | Manage a project's tenancy schema (the per-table tenant-key map). |
| [`secrets`](#boatramp-secrets) | Manage a project's internal sealed secret store. |
| [`email`](#boatramp-email) | Manage a project's SMTP delivery profiles (`email` feature). |
| [`sql`](#boatramp-sql) | Operator SQL to a managed database (apply a migration, run a query, probe reachability). |
| [`token`](#boatramp-token) | Manage control-plane API tokens. |
| [`cluster`](#boatramp-cluster) | Operate a cluster's dynamic-join membership. |
| [`operator`](#boatramp-operator) | Run the in-binary Kubernetes operator / print its manifests. |
| [`security`](#boatramp-security) | Inspect the operator security posture. |
| [`auth`](#boatramp-auth) | Generate/inspect the root key; edit the RBAC policy. |
| [`gateway`](#boatramp-gateway) | Publish a private service through the reverse-proxy gateway. |
| [`compute`](#boatramp-compute) | Manage microVM compute workloads. |
| [`blob`](#boatramp-blob) | Upload a file as a content-addressed blob. |
| [`config`](#boatramp-config) | Read/change the dynamic daemon config (no restart). |
| [`mcp`](#boatramp-mcp) | Run the Model Context Protocol server (drive boatramp from an AI agent). |
| [`dns`](#boatramp-dns) | Configure DNS and issue wildcard preview certs (`acme-dns` feature). |
| [`logs`](#boatramp-logs) | Tail a site's captured guest stdout/stderr. |
| [`stats`](#boatramp-stats) | Show handler stats, consumer lag, and dead letters. |
| [`dlq`](#boatramp-dlq) | Purge or redrive a consumer topic's dead-letter queue. |
| [`prune`](#boatramp-prune) | Delete orphan deployments and unreferenced blobs. |
| [`scrub`](#boatramp-scrub) | Verify every stored blob still hashes to its key. |
| [`cert-status`](#boatramp-cert-status) | Show cluster-managed certificate status. |
| [`completions <shell>`](#boatramp-completions-man) | Print a shell-completion script. |
| [`man`](#boatramp-completions-man) | Render the man page to stdout. |
| [`cloudflare`](#boatramp-cloudflare) | Deploy to Cloudflare Containers natively over the REST API (`cluster` feature). |

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
| `--blobs <fs\|s3\|gcs\|azure>` | `BOATRAMP_BLOBS` | `fs` | Blob backend (`s3`/`gcs`/`azure` are in the default build). |
| `--kv <slatedb\|memory\|cloudflare>` | `BOATRAMP_KV` | `slatedb` | KV backend (`cloudflare` is in the default build). |
| `--kv-s3` | `BOATRAMP_KV_S3` | `false` | Run the SlateDB KV on the S3/R2 object store (reusing the `--blobs s3` config) instead of local disk — durable metadata for a volumeless container. |
| `--kv-s3-prefix <prefix>` | `BOATRAMP_KV_S3_PREFIX` | `_kv` | Key prefix for the `--kv-s3` store within the bucket. |
| `--s3-bucket <name>` | `BOATRAMP_S3_BUCKET` | — | S3/R2 bucket (`--blobs s3` and/or `--kv-s3`). |
| `--s3-endpoint <url>` | `BOATRAMP_S3_ENDPOINT` | — | S3 endpoint (MinIO / R2). |
| `--s3-region <region>` | `BOATRAMP_S3_REGION` | — | S3 region (R2: `auto`). |
| `--s3-path-style` | `BOATRAMP_S3_PATH_STYLE` | `false` | Use path-style S3 addressing (R2 accepts it). |
| `--gcs-bucket <name>` | `BOATRAMP_GCS_BUCKET` | — | GCS bucket (`--blobs gcs`). Credentials via Application Default Credentials. |
| `--gcs-endpoint <url>` | `BOATRAMP_GCS_ENDPOINT` | — | GCS endpoint (a `fake-gcs-server` emulator). |
| `--gcs-anonymous` | `BOATRAMP_GCS_ANONYMOUS` | `false` | Skip GCS credential resolution (the emulator). |
| `--azure-account <name>` | `BOATRAMP_AZURE_ACCOUNT` | — | Azure storage account (`--blobs azure`). |
| `--azure-container <name>` | `BOATRAMP_AZURE_CONTAINER` | — | Azure container (`--blobs azure`). |
| `--azure-access-key <key>` | `BOATRAMP_AZURE_ACCESS_KEY` | — | Azure shared-key auth (prefer the env var). |
| `--azure-emulator` | `BOATRAMP_AZURE_EMULATOR` | `false` | Use the Azurite emulator (well-known dev credentials). |
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
| `--auto-migrate` | — | `false` | Migrate a pre-0.2.0 store to the project-scoped layout at startup instead of refusing to serve. The migration is online, idempotent, and resumable; see [`migrate`](#boatramp-migrate) for the explicit operator step. |
| `--cluster-rate-limit` | `BOATRAMP_CLUSTER_RATE_LIMIT` | `false` | Rate-limit cluster-wide via the KV, not per node. |
| `--shared-cache-coherence` | `BOATRAMP_SHARED_CACHE_COHERENCE` | `false` | Keep the config cache coherent across processes sharing one KV. |
| `--cluster-init` | `BOATRAMP_CLUSTER_INIT` | `false` | **Found** a new cluster from this node (explicit, one-time). See [Deploy a cluster](../how-to/deploy-cluster.md). |
| `--cluster-join <ticket>` | `BOATRAMP_CLUSTER_JOIN` | — | **Join** an existing cluster with a one-paste ticket from `cluster add`. |
| `--cluster-advertise-addr <url>` | `BOATRAMP_CLUSTER_ADVERTISE_ADDR` | `https://<cluster.listen>` | This node's reachable mesh URL peers dial (set behind NAT / `0.0.0.0`). |

```sh
boatramp serve --config boatramp.cfg \
  --addr 0.0.0.0:8080 --tls acme --acme-domain pad.example.com
```

## `boatramp project`

Manage [projects](../how-to/projects.md) — the Workspace that owns sites,
functions, and compute, and is the tenant boundary a handler's row-level scope
resolves to. Takes the common `--server` flag.

| Sub-action | Description |
| --- | --- |
| `create <name>` | Create a project. `<name>` is a slug (no `/`). Flags: `--display <name>`, `--description <text>`, `--region <name>` (default region for the project's compute/replicas). |
| `ls` | List all projects. |
| `show <name>` | Print one project's full record. |
| `rm <name>` | Delete a project. Refused (with an enumeration of what remains) while it still owns resources, and always for the reserved `default`. `--force` cascades the teardown (deprovision managed DBs, remove compute workloads + volumes, delete functions + sites, clear secrets + GraphQL safelist, then remove the project); `--dry-run` prints what would be destroyed and changes nothing; `--force` prompts for a typed-name confirmation unless `--yes`/`-y` (required when stdin isn't a terminal). |

## `boatramp apply`

Reconcile a whole project — its member sites (each a content dir + optional
build + routing + config), top-level functions, and compute workloads — from one
declarative RON manifest, in a single pass. Sites reuse the content-addressed
`sync` flow (upload only the missing blobs, then activate); functions and compute
are create-or-replace. `apply` is **pure upsert and never prunes**, so declarative
and imperative (CLI/API) management coexist. See
[Declare a project with `apply`](../how-to/apply.md).

| Flag | Default | Description |
| --- | --- | --- |
| `-f`, `--file <path>` | `apply.cfg` | The project manifest (RON). |
| `--server <url>` | — | Server base URL (overrides `[publish].server`; env `BOATRAMP_SERVER`). |
| `--dry-run` | — | Print the plan (what would be built/deployed/activated) and mutate nothing. |
| `--build` | — | Run each site's configured build command before publishing it. |

The target project is the manifest's `project:` field, else the global
`--project` / `default`.

## `boatramp migrate`

Migrate a pre-0.2.0 control-plane store to the project-scoped layout (mutable
per-name records re-key under `project/<proj>/…`; no content-addressed body moves).
The migration is online, idempotent, and resumable. `serve` refuses an unmigrated
store unless started with [`--auto-migrate`](#boatramp-serve). See
[Upgrade a store to project scoping](../how-to/migrate-to-projects.md).

| Flag | Default | Description |
| --- | --- | --- |
| `--data-dir <path>` | `BOATRAMP_DATA_DIR` | Blob + KV root (the store to migrate). |
| `--kv <slatedb\|memory\|cloudflare>` | `slatedb` | KV backend. |
| `--dry-run` | — | Scan and print the rewrites; write nothing. |
| `--stage` | — | Copy-only pass: write the new keys but leave the old ones for a soak/rollback window (the `2-dual` state). |
| `--finalize` | — | Delete the old-layout keys left by an earlier `--stage`, completing the migration. |

A plain `boatramp migrate` (no `--stage`) copies and finalizes in one shot.

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

## `boatramp compose`

Fuse a root ("edge") component with one or more plugin components into a single
linked component, in-process — no external toolchain, no network hop. The fused
component's exports are unchanged (still e.g. `wasi:http/incoming-handler`); only
the imports a plugin satisfies are linked internally, while host imports
(`wasi:http`, `sql`, `kv`, …) stay imported for the runtime to supply. Deploy the
one fused `.wasm` through the normal content-addressed path. See
[Compose components into one handler](../how-to/compose.md).

| Flag | Description |
| --- | --- |
| `--edge <COMPONENT>` | The root component: exports the handler world, imports what the plugins provide. |
| `--plugin <COMPONENT>` | A plugin whose exports satisfy one of the edge's imports. Repeatable. |
| `-o`, `--output <PATH>` | Where to write the fused component. |

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

## `boatramp handlers`

Manage a site's handler policy — enable/disable, the import allowlist, resource
caps, the edge response cache, and browser cookie auth. See
[Handler host bindings](../how-to/handler-bindings.md).

| Sub-action | Description |
| --- | --- |
| `show` | Show the site's current handler policy. |
| `enable [--allow <import>…] [--max-memory-mb <n>] [--max-timeout-ms <n>] [--max-concurrency <n>] [--max-fuel <n>]` | Enable handlers on the site. `--allow` (repeatable) **replaces** the whole import allowlist when given; the cap flags are optional. |
| `disable` | Disable handlers on the site (keeps the allowlist + caps for a later re-enable). |
| `allow <import>…` | Add interface(s) to the site's import allowlist. |
| `deny <import>…` | Remove interface(s) from the site's import allowlist. |
| `cache enable [--max-entry-bytes <n>] [--max-ttl-secs <n>]` / `cache disable` | Configure the edge response cache for handler routes. |
| `cookie-auth set --cookie-name <c> [--allowed-origin <o>…]` / `cookie-auth clear` | Treat the named cookie as the application bearer (with an optional cross-origin CSRF allowlist), or turn cookie session auth off. |

## `boatramp function`

Manage top-level [functions](../how-to/functions.md) — deploy, roll back/alias,
invoke, triggers, and the local dev harness. Takes a `--server` flag; site-scoped
sub-actions also read `--site`.

| Sub-action | Description |
| --- | --- |
| `ls [--site <s>]` | List functions (optionally for one site). |
| `get <site>/<name>` | Show one function by its `<site>/<name>`. |
| `deploy <name> <wasm> [--substrate wasm\|microvm\|container] [--webhook-secret-env <var>] [--webhook-ingress-topic <t>]` | Deploy a version of a function from a component `.wasm` (uploaded as a blob). |
| `rollback <name> --to <version>` | Roll a function's active version back to a specific version. |
| `alias <name> <label> <version>` | Point an alias label (e.g. `prod`, `staging`) at a version. |
| `rm <name>` | Remove a top-level function. |
| `invoke <name> [--data <body>\|--data-file <path>] [--content-type <ct>] [--async] [--idempotency-key <k>] [--version <v>]` | Invoke a function; reads the body from `--data`/`--data-file`/stdin and prints the response. `--async` enqueues and prints an invocation id. |
| `invocation <name> <id>` | Show a durable (async) invocation's status/result by id. |
| `usage <name>` | Show a function's usage aggregate (invocations, duration, bytes). |
| `trigger add\|ls\|rm` | Manage a function's scheduled/event triggers: `add` takes exactly one of `--cron` / `--queue` / `--blob`. |
| `init <name> [--lang rust\|js\|python] [--dir <path>]` | Scaffold a new function project from a language template. |
| `build [<dir>]` | Build a function project to a `wasi:http` component; prints the produced `.wasm` path. |
| `test <wasm> [--path <p>] [--method <m>] [--body <b>] [--content-type <ct>] [--expect-status <n>] [--expect-body <substr>]` | Run a component locally against one request and assert on the response. |
| `dev <wasm> [--port <n>]` | Serve a component locally on an HTTP port (the local dev harness). |

## `boatramp graphql`

Manage a project's GraphQL admin — the persisted-operation safelist and the
federation subgraph registry. See [Serve a GraphQL API](../how-to/graphql.md).

| Sub-action | Description |
| --- | --- |
| `safelist add [<op>\|--file <path>]` | Register a trusted operation (query text inline or from a file). |
| `safelist ls` | List the registered trusted operations. |
| `safelist rm <hash>` | Remove a trusted operation by its hash. |
| `subgraph put <name> <sdl-file>` | Publish (or replace) a Wasm subgraph from its SDL file. |
| `subgraph sql <name> <json-file>` | Publish (or replace) a SQL subgraph from a request JSON file (`{site, config}`). |
| `subgraph function <name>` | Register (or refresh) a function subgraph by introspecting the deployed function of the same name. |
| `subgraph rm <name>` | Remove a subgraph. |
| `supergraph` | Print the composed supergraph SDL. |

## `boatramp tenancy`

Manage a project's [tenancy schema](./siteconfig.md#tenancyschema) — the per-table
tenant-key map that scopes guest `sql`/`orm` queries. `Project·Admin`. See
[Isolate tenants in one database](../how-to/tenant-isolation.md).

| Sub-action | Description |
| --- | --- |
| `show` | Print the project's current tenancy schema as JSON (a project with none prints the default `tenant_id`/no-tables schema). |
| `apply <file>` | Replace the project's tenancy schema from a JSON file (as produced by `tenancy show`). |
| `clear` | Clear the schema, reverting to legacy single-column scoping. Idempotent. |

## `boatramp secrets`

Manage a project's internal, sealed [secret store](../how-to/handler-bindings.md)
(a guest names a secret as `boatramp:<name>` in its `secrets` map). The store
holds only sealed bytes — the API never returns a value.

| Sub-action | Description |
| --- | --- |
| `set <name> [--stdin\|--file <path>\|--value <v>]` | Seal `value` under `name` (setting an existing name rotates it). Prefer `--stdin`/`--file` so the plaintext doesn't hit argv/history. |
| `rotate <name> …` | Alias for `set` (overwrite in place), for intent-clarity. |
| `ls` | List the project's secrets: name / revision / last-updated (never a value). |
| `rm <name>` | Remove a secret by name. |

## `boatramp email`

Manage a project's SMTP delivery profiles (a guest's `email` capability selects
one by name). Needs the `email` feature. Passwords stay sealed — never returned.
See [Send email from a function](../how-to/email.md).

| Sub-action | Description |
| --- | --- |
| `set <name> [--host <h>] [--port <n>] [--security starttls\|tls\|plaintext] [--username <u>] [--password/--password-stdin] [--no-auth] [--from <addr>] [--durable <bool>]` | Create or **update** an SMTP profile — fields you pass overwrite, fields you omit keep their stored value (the sealed password is preserved unless you pass a new one). `--host` + `--from` are required on create. |
| `ls` | List the project's SMTP profiles (redacted). |
| `show <name>` | Show one profile's redacted config. |
| `rm <name>` | Remove a profile by name. |

## `boatramp sql`

Operator SQL to a managed database. See [Handler bindings](../how-to/handler-bindings.md).

| Sub-action | Description |
| --- | --- |
| `exec [--db <name>] [--file <path>]` | Apply a migration **script** (multiple statements — `CREATE EXTENSION`, tables, RLS, chained DDL/DML) to a managed database, from `--file` or stdin. `--db` is the binding name (empty = the site's default database). |
| `query <sql> [--db <name>] [--format table\|json]` | Run one row-returning query and print the result. |
| `ping [--db <name>]` | Actively TCP-probe each replica of a managed database — a reachability check that bypasses the stored-health gate `query` trips on (distinguishes "the DB is down" from "up but the resolver won't serve it"). Admin-scoped. |

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
| `--role <role>` | Role, repeatable: `<role>` (global), `<role>:<project>/<site>` (site-scoped), or `<role>:<project>` (project-scoped). A legacy `<role>:<site>` is read as `default/<site>`. Required. See the [RBAC reference](./rbac.md). |
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

Operate a self-hosted cluster's dynamic-join membership. See
[Deploy a self-hosted cluster](../how-to/deploy-cluster.md).

| Sub-action | Description |
| --- | --- |
| `add --root-pubkey <k> [--seed <addr>] [--ttl-secs <n>] [--print-token-only]` | Print a one-paste **join ticket** (single-use token + seed + root anchor) for a new node. |
| `status [--full]` | Show membership address-primary (ADDRESS/ROLE/NODE/STATE); `--full` shows whole node ids. |
| `promote <address\|node>` | Promote a caught-up learner to a voter (build a quorum on bare metal). Target the leader. |
| `remove <address\|node>` | Remove a node (subsumes `revoke`): revoke trust cluster-wide + drop from the quorum. Target the leader. |
| `join-token [--ttl-secs <n>]` | Mint a raw single-use bearer join token (low-level; prefer `add`). |
| `rotate-key` | Rotate the `--server` node's own mesh key, make-before-break (node-local). |
| `revoke <node>` | Revoke a node by raw node id (low-level; prefer `remove`). |

## `boatramp operator`

Run the in-binary Kubernetes operator, or print its install manifests. See
[Run on Kubernetes](../how-to/kubernetes.md). The `operator` feature is in the
default (batteries-included) build; a minimal build re-adds it with `--features operator`.

| Sub-action | Description |
| --- | --- |
| `run [--namespace <ns>]` | Run the controller: watch the boatramp CRDs and reconcile them. |
| `crds` | Print the CRD YAML (`BoatRampCluster` / `Site` / `Function`). |
| `manifests` | Print the full install bundle: CRDs + least-privilege RBAC + the operator Deployment. |

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
| `pubkey --private-key <alg:hex>` | Derive the public key from a root private key. |
| `pin --root-pubkey <k>` | Resolve a `--tls rpk` server's TLS pin from the root anchor (prints `BOATRAMP_SERVER_PUBKEY`). |
| `rotate-root [--add <pubkey>] [--retire <pubkey>]` | Make-before-break root rotation: trust a new anchor, or retire an old one; no flag lists the extra anchors. See [Migrate the root key](../how-to/migrate-root-key.md). |
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
| `rm <name>` | Remove a workload (its replicas are stopped). Its persistent volume is left on disk — reclaim it with `compute volume rm`. |
| `exec <name> -- <cmd…>` | Run a command inside a running workload replica (docker-exec style) — e.g. pipe a SQL file into `psql`, or run `pg_dump`. `--stdin` feeds this process's stdin to the command. Requires the `allow_compute_exec` posture; container + docker backends only. |
| `volume ls` | List persistent volumes on the node (`NAME`, `SIZE`, and whether a registered workload still references it). |
| `volume rm <name>` | Remove a persistent volume. Refused (`409`) while a registered workload's active spec still mounts it, unless `--force`. |
| `status [<workload>] [--format table\|json]` | Show observed per-replica runtime state — stored health, lifecycle phase, assigned IP:port, age vs startup grace, backend (the record the endpoint resolver reads). Node-global; admin-scoped. |
| `set-health <workload> <replica> --healthy <true\|false>` | Force one replica's stored health flag — the escape hatch when a recovered replica is stuck `healthy=false` and the resolver won't serve it. Node-global; admin-scoped. |
| `reconcile` | Force the reconcile loop to run a convergence pass now (the "kick it" lever for a workload stuck mid-reconcile). Fire-and-forget; follow with `compute status`. Node-global; admin-scoped. |
| `restart <workload> <replica>` | Stop one replica and let the reconcile loop relaunch a fresh one (re-running IP allocation) — the live workaround for a wedged replica or a stale IP. Node-global; admin-scoped. |
| `ip ls` | List every replica's assigned IP (`IP`/`OWNER`/`HEALTHY`), flagging duplicate-IP collisions. Node-global; admin-scoped. |
| `dns ls` | List internal service-discovery names and the healthy replica IPs each resolves to. Node-global; admin-scoped. |
| `dns resolve <workload>` | Resolve one workload's internal name (in the `--project` tenant) to its healthy replica IPs — exactly as a same-project peer's lookup would. Node-global; admin-scoped. |
| `netdiag <workload>` | Actively TCP-probe a workload's replicas from the node, alongside their stored state — `REACHABLE=yes` + `HEALTHY=no` is the reachable-but-not-served signature. Node-global; admin-scoped. |

`set` takes exactly one **root-filesystem source** (matched to the substrate);
`build` instead takes `--image` + `--size-mib` and produces a `--rootfs` source:

| Flag | Default | Description |
| --- | --- | --- |
| `--image <ref>` | — | An OCI image reference the runtime pulls (`set`: docker/cloudflare). On `build`, the OCI image to build an ext4 rootfs *from*. |
| `--tar <hash\|file\|url>` | — | A tar rootfs archive for the native `container` substrate (`set` only). A blob hash, a local file, or a URL (file/URL is uploaded). |
| `--rootfs <hash\|file\|url>` | — | A rootfs filesystem image (a block device — `ext4` by default, or any filesystem the guest kernel mounts) for the `firecracker` micro-VM (`set` only). A blob hash, a local file, or a URL (file/URL is uploaded). |
| `--kernel <hash\|file\|url>` | — | The vmlinux kernel the micro-VM boots (a `--rootfs` / `build` workload) — a blob hash, a local file, or a URL. See [the kernel note](#the-kernel-blob). |
| `--size-mib <n>` | `1024` | ext4 rootfs image size (`build` only). |
| `--port <n>` | — | In-guest TCP port the app listens on. Required. |
| `--vcpus <n>` | `1` | Virtual CPUs. |
| `--mem-mib <n>` | `256` | Guest memory (MiB). |
| `--replicas <n>` | `1` | Desired replica count. |
| `--entrypoint <arg>` | — | In-guest entrypoint argv (repeatable). |
| `--env <K=V>` | — | Environment variable (repeatable). |
| `--restart <always\|…>` | `always` | Restart policy. |
| `--scale-to-zero` | `false` | Snapshot + stop when idle; restore on the next request. |
| `--startup-grace-secs <n>` | `30` | Seconds a freshly launched replica has to become healthy before a still-unhealthy one is treated as a broken launch (stop + relaunch). Raise it for a slow-initializing image (a stock database's first `initdb`). Managed databases use a larger per-engine default (Postgres 60, MySQL 120). |
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

## `boatramp mcp`

Run the [Model Context Protocol](https://modelcontextprotocol.io) server so an AI
agent (Claude, Codex, …) can drive one or more instances. Bare `boatramp mcp`
serves over **stdio** (what a desktop agent spawns); the server can also be reached
over **HTTP** at `/mcp` on any `boatramp serve` (on by default). See
[Drive boatramp from an AI agent](../how-to/mcp.md).

| Sub-action | Description |
| --- | --- |
| _(none)_ / `serve` | Serve the MCP protocol over stdio until the client disconnects. |
| `setup add <name> --server <url> [flags]` | Register an instance in `~/.config/boatramp/mcp.toml`. |
| `setup list` | List the registered instances. |
| `setup remove <name>` | Remove a registered instance. |

`setup add` flags: `--token <spec>` (an `env:VAR` / `path:/file` / literal token),
`--holder-key <spec>` (a `cnf` holder key for DPoP), `--server-pubkey <hex>` (pin
the server's raw public key), `--insecure` (skip TLS verification). Secrets are
stored as **specs**, never resolved into the file.

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

Tail a site's — or a standalone function's — captured guest stdout/stderr. See
[Observe a running server](../how-to/observe.md).

| Flag | Default | Description |
| --- | --- | --- |
| `--site <name>` | `BOATRAMP_SITE` | Site whose guest logs to tail. Mutually exclusive with `--function`. |
| `--function <name>` | — | Tail a **standalone function**'s captured stdout/stderr instead of a site (a GraphQL subgraph, auth function, or worker invoked via `invoke`, whose `println!`/`eprintln!` is otherwise unreadable). Scoped to `--project`; **takes precedence over `--site`**. |
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

Deploy boatramp to Cloudflare Containers **natively** over the CF REST API (no
wrangler) — behind an edge Worker, as a single **durable** instance with all
state in R2. Needs the `cluster` feature and `CLOUDFLARE_ACCOUNT_ID` +
`CLOUDFLARE_API_TOKEN` (Workers Scripts, Containers, R2, D1 scopes). A multi-node
Raft quorum isn't possible on the platform, so only `--quorum 1` deploys. See
[Deploy on Cloudflare Containers](../how-to/deploy-cloudflare.md).

| Flag | Default | Description |
| --- | --- | --- |
| `--region <code>` | — | CF region to run in (repeatable; on CF only one deploys). |
| `--primary <code>` | — | The primary region (must be one of `--region`). |
| `--quorum <n>` | `3` | Voting nodes — must be `1` on Cloudflare (single durable instance). |
| `--image <ref>` | `boatramp:latest` | Container image (pushed to a registry CF can pull). |
| `--domain <host>` | — | Public domain the edge Worker serves (repeatable). |
| `--r2-bucket <name>` | `boatramp-blobs` | R2 bucket for durable blobs + the SlateDB KV. |
| `--d1 <name>` | `boatramp-sql` | D1 database for the handler `sql` binding. |
| `--auth-root-private-key <alg:hex>` | env `BOATRAMP_AUTH_ROOT_PRIVATE_KEY` | Control-plane root key; generated + printed once if unset. |
| `--container-env <KEY=VALUE>` | — | Extra env for the container (repeatable) — e.g. a handler's webhook secret. |
| `--dry-run` | `false` | Print the plan; mutate nothing. |
| `--emit-artifacts <dir>` | — | Write reference artifacts (Dockerfile, edge Worker, node configs) instead of deploying. |
