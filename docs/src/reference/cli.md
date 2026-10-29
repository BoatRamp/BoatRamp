# CLI

`boatramp` is one binary: the server (`serve`) and every client command. This
page documents each command. Any command also prints its own flags with
`boatramp <command> --help`, and group commands list their sub-actions with
`boatramp <command> help`.

Precedence for any overridable value: **explicit CLI flag > environment variable > config
file > built-in default** (one layered resolver — see [the configuration
model](../explanation/config-model.md)). Project commands read `project.cfg`; `serve` and the
daemon operations (`migrate`, `blob`, `token`) read `boatramp.cfg`, and the `BOATRAMP_*`
daemon-config env vars resolve the same for all of them.

## Global flags

| Flag | Description |
| --- | --- |
| `--config <path>` | Config file (`project.cfg` for client commands, `boatramp.cfg` for `serve`). |
| `-h`, `--help` | Print help for the binary or a subcommand. |
| `-V`, `--version` | Print the version. |
| `--output-format <human\|json>` | How command results are rendered: `human` (default) or `json`. Global — accepted on any subcommand; env `BOATRAMP_OUTPUT_FORMAT`. |

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
| [`capabilities`](#boatramp-capabilities) | Print the capability surface this host implements, or check a component's `requires` against this build. |
| [`deployments`](#boatramp-deployments) | List a site's deployment history. |
| [`rollback`](#boatramp-rollback) | Roll back to the previous (or a specific) deployment. |
| [`status`](#boatramp-status) | Show a site's current deployment. |
| [`domain`](#boatramp-domain) | Attach/detach hostnames to a site. |
| [`alias`](#boatramp-alias) | Manage named pointers to deployments. |
| [`access`](#boatramp-access) | Configure visitor access control. |
| [`handlers`](#boatramp-handlers) | Manage a site's handler policy (enable/disable, import allowlist, caps, edge cache, cookie auth). |
| [`compression`](#boatramp-compression) | Configure on-the-fly response compression for a site (`compression` feature). |
| [`security-headers`](#boatramp-security-headers) | Configure a site's response security headers (HTTPS redirect, HSTS, CSP, X-Frame-Options). |
| [`function`](#boatramp-function) | Manage top-level functions (deploy, invoke, triggers, local dev). |
| [`workflow`](#boatramp-workflow) | Define + run declarative function-orchestration workflows. |
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
| [`db`](#boatramp-db) | Inspect the project's declarative managed databases (read-only). |
| [`blob`](#boatramp-blob) | Upload artifacts, and migrate/drain/purge the node blob backend. |
| [`kv`](#boatramp-kv) | Maintain the control-plane SlateDB store — WAL/manifest recovery, checkpoint, compact, portable dump (`slatedb` feature). |
| [`config`](#boatramp-config) | Read/change the dynamic daemon config (no restart); migrate an `apply` manifest. |
| [`mcp`](#boatramp-mcp) | Run the Model Context Protocol server (drive boatramp from an AI agent). |
| [`dns`](#boatramp-dns) | Configure DNS and issue wildcard preview certs (`acme-dns` feature). |
| [`logs`](#boatramp-logs) | Tail a site's captured guest stdout/stderr. |
| [`stats`](#boatramp-stats) | Show handler stats, consumer lag, and dead letters. |
| [`dlq`](#boatramp-dlq) | Purge or redrive a consumer topic's dead-letter queue. |
| [`queue`](#boatramp-queue) | Inspect a consumer topic's live work-queue (peek/replay/groups) and manage its delivery. |
| [`prune`](#boatramp-prune) | Delete orphan deployments and unreferenced blobs. |
| [`scrub`](#boatramp-scrub) | Verify every stored blob still hashes to its key. |
| [`cert-status`](#boatramp-cert-status) | Show cluster-managed certificate status. |
| [`version`](#boatramp-version) | Report the boatramp version — this binary's, or a running daemon's. |
| [`completions <shell>`](#boatramp-completions-man) | Print a shell-completion script. |
| [`man`](#boatramp-completions-man) | Render the man page to stdout. |
| [`cloudflare`](#boatramp-cloudflare) | Deploy to Cloudflare Containers natively over the REST API (`cluster` feature). |
| [`forward`](#boatramp-forward) | Forward a local port to an in-cluster service over the overlay fabric (`overlay` feature). |
| [`expose`](#boatramp-expose) | Publish a local service INTO the cluster over the overlay fabric — the reverse of `forward` (`overlay` feature). |
| [`overlay`](#boatramp-overlay) | Admin tooling for overlay forwarding: mint a dial/publish capability + ticket, pair devices, administer the flow policy (`overlay` feature). |
| [`tunnel`](#boatramp-tunnel) | Run a local proxy daemon that reaches overlay services by name — SOCKS5 (+ optional HTTP CONNECT), or a full TUN virtual interface with `--tun` (the extra `tun` feature) (`overlay` feature). |
| [`connect`](#boatramp-connect) | One-shot dial of a single overlay service, splicing stdin/stdout (`overlay` feature). |

Exit status is `0` on success and non-zero on failure; see
[Errors & exit codes](./errors.md).

## `boatramp serve`

Run the server: selects backends, TLS, auth, and (with the `cluster` feature)
cluster mode. The `cluster:` and `compute:` sections are configured in
[`boatramp.cfg`](./boatramp-cfg.md), not on the command line.

The config file (`--config <path>`, default `boatramp.cfg`) is RON or JSON —
auto-detected by extension; pass `--format <ron|json>` to override (e.g. a
Nickel-generated config on a non-`.json` path). See
[Author configs in RON or JSON](../how-to/config-formats.md).

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
| `doctor` | Scan for resource identifiers the v0.7.0 strict slug allowlist no longer accepts (`Project·Read`, read-only) — a CI preflight for that breaking cutover. Lists each non-conforming name, why it fails, what it affects, and a suggested fix; exits non-zero if any are found. |
| `rm <name>` | Delete a project. Refused (with an enumeration of what remains) while it still owns resources, and always for the reserved `default`. `--force` cascades the teardown (deprovision managed DBs, remove compute workloads + volumes, delete functions + sites, clear secrets + GraphQL safelist, then remove the project); `--dry-run` prints what would be destroyed and changes nothing; `--force` prompts for a typed-name confirmation unless `--yes`/`-y` (required when stdin isn't a terminal). |
| `migrate {apply,dry-run,baseline,status}` | Drive the project's owner-gated schema migrations for a managed database. The mutating verbs run as the project's non-superuser owner role and need `Project·Admin`; `status` needs `Project·Read`. See [In-app schema migrations](../how-to/in-app-migrations.md). |
| `repair [--apply]` | Repair a managed tenant's provisioning drift (the owner-model retrofit that unblocks `migrate`). Defaults to a dry-run; `--apply` converges. Fixes provisioning only — never touches schema or data. `Project·Admin`. |
| `tenant-secrets {set,rotate,ls,rm}` | Manage the project's **per-tenant** sealed secrets — each tenant's own third-party credential, sealed server-side under `(tenant, name)`, each verb taking `--tenant <t>`. Distinct from the per-project `boatramp secrets` env store. Mutating verbs need `Secrets·Write`; `ls` needs `Secrets·Read`. |
| `export <name> --out <file>` | Stream the project (managed-DB dumps + control-plane KV slice + blobs) to a portable `BRPROJ` bundle, from a **running node** (`Project·Admin` on the project). See [Export, import & clone a project](../how-to/clone-project.md). |
| `export <name> --resumable <DIR> [--mode <differential\|incremental> --base <DIR>]` | Write a **resumable** member-object directory under the node's `[serve] resumable_export_dir` base (a re-run skips members already present + SHA-verified) instead of streaming a file. `--mode`/`--base` take a **delta** against a prior resumable `--base` dir — `incremental` (vs the parent, forming a chain) or `differential` (vs a fixed base); omit for a full resumable export. `--out` and `--resumable` are mutually exclusive. See [Incremental & true-delta export](../how-to/delta-export.md). |
| `import <name> --in <file>` | Import a `BRPROJ` bundle into a project on a **running node** (`Project·Admin` on the target project); a dry-run plan by default, `--apply` executes. See [Export, import & clone a project](../how-to/clone-project.md). |
| `import <name> --resumable <DIR> [--apply]` | Import a **resumable**/delta member-object directory of this name on the node (the output of a resumable export). A delta's whole chain (base → … → this link) is resolved and applied in order. `--in` and `--resumable` are mutually exclusive; dry-run by default. |
| `import <name> --clone-from <URL> [--clone-source-project <P>] [--clone-source-token-file <FILE>] [--clone-data-only] [--clone-verify] [--apply]` | **Streaming clone:** pull the project directly from a live **source** node (an `https://` URL) and restore each member as it streams in — no `BRPROJ` bundle staged anywhere (manifest-diff resumable, blobs bucket → bucket). `--clone-source-project` defaults to the target name; the source-node `Project·Admin` token comes from `--clone-source-token-file` or `BOATRAMP_CLONE_SOURCE_TOKEN` (sent in a header, never on argv). Needs `Project·Admin` on **both** the source and the target. `--clone-from` is mutually exclusive with `--in`/`--resumable`. The **default dry-run is a cheap plan** (manifest + diff only — no transfer); `--apply` streams + commits with live progress; `--clone-verify` is a stream-level validate without mutating. See [Streaming clone](../how-to/clone-project.md#streaming-clone-pull-from-a-live-source-node). |

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
| `-f`, `--file <path>` | `apply.cfg` | The project manifest (RON or JSON — auto-detected by extension). |
| `--format <ron\|json>` | auto | Manifest format. Auto-detected from the extension (`.json` ⇒ JSON, else RON); set explicitly when piping Nickel/JSON to a non-`.json` path. See [Author configs in RON or JSON](../how-to/config-formats.md). |
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

> **Three unrelated `migrate` verbs.** Don't confuse them:
> - **`boatramp migrate`** (this top-level command) — the one-time pre-0.2.0
>   control-plane store re-key to the project-scoped layout.
> - **[`boatramp blob migrate`](#boatramp-blob)** — an offline, node-local copy of the
>   whole blob backend from one storage config to another (fs→cloud, region→region).
> - **[`boatramp config migrate`](#boatramp-config)** — a client-side upgrade of an
>   `apply` manifest to the current schema `version`.
>
> They share only the word "migrate"; each help text cross-disambiguates.

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

## `boatramp capabilities`

Print the capability surface this host implements — the `boatramp:handlers`
package version, the imports a deploy may declare, and the capability features a
guest may `require` in its manifest (each with its stability). Same data as
`GET /api/capabilities`. The global `--output-format json` emits the raw surface
object. With no flag it is a plain report; `--check <component.wasm>` is the
shift-left CI gate — it scans a component's manifest `requires` and exits
non-zero if this build is missing any required capability (needs the `handlers`
feature).

| Flag | Description |
| --- | --- |
| `--check <component.wasm>` | Scan a component's `requires` against this build and exit non-zero on a gap (CI gating), instead of printing the surface. |

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

## `boatramp compression`

Turn on-the-fly response compression on or off for a site (edits the site's
`compression` policy over the control-plane API). Needs the `compression`
feature. Takes the common `--server` / `--site` flags.

| Sub-action | Description |
| --- | --- |
| `show` | Show the site's current compression policy (enabled + min-size). |
| `on [--min-size <bytes>]` | Enable compression; `--min-size` only compresses responses at least this many bytes. |
| `off` | Disable response compression. |

## `boatramp security-headers`

Configure a site's response **security headers** — the HTTP→HTTPS redirect,
HSTS, Content-Security-Policy, and X-Frame-Options (edits the site's `security`
policy over the control-plane API). This is the **site**'s edge headers,
distinct from [`boatramp security`](#boatramp-security) (the operator posture).
Takes the common `--server` / `--site` flags.

| Sub-action | Description |
| --- | --- |
| `show` | Show the site's current security-header policy. |
| `https-redirect <on\|off>` | Turn the HTTP→HTTPS redirect on or off. |
| `hsts set [--max-age <secs>] [--include-subdomains] [--preload]` / `hsts off` | Set `Strict-Transport-Security` (`--max-age` default `31536000`), or remove it. |
| `csp set <policy>` / `csp clear` | Set or remove the `Content-Security-Policy` header. |
| `frame-options set <value>` / `frame-options clear` | Set `X-Frame-Options` (`DENY` / `SAMEORIGIN`), or remove it. |

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

## `boatramp workflow`

Define and run declarative **function-orchestration workflows** — a small DAG of
function-invocation steps. `define` uploads the step DAG (validated
server-side), `run` starts a durable run the executor advances, and `run-status`
polls it. Takes a `--server` flag.

| Sub-action | Description |
| --- | --- |
| `define <name> --file <path>` | Define/replace a workflow from a JSON steps file (a bare array, or an object with a `steps` array; `-` = stdin). |
| `ls` | List defined workflows. |
| `get <name>` | Show one workflow definition (its steps). |
| `run <name> [--data <body>]` | Start a run (optionally with an input body delivered to the root steps) and print its id. |
| `run-status <name> <id>` | Show a run's status + per-step state (status, attempts). |
| `rm <name>` | Remove a workflow definition. |

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
| `test-extract --value <v> [--template <t>\|--regex <re>] [--namespace <ns>]` | Dry-run a `token`-source claim transform **locally** (no server), through the same `derive_tenant` the host runs. Prints the derived tenant key, or the exact stage that denied it — so a `--template` (`{tenant}`/`{_}`) or `--regex` (`(?<tenant>…)`) misconfiguration is a quick local check instead of staring at fail-closed requests. |

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
See [Send email from a function](../how-to/send-email.md).

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
| `query <sql> [--db <name>]` | Run one row-returning query and print the result (add the global `--output-format json` for structured rows). |
| `ping [--db <name>]` | Actively TCP-probe each replica of a managed database — a reachability check that bypasses the stored-health gate `query` trips on (distinguishes "the DB is down" from "up but the resolver won't serve it"). Admin-scoped. |
| `move --db <name> --to <name> [--site <site>]` | **Relocate** a managed libsql database to a new binding name, data intact — vacuum-copies to the destination, verifies it, then removes the source. `--db` is the **source** binding (default = the site's default database); `--to` is the **destination** binding and must not already exist; `--site` falls back to `[publish].site`. Local single-node only — a remote/sqld backend is refused. Destructive; node-level `System·Admin` (not the project-scoped right `exec`/`query`/`ping` use). |

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

## `boatramp overlay`

Overlay forward-flow tooling (the server side is configured under
[`[overlay]`](./boatramp-cfg.md#overlay)). Requires the `overlay` feature.

| Command | Meaning |
| --- | --- |
| `id` | Print this operator's overlay identity (`ed25519:<hex>` + `bro1…`), load-or-generated at `~/.config/boatramp/overlay.key` (0600, like an SSH key). It is what self-serve `forward svc/<name>` binds its dial capability to. |
| `ls` | List the cluster's overlay service directory (`GET /api/overlay/services`) — the services you can `forward` to. |
| `resolve <name>` | Resolve one service name to its topology (relay + egress identities + relay posture). |
| `grant <service>` | **Control-plane-less** path: mint a dial capability + a one-flag forward ticket (below). |
| `grant-expose <service>` | **Control-plane-less** path: mint a publish capability + a one-flag expose ticket (the reverse-ingress analog of `grant`, for [`boatramp expose --ticket`](#boatramp-expose)). |
| `invite` | Mint a single-use `overlay-enroll` invitation (`--role node\|device\|workload --scope <svc>`) + a `brojoin1.…` ticket for `overlay join`. A confidential bearer secret — deliver it over a private channel. |
| `join <ticket>` | Redeem a `brojoin1.…` invitation: prove possession of this operator's overlay identity and be admitted into the relay's live trust set, adopting the returned membership credential. |
| `pair` | Pair with another operator's device and mutually verify identities with a short authentication string (SAS), detecting an active man-in-the-middle. |
| `pair-code` | Mint a single-use, short-TTL pairing rendezvous code (`bropair1…`) so two NAT'd peers can meet through the cluster relay (`POST /api/overlay/pair-code`, `Overlay·Admin`). |
| `policy ls` | Show the active overlay **flow policy** (Cedar text) + its version (`GET /api/overlay/policy`, `System·Admin`). |
| `policy set <file>` | Replace the flow policy from a `.cedar` file (or `-` for stdin) (`PUT`, `System·Admin`); `--if-match <version>` for a conditional write, a validation failure prints the server's `400` verbatim, an empty file turns the gate off. |
| `policy test` | Dry-run a dial/expose mint against the policy (`POST …/test`, `System·Admin`) — prints ALLOW/DENY + TTL ceiling + deciding policies; mints nothing. |

**`overlay ls` / `resolve`** read the live directory over your boatramp token (`Overlay·Read`); they
take `--server` (else `[publish].server`). This is the discovery that lets `boatramp forward svc/db`
work with no topology flags. Human `ls` output is headerless, tab-separated (pipe-friendly), one row
per service with the columns **service, relay address, egress id, client-auth posture**
(`capability-only` or `mutual-pin`); `--output-format json` emits the same fields as objects. On a
`resolve` miss the error points you at `overlay ls`.

**`overlay grant <service>`** is the offline/airgapped alternative to self-serve: it mints a
holder-bound overlay-dial capability (signing with the cluster root key — `[serve.signer]` /
`--auth-root-private-key` / `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`, the same signer `token mint` uses) and
packages the relay + egress identities, the capability, and (by default) a fresh client identity into
a single **forward ticket** (`brfwd1.…`, the overlay analog of a cluster join ticket) redeemed with
`boatramp forward <local> --ticket <blob>`. It also prints a client id + `[overlay] allowed_clients`
entry: **enroll it only if the relay is `mutual-pin`** — a `capability-only` relay needs no
enrollment, the ticket works as-is. Flags: `--relay <host:port>`, `--relay-id`/`--egress-id`,
`--holder-pub <id>` (bind a client-generated identity; the ticket then carries no secret),
`--ttl-secs <n>` (default 3600), `--config <path>`.

**`overlay grant-expose <service>`** mirrors `grant` for the reverse-ingress (publish) direction: it
mints a holder-bound overlay-**publish** capability + a one-flag **expose ticket** (`brexp1.…`)
redeemed with `boatramp expose <local> svc/<name> --ticket <blob>`. The ticket additionally carries
the cluster trust root's public key, because the exposer (the terminator) independently verifies
each incoming forward client's dial capability against it (zero-trust). Flags mirror `grant`:
`--relay <host:port>`, `--relay-id`, `--holder-pub <id>`, `--ttl-secs <n>` (default 3600),
`--config <path>`.

**`overlay invite` / `overlay join`** are the offline enrollment pair: `invite --role
node|device|workload --scope <svc>` mints a single-use `overlay-enroll` invitation + a `brojoin1.…`
ticket (signed with the cluster root key, like `grant`); the new peer redeems it with `overlay join
<ticket>`, proving possession of their own overlay identity to be admitted into the relay's live
trust set. The invitation is a confidential bearer secret (anyone holding it, plus their own
overlay key, can enroll until it is spent) — deliver it over a private channel; its blast radius is
bounded by its TTL and single-use redemption.

**`overlay pair` / `overlay pair-code`** mutually verify two operators' overlay identities with a
short authentication string (SAS) — detecting an active man-in-the-middle — and pin the peer's
proven identity (locally, in-memory). Two transports:

- **Direct dial**: one side `overlay pair --listen <host:port>` (the responder), the other
  `overlay pair <host:port>` (the initiator) — for peers that can reach each other directly.
- **Relay rendezvous**: for NAT'd peers that cannot direct-dial, they meet through the cluster's
  ingress relay (relay-blind — it bridges only ciphertext). One side mints a single-use,
  short-TTL code with `overlay pair-code` (`bropair1…`, gated `Overlay·Admin` — `POST
  /api/overlay/pair-code` — minting one stands up a relay rendezvous slot), shares it with the new
  peer, then parks it with `overlay pair --accept <code>`; the peer redeems it with `overlay pair
  <code>`. `pair-code --short` also mints a human-typeable **short code** (e.g. `1234-5678`,
  digit count set by [`[overlay] pair_short_code_digits`](boatramp-cfg.md#overlay), default 8),
  redeemed with `overlay pair --short <code>` — the initiator looks up the relay's topology via the
  **unauthenticated** `GET /api/overlay/pair-relay` (a short code carries no topology of its own;
  this route discloses only the relay's public socket + identity, not a capability).

Both transports run the same relay-blind E2EE handshake plus a **commit-then-reveal** nonce
exchange (à la ZRTP / Bluetooth numeric comparison: each side commits to its contribution before
either reveals), then derive a SAS the two operators **compare out of band** — 3 words (e.g.
`cargo-delta-hotel`) or 8 keypad digits. `--expect <SAS_WORDS>` is the non-interactive confirm
(required when stdin is not a TTY); the pairing aborts on any mismatch, with no way to skip the
check. Commit-then-reveal matters: without it, a relay-in-the-middle could learn one leg's SAS
target and grind its own KEM contribution offline until the two human-compared codes collide; the
commitment forces both sides to fix their contribution before either learns the other's, which is
what keeps the SAS's ~1-in-16.7-million collision odds real on a per-*online*-attempt basis. A
**leaked pairing code only lets someone race to redeem it first** — not forge a matching SAS: the
rendezvous is first-redeem-wins, but whoever ends up on the other end of the handshake still has to
produce a SAS that matches what the legitimate peer expects, and a MITM's two independent legs
diverge.

By default a relay's pairing PARK is **open** (unauthenticated — the SAS is the trust anchor). An
operator can tighten it per relay with [`[overlay] pairing_park =
"authenticated"`](boatramp-cfg.md#overlay): the accepter must then present a holder-bound
`overlay-pairing-park` capability and prove possession of it. Mint that capability by passing the
accepter's own overlay public key (from their `overlay id`) to `overlay pair-code
--accepter-pubkey <pubkey>`; hand them the capability (the `park_cap` it prints) alongside the
code, and they present it with `overlay pair --accept <code> --park-cap <cap>`. Redemption itself
stays unauthenticated in both PARK modes — only the accepter side gets the extra check.

**`overlay policy {ls,set,test}`** administers the cluster's overlay **flow policy** — the per-flow
access gate that decides which dial/publish-cap mints the control plane will issue (**deny-or-shrink-TTL
only**), separate from the RBAC that grants `Overlay·Write`/`Admin`. All three verbs need `System·Admin`
and take `--server` (else `[publish].server`). `set` validates server-side (parse + schema + a single
`not_after` upper bound); a malformed or recurring-temporal policy prints the server's `400` body
verbatim, and the FIRST stored policy warns because the gate becomes default-deny. `test` takes
`--action dial|expose --service <name>` (optionally `--holder`, `--role`, `--scope`, `--enrolled`,
`--ttl-secs`) and previews the decision without minting — use it before relying on a new policy.
A policy rule may also scope to the resolved **node** serving the request (`resource in
Overlay::Node::"<id>"` — the dial target's `egress_id`, or the expose relay's `relay_id`); the CLI's
`policy test` has no `--node` flag to preview a node-scoped rule (the console's test form does) —
use `boatramp overlay resolve <service>` to find the node id, then check the policy's effect via the
console, or temporarily store a service-scoped test policy instead.

## `boatramp forward`

Forward a local port to an in-cluster service over the overlay fabric — relay-blind, capability-gated,
`ssh -L`-shaped, with no OS capture. Requires the `overlay` feature.

```
boatramp forward 127.0.0.1:5432 svc/db
```

The headline case is **self-serve**: give a local address and a service name and nothing else — the
CLI uses your boatramp token to resolve the service's topology and mint a dial capability via the
control plane (`POST /api/overlay/dial`, `Overlay·Write`), binding it to your persistent overlay
identity (`~/.config/boatramp/overlay.key`). Zero hand-typed topology, and **no per-dial grant** once
your token carries the `Overlay·Write` right — the mint happens for you on every `forward`.

**First-run setup (one-time, by an admin).** Self-serve needs your boatramp token to hold the
`Overlay·Write` right (admins have it already via the `admin` role). None of the eight
[built-in roles](./rbac.md#default-roles) besides `admin` grant it, so for a non-admin operator an
admin first defines a custom role with `boatramp auth policy set` — e.g. an `overlay` role whose
rights include `overlay`·`write` (dial) and `overlay`·`read` (browse the directory) — then mints a
token against it: `boatramp token mint --role overlay`. With that, you never touch a per-service
grant again.

**Walkthrough.**

```
boatramp overlay ls                 # see which services you can reach
boatramp forward 127.0.0.1:5432 svc/db   # resolve + mint + forward, in one step
psql -h 127.0.0.1 -p 5432 …         # your local tool, now tunnelled to svc/db
```

If your token lacks `Overlay·Write`, `forward` fails with an actionable message (ask an admin for an
overlay role, or use a `--ticket`) rather than a dead port.

For deployments **without** a reachable control plane, a `--ticket` from
[`overlay grant`](#boatramp-overlay) or the explicit flags supply the same inputs by hand.

| Flag | Meaning |
| --- | --- |
| `<local-addr>` | Local address to bind and forward (e.g. `127.0.0.1:5432`). |
| `<service>` | The in-cluster service (e.g. `svc/db`). With no `--ticket`/explicit flags it is resolved via the control plane. |
| `--server <url>` | boatramp server for self-serve resolution (else `[publish].server`). |
| `--ticket <blob>` | A `brfwd1.…` forward ticket (control-plane-less). Conflicts with the explicit flags. |
| `--relay <addr>` / `--relay-id <id>` / `--egress-id <id>` / `--token <cap>` / `--token-file <path>` | The fully explicit escape hatch. |
| `--identity <seed\|path>` | Override the overlay identity (defaults to the persistent operator key; required with a `--holder-pub` ticket). |
| `--capability-only` | Dial the relay server-auth-only (present no client cert) — for a **capability-only** relay reached via `--ticket`/explicit flags. Ignored on self-serve (the posture comes from the control plane, with a note on stderr if you pass it anyway). |

Before binding the port, `forward` runs **one eager preflight dial** that validates the whole path —
relay reachable, capability authorized, egress reachable — and only prints the `ready` banner after it
succeeds; on failure it prints an actionable error and exits **without binding**, so you never get a
silently dead port. (The preflight opens one brief backend connection that closes immediately with no
application bytes.) Runs until interrupted (Ctrl-C); each accepted connection opens a capability-gated,
relay-blind flow that promotes to a direct link when one is reachable. The first runtime failure after
startup is also surfaced loudly (on stderr, not just the log), with causes matched to the relay
posture — a capability-only self-serve relay has no `allowed_clients`, so enrollment is never blamed
there.

## `boatramp expose`

Publish a **local** service INTO the cluster over the overlay fabric — the reverse of `forward`. The
exposer dials the relay OUTBOUND (so a NAT'd / undialable service can still be published) and holds
the connection open; a cluster-side `boatramp forward svc/<name>` then reaches it, relay-blind and
end-to-end encrypted. Requires the `overlay` feature.

```
boatramp expose 127.0.0.1:5432 as svc/db
```

The headline case is **self-serve**: give a local address and a service name and nothing else — the
CLI uses your boatramp token to resolve this node's ingress-relay topology and mint a holder-bound
**publish** capability via the control plane (`POST /api/overlay/expose`, `Overlay·Admin`), binding it
to your persistent overlay identity (`~/.config/boatramp/overlay.key`), then registers. Zero
hand-typed topology.

**Publishing is gated higher than dialing.** Self-serve expose needs your boatramp token to hold
`Overlay·Admin` — strictly above the `Overlay·Write` that `forward` needs — because publishing CLAIMS
a service name that forward clients trust and pin as their encrypted peer. Admins have it via the
`admin` role; a non-admin operator is granted it explicitly by an admin. If your token lacks it,
`expose` fails with an actionable message (ask an admin for `Overlay·Admin`, or use a `--ticket`) —
the `401` message names the real auth mechanism (`BOATRAMP_TOKEN` / `[publish].token`), never a
phantom command.

For deployments **without** a reachable control plane, a `--ticket` from
[`overlay grant-expose`](#boatramp-overlay) or the explicit flags supply the same inputs by hand.

| Flag | Meaning |
| --- | --- |
| `<local-addr>` | The local service to publish (e.g. `127.0.0.1:5432`) — what the exposer connects to per inbound flow. |
| `<service>` | The in-cluster name to publish AS (e.g. `svc/db`), optionally after the literal `as`. With no `--ticket`/explicit flags it self-serves via the control plane. |
| `--server <url>` | boatramp server for self-serve resolution (else `[publish].server`). |
| `--ticket <blob>` | A `brexp1.…` expose ticket (control-plane-less). Conflicts with the explicit flags. |
| `--relay <addr>` / `--relay-id <id>` / `--token <cap>` / `--token-file <path>` / `--trust-root <pub>` | The fully explicit escape hatch (the exposer verifies incoming dial capabilities against `--trust-root`). |
| `--identity <seed\|path>` | Override the overlay identity (defaults to the persistent operator key; required with a `--holder-pub` ticket). |
| `--capability-only` | Dial the relay server-auth-only (present no client cert) — for a **capability-only** relay reached via `--ticket`/explicit flags. Ignored on self-serve (the posture comes from the control plane, with a note on stderr if you pass it anyway). |

A local preflight validates the publish capability (signature, scope, holder) before any network
round-trip, so an expired / wrong-service / wrong-identity capability fails loudly and immediately.
The `ready` banner prints only after a confirmed registration (a name already claimed by a live
exposer fails first — names are first-live-claim-wins). The exposer is the terminator, so it
independently authorizes each incoming forward client's dial capability against the cluster trust root
(zero-trust, exactly like an in-cluster egress). Runs until interrupted (Ctrl-C).

## `boatramp tunnel`

Run a local SOCKS5 (+ optional HTTP `CONNECT`) proxy daemon that reaches overlay services **by
name** — ordinary tools (`psql`, `curl`, a browser via its SOCKS proxy setting) dial any cataloged
service without a dedicated `forward` per port. Requires the `overlay` feature.

```
boatramp tunnel
```

Self-serve, the same way as `forward`: the CLI uses your boatramp token to mint dial capabilities
via the control plane, binding to your persistent overlay identity
(`~/.config/boatramp/overlay.key`). SOCKS is the only consumption front-end this release ships, so
it is on by default; `--tun` replaces it with the TUN virtual-interface front-end instead.

| Flag | Meaning |
| --- | --- |
| `--server <url>` | boatramp server for self-serve resolution (else `[publish].server`). |
| `--socks [<addr>]` | Bind the SOCKS5 front-end to `<addr>` — default, and the value when passed bare, `127.0.0.1:1080`. Always on unless `--tun` is passed. |
| `--http-connect [<addr>]` | Also bind a small HTTP `CONNECT` front-end to `<addr>` (for `HTTPS_PROXY`/`http.proxy`-style clients) — default when passed bare `127.0.0.1:1081`. Off unless passed. |
| `--no-local-auth` | Disable the auto-generated local SOCKS/CONNECT credential (required by default) — a loopback port with no local auth lets ANY local user proxy under your overlay identity. Pass this only on a single-user host where that is an acceptable tradeoff. |
| `--tun` | Start the TUN virtual-interface front-end instead of SOCKS (Linux, macOS, Windows). Needs this binary's `tun` cargo feature plus privilege to open the device: `CAP_NET_ADMIN`/root on Linux, root on macOS, Administrator (with the bundled `wintun.dll`) on Windows. |
| `--cidr <cidr>` | The synthetic CIDR routed into the TUN device (default `100.64.0.0/10`). Only meaningful with `--tun`. |
| `--dns-zone <tld>` | The embedded DNS zone's TLD (default `internal`). Only meaningful with `--tun`. |
| `--cluster <name>` | The embedded DNS zone's `<cluster>` label (defaults to `[publish].project`, else `default`). Only meaningful with `--tun`. |
| `--cleanup` | Detect and revert a dirty-state marker left by a crashed previous `--tun` run, then exit — starts no front-end. Safe to run with no marker present. |
| `--max-connections <n>` | Cap on concurrent accepted connections, SOCKS + HTTP CONNECT combined. |
| `--allow-non-loopback` | Acknowledge binding `--socks`/`--http-connect` to a non-loopback address. Absent this flag, a non-loopback bind is refused outright: this proxy dials under YOUR operator identity, so exposing it to the LAN (especially with `--no-local-auth`) would hand anyone who can reach it an unauthenticated by-name proxy into your overlay. |

With no `--tun`/`--cleanup`, `tunnel` loads (or generates) the local SOCKS/CONNECT credential,
binds the requested front-end(s), and runs until interrupted (Ctrl-C); each accepted connection
resolves a bare service name (e.g. `db`) through the same self-serve control-plane path `forward`
uses, dials it, and splices the two streams, relay-blind and capability-gated.

## `boatramp connect`

One-shot dial of a single overlay service, splicing stdin/stdout until either side closes — the
shape an `ssh ProxyCommand` or a script pipes through, for a caller that already has one specific
destination in mind and does not want to stand up a `tunnel` daemon for it. Requires the `overlay`
feature.

```
boatramp connect svc/db
```

| Flag | Meaning |
| --- | --- |
| `<service>` | The overlay service to reach (e.g. `db`, `svc-db`, or `svc/db`). |
| `--server <url>` | boatramp server for self-serve resolution (else `[publish].server`). |

Reuses the exact same control-plane wiring and persistent overlay identity as `tunnel`/`forward`
(`~/.config/boatramp/overlay.key`) — only the front-end differs (one spliced stdio pair instead of
a SOCKS daemon). Runs until either `service` or the local process closes its side.

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
| `apply [-f/--file <path>] [--format <ron\|json>] [--dry-run]` | Declaratively apply a whole gateway (upstreams + routes + project ceilings) from a file, **replacing** the site's current gateway — the declarative analogue of the imperative verbs above. `--file` defaults to `gateway.cfg` (RON or JSON, auto-detected by extension); `--dry-run` validates and shows what would change without writing it. |
| `export [-f/--file <path>] [--format <ron\|json>]` | Export the site's current gateway as a declarative document that round-trips with `apply`. Writes to `--file`, or stdout when omitted (stdout defaults to RON; a `.json` path ⇒ JSON). |

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
| `bind-blob --site <site> [--container <c>] [--project <p>] [--export]` | Mint a blob-shim `BOATRAMP_BLOB_URL` + token for a **non-managed** local process (dev/CI) — the blob analogue of `DATABASE_URL`; the process then shares a site's `hblob/{site}/…` namespace. Requires the `allow_dev_blob_bind` posture (on by default only in `dev`); System·Admin. `eval "$(boatramp compute bind-blob --site mailroom --export)"`. |
| `bind-messaging [--topic <t>] [--project <p>] [--export]` | Mint a messaging-shim `BOATRAMP_MESSAGING_URL` + token for a **non-managed** local process (dev/CI) — the messaging analogue of `bind-blob`; the process can then publish AND consume (claim/ack/nack) the `{project}/bus/<topic>` project bus. Requires the `allow_dev_messaging_bind` posture (on by default only in `dev`); System·Admin. `eval "$(boatramp compute bind-messaging --topic deliver --export)"`. |
| `volume ls` | List persistent volumes on the node (`NAME`, `SIZE`, and whether a registered workload still references it). |
| `volume rm <name>` | Remove a persistent volume. Refused (`409`) while a registered workload's active spec still mounts it, unless `--force`. |
| `status [<workload>]` | Show observed per-replica runtime state — stored health, lifecycle phase, assigned IP:port, age vs startup grace, backend (the record the endpoint resolver reads). Node-global; admin-scoped. Add the global `--output-format json` for the structured view. |
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

## `boatramp db`

Inspect and operator-provision a project's **managed databases**. A managed database is
declared in the `databases:` block of an [`apply`](#boatramp-apply) manifest — boatramp
then provisions it, mints and seals its credential, and follows the workload across
restarts. There is deliberately **no `db create`**: the manifest is the sole authoring
surface (a create verb would compete as a second source of truth). The read verbs
(`ls`/`get`/`status`) are `Project·Read`; the provisioning verbs (`ensure database`,
`ensure user`, `drop user`) re-run an idempotent action against an **already-declared**
database and gate at `Project·Admin`. Takes the common `--server` flag.

| Sub-action | Description |
| --- | --- |
| `ls` | List the project's declared managed databases (`NAME`, `KIND`, `TENANT`, `SCOPE`, `SIZE`). |
| `get <name>` | Show one declared database's declaration. |
| `status <name>` | Show one declared database's declaration + its live **readiness** (`starting` / `service-ready` / `provisioned` / `provision-failed` — distinct from bare TCP health; a workload is `provisioned` only once its post-launch provisioning, e.g. a default-project `CREATE DATABASE`, has run). Also surfaces a **data-dir** ownership signal when a managed database is stuck `starting` because its data directory carries foreign-owned files (the filesystem fault `boatramp project repair` does not fix); read-only — it never chowns. |
| `ensure database <name>` | Idempotently (re-)provision an already-declared database — e.g. force the default-project database setup to run now rather than waiting for the first binding. `Project·Admin`. |
| `ensure user <name> <user>` | Idempotently provision a login role `<user>` on the managed database `<name>`. By default the host mints + seals the password; `--password-secret <secret>` binds a **bring-your-own** password from a sealed secret instead. On a shared cluster the role name is per-tenant-qualified so it can't collide across tenants. `Project·Admin`. |
| `drop user <name> <user>` | Drop the login role `<user>` on `<name>` (idempotent — absent is still success). `Project·Admin`. |
| `restart [--db <name>]` | Restart a **dedicated, project-scoped** managed database — stop its replica so the reconcile loop relaunches it fresh (same data volume), applying any **pending** restart-requiring config change (e.g. a flipped `delta_capture`) in the process. `--db` defaults to `default`. A shared-tenant/site-scoped/BYO binding is refused. Prints the workload, whether a pending change was applied, and replicas stopped. `Project·Admin`. |

The global `--output-format json` emits the raw record instead of the human table.
To declare or change a database, edit the manifest's `databases:` block — see
[Declare a managed database](../how-to/managed-databases.md),
[Declare a project with `apply`](../how-to/apply.md), and the
[project.cfg schema](./project-cfg.md).

## `boatramp blob`

Upload artifacts and manage the node's blob **storage backend**. `blob put` is the
day-to-day artifact uploader; the `migrate` / `drain` / `purge` / `status` verbs move a
node from one blob backend to another (fs→cloud, provider→provider, region→region)
without a re-apply, then reclaim the old store.

| Sub-action | Description |
| --- | --- |
| `put <file>` | Upload a file as a content-addressed blob; prints its hash (the key to pass to `compute set --kernel/--rootfs`). |
| `mint-upload` | Mint a scoped, short-lived S3 upload credential for a project+site's blob container, so an external client (browser, bulk agent) can upload directly over the S3 protocol; TTL + max-bytes clamp to operator ceilings. `blob-upload` feature, gated `BlobUpload·Write`. See [Direct-to-storage blob ingress](../how-to/blob-ingress.md). |
| [`migrate`](#blob-migrate) | **Offline, node-local** copy of every object from one blob backend to another. |
| [`drain`](#blob-drain) | **Daemon-mediated** drain of a managed node's configured read-fallback secondary → primary. |
| [`purge`](#blob-purge) | Reclaim unreferenced blobs, or a drained secondary's objects (dry-run by default). |
| [`status`](#blob-status) | Print the node's blob migration posture (`{ blob_fallback_active }`). |
| `verify` | List every blob a live site deployment or function references that is MISSING from the backend — a dead reference that would 404 on invoke/serve. Read-only (`System·Read`). |
| `rehome` | Default-scope blob re-home (v0.31.0): re-homes the node's own bare default-scoped blob objects to their two-segment `…/default/…` spelling, in place. Offline + node-local, mirrors `boatramp migrate --stage`/`--finalize`. Run with the node stopped. |

> **The three blob-storage `migrate`/`drain` verbs.** `blob migrate` is **offline** — it
> builds *both* backends in the CLI process from two node config files and never contacts a
> server, so it needs local access to the backends' credentials (for a pre-boot copy, or a
> node you can shell into). `blob drain` is its **daemon-mediated** counterpart for a
> managed node reachable only over the control plane: the running daemon (which already
> holds both backends open) drains its *own* configured secondary. `blob purge
> --drained-source` then removes the decommissioned old store. See
> [Switch the blob backend with zero downtime](../how-to/blob-backend-migration.md). (`boatramp blob migrate` is
> unrelated to the top-level [`boatramp migrate`](#boatramp-migrate) store re-key.)

### `blob migrate`

Copy every object from a **source** blob backend to a **destination** backend, offline. It
is a **node-local** operation: it builds both backends in-process from node config files
(`boatramp.cfg` shape — each side's `[serve]` blob block + optional `[secrets]` for a
sealed S3 credential), so it takes no `--server` and needs local credential access, not a
control-plane token. The copy `get`→`put`s each object, **skipping** any key already
`head`-present in the destination at a matching size — so it is **idempotent and
resumable** (a re-run after an interruption is a near-no-op) and **read-only on the source**
(it never deletes, and the source stays authoritative until you flip `[serve].blobs`). The
resolved source/dest identities are echoed and an equal source==dest is refused.

| Flag | Default | Description |
| --- | --- | --- |
| `--from <config>` | fallback secondary | Node config file whose `[serve]` blob block defines the **source**. Omitted ⇒ the `--node-config`'s `[serve.blob_fallback]` secondary (the drain one-liner); error if none. |
| `--to <config>` | `--node-config`'s primary | Node config file whose `[serve]` blob block defines the **destination**. Omitted ⇒ the node config's own primary backend. |
| `--node-config <path>` | `boatramp.cfg` | Running node's config — the source of the `--from`/`--to` defaults. Read only when `--from` or `--to` is omitted. |
| `--concurrency <n>` | `8` | Bounded number of objects copied in flight at once. |
| `--no-verify` | verify on | Skip the post-copy verify pass. By default, every source object is head-confirmed present in the destination; any miss is a **non-zero exit**. |
| `--dry-run` | — | Enumerate + classify (would-copy / would-skip) and report; copy nothing. |
| `--prefix <p>` | all | Restrict the copy to source keys under this prefix. |

JSON output: pass the global `--output-format json` flag (see [Global flags](#global-flags)).

A verified `fallback secondary → primary` drain additionally prints
`SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node.`

### `blob drain`

Drain the running daemon's configured `[serve.blob_fallback]` **secondary → primary** over
the control plane — for a **managed node** reachable only via `--server` (no local disk / no
`fly ssh`), where the offline [`blob migrate`](#blob-migrate) cannot run. The client names
**no** source or destination: the daemon (which already holds both backends of its fallback
composite open) drains only its *own* configured pair, a tighter authorization surface than
the offline CLI's arbitrary `--from`/`--to`. Requires `--server`; gated at **`System·Admin`**
(a project admin / publisher / deployer cannot reach it). No fallback configured ⇒ `422`.

Progress streams as it arrives; on a verified drain it prints
`SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback`. The copy is
**resumable**, so a dropped connection (e.g. an edge idle-timeout on a long drain) is safe to
re-run.

| Flag | Description |
| --- | --- |
| `--dry-run` | Enumerate + classify on the daemon and report; copy nothing. |
| `--concurrency <n>` | Bounded copy concurrency on the daemon. |
| `--prefix <p>` | Restrict the drain to secondary keys under this prefix. |

JSON output: pass the global `--output-format json` flag; progress lines stay on stderr.

### `blob purge`

Reclaim a **provably-safe** blob set over the control plane. **Dry-run by default** (reports
what *would* be reclaimed and deletes nothing) — pass `--apply` to execute. Gated at
**`System·Admin`**. Exactly **one** mode is required:

| Flag | Description |
| --- | --- |
| `--unreferenced` | On-demand garbage collection: prune content-addressed blobs that **no live deploy manifest references** (the everyday storage reclaim). **Refused (`409`)** while a read-fallback secondary is attached (`[serve.blob_fallback]`) — drain and drop the fallback first, else GC could phantom-reclaim a secondary-only orphan. |
| `--drained-source` | The migration **decommission**: after a `drain`/`migrate`, delete each old-secondary object **only once it is byte-confirmed** (present at a matching size) in the primary. **Fail-closed** — an unconfirmed object survives, never deleted. Requires a configured `[serve.blob_fallback]` (else `422`). |
| `--apply` | Actually delete (default: dry-run — report only). |
| `--prefix <p>` | Restrict a `--drained-source` purge to source keys under this prefix (ignored by `--unreferenced`). |

JSON output: pass the global `--output-format json` flag; progress lines stay on stderr.

### `blob status`

Print the node's structured blob **migration posture** — whether a read-fallback secondary
is currently attached (the node is mid-migration) — as `{ "blob_fallback_active": <bool> }`.
The direct answer to "is this node still in transition mode?", instead of grepping the
startup log warning. Read-only (`System·Read`).

Pass the global `--output-format json` flag for the structured `{ "blob_fallback_active": <bool> }` posture.

## `boatramp kv`

Maintain the control-plane **SlateDB** store. Needs the `slatedb` feature. These
are SlateDB-specific tools (manifest / WAL / `.compactions`): run against a
non-SlateDB `--kv` backend they print a clear "not applicable" message rather
than acting. The mutating verbs are **dry-run by default** (pass `--apply`), and
the recovery/compaction verbs are **offline** (stop the daemon first — SlateDB is
single-writer). Every verb addresses the store with the shared `--kv` /
`--data-dir` (local `<data-dir>/kv-slate`) or `--kv-s3` + `--s3-*` flags.

| Sub-action | Description |
| --- | --- |
| `repair [--apply]` | Quarantine a torn **trailing WAL tail** so the store opens again after a crash/partial-snapshot (the offline tail-only recovery). Refuses on a mid-range gap or unreadable manifest. |
| `recover [--apply] [--adopt-volume <path>]` | The superset of `repair`: dry-run diagnoses the whole store; `--apply` repairs a recoverable shape in place; for an unsafe shape (a torn compacted/L0 SST), `--adopt-volume` validates + adopts an operator-attached clean volume snapshot. |
| `status [--ack]` | Show the durable `DEGRADED` breadcrumb a self-heal-on-open wrote (reads without opening the store); `--ack` clears it once the loss window is reviewed. |
| `checkpoint [--live]` | Flush the store to a consistent, guaranteed-bootable state (drain WAL→L0) so a volume snapshot is reliable. Offline (open+close) by default; `--live` checkpoints a running daemon over `POST /api/kv-checkpoint` (`System·Admin`). |
| `stats` | Report the store's physical-vs-logical footprint (per-subdir); the gap is reclaimable garbage. Read-only. |
| `compact [--apply] [--timeout-secs <n>]` | Full-merge compact + GC to reclaim the physical-vs-logical gap. Dry-run by default; `--apply` is offline-only and the GC is irreversible. |
| `export --out <file> [--store <endpoint>]` | Write a portable, backend-agnostic logical dump (sealed secret ciphertext + plaintext config/RBAC, never the KEK). Sensitive — protect it at rest. |
| `import <file> [--apply] [--force] [--store <endpoint>]` | Import a dump into a store, rebuilding a fresh clean store. Dry-run by default; `--apply` imports + verifies byte-for-byte; a non-empty destination is refused unless `--force`. |
| `migrate --from <endpoint> --to <endpoint> [--apply] [--force]` | Migrate a store→store over the portable dump (the SlateDB⇄SQL adoption path). Dry-run by default; refuses a non-empty `--to` unless `--force`. |

An endpoint descriptor (for `export`/`import`/`migrate`) is `memory`,
`slatedb:<data-dir>`, `sqlite:<path>`, or `postgres:<ENV_VAR>` / `mysql:<ENV_VAR>`
(the env var **names** the var holding the connection URL). This `kv migrate` is a
KV store→store copy — unrelated to the top-level [`boatramp migrate`](#boatramp-migrate)
and [`boatramp blob migrate`](#boatramp-blob).

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
| `dump [--file boatramp.cfg] [--explain]` | Print the resolved **static** daemon config (`boatramp.cfg` + `BOATRAMP_*` env) as JSON, secrets redacted. **Client-side only** — no server is contacted. |
| `migrate <file> [--write]` | Upgrade an [`apply`](#boatramp-apply) manifest to the current schema. **Client-side only** — no server is contacted. |

`config set` on a `restart`-class key (a trust anchor, posture, or listener
setting) fails with a pointer to `boatramp.cfg` rather than silently doing
nothing.

### `config migrate`

`config migrate <file>` upgrades an [`apply`](#boatramp-apply) manifest to the current
schema and prints the result (or, with `--write`, rewrites the file in place). It is
**purely client-side** — it reads and rewrites the file locally and never contacts a server.

The `version:` semantics drive it:

- **Absent `version:`** — the manifest is parsed **strictly against the current schema**. An
  old-shaped manifest that omits `version:` fails with an error pointing here.
- **`version: N` older than current** — the manifest opts into the loose-parse → migrate →
  typed pipeline: it is migrated forward through the registered chain (`vN → … → current`).
- The migrated output **omits `version:`** (current = absent). Declare `version: <what you
  wrote against>` only to keep migration support for a future schema change.

```sh
# Upgrade a pre-v0.6.0 manifest in place (add `version: 1` at its top first).
boatramp config migrate apply.cfg --write
```

See [Declare a project with `apply`](../how-to/apply.md) for the manifest schema and the
version-migration workflow.

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

## `boatramp queue`

Inspect and manage a consumer topic's **live** work-queue — as opposed to its
dead-letter store, which [`dlq`](#boatramp-dlq) manages. Takes the common
`--server` / `--site` flags. Add `--bus` to target the shared **project bus**
(`{project}/bus/{topic}`) instead of a single site's queues: reads then need
`Project·Read`, the destructive ops `Project·Admin`. See
[Run background work](../how-to/background-work.md).

| Sub-action | Description |
| --- | --- |
| `peek <topic> [--alias <a>] [--limit <n>]` | Show the head of a topic's live work-queue (id, attempts, leased/claimable, payload) **without consuming** — no lease, no attempt charged. |
| `replay <topic> [--after <id>] [--limit <n>] [--alias <a>]` | Replay a **grouped** topic's retained history from an offset, without consuming (no lease, no cursor touched). |
| `groups <topic> [--alias <a>]` | List a topic's consumer groups (cursor, in-flight, lag). |
| `group-reset <topic> <group> [--earliest\|--latest] [--alias <a>]` | Reset a group's cursor — re-consume from earliest (default) or skip to the head (`--latest`). |
| `group-delete <topic> <group> [--alias <a>]` | Delete a consumer group (its state + dead-letters). |
| `pause <topic> [--alias <a>]` / `resume <topic> [--alias <a>]` | Suppress delivery for a topic (publish + in-flight ack/nack keep flowing), or resume it. |
| `policy <topic> [--max-depth <n>] [--max-rate <n>] [--max-unflushed <n>] [--alias <a>]` | Set a per-topic operator flow-control policy; omit a flag to leave that axis uncapped (`--max-unflushed` is single-node only). |

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

## `boatramp version`

Report the boatramp version: this binary's by default, or — with `--server <url>`
(or `--remote` for the configured `[publish].server`) — a **running daemon's**,
read from `GET /api/version` (gated at `system·read`; there is no unauthenticated
version surface). Distinct from the built-in `boatramp --version` flag, and honors
the global `--output-format json`.

| Flag | Description |
| --- | --- |
| `--server <url>` | Query the running daemon at this URL instead of reporting this binary's version. |
| `--remote` | Query the configured daemon (`[publish].server` / `BOATRAMP_SERVER`); ignored when `--server` is given. |

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
