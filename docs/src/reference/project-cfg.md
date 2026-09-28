# project.cfg schema

`project.cfg` is the per-project config, read by the client commands (`sync`,
`build`, `bundle`, `validate`). It is [RON](https://github.com/ron-rs/ron), lives
in the project folder, and is optional — a missing file means all defaults.

```ron
(
    publish: ( server: "https://pad.example.com", site: "my-site" ),
    build: ( command: "npm run build", output: "dist" ),
    routing: (
        clean_urls: true,
        redirects: [ (from: "/old/:slug", to: "/new/:slug", status: 301) ],
    ),
)
```

Sections:

| Section | Purpose |
| --- | --- |
| `publish` | Where and what to publish (`sync`). |
| `build` | An optional build command run before `sync`. |
| `bundle` | The in-process JS/CSS bundler (`bundler` feature). |
| `routing` | Redirects, rewrites, headers, handlers — folded into the deployment. |

## `publish`

| Field | Type | Description |
| --- | --- | --- |
| `server` | url | Server base URL. Flag `--server`, env `BOATRAMP_SERVER`. |
| `site` | string | Site to publish to. Flag `--site`, env `BOATRAMP_SITE`. |
| `token` | string | Control-plane token. Prefer `BOATRAMP_TOKEN` so it is not on disk. |
| `project` | string | The [project](../how-to/projects.md) this config's site belongs to; overridden by `--project` / `BOATRAMP_PROJECT`, defaults to `default`. |

See also the separate [`apply.cfg`](../how-to/apply.md) project manifest, which
declares a whole project — its member sites, top-level functions, compute
workloads, managed databases, and tenancy schema — as one applied unit. Its
field-by-field schema is [below](#applycfg-manifest-schema).

## `build`

Run before `sync`; its output directory is what gets published.

| Field | Type | Description |
| --- | --- | --- |
| `command` | string | Shell command to run (e.g. `npm run build`). |
| `output` | string | Directory the build emits and `sync` publishes (e.g. `dist`). |

## `bundle`

The in-process bundler (Rolldown for JS/TS, lightningcss for CSS). Needs the
`bundler` feature.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `outdir` | string | `dist` | Output directory for bundled assets. |
| `js` | list | — | JS/TS entry points (tree-shaken, code-split). |
| `css` | list | — | CSS entry points (`@import` inlined). |
| `minify` | bool | `true` | Minify the output. |

## `routing`

The bulk of a project's config: redirects, rewrites, headers, SPA fallback,
clean URLs, error documents, and the handler/consumer/cron/stream declarations.
It is compiled and checked at `sync` (and by `boatramp validate`), then folded
into the immutable deployment manifest — so it is atomic with the content and
rolls back with it.

The full field-by-field schema is on its own page:
[Routing config schema](./routing.md).

Validate a `project.cfg` (including `routing`) without publishing:

```sh
boatramp validate
```

```text
project.cfg: routing OK (2 redirects, 1 handler)
```

# `apply.cfg` manifest schema

`apply.cfg` is a separate, project-level [RON](https://github.com/ron-rs/ron)
manifest read by [`boatramp apply`](../how-to/apply.md). Where `project.cfg`
configures **one** site's publish, `apply.cfg` declares a **whole project** —
its member sites, top-level functions, compute workloads, managed databases, and
tenancy schema — and reconciles it as one applied unit. It is **upsert, never
prune**: `apply` create-or-replaces only the resources it names and never deletes
anything absent from the manifest, so declarative and imperative management
coexist.

Unlike `project.cfg`, a **missing** manifest is an error (there is nothing to
apply). The default filename is `apply.cfg` (`-f` overrides it).

## Manifest top-level fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `version` | u32? | absent ⇒ current | Manifest schema version — see [below](#version--migration). |
| `project` | string? | resolved | Target project. Absent ⇒ `--project` / `BOATRAMP_PROJECT` / the `default` project. |
| `sites` | list\<ApplySite\> | `[]` | Sites to publish (each an atomic content-addressed deployment; see the [`apply` how-to](../how-to/apply.md)). |
| `functions` | list\<ApplyFunction\> | `[]` | Top-level functions to deploy (create-or-replace). |
| `compute` | list\<ApplyCompute\> | `[]` | Compute workloads to create-or-replace — see [`compute`](#compute-workloads-computespec). |
| `databases` | list\<ApplyDatabase\> | `[]` | Declared managed databases — see [`databases`](#managed-databases-databases). |
| `tenancy` | TenancySchema? | untouched | The project's [tenant-isolation schema](./siteconfig.md#tenancyschema). Reconciled **before** sites/functions. Absent ⇒ the stored schema is left untouched (use `boatramp tenancy clear` to remove one). |

The whole document is parsed with `deny_unknown_fields`, so a typo or an
excluded key fails to parse rather than being silently ignored.

## `version` + migration

The optional top-level `version: <u32>` opts a document into the migration
framework (v0.6.0):

- **Absent (or equal to the current schema)** ⇒ parsed **strictly** against the
  current typed schema. An old-shaped manifest that omits `version` fails with an
  upgrade error naming the migration path (the most common cause is a pre-v0.6.0
  raw-JSON `compute[].spec`).
- **`version: N` older than current** ⇒ the document is run through the registered
  migration chain (vN → … → current) via **`boatramp config migrate <file>`**
  ([`--write`](./cli.md#boatramp-config) rewrites in place), then parsed strictly.
  An upgraded/migrated manifest **omits `version:`** (current = absent).
- **`version: N` newer than this build understands** ⇒ rejected.

> **Declare the schema you wrote against to get migration support; omit `version:`
> and your manifest is parsed as current.** Add `version: 1` (the pre-v0.6.0
> schema) only when upgrading an old manifest with `config migrate`.

The manifest is authored in **RON**. As of v0.6.5 a **JSON** manifest is also
accepted for interop (current schema only — a JSON document is not run through the
migration chain); RON stays the canonical authoring format. See the
[config formats how-to](../how-to/apply.md).

## `compute` workloads (`ComputeSpec`)

Each `compute[]` entry is a workload name plus a **typed** spec (v0.6.0 — before
this, `spec` was a raw JSON blob; it is now the typed `ComputeSpec`, so a
malformed spec fails at parse time). It mirrors the server's `PutComputeRequest`:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | — | Workload name (project-scoped). |
| `spec` | ComputeSpec | — | The immutable workload spec (below). |
| `replicas` | u32 | `1` | Desired replica count. |
| `placement` | PlacementConstraints | none | `regions` (list) + `labels` (map) a replica's node must satisfy. |

`ComputeSpec` key fields:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `root` | RootSource | — | The workload's root filesystem source — see [`RootSource`](#rootsource) below. |
| `kernel` | string | — | Blob hash of the `vmlinux` kernel; applies only to a micro-VM (`rootfs(…)`) source, omitted otherwise. |
| `vcpus` | u32 | — | Virtual CPUs. |
| `mem_mib` | u32 | — | Guest memory (MiB). |
| `port` | u16 | — | The in-guest TCP port the app listens on (the gateway targets it). |
| `entrypoint` | list\<string\> | `[]` | The in-guest argv the init execs. |
| `env` | map\<string, string\> | `{}` | Environment variables for the entrypoint. |
| `volumes` | list\<VolumeRef\> | `[]` | Persistent volumes (`mount` / `name` / `size_mib`); opt-in (default root is read-only + ephemeral scratch). |
| `restart` | enum | `always` | `never` (run-to-completion), `on_failure`, or `always`. |
| `startup_grace_secs` | u32 | `30` | Window a fresh replica has to become healthy before it is treated as a broken launch. |
| `isolation` | enum | `trusted` | `trusted` (shared-kernel container is fine) or `untrusted` (requires a micro-VM / managed platform). |
| `scale_to_zero` | bool | `false` | Snapshot + stop when idle; cold-restore on the next request. |
| `writable_root` | bool | `false` | Writable root FS instead of the hardened read-only default (honored only under the single-tenant posture). |
| `bindings` | list\<ComputeBinding\> | `[]` | Managed resources (`kind: sql`, …) resolved to a tenant-scoped endpoint + credential injected into the guest env at launch. |

### `RootSource`

A tagged, snake_case newtype variant selecting the root FS form (matched 1:1 to
the backends that accept it):

| Variant | Source | Backends |
| --- | --- | --- |
| `image("repo:tag")` | An OCI image reference pulled from a registry. | `docker`, `cloudflare` |
| `tar("<blob-hash>")` | A tar rootfs archive (a shared-store blob hash) staged + unpacked. | native `container` |
| `rootfs("<blob-hash>")` | A rootfs block image (a shared-store blob hash) attached as the root device (paired with `kernel`). | `firecracker` micro-VM |

```ron
compute: [
    ( name: "api",
      spec: ( root: image("ghcr.io/acme/api:1"), vcpus: 1, mem_mib: 512, port: 8080 ),
      replicas: 2 ),
]
```

## Managed databases (`databases`)

The `databases:` block (v0.6.0) is the **declarative front door** onto boatramp's
managed-database provisioning — the SOLE authoring surface for a project-scoped
managed DB (there is deliberately **no** imperative `db create`; a create verb
would compete as a second source of truth). Declaring an entry no longer requires
an operator to hand-edit `boatramp.cfg` — a project author adds an entry and runs
`boatramp apply`.

Each `ApplyDatabase` is a **typed, SAFE projection** of the node-static external
database config, restricted to the fields a project author may safely declare.
Reconciled **before** sites/functions/compute, so a handler shipped in the same
apply binds an already-provisioned DB. It is **PUT-only** (create-or-replace +
eager provision); removing an entry **NEVER deprovisions** the database, volume,
or credential (teardown stays an explicit imperative verb — a data-loss guard).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | — | Binding name — how a guest reaches it via `sql.open("<name>")` and the `{name}` key segment. |
| `kind` | enum | — | The engine: `postgres` or `mysql`. |
| `version` | u32? | engine default | Engine major version (e.g. `16`). A **change** on re-apply routes through the owner-gated migrate/repair path, never a silent re-init. |
| `extensions` | list\<string\> | `[]` | Trusted extensions to make available (Postgres). Advisory — enabling one still routes through the owner-gated migration step + operator allowlist. |
| `size` | enum | `small` | Sizing **preset**: `small` / `medium` / `large` → bounded vcpus/mem/volume (NOT raw VM knobs — the disk-exhaustion guard). |
| `tenant` | enum | `single` | Isolation mechanism: `single` (dedicated server per tenant) or `shared` (one server, per-tenant db + role). A **change** on re-apply is refused. |
| `tenant_scope` | enum | `project` | Tenant grain: `project` or `site`. A **change** on re-apply is refused. |
| `read_only` | bool | `false` | Open every transaction `READ ONLY`. |
| `rls_session` | bool | `false` | Opt-in native-RLS session injection. |
| `tenant_guc` | string? | — | Postgres session GUC for the host-resolved tenant (RLS backstop; honored with `rls_session` + Postgres). |
| `session_guc` | string? | — | Session GUC for the anonymous session axis (RLS backstop). |
| `tenant_all_marker` | string? | — | The reserved sentinel written to `tenant_guc` on an `all`-scoped read. |
| `pool_max` | u32? | — | Max pooled connections. **Capped** to an operator ceiling (64) at lowering. |
| `connect_timeout_secs` | u64? | — | Connection/acquire timeout. **Capped** (60s). |
| `startup_grace_secs` | u32? | — | Startup grace for the managed server's first `initdb`. **Capped** (600s). |

**Excluded — the security contract.** These are **not** fields; a manifest that
names one **fails to parse** (`deny_unknown_fields`), because the credential is
minted + sealed server-side and never lives in a committable manifest:

| Excluded field | Why |
| --- | --- |
| `image` | Arbitrary-OCI RCE — boatramp always picks the stock engine image at lowering. |
| `password_env` | Omitting it is what selects the managed-credential path; a declared DB can NEVER bring its own password. |
| `url_env` / `read_url_env` / `migration_url_env` | BYO-secret / SSRF / arbitrary-host reach. |
| `path` | Host-fs traversal. |
| `compute` | The per-project server workload is DERIVED (project-qualified), never author-named — so a manifest can only provision onto its own project's server. |

**Semantics.** Declaring a database mints owner-role identities, so the declare +
provision route is **`Project·Admin`-gated** (the same owner-grade placement as
migrate/repair — a project publisher/deployer can never reach it). A declared
database is persisted **project-scoped** at `project/{project}/database/{name}`
and **MERGED** with the node-static `[handlers].bindings.sql.databases` map at one
resolution point where **daemon-static config WINS, fail-closed, on a same-name
conflict** — a project manifest may never shadow or downgrade a node operator's
bring-your-own binding. Two operator ceilings guard the node's disk:
`max_declared_databases` (count, default 16) and `max_declared_volume_mib`
(aggregate volume, default 512 GiB), enforced fail-closed at `declare` (a `422`).

Read-only inspection is `boatramp db ls | get <name> | status <name>`
([CLI reference](./cli.md#boatramp-db)); there is no `db create`. See the
[`apply` how-to](../how-to/apply.md) for the end-to-end flow.

```ron
databases: [
    ( name: "app", kind: postgres, version: 16, size: medium,
      tenant: shared, tenant_scope: project, extensions: ["pgcrypto"],
      rls_session: true, tenant_guc: "app.tenant_id" ),
]
```
