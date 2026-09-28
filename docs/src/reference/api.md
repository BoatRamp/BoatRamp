# Control-plane HTTP API

The control-plane API is the transport the CLI speaks to a server. Most operators
never call it directly — the `boatramp` subcommands wrap it — but it is a stable,
documented surface for building your own tooling. This page lists the endpoints;
the [CLI reference](./cli.md) maps each command onto them.

## Conventions

- **Base path.** Every control-plane endpoint is under `/api`. Public serving
  (host-routed content, `/_sites/*`, `/healthz`) is a separate, unauthenticated
  surface.
- **Authentication.** A bearer token in `Authorization: Bearer <token>`. Every
  `/api/*` request is authenticated and authorized, except the handful gated by
  their own single-use credential (bootstrap, join, OIDC exchange). The exact
  right each endpoint requires is in the
  [request-to-right mapping](./rbac.md#request-to-right-mapping).
- **Bodies.** Requests and responses are JSON, except blob upload (raw bytes) and
  `/api/metrics` (Prometheus text).
- **Errors.** A non-2xx status carries a JSON `{ "error": "..." }`. `401` is a
  missing or invalid token; `403` is a valid token without the required right.

## Projects

A [project](../how-to/projects.md) owns sites, functions, and compute, and is the
tenant boundary. Since 0.2.0 every site/function/compute/workflow endpoint has a
project-scoped counterpart under `/api/projects/:project/…`; the legacy top-level
paths (`/api/sites/…`, `/api/functions/…`, `/api/compute/…`, `/api/workflows/…`)
target the reserved `default` project and stay byte-identical to pre-0.2.0.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/projects` | List projects. |
| `POST` | `/api/projects` | Create a project. |
| `GET` | `/api/projects/:project` | Get one project's record. |
| `DELETE` | `/api/projects/:project` | Delete an empty project (refused while it owns resources or is `default`). |
| any | `/api/projects/:project/sites/…` | Per-project site endpoints — the same shapes as [Sites & deployments](#sites--deployments), scoped to the project. |
| any | `/api/projects/:project/{functions,compute,workflows,graphql}/…` | Per-project function / compute / workflow / GraphQL-admin endpoints, scoped to the project. |

## Sites & deployments

The paths below target the `default` project; the `/api/projects/:project/sites/…`
counterparts are identical but scoped to `:project`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/sites` | List sites. |
| `POST` | `/api/sites/:site/deployments` | Create a deployment from a manifest. |
| `GET` | `/api/sites/:site/deployments` | List a site's deployments. |
| `GET` | `/api/sites/:site/deployments/:id` | Get one deployment. |
| `POST` | `/api/sites/:site/deployments/:id/activate` | Make a deployment the live one. |
| `GET` | `/api/sites/:site/current` | The currently active deployment. |
| `GET`/`PUT` | `/api/sites/:site/config` | Read / replace the [site config](./siteconfig.md). |
| `GET`/`PUT`/`DELETE` | `/api/sites/:site/aliases/:name` | Manage named aliases. |
| `GET` | `/api/sites/:site/aliases` | List aliases. |

## Blobs

| Method | Path | Purpose |
| --- | --- | --- |
| `PUT` | `/api/blobs/:hash` | Upload a content-addressed blob (raw body; the server verifies the hash). |

### Blob-backend migration (node-level)

Complete a zero-downtime blob-backend switch on a managed node reachable only over the
control plane (no `fly ssh` / local shell). These operate on the node's **own** configured
blob store — never a client-named backend — so they are gated at `system` · `admin` (the
destructive drain/purge) or `system` · `read` (the status probe), like `prune` / `scrub` /
`sql-move`. The singular hyphenated paths (`blob-drain`, `blob-status`, `blob-purge`)
deliberately do **not** collide with the `/api/blobs/…` (`Blobs` · `Deploy`) content-upload
matcher, so a ship-only publisher can never reach them.

#### `POST /api/blob-drain`

Since 0.6.3. Drain the node's own configured `[serve].blob_fallback` read-fallback
**secondary → primary** (`Storage::drain_pair` on the live composite), so the fallback can be
removed. The client guides; the running daemon (which already holds both backends open)
executes. `system` · `admin`.

The body names **no** source or destination — the daemon drains only its own configured pair:

```json
{ "dry_run": false, "concurrency": 8, "prefix": "" }
```

All fields are optional (`deny_unknown_fields`); `dry_run` defaults to `false`, `concurrency`
to the engine default (8), an absent/empty `prefix` drains every object.

The response is an **NDJSON** stream (`application/x-ndjson`) — one JSON object per line — kept
alive over a chunked connection so an edge idle-timeout can't cut a long copy (the copy is
idempotent and resumable, so a dropped connection is safe to re-run). Progress lines are tagged
`"type":"progress"`; the final line is tagged `"type":"report"`:

```
{"type":"progress","done":2,"total":3,"copied":2,"skipped":0,"copied_bytes":4096,"dry_run":false}
{"type":"report","total_objects":3,"copied_objects":3,"skipped_objects":0,"copied_bytes":6144,"verified":true,"dry_run":false,"secondary_drained":true,"message":"SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node."}
```

`secondary_drained` is `true` **only** on a verified-complete, non-dry-run drain. A verify
failure reports `secondary_drained:false` plus the missing keys. With no `[serve].blob_fallback`
configured, the request is a **422** (`{ "error": "no blob_fallback configured; nothing to drain" }`).

#### `GET /api/blob-status`

Since 0.6.4. Query the node's structured transition-mode state — whether a read-fallback
secondary is currently attached (the node is mid-migration) — instead of grepping the startup
log warning. `system` · `read`.

```json
{ "blob_fallback_active": true }
```

#### `POST /api/blob-purge`

Since 0.6.4. Reclaim a **provably-safe-only** object set on the node's blob store. Dry-run by
default (report only, delete nothing); `apply: true` deletes. `system` · `admin`.

```json
{ "mode": "unreferenced", "apply": false, "prefix": "" }
```

`deny_unknown_fields`. `mode` is required and is one of:

- `"unreferenced"` — on-demand garbage collection: delete content-addressed blobs no live
  deploy manifest references (nothing serving can break). Refused with **409** while a
  read-fallback secondary is attached (drain and drop `[serve].blob_fallback` first). `prefix`
  is ignored in this mode.
- `"drained_source"` — the migration decommission: delete the read-fallback secondary's objects
  that are **byte-confirmed present in the primary** (fail-closed — an unconfirmed object is
  kept). `prefix` restricts the scope. With no `[serve].blob_fallback` configured, the request is
  a **422**.

The response is **NDJSON** (progress lines then a final `"type":"report"` line), the same shape
as the drain:

```
{"type":"report","mode":"drained_source","apply":true,"considered":3,"purged":1,"would_purge":0,"skipped_unconfirmed":2,"purged_bytes":17,"message":"drained-source purge complete: reclaimed 1 confirmed-duplicated object(s) (17 byte(s)); kept 2 unconfirmed"}
```

See [Migrate the blob backend](../how-to/blob-backend-migration.md).

## Domains

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`/`POST`/`DELETE` | `/api/sites/:site/domains/:host/verification` | Manage a domain-ownership challenge. |
| `POST` | `/api/sites/:site/domains/:host/verification/check` | Check the challenge. |
| `GET` | `/api/sites/:site/domain-verifications` | List pending verifications. |

## Tokens

| Method | Path | Purpose |
| --- | --- | --- |
| `POST`/`GET` | `/api/tokens` | Mint / list tokens. |
| `DELETE` | `/api/tokens/:id` | Revoke a token by its id. |
| `POST` | `/api/tokens/bootstrap` | Mint the first admin token with the single-use bootstrap secret. |
| `GET` | `/api/auth/whoami` | The presented token's own roles. |
| `POST` | `/api/auth/exchange` | Exchange an OIDC JWT for a short-TTL token (`oidc` feature). |

## Cluster

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/cluster/join-token` | Mint a single-use bearer mesh join token (admin). |
| `POST` | `/api/cluster/join` | Admit a joining node (gated by the join token in the body + a possession proof, not admin RBAC). |
| `GET` | `/api/cluster/members` | List the Raft membership (node, voter, caught-up, leader, address). |
| `POST` | `/api/cluster/promote` | Promote a caught-up learner to a voter (leader-only). |
| `POST` | `/api/cluster/rotate-key` | Rotate this node's mesh key (make-before-break). |
| `POST` | `/api/cluster/revoke` | Revoke a node from the mesh (durable tombstone + drop from quorum). |

See [Deploy a self-hosted cluster](../how-to/deploy-cluster.md) and
[Run on Kubernetes](../how-to/kubernetes.md).

## Root anchors

Make-before-break root-key rotation (`auth rotate-root`). Admin-scoped.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/auth/root` | List the extra trusted root anchors. |
| `PUT` | `/api/auth/root` | Trust a new root anchor (`{ "pubkey": "alg:hex" }`). |
| `DELETE` | `/api/auth/root/:pubkey` | Retire a root anchor. |

See [Migrate the root key](../how-to/migrate-root-key.md).

## Certificates & cache

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/certs` | TLS certificate status. |
| `POST` | `/api/cache/invalidate` | Invalidate cached responses. |

## Operations

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`/`POST` | `/api/prune` | Report / delete unreferenced deployments. |
| `POST` | `/api/scrub` | Delete unreferenced blobs. |
| `GET` | `/api/metrics` | Prometheus exposition (always available). |
| `GET`/`PUT` | `/api/authz/policy` | Read / replace the [RBAC policy](./rbac.md#the-policy-document). |

## Functions & workflows

Top-level (`default`-project) function and workflow endpoints; the
`/api/projects/:project/…` counterparts scope to another project.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/functions` | List functions. |
| `GET`/`PUT`/`DELETE` | `/api/functions/:name` | Manage one function (its current version). |
| `POST` | `/api/functions/:name/versions` | Deploy a new function version. |
| `POST` | `/api/functions/:name/rollback` | Roll back to a prior version. |
| `PUT`/`DELETE` | `/api/functions/:name/aliases/:label` | Manage a version alias. |
| `POST` | `/api/functions/:name/invoke` | Invoke synchronously / async / scheduled. |
| `GET` | `/api/functions/:name/invocations/:id` | Get an async invocation record. |
| `GET`/`POST`/`DELETE` | `/api/functions/:name/triggers[/:id]` | Manage event triggers (webhook/queue/cron/blob). |
| `GET` | `/api/functions/:name/usage` | Metering / quota counters. |
| `GET`/`PUT`/`DELETE` | `/api/workflows/:name` | Manage a declarative workflow. |
| `GET` | `/api/workflows/:name/runs[/:id]` | List / get workflow runs. |

## Compute

Top-level paths target the `default` project; `/api/projects/:project/compute/…`
scopes to another project.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/compute` | List compute workloads. |
| `GET`/`PUT`/`DELETE` | `/api/compute/:name` | Manage one workload. |
| `POST` | `/api/compute/:name/exec` | Run a command inside a running replica (docker-exec style; posture-gated by `allow_compute_exec`). Since 0.3.9. |

The control-plane surface is uniform whether or not execution is available on the
node. Only the **microVM** backend needs `/dev/kvm`; the native **container** backend
instead needs the `br-boatramp` bridge and `CAP_NET_ADMIN` (both compute backends are
Linux-only). On macOS / Windows compute runs through the remote-docker backend. See
[Run compute workloads](../how-to/compute.md).

### Compute operations (node-global)

These operate across **every** tenant on the node and are gated at `system` · `admin`
— not the per-project `/api/compute/*` right. Since 0.3.9 (volumes: 0.3.11;
maintenance/diagnostics: 0.3.14).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/compute/volumes` | List persistent volumes (in-use vs orphaned). |
| `DELETE` | `/api/compute/volumes/:name` | Reclaim a volume (`?force=true` to remove one still referenced). |
| `GET` | `/api/compute/status` | Observed per-replica runtime state (health, lifecycle phase, IP:port, backend). |
| `GET` | `/api/compute/ipam` | The compute-bridge IP-pool allocation. |
| `GET` | `/api/compute/dns` | The internal-DNS fleet view. |
| `POST` | `/api/compute/dns/resolve` | Resolve an internal name as a container would (diagnostic). |
| `POST` | `/api/compute/reconcile` | Force a reconcile pass. |
| `POST` | `/api/compute/maintenance/set-health` | Override a replica's stored health. |
| `POST` | `/api/compute/maintenance/restart` | Stop + relaunch a replica. |
| `POST` | `/api/compute/maintenance/netdiag` | Run a network diagnostic. |

See [Diagnose compute](../how-to/diagnose-compute.md).

## Managed SQL (operator)

Run a migration script or a single query against a managed co-located database via
its sealed credential (resolved server-side). Project-owned (`project` · `deploy`);
writes are additionally posture-gated. Top-level paths target the `default` project;
`/api/projects/:project/sql/…` scopes to another project. Since 0.3.9 (`ping`: 0.3.14).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/sql/:db/exec` | Run a migration / statement script against the managed database `:db`. |
| `POST` | `/api/sql/:db/query` | Run a single query and return its rows. |
| `POST` | `/api/sql/:db/ping` | Active per-replica reachability probe (bypasses the stored-health gate). |

## Schema migrations (owner-gated)

Apply an ordered migration step set — `function` / `sql` / `extension` steps — to a
managed database `:db`, run as the project's non-superuser **owner** role and tracked in
a host-owned ledger. Input is **upload-then-trigger**: the JSON step-set bundle is
uploaded via `PUT /api/blobs/:hash` and referenced by hash. The mutating verbs are gated
at `project` · `admin` (never the deploy-grade publisher right `/api/sql/` uses); `status`
needs only `project` · `read`. Top-level paths target the `default` project;
`/api/projects/:project/migrate/…` scopes to another project. Since 0.4.25 (Postgres only).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/migrate/:db/apply` | Apply the pending suffix of the bundle; body `{ bundle }`. `project` · `admin`. |
| `POST` | `/api/migrate/:db/dry-run` | Report which ids would apply, running nothing; body `{ bundle }`. `project` · `admin`. |
| `POST` | `/api/migrate/:db/baseline` | Record the prefix through `up_to` as already-applied without running it; body `{ bundle, up_to }`. `project` · `admin`. |
| `GET` | `/api/migrate/:db/status` | Read the applied-migration ledger (id, ordinal, hash, kind, applied-at, origin). `project` · `read`. |

See [Run owner-gated schema migrations](../how-to/in-app-migrations.md).

## Provisioning drift-repair (owner-gated)

Converge a managed database's provisioning against spec — create/seal the non-superuser owner
role, re-own the database + its objects + the migration ledger, re-grant runtime privileges —
idempotently and data-preservingly (`boatramp project repair`). Deliberately **not** under
`/api/sql/` (whose catch-all resolves to `project` · `deploy`, which a ship-only publisher holds
— nesting there would be an escalation); its own `/api/repair/*` prefix gates **both** verbs at
`project` · `admin`. Dry-run is the report-only posture the CLI uses by default. Top-level paths
target the `default` project; `/api/projects/:project/repair/…` scopes to another project. Since
0.5.2 (all SQL backends).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/repair/:db/apply` | Apply the reconcile — converge provisioning against spec. `project` · `admin`. |
| `POST` | `/api/repair/:db/dry-run` | Drift-detect + report the plan, changing nothing (the default CLI posture). `project` · `admin`. |

## Managed databases (declarative)

The project-scoped declarative front door onto the daemon-level managed-database provisioning
stack (a per-tenant Postgres/MySQL whose credential boatramp mints and seals). These back
`boatramp db ls | get | status` and the `apply`-manifest `databases:` block; there is no
`db create` — the manifest is the sole authoring surface. Declaring a database mints owner-role
identities (`CREATE ROLE` / owner-role DDL as superuser), so the write verbs gate at
`project` · `admin` — the same owner-grade placement as `/api/migrate/` and `/api/repair/`, above
the project-deploy catch-all, so a `project_publisher` / deployer can never reach them; the reads
are `project` · `read`. Top-level paths target the `default` project;
`/api/projects/:project/databases/…` scopes to another project. Since 0.6.0.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/databases` | List the project's declared databases (each an `ApplyDatabase`). `project` · `read`. |
| `GET` | `/api/databases/:name` | Get one declared database, or `404`. `project` · `read`. |
| `PUT` | `/api/databases/:name` | Declare (persist + eagerly provision) a database from an `ApplyDatabase` body. `204` on success. `project` · `admin`. |
| `POST` | `/api/databases/:name/ensure` | Re-provision an already-declared database idempotently. `204`. `project` · `admin`. |
| `GET` | `/api/databases/:name/status` | The stored declaration + a coarse provisioned signal. `project` · `read`. |

The `PUT` body is a typed `ApplyDatabase` (`deny_unknown_fields`) — a **safe projection** that
carries only the fields a project author may declare. Naming an excluded field (`image`,
`password_env` / `url_env` / `read_url_env` / `migration_url_env`, `path`, `compute`) fails to
parse — those are the security contract (arbitrary-image RCE, BYO-secret/SSRF, host-fs traversal,
author-named workload). The credential is never carried or referenced; boatramp fully manages and
seals it.

```json
{
  "name": "app",
  "kind": "postgres",
  "version": 16,
  "size": "medium",
  "tenant": "shared",
  "tenant_scope": "project",
  "extensions": ["pgcrypto"],
  "rls_session": true,
  "tenant_guc": "app.tenant_id"
}
```

Only `name` and `kind` (`postgres` / `mysql`) are required. `size` is a `small` / `medium` /
`large` preset (default `small`, → bounded vcpus/mem/volume, not raw VM knobs); `tenant` is
`single` (default) / `shared`; `tenant_scope` is `project` (default) / `site`. The remaining
optional fields — `version`, `extensions`, `read_only`, the RLS knobs (`rls_session`, `tenant_guc`,
`session_guc`, `tenant_all_marker`), and the capped `pool_max` / `connect_timeout_secs` /
`startup_grace_secs` — are omitted from a response when unset.

`GET /api/databases` returns a JSON array of `ApplyDatabase`; `GET /api/databases/:name` returns
one. `GET /api/databases/:name/status` wraps the declaration with a workload handle and a coarse
provisioned fact (never a secret):

```json
{
  "database": { "name": "app", "kind": "postgres", "size": "medium", "tenant": "shared", "tenant_scope": "project" },
  "workload": "bramp-db-<project>-app",
  "declared": true
}
```

The declarative `databases:` manifest block that drives these routes is covered under
[Declare a managed database](../how-to/managed-databases.md); see also [Apply a manifest](../how-to/apply.md).

## Secrets & email profiles

Project-scoped credential stores, gated by the `secrets` right (see
[RBAC](./rbac.md#request-to-right-mapping)). A value never leaves over the API — the
list/show responses are metadata-only (secrets) or redacted (email). Present only
when a `[secrets]` key envelope is configured (else a clear `501`). Secrets since
0.3.10; email profiles since 0.3.18.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/projects/:project/secrets` | Set (seal) a secret `{ name, value }`; returns metadata, never the value. |
| `GET` | `/api/projects/:project/secrets` | List secret names + metadata (no values). |
| `DELETE` | `/api/projects/:project/secrets/:name` | Delete a secret. |
| `PUT` | `/api/projects/:project/email/profiles/:name` | Set / partial-update an SMTP profile (sealed password); returns the redacted profile. |
| `GET` | `/api/projects/:project/email/profiles[/:name]` | List / show email profiles (redacted). |
| `DELETE` | `/api/projects/:project/email/profiles/:name` | Delete an email profile. |

See [Store secrets](../how-to/secrets.md) and [Send email](../how-to/send-email.md).

## Tenancy schema

The project's per-table tenant-key map — the isolation boundary that scopes every
guest query. Read with `project` · `read`; replace/clear with `project` · `admin`
(above the publisher's deploy right, so a publisher cannot redraw the boundary).
Since 0.4.3.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/projects/:project/tenancy` | Read the tenancy schema. |
| `PUT` | `/api/projects/:project/tenancy` | Replace the tenancy schema. |
| `DELETE` | `/api/projects/:project/tenancy` | Clear it (back to deny-by-default). |

See [Isolate tenants](../how-to/tenant-isolation.md).

## GraphQL

The subgraph registry, the operation safelist, and the composed supergraph — a
project-owned surface. Top-level paths target the `default` project;
`/api/projects/:project/graphql/…` scopes to another project. See
[Serve a GraphQL API](../how-to/graphql.md).

| Method | Path | Purpose |
| --- | --- | --- |
| `PUT`/`DELETE` | `/api/graphql/subgraphs/:name` | Register (SDL body) / unregister a subgraph; a publish recomposes and is rejected if it doesn't compose. |
| `PUT` | `/api/graphql/subgraphs/:name/sql` | Register a SQL-backed subgraph by introspecting a site's managed database. |
| `PUT` | `/api/graphql/subgraphs/:name/function` | Register a function-backed subgraph by introspecting its `_service { sdl }`. |
| `GET` | `/api/graphql/supergraph` | The composed supergraph (subgraphs, `@key` entities, root fields). |
| `POST`/`GET` | `/api/graphql/safelist` | Register a trusted operation (returns its hash) / list the safelist. |
| `DELETE` | `/api/graphql/safelist/:hash` | Remove an operation from the safelist. |

A function that self-declares a subgraph auto-registers on deploy; pass
`?register_subgraph=false` to `PUT /api/functions/:name` to opt a deploy out. See
[Federation](../how-to/graphql.md#federation).

## Observability

Present with the `handlers` feature.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/sites/:site/_boatramp/handlers` | Per-handler operator stats. |
| `GET` | `/api/sites/:site/_boatramp/logs` | Captured per-site guest logs. |
| `GET` | `/api/sites/:site/_boatramp/logs/stream` | Stream per-site logs (SSE). |
| `POST` | `/api/sites/:site/_boatramp/dlq` | Dead-letter-queue operations. |
| `GET`/`POST` | `/api/projects/:project/_boatramp/bus/dlq` | Shared **project-bus** DLQ: inspect (`Project·Read`) / purge·redrive·discard (`Project·Admin`). Since 0.4.24. |
| `GET` | `/api/projects/:project/_boatramp/bus/queue/{peek,replay,groups}` | Project-bus live-queue inspection (`Project·Read`). Since 0.4.24. |
| `POST` | `/api/projects/:project/_boatramp/bus/queue/{group,pause}` | Project-bus group reset·delete / pause·resume (`Project·Admin`). Since 0.4.24. |
| `GET` | `/api/functions/:name/_boatramp/logs` | Captured per-function guest logs (project-owned read). Since 0.3.17. |
| `GET` | `/api/functions/:name/_boatramp/logs/stream` | Stream per-function logs (SSE). Since 0.3.17. |

The function-logs endpoints have a `/api/projects/:project/functions/…` counterpart
scoped to another project. See [Observe a running server](../how-to/observe.md).

## Agent (MCP)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST`/`GET`/`DELETE` | `/mcp` | [Model Context Protocol](../how-to/mcp.md#over-http) endpoint (streamable-http), for driving this node from an AI agent. |

Unlike `/api/*`, `/mcp` is gated only by a **valid plain bearer** (not a specific
right): each MCP tool call is separately re-authorized in-process against the
forwarded token's scope. On by default; toggle with `mcp.enabled`
([daemon config](./daemon-config.md)). `cnf`/DPoP tokens are rejected — use a plain
bearer or the stdio transport.

## Public (unauthenticated) endpoints

Never token-authenticated. Visitor access control (basic auth / IP rules / rate
limit) is applied per-site inside the serving handlers.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness. |
| `GET` | `/readyz` | Readiness. |
| any | `/` (host-routed) | Serve site content, selected by `Host` — see [How a request reaches your site](../explanation/addressing.md). |
| any | `/_sites/<name>/*` | Serve a site by name (admin/testing). |
| `GET` | `/_deploy/*` | Serve a deployment by id (an unguessable content-hash capability). |
