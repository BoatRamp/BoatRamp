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

Requires KVM on the serving host; the control-plane surface is uniform whether or
not execution is available. See [Run compute workloads](../how-to/compute.md).

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

## Per-site observability

Present with the `handlers` feature.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/sites/:site/_boatramp/handlers` | Per-handler operator stats. |
| `GET` | `/api/sites/:site/_boatramp/logs` | Captured guest logs. |
| `GET` | `/api/sites/:site/_boatramp/logs/stream` | Stream logs (SSE). |
| `POST` | `/api/sites/:site/_boatramp/dlq` | Dead-letter-queue operations. |

See [Observe a running server](../how-to/observe.md).

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
