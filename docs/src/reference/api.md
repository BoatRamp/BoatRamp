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

## Sites & deployments

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
| `POST` | `/api/cluster/join-token` | Mint a single-use mesh join token. |
| `POST` | `/api/cluster/join` | Admit a joining node presenting a join token. |
| `POST` | `/api/cluster/rotate-key` | Rotate this node's mesh key (make-before-break). |
| `POST` | `/api/cluster/revoke` | Revoke a node from the mesh. |

See [Manage cluster mesh certificates](../how-to/cluster-certs.md).

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

## Compute

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/compute` | List compute workloads. |
| `GET`/`PUT`/`DELETE` | `/api/compute/:name` | Manage one workload. |

Requires KVM on the serving host; the control-plane surface is uniform whether or
not execution is available. See [Run compute workloads](../how-to/compute.md).

## Per-site observability

Present with the `handlers` feature.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/sites/:site/_boatramp/handlers` | Per-handler operator stats. |
| `GET` | `/api/sites/:site/_boatramp/logs` | Captured guest logs. |
| `GET` | `/api/sites/:site/_boatramp/logs/stream` | Stream logs (SSE). |
| `POST` | `/api/sites/:site/_boatramp/dlq` | Dead-letter-queue operations. |

See [Observe a running server](../how-to/observe.md).

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
