# RBAC roles, actions & resources

The control-plane API authorizes every request against a set of **rights**. A
right is an [action](#actions) on a [resource](#resources), optionally scoped to
a [project](../how-to/projects.md) or a `<project>/<site>`. A token carries one or
more granted [roles](#default-roles); a role expands to a set of rights. A request
is allowed when a held right satisfies the right the request requires.

For issuing and verifying tokens, see
[Bootstrap authentication](../how-to/auth-bootstrap.md) and
[Make a scoped CI deploy token](../how-to/ci-token.md); for the design, see
[Authentication & authorization](../explanation/auth-model.md).

## Actions

| Action | Meaning |
| --- | --- |
| `read` | Read and list (`GET` endpoints). |
| `write` | Mutate configuration: site config, aliases, domain verification, cache. |
| `deploy` | Ship content: create and activate deployments, upload blobs. |
| `admin` | Full control of the resource. |

Only `admin` implies the others: a held `admin` right on a resource satisfies a
required `read`, `write`, `deploy`, or `admin` on that same resource. The other
three actions are independent. Implication is per-resource — `admin` on `tokens`
does not satisfy any right on `site`.

## Resources

Four resources are target-scoped: `site` (target `<project>/<site>`), `project`
(target `<project>`, since 0.2.0), `secrets` (target `<project>`, since 0.3.10), and
`blob_upload` (target `<project>`, at the mint route). The rest are global.

| Resource | Scoped | Governs |
| --- | --- | --- |
| `site` | `<project>/<site>` | Per-site deployments, config, aliases, domain verification, per-site observability. |
| `project` | `<project>` | The project entity plus the resources it owns — its functions, compute workloads, workflows, and GraphQL admin surface (subgraph registry + safelist). A `project` grant is the tenant boundary: a token scoped to one project cannot touch a sibling. |
| `secrets` | `<project>` | The project's sealed secret store — its `boatramp:<name>` values and SMTP email profiles. Separate from `project` so managing credentials is a distinct, admin-gated right, auditable on its own (since 0.3.10). |
| `blobs` | global | Content-addressed blob uploads. |
| `blob_upload` | `<project>` at the mint route | Minting a scoped, short-lived S3-ingress upload credential for a project's blob container (`POST /api/blob-mint-upload`, `boatramp blob mint-upload`). Deliberately separate from `blobs` (a `deploy`-grade action every publisher holds): minting an external-ingress credential is admin-gated, granted only via `admin` — never a default tenant role. |
| `tokens` | global | API token management. |
| `certs` | global | TLS certificate status. |
| `cache` | global | Cache invalidation. |
| `system` | global | Metrics, prune, scrub, site/project listing, cluster membership, authz policy. |
| `overlay` | global | Overlay forward-flow discovery + capability minting (`/api/overlay/*`). Three tiers: `read` lists/resolves the service directory; `write` mints a holder-bound **dial** capability (self-serve `boatramp forward`); `admin` mints a holder-bound **publish** capability (self-serve `boatramp expose`) — strictly above `write`, because publishing claims a service name that forward clients trust and pin. Granted only via `admin` (or an explicit grant), never a default tenant role. **`admin` is coarse: it may mint a publish capability for ANY service name, and a live exposer shadows a static route of the same name — so an `overlay·admin` holder can reroute or capture any service's forward-client traffic. Treat it as near-admin trust and keep it admin-only until per-name publish scoping exists.** |

## Default roles

The built-in policy defines eight roles. A grant marked *(site)* binds to the role
instance's `<project>/<site>` target; *(project)* binds to its `<project>` target;
*(project/\*)* is a wildcard over every site in the bound project; *(any)* is a
global right.

| Role | Scoped | Grants |
| --- | --- | --- |
| `admin` | global | `admin` on every resource. |
| `publisher` | site | `read`, `write`, `deploy` on `site` *(site)*; `deploy` on `blobs` *(any)*. |
| `deployer` | site | `read`, `deploy` on `site` *(site)*; `deploy` on `blobs` *(any)*. No config write. |
| `viewer` | site | `read` on `site` *(site)*. |
| `operator` | global | `read` on `system` *(any)*; `read` on `certs` *(any)*; `write` on `cache` *(any)*. No site access. |
| `project_admin` | project | `admin` on `project` *(project)*; `admin` on `secrets` *(project)*; `admin` on `site` *(project/\*)*; `deploy` on `blobs` *(any)*. Full control of one project and everything it owns — including managing its sealed secrets and email profiles (a publisher can only *reference* a `boatramp:<name>`, not manage it). |
| `project_publisher` | project | `read`, `write`, `deploy` on `project` *(project)* and on `site` *(project/\*)*; `deploy` on `blobs` *(any)*. Ships sites/functions/compute in the project; cannot admin the project entity. |
| `project_viewer` | project | `read` on `project` *(project)* and on `site` *(project/\*)*. Read-only across one project. |

An unknown role name grants nothing — it is ignored, not an error.

## Scoping

A granted role is written `<role>` (global) or `<role>:<target>` (bound). The
suffix after the first `:` is the target; an empty suffix parses as global. A
**site** role's target is `<project>/<site>`; a **project** role's target is a bare
`<project>`.

| Spec | Interpretation |
| --- | --- |
| `admin` | Global `admin`. |
| `publisher:acme/blog` | `publisher` bound to site `blog` in project `acme`. |
| `viewer:acme/docs` | `viewer` bound to site `docs` in project `acme`. |
| `project_admin:acme` | `project_admin` bound to project `acme` (and every site it owns). |
| `project_viewer:acme` | read-only across project `acme`. |

**Back-compat:** a legacy bare site target (`publisher:blog`, no project segment) is
normalized to the reserved `default` project (`publisher:default/blog`) before the
decision, so pre-0.2.0 tokens keep working unchanged.

Granting a site- or project-scoped role **without** a target (e.g. `publisher` with
no `:target`) drops its scoped rights — a global `publisher` grants only its `blobs`
right. Target matching is exact; a global (wildcard) grant covers every site. A
`project_*` role covers every site in its bound project via a `<project>/*` wildcard.

A token carries a list of granted roles; the rights it confers are the union of
each role's expanded rights. A token minted with `--role publisher:acme/blog --role
viewer:acme/docs` may write `acme/blog`, read `acme/docs`, and upload blobs.

## Request-to-right mapping

Each control-plane endpoint requires exactly one right. A few endpoints require
no right and are gated by their own single-use credential instead. Any unmapped
`/api/*` path falls through to `system` · `admin` (deny-safe), so a narrow token
can never reach an ungated action.

Site and project targets below are the values the right is scoped to. A legacy
`/api/sites/<site>/…` path scopes to `default/<site>`; a `/api/projects/<proj>/…`
path scopes to `<proj>` (or `<proj>/<site>` for its sites).

| Method | Path | Required right |
| --- | --- | --- |
| `POST` | `/api/auth/exchange` | none (carries an IdP JWT) |
| `GET` | `/api/auth/whoami` | none (any valid token) |
| `POST` | `/api/tokens/bootstrap` | none (bootstrap secret) |
| `POST` | `/api/cluster/join` | none (single-use join token) |
| `PUT` | `/api/blobs/<hash>` | `blobs` · `deploy` |
| `POST` | `/api/blob-mint-upload` | `blob_upload` · `write` *(proj, from the request path)* — `blob-upload` feature |
| `GET` | `/api/sites` | `system` · `read` |
| `GET` | `/api/projects` | `system` · `read` |
| `POST` | `/api/projects` | `system` · `admin` |
| `GET` | `/api/projects/<proj>` | `project` · `read` *(proj)* |
| `DELETE` | `/api/projects/<proj>` | `project` · `admin` *(proj)* |
| `GET` | `/api/projects/<proj>/{functions,compute,workflows,graphql}[/…]` | `project` · `read` *(proj)* |
| `POST`/`PUT`/`DELETE` | `/api/projects/<proj>/{functions,compute,workflows,graphql}/…` | `project` · `deploy` *(proj)* |
| `GET` | `/api/projects/<proj>/secrets` | `secrets` · `read` *(proj)* |
| `POST`/`DELETE` | `/api/projects/<proj>/secrets[/<name>]` | `secrets` · `write` *(proj)* |
| `GET` | `/api/projects/<proj>/email/profiles[/<name>]` | `secrets` · `read` *(proj)* |
| `PUT`/`DELETE` | `/api/projects/<proj>/email/profiles/<name>` | `secrets` · `write` *(proj)* |
| `GET` | `/api/projects/<proj>/tenancy` | `project` · `read` *(proj)* |
| `PUT`/`DELETE` | `/api/projects/<proj>/tenancy` | `project` · `admin` *(proj)* — mutating the tenant-isolation boundary is owner-level, above the publisher's `deploy` |
| `POST` | `/api/[projects/<proj>/]sites/<site>/deployments` | `site` · `deploy` *(target)* |
| `GET` | `/api/[projects/<proj>/]sites/<site>/deployments[/<id>]` | `site` · `read` *(target)* |
| `POST` | `/api/[projects/<proj>/]sites/<site>/deployments/<id>/activate` | `site` · `deploy` *(target)* |
| `GET` | `/api/[projects/<proj>/]sites/<site>/config` | `site` · `read` *(target)* |
| `PUT` | `/api/[projects/<proj>/]sites/<site>/config` | `site` · `write` *(target)* |
| `PUT`/`DELETE` | `/api/[projects/<proj>/]sites/<site>/aliases/<name>` | `site` · `write` *(target)* |
| `GET` | `/api/{functions,compute,workflows,graphql}[/…]` (legacy) | `project` · `read` *(default)* |
| `POST`/`PUT`/`DELETE` | `/api/{functions,compute,workflows,graphql}/…` (legacy) | `project` · `deploy` *(default)* |
| `GET` | `/api/functions/<name>/_boatramp/logs[/stream]` | `project` · `read` *(default; `proj` for the project-scoped path)* |
| `POST` | `/api/compute/<name>/exec` | `project` · `deploy` *(default)* — additionally gated at the handler by the `allow_compute_exec` posture |
| `POST` | `/api/sql/<db>/{exec,query,ping}` | `project` · `deploy` *(default)* — SQL writes are additionally posture-gated |
| `GET`/`DELETE` | `/api/compute/volumes[/<name>]` | `system` · `admin` (node-global — **not** the per-project `/api/compute/*` right) |
| `GET`/`POST` | `/api/compute/{status,ipam,dns[/resolve],reconcile}` | `system` · `admin` (node-global — **not** the per-project `/api/compute/*` right) |
| `POST` | `/api/compute/maintenance/{set-health,restart,netdiag}` | `system` · `admin` (node-global — **not** the per-project `/api/compute/*` right) |
| `GET` | `/api/overlay/services` | `overlay` · `read` |
| `POST` | `/api/overlay/dial` | `overlay` · `write` (mint a holder-bound dial capability) |
| `POST` | `/api/overlay/expose` | `overlay` · `admin` — minting a **publish** capability claims a service name forward clients pin, strictly above dial's `overlay` · `write` |
| `POST` | `/api/overlay/invite` | `overlay` · `admin` — minting a single-use `overlay-enroll` invitation admits a NEW identity into the overlay trust set once redeemed |
| `POST` | `/api/overlay/enroll` | none — the enrollee presents a single-use overlay-enroll invitation (verified by the handler), not an admin bearer |
| `POST` | `/api/overlay/pair-code` | `overlay` · `admin` — minting a pairing rendezvous code stands up a relay slot; redemption itself is unauthenticated (the SAS backstops it) |
| `GET` | `/api/overlay/pair-relay` | none — an unauthenticated relay-topology lookup for the human-typeable short-code path (discloses only the relay socket + identity, never a capability) |
| `GET`/`PUT`/`POST` | `/api/overlay/policy[/test]` | `system` · `admin` — editing the overlay **flow policy** is a node-admin act, and `GET`/`test` are a policy-enumeration oracle, so all three sit at the top tier (**not** an `overlay·*` right). The flow policy is a *separate* gate that can only deny-or-shrink a mint `overlay·write`/`admin` already permits — a first step toward the per-name publish scoping the `overlay·admin` note above calls for. |
| `POST`/`DELETE` | `/api/tokens[/<id>]` | `tokens` · `admin` |
| `GET` | `/api/certs` | `certs` · `read` |
| `POST` | `/api/cache/invalidate` | `cache` · `write` |
| `GET` | `/api/metrics` | `system` · `read` |
| `GET`/`POST` | `/api/prune`, `/api/scrub` | `system` · `admin` |
| `POST` | `/api/project-export` | `system` · `admin` — stream a project to a `BRPROJ` bundle from a running node (`project-export` feature) |
| `POST` | `/api/project-import` | `system` · `admin` — import a `BRPROJ` bundle into a project on a running node (`project-export` feature) |
| any | `/api/authz/*` | `system` · `admin` |
| any | other `/api/*` | `system` · `admin` (deny-safe) |

**Node-global compute endpoints are `system` · `admin`, never the per-project
`/api/compute/*` right.** The persistent-volume (`compute/volumes[/<name>]`) and
maintenance/diagnostic (`compute/{status,ipam,dns,reconcile}` and
`compute/maintenance/*`) surfaces operate across *every* tenant on the node — they
enumerate and remove volumes, and observe and override the reconcile plane, for all
projects. They are gated explicitly at `system` · `admin`, above the general
`/api/compute/*` mapping that a project-scoped grant would otherwise satisfy, in both
the direct (`/api/compute/…`) and project-scoped (`/api/projects/<proj>/compute/…`)
path forms — so a project token can never reach another tenant's volumes or state.

## The policy document

The role-to-rights mapping is data, stored as JSON at the KV key `authz/policy`
(schema v1). When the key is absent the built-in default above applies. A
replacement is validated server-side and rejected if invalid, so a bad policy
cannot brick the control plane. Editing it requires an `admin` token:

```sh
boatramp auth policy get              # print the active policy as JSON
boatramp auth policy set policy.json  # validated server-side before storing
```
