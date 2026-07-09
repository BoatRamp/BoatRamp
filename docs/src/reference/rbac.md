# RBAC roles, actions & resources

The control-plane API authorizes every request against a set of **rights**. A
right is an [action](#actions) on a [resource](#resources), optionally scoped to
a site. A token carries one or more granted [roles](#default-roles); a role
expands to a set of rights. A request is allowed when a held right satisfies the
right the request requires.

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

Only `site` is target-scoped (the target is a site name); the other five are
global.

| Resource | Scoped | Governs |
| --- | --- | --- |
| `site` | site | Per-site deployments, config, aliases, domain verification, per-site observability. |
| `blobs` | global | Content-addressed blob uploads. |
| `tokens` | global | API token management. |
| `certs` | global | TLS certificate status. |
| `cache` | global | Cache invalidation. |
| `system` | global | Metrics, prune, scrub, site listing, cluster membership, authz policy. |

## Default roles

The built-in policy defines five roles. A grant marked *(site)* binds to the
role instance's target; *(any)* is a global right.

| Role | Scoped | Grants |
| --- | --- | --- |
| `admin` | global | `admin` on every resource. |
| `publisher` | site | `read`, `write`, `deploy` on `site` *(site)*; `deploy` on `blobs` *(any)*. |
| `deployer` | site | `read`, `deploy` on `site` *(site)*; `deploy` on `blobs` *(any)*. No config write. |
| `viewer` | site | `read` on `site` *(site)*. |
| `operator` | global | `read` on `system` *(any)*; `read` on `certs` *(any)*; `write` on `cache` *(any)*. No site access. |

An unknown role name grants nothing — it is ignored, not an error.

## Scoping

A granted role is written `<role>` (global) or `<role>:<site>` (bound to one
site). The suffix after the first `:` is the target site; an empty suffix parses
as global.

| Spec | Interpretation |
| --- | --- |
| `admin` | Global `admin`. |
| `publisher:blog` | `publisher` bound to site `blog`. |
| `viewer:docs` | `viewer` bound to site `docs`. |

Granting a site-scoped role **without** a target (e.g. `publisher` with no
`:site`) drops its site rights — a global `publisher` grants only its `blobs`
right. Site matching is exact; a global (wildcard) grant covers every site.

A token carries a list of granted roles; the rights it confers are the union of
each role's expanded rights. A token minted with `--role publisher:blog --role
viewer:docs` may write `blog`, read `docs`, and upload blobs.

## Request-to-right mapping

Each control-plane endpoint requires exactly one right. A few endpoints require
no right and are gated by their own single-use credential instead. Any unmapped
`/api/*` path falls through to `system` · `admin` (deny-safe), so a narrow token
can never reach an ungated action.

| Method | Path | Required right |
| --- | --- | --- |
| `POST` | `/api/auth/exchange` | none (carries an IdP JWT) |
| `GET` | `/api/auth/whoami` | none (any valid token) |
| `POST` | `/api/tokens/bootstrap` | none (bootstrap secret) |
| `POST` | `/api/cluster/join` | none (single-use join token) |
| `PUT` | `/api/blobs/<hash>` | `blobs` · `deploy` |
| `GET` | `/api/sites` | `system` · `read` |
| `POST` | `/api/sites/<site>/deployments` | `site` · `deploy` |
| `GET` | `/api/sites/<site>/deployments[/<id>]` | `site` · `read` |
| `POST` | `/api/sites/<site>/deployments/<id>/activate` | `site` · `deploy` |
| `GET` | `/api/sites/<site>/config` | `site` · `read` |
| `PUT` | `/api/sites/<site>/config` | `site` · `write` |
| `PUT`/`DELETE` | `/api/sites/<site>/aliases/<name>` | `site` · `write` |
| `POST`/`DELETE` | `/api/tokens[/<id>]` | `tokens` · `admin` |
| `GET` | `/api/certs` | `certs` · `read` |
| `POST` | `/api/cache/invalidate` | `cache` · `write` |
| `GET` | `/api/metrics` | `system` · `read` |
| `GET`/`POST` | `/api/prune`, `/api/scrub` | `system` · `admin` |
| any | `/api/authz/*` | `system` · `admin` |
| any | other `/api/*` | `system` · `admin` (deny-safe) |

## The policy document

The role-to-rights mapping is data, stored as JSON at the KV key `authz/policy`
(schema v1). When the key is absent the built-in default above applies. A
replacement is validated server-side and rejected if invalid, so a bad policy
cannot brick the control plane. Editing it requires an `admin` token:

```sh
boatramp auth policy get              # print the active policy as JSON
boatramp auth policy set policy.json  # validated server-side before storing
```
