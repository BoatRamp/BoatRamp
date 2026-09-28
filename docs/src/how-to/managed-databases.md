# Declare a managed database

A project handler that opens a `sql` / `orm` binding needs a database behind it.
boatramp can **provision and fully manage** that database for you — mint its
credential, seal it, follow the workload across restarts — driven entirely from
the `apply` manifest. You declare *what* you want (a Postgres 16, medium-sized,
shared-tenant, with `pgcrypto`); boatramp provisions it, wires the `sql` binding,
and **never puts the credential in your manifest**.

This is the declarative front door onto the daemon-level managed-database stack.
Before v0.6.0 an operator had to hand-edit `boatramp.cfg`; now a project author
adds a `databases:` entry and runs `boatramp apply`.

## Before you start

- A boatramp server and a token with **`Project·Admin`** — declaring a database
  mints owner-role identities (it is the same owner-grade gate as schema
  migrations and repair). A publisher/deployer token cannot declare one. See
  [Bootstrap authentication & mint tokens](./auth-bootstrap.md).
- An `apply` manifest for the project. See
  [Declare a project with `apply`](./apply.md).

## 1. Declare the database in the manifest

Add a `databases: [ … ]` block to the manifest. Each entry is a typed, **safe**
projection of the internal database config — it carries only the fields a project
author may safely set:

```ron
(
    project: "acme",

    databases: [
        ( name: "app", kind: postgres, version: 16, size: medium,
          tenant: shared, tenant_scope: project,
          extensions: ["pgcrypto"],
          rls_session: true, tenant_guc: "app.tenant_id" ),
    ],

    sites: [
        // a site whose handler opens sql.open("app") — bound to the DB above
        ( name: "www", path: "www/dist" ),
    ],
)
```

Databases are reconciled **before** sites, functions, and compute, so a handler
shipped in the same `apply` binds an already-provisioned database. The block is
additive — an absent `databases:` still parses (no version bump, no migration).

### Fields you can declare

| Field | Meaning |
| --- | --- |
| `name` | The binding name — what a handler opens (`sql.open("app")`). |
| `kind` | `postgres` or `mysql`. |
| `version` | The engine major version (e.g. `16`). |
| `size` | A `small` / `medium` / `large` **preset** → bounded vcpus/mem/volume (not raw VM knobs). |
| `extensions` | Postgres extensions to enable (subject to the operator's trusted-extension allowlist). |
| `tenant` | `single` (dedicated) or `shared` (one server, per-tenant isolation). |
| `tenant_scope` | `project` or `site` — the granularity a shared server isolates by. |
| `read_only` | Provision a read-only binding. |
| `rls_session` / `tenant_guc` / `session_guc` / `tenant_all_marker` | Row-level-security / session knobs for tenant isolation. |
| `pool_max` / `connect_timeout_secs` / `startup_grace_secs` | Connection knobs — each **capped** to an operator ceiling. |

See the [`databases:` schema](../reference/project-cfg.md#managed-databases-databases) for the full
field reference.

### Fields you cannot declare — the security contract

These are deliberately **not** manifest fields; a manifest that names one **fails
to parse**:

- `image` — a manifest can't name an arbitrary OCI image (RCE).
- `password_env` / `url_env` / `read_url_env` / `migration_url_env` — no
  BYO-secret / SSRF / arbitrary-host references. **Omitting `password_env` is
  exactly what makes a declared database the fully-managed path**: boatramp mints
  and seals the credential, so the manifest never carries or references a secret.
- `path` — no host-filesystem traversal.
- `compute` — the per-project server workload is **derived**, never author-named.

## 2. Apply

```console
$ boatramp apply -f apply.cfg
```

`apply` persists the declaration, then eagerly triggers the idempotent provision,
so the database exists by the time `apply` returns. The credential is **minted
and sealed server-side** and the `sql` binding is wired — nothing about the
secret ever crosses the wire in the manifest.

Re-applying is safe and converges: a same-name re-apply consumes no fresh
resource. A re-apply that **changes an identity field** (`kind` / `tenant` /
`tenant_scope`) of an existing declared database is **refused** — a silent
data-loss / orphan guard. **Removing** a `databases:` entry never drops the
database, its volume, or the credential; teardown stays an explicit imperative
verb (removal is decoupled from the manifest so an accidental deletion can't
destroy data).

## 3. Inspect (read-only)

The `boatramp db` command inspects the project's declared databases. It is
**read-only** — there is deliberately **no `db create`**: the manifest is the
sole authoring surface (a create verb would compete as a second source of truth).
These reads are `Project·Read`.

```console
$ boatramp db ls
NAME                      KIND        TENANT    SCOPE     SIZE
app                       postgres    shared    project   Medium

$ boatramp db get app                  # the full declaration
$ boatramp db status app               # declaration + derived server-workload handle
database `app`
  server workload: <derived-handle>
  declared:        yes
```

Add `--json` to any of them for the raw structured view. To declare, change, or
tear down a database, edit the manifest and `apply` (or use the imperative
teardown verb) — not this command.

## How the declaration merges with node config

A declared database is persisted to a project-scoped, cluster-replicated
control-plane store (under the `project/<proj>/` prefix, so a project teardown
reaps it). At serve time, boatramp merges this per-project store with the
node-static `[handlers].bindings.sql.databases` map at **one** merge point, where
**the node-operator's static config wins, fail-closed, on a same-name conflict**.
A project manifest can never shadow, override, or downgrade an operator's
bring-your-own binding — the refusal is enforced at the merge point, so even a
node reloading config with both present refuses (not merely the `apply` CLI).

## Limits

Two operator-configurable **per-project ceilings** guard against a `Project·Admin`
declaring an unbounded number of databases (each eagerly provisioning a
multi-GiB volume), enforced fail-closed at declare (a `422` before any provision):

- `handlers.bindings.sql.max_declared_databases` — a count (default 16).
- `handlers.bindings.sql.max_declared_volume_mib` — an aggregate volume cap
  (default 512 GiB).

The provisioning is bound to the caller's project — a manifest can only ever
provision onto its **own** project's server.

## See also

- [`databases:` schema](../reference/project-cfg.md#managed-databases-databases)
- [Declare a project with `apply`](./apply.md)
- [`boatramp db` CLI](../reference/cli.md#boatramp-db)
- [Isolate tenants within a project](./tenant-isolation.md)
- [Use kv / sql / blobstore / messaging](./handler-bindings.md)
