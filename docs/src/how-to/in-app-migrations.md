# Run owner-gated schema migrations

Your handlers own their **rows**; you also need to evolve the **schema** they run
against — add a table, an index, an RLS policy, a column. boatramp gives you an
owner-gated, control-plane migration surface for its managed databases: **you supply
the ordered migration steps, boatramp owns the sequencing, tracking, idempotency, and
transactionality**, and you trigger it with an admin token. There is no migration
framework to embed and no long-lived DDL credential to hand out — a step runs once, in
order, and is recorded so a re-run is a no-op.

> **Postgres only (this release).** The owner-role / RLS model and transactional DDL
> are Postgres semantics. A migration against a MySQL managed database is refused with a
> clear error. Shipped in v0.4.25.

## What boatramp owns, what you supply

You supply an **ordered set of steps**. Each step has a stable author-given `id` and is
exactly one of:

- a **`sql`** script — DDL/DML applied as the project owner role, or
- an **`extension`** — an allowlisted Postgres extension enabled by name.

boatramp owns everything else: it applies only the **pending suffix** (steps whose `id`
isn't already recorded), each `sql` step committed **atomically together with its ledger
row**, in the order you gave, exactly once. It refuses a set that reordered or changed an
already-applied step (see [How it stays safe](#how-it-stays-safe)).

## Trigger a migration

The surface is three admin endpoints on a managed database `:db`. All examples assume an
admin token in `BOATRAMP_TOKEN` (see [Bootstrap authentication](./auth-bootstrap.md)).
Paths below target the `default` project; the `/api/projects/<project>/migrate/…`
counterpart scopes to another project.

**Apply** the pending steps:

```sh
curl -sS -X POST https://cp.example.com/api/projects/acme/migrate/appdb/apply \
  -H "Authorization: Bearer $BOATRAMP_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "steps": [
      { "id": "0001_init",
        "sql": "CREATE TABLE orders (id bigserial PRIMARY KEY, tenant_id text NOT NULL, total numeric NOT NULL);" },
      { "id": "0002_pgcrypto", "extension": "pgcrypto" },
      { "id": "0003_orders_tenant_idx",
        "sql": "CREATE INDEX CONCURRENTLY orders_tenant_idx ON orders (tenant_id);",
        "no_transaction": true }
    ]
  }'
```

The response is a structured report:

```json
{ "newly_applied":   ["0002_pgcrypto", "0003_orders_tenant_idx"],
  "already_applied": ["0001_init"],
  "pending":         [],
  "failed":          null }
```

- `already_applied` — recorded on an earlier call, skipped (idempotent no-op).
- `newly_applied` — applied by **this** call, in order.
- `failed` — the step that ran but failed (see below); `null` on success.

**Dry-run** to see the plan without touching the database — same body, `pending` lists
the ids that *would* apply:

```sh
curl -sS -X POST .../migrate/appdb/dry-run -H "Authorization: Bearer $BOATRAMP_TOKEN" \
  -H 'content-type: application/json' -d @migrations.json
```

**Status** reads the applied ledger (id, ordinal, content hash, kind, applied-at):

```sh
curl -sS .../migrate/appdb/status -H "Authorization: Bearer $BOATRAMP_TOKEN"
```

### Tokens: admin to mutate, read to inspect

`apply` and `dry-run` require a **`Project·Admin`** token; `status` needs only
**`Project·Read`**. This is deliberately stronger than the deploy-grade *publisher* right
that ships code — DDL redraws the schema, so **a ship-only CI token cannot migrate the
schema**. Mint a scoped admin token per project rather than reusing the fleet root
(see [Make a scoped deploy token](./ci-token.md)).

### A step that fails: `200`/`422` vs the error codes

boatramp splits "couldn't attempt the request" from "a step ran but failed":

- A step that **runs but the SQL fails** comes back as **HTTP 422** with a structured
  body — the prefix before it is applied and recorded, and `failed` names exactly which
  migration broke and why:

  ```json
  { "newly_applied": ["0001_init"],
    "already_applied": [],
    "pending": [],
    "failed": { "id": "0002_bad", "error": "relation \"orders\" does not exist" } }
  ```

  A clean apply is **200**. Either way the body is the same `MigrationReport` shape, so a
  thin client parses `failed{id,error}` and branches on the status.

- Everything else is a non-2xx *without* a report body: **409** (the set diverged from
  the ledger, or an applied step's body changed), **503 + `Retry-After`** (the managed
  database is still starting — retryable), **501** (no managed database on this node),
  **400** (a malformed step, or a raw `CREATE EXTENSION` — see below).

## How it stays safe

This is the part that matters. The migration surface runs owner-authority DDL without
ever handing out cluster-superuser reach.

**DDL runs as a dedicated per-project non-superuser owner role.** Every managed tenant is
provisioned with a **three-identity** model:

- the **cluster superuser** — only ever provisions the shells (creates the database and
  the roles); a migration never connects as it;
- a per-project **owner role** (`<db>_<tenant>_owner`), created explicitly
  `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION` — this is who your `sql`
  steps run as;
- the **runtime login role** your handlers connect as, kept a **non-owner** so
  row-level security is still enforced against it.

Because the owner role is a plain non-superuser that owns only this tenant's own
database, **Postgres itself denies** the dangerous moves — cross-database access,
`ALTER ROLE … SUPERUSER`, `COPY … TO PROGRAM`, an untrusted `CREATE EXTENSION` — by
privilege, not by a check boatramp has to remember. A migration is confined to the
tenant's own schema by the database engine.

**The ledger is host-owned.** Applied migrations are tracked in
`boatramp_migrations.schema_migrations` — a schema **outside `public`** that the owner
role owns and the runtime app role has no grant on (the app only ever gets DML on
`public`). Your handlers cannot read, forge, or clear their own migration history.

**Ordering is fixed and immutable.** On every apply boatramp checks the recorded ledger
is an ordered **prefix** of the steps you sent, matching `id` **and** a content hash of
each step's body:

- a **reordered or dropped** step ⇒ `409` (prefix divergence), and
- **editing an already-applied step's body** ⇒ `409` (content-hash mismatch).

So you cannot silently re-apply, reorder, or rewrite history — the only legal change to a
migration set is **appending** new steps. (A transactional `sql` step also may not carry
its own `BEGIN`/`COMMIT`/`ROLLBACK`, which would desync the atomic wrapper; that's a `400`
— use a `no_transaction` step if you need to manage the transaction yourself.)

## Enable an extension

A raw `sql` step **may not** `CREATE EXTENSION` (a `400`, or refused fail-closed by the
non-superuser owner regardless). Enable an extension with a dedicated `extension` step:

```json
{ "id": "0002_pgcrypto", "extension": "pgcrypto" }
```

boatramp runs a host-templated `CREATE EXTENSION IF NOT EXISTS "<name>"` — no guest SQL,
no injection surface — but only if `<name>` is on the operator's **trusted-extension
allowlist**, set in the node config:

```toml
[handlers.bindings.sql]
migrate_trusted_extensions = ["pgcrypto", "uuid-ossp", "citext"]
```

An empty/unset list means **no extension** can be enabled through a migration (the safest
default); a name not on the list is refused with a `400`. This allowlist is the *single,
operator-controlled gate* on which extensions a project may install — deliberately the
operator's decision, not the app author's, because some extensions
(`dblink`, `postgres_fdw`, …) widen cross-database reach. Keep it tight and add those only
knowingly.

## Non-transactional steps

boatramp wraps each `sql` step and its ledger row in one transaction so DDL and its record
commit (or roll back) together. Some Postgres DDL cannot run inside a transaction —
`CREATE INDEX CONCURRENTLY`, `ALTER TYPE … ADD VALUE`, `VACUUM`, `CREATE DATABASE`. Mark
those `no_transaction: true`:

```json
{ "id": "0003_orders_tenant_idx",
  "sql": "CREATE INDEX CONCURRENTLY orders_tenant_idx ON orders (tenant_id);",
  "no_transaction": true }
```

The trade-off is explicit: boatramp runs the script, then records the ledger row in a
**following** statement, so there's a window where the DDL applied but the row didn't
(a crash between them). The author **owns that step's idempotency** — write it so a re-run
is safe (`CREATE INDEX CONCURRENTLY IF NOT EXISTS`, an `ADD VALUE IF NOT EXISTS`), because
a re-submit will run it again. Transactional steps have no such window; reach for
`no_transaction` only for DDL Postgres forbids in a transaction.

## Operators: migrating existing tenants to the owner model

New tenants provision with the three-identity model **automatically** — nothing to do. A
tenant provisioned by a **pre-v0.4.25** boatramp, though, has its database owned by the
runtime role and its tables owned by the cluster superuser; there is no owner role yet, so
a migration has nowhere to connect as owner. Move such a tenant once, as a one-shot step.

Find the boatramp-derived owner role name — it's the `_owner`-suffixed per-tenant role, in
`pg_roles` (it will exist after you re-run provisioning; the name is derived from the
managed binding + tenant). Then, **as the superuser, against that tenant's database**:

```sql
ALTER DATABASE "<db>" OWNER TO "<owner_role>";
REASSIGN OWNED BY <superuser> TO "<owner_role>";
```

Then re-run provisioning (it is idempotent) so the owner-keyed default privileges and the
sealed owner credential are in place. After that, the migration surface can connect as the
owner role and the tenant is on the modern model. This is the operator's one-shot step;
tenants created afterward need none of it.

## A note on the pattern

This surface is the first instance of a general boatramp shape: an **owner-authenticated
control-plane operation with a thin client** — the caller assembles a declarative request
(here, the ordered step set) and posts it with an admin token, while boatramp owns the
privileged, sequenced, tracked execution. There is no long-lived privileged credential in
the client and no imperative script running against your database. Expect the same
"admin request → owner-only admin API" shape to generalize to future privileged
operations.

## See also

- [Isolate tenants within a project](./tenant-isolation.md) — the RLS the runtime role is
  held to, which the owner/runtime split preserves.
- [Use kv / sql / blobstore / messaging](./handler-bindings.md) — the managed `sql`
  binding a migration targets.
- [Bootstrap authentication & mint tokens](./auth-bootstrap.md) /
  [Make a scoped deploy token](./ci-token.md) — the admin token these endpoints need.
- [Control-plane HTTP API](../reference/api.md) — the full endpoint reference.
