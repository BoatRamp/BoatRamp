# Use the sql & orm bindings

**For: app developers**

The `sql` binding gives a handler a **libsql database per site** — a real database
per site, not schema separation, so one site's tables never collide with another's.
Use it for relational data and queries. You can also point a name at your own
external Postgres/MySQL ([below](#bring-your-own-database-external-postgres--mysql)),
or at a database boatramp runs ([below](#managed-sql-on-a-database-boatramp-runs)).
For most queries you can build them with the typed
[`orm` builder](#typed-queries-with-the-orm-builder) instead of writing SQL strings
— same databases, same transaction, injection-safe.

This is one of the four data bindings an operator wires up — see
[Use handler bindings](./handler-bindings.md) for the shared mechanics. Grant it by
naming `sql` (or a named database `sql:<name>`) in the handler's `imports` — see
[Grant a binding](./handler-bindings.md#grant-a-binding).

## Configure the `sql` backend

The `sql` binding is the one data binding with a server-side backend choice, set
in the `handlers` section of `boatramp.cfg`. Single-node — the default — gives
each site an embedded libsql file under `<data-dir>/handlers-sql`; omit the `sql`
key to get this. In a cluster, point every node at one shared `sqld`, where each
site becomes a namespace, so every node serves the same per-site database:

```ron
handlers: (
    bindings: (
        sql: (
            url: "http://sqld:8080",
            admin_url: "http://sqld:9090",
            token_env: "BOATRAMP_SQL_TOKEN",
        ),
    ),
),
```

For the full field list — including `preview_mode` and the token env vars — see
the [boatramp.cfg schema](../reference/boatramp-cfg.md). The kv, blobstore, and
messaging bindings take no per-binding backend block; they follow the server's
`kv` and `blobs` backends set under `serve`.

## Bring your own database (external Postgres / MySQL)

libsql gives every site a **managed, isolated** database for free — the right
default for multi-tenant data. When you instead want a handler or function to
talk to a database *you* run — an existing Postgres or MySQL, a managed service
like Neon / Supabase / PlanetScale — declare it as a **named external database**.
The guest opens it by name through the same interface; only the server config
differs.

The `sql-postgres` / `sql-mysql` features are in the default build (a
`--no-default-features` build re-adds them). Declare each database under
`handlers.bindings.sql.databases`. The connection URL is a secret, so it is named
indirectly through an env var:

```ron
handlers: (
    bindings: (
        sql: (
            databases: {
                // Opened by the guest as `sql.open("analytics")`.
                "analytics": (
                    kind: "postgres",             // or "mysql"
                    url_env: "ANALYTICS_PG_URL",   // secret: postgres://user:pw@host/db
                    pool_max: 16,
                    read_only: true,               // reject writes at the engine
                ),
                "events": (
                    kind: "mysql",
                    url_env: "EVENTS_MYSQL_URL",
                    read_url_env: "EVENTS_MYSQL_REPLICA_URL", // open-read-only → replica
                    allow_preview: true,           // let preview deployments reach it
                ),
            },
        ),
    ),
),
```

**Grant a named database explicitly.** The bare `sql` capability grants only the *default*
(managed, per-site libsql) database — `sql.open("")`. A **named** database needs its own grant: the
handler imports `sql:<name>` (e.g. `sql:analytics`) — or `sql:*` for every name the site exposes —
and the site's [`allow_imports`](../reference/siteconfig.md#handlers) must list it too (the site is
the hard ceiling). A handler that opens only `analytics` imports `sql:analytics`, and
`sql.open("events")` from it then **fails closed**. This is the seam for **least-privilege tenant
isolation** at the *connection* level: give the tenant-facing path a normal role (say `sql:product`)
and any privileged path its own binding (`sql:privileged`) — each a distinct connection + credential.
On top of that, **in-site row scoping is host-forced** (see [tenant isolation](./tenant-isolation.md)):
when the site declares scoped tenancy the host injects the `tenant_id` predicate itself, so a missed
`WHERE` can't leak across tenants, with Postgres `FORCE ROW LEVEL SECURITY` a live backstop rather
than resting on app discipline alone.

The guest code is unchanged — the name simply resolves to the external database
instead of a per-site libsql one, and the **placeholders stay `?N`** on every
engine (the host rewrites them to Postgres `$N` / MySQL `?` for you):

```rust
let db = sql::open("analytics")?;               // the configured Postgres
let rows = db.query("SELECT id, name FROM signups WHERE country = ?1",
                    &[Value::Text(country)])?;
```

> **Raw SQL under scoped tenancy uses the `{scope}` marker.** If the site/function declares in-site
> tenancy, place `{scope}` where the tenant predicate belongs and the host fills it (`tenant_id =
> ?N`) from the verified source — `... WHERE status = ?1 AND {scope}`. A scoped statement that omits
> the marker is **refused** (fail-closed), so raw SQL can't silently skip the tenant boundary. A
> plain (no-tenancy) app writes ordinary SQL and needs no marker. The typed `orm` builder injects
> the same predicate structurally, no marker needed — see [tenant isolation](./tenant-isolation.md).

> **Placeholders are always `?1`, `?2`, …** — the SQLite-style numbered form —
> regardless of which engine backs the database. Writing native Postgres `$1` (or
> a `:name` placeholder) is rejected, so the same SQL is portable across the
> managed libsql default and an external Postgres/MySQL. Need a cast for a strict
> Postgres type? Put it on the placeholder: `?1::int`.

Keep these properties in mind — they are the deliberate trade-off of pointing at
a database boatramp doesn't manage:

- **Isolation is yours.** An external database is a single, *shared* endpoint:
  every site/function granted `sql:<name>` (or `sql:*`) and opening the name
  reaches the same database with whatever that connection's role can do (it runs
  arbitrary SQL there). Prefer it for a single-tenant deployment or a genuinely
  shared database; keep competing tenants' data on the managed libsql default —
  or, when the shared DB *is* multi-tenant, give the tenant path a
  least-privilege named binding (above) and enforce `FORCE ROW LEVEL SECURITY`.
- **Previews are refused by default.** A preview deployment can't open an
  external database unless it was declared with `allow_preview: true`, so a
  preview never accidentally writes to your live data.
- **Values map to the same small vocabulary.** Booleans, integers, floats, text,
  and blobs round-trip natively; timestamps, UUIDs, `numeric`/`decimal`, and
  JSON come back as text. A column type outside that set is a clear error asking
  you to cast it (`SELECT col::text`). MySQL has no native boolean, so a
  `TINYINT` (its bool) reads back as the integer `0`/`1`.

## Managed SQL on a database boatramp runs

If the Postgres/MySQL is itself a **compute workload boatramp runs** (see
[Run a container or microVM](./compute.md)), you don't have to hand-map a
connection URL at all. Point the database at the workload with `compute` instead
of `url_env`, and boatramp wires the rest:

```ron
handlers: (
    bindings: (
        sql: (
            databases: {
                // Opened by the guest as `sql.open("app")`; backed by the
                // compute workload named "pg" that boatramp runs.
                "app": (
                    kind: "postgres",
                    compute: "pg",         // a compute workload, not a URL
                    database: "app",       // db name inside the server
                    user: "app",           // connecting user
                    // no password_env → boatramp manages the credential
                ),
            },
        ),
    ),
),
// Required: a secrets envelope to seal the managed credential at rest.
secrets: ( envelope: "local" ),
```

> This is the **node-static (`boatramp.cfg`) surface** onto the managed-database
> stack. For the **declarative front door** — declaring a database in a project's
> `apply` manifest (the recommended path since v0.6.0) — see
> [Declare a managed database](./managed-databases.md).

With `password_env` omitted, boatramp **fully manages the credential**: on first
launch it generates a strong password, seals it with the [`secrets`](../reference/boatramp-cfg.md#secrets)
envelope, injects it into the `pg` workload's server-init env (`POSTGRES_*` /
`MYSQL_*`) so the database initializes with it, and connects the handler with the
same sealed password — you set no DB secret anywhere. It then resolves the
workload's live endpoint per use, so the binding **follows the database across
restarts** with no config change.

Two requirements make this safe and durable:

- **A `[secrets]` envelope is mandatory.** boatramp refuses to manage a
  credential it cannot seal, rather than store a DB password in cleartext — a
  managed database with no `[secrets]` fails to start with a clear error. (Set
  `password_env` instead to bring your own credential for a compute-backed
  database.)
- **Give the DB workload a persistent volume.** The password is baked into the
  database on first init, so the data directory must survive restarts for it to
  keep accepting the same credential. See
  [persistent volumes](./compute.md).

### Serving posture — `serve_as` (shared + `rls_session` Postgres)

For a **`tenant: shared`** managed-**Postgres** binding with **`rls_session`**, boatramp mints a
per-tenant *owner* role (which owns the schema + runs migrations) distinct from the per-tenant
*runtime* role a request is served by. The optional `serve_as` knob declares **which identity serves
a request**, and — mechanically — whether boatramp installs the `FORCE ROW LEVEL SECURITY` trigger:

```ron
"app": (
    kind: "postgres",
    compute: "pg",
    database: "app",
    user: "postgres",            // the shared server's superuser (runs provisioning DDL)
    tenant: "shared", tenant_scope: "project",
    rls_session: true, tenant_guc: "app.tenant_id",
    serve_as: "non-owner",       // the default — may be omitted
),
```

- **`serve_as: "non-owner"` (the default, the safe posture)** — the serving DSN authenticates as the
  per-tenant **non-owner** runtime role. PostgreSQL enforces a plain `ENABLE ROW LEVEL SECURITY`
  table against a non-owner, so your RLS holds **with no `FORCE`**. No FORCE trigger is installed.
  This is the right choice for an RLS-aware app — serving as your own table owner would silently
  **bypass** your `ENABLE`-only policies.
- **`serve_as: "owner"`** — the serving DSN authenticates **as the per-tenant owner role**
  (operate-as-owner, so one DSN can auto-migrate its own schema). Because `ENABLE` does *not* bind a
  table's owner, boatramp installs the **FORCE-on-ENABLE** event trigger for this binding, so RLS
  binds the owner too. Choose it only for a self-migrating app that must own its schema on its
  serving DSN.

The invariant **owner-serving ⟺ `FORCE` present** is enforced **fail-closed** in two coupled places:
the serving-path guard refuses an owner serving role unless this binding declared `serve_as: "owner"`
(the posture that installs `FORCE`); and, because the FORCE-on-ENABLE trigger only upgrades tables
created/altered *after* it is installed, the owner-posture **provision** additionally FORCE-sweeps
every pre-existing `ENABLE`-only table and refuses if any table is still `ENABLE`-but-not-`FORCE` —
so `FORCE` is actually live (not merely posture-declared) before the owner is ever served, even after
a posture flip onto a populated database or a cross-posture clone. `serve_as` is **ignored** outside the shared + `rls_session` +
Postgres cell (a `tenant: single`/dedicated binding has no owner/non-owner choice — see the next
section; the reserved `default` tenant on a shared server serves as its plain user; MySQL has no
owner/runtime split). The migration/DDL identity
(`migration_url_env`, `{{sql.migration_dsn}}`) is always the owner role, regardless of `serve_as`.

### Non-superuser RLS on a superuser-owned cell — `rls_session` on `tenant: single` or `Shared` + default

Some managed-Postgres cells have a database owned by the **bootstrap superuser** (`POSTGRES_USER`)
with no per-tenant owner/runtime role split: a **`tenant: single`** dedicated container (any tenant),
and the reserved **`Shared` + default** tenant (the shared server's own init database). By default the
runtime is served as that superuser, which — like any superuser — **bypasses row-level security**, so
an app's own `FORCE ROW LEVEL SECURITY` is silently un-enforced. Set **`rls_session: true`** on the
binding to opt into capability parity with the shared non-owner posture: boatramp provisions a **stable
non-superuser app role** and serves the runtime as it instead.

```ron
"app": (
    kind: "postgres",
    compute: "pg",
    database: "app",
    user: "postgres",            // the dedicated container's bootstrap superuser
    tenant: "single", tenant_scope: "project",
    rls_session: true, tenant_guc: "app.tenant_id",   // ← opt in: serve as a non-superuser app role
),
```

- The superuser still **owns the schema** and runs migrations (the migration DSN,
  `{{sql.migration_dsn}}`, stays the superuser); the provisioned app role **owns nothing** — it gets
  only `GRANT` + default privileges, so it is a non-owner a plain `ENABLE ROW LEVEL SECURITY` table
  binds. Your app's RLS is now **load-bearing** on the serving DSN.
- The role is **stable** (one per database, not per-replica), so it sidesteps object-ownership
  orphaning; its credential is sealed under its own key, never the superuser's. On a shared server it
  is a cluster role confined to its own (default-tenant) database.
- On a **`Shared`** server this layers on top of the **structural cross-tenant isolation** (the host
  injects the tenant predicate and scopes each tenant to its own database — see
  [tenant isolation](./tenant-isolation.md)); that boundary is unchanged and still applies to the
  non-superuser role. The opt-in only *adds* enforcement of the app's **own** RLS.
- **Default off:** an un-opted binding is unchanged — it serves as the superuser with no RLS
  enforcement. When opted in, boatramp **refuses fail-closed** if the resolved runtime role is still a
  superuser / `BYPASSRLS`, so an app can never silently believe it has RLS while served by a superuser.
  (`serve_as` is not consulted — a superuser-owned cell always serves the non-superuser app role. A
  `Shared` *non-default* tenant is a different cell: it already serves a per-tenant non-owner role.)
- **Adopting it on a database that already exists:** turning `rls_session` on for a managed Postgres
  that was already provisioned without it just works — flip it in the manifest and `apply`. The app
  role is created **in place** on the existing database on the next reconcile (no restart, same data
  volume, base credential untouched); until it exists the binding fails closed rather than serving as
  the superuser. See [Adopt `rls_session` on a database that already exists](./managed-databases.md#adopt-rls_session-on-a-database-that-already-exists).

## Typed queries with the `orm` builder

The `orm` binding is a **typed, injection-safe, tenant-scoped query builder** over the
*same* databases as `sql` — you build a query as a value instead of writing a SQL string,
and the host compiles it to parameterised SQL for whichever engine backs the database
(libsql, Postgres, or MySQL). It rides the **`sql` grant**: no separate import token, no
separate backend config. A handler granted `sql` (or `sql:<name>`) opens the same database
with `orm.open(name)` that it would with `sql.open(name)`, on the **same transaction** — so
you can mix the two freely, and `orm.open` on an ungranted name fails closed exactly like
`sql.open`.

It covers the shapes an app realistically uses without dropping to raw SQL: `SELECT`, `INSERT`
(multi-row), `UPDATE`, and `DELETE`; nested `AND`/`OR`/`NOT`, joins with aliases, aggregates with
`GROUP BY`/`HAVING`, `BETWEEN`/`IN`/`LIKE`/`IS NULL`, `ORDER BY`, `LIMIT`/`OFFSET`; arithmetic + a
portable function set; `RETURNING`; `ON CONFLICT` upserts; `UNION`; `CASE` (and a boolean/comparison
`ORDER BY` via `CASE`); `DISTINCT ON` (Postgres, fails closed elsewhere); JSON — static-key-path
extract, a bound-key `->>`, and jsonb `||` merge; a narrow correlated roll-up
(`related-aggregate`), a narrow scalar subquery, and an `IN`-subquery (all single-named-table,
behind the `orm-subquery` capability); `INSERT … SELECT`; pgvector distance/`ORDER BY`
nearest-neighbour (the `orm-vector` capability — cosine `<=>` / L2 `<->`, Postgres-only); and an
**own-vs-base preference** for base-vs-override reads — `own_first()` / `is_own()` (the experimental
`orm-own-pref` capability, see below). Every value is a bound parameter and every
identifier is validated, so a query **cannot** construct an injection; an unbounded `UPDATE`/`DELETE`
(no filter, no tenant scope) is refused. Reach for raw `sql` only for what the builder still doesn't
model — CTEs, window functions, open/free-form nested subqueries.

**Tenant scoping is host-forced — you pass no tenant value.** If the site (or function) declares
in-site tenancy ([tenant isolation](./tenant-isolation.md)), the host injects the tenant predicate
into every query the builder produces — a `WHERE tenant_id = ?` on reads, an auto-stamped column on
inserts, reaching every joined table and subquery — from the request's verified source, not from
anything the guest supplies. A plain (single-tenant / no-tenancy) app builds queries unchanged and
nothing is injected. (Pre-0.4 you called `open(..).scoped(col, value)`; that guest-supplied scope is
gone — see [tenant isolation](./tenant-isolation.md#migrating-from-pre-04).)

```rust
// Same database + transaction as `sql.open("")`; the host folds the tenant scope into every
// query (when the site declares scoped tenancy) — the guest never names it.
let db = orm::open("")?;

let rows = db.query("work_order")
    .select([col("id"), col("state")])
    .filter(and([
        col("project_id").eq(project_id),
        or([col("priority").ge(3), col("escalated").eq(true)]),
    ]))
    .order_by_desc("created_at")
    .limit(20)
    .run()?;
// Under scoped tenancy the host prepends the tenant predicate:
// SELECT id, state FROM work_order
// WHERE tenant_id = ?1 AND (project_id = ?2 AND (priority >= ?3 OR escalated = ?4))
// ORDER BY created_at DESC LIMIT 20
```

**Prefer a tenant's override over the shared base (`own_first()` / `is_own()`).** On an `own+null`
read of a two-layer table — a shared **base** row (`tenant_id IS NULL`) plus an optional per-tenant
**override** — you often want *the tenant's own row if present, else the base*. Because the tenant
column is host-injected and hidden, you can't write `ORDER BY (tenant_id IS NOT NULL)`. Instead
`own_first()` sorts own rows ahead of base ones without naming the column, so the base-vs-override
lookup is just `db.query("t").filter(key_pred).own_first().limit(1)`. The host lowers it, using the
same resolved tenant it injects for the scope, to `ORDER BY (CASE WHEN <own> THEN 1 ELSE 0 END)
DESC`. `is_own()` is the underlying `0`/`1` expression (usable in `select`, or `is_own().eq(1)` to
keep only overrides). It **fails closed** without an own-tenant (`own`/`own+null`) read, and needs
the experimental **`orm-own-pref`** capability — declare `requires = ["orm-own-pref"]`.

The builder is provided by the authoring kit's `compat::orm` module behind its
off-by-default `orm` cargo feature — turn it on only against a boatramp that ships
the `orm` interface. See that kit's authoring guide for the full surface (inserts,
upserts, `RETURNING`, JSON, subqueries, `UNION`, `CASE`, expressions, `own_first`).

See the [boatramp.cfg schema](../reference/boatramp-cfg.md#external-sql-databases)
for the full field list and [Cargo features](../reference/features.md) for the
build features.

## Transactions: one per invocation, and when they commit

Each invocation gets **one transaction per database** it opens, begun lazily on the first
statement and closed by the host when the guest is done — you never `BEGIN`/`COMMIT` yourself.
A database you never open starts no transaction. The `sql` and `orm` bindings share the *same*
transaction for a given name, so you can mix them freely.

**When the transaction commits depends on the handler kind — and the difference is deliberate:**

- A **`wasi:http` handler** has no application-level outcome channel (it only produces a response),
  so its SQL **commits whenever the guest does not trap**. A handler that returns a `500` (or any
  status) *still commits* its writes. To abort the writes, **trap** (panic / `unreachable`).
- A **messaging consumer** (and the **session** and **tcp-connection** handlers) returns
  `result<_, error>`, so its SQL **commits only when `handle` returns `ok`**. Returning a non-`ok`
  result — or trapping — **rolls back every SQL write and redelivers** the message (eventually
  dead-lettering it after the max attempts). This is the natural way for a consumer to say "I could
  not process this, try again": the transaction abort and the redelivery are the same decision.

So a consumer that writes rows and then returns an error leaves **no rows behind** — plan your
idempotency around redelivery, not around partial writes. **This "no rows behind" guarantee is the
guest-`Err` rollback case only** — see the at-least-once caveat below for what a *commit failure*
redelivers.

**If a commit itself fails** (the backend rejected or dropped it at commit time), the write is
lost — boatramp never hides this. The failure is logged at `ERROR`, counted on the component's
`commit_failed` stat (watch it: every nonzero value is a lost write), and for a consumer / session /
tcp handler the invocation is **failed** so the message redelivers rather than being acked as done.
The one case it cannot fully recover is a `wasi:http` handler whose response head is already on the
wire when the commit fails — there the `200` cannot be un-sent, so the failure is logged and metered
but the client may have seen success. Keep commit-critical work on the consumer path when you need
that guarantee.

> **At-least-once on a commit failure — it can double-apply.** The rollback-on-`Err` path above
> leaves no rows behind, but a redelivery caused by a *commit failure* is **at-least-once** and can
> **apply the same write twice**. Two cases:
>
> - **Multiple databases in one invocation.** `finalize` commits each database **independently —
>   there is no two-phase commit** across them. If the invocation opened DB-A *and* DB-B, DB-A's
>   commit succeeds, and then DB-B's commit fails, the invocation is failed and the message
>   redelivers — re-running the handler and **re-applying DB-A's already-committed write**.
> - **Commit ambiguity.** A commit can land on the server yet report an error back to the host (a
>   connection drop after the backend durably committed, a timeout on the ack). boatramp must treat
>   that as a failure and redeliver, so the write that *did* land gets applied again.
>
> Therefore **idempotency keys or upserts are required** for any consumer that writes to **more than
> one database** or whose writes are **not naturally idempotent**. Design the handler so a redelivery
> that re-applies a committed write is a no-op (e.g. `INSERT ... ON CONFLICT DO NOTHING/UPDATE`,
> keyed on a message/dedup id), not a duplicate row or a double-counted increment.

## See also

- [Declare a managed database](./managed-databases.md) — the declarative `apply` front door.
- [Isolate tenants within a project](./tenant-isolation.md) — host-forced row scoping.
- [Run owner-gated schema migrations](./in-app-migrations.md) — evolve the schema safely.

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
