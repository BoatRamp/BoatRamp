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
nearest-neighbour (the experimental `orm-vector` capability, Postgres-only); and an **own-vs-base
preference** for base-vs-override reads — `own_first()` / `is_own()` (the experimental `orm-own-pref`
capability, see below). Every value is a bound parameter and every
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

## See also

- [Declare a managed database](./managed-databases.md) — the declarative `apply` front door.
- [Isolate tenants within a project](./tenant-isolation.md) — host-forced row scoping.
- [Run owner-gated schema migrations](./in-app-migrations.md) — evolve the schema safely.

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
