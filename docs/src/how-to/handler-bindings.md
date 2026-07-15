# Use kv / sql / blobstore / messaging

A handler is a WebAssembly component that runs a dynamic route. It imports only
the host interfaces it declares, intersected with what the site grants — deny by
default. This page covers the four data bindings an operator wires up:
`wasi:keyvalue`, `sql`, `wasi:blobstore`, and `wasi:messaging`. To ship a
component, see [Deploy a handler](./deploy-handler.md).

## Grant a binding

Each binding a handler uses goes in the `imports` list of its `routing.handlers`
entry in `project.cfg`. Name only what the handler calls; a component that
imports an interface the site does not allow fails validation at `sync`:

```ron
routing: (
    handlers: [
        ( route: "/api/**", component: "api.wasm",
          methods: ["GET", "POST"],
          imports: ["wasi:keyvalue", "sql", "wasi:blobstore", "wasi:messaging"] ),
    ],
),
```

The site's allowed-imports policy caps this list: a binding you name that the
site does not permit is refused at activation.

## The four data bindings

- **`wasi:keyvalue`** — a per-site key/value store. Use it for session state,
  counters, and small hot records the handler reads and writes on the request
  path.
- **`sql`** — a libsql database per site. This is a real database per site, not
  schema separation, so one site's tables never collide with another's. Use it
  for relational data and queries. You can also point a name at your own external
  Postgres/MySQL — see [Bring your own database](#bring-your-own-database-external-postgres--mysql).
- **`wasi:blobstore`** — per-site blob storage over the server's `Storage`
  backend, key-prefixed per site. Use it for uploaded files and generated
  artifacts too large for the key/value store.
- **`wasi:messaging`** — publish/subscribe and queues. A handler publishes to a
  topic; a **consumer** declared in `routing.consumers` subscribes to that topic
  and processes each message off the request path. Grant `wasi:messaging` to both
  the publishing handler and the consuming component, and match the topic name on
  each side. See [Run consumers, crons, and streams](./background-work.md).

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

Build with the engine's feature (`--features sql-postgres` and/or `sql-mysql`),
then declare each database under `handlers.bindings.sql.databases`. The
connection URL is a secret, so it is named indirectly through an env var:

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

The guest code is unchanged — the name simply resolves to the external database
instead of a per-site libsql one:

```rust
let db = sql::open("analytics")?;               // the configured Postgres
let rows = db.query("SELECT id, name FROM signups WHERE country = $1",
                    &[Value::Text(country)])?;
```

Keep these properties in mind — they are the deliberate trade-off of pointing at
a database boatramp doesn't manage:

- **Isolation is yours.** An external database is a single, *shared* endpoint:
  every site/function that is granted the `sql` binding and opens the name
  reaches the same database with whatever the connection URL can do (it runs
  arbitrary SQL there). Prefer it for a single-tenant deployment or a genuinely
  shared database; keep competing tenants' data on the managed libsql default.
- **Previews are refused by default.** A preview deployment can't open an
  external database unless it was declared with `allow_preview: true`, so a
  preview never accidentally writes to your live data.
- **Values map to the same small vocabulary.** Booleans, integers, floats, text,
  and blobs round-trip natively; timestamps, UUIDs, `numeric`/`decimal`, and
  JSON come back as text. A column type outside that set is a clear error asking
  you to cast it (`SELECT col::text`). MySQL has no native boolean, so a
  `TINYINT` (its bool) reads back as the integer `0`/`1`.

See the [boatramp.cfg schema](../reference/boatramp-cfg.md#external-sql-databases)
for the full field list and [Cargo features](../reference/features.md) for the
build features.

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
