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

## Invoke a sibling function

A handler can call a sibling [top-level function](./functions.md) **in-process**,
exactly as a function invokes another. Grant `invoke` in the handler's `imports`,
then list the functions it may reach in an `invoke_targets` allowlist — deny by
default (an empty list invokes nothing, even with `invoke` granted), with `*`
wildcards (`*`, `img-*`, or a literal name):

```ron
routing: (
    handlers: [
        ( route: "/api/**", component: "api.wasm",
          methods: ["GET", "POST"],
          imports: ["invoke"],
          invoke_targets: ["resize", "thumb-*"] ),
    ],
),
```

Like every binding, `invoke` is capped by the site's allowed-imports policy: a
site that does not permit it refuses the handler at activation. The callee is
quota-admitted and depth-capped, and the caller's `Authorization` header is
forwarded to it unchanged.

### Stream a large response

`invoke` returns the callee's response **whole** — the simple default. When a
sibling returns a large or incrementally-produced result, use the streaming
variant instead so the body is never buffered whole in host memory. It hands back
`status` and `headers` up front and an `incoming-response` resource you pull the
body from incrementally:

```rust
let resp = invoke::invoke_streaming("report", &request)?;   // same target allowlist
let status = resp.status();
loop {
    let chunk = resp.read(64 * 1024)?;   // up to N more bytes, blocking
    if chunk.is_empty() { break; }        // empty ⇒ end of stream
    sink.write_all(&chunk);
}
```

Both variants share the exact same in-process path, target allowlist, and
call-depth cap; only the response body's delivery differs. The **request** body is
still passed whole (request streaming is a separate step). Streamed responses are
metered at hand-off from a declared `Content-Length` when present.

## Authenticate a browser with a session cookie

A browser app usually holds its session in an `HttpOnly` cookie its own auth
handler sets — a token JavaScript can't read (so it survives XSS). boatramp can
treat that cookie as the **application bearer** for a site, so every handler,
GraphQL query, data-connector read, and sibling `invoke` sees the caller's
identity **without the app ever putting a token in JavaScript**. Opt in on the
site's `handlers` config (it's general — not GraphQL-specific):

```ron
handlers: (
    enabled: true,
    cookie_auth: (
        cookie_name: "__Host-session",
        // Omit `allowed_origins` for the common case — the app and its API share
        // one origin. Only list the *extra* origins a browser app served from a
        // **different** origin than this API needs (see CSRF below).
    ),
)
```

When set, a request that carries the named cookie but **no** `Authorization`
header is authenticated from the cookie value — boatramp injects it as
`Authorization: Bearer <value>` at the edge, so it flows everywhere a header
bearer already does and is verified byte-identically (your app's own authorizer /
OIDC config, the data connector's `claims_from_token`, the GraphQL field guards).
The **`Authorization` header always wins**, so API clients (curl, mobile) are
unaffected.

**boatramp only reads the cookie — your app sets, refreshes, and verifies it.**
The value is an opaque app bearer. Set these attributes on the cookie; two are
**security requirements**, not just advice (boatramp can't enforce a cookie it
only reads):

- **`HttpOnly`** — unreadable by JS (the whole point; XSS-safe).
- **`Secure`** — HTTPS only.
- **`SameSite=Lax` (required for CSRF safety).** A `Lax` cookie is withheld on the
  cross-site POST/`fetch` an attack would use — the browser half of the defense.
  Use **`Lax`, not `Strict`**: `Strict` withholds the cookie when a user arrives
  from an external link (email, another site), landing them logged-out on first
  load; `Lax` still sends it on that top-level navigation.
- **`__Host-` name prefix** (recommended). It forbids a `Domain` attribute, so a
  sibling or parent subdomain can't set a cookie that shadows yours.

**CSRF.** A cookie-authenticated request passes the origin check when it is
**same-origin** — its `Origin` (or, absent that, `Referer`) authority equals the
request's own `Host`. That covers the normal SPA case (a page calling its own
`/graphql`) with **no configuration**: `allowed_origins: []` means *same-origin
only*. A cross-site attacker's browser sends *their* origin, never your `Host`,
so same-origin is definitionally CSRF-safe. `allowed_origins` then lists only the
**extra** cross-origins to accept — for a browser app served from a *different*
origin than this API. A cross-origin request that's neither same-origin nor listed
is rejected `403`. A header-bearer request isn't CSRF-able (the attacker doesn't
have the token), so it's exempt. A request with **no** `Origin`/`Referer` — a
same-origin top-level navigation — is allowed, so a **cookie-auth handler must
keep its `GET`/`HEAD` side-effect-free** (state changes go through `POST`/etc.,
where the browser sends `Origin`). If the site also enables the
[response cache](./caching.md#cache-handler-responses-at-the-edge), never mark a
per-user response `public`.

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

The guest code is unchanged — the name simply resolves to the external database
instead of a per-site libsql one, and the **placeholders stay `?N`** on every
engine (the host rewrites them to Postgres `$N` / MySQL `?` for you):

```rust
let db = sql::open("analytics")?;               // the configured Postgres
let rows = db.query("SELECT id, name FROM signups WHERE country = ?1",
                    &[Value::Text(country)])?;
```

> **Placeholders are always `?1`, `?2`, …** — the SQLite-style numbered form —
> regardless of which engine backs the database. Writing native Postgres `$1` (or
> a `:name` placeholder) is rejected, so the same SQL is portable across the
> managed libsql default and an external Postgres/MySQL. Need a cast for a strict
> Postgres type? Put it on the placeholder: `?1::int`.

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

See the [boatramp.cfg schema](../reference/boatramp-cfg.md#external-sql-databases)
for the full field list and [Cargo features](../reference/features.md) for the
build features.

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
