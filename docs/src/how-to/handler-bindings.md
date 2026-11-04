# Use handler bindings

**For: app developers**

A handler is a WebAssembly component that runs a dynamic route. It imports only
the host interfaces it declares, intersected with what the site grants — deny by
default. This page is the shared front door for the **four data bindings** an
operator wires up — `wasi:keyvalue`, `sql`, `wasi:blobstore`, and
`wasi:messaging` — each with its own focused page, plus the cross-cutting
mechanics every binding shares: how a binding is granted, how a handler calls a
sibling function, and how a browser session cookie authenticates. To ship a
component, see [Deploy a handler](./deploy-handler.md). For the other thing a
handler is granted — API keys, database URLs, and the like — see [Give handlers &
functions secrets](./secrets.md).

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

Each data binding has its own page — start there for the grant, the backend, and
the guest-facing surface:

- **[`wasi:keyvalue`](./handler-binding-kv.md)** — a per-site key/value store. Use
  it for session state, counters, and small hot records the handler reads and
  writes on the request path.
- **[`sql`](./handler-binding-sql.md)** — a libsql database per site. This is a
  real database per site, not schema separation, so one site's tables never
  collide with another's. Use it for relational data and queries. You can also
  point a name at your own external Postgres/MySQL — see [Bring your own
  database](./handler-binding-sql.md#bring-your-own-database-external-postgres--mysql).
  For most queries you can build them with the typed
  [`orm` builder](./handler-binding-sql.md#typed-queries-with-the-orm-builder)
  instead of writing SQL strings — same databases, same transaction,
  injection-safe.
- **[`wasi:blobstore`](./handler-binding-blob.md)** — per-site blob storage over
  the server's `Storage` backend, key-prefixed per site. Use it for uploaded
  files and generated artifacts too large for the key/value store.
- **[`wasi:messaging`](./handler-binding-messaging.md)** — publish/subscribe and
  queues. A handler publishes to a topic; a **consumer** declared in
  `routing.consumers` subscribes to that topic and processes each message off the
  request path. Grant `wasi:messaging` to both the publishing handler and the
  consuming component, and match the topic name on each side. See [Run consumers,
  crons, and streams](./background-work.md).

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

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
