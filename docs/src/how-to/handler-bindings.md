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
  for relational data and queries.
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

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
