# WebAssembly Handlers

boatramp runs sandboxed **WebAssembly components** for dynamic routes — no
product-specific SDK, just standard WASI 0.2 interfaces. A handler is a
component that exports `wasi:http/incoming-handler`; a **consumer** exports
`wasi:messaging/incoming-handler` and is invoked per message; **crons** invoke a
route on a schedule; **streams** fan out messaging topics as server-sent events
(or, with `websocket: true`, a bidirectional WebSocket).

Handlers need a build with the `handlers` feature (it pulls the wasmtime
engine).

## Host bindings

A component may import only the interfaces it declares, intersected with what
the site allows (deny by default):

| Interface | Provides |
| --- | --- |
| `wasi:http`, `wasi:io` | request/response, streaming bodies |
| `wasi:keyvalue` | a per-site key/value store (SlateDB-backed) |
| `wasi:blobstore` | per-site blob storage (the `Storage` backend, prefixed) |
| `sql` | a libsql database **per site** (a real DB, not schema separation) |
| `wasi:messaging` | publish/subscribe + queues (consumers, dead-letter) |
| `wasi:clocks`, `wasi:random` | time and randomness |

The guest gets only what the deploy requested *and* the site granted — host env
vars and unlisted interfaces (e.g. `wasi:filesystem`) are refused even if named.

## Deploy-scoped config (`project.cfg` `routing`)

Handlers, consumers, crons, and streams are declared in the `routing` section of
`project.cfg` (folded into the immutable deployment manifest):

```ron
routing: (
    handlers: [
        ( route: "/api/**", component: "api.wasm",
          methods: ["GET", "POST"],
          imports: ["sql", "wasi:keyvalue"] ),
    ],
    consumers: [
        ( topic: "emails", component: "mailer.wasm",
          imports: ["sql", "wasi:keyvalue"] ),
    ],
    crons: [ ( schedule: "0 * * * *", route: "/api/rollup" ) ],
    streams: [
        // Server-sent events: fan a topic out to clients (server→client).
        ( route: "/sse/events", topics: ["events"] ),
        // WebSocket (bidirectional): the same fan-out plus client messages are
        // published to `publish_topic` for a consumer/handler to process.
        ( route: "/ws", topics: ["events"], websocket: true, publish_topic: "ingest" ),
    ],
),
```

Handlers sit in the pipeline **after redirects, before static** (redirects >
handlers > streams > static). At `sync`, each component blob is validated:
parseable, exports the required interface, and every import is in the allowlist.

## Site policy (`SiteConfig`)

The site caps what any deployment may do — the requested config is intersected
against this at activation (deny by default). Site policy lives in `SiteConfig`
(in the control-plane KV, not a file); it carries:

- `enabled` — whether handlers run for the site at all.
- `allow_imports` — the interfaces handlers may import, e.g.
  `["sql", "wasi:keyvalue", "wasi:blobstore", "wasi:messaging", "wasi:http"]`.
- Optional caps: `max_memory_mb`, `max_timeout_ms`, `max_concurrency`,
  `max_fuel` (CPU instruction budget; a guest that exceeds it traps
  "out-of-fuel"), `max_stream_connections`, `max_log_rate`, `secrets`,
  `background_aliases`.

Background work (consumers, crons) runs for the **current** deployment; previews
never run background work unless explicitly opted in via `background_aliases`.

## SQL backend (`boatramp.cfg`)

Which backend serves the `sql` binding is a *server* setting, in the `handlers`
section of `boatramp.cfg`:

```ron
handlers: (
    bindings: (
        // Single-node (default): an embedded libsql file per site under
        // <data-dir>/handlers-sql. Omit `sql` entirely to use the default.
        sql: (
            // Cluster: a sqld namespace per site.
            // url: "http://sqld:8080",
            // admin_url: "http://sqld:9090",
            // token_env: "BOATRAMP_SQL_TOKEN",
            // admin_token_env: "BOATRAMP_SQL_ADMIN",
            // preview_mode: "empty",   // empty | branch | shared
        ),
    ),
),
```

Tail guest output and stats with [`boatramp logs` / `boatramp
stats`](./observability.md).

## Engine performance

The engine compiles each component once (cached by content hash, kept
pre-instantiated) and keeps a **persisted on-disk compile cache**, so the first
request after a restart skips recompilation. A server-side knob (in the
`handlers` section of `boatramp.cfg`) tunes instantiation further:

```ron
handlers: (
    pooling: false,   // opt-in wasmtime pooling allocator: faster instantiation,
                      // but reserves a large block of virtual memory up front —
                      // benchmark before enabling for your workload.
),
```

Per-handler CPU is bounded by `max_fuel` (see the caps above) in addition to the
wall-clock timeout; a guest that exceeds it traps as `out-of-fuel`.
