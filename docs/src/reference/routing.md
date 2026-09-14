# Routing config schema

The `routing` section of `project.cfg` is the **deploy-scoped** config tier. It
is authored in [RON](https://github.com/ron-rs/ron), parsed at `sync`, and folded
into the immutable deployment manifest — so it is atomic with the content and
rolls back with it. Every field is optional; an empty `routing: ()` is all
defaults.

Validate it without publishing:

```sh
boatramp validate
```

```text
project.cfg: routing OK (2 redirects, 1 handler)
```

## Top-level fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `version` | u32 | `1` | Schema version, pinned at 1. |
| `index` | list\<string\> | `["index.html"]` | Directory-index candidates, tried in order. |
| `clean_urls` | bool | `false` | Map extensionless URLs to `.html` (`/about` → `/about.html`). |
| `case_insensitive` | bool | `false` | Match paths case-insensitively against redirects, rewrites, and files. |
| `trailing_slash` | enum | `Preserve` | Trailing-slash policy — see [below](#trailing_slash). |
| `error_documents` | map\<u16, string\> | `{}` | Status code → error document (`404: "/404.html"`). |
| `redirects` | list\<Redirect\> | `[]` | Redirect rules, first match wins. |
| `rewrites` | list\<Rewrite\> | `[]` | Internal-rewrite or reverse-proxy rules, first match wins. |
| `headers` | list\<HeaderRule\> | `[]` | Response-header rules; every matching rule applies, in order. |
| `cache` | CacheConfig | — | Default `Cache-Control` — see [below](#cache). |
| `mime_overrides` | map\<string, string\> | `{}` | Extension → MIME override (`".webmanifest": "..."`). |
| `proxy_allow` | list\<string\> | `[]` | Allowed upstream hosts for proxy rewrites — see [below](#proxy_allow). |
| `handlers` | list\<HandlerConfig\> | `[]` | WebAssembly request handlers, matched after redirects, before static lookup. |
| `consumers` | list\<ConsumerConfig\> | `[]` | Message-consumer components, invoked per message on a topic. |
| `crons` | list\<CronConfig\> | `[]` | Scheduled handler invocations. |
| `streams` | list\<StreamConfig\> | `[]` | Host-level SSE / WebSocket endpoints fanning out topics. |
| `sessions` | list\<SessionConfig\> | `[]` | Duplex, resumable session routes served by a guest `session-handler` — see [`sessions`](#sessions). |

Pattern fields (`from`, `matches`, handler `route`) use the
[path matcher](#patterns) syntax and are compiled at `validate`/`sync`, so a bad
pattern fails at deploy time rather than at request time.

## `trailing_slash`

| Value | Effect |
| --- | --- |
| `Preserve` | Leave the path as-is (default). |
| `Always` | Redirect to add a trailing slash. |
| `Never` | Redirect to strip a trailing slash. |

## `redirects`

Each rule redirects a matching path. First match wins.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `from` | pattern | — | Source path pattern. |
| `to` | string | — | Destination, with `:name` / `:splat` substitution. |
| `status` | u16 | `308` | HTTP status. `308` is permanent and method-preserving. |
| `when` | string | — | Optional [condition](#conditional-rules-when) — the rule fires only if it and `from` both match. |

```ron
redirects: [ (from: "/old/:slug", to: "/new/:slug", status: 301) ],
```

## `rewrites`

A rewrite serves a different resource without changing the URL. An internal
`to` (a path) rewrites; an absolute-URL `to` reverse-proxies to that upstream.
First match wins.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `from` | pattern | — | Source path pattern. |
| `to` | string | — | Internal path or absolute proxy URL, with `:name` / `:splat` substitution. |
| `status` | u16 | `200` | Status served for an internal rewrite (e.g. `200` for SPA fallback). |
| `when` | string | — | Optional [condition](#conditional-rules-when) — the rule fires only if it and `from` both match. |

An SPA fallback is a rewrite of everything to the app shell:

```ron
rewrites: [ (from: "/*", to: "/index.html", status: 200) ],
```

Proxy rewrites are constrained by [`proxy_allow`](#proxy_allow).

## Conditional rules (`when`)

A redirect or rewrite may carry a **`when`** condition — a small server-side
expression over the request. The rule fires only when its `from` pattern matches
**and** its `when` is true; otherwise the router keeps looking. This is how you do
language- or file-aware routing without a WASM handler, and it runs in the routing
hot path (compiled once at `sync`, then a fast in-memory evaluation per request).

```ron
routing: (
  redirects: [
    // Send the root to the visitor's preferred locale.
    ( from: "/", to: "/fr/", status: 302, when: "prefers_language(['fr','en']) == 'fr'" ),
    ( from: "/", to: "/en/", status: 302, when: "prefers_language(['en','fr']) == 'en'" ),
    // Fall back to the English page when a localized file is missing in this deploy.
    ( from: "/fr/*", to: "/en/:splat", status: 302, when: "!file_exists(path)" ),
  ],
)
```

The expression language is a **subset of [CEL](https://cel.dev/)** — boolean
expressions only, no loops, no timestamps, no regex — so it is bounded and cheap.
It is compiled and type-checked at `boatramp validate` / `sync` (a bad expression
fails the deploy).

**Variables** (strings): `method`, `host`, `path` (the normalized request path).

**Functions:**

| Call | Result | Notes |
| --- | --- | --- |
| `header("name")` | string | Request header value (`""` if absent). Name must be a literal. |
| `cookie("name")` | string | Cookie value (`""` if absent). |
| `query("name")` | string | Query-string value (`""` if absent). |
| `file_exists("/path")` | bool | Does that path serve a file in *this* deployment (honors clean-URLs + index)? |
| `accepts_language("fr")` | bool | Does `Accept-Language` accept the tag (primary-subtag match)? |
| `prefers_language(["fr","en"])` | string | The first listed tag the request accepts, else `""`. |

**Operators:** `==` `!=` `in` `&&` `||` `!`, string concatenation with `+`, and the
string/list methods `.startsWith(…)`, `.endsWith(…)`, `.contains(…)`.

```ron
when: "method == 'GET' && header('X-Country') == 'IT' && path.startsWith('/shop')"
```

### Computed destinations (`${…}`)

A `to` destination may embed `${<expr>}` — a string-valued expression from the same
language — so **one** rule can route to a computed target. `${…}` interpolation runs
*before* the usual `:name` / `:splat` capture expansion. The classic use is sending
a visitor to their negotiated locale in a single rule:

```ron
redirects: [
  ( from: "/",
    to: "/${prefers_language(['fr','en','de'])}/",
    status: 302,
    // Only redirect when a supported locale is actually accepted (else "//").
    when: "prefers_language(['fr','en','de']) != ''" ),
],
```

Embedded expressions are type-checked at `validate`/`sync` (each must be a string),
and — like conditions — a `${…}` that reads a header/cookie/`Accept-Language`
contributes to the response `Vary`.

> **Caching.** A condition that reads `Accept-Language`, a cookie, or a header makes
> the response depend on that dimension, so boatramp automatically adds the matching
> **`Vary`** header (e.g. `Vary: accept-language`) to the response — a downstream
> cache then keys on it and never serves one visitor's locale redirect to another.
> Conditions that read only the URL + deploy content (`path`, `file_exists`) add no
> `Vary`.

## `headers`

Each rule sets or removes response headers on matching paths. All matching rules
apply, in order.

| Field | Type | Description |
| --- | --- | --- |
| `matches` | pattern | Path pattern (named `matches` because `for` is a keyword). |
| `set` | map\<string, string\> | Headers to set. |
| `unset` | list\<string\> | Header names to remove. |

```ron
headers: [ (matches: "/assets/*", set: { "Cache-Control": "public, max-age=31536000, immutable" }) ],
```

## `cache`

| Field | Type | Description |
| --- | --- | --- |
| `default` | string? | Default `Cache-Control` for responses not covered by a header rule. |

## `proxy_allow`

Upstream hosts a proxy rewrite may target. An entry is an exact host or a
`.suffix` for a subtree (`.internal.example.com`). When the list is **empty**,
proxying to any *public* host is allowed; private, loopback, and link-local
addresses are always blocked as an SSRF guard, regardless of this list. To proxy
to a private address, declare a [gateway upstream](./siteconfig.md#gateway)
instead.

## `handlers`

A [WebAssembly handler](../explanation/compute-model.md) bound to a route.
Matched after redirects, before static lookup. See
[Deploy a handler](../how-to/deploy-handler.md).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `route` | pattern | — | Route pattern. |
| `methods` | list\<string\> | `[]` (all) | HTTP methods answered (`GET`, `POST`, …). |
| `component` | string | — | Path to the component `.wasm` within the deployment. |
| `imports` | list\<string\> | `[]` | Requested capabilities — see [imports](#imports). |
| `streaming` | bool | `false` | A **streaming** handler: the guest writes its response body incrementally (SSE, chunked, agent token streaming) via a `#[handler(stream)]` body. Served on the isolated streaming lane (its own concurrency budget + a much larger wall-clock), so a long-lived stream never holds a fast-request slot. |
| `limits` | HandlerLimits | — | Optional resource caps, intersected with the site caps at activation. |
| `env` | map\<string, string\> | `{}` | Static environment variables. **Never secrets** — a credential-shaped value is rejected at validate; use `[handlers].secrets` in `boatramp.cfg` for those. |
| `invoke_targets` | list\<string\> | `[]` | Function names this handler may call via the `invoke` import — see [invoke_targets](#invoke_targets). |
| `tenancy` | Tenancy? | `None` (inherit site) | Per-handler in-site [tenancy decision](./siteconfig.md#handlerstenancy) for this route, overriding the site-level ceiling. Absent ⇒ inherit the site decision. When present it must **narrow within** the site ceiling — a widening is refused fail-closed at bind. Same canonical RON shape as the site's, e.g. `(mode: "scoped", column: "tenant_id", sources: [(kind: "token", claim: "tid")], read: "own", write: "own")`. |
| `token_claims` | HandlerGraphqlTokenClaims? | `None` (inherit) | Per-handler JWKS/issuer config verifying the app bearer for a `token` tenant source, overriding the site's `[handlers.graphql.data].claims_from_token`. Only consulted when this handler's (or the inherited) `tenancy` names a `token` source. Fields: `issuer`, `jwks_env`/`jwks_url`, optional `audience`. |

### `imports`

The capability vocabulary a handler may request. An unrecognized import is
rejected at validate.

| Import | Grants |
| --- | --- |
| `invoke` | Call sibling functions by name, gated by [`invoke_targets`](#invoke_targets). |
| `graphql` | Run a GraphQL operation against the project's supergraph (`graphql::run`), propagating the caller's resolved principal to sub-fetches. |
| `email` | Send mail through a per-project SMTP profile (`boatramp:handlers/email`). Gated by the `allow_guest_email` posture knob — off under `multi-tenant`. |
| `capability` | Mint fleet-signed target-capability tokens (`boatramp:handlers/capability`). Gated by the `allow_guest_mint_capability` posture knob — off under `multi-tenant`. |
| `wasi:http` | Outbound HTTP. |
| `wasi:keyvalue` | Per-site KV store. |
| `wasi:blobstore` | Per-site blob store. |
| `wasi:messaging` | Publish / subscribe on topics. |
| `sql` | The **default** per-site SQL database (managed libsql), opened as `sql.open("")`. |
| `sql:<name>` | A specific operator-configured [named database](../how-to/handler-bindings.md#bring-your-own-database-external-postgres--mysql) (e.g. `sql:analytics`), opened as `sql.open("<name>")` — its own connection + role, for least-privilege isolation. |
| `sql:*` | Every named database the site exposes (a convenience grant; the site's `allow_imports` is still the hard ceiling). |
| `admin:domains` / `admin:email` / `admin:site` / `admin:secrets` | A guest project-self-config surface via `boatramp:handlers/admin`. Each is a **specific** surface grant (a bare `admin` and `admin:*` are deliberately not accepted — deny-by-default, least-privilege) and is additionally gated by the matching `allow_guest_admin_*` posture knob (all off under `multi-tenant`). |
| `session` | A duplex/resumable [session](#sessions) route's per-frame session binding. Accepted in `imports` but advertised only when the host is built with the `session` feature (the `requires` ABI gate enforces host support at activation). |
| `tenancy` | Host-verify a guest-presented token to seal an async-lane producer context (`boatramp:handlers/tenancy` `present-token`). Accepted in `imports` but advertised only when the host is built with the `messaging` feature. |
| `wasi:io`, `wasi:clocks`, `wasi:random`, `wasi:logging` | Standard host facilities (`wasi:logging` messages are captured into the site's logs alongside stdout/stderr). |

The site's [`allow_imports`](./siteconfig.md#handlers) is the allowlist; a
handler requesting an import the site does not permit is denied at activation.

### `invoke_targets`

The deny-by-default allowlist of sibling function names this handler may call
through the `invoke` import. Each entry may use `*` wildcards (`*` = any function,
`img-*` = a family, `resize` = one literal). It is only consulted when `imports`
contains `invoke` (which the site's `allow_imports` must also permit); an empty
list means the handler cannot invoke anything even with the import.

```ron
handlers: [ (route: "/api", component: "api.wasm", imports: ["invoke"], invoke_targets: ["resize", "img-*"]) ],
```

### `limits` (HandlerLimits)

| Field | Type | Description |
| --- | --- | --- |
| `memory_mb` | u32? | Max linear memory, MiB. |
| `timeout_ms` | u32? | Wall-clock timeout, ms. |
| `fuel` | u64? | CPU budget in wasmtime fuel units (deterministic instruction-count bound). Omitted = unmetered. |

Each field may only **lower** the corresponding site cap, never raise it. A request
handler is connection-bearing, so its `timeout_ms` is additionally capped by the
engine's **sync** ceiling (`handlers.sync_max_timeout_ms`, default 10s) — a route that
declares more is clamped back down. Genuinely long-running work belongs on the
[async path](../how-to/functions.md#long-running-jobs-run-async-not-sync) (a durable
`--async` invocation or a workflow), not a request handler held open.

## `consumers`

A component invoked once per message on a topic. See
[Run consumers, crons, and streams](../how-to/background-work.md).

| Field | Type | Description |
| --- | --- | --- |
| `topic` | string | Topic to subscribe to. A `bus:<topic>` prefix subscribes to the shared, project-scoped bus (so producers and consumers in different components meet on one topic); a plain topic is site-private. |
| `component` | string | Path to the component `.wasm`. |
| `imports` | list\<string\> | Requested capabilities. |
| `group` | string | Consumer group. Empty (default) = the competing-consumer **work-queue** (one consumer handles each message); a non-empty name = a durable **fan-out** subscriber that receives *every* message on its own cursor, independent of other groups. |
| `start` | `latest` \| `earliest` | Where a non-empty `group` starts on first subscription: `latest` (default — only new events) or `earliest` (replay the retained backlog). Ignored for the work-queue. |
| `tenancy` | Tenancy? | In-site [tenancy decision](./siteconfig.md#handlerstenancy) for this consumer's `sql`/`orm` when a drained message is processed — the async-lane analog of a function's tenancy. Typically resolves from the `signed_context` source the producer stamped, e.g. `(mode: "scoped", column: "tenant_id", sources: [(kind: "signed_context")], read: "own", write: "own")`. Absent ⇒ *undeclared* (refused under `multi-tenant`, `disabled` under single-tenant/dev). |
| `token_claims` | HandlerGraphqlTokenClaims? | JWKS/issuer config verifying an app bearer for a `token` tenant source (rare on the async lane, but supported when a consumer is invoked with a forwarded bearer). Absent ⇒ the `token` source can't verify (fail-closed). |

## `crons`

A scheduled invocation of a declared handler route.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `schedule` | string | — | Standard 5-field cron (`minute hour dom month dow`). |
| `route` | string | — | Handler route to invoke; must be served by a declared handler. |
| `overlap` | enum | `Skip` | `Skip` a tick if the previous run is still in flight, or `Allow` concurrent runs. |

## `streams`

A host-level endpoint that fans out messaging topics to connected clients.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `route` | string | — | Route the endpoint is served at. |
| `topics` | list\<string\> | — | Topics broadcast to clients (server→client). |
| `websocket` | bool | `false` | Serve as a WebSocket instead of SSE (adds a client→server direction). |
| `publish_topic` | string? | — | For a WebSocket, the topic client→server messages publish to. Omitted = receive-only. |

## `sessions`

A **duplex, resumable session** route: a long-lived, client-addressable, bidirectional channel
served by a guest component's `session-handler` export, which the host re-enters per inbound frame.
The host opens the session on `route` (SSE-out + POST-in), binds the verified principal, orders +
resumes outbound frames, and persists a checkpoint. Frames are opaque bytes. Unlike a
[`stream`](#streams) (host-only pub/sub fan-out), a session runs guest code and carries a
backchannel.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `route` | pattern | — | Route the session is opened at (the client `GET`s it for the SSE stream and `POST`s inbound frames to it). |
| `component` | string | — | Path to the session component `.wasm` (exports `session-handler`). |
| `imports` | list\<string\> | `[]` | Requested capabilities — a session handler declares `session` plus whatever `sql`/`invoke`/… it uses per frame. See [imports](#imports). |
| `limits` | HandlerLimits | — | Optional resource caps, capped by site config at activation. |
| `env` | map\<string, string\> | `{}` | Static environment variables (never secrets). |
| `invoke_targets` | list\<string\> | `[]` | Function names the session may call via `invoke` (same contract as a handler's [`invoke_targets`](#invoke_targets)). |
| `tenancy` | Tenancy? | `None` (plain) | In-site [tenancy decision](./siteconfig.md#handlerstenancy) for this session's `sql`/`orm`. Resolved once at **open** from the verified source and carried across every re-entry, e.g. `(mode: "scoped", column: "tenant_id", sources: [(kind: "token", claim: "tid")], read: "own", write: "own")`. |
| `token_claims` | HandlerGraphqlTokenClaims? | `None` (inherit) | JWKS/issuer config verifying the app bearer for a `token`-sourced tenant (same as a handler's). |

## Patterns

Route, redirect, rewrite, and header patterns share one matcher syntax:

| Token | Matches | Capture |
| --- | --- | --- |
| `:name` | One path segment | `:name` in `to` |
| `*` / `/*` | The rest of the path | `:splat` in `to` |
| literal | Itself | — |

Path normalization (dot-segment collapsing, the trailing-slash policy) runs
*before* matching, so patterns always see a canonical path and cannot be bypassed
with `..` or a double slash. See [The request pipeline](../explanation/request-pipeline.md).
