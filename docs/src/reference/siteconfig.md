# SiteConfig schema

`SiteConfig` is the **site-scoped, mutable** config tier: domains, transport
security, visitor access control, handler caps, compression, and the gateway. It
is stored as JSON in the KV (not in a deployment manifest), so it changes
independently of content and does not roll back with a deployment. Most of it is
managed through subcommands rather than edited by hand.

The tiers, contrasted:

| | [Routing](./routing.md) (`project.cfg`) | SiteConfig (KV) |
| --- | --- | --- |
| Scope | One deployment | The whole site |
| Lifecycle | Immutable, rolls back with content | Mutable, independent |
| Edited via | `project.cfg` + `sync` | `boatramp domain` / `access` / `gateway` / API |

## Top-level fields

| Field | Type | Default | Managed by |
| --- | --- | --- | --- |
| `version` | u32 | `1` | — (pinned at 1) |
| `domains` | DomainConfig | empty | [`boatramp domain`](#domains) |
| `security` | SecurityConfig | off | API / [transport security](#security) |
| `access` | AccessConfig | open | [`boatramp access`](../how-to/visitor-access.md) |
| `handlers` | HandlersSiteConfig? | `None` (disabled) | [handler caps](#handlers) |
| `compression` | CompressionConfig | off | [`boatramp compression`](../how-to/compression.md) |
| `gateway` | GatewayConfig? | `None` | [`boatramp gateway`](../how-to/gateway.md) |

## `domains`

The hostnames a site answers to (virtualhost routing). See
[Serve a custom domain](../how-to/custom-domain.md).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `primary` | string? | — | Canonical hostname (`example.com`). |
| `aliases` | list\<string\> | `[]` | Additional exact hostnames (`www.example.com`). |
| `wildcards` | list\<string\> | `[]` | Wildcard patterns (`*.example.com`), matched by suffix at any depth. |
| `canonical_redirect` | bool | `false` | 301 exact-alias hosts to `primary` (apex↔www). Wildcard hosts serve as-is. |

## `security`

Site-tier transport security. Off by default; opt in once TLS is in front
(directly or via a terminating proxy). The effective scheme is read from
`X-Forwarded-Proto` behind a trusted proxy. See
[Harden the security posture](../how-to/security-posture.md).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `https_redirect` | bool | `false` | 301 plain-HTTP requests to HTTPS. |
| `hsts` | Hsts? | — | Send `Strict-Transport-Security` on HTTPS responses. |
| `csp` | string? | — | `Content-Security-Policy` header value (opt-in; no safe default for static sites). |
| `frame_options` | string? | — | `X-Frame-Options` value (`DENY`, `SAMEORIGIN`). |

### `hsts`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `max_age` | u64 | `31536000` | `max-age` in seconds (one year). |
| `include_subdomains` | bool | `true` | Apply to subdomains. |
| `preload` | bool | `false` | Request browser-preload-list inclusion (hard to undo — explicit opt-in). |

## `access`

Visitor access control — WAF, IP rules, rate limiting, basic auth, trusted-proxy
handling. This is the full mechanism for restricting who may *view* a site; it is
separate from control-plane [RBAC](./rbac.md). Managed with `boatramp access` and
documented in [Restrict visitor access](../how-to/visitor-access.md).

## `handlers`

Site-scoped handler policy: the capability allowlist and resource caps a
deployment's requested [handler config](./routing.md#handlers) is intersected
against at activation (deny by default). `None` disables handlers for the site
entirely.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Whether handlers run for this site at all. |
| `allow_imports` | list\<string\> | `[]` | Interfaces handlers on this site may import (subset of the [import vocabulary](./routing.md#imports)). |
| `max_memory_mb` | u32? | — | Cap on per-handler memory (MiB). |
| `max_timeout_ms` | u32? | — | Cap on per-handler wall-clock timeout (ms). |
| `max_concurrency` | u32? | — | Cap on concurrent invocations for the site. |
| `max_fuel` | u64? | — | Cap on per-handler CPU fuel; a handler's own `fuel` may only lower it. |
| `secrets` | map\<string, string\> | `{}` | Env-var name → secret **reference** (a host env-var name, resolved server-side — never a literal secret). |
| `background_aliases` | list\<string\> | `[]` | Named aliases (besides current) whose deployments also run consumers and crons. See [Run background work](../how-to/background-work.md). |
| `max_stream_connections` | u32? | — | Cap on concurrent SSE/WebSocket connections for the site. |
| `max_log_rate` | u32? | — | Cap on captured guest log lines per second (over-cap lines are dropped, counted). |
| `cache` | HandlerCacheConfig? | `None` (off) | [Edge response cache](#handlerscache). |
| `graphql` | HandlerGraphqlConfig? | `None` (off) | [GraphQL edge features](#handlersgraphql). |
| `cookie_auth` | CookieAuthConfig? | `None` (off) | [Browser cookie session auth](#handlerscookie_auth). |

A handler that requests an import not in `allow_imports`, or exceeds a cap, is
rejected at activation — not at request time. See
[Handler host bindings](../how-to/handler-bindings.md).

### `handlers.cache`

Host-level **response cache**: a cacheable `GET`/`HEAD` response is served for a
later identical request **without re-instantiating the handler**. Opt-in per
response, driven by the handler's own `Cache-Control`; never caches a private
response (`no-store`/`private`/`no-cache`, a `Set-Cookie`, `Vary: *`, or an
`Authorization` request without `public`/`s-maxage`). Entries are keyed by the
request's project-qualified scope, honor `Vary`, and expire by TTL. Backed by the
site's KV store. See [Cache handler responses](../how-to/caching.md#cache-handler-responses-at-the-edge).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch; inert even if present when `false`. |
| `max_entry_bytes` | u64? | `262144` (256 KiB) | Largest cacheable entry (status+headers+body); a bigger response streams through uncached. |
| `max_ttl_secs` | u64? | `3600` | Upper bound on a stored entry's TTL, clamping an over-long `max-age`. |

### `handlers.graphql`

GraphQL edge features. Off unless present + `enabled`. See
[Serve a GraphQL API](../how-to/graphql.md).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master switch for the GraphQL edge. |
| `max_depth` | u32? | server default | Deepest allowed selection nesting (fragments expanded). |
| `max_complexity` | u32? | server default | Largest allowed total field count (schema-free cost proxy). |
| `introspection` | bool? | posture default | Allow schema-introspection queries (off under the multi-tenant posture). |
| `persisted_queries` | bool | `false` | Resolve a query hash to the stored query (bandwidth + parse saving). |
| `safelist` | bool | `false` | Only pre-registered query hashes run (a query allowlist); implies and is stronger than `persisted_queries`. |
| `federated` | bool | `false` | This site is a supergraph **gateway**: plan a query against the project's registered subgraphs and dispatch fetches to them. |
| `graphiql` | bool | `false` | Serve the in-browser GraphiQL explorer to a browser `GET`. |
| `data` | HandlerGraphqlDataConfig? | `None` | Declarative [data connector](../how-to/graphql.md#graphql-from-your-database-no-resolver-code): generate the API from a managed database (queries compiled to SQL). Deny-by-default exposure; a `claims_from_token` block can bind a claim from a verified application bearer for multi-tenant row isolation. |

### `handlers.cookie_auth`

Browser **cookie session auth**. Off unless present. A request carrying the named
cookie but **no** `Authorization` header is authenticated from the cookie value —
boatramp injects it as the app bearer everywhere the header bearer flows (the
`Authorization` header always wins). boatramp **only reads** the cookie; the app
sets, refreshes, and verifies it. Set the cookie `HttpOnly; Secure; SameSite=Lax`
with a `__Host-` prefix. See
[Authenticate a browser with a session cookie](../how-to/handler-bindings.md#authenticate-a-browser-with-a-session-cookie).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `cookie_name` | string | — | The cookie whose value becomes the bearer when no `Authorization` header is present. |
| `allowed_origins` | list\<string\> | `[]` | **Additional** cross-origin CSRF allowlist. Same-origin (request `Origin`/`Referer` authority == own `Host`) always passes, so `[]` ⇒ *same-origin only* — no config for the usual SPA. List the extra origins a browser app on a **different** origin than this API may use; a cross-origin request that's neither same-origin nor listed is rejected `403`. Each entry is a `scheme://host[:port]` origin. |

## `compression`

On-the-fly response compression. Opt-in, and complementary to serving a
precompressed variant. A response is compressed only when it has no precompressed
variant or existing `Content-Encoding`, its type is compressible, and (when the
length is known) it is at least `min_size`. Credentialed responses are skipped
for BREACH safety. See [Compress responses](../how-to/compression.md).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Master toggle. |
| `min_size` | u64 | `1024` | Don't compress a response with a `Content-Length` below this (bytes). Streaming responses with no declared length are always eligible. |

## `gateway`

Reverse-proxy gateway for publishing private services. `None` means no gateway
routes. Declaring an upstream here is what authorizes reaching a private address
— the [SSRF guard](./routing.md#proxy_allow) stays public-only otherwise. Fields
cover upstream pools, load balancing, and health checking; see
[Expose a private service through the gateway](../how-to/gateway.md).
