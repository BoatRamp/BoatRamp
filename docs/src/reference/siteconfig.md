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
| `contexts` | map\<string, string\> | `{}` | Per-host **tenant-context tag**: host-or-wildcard → an opaque in-site tenant id, the `domain` [tenant source](../how-to/tenant-isolation.md#dimension-1-the-tenant-source). Lets one deployment serve many customer storefronts, each domain its own tenant. An exact host with no entry inherits `primary`'s tag; a subdomain inherits its wildcard's. Bound as a parameter, never formatted into SQL. |

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
| `disable_log_capture` | bool | `false` | Opt **out** of capturing guest `stdout`/`stderr` + `wasi:logging`. Capture is on by default (logs endpoint + SSE tail + `serve.log` mirror); set `true` to discard it, e.g. when guest output may carry secrets/PII. |
| `cache` | HandlerCacheConfig? | `None` (off) | [Edge response cache](#handlerscache). |
| `graphql` | HandlerGraphqlConfig? | `None` (off) | [GraphQL edge features](#handlersgraphql). |
| `cookie_auth` | CookieAuthConfig? | `None` (off) | [Browser cookie session auth](#handlerscookie_auth). |
| `tenancy` | Tenancy? | `None` (undeclared) | Site-level in-site [tenancy decision](#handlerstenancy) for `sql`/`orm` access — the ceiling for this site's handlers. |
| `allow_ceiling_exceptions` | bool | `false` | Whether a route may deliberately **exceed** this site's `tenancy` ceiling via [`exceed_site_ceiling`](../how-to/tenant-isolation.md#an-unscoped-all-route-under-an-own-site-authorized-exception) (key 1 of the three-key model). While `false`, every route's exception token is inert (a widening still fails closed) — so a site at the default is provably exception-free. Enabling it authorizes nothing by itself: a route must also carry `exceed_site_ceiling: true`, and an `all` grant still needs the operator [`allow_cross_tenant_db`](../how-to/tenant-isolation.md#dimension-2-the-access-mode-per-readwrite-axis) posture. |

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

### `handlers.tenancy`

The site's **in-site tenancy decision** — how the host scopes `sql`/`orm` row access across
sub-tenants sharing one database. Absent (`None`) means *undeclared*: refused at activation for a
`sql`/`orm`-importing site under the `multi-tenant` posture (which requires an explicit decision),
treated as `disabled` under single-tenant/dev. Three shapes (a tagged `mode`):

```json
{ "mode": "disabled" }
```
Deliberately no in-site tenancy — plain queries (the project = database boundary is the whole
isolation). The explicit "single-tenant / no tenancy" declaration.

```json
{ "mode": "scoped",
  "column": "tenant_id",
  "sources": [ { "kind": "token", "claim": "tid" } ],
  "read":  "own",
  "write": "own" }
```
In-site sub-tenancy on `column`, resolving "own" from the first applicable `sources` entry, at
per-axis access grants. In `project.cfg` / `apply.cfg` RON the canonical spelling is
`(mode: "scoped", column: "tenant_id", sources: [(kind: "token", claim: "tid")], read: "own", write: "own")`.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `column` | string | — | The tenant column the host scopes on (validated as an identifier). |
| `sources` | list\<TenantSource\> | `[{"kind":"none"}]` | Host-verified sources the "own" tenant resolves from, in **priority order** — the host picks the first whose current-trigger input is present (a `token` on an authenticated request, `domain` on a storefront, `signed_context` on an async job), so one component serves multiple trigger kinds. The pre-Stage-2 singular `source: {…}` field is still accepted (a one-element list) for back-compat. |
| `read` | AccessMode | `own` | Which tenant-set reads may reach. |
| `write` | AccessMode | `own` | Which tenant-set writes may reach. |

Each `TenantSource` is `{"kind":"token","claim":"tid"}` (a verified JWT claim, `claim` default
`tid`), `{"kind":"domain"}` (the routed domain's [`contexts`](#domains) tag), `{"kind":"signed_context"}`
(a host-verifiable envelope on an async job/message — the async-lane "own"), or `{"kind":"none"}`
(anonymous — an "own" grant then fails closed).

`AccessMode` is one of `none` (deny), `null` (the `tenant_id IS NULL` shared baseline only), `own`
(the resolved tenant), `own_or_null` (both), or `all` (cross-tenant — default-deny, gated by the
[`allow_cross_tenant_db`](./boatramp-cfg.md) posture ceiling; capped to `own` when off). `own_or_null`
on the **write** axis degrades to `own` (a write never touches the shared baseline). A top-level
function's own [`tenancy`](../how-to/apply.md) block narrows within this site ceiling. Full model:
[Isolate tenants in one database](../how-to/tenant-isolation.md).

```json
{ "mode": "target",
  "via": [ "domain" ],
  "public": "storefront",
  "write": [ "status" ],
  "null_base": false }
```
**Target**: this route reads (and, with a non-empty `write` allowlist, writes) a **second** tenant
`B`'s PUBLIC subset — never the caller's own tenant. The host resolves `B` from the first applicable
`via` source and binds the target scope before the guest runs, confining every access to
`tenant = B AND <public subset>`. Gated by the operator's [`target_eligible_fields`](#tenancyschema)
allowlist.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `via` | list\<TargetSource\> | — | Prioritized target-source list (first-resolves-wins): `"domain"` (the terminating request domain, write-capable), `"handle"` (a public slug from a third-party origin — **read-only**, admissible only on a `world_public` subset), or `"capability"` (a host-verified capability token carrying `tid`/`sub` — the token is the authorization, can back a target write). |
| `public` | string | — | Names the host-held [public subset](#tenancyschema) (a table in the project's `public_subsets`) accesses confine to. |
| `write` | list\<string\> | `[]` | Deny-by-default SET-allowlist of columns a target write (INSERT/UPDATE via the typed `orm` only) may set. **Empty ⇒ read-only.** The tenant + visibility columns must not appear here (a target write can't change ownership or flip visibility); a DELETE and any raw-SQL write are refused. |
| `null_base` | bool | `false` | `target_or_null`: when `true`, a target READ confines to `(<tenant col> = B OR <tenant col> IS NULL) AND <public subset>` — `B`'s public rows plus the shared `NULL`-tenant base/reference rows. Read-only (a target write still stamps `B`); the `NULL` disjunct is added only on plain tenant-column tables. |

### `TenancySchema`

The **project-level** tenant-isolation schema — the host-held facts the scope injector keys off,
declared per project (not per component) with [`boatramp tenancy apply`](./cli.md#boatramp-tenancy),
not in `SiteConfig`. A `target` tenancy decision (above) needs the operator to have opened the axis
in this schema; a project that declares none uses the legacy single-column scoping. Key fields:

| Field | Type | Description |
| --- | --- | --- |
| `default_tenant_key` | string | The tenant column for a `tenant`-scoped table (default `tenant_id`). |
| `session_key` | string? | The anonymous-session column for `tenant_or_session` tables, present iff the project uses the session axis. |
| `tables` | map\<string, TableScope\> | Per-table scope facts, authoritative + exhaustive when present (a table with no entry is refused, deny-by-default). A `TableScope` is `tenant`, `tenant_keyed { key }`, `unscoped`, or `tenant_or_session`. |
| `target_eligible_fields` | set\<string\> | The operator's allowlist ceiling: which root Query/Mutation fields (and plain-wasm route ids) may carry a `target` scope at all. Empty ⇒ no field may be target (deny-by-default). |
| `public_subsets` | map\<string, PublicSubset\> | Per-table PUBLIC subset definitions a target read/write confines to: a visibility `predicate` (a closed conjunction of `column <op> literal` / null-test terms) plus the deny-by-default `world_public` (admits the anonymous `handle` source) and `listable` (handle-discoverable) flags. A `target` field over a table with no entry is refused. |
| `handles` | map\<string, string\> | Operator-curated PUBLIC handle/slug → target tenant context tag `B`. A `handle` target source resolves `B` only for a slug listed here (deny-by-default) and only when the route's `public` subset is `world_public`. |

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
