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
| `webhook_sinks` | list\<WebhookSink\> | `[]` | Host-run webhook sinks — drain a project-bus topic and deliver each message as a signed, SSRF-confined outbound POST. See [below](#webhook_sinks). |
| `crons` | list\<CronConfig\> | `[]` | Scheduled handler invocations. |
| `streams` | list\<StreamConfig\> | `[]` | Host-level SSE / WebSocket endpoints fanning out topics. |
| `sessions` | list\<SessionConfig\> | `[]` | Duplex, resumable session routes served by a guest `session-handler` — see [`sessions`](#sessions). |
| `base_path` | string | `""` | Opt-in sub-path mount — serve the deploy under `/myapp` instead of at the site root. See [below](#base_path). |

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

## `base_path`

An **opt-in sub-path mount**. By default a deploy is served at the site **root**
(`/`). Set `base_path` to serve it under a sub-path instead:

```ron
(
    base_path: "/myapp",
)
```

With this set, a request to `https://site.example.com/myapp/foo` is routed to the
app as `/foo` — the base is **stripped before** any redirect, rewrite, handler, or
static lookup sees it — and the base is **re-added** to the `Location` of every
server-generated redirect (trailing-slash normalization and `redirects` rules), so
an app-internal link resolves correctly behind the mount. A request that is **not**
under the mount — an unrelated path, the prefix-only `/myappX`, or a `..`-traversal
that climbs out — is **not served** (`404`, fail-closed). The mount is applied
identically on the Cloudflare edge path, so behavior is the same on every topology.

> **This is for a site _built with a matching_ base path** — a framework's
> `base` / `basePath` build option (Vite `base`, Next.js `basePath`, SvelteKit
> `paths.base`, …) so the app's **own** asset and link references already carry the
> `/myapp` prefix. It is **not** a rescue for hand-authored absolute URLs
> (`<img src="/logo.png">`), `fetch('/api')`, CSS `url(/…)`, or service-worker
> scope — the server cannot rewrite those. If your site was not built for a
> sub-path, serve it at the root via [host routing](../explanation/addressing.md)
> instead.

Validation (`boatramp validate`) rejects a malformed mount at deploy time: it must
be a clean absolute sub-path (`/myapp`, `/team/app`), not the bare root `/`, and it
may not contain `//`, a `.`/`..` segment, a glob (`*`), a query/fragment, or
whitespace. See [How a request reaches your site](../explanation/addressing.md) for
how `base_path` fits alongside the other addressing modes.

### Whole-site remount and operator routes

`base_path` remounts the **entire** site under the prefix: the deploy answers only
paths under the mount, and **every external path outside the mount returns `404`**
(fail-closed — nothing of the site is served at the root any more).

This interacts with an operator's [per-site gateway](./siteconfig.md#gateway)
overlay (`routes` / `reserved_paths`):

- An operator route (or reserved path) that **overlaps** the mount still **wins** —
  it is judged against the **full external path**, so a tenant `base_path` can never
  shadow or capture it. For `base_path: "/ops"`, an operator route `/ops/**` is
  served by the operator upstream, not the tenant.
- An operator route whose path falls **outside** the tenant's mount returns `404` on
  that based deploy — fail-closed: the tenant can neither capture it nor reach
  operator content; the route is simply **unreachable on that one deploy** (a direct
  consequence of the whole-site remount, not a bug).

So an operator path that must stay reachable **regardless** of a tenant's mount
belongs at the node-global router layer — the paths matched before per-site routing
(`/api/*`, `/healthz`, `/readyz`, `/mcp`, `/.well-known/*`) — not as a per-site
gateway overlay. The per-site overlay is a routing convenience, not the place for
mandatory operator enforcement.

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
| `upload_containers` | list\<string\> | `[]` | Blob containers this handler may mint an S3 upload credential for via a [`blob-upload`](#imports) import — see [upload_containers](#upload_containers). Deny-by-default (empty ⇒ mint nothing). |
| `egress_allowlist` | list\<string\> | `[]` | `host:port` / `ip:port` / `CIDR:port` targets this handler may dial via the [`wasi:sockets`](#imports) import — see [egress_allowlist](#egress_allowlist). Deny-by-default (empty ⇒ reach nothing). |
| `dynamic_egress_hosts` | list\<string\> | `[]` | `host-glob:port` targets this handler may dial by NAME at runtime via the host-mediated [`wasi:sockets`](#imports) import (`connect-tls`) — see [dynamic_egress_hosts](#dynamic_egress_hosts). Deny-by-default; HTTPS-only; gated by the posture `allow_guest_dynamic_egress`. |
| `dns_publish_zones` | list\<string\> | `[]` | Zone-suffix globs this handler may WRITE DNS records under via the [`dns-publish`](#imports) import — see [dns_publish_zones](#dns_publish_zones). Deny-by-default (empty ⇒ write nothing). |
| `dns_publish_ns_targets` | list\<string\> | `[]` | Nameserver-target globs a sub-zone `NS` record this handler writes may delegate to — see [dns_publish_ns_targets](#dns_publish_ns_targets). Only consulted for a non-apex `NS` record when the node posture `guest_dns_publish_ns` is `allowlist`. |
| `tenancy` | Tenancy? | `None` (inherit site) | Per-handler in-site [tenancy decision](./siteconfig.md#handlerstenancy) for this route, overriding the site-level ceiling. Absent ⇒ inherit the site decision. When present it must **narrow within** the site ceiling — a widening is refused fail-closed at bind. Same canonical RON shape as the site's, e.g. `(mode: "scoped", column: "tenant_id", sources: [(kind: "token", claim: "tid")], read: "own", write: "own")`. A `scoped` tenancy may add `exceed_site_ceiling: true` to deliberately **exceed** the ceiling (an authorized [inline exception](../how-to/tenant-isolation.md#an-unscoped-all-route-under-an-own-site-authorized-exception)) — takes effect only when the site sets [`allow_ceiling_exceptions`](./siteconfig.md#handlersallow_ceiling_exceptions) and (for `all`) the operator posture permits cross-tenant; otherwise the deploy is refused with a message naming the route. |
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
| `blob-upload:write` / `blob-upload:multipart` | Mint a scoped S3 upload credential (`boatramp:handlers/blob-upload`) so a client uploads a blob directly, outside the sandbox. Gated by the per-handler [`upload_containers`](#upload_containers) allowlist (empty ⇒ deny-all); the project + site are host-forced from the resolved invocation scope. `:write` mints a single-object presigned PUT / temp credential; `:multipart` additionally permits multipart uploads. A bare `blob-upload` or `blob-upload:*` wildcard is rejected. See [S3-compatible blob ingress](../how-to/blob-ingress.md). |
| `wasi:http` | Outbound HTTP. |
| `wasi:keyvalue` | Per-site KV store. |
| `wasi:blobstore` | Per-site blob store. |
| `wasi:messaging` | Publish / subscribe on topics. |
| `sql` | The **default** per-site SQL database (managed libsql), opened as `sql.open("")`. |
| `sql:<name>` | A specific operator-configured [named database](../how-to/handler-binding-sql.md#bring-your-own-database-external-postgres--mysql) (e.g. `sql:analytics`), opened as `sql.open("<name>")` — its own connection + role, for least-privilege isolation. |
| `sql:*` | Every named database the site exposes (a convenience grant; the site's `allow_imports` is still the hard ceiling). |
| `admin:domains` / `admin:email` / `admin:site` / `admin:secrets` | A guest project-self-config surface via `boatramp:handlers/admin`. Each is a **specific** surface grant (a bare `admin` and `admin:*` are deliberately not accepted — deny-by-default, least-privilege) and is additionally gated by the matching `allow_guest_admin_*` posture knob (all off under `multi-tenant`). |
| `session` | A duplex/resumable [session](#sessions) route's per-frame session binding. Accepted in `imports` but advertised only when the host is built with the `session` feature (the `requires` ABI gate enforces host support at activation). |
| `tenancy` | Host-verify a guest-presented token to seal an async-lane producer context (`boatramp:handlers/tenancy` `present-token`). Accepted in `imports` but advertised only when the host is built with the `messaging` feature. |
| `wasi:sockets` | Host-mediated outbound TCP `connect` (`boatramp:handlers/tcp-egress`) — never a raw socket. Gated by the per-handler [`egress_allowlist`](#egress_allowlist) (empty ⇒ deny-all) **and** the node posture `allow_guest_tcp_egress` (off under `multi-tenant`); the dial is connect-only and still SSRF-floored even against an allowlisted target. The SAME grant also drives the **runtime-resolved-host** dial via [`dynamic_egress_hosts`](#dynamic_egress_hosts) (gated by the separate posture `allow_guest_dynamic_egress`, HTTPS-only), **and** the host-mediated [**HTTP request** to a runtime host](#http-egress-host-mediated-http-to-a-runtime-host) (`boatramp:handlers/http-egress` `emit-http-dynamic`) — same grant, same `dynamic_egress_hosts` allowlist, same gate. Advertised Experimental. |
| `dns-resolve` | Host-side MX/address resolution (`boatramp:handlers/dns-resolve`, `resolve-mx`/`resolve-addr`) without holding `wasi:sockets`. Gated by the same `allow_guest_tcp_egress` posture as `wasi:sockets`; results are SSRF-floored. Advertised Experimental. |
| `dns-publish` | Host-side DNS **write** (`boatramp:handlers/dns-publish`) — the guest NAMES a zone/record and the host performs the mutation through a host-held provider credential (the guest never holds a zone-write token). Three-layer fail-closed gate: the node posture `allow_guest_dns_publish` (**off** in every built-in profile), the per-handler [`dns_publish_zones`](#dns_publish_zones) writable-zone allowlist (empty ⇒ deny-all), and a per-invocation rate budget + audit log. A sub-zone `NS` record's target is additionally checked against [`dns_publish_ns_targets`](#dns_publish_ns_targets) when the node posture `guest_dns_publish_ns` is `allowlist`. Advertised Experimental. |
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

### `upload_containers`

The deny-by-default allowlist of blob containers this handler may mint an S3
upload credential for through a [`blob-upload:write` / `blob-upload:multipart`](#imports)
import (empty ⇒ deny-all — a handler that declares the import but names no
container can mint nothing). Only consulted when `imports` contains a
`blob-upload:*` right the site also permits.

An entry may carry the literal token **`{tenant}`** (e.g. `"assets-{tenant}"`).
Before minting, the **host** substitutes **this invocation's own resolved tenant**
(the same `ScopeAxis::Tenant` fact the SQL scope injector uses — never
guest-supplied) into `{tenant}`, **before** the allowlist match and the scope
stamp. This authorizes an unbounded **per-tenant container family**
(`assets-<tid>`, one per tenant) that a static exact list could never enumerate,
while keeping a cross-tenant mint **structurally impossible**: the entry only ever
expands to the guest's own tenant, so a guest asking for `assets-<other-tid>` fails
the allowlist. An `all` / anonymous / target / unscoped invocation has no resolved
tenant, so a `{tenant}` entry there **fails closed** (`no-resolved-tenant`). An
entry without `{tenant}` keeps plain exact-match (additive, non-breaking).

```ron
handlers: [ (route: "/upload", component: "up.wasm", imports: ["blob-upload:write"], upload_containers: ["assets-{tenant}"]) ],
```

See [S3-compatible blob ingress](../how-to/blob-ingress.md).

### `egress_allowlist`

The deny-by-default allowlist of `host:port` / `ip:port` / `CIDR:port` targets this
handler may `connect` to through the gated [`wasi:sockets`](#imports) import (empty ⇒
reach nothing). A domain entry is resolved host-side and matched against the resolved
peer IP; an `ip:port` / `CIDR:port` entry is matched structurally. The gate is
`connect`-only (never `bind`/`listen`), and even an allowlisted target is still held to
the SSRF floor unless the posture also allows private egress. Only consulted when
`imports` contains `wasi:sockets` **and** the node posture `allow_guest_tcp_egress` is on.

```ron
handlers: [ (route: "/api", component: "api.wasm", imports: ["wasi:sockets"], egress_allowlist: ["db.internal:5432"]) ],
```

### `dynamic_egress_hosts`

The deny-by-default allowlist for a **runtime-resolved host** the guest dials by NAME
through the host-mediated [`wasi:sockets`](#imports) capability. It authorizes **two** host-mediated
runtime-host verbs under the one grant: the raw-TLS `tcp-egress` `connect-tls` dial (BR-REQ-2) and
the host-framed [`http-egress` `emit-http-dynamic`](#http-egress-host-mediated-http-to-a-runtime-host)
HTTP request (BR-REQ-3). Unlike [`egress_allowlist`](#egress_allowlist) — which matches a *resolved
peer IP* against a fixed deploy-time list — this matches the HOSTNAME the guest supplies at call time
against operator-authored `host-glob:port` globs, so a per-tenant host **not known at deploy**
(e.g. a per-tenant OIDC issuer like a tenant's Okta org) is reachable without widening the IP
list. The specific host is resolved at runtime (from the guest's own per-tenant config); only
the glob pattern is configured here.

Entry syntax is `<host-glob>:<port>` with the same globbing as a DNS zone / gateway host:
`oauth2.googleapis.com:443` (exact), `*.okta.com:443` (one label), `**.okta.com:443` (any
depth), `**:443` (anything). A malformed entry (missing/non-numeric port, empty host-glob, a
`*.`/`**.` with no suffix) is **rejected loudly at `apply`/`validate`**, not silently ignored.
It is **HTTPS-only** (consulted ONLY on the implicit-TLS `connect-tls` dial — a plaintext dial
never uses it), keeps the SSRF floor (every resolved address must be globally routable unless
the posture allows private egress) and the one-shot DNS-rebind choke (resolve once, connect to
a pinned address), and is only consulted when `imports` declares `wasi:sockets` **and** the node
posture `allow_guest_dynamic_egress` is on (empty ⇒ deny-all).

> **Operator caveats.** (1) A `**` entry allows **any** global host on that port — a footgun;
> scope as tightly as the IdP allows. (2) The match is on the host NAME FAMILY, not a single IP:
> a suffix like `*.okta.com` makes **every** org under that multi-tenant IdP reachable (it does
> not pin to a specific tenant's IP). Prefer the most specific host you can.

Honored on **handler, consumer, session, and standalone-function** components alike — a session
component's guest gets the SAME gated egress (static `egress_allowlist` + this runtime-host list)
a handler does, through the same `resolve_and_gate_tcp_egress` gate.

```ron
handlers: [ (route: "/sso/callback", component: "sso.wasm", imports: ["wasi:sockets"],
             dynamic_egress_hosts: ["oauth2.googleapis.com:443", "www.googleapis.com:443", "*.okta.com:443"]) ],
```

### `http-egress` (host-mediated HTTP to a runtime host)

A guest that imports `wasi:sockets` and declares `dynamic_egress_hosts` can also call the
host-mediated **HTTP request** verb `boatramp:handlers/http-egress` `emit-http-dynamic(host, port,
request)` (BR-REQ-3) — the ergonomic sibling of the raw-TLS `tcp-egress` `connect-tls` dial. Where
`connect-tls` hands the guest a raw TLS byte stream (so an HTTP call means hand-rolling HTTP/1.1),
`emit-http-dynamic` lets the guest name a host + a request (method, path, headers, body) and the
**host** owns the HTTP/1 framing and strict TLS, returning one buffered `response` (status, headers,
body). So a per-tenant OIDC token POST + a JWKS GET become one-line calls in any guest language.

It is gated by the **exact same** controls as `connect-tls`'s runtime-host path — one grant
(`wasi:sockets`), one allowlist (`dynamic_egress_hosts`), one posture (`allow_guest_dynamic_egress`),
one gate (`resolve_and_gate_tcp_egress`): the host is validated by NAME against `dynamic_egress_hosts`,
every resolved address is held to the `is_global_ip` SSRF floor, the name is resolved **once** and the
host connects only to that pinned address (DNS-rebind choke), and TLS is terminated **strict** (webpki
⊕ the operator's extra roots). It is **HTTPS-only** (there is no cleartext verb), and the host supplies
the framing headers (`host`, `connection: close`, `content-length`) — a guest copy of any of those is
dropped. The response is bounded by a per-call timeout **and** a response-size cap (a larger response
is refused with `response-too-large`, never truncated). **Redirects are not followed**: a 3xx is
returned as-is, and the guest re-calls for the new host (which is itself re-gated against the
allowlist) — so the host never auto-follows a redirect to an un-gated host. A guest declares
`requires = ["http-egress"]` so a deploy against a host predating BR-REQ-3 is refused cleanly.

### `dns_publish_zones`

The deny-by-default **writable-zone allowlist** (globs) for the gated
[`dns-publish`](#imports) capability: the zone suffixes this handler may WRITE DNS
records under (empty ⇒ write nothing). The allowlist constrains a record's OWN
name/owner only — an rdata TARGET (a CNAME/MX/SRV/NS exchange/target) may legitimately
point at another domain and is never constrained by it. Matched case-insensitively
(exact, `*.suffix` one label, `**.suffix` any depth). Only consulted when `imports`
contains `dns-publish` **and** the node posture `allow_guest_dns_publish` is on.

```ron
handlers: [ (route: "/api", component: "api.wasm", imports: ["dns-publish"], dns_publish_zones: ["*.example.com"]) ],
```

### `dns_publish_ns_targets`

The deny-by-default allowlist (globs) of nameserver targets a **sub-zone `NS`** record
this handler writes may delegate to — the analog of
[`dns_publish_zones`](#dns_publish_zones) but for the NS record's rdata TARGET rather
than its own name. Only consulted when the node posture `guest_dns_publish_ns` is
`allowlist` and the record is a non-apex `NS`; irrelevant under `none` (all sub-zone NS
refused) or `any` (all permitted). Does not affect any other record type.

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
| `upload_containers` | list\<string\> | Blob containers this consumer may mint an S3 upload credential for via a [`blob-upload`](#imports) import — same deny-by-default allowlist and host-forced [`{tenant}` template](#upload_containers) as a handler's. |
| `egress_allowlist` | list\<string\> | Outbound-TCP targets this consumer may dial via [`wasi:sockets`](#imports) — same deny-by-default [allowlist](#egress_allowlist) as a handler's. |
| `dynamic_egress_hosts` | list\<string\> | Runtime-resolved `host-glob:port` targets this consumer may dial by NAME — same deny-by-default [allowlist](#dynamic_egress_hosts) as a handler's (HTTPS-only, posture `allow_guest_dynamic_egress`). |
| `dns_publish_zones` | list\<string\> | Zone-suffix globs this consumer may WRITE DNS records under via [`dns-publish`](#imports) — same deny-by-default [allowlist](#dns_publish_zones) as a handler's. |
| `dns_publish_ns_targets` | list\<string\> | Nameserver-target globs a sub-zone `NS` record this consumer writes may delegate to — see [dns_publish_ns_targets](#dns_publish_ns_targets). |
| `group` | string | Consumer group. Empty (default) = the competing-consumer **work-queue** (one consumer handles each message); a non-empty name = a durable **fan-out** subscriber that receives *every* message on its own cursor, independent of other groups. |
| `start` | `latest` \| `earliest` | Where a non-empty `group` starts on first subscription: `latest` (default — only new events) or `earliest` (replay the retained backlog). Ignored for the work-queue. |
| `tenancy` | Tenancy? | In-site [tenancy decision](./siteconfig.md#handlerstenancy) for this consumer's `sql`/`orm` when a drained message is processed — the async-lane analog of a function's tenancy. Typically resolves from the `signed_context` source the producer stamped, e.g. `(mode: "scoped", column: "tenant_id", sources: [(kind: "signed_context")], read: "own", write: "own")`. Absent ⇒ *undeclared* (refused under `multi-tenant`, `disabled` under single-tenant/dev). |
| `token_claims` | HandlerGraphqlTokenClaims? | JWKS/issuer config verifying an app bearer for a `token` tenant source (rare on the async lane, but supported when a consumer is invoked with a forwarded bearer). Absent ⇒ the `token` source can't verify (fail-closed). |

## `webhook_sinks`

A **webhook sink** is a host-run pseudo-consumer that drains a project-bus topic and
delivers each message as a **signed, SSRF-confined outbound POST** — the no-code way
to push bus events to an external endpoint, riding the same durable
claim/lease/ack/nack/redelivery/DLQ core a [consumer](#consumers) uses (an HTTP 2xx
acks the message; a non-2xx / timeout / floor-refusal nacks it with a backoff and it
dead-letters at `max_attempts`). The **same** `WebhookSink` record is declared here in
config *or* registered at runtime via `PUT /api/projects/{project}/bus/sinks/{name}`
(`Messaging·Admin`); both run the same validation. For the delivery flow, the HMAC
signature scheme, and the config-vs-runtime interaction, see
[Consume the bus from outside the sandbox](../how-to/background-work.md#d-webhook-sink-host-run-signed-delivery).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | — | Sink name — a valid resource slug, unique within the project. (On the runtime surface the `{name}` path segment is authoritative.) |
| `topic` | string | — | The project-bus topic to drain (`"orders/created"`). Namespaced host-side to `{project}/bus/<topic>`; no leading `/` and no `.`/`..` segments. |
| `group` | string | `""` | Durable fan-out lane (own cursor / lease / DLQ). Empty ⇒ the default competing-consumer work-queue. A non-empty group must be a single clean segment. |
| `url_secret` | string | — | **Sealed** `boatramp:<name>` reference to the destination URL in the project secret store. Never a plaintext URL (the raw URL never rides config or a request body, and is never logged). Must resolve to an **https** URL. |
| `sign_secret` | string | — | **Sealed** `boatramp:<name>` reference to the per-sink HMAC-SHA256 signing key the POST body + headers are signed with. |
| `egress_allow` | list\<string\> | — | Per-sink egress allowlist: `host-glob:port` entries the resolved destination must match (register-time **and** delivery-time). HTTPS-only, names only (an IP literal never matches), **empty ⇒ deny-all** — so at least one entry is required. |
| `lease_ms` | u64? | server default | Visibility lease (ms) per claimed message. |
| `max_attempts` | u32? | server default | Dead-letter threshold. |
| `backoff_ms` | u64? | — | Linear redelivery backoff base (ms): a failed delivery is held `backoff_ms × attempts`. Floored to a minimum server backoff so a `0`/unset sink can't hot-loop a failing endpoint. |
| `max_ack_pending` | usize? | — | Max leased-but-unacked messages outstanding at once (back-pressure). |

Secret names are `[A-Za-z0-9._-]` (no `/`). Both `url_secret` and `sign_secret` must
be **sealed before** a runtime `PUT` registers the sink — an unresolved/plaintext
reference is a `400`. The destination is held to an SSRF floor (https-only, every
resolved address globally routable, DNS-rebind-pinned) at register **and** every
delivery; there is deliberately no `allow_private` field — relaxing the floor is
operator-only, never consumer-settable. A project may hold at most **256** sinks.

```ron
webhook_sinks: [
    ( name: "orders", topic: "orders/created", group: "webhook",
      url_secret: "boatramp:orders-url", sign_secret: "boatramp:orders-sign",
      egress_allow: ["hooks.example.com:443"], max_attempts: 8 ),
],
```

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
| `authz` | StreamAuthz? | `None` (open broadcast) | **Per-connection authorization.** Absent ⇒ the fixed `topics` broadcast to every connection. Present ⇒ each connection is authorized before it attaches and subscribes only the topics it is authorized for. Capture the scope in `route` with `:name` and reference it in `topics` with `{name}`. Two forms: `scoped(token_claims, membership: [claim(param, claim) \| sql(source?, query)])` (host-resolved — verify the bearer, check each membership, subscribe only the resolved topics; deny-by-default AND) or `guest_mediated(token_claims?, handler)` (a guest function returns the topic set, confined to the declared `topics` templates). For `guest_mediated`, `handler` is the **bare name of a deployed top-level function** (the per-subscribe invoke target — `boatramp function deploy <name> …`, or a top-level `functions:` entry), **not** a route path and **not** `<site>/<name>`; deploy that authorizer function **before** activating the stream (activation refuses a stream whose `handler` resolves to no function). Confinement matches a `{name}` template **whole-segment only** — a partial-segment template like `shared/mbx-{mailbox}/events` is treated as a literal and parameterizes nothing. Optional `max_topics_per_connection: <n>` caps how many confined topics one connection may be granted (a larger return refuses the connection with a `502`); omit for unlimited (default), `0` is rejected at validate. See [Per-subscriber scoped streams](../how-to/background-work.md#per-subscriber-scoped-streams-authz). |
| `cors_allowed_origins` | list\<string\> | `[]` | **Operator CORS allowlist** for this host-served stream — the origins a cross-origin browser `EventSource` / `fetch` may read it from. A native stream has no guest to emit `Access-Control-*`, so a cross-origin request is blocked unless its origin is listed here. Each entry is an exact `scheme://host[:port]` origin; a single `"*"` permits any origin (still echoed back specifically, never literal `*`). The host answers the preflight `OPTIONS` and echoes `Access-Control-Allow-Origin` for a **matched** origin only, always with `Vary: Origin`; `Access-Control-Allow-Credentials` is **never** set (bearer auth, not cookies). The allowlist is config, never request-derived. Empty (default) ⇒ no CORS headers at all (same-origin only) — an existing deploy is byte-for-byte unchanged. See [Push events to browsers over SSE](../how-to/background-work.md#push-events-to-browsers-over-sse-streams). |

`StreamConfig` is `#[non_exhaustive]` (0.75.0): a library consumer constructs it via
`StreamConfig::builder(route)` — e.g. `StreamConfig::builder("/events").topics(vec!["orders/created".into()]).build()`
— or `StreamConfig::default()` followed by field assignment, never an exhaustive or
`..Default::default()` struct literal (neither compiles across a crate boundary once a struct is
sealed). This keeps a field added in a later release (such as `cors_allowed_origins` in 0.74.0)
a non-breaking change for downstream crates. (RON authoring in `project.cfg` is unaffected.)

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
| `egress_allowlist` | list\<string\> | `[]` | Outbound-TCP targets the session may dial via [`wasi:sockets`](#imports) — same deny-by-default [allowlist](#egress_allowlist) as a handler's. (Distinct from a `[serve.listeners.<name>]` TCP listener's own `egress_allowlist`, which gates that listener's `promote-connection` escalation instead.) |
| `dynamic_egress_hosts` | list\<string\> | `[]` | Runtime-resolved `host-glob:port` targets this session may dial by NAME — same deny-by-default [allowlist](#dynamic_egress_hosts) as a handler's (HTTPS-only, posture `allow_guest_dynamic_egress`). A session gets the SAME gated egress a handler does. |
| `dns_publish_zones` | list\<string\> | `[]` | Zone-suffix globs the session may WRITE DNS records under via [`dns-publish`](#imports) — same deny-by-default [allowlist](#dns_publish_zones) as a handler's. |
| `dns_publish_ns_targets` | list\<string\> | `[]` | Nameserver-target globs a sub-zone `NS` record the session writes may delegate to — see [dns_publish_ns_targets](#dns_publish_ns_targets). |
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
