# The request pipeline

Every request for served content runs through one ordered pipeline. Each stage is
driven by the site's config, and the stages run in a fixed order so the behavior
is predictable. Nothing is buffered whole in memory — the response streams from
the backend as soon as the pipeline resolves it.

## The order

1. **Host → site.** The `Host` header selects the site (virtualhost routing),
   with an optional default site for an unmatched host. The full set of ways a
   request is matched to a site is in
   [How a request reaches your site](./addressing.md).
2. **Transport.** HTTPS redirect and HSTS, proxy-aware through
   `X-Forwarded-Proto` from a trusted proxy.
3. **Access control.** WAF, then IP rules, then rate limit, then basic auth — the
   first to reject wins. See
   [Restrict visitor access](../how-to/visitor-access.md).
4. **Path normalization.** Clean URLs, the trailing-slash policy, and dot-segment
   collapsing (traversal-safe).
5. **Route.** Redirects, then handlers, then rewrites / SPA fallback /
   reverse-proxy. A redirect or rewrite may carry a `when` condition evaluated
   against the request (language, cookies, headers, file existence), which
   contributes to the response `Vary`.
6. **Resolve.** Map the path to a manifest entry — a directory index, or a custom
   error document when nothing matches.
7. **HTTP correctness.** Conditional `304`, `Range` / `206`, `ETag`, response
   headers, `Cache-Control`, and compression negotiation.

An early stage can end the request — a rejected access-control check, a redirect,
a handler that answers — before the later stages run.

## Inside handler dispatch

When stage 5 routes a request to a **handler** (a Wasm component) rather than
static content, a small sub-pipeline runs around the component, in this order:

1. **Cookie session auth.** If the site enables
   [`cookie_auth`](../how-to/handler-bindings.md#authenticate-a-browser-with-a-session-cookie)
   and the request carries the named cookie but no `Authorization` header, boatramp
   injects `Authorization: Bearer <cookie>` **here**, before anything downstream —
   so the GraphQL edge, the data connector, the handler, and any sibling `invoke`
   all see the same bearer. A cookie-authenticated request is CSRF-checked first.
2. **GraphQL edge** (if `graphql` is on). The [query-guard](../how-to/graphql.md#the-query-guard)
   rejects an over-deep/complex or disallowed operation before the handler runs;
   persisted-query/safelist resolution and — for a gateway site — federation
   planning + execution happen here instead of invoking a single component.
3. **Response cache lookup** (if [`cache`](../how-to/caching.md#cache-handler-responses-at-the-edge)
   is on). A cacheable `GET`/`HEAD` hit is served without instantiating the handler.
4. **Handler execution.** The component runs with its granted host bindings.
5. **Response cache store.** A cacheable response is stored **after** the bearer
   injection above, so its cache key already reflects the authenticated request and
   a private per-user response is not stored (see the caching rules).

## Why the order is fixed

The order encodes precedence you would otherwise have to reason about per
request. Access control runs before any content work, so a blocked request never
touches the manifest. Redirects run before handlers, so a moved path does not
invoke code. Path normalization runs before routing, so route patterns match a
canonical path and cannot be bypassed with `..` or a double slash.

## The routing core is pure and shared

Stages 4 through 7 — normalization, routing, resolution, and HTTP correctness —
are pure functions in `boatramp_core::route`, with no I/O. That has two
consequences. They are unit-tested in isolation, against inputs rather than a
running server. And they are reused by the Cloudflare edge Worker, so a request
routes identically at the edge and at the origin — the two cannot drift, because
they run the same code. See the [architecture overview](./architecture.md).
