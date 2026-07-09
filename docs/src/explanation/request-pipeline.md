# The request pipeline

Every request for served content runs through one ordered pipeline. Each stage is
driven by the site's config, and the stages run in a fixed order so the behavior
is predictable. Nothing is buffered whole in memory — the response streams from
the backend as soon as the pipeline resolves it.

## The order

1. **Host → site.** The `Host` header selects the site (virtualhost routing),
   with an optional default site for an unmatched host.
2. **Transport.** HTTPS redirect and HSTS, proxy-aware through
   `X-Forwarded-Proto` from a trusted proxy.
3. **Access control.** WAF, then IP rules, then rate limit, then basic auth — the
   first to reject wins. See
   [Restrict visitor access](../how-to/visitor-access.md).
4. **Path normalization.** Clean URLs, the trailing-slash policy, and dot-segment
   collapsing (traversal-safe).
5. **Route.** Redirects, then handlers, then rewrites / SPA fallback /
   reverse-proxy.
6. **Resolve.** Map the path to a manifest entry — a directory index, or a custom
   error document when nothing matches.
7. **HTTP correctness.** Conditional `304`, `Range` / `206`, `ETag`, response
   headers, `Cache-Control`, and compression negotiation.

An early stage can end the request — a rejected access-control check, a redirect,
a handler that answers — before the later stages run.

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
