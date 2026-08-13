# Control caching

boatramp already sets a sensible `Cache-Control` on every file it serves, adds a
strong `ETag`, answers conditional requests with `304`, and honors `Range` — you
do not configure any of that. This page covers the one thing you do control:
overriding `Cache-Control` per path, so hashed assets cache for a year and HTML
always revalidates.

## When to override

Reach for a header rule when the automatic default is wrong for a path. Two cases
cover almost everything:

- **Long-lived immutable assets** — files whose name changes when their content
  does (`app.4f3a2b2c.js`). Cache them for a year.
- **Always-revalidate documents** — HTML, JSON feeds, anything that keeps its URL
  across deploys. Force a check on every request.

boatramp's defaults already do this for content-hashed filenames and HTML. Add
rules when your paths do not match that shape (an unhashed `/vendor/` bundle, a
hand-written `/api/config.json`), or when you want a blanket policy.

## Set Cache-Control per path

Header rules live in `project.cfg` under `routing.headers`. Each rule has a path
`matches` pattern and a `set` map; every matching rule applies, in order.

```ron
(
    routing: (
        headers: [
            // Fingerprinted assets — safe to cache for a year.
            (matches: "/assets/**", set: {
                "Cache-Control": "public, max-age=31536000, immutable",
            }),
            // Documents — always revalidate so a new deploy is picked up.
            (matches: "**.html", set: {
                "Cache-Control": "public, max-age=0, must-revalidate",
            }),
        ],
        // Blanket fallback for anything no rule matches.
        cache: (default: "public, max-age=3600"),
    ),
)
```

A matching `routing.headers` rule wins; `cache.default` fills the gaps;
boatramp's per-file defaults apply where neither is set. Rules are folded into
the immutable deployment at `sync`, so they roll back with the content. Run
`boatramp validate` to check the patterns before you publish.

## Verify the response

Request an asset and read the headers back:

```sh
curl -sI https://my-site.example/assets/app.4f3a2b2c.js
```

```text
HTTP/2 200
cache-control: public, max-age=31536000, immutable
etag: "9f86d081884c7d65..."
accept-ranges: bytes
vary: accept-encoding
```

The `etag` and `accept-ranges` are automatic. To confirm revalidation, send the
tag back — an unchanged asset answers `304`:

```sh
curl -sI https://my-site.example/assets/app.4f3a2b2c.js \
  -H 'If-None-Match: "9f86d081884c7d65..."'
```

```text
HTTP/2 304
etag: "9f86d081884c7d65..."
```

## Conditional routing varies automatically

If a [conditional redirect/rewrite](./routing.md#route-on-the-request-conditional-rules)
decides the response from a request header (`Accept-Language`, a cookie, `X-…`),
boatramp adds the matching **`Vary`** header for you — e.g. a locale redirect
gets `vary: accept-language`. A shared cache then keys on that dimension and never
serves one visitor's redirect to another. You don't set this by hand; conditions
that read only the URL + deploy content (`path`, `file_exists`) add no `Vary`.

## Cache handler responses at the edge

Everything above is about **static files**. A **handler** (a Wasm component) can
also opt into a host-level **response cache** that serves a cacheable `GET`/`HEAD`
response **without re-instantiating the handler** — the execution analogue of the
compile cache. It's off by default; turn it on in the site's handler config:

```ron
// boatramp.cfg — the site's handler config
handlers: (
    enabled: true,
    cache: (
        enabled: true,
        max_entry_bytes: Some(262144),   // largest cacheable response; default 256 KiB
        max_ttl_secs:    Some(3600),     // clamp an over-long max-age; default 3600s
    ),
)
```

The cache is **opt-in per response**, driven by the handler's own headers — it
never guesses. A response is stored only when **all** of these hold:

- the request is a `GET` or `HEAD`,
- the handler sets `Cache-Control: max-age=…` (or `s-maxage=…`),
- its size is known (`Content-Length`) and within `max_entry_bytes`.

And it is **never** stored when the response is private:

- `Cache-Control: no-store`, `private`, or `no-cache`,
- it carries a `Set-Cookie`,
- `Vary: *`, or
- the **request** carried an `Authorization` header and the response did not
  explicitly opt in with `public` or `s-maxage`.

Entries are keyed by the request's **project-qualified scope** (so two tenants
never collide), honor the response's `Vary` header, and expire by TTL (clamped to
`max_ttl_secs`, lazily evicted on read). The cache is backed by the site's KV
store.

> **With cookie auth.** A [cookie-authenticated](./handler-bindings.md#authenticate-a-browser-with-a-session-cookie)
> request carries an `Authorization` header (boatramp injects it from the
> cookie), so it inherits the rule above: a per-user response is not cached unless
> the handler explicitly marks it `public`/`s-maxage`. **Never** mark a per-user
> response `public` — that would let it be stored and served to another user.

## Reference

- Full `routing` schema, including `cache.default` and header-rule fields:
  [project.cfg reference](../reference/project-cfg.md).
- Handler `cache` fields: [SiteConfig reference](../reference/siteconfig.md).
- Content negotiation and `Content-Encoding`: [Enable compression](./compression.md).
