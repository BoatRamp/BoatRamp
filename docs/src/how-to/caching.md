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

## Reference

- Full `routing` schema, including `cache.default` and header-rule fields:
  [project.cfg reference](../reference/project-cfg.md).
- Content negotiation and `Content-Encoding`: [Enable compression](./compression.md).
