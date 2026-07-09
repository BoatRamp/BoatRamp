# Configure routing

Routing rules — redirects, rewrites, response headers, an SPA fallback, clean
URLs, the trailing-slash policy, and custom error documents — live in the
`routing` section of `project.cfg`. This section folds into the immutable
deployment manifest, so it activates and rolls back atomically with the content
it ships. Handlers, consumers, crons, and streams also live in `routing`; those
are covered in [Deploy a handler](./deploy-handler.md).

## Write the routing config

`project.cfg` is RON. Set the rules you need under `routing`:

```ron
(
    publish: ( server: "https://pad.example.com", site: "my-site" ),
    routing: (
        // Serve /about for /about.html and drop the extension in links.
        clean_urls: true,
        // Send old paths to new ones. `:slug` captures a path segment.
        redirects: [
            (from: "/old/:slug", to: "/new/:slug", status: 301),
            (from: "/blog", to: "/articles", status: 302),
        ],
        // Long-cache fingerprinted assets by glob match.
        headers: [
            (matches: "**.js", set: { "Cache-Control": "public, max-age=31536000, immutable" }),
        ],
        // Serve your own 404 page for unmatched paths.
        error_documents: { 404: "/404.html" },
    ),
)
```

For a single-page app, add a rewrite so unmatched paths render the app shell
instead of a 404:

```ron
rewrites: [ (from: "/**", to: "/index.html") ],
```

A rewrite serves a different file under the requested URL; a redirect sends the
client a new URL with a 3xx status.

## Validate before you publish

`boatramp validate` parses `project.cfg` and checks the routing rules — glob
patterns, redirect targets, status codes — before anything ships:

```sh
boatramp validate
```

```text
project.cfg: routing OK (2 redirects, 1 rewrite, 1 header rule, clean_urls on)
```

Migrating from Netlify or Cloudflare Pages? `sync` folds `_redirects` and
`_headers` files into this config, so you keep those rules without rewriting them
— see [Migrate from Netlify / Cloudflare Pages](./migrate.md).

## Publish and verify

Publish the deployment, then confirm the redirect:

```sh
boatramp sync ./dist --site my-site
curl -sI https://pad.example.com/old/hello
```

```text
HTTP/2 301
location: /new/hello
```

The redirect belongs to this deployment. Roll back — or activate a previous
deployment — and the routing rules revert with the content in the same step;
there is no separate routing state to reconcile.

## Reference

- Full `routing` schema and every field: [project.cfg schema](../reference/project-cfg.md).
- Match order, glob syntax, and precedence: [Routing config schema](../reference/routing.md).
