# Migrate from Netlify / Cloudflare Pages

Move a static site to boatramp without rewriting your redirect and header rules.
On `sync`, boatramp folds a Netlify-style `_redirects` file and a `_headers` file
from the root of your published folder into the deployment's routing, so those
rules keep working as they are.

## Before you start

- A built site directory (for example `./dist`).
- A boatramp server and a site name. See
  [Publish, roll back, and alias a site](./publish.md).

## 1. Keep your build output as-is

Build your site with your existing toolchain. Do not change the output. Keep
`_redirects` and `_headers` at the root of the folder you publish:

```text
dist/
├── index.html
├── _redirects
└── _headers
```

A `_redirects` line such as `/old/* /new/:splat 301` and a `_headers` block carry
over unchanged.

## 2. Sync the folder

Point `sync` at the build output:

```sh
boatramp sync ./dist --site my-site
```

```text
folded 4 rule(s) from _redirects, 2 from _headers
uploading 12 missing blob(s)… done
activated my-site -> 4f3a2b2c
```

The folded rules join the deployment's immutable routing manifest, so they roll
back atomically with the content.

## 3. Confirm a redirect

Request an old path and check the redirect and its target:

```sh
curl -sI https://my-site.example/old/page
```

```text
HTTP/2 301
location: /new/page
```

## Beyond `_redirects` and `_headers`

Those two files cover redirects and header rules. For rewrites, SPA fallback,
reverse-proxy targets, clean URLs, custom error documents, and handlers, write
the `routing` section of `project.cfg`. See [Configure routing](./routing.md) and
the [project.cfg schema](../reference/project-cfg.md).
