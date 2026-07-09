# How a request reaches your site

boatramp serves a site at a **root mountpoint** — the site's files answer at `/`,
`/assets/app.js`, `/api`, exactly as they were authored. This page explains every
way a request is matched to a site, in the order you meet them: the local
single-site default, host/domain routing in production, the zero-DNS
`<site>.localhost` convenience, and the explicit by-name admin route.

The routing itself is one pure function shared by every deployment target, so a
request resolves the same way on a single node, a cluster, or Cloudflare
Containers. What differs is only *which host names resolve to which site*.

## The single-site default (local first run)

When a server serves exactly one site, that site answers at the root of the
listener. Run `boatramp serve`, publish one site, and it is there:

```sh
curl http://127.0.0.1:8080/
```

No host header, no domain, no path prefix. This is the first-run experience in
[Publish your first site](../tutorials/first-site.md): the site you just
published *is* the site at `/`. Publish a second site and the default turns off
(the server can no longer guess which one you mean) — then you address sites by
host, below.

## Host / domain routing (production)

In production a site answers on a hostname you attach to it. The `Host` header of
each request selects the site; the request path is served at that host's root. A
site can hold a primary hostname, exact aliases, and wildcards — see the
[`domains` config](../reference/siteconfig.md#domains).

```sh
boatramp domain add app.example.com --method dns
boatramp domain verify app.example.com
```

boatramp routes a host only after you prove you control it, so attaching is a
verify-then-route task — see [Attach a custom domain](../how-to/custom-domain.md).
Because selection rides the `Host` header, it behaves identically on every
topology; a domain is registered once and every node resolves it. A host that
matches no attached domain returns `404`, unless a
[default site](#the-single-site-default-local-first-run) or an explicit
`--default-site` catch-all is set.

## `<site>.localhost` (zero-DNS local multi-site)

To work on several sites locally without editing DNS or `/etc/hosts`, address a
site by putting its name in the first host label. `blog.localhost` resolves to the
site named `blog`, served at root:

```sh
curl -H 'Host: blog.localhost' http://127.0.0.1:8080/
# or, so the browser/curl resolves it to loopback:
curl --resolve blog.localhost:8080:127.0.0.1 http://blog.localhost:8080/
```

Most resolvers (macOS, systemd-resolved) send `*.localhost` to loopback already,
so a browser can just visit `http://blog.localhost:8080/`. On systems that do not
(bare Windows, some musl setups), use `--resolve` or an explicit `Host` header —
that is a client resolver gap, not a difference in how boatramp behaves.

First-label routing never overrides a registered domain: an attached host always
wins over a same-named label.

> **Note:** the single-site default and `<site>.localhost` routing are
> conveniences for local and single-operator use. They are **on** for a loopback
> bind, and under the `single-tenant` and `dev` [security
> postures](./security-posture.md); they are **off** under the default strict
> `multi-tenant` posture on a public address, where an unmatched host resolves
> only to an explicit `--default-site` or `404`. This keeps a public multi-tenant
> server from ever resolving `Host: <sitename>.attacker.example` to one of your
> sites by name.

## `/_sites/<name>` (explicit by-name, admin/testing)

Every site is also reachable by name at `/_sites/<name>/…`, regardless of host.
This is an **admin and testing** affordance — a quick way to hit a specific site
without attaching a host:

```sh
curl http://127.0.0.1:8080/_sites/blog/
```

It is **not** a hosting model. Because the site's content is served under a path
prefix, a site authored for root — with absolute references like `/assets/app.js`
or `fetch('/api')` — breaks here: those URLs resolve against the origin root, not
the `/_sites/blog/` prefix. Use host routing (or the single-site default) to serve
such a site; reach for `/_sites/<name>` only for by-name inspection.

> **Deprecated:** the older `/sites/<name>/…` prefix is a deprecated alias for
> `/_sites/<name>/…` and still works for now. Prefer `/_sites/`.

## Sub-path mounts

Serving a site under a deliberate sub-path (for a site *built* with a matching
base path, e.g. a framework's `base` / `basePath`) is not available yet. Absolute
URLs authored for root cannot be rewritten server-side in the general case, so the
supported model is a root mountpoint via host routing. See
[Maturity, validation & support](./maturity.md) for status.

## Choosing

| You want | Use |
| --- | --- |
| A quick local first run | The single-site default — publish one site, hit `/`. |
| Several sites locally, no DNS | `<site>.localhost` (first-label routing). |
| Production on your own hostname | [Attach a domain](../how-to/custom-domain.md); the site answers at its host's root. |
| To inspect a specific site by name | `/_sites/<name>/` (admin/testing). |
