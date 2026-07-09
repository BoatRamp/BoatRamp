# Domains & Virtualhosts

A site answers on the explicit `/sites/<name>/…` route always, and on any
**domains** you attach. Domains are resolved from the request `Host` header.

## Ownership verification

Attaching a custom domain is gated on proving you control it — *before* it routes
or becomes eligible for a certificate:

```sh
boatramp domain add app.example.com --method http   # or: --method dns
#   → prints a token to publish (an HTTP file or a _boatramp-verify TXT record)
boatramp domain verify app.example.com               # checks it, then attaches
boatramp domain ls                                   # attached + pending
```

- **HTTP token** — serve the printed token under
  `/.well-known/boatramp-domain-verification/<token>` on the host. Works in
  every build.
- **DNS TXT** — publish a `_boatramp-verify.<host>` TXT record. Proves control
  while the domain still points elsewhere (good for migrations). Needs a server
  built with the `domain-verify-dns` feature.

Until a host is verified it never enters routing and never requests a cert.

With a managed-DNS provider configured, `domain add --auto --provider <name>`
publishes the DNS-TXT challenge and verifies it for you — see
[Auto-DNS & Custom Domains](./auto-dns.md).

## Wildcards and canonical hosts

- A `*.example.com` entry matches by suffix at any depth; an exact match always
  wins over a wildcard.
- Set `domains.canonical_redirect` to 301 exact aliases (e.g. `www`) to the
  primary host. Wildcard hosts serve as-is.

## Unmatched hosts

A `Host` that matches no domain returns `404`, or — if you set
`[serve].default_site` — falls back to that catch-all site.

## Preview hosts

Each deployment is reachable by id at `/_deploy/<id>/…` and, under a wildcard
preview cert, at `<id>.deploy.<site-host>`. Preview ids are unguessable content
hashes; set `[serve].protect_previews` to additionally require a bearer token.
