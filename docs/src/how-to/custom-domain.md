# Attach a custom domain

To serve a site on a hostname of your own — `app.example.com` — you attach that
host to the site, and it answers at that host's root. boatramp routes a host only
after you prove you control it. For every way a request is matched to a site, see
[How a request reaches your site](../explanation/addressing.md).

`domain add` does as much as it can in one step: when the host already resolves to
this server, it verifies over HTTP and attaches immediately — no prior deploy, no
manual token juggling. When there's still a manual step (a live domain pointing
elsewhere), it prints the challenge and you finish with `domain verify`.

## Before you start

- A site to attach the host to.
- Control of the host: it either already points at this server, or you can serve
  a file on it (HTTP), or you have access to its DNS zone (DNS TXT).
- For the DNS-TXT method, a server built with the `domain-verify-dns` feature.

## The common case: the host already points here

If `app.example.com` already resolves to this boatramp server (its A/CNAME points
at the box, e.g. right after you cut a CNAME over to it), a single command
verifies and attaches it:

```sh
boatramp domain add app.example.com
```

```text
started http verification for app.example.com

Serve this token, then run `boatramp domain verify app.example.com`:
  GET http://app.example.com/.well-known/boatramp-domain-verification/7f3c9a2e…
  body: 7f3c9a2e…

checking whether app.example.com already resolves here…
✓ verified app.example.com and attached it to my-site
```

boatramp serves its own challenge token from the edge (before host routing), so a
host pointed at the server proves ownership over HTTP with **no prior deploy** —
this is what removes the old "the host 404s its own challenge" chicken-and-egg.
The host now routes and is eligible for a certificate.

## Migrating a live domain (still pointing elsewhere)

When the host still serves live traffic from somewhere else, prove ownership over
DNS *before* you cut anything over. If a managed-DNS provider is configured, one
command publishes the `_boatramp-verify` TXT, waits for it to resolve, and
attaches — it never touches the host's A/CNAME:

```sh
boatramp domain add app.example.com --provider cloudflare
```

See [Automate DNS with a provider](../how-to/auto-dns.md). Without a provider, add
the TXT record yourself and verify in two steps:

```sh
boatramp domain add app.example.com --method dns
# add the printed _boatramp-verify.<host> TXT to your zone, then:
boatramp domain verify app.example.com
```

Because DNS proves zone control while the host still points away, you can verify
and attach first, then cut the A/CNAME over when you're ready.

## Serving the token yourself (HTTP, host elsewhere)

If you'd rather prove control by serving a file — and the host isn't pointed here
yet — start the challenge, place the token, then verify. `--no-wait` skips the
immediate self-check when you know there's a manual step:

```sh
boatramp domain add app.example.com --no-wait
```

```text
started http verification for app.example.com

Serve this token, then run `boatramp domain verify app.example.com`:
  GET http://app.example.com/.well-known/boatramp-domain-verification/7f3c9a2e…
  body: 7f3c9a2e…

then run `boatramp domain verify app.example.com`
```

Serve the token body at that path on the host, then:

```sh
boatramp domain verify app.example.com
```

```text
verified app.example.com and attached it to my-site
```

If the check fails the host stays pending — confirm the token resolves (or the TXT
record has propagated) and run `domain verify` again. A pending host does not route
and cannot request a certificate.

## Confirm the attachment

List the site's domains to see what routes and what is still pending:

```sh
boatramp domain ls
```

```text
app.example.com   (primary)
beta.example.com

pending verification:
  gamma.example.com  (dns, unverified)
```

## Remove a domain

Detach a host — attached or still pending — with `domain rm`. It stops routing
immediately:

```sh
boatramp domain rm app.example.com
```

```text
detached app.example.com from my-site
```

## Next: get a certificate

An attached host is eligible for a certificate but does not have one yet. Issue
one so the domain serves over HTTPS — see
[Get an automatic certificate](../how-to/acme-cert.md).
